//! `MCPGCluster` controller — validates a cluster-coordination
//! backend binding and reports its bindability + blast radius.
//!
//! Unlike the gateway / plugin-set controllers, this controller
//! synthesises **no** child Kubernetes objects. A cluster binding is
//! consumed gateway-side: the gateway controller resolves
//! `spec.clusterRef`, renders the backend's `cluster:` block into the
//! gateway config, and folds the cluster's `configHash` into its
//! pod-roll trigger (see `controllers::gateway::resolve_cluster`).
//!
//! This controller's job is therefore:
//!
//! 1. Resolve `spec.backend` → cluster cdylib plugin id (or
//!    `single_node`, which needs none).
//! 2. When `spec.pluginRef` is set, require that cluster-scoped
//!    `MCPGPlugin` to be `Ready` (verified + not revoked) before
//!    declaring the cluster bindable — so a coordinator can't come up
//!    behind an unverified cluster plugin.
//! 3. Compute the rendered `cluster:` block's SHA-256 (the gateway
//!    pod-roll trigger) and count bound gateways (blast radius).
//! 4. Surface all of that on `.status` with a `Ready` condition.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use futures::StreamExt;
use kube::api::Api;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::events::{Event as K8sEvent, EventType};
use kube::runtime::watcher;
use kube::{Resource, ResourceExt};
use mcpg_operator_api::conditions::{Condition, reasons, types as ctype};
use mcpg_operator_api::v1alpha1::{MCPGCluster, MCPGClusterStatus, MCPGGateway, MCPGPlugin};
use rand::Rng;
use sha2::{Digest, Sha256};
use tracing::{error, info, instrument};

use crate::FIELD_MANAGER_PREFIX;
use crate::controllers::gateway::ControllerContext;
use crate::reconcile::{OPERATOR_FINALIZER, ensure_finalizer, patch_status, remove_finalizer};
use crate::telemetry::ReconcileOutcome;

const FIELD_MANAGER_SUFFIX: &str = "cluster-controller";
const CONTROLLER_NAME: &str = "cluster";

/// Reasons surfaced on `MCPGCluster.status.conditions[Ready]`.
mod cluster_reason {
    /// Backend bindable (plugin verified when `pluginRef` set, or
    /// `single_node`).
    pub const BINDABLE: &str = "Bindable";
    /// `pluginRef` names an `MCPGPlugin` that doesn't exist.
    pub const PLUGIN_NOT_FOUND: &str = "ClusterPluginNotFound";
    /// `pluginRef` plugin exists but isn't `Ready` (unverified /
    /// revoked / still pulling).
    pub const PLUGIN_NOT_READY: &str = "ClusterPluginNotReady";
}

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("status: {0}")]
    Status(#[from] crate::reconcile::StatusError),
    #[error("finalizer: {0}")]
    Finalizer(#[from] crate::reconcile::FinalizerError),
    #[error("kube: {0}")]
    Kube(#[from] kube::Error),
    #[error("missing name on MCPGCluster")]
    MissingName,
}

/// Run the cluster controller until cancelled. Re-reconciles a
/// cluster when a bound `MCPGGateway` changes (blast-radius count) or
/// the referenced `MCPGPlugin` flips readiness.
pub async fn run(ctx: Arc<ControllerContext>) -> anyhow::Result<()> {
    let api: Api<MCPGCluster> = Api::all(ctx.client.clone());

    info!("starting cluster controller");

    Controller::new(api, watcher::Config::default())
        .watches(
            Api::<MCPGGateway>::all(ctx.client.clone()),
            watcher::Config::default(),
            map_gateway_to_clusters,
        )
        .watches(
            Api::<MCPGPlugin>::all(ctx.client.clone()),
            watcher::Config::default(),
            map_plugin_to_clusters,
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => info!(name = %obj.name, "cluster reconciled"),
                Err(err) => error!(error = ?err, "cluster reconcile failed"),
            }
        })
        .await;

    Ok(())
}

/// A gateway change re-reconciles the cluster it binds (so
/// `boundGateways` stays current). Gateways with no `clusterRef`
/// map to nothing.
fn map_gateway_to_clusters(
    gw: MCPGGateway,
) -> Vec<kube::runtime::reflector::ObjectRef<MCPGCluster>> {
    gw.spec
        .cluster_ref
        .as_ref()
        .map(|r| vec![kube::runtime::reflector::ObjectRef::new(&r.name)])
        .unwrap_or_default()
}

/// An `MCPGPlugin` readiness flip re-reconciles any cluster that
/// pins it via `pluginRef`. We can't cheaply reverse-index without
/// listing, so we re-reconcile by matching name at reconcile time;
/// here we conservatively map the plugin to a cluster of the same
/// name (the common convention) — the reconcile re-checks the real
/// `pluginRef` regardless, so a missed edge just waits for resync.
fn map_plugin_to_clusters(
    plugin: MCPGPlugin,
) -> Vec<kube::runtime::reflector::ObjectRef<MCPGCluster>> {
    vec![kube::runtime::reflector::ObjectRef::new(&plugin.name_any())]
}

#[instrument(
    skip_all,
    fields(name = %obj.name_any(), generation = obj.metadata.generation.unwrap_or(0))
)]
async fn reconcile(
    obj: Arc<MCPGCluster>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let started = Instant::now();
    let metrics = ctx.metrics.operator_metrics().clone();
    let result = reconcile_inner(obj, ctx).await;
    let outcome = match &result {
        Ok((_, o)) => *o,
        Err(ReconcileError::MissingName) => ReconcileOutcome::PermanentError,
        Err(_) => ReconcileOutcome::TransientError,
    };
    metrics.observe_reconcile(CONTROLLER_NAME, outcome, started.elapsed().as_secs_f64());
    result.map(|(action, _)| action)
}

async fn reconcile_inner(
    obj: Arc<MCPGCluster>,
    ctx: Arc<ControllerContext>,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    let name = obj
        .metadata
        .name
        .clone()
        .ok_or(ReconcileError::MissingName)?;
    let observed_generation = obj.metadata.generation.unwrap_or(0);
    let cluster_api: Api<MCPGCluster> = Api::all(ctx.client.clone());

    // Deletion branch — no synthesised children, so just release the
    // finalizer (bound gateways fall back to single_node on their own
    // next reconcile, which the gateway controller surfaces).
    if obj.metadata.deletion_timestamp.is_some() {
        info!(name = %name, "cluster deletion in progress; releasing finalizer");
        remove_finalizer(&cluster_api, &name, OPERATOR_FINALIZER).await?;
        return Ok((Action::await_change(), ReconcileOutcome::Success));
    }
    ensure_finalizer(&cluster_api, &name, obj.as_ref(), OPERATOR_FINALIZER).await?;

    let backend = obj.spec.backend;
    let plugin_id = backend.plugin_id().map(str::to_owned);

    // Rendered config block + its hash (the gateway pod-roll trigger).
    let config_block = obj.spec.render_cluster_block();
    let config_hash = {
        let json = serde_json::to_string(&config_block).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(json.as_bytes());
        hex::encode(h.finalize())
    };

    // Bindability gate: when `pluginRef` is set, the named
    // cluster-scoped MCPGPlugin must be Ready.
    let (ready, reason, message) = match &obj.spec.plugin_ref {
        Some(plugin_ref) => {
            let plugin_api: Api<MCPGPlugin> = Api::all(ctx.client.clone());
            match plugin_api.get_opt(&plugin_ref.name).await? {
                None => (
                    false,
                    cluster_reason::PLUGIN_NOT_FOUND,
                    format!("clusterPlugin '{}' not found", plugin_ref.name),
                ),
                Some(p) if plugin_is_ready(&p) => (
                    true,
                    cluster_reason::BINDABLE,
                    format!(
                        "backend '{}' bindable via verified plugin '{}'",
                        backend.config_kind(),
                        plugin_ref.name
                    ),
                ),
                Some(_) => (
                    false,
                    cluster_reason::PLUGIN_NOT_READY,
                    format!(
                        "clusterPlugin '{}' is not Ready (unverified / revoked / pulling)",
                        plugin_ref.name
                    ),
                ),
            }
        }
        // No pluginRef: single_node needs no plugin; an external
        // backend trusts the gateway's pluginSetRef to carry the
        // cdylib. Bindable either way.
        None => (
            true,
            cluster_reason::BINDABLE,
            if backend.is_single_node() {
                "in-process single_node coordinator".to_owned()
            } else {
                format!(
                    "backend '{}' bindable (cdylib supplied via gateway pluginSetRef)",
                    backend.config_kind()
                )
            },
        ),
    };

    // Blast radius: how many gateways bind this cluster.
    let bound_gateways = count_bound_gateways(&ctx.client, &name).await?;

    // Status.
    let mut conditions = obj
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();
    mcpg_operator_api::conditions::set_condition(
        &mut conditions,
        Condition::new(
            ctype::READY,
            if ready { "True" } else { "False" },
            if ready { reasons::RECONCILED } else { reason },
            message.clone(),
            Some(observed_generation),
        ),
    );

    let status = MCPGClusterStatus {
        conditions,
        observed_generation: Some(observed_generation),
        plugin_id: plugin_id.clone(),
        bound_gateways: Some(bound_gateways),
        config_hash: Some(config_hash),
        last_reconcile_time: Some(Utc::now()),
    };

    let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");
    if let Err(e) = patch_status(&cluster_api, &name, &status, &fm).await {
        tracing::warn!(error = ?e, "cluster: status patch failed");
    }

    // Emit an Event on the not-bindable path so `kubectl describe`
    // shows why a gateway binding is stuck.
    if !ready {
        let evt = K8sEvent {
            type_: EventType::Warning,
            reason: reason.to_owned(),
            note: Some(message.clone()),
            action: "Bind".to_owned(),
            secondary: None,
        };
        let _ = ctx
            .recorders
            .cluster
            .publish(&evt, &obj.object_ref(&()))
            .await;
    }

    let requeue = Action::requeue(jittered_resync(ctx.config.resync_interval_secs));
    if ready {
        Ok((requeue, ReconcileOutcome::Success))
    } else {
        // Dependency pending (plugin not ready/found): the
        // `.watches()` on MCPGPlugin nudges us when it flips; the
        // resync requeue is the backstop.
        Ok((requeue, ReconcileOutcome::DependencyPending))
    }
}

/// Periodic resync interval, jittered ±20% so a fleet of clusters
/// doesn't thundering-herd the apiserver on the same tick. Mirrors
/// the gateway controller's helper.
fn jittered_resync(base_secs: u64) -> Duration {
    let base = base_secs as f64;
    let jitter_factor = 0.8 + rand::thread_rng().gen_range(0.0..0.4);
    Duration::from_secs_f64(base * jitter_factor)
}

/// True when an `MCPGPlugin` has a `Ready=True` condition and isn't
/// flagged revoked.
fn plugin_is_ready(p: &MCPGPlugin) -> bool {
    let Some(status) = p.status.as_ref() else {
        return false;
    };
    if status.revoked_by_sha == Some(true) {
        return false;
    }
    status
        .conditions
        .iter()
        .any(|c| c.r#type == ctype::READY && c.status == "True")
}

/// Count `MCPGGateway`s (cluster-wide) whose `clusterRef.name`
/// matches this cluster.
async fn count_bound_gateways(
    client: &kube::Client,
    cluster_name: &str,
) -> Result<i64, ReconcileError> {
    let api: Api<MCPGGateway> = Api::all(client.clone());
    let gateways = api.list(&Default::default()).await?;
    let count = gateways
        .items
        .iter()
        .filter(|g| {
            g.spec
                .cluster_ref
                .as_ref()
                .is_some_and(|r| r.name == cluster_name)
        })
        .count();
    Ok(count as i64)
}

fn error_policy(
    obj: Arc<MCPGCluster>,
    err: &ReconcileError,
    ctx: Arc<ControllerContext>,
) -> Action {
    match err {
        ReconcileError::MissingName => Action::await_change(),
        _ => {
            let key = crate::backoff::resource_key(CONTROLLER_NAME, "", &obj.name_any());
            let count = ctx.backoff.record_error(&key);
            let delay = ctx.backoff.duration_for(&key);
            tracing::warn!(
                key = %key,
                consecutive_errors = count,
                requeue_secs = delay.as_secs(),
                error = ?err,
                "cluster: reconcile error; backing off"
            );
            Action::requeue(delay)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::{ClusterBackend, MCPGClusterSpec};

    fn cluster(spec: MCPGClusterSpec) -> MCPGCluster {
        MCPGCluster {
            metadata: ObjectMeta {
                name: Some("prod-cluster".into()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    #[test]
    fn single_node_renders_kind_only() {
        let c = cluster(MCPGClusterSpec {
            backend: ClusterBackend::SingleNode,
            ..Default::default()
        });
        let block = c.spec.render_cluster_block();
        assert_eq!(block["kind"], "single_node");
    }

    #[test]
    fn plugin_ready_requires_ready_condition_and_not_revoked() {
        use mcpg_operator_api::v1alpha1::{MCPGPlugin, MCPGPluginSpec};
        let mk = |conds: Vec<Condition>, revoked: Option<bool>| MCPGPlugin {
            metadata: ObjectMeta {
                name: Some("cluster-redis".into()),
                ..Default::default()
            },
            spec: MCPGPluginSpec {
                plugin_id: "dev.mcpg.cluster.redis".into(),
                version: "1.0.0".into(),
                plugin_class: "cluster".into(),
                ..Default::default()
            },
            status: Some(mcpg_operator_api::v1alpha1::MCPGPluginStatus {
                conditions: conds,
                revoked_by_sha: revoked,
                ..Default::default()
            }),
        };
        let ready = Condition::new(ctype::READY, "True", reasons::RECONCILED, "ok", Some(1));
        let not_ready = Condition::new(ctype::READY, "False", "Pulling", "x", Some(1));
        assert!(plugin_is_ready(&mk(vec![ready.clone()], None)));
        assert!(!plugin_is_ready(&mk(vec![not_ready], None)));
        // Ready but revoked → not bindable.
        assert!(!plugin_is_ready(&mk(vec![ready], Some(true))));
        // No status → not ready.
        assert!(!plugin_is_ready(&MCPGPlugin {
            metadata: ObjectMeta::default(),
            spec: MCPGPluginSpec::default(),
            status: None,
        }));
    }

    #[test]
    fn gateway_with_no_clusterref_maps_to_nothing() {
        let gw = MCPGGateway {
            metadata: ObjectMeta {
                name: Some("g".into()),
                namespace: Some("ns".into()),
                ..Default::default()
            },
            spec: Default::default(),
            status: None,
        };
        assert!(map_gateway_to_clusters(gw).is_empty());
    }
}
