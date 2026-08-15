//! `MCPGPluginMirror` controller — validates an in-cluster OCI mirror
//! declaration and reports its health + blast radius.
//!
//! Like the cluster / route controllers, this synthesises no child
//! objects. The mirror is consumed in the plugin controller's pull
//! path: a `MCPGPlugin` with `spec.oci.mirrorRef` set has its image ref
//! rewritten through the named mirror before the pull (see
//! `controllers::plugin` + `oci_pull::mirror`).
//!
//! This controller:
//!
//! 1. Resolves the mirror's backing Kubernetes `Service` and reports
//!    `reachable` — the Service existing in-cluster is the necessary
//!    precondition for a pull. We deliberately do NOT make an outbound
//!    HTTP probe: the operator carries no general HTTP client, an
//!    air-gapped operator's egress is locked down, and the real
//!    end-to-end test is the plugin pull itself (surfaced on the
//!    `MCPGPlugin` status). Service-existence is the cheap, faithful,
//!    dependency-free signal.
//! 2. Counts `MCPGPlugin`s referencing this mirror (`proxiedReferences`).
//! 3. Surfaces `endpointHost` + a `Ready` condition.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::api::Api;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::events::{Event as K8sEvent, EventType};
use kube::runtime::watcher;
use kube::{Resource, ResourceExt};
use mcpg_operator_api::conditions::{Condition, reasons, types as ctype};
use mcpg_operator_api::v1alpha1::{MCPGPlugin, MCPGPluginMirror, MCPGPluginMirrorStatus};
use rand::Rng;
use tracing::{error, info, instrument};

use crate::FIELD_MANAGER_PREFIX;
use crate::controllers::gateway::ControllerContext;
use crate::reconcile::{OPERATOR_FINALIZER, ensure_finalizer, patch_status, remove_finalizer};
use crate::telemetry::ReconcileOutcome;

const FIELD_MANAGER_SUFFIX: &str = "plugin-mirror-controller";
const CONTROLLER_NAME: &str = "plugin-mirror";

mod mirror_reason {
    /// Mirror Service resolves in-cluster.
    pub const REACHABLE: &str = "MirrorServiceFound";
    /// The backing Service doesn't exist — plugin pulls will fail.
    pub const SERVICE_NOT_FOUND: &str = "MirrorServiceNotFound";
}

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("status: {0}")]
    Status(#[from] crate::reconcile::StatusError),
    #[error("finalizer: {0}")]
    Finalizer(#[from] crate::reconcile::FinalizerError),
    #[error("kube: {0}")]
    Kube(#[from] kube::Error),
    #[error("missing name on MCPGPluginMirror")]
    MissingName,
}

/// Run the plugin-mirror controller until cancelled. Re-reconciles a
/// mirror when a referencing `MCPGPlugin` changes (proxied count) or
/// the backing `Service` changes (reachability).
pub async fn run(ctx: Arc<ControllerContext>) -> anyhow::Result<()> {
    let api: Api<MCPGPluginMirror> = Api::all(ctx.client.clone());

    info!("starting plugin-mirror controller");

    Controller::new(api, watcher::Config::default())
        .watches(
            Api::<MCPGPlugin>::all(ctx.client.clone()),
            watcher::Config::default(),
            map_plugin_to_mirrors,
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => info!(name = %obj.name, "plugin-mirror reconciled"),
                Err(err) => error!(error = ?err, "plugin-mirror reconcile failed"),
            }
        })
        .await;

    Ok(())
}

/// A plugin change re-reconciles the mirror it references (so
/// `proxiedReferences` stays current).
fn map_plugin_to_mirrors(
    plugin: MCPGPlugin,
) -> Vec<kube::runtime::reflector::ObjectRef<MCPGPluginMirror>> {
    plugin
        .spec
        .oci
        .mirror_ref
        .as_ref()
        .map(|r| vec![kube::runtime::reflector::ObjectRef::new(&r.name)])
        .unwrap_or_default()
}

#[instrument(
    skip_all,
    fields(name = %obj.name_any(), generation = obj.metadata.generation.unwrap_or(0))
)]
async fn reconcile(
    obj: Arc<MCPGPluginMirror>,
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
    obj: Arc<MCPGPluginMirror>,
    ctx: Arc<ControllerContext>,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    let name = obj
        .metadata
        .name
        .clone()
        .ok_or(ReconcileError::MissingName)?;
    let observed_generation = obj.metadata.generation.unwrap_or(0);
    let mirror_api: Api<MCPGPluginMirror> = Api::all(ctx.client.clone());

    if obj.metadata.deletion_timestamp.is_some() {
        info!(name = %name, "plugin-mirror deletion in progress; releasing finalizer");
        remove_finalizer(&mirror_api, &name, OPERATOR_FINALIZER).await?;
        return Ok((Action::await_change(), ReconcileOutcome::Success));
    }
    ensure_finalizer(&mirror_api, &name, obj.as_ref(), OPERATOR_FINALIZER).await?;

    let svc = &obj.spec.endpoint.service;
    let endpoint_host = svc.host();

    // Reachability = the backing Service exists in its namespace.
    let svc_api: Api<Service> = Api::namespaced(ctx.client.clone(), &svc.namespace);
    let reachable = svc_api.get_opt(&svc.name).await?.is_some();
    let (reason, message) = if reachable {
        (
            mirror_reason::REACHABLE,
            format!(
                "mirror Service {}/{} resolves; pulls route to {endpoint_host}",
                svc.namespace, svc.name
            ),
        )
    } else {
        (
            mirror_reason::SERVICE_NOT_FOUND,
            format!(
                "mirror Service {}/{} not found; plugin pulls through this mirror will fail",
                svc.namespace, svc.name
            ),
        )
    };

    let proxied = count_proxied_plugins(&ctx.client, &name).await?;

    let mut conditions = obj
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();
    mcpg_operator_api::conditions::set_condition(
        &mut conditions,
        Condition::new(
            ctype::READY,
            if reachable { "True" } else { "False" },
            if reachable {
                reasons::RECONCILED
            } else {
                reason
            },
            message.clone(),
            Some(observed_generation),
        ),
    );

    let status = MCPGPluginMirrorStatus {
        conditions,
        observed_generation: Some(observed_generation),
        reachable: Some(reachable),
        proxied_references: Some(proxied),
        endpoint_host: Some(endpoint_host),
        last_reconcile_time: Some(Utc::now()),
    };

    let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");
    if let Err(e) = patch_status(&mirror_api, &name, &status, &fm).await {
        tracing::warn!(error = ?e, "plugin-mirror: status patch failed");
    }

    if !reachable {
        let evt = K8sEvent {
            type_: EventType::Warning,
            reason: reason.to_owned(),
            note: Some(message.clone()),
            action: "Resolve".to_owned(),
            secondary: None,
        };
        let _ = ctx
            .recorders
            .plugin_mirror
            .publish(&evt, &obj.object_ref(&()))
            .await;
    }

    let requeue = Action::requeue(jittered_resync(ctx.config.resync_interval_secs));
    let outcome = if reachable {
        ReconcileOutcome::Success
    } else {
        ReconcileOutcome::DependencyPending
    };
    Ok((requeue, outcome))
}

/// Count `MCPGPlugin`s (cluster-wide) whose `oci.mirrorRef.name`
/// matches this mirror.
async fn count_proxied_plugins(
    client: &kube::Client,
    mirror_name: &str,
) -> Result<i64, ReconcileError> {
    let api: Api<MCPGPlugin> = Api::all(client.clone());
    let plugins = api.list(&Default::default()).await?;
    let count = plugins
        .items
        .iter()
        .filter(|p| {
            p.spec
                .oci
                .mirror_ref
                .as_ref()
                .is_some_and(|r| r.name == mirror_name)
        })
        .count();
    Ok(count as i64)
}

/// Periodic resync interval, jittered ±20%. Mirrors the gateway
/// controller's helper.
fn jittered_resync(base_secs: u64) -> Duration {
    let base = base_secs as f64;
    let jitter_factor = 0.8 + rand::thread_rng().gen_range(0.0..0.4);
    Duration::from_secs_f64(base * jitter_factor)
}

fn error_policy(
    obj: Arc<MCPGPluginMirror>,
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
                "plugin-mirror: reconcile error; backing off"
            );
            Action::requeue(delay)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::gateway::LocalObjectReference;
    use mcpg_operator_api::v1alpha1::{MCPGPlugin, MCPGPluginSpec, OciImageRef};

    fn plugin_with_mirror(mirror: Option<&str>) -> MCPGPlugin {
        MCPGPlugin {
            metadata: ObjectMeta {
                name: Some("p".into()),
                ..Default::default()
            },
            spec: MCPGPluginSpec {
                oci: OciImageRef {
                    image: "ghcr.io/x/y:1".into(),
                    pull_secret_ref: None,
                    mirror_ref: mirror.map(|n| LocalObjectReference { name: n.into() }),
                },
                ..Default::default()
            },
            status: None,
        }
    }

    #[test]
    fn map_plugin_with_mirror_ref_targets_the_mirror() {
        let refs = map_plugin_to_mirrors(plugin_with_mirror(Some("airgap-mirror")));
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "airgap-mirror");
    }

    #[test]
    fn map_plugin_without_mirror_ref_is_empty() {
        assert!(map_plugin_to_mirrors(plugin_with_mirror(None)).is_empty());
    }
}
