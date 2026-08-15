//! `MCPGTenant` controller — materialises a declarative tenant
//! boundary.
//!
//! Like the cluster / route / plugin-mirror controllers it synthesises
//! no gateway workloads. For each namespace a tenant *owns* it drives
//! three pieces of operator-side isolation:
//!
//! 1. **Per-namespace Secret-write RBAC** — the same
//!    [`crate::rbac::ensure_tenant_secret_binding`] the plugin-set path
//!    fires implicitly, but now driven *declaratively* from
//!    `spec.namespaces`, with finalizer-driven teardown of the
//!    tenant-owned objects.
//! 2. **Namespace label** `mcpg.dev/tenant=<name>` so admission can
//!    resolve namespace → tenant.
//! 3. **A generated `ResourceQuota`** scoped to the MCPG count quotas —
//!    the *race-safe* count enforcement. The admission
//!    webhook's count-check is only a nicer error; this `ResourceQuota`
//!    is the apiserver-side lock.
//!
//! Counts in status (`observed.*`) are observability only and refresh on
//! the periodic resync — they are never the quota enforcement point.
//!
//! Cross-resource watches (gateway/pluginset/route → owning tenant) are
//! a future optimisation; a `map` closure has no client to resolve
//! namespace → tenant, so v1 refreshes counts on the jittered resync.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use futures::StreamExt;
use k8s_openapi::api::core::v1::{Namespace, ResourceQuota, ResourceQuotaSpec};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use kube::api::{Api, Patch, PatchParams};
use kube::core::ObjectMeta;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::events::{Event as K8sEvent, EventType};
use kube::runtime::watcher;
use kube::{Resource, ResourceExt};
use mcpg_operator_api::conditions::{Condition, reasons, set_condition, types as ctype};
use mcpg_operator_api::v1alpha1::{
    MCPGGateway, MCPGPluginSet, MCPGRoute, MCPGTenant, MCPGTenantStatus, TenantObservedCounts,
    TenantQuotas,
};
use rand::Rng;
use tracing::{error, info, instrument, warn};

use crate::FIELD_MANAGER_PREFIX;
use crate::controllers::gateway::ControllerContext;
use crate::reconcile::{OPERATOR_FINALIZER, ensure_finalizer, patch_status, remove_finalizer};
use crate::telemetry::ReconcileOutcome;

const FIELD_MANAGER_SUFFIX: &str = "tenant-controller";
const CONTROLLER_NAME: &str = "tenant";

/// Label key the operator stamps on owned namespaces. Admission resolves
/// namespace → tenant via this label (falling back to a tenant list when
/// the label hasn't propagated yet).
pub const TENANT_LABEL: &str = "mcpg.dev/tenant";

/// Name of the `ResourceQuota` the controller generates per owned
/// namespace. One per namespace, named after the tenant so multiple
/// tenants never collide (a namespace is exclusively owned anyway).
fn quota_name(tenant: &str) -> String {
    format!("mcpg-tenant-{tenant}")
}

mod tenant_reason {
    /// Every declared namespace exists + is bound.
    pub const ALL_BOUND: &str = "AllNamespacesBound";
    /// At least one declared namespace is missing.
    pub const NAMESPACE_MISSING: &str = "NamespaceMissing";
    /// An owned namespace already exceeds a declared quota.
    pub const OVER_QUOTA: &str = "PreExistingOverage";
    /// Observed counts are within all declared quotas.
    pub const WITHIN_QUOTA: &str = "WithinLimits";
}

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("status: {0}")]
    Status(#[from] crate::reconcile::StatusError),
    #[error("finalizer: {0}")]
    Finalizer(#[from] crate::reconcile::FinalizerError),
    #[error("kube: {0}")]
    Kube(#[from] kube::Error),
    #[error("missing name on MCPGTenant")]
    MissingName,
}

/// Run the tenant controller until cancelled.
pub async fn run(ctx: Arc<ControllerContext>) -> anyhow::Result<()> {
    let api: Api<MCPGTenant> = Api::all(ctx.client.clone());

    info!("starting tenant controller");

    Controller::new(api, watcher::Config::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => info!(name = %obj.name, "tenant reconciled"),
                Err(err) => error!(error = ?err, "tenant reconcile failed"),
            }
        })
        .await;

    Ok(())
}

#[instrument(
    skip_all,
    fields(name = %obj.name_any(), generation = obj.metadata.generation.unwrap_or(0))
)]
async fn reconcile(
    obj: Arc<MCPGTenant>,
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
    obj: Arc<MCPGTenant>,
    ctx: Arc<ControllerContext>,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    let name = obj
        .metadata
        .name
        .clone()
        .ok_or(ReconcileError::MissingName)?;
    let observed_generation = obj.metadata.generation.unwrap_or(0);
    let tenant_api: Api<MCPGTenant> = Api::all(ctx.client.clone());
    let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");

    // Deletion: tear down the tenant-owned objects (ResourceQuota +
    // namespace label) across owned namespaces, then release the
    // finalizer. The shared Secret-write RoleBinding is intentionally
    // left in place — it may still be needed by MCPGPluginSets in the
    // namespace (it is constant-named, not tenant-owned). See rbac.rs.
    if obj.metadata.deletion_timestamp.is_some() {
        info!(name = %name, "tenant deletion in progress; cleaning owned namespaces");
        for ns in &obj.spec.namespaces {
            teardown_namespace(&ctx.client, ns, &name).await;
        }
        remove_finalizer(&tenant_api, &name, OPERATOR_FINALIZER).await?;
        return Ok((Action::await_change(), ReconcileOutcome::Success));
    }
    ensure_finalizer(&tenant_api, &name, obj.as_ref(), OPERATOR_FINALIZER).await?;

    let operator_ns = operator_namespace();

    // Bind each owned namespace that exists. Missing namespaces are
    // skipped (not fatal) and surface via NamespacesBound=False.
    let mut bound: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for ns in &obj.spec.namespaces {
        let ns_api: Api<Namespace> = Api::all(ctx.client.clone());
        if ns_api.get_opt(ns).await?.is_none() {
            missing.push(ns.clone());
            continue;
        }

        // 1. Per-namespace Secret-write RBAC (idempotent SSA).
        if let Err(e) = crate::rbac::ensure_tenant_secret_binding(
            &ctx.client,
            ns,
            &operator_ns,
            &ctx.config.operator_service_account,
            &fm,
        )
        .await
        {
            warn!(namespace = %ns, error = ?e, "tenant: RoleBinding ensure failed");
        }

        // 2. Namespace label for admission resolution.
        if let Err(e) = ensure_namespace_label(&ctx.client, ns, &name, &fm).await {
            warn!(namespace = %ns, error = ?e, "tenant: namespace label patch failed");
        }

        // 3. ResourceQuota — race-safe count enforcement.
        if let Err(e) =
            ensure_resource_quota(&ctx.client, ns, &name, obj.spec.quotas.as_ref(), &fm).await
        {
            warn!(namespace = %ns, error = ?e, "tenant: ResourceQuota apply failed");
        }

        bound.push(ns.clone());
    }

    // Observed counts across bound namespaces (observability only).
    let observed = count_resources(&ctx.client, &bound).await?;
    let over_quota = quota_exceeded(obj.spec.quotas.as_ref(), &observed);

    // Conditions.
    let mut conditions = obj
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();

    let all_bound = missing.is_empty();
    set_condition(
        &mut conditions,
        Condition::new(
            "NamespacesBound",
            if all_bound { "True" } else { "False" },
            if all_bound {
                tenant_reason::ALL_BOUND
            } else {
                tenant_reason::NAMESPACE_MISSING
            },
            if all_bound {
                format!("{} namespace(s) bound", bound.len())
            } else {
                format!("missing namespace(s): {}", missing.join(", "))
            },
            Some(observed_generation),
        ),
    );

    set_condition(
        &mut conditions,
        Condition::new(
            "QuotaWithinLimits",
            if over_quota { "False" } else { "True" },
            if over_quota {
                tenant_reason::OVER_QUOTA
            } else {
                tenant_reason::WITHIN_QUOTA
            },
            if over_quota {
                "an owned namespace already exceeds a declared quota; the generated \
                 ResourceQuota admits existing objects but blocks new ones"
                    .to_owned()
            } else {
                String::new()
            },
            Some(observed_generation),
        ),
    );

    // Ready = all declared namespaces bound (RBAC + quota materialised).
    set_condition(
        &mut conditions,
        Condition::new(
            ctype::READY,
            if all_bound { "True" } else { "False" },
            if all_bound {
                reasons::RECONCILED
            } else {
                reasons::DEPENDENCY_MISSING
            },
            if all_bound {
                String::new()
            } else {
                format!("{} declared namespace(s) not yet present", missing.len())
            },
            Some(observed_generation),
        ),
    );

    let status = MCPGTenantStatus {
        conditions,
        observed_generation: Some(observed_generation),
        bound_namespaces: bound,
        observed: Some(observed),
        last_reconcile_time: Some(Utc::now()),
    };

    if let Err(e) = patch_status(&tenant_api, &name, &status, &fm).await {
        warn!(error = ?e, "tenant: status patch failed");
    }

    if !missing.is_empty() {
        let evt = K8sEvent {
            type_: EventType::Warning,
            reason: tenant_reason::NAMESPACE_MISSING.to_owned(),
            note: Some(format!(
                "declared namespace(s) not found: {}",
                missing.join(", ")
            )),
            action: "Bind".to_owned(),
            secondary: None,
        };
        let _ = ctx
            .recorders
            .tenant
            .publish(&evt, &obj.object_ref(&()))
            .await;
    }

    let requeue = Action::requeue(jittered_resync(ctx.config.resync_interval_secs));
    let outcome = if all_bound {
        ReconcileOutcome::Success
    } else {
        ReconcileOutcome::DependencyPending
    };
    Ok((requeue, outcome))
}

/// SSA-patch the `mcpg.dev/tenant` label onto a namespace.
async fn ensure_namespace_label(
    client: &kube::Client,
    namespace: &str,
    tenant: &str,
    field_manager: &str,
) -> Result<(), kube::Error> {
    let api: Api<Namespace> = Api::all(client.clone());
    let mut labels = BTreeMap::new();
    labels.insert(TENANT_LABEL.to_owned(), tenant.to_owned());
    let patch = Namespace {
        metadata: ObjectMeta {
            name: Some(namespace.to_owned()),
            labels: Some(labels),
            ..Default::default()
        },
        ..Default::default()
    };
    let pp = PatchParams::apply(field_manager).force();
    api.patch(namespace, &pp, &Patch::Apply(&patch)).await?;
    Ok(())
}

/// SSA-apply the per-namespace count `ResourceQuota`. When the tenant
/// declares no count quotas the quota object is removed (so loosening a
/// quota to "unlimited" doesn't leave a stale cap behind).
async fn ensure_resource_quota(
    client: &kube::Client,
    namespace: &str,
    tenant: &str,
    quotas: Option<&TenantQuotas>,
    field_manager: &str,
) -> Result<(), kube::Error> {
    let api: Api<ResourceQuota> = Api::namespaced(client.clone(), namespace);
    let name = quota_name(tenant);

    let hard = quotas.map(build_hard_limits).unwrap_or_default();
    if hard.is_empty() {
        // No count quotas declared — ensure no stale ResourceQuota lingers.
        let _ = api.delete(&name, &Default::default()).await;
        return Ok(());
    }

    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_owned(),
        "mcpg-operator".to_owned(),
    );
    labels.insert("mcpg.dev/tenant".to_owned(), tenant.to_owned());

    let rq = ResourceQuota {
        metadata: ObjectMeta {
            name: Some(name.clone()),
            namespace: Some(namespace.to_owned()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(ResourceQuotaSpec {
            hard: Some(hard),
            ..Default::default()
        }),
        status: None,
    };
    let pp = PatchParams::apply(field_manager).force();
    api.patch(&name, &pp, &Patch::Apply(&rq)).await?;
    Ok(())
}

/// Translate declared quotas into a `ResourceQuota.spec.hard` map keyed
/// by the K8s `count/<resource>.<group>` convention.
fn build_hard_limits(q: &TenantQuotas) -> BTreeMap<String, Quantity> {
    let mut hard = BTreeMap::new();
    if let Some(n) = q.max_gateways {
        hard.insert(
            "count/mcpggateways.mcpg.dev".to_owned(),
            Quantity(n.to_string()),
        );
    }
    if let Some(n) = q.max_plugin_sets {
        hard.insert(
            "count/mcpgpluginsets.mcpg.dev".to_owned(),
            Quantity(n.to_string()),
        );
    }
    if let Some(n) = q.max_routes {
        hard.insert(
            "count/mcpgroutes.mcpg.dev".to_owned(),
            Quantity(n.to_string()),
        );
    }
    // max_replicas_per_gateway is a FIELD constraint (not a count) and
    // has no ResourceQuota representation — enforced by the webhook.
    hard
}

/// Remove the tenant-owned objects from a namespace (deletion path).
async fn teardown_namespace(client: &kube::Client, namespace: &str, tenant: &str) {
    let rq_api: Api<ResourceQuota> = Api::namespaced(client.clone(), namespace);
    let _ = rq_api
        .delete(&quota_name(tenant), &Default::default())
        .await;

    // Drop the tenant label. SSA with our field manager + the label
    // absent prunes it from our managed-fields entry.
    let ns_api: Api<Namespace> = Api::all(client.clone());
    let patch = Namespace {
        metadata: ObjectMeta {
            name: Some(namespace.to_owned()),
            labels: Some(BTreeMap::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");
    let pp = PatchParams::apply(&fm).force();
    let _ = ns_api.patch(namespace, &pp, &Patch::Apply(&patch)).await;
}

/// Count MCPG resources across the given namespaces (observability).
async fn count_resources(
    client: &kube::Client,
    namespaces: &[String],
) -> Result<TenantObservedCounts, ReconcileError> {
    let mut counts = TenantObservedCounts::default();
    for ns in namespaces {
        let gw: Api<MCPGGateway> = Api::namespaced(client.clone(), ns);
        counts.gateways += gw.list(&Default::default()).await?.items.len() as i64;
        let ps: Api<MCPGPluginSet> = Api::namespaced(client.clone(), ns);
        counts.plugin_sets += ps.list(&Default::default()).await?.items.len() as i64;
        let rt: Api<MCPGRoute> = Api::namespaced(client.clone(), ns);
        counts.routes += rt.list(&Default::default()).await?.items.len() as i64;
    }
    Ok(counts)
}

/// True when observed counts exceed any declared quota. Pure — the
/// per-namespace ResourceQuota is the real gate; this only drives the
/// soft `QuotaWithinLimits` signal. Compares the aggregate observed
/// count against the (per-namespace) cap, so it's a conservative
/// "something might be over" hint.
fn quota_exceeded(quotas: Option<&TenantQuotas>, observed: &TenantObservedCounts) -> bool {
    let Some(q) = quotas else { return false };
    over(q.max_gateways, observed.gateways)
        || over(q.max_plugin_sets, observed.plugin_sets)
        || over(q.max_routes, observed.routes)
}

fn over(limit: Option<i64>, observed: i64) -> bool {
    limit.is_some_and(|l| observed > l)
}

fn operator_namespace() -> String {
    // Mirrors controllers::plugin::operator_namespace — hardcoded to
    // mcpg-system until OperatorConfig surfaces it.
    "mcpg-system".to_owned()
}

/// Periodic resync interval, jittered ±20%.
fn jittered_resync(base_secs: u64) -> Duration {
    let base = base_secs as f64;
    let jitter_factor = 0.8 + rand::thread_rng().gen_range(0.0..0.4);
    Duration::from_secs_f64(base * jitter_factor)
}

fn error_policy(obj: Arc<MCPGTenant>, err: &ReconcileError, ctx: Arc<ControllerContext>) -> Action {
    match err {
        ReconcileError::MissingName => Action::await_change(),
        _ => {
            let key = crate::backoff::resource_key(CONTROLLER_NAME, "", &obj.name_any());
            let count = ctx.backoff.record_error(&key);
            let delay = ctx.backoff.duration_for(&key);
            warn!(
                key = %key,
                consecutive_errors = count,
                requeue_secs = delay.as_secs(),
                error = ?err,
                "tenant: reconcile error; backing off"
            );
            Action::requeue(delay)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_name_is_tenant_scoped() {
        assert_eq!(quota_name("team-payments"), "mcpg-tenant-team-payments");
    }

    #[test]
    fn build_hard_limits_uses_count_keys() {
        let q = TenantQuotas {
            max_gateways: Some(5),
            max_plugin_sets: Some(10),
            max_routes: Some(50),
            max_replicas_per_gateway: Some(20),
        };
        let hard = build_hard_limits(&q);
        assert_eq!(hard["count/mcpggateways.mcpg.dev"].0, "5");
        assert_eq!(hard["count/mcpgpluginsets.mcpg.dev"].0, "10");
        assert_eq!(hard["count/mcpgroutes.mcpg.dev"].0, "50");
        // replica cap is a field constraint, NOT a ResourceQuota key
        assert!(!hard.keys().any(|k| k.contains("replica")));
    }

    #[test]
    fn build_hard_limits_omits_unset() {
        let q = TenantQuotas {
            max_gateways: Some(3),
            ..Default::default()
        };
        let hard = build_hard_limits(&q);
        assert_eq!(hard.len(), 1);
        assert!(hard.contains_key("count/mcpggateways.mcpg.dev"));
    }

    #[test]
    fn quota_exceeded_detects_overage() {
        let q = TenantQuotas {
            max_gateways: Some(2),
            ..Default::default()
        };
        let under = TenantObservedCounts {
            gateways: 2,
            ..Default::default()
        };
        let over = TenantObservedCounts {
            gateways: 3,
            ..Default::default()
        };
        assert!(!quota_exceeded(Some(&q), &under));
        assert!(quota_exceeded(Some(&q), &over));
    }

    #[test]
    fn quota_exceeded_false_when_no_quota() {
        let observed = TenantObservedCounts {
            gateways: 100,
            ..Default::default()
        };
        assert!(!quota_exceeded(None, &observed));
    }
}
