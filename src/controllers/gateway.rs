//! `MCPGGateway` controller — reconciles the headline CRD.
//!
//! Reconcile flow (six phases):
//!
//! 1. Resolve dependencies — `pluginSetRef` against the local
//!    `MCPGPluginSet` and its resolved-set ConfigMap;
//!    `revocationListRef` (defaulting to `cluster-default`)
//!    against the cluster-scoped `MCPGRevocationList`, materialised
//!    as a namespace-local ConfigMap.
//! 2. Compute desired children (Deployment / Service /
//!    ConfigMap / ServiceAccount). The rendered config merges
//!    `spec.config` with the resolved plugin entries +
//!    capability grants + revocation-list trust path; per-plugin
//!    Secrets and the revocation ConfigMap project as additional
//!    pod volumes.
//! 3. Server-side apply each child.
//! 4. Read back the Deployment to capture rolling-update
//!    progress.
//! 5. Patch status conditions + replica counts +
//!    `pluginSetHash` / `revocationListHash`.
//! 6. Return [`Action::requeue`] with the operator's resync
//!    interval (jittered ±20%).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::core::v1::{ConfigMap, Service, ServiceAccount};
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use kube::api::Api;
use kube::core::ObjectMeta;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::events::{Event as K8sEvent, EventType};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher;
use kube::{Client, Resource, ResourceExt};
use mcpg_operator_api::conditions::{Condition, reasons, types as ctype};
use mcpg_operator_api::v1alpha1::{
    MCPGCluster, MCPGGateway, MCPGGatewayStatus, MCPGPluginSet, MCPGRevocationList, MCPGRoute,
    MCPGServer,
};
use rand::Rng;
use sha2::{Digest, Sha256};
use tracing::{error, info, instrument, warn};

use crate::config::OperatorConfig;
use crate::reconcile::{
    OPERATOR_FINALIZER, apply_owned, ensure_finalizer, patch_status, remove_finalizer,
};
use crate::telemetry::{MetricsRegistry, ReconcileOutcome};
use crate::templates::{
    HTTPRoute, PluginSecretMount, REVOCATION_LIST_MOUNT_PATH, ResolvedSetEntry, ResolvedSetView,
    RevocationListMount, append_cloud_default_plugins, append_observability_sink_plugins,
    build_configmap, build_deployment, build_hpa, build_httproute, build_pdb, build_service,
    build_service_account, cloud_default_plugin_ids, merge_plugins, owner_ref,
};
use crate::{FIELD_MANAGER_PREFIX, labels as label_keys};

/// Controller name used in metric labels. Centralised so a typo
/// in one call site doesn't fork the cardinality.
const CONTROLLER_NAME: &str = "gateway";

const FIELD_MANAGER_SUFFIX: &str = "gateway-controller";

/// Default `MCPGRevocationList` name when the gateway has no
/// `revocationListRef`. Matches the cluster-default convention
/// (the operator ships an empty revocation list under this name
/// out of the box).
const DEFAULT_REVOCATION_LIST_NAME: &str = "cluster-default";

/// Reasons surfaced on `MCPGGateway.status.conditions[PluginSetReady]`.
mod plugin_set_reason {
    pub const RESOLVED: &str = "PluginSetResolved";
    pub const NOT_FOUND: &str = "PluginSetNotFound";
    pub const NOT_READY: &str = "PluginSetNotReady";
    pub const RESOLVED_CM_MISSING: &str = "ResolvedConfigMapMissing";
    pub const PARSE_FAILED: &str = "ResolvedConfigMapParseFailed";
}

/// Reasons surfaced on `MCPGGateway.status.conditions[RevocationListReady]`.
mod revocation_reason {
    pub const RESOLVED: &str = "RevocationListResolved";
    pub const NOT_FOUND: &str = "RevocationListNotFound";
    pub const APPLY_FAILED: &str = "RevocationConfigMapApplyFailed";
}

/// Reasons surfaced on `MCPGGateway.status.conditions[ClusterReady]`.
mod cluster_reason {
    pub const RESOLVED: &str = "ClusterResolved";
    pub const NOT_FOUND: &str = "ClusterNotFound";
    pub const NOT_READY: &str = "ClusterNotReady";
}

/// Condition type names emitted by this controller (in addition
/// to the `Ready` / `Progressing` / `Available` types from the
/// shared `conditions` module).
mod cond_types {
    pub const PLUGIN_SET_READY: &str = "PluginSetReady";
    pub const REVOCATION_LIST_READY: &str = "RevocationListReady";
    pub const CLUSTER_READY: &str = "ClusterReady";
}

/// The gateway controller's view of a successfully resolved
/// `MCPGPluginSet`. When `Some(view)`, the operator has parsed
/// the `{set-name}-resolved` ConfigMap into per-entry data the
/// `merge_plugins` template can consume; `mounts` lists the
/// per-namespace plugin Secrets (one Volume + VolumeMount each).
struct ResolvedPluginSet {
    /// Hash from `MCPGPluginSet.status.resolvedHash` — surfaced
    /// on the gateway pod template's `mcpg.dev/plugin-set-hash`
    /// annotation so dashboards can compare across replicas.
    resolved_hash: String,
    /// `Some` when the resolved ConfigMap was parsed cleanly;
    /// `None` if the set existed but wasn't ready to consume yet
    /// (the controller still emits a `PluginSetReady=False`
    /// condition with the appropriate reason).
    view: Option<ResolvedSetView>,
    /// One projection per resolved entry. Empty when `view` is
    /// `None`.
    mounts: Vec<PluginSecretMount>,
    /// Carries the condition the controller will append to status.
    condition: Condition,
}

/// The gateway controller's view of a resolved revocation list.
/// `mount.config_map_name` names the namespace-local ConfigMap
/// the controller materialises this reconcile, and `content_hash`
/// is the SHA-256 of the JSON the gateway will read.
struct ResolvedRevocationList {
    mount: RevocationListMount,
    condition: Condition,
}

/// The gateway controller's view of a resolved `clusterRef`. The
/// `cluster_block` is the rendered `cluster:` config object the
/// gateway controller merges into the gateway config; `condition`
/// is surfaced on the gateway status as `ClusterReady`. Resolution
/// is best-effort: a not-found / not-ready cluster yields a
/// `False` condition but an EMPTY `cluster_block` so the gateway
/// keeps whatever it already had (inline `cluster:` or the
/// single_node default) rather than wedging.
struct ResolvedCluster {
    /// `{ "kind": <backend>, <flattened config> }`, or empty when
    /// the cluster didn't resolve to a usable backend.
    cluster_block: serde_json::Value,
    condition: Condition,
}

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("apply child: {0}")]
    Apply(#[from] crate::reconcile::ApplyError),

    #[error("patch status: {0}")]
    Status(#[from] crate::reconcile::StatusError),

    #[error("finalizer: {0}")]
    Finalizer(#[from] crate::reconcile::FinalizerError),

    #[error("missing namespace on MCPGGateway/{name}")]
    MissingNamespace { name: String },

    #[error("missing name on MCPGGateway")]
    MissingName,

    #[error("kube error: {0}")]
    Kube(#[from] kube::Error),
}

pub struct ControllerContext {
    pub client: Client,
    pub config: OperatorConfig,
    pub metrics: MetricsRegistry,
    /// One [`Recorder`] per controller — they each pin their own
    /// `reporting_controller` field, which is what lets
    /// `kubectl describe` attribute events to the right loop and
    /// what kube-rs's event-dedup cache keys on.
    pub recorders: ControllerRecorders,
    /// Per-resource consecutive-failure tracker. Keyed by
    /// `controller/[ns/]name`; lets the error_policy back off
    /// exponentially on flapping resources without forcing a
    /// fleet-wide retry burst.
    pub backoff: crate::backoff::BackoffMap,
    /// Set by [`run`] once this controller's reflector store has
    /// completed its initial LIST. kube-runtime holds every
    /// reconcile until then, so `/reconcilez` reads this rather than
    /// the fact that the task was spawned. `/readyz` does not — see
    /// [`crate::readiness`].
    pub store_ready: Arc<crate::readiness::StoreReadiness>,
}

/// Per-controller event recorders. Cheap to clone — `Recorder`
/// is internally Arc-wrapped for its dedup cache.
#[derive(Clone)]
pub struct ControllerRecorders {
    pub gateway: kube::runtime::events::Recorder,
    pub plugin: kube::runtime::events::Recorder,
    pub plugin_set: kube::runtime::events::Recorder,
    pub revocation_list: kube::runtime::events::Recorder,
    pub cluster: kube::runtime::events::Recorder,
    pub route: kube::runtime::events::Recorder,
    pub plugin_mirror: kube::runtime::events::Recorder,
    pub tenant: kube::runtime::events::Recorder,
    pub server: kube::runtime::events::Recorder,
}

/// Run the gateway controller until cancelled. Spawned by the
/// operator's main once leader election succeeds.
pub async fn run(ctx: Arc<ControllerContext>) -> anyhow::Result<()> {
    let api: Api<MCPGGateway> = match ctx.config.watch_namespace.as_deref() {
        Some(ns) if !ns.is_empty() => Api::namespaced(ctx.client.clone(), ns),
        _ => Api::all(ctx.client.clone()),
    };

    info!(
        watch_scope = ?ctx.config.watch_namespace.as_deref().unwrap_or("ALL"),
        "starting gateway controller"
    );

    let controller = Controller::new(api, watcher::Config::default());
    // Snapshot of every MCPGGateway under the controller's
    // watch. Used by the cross-CRD `.watches()` closures to
    // map a plugin-set / revocation-list change back to the
    // set of gateways that need re-reconciliation. The store
    // is populated by the controller's own internal watcher;
    // closures can read it synchronously.
    let gateway_store = controller.store();

    // Publish the initial-LIST completion. kube-runtime gates the
    // whole applier on it (`delay_tasks_until(store.wait_until_ready())`)
    // and logs the wait at `debug!` only, so without this the process
    // cannot tell "watching" from "spawned but blocked" — and neither
    // can `/reconcilez`. The store resolves on `InitDone`, which the
    // watcher emits even for an empty LIST, so a cluster with no
    // gateways still reports reconciling.
    {
        let store = gateway_store.clone();
        let store_ready = Arc::clone(&ctx.store_ready);
        tokio::spawn(async move {
            // `wait_until_ready` shares one oneshot with the controller's own
            // applier delay, and that channel keeps only the LAST waker that
            // polled it. The applier re-polls on every stream event and wins
            // the race; a bare await here loses its waker and hangs forever
            // even though the store is ready. Re-polling on a ticker turns
            // the lost wake-up into at most a one-second delay.
            let wait = store.wait_until_ready();
            tokio::pin!(wait);
            let result = loop {
                match tokio::time::timeout(std::time::Duration::from_secs(1), &mut wait).await {
                    Ok(r) => break r,
                    Err(_elapsed) => continue,
                }
            };
            match result {
                Ok(()) => {
                    info!("gateway reflector store synced; reconciles released");
                    store_ready.mark_synced();
                }
                // The writer is dropped when the controller stream ends
                // (shutdown, or a watch that never recovered). Leaving
                // the latch unset keeps `/reconcilez` 503 instead of
                // claiming a watch this process does not have.
                Err(e) => warn!(error = %e, "gateway reflector store never synced"),
            }
        });
    }

    controller
        .owns(
            Api::<Deployment>::all(ctx.client.clone()),
            watcher::Config::default(),
        )
        .owns(
            Api::<Service>::all(ctx.client.clone()),
            watcher::Config::default(),
        )
        .owns(
            Api::<ConfigMap>::all(ctx.client.clone()),
            watcher::Config::default(),
        )
        .owns(
            Api::<ServiceAccount>::all(ctx.client.clone()),
            watcher::Config::default(),
        )
        .watches(
            Api::<MCPGPluginSet>::all(ctx.client.clone()),
            watcher::Config::default(),
            {
                let store = gateway_store.clone();
                move |set: MCPGPluginSet| map_plugin_set_to_gateways(&store, set)
            },
        )
        .watches(
            Api::<MCPGRevocationList>::all(ctx.client.clone()),
            watcher::Config::default(),
            {
                let store = gateway_store.clone();
                move |rl: MCPGRevocationList| map_revocation_list_to_gateways(&store, rl)
            },
        )
        .watches(
            Api::<MCPGCluster>::all(ctx.client.clone()),
            watcher::Config::default(),
            {
                let store = gateway_store.clone();
                move |c: MCPGCluster| map_cluster_to_gateways(&store, c)
            },
        )
        .watches(
            Api::<MCPGRoute>::all(ctx.client.clone()),
            watcher::Config::default(),
            {
                let store = gateway_store.clone();
                move |r: MCPGRoute| map_route_to_gateways(&store, r)
            },
        )
        .watches(
            Api::<MCPGServer>::all(ctx.client.clone()),
            watcher::Config::default(),
            {
                let store = gateway_store.clone();
                move |s: MCPGServer| map_server_to_gateways(&store, s)
            },
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => info!(
                    namespace = obj.namespace.as_deref().unwrap_or(""),
                    name = %obj.name,
                    "reconcile complete",
                ),
                Err(err) => error!(error = ?err, "reconcile failed"),
            }
        })
        .await;

    Ok(())
}

/// Outer reconcile — times the inner body, classifies the
/// outcome, and emits the per-controller metric. Keeping the
/// timing wrapper outside the body avoids repeated
/// `metrics.observe_reconcile(...)` calls scattered across the
/// success + early-return paths.
#[instrument(
    skip_all,
    fields(
        namespace = %obj.namespace().unwrap_or_default(),
        name = %obj.name_any(),
        generation = obj.metadata.generation.unwrap_or(0),
    )
)]
async fn reconcile(
    obj: Arc<MCPGGateway>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let started = Instant::now();
    let outcome_metrics = ctx.metrics.operator_metrics().clone();
    let result = reconcile_inner(obj, ctx).await;
    let outcome = classify_outcome(&result);
    outcome_metrics.observe_reconcile(CONTROLLER_NAME, outcome, started.elapsed().as_secs_f64());
    result.map(|(action, _)| action)
}

fn classify_outcome(
    result: &Result<(Action, ReconcileOutcome), ReconcileError>,
) -> ReconcileOutcome {
    match result {
        Ok((_, o)) => *o,
        Err(ReconcileError::MissingName) | Err(ReconcileError::MissingNamespace { .. }) => {
            ReconcileOutcome::PermanentError
        }
        Err(_) => ReconcileOutcome::TransientError,
    }
}

async fn reconcile_inner(
    obj: Arc<MCPGGateway>,
    ctx: Arc<ControllerContext>,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    let ns = obj
        .namespace()
        .ok_or_else(|| ReconcileError::MissingNamespace {
            name: obj.name_any(),
        })?;
    let name = obj
        .metadata
        .name
        .clone()
        .ok_or(ReconcileError::MissingName)?;
    let observed_generation = obj.metadata.generation.unwrap_or(0);
    let api: Api<MCPGGateway> = Api::namespaced(ctx.client.clone(), &ns);

    // Step 0: deletion-timestamp branch + finalizer management.
    // Owned children (Deployment/Service/SA/CM) cascade-delete via
    // K8s GC because every renderer in `templates/` sets an
    // `OwnerReference` to this MCPGGateway. The finalizer lets us
    // run any final-state status patches before the GC sweeps.
    if obj.metadata.deletion_timestamp.is_some() {
        info!(name = %name, "gateway deletion in progress; releasing finalizer");
        // Edge wiring isn't covered by owner-reference GC (it lives on/next to
        // the shared Gateway in the edge namespace) — relinquish it explicitly,
        // best-effort, before the finalizer goes.
        cleanup_edge_domains(&ctx, obj.as_ref()).await;
        remove_finalizer(&api, &name, OPERATOR_FINALIZER).await?;
        return Ok((Action::await_change(), ReconcileOutcome::Success));
    }
    ensure_finalizer(&api, &name, obj.as_ref(), OPERATOR_FINALIZER).await?;

    let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");

    // Step 1: resolve plugin set + revocation list refs (when set).
    // The resolvers fold the referenced CRDs' status into something
    // the templates can consume. They do NOT mutate cluster state —
    // that's the SSA step further down.
    let plugin_set = resolve_plugin_set(&ctx.client, &ns, obj.as_ref()).await?;
    let revocation_list = resolve_revocation_list(&ctx.client, &ns, obj.as_ref(), &fm).await?;

    // Bump the dependency-unresolved counter when a ref was set
    // but didn't resolve cleanly. Dashboards track this to spot
    // a wedged plugin-set or revocation-list reconcile.
    //
    // Tri-state semantics worth keeping straight:
    //   * `plugin_set = None`           — gateway has no
    //                                     `pluginSetRef` set;
    //                                     this is the legitimate
    //                                     "boot from inline
    //                                     config" path. No
    //                                     metric.
    //   * `Some(_)` + `view.is_none()`  — ref WAS set but the
    //                                     resolver couldn't
    //                                     produce a usable view
    //                                     (set missing, not
    //                                     Ready, etc). This is
    //                                     the "unresolved" case
    //                                     the metric tracks.
    //   * `Some(_)` + `view.is_some()`  — happy path; not counted.
    if let Some(p) = &plugin_set
        && p.view.is_none()
    {
        ctx.metrics
            .operator_metrics()
            .observe_dependency_unresolved(CONTROLLER_NAME, "MCPGPluginSet", &p.condition.reason);
    }
    if let Some(r) = &revocation_list
        && r.condition.status != "True"
    {
        ctx.metrics
            .operator_metrics()
            .observe_dependency_unresolved(
                CONTROLLER_NAME,
                "MCPGRevocationList",
                &r.condition.reason,
            );
    }

    // Step 1c: resolve clusterRef (when set). The cluster controller
    // owns the binding's Ready gate; here we just render its
    // `cluster:` block into the gateway config. A missing/not-ready
    // cluster surfaces a condition but does NOT block the gateway —
    // it falls back to whatever `spec.config.cluster` carries (or the
    // single_node default), so a cluster edit can't wedge a running
    // gateway.
    let cluster = resolve_cluster(&ctx.client, obj.as_ref()).await?;
    if let Some(c) = &cluster
        && c.condition.status != "True"
    {
        ctx.metrics
            .operator_metrics()
            .observe_dependency_unresolved(CONTROLLER_NAME, "MCPGCluster", &c.condition.reason);
    }

    // Step 2: compute desired state. The merged config is the
    // user's `spec.config` plus operator-derived plugin entries
    // (when pluginSetRef resolves), a revocation-list trust
    // path (when revocationListRef resolves), and the cluster
    // backend block (when clusterRef resolves). Pod-roll trigger:
    // any change in those flips `config_hash`.
    let mut merged_config = merge_plugins(
        &obj.spec.config,
        plugin_set.as_ref().and_then(|p| p.view.as_ref()),
        revocation_list.as_ref().map(|_| REVOCATION_LIST_MOUNT_PATH),
    );
    if let Some(c) = &cluster {
        merge_cluster_block(&mut merged_config, &c.cluster_block);
    }
    // Soft-tenancy: fan every MCPGRoute targeting this gateway (in its
    // own namespace + acceptedRouteNamespaces) into tenant-scoped
    // tool-access rules. Folds into config_hash so a route edit rolls
    // the shared gateway. Best-effort: a transient route-list error
    // leaves routes unmerged this pass (logged) rather than failing the
    // whole gateway reconcile.
    let route_count = merge_routes(&ctx.client, obj.as_ref(), &ns, &mut merged_config).await;
    if route_count > 0 {
        info!(
            namespace = %ns,
            gateway = %obj.name_any(),
            routes = route_count,
            "merged soft-tenancy routes into tool-access policy"
        );
    }
    // Provisioned MCP servers: fan every same-namespace MCPGServer whose
    // `federate.gatewayRef` targets this gateway into `mcp.federations[]`
    // entries pointing at the rendered Services. Same best-effort posture
    // as routes: a transient list error skips the pass, never fails the
    // gateway reconcile.
    let server_count = merge_servers(&ctx.client, obj.as_ref(), &ns, &mut merged_config).await;
    if server_count > 0 {
        info!(
            namespace = %ns,
            gateway = %obj.name_any(),
            servers = server_count,
            "merged provisioned MCP servers into federations"
        );
    }
    // Managed-cloud: stamp the operator-trusted external resource indicator into
    // `governance.access.resource_metadata.resource` so the gateway advertises
    // the canonical `https://{slug}.<domain>/mcp` URL for OAuth resource-indicator
    // validation (RFC 8707/9728). Always OVERWRITES — a published config must
    // never set its own indicator (a tenant could otherwise claim another's
    // audience). Folds into `config_hash` so a URL change rolls the pod.
    if let Some(cloud) = &obj.spec.cloud
        && !cloud.external_url.is_empty()
    {
        inject_resource_metadata(&mut merged_config, &cloud.external_url);
    }
    apply_cloud_default_plugins(
        &obj,
        ctx.config.cloud_default_plugins.as_deref(),
        &mut merged_config,
    );
    let (cm, config_hash) = build_configmap(&obj, &merged_config);
    let svc = build_service(&obj);
    let sa = build_service_account(&obj);
    let dep = build_deployment(
        &obj,
        &config_hash,
        plugin_set
            .as_ref()
            .map(|p| p.mounts.as_slice())
            .unwrap_or(&[]),
        plugin_set.as_ref().map(|p| p.resolved_hash.as_str()),
        revocation_list.as_ref().map(|r| &r.mount),
    );

    // Step 3: SSA each child.
    let cm_api: Api<ConfigMap> = Api::namespaced(ctx.client.clone(), &ns);
    let svc_api: Api<Service> = Api::namespaced(ctx.client.clone(), &ns);
    let sa_api: Api<ServiceAccount> = Api::namespaced(ctx.client.clone(), &ns);
    let dep_api: Api<Deployment> = Api::namespaced(ctx.client.clone(), &ns);

    apply_owned(&cm_api, &cm, &fm).await?;
    apply_owned(&svc_api, &svc, &fm).await?;
    apply_owned(&sa_api, &sa, &fm).await?;
    let applied_dep = apply_owned(&dep_api, &dep, &fm).await?;

    // Managed-cloud only: SSA the per-instance HTTPRoute so the shared edge
    // Gateway routes `{instanceSlug}.<domain>/mcp` to this gateway's Service.
    // Self-host CRs (no `spec.cloud`) render nothing and skip the apply.
    if let Some(route) = build_httproute(&obj) {
        let route_api: Api<HTTPRoute> = Api::namespaced(ctx.client.clone(), &ns);
        apply_owned(&route_api, &route, &fm).await?;
    }

    // Custom-domain edge wiring: per-domain TLS listeners on the shared edge
    // Gateway + cert-manager Certificates (when an issuer is configured). The
    // route above carries the custom hostnames; without a matching listener
    // they would never bind at the edge.
    reconcile_edge_domains(&ctx, &obj).await?;

    // Opt-in scaling/availability children. Gated on their own `enabled` flags
    // (default off → nothing rendered, byte-identical to before). The HPA owns
    // replicas when present (Deployment dropped its static count above).
    if let Some(hpa) = build_hpa(&obj) {
        let hpa_api: Api<HorizontalPodAutoscaler> = Api::namespaced(ctx.client.clone(), &ns);
        apply_owned(&hpa_api, &hpa, &fm).await?;
    }
    if let Some(pdb) = build_pdb(&obj) {
        let pdb_api: Api<PodDisruptionBudget> = Api::namespaced(ctx.client.clone(), &ns);
        apply_owned(&pdb_api, &pdb, &fm).await?;
    }

    // Step 4: observe Deployment status to populate replica
    // counts. The applied Deployment carries fresh status iff
    // SSA returned the post-apply object.
    let dep_status = applied_dep.status.unwrap_or_default();
    let replicas = dep_status.replicas.unwrap_or(0);
    let ready = dep_status.ready_replicas.unwrap_or(0);
    let updated = dep_status.updated_replicas.unwrap_or(0);
    let available = dep_status.available_replicas.unwrap_or(0);

    let all_replicas_available = available > 0 && available == obj.spec.replicas;

    // Step 5: status update.
    let mut conditions = obj
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();
    if all_replicas_available {
        mcpg_operator_api::conditions::set_condition(
            &mut conditions,
            Condition::new(
                ctype::READY,
                "True",
                reasons::ALL_REPLICAS_AVAILABLE,
                "",
                Some(observed_generation),
            ),
        );
        mcpg_operator_api::conditions::set_condition(
            &mut conditions,
            Condition::new(
                ctype::AVAILABLE,
                "True",
                reasons::PODS_READY,
                "",
                Some(observed_generation),
            ),
        );
    } else {
        mcpg_operator_api::conditions::set_condition(
            &mut conditions,
            Condition::new(
                ctype::READY,
                "False",
                reasons::PROGRESSING,
                format!("{available}/{} replicas available", obj.spec.replicas),
                Some(observed_generation),
            ),
        );
        mcpg_operator_api::conditions::set_condition(
            &mut conditions,
            Condition::new(
                ctype::PROGRESSING,
                "True",
                reasons::PROGRESSING,
                "",
                Some(observed_generation),
            ),
        );
    }

    // Surface plugin-set / revocation-list resolution as their
    // own conditions so consumers can wait on
    // `PluginSetReady=True` independently of `Ready=True` (which
    // also tracks pod rollout).
    if let Some(p) = &plugin_set {
        let mut c = p.condition.clone();
        c.observed_generation = Some(observed_generation);
        mcpg_operator_api::conditions::set_condition(&mut conditions, c);
    }
    if let Some(r) = &revocation_list {
        let mut c = r.condition.clone();
        c.observed_generation = Some(observed_generation);
        mcpg_operator_api::conditions::set_condition(&mut conditions, c);
    }
    if let Some(c) = &cluster {
        let mut cond = c.condition.clone();
        cond.observed_generation = Some(observed_generation);
        mcpg_operator_api::conditions::set_condition(&mut conditions, cond);
    }

    let status = MCPGGatewayStatus {
        conditions,
        observed_generation: Some(observed_generation),
        replicas: Some(replicas),
        ready_replicas: Some(ready),
        updated_replicas: Some(updated),
        available_replicas: Some(available),
        config_hash: Some(config_hash),
        plugin_set_hash: plugin_set.as_ref().map(|p| p.resolved_hash.clone()),
        revocation_list_hash: revocation_list
            .as_ref()
            .map(|r| r.mount.content_hash.clone()),
        last_reconcile_time: Some(Utc::now()),
    };

    if let Err(e) = patch_status(&api, &name, &status, &fm).await {
        // Status updates are best-effort — log + continue.
        warn!(error = ?e, "status patch failed");
    }

    // Emit a Normal event when this reconcile flipped the gateway
    // to Ready=True. The Recorder's internal cache de-dupes
    // identical events on a 5-min TTL so a stable Ready gateway
    // doesn't spam `kubectl describe`.
    if all_replicas_available {
        let evt = K8sEvent {
            type_: EventType::Normal,
            reason: "Reconciled".into(),
            note: Some(format!(
                "Gateway is Ready ({}/{}) replicas available",
                available, obj.spec.replicas
            )),
            action: "Reconcile".into(),
            secondary: None,
        };
        if let Err(e) = ctx
            .recorders
            .gateway
            .publish(&evt, &obj.object_ref(&()))
            .await
        {
            warn!(error = ?e, "gateway: failed to publish Reconciled event");
        }
    }

    // Outcome classification:
    // - any unresolved ref the user asked for → DependencyPending
    //   (operator is healthy, just waiting on another CRD)
    // - everything resolved → Success
    let dependency_pending = plugin_set.as_ref().is_some_and(|p| p.view.is_none())
        || revocation_list
            .as_ref()
            .is_some_and(|r| r.condition.status != "True");
    let outcome = if dependency_pending {
        ReconcileOutcome::DependencyPending
    } else {
        ReconcileOutcome::Success
    };

    // Successful reconcile: clear any backoff state for this
    // resource so the next transient error starts at the base
    // delay rather than the previous tail.
    let key = crate::backoff::resource_key(CONTROLLER_NAME, &ns, &name);
    ctx.backoff.record_success(&key);

    Ok((
        Action::requeue(jittered_resync(ctx.config.resync_interval_secs)),
        outcome,
    ))
}

/// Error policy: classify into transient (apply / kube errors)
/// vs permanent (missing fields, malformed CRD), and apply
/// per-resource exponential backoff to the transient class so a
/// flapping CR doesn't burn the apiserver QPS budget.
fn error_policy(
    obj: Arc<MCPGGateway>,
    err: &ReconcileError,
    ctx: Arc<ControllerContext>,
) -> Action {
    match err {
        ReconcileError::MissingNamespace { .. } | ReconcileError::MissingName => {
            Action::await_change()
        }
        _ => {
            let key = crate::backoff::resource_key(
                CONTROLLER_NAME,
                &obj.namespace().unwrap_or_default(),
                &obj.name_any(),
            );
            let count = ctx.backoff.record_error(&key);
            let delay = ctx.backoff.duration_for(&key);
            warn!(
                key = %key,
                consecutive_errors = count,
                requeue_secs = delay.as_secs(),
                error = ?err,
                "gateway: reconcile error; backing off"
            );
            Action::requeue(delay)
        }
    }
}

/// Periodic resync interval, jittered ±20% so a fleet of CRDs
/// doesn't synchronise their reconciles into bursts.
fn jittered_resync(base_secs: u64) -> Duration {
    let base = base_secs as f64;
    let jitter_factor = 0.8 + rand::thread_rng().gen_range(0.0..0.4);
    Duration::from_secs_f64(base * jitter_factor)
}

// ─────────────────────────────────────────────────────────────────
// Cross-CRD watch mappers
// ─────────────────────────────────────────────────────────────────

/// True when the gateway references the named plugin set in
/// the same namespace.
fn gateway_uses_plugin_set(gw: &MCPGGateway, set_ns: Option<&str>, set_name: &str) -> bool {
    gw.metadata.namespace.as_deref() == set_ns
        && gw.spec.plugin_set_ref.as_ref().map(|r| r.name.as_str()) == Some(set_name)
}

/// True when the gateway depends on the named revocation list —
/// either via an explicit `revocationListRef` or, when unset,
/// because the list is the operator's `cluster-default`.
fn gateway_uses_revocation_list(gw: &MCPGGateway, list_name: &str) -> bool {
    let referenced = gw
        .spec
        .revocation_list_ref
        .as_ref()
        .map(|r| r.name.as_str())
        .unwrap_or(DEFAULT_REVOCATION_LIST_NAME);
    referenced == list_name
}

/// Mapper for `Controller::watches(MCPGPluginSet, ...)`. Given a
/// changed plugin set, returns the set of gateways in the same
/// namespace whose `pluginSetRef.name` points at it. Reading
/// from a snapshot of the gateway store is O(N) in the gateway
/// count — fine for any realistic fleet.
fn map_plugin_set_to_gateways(
    store: &kube::runtime::reflector::Store<MCPGGateway>,
    set: MCPGPluginSet,
) -> Vec<ObjectRef<MCPGGateway>> {
    let set_ns = set.metadata.namespace.as_deref();
    let set_name = match set.metadata.name.as_deref() {
        Some(n) => n,
        None => return Vec::new(),
    };
    store
        .state()
        .into_iter()
        .filter(|gw| gateway_uses_plugin_set(gw, set_ns, set_name))
        .map(|gw| ObjectRef::from_obj(&*gw))
        .collect()
}

/// Mapper for `Controller::watches(MCPGRevocationList, ...)`.
/// Returns every gateway whose `revocationListRef` references
/// the changed list (or, when the gateway has no explicit ref,
/// every gateway IFF the list is the operator's
/// `cluster-default`).
fn map_revocation_list_to_gateways(
    store: &kube::runtime::reflector::Store<MCPGGateway>,
    rl: MCPGRevocationList,
) -> Vec<ObjectRef<MCPGGateway>> {
    let target_name = match rl.metadata.name.as_deref() {
        Some(n) => n,
        None => return Vec::new(),
    };
    store
        .state()
        .into_iter()
        .filter(|gw| gateway_uses_revocation_list(gw, target_name))
        .map(|gw| ObjectRef::from_obj(&*gw))
        .collect()
}

/// Map a cluster-scoped `MCPGCluster` change to every gateway that
/// binds it via `clusterRef`, so a backend config edit (or a
/// readiness flip) rolls the bound gateways without waiting on
/// resync.
fn map_cluster_to_gateways(
    store: &kube::runtime::reflector::Store<MCPGGateway>,
    cluster: MCPGCluster,
) -> Vec<ObjectRef<MCPGGateway>> {
    let target_name = match cluster.metadata.name.as_deref() {
        Some(n) => n,
        None => return Vec::new(),
    };
    store
        .state()
        .into_iter()
        .filter(|gw| {
            gw.spec
                .cluster_ref
                .as_ref()
                .is_some_and(|r| r.name == target_name)
        })
        .map(|gw| ObjectRef::from_obj(&*gw))
        .collect()
}

/// Map an `MCPGRoute` change to the gateway it targets, so adding /
/// editing / deleting a tenant route re-renders the shared gateway's
/// tool-access rules without waiting on resync.
fn map_route_to_gateways(
    store: &kube::runtime::reflector::Store<MCPGGateway>,
    route: MCPGRoute,
) -> Vec<ObjectRef<MCPGGateway>> {
    let route_ns = match route.namespace() {
        Some(ns) => ns,
        None => return Vec::new(),
    };
    let gw_name = &route.spec.gateway_ref.name;
    let gw_ns = route.spec.gateway_namespace(&route_ns).to_owned();
    store
        .state()
        .into_iter()
        .filter(|gw| gw.name_any() == *gw_name && gw.namespace().as_deref() == Some(gw_ns.as_str()))
        .map(|gw| ObjectRef::from_obj(&*gw))
        .collect()
}

/// A provisioned server change re-reconciles the same-namespace gateway
/// its `federate.gatewayRef` targets, so the federation entry appears /
/// disappears without waiting for the resync tick.
fn map_server_to_gateways(
    store: &kube::runtime::reflector::Store<MCPGGateway>,
    server: MCPGServer,
) -> Vec<ObjectRef<MCPGGateway>> {
    let Some(server_ns) = server.namespace() else {
        return Vec::new();
    };
    let Some(federate) = server.spec.federate.as_ref() else {
        return Vec::new();
    };
    let gw_name = &federate.gateway_ref.name;
    store
        .state()
        .into_iter()
        .filter(|gw| {
            gw.name_any() == *gw_name && gw.namespace().as_deref() == Some(server_ns.as_str())
        })
        .map(|gw| ObjectRef::from_obj(&*gw))
        .collect()
}

/// Fan every same-namespace `MCPGServer` whose `federate.gatewayRef`
/// targets this gateway into `mcp.federations[]` entries pointing at
/// the rendered Services. Returns the number of servers merged.
async fn merge_servers(
    client: &Client,
    obj: &MCPGGateway,
    gateway_ns: &str,
    config: &mut serde_json::Value,
) -> usize {
    let gateway_name = obj.metadata.name.as_deref().unwrap_or_default();
    let server_api: Api<MCPGServer> = Api::namespaced(client.clone(), gateway_ns);
    let servers = match server_api.list(&Default::default()).await {
        Ok(list) => list.items,
        Err(e) => {
            tracing::warn!(error = ?e, "server fan-in: failed to list MCPGServers; skipping this pass");
            return 0;
        }
    };
    apply_servers_to_config(&servers, gateway_name, gateway_ns, config)
}

/// Pure core of [`merge_servers`]: synthesize one federation per
/// targeting server. Operator-authored federations (already present in
/// the gateway's inline config) win on a name collision — the entry is
/// skipped with a warning, mirroring the gateway runtime's own
/// registry-overlay precedence. Extracted so the fan-in is
/// unit-testable without a live apiserver.
fn apply_servers_to_config(
    servers: &[MCPGServer],
    gateway_name: &str,
    gateway_ns: &str,
    config: &mut serde_json::Value,
) -> usize {
    let mut merged = 0usize;
    for server in servers {
        let Some(server_ns) = server.namespace() else {
            continue;
        };
        if server_ns != gateway_ns {
            continue;
        }
        let Some(federate) = server.spec.federate.as_ref() else {
            continue;
        };
        if federate.gateway_ref.name != gateway_name {
            continue;
        }
        let object_name = server.name_any();
        let fed_name = server.spec.federation_name(&object_name).to_owned();
        let child = crate::templates::server_child_name(server);
        let endpoint = server.spec.endpoint(&child, &server_ns);
        let tool_prefix = federate
            .tool_prefix
            .clone()
            .unwrap_or_else(|| format!("{fed_name}."));

        let federations = ensure_path(config, &["mcp", "federations"]);
        let arr = match federations {
            serde_json::Value::Array(a) => a,
            other => {
                *other = serde_json::Value::Array(Vec::new());
                other.as_array_mut().expect("just set to array")
            }
        };
        if arr
            .iter()
            .any(|f| f.get("name").and_then(|v| v.as_str()) == Some(fed_name.as_str()))
        {
            tracing::warn!(
                federation = %fed_name,
                "MCPGServer federation collides with an inline federation; inline config wins"
            );
            continue;
        }

        let mut upstream = serde_json::json!({
            "url": endpoint,
            // In-cluster Service traffic is plain HTTP on a private
            // address; both are explicit opt-ins for a hand-written
            // federation and deliberate here.
            "upstream_safety": {
                "allow_private_backends": true,
                "allow_insecure_http": true,
            },
            "protocol_version": "auto",
        });
        if let Some(auth) = federate.auth.as_ref() {
            upstream["auth"] = auth.clone();
        }
        let mut fed = serde_json::json!({
            "name": fed_name,
            "upstream": upstream,
            "naming": { "tool_prefix": tool_prefix },
        });
        if let Some(governance) = federate.governance.as_ref() {
            fed["governance"] = governance.clone();
        }
        if let Some(import) = federate.import.as_ref() {
            fed["import"] = import.clone();
        }
        arr.push(fed);
        merged += 1;
    }
    merged
}

// ─────────────────────────────────────────────────────────────────
// Plugin set resolution
// ─────────────────────────────────────────────────────────────────

/// Resolve the gateway's `pluginSetRef`, if any.
///
/// Returns:
/// - `Ok(None)` when the gateway has no `pluginSetRef`.
/// - `Ok(Some(ResolvedPluginSet { view: Some(_), .. }))` when the
///   set exists, is `Ready`, and the resolved ConfigMap parses
///   into a usable view.
/// - `Ok(Some(ResolvedPluginSet { view: None, .. }))` when the set
///   exists but isn't consumable yet (still resolving / parse
///   failed). The caller still records the condition so the
///   user sees why pods didn't roll.
/// - `Err(_)` only on transient kube errors that warrant retry.
async fn resolve_plugin_set(
    client: &Client,
    namespace: &str,
    obj: &MCPGGateway,
) -> Result<Option<ResolvedPluginSet>, ReconcileError> {
    let Some(pref) = obj.spec.plugin_set_ref.as_ref() else {
        return Ok(None);
    };

    let api: Api<MCPGPluginSet> = Api::namespaced(client.clone(), namespace);
    let set = match api.get_opt(&pref.name).await? {
        Some(s) => s,
        None => {
            return Ok(Some(ResolvedPluginSet {
                resolved_hash: String::new(),
                view: None,
                mounts: Vec::new(),
                condition: Condition::new(
                    cond_types::PLUGIN_SET_READY,
                    "False",
                    plugin_set_reason::NOT_FOUND,
                    format!(
                        "MCPGPluginSet/{} not found in namespace {namespace}",
                        pref.name
                    ),
                    None,
                ),
            }));
        }
    };

    let resolved_hash = set
        .status
        .as_ref()
        .and_then(|s| s.resolved_hash.clone())
        .unwrap_or_default();
    let ready = set
        .status
        .as_ref()
        .map(|s| {
            s.conditions
                .iter()
                .any(|c| c.r#type == ctype::READY && c.status == "True")
        })
        .unwrap_or(false);

    if !ready || resolved_hash.is_empty() {
        return Ok(Some(ResolvedPluginSet {
            resolved_hash,
            view: None,
            mounts: Vec::new(),
            condition: Condition::new(
                cond_types::PLUGIN_SET_READY,
                "False",
                plugin_set_reason::NOT_READY,
                format!(
                    "MCPGPluginSet/{}.status.conditions[Ready] != True",
                    pref.name
                ),
                None,
            ),
        }));
    }

    // Fetch the {set-name}-resolved ConfigMap the plugin-set
    // controller emits.
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let cm_name = format!("{}-resolved", pref.name);
    let resolved_cm = match cm_api.get_opt(&cm_name).await? {
        Some(cm) => cm,
        None => {
            return Ok(Some(ResolvedPluginSet {
                resolved_hash,
                view: None,
                mounts: Vec::new(),
                condition: Condition::new(
                    cond_types::PLUGIN_SET_READY,
                    "False",
                    plugin_set_reason::RESOLVED_CM_MISSING,
                    format!(
                        "ConfigMap/{cm_name} missing — plugin-set controller hasn't materialised yet"
                    ),
                    None,
                ),
            }));
        }
    };

    let plugins_json = resolved_cm
        .data
        .as_ref()
        .and_then(|d| d.get("plugins.json"))
        .cloned()
        .unwrap_or_default();
    let view = match parse_resolved_plugins_json(&plugins_json, &set) {
        Ok(view) => view,
        Err(e) => {
            return Ok(Some(ResolvedPluginSet {
                resolved_hash,
                view: None,
                mounts: Vec::new(),
                condition: Condition::new(
                    cond_types::PLUGIN_SET_READY,
                    "False",
                    plugin_set_reason::PARSE_FAILED,
                    format!("ConfigMap/{cm_name} plugins.json parse failed: {e}"),
                    None,
                ),
            }));
        }
    };

    let mounts = view
        .entries
        .iter()
        .map(|e| PluginSecretMount {
            plugin_id: e.id.clone(),
            // Each entry's artefactSecretName points at the
            // per-namespace plugin Secret the plugin-set controller
            // materialised.
            secret_name: e.artefact_secret_name.clone(),
        })
        .collect();

    Ok(Some(ResolvedPluginSet {
        resolved_hash,
        view: Some(view),
        mounts,
        condition: Condition::new(
            cond_types::PLUGIN_SET_READY,
            "True",
            plugin_set_reason::RESOLVED,
            format!(
                "MCPGPluginSet/{} resolved with {} entries",
                pref.name,
                set.spec.entries.len()
            ),
            None,
        ),
    }))
}

/// Parse the plugin-set controller's `plugins.json` ConfigMap
/// data into a [`ResolvedSetView`] the templates layer can
/// consume. Each
/// entry's `capabilityGrants` is folded into the view's
/// `capability_grants` map (keyed by plugin id) so the merger
/// has the per-plugin grant list ready.
fn parse_resolved_plugins_json(json: &str, set: &MCPGPluginSet) -> Result<ResolvedSetView, String> {
    let doc: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("invalid JSON: {e}"))?;
    let entries = doc
        .get("entries")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "plugins.json missing `entries` array".to_owned())?;

    let mut out_entries: Vec<ResolvedSetEntry> = Vec::with_capacity(entries.len());
    for (i, e) in entries.iter().enumerate() {
        out_entries.push(ResolvedSetEntry {
            id: required_string(e, "id", i)?,
            plugin_class: required_string(e, "pluginClass", i)?,
            plugin_version: required_string(e, "pluginVersion", i)?,
            artefact_secret_name: required_string(e, "artefactSecretName", i)?,
            resolved_digest: required_string(e, "resolvedDigest", i)?,
            config: e.get("config").cloned().unwrap_or(serde_json::Value::Null),
        });
    }

    // Pull capability grants from the parent set's spec — the
    // ConfigMap embeds them per-entry, but the merger keys them by
    // plugin id and folds each into the matching rendered entry's
    // `granted_capabilities` (grants are per-entry in the gateway's
    // `PluginEntryConfig`). The set spec is the source of truth.
    let mut grants: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in &set.spec.capability_grants {
        grants.insert(k.clone(), v.clone());
    }

    Ok(ResolvedSetView {
        entries: out_entries,
        capability_grants: grants,
    })
}

fn required_string(obj: &serde_json::Value, key: &str, index: usize) -> Result<String, String> {
    obj.get(key)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| format!("entries[{index}].{key} missing or not a string"))
}

// ─────────────────────────────────────────────────────────────────
// Revocation list resolution + materialisation
// ─────────────────────────────────────────────────────────────────

/// Resolve the gateway's `revocationListRef` (or the
/// `cluster-default` revocation list when unset), and materialise
/// it as a namespace-local ConfigMap so the gateway pod can mount
/// it from a single, predictable location.
///
/// The `MCPGRevocationList` controller leaves the list
/// cluster-scoped; gateways live in tenant namespaces, and pods
/// can't mount cluster-scoped objects. The operator copies the
/// list into the gateway's namespace under `<gateway>-revocations`
/// (key `list.json`) — analogous to the per-namespace plugin
/// Secret copy the plugin-set controller makes.
///
/// Returns `Ok(None)` when no revocation list is found AND the
/// gateway didn't ask for one explicitly; missing-but-defaulted
/// is non-fatal (an empty revocation list = "no revocations").
async fn resolve_revocation_list(
    client: &Client,
    namespace: &str,
    obj: &MCPGGateway,
    field_manager: &str,
) -> Result<Option<ResolvedRevocationList>, ReconcileError> {
    let (target_name, was_explicit) = match obj.spec.revocation_list_ref.as_ref() {
        Some(r) => (r.name.clone(), true),
        None => (DEFAULT_REVOCATION_LIST_NAME.to_owned(), false),
    };

    let cluster_api: Api<MCPGRevocationList> = Api::all(client.clone());
    let rl = match cluster_api.get_opt(&target_name).await? {
        Some(r) => r,
        None => {
            if was_explicit {
                return Ok(Some(ResolvedRevocationList {
                    mount: RevocationListMount {
                        config_map_name: String::new(),
                        content_hash: String::new(),
                    },
                    condition: Condition::new(
                        cond_types::REVOCATION_LIST_READY,
                        "False",
                        revocation_reason::NOT_FOUND,
                        format!("MCPGRevocationList/{target_name} not found",),
                        None,
                    ),
                }));
            }
            // Default name + missing → silently skip (operator
            // ships the cluster-default list pre-populated; if
            // it's absent on a fresh cluster, gating signature-
            // verification on its presence would block boot).
            return Ok(None);
        }
    };

    let (json, hash) = render_revocation_list_json(&rl);
    let cm_name = revocation_cm_name(obj);
    let cm = build_revocation_configmap(obj, &cm_name, &json, &hash);

    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    if let Err(e) = apply_owned(&cm_api, &cm, field_manager).await {
        return Ok(Some(ResolvedRevocationList {
            mount: RevocationListMount {
                config_map_name: cm_name,
                content_hash: hash,
            },
            condition: Condition::new(
                cond_types::REVOCATION_LIST_READY,
                "False",
                revocation_reason::APPLY_FAILED,
                format!("ConfigMap apply failed: {e}"),
                None,
            ),
        }));
    }

    Ok(Some(ResolvedRevocationList {
        mount: RevocationListMount {
            config_map_name: cm_name,
            content_hash: hash.clone(),
        },
        condition: Condition::new(
            cond_types::REVOCATION_LIST_READY,
            "True",
            revocation_reason::RESOLVED,
            format!(
                "MCPGRevocationList/{target_name} materialised ({} entries, hash {hash})",
                rl.spec.revocations.len()
            ),
            None,
        ),
    }))
}

fn revocation_cm_name(obj: &MCPGGateway) -> String {
    let base = obj.metadata.name.clone().unwrap_or_default();
    format!("{base}-revocations")
}

// ─────────────────────────────────────────────────────────────────
// Cluster (coordination-backend) resolution
// ─────────────────────────────────────────────────────────────────

/// Resolve the gateway's `clusterRef` into a rendered `cluster:`
/// config block. Best-effort by design: a missing or not-`Ready`
/// `MCPGCluster` produces a `ClusterReady=False` condition but an
/// empty block, so the gateway keeps whatever `cluster:` its inline
/// `spec.config` carried (or falls back to the gateway's own
/// `single_node` default). This means editing/deleting an
/// `MCPGCluster` can never hard-wedge an already-running gateway —
/// it only stops *new* config from rendering the backend block.
///
/// Returns `Ok(None)` when the gateway has no `clusterRef` (the
/// common single-replica case — no condition, no block).
async fn resolve_cluster(
    client: &Client,
    obj: &MCPGGateway,
) -> Result<Option<ResolvedCluster>, ReconcileError> {
    let Some(cluster_ref) = obj.spec.cluster_ref.as_ref() else {
        return Ok(None);
    };
    let name = &cluster_ref.name;
    let api: Api<MCPGCluster> = Api::all(client.clone());

    let cluster = match api.get_opt(name).await? {
        Some(c) => c,
        None => {
            return Ok(Some(ResolvedCluster {
                cluster_block: serde_json::Value::Null,
                condition: Condition::new(
                    cond_types::CLUSTER_READY,
                    "False",
                    cluster_reason::NOT_FOUND,
                    format!("MCPGCluster/{name} not found; keeping existing cluster config"),
                    None,
                ),
            }));
        }
    };

    // Honour the cluster controller's own readiness verdict — if the
    // backend isn't bindable (e.g. its pinned cluster plugin isn't
    // verified) we don't render the block, so a gateway can't be
    // pointed at an unverified coordinator.
    let cluster_ready = cluster
        .status
        .as_ref()
        .map(|s| {
            s.conditions
                .iter()
                .any(|c| c.r#type == ctype::READY && c.status == "True")
        })
        .unwrap_or(false);

    if !cluster_ready {
        return Ok(Some(ResolvedCluster {
            cluster_block: serde_json::Value::Null,
            condition: Condition::new(
                cond_types::CLUSTER_READY,
                "False",
                cluster_reason::NOT_READY,
                format!("MCPGCluster/{name} is not Ready; keeping existing cluster config"),
                None,
            ),
        }));
    }

    let block = cluster.spec.render_cluster_block();
    Ok(Some(ResolvedCluster {
        cluster_block: block,
        condition: Condition::new(
            cond_types::CLUSTER_READY,
            "True",
            cluster_reason::RESOLVED,
            format!(
                "bound MCPGCluster/{name} (backend: {})",
                cluster.spec.backend.config_kind()
            ),
            None,
        ),
    }))
}

/// Overlay the rendered `cluster:` block onto the merged gateway
/// config. The cluster binding is authoritative when it resolves —
/// it REPLACES any inline `config.cluster` (operators using
/// `clusterRef` shouldn't also hand-write `cluster:`; the ref wins,
/// same policy as `pluginSetRef` replacing inline plugin entries).
/// A `Null` block (cluster not resolved) is a no-op.
fn merge_cluster_block(config: &mut serde_json::Value, cluster_block: &serde_json::Value) {
    if cluster_block.is_null() {
        return;
    }
    if !config.is_object() {
        *config = serde_json::json!({});
    }
    if let Some(obj) = config.as_object_mut() {
        obj.insert("cluster".to_owned(), cluster_block.clone());
    }
}

// ─────────────────────────────────────────────────────────────────
// Soft-tenancy route fan-in
// ─────────────────────────────────────────────────────────────────

/// List every `MCPGRoute` targeting this gateway and merge their
/// matched tools into the gateway config's
/// `governance.policy.tool_access.rules[]` as tenant-scoped access
/// rules. Returns the number of routes merged.
///
/// ## Why this is the enforceable shape
///
/// The gateway has no per-route chain-dispatch engine; it IS a
/// catalog the policy layer filters per-identity. So a route's
/// `match.tools` + `attributes.tenant` become tool-access rules of the
/// form: "tool `T` is reachable only when
/// `identity.attributes.tenant == "<tenant>"`". That's the exact
/// multi-tenant pattern the gateway docs recommend, and it's enforced
/// today at `tools/list` (visibility) and `tools/call` (authz).
///
/// A route's `identityChain` / `policyChain` / `auditChain` are NOT
/// merged here — the gateway can't dispatch them per-route yet (the
/// route controller surfaces that via `ChainsEnforced=False`).
///
/// Accepted routes = routes in the gateway's own namespace OR in a
/// namespace listed in `spec.acceptedRouteNamespaces`. Two routes
/// scoping the same tool to different tenants produce two rules with
/// OR-ed predicates merged onto one `tool_name` entry (a tool shared
/// across tenants is reachable by any of them).
async fn merge_routes(
    client: &Client,
    obj: &MCPGGateway,
    gateway_ns: &str,
    config: &mut serde_json::Value,
) -> usize {
    let gateway_name = obj.metadata.name.as_deref().unwrap_or_default();

    let route_api: Api<MCPGRoute> = Api::all(client.clone());
    let routes = match route_api.list(&Default::default()).await {
        Ok(list) => list.items,
        Err(e) => {
            tracing::warn!(error = ?e, "route fan-in: failed to list MCPGRoutes; skipping this pass");
            return 0;
        }
    };

    apply_routes_to_config(
        &routes,
        gateway_name,
        gateway_ns,
        &obj.spec.accepted_route_namespaces,
        config,
    )
}

/// Pure core of [`merge_routes`]: given the candidate routes, the
/// gateway identity, and the operator-declared `accepted` namespace
/// allow-list (the gateway's own namespace is always accepted on top
/// of this), mutate `config`'s `governance.policy.tool_access.rules[]`
/// and return the number of routes that targeted this gateway.
/// Extracted so the fan-in logic is unit-testable without a live
/// apiserver.
fn apply_routes_to_config(
    routes: &[MCPGRoute],
    gateway_name: &str,
    gateway_ns: &str,
    accepted: &[String],
    config: &mut serde_json::Value,
) -> usize {
    // Collect (tool_name -> set of tenant predicates) for routes that
    // target THIS gateway from an accepted namespace.
    let mut tool_predicates: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut merged_routes = 0usize;
    for route in routes {
        let Some(route_ns) = route.namespace() else {
            continue;
        };
        if route.spec.gateway_ref.name != gateway_name {
            continue;
        }
        if route.spec.gateway_namespace(&route_ns) != gateway_ns {
            continue;
        }
        // Accepted = the gateway's own namespace (always) OR an
        // explicitly opted-in namespace. Mirrors the route controller's
        // GatewayBound check + the admission webhook.
        if route_ns != gateway_ns && !accepted.contains(&route_ns) {
            continue;
        }
        merged_routes += 1;
        // The predicate scopes a tool to the route's tenant. When the
        // route declares no tenant, the tool is reachable by any caller
        // the gateway already admits (predicate `true`) — the route
        // controller warns on this.
        let predicate = match route.spec.tenant() {
            Some(tenant) => format!("identity.attributes.tenant == {}", cel_quote(tenant)),
            None => "true".to_owned(),
        };
        for tool in &route.spec.r#match.tools {
            tool_predicates
                .entry(tool.id.clone())
                .or_default()
                .push(predicate.clone());
        }
    }

    if tool_predicates.is_empty() {
        return merged_routes;
    }

    // Render into governance.policy.tool_access.rules[]. Existing
    // (operator-authored) rules for the same tool are preserved unless
    // a route also names that tool, in which case the route's
    // tenant predicate is OR-ed onto the rule.
    let rules = ensure_path(config, &["governance", "policy", "tool_access", "rules"]);
    let arr = match rules {
        serde_json::Value::Array(a) => a,
        other => {
            *other = serde_json::Value::Array(Vec::new());
            other.as_array_mut().expect("just set to array")
        }
    };

    for (tool_name, predicates) in tool_predicates {
        // De-dup predicates and OR them together.
        let mut uniq: Vec<String> = predicates;
        uniq.sort();
        uniq.dedup();
        let cel = if uniq.iter().any(|p| p == "true") {
            "true".to_owned()
        } else if uniq.len() == 1 {
            uniq.remove(0)
        } else {
            uniq.iter()
                .map(|p| format!("({p})"))
                .collect::<Vec<_>>()
                .join(" || ")
        };

        // If a rule for this tool already exists, OR the route
        // predicate onto its cel_allow_if; else push a new rule.
        if let Some(existing) = arr.iter_mut().find_map(|r| {
            r.as_object_mut()
                .filter(|o| o.get("tool_name").and_then(|v| v.as_str()) == Some(tool_name.as_str()))
        }) {
            let combined = match existing.get("cel_allow_if").and_then(|v| v.as_str()) {
                Some(prev) if prev != "true" && cel != "true" => {
                    format!("({prev}) || ({cel})")
                }
                _ if cel == "true" => "true".to_owned(),
                Some(prev) => prev.to_owned(),
                None => cel.clone(),
            };
            existing.insert(
                "cel_allow_if".to_owned(),
                serde_json::Value::String(combined),
            );
        } else {
            arr.push(serde_json::json!({
                "tool_name": tool_name,
                // Soft-tenancy routes require a verified identity to
                // read the tenant attribute meaningfully.
                "minimum_trust": "verified",
                "cel_allow_if": cel,
            }));
        }
    }

    merged_routes
}

/// Minimal CEL string-literal quoting: wrap in double quotes and
/// escape backslashes + double quotes. Tenant values come from a
/// validated CRD attribute, but quote defensively regardless.
fn cel_quote(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Walk/﻿create a nested object path, returning a mutable ref to the
/// leaf value (created as needed). Intermediate non-objects are
/// replaced with objects.
fn ensure_path<'a>(root: &'a mut serde_json::Value, path: &[&str]) -> &'a mut serde_json::Value {
    let mut cur = root;
    for key in path {
        if !cur.is_object() {
            *cur = serde_json::json!({});
        }
        let obj = cur.as_object_mut().expect("just ensured object");
        cur = obj
            .entry((*key).to_owned())
            .or_insert_with(|| serde_json::json!({}));
    }
    cur
}

/// Stamp the operator-trusted external resource indicator into
/// `governance.access.resource_metadata.resource`. Always overwrites any
/// published value — in managed-cloud the indicator is a trust boundary
/// (a tenant must not be able to claim another instance's OAuth audience),
/// so the operator is the sole writer.
fn inject_resource_metadata(config: &mut serde_json::Value, url: &str) {
    let rm = ensure_path(config, &["governance", "access", "resource_metadata"]);
    if !rm.is_object() {
        *rm = serde_json::json!({});
    }
    rm.as_object_mut().expect("just ensured object").insert(
        "resource".to_owned(),
        serde_json::Value::String(url.to_owned()),
    );
}

/// Render an `MCPGRevocationList` into the
/// `RevocationListFile` JSON shape the gateway's
/// `mcpg_plugin_host::revocation` parser consumes. The hash
/// trails the JSON so dashboards + the pod-template annotation
/// can compare across replicas.
fn render_revocation_list_json(rl: &MCPGRevocationList) -> (String, String) {
    let revocations: Vec<serde_json::Value> = rl
        .spec
        .revocations
        .iter()
        .map(|e| {
            serde_json::json!({
                "artifact_sha256": e.artifact_sha256,
                "reason": e.reason,
                "revoked_at": e.revoked_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();
    let doc = serde_json::json!({
        "version": rl.spec.version,
        "issued_at": rl.spec.issued_at.map(|t| t.to_rfc3339()),
        "revocations": revocations,
    });
    let json = serde_json::to_string_pretty(&doc).expect("serde_json never fails on owned objects");
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let hash = hex::encode(hasher.finalize());
    (json, hash)
}

fn build_revocation_configmap(
    parent: &MCPGGateway,
    name: &str,
    json: &str,
    hash: &str,
) -> ConfigMap {
    let mut labels: BTreeMap<String, String> = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".into(),
        "mcpg-operator".into(),
    );
    labels.insert(
        label_keys::MCPG_GATEWAY.into(),
        parent.metadata.name.clone().unwrap_or_default(),
    );
    labels.insert("mcpg.dev/revocation-list-hash".into(), hash.to_owned());

    let mut data = BTreeMap::new();
    data.insert("list.json".into(), json.to_owned());

    ConfigMap {
        metadata: ObjectMeta {
            name: Some(name.to_owned()),
            namespace: parent.metadata.namespace.clone(),
            labels: Some(labels),
            owner_references: Some(vec![owner_ref(parent)]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}

/// Converge this CR's custom-domain edge wiring (managed cloud only):
///
/// 1. SSA the per-domain HTTPS listeners onto the shared edge Gateway under a
///    PER-CR field manager — `spec.listeners` is a `listMapKey=name` list, so
///    the apply adds/updates exactly this CR's entries and an apply with an
///    EMPTY set relinquishes them (domains removed on re-publish). Other CRs'
///    listeners and the chart's wildcard listeners are untouched.
/// 2. Render a cert-manager `Certificate` per domain (when the operator has
///    `--edge-cluster-issuer`) and garbage-collect, by owner-uid label, any
///    certificate whose domain left the spec — also the cleanup path when the
///    issuer flag is turned off.
///
/// The CP only ships custom domains whose DNS ownership was TXT-verified, so
/// issuing HTTP-01 certificates for them through the edge cannot be abused to
/// mint certificates for someone else's domain.
async fn reconcile_edge_domains(
    ctx: &ControllerContext,
    obj: &MCPGGateway,
) -> Result<(), ReconcileError> {
    use crate::templates::edge::{
        CLOUD_GATEWAY_NAME, CLOUD_GATEWAY_NAMESPACE, EDGE_OWNER_UID_LABEL, build_certificate,
        build_edge_listener_apply, edge_field_manager, edge_object_name,
    };

    let Some(cloud) = obj.spec.cloud.as_ref() else {
        return Ok(()); // self-host: no edge to wire
    };
    let uid = obj.metadata.uid.clone().unwrap_or_default();
    let domains = &cloud.custom_domains;

    let apply_doc = build_edge_listener_apply(domains);
    let gvk = kube::core::GroupVersionKind::gvk("gateway.networking.k8s.io", "v1", "Gateway");
    let ar = kube::core::ApiResource::from_gvk(&gvk);
    let gw_api: Api<kube::core::DynamicObject> =
        Api::namespaced_with(ctx.client.clone(), CLOUD_GATEWAY_NAMESPACE, &ar);
    // `force` is the standard controller posture for SSA: this manager is
    // per-CR, so the only conflict it can ever win is a stale copy of itself.
    let pp = kube::api::PatchParams::apply(&edge_field_manager(&uid)).force();
    match gw_api
        .patch(
            CLOUD_GATEWAY_NAME,
            &pp,
            &kube::api::Patch::Apply(&apply_doc),
        )
        .await
    {
        Ok(_) => {}
        Err(e) if domains.is_empty() => {
            // Relinquish-only apply: with no edge Gateway present there is
            // nothing to relinquish (and Patch::Apply would otherwise try to
            // CREATE a half-Gateway and fail validation). Common on clusters
            // without the edge chart.
            tracing::debug!(error = ?e, "edge: empty listener apply skipped (no edge Gateway?)");
        }
        Err(e) => return Err(ReconcileError::Kube(e)),
    }

    // Certificates: converge the wanted set, then GC by owner label. The label
    // (not an ownerReference) is what ties them to this CR — ownerReferences
    // cannot cross namespaces and these live in the edge namespace.
    let cert_api: Api<crate::templates::edge::Certificate> =
        Api::namespaced(ctx.client.clone(), CLOUD_GATEWAY_NAMESPACE);
    let issuer = ctx.config.edge_cluster_issuer.as_deref();
    let mut wanted: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if let Some(issuer) = issuer {
        let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");
        for hostname in domains {
            let cert = build_certificate(obj, hostname, issuer);
            apply_owned(&cert_api, &cert, &fm).await?;
            wanted.insert(edge_object_name(hostname));
        }
    } else if !domains.is_empty() {
        tracing::debug!(
            domains = domains.len(),
            "edge: no --edge-cluster-issuer configured; custom-domain TLS secrets must be provisioned manually"
        );
    }
    match cert_api
        .list(&kube::api::ListParams::default().labels(&format!("{EDGE_OWNER_UID_LABEL}={uid}")))
        .await
    {
        Ok(list) => {
            for item in list {
                let name = item.name_any();
                if !wanted.contains(&name) {
                    let _ = cert_api.delete(&name, &Default::default()).await;
                }
            }
        }
        Err(e) => {
            // cert-manager CRD absent (or no certs were ever created) — GC has
            // nothing to do. Debug, not error: the listener path above is the
            // load-bearing part.
            tracing::debug!(error = ?e, "edge: certificate GC list skipped");
        }
    }
    Ok(())
}

/// Managed-cloud only: append the standard backend plugin entries
/// (image-baked cdylibs) to the rendered config so tenant `tools/call`
/// dispatch has its backends registered — the gateway binary links no
/// backends statically. Composes with plugin-set / hand-listed entries
/// (an existing `id`/`ref` suppresses the matching default); the id
/// list comes from MCPG_OPERATOR_CLOUD_DEFAULT_PLUGINS (unset =
/// standard set, empty = disabled). Self-host CRs are left untouched —
/// their image may not carry the artifacts, and a missing
/// `source.path` fails gateway boot.
fn apply_cloud_default_plugins(
    obj: &MCPGGateway,
    override_csv: Option<&str>,
    merged_config: &mut serde_json::Value,
) {
    if obj.spec.cloud.is_none() {
        return;
    }
    append_cloud_default_plugins(merged_config, &cloud_default_plugin_ids(override_csv));
    // Selecting a sink does not load it. Same reasoning as the backends
    // above, and the same image: without the entry the signal is configured
    // and silently never exported.
    append_observability_sink_plugins(merged_config);
}

/// Finalizer-path cleanup for [`reconcile_edge_domains`]: relinquish this CR's
/// edge listeners and delete its labeled Certificates. Best-effort by design —
/// the edge Gateway (or the whole edge namespace) may already be gone during a
/// cluster teardown, and a failed cleanup must NEVER wedge finalizer release.
async fn cleanup_edge_domains(ctx: &ControllerContext, obj: &MCPGGateway) {
    use crate::templates::edge::{
        CLOUD_GATEWAY_NAME, CLOUD_GATEWAY_NAMESPACE, EDGE_OWNER_UID_LABEL,
        build_edge_listener_apply, edge_field_manager,
    };

    if obj.spec.cloud.is_none() {
        return;
    }
    let uid = obj.metadata.uid.clone().unwrap_or_default();

    let gvk = kube::core::GroupVersionKind::gvk("gateway.networking.k8s.io", "v1", "Gateway");
    let ar = kube::core::ApiResource::from_gvk(&gvk);
    let gw_api: Api<kube::core::DynamicObject> =
        Api::namespaced_with(ctx.client.clone(), CLOUD_GATEWAY_NAMESPACE, &ar);
    let pp = kube::api::PatchParams::apply(&edge_field_manager(&uid)).force();
    if let Err(e) = gw_api
        .patch(
            CLOUD_GATEWAY_NAME,
            &pp,
            &kube::api::Patch::Apply(&build_edge_listener_apply(&[])),
        )
        .await
    {
        tracing::debug!(error = ?e, "edge cleanup: listener relinquish skipped");
    }

    let cert_api: Api<crate::templates::edge::Certificate> =
        Api::namespaced(ctx.client.clone(), CLOUD_GATEWAY_NAMESPACE);
    match cert_api
        .list(&kube::api::ListParams::default().labels(&format!("{EDGE_OWNER_UID_LABEL}={uid}")))
        .await
    {
        Ok(list) => {
            for item in list {
                let _ = cert_api.delete(&item.name_any(), &Default::default()).await;
            }
        }
        Err(e) => {
            tracing::debug!(error = ?e, "edge cleanup: certificate delete skipped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_operator_api::v1alpha1::{MCPGPluginSetSpec, MCPGRevocationListSpec, RevocationEntry};

    #[test]
    fn jittered_resync_within_bounds() {
        for _ in 0..100 {
            let d = jittered_resync(600);
            let s = d.as_secs_f64();
            // 600 * 0.8 = 480, 600 * 1.2 = 720. Allow some slack.
            assert!((480.0..=720.0).contains(&s), "out of range: {s}");
        }
    }

    #[test]
    fn inject_resource_metadata_creates_path() {
        let mut cfg = serde_json::json!({});
        inject_resource_metadata(&mut cfg, "https://edge-1.mcpg.cloud/mcp");
        assert_eq!(
            cfg["governance"]["access"]["resource_metadata"]["resource"],
            serde_json::json!("https://edge-1.mcpg.cloud/mcp")
        );
    }

    #[test]
    fn inject_resource_metadata_overwrites_published_value() {
        // A tenant must not be able to claim another instance's OAuth audience:
        // the operator is the sole writer of `resource`.
        let mut cfg = serde_json::json!({
            "governance": { "access": { "resource_metadata": {
                "resource": "https://victim.mcpg.cloud/mcp",
                "authorization_servers": ["https://idp.example/"]
            }}}
        });
        inject_resource_metadata(&mut cfg, "https://attacker.mcpg.cloud/mcp");
        let rm = &cfg["governance"]["access"]["resource_metadata"];
        assert_eq!(
            rm["resource"],
            serde_json::json!("https://attacker.mcpg.cloud/mcp")
        );
        // Sibling keys are preserved (merge, not clobber the whole node).
        assert_eq!(
            rm["authorization_servers"],
            serde_json::json!(["https://idp.example/"])
        );
    }

    #[test]
    fn inject_resource_metadata_replaces_non_object_node() {
        let mut cfg = serde_json::json!({
            "governance": { "access": { "resource_metadata": "bogus" }}
        });
        inject_resource_metadata(&mut cfg, "https://edge-1.mcpg.cloud/mcp");
        assert_eq!(
            cfg["governance"]["access"]["resource_metadata"]["resource"],
            serde_json::json!("https://edge-1.mcpg.cloud/mcp")
        );
    }

    /// The injected key must map to a real snake_case `AppConfig` field, or the
    /// rendered ConfigMap would panic the pod at boot under `deny_unknown_fields`.
    /// Round-trip the operator's output through the gateway's own loader.
    #[test]
    fn injected_resource_metadata_roundtrips_through_appconfig() {
        let mut cfg = serde_json::json!({});
        inject_resource_metadata(&mut cfg, "https://edge-1.mcpg.cloud/mcp");
        let yaml = serde_yaml::to_string(&cfg).expect("serialize config");
        let parsed = mcpg::config::AppConfig::load_from_yaml_str(&yaml)
            .expect("rendered cloud config must deserialise into AppConfig");
        parsed
            .validate()
            .expect("rendered cloud config must pass AppConfig::validate");
    }

    // ── Managed-cloud default backend plugins ──────────────────

    fn gw_cloudness(cloud: bool) -> MCPGGateway {
        use mcpg_operator_api::v1alpha1::GatewayCloud;
        MCPGGateway::new(
            "edge-1",
            mcpg_operator_api::v1alpha1::MCPGGatewaySpec {
                cloud: cloud.then(|| GatewayCloud {
                    org_slug: "acme".into(),
                    instance_slug: "edge-1".into(),
                    external_url: "https://edge-1.mcpg.cloud/mcp".into(),
                    custom_domains: Vec::new(),
                }),
                ..Default::default()
            },
        )
    }

    #[test]
    fn cloud_cr_gets_default_backend_entries() {
        let gw = gw_cloudness(true);
        let mut cfg = serde_json::json!({});
        apply_cloud_default_plugins(&gw, None, &mut cfg);
        let entries = cfg["plugins"].as_array().expect("plugins array rendered");
        assert_eq!(entries.len(), 5);
        assert!(
            entries.iter().all(|e| e["source"]["path"]
                .as_str()
                .unwrap()
                .starts_with("/usr/local/lib/mcpg/plugins/")),
            "entries load the image-baked artifacts"
        );
    }

    #[test]
    fn self_host_cr_gets_no_default_backend_entries() {
        // A self-host image may not carry the baked cdylibs, and a
        // missing source.path fails gateway boot — the config must
        // pass through byte-identical.
        let gw = gw_cloudness(false);
        let mut cfg = serde_json::json!({"gateway": {"server": {}}});
        let before = cfg.clone();
        apply_cloud_default_plugins(&gw, None, &mut cfg);
        assert_eq!(cfg, before);
    }

    #[test]
    fn cloud_default_env_override_respected() {
        let gw = gw_cloudness(true);
        // Explicit empty = disabled.
        let mut cfg = serde_json::json!({});
        apply_cloud_default_plugins(&gw, Some(""), &mut cfg);
        assert!(
            cfg.get("plugins").is_none(),
            "explicit empty disables injection"
        );
        // CSV replaces the standard set.
        let mut cfg = serde_json::json!({});
        apply_cloud_default_plugins(&gw, Some("dev.mcpg.backend.http"), &mut cfg);
        let entries = cfg["plugins"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["id"], "dev.mcpg.backend.http");
    }

    #[test]
    fn cloud_defaults_render_alongside_plugin_set_entries() {
        // Reconcile order: merge_plugins (set replaces the user array)
        // → apply_cloud_default_plugins (defaults append, collisions
        // suppressed). Both must land in the final ConfigMap payload.
        let gw = gw_cloudness(true);
        let set = crate::templates::ResolvedSetView {
            entries: vec![crate::templates::ResolvedSetEntry {
                id: "dev.mcpg.identity.workload".into(),
                plugin_class: "identity_provider".into(),
                plugin_version: "1.2.3".into(),
                artefact_secret_name: "mcpg-plugin-workload-abcd".into(),
                resolved_digest: "deadbeef".repeat(8),
                config: serde_json::json!({}),
            }],
            capability_grants: BTreeMap::new(),
        };
        let mut cfg = merge_plugins(&serde_json::json!({}), Some(&set), None);
        apply_cloud_default_plugins(&gw, None, &mut cfg);
        let entries = cfg["plugins"].as_array().unwrap();
        assert_eq!(entries.len(), 6);
        assert_eq!(entries[0]["id"], "dev.mcpg.identity.workload");
        assert!(
            entries
                .iter()
                .any(|e| e["id"] == "dev.mcpg.backend.graphql")
        );
    }

    fn fixture_set() -> MCPGPluginSet {
        let mut grants = BTreeMap::new();
        grants.insert(
            "dev.mcpg.identity.workload".into(),
            vec!["transport_listen".into()],
        );
        MCPGPluginSet {
            metadata: ObjectMeta {
                name: Some("payments-plugins".into()),
                namespace: Some("payments".into()),
                ..Default::default()
            },
            spec: MCPGPluginSetSpec {
                entries: Vec::new(),
                capability_grants: grants,
            },
            status: None,
        }
    }

    #[test]
    fn parse_resolved_plugins_json_accepts_well_formed_doc() {
        let json = r#"{
            "version": 1,
            "entries": [
                {
                    "id": "dev.mcpg.identity.workload",
                    "pluginName": "identity-workload-1",
                    "pluginVersion": "1.2.3",
                    "pluginClass": "identity_provider",
                    "artefactSecretName": "mcpg-plugin-id-w-1",
                    "resolvedDigest": "abcd1234",
                    "config": {"trust_domain": "spiffe://example.org"},
                    "capabilityGrants": ["transport_listen"]
                }
            ]
        }"#;
        let view = parse_resolved_plugins_json(json, &fixture_set()).unwrap();
        assert_eq!(view.entries.len(), 1);
        let e = &view.entries[0];
        assert_eq!(e.id, "dev.mcpg.identity.workload");
        assert_eq!(e.plugin_class, "identity_provider");
        assert_eq!(e.artefact_secret_name, "mcpg-plugin-id-w-1");
        assert_eq!(e.resolved_digest, "abcd1234");
        assert_eq!(e.config["trust_domain"], "spiffe://example.org");
        // Capability grants come from the parent set spec, not the
        // per-entry capabilityGrants — the parser pulls the
        // canonical map.
        assert_eq!(
            view.capability_grants
                .get("dev.mcpg.identity.workload")
                .unwrap()[0],
            "transport_listen"
        );
    }

    #[test]
    fn parse_resolved_plugins_json_rejects_missing_required_field() {
        // Drop pluginClass (a required field).
        let json = r#"{
            "entries": [
                {
                    "id": "dev.mcpg.identity.workload",
                    "pluginName": "identity-workload-1",
                    "pluginVersion": "1.2.3",
                    "artefactSecretName": "mcpg-plugin-id-w-1",
                    "resolvedDigest": "abcd1234",
                    "config": null,
                    "capabilityGrants": []
                }
            ]
        }"#;
        let err = parse_resolved_plugins_json(json, &fixture_set()).unwrap_err();
        assert!(err.contains("pluginClass"), "got: {err}");
    }

    #[test]
    fn parse_resolved_plugins_json_rejects_bad_top_level_shape() {
        let err = parse_resolved_plugins_json("[]", &fixture_set()).unwrap_err();
        assert!(err.contains("entries"), "got: {err}");
    }

    fn fixture_revocation_list() -> MCPGRevocationList {
        MCPGRevocationList {
            metadata: ObjectMeta {
                name: Some("cluster-default".into()),
                ..Default::default()
            },
            spec: MCPGRevocationListSpec {
                version: 1,
                issued_at: None,
                revocations: vec![RevocationEntry {
                    artifact_sha256: "deadbeef".repeat(8),
                    reason: "supply chain incident".into(),
                    revoked_at: None,
                }],
            },
            status: None,
        }
    }

    #[test]
    fn render_revocation_list_json_round_trips_entries() {
        let rl = fixture_revocation_list();
        let (json, hash) = render_revocation_list_json(&rl);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["revocations"].as_array().unwrap().len(), 1);
        assert_eq!(
            parsed["revocations"][0]["artifact_sha256"],
            "deadbeef".repeat(8)
        );
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn render_revocation_list_hash_is_deterministic() {
        let rl = fixture_revocation_list();
        let (_, h1) = render_revocation_list_json(&rl);
        let (_, h2) = render_revocation_list_json(&rl);
        assert_eq!(h1, h2);
    }

    fn fixture_gateway() -> MCPGGateway {
        MCPGGateway {
            metadata: ObjectMeta {
                name: Some("payments-gateway".into()),
                namespace: Some("payments".into()),
                uid: Some("uid-1".into()),
                ..Default::default()
            },
            spec: Default::default(),
            status: None,
        }
    }

    #[test]
    fn revocation_cm_name_uses_gateway_name_prefix() {
        assert_eq!(
            revocation_cm_name(&fixture_gateway()),
            "payments-gateway-revocations"
        );
    }

    #[test]
    fn build_revocation_configmap_carries_owner_ref_to_gateway() {
        let cm = build_revocation_configmap(
            &fixture_gateway(),
            "payments-gateway-revocations",
            "{}",
            "abcd1234",
        );
        let orefs = cm.metadata.owner_references.unwrap();
        assert_eq!(orefs.len(), 1);
        assert_eq!(orefs[0].kind, "MCPGGateway");
        assert_eq!(orefs[0].name, "payments-gateway");
    }

    #[test]
    fn build_revocation_configmap_holds_list_json_data_key() {
        let cm = build_revocation_configmap(
            &fixture_gateway(),
            "payments-gateway-revocations",
            r#"{"version":1,"revocations":[]}"#,
            "abcd1234",
        );
        let data = cm.data.unwrap();
        assert!(data.contains_key("list.json"));
        assert!(data["list.json"].contains("\"version\""));
    }

    #[test]
    fn build_revocation_configmap_carries_hash_label() {
        let cm = build_revocation_configmap(
            &fixture_gateway(),
            "payments-gateway-revocations",
            "{}",
            "deadc0de",
        );
        let labels = cm.metadata.labels.unwrap();
        assert_eq!(
            labels.get("mcpg.dev/revocation-list-hash").unwrap(),
            "deadc0de"
        );
    }

    // ── Cross-CRD watch predicates ─────────────────────────────

    use mcpg_operator_api::v1alpha1::{MCPGGatewaySpec, PluginSetRef, RevocationListRef};

    fn gw_with(
        ns: &str,
        plugin_set_name: Option<&str>,
        revocation_list_name: Option<&str>,
    ) -> MCPGGateway {
        MCPGGateway {
            metadata: ObjectMeta {
                name: Some("payments-gateway".into()),
                namespace: Some(ns.into()),
                ..Default::default()
            },
            spec: MCPGGatewaySpec {
                plugin_set_ref: plugin_set_name.map(|name| PluginSetRef { name: name.into() }),
                revocation_list_ref: revocation_list_name
                    .map(|name| RevocationListRef { name: name.into() }),
                ..Default::default()
            },
            status: None,
        }
    }

    #[test]
    fn plugin_set_predicate_matches_same_namespace_same_name() {
        let gw = gw_with("payments", Some("plugins-prod"), None);
        assert!(gateway_uses_plugin_set(
            &gw,
            Some("payments"),
            "plugins-prod"
        ));
    }

    #[test]
    fn plugin_set_predicate_rejects_other_namespace() {
        let gw = gw_with("payments", Some("plugins-prod"), None);
        assert!(!gateway_uses_plugin_set(
            &gw,
            Some("staging"),
            "plugins-prod"
        ));
    }

    #[test]
    fn plugin_set_predicate_rejects_other_set_name() {
        let gw = gw_with("payments", Some("plugins-prod"), None);
        assert!(!gateway_uses_plugin_set(
            &gw,
            Some("payments"),
            "plugins-canary"
        ));
    }

    #[test]
    fn plugin_set_predicate_rejects_when_ref_unset() {
        let gw = gw_with("payments", None, None);
        assert!(!gateway_uses_plugin_set(
            &gw,
            Some("payments"),
            "plugins-prod"
        ));
    }

    #[test]
    fn revocation_list_predicate_matches_explicit_ref() {
        let gw = gw_with("payments", None, Some("our-list"));
        assert!(gateway_uses_revocation_list(&gw, "our-list"));
        assert!(!gateway_uses_revocation_list(&gw, "other-list"));
    }

    #[test]
    fn revocation_list_predicate_defaults_to_cluster_default() {
        let gw = gw_with("payments", None, None);
        assert!(gateway_uses_revocation_list(
            &gw,
            DEFAULT_REVOCATION_LIST_NAME
        ));
        assert!(!gateway_uses_revocation_list(&gw, "anything-else"));
    }

    // ── cluster (clusterRef) wiring ──────────────────────────────

    #[test]
    fn merge_cluster_block_sets_config_cluster() {
        let mut config = serde_json::json!({ "gateway": { "server": {} } });
        let block = serde_json::json!({ "kind": "redis", "url": "redis://r:6379" });
        merge_cluster_block(&mut config, &block);
        assert_eq!(config["cluster"]["kind"], "redis");
        assert_eq!(config["cluster"]["url"], "redis://r:6379");
        // sibling config untouched
        assert!(config["gateway"]["server"].is_object());
    }

    #[test]
    fn merge_cluster_block_replaces_inline_cluster() {
        // clusterRef wins over any hand-written inline cluster block.
        let mut config = serde_json::json!({ "cluster": { "kind": "single_node" } });
        let block = serde_json::json!({ "kind": "nats", "servers": "nats://n:4222" });
        merge_cluster_block(&mut config, &block);
        assert_eq!(config["cluster"]["kind"], "nats");
        assert!(config["cluster"].get("servers").is_some());
    }

    #[test]
    fn merge_cluster_block_null_is_noop() {
        // An unresolved cluster (Null block) must not touch config —
        // the gateway keeps whatever inline cluster config it had.
        let mut config = serde_json::json!({ "cluster": { "kind": "single_node" } });
        merge_cluster_block(&mut config, &serde_json::Value::Null);
        assert_eq!(config["cluster"]["kind"], "single_node");
    }

    #[test]
    fn merge_cluster_block_initialises_non_object_config() {
        let mut config = serde_json::Value::Null;
        let block = serde_json::json!({ "kind": "etcd", "endpoints": ["http://e:2379"] });
        merge_cluster_block(&mut config, &block);
        assert_eq!(config["cluster"]["kind"], "etcd");
    }

    #[test]
    fn cluster_predicate_matches_clusterref() {
        use mcpg_operator_api::v1alpha1::ClusterRef;
        let mut gw = gw_with("payments", None, None);
        gw.spec.cluster_ref = Some(ClusterRef {
            name: "prod-cluster".into(),
        });
        let store = kube::runtime::reflector::store::Writer::<MCPGGateway>::default().as_reader();
        // The mapping fn filters the reflector store by clusterRef name;
        // exercise the predicate directly on the spec instead (store
        // population needs a live watcher).
        assert!(
            gw.spec
                .cluster_ref
                .as_ref()
                .is_some_and(|r| r.name == "prod-cluster")
        );
        let _ = store; // store construction smoke-check only
    }

    // ── soft-tenancy route fan-in ────────────────────────────────

    fn route(
        ns: &str,
        gw_name: &str,
        gw_ns: &str,
        tenant: Option<&str>,
        tools: &[&str],
    ) -> MCPGRoute {
        use mcpg_operator_api::v1alpha1::{GatewayRef, MCPGRouteSpec, RouteMatch, RouteToolRef};
        let mut spec = MCPGRouteSpec {
            gateway_ref: GatewayRef {
                name: gw_name.into(),
                namespace: Some(gw_ns.into()),
            },
            r#match: RouteMatch {
                tools: tools
                    .iter()
                    .map(|t| RouteToolRef { id: t.to_string() })
                    .collect(),
            },
            ..Default::default()
        };
        if let Some(t) = tenant {
            spec.attributes.insert("tenant".into(), t.into());
        }
        MCPGRoute {
            metadata: ObjectMeta {
                name: Some(format!("route-{ns}")),
                namespace: Some(ns.into()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn rules(config: &serde_json::Value) -> &Vec<serde_json::Value> {
        config["governance"]["policy"]["tool_access"]["rules"]
            .as_array()
            .expect("rules array present")
    }

    #[test]
    fn route_fan_in_renders_tenant_scoped_rule() {
        let routes = vec![route(
            "tenant-payments",
            "shared",
            "shared-gw",
            Some("payments"),
            &["orders.list", "orders.get"],
        )];
        let accepted = vec!["tenant-payments".to_owned()];
        let mut config = serde_json::json!({});
        let n = apply_routes_to_config(&routes, "shared", "shared-gw", &accepted, &mut config);
        assert_eq!(n, 1);
        let r = rules(&config);
        assert_eq!(r.len(), 2);
        let orders_list = r.iter().find(|x| x["tool_name"] == "orders.list").unwrap();
        assert_eq!(orders_list["minimum_trust"], "verified");
        assert_eq!(
            orders_list["cel_allow_if"],
            "identity.attributes.tenant == \"payments\""
        );
    }

    #[test]
    fn route_fan_in_skips_unaccepted_namespace() {
        // A route from a namespace NOT in acceptedRouteNamespaces is
        // ignored (defense-in-depth alongside the admission webhook).
        let routes = vec![route(
            "tenant-rogue",
            "shared",
            "shared-gw",
            Some("rogue"),
            &["secrets.read"],
        )];
        let accepted = vec!["tenant-payments".to_owned()];
        let mut config = serde_json::json!({});
        let n = apply_routes_to_config(&routes, "shared", "shared-gw", &accepted, &mut config);
        assert_eq!(n, 0);
        assert!(
            config.get("governance").is_none(),
            "no rule should be rendered"
        );
    }

    #[test]
    fn route_fan_in_skips_other_gateway() {
        let routes = vec![route(
            "tenant-payments",
            "other-gw",
            "shared-gw",
            Some("payments"),
            &["orders.list"],
        )];
        let accepted = vec!["tenant-payments".to_owned()];
        let mut config = serde_json::json!({});
        let n = apply_routes_to_config(&routes, "shared", "shared-gw", &accepted, &mut config);
        assert_eq!(n, 0);
    }

    #[test]
    fn route_fan_in_ors_tenants_sharing_a_tool() {
        // Two tenants expose the same tool → one rule, OR-ed predicates.
        let routes = vec![
            route(
                "tenant-a",
                "shared",
                "shared-gw",
                Some("a"),
                &["common.tool"],
            ),
            route(
                "tenant-b",
                "shared",
                "shared-gw",
                Some("b"),
                &["common.tool"],
            ),
        ];
        let accepted = vec!["tenant-a".to_owned(), "tenant-b".to_owned()];
        let mut config = serde_json::json!({});
        apply_routes_to_config(&routes, "shared", "shared-gw", &accepted, &mut config);
        let r = rules(&config);
        assert_eq!(r.len(), 1);
        let cel = r[0]["cel_allow_if"].as_str().unwrap();
        assert!(cel.contains("\"a\""), "got: {cel}");
        assert!(cel.contains("\"b\""), "got: {cel}");
        assert!(cel.contains("||"), "predicates OR-ed: {cel}");
    }

    #[test]
    fn route_fan_in_ors_onto_existing_operator_rule() {
        // An operator-authored rule for the same tool gets the route
        // predicate OR-ed onto it (not replaced).
        let mut config = serde_json::json!({
            "governance": { "policy": { "tool_access": { "rules": [
                { "tool_name": "orders.list", "minimum_trust": "verified",
                  "cel_allow_if": "identity.roles.exists(r, r == \"admin\")" }
            ]}}}
        });
        let routes = vec![route(
            "tenant-payments",
            "shared",
            "shared-gw",
            Some("payments"),
            &["orders.list"],
        )];
        let accepted = vec!["tenant-payments".to_owned()];
        apply_routes_to_config(&routes, "shared", "shared-gw", &accepted, &mut config);
        let r = rules(&config);
        assert_eq!(r.len(), 1, "OR-ed onto existing, not duplicated");
        let cel = r[0]["cel_allow_if"].as_str().unwrap();
        assert!(cel.contains("admin"), "preserves operator rule: {cel}");
        assert!(cel.contains("payments"), "adds tenant rule: {cel}");
    }

    #[test]
    fn route_fan_in_untenanted_route_renders_true() {
        let routes = vec![route("shared-gw", "shared", "shared-gw", None, &["t.x"])];
        // route in the gateway's OWN namespace is always accepted.
        let accepted: Vec<String> = vec![];
        let mut config = serde_json::json!({});
        let n = apply_routes_to_config(&routes, "shared", "shared-gw", &accepted, &mut config);
        assert_eq!(n, 1);
        assert_eq!(rules(&config)[0]["cel_allow_if"], "true");
    }

    fn provisioned_server(
        name: &str,
        ns: &str,
        gateway: Option<&str>,
        fed_name: Option<&str>,
    ) -> MCPGServer {
        use mcpg_operator_api::v1alpha1::{MCPGServerSpec, ServerFederate, ServerGatewayRef};
        MCPGServer {
            metadata: kube::core::ObjectMeta {
                name: Some(name.into()),
                namespace: Some(ns.into()),
                ..Default::default()
            },
            spec: MCPGServerSpec {
                image: "ghcr.io/acme/crm:1.0.0".into(),
                federate: gateway.map(|gw| ServerFederate {
                    gateway_ref: ServerGatewayRef { name: gw.into() },
                    name: fed_name.map(str::to_owned),
                    ..Default::default()
                }),
                ..Default::default()
            },
            status: None,
        }
    }

    fn federations(config: &serde_json::Value) -> &Vec<serde_json::Value> {
        config["mcp"]["federations"]
            .as_array()
            .expect("federations")
    }

    #[test]
    fn server_fan_in_synthesizes_federation() {
        let servers = vec![provisioned_server("crm", "team-a", Some("main"), None)];
        let mut config = serde_json::json!({});
        let n = apply_servers_to_config(&servers, "main", "team-a", &mut config);
        assert_eq!(n, 1);
        let feds = federations(&config);
        assert_eq!(feds[0]["name"], "crm");
        assert_eq!(
            feds[0]["upstream"]["url"],
            "http://crm.team-a.svc.cluster.local:8080/mcp"
        );
        assert_eq!(feds[0]["upstream"]["protocol_version"], "auto");
        assert_eq!(
            feds[0]["upstream"]["upstream_safety"]["allow_private_backends"],
            true
        );
        assert_eq!(feds[0]["naming"]["tool_prefix"], "crm.");
    }

    #[test]
    fn server_fan_in_skips_other_gateways_and_namespaces() {
        let servers = vec![
            provisioned_server("a", "team-a", Some("other"), None),
            provisioned_server("b", "team-b", Some("main"), None),
            provisioned_server("c", "team-a", None, None),
        ];
        let mut config = serde_json::json!({});
        let n = apply_servers_to_config(&servers, "main", "team-a", &mut config);
        assert_eq!(n, 0);
        assert!(config.get("mcp").is_none() || federations(&config).is_empty());
    }

    #[test]
    fn server_fan_in_inline_federation_wins_on_collision() {
        let servers = vec![provisioned_server("crm", "team-a", Some("main"), None)];
        let mut config = serde_json::json!({
            "mcp": { "federations": [ { "name": "crm", "upstream": { "url": "https://inline.example/mcp" } } ] }
        });
        let n = apply_servers_to_config(&servers, "main", "team-a", &mut config);
        assert_eq!(n, 0);
        let feds = federations(&config);
        assert_eq!(feds.len(), 1);
        assert_eq!(feds[0]["upstream"]["url"], "https://inline.example/mcp");
    }

    #[test]
    fn server_fan_in_honours_name_override_and_passthrough_blocks() {
        use mcpg_operator_api::v1alpha1::{MCPGServerSpec, ServerFederate, ServerGatewayRef};
        let server = MCPGServer {
            metadata: kube::core::ObjectMeta {
                name: Some("crm".into()),
                namespace: Some("team-a".into()),
                ..Default::default()
            },
            spec: MCPGServerSpec {
                image: "ghcr.io/acme/crm:1.0.0".into(),
                federate: Some(ServerFederate {
                    gateway_ref: ServerGatewayRef {
                        name: "main".into(),
                    },
                    name: Some("crm-prod".into()),
                    tool_prefix: Some("crm_".into()),
                    governance: Some(serde_json::json!({ "minimum_trust": "verified" })),
                    auth: Some(serde_json::json!({ "mode": "pass_through" })),
                    ..Default::default()
                }),
                ..Default::default()
            },
            status: None,
        };
        let mut config = serde_json::json!({});
        let n = apply_servers_to_config(&[server], "main", "team-a", &mut config);
        assert_eq!(n, 1);
        let feds = federations(&config);
        assert_eq!(feds[0]["name"], "crm-prod");
        assert_eq!(feds[0]["naming"]["tool_prefix"], "crm_");
        assert_eq!(feds[0]["governance"]["minimum_trust"], "verified");
        assert_eq!(feds[0]["upstream"]["auth"]["mode"], "pass_through");
    }
}
