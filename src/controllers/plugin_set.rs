//! `MCPGPluginSet` controller — resolves cluster-scoped
//! `MCPGPlugin` references into per-namespace plugin Secrets that
//! gateway pods mount, plus a resolved-set ConfigMap that the
//! gateway controller reads to render the gateway's
//! `plugins[]` block.
//!
//! Reconcile flow:
//!
//! 1. For each `spec.entries[]`, resolve the cluster-scoped
//!    `MCPGPlugin` by name. Reject entries whose plugin is
//!    missing, not Ready, revoked, or whose declared id
//!    diverges from the plugin's `spec.pluginId`.
//! 2. For every successfully resolved entry, copy the operator-
//!    namespace plugin Secret into the consuming namespace
//!    (per the locked design decision — operator-side
//!    cross-namespace copy, not projected mounts).
//! 3. Render a resolved-set ConfigMap so the gateway controller
//!    can consume the entries without re-resolving.
//! 4. Reconcile-time prune stale per-namespace Secrets — an
//!    entry that was removed since the last reconcile leaves
//!    behind a Secret that no longer matches the desired set.
//!    The prune step compares the desired set against the
//!    operator's labeled Secrets in the namespace.
//! 5. Patch status: conditions, resolvedEntries, totalEntries,
//!    resolvedHash, failedEntries.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use futures::StreamExt;
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use kube::api::{Api, DeleteParams, ListParams};
use kube::core::ObjectMeta;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::events::{Event as K8sEvent, EventType};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher;
use kube::{Resource, ResourceExt};
use mcpg_operator_api::conditions::{Condition, reasons, types as ctype};
use mcpg_operator_api::v1alpha1::{FailedEntry, MCPGPlugin, MCPGPluginSet, MCPGPluginSetStatus};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, instrument, warn};

use crate::FIELD_MANAGER_PREFIX;
use crate::controllers::gateway::ControllerContext;
use crate::reconcile::{
    OPERATOR_FINALIZER, apply_owned, ensure_finalizer, patch_status, remove_finalizer,
};
use crate::telemetry::ReconcileOutcome;

const FIELD_MANAGER_SUFFIX: &str = "plugin-set-controller";
const CONTROLLER_NAME: &str = "plugin-set";

/// Label applied to every Secret + ConfigMap the controller
/// materialises in a tenant namespace. Used for prune-time
/// "is this resource ours?" identification.
const MANAGED_BY_SET_LABEL: &str = "mcpg.dev/managed-by-set";

/// Label that records the SHA-256 of the resolved set. Lets ops
/// dashboards compare across namespaces + lets the gateway
/// controller detect "set changed → roll pods".
const RESOLVED_HASH_LABEL: &str = "mcpg.dev/resolved-hash";

/// Reasons the per-entry resolution can fail. Each surfaces as
/// a `MCPGPluginSet.status.failedEntries[].reason` value
/// (CamelCase per K8s convention).
mod fail_reason {
    pub const PLUGIN_NOT_FOUND: &str = "PluginNotFound";
    pub const PLUGIN_NOT_READY: &str = "PluginNotReady";
    pub const PLUGIN_REVOKED: &str = "PluginRevoked";
    pub const PLUGIN_ID_MISMATCH: &str = "PluginIdMismatch";
    pub const ARTEFACT_SECRET_MISSING: &str = "ArtefactSecretMissing";
}

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("kube: {0}")]
    Kube(#[from] kube::Error),
    #[error("apply: {0}")]
    Apply(#[from] crate::reconcile::ApplyError),
    #[error("status: {0}")]
    Status(#[from] crate::reconcile::StatusError),
    #[error("finalizer: {0}")]
    Finalizer(#[from] crate::reconcile::FinalizerError),
    #[error("missing name on MCPGPluginSet")]
    MissingName,
    #[error("missing namespace on MCPGPluginSet/{name}")]
    MissingNamespace { name: String },
    /// Tenant RoleBinding ensure failed.
    /// Without it, Secret materialisation in the tenant namespace
    /// will hit `Forbidden` because the operator's cluster-wide
    /// `secrets [create, patch, delete]` was dropped. Surface as
    /// transient — the next reconcile retries.
    #[error("tenant rbac: {0}")]
    TenantRbac(kube::Error),
}

/// Run the plugin-set controller until cancelled.
pub async fn run(ctx: Arc<ControllerContext>) -> anyhow::Result<()> {
    let api: Api<MCPGPluginSet> = match ctx.config.watch_namespace.as_deref() {
        Some(ns) if !ns.is_empty() => Api::namespaced(ctx.client.clone(), ns),
        _ => Api::all(ctx.client.clone()),
    };

    info!(
        watch_scope = ?ctx.config.watch_namespace.as_deref().unwrap_or("ALL"),
        "starting plugin-set controller"
    );

    let controller = Controller::new(api, watcher::Config::default());
    let set_store = controller.store();

    controller
        .owns(
            Api::<Secret>::all(ctx.client.clone()),
            watcher::Config::default(),
        )
        .owns(
            Api::<ConfigMap>::all(ctx.client.clone()),
            watcher::Config::default(),
        )
        .watches(
            Api::<MCPGPlugin>::all(ctx.client.clone()),
            watcher::Config::default(),
            {
                let store = set_store.clone();
                move |plugin: MCPGPlugin| map_plugin_to_plugin_sets(&store, plugin)
            },
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => info!(
                    namespace = obj.namespace.as_deref().unwrap_or(""),
                    name = %obj.name,
                    "plugin-set reconcile complete"
                ),
                Err(err) => error!(error = ?err, "plugin-set reconcile failed"),
            }
        })
        .await;
    Ok(())
}

#[instrument(
    skip_all,
    fields(
        namespace = %obj.namespace().unwrap_or_default(),
        name = %obj.name_any(),
        generation = obj.metadata.generation.unwrap_or(0),
    )
)]
async fn reconcile(
    obj: Arc<MCPGPluginSet>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let started = Instant::now();
    let metrics = ctx.metrics.operator_metrics().clone();
    let result = reconcile_inner(obj, ctx).await;
    let outcome = match &result {
        Ok((_, o)) => *o,
        Err(ReconcileError::MissingName) | Err(ReconcileError::MissingNamespace { .. }) => {
            ReconcileOutcome::PermanentError
        }
        Err(_) => ReconcileOutcome::TransientError,
    };
    metrics.observe_reconcile(CONTROLLER_NAME, outcome, started.elapsed().as_secs_f64());
    result.map(|(action, _)| action)
}

async fn reconcile_inner(
    obj: Arc<MCPGPluginSet>,
    ctx: Arc<ControllerContext>,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    let name = obj
        .metadata
        .name
        .clone()
        .ok_or(ReconcileError::MissingName)?;
    let namespace = obj
        .namespace()
        .ok_or_else(|| ReconcileError::MissingNamespace { name: name.clone() })?;
    let observed_generation = obj.metadata.generation.unwrap_or(0);
    let set_api: Api<MCPGPluginSet> = Api::namespaced(ctx.client.clone(), &namespace);

    // Step 0: deletion-timestamp branch + finalizer management.
    // Per-namespace plugin Secrets + the resolved-set ConfigMap
    // are owner-ref'd to this MCPGPluginSet, so K8s GC handles
    // cascade-delete. The finalizer just blocks removal until
    // we've patched a final-state status.
    if obj.metadata.deletion_timestamp.is_some() {
        info!(
            name = %name,
            namespace = %namespace,
            "plugin-set deletion in progress; releasing finalizer"
        );
        remove_finalizer(&set_api, &name, OPERATOR_FINALIZER).await?;
        return Ok((Action::await_change(), ReconcileOutcome::Success));
    }
    ensure_finalizer(&set_api, &name, obj.as_ref(), OPERATOR_FINALIZER).await?;

    let plugin_api: Api<MCPGPlugin> = Api::all(ctx.client.clone());

    // Steps 1-2: resolve each entry in spec order.
    let mut resolved: Vec<ResolvedEntry> = Vec::new();
    let mut failed: Vec<FailedEntry> = Vec::new();
    for entry in &obj.spec.entries {
        if !entry.enabled {
            // Disabled entries pass through to status without
            // consuming any cluster lookups — operators see them
            // in `kubectl get` but the controller skips
            // materialisation.
            debug!(
                entry_id = %entry.id,
                plugin = %entry.plugin_ref.name,
                "plugin-set: entry disabled, skipping"
            );
            continue;
        }

        match resolve_entry(&plugin_api, entry).await {
            Ok(r) => resolved.push(r),
            Err(rejection) => {
                ctx.metrics
                    .operator_metrics()
                    .observe_dependency_unresolved(CONTROLLER_NAME, "MCPGPlugin", rejection.reason);
                failed.push(FailedEntry {
                    id: entry.id.clone(),
                    reason: rejection.reason.into(),
                    message: rejection.message,
                });
            }
        }
    }

    let total_entries = obj.spec.entries.len() as i64;
    let resolved_count = resolved.len() as i64;
    let all_resolved = failed.is_empty()
        && resolved_count + (total_entries - resolved_count - failed.len() as i64) == total_entries;

    // Step 3: materialise per-namespace Secret copies + the
    // resolved-set ConfigMap. Each Secret carries an owner ref
    // back to this MCPGPluginSet so deletion of the set
    // cascades.
    let secret_api: Api<Secret> = Api::namespaced(ctx.client.clone(), &namespace);
    let cm_api: Api<ConfigMap> = Api::namespaced(ctx.client.clone(), &namespace);
    let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");
    let operator_ns = operator_namespace();

    // Ensure the per-tenant RoleBinding exists *before* the
    // Secret materialisation loop. The chart grants no
    // cluster-wide `secrets [create, patch, delete]`; the
    // operator's write reach is now bounded by the
    // `mcpg-operator-tenant-secrets` ClusterRole, which only takes
    // effect in a namespace once a RoleBinding for our SA is
    // present. Idempotent — SSA refresh is cheap.
    crate::rbac::ensure_tenant_secret_binding(
        &ctx.client,
        &namespace,
        &operator_ns,
        &ctx.config.operator_service_account,
        &fm,
    )
    .await
    .map_err(|e| {
        warn!(
            namespace = %namespace,
            error = ?e,
            "plugin-set: failed to ensure tenant RoleBinding; \
             Secret materialisation will fail with Forbidden \
             until this is resolved"
        );
        ReconcileError::TenantRbac(e)
    })?;

    let mut desired_secret_names: BTreeSet<String> = BTreeSet::new();
    for r in &resolved {
        desired_secret_names.insert(r.artefact_secret_name.clone());

        // Read the source Secret from the operator namespace.
        let source_api: Api<Secret> = Api::namespaced(ctx.client.clone(), &operator_ns);
        let source = match source_api.get_opt(&r.artefact_secret_name).await? {
            Some(s) => s,
            None => {
                // Source disappeared between resolve + apply.
                // Surface as a failed entry on the next reconcile;
                // this run skips materialisation for the entry.
                warn!(
                    plugin = %r.plugin_name,
                    secret = %r.artefact_secret_name,
                    "plugin-set: source Secret vanished mid-reconcile"
                );
                continue;
            }
        };

        let copy = build_namespace_copy(&obj, &namespace, &source, r);
        apply_owned(&secret_api, &copy, &fm).await?;
    }

    // Compute the resolved-set hash + materialise the ConfigMap.
    let (resolved_doc, resolved_hash) = render_resolved_set(&obj, &resolved);
    let cm = build_resolved_configmap(&obj, &namespace, &resolved_doc, &resolved_hash);
    apply_owned(&cm_api, &cm, &fm).await?;

    // Step 4: prune stale per-namespace Secrets (entries that
    // were removed since the last reconcile).
    prune_stale_secrets(&secret_api, &name, &desired_secret_names).await;

    // Step 5: status update.
    let mut conditions = obj
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();
    if all_resolved {
        mcpg_operator_api::conditions::set_condition(
            &mut conditions,
            Condition::new(
                ctype::READY,
                "True",
                reasons::RECONCILED,
                format!("{resolved_count}/{total_entries} entries resolved"),
                Some(observed_generation),
            ),
        );
        mcpg_operator_api::conditions::set_condition(
            &mut conditions,
            Condition::new(
                "EntriesResolved",
                "True",
                reasons::RECONCILED,
                "",
                Some(observed_generation),
            ),
        );
    } else {
        let detail = if failed.is_empty() {
            format!("{resolved_count}/{total_entries} entries resolved")
        } else {
            format!(
                "{resolved_count}/{total_entries} entries resolved; {} failed",
                failed.len()
            )
        };
        mcpg_operator_api::conditions::set_condition(
            &mut conditions,
            Condition::new(
                ctype::READY,
                "False",
                reasons::PROGRESSING,
                detail.clone(),
                Some(observed_generation),
            ),
        );
        mcpg_operator_api::conditions::set_condition(
            &mut conditions,
            Condition::new(
                "EntriesResolved",
                "False",
                if failed.is_empty() {
                    reasons::DEPENDENCY_PENDING
                } else {
                    "EntriesFailed"
                },
                detail,
                Some(observed_generation),
            ),
        );
    }

    // Compute outcome before `failed` is moved into the status.
    // Disabled entries → partial resolution is intentional (Success);
    // a populated `failed` list → DependencyPending (we're waiting
    // on an upstream MCPGPlugin to become Ready / not-revoked).
    let outcome = if failed.is_empty() {
        ReconcileOutcome::Success
    } else {
        ReconcileOutcome::DependencyPending
    };

    let status = MCPGPluginSetStatus {
        conditions,
        observed_generation: Some(observed_generation),
        resolved_entries: Some(resolved_count),
        total_entries: Some(total_entries),
        resolved_hash: Some(resolved_hash),
        failed_entries: failed,
        last_reconcile_time: Some(Utc::now()),
    };
    if let Err(e) = patch_status(&set_api, &name, &status, &fm).await {
        warn!(error = ?e, "plugin-set: status patch failed");
    }

    if matches!(outcome, ReconcileOutcome::Success) {
        let evt = K8sEvent {
            type_: EventType::Normal,
            reason: "Reconciled".into(),
            note: Some(format!("{resolved_count}/{total_entries} entries resolved")),
            action: "Resolve".into(),
            secondary: None,
        };
        if let Err(e) = ctx
            .recorders
            .plugin_set
            .publish(&evt, &obj.object_ref(&()))
            .await
        {
            warn!(error = ?e, "plugin-set: failed to publish Reconciled event");
        }
        let key = crate::backoff::resource_key(CONTROLLER_NAME, &namespace, &name);
        ctx.backoff.record_success(&key);
    }

    Ok((Action::requeue(Duration::from_secs(300)), outcome))
}

fn error_policy(
    obj: Arc<MCPGPluginSet>,
    err: &ReconcileError,
    ctx: Arc<ControllerContext>,
) -> Action {
    match err {
        ReconcileError::MissingName | ReconcileError::MissingNamespace { .. } => {
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
                "plugin-set: reconcile error; backing off"
            );
            Action::requeue(delay)
        }
    }
}

/// True when `set` has at least one entry whose
/// `plugin_ref.name` matches the given plugin name.
fn plugin_set_references(set: &MCPGPluginSet, plugin_name: &str) -> bool {
    set.spec
        .entries
        .iter()
        .any(|e| e.plugin_ref.name == plugin_name)
}

/// Mapper for `Controller::watches(MCPGPlugin, ...)`. Given a
/// changed cluster-scoped plugin, returns every plugin set whose
/// entries reference it. The set's plugin entries use a
/// `LocalObjectReference.name` so we filter by that field; the
/// plugin set is namespace-scoped but the plugin reference is
/// cluster-wide, so a single plugin update can fan out to plugin
/// sets in many namespaces.
fn map_plugin_to_plugin_sets(
    store: &kube::runtime::reflector::Store<MCPGPluginSet>,
    plugin: MCPGPlugin,
) -> Vec<ObjectRef<MCPGPluginSet>> {
    let plugin_name = match plugin.metadata.name.as_deref() {
        Some(n) => n,
        None => return Vec::new(),
    };
    store
        .state()
        .into_iter()
        .filter(|set| plugin_set_references(set, plugin_name))
        .map(|set| ObjectRef::from_obj(&*set))
        .collect()
}

// ─────────────────────────────────────────────────────────────────
// Resolution
// ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ResolvedEntry {
    /// Operator-supplied id from the entry (matches the plugin's
    /// `spec.pluginId`).
    entry_id: String,
    /// Cluster-scoped `MCPGPlugin` resource name.
    plugin_name: String,
    /// Plugin's reported `spec.version`.
    plugin_version: String,
    /// Plugin's reported `spec.pluginClass` (e.g. `identity_provider`,
    /// `policy_engine`). Carried through so the gateway controller
    /// can register each entry into the right plugin chain without
    /// re-fetching the cluster-scoped MCPGPlugin.
    plugin_class: String,
    /// Resolved Secret name in the operator namespace.
    artefact_secret_name: String,
    /// Resolved cdylib digest (SHA-256 hex).
    resolved_digest: String,
    /// Operator-supplied per-entry config (untyped — gateway
    /// validates schema per plugin).
    config: serde_json::Value,
}

#[derive(Debug, Clone)]
struct EntryRejection {
    reason: &'static str,
    message: String,
}

async fn resolve_entry(
    plugin_api: &Api<MCPGPlugin>,
    entry: &mcpg_operator_api::v1alpha1::MCPGPluginSetEntry,
) -> Result<ResolvedEntry, EntryRejection> {
    let plugin = match plugin_api.get_opt(&entry.plugin_ref.name).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Err(EntryRejection {
                reason: fail_reason::PLUGIN_NOT_FOUND,
                message: format!("MCPGPlugin/{} does not exist", entry.plugin_ref.name),
            });
        }
        Err(e) => {
            return Err(EntryRejection {
                reason: fail_reason::PLUGIN_NOT_FOUND,
                message: format!("MCPGPlugin/{} lookup failed: {e}", entry.plugin_ref.name),
            });
        }
    };

    if plugin.spec.plugin_id != entry.id {
        return Err(EntryRejection {
            reason: fail_reason::PLUGIN_ID_MISMATCH,
            message: format!(
                "entry.id `{}` != MCPGPlugin/{}.spec.pluginId `{}`",
                entry.id, entry.plugin_ref.name, plugin.spec.plugin_id
            ),
        });
    }

    let status = plugin.status.as_ref();
    let revoked = status.and_then(|s| s.revoked_by_sha).unwrap_or(false);
    if revoked {
        return Err(EntryRejection {
            reason: fail_reason::PLUGIN_REVOKED,
            message: format!(
                "MCPGPlugin/{} status.revokedBySha=true; consuming sets refuse to render",
                entry.plugin_ref.name
            ),
        });
    }

    let ready = status
        .map(|s| {
            s.conditions
                .iter()
                .any(|c| c.r#type == ctype::READY && c.status == "True")
        })
        .unwrap_or(false);
    if !ready {
        return Err(EntryRejection {
            reason: fail_reason::PLUGIN_NOT_READY,
            message: format!(
                "MCPGPlugin/{} status.conditions[Ready] != True",
                entry.plugin_ref.name
            ),
        });
    }

    let artefact_secret_name = match status.and_then(|s| s.artefact_secret_name.clone()) {
        Some(s) if !s.is_empty() => s,
        _ => {
            return Err(EntryRejection {
                reason: fail_reason::ARTEFACT_SECRET_MISSING,
                message: format!(
                    "MCPGPlugin/{} status.artefactSecretName is unset (controller hasn't materialised yet)",
                    entry.plugin_ref.name
                ),
            });
        }
    };
    let resolved_digest = status
        .and_then(|s| s.resolved_digest.clone())
        .unwrap_or_default();

    Ok(ResolvedEntry {
        entry_id: entry.id.clone(),
        plugin_name: entry.plugin_ref.name.clone(),
        plugin_version: plugin.spec.version.clone(),
        plugin_class: plugin.spec.plugin_class.clone(),
        artefact_secret_name,
        resolved_digest,
        config: entry.config.clone().unwrap_or(serde_json::Value::Null),
    })
}

// ─────────────────────────────────────────────────────────────────
// Materialisation
// ─────────────────────────────────────────────────────────────────

/// Render the resolved set into a JSON document the gateway
/// controller reads to assemble its `plugins[]` block.
/// Returns (json, sha256-hex).
fn render_resolved_set(parent: &MCPGPluginSet, resolved: &[ResolvedEntry]) -> (String, String) {
    let entries: Vec<_> = resolved
        .iter()
        .map(|r| {
            let grants = parent
                .spec
                .capability_grants
                .get(&r.entry_id)
                .cloned()
                .unwrap_or_default();
            json!({
                "id": r.entry_id,
                "pluginName": r.plugin_name,
                "pluginVersion": r.plugin_version,
                "pluginClass": r.plugin_class,
                "artefactSecretName": r.artefact_secret_name,
                "resolvedDigest": r.resolved_digest,
                "config": r.config,
                "capabilityGrants": grants,
            })
        })
        .collect();

    // version=1 lets us bump the doc shape later without
    // breaking the gateway controller's parser.
    let doc = json!({
        "version": 1,
        "entries": entries,
    });
    let json = serde_json::to_string_pretty(&doc).expect("serde_json::Map → String never fails");

    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    (json, hex::encode(hasher.finalize()))
}

fn build_namespace_copy(
    parent: &MCPGPluginSet,
    namespace: &str,
    source: &Secret,
    entry: &ResolvedEntry,
) -> Secret {
    let mut labels: BTreeMap<String, String> = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".into(),
        "mcpg-operator".into(),
    );
    labels.insert(
        MANAGED_BY_SET_LABEL.into(),
        parent
            .metadata
            .name
            .clone()
            .unwrap_or_else(|| "unknown".into()),
    );
    labels.insert("mcpg.dev/plugin".into(), entry.entry_id.replace('.', "-"));
    labels.insert("mcpg.dev/version".into(), entry.plugin_version.clone());
    labels.insert("mcpg.dev/source-namespace".into(), operator_namespace());

    let owner_ref = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
        api_version: "mcpg.dev/v1alpha1".into(),
        kind: "MCPGPluginSet".into(),
        name: parent.metadata.name.clone().unwrap_or_default(),
        uid: parent.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    };

    Secret {
        metadata: ObjectMeta {
            name: Some(entry.artefact_secret_name.clone()),
            namespace: Some(namespace.to_owned()),
            labels: Some(labels),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        type_: Some("mcpg.dev/plugin".into()),
        // Same rationale as the operator-namespace plugin Secret:
        // bytes are content-addressed, marking immutable lets the
        // kubelet skip the per-mount fsnotify watch + the
        // apiserver reject any UPDATE.
        immutable: Some(true),
        data: source.data.clone(),
        ..Default::default()
    }
}

fn build_resolved_configmap(
    parent: &MCPGPluginSet,
    namespace: &str,
    rendered: &str,
    resolved_hash: &str,
) -> ConfigMap {
    let mut labels: BTreeMap<String, String> = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".into(),
        "mcpg-operator".into(),
    );
    let parent_name = parent
        .metadata
        .name
        .clone()
        .unwrap_or_else(|| "unknown".into());
    labels.insert(MANAGED_BY_SET_LABEL.into(), parent_name.clone());
    labels.insert(RESOLVED_HASH_LABEL.into(), resolved_hash.to_owned());

    let owner_ref = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
        api_version: "mcpg.dev/v1alpha1".into(),
        kind: "MCPGPluginSet".into(),
        name: parent_name.clone(),
        uid: parent.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    };

    let mut data = BTreeMap::new();
    data.insert("plugins.json".into(), rendered.to_owned());

    ConfigMap {
        metadata: ObjectMeta {
            name: Some(format!("{parent_name}-resolved")),
            namespace: Some(namespace.to_owned()),
            labels: Some(labels),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}

// ─────────────────────────────────────────────────────────────────
// Pruning
// ─────────────────────────────────────────────────────────────────

/// Delete any Secret in the namespace labelled
/// `mcpg.dev/managed-by-set: <set-name>` whose name is NOT in
/// the desired set. Errors are logged, not propagated — a
/// failed prune doesn't block the rest of the reconcile.
async fn prune_stale_secrets(api: &Api<Secret>, set_name: &str, desired: &BTreeSet<String>) {
    let lp = ListParams::default().labels(&format!("{MANAGED_BY_SET_LABEL}={set_name}"));
    let existing = match api.list(&lp).await {
        Ok(l) => l,
        Err(e) => {
            warn!(error = ?e, "plugin-set: prune: list failed; skipping");
            return;
        }
    };

    let dp = DeleteParams::default();
    for s in existing.items {
        let Some(name) = s.metadata.name.as_ref() else {
            continue;
        };
        if desired.contains(name) {
            continue;
        }
        match api.delete(name, &dp).await {
            Ok(_) => info!(secret = %name, "plugin-set: pruned stale secret"),
            Err(e) => warn!(
                secret = %name,
                error = ?e,
                "plugin-set: prune: delete failed"
            ),
        }
    }
}

fn operator_namespace() -> String {
    // Mirrors `controllers/plugin.rs::operator_namespace`; hardcoded
    // to mcpg-system (not yet wired through OperatorConfig).
    "mcpg-system".to_owned()
}

// ─────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::ByteString;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::{
        LocalObjectReference, MCPGPluginSet as ApiSet, MCPGPluginSetEntry, MCPGPluginSetSpec,
    };

    fn fixture_set(entries: Vec<MCPGPluginSetEntry>) -> ApiSet {
        ApiSet {
            metadata: ObjectMeta {
                name: Some("payments-plugins".into()),
                namespace: Some("payments".into()),
                uid: Some("set-uid-1".into()),
                ..Default::default()
            },
            spec: MCPGPluginSetSpec {
                entries,
                capability_grants: Default::default(),
            },
            status: None,
        }
    }

    fn fixture_entry(id: &str, plugin_name: &str) -> MCPGPluginSetEntry {
        MCPGPluginSetEntry {
            id: id.into(),
            plugin_ref: LocalObjectReference {
                name: plugin_name.into(),
            },
            enabled: true,
            enforce: true,
            config: None,
        }
    }

    fn fixture_resolved(id: &str) -> ResolvedEntry {
        ResolvedEntry {
            entry_id: id.into(),
            plugin_name: format!("{id}-resource"),
            plugin_version: "1.2.3".into(),
            plugin_class: "identity_provider".into(),
            artefact_secret_name: format!("mcpg-plugin-{}-abcd1234", id.replace('.', "-")),
            resolved_digest: "abcd1234".repeat(8),
            config: serde_json::json!({}),
        }
    }

    #[test]
    fn render_resolved_set_includes_every_entry_with_grants() {
        let mut grants = BTreeMap::new();
        grants.insert(
            "dev.mcpg.identity.workload".into(),
            vec!["transport_listen".into()],
        );
        let mut set = fixture_set(vec![fixture_entry("dev.mcpg.identity.workload", "p")]);
        set.spec.capability_grants = grants;

        let resolved = vec![fixture_resolved("dev.mcpg.identity.workload")];
        let (json, hash) = render_resolved_set(&set, &resolved);

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["version"], 1);
        let entries = parsed["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry["id"], "dev.mcpg.identity.workload");
        assert_eq!(entry["pluginName"], "dev.mcpg.identity.workload-resource");
        assert_eq!(entry["pluginVersion"], "1.2.3");
        assert_eq!(entry["pluginClass"], "identity_provider");
        assert_eq!(entry["capabilityGrants"][0], "transport_listen");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn resolved_hash_is_deterministic_for_same_input() {
        let set = fixture_set(vec![fixture_entry("dev.mcpg.identity.workload", "p")]);
        let resolved = vec![fixture_resolved("dev.mcpg.identity.workload")];
        let (_, h1) = render_resolved_set(&set, &resolved);
        let (_, h2) = render_resolved_set(&set, &resolved);
        assert_eq!(h1, h2);
    }

    #[test]
    fn resolved_hash_changes_on_any_change() {
        let set = fixture_set(vec![fixture_entry("dev.mcpg.identity.workload", "p")]);
        let r1 = vec![fixture_resolved("dev.mcpg.identity.workload")];
        let mut r2 = r1.clone();
        r2[0].plugin_version = "1.2.4".into();
        let (_, h1) = render_resolved_set(&set, &r1);
        let (_, h2) = render_resolved_set(&set, &r2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn resolved_hash_changes_on_grant_addition() {
        let set1 = fixture_set(vec![fixture_entry("dev.mcpg.identity.workload", "p")]);
        let mut set2 = set1.clone();
        set2.spec.capability_grants.insert(
            "dev.mcpg.identity.workload".into(),
            vec!["transport_listen".into()],
        );
        let resolved = vec![fixture_resolved("dev.mcpg.identity.workload")];
        let (_, h1) = render_resolved_set(&set1, &resolved);
        let (_, h2) = render_resolved_set(&set2, &resolved);
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_namespace_copy_carries_owner_ref_to_set() {
        let set = fixture_set(vec![]);
        let source = Secret {
            metadata: ObjectMeta {
                name: Some("src".into()),
                ..Default::default()
            },
            data: Some({
                let mut m = BTreeMap::new();
                m.insert("plugin.so".into(), ByteString(vec![1, 2, 3]));
                m
            }),
            ..Default::default()
        };
        let entry = fixture_resolved("dev.mcpg.identity.workload");
        let copy = build_namespace_copy(&set, "payments", &source, &entry);
        let orefs = copy.metadata.owner_references.unwrap();
        assert_eq!(orefs[0].kind, "MCPGPluginSet");
        assert_eq!(orefs[0].name, "payments-plugins");
        assert_eq!(orefs[0].uid, "set-uid-1");
        assert_eq!(orefs[0].controller, Some(true));
    }

    #[test]
    fn build_namespace_copy_propagates_source_data() {
        let set = fixture_set(vec![]);
        let mut source_data = BTreeMap::new();
        source_data.insert("plugin.so".into(), ByteString(vec![0xDE, 0xAD]));
        source_data.insert("plugin.yaml".into(), ByteString(b"id: x".to_vec()));
        let source = Secret {
            metadata: ObjectMeta {
                name: Some("src".into()),
                ..Default::default()
            },
            data: Some(source_data.clone()),
            ..Default::default()
        };
        let entry = fixture_resolved("dev.mcpg.identity.workload");
        let copy = build_namespace_copy(&set, "payments", &source, &entry);
        assert_eq!(copy.data.unwrap(), source_data);
    }

    #[test]
    fn build_namespace_copy_labels_include_managed_by_set() {
        let set = fixture_set(vec![]);
        let source = Secret::default();
        let entry = fixture_resolved("dev.mcpg.identity.workload");
        let copy = build_namespace_copy(&set, "payments", &source, &entry);
        let labels = copy.metadata.labels.unwrap();
        assert_eq!(
            labels.get(MANAGED_BY_SET_LABEL).unwrap(),
            "payments-plugins"
        );
        assert_eq!(
            labels.get("mcpg.dev/plugin").unwrap(),
            "dev-mcpg-identity-workload"
        );
    }

    #[test]
    fn build_namespace_copy_marks_secret_immutable() {
        // Plugin bytes are content-addressed; the Secret should
        // never be modified once written. Immutable lets the
        // kubelet skip the fsnotify watch + lets the apiserver
        // reject any UPDATE attempt as a defence-in-depth gate.
        let set = fixture_set(vec![]);
        let source = Secret::default();
        let entry = fixture_resolved("dev.mcpg.identity.workload");
        let copy = build_namespace_copy(&set, "payments", &source, &entry);
        assert_eq!(copy.immutable, Some(true));
    }

    #[test]
    fn build_resolved_configmap_carries_resolved_hash_label() {
        let set = fixture_set(vec![]);
        let cm = build_resolved_configmap(&set, "payments", "{}", "abcd1234");
        let labels = cm.metadata.labels.unwrap();
        assert_eq!(labels.get(RESOLVED_HASH_LABEL).unwrap(), "abcd1234");
        assert_eq!(
            labels.get(MANAGED_BY_SET_LABEL).unwrap(),
            "payments-plugins"
        );
    }

    #[test]
    fn build_resolved_configmap_name_suffixed_with_resolved() {
        let set = fixture_set(vec![]);
        let cm = build_resolved_configmap(&set, "payments", "{}", "h");
        assert_eq!(
            cm.metadata.name.as_deref(),
            Some("payments-plugins-resolved")
        );
    }

    #[test]
    fn build_resolved_configmap_data_holds_plugins_json() {
        let set = fixture_set(vec![]);
        let cm = build_resolved_configmap(&set, "payments", "{\"a\":1}", "h");
        assert_eq!(cm.data.unwrap().get("plugins.json").unwrap(), "{\"a\":1}");
    }

    #[test]
    fn entry_rejection_id_mismatch_message_format() {
        // We don't have a kube client to stand up resolve_entry,
        // but we can sanity-check the EntryRejection variant
        // shape since it lands in MCPGPluginSetStatus.
        let r = EntryRejection {
            reason: fail_reason::PLUGIN_ID_MISMATCH,
            message: "entry.id `a` != ...".into(),
        };
        let fe = FailedEntry {
            id: "a".into(),
            reason: r.reason.into(),
            message: r.message,
        };
        assert_eq!(fe.reason, "PluginIdMismatch");
    }

    // ── Cross-CRD watch predicate ──────────────────────────────

    #[test]
    fn plugin_set_references_matches_referenced_plugin() {
        let set = fixture_set(vec![fixture_entry(
            "dev.mcpg.identity.workload",
            "identity-workload-1.2.3",
        )]);
        assert!(plugin_set_references(&set, "identity-workload-1.2.3"));
    }

    #[test]
    fn plugin_set_references_rejects_unrelated_plugin() {
        let set = fixture_set(vec![fixture_entry(
            "dev.mcpg.identity.workload",
            "identity-workload-1.2.3",
        )]);
        assert!(!plugin_set_references(&set, "policy-cedar-1.0.0"));
    }

    #[test]
    fn plugin_set_references_handles_empty_set() {
        let set = fixture_set(vec![]);
        assert!(!plugin_set_references(&set, "anything"));
    }

    #[test]
    fn plugin_set_references_matches_any_of_multiple_entries() {
        let set = fixture_set(vec![
            fixture_entry("dev.mcpg.identity.workload", "identity-workload"),
            fixture_entry("dev.mcpg.policy.cedar", "policy-cedar"),
        ]);
        assert!(plugin_set_references(&set, "policy-cedar"));
    }
}
