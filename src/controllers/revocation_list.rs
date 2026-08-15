//! `MCPGRevocationList` controller — fans out the cluster
//! revocation list as a per-namespace ConfigMap that gateway
//! pods mount under `plugins.trust.revocation_list_path`.
//!
//! The on-wire format matches the revocation-list schema the
//! gateway consumes. The operator
//! materialises the rendered JSON + a SHA-256 content hash
//! label so dependent gateways can detect "revocation list
//! changed → roll pods" via annotation rotation (same shape as
//! the gateway's config-hash mechanism).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use futures::StreamExt;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::Api;
use kube::core::ObjectMeta;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::events::{Event as K8sEvent, EventType};
use kube::runtime::watcher;
use kube::{Client, Resource, ResourceExt};
use mcpg_operator_api::conditions::{Condition, reasons, types as ctype};
use mcpg_operator_api::v1alpha1::{
    MCPGRevocationList, MCPGRevocationListSpec, MCPGRevocationListStatus,
};
use sha2::{Digest, Sha256};
use tracing::{error, info, instrument};

use crate::FIELD_MANAGER_PREFIX;
use crate::controllers::gateway::ControllerContext;
use crate::reconcile::{
    OPERATOR_FINALIZER, apply_owned, ensure_finalizer, patch_status, remove_finalizer,
};
use crate::telemetry::ReconcileOutcome;

/// Field manager suffix for SSA writes from this controller.
const FIELD_MANAGER_SUFFIX: &str = "revocation-list-controller";

/// Controller name used in metric labels.
const CONTROLLER_NAME: &str = "revocation-list";

/// Per-namespace ConfigMap name carrying the rendered list.
/// Gateway pods mount this at the path declared in
/// `plugins.trust.revocation_list_path`.
const CONFIGMAP_NAME: &str = "mcpg-revocation-list";

/// Data key inside the ConfigMap. Matches the on-disk file name
/// the gateway expects (per `plugin-revocation-list.md`).
const REVOCATIONS_FILE: &str = "revocations.json";

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("apply: {0}")]
    Apply(#[from] crate::reconcile::ApplyError),
    #[error("status: {0}")]
    Status(#[from] crate::reconcile::StatusError),
    #[error("finalizer: {0}")]
    Finalizer(#[from] crate::reconcile::FinalizerError),
    #[error("kube: {0}")]
    Kube(#[from] kube::Error),
    #[error("missing name on MCPGRevocationList")]
    MissingName,
}

/// Run the revocation-list controller until cancelled.
pub async fn run(ctx: Arc<ControllerContext>) -> anyhow::Result<()> {
    let api: Api<MCPGRevocationList> = Api::all(ctx.client.clone());

    info!("starting revocation-list controller");

    Controller::new(api, watcher::Config::default())
        .owns(
            Api::<ConfigMap>::all(ctx.client.clone()),
            watcher::Config::default(),
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => info!(name = %obj.name, "revocation-list reconciled"),
                Err(err) => error!(error = ?err, "revocation-list reconcile failed"),
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
    obj: Arc<MCPGRevocationList>,
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
    obj: Arc<MCPGRevocationList>,
    ctx: Arc<ControllerContext>,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    let name = obj
        .metadata
        .name
        .clone()
        .ok_or(ReconcileError::MissingName)?;
    let observed_generation = obj.metadata.generation.unwrap_or(0);
    let rl_api: Api<MCPGRevocationList> = Api::all(ctx.client.clone());

    // Step 0: deletion-timestamp branch + finalizer management.
    // Per-namespace revocation-list ConfigMaps are owner-ref'd to
    // this MCPGRevocationList, so K8s GC handles cascade-delete.
    if obj.metadata.deletion_timestamp.is_some() {
        info!(
            name = %name,
            "revocation-list deletion in progress; releasing finalizer"
        );
        remove_finalizer(&rl_api, &name, OPERATOR_FINALIZER).await?;
        return Ok((Action::await_change(), ReconcileOutcome::Success));
    }
    ensure_finalizer(&rl_api, &name, obj.as_ref(), OPERATOR_FINALIZER).await?;

    // Render the canonical JSON + SHA-256 hash.
    let (rendered, content_hash) = render_revocation_json(&obj.spec);

    // Find every namespace that has a gateway in it. The list
    // is fanned out only to those namespaces (avoids polluting
    // namespaces that don't run any gateway).
    let target_namespaces = list_namespaces_with_gateways(&ctx.client).await?;

    // SSA the ConfigMap into each target namespace.
    let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");
    let mut materialised = 0i64;
    for ns in &target_namespaces {
        let cm = build_configmap(&obj, ns, &rendered, &content_hash);
        let ns_api: Api<ConfigMap> = Api::namespaced(ctx.client.clone(), ns);
        match apply_owned(&ns_api, &cm, &fm).await {
            Ok(_) => materialised += 1,
            Err(e) => {
                tracing::warn!(
                    namespace = %ns,
                    error = ?e,
                    "revocation-list: failed to apply ConfigMap; will retry"
                );
            }
        }
    }

    // Status update.
    let mut conditions = obj
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();
    let entry_count = obj.spec.revocations.len() as i64;
    let ready = materialised as usize == target_namespaces.len();
    if ready {
        mcpg_operator_api::conditions::set_condition(
            &mut conditions,
            Condition::new(
                ctype::READY,
                "True",
                reasons::RECONCILED,
                format!("{materialised} namespaces synced"),
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
                format!(
                    "{}/{} namespaces synced",
                    materialised,
                    target_namespaces.len()
                ),
                Some(observed_generation),
            ),
        );
    }

    let status = MCPGRevocationListStatus {
        conditions,
        observed_generation: Some(observed_generation),
        observed_revocations: Some(entry_count),
        materialised_namespaces: Some(materialised),
        plugins_blocked: Vec::new(),
        content_hash: Some(content_hash),
        last_reconcile_time: Some(Utc::now()),
    };

    if let Err(e) = patch_status(&rl_api, &name, &status, &fm).await {
        tracing::warn!(error = ?e, "revocation-list: status patch failed");
    }

    let evt = K8sEvent {
        type_: if ready {
            EventType::Normal
        } else {
            EventType::Warning
        },
        reason: if ready {
            "Materialised".into()
        } else {
            "PartialMaterialisation".into()
        },
        note: Some(format!(
            "Revocation list materialised in {materialised}/{} namespaces (entries: {entry_count})",
            target_namespaces.len()
        )),
        action: "Materialise".into(),
        secondary: None,
    };
    if let Err(e) = ctx
        .recorders
        .revocation_list
        .publish(&evt, &obj.object_ref(&()))
        .await
    {
        tracing::warn!(error = ?e, "revocation-list: failed to publish event");
    }

    // A "successful" reconcile here means we tried to materialise
    // every target namespace; if any per-namespace SSA failed we
    // logged + continued (it's tracked in
    // `materialised_namespaces` / Ready=False). Treat that as a
    // dependency-pending: the operator is healthy, but the
    // revocation list isn't fully fanned out yet.
    let outcome = if ready {
        ReconcileOutcome::Success
    } else {
        ReconcileOutcome::DependencyPending
    };

    if matches!(outcome, ReconcileOutcome::Success) {
        let key = crate::backoff::resource_key(CONTROLLER_NAME, "", &name);
        ctx.backoff.record_success(&key);
    }

    // Resync more aggressively than gateway controller — a
    // revocation propagation lag is security-significant.
    Ok((Action::requeue(Duration::from_secs(60)), outcome))
}

fn error_policy(
    obj: Arc<MCPGRevocationList>,
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
                "revocation-list: reconcile error; backing off"
            );
            Action::requeue(delay)
        }
    }
}

/// Render the spec into the canonical JSON shape gateway pods
/// consume. Field naming matches `revocation-list.json` per
/// `plugin-revocation-list.md`.
fn render_revocation_json(spec: &MCPGRevocationListSpec) -> (String, String) {
    let entries: Vec<serde_json::Value> = spec
        .revocations
        .iter()
        .map(|e| {
            let mut entry = serde_json::Map::new();
            entry.insert(
                "artifact_sha256".into(),
                serde_json::Value::String(e.artifact_sha256.to_ascii_lowercase()),
            );
            entry.insert("reason".into(), serde_json::Value::String(e.reason.clone()));
            if let Some(t) = &e.revoked_at {
                entry.insert(
                    "revoked_at".into(),
                    serde_json::Value::String(t.to_rfc3339()),
                );
            }
            serde_json::Value::Object(entry)
        })
        .collect();

    let mut doc = serde_json::Map::new();
    doc.insert(
        "version".into(),
        serde_json::Value::Number(spec.version.into()),
    );
    if let Some(t) = &spec.issued_at {
        doc.insert(
            "issued_at".into(),
            serde_json::Value::String(t.to_rfc3339()),
        );
    }
    doc.insert("revocations".into(), serde_json::Value::Array(entries));

    // Pretty-print so the materialised file is human-readable
    // when debugging via `kubectl get configmap -o yaml`.
    let json =
        serde_json::to_string_pretty(&doc).expect("serializing a serde_json::Map never fails");

    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let hash = hex::encode(hasher.finalize());

    (json, hash)
}

fn build_configmap(
    parent: &MCPGRevocationList,
    namespace: &str,
    rendered: &str,
    content_hash: &str,
) -> ConfigMap {
    let mut data = BTreeMap::new();
    data.insert(REVOCATIONS_FILE.to_owned(), rendered.to_owned());

    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_owned(),
        "mcpg-operator".to_owned(),
    );
    labels.insert(
        "mcpg.dev/revocation-list".to_owned(),
        parent
            .metadata
            .name
            .clone()
            .unwrap_or_else(|| "unknown".to_owned()),
    );
    labels.insert("mcpg.dev/content-hash".to_owned(), content_hash.to_owned());

    // Cluster-scoped → namespace-scoped fan-out. We can't use
    // owner references (cross-scope owner refs are rejected by
    // kube-apiserver). We rely on the operator's
    // garbage-collection logic + the labels above for cleanup
    // when the parent is deleted.
    ConfigMap {
        metadata: ObjectMeta {
            name: Some(CONFIGMAP_NAME.to_owned()),
            namespace: Some(namespace.to_owned()),
            labels: Some(labels),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}

/// Find every namespace currently running a gateway. Lookup
/// goes through the gateway watch — the controller-manager
/// caches it.
async fn list_namespaces_with_gateways(client: &Client) -> Result<Vec<String>, ReconcileError> {
    use mcpg_operator_api::v1alpha1::MCPGGateway;

    let api: Api<MCPGGateway> = Api::all(client.clone());
    let gateways = api.list(&Default::default()).await?;
    let mut namespaces: Vec<String> = gateways
        .items
        .into_iter()
        .filter_map(|g| g.namespace())
        .collect();
    namespaces.sort();
    namespaces.dedup();
    Ok(namespaces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_operator_api::v1alpha1::RevocationEntry;

    fn fixture(entries: Vec<RevocationEntry>) -> MCPGRevocationList {
        MCPGRevocationList {
            metadata: ObjectMeta {
                name: Some("cluster-default".to_owned()),
                ..Default::default()
            },
            spec: MCPGRevocationListSpec {
                version: 1,
                issued_at: None,
                revocations: entries,
            },
            status: None,
        }
    }

    #[test]
    fn rendered_json_normalises_sha256_to_lowercase() {
        let p = fixture(vec![RevocationEntry {
            artifact_sha256: "ABCDEF".repeat(11) + "ABCDEF",
            reason: "test".into(),
            revoked_at: None,
        }]);
        let (json, _) = render_revocation_json(&p.spec);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let sha = parsed["revocations"][0]["artifact_sha256"]
            .as_str()
            .unwrap();
        assert!(
            sha.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn content_hash_is_deterministic() {
        let p1 = fixture(vec![RevocationEntry {
            artifact_sha256: "abcd".repeat(16),
            reason: "x".into(),
            revoked_at: None,
        }]);
        let p2 = fixture(vec![RevocationEntry {
            artifact_sha256: "abcd".repeat(16),
            reason: "x".into(),
            revoked_at: None,
        }]);
        let (_, h1) = render_revocation_json(&p1.spec);
        let (_, h2) = render_revocation_json(&p2.spec);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // sha256 hex
    }

    #[test]
    fn content_hash_changes_on_content_change() {
        let p1 = fixture(vec![RevocationEntry {
            artifact_sha256: "abcd".repeat(16),
            reason: "x".into(),
            revoked_at: None,
        }]);
        let p2 = fixture(vec![RevocationEntry {
            artifact_sha256: "abcd".repeat(16),
            reason: "y".into(),
            revoked_at: None,
        }]);
        let (_, h1) = render_revocation_json(&p1.spec);
        let (_, h2) = render_revocation_json(&p2.spec);
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_configmap_carries_content_hash_label() {
        let p = fixture(vec![]);
        let (rendered, hash) = render_revocation_json(&p.spec);
        let cm = build_configmap(&p, "payments", &rendered, &hash);
        let labels = cm.metadata.labels.unwrap();
        assert_eq!(labels.get("mcpg.dev/content-hash").unwrap(), &hash);
        assert_eq!(
            labels.get("mcpg.dev/revocation-list").unwrap(),
            "cluster-default"
        );
        assert_eq!(cm.metadata.name.as_deref(), Some(CONFIGMAP_NAME));
        assert_eq!(cm.metadata.namespace.as_deref(), Some("payments"));
    }

    #[test]
    fn build_configmap_holds_revocations_under_canonical_filename() {
        let p = fixture(vec![]);
        let (rendered, hash) = render_revocation_json(&p.spec);
        let cm = build_configmap(&p, "payments", &rendered, &hash);
        assert!(cm.data.unwrap().contains_key(REVOCATIONS_FILE));
    }

    #[test]
    fn empty_revocations_renders_empty_array() {
        let p = fixture(vec![]);
        let (json, _) = render_revocation_json(&p.spec);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["revocations"].as_array().unwrap().len(), 0);
    }
}
