//! Status subresource helpers.

use kube::Resource;
use kube::api::{Api, Patch, PatchParams};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use tracing::debug;

#[derive(Debug, thiserror::Error)]
pub enum StatusError {
    #[error("status patch failed for {kind}/{name}: {source}")]
    Patch {
        kind: &'static str,
        name: String,
        #[source]
        source: kube::Error,
    },
}

/// Single retry attempt on 409 conflict. Status SSA conflicts
/// are usually transient (another reconciler write or a
/// resourceVersion race); retrying once after a short jitter
/// converges in the common case. Past two attempts we surface
/// the error so the controller can requeue.
///
/// A dropped 409 would leave the next reconcile reading stale
/// status, so the patch is retried once. The single-retry shape
/// is intentionally conservative — we don't want a tight retry
/// loop hammering the apiserver.
const STATUS_RETRY_DELAY_MS: u64 = 100;

/// Patch the `/status` subresource via SSA. Status writes don't
/// fight `spec` writes because the API server exposes `/status`
/// as its own endpoint with separate field-manager scoping.
///
/// Retries once on HTTP 409 (conflict) — see [`STATUS_RETRY_DELAY_MS`].
pub async fn patch_status<K, S>(
    api: &Api<K>,
    name: &str,
    status: &S,
    field_manager: &str,
) -> Result<K, StatusError>
where
    K: Resource + Serialize + DeserializeOwned + Clone + Debug,
    <K as Resource>::DynamicType: Default,
    S: Serialize,
{
    // Status patch is a strategic-merge / SSA against the
    // `/status` subresource. We use server-side apply so
    // condition transitions stay deterministic across leader
    // changes.
    let pp = PatchParams::apply(field_manager).force();
    // Server-side apply requires the GVK in the body; without apiVersion+kind
    // the apiserver rejects the patch with "invalid object type: /, Kind=".
    let dt = <K as Resource>::DynamicType::default();
    let body = serde_json::json!({
        "apiVersion": K::api_version(&dt).to_string(),
        "kind": K::kind(&dt).to_string(),
        "status": status,
    });

    match api.patch_status(name, &pp, &Patch::Apply(&body)).await {
        Ok(k) => Ok(k),
        Err(e) if is_conflict(&e) => {
            debug!(name = %name, "status patch conflict; retrying once");
            tokio::time::sleep(std::time::Duration::from_millis(STATUS_RETRY_DELAY_MS)).await;
            api.patch_status(name, &pp, &Patch::Apply(body))
                .await
                .map_err(|e| StatusError::Patch {
                    kind: std::any::type_name::<K>(),
                    name: name.to_owned(),
                    source: e,
                })
        }
        Err(e) => Err(StatusError::Patch {
            kind: std::any::type_name::<K>(),
            name: name.to_owned(),
            source: e,
        }),
    }
}

/// Returns `true` when the error is a HTTP 409 from the apiserver
/// — the only error we retry on. Any other error (network, RBAC,
/// 500, ...) gets surfaced to the controller for proper backoff.
fn is_conflict(err: &kube::Error) -> bool {
    matches!(err, kube::Error::Api(api_err) if api_err.code == 409)
}
