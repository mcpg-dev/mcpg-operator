//! Finalizer helpers — `kube-rs` does have a `finalizer()` helper
//! but its return type bakes in the wrapped reconcile's error
//! type, which collides awkwardly with our per-controller
//! `ReconcileError` enums + the metric outcome we read out of the
//! reconcile body. The two-line patch helpers below let each
//! controller drive the add / remove explicitly.

use kube::Resource;
use kube::api::{Api, Patch, PatchParams};
use serde::de::DeserializeOwned;
use std::fmt::Debug;

/// The single finalizer name every operator-managed CRD carries.
/// Centralising this avoids per-CRD typos and makes garbage
/// collection auditable (`kubectl get … -o jsonpath` for it).
pub const OPERATOR_FINALIZER: &str = "mcpg.dev/operator";

#[derive(Debug, thiserror::Error)]
pub enum FinalizerError {
    #[error("kube error patching finalizer on {kind}/{name}: {source}")]
    Patch {
        kind: &'static str,
        name: String,
        #[source]
        source: kube::Error,
    },

    /// The finalizer-add JSON Patch failed its
    /// `test`-on-`resourceVersion` precondition — another writer
    /// modified the resource between our read and our write.
    /// Caller should re-fetch and retry on the next reconcile.
    #[error("finalizer add for {kind}/{name} conflicted on resourceVersion")]
    Conflict { kind: &'static str, name: String },
}

/// Add `finalizer` to the resource's `metadata.finalizers` if it
/// isn't already there. No-op + returns `false` when the
/// finalizer is already present; returns `true` when the patch
/// went out (the caller may choose to `await_change()` to wait
/// for the resulting watch event before proceeding).
///
/// Uses a JSON Patch (RFC 6902) with a `test` op on
/// `resourceVersion` so the operation is atomic w.r.t. concurrent
/// writers. If the resource was modified between our read and our
/// write (e.g. another controller added its own finalizer), the
/// `test` fails with HTTP 409 and we surface a
/// [`FinalizerError::Conflict`] — the caller is expected to
/// requeue with a fresh fetch.
///
/// The patch is an `add` op on `/metadata/finalizers/-`
/// (array-append), never a merge patch on the full finalizers
/// array — a full-array write would clobber other controllers'
/// finalizers when they race; the append composes safely.
pub async fn ensure_finalizer<K>(
    api: &Api<K>,
    name: &str,
    current: &K,
    finalizer: &str,
) -> Result<bool, FinalizerError>
where
    K: Resource + DeserializeOwned + Clone + Debug,
    <K as Resource>::DynamicType: Default,
{
    if current
        .meta()
        .finalizers
        .as_ref()
        .is_some_and(|f| f.iter().any(|name| name == finalizer))
    {
        return Ok(false);
    }

    let resource_version =
        current
            .meta()
            .resource_version
            .as_deref()
            .ok_or_else(|| FinalizerError::Patch {
                kind: std::any::type_name::<K>(),
                name: name.to_owned(),
                source: kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
                    "missing metadata.resourceVersion (cannot atomically add finalizer)".to_owned(),
                )),
            })?;

    let ops = if current.meta().finalizers.is_some() {
        // Array exists — append to it. Strategic-merge would also
        // work for `+listType=set` finalizers, but JSON Patch is
        // explicit + universally supported.
        serde_json::json!([
            { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
            { "op": "add",  "path": "/metadata/finalizers/-",     "value": finalizer }
        ])
    } else {
        // Array is null/absent — create it with one entry.
        serde_json::json!([
            { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
            { "op": "add",  "path": "/metadata/finalizers",       "value": [finalizer] }
        ])
    };

    let pp = PatchParams::default();
    api.patch(
        name,
        &pp,
        &Patch::<()>::Json(serde_json::from_value(ops).unwrap()),
    )
    .await
    .map_err(|e| {
        if is_conflict(&e) {
            FinalizerError::Conflict {
                kind: std::any::type_name::<K>(),
                name: name.to_owned(),
            }
        } else {
            FinalizerError::Patch {
                kind: std::any::type_name::<K>(),
                name: name.to_owned(),
                source: e,
            }
        }
    })?;
    Ok(true)
}

/// Returns `true` iff the kube error is a HTTP 409. The
/// finalizer-add path treats this as a soft failure: the caller
/// re-fetches the resource and retries on the next reconcile.
fn is_conflict(err: &kube::Error) -> bool {
    matches!(err, kube::Error::Api(api_err) if api_err.code == 409)
}

/// Remove `finalizer` from the resource's `metadata.finalizers`
/// if present. Re-fetches the resource by name first so we patch
/// with the latest finalizer list (the in-flight reconcile may
/// hold a stale snapshot if other controllers ran in parallel).
pub async fn remove_finalizer<K>(
    api: &Api<K>,
    name: &str,
    finalizer: &str,
) -> Result<(), FinalizerError>
where
    K: Resource + DeserializeOwned + Clone + Debug,
    <K as Resource>::DynamicType: Default,
{
    let current = match api.get_opt(name).await.map_err(|e| FinalizerError::Patch {
        kind: std::any::type_name::<K>(),
        name: name.to_owned(),
        source: e,
    })? {
        Some(c) => c,
        None => return Ok(()),
    };
    let filtered: Vec<String> = current
        .meta()
        .finalizers
        .as_ref()
        .map(|f| {
            f.iter()
                .filter(|f| f.as_str() != finalizer)
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if let Some(f) = current.meta().finalizers.as_ref()
        && filtered.len() == f.len()
    {
        return Ok(());
    }

    let patch = serde_json::json!({
        "metadata": {
            "finalizers": filtered
        }
    });
    let pp = PatchParams::default();
    api.patch(name, &pp, &Patch::Merge(patch))
        .await
        .map_err(|e| FinalizerError::Patch {
            kind: std::any::type_name::<K>(),
            name: name.to_owned(),
            source: e,
        })?;
    Ok(())
}

/// True when the resource carries `finalizer` in its metadata.
pub fn has_finalizer<K>(obj: &K, finalizer: &str) -> bool
where
    K: Resource,
{
    obj.meta()
        .finalizers
        .as_ref()
        .is_some_and(|f| f.iter().any(|name| name == finalizer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::core::ObjectMeta;

    fn cm_with_finalizers(finalizers: Vec<String>) -> ConfigMap {
        ConfigMap {
            metadata: ObjectMeta {
                name: Some("test".into()),
                finalizers: Some(finalizers),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn has_finalizer_returns_true_when_present() {
        let cm = cm_with_finalizers(vec![OPERATOR_FINALIZER.into()]);
        assert!(has_finalizer(&cm, OPERATOR_FINALIZER));
    }

    #[test]
    fn has_finalizer_returns_false_when_list_unset() {
        let cm = ConfigMap::default();
        assert!(!has_finalizer(&cm, OPERATOR_FINALIZER));
    }

    #[test]
    fn has_finalizer_returns_false_when_other_present() {
        let cm = cm_with_finalizers(vec!["other.example.com/x".into()]);
        assert!(!has_finalizer(&cm, OPERATOR_FINALIZER));
    }
}
