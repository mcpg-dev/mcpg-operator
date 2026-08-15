//! Server-side apply helpers.
//!
//! Every controller writes children via SSA with a stable
//! field-manager (`mcpg-operator/<controller-name>`). Conflicts
//! return as a transient error and trigger a re-reconcile.

use kube::Resource;
use kube::api::{Api, Patch, PatchParams};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt::Debug;

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("SSA apply failed for {kind}/{name}: {source}")]
    Apply {
        kind: &'static str,
        name: String,
        #[source]
        source: kube::Error,
    },
}

/// Server-side apply a child resource. The field manager uses
/// `mcpg-operator/<controller>` so multiple controllers don't
/// collide on shared fields.
pub async fn apply_owned<K>(api: &Api<K>, obj: &K, field_manager: &str) -> Result<K, ApplyError>
where
    K: Resource + Serialize + DeserializeOwned + Clone + Debug,
    <K as Resource>::DynamicType: Default,
{
    let name = obj.meta().name.clone().ok_or_else(|| ApplyError::Apply {
        kind: std::any::type_name::<K>(),
        name: "<unnamed>".to_owned(),
        source: kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
            "missing metadata.name".to_owned(),
        )),
    })?;

    // `force = true` reclaims fields from another manager when
    // the operator owns them. Without it, conflicts on managed
    // fields fail with 409. We set force here because every
    // operator child resource is operator-managed; user edits
    // to operator fields are rejected by the validating webhook
    // before they ever land in apiserver.
    let pp = PatchParams::apply(field_manager).force();

    api.patch(&name, &pp, &Patch::Apply(obj))
        .await
        .map_err(|e| ApplyError::Apply {
            kind: std::any::type_name::<K>(),
            name,
            source: e,
        })
}
