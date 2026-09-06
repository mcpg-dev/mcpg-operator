//! Tenant-aware admission helpers.
//!
//! These resolve the `MCPGTenant` that owns a namespace and enforce the
//! two tenant guarantees that *can't* be expressed as a native
//! `ResourceQuota`:
//!
//! - **Plugin allowlist** — an `MCPGPluginSet` in a tenant namespace may
//!   only reference plugins the tenant is allowed.
//! - **Per-gateway replica cap** — a *field* constraint, so it has no
//!   admission race and is webhook-only.
//!
//! Count quotas (gateway / pluginset / route counts) are NOT enforced
//! here — the tenant controller generates a per-namespace
//! `ResourceQuota` that the apiserver enforces race-free. Doing the
//! count check here too would be a redundant, racy second gate.
//!
//! **Fail-open on lookup error:** if the tenant list can't be fetched we
//! admit (and log). Admission must not hard-fail the apiserver on a
//! transient read; the controller-side `ResourceQuota` + RBAC remain the
//! durable guarantees. A namespace with no owning tenant is unconstrained
//! — exactly today's behaviour, preserving opt-in compatibility.

use kube::api::Api;
use mcpg_operator_api::v1alpha1::{MCPGGateway, MCPGPlugin, MCPGPluginSet, MCPGTenant};
use tracing::warn;

/// Find the `MCPGTenant` that owns `namespace`, if any. Lists tenants
/// (cluster-scoped, few in number) and returns the first whose
/// `spec.namespaces` contains the namespace.
pub async fn owning_tenant(client: &kube::Client, namespace: &str) -> Option<MCPGTenant> {
    let api: Api<MCPGTenant> = Api::all(client.clone());
    match api.list(&Default::default()).await {
        Ok(list) => list
            .items
            .into_iter()
            .find(|t| t.spec.owns_namespace(namespace)),
        Err(e) => {
            warn!(error = ?e, namespace, "tenant_guard: tenant list failed; admitting (fail-open)");
            None
        }
    }
}

/// Enforce the tenant plugin allowlist for an `MCPGPluginSet`. Resolves
/// the owning tenant; if one exists, every entry's referenced plugin
/// must be allowed (by resource name / capability id, or by the
/// referenced `MCPGPlugin`'s OCI image prefix). Returns `Err(reason)` to
/// deny.
pub async fn enforce_pluginset_allowlist(
    client: &kube::Client,
    obj: &MCPGPluginSet,
) -> Result<(), String> {
    let Some(namespace) = obj.metadata.namespace.as_deref() else {
        return Ok(());
    };
    let Some(tenant) = owning_tenant(client, namespace).await else {
        return Ok(());
    };
    let tenant_name = tenant.metadata.name.as_deref().unwrap_or("<tenant>");

    let plugin_api: Api<MCPGPlugin> = Api::all(client.clone());
    for entry in &obj.spec.entries {
        // Resolve the referenced plugin's image (best-effort) so a
        // registryPrefix allowlist can match. Name/id matching needs no
        // lookup.
        let image = plugin_api
            .get_opt(&entry.plugin_ref.name)
            .await
            .ok()
            .flatten()
            .map(|p| p.spec.oci.image);

        if !tenant
            .spec
            .plugin_allowed(&entry.plugin_ref.name, &entry.id, image.as_deref())
        {
            return Err(format!(
                "plugin `{}` (id `{}`) is not in tenant `{tenant_name}`'s allowedPlugins; \
                 namespace `{namespace}` is governed by that tenant",
                entry.plugin_ref.name, entry.id
            ));
        }
    }
    Ok(())
}

/// Enforce the tenant per-gateway replica cap for an `MCPGGateway`. Checks the
/// *effective* ceiling, so an HPA can't scale past the cap the static-replica
/// check enforces.
pub async fn enforce_gateway_replica_cap(
    client: &kube::Client,
    obj: &MCPGGateway,
) -> Result<(), String> {
    let Some(namespace) = obj.metadata.namespace.as_deref() else {
        return Ok(());
    };
    let Some(tenant) = owning_tenant(client, namespace).await else {
        return Ok(());
    };
    let cap = tenant
        .spec
        .quotas
        .as_ref()
        .and_then(|q| q.max_replicas_per_gateway);
    if let Some(max) = cap {
        let (ceiling, field) = obj.spec.effective_replica_ceiling();
        let ceiling = i64::from(ceiling);
        if ceiling > max {
            let tenant_name = tenant.metadata.name.as_deref().unwrap_or("<tenant>");
            return Err(format!(
                "{field} {ceiling} exceeds tenant `{tenant_name}`'s maxReplicasPerGateway {max}"
            ));
        }
    }
    Ok(())
}
