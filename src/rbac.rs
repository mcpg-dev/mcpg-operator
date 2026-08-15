//! Per-tenant RBAC management for plugin Secret writes.
//!
//! The operator dynamically creates a RoleBinding in every
//! tenant namespace that hosts an `MCPGPluginSet` so that the
//! operator's ServiceAccount has `secrets [create, patch, delete]`
//! verbs *only* in those namespaces. The main operator
//! ClusterRole carries no cluster-wide write verbs — write blast
//! radius is bounded by the set of namespaces with active
//! PluginSets.
//!
//! ## Bindings owned vs. unowned
//!
//! The RoleBinding is intentionally **not** owner-ref'd to the
//! triggering MCPGPluginSet: a single namespace may host multiple
//! sets, and cascade-deleting the binding when any one set is
//! removed would break the others. Cleanup is left as a manual
//! `kubectl delete` against the
//! `app.kubernetes.io/managed-by=mcpg-operator` label until the
//! follow-up commit that adds last-set-leaves finalizer-driven
//! removal.
//!
//! ## ClusterRole assumed to exist
//!
//! [`TENANT_SECRETS_CLUSTER_ROLE`] is the constant name of the
//! `secrets [create, patch, delete]` ClusterRole the chart ships.
//! The chart must render it; without it, the apply will succeed
//! (a RoleBinding referencing a missing role is admitted) but the
//! operator's Secret writes will then fail with `Forbidden`. The
//! Helm chart and this module agree on the name via this
//! constant.
//!
//! ## Scope
//!
//! This module bounds the **write** half of Secret access. The
//! **read** half (cluster-wide `secrets [get, list, watch]` for
//! the controller's `.owns(Api::<Secret>::all(...))` reflector)
//! remains as a documented residual privilege — closing it
//! requires a controller refactor to per-namespace reflectors.

use k8s_openapi::api::rbac::v1::{RoleBinding, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Client;
use kube::api::{Api, Patch, PatchParams};
use std::collections::BTreeMap;
use tracing::{debug, instrument};

/// Constant name of the `secrets [create, patch, delete]`
/// ClusterRole the Helm chart ships. Bound dynamically per
/// tenant namespace via [`ensure_tenant_secret_binding`].
pub const TENANT_SECRETS_CLUSTER_ROLE: &str = "mcpg-operator-tenant-secrets";

/// Constant name of the per-tenant RoleBinding written by
/// [`ensure_tenant_secret_binding`]. One per namespace.
pub const TENANT_SECRETS_BINDING_NAME: &str = "mcpg-operator-tenant-secrets";

/// SSA-create the tenant RoleBinding in `namespace` if it does
/// not already exist (or refresh it if the operator's SA
/// reference rotated). Idempotent — safe to call on every
/// reconcile.
///
/// `operator_namespace` is where the operator's ServiceAccount
/// lives; `operator_service_account` is its name. Both come from
/// the operator process at boot via the `OPERATOR_NAMESPACE` /
/// `OPERATOR_SERVICE_ACCOUNT` env vars (set by the Helm-rendered
/// Deployment).
///
/// `field_manager` should follow the controller-naming convention
/// (`mcpg-operator/<controller>`) so SSA conflicts are tracked
/// per controller.
#[instrument(skip(client))]
pub async fn ensure_tenant_secret_binding(
    client: &Client,
    namespace: &str,
    operator_namespace: &str,
    operator_service_account: &str,
    field_manager: &str,
) -> Result<(), kube::Error> {
    if namespace == operator_namespace {
        // Operator's own namespace gets the binding pre-created
        // by the Helm chart (static Helm template, not dynamic).
        // Re-creating it dynamically would race with chart
        // upgrades and pollute the SSA managed-fields ledger.
        debug!(
            namespace,
            "tenant RoleBinding skipped — operator namespace is chart-managed"
        );
        return Ok(());
    }

    let api: Api<RoleBinding> = Api::namespaced(client.clone(), namespace);
    let binding = build_tenant_binding(namespace, operator_namespace, operator_service_account);

    let pp = PatchParams::apply(field_manager).force();
    api.patch(TENANT_SECRETS_BINDING_NAME, &pp, &Patch::Apply(&binding))
        .await?;

    debug!(
        namespace,
        binding = TENANT_SECRETS_BINDING_NAME,
        "tenant RoleBinding ensured"
    );
    Ok(())
}

fn build_tenant_binding(
    namespace: &str,
    operator_namespace: &str,
    operator_service_account: &str,
) -> RoleBinding {
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_owned(),
        "mcpg-operator".to_owned(),
    );
    labels.insert(
        "app.kubernetes.io/component".to_owned(),
        "tenant-rbac".to_owned(),
    );

    RoleBinding {
        metadata: ObjectMeta {
            name: Some(TENANT_SECRETS_BINDING_NAME.to_owned()),
            namespace: Some(namespace.to_owned()),
            labels: Some(labels),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_owned(),
            kind: "ClusterRole".to_owned(),
            name: TENANT_SECRETS_CLUSTER_ROLE.to_owned(),
        },
        subjects: Some(vec![Subject {
            api_group: Some("".to_owned()),
            kind: "ServiceAccount".to_owned(),
            name: operator_service_account.to_owned(),
            namespace: Some(operator_namespace.to_owned()),
        }]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_targets_tenant_cluster_role() {
        let b = build_tenant_binding("tenant-a", "mcpg-operator-system", "mcpg-operator");
        assert_eq!(b.role_ref.kind, "ClusterRole");
        assert_eq!(b.role_ref.name, TENANT_SECRETS_CLUSTER_ROLE);
        assert_eq!(b.role_ref.api_group, "rbac.authorization.k8s.io");
    }

    #[test]
    fn binding_subject_is_operator_service_account() {
        let b = build_tenant_binding("tenant-a", "mcpg-operator-system", "mcpg-operator");
        let subjects = b.subjects.expect("subjects present");
        assert_eq!(subjects.len(), 1);
        let s = &subjects[0];
        assert_eq!(s.kind, "ServiceAccount");
        assert_eq!(s.name, "mcpg-operator");
        assert_eq!(s.namespace.as_deref(), Some("mcpg-operator-system"));
    }

    #[test]
    fn binding_namespace_is_tenant_not_operator() {
        let b = build_tenant_binding("payments", "mcpg-operator-system", "mcpg-operator");
        assert_eq!(b.metadata.namespace.as_deref(), Some("payments"));
    }

    #[test]
    fn binding_has_managed_by_label_for_audit_filtering() {
        let b = build_tenant_binding("tenant-a", "mcpg-operator-system", "mcpg-operator");
        let labels = b.metadata.labels.expect("labels present");
        assert_eq!(
            labels
                .get("app.kubernetes.io/managed-by")
                .map(String::as_str),
            Some("mcpg-operator")
        );
        assert_eq!(
            labels
                .get("app.kubernetes.io/component")
                .map(String::as_str),
            Some("tenant-rbac")
        );
    }

    #[test]
    fn binding_name_is_constant_per_namespace() {
        let b1 = build_tenant_binding("a", "op", "sa");
        let b2 = build_tenant_binding("b", "op", "sa");
        assert_eq!(b1.metadata.name, b2.metadata.name);
        assert_eq!(
            b1.metadata.name.as_deref(),
            Some(TENANT_SECRETS_BINDING_NAME)
        );
    }
}
