//! Validating webhook for `MCPGTenant`.
//!
//! Two classes of check:
//!
//! - **Pure field shape** — `namespaces` non-empty + no duplicates;
//!   every `allowedPlugins` entry has at least one matcher; quota values
//!   non-negative.
//! - **Cross-resource (client-backed)** — **namespace exclusivity**: no
//!   declared namespace may be owned by a *different* `MCPGTenant`. A
//!   namespace belongs to at most one tenant.

use std::collections::BTreeSet;

use axum::Json;
use axum::extract::State;
use kube::api::Api;
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use mcpg_operator_api::v1alpha1::MCPGTenant;
use tracing::warn;

use crate::admission::server::AdmissionState;

pub async fn validate(
    State(state): State<AdmissionState>,
    Json(review): Json<AdmissionReview<MCPGTenant>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let req: AdmissionRequest<MCPGTenant> = match review.try_into() {
        Ok(r) => r,
        Err(e) => {
            warn!(error = ?e, "malformed admission review");
            return Json(AdmissionResponse::invalid("malformed admission review").into_review());
        }
    };

    let response = AdmissionResponse::from(&req);
    let Some(obj) = &req.object else {
        return Json(response.into_review());
    };

    // Pure field validation first (cheap, no I/O).
    if let Err(reason) = validate_spec(obj) {
        return Json(response.deny(reason).into_review());
    }

    // Cross-resource: namespace exclusivity. The object's own name is
    // excluded so an update to an existing tenant doesn't conflict with
    // itself.
    let self_name = obj.metadata.name.clone().unwrap_or_default();
    let response = match check_namespace_exclusivity(&state.client, obj, &self_name).await {
        Ok(()) => response,
        Err(reason) => response.deny(reason),
    };

    Json(response.into_review())
}

/// Pure shape checks.
fn validate_spec(obj: &MCPGTenant) -> Result<(), String> {
    let spec = &obj.spec;

    if spec.namespaces.is_empty() {
        return Err("spec.namespaces must not be empty".to_owned());
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for ns in &spec.namespaces {
        if ns.trim().is_empty() {
            return Err("spec.namespaces[] entries must not be empty".to_owned());
        }
        if !seen.insert(ns.as_str()) {
            return Err(format!("spec.namespaces lists `{ns}` more than once"));
        }
    }

    for (i, a) in spec.allowed_plugins.iter().enumerate() {
        let name_set = a.name.as_ref().is_some_and(|n| !n.trim().is_empty());
        let prefix_set = a
            .registry_prefix
            .as_ref()
            .is_some_and(|p| !p.trim().is_empty());
        if !name_set && !prefix_set {
            return Err(format!(
                "spec.allowedPlugins[{i}] must set `name` or `registryPrefix` \
                 (an empty matcher matches nothing)"
            ));
        }
    }

    if let Some(q) = &spec.quotas {
        for (field, val) in [
            ("maxGateways", q.max_gateways),
            ("maxPluginSets", q.max_plugin_sets),
            ("maxRoutes", q.max_routes),
            ("maxReplicasPerGateway", q.max_replicas_per_gateway),
        ] {
            if let Some(v) = val
                && v < 0
            {
                return Err(format!("spec.quotas.{field} must be ≥ 0 (got {v})"));
            }
        }
    }

    if let Some(id) = &spec.identity_attribute
        && id.key.trim().is_empty()
    {
        return Err("spec.identityAttribute.key must not be empty when set".to_owned());
    }

    Ok(())
}

/// Deny when any declared namespace is already owned by a different
/// tenant. Fail-open on a list error (admission must not hard-fail the
/// apiserver on a transient read).
async fn check_namespace_exclusivity(
    client: &kube::Client,
    obj: &MCPGTenant,
    self_name: &str,
) -> Result<(), String> {
    let api: Api<MCPGTenant> = Api::all(client.clone());
    let existing = match api.list(&Default::default()).await {
        Ok(l) => l,
        Err(e) => {
            warn!(error = ?e, "tenant validator: list failed; admitting (fail-open)");
            return Ok(());
        }
    };

    for other in &existing.items {
        let other_name = other.metadata.name.as_deref().unwrap_or_default();
        if other_name == self_name {
            continue; // self (update path)
        }
        let overlap = obj.spec.overlapping_namespaces(&other.spec);
        if !overlap.is_empty() {
            return Err(format!(
                "namespace(s) {} already owned by MCPGTenant `{other_name}`; \
                 namespaces are exclusively owned",
                overlap.join(", ")
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::{
        AllowedPlugin, MCPGTenantSpec, TenantIdentityAttribute, TenantQuotas,
    };

    fn fixture(spec: MCPGTenantSpec) -> MCPGTenant {
        MCPGTenant {
            metadata: ObjectMeta {
                name: Some("team-payments".into()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn base() -> MCPGTenantSpec {
        MCPGTenantSpec {
            namespaces: vec!["payments".into()],
            allowed_plugins: vec![AllowedPlugin {
                name: Some("identity-workload".into()),
                registry_prefix: None,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn valid_tenant_admits() {
        validate_spec(&fixture(base())).unwrap();
    }

    #[test]
    fn empty_namespaces_rejected() {
        let mut s = base();
        s.namespaces.clear();
        assert!(
            validate_spec(&fixture(s))
                .unwrap_err()
                .contains("namespaces")
        );
    }

    #[test]
    fn duplicate_namespace_rejected() {
        let mut s = base();
        s.namespaces = vec!["a".into(), "a".into()];
        assert!(
            validate_spec(&fixture(s))
                .unwrap_err()
                .contains("more than once")
        );
    }

    #[test]
    fn empty_allowlist_matcher_rejected() {
        let mut s = base();
        s.allowed_plugins = vec![AllowedPlugin::default()];
        assert!(
            validate_spec(&fixture(s))
                .unwrap_err()
                .contains("matches nothing")
        );
    }

    #[test]
    fn negative_quota_rejected() {
        let mut s = base();
        s.quotas = Some(TenantQuotas {
            max_gateways: Some(-1),
            ..Default::default()
        });
        assert!(
            validate_spec(&fixture(s))
                .unwrap_err()
                .contains("maxGateways")
        );
    }

    #[test]
    fn empty_identity_key_rejected() {
        let mut s = base();
        s.identity_attribute = Some(TenantIdentityAttribute {
            key: "  ".into(),
            value: "x".into(),
        });
        assert!(
            validate_spec(&fixture(s))
                .unwrap_err()
                .contains("identityAttribute.key")
        );
    }

    #[test]
    fn empty_allowlist_is_allowed_shape() {
        // An empty allowedPlugins LIST is valid (means deny-all at
        // enforcement time); only an empty *matcher entry* is rejected.
        let mut s = base();
        s.allowed_plugins.clear();
        validate_spec(&fixture(s)).unwrap();
    }
}
