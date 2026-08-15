//! Validating webhook for `MCPGRoute`.
//!
//! Spec-shape checks the OpenAPI schema can't express:
//!
//! - `gatewayRef.name` must be non-empty.
//! - `match.tools` must be non-empty (a route that matches nothing is
//!   almost always a mistake) and free of duplicate / empty tool ids.
//! - chain plugin ids (identity / policy / audit) must be non-empty
//!   strings.
//! - a route with NO `attributes.tenant` exposes its tools to ANY
//!   caller the gateway admits (the rendered CEL predicate is `true`);
//!   that's a footgun in a multi-tenant gateway, so we **warn** (admit
//!   with a warning) rather than reject — single-tenant gateways
//!   legitimately omit it.
//!
//! Cross-resource checks (does the gateway exist? does it accept this
//! namespace? do the chain plugins exist in its plugin set?) are NOT
//! done here — they need a gateway/plugin-set lookup and live in the
//! route controller's reconcile (`GatewayBound` / `Ready` conditions),
//! so a route can be admitted before its gateway is created.

use std::collections::BTreeSet;

use axum::Json;
use axum::extract::State;
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use mcpg_operator_api::v1alpha1::MCPGRoute;
use tracing::warn;

use crate::admission::server::AdmissionState;

pub async fn validate(
    State(_state): State<AdmissionState>,
    Json(review): Json<AdmissionReview<MCPGRoute>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let req: AdmissionRequest<MCPGRoute> = match review.try_into() {
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

    let response = match validate_spec(obj) {
        Ok(warnings) => {
            let mut r = response;
            if !warnings.is_empty() {
                r.warnings = Some(warnings);
            }
            r
        }
        Err(reason) => response.deny(reason),
    };

    Json(response.into_review())
}

/// Returns `Ok(warnings)` on admit (possibly with non-fatal warnings)
/// or `Err(reason)` on reject.
fn validate_spec(obj: &MCPGRoute) -> Result<Vec<String>, String> {
    let spec = &obj.spec;
    let mut warnings = Vec::new();

    if spec.gateway_ref.name.trim().is_empty() {
        return Err("spec.gatewayRef.name must not be empty".to_owned());
    }

    if spec.r#match.tools.is_empty() {
        return Err(
            "spec.match.tools must list at least one tool (a route that matches no tools \
             has no effect)"
                .to_owned(),
        );
    }

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (i, tool) in spec.r#match.tools.iter().enumerate() {
        let id = tool.id.trim();
        if id.is_empty() {
            return Err(format!("spec.match.tools[{i}].id must not be empty"));
        }
        if !seen.insert(id) {
            return Err(format!(
                "spec.match.tools contains duplicate tool id '{id}'"
            ));
        }
    }

    for (chain_name, chain) in [
        ("identityChain", &spec.identity_chain),
        ("policyChain", &spec.policy_chain),
        ("auditChain", &spec.audit_chain),
    ] {
        for (i, id) in chain.iter().enumerate() {
            if id.trim().is_empty() {
                return Err(format!("spec.{chain_name}[{i}] must not be empty"));
            }
        }
    }

    if spec.tenant().is_none() {
        warnings.push(
            "spec.attributes.tenant is unset: this route's tools will be reachable by ANY \
             caller the gateway admits (no tenant scoping). Set attributes.tenant for a \
             tenant-isolated route."
                .to_owned(),
        );
    }

    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::{GatewayRef, MCPGRouteSpec, RouteMatch, RouteToolRef};

    fn route(spec: MCPGRouteSpec) -> MCPGRoute {
        MCPGRoute {
            metadata: ObjectMeta {
                name: Some("r".into()),
                namespace: Some("tenant-a".into()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn base() -> MCPGRouteSpec {
        let mut spec = MCPGRouteSpec {
            gateway_ref: GatewayRef {
                name: "shared".into(),
                namespace: Some("shared-gw".into()),
            },
            r#match: RouteMatch {
                tools: vec![RouteToolRef {
                    id: "orders.list".into(),
                }],
            },
            ..Default::default()
        };
        spec.attributes.insert("tenant".into(), "payments".into());
        spec
    }

    #[test]
    fn valid_route_admits_without_warnings() {
        assert_eq!(validate_spec(&route(base())).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn empty_gateway_ref_rejected() {
        let mut s = base();
        s.gateway_ref.name = "  ".into();
        assert!(
            validate_spec(&route(s))
                .unwrap_err()
                .contains("gatewayRef.name")
        );
    }

    #[test]
    fn empty_tools_rejected() {
        let mut s = base();
        s.r#match.tools.clear();
        assert!(
            validate_spec(&route(s))
                .unwrap_err()
                .contains("match.tools")
        );
    }

    #[test]
    fn duplicate_tool_rejected() {
        let mut s = base();
        s.r#match.tools = vec![
            RouteToolRef {
                id: "orders.list".into(),
            },
            RouteToolRef {
                id: "orders.list".into(),
            },
        ];
        assert!(validate_spec(&route(s)).unwrap_err().contains("duplicate"));
    }

    #[test]
    fn empty_chain_entry_rejected() {
        let mut s = base();
        s.identity_chain = vec!["".into()];
        assert!(
            validate_spec(&route(s))
                .unwrap_err()
                .contains("identityChain")
        );
    }

    #[test]
    fn missing_tenant_warns_not_rejects() {
        let mut s = base();
        s.attributes.remove("tenant");
        let warnings = validate_spec(&route(s)).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("tenant"));
    }
}
