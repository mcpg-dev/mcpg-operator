//! Validating webhook for `MCPGServer`.
//!
//! Spec-shape checks the OpenAPI schema can't express:
//!
//! - `image` must be non-empty; with `spec.verify` set it must be
//!   digest-pinned (`repo@sha256:…`) — a tag can be re-pointed after
//!   verification, defeating the signature gate.
//! - `port` must be a valid TCP port.
//! - `federate.gatewayRef.name` must be non-empty when `federate` is
//!   set; the federation name (override or object name) must be a
//!   config-safe token.
//! - `federate.governance` must be a block the gateway accepts: known
//!   keys only, a known trust level, and an `allow_if` that compiles.
//!   An update that leaves the block as it was is not held to this, so a
//!   stored server whose block the gateway refuses can still be edited
//!   and have its finalizer released on delete. The server controller and
//!   the gateway fan-in check it again, and keep such a server out of the
//!   gateway.
//! - a non-digest image WITHOUT `verify` is admitted with a warning
//!   (moving tags make rollbacks + provenance murky) rather than
//!   rejected — dev clusters legitimately track tags.
//!
//! Cross-resource checks (does the gateway exist?) live in the server
//! controller's reconcile (`GatewayBound`), so a server can be admitted
//! before its gateway is created.

use axum::Json;
use axum::extract::State;
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use mcpg_operator_api::v1alpha1::MCPGServer;
use tracing::warn;

use crate::admission::server::AdmissionState;

pub async fn validate(
    State(_state): State<AdmissionState>,
    Json(review): Json<AdmissionReview<MCPGServer>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let req: AdmissionRequest<MCPGServer> = match review.try_into() {
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

    let response = match validate_spec(obj, req.old_object.as_ref()) {
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

/// `old` is the object an UPDATE replaces; `None` on CREATE.
fn validate_spec(obj: &MCPGServer, old: Option<&MCPGServer>) -> Result<Vec<String>, String> {
    let spec = &obj.spec;
    let mut warnings = Vec::new();

    if spec.image.trim().is_empty() {
        return Err("spec.image must be a non-empty container image reference".to_owned());
    }
    let digest_pinned = spec.image.contains("@sha256:");
    if spec.verify.is_some() && !digest_pinned {
        return Err(
            "spec.verify requires a digest-pinned spec.image (repo@sha256:…): a tag can be \
             re-pointed after verification"
                .to_owned(),
        );
    }
    if spec.verify.is_none() && !digest_pinned {
        warnings.push(
            "spec.image is not digest-pinned; provenance and rollback are ambiguous under a \
             moving tag"
                .to_owned(),
        );
    }

    let port = spec.port();
    if !(1..=65535).contains(&port) {
        return Err(format!("spec.port {port} is not a valid TCP port"));
    }
    if let Some(replicas) = spec.replicas
        && replicas < 0
    {
        return Err("spec.replicas must be >= 0".to_owned());
    }

    if let Some(federate) = spec.federate.as_ref() {
        if federate.gateway_ref.name.trim().is_empty() {
            return Err("spec.federate.gatewayRef.name must be non-empty".to_owned());
        }
        let fed_name = spec.federation_name(obj.metadata.name.as_deref().unwrap_or_default());
        if fed_name.trim().is_empty() {
            return Err("federation name resolves to empty".to_owned());
        }
        if !fed_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(format!(
                "federation name '{fed_name}' must be alphanumeric plus '-', '_', '.'"
            ));
        }
        for (field, value) in [
            ("governance", federate.governance.as_ref()),
            ("import", federate.import.as_ref()),
            ("auth", federate.auth.as_ref()),
        ] {
            if let Some(v) = value
                && !v.is_object()
            {
                return Err(format!("spec.federate.{field} must be a JSON object"));
            }
        }
        let unchanged = old.is_some_and(|old| {
            old.spec
                .federate
                .as_ref()
                .is_some_and(|previous| previous.governance == federate.governance)
        });
        // A stored block the gateway refuses is kept out of the gateway by the
        // fan-in; refusing every write that carries it unchanged would refuse
        // the finalizer release too, and hold the server in Terminating.
        if !unchanged && let Some(error) = crate::templates::federate_governance_error(federate) {
            return Err(error);
        }
    }

    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::{MCPGServerSpec, ServerFederate, ServerGatewayRef};

    fn server(spec: MCPGServerSpec) -> MCPGServer {
        MCPGServer {
            metadata: ObjectMeta {
                name: Some("crm".into()),
                namespace: Some("team-a".into()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn minimal() -> MCPGServerSpec {
        serde_yaml::from_str("image: ghcr.io/acme/crm:1.0.0\n").unwrap()
    }

    #[test]
    fn tag_image_without_verify_warns_but_admits() {
        let warnings = validate_spec(&server(minimal()), None).expect("admitted");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("digest-pinned"));
    }

    #[test]
    fn verify_requires_digest_pin() {
        let mut spec = minimal();
        spec.verify = Some(serde_yaml::from_str(
            "cosignIdentity:\n  oidcIssuer: https://token.actions.githubusercontent.com\n  certificateIdentityRegexp: \"^https://github.com/acme/\"\n",
        )
        .unwrap());
        let err = validate_spec(&server(spec), None).unwrap_err();
        assert!(err.contains("digest-pinned"), "got: {err}");
    }

    #[test]
    fn digest_pin_admits_without_warning() {
        let mut spec = minimal();
        spec.image = format!("ghcr.io/acme/crm@sha256:{}", "a".repeat(64));
        let warnings = validate_spec(&server(spec), None).expect("admitted");
        assert!(warnings.is_empty());
    }

    #[test]
    fn federate_gateway_name_required() {
        let mut spec = minimal();
        spec.federate = Some(ServerFederate {
            gateway_ref: ServerGatewayRef { name: "  ".into() },
            ..Default::default()
        });
        let err = validate_spec(&server(spec), None).unwrap_err();
        assert!(err.contains("gatewayRef.name"), "got: {err}");
    }

    #[test]
    fn federate_blocks_reject_non_objects() {
        let mut spec = minimal();
        spec.federate = Some(ServerFederate {
            gateway_ref: ServerGatewayRef {
                name: "main".into(),
            },
            governance: Some(serde_json::json!("not-an-object")),
            ..Default::default()
        });
        let err = validate_spec(&server(spec), None).unwrap_err();
        assert!(err.contains("governance"), "got: {err}");
    }

    #[test]
    fn federate_governance_the_gateway_refuses_is_rejected() {
        for (governance, needle) in [
            (
                serde_json::json!({ "cel_allow_if": "true" }),
                "cel_allow_if",
            ),
            (
                serde_json::json!({ "minimum_trust": "root" }),
                "spec.federate.governance",
            ),
            (
                serde_json::json!({ "allow_if": "tool_name == " }),
                "spec.federate.governance.allow_if",
            ),
        ] {
            let mut spec = minimal();
            spec.federate = Some(ServerFederate {
                gateway_ref: ServerGatewayRef {
                    name: "main".into(),
                },
                governance: Some(governance.clone()),
                ..Default::default()
            });
            let err = validate_spec(&server(spec), None).unwrap_err();
            assert!(err.contains(needle), "{governance}: {err}");
        }

        let mut spec = minimal();
        spec.federate = Some(ServerFederate {
            gateway_ref: ServerGatewayRef {
                name: "main".into(),
            },
            governance: Some(serde_json::json!({
                "minimum_trust": "verified",
                "allow_if": "\"crm\" in identity.groups",
                "required_scopes": ["crm.read"],
            })),
            ..Default::default()
        });
        validate_spec(&server(spec), None).expect("a valid block is admitted");
    }

    /// A stored server whose block the gateway refuses can still be written
    /// with that block unchanged (an edit, or the finalizer release on
    /// delete); a write that sets or changes the block is held to the check.
    #[test]
    fn an_update_that_keeps_an_admitted_governance_block_is_not_refused() {
        let with_governance = |governance: serde_json::Value| {
            let mut spec = minimal();
            spec.federate = Some(ServerFederate {
                gateway_ref: ServerGatewayRef {
                    name: "main".into(),
                },
                governance: Some(governance),
                ..Default::default()
            });
            server(spec)
        };
        let admitted = with_governance(serde_json::json!({ "cel_allow_if": "true" }));

        let mut releasing = admitted.clone();
        releasing.metadata.finalizers = Some(Vec::new());
        releasing.spec.image = "ghcr.io/acme/crm:1.0.1".into();
        validate_spec(&releasing, Some(&admitted)).expect("the unchanged block is not re-judged");

        let changed = with_governance(serde_json::json!({ "allow_if": "tool_name == " }));
        let err = validate_spec(&changed, Some(&admitted)).unwrap_err();
        assert!(err.contains("spec.federate.governance.allow_if"), "{err}");

        let mut unfederated = admitted.clone();
        unfederated.spec.federate = None;
        let err = validate_spec(&admitted, Some(&unfederated)).unwrap_err();
        assert!(err.contains("cel_allow_if"), "{err}");
    }

    #[test]
    fn invalid_port_rejected() {
        let mut spec = minimal();
        spec.port = Some(0);
        assert!(validate_spec(&server(spec), None).is_err());
    }
}
