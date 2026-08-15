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

fn validate_spec(obj: &MCPGServer) -> Result<Vec<String>, String> {
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
        let warnings = validate_spec(&server(minimal())).expect("admitted");
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
        let err = validate_spec(&server(spec)).unwrap_err();
        assert!(err.contains("digest-pinned"), "got: {err}");
    }

    #[test]
    fn digest_pin_admits_without_warning() {
        let mut spec = minimal();
        spec.image = format!("ghcr.io/acme/crm@sha256:{}", "a".repeat(64));
        let warnings = validate_spec(&server(spec)).expect("admitted");
        assert!(warnings.is_empty());
    }

    #[test]
    fn federate_gateway_name_required() {
        let mut spec = minimal();
        spec.federate = Some(ServerFederate {
            gateway_ref: ServerGatewayRef { name: "  ".into() },
            ..Default::default()
        });
        let err = validate_spec(&server(spec)).unwrap_err();
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
        let err = validate_spec(&server(spec)).unwrap_err();
        assert!(err.contains("governance"), "got: {err}");
    }

    #[test]
    fn invalid_port_rejected() {
        let mut spec = minimal();
        spec.port = Some(0);
        assert!(validate_spec(&server(spec)).is_err());
    }
}
