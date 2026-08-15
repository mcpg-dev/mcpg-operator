//! Validating webhook for `MCPGPluginMirror`.
//!
//! Spec-shape checks the OpenAPI schema can't express:
//!
//! - `endpoint.service.{namespace,name}` non-empty, `port` in 1..=65535.
//! - `upstream.{registry,namespace}` non-empty (the rewrite prefix is
//!   `<registry>/<namespace>/`; an empty half would match nothing or
//!   everything).
//! - `upstream.registry` looks like a registry host (contains a `.` or
//!   `:` — catches `ghcr.io`, `localhost:5000`; rejects a bare word
//!   that's almost certainly a mistake).
//! - `auth.secretRef.secretName` non-empty when `auth` is set.

use axum::Json;
use axum::extract::State;
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use mcpg_operator_api::v1alpha1::MCPGPluginMirror;
use tracing::warn;

use crate::admission::server::AdmissionState;

pub async fn validate(
    State(_state): State<AdmissionState>,
    Json(review): Json<AdmissionReview<MCPGPluginMirror>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let req: AdmissionRequest<MCPGPluginMirror> = match review.try_into() {
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
        Ok(()) => response,
        Err(reason) => response.deny(reason),
    };

    Json(response.into_review())
}

fn validate_spec(obj: &MCPGPluginMirror) -> Result<(), String> {
    let spec = &obj.spec;
    let svc = &spec.endpoint.service;

    if svc.namespace.trim().is_empty() {
        return Err("spec.endpoint.service.namespace must not be empty".to_owned());
    }
    if svc.name.trim().is_empty() {
        return Err("spec.endpoint.service.name must not be empty".to_owned());
    }
    if svc.port == 0 {
        return Err("spec.endpoint.service.port must be in 1..=65535".to_owned());
    }

    if spec.upstream.registry.trim().is_empty() {
        return Err("spec.upstream.registry must not be empty".to_owned());
    }
    if !spec.upstream.registry.contains('.') && !spec.upstream.registry.contains(':') {
        return Err(format!(
            "spec.upstream.registry '{}' does not look like a registry host (expected a \
             hostname like 'ghcr.io' or 'host:port')",
            spec.upstream.registry
        ));
    }
    if spec.upstream.namespace.trim().is_empty() {
        return Err("spec.upstream.namespace must not be empty".to_owned());
    }

    if let Some(auth) = &spec.auth
        && auth.secret_ref.secret_name.trim().is_empty()
    {
        return Err("spec.auth.secretRef.secretName must not be empty when auth is set".to_owned());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::{
        MCPGPluginMirrorSpec, MirrorEndpoint, MirrorService, MirrorUpstream,
    };

    fn fixture(spec: MCPGPluginMirrorSpec) -> MCPGPluginMirror {
        MCPGPluginMirror {
            metadata: ObjectMeta {
                name: Some("m".into()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn base() -> MCPGPluginMirrorSpec {
        MCPGPluginMirrorSpec {
            endpoint: MirrorEndpoint {
                service: MirrorService {
                    namespace: "oci-mirror".into(),
                    name: "harbor".into(),
                    port: 80,
                    path_prefix: None,
                },
                insecure: true,
            },
            upstream: MirrorUpstream {
                registry: "ghcr.io".into(),
                namespace: "mcpg-dev/source-code".into(),
            },
            auth: None,
            resync_interval: None,
        }
    }

    #[test]
    fn valid_mirror_admits() {
        validate_spec(&fixture(base())).unwrap();
    }

    #[test]
    fn zero_port_rejected() {
        let mut s = base();
        s.endpoint.service.port = 0;
        assert!(validate_spec(&fixture(s)).unwrap_err().contains("port"));
    }

    #[test]
    fn empty_service_name_rejected() {
        let mut s = base();
        s.endpoint.service.name = "  ".into();
        assert!(
            validate_spec(&fixture(s))
                .unwrap_err()
                .contains("service.name")
        );
    }

    #[test]
    fn bare_word_registry_rejected() {
        let mut s = base();
        s.upstream.registry = "ghcr".into();
        assert!(
            validate_spec(&fixture(s))
                .unwrap_err()
                .contains("registry host")
        );
    }

    #[test]
    fn host_port_registry_ok() {
        let mut s = base();
        s.upstream.registry = "localhost:5000".into();
        validate_spec(&fixture(s)).unwrap();
    }

    #[test]
    fn empty_upstream_namespace_rejected() {
        let mut s = base();
        s.upstream.namespace = "".into();
        assert!(
            validate_spec(&fixture(s))
                .unwrap_err()
                .contains("upstream.namespace")
        );
    }
}
