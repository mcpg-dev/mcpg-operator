//! Validating webhook for `MCPGCluster`.
//!
//! Spec-shape checks the OpenAPI schema can't express:
//!
//! - `single_node` must NOT carry backend `config` (it takes no
//!   params; a stray block is almost always a mis-set `backend`).
//! - Non-`single_node` backends MUST carry a non-empty `config`
//!   (an external coordinator with no address/connection block is a
//!   misconfiguration that would only surface at gateway boot).
//! - `credentialRefs[].name` must be unique + non-empty (they map to
//!   `cred://cluster/<name>`; collisions silently shadow).
//! - `credentialRefs[].secretName` must be non-empty.
//!
//! Backend bindability (is the pinned plugin verified?) is a
//! cross-resource check and lives in the cluster controller's
//! reconcile, not at admission — so a cluster can be admitted before
//! its plugin finishes verifying.

use std::collections::BTreeSet;

use axum::Json;
use axum::extract::State;
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use mcpg_operator_api::v1alpha1::MCPGCluster;
use tracing::warn;

use crate::admission::server::AdmissionState;

pub async fn validate(
    State(_state): State<AdmissionState>,
    Json(review): Json<AdmissionReview<MCPGCluster>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let req: AdmissionRequest<MCPGCluster> = match review.try_into() {
        Ok(r) => r,
        Err(e) => {
            warn!(error = ?e, "malformed admission review");
            return Json(AdmissionResponse::invalid("malformed admission review").into_review());
        }
    };

    let response = AdmissionResponse::from(&req);
    let Some(obj) = &req.object else {
        // DELETE carries no object — admit.
        return Json(response.into_review());
    };

    let response = match validate_spec(obj) {
        Ok(()) => response,
        Err(reason) => response.deny(reason),
    };

    Json(response.into_review())
}

fn validate_spec(obj: &MCPGCluster) -> Result<(), String> {
    let spec = &obj.spec;

    if spec.backend.is_single_node() {
        if !spec.config.is_empty() {
            return Err(
                "spec.config must be empty for the single_node backend (it takes no \
                 parameters). Did you mean to set spec.backend to redis / nats / consul / etcd?"
                    .to_owned(),
            );
        }
    } else if spec.config.is_empty() {
        return Err(format!(
            "spec.config must not be empty for the '{}' backend — it needs at least a \
             connection address (e.g. `url`/`servers`/`endpoints`).",
            spec.backend.config_kind()
        ));
    }

    // Transport-security parity with the gateway boot guard: reject a
    // plaintext coordinator at admission rather than letting it CrashLoop the
    // bound gateway pods with an opaque error. Opt out per-cluster with
    // `spec.config.allow_insecure_transport: true` (local/dev only).
    if let Some(reason) = spec.insecure_transport_reason() {
        return Err(format!(
            "spec.config: {reason}. The cluster coordinator carries all shared state \
             (sessions, credential-cache events, delivery payloads) across bound gateways — \
             a plaintext transport exposes them. Use a TLS scheme, or set \
             `spec.config.allow_insecure_transport: true` to accept plaintext (local/dev only)."
        ));
    }

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (i, cred) in spec.credential_refs.iter().enumerate() {
        if cred.name.trim().is_empty() {
            return Err(format!("spec.credentialRefs[{i}].name must not be empty"));
        }
        if cred.secret_name.trim().is_empty() {
            return Err(format!(
                "spec.credentialRefs[{i}].secretName must not be empty"
            ));
        }
        if !seen.insert(cred.name.as_str()) {
            return Err(format!(
                "spec.credentialRefs[{i}].name '{}' is duplicated; each credential name \
                 maps to a distinct cred://cluster/<name> and must be unique",
                cred.name
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::{ClusterBackend, ClusterCredentialRef, MCPGClusterSpec};

    fn fixture(spec: MCPGClusterSpec) -> MCPGCluster {
        MCPGCluster {
            metadata: ObjectMeta {
                name: Some("c".into()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn cfg(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect()
    }

    #[test]
    fn single_node_with_config_rejected() {
        let s = MCPGClusterSpec {
            backend: ClusterBackend::SingleNode,
            config: cfg(&[("url", "x")]),
            ..Default::default()
        };
        assert!(
            validate_spec(&fixture(s))
                .unwrap_err()
                .contains("single_node")
        );
    }

    #[test]
    fn single_node_empty_config_ok() {
        let s = MCPGClusterSpec {
            backend: ClusterBackend::SingleNode,
            ..Default::default()
        };
        validate_spec(&fixture(s)).unwrap();
    }

    #[test]
    fn external_backend_empty_config_rejected() {
        let s = MCPGClusterSpec {
            backend: ClusterBackend::Redis,
            ..Default::default()
        };
        assert!(
            validate_spec(&fixture(s))
                .unwrap_err()
                .contains("must not be empty")
        );
    }

    #[test]
    fn external_backend_with_config_ok() {
        let s = MCPGClusterSpec {
            backend: ClusterBackend::Nats,
            config: cfg(&[("servers", "nats://n:4222")]),
            ..Default::default()
        };
        validate_spec(&fixture(s)).unwrap();
    }

    #[test]
    fn duplicate_credential_name_rejected() {
        let s = MCPGClusterSpec {
            backend: ClusterBackend::Redis,
            config: cfg(&[("url", "rediss://r:6379")]),
            credential_refs: vec![
                ClusterCredentialRef {
                    name: "password".into(),
                    secret_name: "s1".into(),
                    key: None,
                },
                ClusterCredentialRef {
                    name: "password".into(),
                    secret_name: "s2".into(),
                    key: None,
                },
            ],
            ..Default::default()
        };
        assert!(
            validate_spec(&fixture(s))
                .unwrap_err()
                .contains("duplicated")
        );
    }

    /// Build a config map from a JSON object literal (for array/bool values).
    fn cfg_json(v: serde_json::Value) -> std::collections::BTreeMap<String, serde_json::Value> {
        match v {
            serde_json::Value::Object(m) => m.into_iter().collect(),
            _ => panic!("expected object"),
        }
    }

    #[test]
    fn plaintext_redis_rejected() {
        let s = MCPGClusterSpec {
            backend: ClusterBackend::Redis,
            config: cfg(&[("url", "redis://r:6379")]),
            ..Default::default()
        };
        assert!(
            validate_spec(&fixture(s))
                .unwrap_err()
                .contains("rediss://")
        );
    }

    #[test]
    fn rediss_redis_ok() {
        let s = MCPGClusterSpec {
            backend: ClusterBackend::Redis,
            config: cfg(&[("url", "rediss://r:6379")]),
            ..Default::default()
        };
        validate_spec(&fixture(s)).unwrap();
    }

    #[test]
    fn plaintext_redis_with_opt_out_ok() {
        let s = MCPGClusterSpec {
            backend: ClusterBackend::Redis,
            config: cfg_json(serde_json::json!({
                "url": "redis://r:6379",
                "allow_insecure_transport": true
            })),
            ..Default::default()
        };
        validate_spec(&fixture(s)).unwrap();
    }

    #[test]
    fn plaintext_consul_rejected() {
        let s = MCPGClusterSpec {
            backend: ClusterBackend::Consul,
            config: cfg(&[("address", "http://consul:8500")]),
            ..Default::default()
        };
        assert!(validate_spec(&fixture(s)).unwrap_err().contains("https://"));
    }

    #[test]
    fn scheme_less_etcd_rejected() {
        let s = MCPGClusterSpec {
            backend: ClusterBackend::Etcd,
            config: cfg_json(serde_json::json!({ "endpoints": ["etcd-0:2379"] })),
            ..Default::default()
        };
        assert!(validate_spec(&fixture(s)).unwrap_err().contains("https://"));
    }

    #[test]
    fn https_etcd_ok() {
        let s = MCPGClusterSpec {
            backend: ClusterBackend::Etcd,
            config: cfg_json(serde_json::json!({
                "endpoints": ["https://etcd-0:2379"],
                "tls": {}
            })),
            ..Default::default()
        };
        validate_spec(&fixture(s)).unwrap();
    }

    #[test]
    fn nats_require_tls_false_rejected() {
        let s = MCPGClusterSpec {
            backend: ClusterBackend::Nats,
            config: cfg_json(serde_json::json!({
                "servers": ["nats://n:4222"],
                "tls": { "require_tls": false }
            })),
            ..Default::default()
        };
        assert!(
            validate_spec(&fixture(s))
                .unwrap_err()
                .contains("require_tls")
        );
    }

    #[test]
    fn empty_credential_secret_name_rejected() {
        let s = MCPGClusterSpec {
            backend: ClusterBackend::Redis,
            config: cfg(&[("url", "rediss://r:6379")]),
            credential_refs: vec![ClusterCredentialRef {
                name: "password".into(),
                secret_name: "  ".into(),
                key: None,
            }],
            ..Default::default()
        };
        assert!(
            validate_spec(&fixture(s))
                .unwrap_err()
                .contains("secretName")
        );
    }
}
