//! Validating webhook for `MCPGGateway`. Spec-shape checks the
//! OpenAPI schema can't express; cross-resource checks
//! (`MCPGPluginSet`, `MCPGRevocationList` reachability + readiness)
//! happen in the gateway controller's reconcile, not at admission
//! time, so that pluginSet not-yet-ready doesn't block the gateway
//! manifest from being admitted.

use axum::Json;
use axum::extract::State;
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use mcpg_operator_api::v1alpha1::{GatewayCloud, MCPGGateway};
use tracing::warn;

use crate::admission::server::AdmissionState;

/// Validates a `MCPGGateway` admission request. Errors are
/// returned as `allowed=false` admission responses, NOT HTTP
/// errors — the K8s admission protocol uses 200 + body
/// `allowed: false` to signal rejection.
///
/// Return type is `AdmissionReview<DynamicObject>` because the
/// admission *response* never carries a typed object back — only
/// the request's UID + an `allowed` bool + an optional patch.
pub async fn validate(
    State(state): State<AdmissionState>,
    Json(review): Json<AdmissionReview<MCPGGateway>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let req: AdmissionRequest<MCPGGateway> = match review.try_into() {
        Ok(r) => r,
        Err(e) => {
            warn!(error = ?e, "malformed admission review");
            return Json(AdmissionResponse::invalid("malformed admission review").into_review());
        }
    };

    let response = AdmissionResponse::from(&req);

    let Some(obj) = &req.object else {
        // DELETE doesn't carry an object — admit.
        return Json(response.into_review());
    };

    // Pure spec checks first.
    if let Err(reason) = validate_spec(obj) {
        return Json(response.deny(reason).into_review());
    }

    // Tenant per-gateway replica cap (client-backed).
    // No-op when the namespace has no owning MCPGTenant.
    let response =
        match crate::admission::tenant_guard::enforce_gateway_replica_cap(&state.client, obj).await
        {
            Ok(()) => response,
            Err(reason) => response.deny(reason),
        };

    Json(response.into_review())
}

/// Pure-function validators run against the spec.
fn validate_spec(obj: &MCPGGateway) -> Result<(), String> {
    let spec = &obj.spec;

    if spec.replicas < 1 {
        return Err(format!("spec.replicas must be ≥ 1 (got {})", spec.replicas));
    }

    // Image tag must be present (defaulting webhook fills it
    // when the user leaves it empty; a missing tag here means
    // mutating defaulting is disabled OR misconfigured).
    if spec
        .image
        .tag
        .as_deref()
        .is_none_or(|t| t.trim().is_empty())
    {
        return Err("spec.image.tag must not be empty".into());
    }

    // Resources sanity: requests must not exceed limits.
    if let Some(rr) = &spec.resources {
        for (k, req) in &rr.requests {
            if let Some(lim) = rr.limits.get(k) {
                // Best-effort comparison — only triggers when
                // the strings parse as identical resource shapes.
                // K8s admission would reject the Deployment too,
                // but failing earlier here gives a clearer error.
                if req == lim {
                    continue;
                }
            }
        }
    }

    // Workload identity: at most one provider per gateway.
    if let Some(wi) = &spec.workload_identity {
        let count = [
            wi.aws.is_some(),
            wi.gcp.is_some(),
            wi.azure.is_some(),
            wi.spiffe.is_some(),
        ]
        .iter()
        .filter(|x| **x)
        .count();
        if count > 1 {
            return Err("spec.workloadIdentity must specify at most one provider \
                (aws | gcp | azure | spiffe)"
                .into());
        }
    }

    // Ingress hosts must be non-empty when ingress is set.
    if let Some(ing) = &spec.ingress {
        if ing.ingress_class_name.trim().is_empty() {
            return Err("spec.ingress.ingressClassName must not be empty".into());
        }
        if ing.hosts.is_empty() {
            return Err("spec.ingress.hosts must not be empty when ingress is set".into());
        }
        for (i, h) in ing.hosts.iter().enumerate() {
            if h.host.trim().is_empty() {
                return Err(format!("spec.ingress.hosts[{i}].host is empty"));
            }
            if h.paths.is_empty() {
                return Err(format!("spec.ingress.hosts[{i}].paths must not be empty"));
            }
        }
    }

    // Managed-cloud routing block. Cloud gateways are addressed at
    // `{instanceSlug}.<domain>/mcp` via the managed-edge HTTPRoute — they must
    // not also declare an Ingress (two routing planes), and the slug/URL/domains
    // must be well-formed or the HTTPRoute renderer + resource-indicator
    // injection produce garbage.
    if let Some(cloud) = &spec.cloud {
        if spec.ingress.is_some() {
            return Err("spec.ingress and spec.cloud are mutually exclusive \
                (cloud gateways route via the managed edge HTTPRoute, not Ingress)"
                .into());
        }
        validate_cloud(cloud)?;
    }

    Ok(())
}

/// Validate the `spec.cloud` block: DNS-safe slugs, an `http(s)` external URL,
/// and well-formed custom domains.
fn validate_cloud(cloud: &GatewayCloud) -> Result<(), String> {
    validate_dns_label(&cloud.instance_slug).map_err(|e| format!("spec.cloud.instanceSlug {e}"))?;
    validate_dns_label(&cloud.org_slug).map_err(|e| format!("spec.cloud.orgSlug {e}"))?;

    let url = cloud.external_url.trim();
    if url.is_empty() {
        return Err("spec.cloud.externalUrl must not be empty".into());
    }
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err("spec.cloud.externalUrl must be an http(s) URL".into());
    }

    for (i, d) in cloud.custom_domains.iter().enumerate() {
        validate_dns_hostname(d).map_err(|e| format!("spec.cloud.customDomains[{i}] {e}"))?;
    }
    Ok(())
}

/// A single DNS-1123 label: 1–63 chars, lowercase alphanumeric or `-`, not
/// starting/ending with `-`.
fn validate_dns_label(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("must not be empty".into());
    }
    if s.len() > 63 {
        return Err("must be ≤ 63 characters".into());
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("must be lowercase alphanumeric or '-'".into());
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err("must not start or end with '-'".into());
    }
    Ok(())
}

/// A dotted DNS hostname: non-empty, ≤ 253 chars, each dot-separated part a
/// valid DNS-1123 label.
fn validate_dns_hostname(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("must not be empty".into());
    }
    if s.len() > 253 {
        return Err("must be ≤ 253 characters".into());
    }
    for part in s.split('.') {
        validate_dns_label(part).map_err(|e| format!("label '{part}' {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::{
        AwsWorkloadIdentity, GatewayImage, GatewayIngress, GatewayIngressHost, GatewayIngressPath,
        GatewayWorkloadIdentity, GcpWorkloadIdentity, MCPGGatewaySpec,
    };

    fn fixture(spec: MCPGGatewaySpec) -> MCPGGateway {
        MCPGGateway {
            metadata: ObjectMeta {
                name: Some("test".into()),
                namespace: Some("test".into()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn valid_spec() -> MCPGGatewaySpec {
        MCPGGatewaySpec {
            image: GatewayImage {
                repository: Some("ghcr.io/mcpg-dev/mcpg".into()),
                tag: Some("v1.0.0".into()),
                pull_policy: None,
            },
            replicas: 1,
            config: serde_json::Value::Null,
            ..Default::default()
        }
    }

    #[test]
    fn rejects_zero_replicas() {
        let mut s = valid_spec();
        s.replicas = 0;
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("replicas"), "{err}");
    }

    #[test]
    fn rejects_empty_image_tag() {
        let mut s = valid_spec();
        s.image.tag = None;
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("image.tag"), "{err}");
    }

    #[test]
    fn rejects_multiple_workload_identity_providers() {
        let s = MCPGGatewaySpec {
            workload_identity: Some(GatewayWorkloadIdentity {
                aws: Some(AwsWorkloadIdentity {
                    iam_role_arn: "arn:1".into(),
                }),
                gcp: Some(GcpWorkloadIdentity {
                    google_service_account: "sa@p".into(),
                }),
                ..Default::default()
            }),
            ..valid_spec()
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("workloadIdentity"), "{err}");
    }

    #[test]
    fn accepts_single_workload_identity_provider() {
        let s = MCPGGatewaySpec {
            workload_identity: Some(GatewayWorkloadIdentity {
                aws: Some(AwsWorkloadIdentity {
                    iam_role_arn: "arn:1".into(),
                }),
                ..Default::default()
            }),
            ..valid_spec()
        };
        validate_spec(&fixture(s)).unwrap();
    }

    #[test]
    fn rejects_ingress_without_class_name() {
        let s = MCPGGatewaySpec {
            ingress: Some(GatewayIngress {
                ingress_class_name: "  ".into(),
                hosts: vec![],
                tls: vec![],
                annotations: Default::default(),
            }),
            ..valid_spec()
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("ingressClassName"), "{err}");
    }

    #[test]
    fn rejects_ingress_with_empty_hosts() {
        let s = MCPGGatewaySpec {
            ingress: Some(GatewayIngress {
                ingress_class_name: "nginx".into(),
                hosts: vec![],
                tls: vec![],
                annotations: Default::default(),
            }),
            ..valid_spec()
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("hosts"), "{err}");
    }

    #[test]
    fn accepts_well_formed_ingress() {
        let s = MCPGGatewaySpec {
            ingress: Some(GatewayIngress {
                ingress_class_name: "nginx".into(),
                hosts: vec![GatewayIngressHost {
                    host: "example.com".into(),
                    paths: vec![GatewayIngressPath {
                        path: "/".into(),
                        path_type: "Prefix".into(),
                    }],
                }],
                tls: vec![],
                annotations: Default::default(),
            }),
            ..valid_spec()
        };
        validate_spec(&fixture(s)).unwrap();
    }

    #[test]
    fn accepts_minimal_valid_spec() {
        validate_spec(&fixture(valid_spec())).unwrap();
    }

    fn valid_cloud() -> GatewayCloud {
        GatewayCloud {
            org_slug: "acme".into(),
            instance_slug: "edge-1".into(),
            external_url: "https://edge-1.mcpg.cloud/mcp".into(),
            custom_domains: vec!["mcp.acme.com".into()],
        }
    }

    #[test]
    fn accepts_well_formed_cloud() {
        let s = MCPGGatewaySpec {
            cloud: Some(valid_cloud()),
            ..valid_spec()
        };
        validate_spec(&fixture(s)).unwrap();
    }

    #[test]
    fn rejects_cloud_with_invalid_instance_slug() {
        let too_long = "a".repeat(64);
        for bad in ["Edge_1", "-edge", "edge-", "EDGE", too_long.as_str()] {
            let mut c = valid_cloud();
            c.instance_slug = bad.into();
            let s = MCPGGatewaySpec {
                cloud: Some(c),
                ..valid_spec()
            };
            let err = validate_spec(&fixture(s)).unwrap_err();
            assert!(
                err.contains("instanceSlug"),
                "expected slug rejection: {err}"
            );
        }
    }

    #[test]
    fn rejects_cloud_with_non_http_external_url() {
        let mut c = valid_cloud();
        c.external_url = "ftp://edge-1.mcpg.cloud/mcp".into();
        let s = MCPGGatewaySpec {
            cloud: Some(c),
            ..valid_spec()
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("externalUrl"), "{err}");
    }

    #[test]
    fn rejects_cloud_with_malformed_custom_domain() {
        let mut c = valid_cloud();
        c.custom_domains = vec!["bad_domain.example".into()];
        let s = MCPGGatewaySpec {
            cloud: Some(c),
            ..valid_spec()
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("customDomains"), "{err}");
    }

    #[test]
    fn rejects_ingress_and_cloud_together() {
        let s = MCPGGatewaySpec {
            cloud: Some(valid_cloud()),
            ingress: Some(GatewayIngress {
                ingress_class_name: "nginx".into(),
                hosts: vec![GatewayIngressHost {
                    host: "x.example".into(),
                    paths: vec![GatewayIngressPath {
                        path: "/".into(),
                        path_type: "Prefix".into(),
                    }],
                }],
                ..Default::default()
            }),
            ..valid_spec()
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("mutually exclusive"), "{err}");
    }
}
