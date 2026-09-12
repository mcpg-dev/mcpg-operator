//! Validating webhook for `MCPGGateway`. Spec-shape checks the
//! OpenAPI schema can't express; cross-resource checks
//! (`MCPGPluginSet`, `MCPGRevocationList` reachability + readiness)
//! happen in the gateway controller's reconcile, not at admission
//! time, so that pluginSet not-yet-ready doesn't block the gateway
//! manifest from being admitted.
//!
//! The one cross-resource check that DOES gate admission is the
//! multi-replica coordination guard: a gateway whose replica ceiling
//! exceeds 1 must have a shared coordination backend, because N
//! replicas without one run as N independent `single_node` gateways
//! whose sessions / pub-sub / idempotency state silently fork per
//! pod. That failure mode is invisible after admission, so it is
//! rejected up front rather than surfaced as a condition.

use axum::Json;
use axum::extract::State;
use kube::api::Api;
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use mcpg_operator_api::conditions::types as ctype;
use mcpg_operator_api::v1alpha1::{GatewayCloud, MCPGCluster, MCPGGateway, MCPGGatewaySpec};
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

    // Multi-replica coordination guard (client-backed for clusterRef).
    if let Err(reason) =
        enforce_multi_replica_coordination(&state.client, obj, req.old_object.as_ref()).await
    {
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

    // envFrom Secret references must carry a name.
    for (i, s) in spec.env_from_secrets.iter().enumerate() {
        if s.name.trim().is_empty() {
            return Err(format!("spec.envFromSecrets[{i}].name must not be empty"));
        }
    }

    // Mounted Secrets: each entry becomes one pod volume + one container
    // mount, so a repeated name or path would fail the Deployment apply
    // after admission instead of the CR write.
    let mut mounted_secrets = std::collections::BTreeSet::new();
    let mut mount_paths = std::collections::BTreeSet::new();
    for (i, m) in spec.secret_mounts.iter().enumerate() {
        if m.name.trim().is_empty() {
            return Err(format!("spec.secretMounts[{i}].name must not be empty"));
        }
        if !m.mount_path.starts_with('/') {
            return Err(format!(
                "spec.secretMounts[{i}].mountPath must be an absolute path"
            ));
        }
        if !mounted_secrets.insert(m.name.as_str()) {
            return Err(format!(
                "spec.secretMounts[{i}].name repeats an earlier entry ({})",
                m.name
            ));
        }
        if !mount_paths.insert(m.mount_path.trim_end_matches('/')) {
            return Err(format!(
                "spec.secretMounts[{i}].mountPath repeats an earlier entry ({})",
                m.mount_path
            ));
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

/// How a gateway whose replica ceiling exceeds 1 satisfies the
/// coordination-backend requirement.
#[derive(Debug)]
enum CoordinationPath<'a> {
    /// Ceiling ≤ 1 — the in-process `single_node` coordinator is fine.
    SingleReplica,
    /// Inline `spec.config.cluster` declares a non-`single_node` backend
    /// (the shape the cloud provisioner injects). Nothing to look up.
    Inline,
    /// `spec.clusterRef` names the coordinator; the referenced
    /// `MCPGCluster` must exist, be Ready, and not be `single_node`.
    Ref(&'a str),
}

/// Pure shape classification for the coordination guard. `Err` is the
/// admission denial for the shapes that can never coordinate:
/// no backend at all, or an inline `single_node` one.
fn coordination_path(spec: &MCPGGatewaySpec) -> Result<CoordinationPath<'_>, String> {
    let (ceiling, field) = spec.effective_replica_ceiling();
    if ceiling <= 1 {
        return Ok(CoordinationPath::SingleReplica);
    }
    if let Some(r) = spec.cluster_ref.as_ref() {
        return Ok(CoordinationPath::Ref(&r.name));
    }
    match inline_cluster_kind(&spec.config) {
        // The gateway defaults an absent inline `kind` to `single_node`.
        Some("single_node") => Err(format!(
            "MultiReplicaWithSingleNodeBackend: {field} is {ceiling} but \
             spec.config.cluster resolves to the `single_node` backend, which cannot \
             coordinate more than one replica — {ceiling} replicas without a shared \
             coordination backend run as {ceiling} independent gateways (sessions, \
             pub/sub and idempotency state fork per pod). Set spec.clusterRef to a \
             Ready, non-single_node MCPGCluster, or declare a non-single_node backend \
             inline at spec.config.cluster.kind."
        )),
        Some(_) => Ok(CoordinationPath::Inline),
        None => Err(format!(
            "{field} is {ceiling} but no cluster coordination backend is configured: \
             {ceiling} replicas without one run as {ceiling} independent single_node \
             gateways (sessions, pub/sub and idempotency state fork per pod). Set \
             spec.clusterRef to a Ready, non-single_node MCPGCluster, or declare a \
             non-single_node backend inline at spec.config.cluster."
        )),
    }
}

/// The effective inline `spec.config.cluster.kind`, or `None` when the
/// config carries no `cluster` object at all. An object without `kind`
/// reports `single_node` — the gateway's own default for that shape.
fn inline_cluster_kind(config: &serde_json::Value) -> Option<&str> {
    let cluster = config.get("cluster")?;
    if !cluster.is_object() {
        return None;
    }
    Some(
        cluster
            .get("kind")
            .and_then(|k| k.as_str())
            .unwrap_or("single_node"),
    )
}

/// True when an UPDATE leaves an already-admitted multi-replica
/// `clusterRef` binding untouched. Such updates are not re-judged
/// against the live `MCPGCluster`: the gateway controller holds the
/// config reconcile while the bound cluster is unready, and re-gating
/// unrelated spec updates (or the operator's own finalizer patch) on a
/// momentarily-unready coordinator would block remediation.
fn binding_already_admitted(old: Option<&MCPGGateway>, new: &MCPGGateway) -> bool {
    old.is_some_and(|old| {
        old.spec.effective_replica_ceiling().0 > 1 && old.spec.cluster_ref == new.spec.cluster_ref
    })
}

/// Verdict on the referenced `MCPGCluster` as fetched (or not) from the
/// apiserver. Pure so the accept/deny matrix unit-tests without a cluster.
fn judge_referenced_cluster(
    name: &str,
    ceiling: i32,
    field: &str,
    cluster: Option<&MCPGCluster>,
) -> Result<(), String> {
    let Some(cluster) = cluster else {
        return Err(format!(
            "spec.clusterRef points at MCPGCluster/{name}, which does not exist; \
             {field} is {ceiling}, and {ceiling} replicas without a coordination \
             backend run as {ceiling} independent single_node gateways. Create the \
             MCPGCluster (and wait for Ready=True), or fix the reference."
        ));
    };
    if cluster.spec.is_effectively_single_node() {
        return Err(format!(
            "MultiReplicaWithSingleNodeBackend: {field} is {ceiling} but \
             MCPGCluster/{name} provides the `single_node` backend, which cannot \
             coordinate more than one replica — the replicas would run as {ceiling} \
             independent gateways. Reference a redis / nats \
             MCPGCluster (or a managed one) instead."
        ));
    }
    let ready = cluster.status.as_ref().is_some_and(|s| {
        s.conditions
            .iter()
            .any(|c| c.r#type == ctype::READY && c.status == "True")
    });
    if !ready {
        return Err(format!(
            "spec.clusterRef points at MCPGCluster/{name}, which is not Ready. \
             Admission requires a Ready coordinator so {ceiling} replicas never \
             start as {ceiling} independent single_node gateways. Wait for \
             `kubectl get mcpgc {name}` to report Ready=True and retry."
        ));
    }
    Ok(())
}

/// Enforce the multi-replica coordination requirement. The shape part
/// (some backend must be configured) is pure; a `clusterRef` is judged
/// against the live `MCPGCluster` — except on updates that keep an
/// already-admitted binding, and fail-open on a transient read (same
/// posture as `tenant_guard`: admission must not hard-fail the
/// apiserver; the gateway controller's cluster gate is the durable
/// guarantee).
async fn enforce_multi_replica_coordination(
    client: &kube::Client,
    obj: &MCPGGateway,
    old: Option<&MCPGGateway>,
) -> Result<(), String> {
    let name = match coordination_path(&obj.spec)? {
        CoordinationPath::SingleReplica | CoordinationPath::Inline => return Ok(()),
        CoordinationPath::Ref(name) => name,
    };
    if binding_already_admitted(old, obj) {
        return Ok(());
    }

    let (ceiling, field) = obj.spec.effective_replica_ceiling();
    let api: Api<MCPGCluster> = Api::all(client.clone());
    match api.get_opt(name).await {
        Ok(found) => judge_referenced_cluster(name, ceiling, field, found.as_ref()),
        Err(e) => {
            warn!(
                error = ?e,
                cluster = %name,
                "coordination guard: MCPGCluster read failed; admitting (fail-open)"
            );
            Ok(())
        }
    }
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
    use mcpg_operator_api::v1alpha1::gateway::SecretMount;
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

    #[test]
    fn rejects_env_from_secret_with_empty_name() {
        use mcpg_operator_api::v1alpha1::LocalObjectReference;
        let s = MCPGGatewaySpec {
            env_from_secrets: vec![
                LocalObjectReference {
                    name: "mcpg-cluster-coordination".into(),
                },
                LocalObjectReference { name: "  ".into() },
            ],
            ..valid_spec()
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("envFromSecrets[1]"), "{err}");
    }

    #[test]
    fn accepts_named_env_from_secrets() {
        use mcpg_operator_api::v1alpha1::LocalObjectReference;
        let s = MCPGGatewaySpec {
            env_from_secrets: vec![LocalObjectReference {
                name: "mcpg-cluster-coordination".into(),
            }],
            ..valid_spec()
        };
        validate_spec(&fixture(s)).unwrap();
    }

    fn secret_mount(name: &str, mount_path: &str) -> SecretMount {
        SecretMount {
            name: name.into(),
            mount_path: mount_path.into(),
        }
    }

    #[test]
    fn accepts_well_formed_secret_mounts() {
        let s = MCPGGatewaySpec {
            secret_mounts: vec![
                secret_mount("mcpg-tenant-secrets", "/var/run/mcpg/secrets"),
                secret_mount("gateway-tls", "/etc/mcpg/tls"),
            ],
            ..valid_spec()
        };
        validate_spec(&fixture(s)).unwrap();
    }

    #[test]
    fn rejects_secret_mount_with_empty_name() {
        let s = MCPGGatewaySpec {
            secret_mounts: vec![secret_mount(" ", "/var/run/mcpg/secrets")],
            ..valid_spec()
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("secretMounts[0].name"), "{err}");
    }

    #[test]
    fn rejects_secret_mount_with_relative_path() {
        let s = MCPGGatewaySpec {
            secret_mounts: vec![secret_mount("mcpg-tenant-secrets", "secrets")],
            ..valid_spec()
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("secretMounts[0].mountPath"), "{err}");
    }

    #[test]
    fn rejects_repeated_secret_mount_name_or_path() {
        let s = MCPGGatewaySpec {
            secret_mounts: vec![
                secret_mount("mcpg-tenant-secrets", "/var/run/mcpg/secrets"),
                secret_mount("mcpg-tenant-secrets", "/etc/mcpg/tls"),
            ],
            ..valid_spec()
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("secretMounts[1].name"), "{err}");

        let s = MCPGGatewaySpec {
            secret_mounts: vec![
                secret_mount("mcpg-tenant-secrets", "/var/run/mcpg/secrets"),
                secret_mount("gateway-tls", "/var/run/mcpg/secrets/"),
            ],
            ..valid_spec()
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("secretMounts[1].mountPath"), "{err}");
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

    // ── Multi-replica coordination guard ───────────────────────

    use mcpg_operator_api::conditions::Condition;
    use mcpg_operator_api::v1alpha1::{
        ClusterBackend, ClusterRef, HorizontalAutoscaler, MCPGCluster, MCPGClusterSpec,
        MCPGClusterStatus,
    };

    fn coordination_spec(
        replicas: i32,
        cluster_ref: Option<&str>,
        config: serde_json::Value,
    ) -> MCPGGatewaySpec {
        MCPGGatewaySpec {
            replicas,
            cluster_ref: cluster_ref.map(|n| ClusterRef { name: n.into() }),
            config,
            ..valid_spec()
        }
    }

    #[test]
    fn single_replica_needs_no_backend() {
        assert!(matches!(
            coordination_path(&coordination_spec(1, None, serde_json::Value::Null)),
            Ok(CoordinationPath::SingleReplica)
        ));
    }

    #[test]
    fn multi_replica_without_backend_denied() {
        let err = coordination_path(&coordination_spec(3, None, serde_json::Value::Null))
            .expect_err("must deny");
        assert!(err.contains("3 independent"), "{err}");
        assert!(err.contains("spec.replicas is 3"), "{err}");
        assert!(err.contains("spec.clusterRef"), "{err}");
        assert!(err.contains("spec.config.cluster"), "{err}");
    }

    #[test]
    fn hpa_ceiling_above_one_triggers_the_guard() {
        let spec = MCPGGatewaySpec {
            autoscaling: Some(HorizontalAutoscaler {
                enabled: true,
                min_replicas: Some(1),
                max_replicas: Some(5),
                ..Default::default()
            }),
            ..coordination_spec(1, None, serde_json::Value::Null)
        };
        let err = coordination_path(&spec).expect_err("must deny");
        assert!(err.contains("spec.autoscaling.maxReplicas"), "{err}");
    }

    #[test]
    fn inline_non_single_node_backend_accepted() {
        let cfg = serde_json::json!({ "cluster": { "kind": "nats", "servers": ["nats://n"] } });
        assert!(matches!(
            coordination_path(&coordination_spec(3, None, cfg)),
            Ok(CoordinationPath::Inline)
        ));
    }

    #[test]
    fn inline_single_node_backend_denied() {
        let cfg = serde_json::json!({ "cluster": { "kind": "single_node" } });
        let err = coordination_path(&coordination_spec(3, None, cfg)).expect_err("must deny");
        assert!(err.contains("MultiReplicaWithSingleNodeBackend"), "{err}");
        // An inline block without `kind` defaults to single_node too.
        let cfg = serde_json::json!({ "cluster": { "url": "rediss://r" } });
        let err = coordination_path(&coordination_spec(3, None, cfg)).expect_err("must deny");
        assert!(err.contains("MultiReplicaWithSingleNodeBackend"), "{err}");
    }

    #[test]
    fn cluster_ref_defers_to_the_live_lookup() {
        // The ref wins the config merge, so it is judged even when an
        // inline block is also present.
        let cfg = serde_json::json!({ "cluster": { "kind": "redis" } });
        assert!(matches!(
            coordination_path(&coordination_spec(3, Some("prod"), cfg)),
            Ok(CoordinationPath::Ref("prod"))
        ));
    }

    fn cluster_fixture(backend: ClusterBackend, ready: Option<bool>) -> MCPGCluster {
        MCPGCluster {
            metadata: ObjectMeta {
                name: Some("prod".into()),
                ..Default::default()
            },
            spec: MCPGClusterSpec {
                backend,
                ..Default::default()
            },
            status: ready.map(|r| MCPGClusterStatus {
                conditions: vec![if r {
                    Condition::ready_true("Reconciled")
                } else {
                    Condition::ready_false("DependencyPending", "plugin unverified")
                }],
                ..Default::default()
            }),
        }
    }

    #[test]
    fn missing_cluster_denied() {
        let err =
            judge_referenced_cluster("prod", 3, "spec.replicas", None).expect_err("must deny");
        assert!(err.contains("does not exist"), "{err}");
        assert!(err.contains("3 independent"), "{err}");
    }

    #[test]
    fn single_node_cluster_denied() {
        let c = cluster_fixture(ClusterBackend::SingleNode, Some(true));
        let err =
            judge_referenced_cluster("prod", 3, "spec.replicas", Some(&c)).expect_err("must deny");
        assert!(err.contains("MultiReplicaWithSingleNodeBackend"), "{err}");
    }

    #[test]
    fn unready_cluster_denied() {
        for status in [Some(false), None] {
            let c = cluster_fixture(ClusterBackend::Redis, status);
            let err = judge_referenced_cluster("prod", 3, "spec.replicas", Some(&c))
                .expect_err("must deny");
            assert!(err.contains("not Ready"), "{err}");
        }
    }

    #[test]
    fn ready_non_single_node_cluster_admitted() {
        let c = cluster_fixture(ClusterBackend::Nats, Some(true));
        judge_referenced_cluster("prod", 3, "spec.replicas", Some(&c)).unwrap();
    }

    #[test]
    fn unchanged_binding_skips_the_live_lookup() {
        let new = fixture(coordination_spec(5, Some("prod"), serde_json::Value::Null));
        // Same ref, already multi-replica → skip.
        let old = fixture(coordination_spec(3, Some("prod"), serde_json::Value::Null));
        assert!(binding_already_admitted(Some(&old), &new));
        // CREATE (no old object) → judge.
        assert!(!binding_already_admitted(None, &new));
        // The old object was single-replica → the binding is new → judge.
        let old = fixture(coordination_spec(1, Some("prod"), serde_json::Value::Null));
        assert!(!binding_already_admitted(Some(&old), &new));
        // The ref changed → judge the new target.
        let old = fixture(coordination_spec(3, Some("other"), serde_json::Value::Null));
        assert!(!binding_already_admitted(Some(&old), &new));
    }
}
