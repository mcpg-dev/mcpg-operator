//! Edge wiring for tenant custom domains: per-domain TLS listeners on the
//! shared platform Gateway + cert-manager `Certificate`s that fill them.
//!
//! Why listeners at all: the chart-provisioned edge Gateway carries a single
//! wildcard HTTPS listener (`*.<zone>`), and Gateway API only attaches an
//! HTTPRoute to listeners whose hostname INTERSECTS the route's. A custom
//! domain (`mcp.example.com`) has no intersection with the wildcard, so
//! without its own listener the route never binds and the host 404s at the
//! edge. Each verified custom domain therefore gets:
//!
//!   1. an HTTPS listener on the shared Gateway (hostname-pinned, TLS
//!      terminate, certificateRef → a per-domain Secret in the edge
//!      namespace), and
//!   2. a cert-manager `Certificate` that fills that Secret via the
//!      operator-configured ClusterIssuer (HTTP-01 through the edge — safe
//!      because the CP only ships custom domains whose DNS ownership was
//!      TXT-verified, and HTTP-01 additionally requires the domain to point
//!      at the edge).
//!
//! Ownership mechanics: the Gateway is a SHARED object (chart-owned base +
//! one listener per domain across many MCPGGateways), so plain
//! get-modify-update would race concurrent reconciles. Instead each
//! MCPGGateway applies a PARTIAL Gateway via server-side apply under its own
//! field manager (`spec.listeners` is a `listMapKey=name` list, so SSA merges
//! per-entry): applying this CR's current listener set adds/updates exactly
//! its entries, and applying an EMPTY set (domains removed / CR deleted)
//! relinquishes them without touching the chart's wildcard listeners or other
//! CRs' entries. Certificates are whole namespaced objects, so they're
//! garbage-collected by label (`mcpg.dev/owner-uid`) instead.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use mcpg_operator_api::v1alpha1::MCPGGateway;

pub use crate::templates::httproute::{CLOUD_GATEWAY_NAME, CLOUD_GATEWAY_NAMESPACE};

/// Label stamped on operator-managed edge Certificates; the value is the
/// owning MCPGGateway's UID. Drives garbage collection (delete certs whose
/// domain left the spec) and the finalizer cleanup (delete all certs for a
/// deleted CR). An owner LABEL rather than an ownerReference because
/// ownerReferences cannot cross namespaces (the cert lives in the edge
/// namespace, the CR in the tenant namespace).
pub const EDGE_OWNER_UID_LABEL: &str = "mcpg.dev/owner-uid";

/// Deterministic per-hostname object name: `cd-<sha256(hostname)[..16]>`.
/// Hash rather than the hostname itself because listener/Secret names must be
/// short DNS labels (≤63 chars) while hostnames run to 253, and the hash is
/// stable across reconciles so SSA keeps matching the same listener entry.
pub fn edge_object_name(hostname: &str) -> String {
    let digest = Sha256::digest(hostname.as_bytes());
    format!("cd-{}", hex::encode(&digest[..8]))
}

/// Name of the TLS Secret (in the edge namespace) a domain's listener
/// references and its Certificate fills.
pub fn cert_secret_name(hostname: &str) -> String {
    format!("{}-tls", edge_object_name(hostname))
}

/// Partial `Gateway` server-side-apply document carrying ONLY this CR's
/// custom-domain listeners. Always built — including with an empty `domains`
/// — because applying the empty set is how a CR relinquishes listeners it no
/// longer wants (domain removed on re-publish, or CR deletion).
pub fn build_edge_listener_apply(domains: &[String]) -> serde_json::Value {
    let listeners: Vec<serde_json::Value> = domains
        .iter()
        .map(|hostname| {
            serde_json::json!({
                "name": edge_object_name(hostname),
                "hostname": hostname,
                "port": 443,
                "protocol": "HTTPS",
                "tls": {
                    "mode": "Terminate",
                    "certificateRefs": [
                        { "kind": "Secret", "name": cert_secret_name(hostname) }
                    ],
                },
                // Tenant HTTPRoutes live in tenant namespaces.
                "allowedRoutes": { "namespaces": { "from": "All" } },
            })
        })
        .collect();
    serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": {
            "name": CLOUD_GATEWAY_NAME,
            "namespace": CLOUD_GATEWAY_NAMESPACE,
        },
        "spec": { "listeners": listeners },
    })
}

/// SSA field manager for a CR's edge-listener entries. Unique per CR so each
/// MCPGGateway's apply only ever adds/removes ITS listeners.
pub fn edge_field_manager(uid: &str) -> String {
    format!("mcpg-operator/edge-domains/{uid}")
}

/// Client-side apply shape for cert-manager's `Certificate` — same hand-rolled
/// pattern as [`crate::templates::httproute`]: the real CRD is installed in
/// the cluster; this is just the SSA body.
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "cert-manager.io",
    version = "v1",
    kind = "Certificate",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSpec {
    pub secret_name: String,
    pub dns_names: Vec<String>,
    pub issuer_ref: IssuerRef,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssuerRef {
    pub name: String,
    pub kind: String,
    pub group: String,
}

/// Render the per-domain Certificate (edge namespace). `issuer` is the
/// operator's `--edge-cluster-issuer`.
pub fn build_certificate(parent: &MCPGGateway, hostname: &str, issuer: &str) -> Certificate {
    let mut cert = Certificate::new(
        &edge_object_name(hostname),
        CertificateSpec {
            secret_name: cert_secret_name(hostname),
            dns_names: vec![hostname.to_owned()],
            issuer_ref: IssuerRef {
                name: issuer.to_owned(),
                kind: "ClusterIssuer".to_owned(),
                group: "cert-manager.io".to_owned(),
            },
        },
    );
    cert.metadata.namespace = Some(CLOUD_GATEWAY_NAMESPACE.to_owned());
    let mut labels = std::collections::BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_owned(),
        "mcpg-operator".to_owned(),
    );
    labels.insert(
        EDGE_OWNER_UID_LABEL.to_owned(),
        parent.metadata.uid.clone().unwrap_or_default(),
    );
    cert.metadata.labels = Some(labels);
    cert
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::MCPGGatewaySpec;

    fn parent() -> MCPGGateway {
        let mut gw = MCPGGateway::new(
            "edge-1",
            MCPGGatewaySpec {
                config: serde_json::json!({}),
                ..Default::default()
            },
        );
        gw.metadata = ObjectMeta {
            name: Some("edge-1".into()),
            namespace: Some("tenant-acme".into()),
            uid: Some("uid-123".into()),
            ..Default::default()
        };
        gw
    }

    #[test]
    fn names_are_deterministic_short_dns_labels() {
        let long_host = format!("{}.example.com", "a".repeat(60));
        for host in ["mcp.example.com", long_host.as_str()] {
            let name = edge_object_name(host);
            assert_eq!(name, edge_object_name(host), "stable across calls");
            assert!(name.len() <= 63, "{name}");
            assert!(name.starts_with("cd-"));
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{name}"
            );
            assert_eq!(cert_secret_name(host), format!("{name}-tls"));
        }
        assert_ne!(
            edge_object_name("a.example.com"),
            edge_object_name("b.example.com")
        );
    }

    #[test]
    fn listener_apply_carries_one_entry_per_domain() {
        let doc = build_edge_listener_apply(&["mcp.acme.com".into(), "api.acme.com".into()]);
        assert_eq!(doc["metadata"]["name"], CLOUD_GATEWAY_NAME);
        assert_eq!(doc["metadata"]["namespace"], CLOUD_GATEWAY_NAMESPACE);
        let listeners = doc["spec"]["listeners"].as_array().unwrap();
        assert_eq!(listeners.len(), 2);
        let l = &listeners[0];
        assert_eq!(l["hostname"], "mcp.acme.com");
        assert_eq!(l["port"], 443);
        assert_eq!(l["protocol"], "HTTPS");
        assert_eq!(l["tls"]["mode"], "Terminate");
        assert_eq!(
            l["tls"]["certificateRefs"][0]["name"],
            cert_secret_name("mcp.acme.com").as_str()
        );
        assert_eq!(l["name"], edge_object_name("mcp.acme.com").as_str());
    }

    #[test]
    fn empty_apply_relinquishes_listeners() {
        // The empty set is the SSA "I own nothing now" document used on domain
        // removal + CR deletion.
        let doc = build_edge_listener_apply(&[]);
        assert!(doc["spec"]["listeners"].as_array().unwrap().is_empty());
    }

    #[test]
    fn certificate_targets_the_listener_secret() {
        let cert = build_certificate(&parent(), "mcp.acme.com", "mcpg-cloud-issuer");
        assert_eq!(
            cert.metadata.name.as_deref(),
            Some(edge_object_name("mcp.acme.com").as_str())
        );
        assert_eq!(
            cert.metadata.namespace.as_deref(),
            Some(CLOUD_GATEWAY_NAMESPACE)
        );
        assert_eq!(cert.spec.secret_name, cert_secret_name("mcp.acme.com"));
        assert_eq!(cert.spec.dns_names, vec!["mcp.acme.com".to_string()]);
        assert_eq!(cert.spec.issuer_ref.kind, "ClusterIssuer");
        assert_eq!(cert.spec.issuer_ref.name, "mcpg-cloud-issuer");
        let labels = cert.metadata.labels.as_ref().unwrap();
        assert_eq!(
            labels.get(EDGE_OWNER_UID_LABEL).map(String::as_str),
            Some("uid-123")
        );
    }

    #[test]
    fn field_manager_is_per_cr() {
        assert_ne!(edge_field_manager("uid-a"), edge_field_manager("uid-b"));
    }
}
