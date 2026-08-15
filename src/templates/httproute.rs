//! Gateway API `HTTPRoute` renderer for host-per-instance routing. Only emitted
//! for managed-cloud gateways (`spec.cloud` set); self-host CRs render nothing.
//!
//! Host-per-instance: each instance is reachable at `{instanceSlug}.<domain>/mcp`
//! (the host carries the identity, so the gateway serves its native `/mcp` with
//! no rewrite). The route attaches to the shared platform Gateway and backends
//! the instance's Service.
//!
//! Hand-rolled minimal type — the real `gateway.networking.k8s.io` CRD is
//! installed in the cluster; this is just the client-side apply shape, which
//! SSAs cleanly via `apply_owned` (CustomResource-derived, GVK in the body).

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use mcpg_operator_api::v1alpha1::MCPGGateway;

use crate::templates::common::{child_name, owner_ref, standard_labels};

const GATEWAY_PORT: u16 = 8787;
/// The shared platform edge Gateway the per-instance routes attach to and the
/// custom-domain listeners are applied onto (`templates::edge`). The edge
/// itself is provisioned by the `mcpg-cloud-edge` chart; making these
/// configurable is a follow-up.
pub const CLOUD_GATEWAY_NAME: &str = "mcpg-cloud-gateway";
pub const CLOUD_GATEWAY_NAMESPACE: &str = "mcpg-edge";

#[derive(CustomResource, Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "HTTPRoute",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteSpec {
    pub parent_refs: Vec<ParentReference>,
    pub hostnames: Vec<String>,
    pub rules: Vec<HttpRouteRule>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ParentReference {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteRule {
    pub matches: Vec<HttpRouteMatch>,
    pub backend_refs: Vec<HttpBackendRef>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteMatch {
    pub path: HttpPathMatch,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HttpPathMatch {
    pub r#type: String,
    pub value: String,
}

impl Default for HttpPathMatch {
    fn default() -> Self {
        Self {
            r#type: "PathPrefix".into(),
            value: "/".into(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HttpBackendRef {
    pub name: String,
    pub port: u16,
}

/// Render the per-instance HTTPRoute, or `None` for a self-host gateway.
pub fn build_httproute(parent: &MCPGGateway) -> Option<HTTPRoute> {
    let cloud = parent.spec.cloud.as_ref()?;

    // Canonical host from the operator-trusted external_url, plus custom domains.
    let mut hostnames: Vec<String> = Vec::new();
    if let Some(h) = host_of(&cloud.external_url) {
        hostnames.push(h);
    }
    hostnames.extend(cloud.custom_domains.iter().cloned());
    if hostnames.is_empty() {
        return None;
    }

    let service = child_name(parent, "");
    let port = parent
        .spec
        .service
        .as_ref()
        .and_then(|s| s.port)
        .map(|p| p as u16)
        .unwrap_or(GATEWAY_PORT);
    let name = child_name(parent, "mcp");

    let spec = HttpRouteSpec {
        parent_refs: vec![ParentReference {
            name: CLOUD_GATEWAY_NAME.to_owned(),
            namespace: Some(CLOUD_GATEWAY_NAMESPACE.to_owned()),
            group: Some("gateway.networking.k8s.io".to_owned()),
            kind: Some("Gateway".to_owned()),
        }],
        hostnames,
        rules: vec![HttpRouteRule {
            // Host carries the instance identity; serve native /mcp, no rewrite.
            matches: vec![HttpRouteMatch {
                path: HttpPathMatch {
                    r#type: "PathPrefix".into(),
                    value: "/mcp".into(),
                },
            }],
            backend_refs: vec![HttpBackendRef {
                name: service,
                port,
            }],
        }],
    };

    let mut route = HTTPRoute::new(&name, spec);
    route.metadata.namespace = parent.metadata.namespace.clone();
    route.metadata.labels = Some(standard_labels(parent));
    route.metadata.owner_references = Some(vec![owner_ref(parent)]);
    Some(route)
}

/// Extract the bare host from `https://host/path` (or `http://`).
fn host_of(url: &str) -> Option<String> {
    let no_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = no_scheme.split('/').next().unwrap_or("");
    (!host.is_empty()).then(|| host.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_operator_api::v1alpha1::{GatewayCloud, GatewayImage, MCPGGatewaySpec};

    fn gw_with_cloud(cloud: Option<GatewayCloud>) -> MCPGGateway {
        let mut gw = MCPGGateway::new(
            "edge-1",
            MCPGGatewaySpec {
                image: GatewayImage::default(),
                replicas: 1,
                config: serde_json::json!({}),
                cloud,
                ..Default::default()
            },
        );
        gw.metadata.namespace = Some("tenant-acme".into());
        gw
    }

    #[test]
    fn no_route_without_cloud() {
        assert!(build_httproute(&gw_with_cloud(None)).is_none());
    }

    #[test]
    fn route_has_host_and_backend() {
        let cloud = GatewayCloud {
            org_slug: "acme".into(),
            instance_slug: "edge-1".into(),
            external_url: "https://edge-1.mcpg.cloud/mcp".into(),
            custom_domains: vec!["mcp.acme.com".into()],
        };
        let route = build_httproute(&gw_with_cloud(Some(cloud))).unwrap();
        assert_eq!(route.metadata.name.as_deref(), Some("edge-1-mcp"));
        assert_eq!(route.metadata.namespace.as_deref(), Some("tenant-acme"));
        assert_eq!(
            route.spec.hostnames,
            vec!["edge-1.mcpg.cloud".to_string(), "mcp.acme.com".to_string()]
        );
        let rule = &route.spec.rules[0];
        assert_eq!(rule.matches[0].path.value, "/mcp");
        assert_eq!(rule.backend_refs[0].name, "edge-1");
        assert_eq!(rule.backend_refs[0].port, 8787);
        assert_eq!(route.spec.parent_refs[0].name, "mcpg-cloud-gateway");
    }
}
