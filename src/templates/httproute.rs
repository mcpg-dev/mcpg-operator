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
/// Path prefixes the edge forwards to a tenant gateway (Gateway API
/// `PathPrefix`, element-boundary matching): the MCP endpoint and the
/// gateway's OAuth / AAuth discovery and token paths.
pub const FORWARDED_PATH_PREFIXES: [&str; 4] = ["/mcp", "/.well-known", "/oauth", "/aauth"];
/// The signed inbound event route (`POST /webhooks/events/{source_id}`),
/// forwarded only for an instance whose config serves an inbound event
/// source. Element-boundary matching keeps the other `/webhooks/*` routes
/// off the edge.
pub const INBOUND_EVENTS_PREFIX: &str = "/webhooks/events";
/// The callbacks of upstream webhook subscriptions
/// (`POST /webhooks/mcp-events/{federation}/{id}`), forwarded only for an
/// instance whose config imports event types from a federated server.
pub const FEDERATED_EVENTS_PREFIX: &str = "/webhooks/mcp-events";
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
            // The OAuth / AAuth surface rides on the same origin — a host
            // fetches `/.well-known/oauth-protected-resource` and redeems
            // grants at `/oauth/token` on the URL it connected to — so those
            // prefixes forward too. Probes, metrics, webhooks and plugin HTTP
            // routes stay off the edge.
            matches: FORWARDED_PATH_PREFIXES
                .iter()
                .chain(serves_inbound_events(&parent.spec.config).then_some(&INBOUND_EVENTS_PREFIX))
                .chain(
                    imports_federated_events(&parent.spec.config)
                        .then_some(&FEDERATED_EVENTS_PREFIX),
                )
                .map(|prefix| HttpRouteMatch {
                    path: HttpPathMatch {
                        r#type: "PathPrefix".into(),
                        value: (*prefix).into(),
                    },
                })
                .collect(),
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

/// Whether the config serves MCP Events with at least one `inbound` event
/// source, the only events surface a caller outside the platform reaches.
pub fn serves_inbound_events(config: &serde_json::Value) -> bool {
    config.pointer("/mcp/configurations/events/enabled") == Some(&serde_json::Value::Bool(true))
        && config
            .pointer("/mcp/capabilities/events")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|types| {
                types
                    .iter()
                    .any(|ty| ty.pointer("/source/inbound").is_some_and(|v| v.is_object()))
            })
}

/// Whether the config serves MCP Events with a federation that imports
/// event types: their upstreams may deliver to its callbacks.
pub fn imports_federated_events(config: &serde_json::Value) -> bool {
    config.pointer("/mcp/configurations/events/enabled") == Some(&serde_json::Value::Bool(true))
        && config
            .pointer("/mcp/federations")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|federations| {
                federations.iter().any(|federation| {
                    federation.pointer("/import/events") == Some(&serde_json::Value::Bool(true))
                })
            })
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
            canonical_url: None,
        };
        let route = build_httproute(&gw_with_cloud(Some(cloud))).unwrap();
        assert_eq!(route.metadata.name.as_deref(), Some("edge-1-mcp"));
        assert_eq!(route.metadata.namespace.as_deref(), Some("tenant-acme"));
        assert_eq!(
            route.spec.hostnames,
            vec!["edge-1.mcpg.cloud".to_string(), "mcp.acme.com".to_string()]
        );
        let rule = &route.spec.rules[0];
        let prefixes: Vec<&str> = rule.matches.iter().map(|m| m.path.value.as_str()).collect();
        assert_eq!(prefixes, vec!["/mcp", "/.well-known", "/oauth", "/aauth"]);
        assert!(rule.matches.iter().all(|m| m.path.r#type == "PathPrefix"));
        assert_eq!(rule.backend_refs[0].name, "edge-1");
        assert_eq!(rule.backend_refs[0].port, 8787);
        assert_eq!(route.spec.parent_refs[0].name, "mcpg-cloud-gateway");
    }

    fn prefixes_for(config: serde_json::Value) -> Vec<String> {
        let mut gw = gw_with_cloud(Some(GatewayCloud {
            org_slug: "acme".into(),
            instance_slug: "edge-1".into(),
            external_url: "https://edge-1.mcpg.cloud/mcp".into(),
            ..Default::default()
        }));
        gw.spec.config = config;
        let route = build_httproute(&gw).unwrap();
        route.spec.rules[0]
            .matches
            .iter()
            .map(|m| m.path.value.clone())
            .collect()
    }

    #[test]
    fn inbound_event_sources_open_their_route_and_nothing_else_does() {
        let inbound = serde_json::json!({
            "mcp": {
                "configurations": { "events": { "enabled": true } },
                "capabilities": { "events": [
                    { "name": "orders.created", "source": { "watch": { "resource": "orders" } } },
                    { "name": "gh.issue", "source": { "inbound": { "source_id": "gh" } } }
                ]}
            }
        });
        assert_eq!(
            prefixes_for(inbound.clone()),
            vec![
                "/mcp",
                "/.well-known",
                "/oauth",
                "/aauth",
                "/webhooks/events"
            ]
        );

        let mut disabled = inbound.clone();
        disabled["mcp"]["configurations"]["events"]["enabled"] = serde_json::json!(false);
        assert_eq!(prefixes_for(disabled).len(), FORWARDED_PATH_PREFIXES.len());

        let mut watch_only = inbound;
        watch_only["mcp"]["capabilities"]["events"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        assert_eq!(
            prefixes_for(watch_only).len(),
            FORWARDED_PATH_PREFIXES.len()
        );

        assert_eq!(
            prefixes_for(serde_json::json!({})).len(),
            FORWARDED_PATH_PREFIXES.len()
        );
    }

    #[test]
    fn a_federation_that_imports_events_opens_the_upstream_callbacks() {
        let importing = serde_json::json!({
            "mcp": {
                "configurations": { "events": { "enabled": true } },
                "federations": [
                    { "name": "docs", "import": { "tools": true } },
                    { "name": "gh", "import": { "tools": true, "events": true } }
                ]
            }
        });
        assert_eq!(
            prefixes_for(importing.clone()).last().map(String::as_str),
            Some("/webhooks/mcp-events")
        );

        let mut tools_only = importing.clone();
        tools_only["mcp"]["federations"][1]["import"]["events"] = serde_json::json!(false);
        assert_eq!(
            prefixes_for(tools_only).len(),
            FORWARDED_PATH_PREFIXES.len()
        );

        let mut disabled = importing;
        disabled["mcp"]["configurations"]["events"]["enabled"] = serde_json::json!(false);
        assert_eq!(prefixes_for(disabled).len(), FORWARDED_PATH_PREFIXES.len());
    }
}
