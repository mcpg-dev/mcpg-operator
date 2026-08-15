//! Service template — exposes the gateway pod's MCP listener.
//! Defaults: ClusterIP on port 8787 (matches the gateway's
//! built-in default and the Helm chart shipped to operators).

use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::core::ObjectMeta;
use mcpg_operator_api::v1alpha1::MCPGGateway;

use crate::templates::common::{child_name, owner_ref, selector_labels, standard_labels};

const DEFAULT_PORT: i32 = 8787;
const DEFAULT_SERVICE_TYPE: &str = "ClusterIP";

pub fn build_service(parent: &MCPGGateway) -> Service {
    let port = parent
        .spec
        .service
        .as_ref()
        .and_then(|s| s.port)
        .unwrap_or(DEFAULT_PORT);
    let service_type = parent
        .spec
        .service
        .as_ref()
        .and_then(|s| s.r#type.as_deref())
        .unwrap_or(DEFAULT_SERVICE_TYPE)
        .to_owned();

    let mut annotations = parent
        .spec
        .service
        .as_ref()
        .map(|s| s.annotations.clone())
        .unwrap_or_default();
    if annotations.is_empty() {
        annotations.clear(); // ensure empty BTreeMap is serialised as None
    }

    Service {
        metadata: ObjectMeta {
            name: Some(child_name(parent, "")),
            namespace: parent.metadata.namespace.clone(),
            labels: Some(standard_labels(parent)),
            owner_references: Some(vec![owner_ref(parent)]),
            annotations: if annotations.is_empty() {
                None
            } else {
                Some(annotations)
            },
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            type_: Some(service_type),
            selector: Some(selector_labels(parent)),
            ports: Some(vec![ServicePort {
                name: Some("http".to_owned()),
                port,
                target_port: Some(IntOrString::String("http".to_owned())),
                protocol: Some("TCP".to_owned()),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::{GatewayService, MCPGGatewaySpec};
    use std::collections::BTreeMap;

    fn fixture(svc: Option<GatewayService>) -> MCPGGateway {
        MCPGGateway {
            metadata: ObjectMeta {
                name: Some("payments-gateway".into()),
                namespace: Some("payments".into()),
                uid: Some("uid-123".into()),
                ..Default::default()
            },
            spec: MCPGGatewaySpec {
                service: svc,
                ..Default::default()
            },
            status: None,
        }
    }

    #[test]
    fn defaults_clusterip_port_8787() {
        let svc = build_service(&fixture(None));
        let spec = svc.spec.unwrap();
        assert_eq!(spec.type_.as_deref(), Some("ClusterIP"));
        let port = &spec.ports.unwrap()[0];
        assert_eq!(port.port, 8787);
        assert_eq!(port.name.as_deref(), Some("http"));
    }

    #[test]
    fn honours_overrides() {
        let svc = build_service(&fixture(Some(GatewayService {
            r#type: Some("LoadBalancer".into()),
            port: Some(443),
            annotations: BTreeMap::new(),
        })));
        let spec = svc.spec.unwrap();
        assert_eq!(spec.type_.as_deref(), Some("LoadBalancer"));
        assert_eq!(spec.ports.unwrap()[0].port, 443);
    }

    #[test]
    fn selector_matches_pod_template_labels() {
        // The Service's selector must match the pod template's
        // labels in the Deployment template, otherwise no
        // endpoints register.
        let p = fixture(None);
        let svc = build_service(&p);
        let sel = svc.spec.unwrap().selector.unwrap();
        let pod_labels = selector_labels(&p);
        for (k, v) in &sel {
            assert_eq!(pod_labels.get(k), Some(v), "selector key {k} must match");
        }
    }

    #[test]
    fn has_owner_ref() {
        let svc = build_service(&fixture(None));
        let orefs = svc.metadata.owner_references.unwrap();
        assert_eq!(orefs[0].kind, "MCPGGateway");
    }
}
