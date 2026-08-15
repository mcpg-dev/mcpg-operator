//! Deployment + Service renderers for `MCPGServer` — a generic MCP
//! server container the operator provisions (contrast the gateway
//! templates, which know mcpg's own binary layout).

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, EnvFromSource, EnvVar, LocalObjectReference, Probe,
    ResourceRequirements, SecretEnvSource, Service, ServicePort, ServiceSpec,
};
use k8s_openapi::api::core::v1::{PodSpec, PodTemplateSpec};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::Resource;
use kube::core::ObjectMeta;
use mcpg_operator_api::v1alpha1::MCPGServer;

use crate::labels;

/// Owner reference pointing back to the parent `MCPGServer`, so K8s GC
/// propagates deletion to the rendered Deployment/Service.
pub fn server_owner_ref(parent: &MCPGServer) -> OwnerReference {
    OwnerReference {
        api_version: MCPGServer::api_version(&()).to_string(),
        kind: MCPGServer::kind(&()).to_string(),
        name: parent.metadata.name.clone().unwrap_or_default(),
        uid: parent.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// The selector subset — stable across image bumps.
pub fn server_selector_labels(parent: &MCPGServer) -> BTreeMap<String, String> {
    let mut labels_map = BTreeMap::new();
    labels_map.insert(labels::APP_NAME.into(), "mcpg-server".into());
    labels_map.insert(
        labels::APP_INSTANCE.into(),
        parent.metadata.name.clone().unwrap_or_default(),
    );
    labels_map
}

fn server_labels(parent: &MCPGServer) -> BTreeMap<String, String> {
    let mut labels_map = server_selector_labels(parent);
    labels_map.insert(labels::APP_COMPONENT.into(), "mcp-server".into());
    labels_map.insert(labels::APP_PART_OF.into(), "mcpg".into());
    labels_map.insert(labels::APP_MANAGED_BY.into(), "mcpg-operator".into());
    labels_map
}

/// Child (Deployment/Service) name. Service names are DNS-1035 labels
/// (alpha-leading), so a non-alpha-leading server name gets the same
/// stable prefix guard the gateway children use.
pub fn server_child_name(parent: &MCPGServer) -> String {
    let raw = parent.metadata.name.clone().unwrap_or_default();
    if raw.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
        raw
    } else {
        format!("mcpg-{raw}")
    }
}

pub fn build_server_deployment(parent: &MCPGServer) -> Deployment {
    let spec = &parent.spec;
    let port = spec.port();
    let env: Vec<EnvVar> = spec
        .env
        .iter()
        .map(|(name, value)| EnvVar {
            name: name.clone(),
            value: Some(value.clone()),
            ..Default::default()
        })
        .collect();
    let env_from: Vec<EnvFromSource> = spec
        .env_from_secrets
        .iter()
        .map(|secret| EnvFromSource {
            secret_ref: Some(SecretEnvSource {
                name: secret.clone(),
                optional: Some(false),
            }),
            ..Default::default()
        })
        .collect();
    let resources = spec.resources.as_ref().map(|r| ResourceRequirements {
        requests: to_quantities(&r.requests),
        limits: to_quantities(&r.limits),
        ..Default::default()
    });
    // MCP servers answer POST-only on the MCP path; a TCP readiness
    // probe avoids requiring a GET-able health route.
    let readiness = Probe {
        tcp_socket: Some(k8s_openapi::api::core::v1::TCPSocketAction {
            port: IntOrString::Int(port),
            ..Default::default()
        }),
        initial_delay_seconds: Some(2),
        period_seconds: Some(5),
        ..Default::default()
    };

    Deployment {
        metadata: ObjectMeta {
            name: Some(server_child_name(parent)),
            namespace: parent.metadata.namespace.clone(),
            labels: Some(server_labels(parent)),
            owner_references: Some(vec![server_owner_ref(parent)]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(spec.replicas()),
            selector: LabelSelector {
                match_labels: Some(server_selector_labels(parent)),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(server_labels(parent)),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    service_account_name: spec.service_account_name.clone(),
                    image_pull_secrets: if spec.image_pull_secrets.is_empty() {
                        None
                    } else {
                        Some(
                            spec.image_pull_secrets
                                .iter()
                                .map(|s| LocalObjectReference {
                                    name: s.name.clone(),
                                })
                                .collect(),
                        )
                    },
                    containers: vec![Container {
                        name: "mcp-server".into(),
                        image: Some(spec.image.clone()),
                        ports: Some(vec![ContainerPort {
                            name: Some("http".into()),
                            container_port: port,
                            protocol: Some("TCP".into()),
                            ..Default::default()
                        }]),
                        env: if env.is_empty() { None } else { Some(env) },
                        env_from: if env_from.is_empty() {
                            None
                        } else {
                            Some(env_from)
                        },
                        resources,
                        readiness_probe: Some(readiness),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub fn build_server_service(parent: &MCPGServer) -> Service {
    Service {
        metadata: ObjectMeta {
            name: Some(server_child_name(parent)),
            namespace: parent.metadata.namespace.clone(),
            labels: Some(server_labels(parent)),
            owner_references: Some(vec![server_owner_ref(parent)]),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            type_: Some("ClusterIP".into()),
            selector: Some(server_selector_labels(parent)),
            ports: Some(vec![ServicePort {
                name: Some("http".into()),
                port: parent.spec.port(),
                target_port: Some(IntOrString::String("http".into())),
                protocol: Some("TCP".into()),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn to_quantities(map: &BTreeMap<String, String>) -> Option<BTreeMap<String, Quantity>> {
    if map.is_empty() {
        return None;
    }
    Some(
        map.iter()
            .map(|(k, v)| (k.clone(), Quantity(v.clone())))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_operator_api::v1alpha1::MCPGServerSpec;

    fn fixture() -> MCPGServer {
        MCPGServer {
            metadata: ObjectMeta {
                name: Some("crm".into()),
                namespace: Some("team-a".into()),
                uid: Some("uid-1".into()),
                ..Default::default()
            },
            spec: serde_yaml::from_str::<MCPGServerSpec>(
                "image: ghcr.io/acme/crm-mcp:1.0.0\nreplicas: 2\nport: 9000\nenv:\n  LOG_LEVEL: info\nenvFromSecrets: [crm-secrets]\nresources:\n  requests: { cpu: 100m }\n",
            )
            .unwrap(),
            status: None,
        }
    }

    #[test]
    fn deployment_renders_container_shape() {
        let d = build_server_deployment(&fixture());
        assert_eq!(d.metadata.name.as_deref(), Some("crm"));
        let spec = d.spec.unwrap();
        assert_eq!(spec.replicas, Some(2));
        let pod = spec.template.spec.unwrap();
        let c = &pod.containers[0];
        assert_eq!(c.image.as_deref(), Some("ghcr.io/acme/crm-mcp:1.0.0"));
        assert_eq!(c.ports.as_ref().unwrap()[0].container_port, 9000);
        assert_eq!(c.env.as_ref().unwrap()[0].name, "LOG_LEVEL");
        assert_eq!(
            c.env_from.as_ref().unwrap()[0]
                .secret_ref
                .as_ref()
                .unwrap()
                .name,
            "crm-secrets"
        );
        assert!(c.resources.as_ref().unwrap().requests.is_some());
        assert!(c.readiness_probe.is_some());
    }

    #[test]
    fn service_selector_matches_pod_labels() {
        let p = fixture();
        let svc = build_server_service(&p);
        let sel = svc.spec.unwrap().selector.unwrap();
        let pod_labels = server_labels(&p);
        for (k, v) in &sel {
            assert_eq!(pod_labels.get(k), Some(v), "selector key {k} must match");
        }
    }

    #[test]
    fn owner_refs_point_at_server() {
        let d = build_server_deployment(&fixture());
        assert_eq!(d.metadata.owner_references.unwrap()[0].kind, "MCPGServer");
        let s = build_server_service(&fixture());
        assert_eq!(s.metadata.owner_references.unwrap()[0].kind, "MCPGServer");
    }

    #[test]
    fn non_alpha_leading_name_gets_prefix() {
        let mut p = fixture();
        p.metadata.name = Some("0198-uuid".into());
        assert_eq!(server_child_name(&p), "mcpg-0198-uuid");
    }
}
