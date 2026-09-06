//! Renderers for a **managed** NATS JetStream coordinator — the objects
//! the cluster controller provisions when an `MCPGCluster` sets
//! `spec.managed`. Unlike the gateway templates (which render a
//! namespaced Deployment owned by the gateway), these render into the
//! operator namespace and are owned by the cluster-scoped `MCPGCluster`
//! (a namespaced dependent may name a cluster-scoped owner, so K8s GC
//! still cascades on cluster deletion).
//!
//! Object set (all in the operator namespace):
//! - a **Secret** holding the generated NATS token + state-encryption key
//!   (+ CA when TLS) — built by the controller (create-once), not here;
//! - a **ConfigMap** with the rendered `nats-server.conf`;
//! - a **StatefulSet** running one NATS server with JetStream on a
//!   file-store `volumeClaimTemplate`;
//! - a **headless Service** (stable network id) + a **client Service**
//!   (the FQDN gateways dial);
//! - optionally a cert-manager **Certificate** (TLS).
//!
//! These are pure renderers: no cluster access, no async.

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{StatefulSet, StatefulSetSpec};
use k8s_openapi::api::core::v1::{
    Capabilities, ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, EnvVar, EnvVarSource,
    HTTPGetAction, ObjectFieldSelector, PersistentVolumeClaim, PersistentVolumeClaimSpec,
    PodSecurityContext, PodSpec, PodTemplateSpec, Probe, ResourceRequirements, SeccompProfile,
    SecretKeySelector, SecretVolumeSource, SecurityContext, Service, ServicePort, ServiceSpec,
    Volume, VolumeMount, VolumeResourceRequirements,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::core::ObjectMeta;
use mcpg_operator_api::v1alpha1::{
    DEFAULT_MANAGED_NATS_IMAGE, DEFAULT_MANAGED_STORAGE_SIZE, MANAGED_NATS_CLIENT_PORT,
    MANAGED_NATS_TOKEN_ENV, MCPGCluster, ManagedIssuerRef, ManagedStorage,
    managed_coordination_secret_name, managed_nats_config_name, managed_nats_headless_service_name,
    managed_nats_service_name, managed_nats_statefulset_name, managed_nats_tls_secret_name,
};

use crate::templates::edge::{Certificate, CertificateSpec, IssuerRef};

/// NATS monitoring port — plain HTTP, carries `/healthz` for probes.
const NATS_MONITOR_PORT: i32 = 8222;
/// NATS cluster (route) port — declared for forward-compat; inert at 1 replica.
const NATS_CLUSTER_PORT: i32 = 6222;
/// Mount path for the rendered `nats-server.conf` ConfigMap.
const NATS_CONFIG_DIR: &str = "/etc/nats-config";
/// JetStream file-store mount (the `volumeClaimTemplate`).
const NATS_DATA_DIR: &str = "/data";
/// Mount path for the cert-manager-issued server TLS Secret.
const NATS_TLS_DIR: &str = "/etc/nats-certs";
/// Env var the NATS server reads its `authorization.token` from.
const NATS_SERVER_TOKEN_ENV: &str = "NATS_TOKEN";
/// Non-root uid/gid the NATS container runs as (restricted-PSA clean; the
/// `fsGroup` makes the JetStream PVC writable).
const NATS_RUN_AS: i64 = 1000;

/// Label selecting every managed-coordinator child of one cluster — the
/// value is the `MCPGCluster` name. The controller lists + prunes by it on
/// deletion (children are NOT owner-referenced: they live in the operator
/// namespace under a cluster-scoped parent, and the codebase's convention
/// for that shape is finalizer-driven cleanup, not owner-ref GC — see
/// `controllers::plugin`).
pub const MANAGED_CLUSTER_LABEL: &str = "mcpg.dev/cluster";

/// Standard labels for every managed-coordinator child.
pub fn managed_labels(cluster_name: &str) -> BTreeMap<String, String> {
    let mut l = BTreeMap::new();
    l.insert("app.kubernetes.io/name".to_owned(), "mcpg-nats".to_owned());
    l.insert(
        "app.kubernetes.io/instance".to_owned(),
        cluster_name.to_owned(),
    );
    l.insert(
        "app.kubernetes.io/component".to_owned(),
        "cluster-coordinator".to_owned(),
    );
    l.insert("app.kubernetes.io/part-of".to_owned(), "mcpg".to_owned());
    l.insert(
        "app.kubernetes.io/managed-by".to_owned(),
        "mcpg-operator".to_owned(),
    );
    l.insert(MANAGED_CLUSTER_LABEL.to_owned(), cluster_name.to_owned());
    l
}

/// Pod selector labels (stable subset).
fn selector_labels(cluster_name: &str) -> BTreeMap<String, String> {
    let mut l = BTreeMap::new();
    l.insert("app.kubernetes.io/name".to_owned(), "mcpg-nats".to_owned());
    l.insert(
        "app.kubernetes.io/instance".to_owned(),
        cluster_name.to_owned(),
    );
    l
}

fn child_meta(cluster: &MCPGCluster, name: String, namespace: &str) -> ObjectMeta {
    let cluster_name = cluster.metadata.name.clone().unwrap_or_default();
    ObjectMeta {
        name: Some(name),
        namespace: Some(namespace.to_owned()),
        labels: Some(managed_labels(&cluster_name)),
        ..Default::default()
    }
}

/// Render the `nats-server.conf`. The token is read from the
/// `$NATS_TOKEN` env (NATS expands `$VAR` in config), so it never lands
/// in the (non-secret) ConfigMap. TLS terminates on the client port when
/// enabled; the monitoring port stays plain HTTP for probes.
pub fn render_nats_conf(tls_enabled: bool) -> String {
    let tls_block = if tls_enabled {
        format!(
            "\ntls {{\n  cert_file: \"{NATS_TLS_DIR}/tls.crt\"\n  key_file: \"{NATS_TLS_DIR}/tls.key\"\n  \
             ca_file: \"{NATS_TLS_DIR}/ca.crt\"\n  timeout: 5\n}}\n"
        )
    } else {
        String::new()
    };
    format!(
        "# Generated by the mcpg operator for a managed MCPGCluster coordinator.\n\
         server_name: $POD_NAME\n\
         listen: 0.0.0.0:{MANAGED_NATS_CLIENT_PORT}\n\
         http: 0.0.0.0:{NATS_MONITOR_PORT}\n\
         \n\
         jetstream {{\n  store_dir: \"{NATS_DATA_DIR}/jetstream\"\n  max_memory_store: 67108864\n}}\n\
         \n\
         authorization {{\n  token: $NATS_TOKEN\n}}\n{tls_block}"
    )
}

/// ConfigMap holding `nats-server.conf`.
pub fn build_nats_configmap(
    cluster: &MCPGCluster,
    namespace: &str,
    tls_enabled: bool,
) -> ConfigMap {
    let cluster_name = cluster.metadata.name.clone().unwrap_or_default();
    let mut data = BTreeMap::new();
    data.insert("nats-server.conf".to_owned(), render_nats_conf(tls_enabled));
    ConfigMap {
        metadata: child_meta(cluster, managed_nats_config_name(&cluster_name), namespace),
        data: Some(data),
        ..Default::default()
    }
}

/// Headless Service — stable per-pod DNS + JetStream peer discovery.
pub fn build_nats_headless_service(cluster: &MCPGCluster, namespace: &str) -> Service {
    let cluster_name = cluster.metadata.name.clone().unwrap_or_default();
    Service {
        metadata: child_meta(
            cluster,
            managed_nats_headless_service_name(&cluster_name),
            namespace,
        ),
        spec: Some(ServiceSpec {
            cluster_ip: Some("None".to_owned()),
            selector: Some(selector_labels(&cluster_name)),
            // Headless Services normally hide not-yet-ready pods; JetStream
            // needs the stable DNS name from the first boot, so publish it early.
            publish_not_ready_addresses: Some(true),
            ports: Some(nats_service_ports()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Client Service — the ClusterIP FQDN gateways dial.
pub fn build_nats_client_service(cluster: &MCPGCluster, namespace: &str) -> Service {
    let cluster_name = cluster.metadata.name.clone().unwrap_or_default();
    Service {
        metadata: child_meta(cluster, managed_nats_service_name(&cluster_name), namespace),
        spec: Some(ServiceSpec {
            type_: Some("ClusterIP".to_owned()),
            selector: Some(selector_labels(&cluster_name)),
            ports: Some(nats_service_ports()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn nats_service_ports() -> Vec<ServicePort> {
    vec![
        ServicePort {
            name: Some("client".to_owned()),
            port: MANAGED_NATS_CLIENT_PORT,
            target_port: Some(IntOrString::String("client".to_owned())),
            protocol: Some("TCP".to_owned()),
            ..Default::default()
        },
        ServicePort {
            name: Some("monitor".to_owned()),
            port: NATS_MONITOR_PORT,
            target_port: Some(IntOrString::String("monitor".to_owned())),
            protocol: Some("TCP".to_owned()),
            ..Default::default()
        },
    ]
}

/// StatefulSet running one NATS server with JetStream file store.
pub fn build_nats_statefulset(
    cluster: &MCPGCluster,
    namespace: &str,
    replicas: i32,
    tls_enabled: bool,
) -> StatefulSet {
    let cluster_name = cluster.metadata.name.clone().unwrap_or_default();
    let managed = cluster.spec.managed.as_ref();
    let image = managed
        .and_then(|m| m.image.clone())
        .filter(|i| !i.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_MANAGED_NATS_IMAGE.to_owned());
    let storage = managed.map(|m| m.storage.clone()).unwrap_or_default();
    let secret_name = managed_coordination_secret_name(&cluster_name);

    let mut volume_mounts = vec![
        VolumeMount {
            name: "config".to_owned(),
            mount_path: NATS_CONFIG_DIR.to_owned(),
            read_only: Some(true),
            ..Default::default()
        },
        VolumeMount {
            name: "data".to_owned(),
            mount_path: NATS_DATA_DIR.to_owned(),
            ..Default::default()
        },
    ];
    let mut volumes = vec![Volume {
        name: "config".to_owned(),
        config_map: Some(ConfigMapVolumeSource {
            name: managed_nats_config_name(&cluster_name),
            ..Default::default()
        }),
        ..Default::default()
    }];
    if tls_enabled {
        volume_mounts.push(VolumeMount {
            name: "tls".to_owned(),
            mount_path: NATS_TLS_DIR.to_owned(),
            read_only: Some(true),
            ..Default::default()
        });
        volumes.push(Volume {
            name: "tls".to_owned(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(managed_nats_tls_secret_name(&cluster_name)),
                ..Default::default()
            }),
            ..Default::default()
        });
    }

    let container = Container {
        name: "nats".to_owned(),
        image: Some(image),
        args: Some(vec![
            "--config".to_owned(),
            format!("{NATS_CONFIG_DIR}/nats-server.conf"),
        ]),
        ports: Some(vec![
            ContainerPort {
                name: Some("client".to_owned()),
                container_port: MANAGED_NATS_CLIENT_PORT,
                protocol: Some("TCP".to_owned()),
                ..Default::default()
            },
            ContainerPort {
                name: Some("monitor".to_owned()),
                container_port: NATS_MONITOR_PORT,
                protocol: Some("TCP".to_owned()),
                ..Default::default()
            },
            ContainerPort {
                name: Some("cluster".to_owned()),
                container_port: NATS_CLUSTER_PORT,
                protocol: Some("TCP".to_owned()),
                ..Default::default()
            },
        ]),
        env: Some(vec![
            EnvVar {
                name: "POD_NAME".to_owned(),
                value_from: Some(EnvVarSource {
                    field_ref: Some(ObjectFieldSelector {
                        field_path: "metadata.name".to_owned(),
                        api_version: None,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            EnvVar {
                name: NATS_SERVER_TOKEN_ENV.to_owned(),
                value_from: Some(EnvVarSource {
                    secret_key_ref: Some(SecretKeySelector {
                        name: secret_name,
                        key: MANAGED_NATS_TOKEN_ENV.to_owned(),
                        optional: Some(false),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ]),
        volume_mounts: Some(volume_mounts),
        readiness_probe: Some(nats_probe(5, 10)),
        liveness_probe: Some(nats_probe(10, 15)),
        resources: build_nats_resources(cluster),
        security_context: Some(SecurityContext {
            allow_privilege_escalation: Some(false),
            run_as_non_root: Some(true),
            run_as_user: Some(NATS_RUN_AS),
            run_as_group: Some(NATS_RUN_AS),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_owned()]),
                add: None,
            }),
            seccomp_profile: Some(SeccompProfile {
                type_: "RuntimeDefault".to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    let pod_labels = managed_labels(&cluster_name);
    StatefulSet {
        metadata: child_meta(
            cluster,
            managed_nats_statefulset_name(&cluster_name),
            namespace,
        ),
        spec: Some(StatefulSetSpec {
            replicas: Some(replicas),
            service_name: Some(managed_nats_headless_service_name(&cluster_name)),
            selector: LabelSelector {
                match_labels: Some(selector_labels(&cluster_name)),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(pod_labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![container],
                    volumes: Some(volumes),
                    security_context: Some(PodSecurityContext {
                        fs_group: Some(NATS_RUN_AS),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            },
            volume_claim_templates: Some(vec![build_nats_pvc(cluster, &storage)]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn nats_probe(initial_delay: i32, period: i32) -> Probe {
    Probe {
        http_get: Some(HTTPGetAction {
            path: Some("/healthz".to_owned()),
            port: IntOrString::String("monitor".to_owned()),
            scheme: Some("HTTP".to_owned()),
            ..Default::default()
        }),
        initial_delay_seconds: Some(initial_delay),
        period_seconds: Some(period),
        timeout_seconds: Some(3),
        failure_threshold: Some(3),
        ..Default::default()
    }
}

fn build_nats_pvc(cluster: &MCPGCluster, storage: &ManagedStorage) -> PersistentVolumeClaim {
    let size = storage
        .size
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_MANAGED_STORAGE_SIZE.to_owned());
    let mut requests = BTreeMap::new();
    requests.insert("storage".to_owned(), Quantity(size));
    PersistentVolumeClaim {
        // The name matches the "data" VolumeMount; the StatefulSet suffixes
        // it with the pod ordinal.
        metadata: ObjectMeta {
            name: Some("data".to_owned()),
            labels: Some(managed_labels(
                cluster.metadata.name.as_deref().unwrap_or_default(),
            )),
            ..Default::default()
        },
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_owned()]),
            resources: Some(VolumeResourceRequirements {
                requests: Some(requests),
                ..Default::default()
            }),
            storage_class_name: storage
                .storage_class_name
                .clone()
                .filter(|s| !s.trim().is_empty()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn build_nats_resources(cluster: &MCPGCluster) -> Option<ResourceRequirements> {
    let managed = cluster.spec.managed.as_ref()?;
    if let Some(rr) = managed.resources.as_ref() {
        let requests: BTreeMap<String, Quantity> = rr
            .requests
            .iter()
            .map(|(k, v)| (k.clone(), Quantity(v.clone())))
            .collect();
        let limits: BTreeMap<String, Quantity> = rr
            .limits
            .iter()
            .map(|(k, v)| (k.clone(), Quantity(v.clone())))
            .collect();
        return Some(ResourceRequirements {
            requests: (!requests.is_empty()).then_some(requests),
            limits: (!limits.is_empty()).then_some(limits),
            claims: None,
        });
    }
    // Modest default request; no limit (JetStream benefits from burst).
    let mut requests = BTreeMap::new();
    requests.insert("cpu".to_owned(), Quantity("100m".to_owned()));
    requests.insert("memory".to_owned(), Quantity("128Mi".to_owned()));
    Some(ResourceRequirements {
        requests: Some(requests),
        limits: None,
        claims: None,
    })
}

/// cert-manager `Certificate` for the NATS server cert (TLS path). DNS
/// SANs cover the client + headless Service FQDNs (and the per-pod
/// wildcard) so a gateway dialing the client FQDN verifies the cert.
pub fn build_nats_certificate(
    cluster: &MCPGCluster,
    namespace: &str,
    issuer: &ManagedIssuerRef,
) -> Certificate {
    let cluster_name = cluster.metadata.name.clone().unwrap_or_default();
    let client = managed_nats_service_name(&cluster_name);
    let headless = managed_nats_headless_service_name(&cluster_name);
    let dns_names = vec![
        client.clone(),
        format!("{client}.{namespace}"),
        format!("{client}.{namespace}.svc"),
        format!("{client}.{namespace}.svc.cluster.local"),
        format!("{headless}.{namespace}.svc.cluster.local"),
        format!("*.{headless}.{namespace}.svc.cluster.local"),
    ];
    let mut cert = Certificate::new(
        &managed_nats_tls_secret_name(&cluster_name),
        CertificateSpec {
            secret_name: managed_nats_tls_secret_name(&cluster_name),
            dns_names,
            issuer_ref: IssuerRef {
                name: issuer.name.clone(),
                kind: issuer.kind.clone(),
                group: issuer.group.clone(),
            },
        },
    );
    cert.metadata = child_meta(
        cluster,
        managed_nats_tls_secret_name(&cluster_name),
        namespace,
    );
    cert
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_operator_api::v1alpha1::{MCPGClusterSpec, ManagedCoordinator, ManagedCoordinatorTls};

    fn managed_cluster(managed: ManagedCoordinator) -> MCPGCluster {
        MCPGCluster {
            metadata: ObjectMeta {
                name: Some("prod".into()),
                uid: Some("uid-1".into()),
                ..Default::default()
            },
            spec: MCPGClusterSpec {
                managed: Some(managed),
                ..Default::default()
            },
            status: None,
        }
    }

    #[test]
    fn children_carry_the_cluster_prune_label() {
        let c = managed_cluster(ManagedCoordinator::default());
        let cm = build_nats_configmap(&c, "mcpg-system", false);
        assert_eq!(
            cm.metadata.labels.as_ref().unwrap()[MANAGED_CLUSTER_LABEL],
            "prod"
        );
        // Cluster-scoped parent → namespaced child: no cross-scope owner
        // ref (finalizer-driven cleanup instead, per the codebase convention).
        assert!(cm.metadata.owner_references.is_none());
    }

    #[test]
    fn configmap_carries_token_via_env_not_data() {
        let c = managed_cluster(ManagedCoordinator::default());
        let cm = build_nats_configmap(&c, "mcpg-system", false);
        assert_eq!(cm.metadata.name.as_deref(), Some("prod-nats-config"));
        assert_eq!(cm.metadata.namespace.as_deref(), Some("mcpg-system"));
        let conf = &cm.data.unwrap()["nats-server.conf"];
        // Token is an env reference, never a literal in the ConfigMap.
        assert!(conf.contains("token: $NATS_TOKEN"), "{conf}");
        assert!(conf.contains("jetstream"), "{conf}");
        assert!(conf.contains("store_dir"), "{conf}");
        // No TLS block for the plaintext path.
        assert!(!conf.contains("cert_file"), "{conf}");
    }

    #[test]
    fn conf_tls_block_only_when_enabled() {
        assert!(render_nats_conf(true).contains("cert_file"));
        assert!(render_nats_conf(true).contains("ca_file"));
        assert!(!render_nats_conf(false).contains("tls {"));
    }

    #[test]
    fn statefulset_shape_plaintext() {
        let c = managed_cluster(ManagedCoordinator::default());
        let ss = build_nats_statefulset(&c, "mcpg-system", 1, false);
        let spec = ss.spec.unwrap();
        assert_eq!(spec.replicas, Some(1));
        assert_eq!(spec.service_name.as_deref(), Some("prod-nats-headless"));
        // One PVC template sized to the default.
        let pvc = &spec.volume_claim_templates.unwrap()[0];
        assert_eq!(pvc.metadata.name.as_deref(), Some("data"));
        let req = &pvc
            .spec
            .as_ref()
            .unwrap()
            .resources
            .as_ref()
            .unwrap()
            .requests
            .as_ref()
            .unwrap()["storage"];
        assert_eq!(req.0, "10Gi");
        let pod = spec.template.spec.as_ref().unwrap();
        let container = &pod.containers[0];
        assert_eq!(container.image.as_deref(), Some("nats:2.10.25-alpine"));
        // Token wired from the coordination Secret.
        let token_env = container
            .env
            .as_ref()
            .unwrap()
            .iter()
            .find(|e| e.name == "NATS_TOKEN")
            .unwrap();
        let sel = token_env
            .value_from
            .as_ref()
            .unwrap()
            .secret_key_ref
            .as_ref()
            .unwrap();
        assert_eq!(sel.name, "prod-coordination");
        assert_eq!(sel.key, "MCPG_CLUSTER_NATS_TOKEN");
        // No TLS volume on the plaintext path.
        assert!(
            !pod.volumes
                .as_ref()
                .unwrap()
                .iter()
                .any(|v| v.name == "tls")
        );
    }

    #[test]
    fn statefulset_mounts_tls_secret_when_enabled() {
        let c = managed_cluster(ManagedCoordinator {
            tls: Some(ManagedCoordinatorTls {
                issuer_ref: Some(ManagedIssuerRef {
                    name: "internal".into(),
                    ..Default::default()
                }),
            }),
            ..Default::default()
        });
        let ss = build_nats_statefulset(&c, "mcpg-system", 1, true);
        let pod = ss.spec.unwrap().template.spec.unwrap();
        assert!(pod.volumes.unwrap().iter().any(|v| v.name == "tls"));
        assert!(
            pod.containers[0]
                .volume_mounts
                .as_ref()
                .unwrap()
                .iter()
                .any(|m| m.name == "tls")
        );
    }

    #[test]
    fn statefulset_honours_storage_overrides() {
        let c = managed_cluster(ManagedCoordinator {
            storage: ManagedStorage {
                size: Some("50Gi".into()),
                storage_class_name: Some("fast-ssd".into()),
            },
            ..Default::default()
        });
        let ss = build_nats_statefulset(&c, "mcpg-system", 1, false);
        let pvc = &ss.spec.unwrap().volume_claim_templates.unwrap()[0];
        let pspec = pvc.spec.as_ref().unwrap();
        assert_eq!(pspec.storage_class_name.as_deref(), Some("fast-ssd"));
        assert_eq!(
            pspec.resources.as_ref().unwrap().requests.as_ref().unwrap()["storage"].0,
            "50Gi"
        );
    }

    #[test]
    fn services_select_the_pods() {
        let c = managed_cluster(ManagedCoordinator::default());
        let client = build_nats_client_service(&c, "mcpg-system");
        assert_eq!(client.metadata.name.as_deref(), Some("prod-nats"));
        let cspec = client.spec.unwrap();
        assert_eq!(cspec.type_.as_deref(), Some("ClusterIP"));
        assert_eq!(
            cspec.selector.unwrap()["app.kubernetes.io/instance"],
            "prod"
        );
        let headless = build_nats_headless_service(&c, "mcpg-system");
        assert_eq!(
            headless.metadata.name.as_deref(),
            Some("prod-nats-headless")
        );
        assert_eq!(headless.spec.unwrap().cluster_ip.as_deref(), Some("None"));
    }

    #[test]
    fn certificate_sans_cover_client_fqdn() {
        let issuer = ManagedIssuerRef {
            name: "mcpg-internal".into(),
            kind: "ClusterIssuer".into(),
            group: "cert-manager.io".into(),
        };
        let c = managed_cluster(ManagedCoordinator::default());
        let cert = build_nats_certificate(&c, "mcpg-system", &issuer);
        assert_eq!(cert.metadata.name.as_deref(), Some("prod-nats-tls"));
        assert_eq!(cert.spec.secret_name, "prod-nats-tls");
        assert!(
            cert.spec
                .dns_names
                .contains(&"prod-nats.mcpg-system.svc.cluster.local".to_owned())
        );
        assert_eq!(cert.spec.issuer_ref.kind, "ClusterIssuer");
    }

    #[test]
    fn children_carry_prune_label_not_owner_refs() {
        let c = managed_cluster(ManagedCoordinator::default());
        let cm = build_nats_configmap(&c, "mcpg-system", false);
        let svc = build_nats_client_service(&c, "mcpg-system");
        let ss = build_nats_statefulset(&c, "mcpg-system", 1, false);
        for meta in [&cm.metadata, &svc.metadata, &ss.metadata] {
            assert_eq!(meta.labels.as_ref().unwrap()[MANAGED_CLUSTER_LABEL], "prod");
            assert!(meta.owner_references.is_none());
        }
    }
}
