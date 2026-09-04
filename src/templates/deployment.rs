//! Deployment template — renders the gateway pod spec.
//!
//! Mirrors the Helm chart's `helm/charts/mcpg/templates/deployment.yaml`
//! shape so a `MCPGGateway` reconciled by this operator produces
//! a pod template a Helm-using operator would recognise. Differences
//! are intentional and documented inline.

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy};
use k8s_openapi::api::core::v1::{
    Capabilities, ConfigMapVolumeSource, Container, ContainerPort, EmptyDirVolumeSource, EnvVar,
    EnvVarSource, HTTPGetAction, KeyToPath, ObjectFieldSelector, PodSecurityContext, PodSpec,
    PodTemplateSpec, Probe, ResourceRequirements, SeccompProfile, SecretVolumeSource,
    SecurityContext, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::core::ObjectMeta;
use mcpg_operator_api::v1alpha1::{GatewayProbe, MCPGGateway};

use crate::templates::common::{child_name, owner_ref, selector_labels, standard_labels};
use crate::{default_gateway_image_repository, default_gateway_image_tag};

/// Container port name used by the Service's `targetPort` and
/// the probes' `port` selectors. Stable across config changes.
const HTTP_PORT_NAME: &str = "http";

/// Annotation injected on the pod template carrying the
/// rendered config's SHA-256. A change to this value rolls pods
/// (which is what we want when the operator updates the
/// ConfigMap content).
const CONFIG_HASH_ANNOTATION: &str = "mcpg.dev/config-hash";

/// Annotation carrying `MCPGPluginSet.status.resolvedHash`. The
/// rendered config also embeds plugin entries (which folds into
/// `config-hash`), but a separate annotation keeps the plugin-
/// set-vs-config drift visible to dashboards.
const PLUGIN_SET_HASH_ANNOTATION: &str = "mcpg.dev/plugin-set-hash";

/// Annotation carrying the operator's view of the active
/// `MCPGRevocationList`'s content hash.
const REVOCATION_LIST_HASH_ANNOTATION: &str = "mcpg.dev/revocation-list-hash";

/// Mount point of the resolved-revocation-list ConfigMap.
const REVOCATION_LIST_MOUNT_DIR: &str = "/etc/mcpg/revocations";

/// Writable runtime directory backed by an `emptyDir`. The rootfs is
/// read-only (restricted PSA) and the gateway runs as 65534 with
/// `fsGroup: 65534`, so an `emptyDir` mounted here is the one path the
/// process can write — the container's working directory is anchored to
/// it so relative runtime writes (the default audit log) land here.
const RUNTIME_DIR: &str = "/var/lib/mcpg";
/// Volume name for [`RUNTIME_DIR`].
const RUNTIME_VOLUME_NAME: &str = "runtime";

/// Filesystem prefix the operator projects per-plugin Secrets
/// under. Mirrors `templates::plugin_render::PLUGIN_MOUNT_ROOT`.
const PLUGIN_MOUNT_ROOT: &str = "/etc/mcpg/plugins";

/// One per-plugin Secret the operator projects into the gateway
/// pod. The controller builds one of these per resolved
/// MCPGPluginSet entry; the deployment template renders them as
/// individual SecretVolumeSource volumes + per-plugin VolumeMounts
/// so a single Pod can read every plugin's bytes from a
/// predictable per-id directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginSecretMount {
    /// Plugin id (reverse-domain). Used both as the mount-path
    /// suffix and in the volume name (after sanitisation).
    pub plugin_id: String,
    /// Name of the per-namespace Secret the plugin-set controller
    /// materialised.
    pub secret_name: String,
}

/// Operator-side view of the resolved revocation list — the
/// gateway controller passes this through when
/// `revocationListRef` is set + the cluster
/// `MCPGRevocationList` is healthy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationListMount {
    /// Name of the namespace-local ConfigMap holding the
    /// revocation list JSON under key `list.json`. Operator-
    /// materialised; see the gateway controller.
    pub config_map_name: String,
    /// SHA-256 of the rendered revocation list — surfaced as
    /// the `mcpg.dev/revocation-list-hash` pod annotation.
    pub content_hash: String,
}

pub fn build_deployment(
    parent: &MCPGGateway,
    config_hash: &str,
    plugin_mounts: &[PluginSecretMount],
    plugin_set_hash: Option<&str>,
    revocation_list: Option<&RevocationListMount>,
    default_pod_annotations: &BTreeMap<String, String>,
) -> Deployment {
    let name = child_name(parent, "gateway");
    let labels = standard_labels(parent);
    let selector = selector_labels(parent);

    let port = parent
        .spec
        .service
        .as_ref()
        .and_then(|s| s.port)
        .unwrap_or(8787);

    Deployment {
        metadata: ObjectMeta {
            name: Some(name),
            namespace: parent.metadata.namespace.clone(),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_ref(parent)]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            // When an HPA owns scaling, the Deployment must not pin `replicas`
            // or the operator and the HPA fight every reconcile. Leave it unset
            // so the HPA is the sole authority; otherwise honour `spec.replicas`.
            replicas: if parent.spec.autoscaling.as_ref().is_some_and(|a| a.enabled) {
                None
            } else {
                Some(parent.spec.replicas)
            },
            selector: LabelSelector {
                match_labels: Some(selector.clone()),
                ..Default::default()
            },
            strategy: Some(DeploymentStrategy {
                type_: Some("RollingUpdate".to_owned()),
                rolling_update: None,
            }),
            template: PodTemplateSpec {
                metadata: Some(build_pod_metadata(
                    parent,
                    &labels,
                    config_hash,
                    plugin_set_hash,
                    revocation_list,
                    default_pod_annotations,
                )),
                spec: Some(build_pod_spec(parent, port, plugin_mounts, revocation_list)),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn build_pod_metadata(
    parent: &MCPGGateway,
    labels: &BTreeMap<String, String>,
    config_hash: &str,
    plugin_set_hash: Option<&str>,
    revocation_list: Option<&RevocationListMount>,
    default_pod_annotations: &BTreeMap<String, String>,
) -> ObjectMeta {
    let mut pod_labels = labels.clone();
    for (k, v) in &parent.spec.pod_labels {
        // User labels added LAST so they don't override
        // operator-managed keys. Specifically, app.kubernetes.io/*
        // and mcpg.dev/* are reserved.
        if k.starts_with("app.kubernetes.io/") || k.starts_with("mcpg.dev/") {
            tracing::warn!(
                ?k,
                "ignoring user pod label collision with operator-managed key"
            );
            continue;
        }
        pod_labels.insert(k.clone(), v.clone());
    }

    // operator-level defaults first, so a CR's own annotations override them
    let mut annotations = default_pod_annotations.clone();
    annotations.extend(parent.spec.pod_annotations.clone());
    annotations.insert(CONFIG_HASH_ANNOTATION.to_owned(), config_hash.to_owned());
    if let Some(h) = plugin_set_hash {
        annotations.insert(PLUGIN_SET_HASH_ANNOTATION.to_owned(), h.to_owned());
    }
    if let Some(r) = revocation_list {
        annotations.insert(
            REVOCATION_LIST_HASH_ANNOTATION.to_owned(),
            r.content_hash.clone(),
        );
    }

    ObjectMeta {
        labels: Some(pod_labels),
        annotations: Some(annotations),
        ..Default::default()
    }
}

fn build_pod_spec(
    parent: &MCPGGateway,
    port: i32,
    plugin_mounts: &[PluginSecretMount],
    revocation_list: Option<&RevocationListMount>,
) -> PodSpec {
    PodSpec {
        service_account_name: Some(child_name(parent, "gateway")),
        automount_service_account_token: Some(false),
        // Disable the legacy Docker-links service-discovery env vars. k8s
        // otherwise injects `<SVCNAME>_SERVICE_HOST` / `<SVCNAME>_PORT` (etc.,
        // uppercased) for every Service in the namespace — and since the
        // gateway Service is named `mcpg-<uid>`, those become `MCPG_<UID>_*`,
        // which collide with the gateway's `MCPG_` config-env prefix and panic
        // it at boot (`unknown field ... for MCPG_ environment variable`). The
        // gateway reads its config from the mounted file, not env links.
        enable_service_links: Some(false),
        security_context: Some(PodSecurityContext {
            run_as_non_root: Some(true),
            run_as_user: Some(65534),
            run_as_group: Some(65534),
            fs_group: Some(65534),
            seccomp_profile: Some(SeccompProfile {
                type_: "RuntimeDefault".to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        containers: vec![build_main_container(
            parent,
            port,
            plugin_mounts,
            revocation_list,
        )],
        volumes: Some(build_volumes(parent, plugin_mounts, revocation_list)),
        node_selector: parent
            .spec
            .scheduling
            .as_ref()
            .filter(|s| !s.node_selector.is_empty())
            .map(|s| s.node_selector.clone()),
        priority_class_name: parent
            .spec
            .scheduling
            .as_ref()
            .and_then(|s| s.priority_class_name.clone()),
        termination_grace_period_seconds: parent
            .spec
            .scheduling
            .as_ref()
            .and_then(|s| s.termination_grace_period_seconds),
        ..Default::default()
    }
}

fn build_volumes(
    parent: &MCPGGateway,
    plugin_mounts: &[PluginSecretMount],
    revocation_list: Option<&RevocationListMount>,
) -> Vec<Volume> {
    let mut volumes = vec![Volume {
        name: "config".to_owned(),
        config_map: Some(ConfigMapVolumeSource {
            name: child_name(parent, "config"),
            ..Default::default()
        }),
        ..Default::default()
    }];

    // Writable runtime scratch (emptyDir). fsGroup 65534 makes it
    // writable by the non-root gateway process; the rootfs itself is
    // read-only.
    volumes.push(Volume {
        name: RUNTIME_VOLUME_NAME.to_owned(),
        empty_dir: Some(EmptyDirVolumeSource::default()),
        ..Default::default()
    });

    for m in plugin_mounts {
        volumes.push(Volume {
            name: plugin_volume_name(&m.plugin_id),
            secret: Some(SecretVolumeSource {
                secret_name: Some(m.secret_name.clone()),
                // Default-mode 0o440 — gateway runs as 65534, the
                // Secret bytes need to be readable but not
                // executable. The cdylib is dlopen'd from a
                // tmpfs the gateway copies into; mounting bytes
                // 0o550 buys nothing here.
                default_mode: Some(0o440),
                ..Default::default()
            }),
            ..Default::default()
        });
    }

    if let Some(r) = revocation_list {
        volumes.push(Volume {
            name: "revocation-list".to_owned(),
            config_map: Some(ConfigMapVolumeSource {
                name: r.config_map_name.clone(),
                items: Some(vec![KeyToPath {
                    key: "list.json".to_owned(),
                    path: "list.json".to_owned(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        });
    }

    volumes
}

/// Sanitise a plugin id (reverse-domain, dots) into a K8s volume
/// name (lowercase alphanumeric / `-`, ≤63 chars). The gateway
/// reads bytes by mount path, so the volume name itself only
/// has to round-trip K8s validation.
fn plugin_volume_name(plugin_id: &str) -> String {
    // Replace any non-alphanumeric with `-`. K8s volume names are
    // RFC1123 — lowercase alphanumeric + `-`, ≤63 chars, must
    // begin + end with an alphanumeric.
    let mut s: String = plugin_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    if s.len() > 56 {
        s.truncate(56);
    }
    let cleaned = s.trim_matches('-').to_owned();
    let prefixed = format!("plugin-{cleaned}");
    if prefixed.len() > 63 {
        prefixed[..63].to_owned()
    } else {
        prefixed
    }
}

fn build_main_container(
    parent: &MCPGGateway,
    port: i32,
    plugin_mounts: &[PluginSecretMount],
    revocation_list: Option<&RevocationListMount>,
) -> Container {
    let image_repo = parent
        .spec
        .image
        .repository
        .clone()
        .unwrap_or_else(|| default_gateway_image_repository().to_owned());
    let image_tag = parent
        .spec
        .image
        .tag
        .clone()
        .unwrap_or_else(|| default_gateway_image_tag().to_owned());
    let image = format!("{image_repo}:{image_tag}");
    let pull_policy = parent
        .spec
        .image
        .pull_policy
        .clone()
        .unwrap_or_else(|| "IfNotPresent".to_owned());

    Container {
        name: "mcpg".to_owned(),
        image: Some(image),
        image_pull_policy: Some(pull_policy),
        // The rootfs is read-only (restricted PSA), so the gateway's
        // relative-path runtime writes — notably the default local-file
        // audit sink's `./mcpg-audit.log` — must resolve into the
        // writable runtime emptyDir. Anchor the working directory there.
        working_dir: Some(RUNTIME_DIR.to_owned()),
        args: Some(vec![
            "--config".to_owned(),
            "/etc/mcpg/config.yaml".to_owned(),
        ]),
        ports: Some(vec![ContainerPort {
            name: Some(HTTP_PORT_NAME.to_owned()),
            container_port: port,
            protocol: Some("TCP".to_owned()),
            ..Default::default()
        }]),
        env: Some(build_env_vars()),
        resources: Some(build_resources(parent)),
        volume_mounts: Some(build_volume_mounts(plugin_mounts, revocation_list)),
        liveness_probe: Some(build_probe(
            parent
                .spec
                .probes
                .as_ref()
                .and_then(|p| p.liveness.as_ref()),
            "/health",
            5,
            15,
        )),
        readiness_probe: Some(build_probe(
            parent
                .spec
                .probes
                .as_ref()
                .and_then(|p| p.readiness.as_ref()),
            "/ready",
            3,
            10,
        )),
        startup_probe: Some(Probe {
            failure_threshold: Some(
                parent
                    .spec
                    .probes
                    .as_ref()
                    .and_then(|p| p.startup.as_ref())
                    .and_then(|p| p.failure_threshold)
                    .unwrap_or(12),
            ),
            ..build_probe(
                parent.spec.probes.as_ref().and_then(|p| p.startup.as_ref()),
                "/health",
                2,
                5,
            )
        }),
        security_context: Some(SecurityContext {
            allow_privilege_escalation: Some(false),
            read_only_root_filesystem: Some(true),
            run_as_non_root: Some(true),
            run_as_user: Some(65534),
            run_as_group: Some(65534),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_owned()]),
                add: None,
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn build_volume_mounts(
    plugin_mounts: &[PluginSecretMount],
    revocation_list: Option<&RevocationListMount>,
) -> Vec<VolumeMount> {
    let mut mounts = vec![VolumeMount {
        name: "config".to_owned(),
        // The base config goes at /etc/mcpg/config.yaml. Mounting
        // the ConfigMap at /etc/mcpg as a directory would shadow
        // any other content under that prefix — but we need
        // /etc/mcpg/plugins and /etc/mcpg/revocations to coexist.
        // Switch to subPath so the ConfigMap projects only the
        // single config.yaml file at /etc/mcpg/config.yaml.
        mount_path: "/etc/mcpg/config.yaml".to_owned(),
        sub_path: Some("config.yaml".to_owned()),
        read_only: Some(true),
        ..Default::default()
    }];

    // Writable runtime scratch — the only path the gateway can write to
    // under the read-only rootfs (see RUNTIME_DIR). Backs the default
    // local-file audit sink + any other relative runtime write.
    mounts.push(VolumeMount {
        name: RUNTIME_VOLUME_NAME.to_owned(),
        mount_path: RUNTIME_DIR.to_owned(),
        ..Default::default()
    });

    for m in plugin_mounts {
        mounts.push(VolumeMount {
            name: plugin_volume_name(&m.plugin_id),
            // Per-plugin directory layout. The gateway expects
            // `plugin.so` + sidecar `plugin.yaml` at this prefix.
            mount_path: format!("{PLUGIN_MOUNT_ROOT}/{}", m.plugin_id),
            read_only: Some(true),
            ..Default::default()
        });
    }

    if revocation_list.is_some() {
        mounts.push(VolumeMount {
            name: "revocation-list".to_owned(),
            mount_path: REVOCATION_LIST_MOUNT_DIR.to_owned(),
            read_only: Some(true),
            ..Default::default()
        });
    }

    mounts
}

fn build_env_vars() -> Vec<EnvVar> {
    vec![
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
            name: "POD_NAMESPACE".to_owned(),
            value_from: Some(EnvVarSource {
                field_ref: Some(ObjectFieldSelector {
                    field_path: "metadata.namespace".to_owned(),
                    api_version: None,
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
        EnvVar {
            name: "NODE_NAME".to_owned(),
            value_from: Some(EnvVarSource {
                field_ref: Some(ObjectFieldSelector {
                    field_path: "spec.nodeName".to_owned(),
                    api_version: None,
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
    ]
}

fn build_resources(parent: &MCPGGateway) -> ResourceRequirements {
    let mut requests = BTreeMap::new();
    let mut limits = BTreeMap::new();

    if let Some(rr) = &parent.spec.resources {
        for (k, v) in &rr.requests {
            requests.insert(k.clone(), Quantity(v.clone()));
        }
        for (k, v) in &rr.limits {
            limits.insert(k.clone(), Quantity(v.clone()));
        }
    }
    if requests.is_empty() {
        requests.insert("cpu".to_owned(), Quantity("200m".to_owned()));
        requests.insert("memory".to_owned(), Quantity("256Mi".to_owned()));
    }
    if limits.is_empty() {
        limits.insert("cpu".to_owned(), Quantity("1".to_owned()));
        limits.insert("memory".to_owned(), Quantity("1Gi".to_owned()));
    }

    ResourceRequirements {
        requests: Some(requests),
        limits: Some(limits),
        claims: None,
    }
}

fn build_probe(
    user: Option<&GatewayProbe>,
    default_path: &str,
    initial_delay: i32,
    period: i32,
) -> Probe {
    let path = user
        .and_then(|p| p.path.clone())
        .unwrap_or_else(|| default_path.to_owned());

    Probe {
        http_get: Some(HTTPGetAction {
            path: Some(path),
            port: IntOrString::String(HTTP_PORT_NAME.to_owned()),
            scheme: Some("HTTP".to_owned()),
            ..Default::default()
        }),
        initial_delay_seconds: Some(
            user.and_then(|p| p.initial_delay_seconds)
                .unwrap_or(initial_delay),
        ),
        period_seconds: Some(user.and_then(|p| p.period_seconds).unwrap_or(period)),
        timeout_seconds: Some(user.and_then(|p| p.timeout_seconds).unwrap_or(3)),
        failure_threshold: Some(user.and_then(|p| p.failure_threshold).unwrap_or(3)),
        success_threshold: user.and_then(|p| p.success_threshold),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::{
        GatewayImage, GatewayResourceRequirements, GatewayService, MCPGGatewaySpec,
    };

    #[test]
    fn operator_default_annotations_lose_to_cr_and_hashes() {
        let mut spec = MCPGGatewaySpec::default();
        spec.pod_annotations
            .insert("prometheus.io/port".to_owned(), "9999".to_owned());
        let defaults = std::collections::BTreeMap::from([
            ("prometheus.io/scrape".to_owned(), "true".to_owned()),
            ("prometheus.io/port".to_owned(), "8080".to_owned()),
        ]);
        let d = build_deployment(&fixture(spec), "hash-1", &[], None, None, &defaults);
        let ann = d
            .spec
            .as_ref()
            .unwrap()
            .template
            .metadata
            .as_ref()
            .unwrap()
            .annotations
            .clone()
            .unwrap();
        assert_eq!(
            ann.get("prometheus.io/scrape").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            ann.get("prometheus.io/port").map(String::as_str),
            Some("9999"),
            "a CR's own annotation overrides the operator default"
        );
        assert!(ann.contains_key(super::CONFIG_HASH_ANNOTATION));
    }

    fn fixture(spec: MCPGGatewaySpec) -> MCPGGateway {
        MCPGGateway {
            metadata: ObjectMeta {
                name: Some("payments-gateway".into()),
                namespace: Some("payments".into()),
                uid: Some("uid-123".into()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    #[test]
    fn deployment_replicas_match_spec() {
        let d = build_deployment(
            &fixture(MCPGGatewaySpec {
                replicas: 5,
                ..Default::default()
            }),
            "abcd",
            &[],
            None,
            None,
            &Default::default(),
        );
        assert_eq!(d.spec.unwrap().replicas, Some(5));
    }

    #[test]
    fn config_hash_lands_on_pod_template_annotations() {
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "deadbeef",
            &[],
            None,
            None,
            &Default::default(),
        );
        let template = d.spec.unwrap().template;
        let annotations = template.metadata.unwrap().annotations.unwrap();
        assert_eq!(annotations.get(CONFIG_HASH_ANNOTATION).unwrap(), "deadbeef");
    }

    #[test]
    fn pod_template_has_security_context_restricted() {
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let pod = d.spec.unwrap().template.spec.unwrap();
        let pod_sec = pod.security_context.unwrap();
        assert_eq!(pod_sec.run_as_non_root, Some(true));
        assert_eq!(pod_sec.run_as_user, Some(65534));
        let container_sec = pod.containers[0].security_context.as_ref().unwrap();
        assert_eq!(container_sec.allow_privilege_escalation, Some(false));
        assert_eq!(container_sec.read_only_root_filesystem, Some(true));
        let caps = container_sec.capabilities.as_ref().unwrap();
        assert_eq!(caps.drop.as_ref().unwrap(), &vec!["ALL".to_owned()]);
    }

    #[test]
    fn service_links_disabled_so_mcpg_env_doesnt_collide() {
        // k8s injects `<SVC>_SERVICE_HOST/PORT/...` env for every Service in
        // the ns; the gateway Service is `mcpg-<uid>`, so those would be
        // `MCPG_<UID>_*` and collide with the gateway's MCPG_ config prefix.
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let pod = d.spec.unwrap().template.spec.unwrap();
        assert_eq!(pod.enable_service_links, Some(false));
    }

    #[test]
    fn writable_runtime_emptydir_anchors_working_dir() {
        // Regression: the rootfs is read-only, so the gateway's relative
        // runtime writes (default local-file audit sink → ./mcpg-audit.log)
        // need a writable working dir. A bare `tini -- mcpg --config` against
        // a read-only rootfs failed at the audit sink before this landed.
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let pod = d.spec.unwrap().template.spec.unwrap();
        let c = &pod.containers[0];
        assert_eq!(
            c.working_dir.as_deref(),
            Some("/var/lib/mcpg"),
            "working dir must be the writable runtime volume"
        );
        let mount = c
            .volume_mounts
            .as_ref()
            .unwrap()
            .iter()
            .find(|m| m.mount_path == "/var/lib/mcpg")
            .expect("runtime mount present");
        assert_ne!(
            mount.read_only,
            Some(true),
            "runtime mount must be writable"
        );
        let vol = pod
            .volumes
            .as_ref()
            .unwrap()
            .iter()
            .find(|v| v.name == "runtime")
            .expect("runtime volume present");
        assert!(vol.empty_dir.is_some(), "runtime volume is an emptyDir");
    }

    #[test]
    fn default_image_pin_used_when_unspecified() {
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let image = d.spec.unwrap().template.spec.unwrap().containers[0]
            .image
            .clone()
            .unwrap();
        assert!(image.starts_with(default_gateway_image_repository()));
        assert!(image.contains(default_gateway_image_tag()));
    }

    /// The rendered image is exactly the resolved defaults, so a runtime
    /// override reaches the pod template rather than stopping at the
    /// accessor. Run the binary with
    /// `MCPG_DEFAULT_GATEWAY_IMAGE_REPOSITORY` set to exercise the
    /// override arm.
    ///
    /// Reads the resolved accessors, never the environment: sibling tests
    /// mutate process env through `temp_env` on other threads, whereas the
    /// `OnceLock`-resolved values are fixed for the life of the binary.
    #[test]
    fn rendered_default_tracks_the_resolved_default() {
        let repo = default_gateway_image_repository();
        let tag = default_gateway_image_tag();
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let image = d.spec.unwrap().template.spec.unwrap().containers[0]
            .image
            .clone()
            .unwrap();
        assert_eq!(image, format!("{repo}:{tag}"));
        if repo != crate::DEFAULT_GATEWAY_IMAGE_REPOSITORY {
            assert!(
                !image.starts_with(crate::DEFAULT_GATEWAY_IMAGE_REPOSITORY),
                "an overridden default left the compiled repository in {image}"
            );
        }
    }

    /// The rendered default is byte-identical to the historical
    /// compiled-in reference whenever nothing overrides it.
    #[test]
    fn default_image_is_unchanged_without_env_overrides() {
        if default_gateway_image_repository() != crate::DEFAULT_GATEWAY_IMAGE_REPOSITORY
            || default_gateway_image_tag() != crate::DEFAULT_GATEWAY_IMAGE_TAG
        {
            return;
        }
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let image = d.spec.unwrap().template.spec.unwrap().containers[0]
            .image
            .clone()
            .unwrap();
        assert_eq!(
            image,
            format!(
                "ghcr.io/mcpg-dev/source-code/gateway:{}",
                crate::DEFAULT_GATEWAY_IMAGE_TAG
            )
        );
    }

    #[test]
    fn user_image_overrides_default() {
        let d = build_deployment(
            &fixture(MCPGGatewaySpec {
                image: GatewayImage {
                    repository: Some("my.private.registry/mcpg".into()),
                    tag: Some("v1.2.3".into()),
                    pull_policy: None,
                },
                ..Default::default()
            }),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let image = d.spec.unwrap().template.spec.unwrap().containers[0]
            .image
            .clone()
            .unwrap();
        assert_eq!(image, "my.private.registry/mcpg:v1.2.3");
    }

    #[test]
    fn default_resources_match_helm_chart() {
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let res = d.spec.unwrap().template.spec.unwrap().containers[0]
            .resources
            .clone()
            .unwrap();
        let req = res.requests.unwrap();
        assert_eq!(req.get("cpu").unwrap().0, "200m");
        assert_eq!(req.get("memory").unwrap().0, "256Mi");
    }

    #[test]
    fn user_resources_override_defaults() {
        let mut requests = BTreeMap::new();
        requests.insert("cpu".into(), "500m".into());
        let mut limits = BTreeMap::new();
        limits.insert("memory".into(), "2Gi".into());

        let d = build_deployment(
            &fixture(MCPGGatewaySpec {
                resources: Some(GatewayResourceRequirements { requests, limits }),
                ..Default::default()
            }),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let res = d.spec.unwrap().template.spec.unwrap().containers[0]
            .resources
            .clone()
            .unwrap();
        assert_eq!(res.requests.unwrap().get("cpu").unwrap().0, "500m");
        assert_eq!(res.limits.unwrap().get("memory").unwrap().0, "2Gi");
    }

    #[test]
    fn config_volume_mounts_config_yaml_via_subpath() {
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let mounts = d.spec.unwrap().template.spec.unwrap().containers[0]
            .volume_mounts
            .clone()
            .unwrap();
        let m = mounts.iter().find(|m| m.name == "config").unwrap();
        // Single-file mount via subPath so /etc/mcpg can carry
        // sibling directories (`plugins/`, `revocations/`).
        assert_eq!(m.mount_path, "/etc/mcpg/config.yaml");
        assert_eq!(m.sub_path.as_deref(), Some("config.yaml"));
    }

    #[test]
    fn config_volume_references_operator_configmap() {
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let volumes = d.spec.unwrap().template.spec.unwrap().volumes.unwrap();
        let cm_vol = volumes.iter().find(|v| v.name == "config").unwrap();
        let cm_src = cm_vol.config_map.as_ref().unwrap();
        assert_eq!(cm_src.name, "payments-gateway-config");
    }

    #[test]
    fn liveness_and_readiness_probes_use_default_paths() {
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let container = &d.spec.unwrap().template.spec.unwrap().containers[0];
        let liveness = container.liveness_probe.as_ref().unwrap();
        let readiness = container.readiness_probe.as_ref().unwrap();
        assert_eq!(
            liveness.http_get.as_ref().unwrap().path.as_deref(),
            Some("/health")
        );
        assert_eq!(
            readiness.http_get.as_ref().unwrap().path.as_deref(),
            Some("/ready")
        );
    }

    #[test]
    fn user_labels_dont_override_managed_keys() {
        let mut user_labels = BTreeMap::new();
        user_labels.insert("app.kubernetes.io/name".to_owned(), "evil".to_owned());
        user_labels.insert("team".to_owned(), "payments".to_owned());

        let d = build_deployment(
            &fixture(MCPGGatewaySpec {
                pod_labels: user_labels,
                ..Default::default()
            }),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let pod_labels = d.spec.unwrap().template.metadata.unwrap().labels.unwrap();
        // Operator-managed key wins.
        assert_eq!(
            pod_labels.get("app.kubernetes.io/name").unwrap(),
            "mcpg-gateway"
        );
        // User-only key is kept.
        assert_eq!(pod_labels.get("team").unwrap(), "payments");
    }

    #[test]
    fn service_account_name_matches_template() {
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let pod = d.spec.unwrap().template.spec.unwrap();
        assert_eq!(
            pod.service_account_name.as_deref(),
            Some("payments-gateway-gateway")
        );
    }

    #[test]
    fn user_service_port_propagates_to_container_port() {
        let d = build_deployment(
            &fixture(MCPGGatewaySpec {
                service: Some(GatewayService {
                    port: Some(443),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let port = d.spec.unwrap().template.spec.unwrap().containers[0]
            .ports
            .clone()
            .unwrap()[0]
            .container_port;
        assert_eq!(port, 443);
    }

    // ── Plugin set + revocation list ───────────────────────────

    fn plugin_mount(id: &str, secret: &str) -> PluginSecretMount {
        PluginSecretMount {
            plugin_id: id.into(),
            secret_name: secret.into(),
        }
    }

    #[test]
    fn one_secret_volume_per_resolved_plugin() {
        let mounts = vec![
            plugin_mount("dev.mcpg.identity.workload", "mcpg-plugin-id-w-1"),
            plugin_mount("dev.mcpg.policy.cedar", "mcpg-plugin-pol-c-1"),
        ];
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &mounts,
            None,
            None,
            &Default::default(),
        );
        let volumes = d.spec.unwrap().template.spec.unwrap().volumes.unwrap();
        let plugin_vols: Vec<_> = volumes.iter().filter(|v| v.secret.is_some()).collect();
        assert_eq!(plugin_vols.len(), 2);
        let names: Vec<&str> = plugin_vols
            .iter()
            .map(|v| v.secret.as_ref().unwrap().secret_name.as_deref().unwrap())
            .collect();
        assert!(names.contains(&"mcpg-plugin-id-w-1"));
        assert!(names.contains(&"mcpg-plugin-pol-c-1"));
    }

    #[test]
    fn plugin_mount_path_is_per_plugin_directory() {
        let mounts = vec![plugin_mount(
            "dev.mcpg.identity.workload",
            "mcpg-plugin-id-w-1",
        )];
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &mounts,
            None,
            None,
            &Default::default(),
        );
        let container_mounts = d.spec.unwrap().template.spec.unwrap().containers[0]
            .volume_mounts
            .clone()
            .unwrap();
        assert!(
            container_mounts
                .iter()
                .any(|m| { m.mount_path == "/etc/mcpg/plugins/dev.mcpg.identity.workload" })
        );
    }

    #[test]
    fn plugin_volumes_are_read_only_with_default_mode_0o440() {
        let mounts = vec![plugin_mount(
            "dev.mcpg.identity.workload",
            "mcpg-plugin-id-w-1",
        )];
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &mounts,
            None,
            None,
            &Default::default(),
        );
        let pod = d.spec.unwrap().template.spec.unwrap();
        let plugin_vol = pod
            .volumes
            .as_ref()
            .unwrap()
            .iter()
            .find(|v| v.secret.is_some())
            .unwrap();
        assert_eq!(
            plugin_vol.secret.as_ref().unwrap().default_mode,
            Some(0o440)
        );

        let plugin_mount = pod.containers[0]
            .volume_mounts
            .as_ref()
            .unwrap()
            .iter()
            .find(|m| m.mount_path.starts_with("/etc/mcpg/plugins/"))
            .unwrap();
        assert_eq!(plugin_mount.read_only, Some(true));
    }

    #[test]
    fn plugin_set_hash_lands_on_pod_template_annotations() {
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "config-h",
            &[],
            Some("set-h"),
            None,
            &Default::default(),
        );
        let annotations = d
            .spec
            .unwrap()
            .template
            .metadata
            .unwrap()
            .annotations
            .unwrap();
        assert_eq!(
            annotations.get("mcpg.dev/plugin-set-hash").unwrap(),
            "set-h"
        );
    }

    #[test]
    fn plugin_set_hash_omitted_when_no_set() {
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &[],
            None,
            None,
            &Default::default(),
        );
        let annotations = d
            .spec
            .unwrap()
            .template
            .metadata
            .unwrap()
            .annotations
            .unwrap();
        assert!(!annotations.contains_key("mcpg.dev/plugin-set-hash"));
    }

    #[test]
    fn revocation_list_volume_mount_at_canonical_path() {
        let rev = RevocationListMount {
            config_map_name: "payments-gateway-revocations".into(),
            content_hash: "deadc0de".into(),
        };
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &[],
            None,
            Some(&rev),
            &Default::default(),
        );
        let mounts = d.spec.unwrap().template.spec.unwrap().containers[0]
            .volume_mounts
            .clone()
            .unwrap();
        assert!(
            mounts
                .iter()
                .any(|m| m.mount_path == "/etc/mcpg/revocations")
        );
    }

    #[test]
    fn revocation_list_volume_projects_list_json_only() {
        let rev = RevocationListMount {
            config_map_name: "payments-gateway-revocations".into(),
            content_hash: "deadc0de".into(),
        };
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &[],
            None,
            Some(&rev),
            &Default::default(),
        );
        let volumes = d.spec.unwrap().template.spec.unwrap().volumes.unwrap();
        let rev_vol = volumes
            .iter()
            .find(|v| v.name == "revocation-list")
            .unwrap();
        let cm = rev_vol.config_map.as_ref().unwrap();
        assert_eq!(cm.name, "payments-gateway-revocations");
        let items = cm.items.as_ref().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].key, "list.json");
        assert_eq!(items[0].path, "list.json");
    }

    #[test]
    fn revocation_list_hash_lands_on_pod_template_annotations() {
        let rev = RevocationListMount {
            config_map_name: "payments-gateway-revocations".into(),
            content_hash: "deadc0de".into(),
        };
        let d = build_deployment(
            &fixture(MCPGGatewaySpec::default()),
            "h",
            &[],
            None,
            Some(&rev),
            &Default::default(),
        );
        let annotations = d
            .spec
            .unwrap()
            .template
            .metadata
            .unwrap()
            .annotations
            .unwrap();
        assert_eq!(
            annotations.get("mcpg.dev/revocation-list-hash").unwrap(),
            "deadc0de"
        );
    }

    #[test]
    fn plugin_volume_name_sanitises_dots_and_prefixes() {
        // Volume names are RFC1123-restricted — alphanumeric +
        // dashes only. Dots in plugin ids must be replaced.
        assert_eq!(
            plugin_volume_name("dev.mcpg.identity.workload"),
            "plugin-dev-mcpg-identity-workload"
        );
    }

    #[test]
    fn plugin_volume_name_caps_at_63_chars() {
        let very_long = format!("dev.mcpg.{}.workload", "x".repeat(80));
        let name = plugin_volume_name(&very_long);
        assert!(name.len() <= 63, "got {} chars", name.len());
        assert!(name.starts_with("plugin-"));
    }
}
