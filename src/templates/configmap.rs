//! ConfigMap template — renders `MCPGGateway.spec.config` into a
//! ConfigMap mounted by the gateway pod at
//! `/etc/mcpg/config.yaml`. Includes a SHA-256 over the rendered
//! bytes so reconcile loops can detect "config changed → roll
//! pods" without a deep diff.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::ConfigMap;
use kube::core::ObjectMeta;
use mcpg_operator_api::v1alpha1::MCPGGateway;
use sha2::{Digest, Sha256};

use crate::labels as label_keys;
use crate::templates::common::{child_name, owner_ref, standard_labels};

/// Length of the config-hash prefix used in the ConfigMap label. K8s caps
/// label values at 63 chars (a full SHA-256 hex is 64); 32 hex chars = 128
/// bits, collision-free for config-change detection. The full hash still
/// rides the deployment pod-template annotation.
const CONFIG_HASH_LABEL_LEN: usize = 32;

/// Returns `(ConfigMap, config_hash)`. The hash is the SHA-256
/// of the rendered YAML bytes — surfaced on the gateway pod
/// template's annotations so any config change rolls pods.
///
/// `merged_config` is the operator-side overlay output (see
/// `crate::templates::plugin_render::merge_plugins`). When the
/// gateway has no `pluginSetRef` / `revocationListRef`, the
/// caller passes `parent.spec.config.clone()` and this is a
/// straight serialisation of the user's config; when refs are
/// resolved, the operator-derived plugin block lands here.
pub fn build_configmap(
    parent: &MCPGGateway,
    merged_config: &serde_json::Value,
) -> (ConfigMap, String) {
    let yaml = serde_yaml::to_string(merged_config)
        .unwrap_or_else(|_| "# (operator: failed to render config; using empty)\n".into());

    let mut hasher = Sha256::new();
    hasher.update(yaml.as_bytes());
    let hash_bytes = hasher.finalize();
    let hash = hex::encode(hash_bytes);

    let mut data = BTreeMap::new();
    data.insert("config.yaml".to_owned(), yaml);

    let name = child_name(parent, "config");
    let mut labels = standard_labels(parent);
    // K8s label values are capped at 63 chars; a full SHA-256 hex is 64, which
    // the apiserver rejects (422). Put a truncated prefix in the label
    // (collision-free for config-change detection) and keep the full hash for
    // the deployment pod-template annotation, which is what drives rollouts.
    labels.insert(
        label_keys::MCPG_CONFIG_HASH.to_owned(),
        hash[..CONFIG_HASH_LABEL_LEN].to_owned(),
    );

    let cm = ConfigMap {
        metadata: ObjectMeta {
            name: Some(name),
            namespace: parent.metadata.namespace.clone(),
            labels: Some(labels),
            owner_references: Some(vec![owner_ref(parent)]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };

    (cm, hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::MCPGGatewaySpec;

    fn fixture(config: serde_json::Value) -> MCPGGateway {
        MCPGGateway {
            metadata: ObjectMeta {
                name: Some("payments-gateway".into()),
                namespace: Some("payments".into()),
                uid: Some("uid-123".into()),
                ..Default::default()
            },
            spec: MCPGGatewaySpec {
                config,
                ..Default::default()
            },
            status: None,
        }
    }

    #[test]
    fn configmap_carries_rendered_yaml() {
        let p = fixture(serde_json::json!({
            "server": { "bindAddress": "0.0.0.0:8787" }
        }));
        let (cm, _) = build_configmap(&p, &p.spec.config);
        let yaml = cm.data.as_ref().unwrap().get("config.yaml").unwrap();
        assert!(yaml.contains("server"), "rendered yaml: {yaml}");
        assert!(yaml.contains("bindAddress"), "rendered yaml: {yaml}");
    }

    #[test]
    fn config_hash_is_deterministic_for_same_input() {
        let p1 = fixture(serde_json::json!({"a": 1, "b": 2}));
        let p2 = fixture(serde_json::json!({"a": 1, "b": 2}));
        let (_, h1) = build_configmap(&p1, &p1.spec.config);
        let (_, h2) = build_configmap(&p2, &p2.spec.config);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // sha256 hex
    }

    #[test]
    fn config_hash_changes_when_config_changes() {
        let p1 = fixture(serde_json::json!({"a": 1}));
        let p2 = fixture(serde_json::json!({"a": 2}));
        let (_, h1) = build_configmap(&p1, &p1.spec.config);
        let (_, h2) = build_configmap(&p2, &p2.spec.config);
        assert_ne!(h1, h2);
    }

    #[test]
    fn config_hash_changes_when_merged_config_differs() {
        // Same parent.spec.config but different merged inputs
        // should produce different hashes — this is exactly the
        // pod-roll trigger we want when a plugin set changes.
        let p = fixture(serde_json::json!({"server": {"bindAddress": "0.0.0.0:8787"}}));
        let merged_a = serde_json::json!({"server": {"bindAddress": "0.0.0.0:8787"}});
        let merged_b = serde_json::json!({
            "server": {"bindAddress": "0.0.0.0:8787"},
            "plugins": {"entries": [{"id": "x"}]}
        });
        let (_, h_a) = build_configmap(&p, &merged_a);
        let (_, h_b) = build_configmap(&p, &merged_b);
        assert_ne!(h_a, h_b);
    }

    #[test]
    fn configmap_has_owner_ref_to_parent() {
        let p = fixture(serde_json::json!({}));
        let (cm, _) = build_configmap(&p, &p.spec.config);
        let orefs = cm.metadata.owner_references.unwrap();
        assert_eq!(orefs.len(), 1);
        assert_eq!(orefs[0].kind, "MCPGGateway");
    }

    #[test]
    fn configmap_carries_config_hash_label() {
        let p = fixture(serde_json::json!({"k": "v"}));
        let (cm, hash) = build_configmap(&p, &p.spec.config);
        let labels = cm.metadata.labels.unwrap();
        let label = labels.get(label_keys::MCPG_CONFIG_HASH).unwrap();
        // Full hash returned for the annotation; the label is the valid-length
        // prefix (K8s label values are capped at 63 chars).
        assert_eq!(hash.len(), 64);
        assert_eq!(label.len(), CONFIG_HASH_LABEL_LEN);
        assert!(label.len() <= 63);
        assert_eq!(label, &hash[..CONFIG_HASH_LABEL_LEN]);
    }
}
