//! Validating webhook for `MCPGPluginSet`.
//!
//! Pure-spec checks: entries non-empty, ids unique within the
//! set, capability grants name plugins that exist in the
//! entries list. Cross-resource validation (referenced
//! `MCPGPlugin` exists + Ready) lives in the controller.

use std::collections::BTreeSet;

use axum::Json;
use axum::extract::State;
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use mcpg_operator_api::v1alpha1::MCPGPluginSet;
use tracing::warn;

use crate::admission::server::AdmissionState;

pub async fn validate(
    State(state): State<AdmissionState>,
    Json(review): Json<AdmissionReview<MCPGPluginSet>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let req: AdmissionRequest<MCPGPluginSet> = match review.try_into() {
        Ok(r) => r,
        Err(e) => {
            warn!(error = ?e, "malformed admission review");
            return Json(AdmissionResponse::invalid("malformed admission review").into_review());
        }
    };

    let response = AdmissionResponse::from(&req);
    let Some(obj) = &req.object else {
        return Json(response.into_review());
    };

    // Pure spec checks first.
    if let Err(reason) = validate_spec(obj) {
        return Json(response.deny(reason).into_review());
    }

    // Tenant plugin allowlist (client-backed). When the
    // namespace has no owning MCPGTenant this is a no-op.
    let response =
        match crate::admission::tenant_guard::enforce_pluginset_allowlist(&state.client, obj).await
        {
            Ok(()) => response,
            Err(reason) => response.deny(reason),
        };

    Json(response.into_review())
}

fn validate_spec(obj: &MCPGPluginSet) -> Result<(), String> {
    let spec = &obj.spec;

    if spec.entries.is_empty() {
        return Err("spec.entries must not be empty".into());
    }

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (i, entry) in spec.entries.iter().enumerate() {
        if entry.id.trim().is_empty() {
            return Err(format!("spec.entries[{i}].id must not be empty"));
        }
        if !entry.id.contains('.') {
            return Err(format!(
                "spec.entries[{i}].id `{}` is not a valid plugin id (expected \
                 reverse-DNS form, e.g. `dev.mcpg.identity.workload`)",
                entry.id
            ));
        }
        if !seen.insert(entry.id.as_str()) {
            return Err(format!(
                "duplicate plugin id `{}` at spec.entries[{i}] — each id may \
                 appear at most once per set",
                entry.id
            ));
        }
        if entry.plugin_ref.name.trim().is_empty() {
            return Err(format!(
                "spec.entries[{i}].pluginRef.name must not be empty"
            ));
        }
    }

    // Capability grants must reference plugin ids that exist in
    // entries[]. A grant for an unknown id is operator
    // misconfiguration — better to fail-fast than silently drop.
    for (id, capabilities) in &spec.capability_grants {
        if !seen.contains(id.as_str()) {
            return Err(format!(
                "spec.capabilityGrants[`{id}`] names a plugin id not in spec.entries[]"
            ));
        }
        if capabilities.is_empty() {
            return Err(format!(
                "spec.capabilityGrants[`{id}`] is empty — either remove the entry \
                 or list the capabilities the plugin needs"
            ));
        }
        // Each grant must name a capability the gateway understands.
        // The gateway rejects unknown grants at boot (deny_unknown_fields
        // on the typed `Capability`), so validate here to surface the typo
        // at `kubectl apply` rather than as a crash-looping pod.
        for cap in capabilities {
            if let Err(e) = mcpg_plugin_protocol::capability::Capability::parse_value(
                &serde_json::Value::String(cap.clone()),
            ) {
                return Err(format!(
                    "spec.capabilityGrants[`{id}`] capability `{cap}` is not a valid \
                     gateway capability ({e}); valid kinds: {}",
                    mcpg_plugin_protocol::capability::Capability::known_names().join(", ")
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::{
        LocalObjectReference, MCPGPluginSetEntry, MCPGPluginSetSpec,
    };
    use std::collections::BTreeMap;

    fn fixture(spec: MCPGPluginSetSpec) -> MCPGPluginSet {
        MCPGPluginSet {
            metadata: ObjectMeta {
                name: Some("payments-plugins".into()),
                namespace: Some("payments".into()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn good_entry(id: &str, plugin_name: &str) -> MCPGPluginSetEntry {
        MCPGPluginSetEntry {
            id: id.into(),
            plugin_ref: LocalObjectReference {
                name: plugin_name.into(),
            },
            enabled: true,
            enforce: true,
            config: None,
        }
    }

    #[test]
    fn rejects_empty_entries() {
        let s = MCPGPluginSetSpec::default();
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("entries must not be empty"), "{err}");
    }

    #[test]
    fn accepts_well_formed_minimal() {
        let s = MCPGPluginSetSpec {
            entries: vec![good_entry(
                "dev.mcpg.identity.workload",
                "identity-workload-1.2.3-linux-amd64",
            )],
            ..Default::default()
        };
        validate_spec(&fixture(s)).unwrap();
    }

    #[test]
    fn rejects_duplicate_ids() {
        let s = MCPGPluginSetSpec {
            entries: vec![
                good_entry("dev.mcpg.identity.workload", "p1"),
                good_entry("dev.mcpg.identity.workload", "p2"),
            ],
            ..Default::default()
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("duplicate plugin id"), "{err}");
    }

    #[test]
    fn rejects_id_without_dot() {
        let s = MCPGPluginSetSpec {
            entries: vec![good_entry("identityworkload", "p1")],
            ..Default::default()
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("reverse-DNS"), "{err}");
    }

    #[test]
    fn rejects_empty_plugin_ref() {
        let mut entry = good_entry("dev.mcpg.identity.workload", "p1");
        entry.plugin_ref.name = "  ".into();
        let s = MCPGPluginSetSpec {
            entries: vec![entry],
            ..Default::default()
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("pluginRef.name"), "{err}");
    }

    #[test]
    fn rejects_capability_grant_for_missing_plugin() {
        let mut grants = BTreeMap::new();
        grants.insert(
            "dev.mcpg.policy.cedar".into(),
            vec!["network_outbound".into()],
        );
        let s = MCPGPluginSetSpec {
            entries: vec![good_entry("dev.mcpg.identity.workload", "p1")],
            capability_grants: grants,
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("policy.cedar"), "{err}");
        assert!(err.contains("not in spec.entries"), "{err}");
    }

    #[test]
    fn rejects_empty_capability_grant_list() {
        let mut grants = BTreeMap::new();
        grants.insert("dev.mcpg.identity.workload".into(), vec![]);
        let s = MCPGPluginSetSpec {
            entries: vec![good_entry("dev.mcpg.identity.workload", "p1")],
            capability_grants: grants,
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn accepts_well_formed_grants() {
        let mut grants = BTreeMap::new();
        grants.insert(
            "dev.mcpg.identity.workload".into(),
            vec!["transport_listen".into()],
        );
        let s = MCPGPluginSetSpec {
            entries: vec![good_entry("dev.mcpg.identity.workload", "p1")],
            capability_grants: grants,
        };
        validate_spec(&fixture(s)).unwrap();
    }

    #[test]
    fn rejects_unknown_capability_kind() {
        // The plugin id exists in entries, so the only thing wrong is
        // the capability vocabulary — admission must reject it rather
        // than let the gateway crash-loop on the unknown grant.
        let mut grants = BTreeMap::new();
        grants.insert(
            "dev.mcpg.identity.workload".into(),
            vec!["cap.host.outbound_network".into()],
        );
        let s = MCPGPluginSetSpec {
            entries: vec![good_entry("dev.mcpg.identity.workload", "p1")],
            capability_grants: grants,
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("cap.host.outbound_network"), "{err}");
        assert!(err.contains("not a valid"), "{err}");
    }
}
