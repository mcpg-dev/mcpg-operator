//! Shared helpers for every template renderer: owner refs,
//! standard labels, name conventions.

use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::Resource;
use mcpg_operator_api::v1alpha1::MCPGGateway;

use crate::labels;

/// Owner reference pointing back to the parent CRD. Used on every
/// child resource so K8s GC propagates parent deletion.
pub fn owner_ref(parent: &MCPGGateway) -> OwnerReference {
    OwnerReference {
        api_version: MCPGGateway::api_version(&()).to_string(),
        kind: MCPGGateway::kind(&()).to_string(),
        name: parent.metadata.name.clone().unwrap_or_default(),
        uid: parent.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// Standard labels every operator-rendered resource carries.
/// These drive cross-resource lookups (e.g. ServiceMonitor
/// selecting Service by `app.kubernetes.io/instance`).
pub fn standard_labels(parent: &MCPGGateway) -> BTreeMap<String, String> {
    let name = parent.metadata.name.clone().unwrap_or_default();
    let mut labels = BTreeMap::new();
    labels.insert(labels::APP_NAME.into(), "mcpg-gateway".into());
    labels.insert(labels::APP_INSTANCE.into(), name.clone());
    labels.insert(labels::APP_COMPONENT.into(), "gateway".into());
    labels.insert(labels::APP_PART_OF.into(), "mcpg".into());
    labels.insert(labels::APP_MANAGED_BY.into(), "mcpg-operator".into());
    if let Some(tag) = parent.spec.image.tag.as_deref().filter(|t| !t.is_empty()) {
        labels.insert(labels::APP_VERSION.into(), tag.to_owned());
    }
    labels.insert(labels::MCPG_GATEWAY.into(), name);
    labels
}

/// The selector subset of `standard_labels` — the labels K8s
/// matchers use to look up Pods. Stable across image-tag bumps
/// (so rolling upgrades don't break the selector).
pub fn selector_labels(parent: &MCPGGateway) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    let name = parent.metadata.name.clone().unwrap_or_default();
    labels.insert(labels::APP_NAME.into(), "mcpg-gateway".into());
    labels.insert(labels::APP_INSTANCE.into(), name);
    labels
}

/// Conventional names for child resources.
///
/// Child resource names must be valid DNS labels, and the Service name
/// specifically must be a DNS-1035 label — its FIRST character must be
/// alphabetic. The canonical instance_uid the provisioner uses as the CR name
/// is a UUIDv7, which is digit-leading: a valid DNS-1123 label
/// (Deployment/ConfigMap/SA accept it) but an INVALID Service name, so the
/// Service apply 422s and the whole reconcile fails before any pod renders.
/// Prefix a stable alpha token when the name isn't already alpha-leading.
/// Applied here (not just on the Service) so every child — including the
/// HTTPRoute backendRef, which also calls `child_name(parent, "")` — resolves
/// to the SAME Service name.
pub fn child_name(parent: &MCPGGateway, suffix: &str) -> String {
    let raw = parent.metadata.name.clone().unwrap_or_default();
    let base = if raw.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
        raw
    } else {
        format!("mcpg-{raw}")
    };
    if suffix.is_empty() {
        base
    } else {
        format!("{base}-{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::MCPGGatewaySpec;

    fn fixture() -> MCPGGateway {
        MCPGGateway {
            metadata: ObjectMeta {
                name: Some("payments-gateway".to_owned()),
                namespace: Some("payments".to_owned()),
                uid: Some("uid-123".to_owned()),
                ..Default::default()
            },
            spec: MCPGGatewaySpec::default(),
            status: None,
        }
    }

    #[test]
    fn owner_ref_points_to_parent() {
        let p = fixture();
        let oref = owner_ref(&p);
        assert_eq!(oref.kind, "MCPGGateway");
        assert_eq!(oref.api_version, "mcpg.dev/v1alpha1");
        assert_eq!(oref.name, "payments-gateway");
        assert_eq!(oref.uid, "uid-123");
        assert_eq!(oref.controller, Some(true));
        assert_eq!(oref.block_owner_deletion, Some(true));
    }

    #[test]
    fn standard_labels_include_kubernetes_recommended() {
        let p = fixture();
        let labels = standard_labels(&p);
        assert_eq!(labels.get(labels::APP_NAME).unwrap(), "mcpg-gateway");
        assert_eq!(
            labels.get(labels::APP_INSTANCE).unwrap(),
            "payments-gateway"
        );
        assert_eq!(labels.get(labels::APP_COMPONENT).unwrap(), "gateway");
        assert_eq!(labels.get(labels::APP_PART_OF).unwrap(), "mcpg");
        assert_eq!(labels.get(labels::APP_MANAGED_BY).unwrap(), "mcpg-operator");
    }

    #[test]
    fn selector_labels_are_subset_of_standard() {
        let p = fixture();
        let std = standard_labels(&p);
        let sel = selector_labels(&p);
        for (k, v) in &sel {
            assert_eq!(
                std.get(k),
                Some(v),
                "selector label {k} must match standard"
            );
        }
    }

    #[test]
    fn child_name_concatenates_with_suffix() {
        let p = fixture();
        assert_eq!(child_name(&p, ""), "payments-gateway");
        assert_eq!(child_name(&p, "tls"), "payments-gateway-tls");
    }

    #[test]
    fn child_name_prefixes_digit_leading_uuid_for_dns1035() {
        // The provisioner names the CR after the canonical instance_uid
        // (UUIDv7, digit-leading). The bare name is an invalid Service name
        // (DNS-1035 requires a leading letter); prefix it so the Service +
        // its HTTPRoute backendRef both resolve to the same valid name.
        let mut p = fixture();
        p.metadata.name = Some("019ea94d-09b6-76a0-8d75-2b174429b90e".to_owned());
        let svc = child_name(&p, "");
        assert_eq!(svc, "mcpg-019ea94d-09b6-76a0-8d75-2b174429b90e");
        assert!(
            svc.chars().next().unwrap().is_ascii_alphabetic(),
            "Service name must be DNS-1035 (leading alphabetic)"
        );
        assert!(svc.len() <= 63, "must fit a DNS label");
        // Alpha-leading names are untouched (self-host / hand-named CRs).
        assert_eq!(child_name(&fixture(), ""), "payments-gateway");
    }
}
