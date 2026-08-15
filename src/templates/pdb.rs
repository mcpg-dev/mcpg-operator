//! `policy/v1.PodDisruptionBudget` renderer.
//!
//! Rendered only when `spec.podDisruptionBudget.enabled` is true, selecting the
//! gateway's pods. Both thresholds are int-or-string (`2` or `"50%"`); if the
//! spec sets neither, defaults to `minAvailable: 1`. A CR without the field
//! renders nothing.

use k8s_openapi::api::policy::v1::{PodDisruptionBudget, PodDisruptionBudgetSpec as K8sPdbSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::core::ObjectMeta;

use mcpg_operator_api::v1alpha1::MCPGGateway;

use crate::templates::common::{child_name, owner_ref, selector_labels, standard_labels};

/// Build the PDB for the gateway, or `None` when absent/disabled.
pub fn build_pdb(parent: &MCPGGateway) -> Option<PodDisruptionBudget> {
    let pdb = parent.spec.pod_disruption_budget.as_ref()?;
    if !pdb.enabled {
        return None;
    }

    let mut min_available = pdb.min_available.as_ref().and_then(value_to_intorstring);
    let max_unavailable = pdb.max_unavailable.as_ref().and_then(value_to_intorstring);
    // A PDB with neither bound is meaningless; default to keeping ≥1 pod up.
    if min_available.is_none() && max_unavailable.is_none() {
        min_available = Some(IntOrString::Int(1));
    }

    Some(PodDisruptionBudget {
        metadata: ObjectMeta {
            name: Some(child_name(parent, "gateway")),
            namespace: parent.metadata.namespace.clone(),
            labels: Some(standard_labels(parent)),
            owner_references: Some(vec![owner_ref(parent)]),
            ..Default::default()
        },
        spec: Some(K8sPdbSpec {
            min_available,
            max_unavailable,
            selector: Some(LabelSelector {
                match_labels: Some(selector_labels(parent)),
                ..Default::default()
            }),
            ..Default::default()
        }),
        status: None,
    })
}

/// CRD int-or-string JSON (`2` or `"50%"`) → `IntOrString`.
fn value_to_intorstring(v: &serde_json::Value) -> Option<IntOrString> {
    if let Some(i) = v.as_i64() {
        Some(IntOrString::Int(i as i32))
    } else {
        v.as_str().map(|s| IntOrString::String(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_operator_api::v1alpha1::{MCPGGatewaySpec, PodDisruptionBudgetSpec};

    fn gw(pdb: Option<PodDisruptionBudgetSpec>) -> MCPGGateway {
        let mut g = MCPGGateway::new(
            "edge-1",
            MCPGGatewaySpec {
                replicas: 3,
                pod_disruption_budget: pdb,
                ..Default::default()
            },
        );
        g.metadata.namespace = Some("tenant-acme".into());
        g
    }

    #[test]
    fn none_without_pdb() {
        assert!(build_pdb(&gw(None)).is_none());
        assert!(
            build_pdb(&gw(Some(PodDisruptionBudgetSpec {
                enabled: false,
                ..Default::default()
            })))
            .is_none()
        );
    }

    #[test]
    fn percentage_min_available_passes_through() {
        let pdb = build_pdb(&gw(Some(PodDisruptionBudgetSpec {
            enabled: true,
            min_available: Some(serde_json::json!("50%")),
            max_unavailable: None,
        })))
        .unwrap();
        let spec = pdb.spec.unwrap();
        assert_eq!(spec.min_available, Some(IntOrString::String("50%".into())));
        assert_eq!(
            spec.selector.unwrap().match_labels.unwrap()["app.kubernetes.io/instance"],
            "edge-1"
        );
    }

    #[test]
    fn defaults_to_min_available_one() {
        let pdb = build_pdb(&gw(Some(PodDisruptionBudgetSpec {
            enabled: true,
            min_available: None,
            max_unavailable: None,
        })))
        .unwrap();
        assert_eq!(pdb.spec.unwrap().min_available, Some(IntOrString::Int(1)));
    }

    #[test]
    fn integer_max_unavailable() {
        let pdb = build_pdb(&gw(Some(PodDisruptionBudgetSpec {
            enabled: true,
            min_available: None,
            max_unavailable: Some(serde_json::json!(1)),
        })))
        .unwrap();
        let spec = pdb.spec.unwrap();
        assert_eq!(spec.max_unavailable, Some(IntOrString::Int(1)));
        assert_eq!(spec.min_available, None);
    }
}
