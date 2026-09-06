//! `policy/v1.PodDisruptionBudget` renderer.
//!
//! Rendered when `spec.podDisruptionBudget.enabled` is true, selecting the
//! gateway's pods. Both thresholds are int-or-string (`2` or `"50%"`); if the
//! spec sets neither, defaults to `minAvailable: 1`. A CR without the field
//! still gets a default budget (`maxUnavailable: 1`) whenever its replica
//! ceiling exceeds 1 — a clustered gateway must not lose several replicas to
//! one voluntary disruption; `enabled: false` opts out and renders nothing.

use k8s_openapi::api::policy::v1::{PodDisruptionBudget, PodDisruptionBudgetSpec as K8sPdbSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::core::ObjectMeta;

use mcpg_operator_api::v1alpha1::MCPGGateway;

use crate::templates::common::{child_name, owner_ref, selector_labels, standard_labels};

/// Build the PDB for the gateway. `None` when the spec disables it, or when
/// the field is absent on a single-replica gateway.
pub fn build_pdb(parent: &MCPGGateway) -> Option<PodDisruptionBudget> {
    let (mut min_available, max_unavailable) = match parent.spec.pod_disruption_budget.as_ref() {
        // Explicit opt-out wins over the multi-replica default.
        Some(pdb) if !pdb.enabled => return None,
        Some(pdb) => (
            pdb.min_available.as_ref().and_then(value_to_intorstring),
            pdb.max_unavailable.as_ref().and_then(value_to_intorstring),
        ),
        // Default budget for multi-replica gateways: voluntary disruptions
        // (drains, upgrades) evict at most one replica at a time.
        None if parent.spec.effective_replica_ceiling().0 > 1 => (None, Some(IntOrString::Int(1))),
        None => return None,
    };
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

    fn gw_with_replicas(replicas: i32, pdb: Option<PodDisruptionBudgetSpec>) -> MCPGGateway {
        let mut g = MCPGGateway::new(
            "edge-1",
            MCPGGatewaySpec {
                replicas,
                pod_disruption_budget: pdb,
                ..Default::default()
            },
        );
        g.metadata.namespace = Some("tenant-acme".into());
        g
    }

    fn gw(pdb: Option<PodDisruptionBudgetSpec>) -> MCPGGateway {
        gw_with_replicas(3, pdb)
    }

    #[test]
    fn none_for_single_replica_without_pdb_field() {
        assert!(build_pdb(&gw_with_replicas(1, None)).is_none());
    }

    #[test]
    fn explicit_disabled_wins_over_the_multi_replica_default() {
        assert!(
            build_pdb(&gw(Some(PodDisruptionBudgetSpec {
                enabled: false,
                ..Default::default()
            })))
            .is_none()
        );
    }

    #[test]
    fn multi_replica_defaults_to_max_unavailable_one() {
        let pdb = build_pdb(&gw(None)).expect("default PDB for replicas > 1");
        let spec = pdb.spec.unwrap();
        assert_eq!(spec.max_unavailable, Some(IntOrString::Int(1)));
        assert_eq!(spec.min_available, None);
        assert_eq!(
            spec.selector.unwrap().match_labels.unwrap()["app.kubernetes.io/instance"],
            "edge-1"
        );
    }

    #[test]
    fn hpa_ceiling_above_one_also_gets_the_default() {
        use mcpg_operator_api::v1alpha1::HorizontalAutoscaler;
        let mut g = gw_with_replicas(1, None);
        g.spec.autoscaling = Some(HorizontalAutoscaler {
            enabled: true,
            min_replicas: Some(1),
            max_replicas: Some(4),
            ..Default::default()
        });
        let pdb = build_pdb(&g).expect("default PDB for an HPA ceiling > 1");
        assert_eq!(pdb.spec.unwrap().max_unavailable, Some(IntOrString::Int(1)));
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
