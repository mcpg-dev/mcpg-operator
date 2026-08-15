//! `autoscaling/v2.HorizontalPodAutoscaler` renderer.
//!
//! Rendered only when `spec.autoscaling.enabled` is true. When it is, the
//! Deployment drops its static `replicas` (see `deployment.rs`) so the HPA is
//! the sole owner of the replica count — otherwise the operator and the HPA
//! fight every reconcile. A CR without `autoscaling` (the default) renders
//! nothing, so non-autoscaled gateways are byte-identical to before.

use k8s_openapi::api::autoscaling::v2::{
    HorizontalPodAutoscaler, HorizontalPodAutoscalerSpec, MetricSpec,
};
use kube::core::ObjectMeta;

use mcpg_operator_api::v1alpha1::{HorizontalAutoscalerMetric, MCPGGateway};

use crate::templates::common::{child_name, owner_ref, standard_labels};

/// Build the HPA targeting the gateway Deployment, or `None` when autoscaling
/// is absent/disabled.
pub fn build_hpa(parent: &MCPGGateway) -> Option<HorizontalPodAutoscaler> {
    let hpa = parent.spec.autoscaling.as_ref()?;
    if !hpa.enabled {
        return None;
    }

    let min = hpa.min_replicas.unwrap_or(1).max(1);
    // max_replicas is required by the API; default to the static replica count
    // (or min) so an enabled-but-unbounded spec still produces a valid object.
    let max = hpa
        .max_replicas
        .unwrap_or_else(|| parent.spec.replicas.max(min))
        .max(min);

    let metrics: Vec<MetricSpec> = if hpa.metrics.is_empty() {
        vec![default_cpu_metric()]
    } else {
        hpa.metrics.iter().filter_map(metric_to_spec).collect()
    };

    // build_spec via JSON so the typed shape stays version-agnostic.
    let spec: HorizontalPodAutoscalerSpec = serde_json::from_value(serde_json::json!({
        "scaleTargetRef": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "name": child_name(parent, "gateway"),
        },
        "minReplicas": min,
        "maxReplicas": max,
        "metrics": metrics,
    }))
    .expect("HPA spec JSON is well-formed");

    Some(HorizontalPodAutoscaler {
        metadata: ObjectMeta {
            name: Some(child_name(parent, "gateway")),
            namespace: parent.metadata.namespace.clone(),
            labels: Some(standard_labels(parent)),
            owner_references: Some(vec![owner_ref(parent)]),
            ..Default::default()
        },
        spec: Some(spec),
        status: None,
    })
}

/// Translate a CRD metric (type + one of resource/pods/object/external as raw
/// JSON) into a typed `MetricSpec`. Drops a metric that fails to deserialise
/// rather than failing the whole render.
fn metric_to_spec(m: &HorizontalAutoscalerMetric) -> Option<MetricSpec> {
    let mut obj = serde_json::Map::new();
    obj.insert("type".to_owned(), serde_json::json!(m.r#type));
    if let Some(r) = &m.resource {
        obj.insert("resource".to_owned(), r.clone());
    }
    if let Some(p) = &m.pods {
        obj.insert("pods".to_owned(), p.clone());
    }
    if let Some(o) = &m.object {
        obj.insert("object".to_owned(), o.clone());
    }
    if let Some(e) = &m.external {
        obj.insert("external".to_owned(), e.clone());
    }
    serde_json::from_value(serde_json::Value::Object(obj)).ok()
}

/// Default to 80% average CPU utilisation when the spec lists no metrics — an
/// HPA with an empty metric list never scales.
fn default_cpu_metric() -> MetricSpec {
    serde_json::from_value(serde_json::json!({
        "type": "Resource",
        "resource": {
            "name": "cpu",
            "target": { "type": "Utilization", "averageUtilization": 80 }
        }
    }))
    .expect("default CPU metric JSON is well-formed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_operator_api::v1alpha1::{HorizontalAutoscaler, MCPGGatewaySpec};

    fn gw(autoscaling: Option<HorizontalAutoscaler>) -> MCPGGateway {
        let mut g = MCPGGateway::new(
            "edge-1",
            MCPGGatewaySpec {
                replicas: 2,
                autoscaling,
                ..Default::default()
            },
        );
        g.metadata.namespace = Some("tenant-acme".into());
        g
    }

    #[test]
    fn none_without_autoscaling() {
        assert!(build_hpa(&gw(None)).is_none());
        assert!(
            build_hpa(&gw(Some(HorizontalAutoscaler {
                enabled: false,
                ..Default::default()
            })))
            .is_none()
        );
    }

    #[test]
    fn renders_bounds_target_and_default_metric() {
        let hpa = build_hpa(&gw(Some(HorizontalAutoscaler {
            enabled: true,
            min_replicas: Some(3),
            max_replicas: Some(10),
            metrics: vec![],
        })))
        .unwrap();
        assert_eq!(hpa.metadata.name.as_deref(), Some("edge-1-gateway"));
        let spec = hpa.spec.unwrap();
        assert_eq!(spec.min_replicas, Some(3));
        assert_eq!(spec.max_replicas, 10);
        assert_eq!(spec.scale_target_ref.name, "edge-1-gateway");
        assert_eq!(spec.scale_target_ref.kind, "Deployment");
        // Default CPU metric injected when none provided.
        assert_eq!(spec.metrics.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn max_never_below_min() {
        // max omitted, replicas=2, min=5 → max clamps up to 5.
        let hpa = build_hpa(&gw(Some(HorizontalAutoscaler {
            enabled: true,
            min_replicas: Some(5),
            max_replicas: None,
            metrics: vec![],
        })))
        .unwrap();
        let spec = hpa.spec.unwrap();
        assert_eq!(spec.min_replicas, Some(5));
        assert!(spec.max_replicas >= 5);
    }
}
