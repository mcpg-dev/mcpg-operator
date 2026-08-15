//! ServiceAccount template — one SA per gateway. Workload
//! identity annotations (IRSA / GKE WI / Azure WI) attach here
//! so the gateway pods inherit them via
//! `automountServiceAccountToken: true`.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::ServiceAccount;
use kube::core::ObjectMeta;
use mcpg_operator_api::v1alpha1::MCPGGateway;

use crate::templates::common::{child_name, owner_ref, standard_labels};

pub fn build_service_account(parent: &MCPGGateway) -> ServiceAccount {
    let mut annotations = BTreeMap::new();

    // Workload identity provider annotations.
    if let Some(wi) = &parent.spec.workload_identity {
        if let Some(aws) = &wi.aws {
            annotations.insert(
                "eks.amazonaws.com/role-arn".to_owned(),
                aws.iam_role_arn.clone(),
            );
        }
        if let Some(gcp) = &wi.gcp {
            annotations.insert(
                "iam.gke.io/gcp-service-account".to_owned(),
                gcp.google_service_account.clone(),
            );
        }
        if let Some(azure) = &wi.azure {
            annotations.insert(
                "azure.workload.identity/client-id".to_owned(),
                azure.client_id.clone(),
            );
        }
        if let Some(spiffe) = &wi.spiffe {
            // Operational annotation — SPIRE agent can't read this
            // directly, but the gateway pod's spiffe-csi sidecar
            // (if present) does.
            annotations.insert(
                "mcpg.dev/spiffe-trust-domain".to_owned(),
                spiffe.trust_domain.clone(),
            );
            annotations.insert("mcpg.dev/spiffe-svid".to_owned(), spiffe.svid.clone());
        }
    }

    let image_pull_secrets = if parent.spec.image_pull_secrets.is_empty() {
        None
    } else {
        Some(
            parent
                .spec
                .image_pull_secrets
                .iter()
                .map(|r| k8s_openapi::api::core::v1::LocalObjectReference {
                    name: r.name.clone(),
                })
                .collect(),
        )
    };

    ServiceAccount {
        metadata: ObjectMeta {
            name: Some(child_name(parent, "gateway")),
            namespace: parent.metadata.namespace.clone(),
            labels: Some(standard_labels(parent)),
            annotations: if annotations.is_empty() {
                None
            } else {
                Some(annotations)
            },
            owner_references: Some(vec![owner_ref(parent)]),
            ..Default::default()
        },
        // We don't auto-mount the SA token into the gateway pod
        // itself — the gateway doesn't talk to kube-apiserver.
        // Workload-identity providers project their own token
        // separately.
        automount_service_account_token: Some(false),
        image_pull_secrets,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::{
        AwsWorkloadIdentity, AzureWorkloadIdentity, GatewayWorkloadIdentity, GcpWorkloadIdentity,
        LocalObjectReference, MCPGGatewaySpec, SpiffeWorkloadIdentity,
    };

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
    fn name_is_gateway_suffixed() {
        let sa = build_service_account(&fixture(MCPGGatewaySpec::default()));
        assert_eq!(
            sa.metadata.name.as_deref(),
            Some("payments-gateway-gateway")
        );
    }

    #[test]
    fn aws_irsa_annotation_present_when_configured() {
        let sa = build_service_account(&fixture(MCPGGatewaySpec {
            workload_identity: Some(GatewayWorkloadIdentity {
                aws: Some(AwsWorkloadIdentity {
                    iam_role_arn: "arn:aws:iam::123:role/r".into(),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }));
        let annotations = sa.metadata.annotations.unwrap();
        assert_eq!(
            annotations.get("eks.amazonaws.com/role-arn").unwrap(),
            "arn:aws:iam::123:role/r"
        );
    }

    #[test]
    fn gcp_workload_identity_annotation() {
        let sa = build_service_account(&fixture(MCPGGatewaySpec {
            workload_identity: Some(GatewayWorkloadIdentity {
                gcp: Some(GcpWorkloadIdentity {
                    google_service_account: "sa@proj.iam.gserviceaccount.com".into(),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }));
        let annotations = sa.metadata.annotations.unwrap();
        assert_eq!(
            annotations.get("iam.gke.io/gcp-service-account").unwrap(),
            "sa@proj.iam.gserviceaccount.com"
        );
    }

    #[test]
    fn azure_workload_identity_annotation() {
        let sa = build_service_account(&fixture(MCPGGatewaySpec {
            workload_identity: Some(GatewayWorkloadIdentity {
                azure: Some(AzureWorkloadIdentity {
                    client_id: "abc-123".into(),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }));
        let annotations = sa.metadata.annotations.unwrap();
        assert_eq!(
            annotations
                .get("azure.workload.identity/client-id")
                .unwrap(),
            "abc-123"
        );
    }

    #[test]
    fn spiffe_emits_operator_internal_annotations() {
        let sa = build_service_account(&fixture(MCPGGatewaySpec {
            workload_identity: Some(GatewayWorkloadIdentity {
                spiffe: Some(SpiffeWorkloadIdentity {
                    trust_domain: "payments.example.com".into(),
                    svid: "spiffe://payments.example.com/sa/orders".into(),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }));
        let annotations = sa.metadata.annotations.unwrap();
        assert_eq!(
            annotations.get("mcpg.dev/spiffe-trust-domain").unwrap(),
            "payments.example.com"
        );
        assert_eq!(
            annotations.get("mcpg.dev/spiffe-svid").unwrap(),
            "spiffe://payments.example.com/sa/orders"
        );
    }

    #[test]
    fn no_workload_identity_omits_annotations() {
        let sa = build_service_account(&fixture(MCPGGatewaySpec::default()));
        assert!(sa.metadata.annotations.is_none());
    }

    #[test]
    fn image_pull_secrets_propagated() {
        let sa = build_service_account(&fixture(MCPGGatewaySpec {
            image_pull_secrets: vec![LocalObjectReference {
                name: "ghcr-pull".into(),
            }],
            ..Default::default()
        }));
        let pulls = sa.image_pull_secrets.unwrap();
        assert_eq!(pulls.len(), 1);
        assert_eq!(pulls[0].name, "ghcr-pull");
    }

    #[test]
    fn token_automount_disabled() {
        let sa = build_service_account(&fixture(MCPGGatewaySpec::default()));
        assert_eq!(sa.automount_service_account_token, Some(false));
    }
}
