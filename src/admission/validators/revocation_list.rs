//! Validating webhook for `MCPGRevocationList`.
//!
//! Cross-field rules:
//!
//! - `version` must equal `1` (only known schema version).
//! - Every `artifactSha256` must be exactly 64 lowercase hex chars
//!   (the operator + gateway compare lower-cased).
//! - Every `reason` must be non-empty (operators surface it in
//!   load-time error + audit events; empty reasons defeat the
//!   audit trail).
//! - No duplicate `artifactSha256` entries (operators consolidate
//!   into one entry per artefact rather than shipping
//!   conflicting reasons).

use std::collections::BTreeSet;

use axum::Json;
use axum::extract::State;
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use mcpg_operator_api::v1alpha1::MCPGRevocationList;
use tracing::warn;

use crate::admission::server::AdmissionState;

const SUPPORTED_VERSION: u8 = 1;
const SHA256_HEX_LEN: usize = 64;

pub async fn validate(
    State(_state): State<AdmissionState>,
    Json(review): Json<AdmissionReview<MCPGRevocationList>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let req: AdmissionRequest<MCPGRevocationList> = match review.try_into() {
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

    let response = match validate_spec(obj) {
        Ok(()) => response,
        Err(reason) => response.deny(reason),
    };

    Json(response.into_review())
}

fn validate_spec(obj: &MCPGRevocationList) -> Result<(), String> {
    let spec = &obj.spec;

    if spec.version != SUPPORTED_VERSION {
        return Err(format!(
            "spec.version={} but only version=1 is supported",
            spec.version
        ));
    }

    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (i, entry) in spec.revocations.iter().enumerate() {
        let sha = entry.artifact_sha256.trim();
        if sha.len() != SHA256_HEX_LEN {
            return Err(format!(
                "spec.revocations[{i}].artifactSha256 must be exactly {SHA256_HEX_LEN} \
                 hex characters (got {})",
                sha.len()
            ));
        }
        if !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "spec.revocations[{i}].artifactSha256 must be hex (got `{sha}`)"
            ));
        }
        let lc = sha.to_ascii_lowercase();
        if !seen.insert(lc.clone()) {
            return Err(format!(
                "duplicate artifactSha256 `{lc}` at index {i} (operators consolidate \
                 into a single entry per artefact)"
            ));
        }
        if entry.reason.trim().is_empty() {
            return Err(format!("spec.revocations[{i}].reason must not be empty"));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::{MCPGRevocationListSpec, RevocationEntry};

    fn fixture(spec: MCPGRevocationListSpec) -> MCPGRevocationList {
        MCPGRevocationList {
            metadata: ObjectMeta {
                name: Some("cluster-default".into()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn good_entry() -> RevocationEntry {
        RevocationEntry {
            artifact_sha256: "abcdef0123456789".repeat(4),
            reason: "test reason".into(),
            revoked_at: None,
        }
    }

    #[test]
    fn rejects_unknown_version() {
        let s = MCPGRevocationListSpec {
            version: 99,
            issued_at: None,
            revocations: vec![],
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("version"), "{err}");
    }

    #[test]
    fn accepts_v1_with_zero_entries() {
        let s = MCPGRevocationListSpec {
            version: 1,
            issued_at: None,
            revocations: vec![],
        };
        validate_spec(&fixture(s)).unwrap();
    }

    #[test]
    fn rejects_short_sha256() {
        let s = MCPGRevocationListSpec {
            version: 1,
            issued_at: None,
            revocations: vec![RevocationEntry {
                artifact_sha256: "abcd".into(),
                reason: "x".into(),
                revoked_at: None,
            }],
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("64 hex"), "{err}");
    }

    #[test]
    fn rejects_non_hex_sha256() {
        let s = MCPGRevocationListSpec {
            version: 1,
            issued_at: None,
            revocations: vec![RevocationEntry {
                artifact_sha256: "Z".repeat(64),
                reason: "x".into(),
                revoked_at: None,
            }],
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("hex"), "{err}");
    }

    #[test]
    fn accepts_uppercase_hex() {
        let s = MCPGRevocationListSpec {
            version: 1,
            issued_at: None,
            revocations: vec![RevocationEntry {
                artifact_sha256: "ABCDEF0123456789".repeat(4),
                reason: "test".into(),
                revoked_at: None,
            }],
        };
        validate_spec(&fixture(s)).unwrap();
    }

    #[test]
    fn rejects_duplicate_entries_case_insensitive() {
        let s = MCPGRevocationListSpec {
            version: 1,
            issued_at: None,
            revocations: vec![
                good_entry(),
                RevocationEntry {
                    artifact_sha256: "ABCDEF0123456789".repeat(4),
                    reason: "duplicate".into(),
                    revoked_at: None,
                },
            ],
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("duplicate"), "{err}");
    }

    #[test]
    fn rejects_empty_reason() {
        let s = MCPGRevocationListSpec {
            version: 1,
            issued_at: None,
            revocations: vec![RevocationEntry {
                artifact_sha256: good_entry().artifact_sha256,
                reason: "  ".into(),
                revoked_at: None,
            }],
        };
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("reason"), "{err}");
    }

    #[test]
    fn accepts_well_formed_full_spec() {
        let s = MCPGRevocationListSpec {
            version: 1,
            issued_at: None,
            revocations: vec![good_entry()],
        };
        validate_spec(&fixture(s)).unwrap();
    }
}
