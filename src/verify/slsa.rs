//! SLSA L3 provenance verification.
//!
//! Given an `MCPGPlugin.spec.trust.slsa_provenance` reference,
//! this module:
//!
//! 1. Reads the named ConfigMap from the operator namespace.
//! 2. Parses the `provenance.intoto.jsonl` data key — one
//!    DSSE-wrapped in-toto attestation per line.
//! 3. Decodes the inner statement (base64-decoded payload).
//! 4. Verifies the statement satisfies the operator's policy:
//!    * `predicateType` is the SLSA Provenance v1 or v0.2 URI.
//!    * `subject[*].digest.sha256` includes the plugin's
//!      verified artefact sha256 (i.e. the very bytes the plugin
//!      controller just pulled — this is what binds the
//!      provenance to *this* release, not a sibling).
//!    * `predicate.buildDefinition.externalParameters.source.repository`
//!      (SLSA v1) or
//!      `predicate.invocation.configSource.uri` (SLSA v0.2)
//!      matches the configured `source_uri`.
//!    * The corresponding source `ref` / tag matches
//!      `source_tag`.
//!
//! ### Trust model + signature note
//!
//! Today the operator does NOT verify the DSSE envelope's
//! cryptographic signature. The trust gate is RBAC: the
//! provenance ConfigMap MUST live in the operator namespace
//! (`mcpg-system` by default), and the operator's ClusterRole
//! grants Secret/ConfigMap write access only to that namespace's
//! Secrets path. Operators who need cryptographic gating MUST
//! restrict ConfigMap write access in the operator namespace
//! to the build pipeline's CI identity.
//!
//! Closing the signature loop with cosign-style attestation
//! signatures (sigstore-rs `trusted_attestation_layers`) lands
//! in a follow-up commit — it requires the SLSA build pipeline
//! to publish attestations via the OCI registry rather than via
//! a ConfigMap, which is a deployment workflow change.

use serde::Deserialize;

use mcpg_operator_api::v1alpha1::SlsaProvenance;

/// SLSA Provenance predicate types we accept. The operator
/// honours both `v0.2` and `v1` because SLSA tooling is in flux
/// — newer build systems emit `v1` while older fleets still
/// produce `v0.2`. Anything else (including `v0.1`) is rejected.
const SLSA_V1_PREDICATE: &str = "https://slsa.dev/provenance/v1";
const SLSA_V02_PREDICATE: &str = "https://slsa.dev/provenance/v0.2";

#[derive(Debug, thiserror::Error)]
pub enum SlsaError {
    #[error(
        "provenance ConfigMap data key `{key}` missing or empty (the build pipeline must populate `data.{key}` with the .intoto.jsonl bytes)"
    )]
    PayloadMissing { key: String },
    #[error("provenance JSONL is empty (no DSSE envelopes to verify)")]
    EnvelopeEmpty,
    #[error("provenance line {line} is not valid JSON: {source}")]
    EnvelopeJson {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("provenance line {line} payload base64 decode failed: {source}")]
    PayloadBase64 {
        line: usize,
        #[source]
        source: base64::DecodeError,
    },
    #[error("provenance line {line} payload is not a valid in-toto Statement: {source}")]
    StatementJson {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error(
        "no in-toto Statement matched the operator's policy: {0} attestations parsed, {1} matched the SLSA predicate type, but none satisfied subject + source URI + source tag (configured: source_uri=`{2}`, source_tag=`{3}`)"
    )]
    NoMatchingStatement(usize, usize, String, String),
}

/// Successful SLSA verification result — surfaced on
/// `MCPGPluginStatus.slsa_verified`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlsaVerifyResult {
    pub envelopes_total: usize,
    pub matched_predicate_type: &'static str,
}

/// In-toto Statement (a.k.a. the inner payload of a DSSE
/// envelope). We only deserialise the fields we match on.
#[derive(Debug, Deserialize)]
struct InTotoStatement {
    #[serde(rename = "predicateType")]
    predicate_type: String,
    subject: Vec<Subject>,
    predicate: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct Subject {
    #[serde(default)]
    digest: Digest,
}

#[derive(Debug, Default, Deserialize)]
struct Digest {
    #[serde(default)]
    sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DsseEnvelope {
    payload: String,
    // DSSE envelope also carries `payloadType` + `signatures`;
    // we don't use them today (see module docs on the trust
    // model). Keeping the deserialiser tolerant of extra
    // fields for forward-compat.
    #[serde(rename = "payloadType")]
    #[serde(default)]
    _payload_type: Option<String>,
}

/// Verify the SLSA provenance JSONL against the configured
/// policy. `artefact_sha256` is the verified plugin bytes' hash
/// (lower-case hex); `policy` is the spec's
/// `MCPGPlugin.spec.trust.slsa_provenance`.
pub fn verify_slsa_provenance(
    jsonl: &str,
    artefact_sha256: &str,
    policy: &SlsaProvenance,
) -> Result<SlsaVerifyResult, SlsaError> {
    if jsonl.trim().is_empty() {
        return Err(SlsaError::EnvelopeEmpty);
    }

    let mut envelopes_total = 0usize;
    let mut predicate_matched = 0usize;
    let mut last_matched_predicate: Option<&'static str> = None;

    for (i, line) in jsonl.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        envelopes_total += 1;

        let envelope: DsseEnvelope =
            serde_json::from_str(line).map_err(|source| SlsaError::EnvelopeJson {
                line: i + 1,
                source,
            })?;
        let payload_bytes =
            base64_decode(&envelope.payload).map_err(|source| SlsaError::PayloadBase64 {
                line: i + 1,
                source,
            })?;
        let stmt: InTotoStatement =
            serde_json::from_slice(&payload_bytes).map_err(|source| SlsaError::StatementJson {
                line: i + 1,
                source,
            })?;

        let predicate_match = match stmt.predicate_type.as_str() {
            SLSA_V1_PREDICATE => Some(SLSA_V1_PREDICATE),
            SLSA_V02_PREDICATE => Some(SLSA_V02_PREDICATE),
            _ => None,
        };
        let Some(matched_predicate) = predicate_match else {
            continue;
        };
        predicate_matched += 1;

        if !subject_matches(&stmt.subject, artefact_sha256) {
            continue;
        }
        if !predicate_source_matches(matched_predicate, &stmt.predicate, policy) {
            continue;
        }

        last_matched_predicate = Some(matched_predicate);
        break;
    }

    if let Some(p) = last_matched_predicate {
        Ok(SlsaVerifyResult {
            envelopes_total,
            matched_predicate_type: p,
        })
    } else {
        Err(SlsaError::NoMatchingStatement(
            envelopes_total,
            predicate_matched,
            policy.source_uri.clone(),
            policy.source_tag.clone(),
        ))
    }
}

fn subject_matches(subjects: &[Subject], artefact_sha: &str) -> bool {
    subjects.iter().any(|s| {
        s.digest
            .sha256
            .as_deref()
            .is_some_and(|h| h.eq_ignore_ascii_case(artefact_sha))
    })
}

/// Drill into the predicate JSON looking for the source URI +
/// source ref. SLSA v1 and v0.2 disagree on the path — we walk
/// both shapes and accept whichever matches.
fn predicate_source_matches(
    predicate_type: &str,
    predicate: &serde_json::Value,
    policy: &SlsaProvenance,
) -> bool {
    match predicate_type {
        SLSA_V1_PREDICATE => slsa_v1_source_matches(predicate, policy),
        SLSA_V02_PREDICATE => slsa_v02_source_matches(predicate, policy),
        _ => false,
    }
}

fn slsa_v1_source_matches(predicate: &serde_json::Value, policy: &SlsaProvenance) -> bool {
    // SLSA v1 path:
    //   predicate.buildDefinition.externalParameters.source.repository
    //   predicate.buildDefinition.externalParameters.source.ref
    let Some(source) = predicate
        .get("buildDefinition")
        .and_then(|b| b.get("externalParameters"))
        .and_then(|e| e.get("source"))
    else {
        return false;
    };
    let repo = source.get("repository").and_then(|r| r.as_str());
    let r#ref = source
        .get("ref")
        .and_then(|r| r.as_str())
        .or_else(|| source.get("digest").and_then(|d| d.as_str()));
    repo == Some(policy.source_uri.as_str()) && r#ref == Some(policy.source_tag.as_str())
}

fn slsa_v02_source_matches(predicate: &serde_json::Value, policy: &SlsaProvenance) -> bool {
    // SLSA v0.2 path:
    //   predicate.invocation.configSource.uri
    //   predicate.invocation.configSource.entryPoint  (or .ref)
    let Some(cfg) = predicate
        .get("invocation")
        .and_then(|i| i.get("configSource"))
    else {
        return false;
    };
    let uri = cfg.get("uri").and_then(|u| u.as_str());
    let r#ref = cfg
        .get("entryPoint")
        .and_then(|e| e.as_str())
        .or_else(|| cfg.get("ref").and_then(|r| r.as_str()));
    uri == Some(policy.source_uri.as_str()) && r#ref == Some(policy.source_tag.as_str())
}

fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn envelope_with_payload(payload: &serde_json::Value) -> String {
        let bytes = serde_json::to_vec(payload).unwrap();
        format!(
            r#"{{"payload":"{}","payloadType":"application/vnd.in-toto+json","signatures":[]}}"#,
            b64(&bytes)
        )
    }

    fn slsa_v1_payload(artefact_sha: &str, repo: &str, r#ref: &str) -> serde_json::Value {
        serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": SLSA_V1_PREDICATE,
            "subject": [{
                "name": "plugin.so",
                "digest": {"sha256": artefact_sha},
            }],
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "source": {
                            "repository": repo,
                            "ref": r#ref,
                        }
                    }
                },
                "runDetails": {}
            }
        })
    }

    fn slsa_v02_payload(artefact_sha: &str, uri: &str, entry: &str) -> serde_json::Value {
        serde_json::json!({
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": SLSA_V02_PREDICATE,
            "subject": [{
                "name": "plugin.so",
                "digest": {"sha256": artefact_sha},
            }],
            "predicate": {
                "invocation": {
                    "configSource": {
                        "uri": uri,
                        "entryPoint": entry,
                    }
                }
            }
        })
    }

    fn policy(source_uri: &str, source_tag: &str) -> SlsaProvenance {
        SlsaProvenance {
            config_map_name: "test-cm".into(),
            source_uri: source_uri.into(),
            source_tag: source_tag.into(),
        }
    }

    #[test]
    fn verify_slsa_accepts_matching_v1_envelope() {
        let p = policy("github.com/mcpg-dev/source-code", "v1.2.3");
        let env = envelope_with_payload(&slsa_v1_payload(
            "deadbeef",
            "github.com/mcpg-dev/source-code",
            "v1.2.3",
        ));
        let result = verify_slsa_provenance(&env, "deadbeef", &p).unwrap();
        assert_eq!(result.matched_predicate_type, SLSA_V1_PREDICATE);
        assert_eq!(result.envelopes_total, 1);
    }

    #[test]
    fn verify_slsa_accepts_matching_v02_envelope() {
        let p = policy("github.com/mcpg-dev/source-code", "v1.2.3");
        let env = envelope_with_payload(&slsa_v02_payload(
            "deadbeef",
            "github.com/mcpg-dev/source-code",
            "v1.2.3",
        ));
        let result = verify_slsa_provenance(&env, "deadbeef", &p).unwrap();
        assert_eq!(result.matched_predicate_type, SLSA_V02_PREDICATE);
    }

    #[test]
    fn verify_slsa_rejects_subject_digest_mismatch() {
        // Provenance attests to a different sha256 — operator
        // must refuse, even though every other policy field
        // matches. This is the "different release smuggled into
        // the same image" defence.
        let p = policy("github.com/mcpg-dev/source-code", "v1.2.3");
        let env = envelope_with_payload(&slsa_v1_payload(
            "wronghash",
            "github.com/mcpg-dev/source-code",
            "v1.2.3",
        ));
        let err = verify_slsa_provenance(&env, "deadbeef", &p).unwrap_err();
        assert!(matches!(err, SlsaError::NoMatchingStatement(_, _, _, _)));
    }

    #[test]
    fn verify_slsa_rejects_source_uri_mismatch() {
        let p = policy("github.com/mcpg-dev/source-code", "v1.2.3");
        let env = envelope_with_payload(&slsa_v1_payload(
            "deadbeef",
            "github.com/attacker-org/evil",
            "v1.2.3",
        ));
        let err = verify_slsa_provenance(&env, "deadbeef", &p).unwrap_err();
        assert!(matches!(err, SlsaError::NoMatchingStatement(_, _, _, _)));
    }

    #[test]
    fn verify_slsa_rejects_source_tag_mismatch() {
        let p = policy("github.com/mcpg-dev/source-code", "v1.2.3");
        let env = envelope_with_payload(&slsa_v1_payload(
            "deadbeef",
            "github.com/mcpg-dev/source-code",
            "v9.9.9-attacker",
        ));
        let err = verify_slsa_provenance(&env, "deadbeef", &p).unwrap_err();
        assert!(matches!(err, SlsaError::NoMatchingStatement(_, _, _, _)));
    }

    #[test]
    fn verify_slsa_rejects_unknown_predicate_type() {
        let p = policy("github.com/mcpg-dev/source-code", "v1.2.3");
        let payload = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://example.com/some-other-attestation/v1",
            "subject": [{"name": "x", "digest": {"sha256": "deadbeef"}}],
            "predicate": {}
        });
        let env = envelope_with_payload(&payload);
        let err = verify_slsa_provenance(&env, "deadbeef", &p).unwrap_err();
        match err {
            SlsaError::NoMatchingStatement(total, matched, _, _) => {
                assert_eq!(total, 1);
                assert_eq!(matched, 0, "non-SLSA predicate should not count");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn verify_slsa_treats_subject_sha256_case_insensitively() {
        // Some SLSA generators emit upper-case hex; the verified
        // artefact hash is lower-case. Match the two
        // case-insensitively so an avoidable mismatch doesn't
        // wedge a release.
        let p = policy("github.com/mcpg-dev/source-code", "v1.2.3");
        let env = envelope_with_payload(&slsa_v1_payload(
            "DEADBEEF",
            "github.com/mcpg-dev/source-code",
            "v1.2.3",
        ));
        verify_slsa_provenance(&env, "deadbeef", &p).unwrap();
    }

    #[test]
    fn verify_slsa_skips_blank_lines_in_jsonl() {
        let p = policy("github.com/mcpg-dev/source-code", "v1.2.3");
        let env = format!(
            "\n\n{}\n\n",
            envelope_with_payload(&slsa_v1_payload(
                "deadbeef",
                "github.com/mcpg-dev/source-code",
                "v1.2.3",
            ))
        );
        verify_slsa_provenance(&env, "deadbeef", &p).unwrap();
    }

    #[test]
    fn verify_slsa_finds_matching_statement_among_multiple_envelopes() {
        let p = policy("github.com/mcpg-dev/source-code", "v1.2.3");
        // Three envelopes: first one wrong predicate type, second
        // wrong source, third matches. Verifier walks until match.
        let env = format!(
            "{}\n{}\n{}\n",
            envelope_with_payload(&serde_json::json!({
                "predicateType": "https://example.com/other/v1",
                "subject": [],
                "predicate": {}
            })),
            envelope_with_payload(&slsa_v1_payload(
                "deadbeef",
                "github.com/wrong-repo/x",
                "v1.2.3",
            )),
            envelope_with_payload(&slsa_v1_payload(
                "deadbeef",
                "github.com/mcpg-dev/source-code",
                "v1.2.3",
            )),
        );
        let result = verify_slsa_provenance(&env, "deadbeef", &p).unwrap();
        assert_eq!(result.envelopes_total, 3);
    }

    #[test]
    fn verify_slsa_rejects_empty_jsonl() {
        let p = policy("github.com/mcpg-dev/source-code", "v1.2.3");
        let err = verify_slsa_provenance("", "deadbeef", &p).unwrap_err();
        assert!(matches!(err, SlsaError::EnvelopeEmpty));
        let err = verify_slsa_provenance("   \n  \n  ", "deadbeef", &p).unwrap_err();
        assert!(matches!(err, SlsaError::EnvelopeEmpty));
    }

    #[test]
    fn verify_slsa_rejects_invalid_json_envelope() {
        let p = policy("github.com/mcpg-dev/source-code", "v1.2.3");
        let err = verify_slsa_provenance("not json{", "deadbeef", &p).unwrap_err();
        assert!(matches!(err, SlsaError::EnvelopeJson { line: 1, .. }));
    }

    #[test]
    fn verify_slsa_rejects_invalid_payload_base64() {
        let p = policy("github.com/mcpg-dev/source-code", "v1.2.3");
        let env = r#"{"payload":"!!not-base64!!","payloadType":"application/vnd.in-toto+json","signatures":[]}"#;
        let err = verify_slsa_provenance(env, "deadbeef", &p).unwrap_err();
        assert!(matches!(err, SlsaError::PayloadBase64 { line: 1, .. }));
    }

    #[test]
    fn verify_slsa_rejects_payload_not_intoto() {
        let p = policy("github.com/mcpg-dev/source-code", "v1.2.3");
        let env = format!(
            r#"{{"payload":"{}","payloadType":"application/vnd.in-toto+json","signatures":[]}}"#,
            b64(b"{\"not\":\"a statement\"}")
        );
        let err = verify_slsa_provenance(&env, "deadbeef", &p).unwrap_err();
        assert!(matches!(err, SlsaError::StatementJson { line: 1, .. }));
    }
}
