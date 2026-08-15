//! Cosign keyless verification.
//!
//! Verifies an OCI image was signed via the Sigstore public-good
//! instance against the cert subject regex + OIDC issuer the
//! operator declared on `MCPGPlugin.spec.trust.cosign_identity`.
//!
//! This runs ON TOP OF the Ed25519 trust path (see
//! [`crate::verify::verify_artefact`]). Ed25519 covers
//! "did our release pipeline sign these bytes"; cosign keyless
//! covers "did the build attestation come from the GitHub Actions
//! identity we trust." Both gates fire in series — a plugin must
//! pass Ed25519 AND, when `cosign_identity` is set, the cosign
//! constraint.
//!
//! Implementation notes:
//!
//! - The TUF root + Fulcio chain + Rekor public key are fetched
//!   on the first verification attempt and cached for the
//!   process lifetime. The fetch is anchored to the embedded
//!   Sigstore TUF root that ships with `sigstore-rs`, so
//!   subsequent runs don't trust whatever DNS resolves to
//!   `tuf-repo-cdn.sigstore.dev` in cold-start.
//! - The custom regex constraint (`CertSubjectRegexVerifier`)
//!   accepts both `Url` and `Email` cert-subject variants. The
//!   issuer check is exact — that's what cosign's standard
//!   `CertSubjectUrlVerifier` does too, and matching the issuer
//!   loosely would let a compromised OIDC provider impersonate a
//!   trusted one.
//! - Verification is bound to a manifest digest the caller supplies,
//!   not to the reference it was configured with. A caller that pulled
//!   by tag resolved that tag at its own moment; resolving it again
//!   here could name a different manifest, leaving a passing cosign
//!   status that does not describe the artefact in hand.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::OnceLock;

use sigstore::cosign::signature_layers::CertificateSubject;
use sigstore::cosign::verification_constraint::VerificationConstraint;
use sigstore::cosign::{ClientBuilder, CosignCapabilities, SignatureLayer, verify_constraints};
use sigstore::errors::Result as SigstoreResult;
use sigstore::registry::{Auth, OciReference};
use sigstore::trust::sigstore::SigstoreTrustRoot;
use tokio::sync::OnceCell;

use mcpg_operator_api::v1alpha1::{CosignIdentity, OciImageRef};

#[derive(Debug, thiserror::Error)]
pub enum CosignError {
    #[error("invalid cosign identity regex `{regexp}`: {source}")]
    InvalidRegex {
        regexp: String,
        #[source]
        source: regex::Error,
    },
    #[error("invalid OCI reference `{image}`: {source}")]
    InvalidReference {
        image: String,
        #[source]
        source: sigstore::errors::SigstoreError,
    },
    #[error("Sigstore TUF trust-root fetch failed: {0}")]
    TrustRoot(String),
    #[error("Sigstore client build failed: {0}")]
    ClientBuild(String),
    #[error("triangulate failed for `{image}`: {detail}")]
    Triangulate { image: String, detail: String },
    #[error("trusted-signature-layers fetch failed for `{image}`: {detail}")]
    Layers { image: String, detail: String },
    #[error(
        "no cosign signature layer matched the trust constraints for `{image}` ({matched}/{total} layers passed; check OIDC issuer + cert subject)"
    )]
    Constraint {
        image: String,
        matched: usize,
        total: usize,
    },
    #[error(
        "the configured cosign identity does not require any constraint (empty issuer + empty regex)"
    )]
    EmptyIdentity,
    #[error(
        "cosign verified `{image}` at digest {got}, but the caller pinned {expected}; \
         the signature does not cover the artefact in hand"
    )]
    DigestMismatch {
        image: String,
        expected: String,
        got: String,
    },
    #[error("cosign verification of `{image}` was requested without a manifest digest to bind to")]
    MissingDigest { image: String },
}

/// Successful cosign verification — the gateway controller
/// surfaces the fields below as part of the plugin's status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignVerifyResult {
    /// Number of signature layers attached to the image (1 in
    /// the common case; multi-signer setups produce >1).
    pub signature_layer_count: usize,
    /// Manifest digest the verified signature is bound to. Equal to
    /// the digest the caller pinned — the verification refuses to
    /// return otherwise.
    pub source_digest: String,
}

/// Operator-configured path to a pre-mirrored Sigstore
/// `trusted_root.json` (TUF metadata), set once at boot from
/// `gateway.config` / operator config. When set, cosign verification
/// loads the trust root from disk with NO network access — the air-gap
/// path. When unset (the default), the trust root is fetched from the
/// public Sigstore TUF CDN at first use.
///
/// Set via [`set_offline_trust_root_path`] during operator startup,
/// before any controller reconciles. A `OnceLock` (not reassignable)
/// so the trust source can't change mid-process.
static OFFLINE_TRUST_ROOT_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Configure cosign to load its Sigstore trust root from a
/// pre-mirrored `trusted_root.json` on disk instead of fetching from
/// the network. Call once at operator boot. `None` (or not calling it)
/// keeps the default online behaviour. Idempotent: a second call is
/// ignored (the first value wins), so trust source is fixed for the
/// process lifetime.
pub fn set_offline_trust_root_path(path: Option<PathBuf>) {
    let _ = OFFLINE_TRUST_ROOT_PATH.set(path);
}

/// Sigstore trust root, built lazily on first `verify_cosign_keyless`
/// call and cached for the process lifetime. Online by default
/// (fetched from the public TUF CDN); loaded from a pre-mirrored
/// `trusted_root.json` when [`set_offline_trust_root_path`] configured
/// one — the air-gap path, which makes no network calls.
static TRUST_ROOT: OnceCell<SigstoreTrustRoot> = OnceCell::const_new();

async fn trust_root() -> Result<&'static SigstoreTrustRoot, CosignError> {
    TRUST_ROOT
        .get_or_try_init(|| async {
            match OFFLINE_TRUST_ROOT_PATH.get().and_then(|p| p.as_ref()) {
                Some(path) => {
                    // Air-gap: load the pre-mirrored TUF trusted-root
                    // from disk. No network access.
                    let bytes = std::fs::read(path).map_err(|e| {
                        CosignError::TrustRoot(format!(
                            "reading offline Sigstore trust root {}: {e}",
                            path.display()
                        ))
                    })?;
                    SigstoreTrustRoot::from_trusted_root_json_unchecked(&bytes)
                        .map_err(|e| CosignError::TrustRoot(e.to_string()))
                }
                None => SigstoreTrustRoot::new(None)
                    .await
                    .map_err(|e| CosignError::TrustRoot(e.to_string())),
            }
        })
        .await
}

/// Custom verification constraint matching cert subject by
/// regex + cert issuer by exact string. The standard sigstore
/// `CertSubjectUrlVerifier` only matches subject by exact
/// string; the operator's `CosignIdentity.certificate_identity_regexp`
/// is explicitly a regex (e.g. `^https://github.com/mcpg-dev/.*`)
/// because plugin signers are typically GitHub Actions identities
/// whose URL changes per branch / tag.
#[derive(Debug)]
struct CertSubjectRegexVerifier {
    subject_re: regex::Regex,
    issuer: String,
}

impl VerificationConstraint for CertSubjectRegexVerifier {
    fn verify(&self, layer: &SignatureLayer) -> SigstoreResult<bool> {
        let cert_sig = match layer.certificate_signature.as_ref() {
            Some(c) => c,
            None => return Ok(false),
        };
        let subject_str = match &cert_sig.subject {
            CertificateSubject::Uri(u) => u.as_str(),
            CertificateSubject::Email(e) => e.as_str(),
        };
        Ok(matches_subject_and_issuer(
            &self.subject_re,
            &self.issuer,
            subject_str,
            cert_sig.issuer.as_deref(),
        ))
    }
}

/// Pure decision function — true when the layer's
/// (subject, issuer) tuple satisfies the configured constraint.
/// Issuer must match exactly; subject is regex-matched.
///
/// Extracted into a free function so unit tests can exercise
/// every truth-table branch without constructing a real
/// `SignatureLayer` (which embeds an X.509 verification key the
/// test harness can't easily fake).
fn matches_subject_and_issuer(
    subject_re: &regex::Regex,
    expected_issuer: &str,
    layer_subject: &str,
    layer_issuer: Option<&str>,
) -> bool {
    // A loose issuer match would let a compromised OIDC provider
    // impersonate a trusted one. Always exact.
    if layer_issuer != Some(expected_issuer) {
        return false;
    }
    subject_re.is_match(layer_subject)
}

/// Verify an OCI image's cosign keyless signature against the
/// configured identity. Returns the verification result on
/// success; `Err` on any constraint failure or transport error.
///
/// `expected_digest` names the manifest the caller is acting on, and
/// is mandatory: verification resolves `image` to exactly that digest
/// rather than following whatever a tag points at now. A tag can move
/// between the caller's step and this one, so a signature found for
/// the tag says nothing about the bytes the caller holds. Any digest
/// this verification lands on other than the pinned one is refused.
///
/// `auth` is the registry credential. Today the operator passes
/// `Auth::Anonymous` for public registries; integrating with
/// `MCPGPlugin.spec.oci.pull_secret_ref` to pass `Auth::Basic`
/// is the natural follow-up.
pub async fn verify_cosign_keyless(
    image: &OciImageRef,
    identity: &CosignIdentity,
    auth: &Auth,
    expected_digest: &str,
) -> Result<CosignVerifyResult, CosignError> {
    if identity.certificate_identity_regexp.is_empty() && identity.oidc_issuer.is_empty() {
        return Err(CosignError::EmptyIdentity);
    }
    if expected_digest.trim().is_empty() {
        return Err(CosignError::MissingDigest {
            image: image.image.clone(),
        });
    }

    let subject_re = regex::Regex::new(&identity.certificate_identity_regexp).map_err(|e| {
        CosignError::InvalidRegex {
            regexp: identity.certificate_identity_regexp.clone(),
            source: e,
        }
    })?;

    // Verify the digest, never the tag the caller was configured with.
    let pinned = crate::oci_pull::pin_to_digest(&image.image, expected_digest);
    let oci_ref = OciReference::from_str(&pinned).map_err(|e| CosignError::InvalidReference {
        image: pinned.clone(),
        source: e,
    })?;

    let trust = trust_root().await?;

    let mut client = ClientBuilder::default()
        .with_trust_repository(trust)
        .map_err(|e| CosignError::ClientBuild(e.to_string()))?
        .build()
        .map_err(|e| CosignError::ClientBuild(e.to_string()))?;

    let (cosign_image, source_digest) =
        client
            .triangulate(&oci_ref, auth)
            .await
            .map_err(|e| CosignError::Triangulate {
                image: pinned.clone(),
                detail: e.to_string(),
            })?;
    // `oci_ref` is digest-pinned, so this holds by construction — it is
    // asserted anyway because everything downstream reads the returned
    // digest as the identity of what was verified.
    if !crate::oci_pull::digests_match(&source_digest, expected_digest) {
        return Err(CosignError::DigestMismatch {
            image: image.image.clone(),
            expected: expected_digest.to_owned(),
            got: source_digest,
        });
    }

    let layers = client
        .trusted_signature_layers(auth, &cosign_image)
        .await
        .map_err(|e| CosignError::Layers {
            image: pinned.clone(),
            detail: e.to_string(),
        })?;

    let total = layers.len();
    let constraint: Box<dyn VerificationConstraint> = Box::new(CertSubjectRegexVerifier {
        subject_re,
        issuer: identity.oidc_issuer.clone(),
    });
    let constraints = [constraint];

    // Count matching layers ourselves so the error message can be
    // specific. `verify_constraints` returns a yes/no; for an
    // observable status we want "0/3 matched" vs "0/0 — no
    // signatures attached".
    let matched = layers
        .iter()
        .filter(|l| constraints.iter().all(|c| c.verify(l).unwrap_or(false)))
        .count();

    if let Err(e) = verify_constraints(&layers, constraints.iter()) {
        let _ = e;
        return Err(CosignError::Constraint {
            image: pinned.clone(),
            matched,
            total,
        });
    }

    Ok(CosignVerifyResult {
        signature_layer_count: total,
        source_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn re(pat: &str) -> regex::Regex {
        regex::Regex::new(pat).unwrap()
    }

    #[test]
    fn matches_url_subject_with_correct_issuer() {
        assert!(matches_subject_and_issuer(
            &re(r"^https://github\.com/mcpg-dev/"),
            "https://token.actions.githubusercontent.com",
            "https://github.com/mcpg-dev/source-code/.github/workflows/release.yml@refs/heads/main",
            Some("https://token.actions.githubusercontent.com"),
        ));
    }

    #[test]
    fn rejects_wrong_issuer_even_when_subject_matches() {
        assert!(!matches_subject_and_issuer(
            &re(r"^https://github\.com/mcpg-dev/"),
            "https://token.actions.githubusercontent.com",
            "https://github.com/mcpg-dev/source-code/release.yml@refs/heads/main",
            Some("https://accounts.google.com"),
        ));
    }

    #[test]
    fn rejects_subject_outside_regex_even_when_issuer_matches() {
        assert!(!matches_subject_and_issuer(
            &re(r"^https://github\.com/mcpg-dev/"),
            "https://token.actions.githubusercontent.com",
            "https://github.com/attacker-org/evil.yml",
            Some("https://token.actions.githubusercontent.com"),
        ));
    }

    #[test]
    fn matches_email_subject() {
        assert!(matches_subject_and_issuer(
            &re(r"^releases@mcpg\.dev$"),
            "https://accounts.google.com",
            "releases@mcpg.dev",
            Some("https://accounts.google.com"),
        ));
    }

    #[test]
    fn rejects_layer_without_issuer() {
        assert!(!matches_subject_and_issuer(
            &re(r".*"),
            "https://anything",
            "anything",
            None,
        ));
    }

    #[test]
    fn issuer_match_is_case_sensitive() {
        // OIDC issuer URLs are case-sensitive (per RFC 8414 §2);
        // matching them case-insensitively would let a compromised
        // OIDC provider register a near-match issuer that
        // case-folds onto a trusted one.
        assert!(!matches_subject_and_issuer(
            &re(r".*"),
            "https://accounts.google.com",
            "anything",
            Some("https://Accounts.Google.com"),
        ));
    }

    #[tokio::test]
    async fn verify_cosign_rejects_empty_identity() {
        let image = OciImageRef {
            image: "ghcr.io/example:latest".into(),
            ..Default::default()
        };
        let identity = CosignIdentity::default();
        let err = verify_cosign_keyless(&image, &identity, &Auth::Anonymous, "sha256:aa")
            .await
            .unwrap_err();
        assert!(matches!(err, CosignError::EmptyIdentity), "got: {err:?}");
    }

    #[tokio::test]
    async fn verify_cosign_refuses_without_a_digest_to_bind_to() {
        // No digest means nothing ties the signature to the artefact
        // the caller pulled; refuse rather than verify the tag.
        let image = OciImageRef {
            image: "ghcr.io/example/plugin:1.2.3".into(),
            ..Default::default()
        };
        let identity = CosignIdentity {
            certificate_identity_regexp: "^https://github\\.com/".into(),
            oidc_issuer: "https://token.actions.githubusercontent.com".into(),
        };
        let err = verify_cosign_keyless(&image, &identity, &Auth::Anonymous, "  ")
            .await
            .unwrap_err();
        assert!(
            matches!(err, CosignError::MissingDigest { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn digest_mismatch_message_names_both_digests() {
        let err = CosignError::DigestMismatch {
            image: "ghcr.io/example/plugin:1.2.3".into(),
            expected: "sha256:aaaa".into(),
            got: "sha256:bbbb".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("sha256:aaaa"), "got: {msg}");
        assert!(msg.contains("sha256:bbbb"), "got: {msg}");
    }

    #[test]
    fn invalid_regex_error_surfaces_pattern_in_message() {
        let bad = "[invalid(";
        let err = regex::Regex::new(bad).unwrap_err();
        let wrapped = CosignError::InvalidRegex {
            regexp: bad.into(),
            source: err,
        };
        assert!(wrapped.to_string().contains(bad));
    }

    #[test]
    fn constraint_error_message_contains_layer_counts() {
        let err = CosignError::Constraint {
            image: "ghcr.io/example/plugin:1.2.3".into(),
            matched: 0,
            total: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("0/3"), "got: {msg}");
        assert!(msg.contains("ghcr.io/example/plugin:1.2.3"), "got: {msg}");
    }
}
