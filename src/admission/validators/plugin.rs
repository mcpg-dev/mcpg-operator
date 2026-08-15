//! Validating webhook for `MCPGPlugin`.
//!
//! Pure-spec checks the OpenAPI schema can't express. The
//! controller layers on cross-resource validation (verify the
//! referenced Secret exists + parses as an Ed25519 key, the OCI
//! artefact pulls successfully, etc.) at reconcile time.
//! Admission rejects only specs that can't possibly be
//! reconciled — the cheap, deterministic checks.

use axum::Json;
use axum::extract::State;
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use mcpg_operator_api::v1alpha1::MCPGPlugin;
use tracing::warn;

use crate::admission::server::AdmissionState;

/// Set of plugin classes the operator recognises. Sourced from
/// [`mcpg_plugin_protocol::abi::ALL_KINDS`] — the single source of
/// truth — so the admission webhook agrees with the gateway by
/// construction.
const KNOWN_PLUGIN_CLASSES: &[&str] = mcpg_plugin_protocol::abi::ALL_KINDS;

pub async fn validate(
    State(_state): State<AdmissionState>,
    Json(review): Json<AdmissionReview<MCPGPlugin>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let req: AdmissionRequest<MCPGPlugin> = match review.try_into() {
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

fn validate_spec(obj: &MCPGPlugin) -> Result<(), String> {
    let spec = &obj.spec;

    if spec.plugin_id.trim().is_empty() {
        return Err("spec.pluginId must not be empty".into());
    }
    // Plugin id format: `dev.mcpg.<class>.<short>` or
    // `<vendor>.<class>.<short>` — at minimum two dot-separated
    // segments. Stricter validation lives at the gateway's
    // boot-time validator.
    if !spec.plugin_id.contains('.') {
        return Err(format!(
            "spec.pluginId `{}` is not a valid plugin id (expected reverse-DNS form, \
             e.g. `dev.mcpg.identity.workload`)",
            spec.plugin_id
        ));
    }

    if spec.version.trim().is_empty() {
        return Err("spec.version must not be empty".into());
    }

    if !KNOWN_PLUGIN_CLASSES.contains(&spec.plugin_class.as_str()) {
        return Err(format!(
            "spec.pluginClass `{}` is not a known PluginClass (known: {})",
            spec.plugin_class,
            KNOWN_PLUGIN_CLASSES.join(", ")
        ));
    }

    // OCI image reference: `<registry>/<repo>:<tag>[@sha256:digest]`.
    // We don't fully parse here (the controller does that via
    // oci-client), but obvious malformed references get caught:
    let img = spec.oci.image.trim();
    if img.is_empty() {
        return Err("spec.oci.image must not be empty".into());
    }
    if !img.contains('/') {
        return Err(format!(
            "spec.oci.image `{img}` lacks a registry component \
             (expected `<registry>/<path>:<tag>`)"
        ));
    }
    if !img.contains(':') && !img.contains('@') {
        return Err(format!(
            "spec.oci.image `{img}` lacks a tag or digest pin \
             (expected `:tag` or `@sha256:...`)"
        ));
    }

    // Production deploys SHOULD digest-pin. We surface a
    // warning-style hint via the deny message format only when
    // tag-only refs are ALSO missing a `cosignIdentity` —
    // belt-and-braces verification is the correct posture.
    let tag_only = !img.contains("@sha256:");
    if tag_only && spec.trust.cosign_identity.is_none() {
        // Tag-only + no cosign = weakest trust posture. Reject
        // outright in v1alpha1 to encourage operators to either
        // digest-pin or configure cosign.
        return Err(format!(
            "spec.oci.image `{img}` is tag-only AND no cosignIdentity is configured. \
             Either pin the image by digest (`@sha256:...`) or set \
             spec.trust.cosignIdentity for keyless verification."
        ));
    }

    if spec.trust.signing_key_ref.secret_name.trim().is_empty() {
        return Err("spec.trust.signingKeyRef.secretName must not be empty".into());
    }
    if spec.trust.signing_key_ref.key.trim().is_empty() {
        return Err("spec.trust.signingKeyRef.key must not be empty".into());
    }

    if let Some(cosign) = &spec.trust.cosign_identity {
        let regex_str = cosign.certificate_identity_regexp.trim();
        if regex_str.is_empty() {
            return Err(
                "spec.trust.cosignIdentity.certificateIdentityRegexp must not be empty".into(),
            );
        }
        // The regex MUST compile + MUST be anchored. An
        // unanchored regex like `github.com/mcpg-dev` accepts
        // attacker subjects like `https://github.com/mcpg-dev-evil/`.
        // We require both `^` at the start and `$` at the end —
        // pre-1.0 we bias toward correctness; the cost is one
        // extra character per regex which is cheap.
        if let Err(e) = regex::Regex::new(regex_str) {
            return Err(format!(
                "spec.trust.cosignIdentity.certificateIdentityRegexp \
                 is not a valid regex: {e}"
            ));
        }
        if !regex_str.starts_with('^') {
            return Err(
                "spec.trust.cosignIdentity.certificateIdentityRegexp must start \
                 with `^` (anchored). Unanchored patterns accept substring \
                 matches and let attacker-controlled subjects pass."
                    .into(),
            );
        }
        if !regex_str.ends_with('$') {
            return Err(
                "spec.trust.cosignIdentity.certificateIdentityRegexp must end \
                 with `$` (anchored). Unanchored tails accept substring \
                 matches."
                    .into(),
            );
        }
        if cosign.oidc_issuer.trim().is_empty() {
            return Err("spec.trust.cosignIdentity.oidcIssuer must not be empty".into());
        }
    }

    if let Some(slsa) = &spec.trust.slsa_provenance {
        if slsa.config_map_name.trim().is_empty() {
            return Err("spec.trust.slsaProvenance.configMapName must not be empty".into());
        }
        if slsa.source_uri.trim().is_empty() {
            return Err("spec.trust.slsaProvenance.sourceUri must not be empty".into());
        }
        if slsa.source_tag.trim().is_empty() {
            return Err("spec.trust.slsaProvenance.sourceTag must not be empty".into());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::{
        CosignIdentity, MCPGPluginSpec, OciImageRef, PluginTrust, SigningKeyRef,
    };

    fn fixture(spec: MCPGPluginSpec) -> MCPGPlugin {
        MCPGPlugin {
            metadata: ObjectMeta {
                name: Some("identity-workload-1.2.3-linux-amd64".into()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn good_spec() -> MCPGPluginSpec {
        MCPGPluginSpec {
            plugin_id: "dev.mcpg.identity.workload".into(),
            version: "1.2.3".into(),
            plugin_class: "identity_provider".into(),
            oci: OciImageRef {
                image: "ghcr.io/mcpg-dev/source-code/plugins/identity-workload:1.2.3-linux-amd64@sha256:abcd1234".into(),
                pull_secret_ref: None,
                mirror_ref: None,
            },
            trust: PluginTrust {
                signing_key_ref: SigningKeyRef {
                    secret_name: "release-trust".into(),
                    key: "release.pub".into(),
                },
                cosign_identity: None,
                slsa_provenance: None,
            },
        }
    }

    #[test]
    fn accepts_well_formed_minimal() {
        validate_spec(&fixture(good_spec())).unwrap();
    }

    #[test]
    fn rejects_empty_plugin_id() {
        let mut s = good_spec();
        s.plugin_id = "  ".into();
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("pluginId"), "{err}");
    }

    #[test]
    fn rejects_plugin_id_without_dot() {
        let mut s = good_spec();
        s.plugin_id = "identityworkload".into();
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("reverse-DNS"), "{err}");
    }

    #[test]
    fn rejects_unknown_plugin_class() {
        let mut s = good_spec();
        s.plugin_class = "frobnicator".into();
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("PluginClass"), "{err}");
    }

    #[test]
    fn rejects_oci_without_tag_or_digest() {
        let mut s = good_spec();
        s.oci.image = "ghcr.io/foo/bar".into();
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("tag or digest"), "{err}");
    }

    #[test]
    fn rejects_oci_without_registry() {
        let mut s = good_spec();
        s.oci.image = "image:tag".into();
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("registry component"), "{err}");
    }

    #[test]
    fn rejects_tag_only_image_without_cosign() {
        // Tag-only + no cosign = weakest trust → admission rejects.
        let mut s = good_spec();
        s.oci.image = "ghcr.io/foo/bar:1.0.0".into();
        s.trust.cosign_identity = None;
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("digest"), "{err}");
        assert!(err.contains("cosignIdentity"), "{err}");
    }

    #[test]
    fn accepts_tag_only_image_with_cosign() {
        let mut s = good_spec();
        s.oci.image = "ghcr.io/foo/bar:1.0.0".into();
        s.trust.cosign_identity = Some(CosignIdentity {
            certificate_identity_regexp: "^https://github.com/foo/.*$".into(),
            oidc_issuer: "https://token.actions.githubusercontent.com".into(),
        });
        validate_spec(&fixture(s)).unwrap();
    }

    #[test]
    fn rejects_unanchored_cosign_regex_at_start() {
        // No `^` — accepts ANY subject containing the substring,
        // including attacker-controlled prefixes.
        let mut s = good_spec();
        s.oci.image = "ghcr.io/foo/bar:1.0.0".into();
        s.trust.cosign_identity = Some(CosignIdentity {
            certificate_identity_regexp: "https://github.com/foo/.*$".into(),
            oidc_issuer: "https://token.actions.githubusercontent.com".into(),
        });
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("must start"), "{err}");
        assert!(err.contains("anchored"), "{err}");
    }

    #[test]
    fn rejects_unanchored_cosign_regex_at_end() {
        // No `$` — accepts attacker-controlled suffixes.
        let mut s = good_spec();
        s.oci.image = "ghcr.io/foo/bar:1.0.0".into();
        s.trust.cosign_identity = Some(CosignIdentity {
            certificate_identity_regexp: "^https://github.com/foo/".into(),
            oidc_issuer: "https://token.actions.githubusercontent.com".into(),
        });
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("must end"), "{err}");
        assert!(err.contains("anchored"), "{err}");
    }

    #[test]
    fn rejects_invalid_cosign_regex() {
        let mut s = good_spec();
        s.oci.image = "ghcr.io/foo/bar:1.0.0".into();
        s.trust.cosign_identity = Some(CosignIdentity {
            certificate_identity_regexp: "^[invalid(".into(),
            oidc_issuer: "https://token.actions.githubusercontent.com".into(),
        });
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("not a valid regex"), "{err}");
    }

    #[test]
    fn rejects_empty_signing_key_secret() {
        let mut s = good_spec();
        s.trust.signing_key_ref.secret_name = "  ".into();
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("signingKeyRef.secretName"), "{err}");
    }

    #[test]
    fn rejects_empty_cosign_identity_when_set() {
        let mut s = good_spec();
        s.trust.cosign_identity = Some(CosignIdentity {
            certificate_identity_regexp: "  ".into(),
            oidc_issuer: "https://issuer".into(),
        });
        let err = validate_spec(&fixture(s)).unwrap_err();
        assert!(err.contains("certificateIdentityRegexp"), "{err}");
    }
}
