//! Thin wrapper around `mcpg_plugin_host::oci::pull` that adds
//! operator-specific concerns: pull-secret resolution from
//! Kubernetes Secrets, mirror reference translation, and
//! tempdir scoping for the artefact + unpack directories.

use std::path::PathBuf;

use base64::Engine as _;
use k8s_openapi::api::core::v1::Secret;
use kube::Client;
use kube::api::Api;
use mcpg_operator_api::v1alpha1::OciImageRef;
use mcpg_plugin_host::oci::{self as host_oci, OciAuth, OciClientOptions, PullOutcome};
use mcpg_plugin_host::package::{self as host_pkg, ArtifactKind, UnpackedPackage};
use serde::Deserialize;
use tracing::debug;

/// Errors raised by the OCI-pull pipeline.
#[derive(Debug, thiserror::Error)]
pub enum PullError {
    #[error("upstream OCI pull: {0}")]
    Upstream(#[from] host_oci::OciError),

    #[error("unpack: {0}")]
    Unpack(#[from] host_pkg::PackageError),

    #[error("pull secret `{name}` missing key `{key}`")]
    MissingSecretKey { name: String, key: String },

    #[error("pull secret `{name}` malformed dockerconfigjson: {detail}")]
    MalformedDockerConfig { name: String, detail: String },

    #[error("kube: {0}")]
    Kube(#[from] kube::Error),

    #[error("I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "expected native cdylib artefact in {reference}, got WASM artefact instead \
         (only native plugins are supported)"
    )]
    UnexpectedWasmArtifact { reference: String },

    #[error(
        "OCI pull for {reference} timed out after {timeout_secs}s; \
         a slow / hung registry will not block reconciles indefinitely. \
         Investigate registry latency / reachability from the operator"
    )]
    Timeout {
        reference: String,
        timeout_secs: u64,
    },
}

/// Default per-pull timeout. 5 minutes is generous for normal
/// pulls (a 100MB plugin over a slow link) and tight enough that
/// a malicious / hung registry doesn't block reconciles forever.
const DEFAULT_PULL_TIMEOUT_SECS: u64 = 300;

/// Options the controller passes to [`pull_and_unpack`].
#[derive(Debug, Clone)]
pub struct PullOptions {
    /// Insecure registries (only used for in-cluster mirrors that
    /// don't expose TLS — public registries should always be HTTPS).
    pub insecure_registries: Vec<String>,

    /// Per-call timeout. A pull that takes longer than this gets
    /// aborted and surfaces as `PullError::Timeout`. Defaults to
    /// 5 minutes — see [`DEFAULT_PULL_TIMEOUT_SECS`].
    pub timeout_secs: u64,
}

impl Default for PullOptions {
    fn default() -> Self {
        Self {
            insecure_registries: Vec::new(),
            timeout_secs: DEFAULT_PULL_TIMEOUT_SECS,
        }
    }
}

/// Result of a successful pull + unpack. The temporary directory
/// stays alive while the controller is reading the bytes; drop
/// the [`PullArtefact`] to clean up.
pub struct PullArtefact {
    /// Manifest digest from the registry (pinned `sha256:<hex>`).
    pub manifest_digest: String,
    /// Operator-extracted SHA-256 of the cdylib bytes (lowercase
    /// hex). Used as the cache key + status field.
    pub artifact_sha256: Option<String>,
    /// Bytes of the cdylib (`plugin.so`).
    pub artifact_bytes: Vec<u8>,
    /// Bytes of the signature file (`plugin.sig`), when present
    /// in the package.
    pub signature_bytes: Option<Vec<u8>>,
    /// Bytes of the descriptor (`plugin.yaml`).
    pub descriptor_bytes: Vec<u8>,
    /// Tempdir that owns the unpacked files. Held so the file
    /// paths inside [`UnpackedPackage`] stay valid until the
    /// caller is done verifying.
    pub _tempdir: tempfile::TempDir,
    /// The operator's view of the unpacked package. The
    /// `artifact_path` field is the input to
    /// [`verify::verify_artefact`].
    pub unpacked: UnpackedPackage,
}

/// Pull an OCI artefact, unpack the canonical zip, and surface
/// the cdylib + descriptor + signature bytes.
pub async fn pull_and_unpack(
    client: &Client,
    operator_namespace: &str,
    spec: &OciImageRef,
    options: &PullOptions,
) -> Result<PullArtefact, PullError> {
    let reference = resolve_reference(spec);

    let auth = match &spec.pull_secret_ref {
        Some(secret_ref) => {
            resolve_pull_auth(
                client,
                operator_namespace,
                &secret_ref.name,
                registry_from_reference(&reference),
            )
            .await?
        }
        None => OciAuth::Anonymous,
    };

    let temp = tempfile::tempdir().map_err(|e| PullError::Io {
        path: std::env::temp_dir(),
        source: e,
    })?;
    let zip_path = temp.path().join("plugin.zip");
    let unpack_dir = temp.path().join("unpacked");

    let host_opts = OciClientOptions {
        insecure_registries: options.insecure_registries.clone(),
    };
    debug!(
        reference = %reference,
        timeout_secs = options.timeout_secs,
        "operator: pulling OCI artefact"
    );
    // Bound the pull. A slow / hung registry would
    // otherwise hold the reconcile worker indefinitely.
    let outcome: PullOutcome = match tokio::time::timeout(
        std::time::Duration::from_secs(options.timeout_secs),
        host_oci::pull(
            &reference,
            &zip_path,
            auth,
            host_opts,
            digest_of(&reference),
        ),
    )
    .await
    {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return Err(PullError::Upstream(e)),
        Err(_elapsed) => {
            return Err(PullError::Timeout {
                reference,
                timeout_secs: options.timeout_secs,
            });
        }
    };

    let unpacked = host_pkg::Package::unpack_to(&zip_path, &unpack_dir)?;
    if matches!(unpacked.artifact_kind, ArtifactKind::Wasm) {
        return Err(PullError::UnexpectedWasmArtifact { reference });
    }

    let artifact_bytes = std::fs::read(&unpacked.artifact_path).map_err(|e| PullError::Io {
        path: unpacked.artifact_path.clone(),
        source: e,
    })?;
    let signature_bytes = match &unpacked.signature_path {
        Some(p) => Some(std::fs::read(p).map_err(|e| PullError::Io {
            path: p.clone(),
            source: e,
        })?),
        None => None,
    };
    let descriptor_bytes = std::fs::read(&unpacked.descriptor_path).map_err(|e| PullError::Io {
        path: unpacked.descriptor_path.clone(),
        source: e,
    })?;

    Ok(PullArtefact {
        manifest_digest: outcome.manifest_digest,
        artifact_sha256: None, // populated by the verify step
        artifact_bytes,
        signature_bytes,
        descriptor_bytes,
        _tempdir: temp,
        unpacked,
    })
}

/// Resolve the wire OCI reference. This takes the literal
/// `spec.image` string — by the time the pull runs, the plugin
/// controller has already applied any `MCPGPluginMirror` rewrite
/// (see `controllers::plugin::resolve_pull_target`) and handed us a
/// derived `OciImageRef` whose `image` is the final pull target.
/// The `mirror_ref` field on the passed spec is therefore always
/// `None` here.
fn resolve_reference(spec: &OciImageRef) -> String {
    spec.image.clone()
}

/// Extract the registry hostname (e.g. `ghcr.io`) from a full OCI
/// reference like `ghcr.io/org/repo:tag`. Used to scope dockerconfigjson
/// auths to the right registry — typical pull secrets carry creds
/// for multiple registries.
pub(crate) fn registry_from_reference(reference: &str) -> &str {
    match reference.split_once('/') {
        Some((host, _)) if host.contains('.') || host.contains(':') => host,
        // Bare repos like `redis:alpine` resolve against
        // docker.io by convention. We follow that convention to
        // pick out auth.
        _ => "index.docker.io",
    }
}

/// Strip the `:tag` / `@digest` suffix from an OCI reference, leaving
/// the repository. A `:` only separates a tag when it follows the last
/// `/` — otherwise it is a registry port (`registry.example.com:5000/x`).
pub(crate) fn repository_of(reference: &str) -> &str {
    let repo = match reference.split_once('@') {
        Some((repo, _)) => repo,
        None => reference,
    };
    let tag_search_from = repo.rfind('/').map(|i| i + 1).unwrap_or(0);
    match repo[tag_search_from..].find(':') {
        Some(i) => &repo[..tag_search_from + i],
        None => repo,
    }
}

/// The `sha256:…` manifest digest an OCI reference pins, if it pins one.
pub(crate) fn digest_of(reference: &str) -> Option<&str> {
    reference.split_once('@').map(|(_, digest)| digest)
}

/// Rewrite `reference` onto an explicit manifest digest, discarding any
/// tag it carried. Two lookups of the same tag can resolve to different
/// manifests, so anything that must act on the bytes another step
/// already resolved has to name them by digest.
pub(crate) fn pin_to_digest(reference: &str, digest: &str) -> String {
    format!("{}@{}", repository_of(reference), digest)
}

/// Compare two OCI digests, tolerating an optional `sha256:` prefix on
/// either side and hex case differences.
pub(crate) fn digests_match(a: &str, b: &str) -> bool {
    fn strip(s: &str) -> &str {
        s.strip_prefix("sha256:").unwrap_or(s)
    }
    strip(a).eq_ignore_ascii_case(strip(b))
}

/// Read a Kubernetes Secret of type `kubernetes.io/dockerconfigjson`
/// and pick out the credentials for the given registry. Returns
/// [`OciAuth::Anonymous`] when the registry isn't named in the
/// secret's auths map (operator does not fail-closed because the
/// upstream registry might be public for *some* paths even when
/// the secret only covers others).
async fn resolve_pull_auth(
    client: &Client,
    namespace: &str,
    secret_name: &str,
    registry: &str,
) -> Result<OciAuth, PullError> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let secret = api.get(secret_name).await?;
    let data = secret.data.unwrap_or_default();

    let dockerconfig = data
        .get(".dockerconfigjson")
        .or_else(|| data.get("dockerconfigjson"))
        .ok_or_else(|| PullError::MissingSecretKey {
            name: secret_name.to_owned(),
            key: ".dockerconfigjson".to_owned(),
        })?;

    let parsed: DockerConfigJson =
        serde_json::from_slice(&dockerconfig.0).map_err(|e| PullError::MalformedDockerConfig {
            name: secret_name.to_owned(),
            detail: e.to_string(),
        })?;

    let entry = match parsed.auths.get(registry) {
        Some(e) => e,
        None => match parsed
            .auths
            .iter()
            .find(|(host, _)| host.starts_with(registry))
        {
            Some((_, e)) => e,
            None => return Ok(OciAuth::Anonymous),
        },
    };

    if let Some(token) = entry.auth.as_deref().filter(|t| !t.trim().is_empty()) {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(token.trim())
            .map_err(|e| PullError::MalformedDockerConfig {
                name: secret_name.to_owned(),
                detail: format!("base64 decode `auths.{registry}.auth`: {e}"),
            })?;
        let decoded = String::from_utf8(raw).map_err(|e| PullError::MalformedDockerConfig {
            name: secret_name.to_owned(),
            detail: format!("`auths.{registry}.auth` not utf-8: {e}"),
        })?;
        let (user, pass) =
            decoded
                .split_once(':')
                .ok_or_else(|| PullError::MalformedDockerConfig {
                    name: secret_name.to_owned(),
                    detail: format!("`auths.{registry}.auth` is not `user:pass`"),
                })?;
        return Ok(OciAuth::Basic {
            username: user.to_owned(),
            password: pass.to_owned(),
        });
    }

    if let (Some(user), Some(pass)) = (&entry.username, &entry.password) {
        return Ok(OciAuth::Basic {
            username: user.clone(),
            password: pass.clone(),
        });
    }

    Ok(OciAuth::Anonymous)
}

#[derive(Deserialize)]
struct DockerConfigJson {
    auths: std::collections::BTreeMap<String, DockerConfigAuth>,
}

#[derive(Deserialize)]
struct DockerConfigAuth {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    /// Base64-encoded `username:password` (the typical kubelet
    /// pull-secret shape).
    #[serde(default)]
    auth: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_from_reference_handles_dotted_host() {
        assert_eq!(
            registry_from_reference("ghcr.io/mcpg-dev/plugins/foo:1.0"),
            "ghcr.io"
        );
        assert_eq!(
            registry_from_reference("registry.example.com:5000/foo:1.0"),
            "registry.example.com:5000"
        );
    }

    #[test]
    fn repository_of_strips_tags_digests_and_keeps_registry_ports() {
        assert_eq!(
            repository_of("ghcr.io/mcpg-dev/plugins/foo:1.0"),
            "ghcr.io/mcpg-dev/plugins/foo"
        );
        assert_eq!(
            repository_of("ghcr.io/mcpg-dev/plugins/foo@sha256:abcd"),
            "ghcr.io/mcpg-dev/plugins/foo"
        );
        // The colon here is a registry port, not a tag separator.
        assert_eq!(
            repository_of("registry.example.com:5000/foo/bar"),
            "registry.example.com:5000/foo/bar"
        );
        assert_eq!(
            repository_of("registry.example.com:5000/foo/bar:2.1"),
            "registry.example.com:5000/foo/bar"
        );
        assert_eq!(repository_of("nginx:alpine"), "nginx");
        assert_eq!(repository_of("ghcr.io/org/repo"), "ghcr.io/org/repo");
    }

    #[test]
    fn pin_to_digest_replaces_a_tag_rather_than_appending_to_it() {
        assert_eq!(
            pin_to_digest("ghcr.io/org/repo:1.0", "sha256:abcd"),
            "ghcr.io/org/repo@sha256:abcd"
        );
        // A ref that already pins a different digest is re-pinned, so a
        // caller can never verify one manifest while holding another.
        assert_eq!(
            pin_to_digest("ghcr.io/org/repo@sha256:0000", "sha256:abcd"),
            "ghcr.io/org/repo@sha256:abcd"
        );
    }

    #[test]
    fn digest_of_reads_only_a_digest_pin() {
        assert_eq!(
            digest_of("ghcr.io/org/repo@sha256:abcd"),
            Some("sha256:abcd")
        );
        assert_eq!(digest_of("ghcr.io/org/repo:1.0"), None);
    }

    #[test]
    fn digests_match_tolerates_prefix_and_case_only() {
        assert!(digests_match("sha256:ABCD", "abcd"));
        assert!(digests_match("sha256:abcd", "sha256:abcd"));
        assert!(!digests_match("sha256:abcd", "sha256:abce"));
    }

    #[test]
    fn registry_from_reference_falls_back_to_dockerhub() {
        assert_eq!(registry_from_reference("nginx:alpine"), "index.docker.io");
        assert_eq!(
            registry_from_reference("library/nginx:alpine"),
            "index.docker.io"
        );
    }
}
