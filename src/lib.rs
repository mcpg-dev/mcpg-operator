//! MCPG Kubernetes operator — library crate.
//!
//! The binary ([`bin/main.rs`](./bin/main.rs)) wires together the
//! pieces declared here. Library-vs-binary split lets us write
//! integration tests against the same modules the binary loads.
//!
//! # Module map
//!
//! - [`config`] — startup config (CLI flags + env vars).
//! - [`telemetry`] — `tracing` + `prometheus-client` setup.
//! - [`templates`] — pure functions that turn a `MCPGGateway`
//!   into K8s `Deployment` / `Service` / `ConfigMap` /
//!   `ServiceAccount` shapes.
//! - [`reconcile`] — controller helpers (server-side apply, owner
//!   refs, status updates, finalizers, status-conflict retry).
//! - [`controllers`] — the four reconcile loops (gateway,
//!   plugin, plugin_set, revocation_list).
//! - [`admission`] — validating webhook server (axum + rustls).
//! - [`leader`] — `coordination.k8s.io/v1.Lease`-backed leader
//!   election state machine.
//! - [`readiness`] — watch-readiness latch backing `/reconcilez`
//!   (set when the gateway controller's reflector store has synced;
//!   `/readyz` stays independent of it).
//! - [`oci_pull`] — operator-side OCI pull pipeline (auth, mirror
//!   translation, per-pull timeout).
//! - [`verify`] — three-layer plugin trust gate (Ed25519 +
//!   cosign keyless + SLSA L3 in-toto).
//! - [`backoff`] — per-resource exponential backoff with jitter.

pub mod admission;
pub mod backoff;
pub mod config;
pub mod controllers;
// Managed-service only: the pull-mode cell agent needs a provisioner to dial,
// and its wire contract is not published.
#[cfg(feature = "fleet")]
pub mod fleet_agent;
pub mod leader;
pub mod oci_pull;
pub mod rbac;
pub mod readiness;
pub mod reconcile;
pub mod telemetry;
pub mod templates;
pub mod verify;

/// Operator's field-manager prefix for server-side apply. Each
/// controller appends its own suffix (e.g.
/// `mcpg-operator/gateway-controller`).
pub const FIELD_MANAGER_PREFIX: &str = "mcpg-operator";

/// Compiled-in fallback for the default gateway image repository, used
/// when a `MCPGGateway` omits `spec.image.repository` and
/// [`ENV_DEFAULT_GATEWAY_IMAGE_REPOSITORY`] is unset. Call
/// [`default_gateway_image_repository`] rather than reading this
/// directly — the accessor layers the runtime override on top.
pub const DEFAULT_GATEWAY_IMAGE_REPOSITORY: &str = "ghcr.io/mcpg-dev/source-code/gateway";

/// Runtime override for the default gateway image repository. Read once
/// from the operator's environment on first use.
///
/// Deliberately runtime and not `option_env!`: an air-gapped or
/// public-registry install must repoint the default without rebuilding
/// the operator binary, and the value differs per install of the same
/// release artifact.
pub const ENV_DEFAULT_GATEWAY_IMAGE_REPOSITORY: &str = "MCPG_DEFAULT_GATEWAY_IMAGE_REPOSITORY";

/// Compile-time pin for the default gateway image tag. The release
/// pipeline overrides this via `RUSTFLAGS` so each operator build
/// ships pinned to a known-good gateway version. Call
/// [`default_gateway_image_tag`] rather than reading this directly.
pub const DEFAULT_GATEWAY_IMAGE_TAG: &str = match option_env!("MCPG_OPERATOR_DEFAULT_GATEWAY_TAG") {
    Some(t) => t,
    None => "v1.0.0-dev",
};

/// Runtime override for the default gateway image tag. Layered ON TOP of
/// the [`DEFAULT_GATEWAY_IMAGE_TAG`] build pin, which stays the value a
/// release artifact ships with when this is unset.
pub const ENV_DEFAULT_GATEWAY_IMAGE_TAG: &str = "MCPG_DEFAULT_GATEWAY_IMAGE_TAG";

static RESOLVED_GATEWAY_IMAGE_REPOSITORY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
static RESOLVED_GATEWAY_IMAGE_TAG: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Effective default gateway image repository: the
/// [`ENV_DEFAULT_GATEWAY_IMAGE_REPOSITORY`] value when it is set to
/// something non-blank, else [`DEFAULT_GATEWAY_IMAGE_REPOSITORY`].
///
/// Resolved once per process, so every `MCPGGateway` reconciled by one
/// operator instance defaults to the same repository even if the
/// environment is mutated underneath it.
pub fn default_gateway_image_repository() -> &'static str {
    RESOLVED_GATEWAY_IMAGE_REPOSITORY
        .get_or_init(|| {
            resolve_image_default(
                ENV_DEFAULT_GATEWAY_IMAGE_REPOSITORY,
                DEFAULT_GATEWAY_IMAGE_REPOSITORY,
            )
        })
        .as_str()
}

/// Effective default gateway image tag: [`ENV_DEFAULT_GATEWAY_IMAGE_TAG`]
/// when set non-blank, else the [`DEFAULT_GATEWAY_IMAGE_TAG`] build pin.
pub fn default_gateway_image_tag() -> &'static str {
    RESOLVED_GATEWAY_IMAGE_TAG
        .get_or_init(|| {
            resolve_image_default(ENV_DEFAULT_GATEWAY_IMAGE_TAG, DEFAULT_GATEWAY_IMAGE_TAG)
        })
        .as_str()
}

/// Read `var` from the environment and normalise it into an image
/// default, falling back to `compiled` when absent or blank.
///
/// Blank and whitespace-only values fall back rather than yielding an
/// empty repository — the caller concatenates `"{repo}:{tag}"`, and an
/// empty half produces an unpullable reference. Trailing `/` is trimmed
/// for the same reason. Neither normalisation can alter `compiled`,
/// which carries no surrounding whitespace or trailing slash.
fn resolve_image_default(var: &str, compiled: &str) -> String {
    match std::env::var(var) {
        Ok(raw) => {
            let trimmed = raw.trim().trim_end_matches('/');
            if trimmed.is_empty() {
                compiled.to_owned()
            } else {
                trimmed.to_owned()
            }
        }
        Err(_) => compiled.to_owned(),
    }
}

/// Common label keys applied by the operator on every resource it
/// owns. Other labels are user-controlled.
pub mod labels {
    /// `app.kubernetes.io/name` — set to `"mcpg"` for gateway
    /// children; `"mcpg-operator"` for operator-self resources.
    pub const APP_NAME: &str = "app.kubernetes.io/name";
    /// `app.kubernetes.io/instance` — set to the parent CRD's
    /// metadata.name; lets `kubectl get -l` filter to one
    /// gateway's child resources.
    pub const APP_INSTANCE: &str = "app.kubernetes.io/instance";
    /// `app.kubernetes.io/component` — `"gateway"`,
    /// `"plugin-secret"`, `"resolved-set"`, etc. Child-shape
    /// classification.
    pub const APP_COMPONENT: &str = "app.kubernetes.io/component";
    /// `app.kubernetes.io/part-of` — always `"mcpg"`.
    pub const APP_PART_OF: &str = "app.kubernetes.io/part-of";
    /// `app.kubernetes.io/managed-by` — always `"mcpg-operator"`.
    /// The garbage collector keys on this when pruning.
    pub const APP_MANAGED_BY: &str = "app.kubernetes.io/managed-by";
    /// `app.kubernetes.io/version` — gateway image tag at the
    /// time of last reconcile.
    pub const APP_VERSION: &str = "app.kubernetes.io/version";

    /// MCPG-specific labels. The reconciler reads these to
    /// identify operator-owned resources during garbage
    /// collection + drift detection.
    /// Parent gateway name on every gateway-owned child.
    pub const MCPG_GATEWAY: &str = "mcpg.dev/gateway";
    /// SHA-256 of the rendered config; flips on any spec change
    /// that propagates to the pod template, which is what triggers
    /// the rolling update.
    pub const MCPG_CONFIG_HASH: &str = "mcpg.dev/config-hash";
}

#[cfg(test)]
mod image_default_tests {
    use super::*;

    /// The published default must be byte-identical with no override in
    /// the environment — this knob is configurability, not a migration.
    #[test]
    fn unset_env_yields_the_compiled_default() {
        temp_env::with_var_unset(ENV_DEFAULT_GATEWAY_IMAGE_REPOSITORY, || {
            assert_eq!(
                resolve_image_default(
                    ENV_DEFAULT_GATEWAY_IMAGE_REPOSITORY,
                    DEFAULT_GATEWAY_IMAGE_REPOSITORY
                ),
                "ghcr.io/mcpg-dev/source-code/gateway"
            );
        });
        temp_env::with_var_unset(ENV_DEFAULT_GATEWAY_IMAGE_TAG, || {
            assert_eq!(
                resolve_image_default(ENV_DEFAULT_GATEWAY_IMAGE_TAG, DEFAULT_GATEWAY_IMAGE_TAG),
                DEFAULT_GATEWAY_IMAGE_TAG
            );
        });
    }

    #[test]
    fn env_repoints_the_repository() {
        temp_env::with_var(
            ENV_DEFAULT_GATEWAY_IMAGE_REPOSITORY,
            Some("registry.airgap.internal/mcpg/gateway"),
            || {
                assert_eq!(
                    resolve_image_default(
                        ENV_DEFAULT_GATEWAY_IMAGE_REPOSITORY,
                        DEFAULT_GATEWAY_IMAGE_REPOSITORY
                    ),
                    "registry.airgap.internal/mcpg/gateway"
                );
            },
        );
    }

    /// The public channel drops the repository path segment, taking the
    /// reference from five segments to four.
    #[test]
    fn env_repoints_to_the_public_channel() {
        temp_env::with_var(
            ENV_DEFAULT_GATEWAY_IMAGE_REPOSITORY,
            Some("ghcr.io/mcpg-dev/gateway"),
            || {
                assert_eq!(
                    resolve_image_default(
                        ENV_DEFAULT_GATEWAY_IMAGE_REPOSITORY,
                        DEFAULT_GATEWAY_IMAGE_REPOSITORY
                    ),
                    "ghcr.io/mcpg-dev/gateway"
                );
            },
        );
    }

    #[test]
    fn env_repoints_the_tag() {
        temp_env::with_var(ENV_DEFAULT_GATEWAY_IMAGE_TAG, Some("v9.9.9"), || {
            assert_eq!(
                resolve_image_default(ENV_DEFAULT_GATEWAY_IMAGE_TAG, DEFAULT_GATEWAY_IMAGE_TAG),
                "v9.9.9"
            );
        });
    }

    /// A blank or whitespace-only override would otherwise render
    /// `":v1.0.0-dev"`, which no registry can serve.
    #[test]
    fn blank_env_falls_back_to_the_compiled_default() {
        for blank in ["", "   ", "\t\n"] {
            temp_env::with_var(ENV_DEFAULT_GATEWAY_IMAGE_REPOSITORY, Some(blank), || {
                assert_eq!(
                    resolve_image_default(
                        ENV_DEFAULT_GATEWAY_IMAGE_REPOSITORY,
                        DEFAULT_GATEWAY_IMAGE_REPOSITORY
                    ),
                    DEFAULT_GATEWAY_IMAGE_REPOSITORY
                );
            });
        }
    }

    #[test]
    fn surrounding_whitespace_and_trailing_slash_are_trimmed() {
        temp_env::with_var(
            ENV_DEFAULT_GATEWAY_IMAGE_REPOSITORY,
            Some("  registry.airgap.internal/mcpg/gateway/  "),
            || {
                assert_eq!(
                    resolve_image_default(
                        ENV_DEFAULT_GATEWAY_IMAGE_REPOSITORY,
                        DEFAULT_GATEWAY_IMAGE_REPOSITORY
                    ),
                    "registry.airgap.internal/mcpg/gateway"
                );
            },
        );
    }

    /// The accessors resolve once and never re-read the environment, so a
    /// mid-run env mutation cannot change what a reconcile renders.
    ///
    /// Asserted against a repeat call rather than the live environment:
    /// sibling tests mutate process env through `temp_env` on other
    /// threads, and a test that read it would race them.
    #[test]
    fn accessors_are_resolved_once_and_stay_stable() {
        let repo = default_gateway_image_repository();
        let tag = default_gateway_image_tag();
        assert!(!repo.is_empty() && !tag.is_empty());
        temp_env::with_var(
            ENV_DEFAULT_GATEWAY_IMAGE_REPOSITORY,
            Some("registry.late.example/mcpg/gateway"),
            || {
                assert_eq!(
                    default_gateway_image_repository(),
                    repo,
                    "a late env mutation must not change an already-resolved default"
                );
            },
        );
        assert_eq!(default_gateway_image_tag(), tag);
    }
}
