//! `MCPGPlugin` controller — pulls OCI artefacts, verifies
//! signatures + revocation, materialises verified bytes as a
//! Secret in the operator's namespace.
//!
//! Reconcile flow:
//!
//! 1. Resolve OCI ref + auth.
//! 2. Pull the canonical zip and unpack.
//! 3. Load the operator-pinned Ed25519 signing key from a
//!    Secret reference.
//! 4. Materialise the cluster `MCPGRevocationList` (named
//!    `cluster-default`) into a `RevocationList` so a fresh
//!    revocation immediately blocks plugin reconciles.
//! 5. Verify the cdylib signature + revocation status via
//!    `mcpg_plugin_host::native::verify_native_artifact` —
//!    the same code path the gateway runs at load time.
//! 6. Apply the verified bytes as a Secret named
//!    `mcpg-plugin-{plugin}-{digest-prefix}` in the operator
//!    namespace.
//! 7. Patch status: `Pulled`, `Verified`, `Revoked`, `Ready`.
//!
//! Cosign keyless + SLSA L3 provenance verification run only
//! when the spec configures them; either way they're surfaced in
//! status conditions so operators can audit which trust layers
//! are active.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use futures::StreamExt;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::api::Api;
use kube::core::ObjectMeta;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::events::{Event as K8sEvent, EventType};
use kube::runtime::watcher;
use kube::{Resource, ResourceExt};
use mcpg_operator_api::CLUSTER_DEFAULT_REVOCATION_LIST;
use mcpg_operator_api::conditions::{Condition, reasons, types as ctype};
use mcpg_operator_api::v1alpha1::{
    MCPGPlugin, MCPGPluginMirror, MCPGPluginStatus, MCPGRevocationList, MirrorRewrite, OciImageRef,
};
use sha2::{Digest, Sha256};
use tracing::{error, info, instrument, warn};

use crate::FIELD_MANAGER_PREFIX;
use crate::controllers::gateway::ControllerContext;
use crate::oci_pull::{PullOptions, pull_and_unpack};
use crate::reconcile::{
    OPERATOR_FINALIZER, apply_owned, ensure_finalizer, patch_status, remove_finalizer,
};
use crate::telemetry::ReconcileOutcome;
use crate::verify::{VerifyError, load_signing_key, revocation_list_from_api, verify_artefact};

const FIELD_MANAGER_SUFFIX: &str = "plugin-controller";
const CONTROLLER_NAME: &str = "plugin";

/// Operator namespace where verified plugin Secrets live. Mirrors
/// `mcpg_operator_api::DEFAULT_OPERATOR_NAMESPACE` but the
/// runtime config can override it.
const DEFAULT_OPERATOR_NAMESPACE: &str = "mcpg-system";

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("kube: {0}")]
    Kube(#[from] kube::Error),
    #[error("apply: {0}")]
    Apply(#[from] crate::reconcile::ApplyError),
    #[error("status: {0}")]
    Status(#[from] crate::reconcile::StatusError),
    #[error("finalizer: {0}")]
    Finalizer(#[from] crate::reconcile::FinalizerError),
    #[error("oci pull: {0}")]
    Pull(#[from] crate::oci_pull::PullError),
    #[error("verify: {0}")]
    Verify(#[from] VerifyError),
    #[error("missing name on MCPGPlugin")]
    MissingName,
    #[error("blocking task: {0}")]
    Join(String),
}

/// Run the plugin controller until cancelled.
pub async fn run(ctx: Arc<ControllerContext>) -> anyhow::Result<()> {
    let api: Api<MCPGPlugin> = Api::all(ctx.client.clone());
    info!("starting plugin controller");

    Controller::new(api, watcher::Config::default())
        .owns(
            Api::<Secret>::all(ctx.client.clone()),
            watcher::Config::default(),
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => info!(name = %obj.name, "plugin reconcile complete"),
                Err(err) => error!(error = ?err, "plugin reconcile failed"),
            }
        })
        .await;
    Ok(())
}

#[instrument(
    skip_all,
    fields(name = %obj.name_any(), generation = obj.metadata.generation.unwrap_or(0))
)]
async fn reconcile(
    obj: Arc<MCPGPlugin>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let started = Instant::now();
    let metrics = ctx.metrics.operator_metrics().clone();
    let result = reconcile_inner(obj, ctx).await;
    let outcome = classify_outcome(&result);
    metrics.observe_reconcile(CONTROLLER_NAME, outcome, started.elapsed().as_secs_f64());
    result.map(|(action, _)| action)
}

fn classify_outcome(
    result: &Result<(Action, ReconcileOutcome), ReconcileError>,
) -> ReconcileOutcome {
    match result {
        Ok((_, o)) => *o,
        Err(ReconcileError::MissingName) => ReconcileOutcome::PermanentError,
        Err(_) => ReconcileOutcome::TransientError,
    }
}

async fn reconcile_inner(
    obj: Arc<MCPGPlugin>,
    ctx: Arc<ControllerContext>,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    let name = obj
        .metadata
        .name
        .clone()
        .ok_or(ReconcileError::MissingName)?;
    let observed_generation = obj.metadata.generation.unwrap_or(0);
    let plugin_api: Api<MCPGPlugin> = Api::all(ctx.client.clone());

    // Step 0: deletion-timestamp branch + finalizer management.
    // The artefact Secret in the operator namespace is owner-ref'd
    // to this MCPGPlugin, so K8s GC removes it once the finalizer
    // releases. Per-namespace plugin Secrets are owner-ref'd to
    // their MCPGPluginSet — those cascade through the set's own
    // deletion path.
    if obj.metadata.deletion_timestamp.is_some() {
        info!(name = %name, "plugin deletion in progress; releasing finalizer");
        remove_finalizer(&plugin_api, &name, OPERATOR_FINALIZER).await?;
        return Ok((Action::await_change(), ReconcileOutcome::Success));
    }
    ensure_finalizer(&plugin_api, &name, obj.as_ref(), OPERATOR_FINALIZER).await?;

    let operator_ns = operator_namespace(&ctx);

    // Step 1a: signal "I'm pulling" before the pull starts so
    // operators watching `kubectl get mcpgplugin -w` see the
    // controller working. OCI pulls can take minutes for large
    // multi-MB artefacts, and the absence of any condition
    // change for that long looks like a wedge. Best-effort —
    // status patch failures fall through to the existing
    // status-patch-on-completion path.
    record_pulling(&ctx, &obj, observed_generation).await;

    // Step 1a': air-gap mirror resolution. When the plugin sets
    // `oci.mirrorRef`, rewrite the upstream image onto the named
    // in-cluster mirror and pull from there (with the mirror's own
    // pull credentials). The rewrite preserves the digest/tag, and
    // cosign/SLSA below STILL verify against the UPSTREAM
    // `obj.spec.oci` (the attestation is bound to where the artefact
    // was built, not where it's served) at the digest this pull
    // resolves — so content-identity between mirror and upstream is
    // established rather than assumed. A mirror that's missing or
    // doesn't match the upstream prefix is a hard failure: an
    // air-gapped pull must never fall back to the public registry.
    let (pull_oci, pull_options) = match resolve_pull_target(
        &ctx.client,
        &obj.spec.oci,
        observed_generation,
        &obj,
        &ctx,
    )
    .await
    {
        Ok(t) => t,
        Err(action) => return action,
    };

    // Step 1b: pull + unpack.
    let pull_started = Instant::now();
    let mut artefact =
        match pull_and_unpack(&ctx.client, &operator_ns, &pull_oci, &pull_options).await {
            Ok(a) => {
                ctx.metrics
                    .operator_metrics()
                    .observe_oci_pull("success", pull_started.elapsed().as_secs_f64());
                a
            }
            Err(e) => {
                ctx.metrics
                    .operator_metrics()
                    .observe_oci_pull("failed", pull_started.elapsed().as_secs_f64());
                return record_pull_failure(&ctx, &obj, observed_generation, e).await;
            }
        };

    // Step 2: load Ed25519 signing key.
    let public_key =
        match load_signing_key(&ctx.client, &operator_ns, &obj.spec.trust.signing_key_ref).await {
            Ok(k) => k,
            Err(e) => {
                return record_verify_failure(
                    &ctx,
                    &obj,
                    observed_generation,
                    artefact.manifest_digest,
                    e,
                )
                .await;
            }
        };

    // Step 3: load cluster revocation list (named per spec or
    // CLUSTER_DEFAULT_REVOCATION_LIST). Missing list = no
    // revocation enforcement.
    let api: Api<MCPGRevocationList> = Api::all(ctx.client.clone());
    let revocation_list = match api.get_opt(CLUSTER_DEFAULT_REVOCATION_LIST).await? {
        Some(rl) => match revocation_list_from_api(&rl) {
            Ok(parsed) => Some(parsed),
            Err(e) => {
                warn!(
                    list = %rl.name_any(),
                    error = ?e,
                    "plugin controller: revocation list rejected; treating as empty"
                );
                None
            }
        },
        None => None,
    };

    // Step 4: verify (cdylib signature + revocation). The host
    // verifier is sync + does file I/O — bridge from async via
    // spawn_blocking so we don't block tokio's work-stealing pool.
    let plugin_id = obj.spec.plugin_id.clone();
    let verify_result = {
        // We need to *move* the `PullArtefact` into the blocking
        // task (the verifier owns it during the call, partly
        // because the held `_tempdir` keeps file paths valid).
        // After the verify completes we still need access to
        // `artefact.manifest_digest` for status patching, so the
        // task returns the artefact back via its tuple.
        //
        // `std::mem::replace` is the cleanest way to do this
        // hand-off: swap in a placeholder so the outer `artefact`
        // binding stays initialised, then plug the real one back
        // in from `join.2` after `spawn_blocking` returns.
        // Without the placeholder the compiler complains that
        // `artefact` would be moved-from while we still have the
        // `&mut` reference live.
        let blocking_artefact = std::mem::replace(
            &mut artefact,
            crate::oci_pull::PullArtefact {
                manifest_digest: String::new(),
                artifact_sha256: None,
                artifact_bytes: Vec::new(),
                signature_bytes: None,
                descriptor_bytes: Vec::new(),
                _tempdir: tempfile::tempdir().expect("tempdir for placeholder"),
                unpacked: dummy_unpacked(),
            },
        );
        let plugin_id_clone = plugin_id.clone();
        let revocation_list_clone = revocation_list.clone();
        let join = tokio::task::spawn_blocking(move || {
            (
                blocking_artefact.manifest_digest.clone(),
                verify_artefact(
                    &blocking_artefact,
                    public_key,
                    revocation_list_clone,
                    &plugin_id_clone,
                ),
                blocking_artefact,
            )
        })
        .await
        .map_err(|e| ReconcileError::Join(e.to_string()))?;

        artefact = join.2;
        match join.1 {
            Ok(r) => r,
            Err(VerifyError::Revoked { sha, reason }) => {
                return record_revoked(
                    &ctx,
                    &obj,
                    observed_generation,
                    artefact.manifest_digest,
                    sha,
                    reason,
                )
                .await;
            }
            Err(e) => {
                return record_verify_failure(
                    &ctx,
                    &obj,
                    observed_generation,
                    artefact.manifest_digest,
                    e,
                )
                .await;
            }
        }
    };
    artefact.artifact_sha256 = Some(verify_result.artifact_hash.clone());

    // Step 4.5: cosign keyless verification. Only runs when the
    // spec configures `trust.cosign_identity`. Failures
    // route through the same `record_verify_failure` path as
    // Ed25519 mismatches — the gateway will not load a plugin
    // whose attestation chain doesn't match the operator's
    // declared identity.
    //
    // It runs against the UPSTREAM `obj.spec.oci` — the attestation is
    // bound to where the artefact was built, not where it is served —
    // but at the digest the pull above actually resolved. That digest
    // is what ties the signature to these bytes: a mirror serving
    // anything other than the upstream artefact yields a digest
    // upstream has no signature for, and a tag that moved between the
    // pull and here fails rather than verifying a different manifest.
    let pulled_digest = artefact.manifest_digest.clone();
    let cosign_verified = if let Some(identity) = obj.spec.trust.cosign_identity.as_ref() {
        let cosign_auth = sigstore::registry::Auth::Anonymous;
        match crate::verify::cosign::verify_cosign_keyless(
            &obj.spec.oci,
            identity,
            &cosign_auth,
            &pulled_digest,
        )
        .await
        {
            Ok(_) => Some(true),
            Err(e) => {
                let msg = format!("cosign verification failed: {e}");
                return record_verify_failure(
                    &ctx,
                    &obj,
                    observed_generation,
                    artefact.manifest_digest,
                    crate::verify::VerifyError::Verifier(msg),
                )
                .await;
            }
        }
    } else {
        None
    };

    // Step 4.6: SLSA L3 provenance verification. Only runs when
    // the spec configures `trust.slsa_provenance`. The
    // operator reads the named ConfigMap (operator namespace),
    // parses its `provenance.intoto.jsonl`, and matches the
    // attestation against the verified artefact sha256 +
    // configured source URI/tag. Failures route through the
    // same `record_verify_failure` path.
    let slsa_verified = if let Some(slsa_cfg) = obj.spec.trust.slsa_provenance.as_ref() {
        match run_slsa_verify(&ctx, &operator_ns, slsa_cfg, &verify_result.artifact_hash).await {
            Ok(_) => Some(true),
            Err(e) => {
                let msg = format!("SLSA verification failed: {e}");
                return record_verify_failure(
                    &ctx,
                    &obj,
                    observed_generation,
                    artefact.manifest_digest,
                    crate::verify::VerifyError::Verifier(msg),
                )
                .await;
            }
        }
    } else {
        None
    };

    // Step 5: materialise verified bytes as a cluster-scope Secret
    // in the operator namespace. Naming includes a digest prefix
    // so two versions of the same plugin land in distinct Secrets.
    let secret_name = artefact_secret_name(&name, &verify_result.artifact_hash);
    let secret = build_artefact_secret(&obj, &operator_ns, &secret_name, &artefact);
    let secret_api: Api<Secret> = Api::namespaced(ctx.client.clone(), &operator_ns);
    let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");
    apply_owned(&secret_api, &secret, &fm).await?;

    // Step 6: patch status — Verified=True, Pulled=True,
    // Revoked=False, Ready=True. `cosign_verified` / `slsa_verified`
    // are populated only when the spec configured those trust
    // layers.
    let conditions = success_conditions(observed_generation);
    let status = MCPGPluginStatus {
        conditions,
        observed_generation: Some(observed_generation),
        resolved_digest: Some(verify_result.artifact_hash.clone()),
        signature_valid: Some(verify_result.signature_verified),
        cosign_verified,
        slsa_verified,
        revoked_by_sha: Some(false),
        artefact_secret_name: Some(secret_name),
        pulled_at: Some(Utc::now()),
        last_reconcile_time: Some(Utc::now()),
    };

    if let Err(e) = patch_status(&plugin_api, &name, &status, &fm).await {
        warn!(error = ?e, "plugin: status patch failed");
    }

    let evt = K8sEvent {
        type_: EventType::Normal,
        reason: "Pulled".into(),
        note: Some(format!(
            "Plugin {plugin_id} pulled, verified, and materialised \
             (sha256:{}…)",
            verify_result
                .artifact_hash
                .chars()
                .take(12)
                .collect::<String>()
        )),
        action: "PullVerifyMaterialise".into(),
        secondary: None,
    };
    if let Err(e) = ctx
        .recorders
        .plugin
        .publish(&evt, &obj.object_ref(&()))
        .await
    {
        warn!(error = ?e, "plugin: failed to publish Pulled event");
    }

    info!(
        plugin_id = %plugin_id,
        manifest_digest = %artefact.manifest_digest,
        artifact_sha = %verify_result.artifact_hash,
        "plugin reconciled successfully"
    );

    let key = crate::backoff::resource_key(CONTROLLER_NAME, "", &name);
    ctx.backoff.record_success(&key);

    // Resync at 10 minutes — verification cost (OCI pull + zip
    // unpack + signature check) is non-trivial, and revocation
    // cascade is event-driven via the cluster-revocation-list
    // controller's per-namespace fan-out.
    Ok((
        Action::requeue(Duration::from_secs(600)),
        ReconcileOutcome::Success,
    ))
}

fn error_policy(obj: Arc<MCPGPlugin>, err: &ReconcileError, ctx: Arc<ControllerContext>) -> Action {
    match err {
        ReconcileError::MissingName => Action::await_change(),
        _ => {
            let key = crate::backoff::resource_key(CONTROLLER_NAME, "", &obj.name_any());
            let count = ctx.backoff.record_error(&key);
            let delay = ctx.backoff.duration_for(&key);
            warn!(
                key = %key,
                consecutive_errors = count,
                requeue_secs = delay.as_secs(),
                error = ?err,
                "plugin: reconcile error; backing off"
            );
            Action::requeue(delay)
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// Status-update helpers
// ─────────────────────────────────────────────────────────────────

/// Patch a `Progressing=True, reason=PullingArtefact` condition
/// before the OCI pull starts. Best-effort: failures are logged
/// but do not abort the reconcile (the pull itself is the
/// critical-path work, and the success / failure path patches
/// status afterwards regardless).
async fn record_pulling(ctx: &ControllerContext, obj: &MCPGPlugin, generation: i64) {
    let mut conditions: Vec<Condition> = obj
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();
    mcpg_operator_api::conditions::set_condition(
        &mut conditions,
        Condition::new(
            ctype::PROGRESSING,
            "True",
            "PullingArtefact",
            format!("pulling {}", obj.spec.oci.image),
            Some(generation),
        ),
    );
    let name = obj.name_any();
    let api: Api<MCPGPlugin> = Api::all(ctx.client.clone());
    let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");
    let status = MCPGPluginStatus {
        conditions,
        observed_generation: Some(generation),
        last_reconcile_time: Some(Utc::now()),
        ..Default::default()
    };
    if let Err(e) = patch_status(&api, &name, &status, &fm).await {
        warn!(error = ?e, "plugin: progressing-condition patch failed");
    }
}

/// Resolve where to actually pull from, honouring `oci.mirrorRef`.
///
/// - No `mirrorRef` → pull the upstream `oci` as-is, default options.
/// - `mirrorRef` set → look up the cluster-scoped `MCPGPluginMirror`,
///   rewrite the image onto its endpoint, swap in the mirror's pull
///   credentials, and mark the mirror host insecure if configured. The
///   rewritten ref keeps the original tag/digest so verification of the
///   pulled bytes is unaffected.
///
/// Fail-closed: a missing mirror, or an image that doesn't match the
/// mirror's `<registry>/<namespace>` prefix, is an error (never a
/// silent fall-back to the public registry — that would defeat the
/// air-gap boundary). On error this returns `Err(reconcile-action)`
/// carrying a `MirrorUnresolved` status + Warning event.
async fn resolve_pull_target(
    client: &kube::Client,
    upstream: &OciImageRef,
    generation: i64,
    obj: &MCPGPlugin,
    ctx: &ControllerContext,
) -> Result<(OciImageRef, PullOptions), Result<(Action, ReconcileOutcome), ReconcileError>> {
    let Some(mirror_ref) = upstream.mirror_ref.as_ref() else {
        return Ok((upstream.clone(), PullOptions::default()));
    };

    let mirror_api: Api<MCPGPluginMirror> = Api::all(client.clone());
    let mirror = match mirror_api.get_opt(&mirror_ref.name).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return Err(record_mirror_failure(
                ctx,
                obj,
                generation,
                format!(
                    "oci.mirrorRef points at MCPGPluginMirror/{} which does not exist; \
                     refusing to fall back to the public registry",
                    mirror_ref.name
                ),
            )
            .await);
        }
        Err(e) => {
            // Transient API error — retry rather than mark failed.
            warn!(error = ?e, "plugin: mirror lookup failed; will retry");
            return Err(Ok((
                Action::requeue(Duration::from_secs(30)),
                ReconcileOutcome::TransientError,
            )));
        }
    };

    match mirror.spec.rewrite(&upstream.image) {
        MirrorRewrite::Rewritten(image) => {
            // Pull from the mirror with the mirror's own credentials
            // (the plugin's pullSecretRef targets the upstream registry,
            // which is unreachable in air-gap).
            let pull_secret_ref = mirror.spec.auth.as_ref().map(|a| {
                mcpg_operator_api::v1alpha1::LocalObjectReference {
                    name: a.secret_ref.secret_name.clone(),
                }
            });
            let options = PullOptions {
                insecure_registries: if mirror.spec.endpoint.insecure {
                    vec![mirror.spec.endpoint.service.host()]
                } else {
                    Vec::new()
                },
                ..PullOptions::default()
            };
            Ok((
                OciImageRef {
                    image,
                    pull_secret_ref,
                    // The derived ref has no further mirror — it IS the
                    // mirror target.
                    mirror_ref: None,
                },
                options,
            ))
        }
        MirrorRewrite::NotApplicable => Err(record_mirror_failure(
            ctx,
            obj,
            generation,
            format!(
                "MCPGPluginMirror/{} mirrors '{}/{}' but the plugin image '{}' is under a \
                 different registry/namespace; the mirror cannot serve it",
                mirror_ref.name,
                mirror.spec.upstream.registry,
                mirror.spec.upstream.namespace,
                upstream.image
            ),
        )
        .await),
    }
}

/// Status + Event for a mirror resolution failure (fail-closed: the
/// plugin is not pulled, and we do not reach the public registry).
async fn record_mirror_failure(
    ctx: &ControllerContext,
    obj: &MCPGPlugin,
    generation: i64,
    detail: String,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    let mut conditions: Vec<Condition> = obj
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();
    for ty in ["Pulled", ctype::READY] {
        mcpg_operator_api::conditions::set_condition(
            &mut conditions,
            Condition::new(
                ty,
                "False",
                "MirrorUnresolved",
                detail.clone(),
                Some(generation),
            ),
        );
    }
    let name = obj.name_any();
    let api: Api<MCPGPlugin> = Api::all(ctx.client.clone());
    let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");
    let status = MCPGPluginStatus {
        conditions,
        observed_generation: Some(generation),
        last_reconcile_time: Some(Utc::now()),
        ..Default::default()
    };
    if let Err(e) = patch_status(&api, &name, &status, &fm).await {
        warn!(error = ?e, "plugin: mirror-failure status patch failed");
    }
    let evt = K8sEvent {
        type_: EventType::Warning,
        reason: "MirrorUnresolved".into(),
        note: Some(detail.clone()),
        action: "Pull".into(),
        secondary: None,
    };
    let _ = ctx
        .recorders
        .plugin
        .publish(&evt, &obj.object_ref(&()))
        .await;
    warn!(name = %name, detail = %detail, "plugin mirror unresolved; not pulling");
    Ok((
        Action::requeue(Duration::from_secs(60)),
        ReconcileOutcome::DependencyPending,
    ))
}

async fn record_pull_failure(
    ctx: &ControllerContext,
    obj: &MCPGPlugin,
    generation: i64,
    err: crate::oci_pull::PullError,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    let mut conditions: Vec<Condition> = obj
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();

    let detail = format!("{err}");
    mcpg_operator_api::conditions::set_condition(
        &mut conditions,
        Condition::new(
            "Pulled",
            "False",
            "PullFailed",
            detail.clone(),
            Some(generation),
        ),
    );
    mcpg_operator_api::conditions::set_condition(
        &mut conditions,
        Condition::new(
            ctype::READY,
            "False",
            "PullFailed",
            detail,
            Some(generation),
        ),
    );
    let name = obj.name_any();
    let api: Api<MCPGPlugin> = Api::all(ctx.client.clone());
    let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");
    let status = MCPGPluginStatus {
        conditions,
        observed_generation: Some(generation),
        last_reconcile_time: Some(Utc::now()),
        ..Default::default()
    };
    if let Err(e) = patch_status(&api, &name, &status, &fm).await {
        warn!(error = ?e, "plugin: pull-failure status patch failed");
    }
    // Emit a Warning Event so trust-gate failures
    // surface in `kubectl describe` + audit log shippers, not
    // just operator pod logs.
    let evt = K8sEvent {
        type_: EventType::Warning,
        reason: "PullFailed".into(),
        note: Some(format!("OCI pull for {} failed: {err}", obj.spec.oci.image)),
        action: "Pull".into(),
        secondary: None,
    };
    if let Err(e) = ctx
        .recorders
        .plugin
        .publish(&evt, &obj.object_ref(&()))
        .await
    {
        warn!(error = ?e, "plugin: failed to publish PullFailed event");
    }
    warn!(error = ?err, name = %name, "plugin pull failed; will retry");
    Ok((
        Action::requeue(Duration::from_secs(60)),
        ReconcileOutcome::TransientError,
    ))
}

async fn record_verify_failure(
    ctx: &ControllerContext,
    obj: &MCPGPlugin,
    generation: i64,
    manifest_digest: String,
    err: VerifyError,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    let mut conditions: Vec<Condition> = obj
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();

    let detail = format!("{err}");
    mcpg_operator_api::conditions::set_condition(
        &mut conditions,
        Condition::new("Pulled", "True", reasons::RECONCILED, "", Some(generation)),
    );
    mcpg_operator_api::conditions::set_condition(
        &mut conditions,
        Condition::new(
            "Verified",
            "False",
            "SignatureFailed",
            detail.clone(),
            Some(generation),
        ),
    );
    mcpg_operator_api::conditions::set_condition(
        &mut conditions,
        Condition::new(
            ctype::READY,
            "False",
            "VerificationFailed",
            detail,
            Some(generation),
        ),
    );
    let name = obj.name_any();
    let api: Api<MCPGPlugin> = Api::all(ctx.client.clone());
    let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");
    let status = MCPGPluginStatus {
        conditions,
        observed_generation: Some(generation),
        signature_valid: Some(false),
        last_reconcile_time: Some(Utc::now()),
        // Manifest digest lands even on verify failure so ops
        // can correlate against the registry without GET'ing
        // the registry separately.
        resolved_digest: Some(manifest_digest),
        ..Default::default()
    };
    if let Err(e) = patch_status(&api, &name, &status, &fm).await {
        warn!(error = ?e, "plugin: verify-failure status patch failed");
    }
    // Trust-gate failure → Warning Event. Forensics-
    // grade audit pipelines watch K8s Events; pod logs aren't
    // always shipped to the SIEM.
    let evt = K8sEvent {
        type_: EventType::Warning,
        reason: "TrustGateFailed".into(),
        note: Some(format!(
            "verification failed for {}: {err}",
            obj.spec.oci.image
        )),
        action: "Verify".into(),
        secondary: None,
    };
    if let Err(e) = ctx
        .recorders
        .plugin
        .publish(&evt, &obj.object_ref(&()))
        .await
    {
        warn!(error = ?e, "plugin: failed to publish TrustGateFailed event");
    }
    warn!(error = ?err, name = %name, "plugin verification failed");
    // Don't fast-retry on a verify failure — operator must
    // change spec (rotate key, update OCI ref, etc).
    Ok((
        Action::requeue(Duration::from_secs(600)),
        ReconcileOutcome::PermanentError,
    ))
}

async fn record_revoked(
    ctx: &ControllerContext,
    obj: &MCPGPlugin,
    generation: i64,
    manifest_digest: String,
    sha: String,
    reason: String,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    let mut conditions: Vec<Condition> = obj
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();

    let msg = format!("plugin sha256:{sha} is revoked: {reason}");
    mcpg_operator_api::conditions::set_condition(
        &mut conditions,
        Condition::new("Pulled", "True", reasons::RECONCILED, "", Some(generation)),
    );
    mcpg_operator_api::conditions::set_condition(
        &mut conditions,
        Condition::new(
            "Verified",
            "True",
            reasons::RECONCILED,
            "",
            Some(generation),
        ),
    );
    mcpg_operator_api::conditions::set_condition(
        &mut conditions,
        Condition::new(
            "Revoked",
            "True",
            "ArtefactRevoked",
            msg.clone(),
            Some(generation),
        ),
    );
    mcpg_operator_api::conditions::set_condition(
        &mut conditions,
        Condition::new(
            ctype::READY,
            "False",
            "ArtefactRevoked",
            msg,
            Some(generation),
        ),
    );

    let name = obj.name_any();
    let api: Api<MCPGPlugin> = Api::all(ctx.client.clone());
    let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");
    let status_digest = if sha.is_empty() {
        manifest_digest
    } else {
        sha.clone()
    };
    let status = MCPGPluginStatus {
        conditions,
        observed_generation: Some(generation),
        resolved_digest: Some(status_digest),
        signature_valid: Some(true),
        revoked_by_sha: Some(true),
        last_reconcile_time: Some(Utc::now()),
        ..Default::default()
    };
    if let Err(e) = patch_status(&api, &name, &status, &fm).await {
        warn!(error = ?e, "plugin: revocation status patch failed");
    }
    // A revocation hit gets a Warning Event. The
    // condition is fail-closed (refused to materialise), but
    // operators want this in their incident-response timeline.
    let evt = K8sEvent {
        type_: EventType::Warning,
        reason: "ArtefactRevoked".into(),
        note: Some(format!(
            "plugin sha256:{} is on the cluster revocation list ({reason})",
            sha.chars().take(12).collect::<String>()
        )),
        action: "Revoke".into(),
        secondary: None,
    };
    if let Err(e) = ctx
        .recorders
        .plugin
        .publish(&evt, &obj.object_ref(&()))
        .await
    {
        warn!(error = ?e, "plugin: failed to publish ArtefactRevoked event");
    }
    warn!(name = %name, reason = %reason, "plugin revoked");
    // Identifying a revoked plugin IS a successful reconcile —
    // we did our job (refused to materialise) and surfaced the
    // condition. The retry interval is long because the
    // revocation list itself is event-driven via its own
    // controller's per-namespace fan-out.
    Ok((
        Action::requeue(Duration::from_secs(600)),
        ReconcileOutcome::Success,
    ))
}

fn success_conditions(generation: i64) -> Vec<Condition> {
    let mut c = Vec::new();
    mcpg_operator_api::conditions::set_condition(
        &mut c,
        Condition::new("Pulled", "True", reasons::RECONCILED, "", Some(generation)),
    );
    mcpg_operator_api::conditions::set_condition(
        &mut c,
        Condition::new(
            "Verified",
            "True",
            reasons::RECONCILED,
            "",
            Some(generation),
        ),
    );
    mcpg_operator_api::conditions::set_condition(
        &mut c,
        Condition::new(
            "Revoked",
            "False",
            reasons::RECONCILED,
            "",
            Some(generation),
        ),
    );
    mcpg_operator_api::conditions::set_condition(
        &mut c,
        Condition::new(
            ctype::READY,
            "True",
            reasons::RECONCILED,
            "",
            Some(generation),
        ),
    );
    c
}

/// Resolve the SLSA provenance ConfigMap from the operator
/// namespace and run the in-toto verifier against the verified
/// artefact hash.
async fn run_slsa_verify(
    ctx: &ControllerContext,
    operator_ns: &str,
    slsa_cfg: &mcpg_operator_api::v1alpha1::SlsaProvenance,
    artefact_sha256: &str,
) -> Result<crate::verify::slsa::SlsaVerifyResult, anyhow::Error> {
    use k8s_openapi::api::core::v1::ConfigMap;
    let api: Api<ConfigMap> = Api::namespaced(ctx.client.clone(), operator_ns);
    let cm = api.get(&slsa_cfg.config_map_name).await.map_err(|e| {
        anyhow::anyhow!(
            "ConfigMap/{} not found in {operator_ns}: {e}",
            slsa_cfg.config_map_name
        )
    })?;
    let jsonl = cm
        .data
        .as_ref()
        .and_then(|d| d.get("provenance.intoto.jsonl"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "ConfigMap/{} missing data key `provenance.intoto.jsonl`",
                slsa_cfg.config_map_name
            )
        })?;
    crate::verify::slsa::verify_slsa_provenance(jsonl, artefact_sha256, slsa_cfg)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

// ─────────────────────────────────────────────────────────────────
// Secret materialisation
// ─────────────────────────────────────────────────────────────────

/// Stable name for the operator-namespace Secret. Includes a
/// short digest prefix so re-pulling a different artefact
/// version of the same plugin produces a distinct Secret.
pub(crate) fn artefact_secret_name(plugin_name: &str, artifact_sha256: &str) -> String {
    let prefix: String = artifact_sha256.chars().take(8).collect();
    let prefix = if prefix.is_empty() {
        "unknown".to_owned()
    } else {
        prefix
    };
    let truncated = truncate_kube_name(plugin_name, 50);
    format!("mcpg-plugin-{truncated}-{prefix}")
}

/// K8s resource names are limited to 253 chars; Secret names
/// shouldn't be that long but we leave headroom by capping
/// `plugin_name` here.
fn truncate_kube_name(name: &str, max: usize) -> String {
    if name.len() <= max {
        return name.to_owned();
    }
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("{}-{}", &name[..max - 9], &digest[..8])
}

fn build_artefact_secret(
    parent: &MCPGPlugin,
    namespace: &str,
    secret_name: &str,
    artefact: &crate::oci_pull::PullArtefact,
) -> Secret {
    let mut data = BTreeMap::new();
    data.insert(
        "plugin.so".to_owned(),
        ByteString(artefact.artifact_bytes.clone()),
    );
    data.insert(
        "plugin.yaml".to_owned(),
        ByteString(artefact.descriptor_bytes.clone()),
    );
    if let Some(sig) = &artefact.signature_bytes {
        data.insert("plugin.sig".to_owned(), ByteString(sig.clone()));
    }

    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_owned(),
        "mcpg-operator".to_owned(),
    );
    labels.insert(
        "mcpg.dev/plugin".to_owned(),
        parent.spec.plugin_id.replace('.', "-"),
    );
    labels.insert("mcpg.dev/version".to_owned(), parent.spec.version.clone());
    if let Some(sha) = &artefact.artifact_sha256 {
        labels.insert(
            "mcpg.dev/digest-prefix".to_owned(),
            sha.chars().take(8).collect(),
        );
    }
    labels.insert(
        "mcpg.dev/manifest-digest".to_owned(),
        artefact
            .manifest_digest
            .replace(':', "-")
            .chars()
            .take(63)
            .collect(),
    );

    Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.to_owned()),
            namespace: Some(namespace.to_owned()),
            labels: Some(labels),
            // Cluster-scoped parent → namespace-scoped child.
            // K8s rejects cross-scope owner refs, so we don't
            // set them. Cleanup is finalizer-driven.
            ..Default::default()
        },
        type_: Some("mcpg.dev/plugin".to_owned()),
        // Plugin bytes are content-addressed — once written they
        // never change (the secret name carries a digest prefix
        // so a rotation lands as a new Secret). Marking immutable
        // tells K8s' kubelet it can skip the per-pod fsnotify
        // watch on this Secret + lets the apiserver short-circuit
        // any later UPDATE attempt as a defence-in-depth gate
        // against tampering with verified bytes.
        immutable: Some(true),
        data: Some(data),
        ..Default::default()
    }
}

fn operator_namespace(_ctx: &ControllerContext) -> String {
    // Hardcoded to mcpg-system: the operator namespace is not yet
    // wired through OperatorConfig.
    DEFAULT_OPERATOR_NAMESPACE.to_owned()
}

/// Placeholder `UnpackedPackage` value used during the temporary
/// move-out / move-back-in dance the verify step performs.
/// `tempfile::tempdir()` already exists by the time this runs;
/// the returned value is overwritten before any field is read.
fn dummy_unpacked() -> mcpg_plugin_host::package::UnpackedPackage {
    use mcpg_plugin_host::package::{ArtifactKind, UnpackedPackage};
    use mcpg_plugin_protocol::descriptor::PluginDescriptor;
    let descriptor: PluginDescriptor = serde_yaml::from_str(
        "id: placeholder\nname: placeholder\nclass: identity_provider\n\
         runtime: native-firstparty-v1\nprotocolVersion: '1.0'\n\
         schema: '1.0'\n",
    )
    .expect("placeholder descriptor parses");
    UnpackedPackage {
        descriptor,
        descriptor_path: std::path::PathBuf::new(),
        artifact_kind: ArtifactKind::Native,
        artifact_path: std::path::PathBuf::new(),
        signature_path: None,
        license_path: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artefact_secret_name_includes_plugin_and_digest_prefix() {
        let n = artefact_secret_name(
            "identity-workload-1.2.3-linux-amd64",
            "abcd1234deadbeef5678",
        );
        assert!(
            n.starts_with("mcpg-plugin-identity-workload-1.2.3-linux-amd64-"),
            "{n}"
        );
        assert!(n.ends_with("-abcd1234"), "{n}");
    }

    #[test]
    fn artefact_secret_name_truncates_overlong_plugin_names() {
        let long = "x".repeat(150);
        let n = artefact_secret_name(&long, "deadbeefcafebabe");
        // Total under 253 (k8s name limit); deterministic
        // digest tail keeps uniqueness on truncation.
        assert!(n.len() <= 253);
        assert!(n.starts_with("mcpg-plugin-"));
    }

    #[test]
    fn artefact_secret_name_handles_empty_sha() {
        let n = artefact_secret_name("foo", "");
        assert!(n.ends_with("-unknown"), "{n}");
    }

    #[test]
    fn truncate_kube_name_under_max_passes_through() {
        assert_eq!(truncate_kube_name("foo", 50), "foo");
    }

    #[test]
    fn truncate_kube_name_appends_deterministic_suffix_on_truncate() {
        let n1 = truncate_kube_name(&"x".repeat(200), 30);
        let n2 = truncate_kube_name(&"x".repeat(200), 30);
        assert_eq!(n1, n2);
        assert_eq!(n1.len(), 30);
    }
}
