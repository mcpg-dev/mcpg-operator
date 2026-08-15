//! `MCPGServer` controller — provisions an MCP server workload
//! (Deployment + Service) and reports whether it is federable.
//!
//! The federation itself is consumed gateway-side: the gateway
//! controller resolves every same-namespace `MCPGServer` whose
//! `federate.gatewayRef` targets it and composes a `mcp.federations[]`
//! entry pointing at the rendered Service (see
//! `controllers::gateway::merge_servers`). This controller owns the
//! workload and the honest status:
//!
//! 1. `ImageVerified` — cosign keyless verification when `spec.verify`
//!    is set. Verification failure blocks (re)rendering the workload —
//!    fail-closed for new/changed specs, fail-static for an already
//!    running Deployment (a registry outage must not tear down a
//!    serving workload).
//! 2. `Ready` — the Deployment reports the requested replicas ready.
//! 3. `GatewayBound` — `federate.gatewayRef` resolves to an
//!    `MCPGGateway` in this namespace.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::Service;
use kube::api::Api;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::events::{Event as K8sEvent, EventType};
use kube::runtime::watcher;
use kube::{Resource, ResourceExt};
use mcpg_operator_api::conditions::{Condition, reasons, types as ctype};
use mcpg_operator_api::v1alpha1::{MCPGServer, MCPGServerStatus, OciImageRef};
use rand::Rng;
use tracing::{error, info, instrument};

use crate::FIELD_MANAGER_PREFIX;
use crate::controllers::gateway::ControllerContext;
use crate::reconcile::{
    OPERATOR_FINALIZER, apply_owned, ensure_finalizer, patch_status, remove_finalizer,
};
use crate::telemetry::ReconcileOutcome;
use crate::templates::{build_server_deployment, build_server_service, server_child_name};

const FIELD_MANAGER_SUFFIX: &str = "server-controller";
const CONTROLLER_NAME: &str = "server";

mod cond_types {
    pub const IMAGE_VERIFIED: &str = "ImageVerified";
    pub const GATEWAY_BOUND: &str = "GatewayBound";
}

mod server_reason {
    pub const BOUND: &str = "GatewayBound";
    pub const GATEWAY_NOT_FOUND: &str = "GatewayNotFound";
    pub const NOT_FEDERATED: &str = "NotFederated";
    pub const VERIFIED: &str = "CosignVerified";
    pub const VERIFY_FAILED: &str = "CosignVerifyFailed";
    pub const DIGEST_REQUIRED: &str = "DigestPinRequired";
    pub const NOT_CONFIGURED: &str = "VerificationNotConfigured";
    pub const ROLLOUT_PENDING: &str = "RolloutPending";
    pub const RENDER_BLOCKED: &str = "RenderBlockedByVerification";
}

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("status: {0}")]
    Status(#[from] crate::reconcile::StatusError),
    #[error("finalizer: {0}")]
    Finalizer(#[from] crate::reconcile::FinalizerError),
    #[error("apply: {0}")]
    Apply(#[from] crate::reconcile::ApplyError),
    #[error("kube: {0}")]
    Kube(#[from] kube::Error),
    #[error("missing name on MCPGServer")]
    MissingName,
    #[error("missing namespace on MCPGServer/{name}")]
    MissingNamespace { name: String },
}

/// Run the server controller until cancelled. Owned Deployments feed
/// readiness back; a gateway change re-resolves `GatewayBound` on the
/// resync tick.
pub async fn run(ctx: Arc<ControllerContext>) -> anyhow::Result<()> {
    let api: Api<MCPGServer> = match ctx.config.watch_namespace.as_deref() {
        Some(ns) if !ns.is_empty() => Api::namespaced(ctx.client.clone(), ns),
        _ => Api::all(ctx.client.clone()),
    };

    info!("starting server controller");

    Controller::new(api, watcher::Config::default())
        .owns(
            Api::<Deployment>::all(ctx.client.clone()),
            watcher::Config::default(),
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => info!(name = %obj.name, "server reconciled"),
                Err(err) => error!(error = ?err, "server reconcile failed"),
            }
        })
        .await;

    Ok(())
}

#[instrument(
    skip_all,
    fields(
        namespace = %obj.namespace().unwrap_or_default(),
        name = %obj.name_any(),
        generation = obj.metadata.generation.unwrap_or(0)
    )
)]
async fn reconcile(
    obj: Arc<MCPGServer>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let started = Instant::now();
    let metrics = ctx.metrics.operator_metrics().clone();
    let result = reconcile_inner(obj, ctx).await;
    let outcome = match &result {
        Ok((_, o)) => *o,
        Err(ReconcileError::MissingName) | Err(ReconcileError::MissingNamespace { .. }) => {
            ReconcileOutcome::PermanentError
        }
        Err(_) => ReconcileOutcome::TransientError,
    };
    metrics.observe_reconcile(CONTROLLER_NAME, outcome, started.elapsed().as_secs_f64());
    result.map(|(action, _)| action)
}

async fn reconcile_inner(
    obj: Arc<MCPGServer>,
    ctx: Arc<ControllerContext>,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    let name = obj
        .metadata
        .name
        .clone()
        .ok_or(ReconcileError::MissingName)?;
    let ns = obj
        .namespace()
        .ok_or_else(|| ReconcileError::MissingNamespace { name: name.clone() })?;
    let observed_generation = obj.metadata.generation.unwrap_or(0);
    let server_api: Api<MCPGServer> = Api::namespaced(ctx.client.clone(), &ns);

    if obj.metadata.deletion_timestamp.is_some() {
        // Child Deployment/Service carry owner refs — K8s GC removes
        // them; the gateway controller drops the federation entry on
        // its next reconcile pass.
        info!(name = %name, "server deletion in progress; releasing finalizer");
        remove_finalizer(&server_api, &name, OPERATOR_FINALIZER).await?;
        return Ok((Action::await_change(), ReconcileOutcome::Success));
    }
    ensure_finalizer(&server_api, &name, obj.as_ref(), OPERATOR_FINALIZER).await?;

    let mut conditions = obj
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();

    // ── ImageVerified ──
    let (verified, verify_reason, verify_msg) = match obj.spec.verify.as_ref() {
        None => (
            true,
            server_reason::NOT_CONFIGURED,
            "spec.verify not set; image admitted without signature verification".to_owned(),
        ),
        Some(verify) => {
            if !obj.spec.image.contains("@sha256:") {
                (
                    false,
                    server_reason::DIGEST_REQUIRED,
                    "spec.verify requires a digest-pinned image (repo@sha256:…)".to_owned(),
                )
            } else {
                let image = OciImageRef {
                    image: obj.spec.image.clone(),
                    ..Default::default()
                };
                // The spec is digest-pinned (checked above), so that
                // digest is what verification binds to.
                let pinned = crate::oci_pull::digest_of(&obj.spec.image).unwrap_or_default();
                let auth = sigstore::registry::Auth::Anonymous;
                match crate::verify::cosign::verify_cosign_keyless(
                    &image,
                    &verify.cosign_identity,
                    &auth,
                    pinned,
                )
                .await
                {
                    Ok(_) => (
                        true,
                        server_reason::VERIFIED,
                        "cosign keyless signature verified".to_owned(),
                    ),
                    Err(e) => (
                        false,
                        server_reason::VERIFY_FAILED,
                        format!("cosign verification failed: {e}"),
                    ),
                }
            }
        }
    };
    set_cond(
        &mut conditions,
        cond_types::IMAGE_VERIFIED,
        verified,
        verify_reason,
        &verify_msg,
        observed_generation,
    );

    // Render + apply the workload only under a passing verification.
    // An existing Deployment stays as-is when verification degrades —
    // fail-static for the running fleet, fail-closed for changes.
    let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");
    let deploy_api: Api<Deployment> = Api::namespaced(ctx.client.clone(), &ns);
    if verified {
        let deployment = build_server_deployment(obj.as_ref());
        apply_owned(&deploy_api, &deployment, &fm).await?;
        let service = build_server_service(obj.as_ref());
        let svc_api: Api<Service> = Api::namespaced(ctx.client.clone(), &ns);
        apply_owned(&svc_api, &service, &fm).await?;
    }

    // ── Ready ── from the live Deployment's reported replicas.
    let child = server_child_name(obj.as_ref());
    let live = deploy_api.get_opt(&child).await?;
    let ready_replicas = live
        .as_ref()
        .and_then(|d| d.status.as_ref())
        .and_then(|s| s.ready_replicas)
        .unwrap_or(0);
    let desired = obj.spec.replicas();
    let (ready, ready_reason, ready_msg) = if !verified {
        (
            false,
            server_reason::RENDER_BLOCKED,
            format!("workload not (re)rendered: {verify_msg}"),
        )
    } else if ready_replicas >= desired {
        (
            true,
            reasons::RECONCILED,
            format!("{ready_replicas}/{desired} replicas ready"),
        )
    } else {
        (
            false,
            server_reason::ROLLOUT_PENDING,
            format!("{ready_replicas}/{desired} replicas ready"),
        )
    };
    set_cond(
        &mut conditions,
        ctype::READY,
        ready,
        ready_reason,
        &ready_msg,
        observed_generation,
    );

    // ── GatewayBound ── (only meaningful with `federate`).
    let mut bound_gateway = None;
    if let Some(federate) = obj.spec.federate.as_ref() {
        let gw_name = &federate.gateway_ref.name;
        let gw_api: Api<mcpg_operator_api::v1alpha1::MCPGGateway> =
            Api::namespaced(ctx.client.clone(), &ns);
        let exists = gw_api.get_opt(gw_name).await?.is_some();
        let (bound, reason, msg) = if exists {
            bound_gateway = Some(format!("{ns}/{gw_name}"));
            (
                true,
                server_reason::BOUND,
                format!("federated into MCPGGateway/{ns}/{gw_name}"),
            )
        } else {
            (
                false,
                server_reason::GATEWAY_NOT_FOUND,
                format!("MCPGGateway/{ns}/{gw_name} not found"),
            )
        };
        set_cond(
            &mut conditions,
            cond_types::GATEWAY_BOUND,
            bound,
            reason,
            &msg,
            observed_generation,
        );
        if !bound {
            let evt = K8sEvent {
                type_: EventType::Warning,
                reason: reason.to_owned(),
                note: Some(msg),
                action: "Bind".to_owned(),
                secondary: None,
            };
            let _ = ctx
                .recorders
                .server
                .publish(&evt, &obj.object_ref(&()))
                .await;
        }
    } else {
        set_cond(
            &mut conditions,
            cond_types::GATEWAY_BOUND,
            false,
            server_reason::NOT_FEDERATED,
            "spec.federate not set; the workload runs but no gateway imports it",
            observed_generation,
        );
    }

    let status = MCPGServerStatus {
        conditions,
        observed_generation: Some(observed_generation),
        ready_replicas: Some(ready_replicas),
        endpoint: Some(obj.spec.endpoint(&child, &ns)),
        bound_gateway,
        last_reconcile_time: Some(Utc::now()),
    };
    if let Err(e) = patch_status(&server_api, &name, &status, &fm).await {
        tracing::warn!(error = ?e, "server: status patch failed");
    }

    if !verified {
        let evt = K8sEvent {
            type_: EventType::Warning,
            reason: verify_reason.to_owned(),
            note: Some(verify_msg),
            action: "Verify".to_owned(),
            secondary: None,
        };
        let _ = ctx
            .recorders
            .server
            .publish(&evt, &obj.object_ref(&()))
            .await;
    }

    let requeue = Action::requeue(jittered_resync(ctx.config.resync_interval_secs));
    let outcome = if ready {
        ReconcileOutcome::Success
    } else {
        ReconcileOutcome::DependencyPending
    };
    Ok((requeue, outcome))
}

fn set_cond(
    conditions: &mut Vec<Condition>,
    type_: &str,
    ok: bool,
    reason: &str,
    message: &str,
    generation: i64,
) {
    mcpg_operator_api::conditions::set_condition(
        conditions,
        Condition::new(
            type_,
            if ok { "True" } else { "False" },
            reason,
            message.to_owned(),
            Some(generation),
        ),
    );
}

/// Periodic resync interval, jittered ±20%. Mirrors the gateway
/// controller's helper.
fn jittered_resync(base_secs: u64) -> Duration {
    let base = base_secs as f64;
    let jitter_factor = 0.8 + rand::thread_rng().gen_range(0.0..0.4);
    Duration::from_secs_f64(base * jitter_factor)
}

fn error_policy(
    _obj: Arc<MCPGServer>,
    err: &ReconcileError,
    _ctx: Arc<ControllerContext>,
) -> Action {
    match err {
        ReconcileError::MissingName | ReconcileError::MissingNamespace { .. } => {
            Action::await_change()
        }
        _ => Action::requeue(Duration::from_secs(10)),
    }
}
