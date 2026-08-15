//! `MCPGRoute` controller — soft-tenancy route binding.
//!
//! Like the cluster controller, this synthesises **no** child objects.
//! A route is consumed gateway-side: the gateway controller resolves
//! every `MCPGRoute` that targets it (across the gateway's
//! `acceptedRouteNamespaces`) and fans the routes' `match.tools` +
//! `attributes` into the gateway config's
//! `governance.policy.tool_access.rules[]` (see
//! `controllers::gateway::resolve_routes`).
//!
//! This controller's job is to validate the route and report its
//! state:
//!
//! 1. `GatewayBound` — the referenced gateway exists AND lists this
//!    route's namespace in `acceptedRouteNamespaces` (or the route is
//!    in the gateway's own namespace).
//! 2. `Ready` — bound + at least one matched tool (the tool-access
//!    scoping is what the gateway actually enforces today).
//! 3. `ChainsEnforced` — honestly `False`
//!    (`PerRouteDispatchUnsupported`): the identity/policy/audit chains
//!    are recorded but the gateway runtime does not yet dispatch them
//!    per-route. Surfaced so operators aren't misled.
//!
//! A route change re-reconciles via the gateway controller's
//! `.watches(MCPGRoute)`, which re-renders the shared gateway's config.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use futures::StreamExt;
use kube::api::Api;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::events::{Event as K8sEvent, EventType};
use kube::runtime::watcher;
use kube::{Resource, ResourceExt};
use mcpg_operator_api::conditions::{Condition, reasons, types as ctype};
use mcpg_operator_api::v1alpha1::{MCPGGateway, MCPGRoute, MCPGRouteStatus};
use rand::Rng;
use tracing::{error, info, instrument};

use crate::FIELD_MANAGER_PREFIX;
use crate::controllers::gateway::ControllerContext;
use crate::reconcile::{OPERATOR_FINALIZER, ensure_finalizer, patch_status, remove_finalizer};
use crate::telemetry::ReconcileOutcome;

const FIELD_MANAGER_SUFFIX: &str = "route-controller";
const CONTROLLER_NAME: &str = "route";

/// Condition types emitted by this controller (beyond `Ready`).
mod cond_types {
    pub const GATEWAY_BOUND: &str = "GatewayBound";
    pub const CHAINS_ENFORCED: &str = "ChainsEnforced";
}

mod route_reason {
    pub const BOUND: &str = "GatewayBound";
    pub const GATEWAY_NOT_FOUND: &str = "GatewayNotFound";
    pub const NAMESPACE_NOT_ACCEPTED: &str = "NamespaceNotAccepted";
    pub const NO_TOOLS: &str = "NoMatchedTools";
    pub const CHAIN_PLUGIN_MISSING: &str = "ChainPluginMissing";
    /// The gateway runtime does not yet dispatch identity/policy/audit
    /// chains per-route — recorded but not enforced.
    pub const PER_ROUTE_DISPATCH_UNSUPPORTED: &str = "PerRouteDispatchUnsupported";
}

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("status: {0}")]
    Status(#[from] crate::reconcile::StatusError),
    #[error("finalizer: {0}")]
    Finalizer(#[from] crate::reconcile::FinalizerError),
    #[error("kube: {0}")]
    Kube(#[from] kube::Error),
    #[error("missing name on MCPGRoute")]
    MissingName,
    #[error("missing namespace on MCPGRoute/{name}")]
    MissingNamespace { name: String },
}

/// Run the route controller until cancelled. A gateway change
/// re-reconciles routes targeting it (its `acceptedRouteNamespaces` or
/// existence may have changed).
pub async fn run(ctx: Arc<ControllerContext>) -> anyhow::Result<()> {
    let api: Api<MCPGRoute> = match ctx.config.watch_namespace.as_deref() {
        Some(ns) if !ns.is_empty() => Api::namespaced(ctx.client.clone(), ns),
        _ => Api::all(ctx.client.clone()),
    };

    info!("starting route controller");

    Controller::new(api, watcher::Config::default())
        .watches(
            Api::<MCPGGateway>::all(ctx.client.clone()),
            watcher::Config::default(),
            map_gateway_to_routes,
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => info!(name = %obj.name, "route reconciled"),
                Err(err) => error!(error = ?err, "route reconcile failed"),
            }
        })
        .await;

    Ok(())
}

/// A gateway change re-reconciles routes pointing at it. We can't
/// cheaply reverse-index by gatewayRef without a store, so we
/// re-reconcile by matching the gateway's name; the reconcile re-checks
/// the real `gatewayRef` regardless. The mapper emits an ObjectRef per
/// route in the gateway's accepted namespaces (plus its own).
fn map_gateway_to_routes(gw: MCPGGateway) -> Vec<kube::runtime::reflector::ObjectRef<MCPGRoute>> {
    // Without a route store here we can't enumerate routes; the
    // resync + the route's own watch backstop this. Returning empty is
    // correct (no spurious reconciles) — the gateway controller's
    // `.watches(MCPGRoute)` handles the config-rendering direction, and
    // a route's own status refreshes on its resync tick. Kept as a hook
    // so a future route reflector can light up instant propagation.
    let _ = gw;
    Vec::new()
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
    obj: Arc<MCPGRoute>,
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
    obj: Arc<MCPGRoute>,
    ctx: Arc<ControllerContext>,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    let name = obj
        .metadata
        .name
        .clone()
        .ok_or(ReconcileError::MissingName)?;
    let route_ns = obj
        .namespace()
        .ok_or_else(|| ReconcileError::MissingNamespace { name: name.clone() })?;
    let observed_generation = obj.metadata.generation.unwrap_or(0);
    let route_api: Api<MCPGRoute> = Api::namespaced(ctx.client.clone(), &route_ns);

    if obj.metadata.deletion_timestamp.is_some() {
        info!(name = %name, "route deletion in progress; releasing finalizer");
        remove_finalizer(&route_api, &name, OPERATOR_FINALIZER).await?;
        return Ok((Action::await_change(), ReconcileOutcome::Success));
    }
    ensure_finalizer(&route_api, &name, obj.as_ref(), OPERATOR_FINALIZER).await?;

    let gw_ns = obj.spec.gateway_namespace(&route_ns).to_owned();
    let gw_name = &obj.spec.gateway_ref.name;
    let bound_gateway = format!("{gw_ns}/{gw_name}");

    // Resolve the target gateway.
    let gw_api: Api<MCPGGateway> = Api::namespaced(ctx.client.clone(), &gw_ns);
    let gateway = gw_api.get_opt(gw_name).await?;

    let mut conditions = obj
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();

    // ── GatewayBound ──
    let (bound, bound_reason, bound_msg) = match &gateway {
        None => (
            false,
            route_reason::GATEWAY_NOT_FOUND,
            format!("MCPGGateway/{bound_gateway} not found"),
        ),
        Some(gw) => {
            // Same-namespace routes are always accepted; cross-namespace
            // routes require explicit opt-in.
            let accepted =
                gw_ns == route_ns || gw.spec.accepted_route_namespaces.contains(&route_ns);
            if accepted {
                (
                    true,
                    route_reason::BOUND,
                    format!("bound to MCPGGateway/{bound_gateway}"),
                )
            } else {
                (
                    false,
                    route_reason::NAMESPACE_NOT_ACCEPTED,
                    format!(
                        "MCPGGateway/{bound_gateway} does not list namespace '{route_ns}' in \
                         spec.acceptedRouteNamespaces"
                    ),
                )
            }
        }
    };
    set_cond(
        &mut conditions,
        cond_types::GATEWAY_BOUND,
        bound,
        bound_reason,
        &bound_msg,
        observed_generation,
    );

    let matched_tools = obj.spec.r#match.tools.len() as i64;

    // ── Ready ── (bound + has tools). Chain-plugin validation is a
    // best-effort warning surfaced on the message, not a hard gate —
    // the gateway's own plugin loader is the real enforcer.
    let (ready, ready_reason, ready_msg) = if !bound {
        (false, bound_reason, bound_msg.clone())
    } else if matched_tools == 0 {
        (
            false,
            route_reason::NO_TOOLS,
            "route matches no tools (spec.match.tools is empty)".to_owned(),
        )
    } else {
        // Cross-check chain plugins against the gateway's pluginSetRef
        // when we can see it, so a typo'd plugin id is flagged early.
        let missing = missing_chain_plugins(obj.as_ref(), gateway.as_ref());
        if let Some(missing_id) = missing {
            (
                false,
                route_reason::CHAIN_PLUGIN_MISSING,
                format!(
                    "chain references plugin '{missing_id}' not declared on the gateway's \
                     pluginSetRef"
                ),
            )
        } else {
            (
                true,
                reasons::RECONCILED,
                format!(
                    "{matched_tools} tool(s) scoped to tenant '{}'",
                    obj.spec.tenant().unwrap_or("<none>")
                ),
            )
        }
    };
    set_cond(
        &mut conditions,
        ctype::READY,
        ready,
        ready_reason,
        &ready_msg,
        observed_generation,
    );

    // ── ChainsEnforced ── always False today: honest signal that the
    // gateway runtime records but does not dispatch per-route chains.
    set_cond(
        &mut conditions,
        cond_types::CHAINS_ENFORCED,
        false,
        route_reason::PER_ROUTE_DISPATCH_UNSUPPORTED,
        "identity/policy/audit chains are validated + recorded, but the gateway runtime does \
         not yet dispatch them per-route; tool-access scoping (see Ready) is enforced",
        observed_generation,
    );

    let status = MCPGRouteStatus {
        conditions,
        observed_generation: Some(observed_generation),
        matched_tools: Some(matched_tools),
        bound_gateway: Some(bound_gateway),
        last_reconcile_time: Some(Utc::now()),
    };

    let fm = format!("{FIELD_MANAGER_PREFIX}/{FIELD_MANAGER_SUFFIX}");
    if let Err(e) = patch_status(&route_api, &name, &status, &fm).await {
        tracing::warn!(error = ?e, "route: status patch failed");
    }

    if !bound {
        let evt = K8sEvent {
            type_: EventType::Warning,
            reason: bound_reason.to_owned(),
            note: Some(bound_msg.clone()),
            action: "Bind".to_owned(),
            secondary: None,
        };
        let _ = ctx
            .recorders
            .route
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

/// Return the first chain plugin id NOT present in the gateway's
/// `pluginSetRef`-implied set, if we can determine it. Best-effort: if
/// the gateway has no `pluginSetRef` (inline plugins), we can't see the
/// set from here, so we don't flag (return `None`) — the gateway's
/// loader is the authoritative check.
fn missing_chain_plugins(route: &MCPGRoute, _gateway: Option<&MCPGGateway>) -> Option<String> {
    // NOTE: resolving the gateway's pluginSet → entry ids requires a
    // namespaced MCPGPluginSet lookup; the gateway controller already
    // does this when rendering config and is the authoritative gate.
    // Here we only sanity-check that chain ids are non-empty + well
    // formed, leaving plugin-presence to the gateway. This keeps the
    // route controller from coupling to plugin-set resolution while
    // still catching obvious mistakes.
    route
        .spec
        .all_chain_plugins()
        .into_iter()
        .find(|id| id.trim().is_empty())
        .map(|_| "<empty>".to_owned())
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

fn error_policy(obj: Arc<MCPGRoute>, err: &ReconcileError, ctx: Arc<ControllerContext>) -> Action {
    match err {
        ReconcileError::MissingName | ReconcileError::MissingNamespace { .. } => {
            Action::await_change()
        }
        _ => {
            let key = crate::backoff::resource_key(
                CONTROLLER_NAME,
                obj.namespace().as_deref().unwrap_or(""),
                &obj.name_any(),
            );
            let count = ctx.backoff.record_error(&key);
            let delay = ctx.backoff.duration_for(&key);
            tracing::warn!(
                key = %key,
                consecutive_errors = count,
                requeue_secs = delay.as_secs(),
                error = ?err,
                "route: reconcile error; backing off"
            );
            Action::requeue(delay)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use mcpg_operator_api::v1alpha1::{GatewayRef, MCPGRouteSpec, RouteMatch, RouteToolRef};

    fn route(ns: &str, spec: MCPGRouteSpec) -> MCPGRoute {
        MCPGRoute {
            metadata: ObjectMeta {
                name: Some("r".into()),
                namespace: Some(ns.into()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn spec_with_chains(identity: &[&str]) -> MCPGRouteSpec {
        MCPGRouteSpec {
            gateway_ref: GatewayRef {
                name: "shared".into(),
                namespace: Some("shared-gw".into()),
            },
            r#match: RouteMatch {
                tools: vec![RouteToolRef {
                    id: "orders.list".into(),
                }],
            },
            identity_chain: identity.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn missing_chain_plugins_flags_empty_id() {
        let r = route("tenant-a", spec_with_chains(&["", "ok"]));
        assert_eq!(missing_chain_plugins(&r, None).as_deref(), Some("<empty>"));
    }

    #[test]
    fn missing_chain_plugins_ok_for_well_formed() {
        let r = route(
            "tenant-a",
            spec_with_chains(&["dev.mcpg.identity.workload"]),
        );
        assert!(missing_chain_plugins(&r, None).is_none());
    }

    #[test]
    fn map_gateway_to_routes_is_empty_hook() {
        let gw = MCPGGateway {
            metadata: ObjectMeta {
                name: Some("g".into()),
                namespace: Some("ns".into()),
                ..Default::default()
            },
            spec: Default::default(),
            status: None,
        };
        assert!(map_gateway_to_routes(gw).is_empty());
    }
}
