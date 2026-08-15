//! `mcpg-operator` binary entry point.
//!
//! - Parse CLI / env config.
//! - Initialise telemetry.
//! - Connect to kube-apiserver.
//! - Run leader election (when enabled).
//! - Spawn the admission + metrics server.
//! - Spawn each controller's reconcile loop.
//! - Wait for shutdown signal.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use kube::Client;
use mcpg_operator::admission::{ServerConfig, run_metrics_server, run_webhook_server};
use mcpg_operator::config::OperatorConfig;
use mcpg_operator::controllers;
use mcpg_operator::leader::{LeaderElectionConfig, run_leader_election};
use mcpg_operator::telemetry::{MetricsRegistry, init_tracing};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 panics on the first TLS handshake when both ring and
    // aws-lc-rs CryptoProviders are linked (plugin-host → oci-client →
    // jsonwebtoken 10 pulls aws-lc-rs alongside kube/axum-server's ring).
    // Install a process default before the kube client connects. Idempotent;
    // mirrors cp-core's `tls_init::install_default_crypto_provider`.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cfg = OperatorConfig::from_args();
    init_tracing(&cfg);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        leader_election = cfg.leader_election,
        watch_namespace = ?cfg.watch_namespace,
        webhook_enabled = cfg.webhook_enabled(),
        offline_trust_root = ?cfg.sigstore_trust_root_path,
        "mcpg-operator starting"
    );

    // Air-gap: point cosign verification at a pre-mirrored Sigstore
    // trust root (no network) when configured. Must run before any
    // plugin reconcile triggers verification.
    mcpg_operator::verify::cosign::set_offline_trust_root_path(
        cfg.sigstore_trust_root_path.clone(),
    );

    let client = Client::try_default()
        .await
        .context("failed to construct kube Client (is KUBECONFIG / in-cluster auth set?)")?;

    let metrics = MetricsRegistry::new();
    let healthy = Arc::new(AtomicBool::new(true));
    let ready = Arc::new(AtomicBool::new(false));
    // Backs `/reconcilez`, never `/readyz`: see the readiness gate below.
    let reconcile_ready = Arc::new(AtomicBool::new(false));

    // Spawn the admission + metrics server.
    let server_handle = {
        let server_cfg = ServerConfig {
            bind: cfg
                .webhook_bind
                .parse()
                .context("invalid --webhook-bind address")?,
            tls_cert_dir: cfg.tls_cert_dir.clone(),
        };
        let state = mcpg_operator::admission::server::AdmissionState {
            client: client.clone(),
            metrics: metrics.clone(),
            healthy: healthy.clone(),
            ready: ready.clone(),
            reconcile_ready: reconcile_ready.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = run_webhook_server(server_cfg, state).await {
                tracing::error!(error = ?e, "admission server failed");
            }
        })
    };

    // Spawn the standalone metrics + health server. The Helm chart's
    // liveness/readiness probes and the metrics Service/ServiceMonitor
    // target this port (`--metrics-bind`, default :8443), separate from
    // the webhook port (:9443). Without it the readiness probe hits a
    // closed port, the pod never goes Ready, and every `wait`-gated
    // downstream apply (operator → CRs) blocks to timeout.
    let metrics_handle = {
        let bind: SocketAddr = cfg
            .metrics_bind
            .parse()
            .context("invalid --metrics-bind address")?;
        let tls_cert_dir = cfg.tls_cert_dir.clone();
        let state = mcpg_operator::admission::server::AdmissionState {
            client: client.clone(),
            metrics: metrics.clone(),
            healthy: healthy.clone(),
            ready: ready.clone(),
            reconcile_ready: reconcile_ready.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = run_metrics_server(bind, tls_cert_dir, state).await {
                tracing::error!(error = ?e, "metrics server failed");
            }
        })
    };

    // Fleet agent (pull-mode cells). Spawned BEFORE leader election on
    // purpose: it is not a controller, it is this cell's only inbound channel
    // from the fleet, and gating it on the lease would leave a standby replica
    // unable to receive work its cell had already been assigned. The agent's
    // applies are idempotent SSA, so more than one replica running it is safe.
    #[cfg(feature = "fleet")]
    if cfg.fleet_attach {
        let endpoint = cfg.fleet_endpoint.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "--fleet-attach requires --fleet-endpoint (the provisioner's fleet listener)"
            )
        })?;
        // Fail fast on a missing credential: without it the agent would loop
        // forever on `unauthenticated`, which reads like a network fault.
        let token = mcpg_operator::fleet_agent::read_token(
            cfg.fleet_token.as_deref(),
            cfg.fleet_token_file.as_deref(),
        )?;
        let agent_client = client.clone();
        let edge = cfg.fleet_edge_address.clone();
        let beat = Duration::from_secs(cfg.fleet_heartbeat_secs.max(5));
        info!(%endpoint, "fleet attach enabled; this operator is a pull-mode cell agent");
        tokio::spawn(async move {
            mcpg_operator::fleet_agent::run(agent_client, endpoint, token, edge, beat).await;
        });
    }

    #[cfg(not(feature = "fleet"))]
    if cfg.fleet_attach {
        anyhow::bail!("--fleet-attach needs the `fleet` feature, which this build does not have");
    }

    // Leader election. The election handle gates the controller
    // spawn — non-leaders run reflectors (warm cache) but skip
    // the reconcile loop. Single-replica dev clusters set
    // `--leader-election=false` to bypass the lease.
    let leader_handle = if cfg.leader_election {
        let le_cfg = LeaderElectionConfig {
            lease_name: cfg.lease_name.clone(),
            lease_namespace: cfg.lease_namespace.clone(),
            identity: cfg.pod_name.clone(),
            lease_duration: Duration::from_secs(cfg.lease_duration_secs),
            renew_deadline: Duration::from_secs(cfg.lease_renew_secs),
            retry_period: Duration::from_secs(cfg.lease_retry_secs),
        };
        let (handle, _task) = run_leader_election(client.clone(), le_cfg)
            .map_err(|e| anyhow::anyhow!("leader-election misconfigured: {e}"))?;

        info!(
            lease = %cfg.lease_name,
            namespace = %cfg.lease_namespace,
            identity = %cfg.pod_name,
            "leader election started; waiting to acquire lease"
        );
        // Mark this process as not-yet-leader for dashboards.
        metrics
            .operator_metrics()
            .set_leader_elected(&cfg.lease_name, false);
        handle.wait_until_leader().await;
        metrics
            .operator_metrics()
            .set_leader_elected(&cfg.lease_name, true);
        info!("leader-election: acquired; spawning controllers");
        Some(handle)
    } else {
        warn!("leader election disabled via --leader-election=false (dev mode)");
        // Dev mode behaves like a permanent leader — pin the
        // gauge so dashboards don't flag it.
        metrics
            .operator_metrics()
            .set_leader_elected(&cfg.lease_name, true);
        None
    };

    // One Recorder per controller — each pins its own
    // reporting_controller string so kubectl describe attributes
    // events correctly. The `instance` field carries the pod
    // name when set (helpful in two-replica deploys).
    let recorder_for = |controller: &str| {
        kube::runtime::events::Recorder::new(
            client.clone(),
            kube::runtime::events::Reporter {
                controller: format!("mcpg-operator/{controller}"),
                instance: Some(cfg.pod_name.clone()),
            },
        )
    };
    let recorders = controllers::gateway::ControllerRecorders {
        gateway: recorder_for("gateway"),
        plugin: recorder_for("plugin"),
        plugin_set: recorder_for("plugin-set"),
        revocation_list: recorder_for("revocation-list"),
        cluster: recorder_for("cluster"),
        route: recorder_for("route"),
        plugin_mirror: recorder_for("plugin-mirror"),
        tenant: recorder_for("tenant"),
        server: recorder_for("server"),
    };

    // Spawn the controllers (only after lease acquired).
    let store_ready = mcpg_operator::readiness::StoreReadiness::new();
    let ctx = Arc::new(controllers::gateway::ControllerContext {
        client: client.clone(),
        config: cfg.clone(),
        metrics: metrics.clone(),
        recorders,
        backoff: mcpg_operator::backoff::BackoffMap::new(),
        store_ready: Arc::clone(&store_ready),
    });

    let gateway_handle = {
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            if let Err(e) = controllers::gateway::run(ctx).await {
                tracing::error!(error = ?e, "gateway controller failed");
            }
        })
    };
    let revocation_handle = {
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            if let Err(e) = controllers::revocation_list::run(ctx).await {
                tracing::error!(error = ?e, "revocation-list controller failed");
            }
        })
    };
    let plugin_handle = {
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            if let Err(e) = controllers::plugin::run(ctx).await {
                tracing::error!(error = ?e, "plugin controller failed");
            }
        })
    };
    let plugin_set_handle = {
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            if let Err(e) = controllers::plugin_set::run(ctx).await {
                tracing::error!(error = ?e, "plugin-set controller failed");
            }
        })
    };
    let cluster_handle = {
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            if let Err(e) = controllers::cluster::run(ctx).await {
                tracing::error!(error = ?e, "cluster controller failed");
            }
        })
    };
    let route_handle = {
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            if let Err(e) = controllers::route::run(ctx).await {
                tracing::error!(error = ?e, "route controller failed");
            }
        })
    };
    let plugin_mirror_handle = {
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            if let Err(e) = controllers::plugin_mirror::run(ctx).await {
                tracing::error!(error = ?e, "plugin-mirror controller failed");
            }
        })
    };
    let tenant_handle = {
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            if let Err(e) = controllers::tenant::run(ctx).await {
                tracing::error!(error = ?e, "tenant controller failed");
            }
        })
    };

    let server_controller_handle = {
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            if let Err(e) = controllers::server::run(ctx).await {
                tracing::error!(error = ?e, "server controller failed");
            }
        })
    };

    // `/readyz` answers "can this pod serve admission?" — process up and
    // lease held. It deliberately does NOT wait on watch health:
    // the webhook Service selects on this probe and the webhook is
    // `failurePolicy: Fail`, so a stalled watch would stop being a delayed
    // reconcile (which kube-rs retries out of) and start rejecting every MCPG
    // CR write in the cluster. A non-leader never reaches this line, so a
    // standby still never turns Ready.
    ready.store(true, Ordering::Release);

    // `/reconcilez` answers the other question — "can this pod reconcile?" —
    // which is false until the gateway controller's reflector store finishes
    // its initial LIST, because kube-runtime holds every reconcile behind it.
    // Spawned rather than awaited: readiness must not block the signal
    // select, or a stalled watch would leave SIGTERM unhandled.
    let reconcile_gate = tokio::spawn(mcpg_operator::readiness::gate_ready(
        Arc::clone(&store_ready),
        reconcile_ready.clone(),
    ));

    // Wait for shutdown signal.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("ctrl-c received; shutting down");
        }
        _ = wait_for_term() => {
            info!("SIGTERM received; shutting down");
        }
    }

    // Drop the gate before clearing the flags: a store that syncs mid-drain
    // must not re-assert a signal shutdown has withdrawn.
    reconcile_gate.abort();
    healthy.store(false, Ordering::Release);
    ready.store(false, Ordering::Release);
    reconcile_ready.store(false, Ordering::Release);

    // Release the lease so peers can acquire immediately rather
    // than waiting for TTL expiry.
    if let Some(le) = &leader_handle {
        le.shutdown();
    }

    // Best-effort drain. Kube-rs's Controller honours
    // shutdown_on_signal (already wired in each controller).
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let _ = gateway_handle.await;
        let _ = revocation_handle.await;
        let _ = plugin_handle.await;
        let _ = plugin_set_handle.await;
        let _ = cluster_handle.await;
        let _ = route_handle.await;
        let _ = plugin_mirror_handle.await;
        let _ = tenant_handle.await;
        let _ = server_controller_handle.await;
        let _ = server_handle.await;
        let _ = metrics_handle.await;
    })
    .await;

    info!("mcpg-operator stopped");
    Ok(())
}

#[cfg(unix)]
async fn wait_for_term() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sig = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    sig.recv().await;
}

#[cfg(not(unix))]
async fn wait_for_term() {
    // On non-unix (Windows), only Ctrl-C is wired by the
    // tokio::select! arm above.
    std::future::pending::<()>().await
}
