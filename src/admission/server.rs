//! HTTPS admission + metrics server.
//!
//! axum + axum-server + rustls. Hosts:
//!
//! - `POST /validate-mcpg-dev-v1alpha1-{kind}` (one per CRD kind)
//! - `GET  /metrics`
//! - `GET  /healthz`
//! - `GET  /readyz`
//! - `GET  /reconcilez`

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use axum::Router;
use axum::routing::{get, post};
use axum_server::tls_rustls::RustlsConfig;
use kube::Client;
use tracing::{info, warn};

use crate::admission::metrics::{
    MetricsState, healthz_handler, metrics_handler, readyz_handler, reconcilez_handler,
};
use crate::admission::validators;
use crate::telemetry::MetricsRegistry;

#[derive(Clone)]
pub struct AdmissionState {
    pub client: Client,
    pub metrics: MetricsRegistry,
    pub healthy: Arc<AtomicBool>,
    pub ready: Arc<AtomicBool>,
    /// Backs `/reconcilez` only. Kept out of `ready` because the webhook
    /// Service selects on the readiness probe: gating admission on watch
    /// health would escalate a self-healing stall into a cluster-wide CR
    /// write rejection under `failurePolicy: Fail`.
    pub reconcile_ready: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub tls_cert_dir: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("missing TLS materials in {0:?}: expected tls.crt and tls.key")]
    MissingTls(PathBuf),
    #[error("failed to load TLS: {0}")]
    Tls(#[from] std::io::Error),
    #[error("server task failed: {0}")]
    Server(String),
}

/// Run the admission + metrics server. Returns when the server
/// stops (graceful shutdown signal or fatal error).
pub async fn run(cfg: ServerConfig, state: AdmissionState) -> Result<(), ServerError> {
    let metrics_state = MetricsState {
        registry: state.metrics.clone(),
        healthy: state.healthy.clone(),
        ready: state.ready.clone(),
        reconcile_ready: state.reconcile_ready.clone(),
    };

    let admission_router = Router::new()
        .route(
            "/validate-mcpg-dev-v1alpha1-mcpggateway",
            post(validators::gateway::validate),
        )
        .route(
            "/validate-mcpg-dev-v1alpha1-mcpgrevocationlist",
            post(validators::revocation_list::validate),
        )
        .route(
            "/validate-mcpg-dev-v1alpha1-mcpgplugin",
            post(validators::plugin::validate),
        )
        .route(
            "/validate-mcpg-dev-v1alpha1-mcpgpluginset",
            post(validators::plugin_set::validate),
        )
        .route(
            "/validate-mcpg-dev-v1alpha1-mcpgcluster",
            post(validators::cluster::validate),
        )
        .route(
            "/validate-mcpg-dev-v1alpha1-mcpgroute",
            post(validators::route::validate),
        )
        .route(
            "/validate-mcpg-dev-v1alpha1-mcpgpluginmirror",
            post(validators::plugin_mirror::validate),
        )
        .route(
            "/validate-mcpg-dev-v1alpha1-mcpgtenant",
            post(validators::tenant::validate),
        )
        .route(
            "/validate-mcpg-dev-v1alpha1-mcpgserver",
            post(validators::server::validate),
        )
        .with_state(state);

    if let Some(cert_dir) = cfg.tls_cert_dir.as_deref() {
        let cert = cert_dir.join("tls.crt");
        let key = cert_dir.join("tls.key");
        if !cert.is_file() || !key.is_file() {
            return Err(ServerError::MissingTls(cert_dir.to_path_buf()));
        }
        let tls = RustlsConfig::from_pem_file(&cert, &key).await?;
        let app = Router::new()
            .merge(admission_router)
            .merge(metrics_router(metrics_state));
        info!(addr = %cfg.bind, "starting webhook + metrics server (TLS)");
        axum_server::bind_rustls(cfg.bind, tls)
            .serve(app.into_make_service())
            .await
            .map_err(|e| ServerError::Server(e.to_string()))?;
    } else {
        // Plaintext mode is for dev only — admission webhooks
        // require TLS. We log a warning so misconfiguration is
        // visible, then refuse to expose webhooks (only metrics +
        // healthz routes pass through).
        warn!(
            "TLS cert dir not configured; webhook routes disabled \
             (metrics + healthz still served plaintext)"
        );
        let app = metrics_router(metrics_state);
        info!(addr = %cfg.bind, "starting metrics server (no TLS, no webhooks)");
        axum_server::bind(cfg.bind)
            .serve(app.into_make_service())
            .await
            .map_err(|e| ServerError::Server(e.to_string()))?;
    }

    Ok(())
}

/// Build the metrics + health router (`/metrics`, `/healthz`,
/// `/readyz`, `/reconcilez`). Shared by the webhook server and the
/// standalone metrics server.
fn metrics_router(state: MetricsState) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(healthz_handler))
        .route("/readyz", get(readyz_handler))
        .route("/reconcilez", get(reconcilez_handler))
        .with_state(state)
}

/// Run the standalone metrics + health server.
///
/// This is the listener the Helm chart's liveness/readiness probes
/// and the metrics Service / ServiceMonitor target (`--metrics-bind`,
/// default `:8443`) — a port distinct from the admission webhook
/// (`:9443`). The webhook server [`run`] also exposes these routes,
/// but the chart probes a *separate* port, so without this listener
/// the readiness probe hits a closed port and the pod never becomes
/// Ready (which in turn blocks every `wait`-gated downstream apply).
///
/// Serves TLS when a cert dir is configured — the chart probes use
/// HTTPS against the cert-manager-managed cert and the ServiceMonitor
/// scrapes `scheme: https` — and plaintext otherwise (dev /
/// out-of-cluster, where no webhook cert is mounted).
pub async fn run_metrics(
    bind: SocketAddr,
    tls_cert_dir: Option<PathBuf>,
    state: AdmissionState,
) -> Result<(), ServerError> {
    let metrics_state = MetricsState {
        registry: state.metrics.clone(),
        healthy: state.healthy.clone(),
        ready: state.ready.clone(),
        reconcile_ready: state.reconcile_ready.clone(),
    };
    let app = metrics_router(metrics_state);

    if let Some(cert_dir) = tls_cert_dir.as_deref() {
        let cert = cert_dir.join("tls.crt");
        let key = cert_dir.join("tls.key");
        if !cert.is_file() || !key.is_file() {
            return Err(ServerError::MissingTls(cert_dir.to_path_buf()));
        }
        let tls = RustlsConfig::from_pem_file(&cert, &key).await?;
        info!(addr = %bind, "starting metrics + health server (TLS)");
        axum_server::bind_rustls(bind, tls)
            .serve(app.into_make_service())
            .await
            .map_err(|e| ServerError::Server(e.to_string()))?;
    } else {
        info!(addr = %bind, "starting metrics + health server (no TLS)");
        axum_server::bind(bind)
            .serve(app.into_make_service())
            .await
            .map_err(|e| ServerError::Server(e.to_string()))?;
    }

    Ok(())
}
