//! `/metrics` + `/healthz` + `/readyz` + `/reconcilez` endpoints.
//! Hosted by the admission server's axum app so we have one HTTPS
//! listener covering everything inbound.
//!
//! Serving admission and running reconciles are separate capabilities
//! with separate signals:
//!
//! - `/readyz` — can this pod serve admission? Process up + lease held.
//!   The chart's readiness probe targets it and the webhook Service
//!   selects on it, so with `failurePolicy: Fail` a 503 here rejects
//!   every MCPG CR write in the cluster. Validation reads the incoming
//!   object, never cached state, so it must not depend on watch health.
//! - `/reconcilez` — can this pod reconcile? The gateway controller's
//!   reflector store has completed its initial LIST, which kube-runtime
//!   holds every reconcile behind. A 503 here is a delay (kube-rs keeps
//!   retrying the watch), not an outage, so nothing gates admission on it.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;

use crate::telemetry::MetricsRegistry;

#[derive(Clone)]
pub struct MetricsState {
    pub registry: MetricsRegistry,
    pub healthy: Arc<std::sync::atomic::AtomicBool>,
    pub ready: Arc<std::sync::atomic::AtomicBool>,
    pub reconcile_ready: Arc<std::sync::atomic::AtomicBool>,
}

pub async fn metrics_handler(State(s): State<MetricsState>) -> impl IntoResponse {
    let body = s.registry.encode();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        body,
    )
}

pub async fn healthz_handler(State(s): State<MetricsState>) -> impl IntoResponse {
    if s.healthy.load(std::sync::atomic::Ordering::Acquire) {
        (StatusCode::OK, "ok\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unhealthy\n")
    }
}

pub async fn readyz_handler(State(s): State<MetricsState>) -> impl IntoResponse {
    if s.ready.load(std::sync::atomic::Ordering::Acquire) {
        (StatusCode::OK, "ready\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    }
}

pub async fn reconcilez_handler(State(s): State<MetricsState>) -> impl IntoResponse {
    if s.reconcile_ready.load(std::sync::atomic::Ordering::Acquire) {
        (StatusCode::OK, "reconciling\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "watch not synced\n")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::readiness::{StoreReadiness, gate_ready};

    struct Flags {
        healthy: Arc<AtomicBool>,
        ready: Arc<AtomicBool>,
        reconcile_ready: Arc<AtomicBool>,
    }

    /// A pod that is up and holds the lease: `/readyz`'s inputs are both
    /// satisfied, so only the watch signal is left to vary.
    fn serving_flags() -> Flags {
        Flags {
            healthy: Arc::new(AtomicBool::new(true)),
            ready: Arc::new(AtomicBool::new(true)),
            reconcile_ready: Arc::new(AtomicBool::new(false)),
        }
    }

    fn state(f: &Flags) -> MetricsState {
        MetricsState {
            registry: MetricsRegistry::new(),
            healthy: Arc::clone(&f.healthy),
            ready: Arc::clone(&f.ready),
            reconcile_ready: Arc::clone(&f.reconcile_ready),
        }
    }

    /// The signal the provisioner's `wait` needs: 503 while kube-runtime is
    /// still holding reconciles behind the initial LIST, 200 once released.
    #[tokio::test]
    async fn reconcilez_is_503_until_the_gateway_store_syncs() {
        let flags = serving_flags();
        let store_ready = StoreReadiness::new();
        let gate = tokio::spawn(gate_ready(
            Arc::clone(&store_ready),
            Arc::clone(&flags.reconcile_ready),
        ));

        tokio::task::yield_now().await;
        let s = state(&flags);
        assert_eq!(
            reconcilez_handler(State(s.clone()))
                .await
                .into_response()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        store_ready.mark_synced();
        tokio::time::timeout(std::time::Duration::from_secs(5), gate)
            .await
            .expect("readiness gate never completed")
            .expect("gate task panicked");

        assert!(flags.reconcile_ready.load(Ordering::Acquire));
        assert_eq!(
            reconcilez_handler(State(s)).await.into_response().status(),
            StatusCode::OK
        );
    }

    /// Regression guard on the blast radius: the webhook Service selects on
    /// the readiness probe and the webhook is `failurePolicy: Fail`, so
    /// coupling `/readyz` to watch health would turn a self-healing watch
    /// stall into a cluster-wide rejection of every MCPG CR write. Admission
    /// validates the incoming object and needs no cache.
    #[tokio::test]
    async fn readyz_and_healthz_ignore_an_unsynced_watch() {
        let flags = serving_flags();
        let s = state(&flags);
        assert!(!flags.reconcile_ready.load(Ordering::Acquire));

        assert_eq!(
            readyz_handler(State(s.clone()))
                .await
                .into_response()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            healthz_handler(State(s.clone()))
                .await
                .into_response()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            reconcilez_handler(State(s)).await.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    /// `/readyz` is still the lease + shutdown signal it was: a pod that has
    /// not acquired the lease (or has begun draining) is not serving.
    #[tokio::test]
    async fn readyz_is_503_when_not_leader_or_draining() {
        let flags = serving_flags();
        flags.ready.store(false, Ordering::Release);
        flags.reconcile_ready.store(true, Ordering::Release);
        let s = state(&flags);

        assert_eq!(
            readyz_handler(State(s.clone()))
                .await
                .into_response()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            healthz_handler(State(s)).await.into_response().status(),
            StatusCode::OK
        );
    }
}
