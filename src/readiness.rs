//! Watch-readiness: whether this process's reconcile loops can actually run.
//!
//! kube-runtime holds every reconcile behind the controller's reflector store
//! completing its initial LIST, and reports that wait at `debug!` only. A
//! controller whose watch is stalled therefore presents exactly like an idle
//! one — it announces itself at startup and then goes quiet, while every
//! `wait`-gated caller downstream (provisioner → CR → `Available=True`) blocks
//! to its own timeout with nothing to attribute it to.
//!
//! This module carries the "store synced" transition out of the controller so
//! the process can publish it on `/reconcilez`.
//!
//! It backs that endpoint and nothing else. Neither `/readyz` nor `/healthz`
//! may consult it: the webhook Service selects on the readiness probe and the
//! webhook is `failurePolicy: Fail`, so gating readiness on watch health would
//! escalate a stall that kube-rs retries out of into a cluster-wide rejection
//! of every MCPG CR write; and liveness must not restart a pod whose cache is
//! the only thing missing, since a restart discards it and re-enters the same
//! stall.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::watch;
use tracing::info;

/// One-way latch for "the gateway controller's reflector store completed its
/// initial LIST". Shared by `Arc` between the controller (which sets it) and
/// the gate (which waits on it).
///
/// The gateway store is the one this tracks: it is the CRD whose
/// `status.conditions` every publish path waits on, and the controller that
/// owns it is the first to be spawned.
pub struct StoreReadiness {
    tx: watch::Sender<bool>,
}

impl StoreReadiness {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tx: watch::channel(false).0,
        })
    }

    /// True once the store has synced. Never returns to false — kube-runtime
    /// retries a dropped watch against the populated cache, so a reconnect is
    /// a resumption, not a cold start.
    #[must_use]
    pub fn is_synced(&self) -> bool {
        *self.tx.borrow()
    }

    /// `send_replace`, not `send`: `send` drops the value when no receiver is
    /// subscribed, so a store that syncs before the gate first polls would
    /// latch nothing and leave `/reconcilez` permanently 503.
    pub fn mark_synced(&self) {
        self.tx.send_replace(true);
    }

    /// Resolve once the store is synced; returns immediately if it already is.
    pub async fn wait_until_synced(&self) {
        let mut rx = self.tx.subscribe();
        // `borrow_and_update` marks the observed value seen, so a `mark_synced`
        // landing between the check and the await still wakes `changed()`.
        while !*rx.borrow_and_update() {
            // The sender is owned by `self`, so this cannot fail while the
            // caller holds the latch.
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}

/// Hold the `/reconcilez` flag false until the gateway controller's store has
/// synced, then flip it.
///
/// Spawned by `main` rather than inlined there: the wait must not block the
/// signal-handling select, or a stalled watch would leave SIGTERM unhandled.
pub async fn gate_ready(store_ready: Arc<StoreReadiness>, reconcile_ready: Arc<AtomicBool>) {
    store_ready.wait_until_synced().await;
    reconcile_ready.store(true, Ordering::Release);
    info!("gateway watch synced; operator reconciling");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn latch_starts_unsynced_and_latches_once() {
        let latch = StoreReadiness::new();
        assert!(!latch.is_synced());
        latch.mark_synced();
        assert!(latch.is_synced());
        // Already-synced waiters must not block.
        latch.wait_until_synced().await;
    }

    /// A sync landing before anyone waits must still latch — the controller's
    /// store can be ready before the gate task is first polled.
    #[tokio::test]
    async fn sync_before_any_waiter_still_latches() {
        let latch = StoreReadiness::new();
        latch.mark_synced();
        let reconcile_ready = Arc::new(AtomicBool::new(false));
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            gate_ready(Arc::clone(&latch), Arc::clone(&reconcile_ready)),
        )
        .await
        .expect("gate blocked on a latch that was already synced");
        assert!(reconcile_ready.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn wait_resolves_on_a_later_sync() {
        let latch = StoreReadiness::new();
        let waiter = {
            let latch = Arc::clone(&latch);
            tokio::spawn(async move { latch.wait_until_synced().await })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        latch.mark_synced();
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("wait_until_synced did not resolve after mark_synced")
            .expect("waiter task panicked");
    }

    #[tokio::test]
    async fn gate_leaves_the_flag_false_until_the_store_syncs() {
        let latch = StoreReadiness::new();
        let reconcile_ready = Arc::new(AtomicBool::new(false));
        let gate = tokio::spawn(gate_ready(Arc::clone(&latch), Arc::clone(&reconcile_ready)));

        // Spawning controllers is not watching: the gate must not flip on the
        // mere existence of the task.
        tokio::task::yield_now().await;
        assert!(!reconcile_ready.load(Ordering::Acquire));

        latch.mark_synced();
        tokio::time::timeout(std::time::Duration::from_secs(5), gate)
            .await
            .expect("readiness gate never completed")
            .expect("gate task panicked");
        assert!(reconcile_ready.load(Ordering::Acquire));
    }
}
