//! Leader election via `coordination.k8s.io/v1.Lease`.
//!
//! Multiple operator replicas share a single Lease resource. One
//! holder at a time runs the controllers; the rest wait. The
//! holder periodically renews the Lease before its TTL expires.
//! On graceful shutdown the holder releases the Lease so the
//! next replica picks up immediately (rather than waiting for
//! TTL expiry).
//!
//! Failure modes:
//!
//! - Holder pod crashes — Lease expires after `lease_duration`
//!   seconds; another replica acquires.
//! - Holder loses apiserver connectivity briefly — renew
//!   loop catches up; if the renew window is missed, the holder
//!   yields (controllers stop) and another replica may acquire.
//! - Two replicas race on acquire — apiserver's optimistic-
//!   concurrency `resourceVersion` arbitrates; loser retries.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use kube::{Client, Error as KubeError};
use tokio::sync::Notify;
use tokio::time::sleep;
use tracing::{debug, error, info, instrument, warn};

/// Configuration for the leader-election loop.
#[derive(Debug, Clone)]
pub struct LeaderElectionConfig {
    /// Lease resource name.
    pub lease_name: String,
    /// Namespace the Lease lives in.
    pub lease_namespace: String,
    /// This pod's identity (used as `holderIdentity`).
    pub identity: String,
    /// How long the Lease is valid after the holder's last
    /// renewal. Other replicas may not acquire before this
    /// expires.
    pub lease_duration: Duration,
    /// Holder's renewal interval. Must be < `lease_duration` —
    /// the holder renews this often to keep the Lease fresh.
    pub renew_deadline: Duration,
    /// Non-holders' poll interval — how often they check
    /// whether the Lease is up for grabs.
    pub retry_period: Duration,
}

impl LeaderElectionConfig {
    /// Sanity-check the timings. Renew deadline must leave
    /// headroom before lease expiry so a missed renewal doesn't
    /// instantly hand the lease to a peer.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.renew_deadline >= self.lease_duration {
            return Err("renew_deadline must be < lease_duration");
        }
        if self.retry_period >= self.renew_deadline {
            return Err("retry_period must be < renew_deadline");
        }
        if self.identity.is_empty() {
            return Err("identity must not be empty");
        }
        if self.lease_name.is_empty() {
            return Err("lease_name must not be empty");
        }
        if self.lease_namespace.is_empty() {
            return Err("lease_namespace must not be empty");
        }
        Ok(())
    }
}

/// Handle returned by [`run_leader_election`]. Lets the caller
/// inspect leadership state and signal shutdown.
pub struct LeaderElection {
    /// True while this replica is the active leader.
    is_leader: Arc<AtomicBool>,
    /// Notified when leadership transitions (acquired or lost).
    transition: Arc<Notify>,
    /// Notified by the caller to request graceful release.
    shutdown: Arc<Notify>,
}

impl LeaderElection {
    /// True iff this replica currently holds the Lease.
    pub fn is_leader(&self) -> bool {
        self.is_leader.load(Ordering::Acquire)
    }

    /// Wait for leadership to transition (acquired or lost).
    /// Useful for tests + status reporting.
    pub async fn wait_for_transition(&self) {
        self.transition.notified().await;
    }

    /// Wait until this replica becomes the leader. Returns
    /// immediately if already leading.
    pub async fn wait_until_leader(&self) {
        loop {
            if self.is_leader() {
                return;
            }
            self.transition.notified().await;
        }
    }

    /// Signal the leader-election loop to release the Lease and
    /// exit. The loop drops the Lease holder field on the next
    /// renew tick (or immediately if the lock is held).
    pub fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }
}

/// Spawn the leader-election loop. Returns a [`LeaderElection`]
/// handle plus the JoinHandle of the spawned task.
pub fn run_leader_election(
    client: Client,
    config: LeaderElectionConfig,
) -> Result<(LeaderElection, tokio::task::JoinHandle<()>), &'static str> {
    config.validate()?;

    let is_leader = Arc::new(AtomicBool::new(false));
    let transition = Arc::new(Notify::new());
    let shutdown = Arc::new(Notify::new());

    let task = {
        let is_leader = Arc::clone(&is_leader);
        let transition = Arc::clone(&transition);
        let shutdown = Arc::clone(&shutdown);
        tokio::spawn(async move {
            run_loop(client, config, is_leader, transition, shutdown).await;
        })
    };

    Ok((
        LeaderElection {
            is_leader,
            transition,
            shutdown,
        },
        task,
    ))
}

/// The main loop. State machine:
///
/// 1. Try to acquire / renew the Lease.
/// 2. If acquired: set `is_leader = true`, notify, sleep
///    `renew_deadline`, repeat.
/// 3. If denied: set `is_leader = false`, notify (if state
///    changed), sleep `retry_period`, repeat.
/// 4. Shutdown signal: release the Lease (if held), exit.
async fn run_loop(
    client: Client,
    cfg: LeaderElectionConfig,
    is_leader: Arc<AtomicBool>,
    transition: Arc<Notify>,
    shutdown: Arc<Notify>,
) {
    let api: Api<Lease> = Api::namespaced(client, &cfg.lease_namespace);

    loop {
        tokio::select! {
            biased;
            _ = shutdown.notified() => {
                info!("leader-election: shutdown requested");
                if is_leader.swap(false, Ordering::AcqRel) {
                    if let Err(e) = release_lease(&api, &cfg).await {
                        warn!(error = ?e, "leader-election: release failed");
                    } else {
                        info!("leader-election: lease released");
                    }
                    transition.notify_waiters();
                }
                return;
            }
            outcome = try_acquire_or_renew(&api, &cfg) => {
                match outcome {
                    Ok(true) => {
                        // We hold the lease.
                        let was_leader = is_leader.swap(true, Ordering::AcqRel);
                        if !was_leader {
                            info!(identity = %cfg.identity, "leader-election: acquired");
                            transition.notify_waiters();
                        }
                        sleep_or_shutdown(&shutdown, cfg.renew_deadline).await;
                    }
                    Ok(false) => {
                        // Another replica holds it.
                        let was_leader = is_leader.swap(false, Ordering::AcqRel);
                        if was_leader {
                            warn!("leader-election: lost lease");
                            transition.notify_waiters();
                        }
                        sleep_or_shutdown(&shutdown, cfg.retry_period).await;
                    }
                    Err(e) => {
                        // Transient error — backoff + retry.
                        let was_leader = is_leader.swap(false, Ordering::AcqRel);
                        if was_leader {
                            warn!(error = ?e, "leader-election: transient error after holding lease; relinquishing");
                            transition.notify_waiters();
                        } else {
                            warn!(error = ?e, "leader-election: transient error during acquire");
                        }
                        sleep_or_shutdown(&shutdown, cfg.retry_period).await;
                    }
                }
            }
        }
    }
}

async fn sleep_or_shutdown(shutdown: &Notify, dur: Duration) {
    tokio::select! {
        _ = sleep(dur) => {}
        _ = shutdown.notified() => {}
    }
}

/// One Lease acquire/renew attempt. Returns `Ok(true)` when this
/// replica holds the Lease after the attempt; `Ok(false)` when
/// another replica owns it; `Err` on transient apiserver errors.
#[instrument(skip(api, cfg), fields(name=%cfg.lease_name, identity=%cfg.identity))]
async fn try_acquire_or_renew(
    api: &Api<Lease>,
    cfg: &LeaderElectionConfig,
) -> Result<bool, KubeError> {
    match api.get(&cfg.lease_name).await {
        Ok(existing) => {
            // Lease exists — check holder + expiry.
            let holder = existing
                .spec
                .as_ref()
                .and_then(|s| s.holder_identity.clone())
                .unwrap_or_default();
            let renew_time = existing
                .spec
                .as_ref()
                .and_then(|s| s.renew_time.as_ref())
                .map(|t| t.0);

            if holder == cfg.identity {
                // We're the holder — renew.
                renew_lease(api, cfg, &existing).await?;
                Ok(true)
            } else if has_expired(renew_time.as_ref(), cfg.lease_duration) {
                // Lease expired — try to take it.
                debug!(prior_holder = %holder, "leader-election: prior lease expired");
                replace_holder(api, cfg, &existing).await?;
                Ok(true)
            } else {
                // Another replica holds a fresh lease.
                debug!(holder = %holder, "leader-election: lease held by peer");
                Ok(false)
            }
        }
        Err(e) if is_not_found(&e) => {
            // Lease doesn't exist yet — create it.
            debug!("leader-election: creating fresh lease");
            create_lease(api, cfg).await?;
            Ok(true)
        }
        Err(e) => Err(e),
    }
}

fn is_not_found(e: &KubeError) -> bool {
    matches!(e, KubeError::Api(s) if s.code == 404)
}

fn has_expired(renew_time: Option<&Timestamp>, lease_duration: Duration) -> bool {
    let Some(rt) = renew_time else {
        return true;
    };
    let now = Timestamp::now();
    let elapsed = now.duration_since(*rt);
    let lease_duration_signed: jiff::SignedDuration = lease_duration
        .try_into()
        .unwrap_or(jiff::SignedDuration::MAX);
    elapsed > lease_duration_signed
}

async fn create_lease(api: &Api<Lease>, cfg: &LeaderElectionConfig) -> Result<(), KubeError> {
    let now = MicroTime(Timestamp::now());
    let lease = Lease {
        metadata: ObjectMeta {
            name: Some(cfg.lease_name.clone()),
            ..Default::default()
        },
        spec: Some(LeaseSpec {
            holder_identity: Some(cfg.identity.clone()),
            lease_duration_seconds: Some(cfg.lease_duration.as_secs() as i32),
            acquire_time: Some(now.clone()),
            renew_time: Some(now),
            lease_transitions: Some(0),
            ..Default::default()
        }),
    };
    api.create(&PostParams::default(), &lease).await?;
    Ok(())
}

async fn renew_lease(
    api: &Api<Lease>,
    cfg: &LeaderElectionConfig,
    existing: &Lease,
) -> Result<(), KubeError> {
    let now = MicroTime(Timestamp::now());
    let mut spec = existing.spec.clone().unwrap_or_default();
    spec.holder_identity = Some(cfg.identity.clone());
    spec.lease_duration_seconds = Some(cfg.lease_duration.as_secs() as i32);
    spec.renew_time = Some(now);
    let patch = serde_json::json!({ "spec": spec });
    api.patch(
        &cfg.lease_name,
        &PatchParams::default(),
        &Patch::Merge(&patch),
    )
    .await?;
    Ok(())
}

async fn replace_holder(
    api: &Api<Lease>,
    cfg: &LeaderElectionConfig,
    existing: &Lease,
) -> Result<(), KubeError> {
    let now = MicroTime(Timestamp::now());
    let prior_transitions = existing
        .spec
        .as_ref()
        .and_then(|s| s.lease_transitions)
        .unwrap_or(0);
    let mut spec = existing.spec.clone().unwrap_or_default();
    spec.holder_identity = Some(cfg.identity.clone());
    spec.lease_duration_seconds = Some(cfg.lease_duration.as_secs() as i32);
    spec.acquire_time = Some(now.clone());
    spec.renew_time = Some(now);
    spec.lease_transitions = Some(prior_transitions + 1);
    let patch = serde_json::json!({ "spec": spec });
    api.patch(
        &cfg.lease_name,
        &PatchParams::default(),
        &Patch::Merge(&patch),
    )
    .await?;
    Ok(())
}

async fn release_lease(api: &Api<Lease>, cfg: &LeaderElectionConfig) -> Result<(), KubeError> {
    // Clear holder_identity + bump renew_time so peers see the
    // release immediately. Don't delete the Lease — preserve
    // lease_transitions counter for observability.
    let patch = serde_json::json!({
        "spec": {
            "holderIdentity": null,
            "renewTime": MicroTime(Timestamp::now()),
        }
    });
    api.patch(
        &cfg.lease_name,
        &PatchParams::default(),
        &Patch::Merge(&patch),
    )
    .await
    .map(|_| ())
    .or_else(|e| {
        if is_not_found(&e) {
            // 404 on release is fine — the Lease already
            // disappeared (TTL controller, manual deletion).
            Ok(())
        } else {
            error!(error = ?e, "leader-election: release patch failed");
            Err(e)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> LeaderElectionConfig {
        LeaderElectionConfig {
            lease_name: "mcpg-operator".into(),
            lease_namespace: "mcpg-system".into(),
            identity: "pod-1".into(),
            lease_duration: Duration::from_secs(30),
            renew_deadline: Duration::from_secs(20),
            retry_period: Duration::from_secs(4),
        }
    }

    #[test]
    fn validate_accepts_well_formed_config() {
        cfg().validate().unwrap();
    }

    #[test]
    fn validate_rejects_renew_deadline_at_or_above_lease_duration() {
        let mut c = cfg();
        c.renew_deadline = c.lease_duration;
        assert!(c.validate().is_err());
        c.renew_deadline = c.lease_duration + Duration::from_secs(1);
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_retry_period_at_or_above_renew_deadline() {
        let mut c = cfg();
        c.retry_period = c.renew_deadline;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_strings() {
        let mut c = cfg();
        c.identity.clear();
        assert!(c.validate().is_err());
        let mut c = cfg();
        c.lease_name.clear();
        assert!(c.validate().is_err());
        let mut c = cfg();
        c.lease_namespace.clear();
        assert!(c.validate().is_err());
    }

    #[test]
    fn has_expired_returns_true_for_no_renew_time() {
        assert!(has_expired(None, Duration::from_secs(30)));
    }

    #[test]
    fn has_expired_returns_true_for_old_renew_time() {
        let renewed_60s_ago = Timestamp::now()
            .checked_sub(jiff::SignedDuration::from_secs(60))
            .unwrap();
        assert!(has_expired(Some(&renewed_60s_ago), Duration::from_secs(30)));
    }

    #[test]
    fn has_expired_returns_false_for_fresh_renew_time() {
        let renewed_5s_ago = Timestamp::now()
            .checked_sub(jiff::SignedDuration::from_secs(5))
            .unwrap();
        assert!(!has_expired(Some(&renewed_5s_ago), Duration::from_secs(30)));
    }
}
