//! Per-resource exponential backoff tracker.
//!
//! `kube-rs`'s `Controller::run` defaults to a fixed-period
//! requeue when the error_policy returns `Action::requeue`. That
//! works for one-off transient errors but degrades a degraded
//! apiserver into a hot loop the moment a few resources start
//! failing. The map below tracks consecutive failures by stable
//! per-resource key and computes an exponential backoff with a
//! ceiling.
//!
//! Usage: each controller's `error_policy` calls
//! [`BackoffMap::record_error`] (which returns the new count) and
//! converts to a [`Duration`] via [`BackoffMap::duration_for`].
//! On success, the controller's reconcile path calls
//! [`BackoffMap::record_success`] to reset.
//!
//! Keys are formed as `controller/[namespace/]name`. Cluster-
//! scoped CRDs omit the namespace segment.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Lower bound of the backoff curve. The first error after a
/// success will requeue at this delay.
const BASE_SECS: u64 = 5;

/// Doubling cap — past this exponent the backoff stays at the
/// ceiling.
const MAX_EXPONENT: u32 = 6;

/// Hard cap — even if the exponent grew unbounded, we never wait
/// longer than this between retries. Stops a wedged dependency
/// from hiding real progress for too long.
const MAX_BACKOFF_SECS: u64 = 300;

/// Cheaply-clonable handle to the per-controller-process map.
#[derive(Clone, Default, Debug)]
pub struct BackoffMap {
    inner: Arc<RwLock<HashMap<String, u32>>>,
}

impl BackoffMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one failure for the given key. Returns the new
    /// consecutive-failure count (so callers can include it in
    /// log lines).
    pub fn record_error(&self, key: &str) -> u32 {
        let mut map = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(key.to_owned()).or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    }

    /// Reset the counter for the given key. No-op when no errors
    /// have been recorded.
    pub fn record_success(&self, key: &str) {
        let mut map = self.inner.write().unwrap_or_else(|e| e.into_inner());
        map.remove(key);
    }

    /// Current consecutive-failure count for the given key
    /// (without modifying it).
    pub fn count(&self, key: &str) -> u32 {
        let map = self.inner.read().unwrap_or_else(|e| e.into_inner());
        map.get(key).copied().unwrap_or(0)
    }

    /// Compute the requeue delay for the given key. The curve is
    /// `BASE * 2^min(count, MAX_EXPONENT)`, capped at
    /// `MAX_BACKOFF_SECS`. Adds ±20% jitter so a fleet doesn't
    /// converge into a synchronised retry burst.
    pub fn duration_for(&self, key: &str) -> Duration {
        backoff_for_count(self.count(key))
    }
}

/// Compute the backoff [`Duration`] for the given consecutive-
/// error count. Pure function, exposed so unit tests can pin
/// the curve without touching the map.
pub fn backoff_for_count(count: u32) -> Duration {
    let exp = count.min(MAX_EXPONENT);
    let secs = BASE_SECS.saturating_mul(1u64 << exp);
    let secs = secs.min(MAX_BACKOFF_SECS);
    let jitter_factor = jitter();
    Duration::from_secs_f64((secs as f64) * jitter_factor)
}

fn jitter() -> f64 {
    use rand::Rng;
    0.8 + rand::thread_rng().gen_range(0.0..0.4)
}

/// Build the per-resource key from the (controller, namespace,
/// name) tuple. `namespace` is empty for cluster-scoped CRDs.
pub fn resource_key(controller: &str, namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        format!("{controller}/{name}")
    } else {
        format!("{controller}/{namespace}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_error_returns_count_one() {
        let m = BackoffMap::new();
        assert_eq!(m.record_error("k"), 1);
    }

    #[test]
    fn consecutive_errors_increment() {
        let m = BackoffMap::new();
        m.record_error("k");
        m.record_error("k");
        assert_eq!(m.record_error("k"), 3);
    }

    #[test]
    fn record_success_resets_count() {
        let m = BackoffMap::new();
        m.record_error("k");
        m.record_error("k");
        m.record_success("k");
        assert_eq!(m.count("k"), 0);
    }

    #[test]
    fn keys_are_isolated() {
        let m = BackoffMap::new();
        m.record_error("a");
        m.record_error("a");
        m.record_error("b");
        assert_eq!(m.count("a"), 2);
        assert_eq!(m.count("b"), 1);
    }

    #[test]
    fn backoff_curve_doubles_until_max_exponent() {
        // count=1 → 5*2 = 10s ±20% (with jitter, secs in 8..=12)
        for _ in 0..10 {
            let d = backoff_for_count(1);
            let s = d.as_secs_f64();
            assert!(
                (8.0..=12.0).contains(&s),
                "count=1 out of expected jittered range: {s}"
            );
        }
    }

    #[test]
    fn backoff_curve_capped_at_max() {
        // Beyond MAX_EXPONENT (6), backoff stays at MAX_BACKOFF_SECS
        // = 300s ±20%.
        for _ in 0..10 {
            let d = backoff_for_count(20);
            let s = d.as_secs_f64();
            assert!(
                (240.0..=360.0).contains(&s),
                "count=20 out of cap range: {s}"
            );
        }
    }

    #[test]
    fn resource_key_omits_empty_namespace() {
        assert_eq!(resource_key("plugin", "", "foo"), "plugin/foo");
    }

    #[test]
    fn resource_key_includes_namespace_when_set() {
        assert_eq!(
            resource_key("gateway", "payments", "foo"),
            "gateway/payments/foo"
        );
    }
}
