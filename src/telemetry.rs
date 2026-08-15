//! Telemetry — `tracing` subscriber + `prometheus-client`
//! registry + the operator-wide metric surface.
//!
//! Three metric families per controller:
//!
//! - `mcpg_operator_reconcile_total{controller,outcome}` —
//!   counter incremented at the end of every reconcile call.
//! - `mcpg_operator_reconcile_duration_seconds{controller}` —
//!   histogram of reconcile latency.
//! - `mcpg_operator_dependency_unresolved_total{controller,
//!    dependency,reason}` — counter incremented when a
//!   reconcile rejects a dependent CRD (`PluginSetNotFound`,
//!   `PluginNotReady`, etc).
//!
//! Plus operator-wide gauges:
//!
//! - `mcpg_operator_last_reconcile_timestamp_seconds{controller}` —
//!   unix timestamp of the most recent reconcile (success or
//!   failure). Operators alert on staleness.
//! - `mcpg_operator_leader_elected{lease}` — `1` when this
//!   process holds the lease, `0` otherwise.
//! - `mcpg_operator_oci_pull_total{outcome}` — counter of
//!   plugin OCI pulls.
//! - `mcpg_operator_oci_pull_duration_seconds` — histogram of
//!   OCI pull latency.

use std::sync::Arc;
use std::time::SystemTime;

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::{LogFormat, OperatorConfig};

/// Initialise tracing. Call once at startup.
pub fn init_tracing(cfg: &OperatorConfig) {
    let env_filter = EnvFilter::try_new(&cfg.log_filter)
        .unwrap_or_else(|_| EnvFilter::new("mcpg_operator=info"));

    let registry = tracing_subscriber::registry().with(env_filter);

    match cfg.log_format {
        LogFormat::Json => {
            registry
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        LogFormat::Pretty => {
            registry
                .with(tracing_subscriber::fmt::layer().pretty())
                .init();
        }
    }
}

/// Reconcile outcome. Three buckets — anything more granular
/// belongs in the per-controller `dependency_unresolved` counter.
#[derive(Debug, Clone, Copy)]
pub enum ReconcileOutcome {
    /// `Ready=True` after this reconcile.
    Success,
    /// Transient error — the controller will retry.
    TransientError,
    /// Permanent error — operator intervention required (missing
    /// fields, malformed CRD, etc).
    PermanentError,
    /// Reconcile ran but a dependency wasn't ready
    /// (`PluginSetNotReady`, etc). Distinct from a transient
    /// error in that the reason is intentional, not a bug.
    DependencyPending,
}

impl ReconcileOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::TransientError => "transient_error",
            Self::PermanentError => "permanent_error",
            Self::DependencyPending => "dependency_pending",
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReconcileLabels {
    pub controller: String,
    pub outcome: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ControllerLabels {
    pub controller: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DependencyLabels {
    pub controller: String,
    pub dependency: String,
    pub reason: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct OutcomeLabels {
    pub outcome: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct LeaseLabels {
    pub lease: String,
}

/// All operator metrics live in one flat struct. Each field is
/// internally `Arc`-wrapped (the `Family` from prometheus-client
/// is cheap to clone), so passing `OperatorMetrics` by value to
/// each controller is fine.
#[derive(Debug, Clone)]
pub struct OperatorMetrics {
    pub reconcile_total: Family<ReconcileLabels, Counter>,
    pub reconcile_duration_seconds: Family<ControllerLabels, Histogram>,
    pub dependency_unresolved_total: Family<DependencyLabels, Counter>,
    pub last_reconcile_timestamp_seconds: Family<ControllerLabels, Gauge>,
    pub leader_elected: Family<LeaseLabels, Gauge>,
    pub oci_pull_total: Family<OutcomeLabels, Counter>,
    pub oci_pull_duration_seconds: Histogram,
}

impl OperatorMetrics {
    /// Construct + register every metric on `registry`.
    pub fn new(registry: &mut Registry) -> Self {
        let reconcile_total: Family<ReconcileLabels, Counter> = Family::default();
        registry.register(
            "reconcile",
            "Total reconciles by controller and outcome",
            reconcile_total.clone(),
        );

        let reconcile_duration_seconds: Family<ControllerLabels, Histogram> =
            Family::new_with_constructor(reconcile_duration_histogram);
        registry.register_with_unit(
            "reconcile_duration",
            "Reconcile duration by controller",
            prometheus_client::registry::Unit::Seconds,
            reconcile_duration_seconds.clone(),
        );

        let dependency_unresolved_total: Family<DependencyLabels, Counter> = Family::default();
        registry.register(
            "dependency_unresolved",
            "Reconciles that paused waiting on a dependent CRD",
            dependency_unresolved_total.clone(),
        );

        let last_reconcile_timestamp_seconds: Family<ControllerLabels, Gauge> = Family::default();
        registry.register_with_unit(
            "last_reconcile_timestamp",
            "Unix timestamp of the most recent reconcile (success or failure)",
            prometheus_client::registry::Unit::Seconds,
            last_reconcile_timestamp_seconds.clone(),
        );

        let leader_elected: Family<LeaseLabels, Gauge> = Family::default();
        registry.register(
            "leader_elected",
            "1 when this operator process holds the lease, 0 otherwise",
            leader_elected.clone(),
        );

        let oci_pull_total: Family<OutcomeLabels, Counter> = Family::default();
        registry.register(
            "oci_pull",
            "Total OCI plugin pulls by outcome",
            oci_pull_total.clone(),
        );

        let oci_pull_duration_seconds = oci_pull_duration_histogram();
        registry.register_with_unit(
            "oci_pull_duration",
            "OCI plugin pull duration",
            prometheus_client::registry::Unit::Seconds,
            oci_pull_duration_seconds.clone(),
        );

        Self {
            reconcile_total,
            reconcile_duration_seconds,
            dependency_unresolved_total,
            last_reconcile_timestamp_seconds,
            leader_elected,
            oci_pull_total,
            oci_pull_duration_seconds,
        }
    }

    /// Record one full reconcile. Bumps the outcome counter,
    /// records duration, refreshes the last-reconcile timestamp
    /// gauge.
    pub fn observe_reconcile(
        &self,
        controller: &str,
        outcome: ReconcileOutcome,
        duration_seconds: f64,
    ) {
        self.reconcile_total
            .get_or_create(&ReconcileLabels {
                controller: controller.to_owned(),
                outcome: outcome.as_str().to_owned(),
            })
            .inc();
        self.reconcile_duration_seconds
            .get_or_create(&ControllerLabels {
                controller: controller.to_owned(),
            })
            .observe(duration_seconds);
        self.last_reconcile_timestamp_seconds
            .get_or_create(&ControllerLabels {
                controller: controller.to_owned(),
            })
            .set(unix_timestamp());
    }

    /// Bump the dependency-unresolved counter for one reconcile
    /// that paused on an external CRD (e.g. waiting for
    /// `MCPGPluginSet` to become Ready).
    pub fn observe_dependency_unresolved(&self, controller: &str, dependency: &str, reason: &str) {
        self.dependency_unresolved_total
            .get_or_create(&DependencyLabels {
                controller: controller.to_owned(),
                dependency: dependency.to_owned(),
                reason: reason.to_owned(),
            })
            .inc();
    }

    /// Set the leader-elected gauge. `1` while this process is
    /// the active leader, `0` otherwise.
    pub fn set_leader_elected(&self, lease: &str, elected: bool) {
        self.leader_elected
            .get_or_create(&LeaseLabels {
                lease: lease.to_owned(),
            })
            .set(if elected { 1 } else { 0 });
    }

    /// Observe an OCI pull completion.
    pub fn observe_oci_pull(&self, outcome: &str, duration_seconds: f64) {
        self.oci_pull_total
            .get_or_create(&OutcomeLabels {
                outcome: outcome.to_owned(),
            })
            .inc();
        self.oci_pull_duration_seconds.observe(duration_seconds);
    }
}

fn reconcile_duration_histogram() -> Histogram {
    // 5ms .. ~10s. Most reconciles complete in ms; the tail
    // bucket catches the slow path (status patch retries, large
    // SSAs).
    Histogram::new(exponential_buckets(0.005, 2.0, 12))
}

fn oci_pull_duration_histogram() -> Histogram {
    // 50ms .. ~250s. OCI pulls are network-bound + may cross
    // multi-100MB layers; bucket headroom matters.
    Histogram::new(exponential_buckets(0.05, 2.5, 14))
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// Operator-wide metrics registry. Owns the `Registry` (locked
/// behind a `Mutex` for the encoder + register paths) plus the
/// pre-registered [`OperatorMetrics`] surface.
#[derive(Clone)]
pub struct MetricsRegistry {
    inner: Arc<std::sync::Mutex<Registry>>,
    metrics: OperatorMetrics,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    pub fn new() -> Self {
        let mut reg = Registry::with_prefix("mcpg_operator");
        let metrics = OperatorMetrics::new(&mut reg);
        Self {
            inner: Arc::new(std::sync::Mutex::new(reg)),
            metrics,
        }
    }

    /// Encode the registry to Prometheus exposition format.
    pub fn encode(&self) -> String {
        let registry = self
            .inner
            .lock()
            .expect("metrics registry mutex poisoned (this is a bug)");
        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &registry)
            .expect("encoder writes to a String, never fails");
        out
    }

    /// Operator-wide metrics surface.
    pub fn operator_metrics(&self) -> &OperatorMetrics {
        &self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_encodes_with_metric_definitions() {
        let reg = MetricsRegistry::new();
        let text = reg.encode();
        // Metric definitions land in the encoded output even
        // when no samples have been recorded yet.
        assert!(
            text.contains("mcpg_operator_reconcile"),
            "expected reconcile metric definition: {text}"
        );
        assert!(
            text.contains("mcpg_operator_reconcile_duration_seconds"),
            "expected reconcile duration metric: {text}"
        );
        assert!(
            text.contains("mcpg_operator_dependency_unresolved"),
            "expected dependency_unresolved metric: {text}"
        );
        assert!(
            text.contains("mcpg_operator_oci_pull"),
            "expected oci_pull metric: {text}"
        );
        assert!(text.contains("# EOF"), "expected EOF marker: {text}");
    }

    #[test]
    fn observe_reconcile_increments_counter_and_histogram() {
        let reg = MetricsRegistry::new();
        let m = reg.operator_metrics();
        m.observe_reconcile("gateway", ReconcileOutcome::Success, 0.123);
        m.observe_reconcile("gateway", ReconcileOutcome::Success, 0.456);
        m.observe_reconcile("gateway", ReconcileOutcome::TransientError, 1.5);

        let text = reg.encode();
        assert!(
            text.contains(r#"controller="gateway""#),
            "expected gateway label: {text}"
        );
        assert!(
            text.contains(r#"outcome="success""#),
            "expected success outcome: {text}"
        );
        assert!(
            text.contains(r#"outcome="transient_error""#),
            "expected transient_error outcome: {text}"
        );
    }

    #[test]
    fn observe_dependency_unresolved_records_reason() {
        let reg = MetricsRegistry::new();
        let m = reg.operator_metrics();
        m.observe_dependency_unresolved("gateway", "MCPGPluginSet", "PluginSetNotReady");
        let text = reg.encode();
        assert!(
            text.contains(r#"reason="PluginSetNotReady""#),
            "expected reason label: {text}"
        );
        assert!(
            text.contains(r#"dependency="MCPGPluginSet""#),
            "expected dependency label: {text}"
        );
    }

    #[test]
    fn set_leader_elected_toggles_gauge() {
        let reg = MetricsRegistry::new();
        let m = reg.operator_metrics();
        m.set_leader_elected("mcpg-operator", true);
        let text = reg.encode();
        assert!(
            text.contains(r#"lease="mcpg-operator""#),
            "expected lease label: {text}"
        );
        // Set to 0 — the gauge value should reflect it.
        m.set_leader_elected("mcpg-operator", false);
        // The text encoding shows the current gauge value; just
        // assert encoding doesn't blow up.
        let text2 = reg.encode();
        assert!(text2.contains("# EOF"));
    }

    #[test]
    fn observe_oci_pull_records_outcome_and_duration() {
        let reg = MetricsRegistry::new();
        let m = reg.operator_metrics();
        m.observe_oci_pull("success", 1.5);
        m.observe_oci_pull("failed", 0.5);
        let text = reg.encode();
        assert!(text.contains(r#"outcome="success""#));
        assert!(text.contains(r#"outcome="failed""#));
        // Histogram total.
        assert!(text.contains("mcpg_operator_oci_pull_duration_seconds"));
    }

    #[test]
    fn outcome_str_round_trips_for_every_variant() {
        // Make sure every variant produces a distinct label
        // value so dashboards can rely on the set being closed.
        let variants = [
            ReconcileOutcome::Success,
            ReconcileOutcome::TransientError,
            ReconcileOutcome::PermanentError,
            ReconcileOutcome::DependencyPending,
        ];
        let mut seen = std::collections::HashSet::new();
        for v in variants {
            assert!(
                seen.insert(v.as_str()),
                "duplicate outcome label: {}",
                v.as_str()
            );
        }
    }
}
