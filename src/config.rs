//! Operator startup config.
//!
//! Three sources, in priority order: CLI flags > env vars > defaults.
//! `clap`'s derive does the work via `env = "..."` attributes.

use std::path::PathBuf;

use clap::Parser;

/// MCPG Kubernetes operator.
///
/// Reconciles `mcpg.dev/MCPGGateway` resources into running
/// gateway Deployments. Designed to run inside a cluster as a
/// 2-replica Deployment with leader election, but supports
/// out-of-cluster execution for development.
#[derive(Debug, Clone, Parser)]
#[command(version, about, long_about = None)]
pub struct OperatorConfig {
    /// Operator binding address for the metrics + healthz HTTPS
    /// server. Defaults to `0.0.0.0:8443`.
    #[arg(
        long,
        env = "MCPG_OPERATOR_METRICS_BIND",
        default_value = "0.0.0.0:8443"
    )]
    pub metrics_bind: String,

    /// Webhook server bind address.
    #[arg(
        long,
        env = "MCPG_OPERATOR_WEBHOOK_BIND",
        default_value = "0.0.0.0:9443"
    )]
    pub webhook_bind: String,

    /// Path to the TLS cert + key the webhook server presents.
    /// Helm chart wires these via cert-manager-projected volumes.
    /// When unset, the webhook server is disabled (operator runs
    /// in reconcile-only mode — useful for dev).
    #[arg(long, env = "MCPG_OPERATOR_TLS_CERT_DIR")]
    pub tls_cert_dir: Option<PathBuf>,

    /// Leader election toggle. Defaults to true (production).
    /// Pass `--no-leader-election` to disable for dev /
    /// single-replica.
    #[arg(
        long,
        env = "MCPG_OPERATOR_LEADER_ELECTION",
        default_value_t = true,
        action = clap::ArgAction::Set,
    )]
    pub leader_election: bool,

    /// Lease name for leader election.
    #[arg(
        long,
        env = "MCPG_OPERATOR_LEASE_NAME",
        default_value = "mcpg-operator"
    )]
    pub lease_name: String,

    /// Namespace where the operator's Lease lives. Operator's own
    /// namespace by default.
    #[arg(
        long,
        env = "MCPG_OPERATOR_LEASE_NAMESPACE",
        default_value = "mcpg-system"
    )]
    pub lease_namespace: String,

    /// Lease duration in seconds.
    #[arg(long, env = "MCPG_OPERATOR_LEASE_DURATION_SECS", default_value_t = 30)]
    pub lease_duration_secs: u64,

    /// Lease renew deadline in seconds (must be < lease_duration).
    #[arg(long, env = "MCPG_OPERATOR_LEASE_RENEW_SECS", default_value_t = 20)]
    pub lease_renew_secs: u64,

    /// Lease retry period in seconds.
    #[arg(long, env = "MCPG_OPERATOR_LEASE_RETRY_SECS", default_value_t = 4)]
    pub lease_retry_secs: u64,

    /// This pod's identity (used as the leader-election holder
    /// identity). Pods get a unique value via the downward-API
    /// envar `POD_NAME`.
    #[arg(long, env = "POD_NAME", default_value = "mcpg-operator")]
    pub pod_name: String,

    /// Periodic reconcile interval (jittered ±20%) in seconds.
    /// Catches missed watch events.
    #[arg(
        long,
        env = "MCPG_OPERATOR_RESYNC_INTERVAL_SECS",
        default_value_t = 600
    )]
    pub resync_interval_secs: u64,

    /// Per-controller concurrent reconcile budget. Higher values
    /// = more parallelism but more apiserver pressure.
    #[arg(long, env = "MCPG_OPERATOR_RECONCILE_CONCURRENCY", default_value_t = 8)]
    pub reconcile_concurrency: usize,

    /// Restrict watches to one namespace (operator's own
    /// namespace + this namespace's CRDs only). Empty = watch
    /// every namespace.
    #[arg(long, env = "MCPG_OPERATOR_WATCH_NAMESPACE")]
    pub watch_namespace: Option<String>,

    /// Name of the operator's own ServiceAccount. Used as the
    /// subject reference when the operator dynamically creates
    /// per-tenant RoleBindings for the
    /// `mcpg-operator-tenant-secrets` ClusterRole (write blast
    /// radius bounded to namespaces with active MCPGPluginSets).
    /// The Helm chart sets this via a
    /// downward-API env var so the operator's pod and the chart's
    /// rendered RBAC can never disagree on the SA name.
    #[arg(
        long,
        env = "MCPG_OPERATOR_SERVICE_ACCOUNT",
        default_value = "mcpg-operator"
    )]
    pub operator_service_account: String,

    /// Log format: `pretty` or `json`.
    #[arg(long, env = "MCPG_OPERATOR_LOG_FORMAT", default_value = "json")]
    pub log_format: LogFormat,

    /// Log level filter (RUST_LOG-style directive).
    #[arg(long, env = "RUST_LOG", default_value = "mcpg_operator=info,kube=warn")]
    pub log_filter: String,

    /// Air-gap: path to a pre-mirrored Sigstore `trusted_root.json`
    /// (TUF metadata). When set, cosign keyless verification loads its
    /// trust root from this file with NO network access — required in
    /// air-gapped clusters where `tuf-repo-cdn.sigstore.dev` is
    /// unreachable. Mount it from a ConfigMap (e.g. `mcpg-trust-roots`)
    /// the sync station populates. When unset, the trust root is
    /// fetched from the public Sigstore TUF CDN (the default).
    #[arg(long, env = "MCPG_OPERATOR_SIGSTORE_TRUST_ROOT")]
    pub sigstore_trust_root_path: Option<PathBuf>,

    /// cert-manager `ClusterIssuer` used to issue TLS certificates for
    /// VERIFIED tenant custom domains (managed cloud). When set, the gateway
    /// controller renders a cert-manager `Certificate` per custom domain in
    /// the edge namespace (next to the per-domain Gateway listener it also
    /// manages), and cert-manager solves HTTP-01 through the edge. When
    /// unset, listeners are still managed but no Certificates are created —
    /// the operator logs that custom-domain TLS needs a manually-provisioned
    /// secret. The issuer must carry an HTTP-01 `gatewayHTTPRoute` solver
    /// (see the `mcpg-cloud-edge` chart's `certManager.http01`).
    #[arg(long, env = "MCPG_OPERATOR_EDGE_CLUSTER_ISSUER")]
    pub edge_cluster_issuer: Option<String>,

    /// Comma-separated plugin ids the gateway controller injects as
    /// `plugins[]` entries into every MANAGED-CLOUD gateway config
    /// (`spec.cloud` set), pointing at the backend cdylibs baked into
    /// the published gateway images under
    /// `/usr/local/lib/mcpg/plugins/<id>/plugin.so`. Unset = the
    /// standard first-party backend set; an explicitly empty value
    /// disables the injection. Self-host CRs never receive these
    /// entries — their image may not carry the artifacts, and the
    /// gateway refuses to boot on a missing `source.path`.
    #[arg(long, env = "MCPG_OPERATOR_CLOUD_DEFAULT_PLUGINS")]
    pub cloud_default_plugins: Option<String>,

    /// Default OTLP traces destination for CLOUD-provisioned gateways.
    /// When set, every rendered tenant-gateway config whose author did not
    /// declare `observability.traces` gets traces enabled through the
    /// dev.mcpg.observability.otlp sink at this URL (typically an in-cluster
    /// collector, e.g. http://otel-collector.monitoring.svc:4317). A config
    /// that declares its own traces block is left untouched. Unset = no
    /// injection.
    #[arg(long, env = "MCPG_OPERATOR_DEFAULT_OTLP_TRACES_URL")]
    pub default_otlp_traces_url: Option<String>,

    /// Extra pod annotations stamped on every rendered gateway pod, as
    /// comma-separated key=value pairs (e.g.
    /// "prometheus.io/scrape=true,prometheus.io/port=8080"). A CR's own
    /// spec.podAnnotations override these on collision; operator-managed
    /// hash annotations always win last.
    #[arg(long, env = "MCPG_OPERATOR_GATEWAY_POD_ANNOTATIONS")]
    pub gateway_pod_annotations: Option<String>,

    /// Run this operator as a PULL-MODE cell agent in addition to its normal
    /// controllers.
    ///
    /// In pull mode the provisioner cannot dial this cluster — that is the
    /// whole point — so the operator dials out instead, receives the objects
    /// the fleet wants applied, verifies the fleet's signature, and applies
    /// them with its own in-cluster ServiceAccount. No cluster credential ever
    /// leaves the cell. Off by default; a push-attached cell needs none of it.
    #[arg(long, env = "MCPG_OPERATOR_FLEET_ATTACH", default_value_t = false)]
    pub fleet_attach: bool,

    /// Fleet-plane gRPC endpoint to dial (the provisioner's
    /// `PROVISIONER_BIND_FLEET` listener), e.g.
    /// `https://fleet.mcpg.cloud:7102`. Required with `--fleet-attach`.
    #[arg(long, env = "MCPG_OPERATOR_FLEET_ENDPOINT")]
    pub fleet_endpoint: Option<String>,

    /// Path to the cell enrolment token, from `mcpg admin cluster register
    /// --attach pull`. PREFERRED over `--fleet-token`: a file can come from a
    /// mounted Secret, while a flag or env var shows up in `kubectl describe
    /// pod`.
    #[arg(long, env = "MCPG_OPERATOR_FLEET_TOKEN_FILE")]
    pub fleet_token_file: Option<PathBuf>,

    /// Cell enrolment token, inline. Use `--fleet-token-file` in production.
    #[arg(long, env = "MCPG_OPERATOR_FLEET_TOKEN")]
    pub fleet_token: Option<String>,

    /// This cell's edge load-balancer address, reported on the fleet
    /// heartbeat so DNS can be pointed at it. Empty leaves whatever the fleet
    /// already recorded rather than blanking it.
    #[arg(long, env = "MCPG_OPERATOR_FLEET_EDGE_ADDRESS", default_value = "")]
    pub fleet_edge_address: String,

    /// Seconds between fleet heartbeats. The heartbeat carries this cell's
    /// capacity, which is the fleet's ONLY capacity signal for a pull cell —
    /// nothing outside it can reach its apiserver.
    #[arg(long, env = "MCPG_OPERATOR_FLEET_HEARTBEAT_SECS", default_value_t = 30)]
    pub fleet_heartbeat_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum LogFormat {
    Pretty,
    Json,
}

impl OperatorConfig {
    /// The gateway-pod annotation defaults, parsed. Malformed pairs (no `=`)
    /// are skipped with a warning rather than failing reconciles.
    pub fn gateway_pod_annotations_map(&self) -> std::collections::BTreeMap<String, String> {
        let mut out = std::collections::BTreeMap::new();
        let Some(raw) = self.gateway_pod_annotations.as_deref() else {
            return out;
        };
        for pair in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match pair.split_once('=') {
                Some((k, v)) if !k.trim().is_empty() => {
                    out.insert(k.trim().to_owned(), v.trim().to_owned());
                }
                _ => tracing::warn!(pair, "gateway_pod_annotations: skipping malformed pair"),
            }
        }
        out
    }

    /// Parse from CLI args + env vars. Aborts the process on
    /// invalid input (clap's default behaviour).
    pub fn from_args() -> Self {
        Self::parse()
    }

    /// True when the webhook server is enabled (TLS cert dir was
    /// provided). When false the operator runs reconcile-only.
    pub fn webhook_enabled(&self) -> bool {
        self.tls_cert_dir.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn gateway_pod_annotations_parse_and_skip_malformed() {
        let cfg = OperatorConfig::try_parse_from([
            "mcpg-operator",
            "--gateway-pod-annotations=prometheus.io/scrape=true, prometheus.io/port=8080 ,broken,=novalue",
        ])
        .unwrap();
        let map = cfg.gateway_pod_annotations_map();
        assert_eq!(
            map.get("prometheus.io/scrape").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            map.get("prometheus.io/port").map(String::as_str),
            Some("8080")
        );
        assert_eq!(map.len(), 2, "malformed pairs are skipped: {map:?}");
    }

    #[test]
    fn defaults_sane() {
        let cfg = OperatorConfig::try_parse_from(["mcpg-operator"]).unwrap();
        assert_eq!(cfg.metrics_bind, "0.0.0.0:8443");
        assert_eq!(cfg.webhook_bind, "0.0.0.0:9443");
        assert!(cfg.leader_election);
        assert_eq!(cfg.lease_name, "mcpg-operator");
        assert_eq!(cfg.resync_interval_secs, 600);
        assert!(!cfg.webhook_enabled());
    }

    #[test]
    fn cli_overrides_defaults() {
        let cfg = OperatorConfig::try_parse_from([
            "mcpg-operator",
            "--leader-election",
            "false",
            "--watch-namespace=payments",
        ])
        .unwrap();
        assert!(!cfg.leader_election);
        assert_eq!(cfg.watch_namespace.as_deref(), Some("payments"));
    }

    #[test]
    fn fleet_attach_is_off_by_default() {
        // A push-attached cell must need none of this wiring.
        let cfg = OperatorConfig::try_parse_from(["mcpg-operator"]).unwrap();
        assert!(!cfg.fleet_attach);
        assert_eq!(cfg.fleet_endpoint, None);
        assert_eq!(cfg.fleet_heartbeat_secs, 30);
    }

    #[test]
    fn fleet_flags_parse() {
        let cfg = OperatorConfig::try_parse_from([
            "mcpg-operator",
            "--fleet-attach",
            "--fleet-endpoint=https://fleet.mcpg.cloud:7102",
            "--fleet-token-file=/var/run/secrets/mcpg/cell-token",
            "--fleet-edge-address=203.0.113.10",
            "--fleet-heartbeat-secs=15",
        ])
        .unwrap();
        assert!(cfg.fleet_attach);
        assert_eq!(
            cfg.fleet_endpoint.as_deref(),
            Some("https://fleet.mcpg.cloud:7102")
        );
        assert_eq!(
            cfg.fleet_token_file.as_deref(),
            Some(std::path::Path::new("/var/run/secrets/mcpg/cell-token"))
        );
        assert_eq!(cfg.fleet_edge_address, "203.0.113.10");
        assert_eq!(cfg.fleet_heartbeat_secs, 15);
    }

    #[test]
    fn cloud_default_plugins_unset_is_none() {
        // Force the var unset for this read and take `temp_env`'s lock, so a
        // sibling test setting it (same process, plain `cargo test`) cannot
        // race a value into this parse.
        temp_env::with_var_unset("MCPG_OPERATOR_CLOUD_DEFAULT_PLUGINS", || {
            let cfg = OperatorConfig::try_parse_from(["mcpg-operator"]).unwrap();
            assert_eq!(cfg.cloud_default_plugins, None);
        });
    }

    /// A SET-but-empty env var must parse as `Some("")` — the explicit
    /// "defaults disabled" state, distinct from unset (= standard set).
    #[test]
    fn cloud_default_plugins_empty_env_is_some_empty() {
        // Scope the env mutation so it cannot leak into sibling tests that
        // run in the same process (plain `cargo test`); `temp_env` also
        // serializes concurrent env access behind its own lock.
        temp_env::with_var("MCPG_OPERATOR_CLOUD_DEFAULT_PLUGINS", Some(""), || {
            let cfg = OperatorConfig::try_parse_from(["mcpg-operator"]).unwrap();
            assert_eq!(cfg.cloud_default_plugins.as_deref(), Some(""));
        });
    }

    #[test]
    fn cloud_default_plugins_env_csv_parses() {
        temp_env::with_var(
            "MCPG_OPERATOR_CLOUD_DEFAULT_PLUGINS",
            Some("dev.mcpg.backend.http,dev.mcpg.backend.mock"),
            || {
                let cfg = OperatorConfig::try_parse_from(["mcpg-operator"]).unwrap();
                assert_eq!(
                    cfg.cloud_default_plugins.as_deref(),
                    Some("dev.mcpg.backend.http,dev.mcpg.backend.mock")
                );
            },
        );
    }
}
