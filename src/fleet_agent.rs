//! `--fleet-attach`: run the operator as a pull-mode cell agent.
//!
//! The operator normally only reconciles CRs that someone else put in its
//! apiserver. In a pull cell there is no "someone else" with reach — the
//! provisioner cannot dial in, which is the entire reason pull mode exists — so
//! the operator additionally dials OUT, receives the objects the fleet wants
//! applied, and writes them itself.
//!
//! What it is NOT is a second scheduler. It never decides what should run: it
//! verifies the fleet's signature on pre-rendered objects, applies them with
//! its own in-cluster ServiceAccount, and reports what it converged on. The
//! decision logic lives in the provisioner, and the loop that drives this lives
//! in `mcpg-fleet-proto` so it is tested without a cluster.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use k8s_openapi::api::core::v1::{Namespace, Node, Pod};
use kube::api::{Api, DeleteParams, DynamicObject, Patch, PatchParams, PropagationPolicy};
use kube::discovery::{Discovery, Scope};
use kube::{Client, ResourceExt};
use mcpg_fleet_proto::agent::{CellObservation, LocalApplier};
use mcpg_fleet_proto::cell_control_client::CellControlClient;
use mcpg_fleet_proto::{CellMessage, RegisterCellRequest};
use tracing::{error, info, warn};

/// Field manager for everything the agent applies. Disjoint from the
/// provisioner's (`mcpg-provisioner/applier`) and from the operator's own
/// controllers, so the three never contend for the same fields.
const FIELD_MANAGER: &str = "mcpg-cell-agent";

/// Backoff bounds for reconnecting. A reconnect is cheap by design — the
/// provisioner re-sends whatever this cell has not acked — so the agent retries
/// forever rather than exiting and taking the operator's controllers with it.
const RECONNECT_MIN: Duration = Duration::from_secs(2);
const RECONNECT_MAX: Duration = Duration::from_secs(60);

/// Applies fleet objects with the cell's own in-cluster credentials.
pub struct KubeCellApplier {
    client: Client,
    /// Resolved once per apply pass: an assignment can carry kinds the cache
    /// has not seen (a CRD installed after the agent started).
    discovery: tokio::sync::Mutex<Option<Discovery>>,
}

impl KubeCellApplier {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            discovery: tokio::sync::Mutex::new(None),
        }
    }

    /// Resolve a `DynamicObject`'s kind to a typed API handle.
    ///
    /// Discovery is cached but re-run when a kind is unknown: a fleet
    /// assignment can reference a CRD that was installed after this agent
    /// started, and failing there would wedge the cell until it restarted.
    async fn api_for(&self, obj: &DynamicObject) -> anyhow::Result<Api<DynamicObject>> {
        let gvk = obj
            .types
            .as_ref()
            .map(|t| {
                kube::api::GroupVersionKind::try_from(t)
                    .map_err(|e| anyhow::anyhow!("unparseable apiVersion/kind: {e}"))
            })
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("object is missing apiVersion/kind"))?;

        let mut guard = self.discovery.lock().await;
        for attempt in 0..2 {
            if guard.is_none() || attempt == 1 {
                *guard = Some(
                    Discovery::new(self.client.clone())
                        .run()
                        .await
                        .context("kube discovery")?,
                );
            }
            if let Some((ar, caps)) = guard.as_ref().and_then(|d| d.resolve_gvk(&gvk)) {
                let ns = obj.namespace();
                return Ok(match (caps.scope, ns) {
                    (Scope::Namespaced, Some(ns)) => {
                        Api::namespaced_with(self.client.clone(), &ns, &ar)
                    }
                    // A namespaced object with no namespace of its own belongs
                    // to the assignment's namespace; the caller sets it before
                    // we get here, so this is the defensive branch.
                    (Scope::Namespaced, None) => {
                        Api::default_namespaced_with(self.client.clone(), &ar)
                    }
                    (Scope::Cluster, _) => Api::all_with(self.client.clone(), &ar),
                });
            }
        }
        Err(anyhow::anyhow!(
            "no server resource for {}/{} — is the CRD installed in this cell?",
            gvk.group,
            gvk.kind
        ))
    }
}

#[async_trait::async_trait]
impl LocalApplier for KubeCellApplier {
    async fn apply(&self, namespace: &str, objects: &[Vec<u8>]) -> anyhow::Result<()> {
        let pp = PatchParams::apply(FIELD_MANAGER).force();
        for (i, raw) in objects.iter().enumerate() {
            let mut obj: DynamicObject = serde_json::from_slice(raw)
                .with_context(|| format!("object {i} in the assignment is not valid JSON"))?;
            let name = obj
                .metadata
                .name
                .clone()
                .ok_or_else(|| anyhow::anyhow!("object {i} has no metadata.name"))?;
            // Namespaced objects are pinned to the assignment's namespace. The
            // provisioner already renders them that way; re-stamping means a
            // malformed or hand-edited object cannot land somewhere else.
            if obj.metadata.namespace.is_some() {
                obj.metadata.namespace = Some(namespace.to_owned());
            }
            let api = self.api_for(&obj).await?;
            api.patch(&name, &pp, &Patch::Apply(&obj))
                .await
                .with_context(|| format!("apply {name}"))?;
        }
        Ok(())
    }

    async fn delete_instance(&self, namespace: &str, instance_uid: &str) -> anyhow::Result<()> {
        // The gateway CR's name IS the canonical instance id, so create and
        // delete agree on identity.
        let api: Api<mcpg_operator_api::v1alpha1::MCPGGateway> =
            Api::namespaced(self.client.clone(), namespace);
        let dp = DeleteParams {
            propagation_policy: Some(PropagationPolicy::Foreground),
            ..Default::default()
        };
        match api.delete(instance_uid, &dp).await {
            Ok(_) => Ok(()),
            // 404-tolerant: a repeated revocation must converge, not error
            // forever.
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(anyhow::anyhow!("delete gateway {instance_uid}: {e}")),
        }
    }

    async fn delete_namespace(&self, namespace: &str) -> anyhow::Result<()> {
        let api: Api<Namespace> = Api::all(self.client.clone());
        let dp = DeleteParams {
            propagation_policy: Some(PropagationPolicy::Foreground),
            ..Default::default()
        };
        match api.delete(namespace, &dp).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(anyhow::anyhow!("delete namespace {namespace}: {e}")),
        }
    }

    async fn observe(&self) -> anyhow::Result<CellObservation> {
        let nodes: Api<Node> = Api::all(self.client.clone());
        let mut allocatable_cpu_m = 0i64;
        let mut allocatable_mem_bytes = 0i64;
        for node in nodes.list(&Default::default()).await?.iter() {
            // A cordoned or NotReady node contributes nothing — which is what
            // we want the allocator to believe.
            let cordoned = node
                .spec
                .as_ref()
                .and_then(|s| s.unschedulable)
                .unwrap_or(false);
            let ready = node
                .status
                .as_ref()
                .and_then(|s| s.conditions.as_ref())
                .map(|cs| cs.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
                .unwrap_or(false);
            if cordoned || !ready {
                continue;
            }
            if let Some(alloc) = node.status.as_ref().and_then(|s| s.allocatable.as_ref()) {
                if let Some(q) = alloc.get("cpu") {
                    allocatable_cpu_m += parse_cpu_millicores(&q.0);
                }
                if let Some(q) = alloc.get("memory") {
                    allocatable_mem_bytes += parse_memory_bytes(&q.0);
                }
            }
        }

        let pods: Api<Pod> = Api::all(self.client.clone());
        let mut requested_cpu_m = 0i64;
        let mut requested_mem_bytes = 0i64;
        for pod in pods.list(&Default::default()).await?.iter() {
            // Terminal pods hold no reservation.
            if matches!(
                pod.status.as_ref().and_then(|s| s.phase.as_deref()),
                Some("Succeeded") | Some("Failed")
            ) {
                continue;
            }
            let Some(spec) = pod.spec.as_ref() else {
                continue;
            };
            for c in &spec.containers {
                let Some(req) = c.resources.as_ref().and_then(|r| r.requests.as_ref()) else {
                    continue;
                };
                if let Some(q) = req.get("cpu") {
                    requested_cpu_m += parse_cpu_millicores(&q.0);
                }
                if let Some(q) = req.get("memory") {
                    requested_mem_bytes += parse_memory_bytes(&q.0);
                }
            }
        }

        let gateways: Api<mcpg_operator_api::v1alpha1::MCPGGateway> = Api::all(self.client.clone());
        let gateway_count = gateways
            .list_metadata(&Default::default())
            .await
            .map(|l| l.items.len() as i32)
            .unwrap_or(0);

        Ok(CellObservation {
            allocatable_cpu_m,
            allocatable_mem_bytes,
            requested_cpu_m,
            requested_mem_bytes,
            gateway_count,
        })
    }
}

/// Kubernetes CPU quantity to millicores. Unparseable input contributes 0
/// rather than poisoning the whole sum.
fn parse_cpu_millicores(q: &str) -> i64 {
    let q = q.trim();
    if let Some(m) = q.strip_suffix('m') {
        return m.parse::<f64>().map(|v| v as i64).unwrap_or(0);
    }
    q.parse::<f64>().map(|v| (v * 1000.0) as i64).unwrap_or(0)
}

/// Kubernetes memory quantity to bytes, handling both the binary (Ki/Mi/Gi) and
/// decimal (K/M/G) suffixes. The binary forms are checked first so `Mi` is not
/// mistaken for `M`.
fn parse_memory_bytes(q: &str) -> i64 {
    let q = q.trim();
    const UNITS: &[(&str, i64)] = &[
        ("Ki", 1 << 10),
        ("Mi", 1 << 20),
        ("Gi", 1 << 30),
        ("Ti", 1i64 << 40),
        ("Pi", 1i64 << 50),
        ("k", 1_000),
        ("K", 1_000),
        ("M", 1_000_000),
        ("G", 1_000_000_000),
        ("T", 1_000_000_000_000),
    ];
    for (suffix, mult) in UNITS {
        if let Some(v) = q.strip_suffix(suffix) {
            return v
                .parse::<f64>()
                .map(|n| (n * *mult as f64) as i64)
                .unwrap_or(0);
        }
    }
    q.parse::<f64>().map(|v| v as i64).unwrap_or(0)
}

/// Enrol and hold the fleet channel, reconnecting forever.
///
/// Never returns on error: a cell whose agent gave up would look healthy (its
/// operator is still reconciling) while silently accepting no new work.
pub async fn run(
    client: Client,
    endpoint: String,
    token: String,
    edge_address: String,
    heartbeat_every: Duration,
) {
    let applier: Arc<dyn LocalApplier> = Arc::new(KubeCellApplier::new(client));
    let mut backoff = RECONNECT_MIN;

    loop {
        match attach_once(&applier, &endpoint, &token, &edge_address, heartbeat_every).await {
            Ok(()) => {
                info!("fleet agent: channel closed; reconnecting");
                backoff = RECONNECT_MIN;
            }
            Err(e) => {
                error!(error = %e, backoff_secs = backoff.as_secs(), "fleet agent: attach failed");
                backoff = (backoff * 2).min(RECONNECT_MAX);
            }
        }
        tokio::time::sleep(backoff).await;
    }
}

/// One enrol + channel lifetime. Returns `Ok` when the stream ends cleanly.
async fn attach_once(
    applier: &Arc<dyn LocalApplier>,
    endpoint: &str,
    token: &str,
    edge_address: &str,
    heartbeat_every: Duration,
) -> anyhow::Result<()> {
    let mut client = CellControlClient::connect(endpoint.to_owned())
        .await
        .with_context(|| format!("dial fleet endpoint {endpoint}"))?;

    let enrolled = client
        .register_cell(RegisterCellRequest {
            enrollment_token: token.to_owned(),
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            kube_version: String::new(),
        })
        .await
        .context("enrol with the fleet")?
        .into_inner();

    // The key that decides what this cell will accept. Delivered at enrolment
    // so a later transport compromise cannot substitute a signing key.
    let verify_key = mcpg_fleet_proto::verify_key_from_bytes(&enrolled.assignment_verify_key)
        .map_err(|e| anyhow::anyhow!("fleet verify key: {e}"))?;

    info!(
        cell = %enrolled.cell_name,
        cell_id = %enrolled.cell_id,
        "fleet agent: enrolled; opening channel"
    );

    let (out_tx, out_rx) = tokio::sync::mpsc::channel::<CellMessage>(64);
    let mut req = tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(out_rx));
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", enrolled.cell_jwt)
            .parse()
            .map_err(|e| anyhow::anyhow!("credential is not a valid header: {e}"))?,
    );
    let inbound = client
        .cell_channel(req)
        .await
        .context("open the fleet channel")?
        .into_inner();

    mcpg_fleet_proto::agent::run_loop(
        applier.clone(),
        verify_key,
        inbound,
        out_tx,
        heartbeat_every,
        edge_address.to_owned(),
    )
    .await;
    Ok(())
}

/// Read the enrolment token, preferring a file so it can come from a mounted
/// Secret rather than an env var visible in `kubectl describe pod`.
pub fn read_token(inline: Option<&str>, path: Option<&std::path::Path>) -> anyhow::Result<String> {
    if let Some(p) = path {
        let raw = std::fs::read_to_string(p)
            .with_context(|| format!("read fleet token from {}", p.display()))?;
        let t = raw.trim().to_owned();
        if t.is_empty() {
            anyhow::bail!("fleet token file {} is empty", p.display());
        }
        return Ok(t);
    }
    match inline.map(str::trim).filter(|t| !t.is_empty()) {
        Some(t) => {
            warn!(
                "fleet token supplied inline; prefer --fleet-token-file so it comes from a \
                 mounted Secret rather than the pod spec"
            );
            Ok(t.to_owned())
        }
        None => anyhow::bail!(
            "--fleet-attach needs a token: set --fleet-token-file (preferred) or --fleet-token"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_quantities_parse_to_millicores() {
        assert_eq!(parse_cpu_millicores("500m"), 500);
        assert_eq!(parse_cpu_millicores("2"), 2000);
        assert_eq!(parse_cpu_millicores("0.5"), 500);
        assert_eq!(parse_cpu_millicores("garbage"), 0);
    }

    #[test]
    fn memory_binary_suffixes_win_over_decimal_ones() {
        // `Mi` must not be read as `M`, or every cell reports ~5% more headroom
        // than it has.
        assert_eq!(parse_memory_bytes("512Mi"), 512 * (1 << 20));
        assert_eq!(parse_memory_bytes("1M"), 1_000_000);
        assert_ne!(parse_memory_bytes("512Mi"), parse_memory_bytes("512M"));
        assert_eq!(parse_memory_bytes("nope"), 0);
    }

    #[test]
    fn a_token_file_is_preferred_and_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "  CELL-abc\n").unwrap();
        assert_eq!(
            read_token(Some("CELL-inline"), Some(&path)).unwrap(),
            "CELL-abc",
            "the mounted Secret must win over the pod spec"
        );
    }

    #[test]
    fn an_empty_or_missing_token_is_a_hard_error() {
        // Starting the agent with no credential would loop forever on
        // unauthenticated, looking like a network fault.
        assert!(read_token(None, None).is_err());
        assert!(read_token(Some("   "), None).is_err());
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        std::fs::write(&empty, "\n").unwrap();
        assert!(read_token(None, Some(&empty)).is_err());
        assert!(read_token(None, Some(&dir.path().join("absent"))).is_err());
    }

    #[test]
    fn an_inline_token_still_works() {
        assert_eq!(read_token(Some("CELL-abc"), None).unwrap(), "CELL-abc");
    }
}
