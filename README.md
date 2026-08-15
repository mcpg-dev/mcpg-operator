# MCPG Operator — Kubernetes operator for the Model Context Protocol Gateway

The MCPG Operator runs MCP gateways as first-class Kubernetes objects. You
declare an `MCPGGateway` and it reconciles the Deployment, Service, ConfigMap,
and ServiceAccount behind it; you declare an `MCPGPlugin` and it pulls the
plugin's OCI artifact, verifies its signature against a cluster-pinned key,
checks it against the cluster revocation list, and materialises the verified
bytes as a Secret that gateway pods mount. Platform teams run it once per
cluster, in the `mcpg-system` namespace, and application teams then never touch
plugin distribution or gateway plumbing directly.

**Rust · nine `mcpg.dev/v1alpha1` custom resources · leader-elected HA · validating admission webhooks · Ed25519 + cosign keyless + SLSA L3 plugin trust**

## What it does

- Reconciles `MCPGGateway` into a Deployment, Service, ConfigMap, and
  ServiceAccount, applied server-side with owner references so parent deletion
  cascades.
- Renders the gateway's boot config by merging `spec.config` with resolved
  plugin entries, capability grants, and the revocation-list trust path, then
  folds the result's SHA-256 into the pod template so a config change rolls the
  pods.
- Pulls `MCPGPlugin` OCI artifacts, verifies them through the **same**
  `mcpg-plugin-host` code path the gateway runs at load time, and publishes the
  verified bytes as a Secret — admission-time and load-time trust decisions
  cannot drift.
- Resolves `MCPGPluginSet` entries into per-namespace plugin Secrets plus a
  resolved-set ConfigMap, and prunes Secrets left behind by removed entries.
- Fans the cluster-scoped `MCPGRevocationList` out as a per-namespace ConfigMap,
  mounts it into gateway pods, and points the rendered
  `gateway.plugin_registry.revocation_list_path` at it.
- Validates `MCPGCluster` coordination bindings and refuses to declare one
  bindable while its backing plugin is unverified.
- Scopes shared gateways per tenant from `MCPGRoute`, folding matched tools and
  attributes into `governance.policy.tool_access.rules[]`.
- Enforces `MCPGTenant` boundaries with an `mcpg.dev/tenant` namespace label,
  per-namespace Secret-write RBAC, and a generated `ResourceQuota` that the
  apiserver — not the webhook — enforces race-free.
- Rewrites plugin pulls through an in-cluster `MCPGPluginMirror` for air-gapped
  clusters, and loads a pre-mirrored Sigstore trust root with no network access.
- Provisions `MCPGServer` MCP workloads and auto-composes them into a target
  gateway's `mcp.federations[]`.
- Serves validating admission webhooks per kind, `/metrics`, `/healthz`, and
  `/readyz`, and elects a leader through a `coordination.k8s.io/v1` Lease so
  standby replicas keep warm caches without mutating anything.
- Renders `HorizontalPodAutoscaler` and `PodDisruptionBudget` children when
  `spec.autoscaling.enabled` / `spec.podDisruptionBudget.enabled` opt in. With
  an HPA in play the Deployment drops its static `replicas` so the two do not
  fight over the replica count.

## Install / Run

The operator ships as a container image and a Helm chart. The chart carries the
CRDs in its `crds/` directory, which Helm installs on the first install of the
release. The admission webhook fails closed, so its TLS must be real: enable
cert-manager or pre-provision the webhook Secret yourself.

```bash
helm install mcpg-operator ./helm/charts/mcpg-operator \
  --namespace mcpg-system --create-namespace \
  --set certManager.enabled=true
```

Full install walkthrough, including chart coordinates:
<https://mcpg.dev/docs/self-hosting/k8s-install>.

For development against a cluster your kubeconfig already points at, run it out
of process. Without `--tls-cert-dir` the webhooks are disabled and only the
metrics and health routes are served, which is the intended dev shape:

```bash
cargo run -p mcpg-operator -- --leader-election false --watch-namespace dev
```

CRD YAML is generated from the Rust types rather than hand-written:

```bash
cargo run -p mcpg-operator --bin crdgen -- --split-by-kind helm/charts/mcpg-operator/crds/
```

## Configuration

Every setting is a CLI flag with an environment-variable equivalent. Precedence
is flags, then environment, then the defaults below.

| Flag | Environment variable | Default | Description |
|---|---|---|---|
| `--metrics-bind` | `MCPG_OPERATOR_METRICS_BIND` | `0.0.0.0:8443` | Bind address for `/metrics`, `/healthz`, `/readyz`. |
| `--webhook-bind` | `MCPG_OPERATOR_WEBHOOK_BIND` | `0.0.0.0:9443` | Bind address for the admission webhook server. |
| `--tls-cert-dir` | `MCPG_OPERATOR_TLS_CERT_DIR` | unset | Directory holding `tls.crt` + `tls.key`. Unset disables the webhooks. |
| `--leader-election` | `MCPG_OPERATOR_LEADER_ELECTION` | `true` | Gate the reconcile loops on a Lease. Pass `--leader-election false` for single-replica development. |
| `--lease-name` | `MCPG_OPERATOR_LEASE_NAME` | `mcpg-operator` | Leader-election Lease name. |
| `--lease-namespace` | `MCPG_OPERATOR_LEASE_NAMESPACE` | `mcpg-system` | Namespace holding the Lease. |
| `--lease-duration-secs` | `MCPG_OPERATOR_LEASE_DURATION_SECS` | `30` | Lease duration. |
| `--lease-renew-secs` | `MCPG_OPERATOR_LEASE_RENEW_SECS` | `20` | Renew deadline; must be below the lease duration. |
| `--lease-retry-secs` | `MCPG_OPERATOR_LEASE_RETRY_SECS` | `4` | Acquisition retry period. |
| `--pod-name` | `POD_NAME` | `mcpg-operator` | Leader-election holder identity and the `instance` field on emitted Events. |
| `--resync-interval-secs` | `MCPG_OPERATOR_RESYNC_INTERVAL_SECS` | `600` | Periodic reconcile interval, jittered ±20%, to catch missed watch events. |
| `--reconcile-concurrency` | `MCPG_OPERATOR_RECONCILE_CONCURRENCY` | `8` | Per-controller concurrent reconcile budget. |
| `--watch-namespace` | `MCPG_OPERATOR_WATCH_NAMESPACE` | unset | Restrict watches to one namespace; unset watches every namespace. |
| `--operator-service-account` | `MCPG_OPERATOR_SERVICE_ACCOUNT` | `mcpg-operator` | Subject used when creating per-tenant RoleBindings. |
| `--log-format` | `MCPG_OPERATOR_LOG_FORMAT` | `json` | `pretty` or `json`. |
| `--log-filter` | `RUST_LOG` | `mcpg_operator=info,kube=warn` | `RUST_LOG`-style directive. |
| `--sigstore-trust-root-path` | `MCPG_OPERATOR_SIGSTORE_TRUST_ROOT` | unset | Path to a pre-mirrored Sigstore `trusted_root.json` for air-gapped cosign verification. |
| `--edge-cluster-issuer` | `MCPG_OPERATOR_EDGE_CLUSTER_ISSUER` | unset | cert-manager `ClusterIssuer` for verified custom-domain TLS. |
| `--cloud-default-plugins` | `MCPG_OPERATOR_CLOUD_DEFAULT_PLUGINS` | unset | Comma-separated backend plugin ids injected into gateways that set `spec.cloud`. Unset is the standard first-party set; an explicitly empty value disables injection. |

The last two apply only to gateways carrying a `spec.cloud` block; a self-hosted
`MCPGGateway` never receives injected plugin entries, because its image may not
carry the artifacts and the gateway refuses to boot on a missing `source.path`.

A minimal gateway. `image` and `config` are the two required fields; every key
inside `image` is optional and falls back to the published gateway image:

```yaml
apiVersion: mcpg.dev/v1alpha1
kind: MCPGGateway
metadata:
  name: gateway-minimal
  namespace: mcpg-apps
spec:
  replicas: 1
  image:
    repository: ghcr.io/mcpg-dev/source-code/gateway
  config:
    gateway:
      server:
        bind_address: "0.0.0.0:8787"
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 200m
      memory: 256Mi
```

The CR spec itself is camelCase, like any Kubernetes object. `spec.config` is
the exception: it is the gateway's own boot config, carried through to the
rendered ConfigMap, so it uses the gateway's snake_case keys — and the gateway
parses them with `deny_unknown_fields`, so a typo there fails at pod boot rather
than at admission. That schema is documented at
<https://mcpg.dev/docs/reference/configuration>.

## Custom resources

All nine kinds live in group `mcpg.dev`, version `v1alpha1`, and carry a
`status.conditions[]` in standard `metav1.Condition` shape so generic
"wait for `Ready=True`" tooling works across every kind.

| Kind | Scope | Short name | Purpose |
|---|---|---|---|
| `MCPGGateway` | Namespaced | `mcpgw` | A gateway deployment and everything it mounts. |
| `MCPGPluginSet` | Namespaced | `mcpgps` | The bundle of plugins one namespace's gateways load. |
| `MCPGRoute` | Namespaced | `mcpgr` | A soft-tenancy route into a shared gateway. |
| `MCPGServer` | Namespaced | `mcpgs` | An in-cluster MCP server workload, optionally auto-federated. |
| `MCPGPlugin` | Cluster | `mcpgp` | One signed plugin artifact and its trust requirements. |
| `MCPGCluster` | Cluster | `mcpgc` | A cluster-coordination backend binding. |
| `MCPGRevocationList` | Cluster | `mcpgrl` | Revoked plugin SHA-256 digests. |
| `MCPGPluginMirror` | Cluster | `mcpgm` | An in-cluster OCI mirror for air-gapped pulls. |
| `MCPGTenant` | Cluster | `mcpgt` | A declarative tenant boundary: namespaces, plugin allowlist, quotas. |

The operator treats a single `MCPGRevocationList` named `cluster-default` as
authoritative; others are advisory. Field-level reference:
<https://mcpg.dev/docs/reference/operator-crds>.

## Plugin trust

An `MCPGPlugin` passes through up to three independent gates before its bytes
become a mountable Secret.

1. **Ed25519 detached signature**, always. The trusted public key comes from a
   Secret the operator pins, and the cluster revocation list is materialised
   first so a fresh revocation blocks the very next reconcile. The verifier is
   `mcpg_plugin_host::native::verify_native_artifact` — literally the function
   the gateway calls at load time.
2. **Cosign keyless**, when `spec.trust.cosignIdentity` is set. The OCI image
   must carry a Sigstore signature matching the declared certificate-identity
   regexp and OIDC issuer.
3. **SLSA L3 provenance**, when `spec.trust.slsaProvenance` is set. The in-toto
   build attestation must match the configured source URI and tag.

A plugin whose descriptor id disagrees with `spec.pluginId` is rejected, and a
`MCPGPluginSet` entry naming a plugin that is missing, not `Ready`, or revoked
is refused rather than silently skipped.

In an air-gapped cluster, point `--sigstore-trust-root-path` at a
`trusted_root.json` mirrored by your sync station and cosign verification does no
network I/O at all. See <https://mcpg.dev/docs/self-hosting/air-gap>.

## Security posture

- **Bounded write blast radius.** The operator's ClusterRole carries no
  cluster-wide Secret write verbs. It creates a RoleBinding to the
  `mcpg-operator-tenant-secrets` ClusterRole in each namespace that actually
  hosts an `MCPGPluginSet`, so Secret writes are confined to namespaces with
  active plugin sets.
- **Webhooks require TLS.** With no `--tls-cert-dir` the operator logs a
  warning and serves only metrics and health routes; it never exposes admission
  handlers over plaintext.
- **Quotas are enforced by the apiserver.** `MCPGTenant` count quotas become a
  generated `ResourceQuota`; the admission webhook's count check would be racy
  and is deliberately not the enforcement point. The webhook enforces only what
  a `ResourceQuota` cannot express — the plugin allowlist and the per-gateway
  replica cap.
- **Admission fails open on lookup error, controllers fail closed on trust.**
  A transient failure reading the tenant list admits the request and logs,
  because admission must not wedge the apiserver; the durable guarantees are the
  `ResourceQuota` and RBAC. Signature and revocation failures, by contrast,
  block the plugin. `MCPGServer` image verification is fail-closed for a new or
  changed spec and fail-static for an already-running Deployment, so a registry
  outage cannot tear down a serving workload.
- **Namespace scoping.** `--watch-namespace` restricts every watch to one
  namespace for a per-team operator install.

## Observability

Metrics are exposed on the `--metrics-bind` listener under the `mcpg_operator`
prefix.

| Metric family | Labels | Meaning |
|---|---|---|
| `mcpg_operator_reconcile` | `controller`, `outcome` | Reconciles by controller and outcome. |
| `mcpg_operator_reconcile_duration_seconds` | `controller` | Reconcile duration histogram. |
| `mcpg_operator_dependency_unresolved` | `controller`, `dependency`, `reason` | Reconciles that paused waiting on a dependent resource. |
| `mcpg_operator_last_reconcile_timestamp_seconds` | `controller` | Unix timestamp of the most recent reconcile, success or failure. |
| `mcpg_operator_leader_elected` | `lease` | `1` when this process holds the lease. |
| `mcpg_operator_oci_pull` | `outcome` | Plugin pulls by outcome. |
| `mcpg_operator_oci_pull_duration_seconds` | — | Plugin pull duration histogram. |

`/healthz` and `/readyz` are served from the same listener, which is what the
chart's liveness and readiness probes target. Each controller emits Kubernetes
Events under its own reporting controller (`mcpg-operator/gateway`,
`mcpg-operator/plugin`, and so on) so `kubectl describe` attributes them
correctly.

## Development

```bash
cargo build -p mcpg-operator
cargo test  -p mcpg-operator
```

The test suite includes a guard that deserialises the operator's rendered
gateway config into the gateway's own `AppConfig`, exercising its
`deny_unknown_fields`, so a rendering drift fails here rather than at a user's
gateway boot.

Regenerate the chart's CRDs after changing any type in `mcpg-operator-api`, then
verify they are in sync:

```bash
cargo run -p mcpg-operator --bin crdgen -- --split-by-kind helm/charts/mcpg-operator/crds/
tools/operator/check-crds.sh
```

The end-to-end suite builds the operator image and drives a real cluster:

```bash
bash k8s/operator/e2e/run.sh
```

## Licence

BUSL-1.1. See [LICENSE](LICENSE).

## See also

- <https://mcpg.dev/docs/self-hosting/kubernetes-operator> — operator concepts
  and day-two operations.
- <https://mcpg.dev/docs/reference/operator-crds> — field-level CRD reference.
- <https://mcpg.dev/docs/self-hosting/k8s-install> — Kubernetes install.
- <https://mcpg.dev/docs/self-hosting/multi-tenant> — tenant boundaries and
  shared-gateway routing.
- <https://mcpg.dev/docs/security/plugin-security> — the signing and revocation
  model the plugin controller enforces.
