//! Operator-side merge of an `MCPGPluginSet`-driven plugin block
//! into the gateway's user-supplied `spec.config`. Produces the
//! final JSON the operator serialises to YAML for the gateway's
//! `/etc/mcpg/config.yaml`.
//!
//! The gateway daemon is configuration-blind to the operator —
//! it boots from a single rendered config and trusts it. The
//! operator's job is to materialise the gateway's top-level
//! `plugins:` array and `gateway.plugin_registry.revocation_list_path`
//! so the gateway sees a fully-baked config.
//!
//! Gateway config shape (the contract this module renders against)
//!
//! The gateway's `AppConfig.plugins` is a **bare array** of
//! `PluginEntryConfig` (`apps/gateway/src/config/plugins.rs`), and
//! `AppConfig` carries `#[serde(deny_unknown_fields)]`. Capability
//! grants are **per-entry** — each plugin entry carries its own
//! `granted_capabilities: [..]` list; there is no top-level
//! `plugins.capability_grants` map and no `plugins.entries`
//! wrapper object.
//!
//! Merge policy
//!
//! - When `pluginSetRef` is set on the `MCPGGateway`, the
//!   operator-derived `plugins:` array REPLACES whatever the user
//!   wrote under `spec.config.plugins`. Operators who want
//!   plugin-set-managed gateways should not hand-list plugins —
//!   admission warns when both are present, and the operator wins.
//! - `MCPGPluginSet.spec.capabilityGrants` (keyed by plugin id) are
//!   folded into each rendered entry's `granted_capabilities` list,
//!   since grants are per-entry in the gateway schema. Grants for a
//!   plugin id not in the set are dropped (the set replaces the whole
//!   plugin list, so such a plugin would not exist on the gateway).
//! - `gateway.plugin_registry.revocation_list_path` is set to the
//!   operator-chosen mount path when `revocationListRef` resolves
//!   to a live `MCPGRevocationList`. When the user has hand-set
//!   this field to a different path, the operator overrides it
//!   (the operator owns this trust gate). The field lives under
//!   `gateway.plugin_registry` (its point-of-use slot), not the
//!   former `plugins.trust:` umbrella.
//!
//! All paths assume the operator-managed pod template (see
//! `crate::templates::deployment::build_deployment`):
//!
//! - Plugin Secrets are projected into
//!   `/etc/mcpg/plugins/<plugin-id>/`.
//! - The revocation-list ConfigMap is projected into
//!   `/etc/mcpg/revocations/list.json`.

use std::collections::BTreeMap;

use serde_json::{Value, json};

/// Single entry as received from the `{set-name}-resolved`
/// ConfigMap's `plugins.json` document. Mirrors the JSON shape
/// the plugin-set controller emits — see
/// `controllers::plugin_set::render_resolved_set`.
#[derive(Debug, Clone)]
pub struct ResolvedSetEntry {
    pub id: String,
    pub plugin_class: String,
    pub plugin_version: String,
    pub artefact_secret_name: String,
    pub resolved_digest: String,
    pub config: Value,
}

/// View of the resolved set the gateway controller passes to
/// [`merge_plugins`]. Decoupled from the plugin-set controller's
/// internal `ResolvedEntry` so the controller can build it from
/// either the parsed `plugins.json` or a fixture in tests.
#[derive(Debug, Clone, Default)]
pub struct ResolvedSetView {
    pub entries: Vec<ResolvedSetEntry>,
    /// Per-plugin grants, keyed by plugin id. Lifted verbatim
    /// from `MCPGPluginSet.spec.capabilityGrants`.
    pub capability_grants: BTreeMap<String, Vec<String>>,
}

/// Where each plugin id's Secret is projected inside the gateway
/// pod's filesystem. `<id>` is the literal plugin id; the gateway
/// reads `plugin.so` + sidecar `plugin.yaml` from this prefix.
const PLUGIN_MOUNT_ROOT: &str = "/etc/mcpg/plugins";

/// Where the operator projects the active revocation list.
pub const REVOCATION_LIST_MOUNT_PATH: &str = "/etc/mcpg/revocations/list.json";

/// Directory inside the published gateway images where the standard
/// first-party backend cdylibs are baked: `<id>/plugin.so` plus the
/// optional capability sidecar `<id>/plugin.so.plugin.yaml` (the
/// gateway's raw-`.so` loader probes `<artifact-path>.plugin.yaml`).
/// The managed-cloud default entries rendered by
/// [`append_cloud_default_plugins`] point here. These paths only
/// resolve on the stock gateway images — a missing `source.path`
/// artifact fails gateway boot — which is why the entries are
/// rendered for cloud CRs only (a self-host CR may run any image).
pub const CLOUD_PLUGIN_IMAGE_ROOT: &str = "/usr/local/lib/mcpg/plugins";

/// The standard backend plugins every managed-cloud gateway carries by
/// default: the generic protocol backends baked into the published
/// gateway images. Each id is paired with the capability grants its
/// descriptor declares as required — host-service calls are filtered
/// per-alias fail-closed, so an under-granted entry would load but be
/// denied at dispatch (e.g. `cred://` resolution inside a binding).
///
/// Every id here must be a SINGLE-entity cdylib: the gateway's
/// raw-`.so` loader builds each same-class adapter from the plugin's
/// first vtable, so a multi-entity export (e.g. `dev.mcpg.backend.sql`,
/// which ships a backend plus two watch strategies) registers its
/// second entity as a duplicate kind and fails boot.
const CLOUD_DEFAULT_BACKEND_PLUGINS: &[(&str, &[&str])] = &[
    ("dev.mcpg.backend.mock", &[]),
    ("dev.mcpg.backend.http", &["network_outbound"]),
    ("dev.mcpg.backend.command", &[]),
    ("dev.mcpg.backend.graphql", &["network_outbound"]),
    ("dev.mcpg.backend.openapi", &["network_outbound"]),
    // NOTE: `backend.grpc` is intentionally NOT a cloud default — it is a BUSL
    // enterprise-system connector (feature `backend.enterprise`), so a community
    // tenant would be refused it at CP plugin-set bind. Team+ tenants add it
    // explicitly. Keep this list to free/Apache single-entity plugins only.
];

/// Resolve the plugin-id list for the managed-cloud defaults.
///
/// `override_csv` is the operator's `MCPG_OPERATOR_CLOUD_DEFAULT_PLUGINS`
/// setting: unset (`None`) selects the built-in standard set; a
/// comma-separated list replaces it; an explicitly empty value disables
/// the defaults entirely. Entries are trimmed and de-duplicated in
/// first-seen order (the gateway rejects duplicate plugin aliases).
pub fn cloud_default_plugin_ids(override_csv: Option<&str>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    match override_csv {
        None => CLOUD_DEFAULT_BACKEND_PLUGINS
            .iter()
            .map(|(id, _)| (*id).to_owned())
            .collect(),
        Some(csv) => csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter(|s| seen.insert(s.to_owned()))
            .map(str::to_owned)
            .collect(),
    }
}

/// Append the managed-cloud default backend entries to the rendered
/// config's `plugins:` array.
///
/// Runs after [`merge_plugins`], so it composes with every source of
/// entries: a resolved `MCPGPluginSet` and a hand-listed
/// `spec.config.plugins` both stay first-class, and any existing entry
/// whose `id` or `ref` already names a default plugin suppresses that
/// default (loading the same manifest id twice would register a
/// duplicate backend kind, which fails gateway boot). Defaults append
/// after existing entries; backend registration is keyed by the kind
/// the cdylib declares, so array order carries no semantics here.
pub fn append_cloud_default_plugins(config: &mut Value, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    if !config.is_object() {
        *config = json!({});
    }
    let obj = config.as_object_mut().expect("config is an object here");
    if !obj.get("plugins").map(Value::is_array).unwrap_or(false) {
        obj.insert("plugins".into(), Value::Array(Vec::new()));
    }
    let entries = obj
        .get_mut("plugins")
        .and_then(Value::as_array_mut)
        .expect("plugins is an array here");
    let taken: std::collections::HashSet<String> = entries
        .iter()
        .flat_map(|e| {
            ["id", "ref"]
                .iter()
                .filter_map(|k| e.get(k).and_then(Value::as_str).map(str::to_owned))
        })
        .collect();
    for id in ids {
        if taken.contains(id) {
            continue;
        }
        entries.push(render_cloud_default_entry(id));
    }
}

/// Observability sink plugins the published gateway images bake, paired
/// with the `class` each descriptor declares.
///
/// A sink is selected by plugin id in `observability.<signal>.sinks[].kind`,
/// but selecting it does not load it: the cdylib still needs a `plugins[]`
/// entry. Without one the signal is configured, the gateway boots, nothing
/// objects, and the metrics are simply never exported — visible only as one
/// WARN at startup.
const BAKED_SINK_PLUGINS: &[(&str, &str)] = &[
    ("dev.mcpg.observability.prometheus", "metrics_sink"),
    ("dev.mcpg.observability.otlp", "telemetry_sink"),
];

/// Sink ids named by the rendered config, in first-seen order.
///
/// Reading this shape is a deliberate exception to the module's
/// schema-blindness, and it degrades the safe way: if `observability` ever
/// moves, no sink is recognised, nothing is appended, and the result is
/// exactly today's behaviour rather than a wrong entry.
fn configured_sink_kinds(config: &Value) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let Some(obs) = config.get("observability") else {
        return out;
    };
    for signal in ["metrics", "traces", "logs"] {
        let Some(sinks) = obs
            .get(signal)
            .and_then(|s| s.get("sinks"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for kind in sinks
            .iter()
            .filter_map(|s| s.get("kind"))
            .filter_map(Value::as_str)
        {
            if seen.insert(kind.to_owned()) {
                out.push(kind.to_owned());
            }
        }
    }
    out
}

/// Give every configured first-party sink the `plugins[]` entry that loads it.
///
/// Only ids in [`BAKED_SINK_PLUGINS`] are added. An entry whose `source.path`
/// names an artifact the image does not carry fails gateway boot, so a
/// third-party sink stays the config author's responsibility — the operator
/// cannot know where its cdylib lives.
pub fn append_observability_sink_plugins(config: &mut Value) {
    let wanted: Vec<(&str, &str)> = configured_sink_kinds(config)
        .into_iter()
        .filter_map(|kind| {
            BAKED_SINK_PLUGINS
                .iter()
                .find(|(id, _)| *id == kind)
                .copied()
        })
        .collect();
    if wanted.is_empty() {
        return;
    }
    for (id, class) in wanted {
        // Re-read the taken set each time: a duplicate plugin id registers a
        // duplicate alias and fails boot, which is worse than the missing
        // signal this exists to fix.
        if plugin_ids(config).contains(id) {
            continue;
        }
        push_plugin_entry(
            config,
            json!({
                "id": id,
                "kind": "native",
                "class": class,
                "source": { "path": format!("{CLOUD_PLUGIN_IMAGE_ROOT}/{id}/plugin.so") },
            }),
        );
    }
}

/// Ids already claimed by an entry, under either key the gateway accepts.
fn plugin_ids(config: &Value) -> std::collections::HashSet<String> {
    config
        .get("plugins")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .flat_map(|e| {
                    ["id", "ref"]
                        .iter()
                        .filter_map(|k| e.get(k).and_then(Value::as_str).map(str::to_owned))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Append one entry, creating `plugins` (and the object itself) if absent.
fn push_plugin_entry(config: &mut Value, entry: Value) {
    if !config.is_object() {
        *config = json!({});
    }
    let obj = config.as_object_mut().expect("config is an object here");
    if !obj.get("plugins").map(Value::is_array).unwrap_or(false) {
        obj.insert("plugins".into(), Value::Array(Vec::new()));
    }
    obj.get_mut("plugins")
        .and_then(Value::as_array_mut)
        .expect("plugins is an array here")
        .push(entry);
}

/// Render one managed-cloud default entry. Grants come from the
/// standard-set table; an override-listed id outside the table gets no
/// grants (the operator cannot know a foreign plugin's requirements).
fn render_cloud_default_entry(id: &str) -> Value {
    let mut entry = json!({
        "id": id,
        "kind": "native",
        "class": "backend",
        "source": {
            "path": format!("{CLOUD_PLUGIN_IMAGE_ROOT}/{id}/plugin.so"),
        },
    });
    let grants: &[&str] = CLOUD_DEFAULT_BACKEND_PLUGINS
        .iter()
        .find(|(known, _)| *known == id)
        .map(|(_, g)| *g)
        .unwrap_or(&[]);
    if !grants.is_empty() {
        entry
            .as_object_mut()
            .expect("json! built an object")
            .insert(
                "granted_capabilities".into(),
                Value::Array(
                    grants
                        .iter()
                        .map(|c| Value::String((*c).to_owned()))
                        .collect(),
                ),
            );
    }
    entry
}

/// Given a deep-cloned base config (the user's `spec.config`),
/// the resolved plugin set, and the mount path of the active
/// revocation list (when any), return the merged JSON document.
///
/// The merge is a value-level overlay — the function does not
/// validate the resulting shape against the gateway's
/// `PluginsConfig` schema. The gateway's own
/// `validate_config_pre_boot` is the source of truth; we keep
/// the operator deliberately schema-blind so the gateway can
/// evolve `PluginsConfig` without forcing a coupled operator
/// release.
pub fn merge_plugins(
    base_config: &Value,
    resolved: Option<&ResolvedSetView>,
    revocation_list_path: Option<&str>,
) -> Value {
    let mut config = base_config.clone();
    if !config.is_object() {
        config = json!({});
    }

    // No plugin set + no revocation list → nothing to merge.
    if resolved.is_none() && revocation_list_path.is_none() {
        return config;
    }

    if let Some(set) = resolved {
        // Replace the top-level `plugins:` array wholesale — the
        // operator owns this list when pluginSetRef is set. Grants
        // are folded into each entry's `granted_capabilities`.
        let entries: Vec<Value> = set
            .entries
            .iter()
            .map(|e| render_entry(e, set.capability_grants.get(&e.id)))
            .collect();
        config
            .as_object_mut()
            .expect("config is an object here")
            .insert("plugins".into(), Value::Array(entries));
    }

    if let Some(path) = revocation_list_path {
        // This field lives at
        // `gateway.plugin_registry.revocation_list_path` (it was
        // formerly `plugins.trust.revocation_list_path`).
        let gateway = ensure_object(&mut config, "gateway");
        let plugin_registry = ensure_object(gateway, "plugin_registry");
        plugin_registry
            .as_object_mut()
            .expect("ensure_object always returns an object")
            .insert(
                "revocation_list_path".into(),
                Value::String(path.to_owned()),
            );
    }

    config
}

/// Render one resolved entry into the gateway's
/// `PluginEntryConfig` JSON shape. The gateway daemon's serde
/// definition lives in `apps/gateway/src/config/plugins.rs`.
///
/// `grants` are this plugin's capability grants from the
/// `MCPGPluginSet` (keyed by id, `None` when the set granted none);
/// they render as the entry's `granted_capabilities` array — the
/// gateway accepts a bare-string array (no-arg capability variants)
/// here, matching `deserialize_granted_capabilities`. Omitted when
/// empty so the gateway's `#[serde(default)]` applies.
fn render_entry(e: &ResolvedSetEntry, grants: Option<&Vec<String>>) -> Value {
    let mut entry = json!({
        "id": e.id,
        // Only native cdylibs ship today. Wasm support is
        // deferred; when it lands the MCPGPlugin spec gains a
        // tier field and this default goes away.
        "kind": "native",
        "class": e.plugin_class,
        "source": {
            "path": format!("{PLUGIN_MOUNT_ROOT}/{}/plugin.so", e.id),
        },
        "config": e.config,
        "signature": {
            "sha256": e.resolved_digest,
        },
        // MCPGPluginSetEntry has no enforce field today — every
        // plugin loads in enforce mode. Shadow-mode operation
        // is not implemented.
        "enforce": true,
    });
    if let Some(caps) = grants.filter(|c| !c.is_empty()) {
        entry
            .as_object_mut()
            .expect("json! built an object")
            .insert(
                "granted_capabilities".into(),
                Value::Array(caps.iter().map(|c| Value::String(c.clone())).collect()),
            );
    }
    entry
}

/// Look up `key` on `value` (assumed to be a JSON object); insert
/// an empty object under `key` if missing; return a `&mut Value`
/// pointing at the nested object so the caller can populate it.
fn ensure_object<'a>(value: &'a mut Value, key: &str) -> &'a mut Value {
    let obj = value
        .as_object_mut()
        .expect("ensure_object called on non-object");
    if !obj.contains_key(key) || !obj[key].is_object() {
        obj.insert(key.to_owned(), Value::Object(Default::default()));
    }
    obj.get_mut(key).expect("just inserted")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str) -> ResolvedSetEntry {
        ResolvedSetEntry {
            id: id.into(),
            plugin_class: "identity_provider".into(),
            plugin_version: "1.2.3".into(),
            artefact_secret_name: format!("mcpg-plugin-{}-abcd1234", id.replace('.', "-")),
            resolved_digest: "deadbeef".repeat(8),
            config: json!({"trust_domain": "spiffe://example.org"}),
        }
    }

    fn one_entry_set() -> ResolvedSetView {
        ResolvedSetView {
            entries: vec![entry("dev.mcpg.identity.workload")],
            capability_grants: {
                let mut g = BTreeMap::new();
                g.insert(
                    "dev.mcpg.identity.workload".into(),
                    vec!["transport_listen".into(), "network_outbound".into()],
                );
                g
            },
        }
    }

    #[test]
    fn merge_with_no_inputs_passes_through_base() {
        let base = json!({"server": {"bindAddress": "0.0.0.0:8787"}});
        let merged = merge_plugins(&base, None, None);
        assert_eq!(merged, base);
    }

    #[test]
    fn merge_replaces_plugins_array_when_set_present() {
        // User hand-listed a plugin; the set replaces the whole array.
        let base = json!({
            "plugins": [
                {"id": "dev.mcpg.user.handwritten", "kind": "native"}
            ]
        });
        let set = one_entry_set();
        let merged = merge_plugins(&base, Some(&set), None);
        let entries = merged["plugins"].as_array().expect("plugins is an array");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["id"], "dev.mcpg.identity.workload");
    }

    #[test]
    fn merge_emits_path_under_plugin_mount_root() {
        let base = json!({});
        let set = one_entry_set();
        let merged = merge_plugins(&base, Some(&set), None);
        let entry = &merged["plugins"][0];
        assert_eq!(
            entry["source"]["path"],
            "/etc/mcpg/plugins/dev.mcpg.identity.workload/plugin.so"
        );
    }

    #[test]
    fn merge_carries_plugin_class_into_class_field() {
        let base = json!({});
        let set = one_entry_set();
        let merged = merge_plugins(&base, Some(&set), None);
        assert_eq!(merged["plugins"][0]["class"], "identity_provider");
    }

    #[test]
    fn merge_carries_resolved_digest_into_signature_sha256() {
        let base = json!({});
        let set = one_entry_set();
        let merged = merge_plugins(&base, Some(&set), None);
        assert_eq!(
            merged["plugins"][0]["signature"]["sha256"],
            "deadbeef".repeat(8)
        );
    }

    #[test]
    fn merge_propagates_per_entry_config_verbatim() {
        let base = json!({});
        let set = one_entry_set();
        let merged = merge_plugins(&base, Some(&set), None);
        assert_eq!(
            merged["plugins"][0]["config"]["trust_domain"],
            "spiffe://example.org"
        );
    }

    #[test]
    fn merge_folds_grants_into_per_entry_granted_capabilities() {
        let base = json!({});
        let set = one_entry_set();
        let merged = merge_plugins(&base, Some(&set), None);
        let caps = merged["plugins"][0]["granted_capabilities"]
            .as_array()
            .expect("granted_capabilities is an array on the entry");
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0], "transport_listen");
    }

    #[test]
    fn merge_omits_granted_capabilities_when_no_grants() {
        let base = json!({});
        let set = ResolvedSetView {
            entries: vec![entry("dev.mcpg.identity.workload")],
            capability_grants: BTreeMap::new(),
        };
        let merged = merge_plugins(&base, Some(&set), None);
        assert!(
            merged["plugins"][0].get("granted_capabilities").is_none(),
            "no grants ⇒ field omitted so the gateway default applies"
        );
    }

    #[test]
    fn merge_replaces_user_supplied_plugins_array_entirely() {
        // A user-hand-listed plugin with its own grants is dropped —
        // the set owns the whole `plugins` array when pluginSetRef is set.
        let base = json!({
            "plugins": [
                {
                    "id": "dev.mcpg.user.unrelated",
                    "kind": "native",
                    "granted_capabilities": ["network_outbound"]
                }
            ]
        });
        let set = one_entry_set();
        let merged = merge_plugins(&base, Some(&set), None);
        let entries = merged["plugins"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["id"], "dev.mcpg.identity.workload");
    }

    #[test]
    fn merge_writes_revocation_list_path_when_provided() {
        let base = json!({});
        let merged = merge_plugins(&base, None, Some(REVOCATION_LIST_MOUNT_PATH));
        assert_eq!(
            merged["gateway"]["plugin_registry"]["revocation_list_path"],
            REVOCATION_LIST_MOUNT_PATH
        );
    }

    #[test]
    fn merge_overrides_user_revocation_list_path() {
        let base = json!({
            "gateway": {
                "plugin_registry": {
                    "revocation_list_path": "/some/where/else.json"
                }
            }
        });
        let merged = merge_plugins(&base, None, Some(REVOCATION_LIST_MOUNT_PATH));
        assert_eq!(
            merged["gateway"]["plugin_registry"]["revocation_list_path"],
            REVOCATION_LIST_MOUNT_PATH
        );
    }

    #[test]
    fn merge_handles_null_base_config() {
        let merged = merge_plugins(&Value::Null, Some(&one_entry_set()), None);
        let entries = merged["plugins"].as_array().expect("plugins is an array");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn merge_preserves_user_plugin_registry_fields() {
        // Operator only owns the revocation_list_path slot under
        // gateway.plugin_registry. User-supplied sibling fields
        // (auth, mirrors, default_signature_policy, …) flow
        // through untouched.
        let base = json!({
            "gateway": {
                "plugin_registry": {
                    "default_signature_policy": "enforce"
                }
            }
        });
        let merged = merge_plugins(&base, None, Some(REVOCATION_LIST_MOUNT_PATH));
        assert_eq!(
            merged["gateway"]["plugin_registry"]["default_signature_policy"],
            "enforce"
        );
        assert_eq!(
            merged["gateway"]["plugin_registry"]["revocation_list_path"],
            REVOCATION_LIST_MOUNT_PATH
        );
    }

    #[test]
    fn merge_default_kind_is_native() {
        let base = json!({});
        let set = one_entry_set();
        let merged = merge_plugins(&base, Some(&set), None);
        assert_eq!(merged["plugins"][0]["kind"], "native");
    }

    #[test]
    fn merge_default_enforce_is_true() {
        let base = json!({});
        let set = one_entry_set();
        let merged = merge_plugins(&base, Some(&set), None);
        assert_eq!(merged["plugins"][0]["enforce"], true);
    }

    #[test]
    fn merge_preserves_unrelated_top_level_blocks() {
        let base = json!({
            "gateway": { "server": { "bind_address": "0.0.0.0:8787" } },
        });
        let merged = merge_plugins(&base, Some(&one_entry_set()), None);
        assert_eq!(merged["gateway"]["server"]["bind_address"], "0.0.0.0:8787");
    }

    // ── Consistency guard ────────────────────────────────────────────
    //
    // The operator is deliberately schema-blind: it renders the
    // gateway's config JSON but never links the gateway crate at
    // runtime. The danger is that the gateway's `AppConfig` schema
    // evolves (e.g. the `plugins` object→array flatten in 35f9ab58)
    // and the operator keeps emitting the old shape — the gateway then
    // fails to boot at the customer, far from operator CI. These tests
    // close that loop by deserialising the operator's rendered output
    // into the gateway's REAL `AppConfig` (dev-dep only), exercising
    // its `deny_unknown_fields` + custom capability deserialiser.

    /// A capability-grant fixture exercising the round-trip guard with
    /// two real gateway capability kinds.
    fn set_with_real_caps() -> ResolvedSetView {
        let mut grants = BTreeMap::new();
        grants.insert(
            "dev.mcpg.identity.workload".to_owned(),
            vec!["network_outbound".to_owned(), "audit_write".to_owned()],
        );
        ResolvedSetView {
            entries: vec![entry("dev.mcpg.identity.workload")],
            capability_grants: grants,
        }
    }

    #[test]
    fn rendered_config_deserialises_into_gateway_appconfig() {
        // A representative operator-rendered config: user base + a
        // plugin-set merge + a revocation-list path.
        let base = json!({
            "gateway": { "server": { "bind_address": "0.0.0.0:8787" } },
            "mcp": { "configurations": { "apps": { "enabled": true } } },
        });
        let merged = merge_plugins(
            &base,
            Some(&set_with_real_caps()),
            Some(REVOCATION_LIST_MOUNT_PATH),
        );

        // THE GUARD: the gateway's own serde must accept it. This is
        // exactly the parse the gateway runs at boot from
        // /etc/mcpg/config.yaml.
        let cfg: mcpg::config::AppConfig = serde_json::from_value(merged)
            .expect("operator-rendered config must deserialise into the gateway's AppConfig");

        // Spot-check the merged plugin survived the round-trip as a
        // first-class entry with its grants.
        assert_eq!(cfg.plugins.len(), 1);
        let entry = &cfg.plugins[0];
        assert_eq!(entry.id, "dev.mcpg.identity.workload");
        assert_eq!(entry.granted_capabilities.len(), 2);
        assert_eq!(
            cfg.gateway.plugin_registry.revocation_list_path.as_deref(),
            Some(REVOCATION_LIST_MOUNT_PATH)
        );
    }

    #[test]
    fn rendered_config_without_plugin_set_deserialises() {
        // The pass-through path (no pluginSetRef): a plain user config
        // with a hand-listed plugin array must also round-trip.
        let base = json!({
            "plugins": [
                {
                    "id": "dev.mcpg.audit.local",
                    "class": "audit_sink",
                    "source": { "path": "/etc/mcpg/plugins/audit/plugin.so" },
                    "granted_capabilities": ["audit_write"]
                }
            ]
        });
        let merged = merge_plugins(&base, None, None);
        let cfg: mcpg::config::AppConfig = serde_json::from_value(merged)
            .expect("pass-through config must deserialise into AppConfig");
        assert_eq!(cfg.plugins.len(), 1);
        assert_eq!(cfg.plugins[0].id, "dev.mcpg.audit.local");
    }

    // ── Managed-cloud default backends ───────────────────────────────

    /// The full standard-set id list, in table order.
    fn standard_ids() -> Vec<String> {
        cloud_default_plugin_ids(None)
    }

    #[test]
    fn cloud_default_ids_unset_env_selects_standard_set() {
        let ids = cloud_default_plugin_ids(None);
        assert_eq!(
            ids,
            vec![
                "dev.mcpg.backend.mock",
                "dev.mcpg.backend.http",
                "dev.mcpg.backend.command",
                "dev.mcpg.backend.graphql",
                "dev.mcpg.backend.openapi",
            ]
        );
    }

    #[test]
    fn cloud_default_ids_empty_env_disables() {
        assert!(cloud_default_plugin_ids(Some("")).is_empty());
        assert!(cloud_default_plugin_ids(Some("  ")).is_empty());
        assert!(cloud_default_plugin_ids(Some(",")).is_empty());
    }

    #[test]
    fn cloud_default_ids_env_overrides_and_dedupes() {
        let ids = cloud_default_plugin_ids(Some(
            " dev.mcpg.backend.http, dev.mcpg.backend.mock ,dev.mcpg.backend.http,",
        ));
        assert_eq!(ids, vec!["dev.mcpg.backend.http", "dev.mcpg.backend.mock"]);
    }

    #[test]
    fn append_defaults_creates_plugins_array_with_standard_entries() {
        let mut config = json!({});
        append_cloud_default_plugins(&mut config, &standard_ids());
        let entries = config["plugins"].as_array().expect("plugins is an array");
        assert_eq!(entries.len(), 5);
        let http = entries
            .iter()
            .find(|e| e["id"] == "dev.mcpg.backend.http")
            .expect("http entry rendered");
        assert_eq!(http["kind"], "native");
        assert_eq!(http["class"], "backend");
        assert_eq!(
            http["source"]["path"],
            "/usr/local/lib/mcpg/plugins/dev.mcpg.backend.http/plugin.so"
        );
        assert_eq!(http["granted_capabilities"], json!(["network_outbound"]));
        // No-required-capability plugins omit the field so the
        // gateway's `#[serde(default)]` applies.
        let mock = entries
            .iter()
            .find(|e| e["id"] == "dev.mcpg.backend.mock")
            .expect("mock entry rendered");
        assert!(mock.get("granted_capabilities").is_none());
    }

    #[test]
    fn append_defaults_never_pins_integrity_or_signature() {
        // The baked artifacts carry no per-release digest the operator
        // could know; the entries must load under the gateway's default
        // signature policy with no digest pin.
        let mut config = json!({});
        append_cloud_default_plugins(&mut config, &standard_ids());
        for e in config["plugins"].as_array().unwrap() {
            assert!(
                e.get("signature").is_none(),
                "no signature block on {}",
                e["id"]
            );
        }
    }

    #[test]
    fn append_defaults_empty_ids_is_a_noop() {
        let mut config = json!({"gateway": {"server": {}}});
        let before = config.clone();
        append_cloud_default_plugins(&mut config, &[]);
        assert_eq!(
            config, before,
            "disabled defaults must not touch the config"
        );
    }

    #[test]
    fn append_defaults_preserves_user_entries_and_skips_id_collisions() {
        // A hand-listed plugin stays first; a user entry that already
        // names a default id suppresses that default (a second load of
        // the same manifest id would duplicate its backend kind).
        let mut config = json!({
            "plugins": [
                { "id": "dev.mcpg.backend.http", "kind": "native", "class": "backend",
                  "source": { "path": "/etc/mcpg/plugins/custom-http/plugin.so" } }
            ]
        });
        append_cloud_default_plugins(&mut config, &standard_ids());
        let entries = config["plugins"].as_array().unwrap();
        assert_eq!(entries.len(), 5, "4 defaults appended after the user entry");
        assert_eq!(
            entries[0]["source"]["path"], "/etc/mcpg/plugins/custom-http/plugin.so",
            "user entry wins and keeps its position"
        );
        assert_eq!(
            entries
                .iter()
                .filter(|e| e["id"] == "dev.mcpg.backend.http")
                .count(),
            1
        );
    }

    #[test]
    fn append_defaults_skips_ref_collisions() {
        // A multi-instance alias (`ref` names the artifact) also
        // suppresses the matching default.
        let mut config = json!({
            "plugins": [
                { "id": "graphql-tenant-a", "ref": "dev.mcpg.backend.graphql", "kind": "native",
                  "class": "backend", "source": { "path": "/etc/mcpg/plugins/graphql-a/plugin.so" } }
            ]
        });
        append_cloud_default_plugins(&mut config, &standard_ids());
        let entries = config["plugins"].as_array().unwrap();
        assert!(
            !entries
                .iter()
                .any(|e| e["id"] == "dev.mcpg.backend.graphql"),
            "ref collision suppresses the default graphql entry"
        );
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn append_defaults_composes_with_plugin_set_merge() {
        // pluginSetRef entries render alongside the defaults: the set
        // replaces the user array, then the defaults append after it.
        let base = json!({});
        let mut merged = merge_plugins(&base, Some(&one_entry_set()), None);
        append_cloud_default_plugins(&mut merged, &standard_ids());
        let entries = merged["plugins"].as_array().unwrap();
        assert_eq!(entries.len(), 6);
        assert_eq!(entries[0]["id"], "dev.mcpg.identity.workload");
        assert!(
            entries
                .iter()
                .any(|e| e["id"] == "dev.mcpg.backend.openapi"),
            "defaults appended after the set entries"
        );
    }

    #[test]
    fn append_defaults_unknown_override_id_gets_no_grants() {
        let mut config = json!({});
        append_cloud_default_plugins(&mut config, &["com.acme.backend.custom".to_owned()]);
        let entry = &config["plugins"][0];
        assert_eq!(
            entry["source"]["path"],
            "/usr/local/lib/mcpg/plugins/com.acme.backend.custom/plugin.so"
        );
        assert!(entry.get("granted_capabilities").is_none());
    }

    #[test]
    fn append_defaults_handles_null_base_config() {
        let mut config = Value::Null;
        append_cloud_default_plugins(&mut config, &standard_ids());
        assert_eq!(config["plugins"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn cloud_defaults_deserialise_into_gateway_appconfig() {
        // Same guard as the plugin-set round-trip: the gateway's own
        // serde (deny_unknown_fields + typed capability parser) must
        // accept the rendered default entries — this is the parse the
        // tenant pod runs at boot.
        let base = json!({
            "gateway": { "server": { "bind_address": "0.0.0.0:8787" } },
        });
        let mut merged = merge_plugins(&base, Some(&set_with_real_caps()), None);
        append_cloud_default_plugins(&mut merged, &standard_ids());
        let cfg: mcpg::config::AppConfig = serde_json::from_value(merged)
            .expect("cloud-default entries must deserialise into the gateway's AppConfig");
        assert_eq!(cfg.plugins.len(), 6);
        let http = cfg
            .plugins
            .iter()
            .find(|p| p.id == "dev.mcpg.backend.http")
            .expect("http default present");
        assert_eq!(http.kind, "native");
        assert_eq!(http.class, "backend");
        assert_eq!(
            http.source.path.as_deref(),
            Some("/usr/local/lib/mcpg/plugins/dev.mcpg.backend.http/plugin.so")
        );
        assert_eq!(http.granted_capabilities.len(), 1);
        // The typed gateway validator must also pass (alias uniqueness,
        // class allowlist, ref format).
        mcpg::config::validate_plugins(&cfg.plugins)
            .expect("rendered defaults must pass the gateway's plugins[] validator");
    }

    fn with_metrics_sink(kind: &str) -> Value {
        json!({
            "gateway": { "server": { "bind_address": "0.0.0.0:8787" } },
            "observability": { "metrics": { "sinks": [{ "kind": kind }] } },
        })
    }

    /// The whole point: the entry must satisfy the gateway's OWN parser and
    /// validator, because a shape the operator likes and the gateway rejects
    /// is the same silent non-export with extra steps.
    #[test]
    fn configured_sink_gets_a_loadable_entry() {
        let mut config = with_metrics_sink("dev.mcpg.observability.prometheus");
        append_observability_sink_plugins(&mut config);
        let cfg: mcpg::config::AppConfig =
            serde_json::from_value(config).expect("sink entry deserialises into AppConfig");
        let sink = cfg
            .plugins
            .iter()
            .find(|p| p.id == "dev.mcpg.observability.prometheus")
            .expect("sink plugin entry present");
        assert_eq!(sink.class, "metrics_sink");
        assert_eq!(
            sink.source.path.as_deref(),
            Some("/usr/local/lib/mcpg/plugins/dev.mcpg.observability.prometheus/plugin.so")
        );
        mcpg::config::validate_plugins(&cfg.plugins)
            .expect("rendered sink entry must pass the gateway's plugins[] validator");
    }

    /// A duplicate alias fails gateway boot, which is worse than the missing
    /// signal this function exists to fix.
    #[test]
    fn existing_entry_is_not_duplicated() {
        let mut config = with_metrics_sink("dev.mcpg.observability.prometheus");
        config["plugins"] = json!([{
            "id": "dev.mcpg.observability.prometheus",
            "kind": "native",
            "class": "metrics_sink",
            "source": { "path": "/somewhere/else/plugin.so" },
        }]);
        append_observability_sink_plugins(&mut config);
        assert_eq!(config["plugins"].as_array().unwrap().len(), 1);
        assert_eq!(
            config["plugins"][0]["source"]["path"], "/somewhere/else/plugin.so",
            "an author's own entry must win over the default"
        );
    }

    /// The image carries no artifact for a third-party sink, and an entry
    /// whose `source.path` does not resolve fails boot — a worse outcome
    /// than the un-exported signal.
    #[test]
    fn foreign_sink_is_left_alone() {
        let mut config = with_metrics_sink("com.example.metrics.datadog");
        append_observability_sink_plugins(&mut config);
        assert!(config.get("plugins").is_none());
    }

    #[test]
    fn no_observability_section_adds_nothing() {
        let mut config = json!({ "gateway": { "server": { "bind_address": "0.0.0.0:8787" } } });
        append_observability_sink_plugins(&mut config);
        assert!(config.get("plugins").is_none());
    }

    /// Traces select their sink from a different signal block; the entry the
    /// gateway needs is the same.
    #[test]
    fn trace_sinks_are_covered_too() {
        let mut config = json!({
            "observability": { "traces": { "sinks": [{ "kind": "dev.mcpg.observability.otlp" }] } },
        });
        append_observability_sink_plugins(&mut config);
        assert_eq!(config["plugins"][0]["id"], "dev.mcpg.observability.otlp");
        assert_eq!(config["plugins"][0]["class"], "telemetry_sink");
    }
}
