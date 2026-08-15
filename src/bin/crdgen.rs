//! Emit CRD YAML to stdout (or per-kind to a directory).
//!
//! Used by Helm-chart packaging to keep
//! `helm/charts/mcpg-operator/crds/` in sync with the Rust types.
//!
//! Lives in the operator crate (not operator-api) because it
//! needs k8s-openapi compiled against a concrete K8s version.
//!
//! Usage:
//!
//! ```bash
//! # Single stream of every CRD to stdout:
//! cargo run -p mcpg-operator --bin crdgen
//!
//! # One file per kind, written to a directory:
//! cargo run -p mcpg-operator --bin crdgen -- --split-by-kind helm/charts/mcpg-operator/crds/
//! ```

use std::process::ExitCode;

use kube::CustomResourceExt;
use mcpg_operator_api::v1alpha1::{
    MCPGCluster, MCPGGateway, MCPGPlugin, MCPGPluginMirror, MCPGPluginSet, MCPGRevocationList,
    MCPGRoute, MCPGServer, MCPGTenant,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() == 3 && args[1] == "--split-by-kind" {
        let dir = &args[2];
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("crdgen: failed to create {dir}: {e}");
            return ExitCode::FAILURE;
        }
        for (kind, yaml) in emit_per_kind() {
            let path = format!("{dir}/{kind}.yaml");
            if let Err(e) = std::fs::write(&path, yaml) {
                eprintln!("crdgen: failed to write {path}: {e}");
                return ExitCode::FAILURE;
            }
            eprintln!("wrote {path}");
        }
        return ExitCode::SUCCESS;
    }

    let mut first = true;
    for (_kind, yaml) in emit_per_kind() {
        if !first {
            println!("---");
        }
        first = false;
        print!("{yaml}");
    }
    ExitCode::SUCCESS
}

/// Returns (kind-lowercase, yaml-bytes) for every CRD shipped by
/// this operator.
fn emit_per_kind() -> Vec<(&'static str, String)> {
    vec![
        ("mcpggateway", emit::<MCPGGateway>()),
        ("mcpgplugin", emit::<MCPGPlugin>()),
        ("mcpgpluginset", emit::<MCPGPluginSet>()),
        ("mcpgrevocationlist", emit::<MCPGRevocationList>()),
        ("mcpgcluster", emit::<MCPGCluster>()),
        ("mcpgroute", emit::<MCPGRoute>()),
        ("mcpgpluginmirror", emit::<MCPGPluginMirror>()),
        ("mcpgtenant", emit::<MCPGTenant>()),
        ("mcpgserver", emit::<MCPGServer>()),
    ]
}

fn emit<T: CustomResourceExt>() -> String {
    serde_yaml::to_string(&T::crd()).expect("CRD always serialises")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_crd_has_a_valid_yaml_emit() {
        for (kind, yaml) in emit_per_kind() {
            assert!(
                yaml.contains("apiVersion: apiextensions.k8s.io/v1"),
                "kind={kind} missing apiVersion in:\n{yaml}"
            );
            assert!(
                yaml.contains("kind: CustomResourceDefinition"),
                "kind={kind} missing kind line in:\n{yaml}"
            );
            assert!(
                yaml.contains("group: mcpg.dev"),
                "kind={kind} missing group"
            );
        }
    }
}
