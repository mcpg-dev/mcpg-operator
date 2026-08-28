//! Pure-function templates that turn a [`MCPGGateway`] into
//! K8s child resources. Each function:
//!
//! - Takes the parent CRD as input.
//! - Produces a fully-populated K8s API object.
//! - Sets owner refs so K8s GC propagates parent deletion.
//! - Sets standard labels (`app.kubernetes.io/*`).
//!
//! No side effects, no cluster access, no async — these are
//! pure renderers tested against fixtures.

mod common;
mod configmap;
mod deployment;
pub mod edge;
pub mod hpa;
pub mod httproute;
pub mod pdb;
pub mod plugin_render;
mod server;
mod service;
mod service_account;

pub use common::{owner_ref, selector_labels, standard_labels};
pub use configmap::build_configmap;
pub use deployment::{PluginSecretMount, RevocationListMount, build_deployment};
pub use hpa::build_hpa;
pub use httproute::{HTTPRoute, build_httproute};
pub use pdb::build_pdb;
pub use plugin_render::{
    CLOUD_PLUGIN_IMAGE_ROOT, REVOCATION_LIST_MOUNT_PATH, ResolvedSetEntry, ResolvedSetView,
    append_cloud_default_plugins, append_observability_sink_plugins, cloud_default_plugin_ids,
    merge_plugins,
};
pub use server::{build_server_deployment, build_server_service, server_child_name};
pub use service::build_service;
pub use service_account::build_service_account;
