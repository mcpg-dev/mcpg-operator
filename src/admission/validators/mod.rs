//! Per-CRD validators. Each handler:
//!
//! - Reads an `AdmissionReview<K>` from the request body.
//! - Runs cross-field + cross-resource validation.
//! - Returns an `AdmissionReview` response with `allowed=true`
//!   (and optional Warning header) or `allowed=false` (with the
//!   reason in `status.message`).
//!
//! All validators are pure — they don't mutate cluster state.
//! Mutating defaults live under `mutators/`.

pub mod cluster;
pub mod gateway;
pub mod plugin;
pub mod plugin_mirror;
pub mod plugin_set;
pub mod revocation_list;
pub mod route;
pub mod server;
pub mod tenant;
