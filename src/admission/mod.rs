//! Admission webhook server (validating + mutating).
//!
//! Two handlers per CRD kind:
//!
//! - `/validate-mcpg-dev-v1alpha1-{kind}` — rejects bad specs.
//! - `/mutate-mcpg-dev-v1alpha1-{kind}` — applies operator
//!   defaults.
//!
//! Pre-1.0 we only serve `v1alpha1`; older alpha versions are
//! dropped wholesale rather than served via a conversion webhook.
//!
//! Plus the metrics + healthz endpoints on the same axum app.

mod metrics;
pub mod server;
pub mod tenant_guard;
mod validators;

pub use server::{ServerConfig, run as run_webhook_server, run_metrics as run_metrics_server};
