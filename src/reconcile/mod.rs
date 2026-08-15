//! Reconcile helpers shared across controllers — server-side
//! apply (SSA), owner-ref management, status updates, conditions,
//! finalizer add/remove.

mod finalizers;
mod ssa;
mod status;

pub use finalizers::{
    FinalizerError, OPERATOR_FINALIZER, ensure_finalizer, has_finalizer, remove_finalizer,
};
pub use ssa::{ApplyError, apply_owned};
pub use status::{StatusError, patch_status};
