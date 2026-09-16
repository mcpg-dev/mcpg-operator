//! The trigger stream a controller watches its own CRs on.
//!
//! Every reconcile ends by writing `status` (conditions, hashes,
//! `lastReconcileTime`). A status write mutates the object, the watch sees the
//! mutation, and the controller reconciles again — a loop that never
//! converges, because the timestamp is different every pass. Filtering the
//! stream on the fields a reconcile is actually a response to breaks it: the
//! operator's own status writes stop scheduling work, while a spec change and
//! a deletion still arrive immediately.
//!
//! What still triggers a reconcile: a spec edit (the apiserver bumps
//! `metadata.generation`), the start of a deletion (`deletionTimestamp` set),
//! any change to an owned child through `.owns(…)`, and the controller's own
//! periodic requeue. `lastReconcileTime` therefore advances once per resync
//! rather than once per second — which is what makes a stalled controller
//! visible as an absence of reconcile lines.

use std::fmt::Debug;
use std::hash::{DefaultHasher, Hash, Hasher};

use futures::Stream;
use kube::Api;
use kube::Resource;
use kube::runtime::reflector::Store;
use kube::runtime::{WatchStreamExt, reflector, watcher};
use serde::de::DeserializeOwned;

/// The CR stream to drive a controller with, plus the reflector store its
/// cross-resource `.watches()` mappers read.
///
/// Pair with [`kube::runtime::Controller::for_stream`]; the store is the same
/// one `Controller::new(..).store()` would have handed back.
pub fn spec_changes<K>(
    api: Api<K>,
) -> (
    impl Stream<Item = Result<K, watcher::Error>> + Send + 'static,
    Store<K>,
)
where
    K: Resource + Clone + Debug + DeserializeOwned + Send + Sync + 'static,
    K::DynamicType: Default + Eq + Hash + Clone,
{
    let (reader, writer) = reflector::store();
    let stream = reflector(writer, watcher(api, watcher::Config::default()))
        .applied_objects()
        .predicate_filter(spec_or_deletion, Default::default());
    (stream, reader)
}

/// What a reconcile is a response to: the spec generation, and whether the
/// object is being deleted.
///
/// `predicates::generation` alone would be enough for spec edits, but the
/// finalizer path has to run the moment `deletionTimestamp` appears — and an
/// apiserver that sets it without bumping the generation would leave the
/// cleanup waiting for the next resync. Hashing both keeps deletion immediate.
///
/// `None` for an object with no generation (the predicate then admits every
/// event, which is the safe direction: reconcile more, not less).
fn spec_or_deletion<K: Resource>(obj: &K) -> Option<u64> {
    let meta = obj.meta();
    let generation = meta.generation?;
    let mut hasher = DefaultHasher::new();
    generation.hash(&mut hasher);
    meta.deletion_timestamp.is_some().hash(&mut hasher);
    Some(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::api::ObjectMeta;

    fn cm(generation: Option<i64>, deleting: bool) -> ConfigMap {
        ConfigMap {
            metadata: ObjectMeta {
                name: Some("x".into()),
                generation,
                deletion_timestamp: deleting.then(|| {
                    k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(jiff::Timestamp::now())
                }),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// A status write changes neither the generation nor the deletion stamp, so
    /// the predicate value is unchanged and the filter drops the event — which
    /// is what stops a reconcile from scheduling itself.
    #[test]
    fn status_only_change_keeps_the_same_predicate_value() {
        assert_eq!(
            spec_or_deletion(&cm(Some(7), false)),
            spec_or_deletion(&cm(Some(7), false))
        );
    }

    #[test]
    fn spec_edit_and_deletion_each_change_it() {
        let steady = spec_or_deletion(&cm(Some(7), false));
        assert_ne!(steady, spec_or_deletion(&cm(Some(8), false)));
        assert_ne!(steady, spec_or_deletion(&cm(Some(7), true)));
    }

    /// No generation ⇒ no basis to compare, so the filter admits everything.
    #[test]
    fn missing_generation_admits_every_event() {
        assert_eq!(spec_or_deletion(&cm(None, false)), None);
    }
}
