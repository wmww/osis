//! Hosting (notes/serving.md, Hosting in the node): the node reads its own `host^.0`
//! (spec/data-model.md §9) and hands its driver a `HostConfig` (`Action::Host`), public data
//! only: which sync IDs it stores for others (`open`, or `labels`), replication peers, policy and
//! caps. The sync IDs it reads are node sync's whatever that says (`osis_host`'s `reader_*`). The
//! hub's store is the node's for good (`hub_store`); hosting stopping drops the labels it kept for
//! others. The hub serves on the node's own listeners, under its one key.

use super::{Action, SyncEngine};
use osis_host::{Admission, HostConfig, HostPolicy, HostStore, LabelCaps};
use std::sync::{Arc, Mutex};
use osis_label::Address;
use osis_schema::core_types::{self as ct, Admit};
use std::collections::BTreeMap;

/// The node's one store (the hub's, `HostStore`) over `store`, admitting nothing under the
/// default policy until `host^.0` says otherwise: the engine's ciphertext store
/// (`Engine::open`), shared with the sync engine and the driver's hub.
pub fn hub_store(store: osis_store::Store, clock: Arc<dyn osis_base::Clock>, rng: Box<dyn osis_crypto::NodeRng>) -> crate::error::Result<Arc<Mutex<HostStore>>> {
    let mut h = HostStore::open(store, clock, HostPolicy::default(), rng).map_err(|_| crate::error::Error::Corrupt("hub store"))?;
    h.set_admission(Admission::Only(Default::default()), Default::default());
    Ok(Arc::new(Mutex::new(h)))
}

/// `hub_store` over `backend` and `root`, created there if none is (tests, the simulator).
pub fn hub_store_on(backend: Box<dyn osis_store::Backend>, root: Box<dyn osis_store::RootStorage>, clock: Arc<dyn osis_base::Clock>, mut rng: Box<dyn osis_crypto::NodeRng>) -> crate::error::Result<Arc<Mutex<HostStore>>> {
    let store = osis_store::Store::open_or_create(backend, root, osis_store::StoreConfig::default(), &mut *rng)?;
    hub_store(store, clock, rng)
}

/// Tests: peer `p`'s engine reopened over a hub store in memory, as a node's: its blobs left
/// behind (a fresh peer holds none the tests read).
#[cfg(test)]
pub(crate) fn on_hub(p: crate::local_peer::Peer) -> crate::Engine {
    let c: Arc<dyn osis_base::Clock> = p.clock.clone();
    let hub = hub_store_on(Box::new(osis_store::MemoryBackend::new()), Box::new(osis_store::MemoryRoot::new()), c.clone(), Box::new(osis_crypto::SeededRng::from_u64(3))).unwrap();
    drop(p.engine);
    crate::Engine::open(Box::new(p.backend.clone()), Box::new(p.root.clone()), hub, crate::Config::default(), c, Box::new(osis_crypto::SeededRng::from_u64(4))).unwrap()
}

/// What `host_step` last handed the driver, and from which engine generation.
#[derive(Clone, Default)]
pub(crate) struct Hosting {
    pub emitted: Option<HostConfig>,
    generation: Option<u64>,
}

/// The host policy of `host^.0`'s knobs (by `HostPolicy` field name) over the defaults.
pub fn host_policy(knobs: &BTreeMap<String, u64>) -> Result<HostPolicy, String> {
    let mut p = HostPolicy::default();
    for (k, v) in knobs {
        p.set(k, *v)?;
    }
    Ok(p)
}

/// `host_policy` of what can be run by: the limits a stored `host^.0` names that this build cannot
/// (another node's: a newer name, or a value out of a known limit's range, whose default then runs)
/// stay out of the policy, and are returned.
pub fn host_policy_known(knobs: &BTreeMap<String, u64>) -> (HostPolicy, BTreeMap<String, u64>) {
    let mut p = HostPolicy::default();
    let mut unknown = BTreeMap::new();
    for (k, v) in knobs {
        if p.set(k, *v).is_err() {
            unknown.insert(k.clone(), *v);
        }
    }
    (p, unknown)
}

impl SyncEngine {
    /// Whether this node hosts now (`host^.0` is set).
    pub fn hosts(&mut self) -> bool {
        self.hosting().is_some()
    }

    /// The node's one store (the hub's), shared with the engine and the driver's hub.
    pub fn hub_store(&self) -> Arc<Mutex<HostStore>> {
        self.hub_store.clone()
    }

    /// This node's `host^.0`, if set.
    pub fn hosting(&mut self) -> Option<ct::Host> {
        let me = self.engine.tid();
        self.engine.get_typed(&me, &ct::HOST).ok().flatten()
    }

    /// What the host runs with now: from `host^.0` (none: not hosting).
    pub fn host_config(&mut self) -> Option<HostConfig> {
        let h = self.hosting()?;
        let (policy, unknown) = host_policy_known(&h.policy);
        if !unknown.is_empty() {
            self.diag(format!("host^.0 policy: limits not run by, the defaults apply: {unknown:?}"));
        }
        let admission = match h.admit {
            Admit::Open => Admission::Open,
            Admit::Listed => Admission::Only(h.labels),
        };
        Some(HostConfig {
            admission,
            replicate: h.replicate.into_iter().map(|a| Address { url: a.url, key: a.key }).collect(),
            policy,
            caps: h.caps.into_iter().map(|(l, c)| (l, LabelCaps { entries: c.entries, bytes: c.bytes })).collect(),
        })
    }

    /// Hands the driver the host config when it changed (`Action::Host`), looked at once per
    /// engine change.
    pub(crate) fn host_step(&mut self, out: &mut Vec<Action>) {
        let g = self.engine.core.generation;
        if self.hosting.generation == Some(g) {
            return;
        }
        self.hosting.generation = Some(g);
        let cfg = self.host_config();
        if cfg != self.hosting.emitted {
            self.hosting.emitted = cfg.clone();
            out.push(Action::Host(cfg.map(Box::new)));
        }
    }

    /// The driver starts afresh: the next step hands it the host config again.
    pub fn host_restart(&mut self) {
        self.hosting = Hosting::default();
    }
}
