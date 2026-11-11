//! Hosting (notes/serving.md, Hosting in the node): the node reads its own `host^.0`
//! (spec/data-model.md §9) and hands its driver a `HostConfig` (`Action::Host`), public data
//! only: the admitted label IDs (`own`: the labels of groups whose standing record chain reaches
//! this node or its person and whose hosts name its key, plus `labels`), replication peers,
//! policy and caps. The hub's store is the node's for good (`hub_store`); hosting stopping drops
//! the labels it kept for others. The hub serves on the node's own listeners, under its one key.

use super::{Action, SyncEngine};
use osis_base::{LabelId, Tid};
use osis_host::{Admission, HostConfig, HostPolicy, HostStore, LabelCaps};
use std::sync::{Arc, Mutex};
use osis_label::Address;
use osis_schema::core_types::{self as ct, Admit};
use std::collections::{BTreeMap, BTreeSet};

/// A hub store in memory, empty and admitting nothing, under the default policy: a node's
/// until its holder opens its own (`SyncEngine::set_hub_store`).
pub fn memory_store(clock: Arc<dyn osis_base::Clock>) -> crate::error::Result<HostStore> {
    let (b, r) = (Box::new(osis_store::MemoryBackend::new()), Box::new(osis_store::MemoryRoot::new()));
    hub_store_over(osis_store::Store::create(b, r, osis_store::StoreConfig::default(), &mut osis_crypto::OsRng)?, clock)
}

/// The hub's store over `store`, admitting nothing under the default policy.
fn hub_store_over(store: osis_store::Store, clock: Arc<dyn osis_base::Clock>) -> crate::error::Result<HostStore> {
    let mut h = HostStore::open(store, clock, HostPolicy::default(), Box::new(osis_crypto::OsRng)).map_err(|_| crate::error::Error::Corrupt("hub store"))?;
    h.set_admission(Admission::Only(Default::default()), Default::default());
    Ok(h)
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

    /// The node's one store (the hub's), shared with the driver's hub.
    pub fn hub_store(&self) -> Arc<Mutex<HostStore>> {
        self.hub_store.clone()
    }

    /// `store` as the node's one store, in place of the one it had (a harness's, seeded).
    pub fn set_hub_store(&mut self, store: HostStore) {
        self.hub_store = Arc::new(Mutex::new(store));
    }

    /// The holder's store for the hub (`<store>/host.redb`), in place of the one in memory;
    /// what it keeps for others is the driver's to set (`host^.0`).
    pub fn open_hub_store(&mut self, store: osis_store::Store) -> crate::error::Result<()> {
        self.hub_store = Arc::new(Mutex::new(hub_store_over(store, self.engine.clock())?));
        Ok(())
    }

    /// This node's `host^.0`, if set.
    pub fn hosting(&mut self) -> Option<ct::Host> {
        let me = self.engine.tid();
        self.engine.get_typed(&me, &ct::HOST).ok().flatten()
    }

    /// Whether group `g` is this node's own for `own` admission (spec/data-model.md §9): its
    /// record chain reaches the node or its account through standing record edges
    /// (`Core::standing_chain`), so an account removed from a group it made stops hosting it.
    /// Invariant: no role edge but a record edge counts, on `g` or on any thing above it, held
    /// by the node or the account: a stranger may grant either one admin without consent, and
    /// must not make this node spend its storage that way (the inbox accept step's principle).
    /// Record links are fixed by the creation record (the tid commits to it); anyone may mint a
    /// record naming the account as first admin, but the group's `label.0` takes admin on it,
    /// which that chain gives only the account's admins (or whom they granted).
    fn owns(&self, g: &Tid) -> bool {
        let (node, account) = (self.engine.tid(), self.engine.account_tid());
        self.engine.core.standing_chain(g).into_iter().any(|x| x == node || Some(x) == account)
    }

    /// What the host runs with now: from `host^.0` (none: not hosting).
    pub fn host_config(&mut self) -> Option<HostConfig> {
        let h = self.hosting()?;
        let key = self.dialable_key();
        let (policy, unknown) = host_policy_known(&h.policy);
        if !unknown.is_empty() {
            self.diag(format!("host^.0 policy: limits not run by, the defaults apply: {unknown:?}"));
        }
        let admission = match h.admit {
            Admit::Open => Admission::Open,
            Admit::Own => {
                let mut ids: BTreeSet<LabelId> = h.labels.clone();
                let labels = self.labels();
                ids.extend(labels.iter().filter(|(g, l)| l.hosts.iter().any(|a| a.key == key) && self.owns(g)).map(|(_, l)| l.id));
                Admission::Only(ids)
            }
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

    /// The driver starts afresh: the next step hands it the host config again. The person
    /// stays (the app set it before the driver started).
    pub fn host_restart(&mut self) {
        self.hosting = Hosting::default();
    }
}
