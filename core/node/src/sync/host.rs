//! Hosting (notes/serving.md, Hosting in the node): the node reads its own `host^.0`
//! (spec/data-model.md §9) and hands its driver a `HostConfig` (`Action::Host`), public data
//! only: the admitted label IDs (`own`: the labels of groups whose standing record chain reaches
//! this node or its person and whose hosts name its key, plus `labels`), replication peers,
//! policy and caps, and which run of hosting this is (a local record, drawn when hosting starts
//! and dropped when it stops; the host store belongs to it). The hub serves on the node's own
//! listeners, under its one key.

use super::{Action, SyncEngine};
use osis_base::{LabelId, Tid};
use osis_host::{Admission, HostConfig, HostPolicy, LabelCaps};
use osis_label::Address;
use osis_schema::core_types::{self as ct, Admit};
use std::collections::{BTreeMap, BTreeSet};

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
    /// Which run of hosting this is, drawn on first use (only while `host^.0` is set:
    /// `host_step` drops it otherwise).
    fn host_store_id(&mut self) -> [u8; 32] {
        if let Some(s) = self.state.host_store {
            return s;
        }
        let mut b = [0u8; 32];
        self.rng.fill_bytes(&mut b);
        self.state.set_host_store(Some(b));
        if let Err(e) = self.state.flush(&mut self.engine) {
            self.diag(format!("sync state: {e}"));
        }
        b
    }

    /// Whether this node hosts now (a run of hosting is on; the driver erases the host store
    /// once it is not).
    pub fn hosts(&self) -> bool {
        self.state.host_store.is_some()
    }

    /// Whether `cfg` is of the current run of hosting: one emitted before hosting stopped (and
    /// maybe started again) is not, and the newer `Action::Host` is on its way.
    pub fn host_current(&self, cfg: &HostConfig) -> bool {
        self.state.host_store == Some(cfg.store_id)
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
        let store_id = self.host_store_id();
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
            store_id,
            admission,
            replicate: h.replicate.into_iter().map(|a| Address { url: a.url, key: a.key }).collect(),
            policy,
            caps: h.caps.into_iter().map(|(l, c)| (l, LabelCaps { entries: c.entries, bytes: c.bytes })).collect(),
        })
    }

    /// Hands the driver the host config when it changed (`Action::Host`), looked at once per
    /// engine change; drops the run of hosting once it stopped.
    pub(crate) fn host_step(&mut self, out: &mut Vec<Action>) {
        let g = self.engine.core.generation;
        if self.hosting.generation == Some(g) {
            return;
        }
        self.hosting.generation = Some(g);
        let cfg = self.host_config();
        if cfg.is_none() && self.state.host_store.is_some() {
            self.state.set_host_store(None);
            if let Err(e) = self.state.flush(&mut self.engine) {
                self.diag(format!("sync state: {e}"));
            }
        }
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
