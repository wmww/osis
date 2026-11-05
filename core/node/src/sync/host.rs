//! Hosting (notes/sync.md Hosting): the node reads its own `host.0^` (spec/data-model.md §9)
//! and hands its driver a `HostConfig` (`Action::Host`), public data only: the host key, listen
//! URLs, the admitted label IDs (`own`: the labels of groups whose owner chain reaches this
//! node or its person and whose hosts name that key, plus `labels`), replication peers, policy and caps. The host secret is
//! a local record, made when hosting starts and shredded when it stops; the driver listens
//! with it.

use super::{Action, SyncEngine};
use osis_base::{LabelId, Tid};
use osis_crypto::{Secret32, SigningSecret};
use osis_host::{Admission, HostConfig, HostPolicy, LabelCaps};
use osis_label::Address;
use osis_schema::core_types::{self as ct, Admit};
use std::collections::{BTreeMap, BTreeSet};

/// The host as the driver last reported it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum HostStatus {
    /// Not running.
    #[default]
    Off,
    /// Listening at these addresses (the first is the one to publish).
    Listening(Vec<Address>),
    /// It could not start (a listen failed).
    Failed(String),
}

/// What `host_step` last handed the driver, and from which engine generation.
#[derive(Default)]
pub(crate) struct Hosting {
    emitted: Option<HostConfig>,
    generation: Option<u64>,
    pub status: HostStatus,
    /// This node's person (`SyncEngine::set_person`), for `own`.
    person: Option<Tid>,
}

/// The host policy of `host.0^`'s knobs (by `HostPolicy` field name) over the defaults.
pub fn host_policy(knobs: &BTreeMap<String, u64>) -> Result<HostPolicy, String> {
    let mut p = HostPolicy::default();
    for (k, v) in knobs {
        p.set(k, *v)?;
    }
    Ok(p)
}

/// `host_policy` of what can be run by: the limits a stored `host.0^` names that this build cannot
/// (another node's newer ones) stay out of the policy, and are returned.
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
    /// The secret this node's host listens with, made on first use (only while `host.0^` is
    /// set: `host_step` shreds it otherwise).
    fn host_secret(&mut self) -> Secret32 {
        if let Some(s) = &self.state.host_secret {
            return s.clone();
        }
        let mut b = [0u8; 32];
        self.rng.fill_bytes(&mut b);
        let s = Secret32::from_bytes(b);
        self.state.set_host_secret(Some(s.clone()));
        if let Err(e) = self.state.flush(&mut self.engine) {
            self.diag(format!("sync state: {e}"));
        }
        s
    }

    /// The host's transport key (every transport's key is the Ed25519 key of its secret), while
    /// it hosts.
    pub fn host_key(&self) -> Option<[u8; 32]> {
        self.state.host_secret.as_ref().map(|s| SigningSecret::from_seed(s).verifying_key().to_bytes())
    }

    /// The host secret the driver listens with for a config naming `key`; none when that is not
    /// the current one (hosting stopped, and maybe started again with a new secret, before the
    /// driver took the config). Never makes one: a stale config must not bring back a secret
    /// `host_step` shredded.
    pub fn host_secret_for(&self, key: &[u8; 32]) -> Option<Secret32> {
        self.state.host_secret.clone().filter(|_| self.host_key().as_ref() == Some(key))
    }

    /// This node's `host.0^`, if set.
    pub fn hosting(&mut self) -> Option<ct::Host> {
        let me = self.engine.tid();
        self.engine.get_typed(&me, &ct::HOST).ok().flatten()
    }

    /// Sets this node's person (the app's, e.g. osis's `me`): `own` admits groups it owns.
    pub fn set_person(&mut self, person: Option<Tid>) {
        self.hosting.person = person;
        self.hosting.generation = None;
    }

    /// Whether group `g` is this node's own for `own` admission (spec/data-model.md §9): its
    /// owner chain reaches the node or its person (`set_person`). Invariant: no role edge
    /// counts, on `g` or on any owner above it, held by the node or the person: a stranger may
    /// grant either one admin without consent, and must not make this node spend its storage
    /// that way (the inbox accept step's principle). Owner links are fixed by the creation
    /// record (the tid commits to it); anyone may mint a record naming the person as owner,
    /// but the group's `label.0` takes admin on it, which that chain gives only the person's
    /// admins (or whom they granted).
    fn owns(&self, g: &Tid) -> bool {
        let node = self.engine.tid();
        self.engine.owner_chain(g).any(|x| x == node || Some(x) == self.hosting.person)
    }

    /// What the host runs with now: from `host.0^` (none: not hosting).
    pub fn host_config(&mut self) -> Option<HostConfig> {
        let h = self.hosting()?;
        let key = SigningSecret::from_seed(&self.host_secret()).verifying_key().to_bytes();
        let (policy, unknown) = host_policy_known(&h.policy);
        if !unknown.is_empty() {
            self.diag(format!("host.0^ policy: limits not run by: {:?}", unknown.keys().collect::<Vec<_>>()));
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
            key,
            listen: h.listen,
            admission,
            replicate: h.replicate.into_iter().map(|a| Address { url: a.url, key: a.key }).collect(),
            policy,
            caps: h.caps.into_iter().map(|(l, c)| (l, LabelCaps { entries: c.entries, bytes: c.bytes })).collect(),
        })
    }

    /// Hands the driver the host config when it changed (`Action::Host`), looked at once per
    /// engine change; shreds the host secret once hosting stopped.
    pub(crate) fn host_step(&mut self, out: &mut Vec<Action>) {
        let g = self.engine.core.generation;
        if self.hosting.generation == Some(g) {
            return;
        }
        self.hosting.generation = Some(g);
        let cfg = self.host_config();
        if cfg.is_none() && self.state.host_secret.is_some() {
            self.state.set_host_secret(None);
            if let Err(e) = self.state.flush(&mut self.engine) {
                self.diag(format!("sync state: {e}"));
            }
        }
        if cfg != self.hosting.emitted {
            self.hosting.emitted = cfg.clone();
            if cfg.is_none() {
                self.hosting.status = HostStatus::Off;
            }
            out.push(Action::Host(cfg.map(Box::new)));
        }
    }

    /// The driver starts afresh: the next step hands it the host config again. The person
    /// stays (the app set it before the driver started).
    pub fn host_restart(&mut self) {
        self.hosting = Hosting { person: self.hosting.person, ..Hosting::default() };
    }

    /// The driver's report of its host.
    pub fn set_host_status(&mut self, s: HostStatus) {
        if let HostStatus::Failed(e) = &s {
            self.diag(format!("hosting: {e}"));
        }
        self.hosting.status = s;
    }

    pub fn host_status(&self) -> &HostStatus {
        &self.hosting.status
    }
}
