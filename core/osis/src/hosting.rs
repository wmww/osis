//! Hosting (notes/api.md Hosting): this node stores and serves groups' data for their holders,
//! whether it reads them or not, as its `host.0^` says (spec/data-model.md §9). Any admin of the
//! node thing may set it; the node's own driver runs the host.

use crate::error::{Error, Result};
use crate::share::{HostAddr, Url};
use crate::Osis;
use osis_base::{LabelId, Tid, hex};
use osis_node::sync::{HostPolicy as HostLimits, HostStatus, host_policy};
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

pub use ct::{Admit, HostCaps};

/// What names a group's data at a node that hosts it, for that node's rules (`Hosting::admitted`,
/// `Hosting::caps`). A group's holders ask `Osis::admission_ids`; it says nothing else about the
/// group, and its text form (`Display`, `FromStr`) is what they pass to whoever runs the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdmissionId(pub(crate) LabelId);

#[doc(hidden)]
impl From<LabelId> for AdmissionId {
    fn from(l: LabelId) -> AdmissionId {
        AdmissionId(l)
    }
}

impl std::fmt::Display for AdmissionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(&self.0.0))
    }
}

impl std::str::FromStr for AdmissionId {
    type Err = Error;
    fn from_str(s: &str) -> Result<AdmissionId> {
        hex::decode(s).and_then(|b| b.try_into().ok()).map(|b| AdmissionId(LabelId(b))).ok_or_else(|| Error::Invalid(format!("not an admission id: {s:?}")))
    }
}

/// How much a host takes on. Past any of these it refuses what is new; nothing it holds is lost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPolicy {
    /// Stored items per group.
    pub group_entries: u64,
    /// Stored bytes per group.
    pub group_bytes: u64,
    /// Groups, all told.
    pub groups: u64,
    /// Stored items, all told.
    pub entries: u64,
    /// Stored bytes, all told.
    pub bytes: u64,
    /// Connections served at once.
    pub connections: usize,
    /// The rest of the host's limits, by their names (tests, `osis host set --policy`).
    #[doc(hidden)]
    pub tuning: BTreeMap<String, u64>,
}

/// The names of `HostPolicy`'s fields among the host's own.
const PLAIN: [(&str, &str); 6] = [("group_entries", "cap_entries"), ("group_bytes", "cap_bytes"), ("groups", "max_labels"), ("entries", "max_entries"), ("bytes", "max_bytes"), ("connections", "max_connections")];

impl Default for HostPolicy {
    fn default() -> HostPolicy {
        HostPolicy::of(&HostLimits::default())
    }
}

impl HostPolicy {
    fn of(p: &HostLimits) -> HostPolicy {
        let tuning = p.knobs().into_iter().filter(|(k, _)| !PLAIN.iter().any(|(_, h)| h == k)).collect();
        HostPolicy { group_entries: p.cap_entries, group_bytes: p.cap_bytes, groups: p.max_labels, entries: p.max_entries, bytes: p.max_bytes, connections: p.max_connections, tuning }
    }

    /// The host's own limits, `Invalid` when it cannot run by them.
    fn limits(&self) -> Result<BTreeMap<String, u64>> {
        let mut k = self.tuning.clone();
        let d = HostLimits::default();
        let mut put = |name: &str, v: u64, def: u64| {
            if v != def {
                k.insert(name.to_string(), v);
            }
        };
        put("cap_entries", self.group_entries, d.cap_entries);
        put("cap_bytes", self.group_bytes, d.cap_bytes);
        put("max_labels", self.groups, d.max_labels);
        put("max_entries", self.entries, d.max_entries);
        put("max_bytes", self.bytes, d.max_bytes);
        put("max_connections", self.connections as u64, d.max_connections as u64);
        host_policy(&k).map_err(Error::Invalid)?;
        Ok(k)
    }

    /// Sets a limit by name: a field's, or one of `tuning`.
    #[doc(hidden)]
    pub fn set(&mut self, name: &str, n: u64) -> std::result::Result<(), String> {
        let host = PLAIN.iter().find(|(p, _)| *p == name).map_or(name, |(_, h)| *h);
        let mut k = self.limits().map_err(|e| e.to_string())?;
        k.insert(host.to_string(), n);
        *self = HostPolicy::of(&host_policy(&k)?);
        Ok(())
    }
}

/// What this node hosts (`host.0^`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hosting {
    /// URLs to listen on (`quic://0.0.0.0:4040`); the node's own sessions to its host
    /// need none.
    pub listen: Vec<Url>,
    /// `Own`: the groups this node's account owns whose hosts name its host address, plus `admitted`
    /// (only owning counts, so a group only read or administered is not one); `Open`: any group
    /// within the caps.
    pub admit: Admit,
    /// Groups it takes whatever `admit` says.
    pub admitted: BTreeSet<AdmissionId>,
    /// Peer hosts what it holds is pushed to.
    pub replicate: Vec<HostAddr>,
    /// What the host takes on.
    pub policy: HostPolicy,
    /// Per-group caps in place of the policy's.
    pub caps: BTreeMap<AdmissionId, HostCaps>,
}

impl Osis {
    /// What this node hosts (none: it does not). `Unsupported` on a client with its own actor.
    pub fn hosting(&self) -> Result<Option<Hosting>> {
        if self.secret_client() {
            return Err(Error::Unsupported("a client with its own actor: hosting is its node's".into()));
        }
        let Some(h) = self.at(self.node(), ct::HOST).get()? else { return Ok(None) };
        Ok(Some(Hosting {
            // what another writer stored and this node could not listen on: the host's status says so
            listen: h.listen.iter().filter_map(|u| u.parse().ok()).collect(),
            admit: h.admit,
            admitted: h.labels.into_iter().map(AdmissionId).collect(),
            replicate: h.replicate.into_iter().map(|a| HostAddr(osis_label::Address { url: a.url, key: a.key })).collect(),
            // what the host runs by, the defaults for knobs it does not know
            policy: HostPolicy::of(&host_policy(&h.policy).unwrap_or_default()),
            caps: h.caps.into_iter().map(|(l, c)| (AdmissionId(l), c)).collect(),
        }))
    }

    /// Starts, changes or (none) stops hosting: writes this node's `host.0^`. Stopping
    /// erases what the host stored, its address with it; a later start has a new host address
    /// and an empty store. Fails `Invalid` on a policy the host cannot run by.
    pub fn set_hosting(&self, h: Option<Hosting>) -> Result<()> {
        let node = self.node();
        let mut w = self.write();
        match h {
            Some(h) => {
                let v = ct::Host {
                    listen: h.listen.iter().map(ToString::to_string).collect(),
                    admit: h.admit,
                    labels: h.admitted.into_iter().map(|a| a.0).collect(),
                    replicate: h.replicate.into_iter().map(|a| ct::Address { url: a.0.url, key: a.0.key }).collect(),
                    policy: h.policy.limits()?,
                    caps: h.caps.into_iter().map(|(a, c)| (a.0, c)).collect(),
                };
                w.at(node, ct::HOST).overwrite(&v)?;
            }
            None => w.at(node, ct::HOST).remove()?,
        }
        w.commit()?;
        Ok(())
    }

    /// What names `group` for hosts' admission rules (several while it moves from one to another,
    /// none when it does not sync). Pass it to whoever runs a host, for `Hosting::admitted` or
    /// `caps`.
    pub fn admission_ids(&self, group: Tid) -> Result<Vec<AdmissionId>> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::ADMISSION_IDS, vec![osis_base::Value::Tid(group)])?;
            return crate::port::codec::Args::of(vec![v]).list()?.into_iter().map(|x| crate::port::codec::Args::of(vec![x]).text()?.parse()).collect();
        }
        Ok(self.locked(|l| l.sync.label_status().iter().filter(|s| s.group == group).map(|s| AdmissionId(s.label)).collect()))
    }

    /// The address this node's host is reached at (the first listener's), once it
    /// listens; `None` while it does not host or has not started. Fails `Network` when it could
    /// not listen.
    pub fn host_address(&self) -> Result<Option<HostAddr>> {
        self.local_only("host_address")?;
        let st = self.locked(|l| l.sync.host_status().clone());
        match st {
            HostStatus::Off => Ok(None),
            HostStatus::Listening(a) => Ok(a.first().cloned().map(HostAddr)),
            HostStatus::Failed(e) => Err(Error::Network(e)),
        }
    }

    /// The key of this node's host address, known without listening: made when hosting first
    /// starts, kept until it stops. With a fixed listen URL, `HostAddr::new(url, key)` is the address
    /// `host_address` will report. `Unsupported` on a client with its own actor.
    pub fn host_key(&self) -> Result<Option<[u8; 32]>> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::HOST_KEY, vec![])?;
            let Some(k) = crate::port::codec::Args::of(vec![v]).opt()? else { return Ok(None) };
            let k = crate::port::codec::Args::of(vec![k]).bytes()?.try_into().map_err(|_| crate::port::codec::bad("host key"))?;
            return Ok(Some(k));
        }
        Ok(self.locked(|l| l.sync.host_key()))
    }
}
