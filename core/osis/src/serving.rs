//! Serving (notes/api.md Serving): this node stores and serves groups' data for their holders,
//! whether it reads them or not, as its `host.0^` says (spec/data-model.md §9). Any admin of the
//! node thing may set it; the node's own driver runs the host.

use crate::error::{Error, Result};
use crate::share::{Address, Url};
use crate::Osis;
use osis_base::{LabelId, Tid, hex};
use osis_node::sync::{HostPolicy as HostLimits, HostStatus, host_policy, host_policy_known};
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

pub use ct::{Admit, HostCaps as ServingCaps};

/// What a serving node knows a group's data by, opaque and saying nothing else about the group: for
/// its rules (`Serving::admitted`, `Serving::caps`). A group's holders ask `Osis::sync_ids` and pass
/// the text form (`Display`, `FromStr`) to whoever runs that node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SyncId(pub(crate) LabelId);

#[doc(hidden)]
impl From<LabelId> for SyncId {
    fn from(l: LabelId) -> SyncId {
        SyncId(l)
    }
}

impl std::fmt::Display for SyncId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(&self.0.0))
    }
}

impl std::str::FromStr for SyncId {
    type Err = Error;
    fn from_str(s: &str) -> Result<SyncId> {
        hex::decode(s).and_then(|b| b.try_into().ok()).map(|b| SyncId(LabelId(b))).ok_or_else(|| Error::Invalid(format!("not a sync ID: {s:?}")))
    }
}

/// How much a serving node takes on. Past any of these it refuses what is new; nothing it holds is
/// lost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServingPolicy {
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
    /// The rest of the limits (`internals::host_limit`). `pub`, so that `..Default::default()`
    /// fills it in, and of a type with nothing to touch.
    #[doc(hidden)]
    pub tuning: ServingTuning,
}

/// `ServingPolicy::tuning`: the other limits by their names, none of them a field's, and those
/// stored by another node that this build cannot run by (a name it does not know, or a value out of
/// a known limit's range), kept for when a policy read here is set unless that sets them.
#[doc(hidden)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServingTuning {
    pub(crate) known: BTreeMap<String, u64>,
    pub(crate) unknown: BTreeMap<String, u64>,
}

/// The names of `ServingPolicy`'s fields among the engine's.
const PLAIN: [(&str, &str); 6] = [("group_entries", "cap_entries"), ("group_bytes", "cap_bytes"), ("groups", "max_labels"), ("entries", "max_entries"), ("bytes", "max_bytes"), ("connections", "max_connections")];

impl Default for ServingPolicy {
    fn default() -> ServingPolicy {
        ServingPolicy::of(&HostLimits::default())
    }
}

impl ServingPolicy {
    fn of(p: &HostLimits) -> ServingPolicy {
        let tuning = p.knobs().into_iter().filter(|(k, _)| !PLAIN.iter().any(|(_, h)| h == k)).collect();
        ServingPolicy { group_entries: p.cap_entries, group_bytes: p.cap_bytes, groups: p.max_labels, entries: p.max_entries, bytes: p.max_bytes, connections: p.max_connections, tuning: ServingTuning { known: tuning, unknown: BTreeMap::new() } }
    }

    /// The stored limits `stored`, as far as this build can run by them, the rest kept.
    fn stored(stored: &BTreeMap<String, u64>) -> ServingPolicy {
        let (p, unknown) = host_policy_known(stored);
        let mut out = ServingPolicy::of(&p);
        out.tuning.unknown = unknown;
        out
    }

    /// The engine's limits, `Invalid` when it cannot run by them; those it could not read stay.
    fn limits(&self) -> Result<BTreeMap<String, u64>> {
        let mut k = self.known_limits()?;
        k.extend(self.tuning.unknown.iter().map(|(n, v)| (n.clone(), *v)));
        Ok(k)
    }

    fn known_limits(&self) -> Result<BTreeMap<String, u64>> {
        let mut k = self.tuning.known.clone();
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

    /// Sets a limit by name: a field's, or one of the engine's.
    pub(crate) fn set(&mut self, name: &str, n: u64) -> std::result::Result<(), String> {
        let host = PLAIN.iter().find(|(p, _)| *p == name).map_or(name, |(_, h)| *h);
        let mut k = self.known_limits().map_err(|e| e.to_string())?;
        k.insert(host.to_string(), n);
        let mut unknown = std::mem::take(&mut self.tuning.unknown);
        // a stored value this build could not run by gives way to one it can
        unknown.remove(host);
        *self = ServingPolicy::of(&host_policy(&k)?);
        self.tuning.unknown = unknown;
        Ok(())
    }
}

/// This node's terms for storing and serving data for others, readable by it or not. Serving is
/// optional, and nothing assumes such a node stays on or has a fixed address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Serving {
    /// URLs to listen on (`quic://0.0.0.0:4040`).
    pub listen: Vec<Url>,
    /// Which groups it takes, beside `admitted`.
    pub admit: Admit,
    /// Groups it takes whatever `admit` says.
    pub admitted: BTreeSet<SyncId>,
    /// Other serving nodes it pushes what it stores to.
    pub replicate: Vec<Address>,
    /// How much it takes on.
    pub policy: ServingPolicy,
    /// Per-group caps in place of the policy's.
    pub caps: BTreeMap<SyncId, ServingCaps>,
}

impl Osis {
    /// This node's terms for serving (none: it does not serve). `Unsupported` on a client with its own
    /// actor.
    pub fn serving(&self) -> Result<Option<Serving>> {
        if self.secret_client() {
            return Err(Error::Unsupported("a client with its own actor: serving is its node's".into()));
        }
        let Some(h) = self.at(self.node(), ct::HOST).get()? else { return Ok(None) };
        Ok(Some(Serving {
            // what another writer stored and this node could not listen on: the serving status says so
            listen: h.listen.iter().filter_map(|u| u.parse().ok()).collect(),
            admit: h.admit,
            admitted: h.labels.into_iter().map(SyncId).collect(),
            replicate: h.replicate.into_iter().map(|a| Address(osis_label::Address { url: a.url, key: a.key })).collect(),
            // what it runs by; a limit it cannot, another node's, stays for a later set
            policy: ServingPolicy::stored(&h.policy),
            caps: h.caps.into_iter().map(|(l, c)| (SyncId(l), c)).collect(),
        }))
    }

    /// Starts, changes or (none) stops serving. Stopping erases what it stored for others, and its
    /// address: a later start has a new address and starts empty. Fails `Invalid` on a policy it
    /// cannot run by.
    pub fn set_serving(&self, h: Option<Serving>) -> Result<()> {
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

    /// What a serving node knows `group` by (several while it moves from one to another, none when it
    /// does not sync). Pass them to whoever runs that node, for `Serving::admitted` or `caps`.
    /// `Unsupported` on a client with its own actor.
    pub fn sync_ids(&self, group: Tid) -> Result<Vec<SyncId>> {
        let remote = |v: osis_base::Value| crate::port::codec::Args::of(vec![v]).list()?.into_iter().map(|x| crate::port::codec::Args::of(vec![x]).text()?.parse()).collect();
        if !self.has_store() {
            return remote(self.rcall(crate::port::method::SYNC_IDS, vec![osis_base::Value::Tid(group)])?);
        }
        // a group this node reads at another: there it syncs, not here
        if let crate::sources::Route::Remote(r) = self.route(group) {
            return remote(r.call(crate::port::method::SYNC_IDS, vec![osis_base::Value::Tid(group)])?);
        }
        Ok(self.locked(|l| l.sync.label_status().iter().filter(|s| s.group == group).map(|s| SyncId(s.label)).collect()))
    }

    /// The address others reach this node's serving at (the first listener's), once it listens; `None`
    /// while it does not serve or has not started. Fails `Network` when it could not listen.
    pub fn serving_address(&self) -> Result<Option<Address>> {
        self.local_only("serving_address")?;
        let st = self.locked(|l| l.sync.host_status().clone());
        match st {
            HostStatus::Off => Ok(None),
            HostStatus::Listening(a) => Ok(a.first().cloned().map(Address)),
            HostStatus::Failed(e) => Err(Error::Network(e)),
        }
    }

    /// The key of `serving_address`, known without listening: made when serving first starts, kept
    /// until it stops. With a fixed listen URL, `Address::new(url, key)` is the address it will report. `Unsupported` on a client with its own actor.
    pub fn serving_key(&self) -> Result<Option<[u8; 32]>> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::SERVING_KEY, vec![])?;
            let Some(k) = crate::port::codec::Args::of(vec![v]).opt()? else { return Ok(None) };
            let k = crate::port::codec::Args::of(vec![k]).bytes()?.try_into().map_err(|_| crate::port::codec::bad("serving key"))?;
            return Ok(Some(k));
        }
        Ok(self.locked(|l| l.sync.host_key()))
    }
}
