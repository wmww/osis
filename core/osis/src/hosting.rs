//! Hosting (notes/api.md Hosting): this node stores and serves labels for their role key
//! holders, whether it reads them or not, as its `host.0^` says (spec/data-model.md §9). Any
//! admin of the node thing may set it; the node's own driver runs the host.

use crate::error::{Error, Result};
use crate::share::HostAddr;
use crate::Osis;
use osis_node::sync::{HostStatus, host_policy};
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

pub use osis_base::LabelId;
pub use ct::{Admit, HostCaps};

/// What this node hosts (`host.0^`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hosting {
    /// Transport URLs to listen on (`quic://0.0.0.0:4040`); the node's own sessions to its host
    /// need none.
    pub listen: Vec<String>,
    /// `Own`: the labels of groups this node's person owns (the owner chain reaches the
    /// person; no role edge counts, so a group only read or administered is not) whose hosts
    /// name its host address, plus `labels`; `Open`: any label within the caps.
    pub admit: Admit,
    pub labels: BTreeSet<LabelId>,
    /// Peer hosts its labels are pushed to.
    pub replicate: Vec<HostAddr>,
    /// Host policy knobs by name (osis-host `HostPolicy` fields), over the defaults.
    pub policy: BTreeMap<String, u64>,
    /// Per-label caps in place of the policy's.
    pub caps: BTreeMap<LabelId, HostCaps>,
}

impl Osis {
    /// What this node hosts (none: it does not).
    pub fn hosting(&self) -> Option<Hosting> {
        if self.is_attached() {
            return None;
        }
        let h = self.get(self.node(), ct::HOST).ok().flatten()?;
        Some(Hosting {
            listen: h.listen,
            admit: h.admit,
            labels: h.labels,
            replicate: h.replicate.into_iter().map(|a| HostAddr::new(&a.url, a.key)).collect(),
            policy: h.policy,
            caps: h.caps,
        })
    }

    /// Starts, changes or (none) stops hosting: writes this node's `host.0^`. Stopping
    /// shreds the host secret and erases the host store; a later start has a new host address
    /// and an empty store. Fails `Invalid` on an
    /// unknown policy knob.
    pub fn set_hosting(&self, h: Option<Hosting>) -> Result<()> {
        self.local_only("set_hosting")?;
        let node = self.node();
        let mut w = self.write();
        match h {
            Some(h) => {
                host_policy(&h.policy).map_err(Error::Invalid)?;
                let v = ct::Host {
                    listen: h.listen,
                    admit: h.admit,
                    labels: h.labels,
                    replicate: h.replicate.into_iter().map(|a| ct::Address { url: a.0.url, key: a.0.key }).collect(),
                    policy: h.policy,
                    caps: h.caps,
                };
                w.at(node, ct::HOST).replace(&v)?;
            }
            None => w.at(node, ct::HOST).remove()?,
        }
        w.commit()?;
        Ok(())
    }

    /// The address this node's host is reached at (`url#key`, the first listener's), once it
    /// listens; `None` while it does not host or has not started. Fails `Network` when it could
    /// not listen.
    pub fn host_address(&self) -> Result<Option<HostAddr>> {
        self.local_only("host_address")?;
        let st = self.locked(|l| l.sync.host_status().clone());
        match st {
            HostStatus::Off => Ok(None),
            HostStatus::Listening(a) => Ok(a.first().map(|a| HostAddr::new(&a.url, a.key))),
            HostStatus::Failed(e) => Err(Error::Network(e)),
        }
    }

    /// The key of this node's host address (the transport key of its host secret), known
    /// without listening: made when `host.0^` is first set, kept until hosting stops. With a
    /// fixed listen URL, `HostAddr::new(url, key)` is the address `host_address` will report.
    pub fn host_key(&self) -> Option<[u8; 32]> {
        if self.is_attached() {
            return None;
        }
        self.locked(|l| l.sync.host_key())
    }
}
