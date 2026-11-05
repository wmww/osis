//! Hosting (notes/api.md Hosting): this node stores and serves labels for their role key
//! holders, whether it reads them or not, as its `host.0^` says (spec/data-model.md §9). Any
//! admin of the node thing may set it; the node's own driver runs the host.

use crate::error::{Error, Result};
use crate::share::{HostAddr, Url};
use crate::Osis;
use osis_node::sync::{HostStatus, host_policy};
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

pub use osis_node::sync::HostPolicy;

pub use osis_base::LabelId;
pub use ct::{Admit, HostCaps};

/// What this node hosts (`host.0^`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hosting {
    /// Transport URLs to listen on (`quic://0.0.0.0:4040`); the node's own sessions to its host
    /// need none.
    pub listen: Vec<Url>,
    /// `Own`: the labels of groups this node's person owns (the owner chain reaches the
    /// person; no role edge counts, so a group only read or administered is not) whose hosts
    /// name its host address, plus `labels`; `Open`: any label within the caps.
    pub admit: Admit,
    pub labels: BTreeSet<LabelId>,
    /// Peer hosts its labels are pushed to.
    pub replicate: Vec<HostAddr>,
    /// What the host allows.
    pub policy: HostPolicy,
    /// Per-label caps in place of the policy's.
    pub caps: BTreeMap<LabelId, HostCaps>,
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
            labels: h.labels,
            replicate: h.replicate.into_iter().map(|a| HostAddr(osis_label::Address { url: a.url, key: a.key })).collect(),
            // what the host runs by, the defaults for knobs it does not know
            policy: host_policy(&h.policy).unwrap_or_default(),
            caps: h.caps,
        }))
    }

    /// Starts, changes or (none) stops hosting: writes this node's `host.0^`. Stopping
    /// shreds the host secret and erases the host store; a later start has a new host address
    /// and an empty store. Fails `Invalid` on a policy the host cannot run by.
    pub fn set_hosting(&self, h: Option<Hosting>) -> Result<()> {
        let node = self.node();
        let mut w = self.write();
        match h {
            Some(h) => {
                let policy = h.policy.knobs();
                host_policy(&policy).map_err(Error::Invalid)?;
                let v = ct::Host {
                    listen: h.listen.iter().map(ToString::to_string).collect(),
                    admit: h.admit,
                    labels: h.labels,
                    replicate: h.replicate.into_iter().map(|a| ct::Address { url: a.0.url, key: a.0.key }).collect(),
                    policy,
                    caps: h.caps,
                };
                w.at(node, ct::HOST).overwrite(&v)?;
            }
            None => w.at(node, ct::HOST).remove()?,
        }
        w.commit()?;
        Ok(())
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

    /// The key of this node's host address (the transport key of its host secret), known
    /// without listening: made when `host.0^` is first set, kept until hosting stops. With a
    /// fixed listen URL, `HostAddr::new(url, key)` is the address `host_address` will report.
    /// `Unsupported` on a client with its own actor.
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
