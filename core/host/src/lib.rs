//! osis-host: hosting, a node storing and serving labels it need not read (spec/sync.md §4-§9):
//! `HostStore` (osis-proto's `LabelStore` over its own osis-store `Store`, removals shredded,
//! with the `HostPolicy` and the admission), `Hub` (sans-I/O: a serving session per connection, cross-connection
//! notices, sweeps, push replication to peer hosts) and the async `driver` over any
//! osis-transport `Transport` (feature `driver`, default). The node runs it from its `host.0^`
//! (`HostConfig`, public data only); osis-node depends on it, never the reverse: hosting reaches
//! no engine, key or sync state.
//! Layer 6 (notes/architecture.md). Notes: notes/sync.md (Implementation (osis-host)).
#![forbid(unsafe_code)]

#[cfg(feature = "driver")]
pub mod driver;
pub mod hub;
pub mod replicate;
pub mod store;

use osis_base::LabelId;
use osis_label::Address;
use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "driver")]
pub use driver::{Control, Endpoint, Log, run};
pub use hub::{ConnId, Hub, HubOutput};
pub use replicate::Replicator;
pub use store::{HostStore, DEPOSIT_ENTRY_BYTES, HostPolicy, Swept, Totals};

/// Which labels a host takes new registrations of (spec/sync.md §5: an unadmitted genesis
/// step gets code 14). Labels it already holds stay served either way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Any label, within the caps.
    Open,
    /// Only these.
    Only(BTreeSet<LabelId>),
}

impl Admission {
    pub fn admits(&self, label: &LabelId) -> bool {
        match self {
            Admission::Open => true,
            Admission::Only(s) => s.contains(label),
        }
    }
}

/// A label's own caps, in place of the policy's `cap_entries` and `cap_bytes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LabelCaps {
    pub entries: u64,
    pub bytes: u64,
}

/// What the node hands its host (from its `host.0^`, spec/data-model.md §9): public data only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostConfig {
    /// The host's transport key (the public key of the node's host secret).
    pub key: [u8; 32],
    /// Transport URLs it listens on, each with the host secret.
    pub listen: Vec<String>,
    pub admission: Admission,
    /// Peer hosts it pushes its labels to.
    pub replicate: Vec<Address>,
    pub policy: HostPolicy,
    pub caps: BTreeMap<LabelId, LabelCaps>,
}
