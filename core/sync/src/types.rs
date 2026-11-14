//! Every type two modules share (notes/sync-boundary.md, Crate layout): each module builds
//! against these and its own section's types alone. The step's input and outputs are here too:
//! the driver makes them, every module's work ends in them.

use crate::store::Store;
use osis_base::{BlobId, Tid, WallMs};
use osis_crypto::{Epoch, NodeRng, Signature};
use osis_engine::Engine;
use osis_label::{Address, Class, Step};
use osis_proto::Code;

pub use osis_engine::sync::{Holding, Path, Wrap};
pub use osis_store::RecordId;

/// A connection. A node numbers the connections it dials (`Out::Dial`); its `Links` numbers the
/// ones it accepts, with `ConnId::ACCEPTED` set, so the two never meet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnId(pub u64);

impl ConnId {
    /// The bit set in the numbers of accepted connections.
    pub const ACCEPTED: u64 = 1 << 63;
    /// The bit set in the numbers of the owner's client connections (`Node::connect`).
    pub const CLIENT: u64 = 1 << 62;

    pub fn accepted(self) -> bool {
        self.0 & ConnId::ACCEPTED != 0
    }
}

/// A peer's authenticated static key (spec/sync-transport.md §1): the dialed node's dialable
/// key, or a dialer's ephemeral one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeKey(pub [u8; 32]);

/// A position in a node log (spec/sync-streams.md §3).
pub type Position = u64;

/// An opaque node-log cursor (spec/sync-streams.md §3).
pub type Cursor = Vec<u8>;

/// Who a member of the shared set is to this node (spec/sync-opens.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceClass {
    /// A peer keeping S unread.
    Store,
    /// A peer reading S.
    Reader,
}

/// What a side opened S by (spec/sync-opens.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Credential {
    /// A read secret of this epoch shown on the connection.
    ReadSecret(Epoch),
    SyncKey,
    SyncProof,
    Claim,
    /// A static entry of S's roster.
    Static([u8; 32]),
    Deposit,
    /// J, judged by roles.
    J,
}

/// One entry of a store of S (spec/sync-ids.md §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub blob: BlobId,
    pub wrap: Wrap,
    pub stamp: Option<Signature>,
    pub deposited: bool,
    /// Logged by this node of its own.
    pub own: bool,
    /// Stamped, or signed as a deposit, under the role-entry domain (spec/sync-ids.md §6 Role
    /// entries).
    pub role: bool,
    pub class: Class,
    pub expires: Option<WallMs>,
}

/// What a source's stream showed of S (spec/sync-streams.md §4): what `known` is made of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceEvent {
    Present(Entry),
    Gone(BlobId),
    Head(Box<Step>),
    Full(bool),
    Refused(BlobId, Code),
}

/// A node's input: what its transport, timer and owner tell it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// A connection is up: one this node dialed (`dialed`, the conn of its `Dial`) or accepted.
    /// `rank`: the route rank (spec/sync-transport.md §1). `listener`: the listening side's static
    /// key (spec/wire.md §11.1): the key dialed, or the key of this node's listener that took it
    /// (its dialable key, or a LAN transport key).
    Up { conn: ConnId, peer: NodeKey, rank: u8, dialed: bool, listener: NodeKey },
    /// Bytes arrived on a connection.
    Bytes { conn: ConnId, bytes: Vec<u8> },
    /// The transport took `bytes` of what this node sent on `conn`, in all so far (written out,
    /// no longer queued at this end): pushes wait on it, and it moves the stall clock
    /// (spec/sync-streams.md §1-§2).
    Taken { conn: ConnId, bytes: u64 },
    /// An up connection ended.
    Closed { conn: ConnId },
    /// A dial failed: the connection never came up.
    Down { conn: ConnId },
    /// The time is `now` (a `Wake` came due, or any time the driver likes).
    Tick { now: WallMs },
    /// The node's owner wrote through the engine (or changed `SyncConfig`): what the write moved
    /// reaches sync through the memos it moved.
    Wrote,
    /// Discovery found a node to dial (spec/sync-transport.md §4): a dial candidate.
    Discovered { addr: Address },
}

/// An output, carried out by `apply` alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Out {
    Send(ConnId, Vec<u8>),
    Dial(ConnId, Address),
    Close(ConnId),
    /// Tick the node at `at`: replaces any earlier wake (each step gives at most one, last).
    Wake(WallMs),
}

/// What a scope of `Node::wait` covers (the osis API's `SyncScope`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    All,
    Thing(Tid),
    Deliveries,
}

/// Where a wait stands (spec/sync-status.md §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Waiting {
    Done,
    Pending,
    /// It can never end, and why.
    Never(&'static str),
}

/// The context every module's step runs in: the engine, the store, the time, the rng, and the
/// outputs other than sessions' bytes.
pub struct Cx<'a> {
    pub engine: &'a mut Engine,
    pub store: &'a mut Store,
    pub now: WallMs,
    pub rng: &'a mut dyn NodeRng,
    pub out: &'a mut Vec<Out>,
}

/// Sync's errors.
#[derive(Debug)]
pub enum Error {
    /// A part of sync not built yet, named.
    NotBuilt(&'static str),
    Engine(osis_engine::Error),
    Store(osis_store::Error),
    Proto(osis_proto::Error),
}

osis_base::impl_error!(Error {
    NotBuilt(m) => ("sync not built: {m}"),
    Engine(e) => ("{e}"),
    Store(e) => ("store: {e}"),
    Proto(e) => ("protocol: {e}"),
});

impl From<osis_engine::Error> for Error {
    fn from(e: osis_engine::Error) -> Error {
        Error::Engine(e)
    }
}

impl From<osis_store::Error> for Error {
    fn from(e: osis_store::Error) -> Error {
        Error::Store(e)
    }
}

impl From<osis_proto::Error> for Error {
    fn from(e: osis_proto::Error) -> Error {
        Error::Proto(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Sync's per-node configuration (local policy).
#[derive(Clone, Debug)]
pub struct SyncConfig {
    /// This node's dialable key, as its transport listens with it.
    pub key: Option<NodeKey>,
    /// Configured dial candidates (spec/sync-opens.md §1): never a filter, never stored as data.
    pub dial: Vec<Address>,
    /// `max_peers` (spec/sync-opens.md §1): this node dials while fewer connections than this
    /// share something with it or are being dialed (`driver::MAX_PEERS` by default).
    pub max_peers: usize,
}

impl Default for SyncConfig {
    fn default() -> SyncConfig {
        SyncConfig { key: None, dial: Vec::new(), max_peers: crate::driver::MAX_PEERS }
    }
}
