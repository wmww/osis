//! Every type two modules share (notes/sync.md, Crates): each module builds
//! against these and its own section's types alone. The step's input and outputs are here too:
//! the driver makes them, every module's work ends in them.

use crate::store::Store;
use osis_base::{BlobId, Mono, SyncId, Tid, WallMs};
use osis_crypto::{NodeRng, Signature};
use osis_engine::Engine;
use osis_blob::{Address, Class};

pub use osis_engine::sync::{Holding, Path, Wrap};
pub use osis_store::RecordId;

/// `resync_ms` (local policy, spec/sync.md): the wait after a peer refuses before asking again:
/// a whole filter after a refused generation (spec/sync-opens.md §5), a refused Pull sent again,
/// a join refused while S stays a member joined again (spec/sync-streams.md §4 Joining). At 0 a
/// peer refusing loops at the speed of the link; at infinity a refusal stops that filter or
/// stream on the connection for good (its opens and joins wait for the next connection).
pub const RESYNC_MS: u64 = 30_000;

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

pub use osis_proto::SourceClass;

/// The class a node holding S as `h` declares (spec/sync-opens.md §4 Source).
pub fn class_of(h: Holding) -> SourceClass {
    match h {
        Holding::Read => SourceClass::Reader,
        Holding::Stub => SourceClass::Stub,
        Holding::Unread => SourceClass::Store,
    }
}

/// What a side opened S by (spec/sync-opens.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Credential {
    /// The sync proof of this sync key.
    SyncProof([u8; 32]),
    /// A claim (its public key).
    Claim([u8; 32]),
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
    /// A dial failed: the connection never came up (`error`: why, as the transport said).
    Down { conn: ConnId, error: String },
    /// A `Wake` came due (or any time the driver likes): the node reads its clocks.
    Tick,
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
    /// Read the connection's bytes (true) or stop reading them (false) until told again: a
    /// connection is read until told not to (spec/sync-transport.md §5 Served connections).
    Read(ConnId, bool),
    /// Tick the node at `at` on its monotonic clock: replaces any earlier wake (each step gives
    /// at most one, last).
    Wake(Mono),
}

/// What a scope of `Node::wait` covers (the osis API's `SyncScope`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    All,
    Thing(Tid),
}

/// Where a wait stands (spec/sync-status.md §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Waiting {
    Done,
    Pending,
    /// These sync IDs in scope are stranded here (spec/permissions.md §4): it fails, though a
    /// re-seal may still come.
    Stranded(Vec<SyncId>),
    /// It can never end, and why.
    Never(&'static str),
}

/// The context every module's step runs in: the engine, the store, the time, the rng, and the
/// outputs other than sessions' bytes.
pub struct Cx<'a> {
    pub engine: &'a mut Engine,
    pub store: &'a mut Store,
    /// The wall clock: for stamps and judging stamped values only.
    pub now: WallMs,
    /// The monotonic clock: every wait kept in memory.
    pub mono: Mono,
    pub rng: &'a mut dyn NodeRng,
    pub out: &'a mut Vec<Out>,
    pub policy: &'a Policy,
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

impl Error {
    /// As a store failure: a store's own (or the engine's), an engine's broken invariant with its
    /// text, else `Corrupt(what)`.
    pub fn into_store(self, what: &'static str) -> osis_store::Error {
        match self {
            Error::Store(e) | Error::Engine(osis_engine::Error::Store(e)) => e,
            Error::Engine(osis_engine::Error::Corrupt(m)) => osis_store::Error::Corrupt(m),
            _ => osis_store::Error::Corrupt(what),
        }
    }
}

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
    pub policy: Policy,
}

impl Default for SyncConfig {
    fn default() -> SyncConfig {
        SyncConfig { key: None, dial: Vec::new(), max_peers: crate::driver::MAX_PEERS, policy: Policy::default() }
    }
}

/// How long a redeem not joined yet is followed (spec/sync-inbox.md §6, local policy;
/// minor consequence): an hour, long enough for a sharer's sleeping device to wake, short enough
/// not to dial a gone one forever. At 0 a redeem gives up at once; at infinity a sharer that never
/// answers is followed and dialed forever. Past it the user redeems the link again.
pub const FOLLOW_LINK_MS: u64 = 60 * 60 * 1000;

/// Which nodes this node dials, proves its actors to and syncs with (spec/sync-opens.md §1
/// Policy): its account's choice, overridable per node. The one seam such a choice goes through:
/// the dial candidates (`dial`), the session's proofs (`identify`), whether a proven peer is
/// kept (`sync_with`) and how long a link's sharer is followed (`follow_link_ms`). Only the
/// default policy exists, every answer yes and `FOLLOW_LINK_MS`; a configuration adds
/// its options here and answers from them (and from what the engine holds, e.g. the account's
/// contacts, once it takes the engine).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {}

impl Policy {
    /// Whether this node dials `to`, a dial candidate: a node that dials nobody still serves.
    pub fn dial(&self, _to: &Address) -> bool {
        true
    }

    /// Whether this node proves its actors on a connection: as the dialer before anything is
    /// proven (`peer` `None`), as the listener once the dialer's proofs are judged. Else it proves
    /// none there, and keeps no record of the peer (spec/sync-opens.md §3).
    pub fn identify(&self, _peer: Option<&crate::session::Proven>) -> bool {
        true
    }

    /// Whether this node syncs with a peer that proved `peer`: else it closes the connection once
    /// the proofs are judged.
    pub fn sync_with(&self, _peer: &crate::session::Proven) -> bool {
        true
    }

    /// How long, from its start, a redeem not joined yet is followed before this node gives it up
    /// (spec/sync-inbox.md §6): `FOLLOW_LINK_MS`.
    pub fn follow_link_ms(&self) -> u64 {
        FOLLOW_LINK_MS
    }
}
