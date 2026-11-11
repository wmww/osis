//! What the drivers and the API see of the sync engine: its config, inputs, outputs and reports.

use osis_base::{LabelId, Tid};
use osis_label::Address;

/// A connection's handle, chosen by the sync engine.
pub type ConnId = u64;

#[derive(Clone, Debug)]
pub struct SyncConfig {
    /// Hosts to keep a connection to besides those the labels name.
    pub hosts: Vec<Address>,
    /// Subscribe to every opened label (pushes, spec/sync.md §8).
    pub subscribe: bool,
    /// Blobs above this many bytes are announced without their bytes and fetched when needed
    /// (lazy chunks, spec/sync.md §6).
    pub inline_limit: u64,
    /// Re-sync interval of opened labels without a subscription.
    pub resync_ms: u64,
    /// Pause before re-dialing a host.
    pub retry_ms: u64,
    /// Dial co-reader nodes known from their `reach.0` (spec/sync.md §5, §10).
    pub peers: bool,
    /// Pause before re-dialing a co-reader node.
    pub peer_retry_ms: u64,
    /// Co-readers dialed per label and in total (by node tid).
    pub max_peers_per_label: usize,
    pub max_peers: usize,
    /// Bytes one peer key, and all peers together, may have uploaded or deposited here that
    /// are not opened, not at a host and still held (co-reader-peer serving).
    pub peer_bytes: u64,
    pub peer_total_bytes: u64,
    /// Peer sessions served at once (more are closed at once).
    pub max_served: usize,
    /// Client sessions (the unix socket) served at once, apart from `max_served`: past it the
    /// oldest one that has not authenticated is closed, else the newcomer. Resource bound: 0
    /// serves no client, infinity lets local dials exhaust memory.
    pub max_clients: usize,
    /// Connections and sessions on the client listener not yet authenticated (notes/client-port.md
    /// §5), apart from `max_served` and `max_clients`: past it the oldest gives way. Resource
    /// bound: 0 lets no client in, infinity lets a flood hold unbounded memory.
    pub client_pending: usize,
    /// A served session without bytes this long is closed.
    pub serve_idle_ms: u64,
    /// A served session that opened no label this long after it started is closed.
    pub serve_open_ms: u64,
    /// How long a complete pass waits for co-readers after a role change (then it counts
    /// hosts only).
    pub peer_pass_wait_ms: u64,
    /// Unopened unvouched entries a label may hold per host (an inbox label a sixteenth).
    pub unvouched_cap: usize,
    /// Every pass judges everything (no work sets): a check that the work sets miss no trigger.
    pub full_passes: bool,
    /// Changes from elsewhere a label's work set may take in before its next pass: past it the
    /// set goes and that pass judges everything. Memory bound, labels a post does not pass wait
    /// till their resync (a performance switch: 0 makes a pass after any change full, infinity
    /// holds 32 B per message since that pass, per label).
    pub work_max: usize,
    /// Ephemeral bytes per label this node holds from others (notes/ephemeral.md Bounds): past
    /// it, further ephemeral commits of that label are not applied (`EphemeralRefused`).
    pub ephemeral_bytes: u64,
    /// Blobs a fill asks for at a time (spec/sync.md §6). Applying a batch holds the node's lock
    /// (at 10^6 about 0.5 s), and each batch waits a round trip. 0 would fetch nothing, so at
    /// least 1 is taken; infinity loses the order to what a reply fits and holds the lock for
    /// minutes.
    pub fill_batch: usize,
}

impl Default for SyncConfig {
    fn default() -> SyncConfig {
        SyncConfig {
            hosts: Vec::new(),
            subscribe: true,
            inline_limit: osis_base::format::MAX_BLOB as u64,
            resync_ms: 60_000,
            retry_ms: 5_000,
            peers: true,
            peer_retry_ms: 60_000,
            max_peers_per_label: 8,
            max_peers: 64,
            peer_bytes: 64 << 20,
            peer_total_bytes: 1 << 30,
            max_served: 64,
            max_clients: 64,
            client_pending: 64,
            serve_idle_ms: 120_000,
            serve_open_ms: 30_000,
            peer_pass_wait_ms: 300_000,
            unvouched_cap: 1 << 16,
            full_passes: false,
            work_max: 1 << 14,
            ephemeral_bytes: 16 << 20,
            fill_batch: 128,
        }
    }
}

/// Inputs of the sync engine.
#[derive(Clone, Debug)]
pub enum Event {
    /// Time passed (a `Wake` came due, or any time).
    Tick,
    /// The engine changed through local calls (commits): look at its events.
    Local,
    /// A connection asked for by `Dial` is up.
    Up { conn: ConnId },
    /// Bytes arrived on a connection.
    Bytes { conn: ConnId, bytes: Vec<u8> },
    /// The transport took bytes sent on these connections since the last `Sent`, with how many it
    /// took in all: progress for the session stall timeout, room for a served session's pushes
    /// (`osis_proto::ServingInput::Taken`). The driver reports it before a `Tick` and before a
    /// connection's `Bytes`; a driver that never does delivers instantly.
    Sent { conns: Vec<(ConnId, u64)> },
    /// A connection is gone, or its dial failed.
    Down { conn: ConnId },
    /// The answer to an `Action::Request` (Auth, Call, Sub; notes/client-port.md §2).
    Reply { conn: ConnId, id: osis_proto::msg::Id, reply: std::result::Result<osis_proto::Outcome, osis_proto::Code> },
    /// Notifies for a served session's subscriptions, after an `Action::Room` (batched per
    /// engine change).
    Notify { conn: ConnId, notes: Vec<(osis_proto::msg::Id, osis_proto::Payload)> },
    /// Notifies wait for a served session: `Action::Room` when the push rule allows.
    WantRoom { conn: ConnId },
    /// The holder of the engine ends a served session (its client was revoked).
    End { conn: ConnId },
    /// What the node's hub handed up for its connections, in order (`osis_host::Up`): node sync
    /// is every hub session's upper layer.
    Hub { ups: Vec<(osis_host::ConnId, osis_host::Up)> },
}

/// Authenticated connections per thin client (a further Auth is Error 4), and the write sessions
/// remembered per client. Resource bound: 0 forbids clients, infinity lets one client fill the
/// `max_clients` pool.
pub const MAX_CONNS_PER_CLIENT: usize = 8;

/// The tier of a served session (notes/client-port.md §0), decided at accept by the transport
/// type, never by a key value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// A unix-socket peer of this process's uid, the same person at the keyboard: it acts as the
    /// node's main actor.
    Main,
    /// A keyed transport: nothing of it reaches the port until its Auth matches `clients^.0`.
    Keyed,
    /// A keyed session whose bearer secret matched this client actor's entry in `clients^.0`
    /// (notes/client-port.md §3). Its requests run as that actor.
    Client(Tid),
}

/// Outputs for the driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Open a connection to `address` (checking the host's key against it, spec/sync.md §10)
    /// with an ephemeral transport key, and report `Up` or `Down`. A co-reader learns this node
    /// by its connection proofs (spec/sync.md §10).
    Dial { conn: ConnId, address: Address },
    Send { conn: ConnId, bytes: Vec<u8> },
    Close { conn: ConnId },
    /// Deliver `Event::Tick` at this wall ms (the driver's clock; replaces earlier ones).
    Wake { at: u64 },
    /// The dialable secret changed (`rotate_reach`): stop listening with the old one, listen
    /// with `dialable_secret()` where the old listener was, and join the LAN again with a fresh
    /// transport key.
    Reach,
    /// Run the host with this config (`host^.0`; listening with `host_secret_for`, reporting with
    /// `set_host_status`), or stop it (none). Dials of its address reach it in-process.
    Host(Option<Box<osis_host::HostConfig>>),
    /// A client-port request on a served session (Auth, Call, Sub: answer by `Event::Reply`;
    /// Unsub: already answered). Not for the driver: the holder of the engine runs it.
    Request { conn: ConnId, tier: Tier, msg: Box<osis_proto::Message> },
    /// Notifies of up to `budget` bytes may go to `conn` now (`Event::Notify`).
    Room { conn: ConnId, budget: usize },
    /// A served session that made client-port requests ended: drop its subscriptions.
    Ended { conn: ConnId },
    /// This served session authenticated as a thin client: its connection leaves the listener's
    /// pending slots (`link::Slots::Pending`). For the driver.
    Authed { conn: ConnId },
    /// For the node's hub (`osis_host::Hub::down`, consecutive ones in one call): a message, a
    /// push room request or a close for one of its connections.
    Hub { conn: osis_host::ConnId, down: osis_host::Down },
}

/// Counters of the work passes did (`SyncEngine::pass_stats`; scale checks).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PassStats {
    /// Passes at hosts and local passes (labels served with no host), and how many judged
    /// everything.
    pub passes: u64,
    /// `labels()` computed anew, inbox hints vetted, claim try lists made and the claim keys in
    /// them (recorded steps and walked ones), inbox keys tried.
    pub label_reads: u64,
    pub vets: u64,
    pub claim_lists: u64,
    pub claim_keys: u64,
    pub inbox_keys: u64,
    /// `changed_at` passes and the labels they fingerprinted (`stamp_changes`).
    pub changed_passes: u64,
    pub changed_labels: u64,
    /// Shared sets (issues/net-shared-set.md): filters sent and received, beacons in filters sent,
    /// Hits, ByRole and Deposit items offered, Hit tables built.
    pub filters_sent: u64,
    pub filters_received: u64,
    pub beacons_sent: u64,
    pub hits_sent: u64,
    pub by_role_sent: u64,
    pub deposits_sent: u64,
    pub tables_built: u64,
    /// Tests of the pending set run, and the beacons they tested; Lost items sent; digests that
    /// differed from the peer's and sync IDs listed in Members.
    pub tests: u64,
    pub tested: u64,
    pub lost_sent: u64,
    pub digests_differ: u64,
    pub members_listed: u64,
    /// Pending commits read again (`Engine::examined`).
    pub examined: u64,
    /// Entries thrown out as unjudgeable (`mark_awaits`): each is fetched again.
    pub awaits: u64,
    pub full: u64,
    /// Bodies judged for upload, entries judged for deletion.
    pub bodies: u64,
    pub entries: u64,
    /// Blobs tried as inbox blobs (a KEM per held key of each actor whose inbox the label is).
    pub inbox_tries: u64,
}

/// One synced label's state (`SyncEngine::label_status`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelStatus {
    pub group: Tid,
    pub label: LabelId,
    pub hosts: usize,
    /// Nodes connected now with it open, whoever dialed, readers or not: a node both sides dialed
    /// counts once, by this node's own connection.
    pub sources: usize,
    /// Of those, the ones this node's own pass ended with, nothing outstanding and nothing changed
    /// since. A session only the other side dialed runs no pass here, so it is never among them.
    pub idle: usize,
    /// Connections up and still opening it: passes about to run, not sources yet.
    pub opening: usize,
    /// Every host refused every key this node holds: none can serve it here (waits for a re-seal).
    pub stranded: bool,
    /// Hosts connected now whose last refusal in a row was "not admitted" (code 14): nodes this
    /// node holds to serve it, that will not.
    pub refused_by: Vec<Address>,
    /// This node left the group and keeps its secrets until its self-removal is placed
    /// (`SyncEngine::leaving`).
    pub leaving: bool,
    /// When it was last seen with a source and every source caught up (raw wall ms), in this run.
    pub last_sync: Option<u64>,
    /// A pass finished here once, or this node made it: no first download is outstanding.
    pub passed: bool,
    /// Replaced (an admin syncs it until it retires, `retire_replaced`).
    pub replaced: bool,
}
