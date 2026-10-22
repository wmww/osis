//! The sans-I/O sync engine (notes/sync.md; notes/architecture.md §2): one synchronous
//! state machine per node, `SyncEngine::handle(Event) -> Vec<Action>`, holding the engine, one
//! osis-proto `ClientSession` per server connection, the labeling decisions and the convergence
//! loop (spec/sync.md §5-§9). Two drivers move its bytes and timers: the tokio driver
//! (`driver`, feature `driver`) and the simulator's step driver. No sync logic lives in a driver.
//!
//! Per server and label: open (sync key of the head, else walk by stale key or claim key),
//! verify the head, download (cursor sync, reconciliation fallback), apply membership commits
//! first, then the pass: re-registration when an admin holds newer epochs (the actor's
//! membership commits the server lacks first, then the step, then the rest), uploads of
//! must-hold bodies, relays, certificates and heartbeats, deletions of must-not-hold bodies.

mod bundle;
mod deliver;
#[cfg(feature = "driver")]
pub mod driver;
mod inbound;
mod local;
mod open;
mod pass;
pub mod peers;
mod serve;
pub(crate) mod state;
mod work;

use crate::engine::Engine;
use crate::error::Result;
use crate::events::{Diagnostic, DiagnosticKind, Origin};
use crate::labeling::{GroupLabel, HeadKeys};
use osis_core::{Clock, LabelId, Tid};
use osis_crypto::CryptoRngCore;
use osis_label::{Address, Step};
use osis_proto::{ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Command};
use state::{ServerKey, State};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::mpsc::Receiver;

pub use pass::Verdicts;
pub use state::Kind as EntryKind;

/// An upload, deposit or delete not answered this long goes again at the next pass (ms): a
/// reply lost on a live connection must not keep it back for good.
const RESEND_MS: u64 = 30_000;

/// Whether a request for `k` went out less than `RESEND_MS` before `now`.
fn in_flight(m: &BTreeMap<(ConnId, LabelId, osis_core::BlobId), u64>, k: &(ConnId, LabelId, osis_core::BlobId), now: u64) -> bool {
    m.get(k).is_some_and(|t| now < t.saturating_add(RESEND_MS))
}

/// Whether `OSIS_TRACE_UPLOADS` asks for the upload trace (`SyncEngine::trace`).
fn tracing() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("OSIS_TRACE_UPLOADS").is_some())
}

/// The earliest Tick asked for after any event (ms).
const MIN_WAKE_MS: u64 = 1_000;
/// How long a projection of this node's commit outside its things' labels waits for the
/// commit's placement there (spec/sync.md §5; local policy).
pub(crate) const PLACE_WAIT_MS: u64 = 5 * 60_000;

/// A connection's handle, chosen by the sync engine.
pub type ConnId = u64;

#[derive(Clone, Debug)]
pub struct SyncConfig {
    /// Servers to keep a connection to besides those the labels name.
    pub servers: Vec<Address>,
    /// Subscribe to every opened label (pushes, spec/sync.md §8).
    pub subscribe: bool,
    /// Blobs above this many bytes are announced without their bytes and fetched when needed
    /// (lazy chunks, spec/sync.md §6).
    pub inline_limit: u64,
    /// Place heartbeats (spec/permissions.md §4; policy, notes/sync.md).
    pub heartbeats: bool,
    /// Heartbeat lifetime (`expires` after the commit's `ts`).
    pub heartbeat_lifetime_ms: u64,
    /// Re-sync interval of opened labels without a subscription.
    pub resync_ms: u64,
    /// Pause before re-dialing a server.
    pub retry_ms: u64,
    /// Deposits skip heartbeats when fewer entries are left in the budget.
    pub tight_budget: u64,
    /// Dial co-reader nodes known from their `/reach` (spec/sync.md §5, §10).
    pub peers: bool,
    /// Pause before re-dialing a co-reader node.
    pub peer_retry_ms: u64,
    /// Co-readers dialed per label and in total (newest heartbeat first).
    pub max_peers_per_label: usize,
    pub max_peers: usize,
    /// Bytes one peer key, and all peers together, may have uploaded or deposited here that
    /// are not opened, not at a server and still held (member-peer serving).
    pub peer_bytes: u64,
    pub peer_total_bytes: u64,
    /// Peer sessions served at once (more are closed at once).
    pub max_served: usize,
    /// A served session without bytes this long is closed.
    pub serve_idle_ms: u64,
    /// A served session that opened no label this long after it started is closed.
    pub serve_open_ms: u64,
    /// How long a complete pass waits for co-readers after a membership change (then it counts
    /// servers only).
    pub peer_pass_wait_ms: u64,
    /// Unopened unvouched entries a label may hold per server (an inbox label a sixteenth).
    pub unvouched_cap: usize,
    /// Every pass judges everything (no work sets): a check that the work sets miss no trigger.
    pub full_passes: bool,
}

impl Default for SyncConfig {
    fn default() -> SyncConfig {
        SyncConfig {
            servers: Vec::new(),
            subscribe: true,
            inline_limit: osis_core::format::MAX_BLOB as u64,
            heartbeats: true,
            heartbeat_lifetime_ms: 2 * osis_core::format::HEARTBEAT_MIN_LIFETIME_MS,
            resync_ms: 60_000,
            retry_ms: 5_000,
            tight_budget: 16,
            peers: true,
            peer_retry_ms: 60_000,
            max_peers_per_label: 8,
            max_peers: 64,
            peer_bytes: 64 << 20,
            peer_total_bytes: 1 << 30,
            max_served: 64,
            serve_idle_ms: 120_000,
            serve_open_ms: 30_000,
            peer_pass_wait_ms: 300_000,
            unvouched_cap: 1 << 16,
            full_passes: false,
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
    /// A connection is gone, or its dial failed.
    Down { conn: ConnId },
}

/// Outputs for the driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Open a connection to `address` (checking the server's key against it, spec/sync.md §10)
    /// and report `Up` or `Down`. Always with an ephemeral transport key; a co-reader learns
    /// this node by its member proof (spec/sync.md §5).
    Dial { conn: ConnId, address: Address },
    Send { conn: ConnId, bytes: Vec<u8> },
    Close { conn: ConnId },
    /// Deliver `Event::Tick` at this wall ms (the driver's clock; replaces earlier ones).
    Wake { at: u64 },
    /// The dialable secret changed (`rotate_reach`): stop listening with the old one, listen
    /// with `dialable_secret()` where the old listener was, and join the LAN again with a fresh
    /// transport key.
    Reach,
}

/// Open state of a label on a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Trying open keys in order.
    Opening,
    /// Registering the recorded path at a server that lacks the label.
    Registering,
    /// Waiting for the server's path to verify its head.
    Verifying,
    Open,
    /// No key opens it here.
    Failed,
}

/// Counters of the work passes did (`SyncEngine::pass_stats`; scale checks).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PassStats {
    /// Passes at servers, and how many judged everything.
    pub passes: u64,
    pub full: u64,
    /// Bodies judged for upload, entries judged for deletion.
    pub bodies: u64,
    pub entries: u64,
}

/// One label on one connection.
pub(crate) struct LConn {
    pub group: Tid,
    pub index: Option<u64>,
    pub phase: Phase,
    pub tries: Vec<open::Try>,
    pub tried_claim: bool,
    pub head: Option<Step>,
    pub keys: HeadKeys,
    /// A Sync exchange is running.
    pub syncing: bool,
    /// The log was read to its end at least once on this connection.
    pub synced: bool,
    /// A pass is wanted once the running exchange ends.
    pub dirty: bool,
    /// A child step sent for registration.
    pub registering: Option<(Step, osis_label::ClaimSet)>,
    /// What the next pass judges (`work`).
    pub work: work::Work,
    pub budget: Option<u64>,
    pub last_sync: u64,
    pub path: Vec<Step>,
    /// A hinted open walked to an unverified step: the server's path is checked after the open.
    pub walk: Option<Step>,
    /// A static-entry open's entry box, opened once the server's path verified the head.
    pub entry_box: Option<osis_schema::core_types::SecretBox>,
    /// Write keys of a server path verified here (a label not recorded in `/label`): stamps
    /// under them vouch for an entry.
    pub writers: Vec<osis_crypto::VerifyingKey>,
}

pub(crate) struct Conn {
    /// A server's address key, or a co-reader node's dialable key (its LAN address may present
    /// another transport key).
    pub server: ServerKey,
    pub address: Address,
    /// A co-reader node, not a server.
    pub peer: bool,
    pub session: ClientSession,
    pub up: bool,
    pub labels: BTreeMap<LabelId, LConn>,
    pub timer: Option<u64>,
    pub offset: Option<i64>,
}

/// One synced label's state (`SyncEngine::label_status`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelStatus {
    pub group: Tid,
    pub label: LabelId,
    pub servers: usize,
    /// Connections up to its servers.
    pub connected: usize,
    /// Connections on which it is open.
    pub open: usize,
    /// Of those, the ones whose last pass ended with nothing outstanding.
    pub idle: usize,
    /// Some server refused every key this node holds (waits for a re-seal).
    pub stranded: bool,
    pub last_sync: Option<u64>,
}

/// A body: its commit and parts `(ai, di)`.
type BodyKey = (osis_core::CommitId, Vec<(usize, usize)>);

/// The sync engine of one node.
/// First back-off after re-encrypting an aspect's deleted chunks, and its cap (local policy:
/// a server deleting each fresh chunk drives at most this rate of commits).
pub(crate) const RELINK_BACKOFF_MS: u64 = 3_600_000;
pub(crate) const RELINK_BACKOFF_MAX_MS: u64 = 7 * 24 * 3_600_000;

pub struct SyncEngine {
    pub(crate) engine: Engine,
    events: Receiver<crate::Event>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) rng: Box<dyn CryptoRngCore + Send>,
    pub(crate) cfg: SyncConfig,
    pub(crate) conns: BTreeMap<ConnId, Conn>,
    next_conn: ConnId,
    /// Servers not connected: when to dial again.
    retry: BTreeMap<ServerKey, (Address, u64)>,
    pub(crate) state: State,
    /// Event counter: pass completions and remote membership commits are ordered by it.
    pub(crate) seq: u64,
    pub(crate) passes: BTreeMap<(ServerKey, LabelId), u64>,
    pub(crate) membership_seen: BTreeMap<Tid, u64>,
    wake: Option<u64>,
    /// When the last Tick was handled (raw wall ms).
    last_tick: u64,
    /// Signals received (also sent as engine events).
    pub(crate) signals: Vec<osis_label::SignalBody>,
    /// Recent diagnostics (also sent as engine events).
    diagnostics: Vec<String>,
    /// Deposits (inbox blobs, a non-writer's membership writes) waiting for a connection to
    /// their server.
    pub(crate) outbox: Vec<local::Outgoing>,
    /// Deposits for a label this node syncs with nobody: logged here, as a peer's deposit would
    /// be (`send_outbox`).
    pub(crate) local_inbox: Vec<(LabelId, Vec<u8>, [u8; osis_crypto::WRAP_LEN])>,
    /// Deposits sent and not answered yet (a label not registered yet, or a rate
    /// limit, sends them again after `retry_ms`).
    pub(crate) inbox_sent: BTreeMap<(ServerKey, osis_core::BlobId), (ConnId, local::Outgoing)>,
    /// Blobs asked for and not received yet.
    pub(crate) fetching: BTreeMap<osis_core::BlobId, ConnId>,
    /// Tree node blobs a judgment of dropped chunks waits for (`dropped_chunks`); a pass
    /// fetches those its server holds.
    pub(crate) tree_wants: BTreeSet<osis_core::BlobId>,
    /// Blobs each body's deltas link (`pass::body_blobs`), once the walk was complete: a body
    /// never changes.
    pub(crate) body_links: BTreeMap<BodyKey, Vec<osis_core::BlobId>>,
    /// Entries uploaded or deposited on a connection and not answered yet, with when (raw ms):
    /// passes within `RESEND_MS` skip them (a burst of passes sent them all again each time).
    pub(crate) sent: BTreeMap<(ConnId, LabelId, osis_core::BlobId), u64>,
    /// Blobs a connection's server did not deliver when fetched.
    pub(crate) missing: BTreeSet<(ConnId, osis_core::BlobId)>,
    /// Deletes sent and not answered yet: later passes skip them.
    pub(crate) deleting: BTreeMap<(ConnId, LabelId, osis_core::BlobId), u64>,
    /// Timed deletes sent and not answered yet: recorded once the server says OK.
    pub(crate) timed_sent: BTreeSet<(ConnId, LabelId, osis_core::BlobId)>,
    /// Re-encrypting deleted chunks (`Engine::relink`) per aspect: when allowed next, and the
    /// interval after that (doubling, `RELINK_BACKOFF_MS` to `RELINK_BACKOFF_MAX_MS`).
    pub(crate) relink_backoff: BTreeMap<(Tid, osis_core::Ak), (u64, u64)>,
    /// Deleted chunks an aspect's back-off holds back, and when to try them again (memory only).
    pub(crate) relink_pending: BTreeSet<osis_core::BlobId>,
    pub(crate) relink_at: u64,
    /// Servers where a replaced label is done with (`retire_at`).
    pub(crate) retired_at: BTreeSet<(ServerKey, LabelId)>,
    /// Certificate copies waiting for a rotation (group, commit, aspects).
    pub(crate) deferred: Vec<(Tid, osis_core::CommitId, BTreeSet<usize>)>,
    /// Commit blobs whose every delta was checked against its header hash (`true`) or found
    /// forged (`false`; the entry is `Bad`): only checked blobs stand in for this node's own
    /// uploads or justify deleting another entry (`SyncEngine::genuine`).
    pub(crate) genuine: BTreeMap<osis_core::BlobId, bool>,
    /// When a certificate left to its author (`SETTLE_MS`), or another node's body or deposit
    /// left to a co-writer (`RELAY_MIN_MS`), is due again (raw ms).
    pub(crate) settle_at: Option<u64>,
    /// Labels synced with nobody want a local pass (`local_passes`); when the last ran (raw
    /// ms), and whether there were any (the periodic pass's wake).
    pub(crate) local_dirty: bool,
    pub(crate) local_last: u64,
    pub(crate) local_any: bool,
    /// Prefix expiries of entries under labels synced with nobody (raw unix ms; read once).
    pub(crate) local_expiry: BTreeMap<osis_core::BlobId, Option<u64>>,
    /// When this node first saw each entry deposited at a server (raw ms; the promotion wait).
    pub(crate) deposit_seen: BTreeMap<(ServerKey, LabelId, osis_core::BlobId), u64>,
    /// Stranded heartbeats already answered by a re-seal.
    pub(crate) resealed: BTreeSet<osis_core::CommitId>,
    /// Commits placed before any other upload (`Delivery::First`).
    pub(crate) first: BTreeSet<osis_core::CommitId>,
    /// Things this node removed itself from (a self-removal not yet uploaded): its own departure
    /// does not stop sealing under their actors (it leaks nothing to the leaver; the rotation is
    /// the next admin's). Its lost secrets are dropped once every label is idle.
    pub(crate) leaving: BTreeSet<Tid>,
    /// Reopens in a row per (connection, label).
    pub(crate) reopens: BTreeMap<(ConnId, LabelId), u32>,
    /// Sessions of forgotten labels whose pushes the server is still to stop.
    pub(crate) unsubscribe: BTreeSet<(ConnId, LabelId)>,
    /// Labels synced, with the actor their keys derive from and their servers.
    pub(crate) label_actors: BTreeMap<LabelId, (Tid, Vec<ServerKey>)>,
    /// (snapshot, body, aspect) judgments settled with the body kept (spec/sync.md §7); a pair
    /// goes once either body is dropped.
    pub(crate) covered_judged: BTreeSet<(osis_core::CommitId, osis_core::CommitId, Tid, osis_core::Ak)>,
    /// What passes did so far (`pass_stats`).
    pub(crate) stats: PassStats,
    /// Engine changes not yet spread to the labels' work sets (`spread_touches`).
    pub(crate) touched: work::Touched,
    /// The commits whose headers list each chunk blob (`dropped_chunks`; built on first use,
    /// kept by applied commits).
    pub(crate) listers: Option<BTreeMap<osis_core::BlobId, BTreeSet<osis_core::CommitId>>>,
    /// Peer sessions this node serves (member peer, spec/sync.md §5).
    pub(crate) served: BTreeMap<ConnId, serve::Served>,
    /// Steps peers registered here since start, by label.
    pub(crate) peer_steps: BTreeMap<LabelId, Vec<(Step, Option<osis_label::ClaimSet>)>>,
    /// Co-readers found on the LAN: their address there and when (raw ms).
    pub(crate) lan: BTreeMap<ServerKey, peers::LanRoute>,
    /// The next `publish_reach` writes a fresh lan secret.
    pub(crate) lan_rotate: bool,
    /// Whether `/reach` placed under a label that no longer qualifies is to be looked for
    /// (`check_reach`: at start, after membership, policy and contact changes).
    pub(crate) reach_check: bool,
    /// Served labels, until `/label`, membership or peer steps change.
    pub(crate) served_cache: Option<Arc<BTreeMap<LabelId, serve::ServedLabel>>>,
    /// Bytes peers uploaded or deposited here, per entry: (peer key, bytes), with running sums
    /// per peer key and in all (stale charges pruned at ticks and when a budget is reached).
    pub(crate) charges: BTreeMap<(LabelId, osis_core::BlobId), ([u8; 32], u64)>,
    pub(crate) charged_per: BTreeMap<[u8; 32], u64>,
    pub(crate) charged_total: u64,
    /// When charges were last pruned (raw ms), and whether a budget was reached since.
    pub(crate) charges_pruned: u64,
    pub(crate) charges_full: bool,
    /// Sizes of blobs served to peers (memory only; pruned at ticks).
    pub(crate) blob_sizes: BTreeMap<osis_core::BlobId, u64>,
    /// LAN tags of the co-readers for the cached window and its neighbours, to dialable keys.
    pub(crate) lan_tags: Option<(u64, peers::LanTags)>,
    /// `peers()` and the `/reach` holders by dialable key, until a commit applies.
    pub(crate) peers_cache: Option<Arc<BTreeMap<[u8; 32], peers::Peer>>>,
    pub(crate) reach_index: Option<Arc<BTreeMap<[u8; 32], Tid>>>,
    /// (engine generation, minute) the caches above were computed at.
    pub(crate) peers_key: (u64, u64),
    /// Co-readers this node received entries of a label from (complete passes wait for them
    /// while a connection to them is up, spec/permissions.md §3).
    pub(crate) peer_received: BTreeMap<LabelId, BTreeSet<ServerKey>>,
    /// When the last remote membership commit of each actor applied (raw ms; the peer part of
    /// `complete_pass` waits at most `peer_pass_wait_ms` from it).
    pub(crate) membership_at: BTreeMap<Tid, u64>,
    /// When the last remote membership commit writing an actor's `/secrets` (a rotation, the
    /// only change its author registers a step for) applied (raw ms; `step_settled`).
    pub(crate) rotation_at: BTreeMap<Tid, u64>,
    /// `placed` answers by commit, valid while `State::version` (the first field) is unchanged and
    /// no engine change came (in memory).
    pub(crate) placed_cache: (u64, BTreeMap<osis_core::CommitId, bool>),
    /// When (raw ms) this node, connected, first found each of its commits not placed
    /// (`hold`; in memory, so the wait starts again after a restart).
    pub(crate) wait_since: BTreeMap<osis_core::CommitId, u64>,
    /// Commits whose projections went unplaced past `PLACE_WAIT_MS` (one diagnostic each).
    pub(crate) late: BTreeSet<osis_core::CommitId>,
    /// Per label, the co-readers a complete pass waits for now (`peer_received` narrowed to
    /// those still reading it with a connection up that has it started; set by `handle`).
    pub(crate) pass_peers: BTreeMap<LabelId, BTreeSet<ServerKey>>,
    /// A membership or roster change since the last step (`members_changed`).
    pub(crate) members_moved: bool,
    /// Commit blobs with linked header lists whose prefix was checked against the resolved
    /// header (spec/commits.md §4).
    pub(crate) prefix_checked: BTreeSet<osis_core::BlobId>,
}

impl SyncEngine {
    /// Wraps an engine. `clock` is the uncorrected wall clock the engine was built on (Hellos
    /// carry it; the correction goes to the engine).
    pub fn new(mut engine: Engine, clock: Arc<dyn Clock>, rng: Box<dyn CryptoRngCore + Send>, cfg: SyncConfig) -> Result<SyncEngine> {
        let events = engine.subscribe();
        let mut state = State::load(&mut engine)?;
        // deposits not answered before a restart go again
        let outbox = state.outbox.values().map(|o| local::Outgoing { label: o.label, server: o.server.clone(), blob: o.blob.clone(), wrap: o.wrap, sig: o.sig, after: 0, tries: 0 }).collect();
        let mut rng = rng;
        rng.fill_bytes(&mut state.feed.log_id);
        Ok(SyncEngine {
            engine,
            events,
            clock,
            rng,
            cfg,
            conns: BTreeMap::new(),
            next_conn: 1,
            retry: BTreeMap::new(),
            state,
            seq: 0,
            passes: BTreeMap::new(),
            membership_seen: BTreeMap::new(),
            wake: None,
            last_tick: 0,
            signals: Vec::new(),
            diagnostics: Vec::new(),
            outbox,
            local_inbox: Vec::new(),
            inbox_sent: BTreeMap::new(),
            leaving: BTreeSet::new(),
            fetching: BTreeMap::new(),
            tree_wants: BTreeSet::new(),
            body_links: BTreeMap::new(),
            sent: BTreeMap::new(),
            timed_sent: BTreeSet::new(),
            deleting: BTreeMap::new(),
            missing: BTreeSet::new(),
            relink_backoff: BTreeMap::new(),
            relink_pending: BTreeSet::new(),
            relink_at: 0,
            retired_at: BTreeSet::new(),
            first: BTreeSet::new(),
            deferred: Vec::new(),
            genuine: BTreeMap::new(),
            settle_at: None,
            local_dirty: true,
            local_last: 0,
            local_any: false,
            local_expiry: BTreeMap::new(),
            deposit_seen: BTreeMap::new(),
            resealed: BTreeSet::new(),
            label_actors: BTreeMap::new(),
            reopens: BTreeMap::new(),
            unsubscribe: BTreeSet::new(),
            served: BTreeMap::new(),
            covered_judged: BTreeSet::new(),
            stats: PassStats::default(),
            touched: work::Touched::default(),
            listers: None,
            peer_steps: BTreeMap::new(),
            lan: BTreeMap::new(),
            lan_rotate: false,
            reach_check: true,
            served_cache: None,
            charges: BTreeMap::new(),
            charged_per: BTreeMap::new(),
            charged_total: 0,
            charges_pruned: 0,
            charges_full: false,
            blob_sizes: BTreeMap::new(),
            lan_tags: None,
            peers_cache: None,
            reach_index: None,
            peers_key: (u64::MAX, 0),
            peer_received: BTreeMap::new(),
            membership_at: BTreeMap::new(),
            rotation_at: BTreeMap::new(),
            placed_cache: (u64::MAX, BTreeMap::new()),
            wait_since: BTreeMap::new(),
            late: BTreeSet::new(),
            pass_peers: BTreeMap::new(),
            members_moved: false,
            prefix_checked: BTreeSet::new(),
        })
        .and_then(|mut s| {
            // a forgetting a crash interrupted before its inbox check
            s.forget_inbox()?;
            Ok(s)
        })
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// The engine, for local writes; follow with `handle(Event::Local)`.
    pub fn engine_mut(&mut self) -> &mut Engine {
        &mut self.engine
    }

    pub fn into_engine(self) -> Engine {
        self.engine
    }

    pub fn config(&self) -> &SyncConfig {
        &self.cfg
    }

    /// Raw wall ms (sessions and timers).
    pub(crate) fn raw_now(&self) -> u64 {
        self.clock.now_wall_ms().0
    }

    /// Corrected wall ms (expiry and bounds).
    pub(crate) fn now(&self) -> u64 {
        self.engine.now().0
    }

    pub(crate) fn diag(&mut self, detail: String) {
        if self.diagnostics.len() < 256 {
            self.diagnostics.push(detail.clone());
        }
        let now = self.engine.now();
        self.engine.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::BadInput, tids: Vec::new(), commit: None, peer: None, detail }, now);
        self.engine.core.events.flush();
    }

    /// Feeds one input; returns what the driver must do.
    pub fn handle(&mut self, ev: Event) -> Vec<Action> {
        let mut out = Vec::new();
        self.state.now = self.now();
        // a Tick consumed the driver's wake: the next one is always asked for again
        if matches!(ev, Event::Tick) {
            self.wake = None;
            self.last_tick = self.raw_now();
        }
        if let Err(e) = self.step(ev, &mut out) {
            self.diag(format!("sync: {e}"));
        }
        // to the open labels' work sets now: with none (offline, LAN or local labels only) the
        // changes go (a label opened later judges everything)
        self.spread_touches();
        self.update_pass_peers();
        if let Err(e) = self.state.flush(&mut self.engine) {
            self.diag(format!("sync state: {e}"));
        }
        // a received removal ended read access (spec/permissions.md §3)
        if let Err(e) = self.drop_lost_due() {
            self.diag(format!("dropping lost secrets: {e}"));
        }
        // a self-removal is up: drop what was lost
        if !self.leaving.is_empty() && self.is_idle() && self.conns.values().any(|c| c.up) {
            self.leaving.clear();
            if let Err(e) = self.drop_lost() {
                self.diag(format!("dropping lost secrets: {e}"));
            }
        }
        self.stop_pushes(&mut out);
        if let Some(at) = self.next_wake()
            && self.wake != Some(at)
        {
            self.wake = Some(at);
            out.push(Action::Wake { at });
        }
        out
    }

    fn step(&mut self, ev: Event, out: &mut Vec<Action>) -> Result<()> {
        match ev {
            Event::Tick => {
                // keep-at-most drops change no read, so no engine event says so: forget the
                // dropped bodies' blobs and let the labels judge them again (spec/commits.md §5)
                // the carrier of a live write goes before its body (spec/commits.md §5)
                for (c, aspects) in self.engine.due_live_drops()? {
                    self.snapshot_first(&aspects, &c)?;
                }
                let due = self.engine.tick_drops()?;
                if !due.is_empty() {
                    self.touched.commits.extend(due.iter().copied());
                    self.mark_dirty();
                    self.forget_dropped(Some(&due))?;
                }
                self.timers(out)?;
                self.serve_timers(out);
                self.relink_lost()?;
            }
            Event::Local => {}
            Event::Up { conn } => {
                let now = self.raw_now();
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.up = true;
                    let o = c.session.handle(now, ClientInput::Start);
                    let lan = c.peer.then(|| (c.server, c.address.clone()));
                    self.outputs(conn, o, out)?;
                    if let Some((k, a)) = lan
                        && self.lan_up(k, &a)
                    {
                        self.lan_switched(conn, k, out);
                    }
                }
            }
            Event::Bytes { conn, bytes } if self.served.contains_key(&conn) => self.serve(conn, osis_proto::ServerInput::Bytes(bytes), out)?,
            Event::Down { conn } if self.served.contains_key(&conn) => {
                self.served.remove(&conn);
            }
            Event::Bytes { conn, bytes } => {
                let now = self.raw_now();
                if let Some(c) = self.conns.get_mut(&conn) {
                    let o = c.session.handle(now, ClientInput::Bytes(bytes));
                    self.outputs(conn, o, out)?;
                }
            }
            Event::Down { conn } => {
                self.fetching.retain(|_, c| *c != conn);
                self.reopens.retain(|(c, _), _| *c != conn);
                self.lost(conn);
            }
        }
        self.engine_events()?;
        if std::mem::take(&mut self.members_moved) {
            self.members_changed(out);
            self.reach_check = true;
        }
        if std::mem::take(&mut self.reach_check) {
            self.check_reach(out)?;
        }
        self.drop_unwanted_peers(out);
        self.connect(out);
        self.send_inbox()?;
        self.send_outbox(out)?;
        self.run_dirty(out)?;
        self.notify_served(out)?;
        Ok(())
    }

    /// A dialed connection ended: redial after the retry pause.
    fn lost(&mut self, conn: ConnId) {
        // requests not answered go again on the next connection
        self.sent.retain(|(c, _, _), _| *c != conn);
        self.timed_sent.retain(|(c, _, _)| *c != conn);
        self.deleting.retain(|(c, _, _), _| *c != conn);
        self.missing.retain(|(c, _)| *c != conn);
        if let Some(c) = self.conns.remove(&conn) {
            // deposits not answered on this connection go out again on the next one
            let back: Vec<(ServerKey, osis_core::BlobId)> = self.inbox_sent.iter().filter(|(_, (x, _))| *x == conn).map(|(k, _)| *k).collect();
            for k in back {
                if let Some((_, o)) = self.inbox_sent.remove(&k) {
                    self.outbox.push(o);
                }
            }
            // a LAN address that never came up: back off that address, not the peer (the next
            // route is dialed at once)
            if c.peer && !c.up && self.lan_failed(c.server, &c.address) {
                return;
            }
            // another route failed while a LAN candidate waited: it goes now (once per pause)
            if c.peer && !c.up && self.lan_cut(c.server) {
                return;
            }
            let pause = if c.peer { self.cfg.peer_retry_ms } else { self.cfg.retry_ms };
            self.retry.insert(c.server, (c.address, self.raw_now().saturating_add(pause)));
        }
    }

    /// Drains engine events: changes mark every open label for a pass; remote membership
    /// commits restart `complete_pass` for the actors they touch.
    pub(crate) fn engine_events(&mut self) -> Result<()> {
        let mut changed = false;
        let mut dropped: BTreeSet<osis_core::CommitId> = BTreeSet::new();
        while let Ok(e) = self.events.try_recv() {
            match e {
                crate::Event::Applied { id, origin, changed: aspects, .. } => {
                    changed = true;
                    dropped.insert(id);
                    self.placed_cache.0 = u64::MAX;
                    self.touched.commits.insert(id);
                    self.touched.states.extend(aspects);
                    if let Some(h) = self.engine.header(&id) {
                        // a creation record moves the reader actors of the thing's bodies
                        self.touched.things.extend(h.aspects.iter().filter(|a| a.ak.as_str() == "/created").map(|a| a.tid));
                        // its chunks may have come with it
                        self.touched.blobs.extend(h.chunks.iter().map(|ch| ch.blob));
                        if let Some(ls) = self.listers.as_mut() {
                            for ch in &h.chunks {
                                ls.entry(ch.blob).or_default().insert(id);
                            }
                        }
                    }
                    if self.engine.header(&id).is_some_and(|h| h.kind.is_membership() || h.aspects.iter().any(|a| a.ak.as_str() == "/label")) {
                        self.served_cache = None;
                        self.members_moved = true;
                        self.touched.full = true;
                    }
                    if origin == Origin::Remote
                        && let Some(h) = self.engine.header(&id)
                        && h.kind.is_membership()
                    {
                        self.seq += 1;
                        let at = self.raw_now();
                        for a in &h.aspects {
                            let actor = self.engine.core.secret_actor(&a.tid).unwrap_or(a.tid);
                            self.membership_seen.insert(actor, self.seq);
                            self.membership_at.insert(actor, at);
                            // only an admin registers its rotation's step: another's (a writer
                            // rotating for a departure) is this admin's to register at once
                            if a.ak.as_str() == "/secrets" && self.engine.core.role_now(&h.author, &actor) == Some(osis_core::Role::Admin) {
                                self.rotation_at.insert(actor, at);
                            }
                        }
                        // new secrets may open a label that failed: retry at the next tick
                        for c in self.conns.values_mut() {
                            for l in c.labels.values_mut().filter(|l| l.phase == Phase::Failed) {
                                l.last_sync = 0;
                            }
                        }
                    }
                }
                crate::Event::Changed { cause, changed: aspects } => {
                    changed = true;
                    if cause == crate::events::Cause::LostAccess {
                        self.touched.full = true;
                    }
                    for (t, a) in &aspects {
                        dropped.extend(self.engine.core.by_aspect.get(&(*t, a.clone())).into_iter().flatten().map(|x| x.1));
                    }
                    self.touched.aspects.extend(aspects);
                }
                // late parts: other labels holding the commit judge its bodies again
                crate::Event::Joined { id } => {
                    changed = true;
                    dropped.insert(id);
                    self.touched.commits.insert(id);
                }
                crate::Event::Roster { .. } => {
                    changed = true;
                    self.served_cache = None;
                    self.members_moved = true;
                    self.touched.full = true;
                }
                _ => {}
            }
        }
        if changed {
            self.mark_dirty();
            let all = self.touched.full || self.cfg.full_passes;
            self.forget_dropped(if all { None } else { Some(&dropped) })?;
        }
        Ok(())
    }

    /// Hands the changes noted since the last pass to every label's work set: the engine's
    /// (`touched`) to all, the sync state's to the label's (`State::touched`).
    pub(crate) fn spread_touches(&mut self) {
        let t = std::mem::take(&mut self.touched);
        let st = std::mem::take(&mut self.state.touched);
        let carriers = std::mem::take(&mut self.state.touched_commits);
        for c in self.conns.values_mut() {
            for (l, lc) in c.labels.iter_mut() {
                let w = &mut lc.work;
                w.full |= t.full;
                w.commits.extend(t.commits.iter().chain(&carriers).copied());
                w.aspects.extend(t.aspects.iter().cloned());
                w.states.extend(t.states.iter().cloned());
                w.things.extend(t.things.iter().copied());
                w.blobs.extend(t.blobs.iter().copied());
                for (_, x) in st.range((*l, state::Touch::Commit(osis_core::CommitId([0; 32])))..).take_while(|(x, _)| x == l) {
                    match x {
                        state::Touch::Commit(c) => w.commits.insert(*c),
                        state::Touch::Blob(b) => w.blobs.insert(*b),
                    };
                }
            }
        }
    }

    /// Every label on every connection wants a pass.
    pub(crate) fn mark_dirty(&mut self) {
        self.local_dirty = true;
        for c in self.conns.values_mut() {
            for l in c.labels.values_mut() {
                l.dirty = true;
            }
        }
    }

    /// Whether every server this node syncs `actor`'s labels with, and every co-reader it
    /// received one of them from and has a connection up to, has had a complete pass of it since
    /// the last membership commit of the actor applied from elsewhere (`flows::SyncState`;
    /// spec/permissions.md §3 re-seal timing).
    pub fn complete_pass(&self, actor: &Tid) -> bool {
        crate::flows::SyncState::complete_pass(self, actor)
    }

    /// Labels this node syncs: every non-replaced label of a labeled group it holds read
    /// secrets of; an admin also keeps its replaced labels until done with them at every server
    /// (spec/sync.md §2: it places the membership-class commits there, the replacement's
    /// `/label` among them, and deletes the content entries; `retire_at`).
    pub fn labels(&mut self) -> Vec<(Tid, GroupLabel)> {
        let mut out = Vec::new();
        for g in self.engine.labeled_groups() {
            if self.engine.epochs(&g).is_none_or(|e| e.read.held_newest_first().is_empty()) {
                continue;
            }
            let admin = self.engine.role_on(&g) == Some(osis_core::Role::Admin);
            for l in self.engine.group_labels(&g).unwrap_or_default() {
                if l.replaced && admin && !self.state.retired.contains(&l.id) {
                    // a server where the label was lost may never settle a pass: a bound
                    let now = self.now();
                    if self.state.replaced_seen(l.id, now).saturating_add(osis_core::format::MEMBERSHIP_KEEP_MS) <= now {
                        self.state.retire(l.id);
                    }
                }
                if !l.replaced || admin && !self.state.retired.contains(&l.id) {
                    out.push((g, l));
                }
            }
        }
        self.label_actors = out.iter().map(|(g, l)| (l.id, (self.engine.core.secret_actor(g).unwrap_or(*g), l.servers.iter().map(|a| a.key).collect()))).collect();
        out
    }

    /// Where each synced label stands (the API's status): per label, its group, its servers,
    /// how many connections are up and have it open, whether every one of those finished a pass
    /// with nothing outstanding, whether any could not open it (stranded), and when it last
    /// synced (raw wall ms).
    pub fn label_status(&mut self) -> Vec<LabelStatus> {
        let mut out = Vec::new();
        for (g, l) in self.labels() {
            let mut st = LabelStatus { group: g, label: l.id, servers: l.servers.len(), connected: 0, open: 0, idle: 0, stranded: false, last_sync: None };
            for c in self.conns.values().filter(|c| l.servers.iter().any(|a| a.key == c.server)) {
                if c.up {
                    st.connected += 1;
                }
                let Some(x) = c.labels.get(&l.id) else { continue };
                match x.phase {
                    Phase::Failed => st.stranded = true,
                    Phase::Open => {
                        st.open += 1;
                        if x.synced && !x.syncing && !x.dirty && x.registering.is_none() && c.session.outstanding() == 0 {
                            st.idle += 1;
                        }
                        if x.synced {
                            st.last_sync = st.last_sync.max(Some(x.last_sync));
                        }
                    }
                    _ => {}
                }
            }
            out.push(st);
        }
        out
    }

    /// Servers with a connection up.
    pub fn connected(&self) -> usize {
        self.conns.values().filter(|c| c.up).count()
    }

    /// Replaces the servers kept connected besides those the labels name.
    pub fn set_servers(&mut self, servers: Vec<Address>) {
        self.cfg.servers = servers;
        self.touched.full = true;
    }

    /// Whether co-readers are dialed (`SyncConfig.peers`; off: running peer connections close).
    pub fn set_peers(&mut self, on: bool) -> Vec<Action> {
        self.cfg.peers = on;
        self.touched.full = true;
        self.handle(Event::Local)
    }

    /// Runs the rotations due before this node encrypts under `g`'s secrets (flows'
    /// `ensure_rotated`, spec/permissions.md §3) and returns the roles it still may not
    /// encrypt under.
    pub(crate) fn uncovered(&mut self, g: &Tid) -> Result<std::collections::BTreeSet<osis_core::Role>> {
        let Some(a) = self.engine.core.secret_actor(g) else { return Ok(Default::default()) };
        if self.engine.core.is_key_actor(&a) || self.leaving.contains(&a) || self.leaving.contains(g) {
            return Ok(Default::default());
        }
        let (done, still) = self.engine.ensure_rotated(&a)?;
        self.take_done(done)?;
        Ok(still)
    }

    /// The roles of `g`'s secret actor this node may not encrypt under now, without rotating.
    pub(crate) fn uncovered_now(&mut self, g: &Tid) -> Result<std::collections::BTreeSet<osis_core::Role>> {
        let Some(a) = self.engine.core.secret_actor(g) else { return Ok(Default::default()) };
        if self.engine.core.is_key_actor(&a) || self.leaving.contains(&a) || self.leaving.contains(g) {
            return Ok(Default::default());
        }
        self.engine.run(|tx| crate::rotation::uncovered_roles(tx, &a))
    }

    /// The servers and co-reader nodes to keep connections to (true: a node).
    fn wanted_servers(&mut self) -> BTreeMap<ServerKey, (Address, bool)> {
        let mut m: BTreeMap<ServerKey, (Address, bool)> = self.cfg.servers.iter().map(|a| (a.key, (a.clone(), false))).collect();
        for (_, l) in self.labels() {
            // an admin's word: servers only (`peer://` nodes come from `/reach` or a link)
            for a in l.servers.into_iter().filter(|a| !peers::is_peer(a)) {
                m.entry(a.key).or_insert((a, false));
            }
        }
        for h in self.state.hints.values() {
            for a in h.servers.iter().filter(|a| !peers::is_peer(a)) {
                m.entry(a.key).or_insert_with(|| (a.clone(), false));
            }
        }
        if self.cfg.peers {
            for (k, (a, _)) in self.peer_addresses() {
                m.entry(k).or_insert((a, true));
            }
            // a link's sharer node (first contact, spec/permissions.md §9) is dialed as a co-reader
            for (k, (a, _)) in self.link_routes() {
                m.entry(k).or_insert((a, true));
            }
        }
        m
    }

    /// Dials wanted servers without a connection (after their retry time); adds labels to
    /// open connections.
    fn connect(&mut self, out: &mut Vec<Action>) {
        let now = self.raw_now();
        let wanted = self.wanted_servers();
        // a server no longer wanted keeps no retry time (it would hold the wake in the past)
        self.retry.retain(|k, _| wanted.contains_key(k));
        for (key, (addr, peer)) in wanted {
            // a co-reader reached off the LAN that is heard on it: its LAN route is dialed beside
            // the running connection, which goes once that is up (`lan_switched`)
            if self.conns.values().any(|c| c.server == key) && !(peer && self.lan_probe(&key, &addr)) {
                continue;
            }
            if self.retry.get(&key).is_some_and(|(_, t)| *t > now) {
                continue;
            }
            self.retry.remove(&key);
            let conn = self.next_conn;
            self.next_conn += 1;
            let mut challenge = [0u8; 32];
            self.rng.fill_bytes(&mut challenge);
            // the key the transport authenticates (a LAN address presents its own)
            let session = ClientSession::new(ClientConfig { peer_static_key: addr.key, challenge });
            self.conns.insert(conn, Conn { server: key, address: addr.clone(), peer, session, up: false, labels: BTreeMap::new(), timer: None, offset: None });
            out.push(Action::Dial { conn, address: addr });
        }
    }

    /// Closes connections to co-readers no longer wanted (removed, or sharing only labels
    /// whose `/reach` this node withholds).
    fn drop_unwanted_peers(&mut self, out: &mut Vec<Action>) {
        if self.conns.values().all(|c| !c.peer) {
            return;
        }
        let wanted: BTreeSet<ServerKey> = if self.cfg.peers { self.peers().keys().copied().chain(self.link_routes().into_keys()).collect() } else { BTreeSet::new() };
        let gone: Vec<ConnId> = self.conns.iter().filter(|(_, c)| c.peer && !wanted.contains(&c.server)).map(|(id, _)| *id).collect();
        for conn in gone {
            out.push(Action::Close { conn });
            self.fetching.retain(|_, c| *c != conn);
            self.reopens.retain(|(c, _), _| *c != conn);
            self.lost(conn);
        }
    }

    /// Runs the session's outputs: frames out, timers, events in.
    pub(crate) fn outputs(&mut self, conn: ConnId, outputs: Vec<ClientOutput>, out: &mut Vec<Action>) -> Result<()> {
        for o in outputs {
            match o {
                ClientOutput::Send(bytes) => out.push(Action::Send { conn, bytes }),
                ClientOutput::Close => {
                    out.push(Action::Close { conn });
                    self.lost(conn);
                }
                ClientOutput::SetTimer(t) => {
                    if let Some(c) = self.conns.get_mut(&conn) {
                        c.timer = Some(t);
                    }
                }
                ClientOutput::Event(e) => self.session_event(conn, e, out)?,
            }
        }
        Ok(())
    }

    /// Sends a command on a connection.
    pub(crate) fn command(&mut self, conn: ConnId, cmd: Command, out: &mut Vec<Action>) -> Result<()> {
        let now = self.raw_now();
        if tracing() {
            self.trace(conn, &cmd);
        }
        let Some(c) = self.conns.get_mut(&conn) else { return Ok(()) };
        let o = c.session.handle(now, ClientInput::Command(cmd));
        self.outputs(conn, o, out)
    }

    /// One stderr line per entry sent (cost attribution, `OSIS_TRACE_UPLOADS`): node, group,
    /// how, bytes, what the entry is (commit, kind, certificate copy, aspects).
    fn trace(&self, conn: ConnId, cmd: &Command) {
        let short = |b: &[u8]| b.iter().take(3).map(|x| format!("{x:02x}")).collect::<String>();
        let t4 = |t: &Tid| t.to_string().chars().take(4).collect::<String>();
        let sent: Vec<(LabelId, osis_core::BlobId, usize, &str)> = match cmd {
            Command::Upload { label, entries } | Command::Sync { label, entries, .. } => entries.iter().map(|e| (*label, osis_label::blob_id(&e.blob), e.blob.len(), "up")).collect(),
            Command::Deposit { label, blob, .. } => vec![(*label, osis_label::blob_id(blob), blob.len(), "dep")],
            _ => return,
        };
        let group = |l: &LabelId| self.conns.get(&conn).and_then(|c| c.labels.get(l)).map(|x| t4(&x.group)).unwrap_or_default();
        for (l, id, n, how) in sent {
            let what = match self.state.entries.get(&(l, id)) {
                Some(e) => match &e.kind {
                    state::Kind::Commit { commit, parts, .. } => {
                        let h = self.engine.header(commit);
                        let aspects: Vec<String> = parts.iter().filter_map(|(ai, _)| h.as_ref().and_then(|h| h.aspects.get(*ai))).map(|a| format!("{}{}", t4(&a.tid), a.ak.as_str())).collect();
                        let kind = h.as_ref().map(|h| format!("{:?}", h.kind)).unwrap_or_default();
                        let author = h.as_ref().map(|h| t4(&h.author)).unwrap_or_default();
                        format!("commit {} {kind} by {author}{} [{}]", short(&commit.0), if e.cert { " cert" } else { "" }, aspects.join(" "))
                    }
                    k => format!("{k:?}"),
                },
                None => "unknown".into(),
            };
            eprintln!("TRACE node {} group {} {how} {n} B blob {}: {what}", t4(&self.engine.tid()), group(&l), short(&id.0));
        }
    }

    fn session_event(&mut self, conn: ConnId, e: ClientEvent, out: &mut Vec<Action>) -> Result<()> {
        use ClientEvent as E;
        match e {
            E::Ready { .. } => self.ready(conn, out)?,
            E::ClockOffset { offset_ms, .. } => {
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.offset = Some(offset_ms);
                }
                let mut v: Vec<i64> = self.conns.values().filter_map(|c| c.offset).collect();
                v.sort_unstable();
                if let Some(m) = v.get(v.len() / 2) {
                    self.engine.set_clock_offset(*m);
                }
            }
            E::Opened { label, head, entry_box } => self.opened(conn, label, head, entry_box, out)?,
            E::Step { label, step } => self.stale_step(conn, label, step, out)?,
            E::Registered { label } => self.registered(conn, label, out)?,
            E::Head { label, head } => self.head_reply(conn, label, head, out)?,
            E::PathSteps { label, steps, more } => self.path_steps(conn, label, steps, more, out)?,
            E::EntryStatus { label, blob_ids, codes, head } => self.entry_status(conn, label, blob_ids, codes, head, out)?,
            E::DeleteStatus { label, blob_ids, codes, head } => self.delete_status(conn, label, blob_ids, codes, head, out)?,
            E::Budget { label, blob_id, code, entries_left, head, .. } => self.budget(conn, label, blob_id, code, entries_left, head, out)?,
            // a Push names its label: one not started on this connection is junk (spec/wire.md
            // §11.2; peer input never grows storage unasked)
            E::Events { label, .. } if !self.conns.get(&conn).is_some_and(|c| c.labels.contains_key(&label)) => self.diag("server pushed a label not opened".into()),
            // a session not open yet: a push left from an earlier session (a forgotten label's,
            // a reopen's) would move the cursor past what its replay has not listed
            E::Events { label, .. } if !self.conns.get(&conn).and_then(|c| c.labels.get(&label)).is_some_and(|x| x.phase == Phase::Open) => {}
            E::Events { label, events, cursor } => {
                if !events.is_empty() {
                    self.received_from(conn, label);
                }
                self.log_events(Some(conn), label, events, cursor, out)?
            }
            E::Want { label, ids } => self.want(conn, label, ids, out)?,
            E::Synced { label } => self.synced(conn, label, out)?,
            E::NeedReconcile { label } => {
                let s = self.conns.get(&conn).map(|c| c.server);
                if let Some(s) = s {
                    self.state.set_cursor(s, label, None);
                    let ids = self.state.present_at(&s, &label);
                    self.command(conn, Command::Reconcile { label, ids }, out)?;
                }
            }
            E::Reconciled { label, need, have } => self.reconciled(conn, label, need, have, out)?,
            E::Fetched { label, items } => {
                // asked for and not there: not asked again on this connection
                let mut gone = false;
                for f in items.iter().filter(|f| f.entry.is_none()) {
                    self.fetching.remove(&f.blob_id);
                    gone |= self.missing.insert((conn, f.blob_id));
                }
                if gone && let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&label)) {
                    lc.dirty = true;
                }
                let evs: Vec<osis_proto::Event> = items.into_iter().filter_map(|f| f.entry.map(|(blob, wrap, stamp)| osis_proto::Event::Added { blob_id: f.blob_id, blob: Some(blob), wrap, stamp })).collect();
                if !evs.is_empty() {
                    self.received_from(conn, label);
                }
                self.log_events(Some(conn), label, evs, None, out)?;
            }
            E::Subscribed { .. } => {}
            E::Signal { label, blob, wrap, auth } => self.signal_in(label, &blob, &wrap, &auth)?,
            E::Refused { label, kind, code } => self.refused(conn, label, kind, code, out)?,
            E::PeerError(e) => self.diag(format!("server: {e}")),
        }
        Ok(())
    }

    /// Hellos done: every label this server holds (by the labels' server lists, or a hint)
    /// starts opening.
    fn ready(&mut self, _conn: ConnId, out: &mut Vec<Action>) -> Result<()> {
        self.add_new_labels(out)
    }

    /// Labels to open, with their group and server keys: the synced labels and inbox hints.
    fn wanted_labels(&mut self) -> Vec<(Tid, LabelId, Vec<ServerKey>)> {
        let mut want: Vec<(Tid, LabelId, Vec<ServerKey>)> = self.labels().into_iter().map(|(g, l)| (g, l.id, l.servers.iter().map(|a| a.key).collect())).collect();
        for (l, h) in &self.state.hints {
            if !want.iter().any(|(_, x, _)| x == l) {
                want.push((h.thing, *l, h.servers.iter().map(|a| a.key).collect()));
            }
        }
        if self.cfg.peers && self.conns.values().any(|c| c.peer) {
            let routes: Vec<_> = self.peer_addresses().into_iter().chain(self.link_routes()).collect();
            for (k, (_, labels)) in routes {
                for (_, l, keys) in want.iter_mut() {
                    if labels.contains(l) {
                        keys.push(k);
                    }
                }
            }
        }
        want
    }

    /// Starts every wanted label not yet on a ready connection to one of its servers.
    fn add_new_labels(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let conns: Vec<(ConnId, ServerKey)> = self.conns.iter().filter(|(_, c)| c.session.is_ready()).map(|(id, c)| (*id, c.server)).collect();
        if conns.is_empty() {
            return Ok(());
        }
        let labels = self.wanted_labels();
        for (conn, server) in conns {
            for (g, l, servers) in &labels {
                let known = self.conns.get(&conn).is_some_and(|c| c.labels.contains_key(l));
                if !known && servers.contains(&server) {
                    self.start_label(conn, *g, *l, out)?;
                }
            }
        }
        Ok(())
    }

    /// Runs passes for open, synced labels marked dirty.
    fn run_dirty(&mut self, out: &mut Vec<Action>) -> Result<()> {
        self.add_new_labels(out)?;
        // a hint is done once the thing's `/label` names the label
        let hints: Vec<(LabelId, Tid)> = self.state.hints.iter().map(|(l, h)| (*l, h.thing)).collect();
        for (l, t) in hints {
            if self.engine.group_labels(&t)?.iter().any(|x| x.id == l) {
                self.state.remove_hint(&l);
            }
        }
        let todo: Vec<(ConnId, LabelId)> = self
            .conns
            .iter()
            .flat_map(|(id, c)| c.labels.iter().filter(|(_, l)| l.dirty && l.synced && !l.syncing && l.phase == Phase::Open && l.registering.is_none()).map(move |(lid, _)| (*id, *lid)))
            .collect();
        for (conn, label) in todo {
            if let Some(l) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&label)) {
                l.dirty = false;
            }
            self.pass(conn, label, out)?;
        }
        if self.local_dirty {
            self.local_passes()?;
        }
        Ok(())
    }

    /// Session pings, periodic re-syncs, heartbeats and retries.
    fn timers(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let now = self.raw_now();
        // certificates left to their author are due: every label judges again
        if self.settle_at.is_some_and(|t| t <= now) {
            self.settle_at = None;
            self.mark_dirty();
        }
        let due: Vec<ConnId> = self.conns.iter().filter(|(_, c)| c.timer.is_some_and(|t| t <= now)).map(|(id, _)| *id).collect();
        for conn in due {
            if let Some(c) = self.conns.get_mut(&conn) {
                c.timer = None;
                let o = c.session.handle(now, ClientInput::Timer);
                self.outputs(conn, o, out)?;
            }
        }
        let resync: Vec<(ConnId, LabelId)> = self
            .conns
            .iter()
            .flat_map(|(id, c)| {
                c.labels.iter().filter(|(_, l)| l.phase == Phase::Open && !l.syncing && l.last_sync.saturating_add(self.cfg.resync_ms) <= now).map(move |(lid, _)| (*id, *lid))
            })
            .collect();
        // labels no key opened: try again from scratch
        let failed: Vec<(ConnId, LabelId, Tid)> = self
            .conns
            .iter()
            .flat_map(|(id, c)| c.labels.iter().filter(|(_, l)| l.phase == Phase::Failed && l.last_sync.saturating_add(self.cfg.resync_ms) <= now).map(move |(lid, l)| (*id, *lid, l.group)))
            .collect();
        for (conn, label, g) in failed {
            self.reopens.remove(&(conn, label));
            self.start_label(conn, g, label, out)?;
        }
        if self.local_any && self.local_last.saturating_add(self.cfg.resync_ms) <= now {
            self.local_dirty = true;
        }
        for (conn, label) in resync {
            if !self.cfg.subscribe || self.conns.get(&conn).and_then(|c| c.labels.get(&label)).is_some_and(|l| !l.synced) {
                self.sync_label(conn, label, out)?;
            } else if let Some(l) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&label)) {
                // subscribed: a pass now and then (heartbeats, timed bounds)
                l.last_sync = now;
                l.dirty = true;
            }
        }
        Ok(())
    }

    /// When the next Tick is wanted (raw wall ms): session timers, re-syncs, served sessions'
    /// idle ends, redials, inbox retries and the engine's expiry and keep-at-most timers. Never
    /// before `MIN_WAKE_MS` after the last Tick, so an item due but not serviceable yet cannot
    /// spin (and later events do not push a due wake back).
    fn next_wake(&mut self) -> Option<u64> {
        let now = self.raw_now();
        let mut t: Option<u64> = None;
        let mut at = |x: u64| t = Some(t.map_or(x, |y: u64| y.min(x)));
        for c in self.conns.values() {
            if let Some(x) = c.timer {
                at(x);
            }
            for l in c.labels.values() {
                // a label waiting for a reply re-syncs after it
                if (l.phase == Phase::Open && !l.syncing) || l.phase == Phase::Failed {
                    at(l.last_sync.saturating_add(self.cfg.resync_ms));
                }
            }
        }
        if let Some(x) = self.serve_wake() {
            at(x);
        }
        for (_, x) in self.retry.values() {
            at(*x);
        }
        if let Some(x) = self.settle_at {
            at(x);
        }
        if self.local_any {
            at(self.local_last.saturating_add(self.cfg.resync_ms));
        }
        let skew = self.now() as i64 - now as i64;
        // an unsent delivery (`at` 0) waits on placement, which wakes by its own events and bound
        if let Some(x) = self.state.sent_inbox.values().filter(|s| s.at != 0).map(|s| s.at.saturating_add(osis_core::format::INBOX_LIFETIME_MS)).min() {
            at((x as i64).saturating_sub(skew).max(0) as u64);
        }
        // a due inbox blob goes once its server's connection is ready (an event of its own)
        for o in self.outbox.iter().filter(|o| o.after > now) {
            at(o.after);
        }
        if let Ok(Some(x)) = self.engine.next_timer() {
            at((x as i64).saturating_sub(skew).max(0) as u64);
        }
        t.map(|x| x.max(self.last_tick.saturating_add(MIN_WAKE_MS)))
    }

    /// Inbox blobs (grants, notices) not yet sent or not yet answered by a server (the outbox
    /// and the delivery records are stored and restored at open); `wait_synced` waits for none.
    pub fn deliveries_pending(&self) -> usize {
        self.outbox.len() + self.inbox_sent.len() + self.state.sent_inbox.values().filter(|s| s.at == 0).count()
    }

    /// Asks every connection to sync every open label now.
    pub fn sync_now(&mut self) -> Vec<Action> {
        let mut out = Vec::new();
        let todo: Vec<(ConnId, LabelId)> = self.conns.iter().flat_map(|(id, c)| c.labels.iter().filter(|(_, l)| l.phase == Phase::Open && !l.syncing).map(move |(lid, _)| (*id, *lid))).collect();
        for (conn, label) in todo {
            if let Err(e) = self.sync_label(conn, label, &mut out) {
                self.diag(format!("sync: {e}"));
            }
        }
        let _ = self.state.flush(&mut self.engine);
        out
    }

    /// Starts a cursor sync of an open label.
    pub(crate) fn sync_label(&mut self, conn: ConnId, label: LabelId, out: &mut Vec<Action>) -> Result<()> {
        let now = self.raw_now();
        let inline_limit = self.cfg.inline_limit;
        let Some(c) = self.conns.get_mut(&conn) else { return Ok(()) };
        let server = c.server;
        let Some(l) = c.labels.get_mut(&label) else { return Ok(()) };
        l.syncing = true;
        l.last_sync = now;
        let cursor = self.state.cursors.get(&(server, label)).copied();
        // a replay lists the live entries only: presence starts over from it (a cursor lost in a
        // crash otherwise kept entries a wiped server no longer holds "present" for good)
        if cursor.is_none() {
            for b in self.state.present_at(&server, &label) {
                self.state.set_present(server, label, b, false);
            }
        }
        self.command(conn, Command::Sync { label, cursor, inline_limit, entries: Vec::new(), gained: Vec::new() }, out)
    }

    /// Label IDs open on a connection to `server` (tests, diagnostics).
    pub fn open_labels(&self, server: &ServerKey) -> BTreeSet<LabelId> {
        self.conns.values().filter(|c| c.server == *server).flat_map(|c| c.labels.iter().filter(|(_, l)| l.phase == Phase::Open).map(|(id, _)| *id)).collect()
    }

    /// Whether every open label on every connection has completed a pass and nothing is
    /// outstanding (tests, simulator quiescence).
    /// A digest of this node's sync state (simulator determinism checks): entries with their
    /// wraps, stamps and kinds, presence, deposits, tombstones, timed deletes, certificates,
    /// carriers, blob records, and which of the blobs they name the store holds.
    pub fn state_digest(&mut self) -> [u8; 32] {
        let s = &self.state;
        let mut h = osis_core::hash::Hasher::new();
        for ((l, b), e) in &s.entries {
            h.update(format!("e{l:?}{b:?}{:?}{:?}{}{:?}", e.wrap, e.stamp.map(|x| x.0), e.cert, e.kind).as_bytes());
        }
        let sets = [("p", &s.present), ("d", &s.deposited), ("g", &s.gone), ("t", &s.timed)];
        for (k, set) in sets {
            for x in set {
                h.update(format!("{k}{x:?}").as_bytes());
            }
        }
        for x in &s.certs {
            h.update(format!("k{x:?}").as_bytes());
        }
        for x in &s.carriers {
            h.update(format!("s{x:?}").as_bytes());
        }
        for (id, r) in &s.blobs {
            h.update(format!("b{id:?}{:?}{:?}{}", r.commit, r.parts, r.cert).as_bytes());
        }
        let ids: BTreeSet<osis_core::BlobId> = s.entries.keys().map(|(_, b)| *b).chain(s.blobs.keys().copied()).collect();
        for b in ids {
            let held = self.engine.has_blob(&b);
            h.update(format!("h{b:?}{held}").as_bytes());
        }
        h.finalize()
    }

    /// What passes did so far (scale checks).
    pub fn pass_stats(&self) -> PassStats {
        self.stats
    }

    pub fn is_idle(&self) -> bool {
        self.conns.values().all(|c| c.session.outstanding() == 0 && c.labels.values().all(|l| l.phase != Phase::Open || (l.synced && !l.syncing && !l.dirty && l.registering.is_none())))
    }

    /// A one-line summary of each label on each connection (tests, diagnostics).
    pub fn describe(&self) -> Vec<String> {
        let mut v = Vec::new();
        for (id, c) in &self.conns {
            for (l, x) in &c.labels {
                v.push(format!(
                    "conn {id} {l:?}: {:?} synced {} syncing {} dirty {} registering {} writer {} reader {} outstanding {} head {:?}",
                    x.phase,
                    x.synced,
                    x.syncing,
                    x.dirty,
                    x.registering.is_some(),
                    x.keys.is_writer(),
                    x.keys.epochs[0].is_some(),
                    c.session.outstanding(),
                    x.head.as_ref().map(|h| h.id().0[0])
                ));
            }
        }
        v
    }

    /// Diagnostics since the last call (tests).
    pub fn take_diagnostics(&mut self) -> Vec<String> {
        std::mem::take(&mut self.diagnostics)
    }

    /// Entries this node knows under a label (tests).
    pub fn entries(&self, l: &LabelId) -> Vec<(osis_core::BlobId, EntryKind)> {
        self.state.entries.iter().filter(|((x, _), _)| x == l).map(|((_, b), e)| (*b, e.kind.clone())).collect()
    }

    /// The wrap and stamp this node keeps for an entry (tests).
    #[doc(hidden)]
    pub fn entry_meta(&self, l: &LabelId, b: &osis_core::BlobId) -> Option<([u8; osis_crypto::WRAP_LEN], Option<osis_crypto::Signature>)> {
        self.state.entries.get(&(*l, *b)).map(|e| (e.wrap, e.stamp))
    }

    /// Whether this node still holds a commit blob's key or ciphertext (tests: a dropped body
    /// leaves neither).
    pub fn holds_blob(&mut self, b: &osis_core::BlobId) -> bool {
        self.state.blobs.contains_key(b) || self.engine.has_blob(b)
    }

    /// Signals received since the last call.
    pub fn take_signals(&mut self) -> Vec<osis_label::SignalBody> {
        std::mem::take(&mut self.signals)
    }
}
