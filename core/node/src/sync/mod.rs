//! The sans-I/O sync engine (notes/node-sync.md; notes/architecture.md §2): one synchronous
//! state machine per node, `SyncEngine::handle(Event) -> Vec<Action>`, holding the engine, one
//! osis-proto `ClientSession` per host connection, the labeling decisions and the convergence
//! loop (spec/sync.md §5-§9). Two drivers move its bytes and timers: the tokio driver
//! (`driver`, feature `driver`) and the simulator's step driver. No sync logic lives in a driver.
//!
//! Per host and label: open (sync key of the head, else walk by stale key or claim key),
//! verify the head, download (cursor sync, reconciliation fallback), apply role commits
//! first, then the pass: re-registration when an admin holds newer epochs (the actor's
//! role commits the host lacks first, then the step, then the rest), uploads of
//! must-hold bodies, relays, certificates and heartbeats, deletions of must-not-hold bodies.

mod bundle;
mod conn;
mod deliver;
mod fill;
mod host;
#[cfg(feature = "driver")]
pub mod driver;
mod inbound;
mod io;
mod local;
mod marks;
mod memory;
mod open;
mod pass;
pub mod peers;
mod receipts;
mod serve;
pub(crate) mod state;
mod status;
mod timers;
mod work;

use crate::engine::Engine;
use crate::error::Result;
use crate::events::{Diagnostic, DiagnosticKind, Origin};
use crate::labeling::{GroupLabel, HeadKeys};
use osis_base::{Ak, Clock, LabelId, Tid};
use osis_crypto::CryptoRngCore;
use osis_label::{Address, Step};
use osis_proto::{ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Code, Command};
use state::{HostKey, State};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::mpsc::Receiver;

pub(crate) use conn::{Conn, LConn, Phase, UNTAGGED, in_flight};
pub use host::{HostStatus, host_policy, host_policy_known};
pub use osis_host::HostPolicy;
pub use io::{Action, ConnId, Event, LabelStatus, MAX_CONNS_PER_CLIENT, PassStats, SyncConfig, Tier};
pub use pass::Verdicts;
pub use state::Kind as EntryKind;

/// The earliest Tick asked for after any event (ms).
const MIN_WAKE_MS: u64 = 1_000;
/// Rounds of passes a step runs on what its passes marked (minor: a chain longer than this waits
/// for the next event, as all of it did at 0; unbounded, a pass marking itself would spin).
const PASS_AGAIN: usize = 8;

/// A body: its commit and parts by aspect index.
type BodyKey = (osis_base::CommitId, Vec<usize>);

/// First back-off after re-encrypting an aspect's deleted chunks, and its cap (local policy:
/// a host deleting each fresh chunk drives at most this rate of commits).
pub(crate) const RELINK_BACKOFF_MS: u64 = 3_600_000;
pub(crate) const RELINK_BACKOFF_MAX_MS: u64 = 7 * 24 * 3_600_000;

/// The labels this node syncs (`SyncEngine::labels`) as last computed, valid within one step
/// while the engine's generation, the retired labels and the time are unchanged.
pub(crate) struct Synced {
    /// Engine generation, retired labels, the time if `labels` read it.
    pub(crate) key: (u64, usize, u64),
    /// A replaced label was judged: an admin edge's `until` makes the answer depend on the time.
    timed: bool,
    labels: Vec<(Tid, Arc<GroupLabel>)>,
    /// The IDs of `labels`.
    pub(crate) ids: BTreeSet<LabelId>,
    /// Per label, the actor its keys derive from and its hosts, `peer://` nodes left out
    /// (`complete_pass`, `peers::host_keys`).
    pub actors: BTreeMap<LabelId, (Tid, Vec<HostKey>)>,
}

impl Default for Synced {
    fn default() -> Synced {
        Synced { key: (u64::MAX, 0, 0), timed: false, labels: Vec::new(), ids: BTreeSet::new(), actors: BTreeMap::new() }
    }
}

/// The sync engine of one node.
pub struct SyncEngine {
    pub(crate) engine: Engine,
    events: Receiver<crate::Event>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) rng: Box<dyn CryptoRngCore + Send>,
    pub(crate) cfg: SyncConfig,
    pub(crate) conns: BTreeMap<ConnId, Conn>,
    next_conn: ConnId,
    /// Hosts not connected: when to dial again.
    retry: BTreeMap<HostKey, (Address, u64)>,
    /// Co-readers redialed at once after an up connection ended, and when (raw ms): at most
    /// once per `peer_retry_ms` each.
    redialed: BTreeMap<HostKey, u64>,
    /// Followed links (by K) whose redemption is under way: their sharer nodes are redialed after
    /// `retry_ms`, not `peer_retry_ms` (`lost`). Memory only: no redemption outlives the process.
    redeeming: BTreeSet<Tid>,
    pub(crate) state: State,
    /// Event counter: pass completions and remote role commits are ordered by it.
    pub(crate) seq: u64,
    /// Per (host, label), the last pass end: its `seq` and when (corrected wall ms).
    /// Kept across disconnects on purpose: readers ask "a pass ended after X", never "on the live
    /// connection". `complete_pass` counts only passes after the actor's last remote role
    /// commit (`role_change`), and finalizing an expired link only those ended after `until`;
    /// what reached the host after a pass end is the same race online, and a duplicate re-seal
    /// costs a box. Clearing would block re-seal and link finalization while one host is down.
    pub(crate) passes: BTreeMap<(HostKey, LabelId), (u64, u64)>,
    wake: Option<u64>,
    /// When the last Tick was handled (raw wall ms).
    last_tick: u64,
    /// Recent diagnostics (also sent as engine events).
    diagnostics: Vec<String>,
    /// Where each queued deposit (`State::outbox`: inbox blobs, a non-writer's own writes)
    /// stands: waiting for its host, or sent and not answered yet.
    pub(crate) outbox: BTreeMap<(HostKey, LabelId, osis_base::BlobId), local::Outgoing>,
    /// Entries left in each deposit budget as a host last reported it (`send_outbox`).
    pub(crate) deposit_room: BTreeMap<(HostKey, LabelId), u64>,
    /// Deposits for a label this node syncs with nobody: logged here, as a peer's deposit would
    /// be (`send_outbox`).
    pub(crate) local_inbox: Vec<(LabelId, Vec<u8>, [u8; osis_crypto::WRAP_LEN])>,
    /// Tree node blobs a judgment of dropped chunks waits for (`dropped_chunks`); a pass
    /// fetches those its host holds.
    pub(crate) tree_wants: BTreeSet<osis_base::BlobId>,
    /// Blobs each body's deltas link (`pass::body_blobs`), once the walk was complete: a body
    /// never changes.
    pub(crate) body_links: BTreeMap<BodyKey, Vec<osis_base::BlobId>>,
    /// Opened inbox entries' payloads (`inbound::inbox_opened`): a blob never changes; one no
    /// entry names any more is dropped by `vet_inbox_hints`.
    pub(crate) inbox_opened: BTreeMap<(LabelId, osis_base::BlobId), Option<Arc<inbound::Opened>>>,
    /// What `vet_inbox_hints` last ran on: the engine, the entries, and when an inbox blob it
    /// counted expires.
    pub(crate) vetted: Option<(u64, u64, u64)>,
    /// (label, thing, index) a hinted label failed under since its last retry
    /// (`vet_inbox_hints`); at most one per inbox blob, and a restart forgets them: tried again.
    pub(crate) hint_failed: BTreeSet<(LabelId, Tid, u64)>,
    pub(crate) inbox_copied: work::InboxCopied,
    /// `secrets_count` at this engine generation (both).
    pub(crate) secrets_counted: std::cell::Cell<Option<((u64, u64), usize)>>,
    /// `pass::pending_sets` at this engine generation (both).
    pub(crate) unsettled_memo: Option<((u64, u64), pass::Unsettled, pass::Unsettled)>,
    /// Re-encrypting deleted chunks (`Engine::relink`) per aspect: when allowed next, and the
    /// interval after that (doubling, `RELINK_BACKOFF_MS` to `RELINK_BACKOFF_MAX_MS`).
    pub(crate) relink_backoff: BTreeMap<(Tid, osis_base::Ak), (u64, u64)>,
    /// Deleted chunks an aspect's back-off holds back, and when to try them again (memory only).
    pub(crate) relink_pending: BTreeSet<osis_base::BlobId>,
    pub(crate) relink_at: u64,
    /// Hosts where a replaced label is done with (`retire_at`).
    pub(crate) retired_at: BTreeSet<(HostKey, LabelId)>,
    /// Certificate copies waiting for a rotation.
    pub(crate) deferred: Vec<Deferred>,
    /// Commit blobs whose every delta was checked against its header hash (`true`) or found
    /// forged (`false`; the entry is `Bad`): only checked blobs stand in for this node's own
    /// uploads or justify deleting another entry (`SyncEngine::genuine`).
    pub(crate) genuine: BTreeMap<osis_base::BlobId, bool>,
    /// New secrets: the boxes of pending commits' other copies are read again (`redeliver`).
    pub(crate) reread_boxes: bool,
    /// The first `redeliver` of this start looks for what a crash lost (`name_after_crash`).
    pub(crate) start_look: bool,
    /// Entries `redeliver` ingested again since the start.
    #[doc(hidden)]
    pub redelivered: u64,
    /// When a certificate left to its author (`SETTLE_MS`), or another node's body or deposit
    /// left to a co-writer (`RELAY_MIN_MS`), is due again (raw ms).
    pub(crate) settle_at: BTreeMap<u64, BTreeSet<LabelId>>,
    /// Labels synced with nobody want a local pass (`local_passes`); when the last ran (raw
    /// ms), and whether there were any (the periodic pass's wake).
    pub(crate) local_dirty: bool,
    pub(crate) local_last: u64,
    pub(crate) local_any: bool,
    /// Prefix expiries of entries under labels synced with nobody (raw unix ms; read once).
    pub(crate) local_expiry: BTreeMap<osis_base::BlobId, Option<u64>>,
    /// The work sets of the local passes, by label (`LConn::work` for a label served here).
    pub(crate) local_work: BTreeMap<osis_base::LabelId, work::Work>,
    /// When this node first saw each entry deposited at a host (raw ms; the promotion wait).
    pub(crate) deposit_seen: BTreeMap<(HostKey, LabelId, osis_base::BlobId), u64>,
    /// This node's uploads a host refused for the label's cap (code 12), until taken there
    /// or no longer held: a purged body they would carry goes first (spec/sync.md §7).
    pub(crate) capped: BTreeSet<(HostKey, LabelId, osis_base::BlobId)>,
    /// Stranded heartbeats already answered by a re-seal.
    pub(crate) resealed: BTreeSet<osis_base::CommitId>,
    /// Suspect entries of heartbeats already judged for repair (`repair_suspects`): (heartbeat
    /// commit, thing, aspect). In memory: after a restart each is judged once more.
    pub(crate) repaired: BTreeSet<(osis_base::CommitId, Tid, osis_base::Ak)>,
    /// Per (node reporting, thing, aspect) a repair snapshotted, this node's state digest just after:
    /// the same state does not snapshot again for that node however often its report differs. In
    /// memory: a restart may write one more.
    pub(crate) repair_state: BTreeMap<(Tid, Tid, osis_base::Ak), [u8; 16]>,
    /// Links whose finalization failed in this run (`finalize_links`): not tried again.
    pub(crate) links_failed: BTreeSet<Tid>,
    /// Tied edges to remove (`untie_unplaced`): what changed since they were last derived
    /// (groups whose `group.0` changed, things whose `roles.0` or roster changed, or all), the
    /// (target, group) pairs whose placement is gone, and those whose removal failed in this run.
    pub(crate) tied: deliver::TiedWork,
    /// Commits placed before any other upload (`Delivery::First`).
    pub(crate) first: BTreeSet<osis_base::CommitId>,
    /// Lost access may wait for this node's own self-removal to be placed (`drop_left`): set
    /// at start, by a self-removal and when the trigger leaves a loss to it; cleared once nothing
    /// lost waits or may come to.
    pub(crate) left: Option<deliver::LeftCheck>,
    /// Sessions of forgotten labels whose pushes the host is still to stop.
    pub(crate) unsubscribe: BTreeSet<(ConnId, LabelId)>,
    /// The synced labels as last computed (`labels()`).
    pub(crate) synced: Synced,
    /// (snapshot, body, aspect) judgments settled with the body kept (spec/sync.md §7); a pair
    /// goes once either body is dropped.
    pub(crate) covered_judged: BTreeSet<(osis_base::CommitId, osis_base::CommitId, Tid, osis_base::Ak)>,
    /// What passes did so far (`pass_stats`).
    pub(crate) stats: PassStats,
    /// Engine changes not yet spread to the labels' work sets (`spread_touches`).
    pub(crate) touched: work::Touched,
    /// Peer sessions this node serves (co-reader peer, spec/sync.md §5).
    pub(crate) served: BTreeMap<ConnId, serve::Served>,
    /// Steps peers registered here since start, by label.
    pub(crate) peer_steps: BTreeMap<LabelId, Vec<(Step, Option<osis_label::ClaimSet>)>>,
    /// Co-readers found on the LAN: their address there and when (raw ms).
    pub(crate) lan: BTreeMap<HostKey, peers::LanRoute>,
    /// The next `publish_reach` writes a fresh lan secret.
    pub(crate) lan_rotate: bool,
    /// Whether `reach.0` placed under a label that no longer qualifies is to be looked for
    /// (`check_reach`: at start, after role, policy and contact changes).
    pub(crate) reach_check: bool,
    /// Served labels, until `label.0`, role or peer steps change.
    pub(crate) served_cache: Option<Arc<BTreeMap<LabelId, serve::ServedLabel>>>,
    pub(crate) charges: serve::Charges,
    /// The engine's actors with secrets of their own when its events were last taken.
    pub(crate) own_keys: BTreeSet<Tid>,
    /// Sizes of blobs served to peers (memory only; pruned at ticks).
    pub(crate) blob_sizes: BTreeMap<osis_base::BlobId, u64>,
    /// Wall time of the last carrier and certificate sweep (memory only; `serve::RECORD_SWEEP_MS`).
    pub(crate) swept: u64,
    pub(crate) peer_cache: peers::PeerCache,
    /// Co-readers this node received entries of a label from (complete passes wait for them
    /// while a connection to them is up, spec/permissions.md §3).
    pub(crate) peer_received: BTreeMap<LabelId, BTreeSet<HostKey>>,
    /// The last remote role commit of each actor applied: its `seq`, and when (raw ms; the peer
    /// part of `complete_pass` waits at most `peer_pass_wait_ms` from it).
    pub(crate) role_change: BTreeMap<Tid, (u64, u64)>,
    /// When this engine was built (raw ms): a role change applied before it came no later,
    /// so the peer wait of an actor with none in `role_change` counts from here.
    pub(crate) started: u64,
    /// When the last remote role commit writing an actor's `secrets.0` (a rotation, the
    /// only change its author registers a step for) applied (raw ms; `step_settled`).
    pub(crate) rotation_at: BTreeMap<Tid, u64>,
    /// `placed` answers by commit, valid while `State::version` (the first field) is unchanged and
    /// no engine change came (in memory).
    pub(crate) placed_cache: (u64, BTreeMap<osis_base::CommitId, bool>),
    /// Per label, the co-readers a complete pass waits for now (`peer_received` narrowed to
    /// those still reading it with a connection up that has it started; set by `handle`).
    pub(crate) pass_peers: BTreeMap<LabelId, BTreeSet<HostKey>>,
    /// A role or roster change since the last step (`holders_changed`).
    pub(crate) holders_moved: bool,
    /// This node's `clients.0^` changed since the last step (`clients_changed`).
    pub(crate) clients_moved: bool,
    /// Commit blobs with linked header lists whose prefix was checked against the resolved
    /// header (spec/commits.md §4).
    pub(crate) prefix_checked: BTreeSet<osis_base::BlobId>,
    /// The memory class's state beside the sync records (`memory`).
    pub(crate) memory: memory::Memory,
    /// Relay-only uploads served sessions made (spec/sync.md §5, as a host admits them).
    pub(crate) relay_gate: osis_proto::RelayGate,
    /// Labels read for receipts only (`read_receipts`; memory only).
    pub(crate) receipts: BTreeMap<LabelId, receipts::Read>,
    /// The host config handed to the driver (`host_step`).
    pub(crate) hosting: host::Hosting,
}

/// A certificate copy waiting for a rotation (`SyncEngine::deferred`): group, commit, aspects,
/// and the owed delivery it carries out (its record stays until the copy is placed, `take_done`).
pub(crate) type Deferred = (Tid, osis_base::CommitId, BTreeSet<usize>, Option<[u8; 32]>);

impl SyncEngine {
    /// Wraps an engine. `clock` is the uncorrected wall clock the engine was built on (Hellos
    /// carry it; the correction goes to the engine).
    pub fn new(mut engine: Engine, clock: Arc<dyn Clock>, rng: Box<dyn CryptoRngCore + Send>, cfg: SyncConfig) -> Result<SyncEngine> {
        // a memory commit marks itself changed like any (`Engine::take_changed`), not by event
        let events = engine.subscribe_durable();
        engine.set_sync_records(&state::Records);
        // keeps the changed commits from now on (`Engine::take_changed`)
        engine.take_changed();
        let mut state = State::load(&mut engine)?;
        engine.core.receipts_only = state.receipts_only.clone();
        // deposits not answered before a restart go again
        let outbox = state.outbox.keys().map(|k| (*k, local::Outgoing::default())).collect();
        let mut rng = rng;
        rng.fill_bytes(&mut state.feed.log_id);
        let started = clock.now_wall_ms().0;
        Ok(SyncEngine {
            engine,
            events,
            clock,
            rng,
            cfg,
            conns: BTreeMap::new(),
            next_conn: 1,
            retry: BTreeMap::new(),
            redialed: BTreeMap::new(),
            redeeming: BTreeSet::new(),
            state,
            seq: 0,
            passes: BTreeMap::new(),
            wake: None,
            last_tick: 0,
            diagnostics: Vec::new(),
            outbox,
            deposit_room: BTreeMap::new(),
            local_inbox: Vec::new(),
            left: Some(deliver::LeftCheck::default()),
            first: BTreeSet::new(),
            tree_wants: BTreeSet::new(),
            body_links: BTreeMap::new(),
            inbox_opened: BTreeMap::new(),
            vetted: None,
            hint_failed: BTreeSet::new(),
            inbox_copied: work::InboxCopied::default(),
            secrets_counted: std::cell::Cell::new(None),
            unsettled_memo: None,
            relink_backoff: BTreeMap::new(),
            relink_pending: BTreeSet::new(),
            relink_at: 0,
            retired_at: BTreeSet::new(),
            deferred: Vec::new(),
            genuine: BTreeMap::new(),
            reread_boxes: true,
            start_look: true,
            redelivered: 0,
            settle_at: BTreeMap::new(),
            local_dirty: true,
            local_last: 0,
            local_any: false,
            local_expiry: BTreeMap::new(),
            local_work: BTreeMap::new(),
            deposit_seen: BTreeMap::new(),
            capped: BTreeSet::new(),
            resealed: BTreeSet::new(),
            repaired: BTreeSet::new(),
            repair_state: BTreeMap::new(),
            links_failed: BTreeSet::new(),
            tied: deliver::TiedWork { all: true, ..Default::default() },
            synced: Synced::default(),
            unsubscribe: BTreeSet::new(),
            served: BTreeMap::new(),
            covered_judged: BTreeSet::new(),
            stats: PassStats::default(),
            touched: work::Touched::default(),
            own_keys: BTreeSet::new(),
            peer_steps: BTreeMap::new(),
            lan: BTreeMap::new(),
            lan_rotate: false,
            reach_check: true,
            served_cache: None,
            charges: serve::Charges::default(),
            blob_sizes: BTreeMap::new(),
            swept: 0,
            peer_cache: peers::PeerCache::default(),
            peer_received: BTreeMap::new(),
            role_change: BTreeMap::new(),
            started,
            rotation_at: BTreeMap::new(),
            placed_cache: (u64::MAX, BTreeMap::new()),
            pass_peers: BTreeMap::new(),
            holders_moved: false,
            clients_moved: false,
            prefix_checked: BTreeSet::new(),
            memory: memory::Memory::default(),
            relay_gate: osis_proto::RelayGate::default(),
            receipts: BTreeMap::new(),
            hosting: host::Hosting::default(),
        })
        .and_then(|mut s| {
            // a forgetting a crash interrupted before its inbox check
            s.forget_inbox()?;
            s.reopen_undropped(None);
            // the keys and ciphertexts of bodies the engine dropped before a crash cut this layer
            // off (its forget runs a step after the dropping transaction, spec/commits.md §5)
            s.forget_dropped(None)?;
            // flows' deliveries a crash cut off before they were carried out
            if let Err(e) = s.take_owed() {
                s.diag(format!("owed deliveries: {e}"));
            }
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

    /// Certificate copies waiting for a rotation or a re-seal (`deferred`).
    pub fn deferred_copies(&self) -> usize {
        self.deferred.len()
    }

    pub fn config(&self) -> &SyncConfig {
        &self.cfg
    }

    /// Tests: knobs a running engine reads at each use (e.g. `retry_ms`).
    pub fn config_mut(&mut self) -> &mut SyncConfig {
        &mut self.cfg
    }

    /// Asks for a pass of `l` at raw ms `t` (`settle_at`).
    pub(crate) fn settle_by(&mut self, t: u64, l: LabelId) {
        self.settle_at.entry(t).or_default().insert(l);
    }

    /// The actor `g`'s keys derive from (`Core::secret_actor`), else `g`.
    pub(crate) fn keys_actor(&self, g: &Tid) -> Tid {
        self.engine.core.secret_actor(g).unwrap_or(*g)
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

    /// Runs the engine's timers now if one is due (`Engine::timers_due`), as a Tick does.
    /// Expiry is a hard bound (spec/crdt.md §4.7) but a Tick comes late (`MIN_WAKE_MS`, a
    /// suspended or offline process), so the API calls this before every call: no call sees a
    /// write at or past its expiry. Its changes go out with the next event.
    pub fn expire_due(&mut self) {
        if !self.engine.timers_due() {
            return;
        }
        self.engine.core.defer_deaths = true;
        let r = self.run_engine_timers();
        let settled = self.engine.defer_deaths(false);
        for e in [r.err(), settled.err()].into_iter().flatten() {
            self.diag(format!("sync: {e}"));
        }
    }

    /// The engine's due expiry and keep-at-most timers, durable and ephemeral, in rounds
    /// (`Engine::tick_round`), a live write's carrier before each (spec/commits.md §5).
    fn run_engine_timers(&mut self) -> Result<()> {
        loop {
            for (c, aspects) in self.engine.due_live_drops()? {
                self.snapshot_first(&aspects, &c)?;
            }
            // what the timers dropped: blobs forgotten, judged again (spec/commits.md §5)
            if !self.engine.tick_round()? {
                break;
            }
        }
        self.engine_events()
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
        let mut ok = self.settled_step(ev, &mut out);
        // what the passes marked (a refetch applied commits, an admin recorded a step) passes now,
        // not at whatever event comes next; a step that failed (a store gone) tries no more
        for _ in 0..PASS_AGAIN {
            if !ok || self.dirty_labels().is_empty() {
                break;
            }
            ok = self.settled_step(Event::Local, &mut out);
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
        if let Err(e) = self.drop_left() {
            self.diag(format!("dropping lost secrets: {e}"));
        }
        self.stop_pushes(&mut out);
        self.host_step(&mut out);
        if let Some(at) = self.next_wake()
            && self.wake != Some(at)
        {
            self.wake = Some(at);
            out.push(Action::Wake { at });
        }
        out
    }

    /// `step` and what it left for the engine to settle; whether all went well.
    fn settled_step(&mut self, ev: Event, out: &mut Vec<Action>) -> bool {
        // one deaths recompute per aspect per step (validity flips, un-merges) (`retention::mark_deaths_due`)
        self.engine.core.defer_deaths = true;
        let r = self.step(ev, out).and_then(|()| self.redeliver());
        // off whatever the step returned: left on, no later transaction would settle
        let settled = self.engine.defer_deaths(false);
        let mut ok = r.is_ok() && settled.is_ok();
        for e in [r.err(), settled.err()].into_iter().flatten() {
            self.diag(format!("sync: {e}"));
        }
        // what the passes' recomputes marked: judged by the next pass
        if self.engine.core.changed.as_ref().is_some_and(|c| !c.is_empty())
            && let Err(e) = self.engine_events()
        {
            ok = false;
            self.diag(format!("sync: {e}"));
        }
        ok
    }

    fn step(&mut self, ev: Event, out: &mut Vec<Action>) -> Result<()> {
        // before the event uses a label (`group_of`), and again after the engine's changes
        self.retire_replaced();
        // what is due goes before any event, not only a Tick: a live body under keep at most 0
        // after replaced is due the moment its kill applies, and its carrier and drop go before
        // the pass that would place it (spec/commits.md §5)
        if matches!(ev, Event::Tick) || self.engine.timers_due() {
            self.run_engine_timers()?;
        }
        match ev {
            Event::Tick => {
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
                    let lan = c.peer.then(|| (c.host, c.address.clone()));
                    self.outputs(conn, o, out)?;
                    if let Some((k, a)) = lan
                        && self.lan_up(k, &a)
                    {
                        self.lan_switched(conn, k, out);
                    }
                }
            }
            Event::Bytes { conn, bytes } if self.served.contains_key(&conn) => self.serve(conn, osis_proto::ServingInput::Bytes(bytes), out)?,
            Event::Down { conn } if self.served.contains_key(&conn) => self.end_served(conn, out),
            Event::Reply { conn, id, reply } => self.serve(conn, osis_proto::ServingInput::Reply { id, reply }, out)?,
            Event::Notify { conn, notes } => self.serve(conn, osis_proto::ServingInput::Notify(notes), out)?,
            Event::WantRoom { conn } => self.serve(conn, osis_proto::ServingInput::WantRoom, out)?,
            Event::End { conn } => {
                if self.served.contains_key(&conn) {
                    self.close_served(conn, out);
                }
            }
            Event::Bytes { conn, bytes } => {
                let now = self.raw_now();
                if let Some(c) = self.conns.get_mut(&conn) {
                    let o = c.session.handle(now, ClientInput::Bytes(bytes));
                    self.outputs(conn, o, out)?;
                }
            }
            Event::Down { conn } => self.lost(conn),
            Event::Sent { conns } => {
                let now = self.raw_now();
                for (conn, n) in conns {
                    if self.served.contains_key(&conn) {
                        self.serve(conn, osis_proto::ServingInput::Taken(n), out)?;
                    } else if let Some(c) = self.conns.get_mut(&conn) {
                        let o = c.session.handle(now, ClientInput::Sent);
                        self.outputs(conn, o, out)?;
                    }
                }
            }
        }
        // links expired or used: a removal of the link key (spec/permissions.md §7)
        self.finalize_links()?;
        // tied edges whose placement is gone (spec/permissions.md §2)
        self.untie_unplaced()?;
        // the step's deaths recomputes before its passes: they mark the bodies whose deaths moved
        self.engine.settle_deaths()?;
        // memory snapshots written here are changes the passes place (`memory_step` first)
        self.memory_step(out)?;
        self.engine_events()?;
        self.retire_replaced();
        if std::mem::take(&mut self.holders_moved) {
            self.holders_changed(out);
            self.reach_check = true;
        }
        if std::mem::take(&mut self.clients_moved) {
            self.clients_changed(out);
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

    /// Whether every host this node syncs `actor`'s labels with, and every co-reader it
    /// received one of them from and has a connection up to, has had a complete pass of it since
    /// the last role commit of the actor applied from elsewhere (`flows::SyncState`;
    /// spec/permissions.md §3 re-seal timing); a label with neither passes once the peer wait is
    /// over (`label_passed`).
    pub fn complete_pass(&self, actor: &Tid) -> bool {
        crate::flows::SyncState::complete_pass(self, actor)
    }

    /// Labels this node syncs: every non-replaced label of a labeled group it holds read
    /// secrets of; an admin also keeps its replaced labels until done with them at every host
    /// (spec/sync.md §2: it places the role-class commits there, the replacement's
    /// `label.0` among them, and deletes the content entries; `retire_at`, `retire_replaced`).
    pub fn labels(&mut self) -> Vec<(Tid, Arc<GroupLabel>)> {
        // the inputs: engine state, retirements, and the time (an admin edge's `until`)
        let now = self.now();
        let key = (self.engine.core.generation, self.state.retired.len(), if self.synced.timed { now } else { 0 });
        if self.synced.key == key {
            #[cfg(debug_assertions)]
            if self.engine.recheck(format!("labels {} {} {}", self.state.version, self.state.retired.len(), self.state.receipts_only.len())) {
                let ids = |v: &[(Tid, Arc<GroupLabel>)]| v.iter().map(|(g, l)| (*g, l.id, l.replaced)).collect::<Vec<_>>();
                let (fresh, _) = self.compute_labels(now);
                assert_eq!(ids(&fresh), ids(&self.synced.labels), "labels() cached");
            }
        } else {
            self.stats.label_reads += 1;
            let (labels, timed) = self.compute_labels(now);
            let actors = labels.iter().map(|(g, l)| (l.id, (self.keys_actor(g), peers::host_keys(&l.hosts).collect()))).collect();
            let ids = labels.iter().map(|(_, l)| l.id).collect();
            let key = (key.0, key.1, if timed { now } else { 0 });
            self.synced = Synced { key, timed, labels, ids, actors };
        }
        self.synced.labels.clone()
    }

    /// `labels`, computed with roles at `now`.
    /// Whether it asked for a role (a replaced label): only then does the time matter.
    fn compute_labels(&mut self, now: u64) -> (Vec<(Tid, Arc<GroupLabel>)>, bool) {
        let ts = osis_base::Ts::make(osis_base::WallMs(now), 0).unwrap_or_default();
        let me = self.engine.tid();
        let (mut out, mut timed) = (Vec::new(), false);
        for g in self.engine.labeled_groups() {
            // held for receipts only: read on demand (`read_receipts`), never synced
            if self.state.receipts_only.contains(&g) || self.engine.epochs(&g).is_none_or(|e| !e.read.holds_any()) {
                continue;
            }
            let labels = self.engine.labels_of(&g);
            let admin = labels.iter().any(|l| l.replaced) && {
                timed = true;
                crate::engine::write::role_of(&self.engine.core, &me, &g, ts) == Some(osis_base::Role::Admin)
            };
            out.extend(labels.into_iter().filter(|l| !l.replaced || admin && !self.state.retired.contains(&l.id)).map(|l| (g, l)));
        }
        (out, timed)
    }

    /// Retires the replaced labels an admin still syncs once `ROLE_KEEP_MS` passed since it
    /// first saw them replaced: a host where the label was lost may never settle a pass.
    fn retire_replaced(&mut self) {
        let now = self.now();
        let replaced: Vec<LabelId> = self.labels().iter().filter(|(_, l)| l.replaced).map(|(_, l)| l.id).collect();
        for l in replaced {
            if self.state.replaced_seen(l, now).saturating_add(osis_base::format::ROLE_KEEP_MS) <= now {
                self.state.retire(l);
            }
        }
    }

    /// Replaces the hosts kept connected besides those the labels name.
    pub fn set_hosts(&mut self, hosts: Vec<Address>) {
        self.cfg.hosts = hosts;
        self.touched.full = true;
    }

    /// Whether co-readers are dialed (`SyncConfig.peers`; off: running peer connections close).
    pub fn set_peers(&mut self, on: bool) -> Vec<Action> {
        self.cfg.peers = on;
        self.touched.full = true;
        self.handle(Event::Local)
    }

    /// The roles of `g`'s secret actor this node may not encrypt under now (`placing`), after
    /// the rotations due first when `rotate` (flows' `ensure_rotated`, spec/permissions.md §3).
    pub(crate) fn uncovered(&mut self, g: &Tid, rotate: bool) -> Result<BTreeSet<osis_base::Role>> {
        let Some(a) = self.engine.core.secret_actor(g) else { return Ok(BTreeSet::new()) };
        if self.engine.core.is_key_actor(&a) {
            return Ok(BTreeSet::new());
        }
        if rotate {
            let (done, still) = self.engine.ensure_rotated(&a)?;
            self.take_done(done)?;
            if still.is_empty() {
                return Ok(still);
            }
        }
        self.placing(&a)
    }

    /// The roles of `a` this node may not encrypt under (`rotation::blocked_roles_of`), a
    /// departure by this node's own self-removal not counted until that commit is placed
    /// (spec/crypto.md §4).
    fn placing(&mut self, a: &Tid) -> Result<BTreeSet<osis_base::Role>> {
        let mut deps = Vec::new();
        for (d, own) in self.engine.run(|tx| crate::rotation::departures_placing(tx, a))? {
            if let Some(c) = own
                && !self.placed(&c)?
            {
                continue;
            }
            deps.push(d);
        }
        let me = self.engine.tid();
        self.engine.run(|tx| crate::rotation::blocked_roles_of(tx, &me, a, &deps))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // spec/sync.md §6: a fetch or deposit in flight on a connection that ended (its session
    // closed it, say on a request timeout, or the transport went down) is asked again on the
    // next connection; the ended one is never answered.
    #[test]
    fn closed_session_forgets_its_fetches_spec_sync_6() {
        for down in [false, true] {
            let lp = crate::local_peer::LocalPeer::new(1, 964, osis_base::WallMs(1_700_000_000_000)).unwrap();
            let p = lp.peers.into_iter().next().unwrap();
            let host = Address { url: "quic://host:1".into(), key: [7; 32] };
            let cfg = SyncConfig { hosts: vec![host.clone()], ..SyncConfig::default() };
            let mut s = SyncEngine::new(p.engine, p.clock, Box::new(osis_crypto::SeededRng::from_u64(965)), cfg).unwrap();
            let conn = s.handle(Event::Tick).into_iter().find_map(|a| if let Action::Dial { conn, .. } = a { Some(conn) } else { None }).unwrap();
            let b = osis_base::BlobId([1; 32]);
            s.conns.get_mut(&conn).unwrap().req.fetching.insert(b);
            let d = osis_crypto::SigningSecret::from_seed(&osis_crypto::Secret32::from_bytes([5; 32]));
            s.queue_deposit(LabelId([1; 16]), std::slice::from_ref(&host), &d, vec![9; 40], [3; osis_crypto::WRAP_LEN], None);
            for o in s.outbox.values_mut() {
                o.sent = Some(conn);
            }
            if down {
                s.handle(Event::Down { conn });
            } else {
                s.outputs(conn, vec![ClientOutput::Close], &mut Vec::new()).unwrap();
            }
            assert!(!s.fetching(&b));
            assert!(s.outbox.values().all(|o| o.sent.is_none()), "the deposit goes again");
            assert_eq!(s.deliveries_pending(), 1);
        }
    }

    // spec/sync.md §6: a blob a connection's host did not deliver is not fetched there again
    // until that host announces it (it holds it now).
    #[test]
    fn undelivered_blob_fetched_again_once_announced_spec_sync_6() {
        let lp = crate::local_peer::LocalPeer::new(1, 968, osis_base::WallMs(1_700_000_000_000)).unwrap();
        let p = lp.peers.into_iter().next().unwrap();
        let host = Address { url: "quic://host:1".into(), key: [7; 32] };
        let cfg = SyncConfig { hosts: vec![host], ..SyncConfig::default() };
        let mut s = SyncEngine::new(p.engine, p.clock, Box::new(osis_crypto::SeededRng::from_u64(969)), cfg).unwrap();
        let conn = s.handle(Event::Tick).into_iter().find_map(|a| if let Action::Dial { conn, .. } = a { Some(conn) } else { None }).unwrap();
        let (l, b) = (LabelId([1; 16]), osis_base::BlobId([1; 32]));
        s.conns.get_mut(&conn).unwrap().req.missing.insert(b);
        s.fetch_on(conn, l, [b], &mut Vec::new()).unwrap();
        assert!(!s.fetching(&b), "not asked again");
        let added = osis_proto::Event::Added { blob_id: b, blob: None, wrap: [3; osis_crypto::WRAP_LEN], stamp: None };
        s.log_events(Some(conn), l, vec![added], None, &mut Vec::new()).unwrap();
        s.fetch_on(conn, l, [b], &mut Vec::new()).unwrap();
        assert!(s.fetching(&b), "asked once announced");
        // likewise when a reconciliation finds the host holding it
        let b2 = osis_base::BlobId([2; 32]);
        s.conns.get_mut(&conn).unwrap().req.missing.insert(b2);
        s.reconciled(conn, l, vec![b2], Vec::new(), &mut Vec::new()).unwrap();
        assert!(s.fetching(&b2), "asked once reconciled");
    }

    // spec/sync.md §6: a connection ending before the entries a reconciliation after a start
    // found missing arrived reconciles that label again on the next: no cursor or entry here
    // names those ephemeral entries (`ephemeral::random_window_inflight_large` seed 100013: a
    // twice-restarted author never got its earlier sessions' commits back). A refused fetch
    // reconciles again too; answered first, it stays reconciled.
    #[test]
    fn reconcile_fetches_lost_reconcile_again_spec_sync_6() {
        for case in ["down", "answered", "refused"] {
            let lp = crate::local_peer::LocalPeer::new(1, 970, osis_base::WallMs(1_700_000_000_000)).unwrap();
            let p = lp.peers.into_iter().next().unwrap();
            let host = Address { url: "quic://host:1".into(), key: [7; 32] };
            let cfg = SyncConfig { hosts: vec![host], ..SyncConfig::default() };
            let mut s = SyncEngine::new(p.engine, p.clock, Box::new(osis_crypto::SeededRng::from_u64(971)), cfg).unwrap();
            let conn = s.handle(Event::Tick).into_iter().find_map(|a| if let Action::Dial { conn, .. } = a { Some(conn) } else { None }).unwrap();
            let key = s.conns[&conn].host;
            let (l, b) = (LabelId([1; 16]), osis_base::BlobId([1; 32]));
            s.memory.reconciling.insert((conn, l));
            s.reconciled(conn, l, vec![b], Vec::new(), &mut Vec::new()).unwrap();
            assert!(s.fetching(&b) && s.memory.reconciled.contains(&(key, l)));
            match case {
                "answered" => s.session_event(conn, ClientEvent::Fetched { label: l, items: vec![osis_proto::msg::Fetched { blob_id: b, entry: None }] }, &mut Vec::new()).unwrap(),
                "refused" => s.session_event(conn, ClientEvent::Refused { label: Some(l), kind: osis_proto::Request::Fetch, code: osis_proto::Code::RATE_LIMITED, fetch: vec![b] }, &mut Vec::new()).unwrap(),
                _ => {}
            }
            let left = s.memory.reconcile_fetches.contains_key(&(conn, l));
            if case != "refused" {
                s.handle(Event::Down { conn });
            }
            assert_eq!(s.memory.reconciled.contains(&(key, l)), case == "answered", "{case}");
            assert!(case == "down" || !left, "{case}: answered or refused fetches are not tracked");
        }
    }

    // spec/sync.md §5: a deposit is kept until each of its hosts answers it, also across a
    // restart; one blob queued under two labels at one host is two deposits.
    #[test]
    fn one_blob_queued_under_two_labels_spec_sync_5() {
        let lp = crate::local_peer::LocalPeer::new(1, 966, osis_base::WallMs(1_700_000_000_000)).unwrap();
        let p = lp.peers.into_iter().next().unwrap();
        let host = Address { url: "quic://host:1".into(), key: [7; 32] };
        let mut s = SyncEngine::new(p.engine, p.clock, Box::new(osis_crypto::SeededRng::from_u64(967)), SyncConfig::default()).unwrap();
        let d = osis_crypto::SigningSecret::from_seed(&osis_crypto::Secret32::from_bytes([5; 32]));
        let delivery = Some((osis_base::Tid::from_bytes([4; 15]), osis_base::CommitId([6; 32])));
        for (l, x) in [(LabelId([1; 16]), None), (LabelId([2; 16]), delivery)] {
            s.queue_deposit(l, std::slice::from_ref(&host), &d, vec![9; 40], [3; osis_crypto::WRAP_LEN], x);
        }
        assert_eq!(s.deliveries_pending(), 2);
        s.state.flush(&mut s.engine).unwrap();
        let back = State::load(&mut s.engine).unwrap();
        assert_eq!(back.outbox.len(), 2, "both survive a restart");
        let got: Vec<_> = back.outbox.values().map(|o| (o.label, o.delivery)).collect();
        assert_eq!(got, vec![(LabelId([1; 16]), None), (LabelId([2; 16]), delivery)], "with the delivery each serves");
    }
}
