//! The sans-I/O sync engine (notes/node-sync.md; notes/architecture.md §2): one synchronous
//! state machine per node, `SyncEngine::handle(Event) -> Vec<Action>`, holding the engine, the
//! upper layer of every session of the node's hub (dialed and served alike), the labeling
//! decisions and the convergence loop (spec/sync.md §5-§9). Two drivers move its bytes and timers: the tokio driver
//! (`driver`, feature `driver`) and the simulator's step driver. No sync logic lives in a driver.
//!
//! Per host and label: open (sync key of the head, else walk by stale key or claim key),
//! verify the head, download (cursor sync, reconciliation fallback), apply role commits
//! first, then the pass: re-registration when an admin holds newer epochs (the actor's
//! role commits the host lacks first, then the step, then the rest), logging of
//! must-hold bodies, relays, certificates, deletions of must-not-hold bodies. Stranded and
//! suspect reports go over connections and inboxes (`reports`).

mod bundle;
mod conn;
mod deliver;
mod fill;
mod host;
#[cfg(feature = "driver")]
pub mod driver;
mod inbound;
mod io;
mod lifetimes;
mod local;
mod marks;
mod memory;
mod open;
mod pass;
mod reports;
pub mod proofs;
pub mod records;
mod shared;
mod stream;
pub mod credentials;
pub mod peers;
mod handoff;
mod serve;
pub(crate) mod state;
mod status;
mod testing;
mod timers;
mod unread;
mod work;

use crate::engine::Engine;
use crate::error::Result;
use crate::events::{Diagnostic, DiagnosticKind, Origin};
use crate::labeling::{GroupLabel, HeadKeys};
use osis_base::{Ak, LabelId, Tid};
use osis_label::{Address, Step};
use osis_proto::Code;
use state::{HostKey, State};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::mpsc::Receiver;

pub(crate) use conn::{Conn, LConn, Phase, in_flight};
pub use host::{host_policy, host_policy_known, hub_store, hub_store_on};
pub use osis_host::HostPolicy;
pub use io::{Action, ConnId, Event, LabelStatus, MAX_CONNS_PER_CLIENT, PassStats, SyncConfig, Tier};
pub use local::drop_all_covered;
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

/// The labels this node syncs (`SyncEngine::labels`): a memo's answer (`SyncEngine::synced_of`),
/// and the one last asked for (`SyncEngine::synced`).
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Synced {
    labels: Vec<(Tid, Arc<GroupLabel>)>,
    /// The IDs of `labels`.
    pub(crate) ids: BTreeSet<LabelId>,
    /// Per label, the actor its keys derive from and its hosts' keys (`complete_pass`,
    /// `peers::host_keys`).
    pub actors: BTreeMap<LabelId, (Tid, Vec<HostKey>)>,
    /// `actors` by actor: the labels of each.
    pub by_actor: BTreeMap<Tid, BTreeSet<LabelId>>,
}

/// An opened inbox payload kept while it awaits: the commit's plaintext, its chain, its records.
pub(crate) type InboxPlain = (Vec<u8>, Vec<osis_base::Value>, Vec<osis_base::CreationRecord>);

/// The sync engine of one node.
pub struct SyncEngine {
    pub(crate) engine: Engine,
    /// Whether `forget_forgettable` has looked at every held commit since this open.
    pub(crate) forget_seeded: bool,
    /// `sweep_pending` has looked at every pending commit since the start (a crash may have come
    /// between an entry leaving and its sweep).
    pub(crate) pending_seeded: bool,
    /// Labels whose `unvouched_cap` refusal was reported (`InputCapped`), until a batch there
    /// fits again.
    pub(crate) unvouched_reported: BTreeSet<LabelId>,
    events: Receiver<crate::Event>,
    pub(crate) rng: Box<dyn osis_crypto::NodeRng>,
    pub(crate) cfg: SyncConfig,
    pub(crate) conns: BTreeMap<ConnId, Conn>,
    next_conn: ConnId,
    /// Hosts not connected: when to dial again.
    retry: BTreeMap<HostKey, (Address, u64)>,
    /// Co-readers redialed at once after an up connection ended, and when (wall ms): at most
    /// once per `peer_retry_ms` each.
    redialed: BTreeMap<HostKey, u64>,
    /// Co-readers whose dialed connection closed as the duplicate of one they dialed here: not
    /// dialed while that session lasts (`bind_record`).
    pub(crate) stand_in: BTreeMap<HostKey, ConnId>,
    /// Followed links (by K) whose redemption is under way: their sharer nodes are redialed after
    /// `retry_ms`, not `peer_retry_ms` (`lost`). Memory only: no redemption outlives the process.
    redeeming: BTreeSet<Tid>,
    /// The role generation and key actors `reprove` last looked at.
    provers_mark: Option<(u64, Vec<Tid>)>,
    /// `own_key`'s cache: the dialable secret's key.
    own_key: Option<[u8; 32]>,
    pub(crate) state: State,
    /// Event counter: pass completions and remote role commits are ordered by it.
    pub(crate) seq: u64,
    /// Per (host, label), the last pass end: its `seq` and when (wall ms).
    /// Kept across disconnects on purpose: readers ask "a pass ended after X", never "on the live
    /// connection". `complete_pass` counts only passes after the actor's last remote role
    /// commit (`role_change`), and finalizing an expired link only those ended after `until`;
    /// what reached the host after a pass end is the same race online, and a duplicate re-seal
    /// costs a box. Clearing would block re-seal and link finalization while one host is down.
    pub(crate) passes: BTreeMap<(HostKey, LabelId), (u64, u64)>,
    wake: Option<u64>,
    /// Per label, when it last had every source caught up (wall ms; `label_status`, memory only).
    last_synced: BTreeMap<LabelId, u64>,
    /// When the last Tick was handled (wall ms).
    last_tick: u64,
    /// Recent diagnostics (also sent as engine events).
    diagnostics: Vec<String>,
    /// The writes of the engine's store and the hub's as last seen, whether a failed one waits
    /// for `restart_in_place`, and the commits counted when it last ran (`handle`).
    store_writes: [osis_store::Writes; 2],
    restart_due: bool,
    restarted_at: Option<[u64; 2]>,
    /// Where each queued deposit (`State::outbox`: inbox blobs, a non-writer's own writes)
    /// stands: waiting for its host, or sent and not answered yet.
    pub(crate) outbox: BTreeMap<(HostKey, LabelId, osis_base::BlobId), local::Outgoing>,
    /// Deposits for a label this node syncs with nobody: logged here, as a peer's deposit would
    /// be (`send_outbox`).
    pub(crate) local_inbox: Vec<(LabelId, Vec<u8>, [u8; osis_crypto::WRAP_LEN])>,
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
    /// Holders of recorded inbox deliveries whose `keys.0` changed since `send_inbox` last
    /// looked (every one at a start): a delivery under a label no longer their inbox is due.
    pub(crate) inbox_moved: BTreeSet<osis_base::Tid>,
    /// `secrets_count` at this engine generation (both).
    pub(crate) secrets_counted: std::cell::Cell<Option<((u64, u64), usize)>>,
    /// `secrets_shape`'s count of reading-only secrets, per engine state.
    pub(crate) reading_counted: std::cell::Cell<Option<((u64, u64), usize)>>,
    /// `pass::pending_sets` at this engine generation (both).
    pub(crate) unsettled_memo: Option<((u64, u64), pass::Unsettled, pass::Unsettled)>,
    /// Re-encrypting deleted chunks (`Engine::relink`) per aspect: when allowed next, and the
    /// interval after that (doubling, `RELINK_BACKOFF_MS` to `RELINK_BACKOFF_MAX_MS`).
    pub(crate) relink_backoff: BTreeMap<(Tid, osis_base::Ak), (u64, u64)>,
    /// Deleted chunks an aspect's back-off holds back, by the group whose label lost them, and
    /// when to try them again (memory only).
    pub(crate) relink_pending: BTreeMap<Tid, BTreeSet<osis_base::BlobId>>,
    /// Entries reopened when what their commit awaited came (`reopen_awaiting`): opened where
    /// their bytes are here, else asked again of a peer whose shared set has their label
    /// (`stream_settle_all`).
    pub(crate) reask: BTreeSet<(LabelId, osis_base::BlobId)>,
    pub(crate) relink_at: u64,
    /// Hosts where a replaced label is done with (`retire_at`).
    pub(crate) retired_at: BTreeSet<(HostKey, LabelId)>,
    /// Certificate copies waiting for a rotation.
    pub(crate) deferred: Vec<Deferred>,
    /// Commit blobs whose every delta was checked against its header hash (`true`) or found
    /// forged (`false`; the entry is `Bad`): only checked blobs stand in for this node's own
    /// entries or justify deleting another entry (`SyncEngine::genuine`).
    pub(crate) genuine: BTreeMap<osis_base::BlobId, bool>,
    /// New secrets: the boxes of pending commits' other copies are read again (`redeliver`).
    pub(crate) reread_boxes: bool,
    /// The first `redeliver` of this start looks for what a crash lost (`name_after_crash`).
    pub(crate) start_look: bool,
    /// Entries `redeliver` ingested again since the start.
    #[doc(hidden)]
    pub redelivered: u64,
    /// `secrets_shape` the awaiting entries were last reopened at (`redeliver`).
    pub(crate) awaits_secrets: (usize, usize),
    /// Inbox blobs to ingest again at the next step (`wake_awaiting`).
    pub(crate) retry_inbox: BTreeSet<(LabelId, osis_base::BlobId)>,
    /// Opened inbox blobs with a commit (the carried one, or a chain certificate) that cannot be
    /// judged yet, and what they await. In memory: a
    /// restart looks at every inbox blob once.
    pub(crate) inbox_awaits: BTreeMap<(LabelId, osis_base::BlobId), BTreeSet<Tid>>,
    /// The opened bytes of the blobs `inbox_awaits` holds (the commit, its chain and records).
    pub(crate) inbox_plain: BTreeMap<(LabelId, osis_base::BlobId), InboxPlain>,
    /// `state.version` the sweep of reading-only sources last ran at (`sweep_unchecked`).
    pub(crate) unchecked_swept: Option<u64>,
    /// When another node's certificate, body or deposit left to its author or a co-writer
    /// (`relay_delay`) is due again (wall ms).
    pub(crate) settle_at: BTreeMap<u64, BTreeSet<LabelId>>,
    /// When this node's passes first saw each label (wall ms; in memory: a start sees every
    /// label anew): another node's card copies wait from then (`copy_due`).
    pub(crate) held_since: BTreeMap<LabelId, u64>,
    /// Every label wants a pass (`passes`), or these do; this node wrote (a label filling at a
    /// source passes too); labels filling at a source whose fill wants a pass (its first batch
    /// done, its end, a resync). When the last passes ran (raw ms), and whether there were any
    /// labels (the periodic pass's wake).
    pub(crate) pass_due: bool,
    pub(crate) due_labels: BTreeSet<osis_base::LabelId>,
    pub(crate) own_wrote: bool,
    pub(crate) fill_due: BTreeSet<osis_base::LabelId>,
    pub(crate) passed_at: u64,
    pub(crate) passing: bool,
    /// The work sets of the passes, by label.
    pub(crate) work: BTreeMap<osis_base::LabelId, work::Work>,
    /// When this node first saw each entry deposited at a host (wall ms; the promotion wait).
    pub(crate) deposit_seen: BTreeMap<(HostKey, LabelId, osis_base::BlobId), u64>,
    /// Stranded reports sent (`reports::stranded`): (label, sync key of the step reached,
    /// recipient). In memory: after a restart each goes once more.
    pub(crate) stranded_sent: BTreeSet<(LabelId, [u8; 32], reports::To)>,
    /// Labels this node found itself stranded on (tests).
    pub(crate) stranded_on: BTreeSet<LabelId>,
    /// Holders reported stranded, by the actor to re-seal them on, until its labels' complete
    /// pass (`reseal`).
    pub(crate) stranded_asks: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Per (actor, holder) re-sealed on a report, the actor's current read epochs then: the
    /// same epochs are not boxed to it again. In memory.
    pub(crate) resealed: BTreeMap<(Tid, Tid), Vec<osis_keys::Epoch>>,
    /// Suspect lists last sent per (connection, label) (`reports::send_suspects`), the engine
    /// generation they were taken at, and whether a label joined a shared set since.
    pub(crate) suspects_sent: BTreeMap<(ConnId, LabelId), Vec<osis_proto::msg::SuspectEntry>>,
    pub(crate) suspects_gen: Option<u64>,
    pub(crate) suspects_due: bool,
    /// Per (node reporting, thing, aspect) a repair snapshotted, this node's state digest just after:
    /// the same state does not snapshot again for that node however often its report differs. In
    /// memory: a restart may write one more.
    pub(crate) repair_state: BTreeMap<(Tid, Tid, osis_base::Ak), [u8; 16]>,
    /// Links whose finalization failed in this run (`finalize_links`): not tried again.
    pub(crate) links_failed: BTreeSet<Tid>,
    /// This account's joined links to check for an end (`leave_ended_links`): the things whose
    /// roles or roster changed since the last check (`None`: all), and the links whose leave
    /// failed in this run (not tried again).
    pub(crate) joined_touched: Option<BTreeSet<Tid>>,
    pub(crate) joined_failed: BTreeSet<Tid>,
    /// Tied edges to remove (`untie_unplaced`): what changed since they were last derived
    /// (groups whose `group.0` changed, things whose `roles.0` or roster changed, or all), the
    /// (target, group) pairs whose placement is gone, and those whose removal failed in this run.
    pub(crate) tied: deliver::TiedWork,
    /// Commits placed before any other entry (`Delivery::First`).
    pub(crate) first: BTreeSet<osis_base::CommitId>,
    /// Labels whose role commits are placed without their relay wait at the next pass: a source
    /// deleted a body this node must hold (`encrypt_again`).
    pub(crate) relay_now: BTreeSet<LabelId>,
    /// Lost access may wait for this node's own self-removal to be placed (`drop_left`): set
    /// at start, by a self-removal and when the trigger leaves a loss to it; cleared once nothing
    /// lost waits or may come to.
    pub(crate) left: Option<deliver::LeftCheck>,
    /// The labels heard out at the last lifetime judgment (`judge_lifetimes`); `None` before the
    /// first: a label heard out since judges the held things again.
    pub(crate) lifetimes_heard: Option<BTreeSet<osis_base::LabelId>>,
    /// The synced labels as last computed (`labels()`).
    /// The labels synced as `labels` last answered: what reads between two asks go by.
    pub(crate) synced: Arc<Synced>,
    /// `labels` (`engine::memo`): built again when what it read of the engine, of the retired
    /// and handed-off sets or, where it judged an admin role, of the time (`Core::time`) changed.
    synced_of: crate::engine::memo::Memo<(), Arc<Synced>>,
    /// (snapshot, body, aspect) judgments settled with the body kept (spec/sync.md §7); a pair
    /// goes once either body is dropped.
    pub(crate) covered_judged: BTreeSet<(osis_base::CommitId, osis_base::CommitId, Tid, osis_base::Ak)>,
    /// What passes did so far (`pass_stats`).
    pub(crate) stats: PassStats,
    /// Records and their connections (`records`).
    pub(crate) records: records::Records,
    /// Each connection's node log stream, both sides (`stream`).
    pub(crate) streams: BTreeMap<ConnId, stream::ConnStream>,
    /// `changed_at` must be stamped again (`stamp_changes`); a start checks everything once.
    pub(crate) changed_due: bool,
    /// `Core::role_generation` at the last `changed_at` pass.
    pub(crate) changed_gen: u64,
    /// Sync IDs whose `changed_at` moved since the last `shared_changed`.
    pub(crate) changed_moved: BTreeSet<LabelId>,
    /// Engine changes not yet spread to the labels' work sets (`spread_touches`).
    pub(crate) touched: work::Touched,
    /// The connections this node's hub serves (spec/sync.md §5, §10).
    pub(crate) served: BTreeMap<ConnId, serve::Served>,
    /// The hub's connection IDs of the served connections and the dialed ones up.
    pub(crate) hub_conns: BTreeMap<osis_host::ConnId, ConnId>,
    /// Push room per connection, dialed or served (`serve::Room`).
    pub(crate) rooms: BTreeMap<ConnId, serve::Room>,
    /// Registrations a host refused for now in a row, per (host, label), whatever connection
    /// (the back-off doubles per refusal), with the last refusal's code (status shows a label not
    /// admitted, code 14). Bounded by labels times hosts.
    pub(crate) refusals: BTreeMap<(HostKey, LabelId), (u32, Code)>,
    /// Co-readers found on the LAN: their address there and when (wall ms).
    pub(crate) lan: BTreeMap<HostKey, peers::LanRoute>,
    /// The next `publish_reach` writes a fresh lan secret.
    pub(crate) lan_rotate: bool,
    /// The account `reach.0` was last checked against (`republish_reach`).
    pub(crate) reach_account: Option<osis_base::Tid>,
    /// Served labels, until `label.0` or role change.
    pub(crate) served_cache: Option<Arc<BTreeMap<LabelId, serve::ServedLabel>>>,
    /// The sync IDs this node keeps and does not read (`unread`).
    pub(crate) unread: unread::Unread,
    pub(crate) charges: serve::Charges,
    /// The engine's actors with secrets of their own when its events were last taken.
    pub(crate) own_keys: BTreeSet<Tid>,
    /// Sizes of blobs served to peers (memory only; pruned at ticks).
    pub(crate) blob_sizes: BTreeMap<osis_base::BlobId, u64>,
    /// Wall time of the last carrier and certificate sweep (memory only; `serve::RECORD_SWEEP_MS`).
    pub(crate) swept: u64,
    pub(crate) peer_cache: peers::PeerCache,
    /// Per label, the sources (`Proven::source`) this node received its entries from: complete
    /// passes wait for each that still reads it, connected or not (spec/permissions.md §3).
    /// Kept while the source is known here (`prune_pass_sources`), so bounded by own nodes and
    /// known accounts, never by connections or records.
    pub(crate) peer_received: BTreeMap<LabelId, BTreeSet<Tid>>,
    /// Per (source, label), the last pass end at that source, as `passes` for hosts; pruned
    /// with `peer_received`.
    pub(crate) peer_passes: BTreeMap<(Tid, LabelId), (u64, u64)>,
    /// The role generation `prune_pass_sources` last ran at.
    pub(crate) sources_gen: u64,
    /// What this node holds moved: the shared sets re-judge and send additions (`shared_changed`).
    pub(crate) shared_dirty: bool,
    /// The last remote role commit of each actor applied: its `seq`, and when (wall ms; the peer
    /// part of `complete_pass` waits at most `peer_pass_wait_ms` from it).
    pub(crate) role_change: BTreeMap<Tid, (u64, u64)>,
    /// Actors with a remote role commit applied this step: each host of their labels is asked
    /// for a pass end (`ask_pass_ends`).
    pub(crate) pass_wanted: BTreeSet<Tid>,
    /// When this engine was built (wall ms): a role change applied before it came no later,
    /// so the peer wait of an actor with none in `role_change` counts from here.
    pub(crate) started: u64,
    /// When the last remote role commit writing an actor's `secrets.0` (a rotation, the
    /// only change its author registers a step for) applied (wall ms; `step_settled`).
    pub(crate) rotation_at: BTreeMap<Tid, u64>,
    /// `placed` answers by commit, valid while `State::version` (the first field) is unchanged and
    /// no engine change came (in memory).
    pub(crate) placed_cache: (u64, BTreeMap<osis_base::CommitId, bool>),
    /// Own commits `placed` last found not placed: the co-reader reports covering them are
    /// recorded (`note_applied`). In memory: the first ask after a start notes again what the
    /// connections reported.
    pub(crate) placed_waiting: BTreeSet<osis_base::CommitId>,
    /// Per secret actor, the roles `ensure_rotated` left blocked when it had nothing to do
    /// (`rotations`, `engine::memo`).
    rotated: crate::engine::memo::Memo<Tid, BTreeSet<osis_base::Role>>,
    /// This node's `clients^.0` changed since the last step (`clients_changed`).
    pub(crate) clients_moved: bool,
    /// Commit blobs with linked header lists whose prefix was checked against the resolved
    /// header (spec/commits.md §4).
    pub(crate) prefix_checked: BTreeSet<osis_base::BlobId>,
    /// The memory class's state beside the sync records (`memory`).
    pub(crate) memory: memory::Memory,
    /// The host config handed to the driver (`host_step`).
    pub(crate) hosting: host::Hosting,
    /// The node's one store beside the engine (notes/serving.md, Hosting in the node): the
    /// hub's, the engine's ciphertext store (`Engine::blobs`).
    pub(crate) hub_store: std::sync::Arc<std::sync::Mutex<osis_host::HostStore>>,
}

/// A certificate copy waiting for a rotation (`SyncEngine::deferred`): group, commit, aspects,
/// and the owed delivery it carries out (its record stays until the copy is placed, `take_done`).
pub(crate) type Deferred = (Tid, osis_base::CommitId, BTreeSet<usize>, Option<[u8; 32]>);

impl SyncEngine {
    /// Wraps an engine; its wall clock is the node's (spec/sync.md §6).
    pub fn new(mut engine: Engine, rng: Box<dyn osis_crypto::NodeRng>, cfg: SyncConfig) -> Result<SyncEngine> {
        // a memory commit marks itself changed like any (`Engine::take_changed`), not by event
        let events = engine.subscribe_durable();
        engine.set_sync_records(&state::Records);
        // the engine's ciphertext store is the hub's: the node's one store
        let any: std::sync::Arc<dyn std::any::Any + Send + Sync> = engine.blobs();
        let hub_store = any.downcast::<std::sync::Mutex<osis_host::HostStore>>().map_err(|_| osis_engine::Error::Misuse("the engine's ciphertext store is not a hub store"))?;
        // every other field is set by `start`
        let store_writes = [engine.store_writes(), hub_store.lock().unwrap_or_else(std::sync::PoisonError::into_inner).store_writes()];
        let mut s = SyncEngine {
            hub_store,
            forget_seeded: Default::default(),
            pending_seeded: Default::default(),
            unvouched_reported: Default::default(),
            engine,
            events,
            rng,
            cfg,
            conns: Default::default(),
            next_conn: 1,
            retry: Default::default(),
            redialed: Default::default(),
            stand_in: Default::default(),
            redeeming: Default::default(),
            provers_mark: Default::default(),
            own_key: Default::default(),
            state: Default::default(),
            seq: Default::default(),
            passes: Default::default(),
            wake: Default::default(),
            last_tick: Default::default(),
            diagnostics: Vec::new(),
            store_writes,
            restart_due: false,
            restarted_at: None,
            outbox: Default::default(),
            local_inbox: Default::default(),
            left: Default::default(),
            lifetimes_heard: Default::default(),
            first: Default::default(),
            relay_now: Default::default(),
            body_links: Default::default(),
            inbox_opened: Default::default(),
            vetted: Default::default(),
            hint_failed: Default::default(),
            inbox_copied: Default::default(),
            inbox_moved: Default::default(),
            secrets_counted: Default::default(),
            reading_counted: Default::default(),
            unsettled_memo: Default::default(),
            relink_backoff: Default::default(),
            relink_pending: Default::default(),
            reask: Default::default(),
            relink_at: Default::default(),
            retired_at: Default::default(),
            deferred: Default::default(),
            genuine: Default::default(),
            reread_boxes: Default::default(),
            start_look: Default::default(),
            redelivered: Default::default(),
            awaits_secrets: Default::default(),
            retry_inbox: Default::default(),
            inbox_awaits: Default::default(),
            inbox_plain: Default::default(),
            unchecked_swept: Default::default(),
            settle_at: Default::default(),
            held_since: Default::default(),
            pass_due: Default::default(),
            due_labels: Default::default(),
            own_wrote: Default::default(),
            fill_due: Default::default(),
            passed_at: Default::default(),
            passing: Default::default(),
            work: Default::default(),
            deposit_seen: Default::default(),
            stranded_sent: Default::default(),
            stranded_on: Default::default(),
            stranded_asks: Default::default(),
            resealed: Default::default(),
            suspects_sent: Default::default(),
            suspects_gen: Default::default(),
            suspects_due: Default::default(),
            repair_state: Default::default(),
            links_failed: Default::default(),
            joined_touched: Default::default(),
            joined_failed: Default::default(),
            tied: Default::default(),
            synced: Default::default(),
            synced_of: crate::engine::memo::Memo::new("labels synced"),
            served: Default::default(),
            hub_conns: Default::default(),
            rooms: Default::default(),
            refusals: Default::default(),
            covered_judged: Default::default(),
            stats: Default::default(),
            records: Default::default(),
            streams: Default::default(),
            changed_due: Default::default(),
            changed_gen: Default::default(),
            touched: Default::default(),
            own_keys: Default::default(),
            lan: Default::default(),
            lan_rotate: Default::default(),
            reach_account: Default::default(),
            served_cache: Default::default(),
            unread: Default::default(),
            charges: Default::default(),
            blob_sizes: Default::default(),
            swept: Default::default(),
            peer_cache: Default::default(),
            peer_received: Default::default(),
            peer_passes: Default::default(),
            sources_gen: Default::default(),
            shared_dirty: Default::default(),
            changed_moved: Default::default(),
            role_change: Default::default(),
            pass_wanted: Default::default(),
            started: Default::default(),
            rotation_at: Default::default(),
            placed_cache: Default::default(),
            placed_waiting: Default::default(),
            rotated: crate::engine::memo::Memo::new("ensure rotated"),
            last_synced: Default::default(),
            clients_moved: Default::default(),
            prefix_checked: Default::default(),
            memory: Default::default(),
            hosting: host::Hosting::default(),
        };
        s.start()?;
        Ok(s)
    }

    /// What a start of node sync holds, read from the store: every field but the engine, its
    /// event subscription, the generator, the config, the hub's store, the host config, the
    /// connection IDs (never repeated), the diagnostics not yet taken and the store writes seen.
    /// Run by `new`, and by `restart_in_place` after a store write failed.
    fn start(&mut self) -> Result<()> {
        // keeps the changed commits from now on (`Engine::take_changed`)
        self.engine.take_changed();
        let loaded = State::load(&mut self.engine)?;
        // deposits not answered before a restart go again
        let outbox_ = loaded.outbox.keys().map(|k| (*k, local::Outgoing::default())).collect();
        let inbox_moved_ = loaded.sent_inbox.keys().map(|k| k.0).collect();
        let started_ = self.engine.now().0;
        let SyncEngine {
            engine: _, events: _, rng: _, cfg: _, hub_store: _, next_conn: _, diagnostics: _, store_writes: _, restart_due: _, restarted_at: _, hosting: _,
            forget_seeded, pending_seeded, unvouched_reported, conns, retry, redialed, stand_in, redeeming, provers_mark, own_key, state, seq, passes, wake, last_tick, outbox, local_inbox, left, lifetimes_heard, first, relay_now, body_links, inbox_opened, vetted, hint_failed, inbox_copied, inbox_moved, secrets_counted, reading_counted, unsettled_memo, relink_backoff, relink_pending, reask, relink_at, retired_at, deferred, genuine, reread_boxes, start_look, redelivered, awaits_secrets, retry_inbox, inbox_awaits, inbox_plain, unchecked_swept, settle_at, held_since, pass_due, due_labels, own_wrote, fill_due, passed_at, passing, work, deposit_seen, stranded_sent, stranded_on, stranded_asks, resealed, suspects_sent, suspects_gen, suspects_due, repair_state, links_failed, joined_touched, joined_failed, tied, synced, synced_of, served, hub_conns, refusals, covered_judged, stats, records, streams, changed_due, changed_gen, touched, own_keys, lan, lan_rotate, reach_account, served_cache, unread, charges, blob_sizes, swept, peer_cache, peer_received, peer_passes, sources_gen, shared_dirty, changed_moved, role_change, pass_wanted, started, rotation_at, placed_cache, placed_waiting, rotated, last_synced, clients_moved, prefix_checked, memory,
        } = self;
        *forget_seeded = false;
        *pending_seeded = false;
        *unvouched_reported = BTreeSet::new();
        *conns = BTreeMap::new();
        *retry = BTreeMap::new();
        *redialed = BTreeMap::new();
        *stand_in = BTreeMap::new();
        *redeeming = BTreeSet::new();
        *provers_mark = None;
        *own_key = None;
        *state = loaded;
        *seq = 0;
        *passes = BTreeMap::new();
        *wake = None;
        *last_tick = 0;
        *outbox = outbox_;
        *local_inbox = Vec::new();
        *left = Some(deliver::LeftCheck::default());
        *lifetimes_heard = None;
        *first = BTreeSet::new();
        *relay_now = BTreeSet::new();
        *body_links = BTreeMap::new();
        *inbox_opened = BTreeMap::new();
        *vetted = None;
        *hint_failed = BTreeSet::new();
        *inbox_copied = work::InboxCopied::default();
        *inbox_moved = inbox_moved_;
        *secrets_counted = std::cell::Cell::new(None);
        *reading_counted = std::cell::Cell::new(None);
        *unsettled_memo = None;
        *relink_backoff = BTreeMap::new();
        *relink_pending = BTreeMap::new();
        *reask = BTreeSet::new();
        *relink_at = 0;
        *retired_at = BTreeSet::new();
        *deferred = Vec::new();
        *genuine = BTreeMap::new();
        *reread_boxes = true;
        *start_look = true;
        *redelivered = 0;
        *awaits_secrets = (0, 0);
        *retry_inbox = BTreeSet::new();
        *inbox_awaits = BTreeMap::new();
        *inbox_plain = BTreeMap::new();
        *unchecked_swept = None;
        *settle_at = BTreeMap::new();
        *held_since = BTreeMap::new();
        *pass_due = true;
        *due_labels = BTreeSet::new();
        *own_wrote = false;
        *fill_due = BTreeSet::new();
        *passed_at = 0;
        *passing = false;
        *work = BTreeMap::new();
        *deposit_seen = BTreeMap::new();
        *stranded_sent = BTreeSet::new();
        *stranded_on = BTreeSet::new();
        *stranded_asks = BTreeMap::new();
        *resealed = BTreeMap::new();
        *suspects_sent = BTreeMap::new();
        *suspects_gen = None;
        *suspects_due = false;
        *repair_state = BTreeMap::new();
        *links_failed = BTreeSet::new();
        *joined_touched = None;
        *joined_failed = BTreeSet::new();
        *tied = deliver::TiedWork { all: true, ..Default::default() };
        *synced = Default::default();
        *synced_of = crate::engine::memo::Memo::new("labels synced");
        *served = BTreeMap::new();
        *hub_conns = BTreeMap::new();
        *refusals = BTreeMap::new();
        *covered_judged = BTreeSet::new();
        *stats = PassStats::default();
        *records = records::Records::default();
        *streams = BTreeMap::new();
        *changed_due = true;
        *changed_gen = 0;
        *touched = work::Touched::default();
        *own_keys = BTreeSet::new();
        *lan = BTreeMap::new();
        *lan_rotate = false;
        *reach_account = None;
        *served_cache = None;
        *unread = unread::Unread::default();
        *charges = serve::Charges::default();
        *blob_sizes = BTreeMap::new();
        *swept = 0;
        *peer_cache = peers::PeerCache::default();
        *peer_received = BTreeMap::new();
        *peer_passes = BTreeMap::new();
        *sources_gen = u64::MAX;
        *shared_dirty = false;
        *changed_moved = BTreeSet::new();
        *role_change = BTreeMap::new();
        *pass_wanted = BTreeSet::new();
        *started = started_;
        *rotation_at = BTreeMap::new();
        *placed_cache = (u64::MAX, BTreeMap::new());
        *placed_waiting = BTreeSet::new();
        *rotated = crate::engine::memo::Memo::new("ensure rotated");
        *last_synced = BTreeMap::new();
        *clients_moved = false;
        *prefix_checked = BTreeSet::new();
        *memory = memory::Memory::default();
        // durable commits forgotten whole whose entries were not yet deleted at hosts
        for (c, header) in self.state.forgotten.clone() {
            self.memory.forgotten.insert(c, memory::Forgotten { header, why: crate::engine::MemoryDrop::Gone });
        }
        // a forgetting a crash interrupted before its inbox check
        self.forget_inbox()?;
        // entries the hub's store holds that the engine's store never committed
        let rederived = std::mem::take(&mut self.state.rederived);
        self.take_hub_changes(rederived)?;
        self.reopen_undropped(None)?;
        self.reopen_all_awaiting();
        // the keys and ciphertexts of bodies the engine dropped before a crash cut this layer
        // off (its forget runs a step after the dropping transaction, spec/commits.md §5)
        self.forget_dropped(None)?;
        // peer budgets as the store holds them
        self.charge_held();
        // flows' deliveries a crash cut off before they were carried out
        if let Err(e) = self.take_owed() {
            self.diag(format!("owed deliveries: {e}"));
        }
        Ok(())
    }

    /// The writes of the engine's store and the hub's (`Store::writes`).
    fn store_writes_now(&self) -> [osis_store::Writes; 2] {
        [self.engine.store_writes(), self.hub_store.lock().unwrap_or_else(std::sync::PoisonError::into_inner).store_writes()]
    }

    /// A store write failed (`handle`). The store and engine are as their last commit left them
    /// (notes/local-store.md, Failed writes recover in place), but what the step took in memory
    /// (stream positions, entries taken, bytes it did not store) may be ahead of them: node sync
    /// starts again from the store as an open does, every connection closed (dialed again as at
    /// a start), so what it had taken is fetched again.
    fn restart_in_place(&mut self, out: &mut Vec<Action>) {
        for conn in self.conns.keys().copied().collect::<Vec<_>>() {
            out.push(Action::Close { conn });
        }
        for conn in self.served.keys().copied().collect::<Vec<_>>() {
            self.close_served(conn, out);
        }
        // what the failed step's engine events told is read again from the store
        while self.events.try_recv().is_ok() {}
        if let Err(e) = self.start() {
            self.diag(format!("sync restart after a store error: {e}"));
        }
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Applies the hub's changes to the sync IDs this node reads (`State::hub_changes`).
    fn hub_changed(&mut self) -> Result<()> {
        let c = self.state.hub_changes(&mut self.engine)?;
        self.take_hub_changes(c)
    }

    /// Opens entries derived from the hub's rows, their bytes held, and forgets the blobs of
    /// those dropped.
    fn take_hub_changes(&mut self, c: state::HubChanges) -> Result<()> {
        for b in &c.gone {
            self.forget_entry_blob(b)?;
        }
        let mut by: BTreeMap<LabelId, Vec<osis_base::BlobId>> = BTreeMap::new();
        for (l, b) in c.derived {
            by.entry(l).or_default().push(b);
        }
        for (l, bs) in by {
            self.open_entries(None, l, &bs)?;
            self.touched.blobs.extend(bs);
        }
        Ok(())
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

    /// Wall ms.
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

    /// A bound on unverified input from other nodes was reached and what came past it was not
    /// kept (notes/node-sync.md, Input giving nothing): the app hears of it.
    pub(crate) fn report_capped(&mut self, detail: String) {
        let now = self.engine.now();
        self.engine.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::InputCapped, tids: Vec::new(), commit: None, peer: None, detail }, now);
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
        if let Err(e) = self.run_engine_timers() {
            self.diag(format!("sync: {e}"));
        }
    }

    /// Every entry past its blob's prefix expiry goes, its bytes with it unless another entry
    /// names them (spec/sync.md §5): whatever its kind or what the engine still knows of its
    /// commit (a request forgotten at its expiry, an entry awaiting a record), at hosts, served
    /// or both, connected or not. Hosts drop it unattended then, and the hub's rows of a sync ID
    /// this node reads expire only here (notes/serving.md), so they agree.
    fn expire_entries(&mut self) -> Result<()> {
        let now = self.now();
        for b in self.state.expire_entries(now) {
            self.forget_entry_blob(&b)?;
        }
        Ok(())
    }

    /// The engine's due expiry timers, durable and ephemeral (spec/commits.md §6).
    fn run_engine_timers(&mut self) -> Result<()> {
        self.engine.tick()?;
        self.engine_events()
    }

    /// Feeds one input; returns what the driver must do.
    pub fn handle(&mut self, ev: Event) -> Vec<Action> {
        let mut out = Vec::new();
        self.state.now = self.now();
        if let Err(e) = self.republish_reach() {
            self.diag(format!("reach.0 after a pairing: {e}"));
        }
        // a Tick consumed the driver's wake: the next one is always asked for again
        if matches!(ev, Event::Tick) {
            self.wake = None;
            self.last_tick = self.now();
        }
        // what the hub changed of the sync IDs this node reads (what its peers sent, its sweep)
        if self.hub_store.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take_moved()
            && let Err(e) = self.hub_changed()
        {
            self.diag(format!("the hub's changes: {e}"));
        }
        // what it changed of the sync IDs it keeps unread (heads, streamed ephemeral entries)
        self.unread_moved();
        let mut ok = self.settled_step(ev, &mut out);
        // what the passes marked (a refetch applied commits, an admin recorded a step) passes now,
        // not at whatever event comes next; a step that failed (a store gone) tries no more
        for _ in 0..PASS_AGAIN {
            if !ok || !self.passes_due() {
                break;
            }
            ok = self.settled_step(Event::Local, &mut out);
        }
        // after the passes heard labels out: a release request written goes up now
        if ok && self.judge_lifetimes() {
            self.settled_step(Event::Local, &mut out);
        }
        // to the open labels' work sets now: with none (offline, LAN or local labels only) the
        // changes go (a label opened later judges everything)
        self.spread_touches();
        self.prune_pass_sources();
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
        self.host_step(&mut out);
        // a sync ID full here with room again is pulled again
        if let Err(e) = self.unread_room(&mut out) {
            self.diag(format!("room again: {e}"));
        }
        // a store write failed in this call or since the last, whichever path met it; a store
        // that takes no commit since the last restart (a dead device) would only fail it again
        let writes = self.store_writes_now();
        self.restart_due |= writes.iter().zip(&self.store_writes).any(|(w, seen)| w.failed != seen.failed);
        self.store_writes = writes;
        if self.restart_due && self.restarted_at != Some(writes.map(|w| w.committed)) {
            self.restart_due = false;
            self.restart_in_place(&mut out);
            self.restarted_at = Some(self.store_writes_now().map(|w| w.committed));
        }
        if let Some(at) = self.next_wake()
            && self.wake != Some(at)
        {
            self.wake = Some(at);
            out.push(Action::Wake { at });
        }
        out
    }

    /// `step`, then what it marked changed; whether all went well.
    fn settled_step(&mut self, ev: Event, out: &mut Vec<Action>) -> bool {
        let r = self.step(ev, out).and_then(|()| self.redeliver());
        let mut ok = r.is_ok();
        if let Err(e) = r {
            self.diag(format!("sync: {e}"));
        }
        // what the passes marked changed: judged by the next pass
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
        // what is due goes before any event, not only a Tick: an expiry goes before the pass that
        // would place what it strips (spec/commits.md §6)
        if matches!(ev, Event::Tick) || self.engine.timers_due() {
            self.run_engine_timers()?;
        }
        // every change committed since the last event is taken in before this one is answered: a
        // purge's bytes are gone before a peer's Fetch reads them (spec/commits.md §5), a role
        // change's served set is fresh before a request is judged by it
        self.engine_events()?;
        self.expire_entries()?;
        // a head the hub moved ends the opens by its old credentials before this event is
        // answered: the hub logged it already, so a Pull would read past it (spec/sync.md §10 Lost)
        if std::mem::take(&mut self.unread.moved) {
            self.stamp_changes()?;
            self.shared_changed(out)?;
        }
        match ev {
            Event::Tick => {
                self.timers(out)?;
                self.serve_timers(out);
                self.relink_lost()?;
            }
            Event::Local => {}
            Event::Up { conn, hub } => self.dialed(conn, hub, out),
            Event::Reply { conn, id, reply } => self.hub_down(conn, osis_host::Down::Reply { id, reply }, out),
            Event::Notify { conn, notes } => self.port_notify(conn, notes, out),
            Event::WantRoom { conn } => self.port_wants_room(conn, out),
            Event::Hub { ups } => {
                for (id, up) in ups {
                    self.hub_up(id, up, out)?;
                }
            }
            Event::End { conn } => {
                if self.served.contains_key(&conn) {
                    self.close_served(conn, out);
                }
            }
            Event::Down { conn } => self.lost(conn),
        }
        // links expired or used: a removal of the link key (spec/permissions.md §7)
        self.finalize_links()?;
        // tied edges whose placement is gone (spec/permissions.md §2)
        self.untie_unplaced()?;
        // snapshots written here are changes the passes place (the trigger and `memory_step` first)
        self.compact_due()?;
        self.memory_step(out)?;
        self.engine_events()?;
        // joined links that ended: this account leaves K (spec/permissions.md §7)
        if self.leave_ended_links()? {
            self.engine_events()?;
        }
        self.retire_replaced();
        self.reprove(out)?;
        self.stamp_changes()?;
        if std::mem::take(&mut self.clients_moved) {
            self.clients_changed(out);
        }
        self.connect(out);
        self.send_inbox()?;
        self.send_outbox(out)?;
        self.run_dirty(out)?;
        self.ask_pass_ends(out)?;
        // after the passes: this step's last sends go first, then what the change ends
        self.shared_changed(out)?;
        self.send_suspects(out)?;
        self.stream_settle_all(out)?;
        // after the re-judging and settling: a peer no longer wanted gets this node's reports
        // of what it applied from it (spec/sync.md §5 Placed: its removal's Applied) first
        self.drop_unwanted_peers(out);
        // the unread sync IDs shared now, their memory entries before the pushes
        self.unread_restream()?;
        // pushes after the re-judging: nothing of this step goes to a member it ended
        self.stream_push(out)?;
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
        let now = self.now();
        self.engine.core.time.set(now);
        // a `label.0` the store refused to read: the labels last answered stand
        let Ok(s) = crate::engine::memo::Memo::get_in(self, |s| &s.synced_of, &(), |s| s.compute_synced().map(Arc::new)) else { return self.synced.labels.clone() };
        // built again since the last ask
        if !Arc::ptr_eq(&s, &self.synced) {
            self.stats.label_reads += 1;
            if s.ids != self.synced.ids {
                self.changed_due = true;
                // the hub's store keeps these as node sync's (`HostStore::set_read`)
                self.hub_store.lock().unwrap_or_else(std::sync::PoisonError::into_inner).set_read(s.ids.clone());
            }
            self.synced = s;
        }
        self.synced.labels.clone()
    }

    /// `labels`, with roles at the time last asked (`Core::time`), read only where a replaced label
    /// asks for a role.
    fn compute_synced(&mut self) -> Result<Synced> {
        let me = self.engine.account_tid();
        let mut labels = Vec::new();
        for g in self.engine.labeled_groups() {
            // handed off (`set_handed_off`): never synced
            if self.state.handed_off.contains(&g) || self.engine.epochs(&g).is_none_or(|e| !e.read.holds_any()) {
                continue;
            }
            let of = self.engine.labels_read(&g)?;
            let admin = of.iter().any(|l| l.replaced) && {
                let ts = osis_base::Ts::make(osis_base::WallMs(self.engine.core.time.get()), 0).unwrap_or_default();
                me.is_some_and(|me| crate::engine::write::role_of(&self.engine.core, &me, &g, ts) == Some(osis_base::Role::Admin))
            };
            labels.extend(of.into_iter().filter(|l| !l.replaced || admin && !self.state.retired.contains(&l.id)).map(|l| (g, l)));
        }
        let actors: BTreeMap<LabelId, (Tid, Vec<HostKey>)> = labels.iter().map(|(g, l)| (l.id, (self.keys_actor(g), peers::host_keys(&l.hosts).collect()))).collect();
        let mut by_actor: BTreeMap<Tid, BTreeSet<LabelId>> = BTreeMap::new();
        for (l, (a, _)) in &actors {
            by_actor.entry(*a).or_default().insert(*l);
        }
        let ids = labels.iter().map(|(_, l)| l.id).collect();
        Ok(Synced { labels, ids, actors, by_actor })
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

    /// The roles of `g`'s secret actor this node may not encrypt under now, and those it may not
    /// even place under (`placing`), after the rotations due
    /// first when `rotate` (flows' `ensure_rotated`, spec/permissions.md §3).
    pub(crate) fn uncovered(&mut self, g: &Tid, rotate: bool) -> Result<Blocked> {
        let Some(a) = self.engine.core.secret_actor(g) else { return Ok(Blocked::default()) };
        if self.engine.core.is_key_actor(&a) {
            return Ok(Blocked::default());
        }
        if rotate && self.rotations(&a)?.is_empty() {
            return Ok(Blocked::default());
        }
        self.placing(&a)
    }

    /// The roles of `a` still blocked after the rotations due (`Engine::ensure_rotated`), run
    /// once per change of what it reads (a memo of its answer when it had nothing to do): the
    /// roles, secrets and record chains, and the clock up to the next `until` or role commit
    /// ahead of it in `a`'s component (`horizon`), which holds `a`'s holders and theirs. A run
    /// that did something is not kept: the next ask runs again.
    fn rotations(&mut self, a: &Tid) -> Result<BTreeSet<osis_base::Role>> {
        let now = self.now();
        self.engine.core.time.set(now);
        let run = |s: &mut Self| {
            // the horizon before the run judges at the wall clock: one read after it would miss
            // an `until` the clock passed during the run (a run that changed the timelines is
            // not kept)
            s.engine.core.time.until(s.engine.core.horizon(std::iter::once(*a)));
            let (done, still) = s.engine.ensure_rotated(a).map_err(Rotating::Failed)?;
            if !done.commits.is_empty() || !done.deliveries.is_empty() || done.drop_lost {
                return Err(Rotating::Did(done, still));
            }
            Ok(still)
        };
        // a debug comparison rotates nothing: what a run would leave, rolled back
        let fresh = |s: &mut Self| {
            let still = s.engine.rotated_already(a).map_err(Rotating::Failed)?;
            assert!(still.is_some(), "rotations of {a:?} went stale: a rotation is due");
            Ok(still.unwrap_or_default())
        };
        match crate::engine::memo::Memo::get_checked_in(self, |s| &s.rotated, a, run, fresh) {
            Ok(still) => Ok(still),
            Err(Rotating::Did(done, still)) => {
                self.take_done(done)?;
                Ok(still)
            }
            Err(Rotating::Failed(e)) => Err(e),
        }
    }

    /// The roles of `a` this node may not encrypt under, and may not place under
    /// (`rotation::blocked_roles_of` by each `Walk`), a departure by this node's own
    /// self-removal not counted until that commit is placed (spec/crypto.md §4).
    fn placing(&mut self, a: &Tid) -> Result<Blocked> {
        let mut deps = Vec::new();
        for (d, own) in self.engine.run(|tx| crate::rotation::departures_placing(tx, a))? {
            if let Some(c) = own
                && !self.placed(&c)?
            {
                continue;
            }
            deps.push(d);
        }
        let Some(me) = self.engine.account_tid() else { return Ok(Blocked::default()) };
        use crate::rotation::{Walk, blocked_roles_of};
        self.engine.run(|tx| Ok(Blocked { encrypt: blocked_roles_of(tx, &me, a, &deps, Walk::Encrypt)?, place: blocked_roles_of(tx, &me, a, &deps, Walk::Place)? }))
    }
}

/// Why `SyncEngine::rotations`' run gave no answer to keep.
enum Rotating {
    /// It rotated (or owes deliveries): what it did, and the roles still blocked.
    Did(crate::flows::Done, BTreeSet<osis_base::Role>),
    Failed(crate::error::Error),
}

/// The roles of an actor a node may not use now (spec/crypto.md §4, Encrypting under).
#[derive(Default)]
pub(crate) struct Blocked {
    /// Not to encrypt under: no content, stamp, step or delete.
    pub encrypt: BTreeSet<osis_base::Role>,
    /// Not even to place certificates or its own role commits under.
    pub place: BTreeSet<osis_base::Role>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// One fresh peer at `T0`: built once (`LocalPeer::cached`).
    fn one_peer() -> crate::local_peer::LocalPeer {
        crate::local_peer::LocalPeer::cached("node::one_peer", || (crate::local_peer::LocalPeer::new(1, 0, osis_base::WallMs(1_700_000_000_000)).unwrap(), ())).0
    }

    // spec/sync.md §6: a deposit in flight on a connection that ended (its session closed it,
    // say on a request timeout, or the transport went down) goes again on the next connection;
    // the ended one is never answered (a fetch goes with its stream).
    #[test]
    fn closed_session_sends_its_deposits_again_spec_sync_6() {
        for down in [false, true] {
            let lp = one_peer();
            let p = lp.peers.into_iter().next().unwrap();
            let host = Address { url: "quic://host:1".into(), key: [7; 32] };
            let cfg = SyncConfig { hosts: vec![host.clone()], ..SyncConfig::default() };
            let mut s = SyncEngine::new(super::host::on_hub(p), Box::new(osis_crypto::SeededRng::from_u64(1)), cfg).unwrap();
            let conn = s.handle(Event::Tick).into_iter().find_map(|a| if let Action::Dial { conn, .. } = a { Some(conn) } else { None }).unwrap();
            let d = osis_crypto::SigningSecret::from_seed(&osis_crypto::Secret32::from_bytes([5; 32]));
            s.queue_deposit(LabelId([1; 16]), std::slice::from_ref(&host), &d, vec![9; 40], [3; osis_crypto::WRAP_LEN], None, false);
            for o in s.outbox.values_mut() {
                o.sent = Some(conn);
            }
            if down {
                s.handle(Event::Down { conn });
            } else {
                // up, then its hub session ends (closed on a stall, or the transport went down)
                s.handle(Event::Up { conn, hub: 1 });
                s.handle(Event::Hub { ups: vec![(1, osis_host::Up::End)] });
            }
            assert!(s.outbox.values().all(|o| o.sent.is_none()), "the deposit goes again");
            assert_eq!(s.deliveries_pending(), 1);
        }
    }

    // spec/sync.md §5: a deposit is kept until each of its hosts answers it, also across a
    // restart; one blob queued under two labels at one host is two deposits.
    #[test]
    fn one_blob_queued_under_two_labels_spec_sync_5() {
        let lp = one_peer();
        let p = lp.peers.into_iter().next().unwrap();
        let host = Address { url: "quic://host:1".into(), key: [7; 32] };
        let mut s = SyncEngine::new(super::host::on_hub(p), Box::new(osis_crypto::SeededRng::from_u64(1)), SyncConfig::default()).unwrap();
        let d = osis_crypto::SigningSecret::from_seed(&osis_crypto::Secret32::from_bytes([5; 32]));
        let delivery = Some((osis_base::Tid::from_bytes([4; 15]), osis_base::CommitId([6; 32])));
        for (l, x) in [(LabelId([1; 16]), None), (LabelId([2; 16]), delivery)] {
            s.queue_deposit(l, std::slice::from_ref(&host), &d, vec![9; 40], [3; osis_crypto::WRAP_LEN], x, false);
        }
        assert_eq!(s.deliveries_pending(), 2);
        s.state.flush(&mut s.engine).unwrap();
        let back = State::load(&mut s.engine).unwrap();
        assert_eq!(back.outbox.len(), 2, "both survive a restart");
        let got: Vec<_> = back.outbox.values().map(|o| (o.label, o.delivery)).collect();
        assert_eq!(got, vec![(LabelId([1; 16]), None), (LabelId([2; 16]), delivery)], "with the delivery each serves");
    }
}
