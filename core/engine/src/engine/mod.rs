//! The engine: one node's local state over its `Store` (notes/architecture.md §2: the node
//! talks to `Store` only). Synchronous, no I/O of its own, time from a `Clock`, randomness
//! injected. Every mutating call runs in one store transaction; engine events are sent after
//! it is durable. A failed transaction undoes its changes to the in-memory indexes (`journal`)
//! and evicts the states it wrote.

pub(crate) mod blobs;
pub(crate) mod clock;
pub(crate) mod groups;
pub(crate) mod held;
pub(crate) mod index;
pub(crate) mod journal;
pub(crate) mod pages;
pub(crate) mod large;
mod read;
pub mod records;
pub(crate) mod secrets;
pub(crate) mod state;
pub mod write;

pub use large::LiveTrees;
pub use write::Mutation;

use crate::apply::Reason;
use crate::error::{Error, Result};
use crate::events::{Event, Events, Origin};
use crate::identity::Identity;
use clock::Hlc;
use osis_commit::{CommitBlob, Form, Header};
use osis_base::{Ak, Clock, CommitId, Tid, Ts, WallMs};
use osis_crdt::{Dot, Fragment, SourceKind};
use osis_crypto::{CryptoRngCore, SeededRng};
use osis_keys::ActorEpochs;
use journal::{JMap, JNested, JSet, JSetMap, Journaled};
use osis_perm::Timelines;
use osis_store::{AspectUnit, Backend, RootStorage, Shred, Store, StoreConfig, Transaction};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::mpsc::Receiver;

/// Engine configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// `/node` software revision.
    pub software: String,
    pub store: StoreConfig,
}

impl Default for Config {
    fn default() -> Config {
        Config { software: format!("osis-node {}", env!("CARGO_PKG_VERSION")), store: StoreConfig::default() }
    }
}

/// An applied commit as the engine indexes it.
#[derive(Clone, Debug)]
pub struct Meta {
    /// What the per-commit indexes read of the header (an open reads it from the index).
    pub view: Arc<View>,
    /// Decoded on first use (an open decodes no header the indexes do not need).
    pub header: LazyHeader,
    pub received: WallMs,
    pub origin: Origin,
    /// Validity per aspect (spec/permissions.md §5.2).
    pub valid: Vec<bool>,
    /// Parts dropped (purge, expiry, keep at most): they count as held.
    pub dropped: BTreeSet<(usize, usize)>,
}

impl Meta {
    /// A commit's meta from its decoded header.
    pub fn new(header: Arc<Header>, received: WallMs, origin: Origin, valid: Vec<bool>, dropped: BTreeSet<(usize, usize)>) -> Meta {
        Meta { view: Arc::new(View::of(&header)), header: LazyHeader::ready(header), received, origin, valid, dropped }
    }
}

/// What the per-commit indexes (`apply::index_commit`, validity, the membership filter) read of
/// a header; persisted in the commit's parts row (`engine::index`), so an open builds them
/// without decoding headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    pub ts: Ts,
    pub kind: osis_commit::Kind,
    pub form: Form,
    pub author: Tid,
    pub actor: Tid,
    /// Some list goes by link: the header is resolved from blobs at open (decoded there).
    pub linked: bool,
    pub aspects: Vec<AspectView>,
    /// A membership commit's frontier (`validity::header_frontier`; perm's adaptation reads it
    /// for demotions); `None` on other kinds.
    pub frontier: Option<Arc<osis_perm::Frontier>>,
    /// The blobs of the chunk list (`Core::by_chunk`).
    pub chunks: Vec<osis_base::BlobId>,
}

/// One aspect entry as `View` keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AspectView {
    pub tid: Tid,
    pub ak: Ak,
    pub lo: u64,
    pub hi: u64,
    /// A relative keep bound (`retention::bounded`).
    pub bounded: bool,
}

impl View {
    pub fn of(h: &Header) -> View {
        View {
            ts: h.ts,
            kind: h.kind,
            form: h.form,
            author: h.author,
            actor: h.actor,
            linked: h.links != osis_commit::Links::default(),
            aspects: h.aspects.iter().map(|a| AspectView { tid: a.tid, ak: a.ak.clone(), lo: a.lo, hi: a.hi, bounded: crate::retention::bounded(a) }).collect(),
            frontier: if h.kind == osis_commit::Kind::Membership { crate::apply::validity::header_frontier(h) } else { None },
            chunks: h.chunks.iter().map(|c| c.blob).collect(),
        }
    }
}

/// A commit's header, decoded from its stored bytes on first use. The bytes hash to the commit
/// ID and were verified on arrival by a build with these rules (the index tag), so decoding
/// does not fail; if it does (a bug, damaged memory) the header reads as its view with every
/// other field empty, the running transaction fails (`Error::Corrupt`) and readers outside one
/// (`Engine::header`) see none (`decoded`).
#[derive(Clone)]
pub struct LazyHeader(Lazy);

#[derive(Clone)]
enum Lazy {
    Ready(Arc<Header>),
    /// Decoded: `Ok`, else `Err` with the fallback header.
    Stored(std::sync::OnceLock<std::result::Result<Arc<Header>, Arc<Header>>>, Arc<StoredHeader>),
}

struct StoredHeader {
    id: CommitId,
    bytes: Box<[u8]>,
    view: Arc<View>,
    fault: Arc<std::sync::atomic::AtomicBool>,
}

impl LazyHeader {
    pub fn ready(h: Arc<Header>) -> LazyHeader {
        LazyHeader(Lazy::Ready(h))
    }

    /// A header held as its canonical bytes (`id`'s), decoded on first use; a failed decode
    /// sets `fault`.
    pub(crate) fn stored(id: CommitId, bytes: Box<[u8]>, view: Arc<View>, fault: Arc<std::sync::atomic::AtomicBool>) -> LazyHeader {
        LazyHeader(Lazy::Stored(std::sync::OnceLock::new(), Arc::new(StoredHeader { id, bytes, view, fault })))
    }

    pub fn arc(&self) -> Arc<Header> {
        self.get().clone()
    }

    /// The header, unless its decode failed (then `arc` and `Deref` give the fallback).
    pub fn decoded(&self) -> Option<Arc<Header>> {
        match &self.0 {
            Lazy::Ready(h) => Some(h.clone()),
            Lazy::Stored(got, s) => got.get_or_init(|| s.decode()).as_ref().ok().cloned(),
        }
    }

    /// Whether the header has been decoded (tests).
    pub fn is_decoded(&self) -> bool {
        match &self.0 {
            Lazy::Ready(_) => true,
            Lazy::Stored(got, _) => got.get().is_some(),
        }
    }

    fn get(&self) -> &Arc<Header> {
        match &self.0 {
            Lazy::Ready(h) => h,
            Lazy::Stored(got, s) => match got.get_or_init(|| s.decode()) {
                Ok(h) | Err(h) => h,
            },
        }
    }
}

impl StoredHeader {
    fn decode(&self) -> std::result::Result<Arc<Header>, Arc<Header>> {
        match decode_stored_header(&self.id, &self.bytes) {
            Some(h) => Ok(Arc::new(h)),
            None => {
                self.fault.store(true, std::sync::atomic::Ordering::Relaxed);
                Err(Arc::new(fallback_header(&self.view)))
            }
        }
    }
}

/// The header whose canonical bytes are `bytes`, if they hash to `id` and decode.
pub(crate) fn decode_stored_header(id: &CommitId, bytes: &[u8]) -> Option<Header> {
    if osis_base::hash::hash(bytes) != id.0 {
        return None;
    }
    let lim = osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: bytes.len() };
    Header::from_stored_value(&osis_base::decode(bytes, &lim).ok()?).ok()
}

fn fallback_header(v: &View) -> Header {
    Header {
        version: osis_base::format::FORMAT_VERSION,
        author: v.author,
        actor: v.actor,
        kind: v.kind,
        ts: v.ts,
        form: v.form,
        schemas: Vec::new(),
        aspects: v.aspects.iter().map(|a| osis_commit::AspectEntry { tid: a.tid, ak: a.ak.clone(), lo: a.lo, hi: a.hi, retention: Default::default(), expires: None, schema: None, keys: Vec::new(), hashes: Vec::new() }).collect(),
        chunks: Vec::new(),
        purge: Vec::new(),
        undoes: None,
        blind: [0; 16],
        keys: Vec::new(),
        frontier: None,
        origins: Vec::new(),
        links: Default::default(),
    }
}

impl std::ops::Deref for LazyHeader {
    type Target = Header;
    fn deref(&self) -> &Header {
        self.get()
    }
}

impl std::fmt::Debug for LazyHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Lazy::Ready(h) => h.fmt(f),
            Lazy::Stored(got, _) => match got.get() {
                Some(Ok(h)) => h.fmt(f),
                Some(Err(_)) => f.write_str("LazyHeader(failed to decode)"),
                None => f.write_str("LazyHeader(not decoded)"),
            },
        }
    }
}

/// Owner of writes: one delta of one node (`[lo, hi)`), a commit-form commit, or exact dots of
/// one node (writes snapshots carry, `ctrs` sorted).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Owned {
    Node { node: Tid, lo: u64, hi: u64 },
    Commit(CommitId),
    Dots { src: osis_crdt::Source, ctrs: Vec<u64> },
}

impl Owned {
    pub fn of(h: &Header, id: &CommitId, ai: usize) -> Option<Owned> {
        let a = h.aspects.get(ai)?;
        Some(match h.form {
            Form::Node => Owned::Node { node: h.author, lo: a.lo, hi: a.hi },
            Form::Commit => Owned::Commit(*id),
        })
    }
    /// `of` from the commit's `View`.
    pub fn of_view(v: &View, id: &CommitId, ai: usize) -> Option<Owned> {
        let a = v.aspects.get(ai)?;
        Some(match v.form {
            Form::Node => Owned::Node { node: v.author, lo: a.lo, hi: a.hi },
            Form::Commit => Owned::Commit(*id),
        })
    }
    /// Whether `d` (an owner dot, never `Derived`) belongs to this delta.
    pub fn owns(&self, d: &Dot) -> bool {
        match (self, d.src.kind()) {
            (Owned::Node { node, lo, hi }, SourceKind::Node(t)) => t == node && *lo <= d.ctr && d.ctr < *hi,
            (Owned::Commit(c), SourceKind::Commit(x)) => c == x,
            (Owned::Dots { src, ctrs }, _) => d.src == *src && ctrs.binary_search(&d.ctr).is_ok(),
            _ => false,
        }
    }
    /// Whether a dot of `src` with a counter in `lo..hi` belongs to this delta.
    pub fn owns_range(&self, src: &osis_crdt::Source, lo: u64, hi: u64) -> bool {
        match (self, src.kind()) {
            (Owned::Node { node, lo: a, hi: b }, SourceKind::Node(t)) => t == node && lo < *b && *a < hi,
            (Owned::Commit(c), SourceKind::Commit(x)) => c == x,
            (Owned::Dots { src: s, ctrs }, _) => s == src && ctrs.get(ctrs.partition_point(|c| *c < lo)).is_some_and(|c| *c < hi),
            _ => false,
        }
    }
}

/// Applies `$m` to every journaled index of a `Core`.
macro_rules! journaled {
    ($c:expr, $m:ident) => {{
        let c = &mut *$c;
        c.held.$m();
        c.commits.$m();
        c.invalid.$m();
        c.by_aspect.$m();
        c.copies.$m();
        c.snapshots.$m();
        c.carried.$m();
        c.by_thing.$m();
        c.by_chunk.$m();
        c.ranges.$m();
        c.pending.$m();
        c.syncing.$m();
        c.void.$m();
        c.valueless.$m();
        c.secrets.$m();
        c.own_keys.$m();
        c.labeled.$m();
        c.delete_hints.$m();
        c.was.$m();
        c.was_of.$m();
        c.moved.$m();
        c.groups.$m();
        c.member_keys.$m();
        c.unresolved.$m();
        c.rotation_role.$m();
        c.grant_overreach.$m();
        c.box_keys.$m();
        c.boxes_to.$m();
        c.epoch_intro.$m();
        c.box_written.$m();
        c.authors.$m();
        c.lost_due.$m();
        c.deaths_due.$m();
        c.first_bounded.$m();
        c.departures.$m();
        c.secrets_unresolved.$m();
    }};
}

/// A held compaction snapshot of an aspect: `ts`, ID, frontiers.
pub(crate) type HeldSnapshot = (Ts, CommitId, osis_crdt::Frontiers);

/// A decoded commit record: received, origin, dropped parts, blob.
pub(crate) type CommitRecord = (WallMs, Origin, BTreeSet<(usize, usize)>, CommitBlob);

/// In-memory state over the store: caches and indexes, rebuilt by `load`. The indexes are
/// journaled (`journal`): a failed transaction undoes its own changes to them.
#[doc(hidden)]
pub struct Core {
    pub id: Identity,
    pub hlc: Hlc,
    pub states: HashMap<(Tid, Ak), Option<Fragment>>,
    /// Page indexes of the cached states kept paged in the store.
    pub pages: HashMap<(Tid, Ak), pages::PageIndex>,
    /// Perm inputs: applied membership commits, roster snapshots, `/created` records.
    pub held: held::Held,
    pub timelines: Timelines,
    /// Components with fewer commits and snapshots are not saved (`index::WALK_CACHE_MIN`;
    /// tests lower it).
    pub walk_cache_min: usize,
    /// Saved walks the running transaction writes, for `Timelines::saved` once it is durable.
    pub walks_done: Option<osis_perm::SaveDone>,
    /// The running transaction called `touch` (`rollback` drops the caches).
    pub dirty: bool,
    /// The paged maps' key index hash key, derived from the node's seed.
    pub key_salt: [u8; 32],
    pub commits: JMap<CommitId, Meta>,
    /// Commits with a part invalid here, per aspect (`Core::index_validity`), so a join finds the
    /// writes to strip in O(invalid parts), not O(history).
    pub invalid: JSetMap<(Tid, Ak), CommitId>,
    /// Held deltas per aspect: (`ts`, commit).
    pub by_aspect: JSetMap<(Tid, Ak), (Ts, CommitId)>,
    /// The commits of `by_aspect` carrying copies of others' writes (snapshots, imports).
    pub copies: JSetMap<(Tid, Ak), (Ts, CommitId)>,
    /// Compaction snapshots held per aspect, with their frontiers: the bodies carrying a write
    /// besides its own (deaths, spec/commits.md §5).
    pub snapshots: JMap<(Tid, Ak), Vec<HeldSnapshot>>,
    /// Writes held snapshots carry whose own commit is not held, per aspect, judged as their
    /// authors' (spec/permissions.md §5.2: a snapshot vouches for nothing).
    pub carried: JMap<(Tid, Ak), Vec<crate::apply::validity::Carried>>,
    /// Held commits per thing they hold a delta of (re-judging a thing's deltas).
    pub by_thing: JSetMap<Tid, CommitId>,
    /// The commits whose header lists each chunk blob (`View::chunks`).
    pub by_chunk: JSetMap<osis_base::BlobId, CommitId>,
    /// Node-form ranges per (tid, ak, node): lo -> (hi, commit).
    pub ranges: JNested<(Tid, Ak, Tid), u64, (u64, CommitId)>,
    pub pending: JMap<CommitId, Reason>,
    /// Pending commits waiting for a record or for deltas, with what their examination read
    /// (`apply::waits`): `reexamine` leaves out those whose inputs did not change. A cache:
    /// dropped by a rollback that changed anything.
    pub(crate) waits: crate::apply::Waits,
    pub syncing: JSet<Tid>,
    pub void: JSet<CommitId>,
    /// What validity may have changed for since the last `rejudge_all`: things whose timeline
    /// changed, commits whose other inputs changed (void, required roles, overreach), or
    /// everything (a rebuild at open).
    pub stale_things: BTreeSet<Tid>,
    pub stale_commits: BTreeSet<CommitId>,
    pub stale_all: bool,
    /// Deltas whose value-carrying writes are held value-less (expired, purged).
    pub valueless: JMap<(Tid, Ak), Vec<Owned>>,
    /// Actors with secrets of their own whose epochs this node holds.
    pub secrets: JMap<Tid, ActorEpochs>,
    /// Things known to have secrets of their own (a `/keys` with keysets).
    pub own_keys: JSet<Tid>,
    /// Things with a `/label` delta held (`Engine::labeled_groups`).
    pub labeled: JSet<Tid>,
    /// Admin and write delete keys of things an inbox payload named (`[admin, write]` bytes),
    /// listed until their `/keys` arrives (spec/crypto.md §7, spec/wire.md §9): taken only from
    /// a commit that applied valid, by an admin of the thing, touching it; the first kept.
    pub delete_hints: JMap<Tid, osis_base::Value>,
    /// Hints of opened inbox payloads whose commit has not applied yet (not persisted).
    pub hint_candidates: BTreeMap<CommitId, Vec<(Tid, osis_base::Value)>>,
    /// `/was` index: t -> things whose `/was` reads t.
    pub was: JSetMap<Tid, Tid>,
    /// The `/was` each thing reads.
    pub was_of: JMap<Tid, Tid>,
    pub moved: JMap<Tid, Tid>,
    /// `/group` definitions and `/groups` (thing -> groups containing it, transitively).
    pub groups: groups::Groups,
    /// Keyed `/members` entries seen: (target, entry dot) -> (member, created value).
    pub member_keys: JMap<(Tid, Dot), Tid>,
    /// Membership commits whose removed keys are not known yet.
    pub unresolved: JSet<CommitId>,
    /// Box keys of keyed `/secrets` entries: (actor, entry dot) -> key.
    pub box_keys: JMap<(Tid, Dot), osis_base::Value>,
    /// Keyed boxes per member: member -> (actor, box key), from `/secrets` entries seen.
    pub boxes_to: JSetMap<Tid, (Tid, osis_base::Value)>,
    /// The earliest noted commit boxing an epoch or writing its keyset: (actor, role, epoch) ->
    /// (`ts`, author node, actor acted for). What introduced the epoch (`rotation`).
    pub epoch_intro: EpochIntro,
    /// Commit-form sources whose writes snapshots may carry, per thing: (thing, commit ID) ->
    /// (the node its writes are judged as, at which `ts`): a commit-form commit's author and
    /// `ts`, an import origin's importer and import `ts`, else a held snapshot's `Authors`
    /// (spec/crdt.md §8).
    pub authors: JMap<(Tid, CommitId), (Tid, Ts)>,
    /// The earliest noted commit writing a box: (actor, box key) -> its `ts`.
    pub box_written: JMap<(Tid, osis_schema::core_types::BoxKey), Ts>,
    /// Linked tenure frontiers decoded (by link content hash) with their canonical size; content
    /// addressed, so never stale.
    pub frontiers: BTreeMap<[u8; 32], (Arc<osis_perm::Frontier>, usize)>,
    /// Things a roster snapshot of which was kept out of perm for a linked frontier not held
    /// here (`validity::add_membership`): no roster snapshot of them is written.
    pub frontier_unknown: BTreeSet<Tid>,
    /// `rotation::departures` per actor with the time it holds until (an edge's `until`, a
    /// write's future `ts`); cleared by `membership_changed`.
    pub departures: JMap<Tid, (Vec<osis_keys::Departure>, Option<WallMs>)>,
    /// `/secrets` writes of applied commits waiting for the keys of the boxes they remove.
    pub secrets_unresolved: JMap<(CommitId, usize), crate::apply::keys::Unresolved>,
    /// Roles `/secrets` and `/keys` deltas need (by commit and aspect index).
    pub rotation_role: JMap<(CommitId, usize), osis_base::Role>,
    /// `/secrets` parts of membership commits that write beyond their grantees' boxes (an invite
    /// grant may carry only those, spec/permissions.md §2).
    pub grant_overreach: JSet<(CommitId, usize)>,
    /// Schemas of local writes (typed views for undo).
    pub schemas: BTreeMap<osis_base::SchemaId, Arc<osis_schema::Schema>>,
    pub events: Events,
    /// States the running transaction wrote (dropped from the cache on rollback).
    pub written: Vec<(Tid, Ak)>,
    /// Tests: let local commits break the writer-side membership rules (to test receivers).
    pub skip_writer_rules: bool,
    /// Set when a lazily held header failed to decode (`LazyHeader`): every later transaction
    /// fails (`Error::Corrupt`).
    pub header_fault: Arc<std::sync::atomic::AtomicBool>,
    /// Tests: after each per-entry `/secrets` ingestion, check that ingesting the whole state
    /// learns nothing more (`apply::atomic::observe_secrets_keys`).
    #[cfg(test)]
    pub check_ingest: bool,
    /// Key actors other than the node whose seed this node holds for now (a recovery key from
    /// its card, a link key; membership flows): they sign commits (`Mutation::sign_as`) and
    /// open their boxes. In memory only.
    pub key_actors: BTreeMap<Tid, Arc<Identity>>,
    /// The lost-access trigger's work list (`rotation::LOST_DUE`).
    pub lost_due: JSet<Tid>,
    /// Aspects whose deaths wait for a replay (`records::DEATHS_DUE`) and what it must judge.
    pub deaths_due: JSetMap<(Tid, Ak), crate::retention::Due>,
    /// The first held body with a relative keep bound per aspect, by `(ts, ID)` (`None`: none),
    /// where known (`retention::first_bounded`).
    pub first_bounded: JMap<(Tid, Ak), Option<(Ts, CommitId)>>,
    /// Replays wait for `Engine::settle_deaths` instead of ending each transaction (node-sync,
    /// within a step).
    pub defer_deaths: bool,
    /// What changed since node-sync last took it (`Engine::take_changed`; `None`: no
    /// node-sync, nothing kept). A mark from an aborted transaction stays: one extra judgment.
    pub changed: Option<Changed>,
    /// `Engine::live_trees` per thing, cleared by every transaction that changes the indexes or
    /// a state (`touch`, `rollback`) and when blobs arrive (`put_blobs`).
    pub live_trees: BTreeMap<Tid, LiveTrees>,
    /// `Engine::bodies` per commit without their plaintexts (the label pass's cost): dropped
    /// when the commit's record is written (late parts, drops), when a thing it touches gets
    /// its creation record, and all when an actor gets secrets of its own (reader actors move);
    /// only commits whose things' owner chains are known are kept.
    pub bodies: BTreeMap<CommitId, Vec<crate::labeling::Body>>,
    /// `Engine::body_live` per body, forgotten per aspect when its state changes (`forget_live`)
    /// and wholly on rollback.
    pub live_bodies: BTreeMap<(CommitId, Tid, Ak), bool>,
    /// Bumped whenever a transaction changes the indexes or a state, or rolls back: caches
    /// derived from them (the sync engine's co-readers) compare it.
    pub generation: u64,
    /// `Engine::labels_of` per group: dropped when its `/label` state is written (`wrote`) and
    /// on rollback.
    pub(crate) labels: BTreeMap<Tid, Vec<std::sync::Arc<crate::labeling::GroupLabel>>>,
    /// `Engine::published_under` for every actor, with the counts it was taken at (held
    /// records, `own_keys`, `labeled`).
    pub(crate) published: Option<Published>,
    /// The sync records this engine's transactions write or drop (`SyncRecords`), set by
    /// node-sync (`Engine::set_sync_records`; `None`: no node-sync, no sync records).
    pub sync_records: Option<&'static dyn SyncRecords>,
}

/// `Core::published`: the counts it was taken at, the published things per actor.
pub(crate) type Published = ((u64, u64, u64), BTreeMap<Tid, std::sync::Arc<BTreeSet<Tid>>>);

/// Node-sync's records that engine transactions touch: an inbox delivery a flow's commit owes
/// (`flows::edges`) and what forgetting drops (`retention::forget`). Implemented by node-sync.
pub trait SyncRecords: Sync {
    /// Records the inbox delivery of `commit` to `member` in the commit's own transaction, so
    /// a crash before node-sync carries it out loses none.
    fn note_unsent(&self, tx: &mut Tx<'_>, member: Tid, commit: CommitId, things: Vec<Tid>, edge_only: bool) -> Result<()>;
    /// Removes the sync records of what is forgotten (`labels`, `things`, `commits`, `parts`)
    /// and returns the blobs among those dropped and `extra` that no kept record names.
    fn forget(&self, tx: &mut Tx<'_>, labels: &BTreeSet<osis_base::LabelId>, things: &BTreeSet<Tid>, commits: &BTreeSet<CommitId>, parts: &BTreeMap<CommitId, BTreeSet<usize>>, extra: BTreeSet<osis_base::BlobId>) -> Result<BTreeSet<osis_base::BlobId>>;
}

/// What node-sync judges again (`Core::changed`).
#[derive(Debug, Default)]
pub struct Changed {
    /// Commits whose record, parts, validity, deaths, bodies or timers changed.
    pub commits: BTreeSet<CommitId>,
    /// Aspects whose state changed other than by a valid write's join (a validity flip, an
    /// un-merge, expiry, purge, a late delta): what waits on the state is judged again.
    pub aspects: BTreeSet<(Tid, Ak)>,
}

impl Changed {
    pub fn is_empty(&self) -> bool {
        self.commits.is_empty() && self.aspects.is_empty()
    }
}

/// (actor, role, epoch) -> the commit that introduced it: (ts, author node, actor, commit ID).
pub(crate) type EpochIntro = JMap<(Tid, osis_base::Role, osis_crypto::Epoch), (Ts, Tid, Tid, CommitId)>;

impl Core {
    /// The held aspects of `t` and their commits (a range of `by_aspect`).
    pub fn aspects_of(&self, t: &Tid) -> impl Iterator<Item = (&(Tid, Ak), &std::collections::BTreeSet<(Ts, CommitId)>)> {
        let t = *t;
        self.by_aspect.range((t, Ak::MIN)..).take_while(move |((x, _), _)| *x == t)
    }

    /// Drops what is derived from rosters, `/secrets` and held epochs (the departures cache):
    /// called wherever those change.
    pub fn membership_changed(&mut self) {
        if !self.departures.is_empty() {
            self.departures.retain(|_, _| false);
        }
    }

    /// Re-evaluates the timelines around the things whose held inputs changed; the things of
    /// changed timelines wait for `rejudge_all`.
    pub fn update_timelines(&mut self) {
        let _s = crate::costs::span("timelines");
        let touched = self.held.take_touched();
        if !touched.is_empty() {
            let changed = self.timelines.update_touched(&self.held, &touched);
            self.stale_things.extend(changed.evaluated);
            // a walk that only went on changed authority only below what it touched
            let below = self.held.reach(&changed.extended);
            self.stale_things.extend(below);
        }
        self.membership_changed();
    }

    /// Whether some validity waits for `rejudge_all`.
    pub fn stale(&self) -> bool {
        self.stale_all || !self.stale_things.is_empty() || !self.stale_commits.is_empty()
    }

    /// Drops what is derived from the state of `(tid, ak)` (a write changes it).
    fn state_changed(&mut self, tid: &Tid, ak: &Ak) {
        self.forget_live(tid, ak);
        if osis_schema::core_types::is_membership_class(ak.as_str()) {
            self.membership_changed();
        }
    }

    /// Forgets the cached liveness of every body with a delta on `(tid, ak)` (its state
    /// changed): a body's liveness spans every aspect of its class, whichever one was asked.
    pub fn forget_live(&mut self, tid: &Tid, ak: &Ak) {
        let commits = &self.commits;
        self.live_bodies.retain(|(c, t, a), _| {
            if t == tid && a == ak {
                return false;
            }
            !commits.get(c).is_some_and(|m| m.header.aspects.iter().any(|x| x.tid == *tid && x.ak == *ak))
        });
    }

    /// Marks commit `c` changed for node-sync (`changed`).
    pub fn mark_changed(&mut self, c: CommitId) {
        if let Some(s) = &mut self.changed {
            s.commits.insert(c);
        }
    }

    /// Marks the state of `(tid, ak)` changed for node-sync (`changed`): the commits whose
    /// parts changed are marked on their own.
    pub fn mark_aspect_changed(&mut self, tid: &Tid, ak: &Ak) {
        if let Some(s) = &mut self.changed {
            s.aspects.insert((*tid, ak.clone()));
        }
    }

    /// Notes that the running transaction writes the state of `k` (evicted on rollback).
    pub fn wrote(&mut self, k: (Tid, Ak)) {
        if k.1.as_str() == "/label" {
            self.labels.remove(&k.0);
        }
        self.written.push(k);
    }

    /// Notes that the running transaction changes the indexes or a state (drops derived caches).
    pub fn touch(&mut self) {
        self.live_trees.clear();
        self.generation += 1;
        self.dirty = true;
    }

    /// The running transaction committed: its journal is forgotten.
    fn commit_journal(&mut self) {
        journaled!(self, commit);
        self.written.clear();
        self.dirty = false;
    }

    /// Undoes the aborted transaction's changes to the caches and indexes (the caches stay when
    /// it changed nothing: a failed read keeps them).
    fn rollback(&mut self) {
        if self.dirty || !self.written.is_empty() {
            self.waits.clear();
            self.dirty = false;
            self.live_trees.clear();
            self.live_bodies.clear();
            self.bodies.clear();
            self.generation += 1;
            self.membership_changed();
            self.labels.clear();
            for k in std::mem::take(&mut self.written) {
                self.states.remove(&k);
                self.pages.remove(&k);
            }
        }
        journaled!(self, rollback);
        // the timelines follow the restored held set; validity flags are restored with `commits`
        let touched = self.held.take_touched();
        if !touched.is_empty() {
            self.timelines.update_touched(&self.held, &touched);
        }
        self.stale_things.clear();
        self.stale_commits.clear();
    }

    fn new(id: Identity, clock: Arc<dyn Clock>) -> Core {
        let key_salt = osis_base::hash::derive_key("osis node key index", id.seed().expose());
        Core {
            id,
            hlc: Hlc::new(clock, Ts::default()),
            states: HashMap::new(),
            pages: HashMap::new(),
            held: held::Held::default(),
            timelines: Timelines::new(),
            walk_cache_min: index::WALK_CACHE_MIN,
            walks_done: None,
            stale_things: BTreeSet::new(),
            stale_commits: BTreeSet::new(),
            stale_all: true,
            dirty: false,
            key_salt,
            commits: JMap::default(),
            invalid: JSetMap::default(),
            by_aspect: JSetMap::default(),
            copies: JSetMap::default(),
            snapshots: JMap::default(),
            carried: JMap::default(),
            by_thing: JSetMap::default(),
            by_chunk: JSetMap::default(),
            ranges: JNested::default(),
            pending: JMap::default(),
            waits: crate::apply::Waits::default(),
            syncing: JSet::default(),
            void: JSet::default(),
            valueless: JMap::default(),
            secrets: JMap::default(),
            own_keys: JSet::default(),
            labeled: JSet::default(),
            delete_hints: JMap::default(),
            hint_candidates: BTreeMap::new(),
            was: JSetMap::default(),
            was_of: JMap::default(),
            moved: JMap::default(),
            groups: groups::Groups::default(),
            member_keys: JMap::default(),
            unresolved: JSet::default(),
            rotation_role: JMap::default(),
            grant_overreach: JSet::default(),
            box_keys: JMap::default(),
            boxes_to: JSetMap::default(),
            epoch_intro: JMap::default(),
            box_written: JMap::default(),
            authors: JMap::default(),
            departures: JMap::default(),
            frontiers: BTreeMap::new(),
            frontier_unknown: BTreeSet::new(),
            secrets_unresolved: JMap::default(),
            schemas: BTreeMap::new(),
            events: Events::default(),
            written: Vec::new(),
            skip_writer_rules: false,
            header_fault: Arc::default(),
            #[cfg(test)]
            check_ingest: false,
            key_actors: BTreeMap::new(),
            lost_due: JSet::default(),
            deaths_due: JSetMap::default(),
            first_bounded: JMap::default(),
            defer_deaths: false,
            changed: None,
            sync_records: None,
            live_trees: BTreeMap::new(),
            bodies: BTreeMap::new(),
            live_bodies: BTreeMap::new(),
            generation: 0,
            labels: BTreeMap::new(),
            published: None,
        }
    }

    pub fn now(&self) -> WallMs {
        self.hlc.wall()
    }

    /// Re-indexes which parts of commit `id` are invalid here (call after setting `Meta::valid`).
    pub fn index_validity(&mut self, id: &CommitId) {
        let Some(m) = self.commits.get(id) else { return };
        for (ai, a) in m.view.aspects.iter().enumerate() {
            let k = (a.tid, a.ak.clone());
            if m.valid.get(ai).copied().unwrap_or(false) {
                self.invalid.remove(&k, id);
            } else {
                self.invalid.insert(k, *id);
            }
        }
    }

    /// The commit that wrote dot `d` on `(tid, ak)`, if held.
    pub fn commit_of(&self, tid: &Tid, ak: &Ak, d: &Dot) -> Option<CommitId> {
        let d = d.owner();
        match d.src.kind() {
            SourceKind::Commit(c) => Some(*c),
            SourceKind::Node(n) => {
                let m = self.ranges.get(&(*tid, ak.clone(), *n))?;
                let (_, (hi, c)) = m.range(..=d.ctr).next_back()?;
                (d.ctr < *hi).then_some(*c)
            }
            SourceKind::Derived(_) => None,
        }
    }
}

/// One transaction with the engine's in-memory state.
pub struct Tx<'a> {
    pub txn: Transaction<'a>,
    pub core: &'a mut Core,
    pub rng: &'a mut dyn CryptoRngCore,
}

impl Tx<'_> {
    /// Loads the state of `(tid, ak)` into the cache: a paged state lazily (its skeleton; pages
    /// as `ensure_*` and `load` need them).
    pub fn load_lazy(&mut self, tid: &Tid, ak: &Ak) -> Result<()> {
        let k = (*tid, ak.clone());
        if self.core.states.contains_key(&k) {
            return Ok(());
        }
        let f = match self.txn.get_aspect(tid, ak)? {
            Some(mut u) if pages::is_paged(&u.state) => {
                // an earlier build's layout is laid out anew, once
                if let Some(whole) = pages::legacy(&mut self.txn, tid, ak, &u.state)? {
                    self.core.touch();
                    self.core.wrote(k.clone());
                    u.state = pages::write_full(&mut self.txn, tid, ak, Some(&whole), true, &self.core.key_salt)?.0;
                    self.txn.put_aspect(tid, ak, &u, Shred::No)?;
                }
                let (f, idx) = pages::open(&u.state, &self.core.key_salt)?;
                self.core.pages.insert(k.clone(), idx);
                Some(f)
            }
            Some(u) if !u.state.is_empty() => Some(state::decode(&u.state)?),
            _ => None,
        };
        self.core.states.insert(k, f);
        Ok(())
    }

    /// Whether the state of `(tid, ak)` is paged with some page not loaded.
    fn held_in_part(&self, tid: &Tid, ak: &Ak) -> bool {
        self.core.pages.get(&(*tid, ak.clone())).is_some_and(|i| !i.whole())
    }

    /// Runs `g` on the cached state of `(tid, ak)` (taken out of the cache meanwhile) and its page
    /// index; nothing for an unpaged state.
    fn with_pages<T>(&mut self, tid: &Tid, ak: &Ak, g: impl FnOnce(&mut Transaction<'_>, &mut pages::PageIndex, &mut Fragment) -> Result<T>) -> Result<Option<T>> {
        let k = (*tid, ak.clone());
        let Some(idx) = self.core.pages.get_mut(&k) else { return Ok(None) };
        let Some(mut f) = self.core.states.get_mut(&k).and_then(Option::take) else { return Ok(None) };
        let r = g(&mut self.txn, idx, &mut f);
        self.core.states.insert(k, Some(f));
        r.map(Some)
    }

    /// Loads the whole state of `(tid, ak)` into the cache.
    pub fn load(&mut self, tid: &Tid, ak: &Ak) -> Result<()> {
        self.load_lazy(tid, ak)?;
        if self.held_in_part(tid, ak) {
            self.with_pages(tid, ak, |txn, idx, f| pages::load_all(txn, tid, ak, idx, f))?;
        }
        Ok(())
    }

    /// Loads what ops at `paths` (op path segments) read and write (`pages::ensure_path`).
    pub fn ensure_paths(&mut self, tid: &Tid, ak: &Ak, paths: &[Vec<osis_crdt::PathSeg>]) -> Result<()> {
        self.load_lazy(tid, ak)?;
        if !self.held_in_part(tid, ak) {
            return Ok(());
        }
        let ok = self.with_pages(tid, ak, |txn, idx, f| {
            for p in paths {
                if !pages::ensure_path(txn, tid, ak, idx, f, p)? {
                    return Ok(false);
                }
            }
            Ok(true)
        })?;
        if ok == Some(false) {
            self.load(tid, ak)?;
        }
        Ok(())
    }

    /// Prepares ops by index into paged sequences to run on the pages loaded, through their
    /// stored placements (`pages::attach_ops`); `false`: load whole instead.
    pub(crate) fn attach_ops(&mut self, tid: &Tid, ak: &Ak, ops: &[osis_crdt::PathOp], edits: &[Option<large::ListEdit>]) -> Result<bool> {
        self.load_lazy(tid, ak)?;
        if !self.held_in_part(tid, ak) {
            return Ok(false);
        }
        Ok(self.with_pages(tid, ak, |txn, idx, f| pages::attach_ops(txn, tid, ak, idx, f, ops, edits))? == Some(true))
    }

    /// Loads what ops run on the pages loaded missed (`pages::absorb`): `Some(true)` run them
    /// again, `Some(false)` nothing missed, `None` load whole.
    pub fn absorb(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
        Ok(self.with_pages(tid, ak, |txn, idx, f| pages::absorb(txn, tid, ak, idx, f))?.flatten())
    }

    /// The visible elements `r` (by index, clamped) of the sequence at `path` (op path segments):
    /// a paged one through its placement (`pages::seq_range`), loading only the pages holding
    /// them; else, or where the placement is missing or damaged (then rebuilt), from the whole
    /// sequence. `None` if absent or not a sequence.
    pub fn read_range(&mut self, tid: &Tid, ak: &Ak, path: &[osis_crdt::PathSeg], r: std::ops::Range<usize>) -> Result<Option<osis_base::Value>> {
        self.load_lazy(tid, ak)?;
        let k = (*tid, ak.clone());
        let mut damaged = None;
        if self.held_in_part(tid, ak) {
            match self.with_pages(tid, ak, |txn, idx, f| pages::seq_range(txn, tid, ak, idx, f, path, r.clone()))? {
                // an empty sequence reads whole (its presence)
                Some(pages::Ranged::Read(p, dots, total)) if total > 0 => {
                    match self.cached(tid, ak).and_then(|f| f.at_steps(&p)).and_then(|s| s.read_elems(&dots)) {
                        Some(v) => return Ok(Some(v)),
                        None => damaged = Some(p),
                    }
                }
                Some(pages::Ranged::Damaged(p)) => damaged = Some(p),
                _ => {}
            }
        }
        self.ensure_paths(tid, ak, &[path.to_vec()])?;
        if let Some(p) = damaged {
            self.core.wrote(k);
            self.with_pages(tid, ak, |txn, idx, f| pages::rebuild_placement(txn, tid, ak, idx, f, &p))?;
        }
        Ok(self.cached(tid, ak).and_then(|f| f.at(path)).filter(Fragment::present).and_then(|s| s.read_elems(&s.visible_range(r)?)))
    }

    /// Loads what joining a delta with this touch reads and rewrites (`pages::ensure_touch`;
    /// `None`: everything).
    pub fn ensure_touch(&mut self, tid: &Tid, ak: &Ak, touch: &pages::Touch) -> Result<()> {
        self.load_lazy(tid, ak)?;
        if !self.held_in_part(tid, ak) {
            return Ok(());
        }
        let ok = match touch {
            Some(t) => self.with_pages(tid, ak, |txn, idx, f| pages::ensure_touch(txn, tid, ak, idx, f, t))? == Some(true),
            None => false,
        };
        if !ok {
            self.load(tid, ak)?;
        }
        Ok(())
    }

    /// The cached state as loaded so far (after `load_lazy` and `ensure_*`).
    pub fn cached(&self, tid: &Tid, ak: &Ak) -> Option<&Fragment> {
        self.core.states.get(&(*tid, ak.clone())).and_then(Option::as_ref)
    }

    /// The whole state of `(tid, ak)`.
    pub fn state(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<&Fragment>> {
        self.load(tid, ak)?;
        Ok(self.cached(tid, ak))
    }

    /// Writes a whole state (keeping the unit's undo buffer unless `clear_undo`); `f` is the
    /// whole state.
    pub fn set_state(&mut self, tid: &Tid, ak: &Ak, f: Option<Fragment>, shred: Shred, clear_undo: bool) -> Result<()> {
        self.core.touch();
        self.core.state_changed(tid, ak);
        self.core.wrote((*tid, ak.clone()));
        let mut unit = self.txn.get_aspect(tid, ak)?.unwrap_or_default();
        let (bytes, idx) = pages::write_full(&mut self.txn, tid, ak, f.as_ref(), pages::is_paged(&unit.state), &self.core.key_salt)?;
        unit.state = bytes;
        match idx {
            Some(idx) => self.core.pages.insert((*tid, ak.clone()), idx),
            None => self.core.pages.remove(&(*tid, ak.clone())),
        };
        if clear_undo {
            unit.undo.clear();
        }
        self.txn.put_aspect(tid, ak, &unit, shred)?;
        let ik = records::aspect_key(records::ASPECTS, tid, ak);
        if f.is_some() {
            self.txn.put_local(&ik, &[], Shred::No)?;
        } else {
            self.txn.remove_local(&ik, Shred::No)?;
        }
        self.core.states.insert((*tid, ak.clone()), f);
        Ok(())
    }

    /// Writes a state a join changed: `touch` (`pages::touch_of` the delta) says what it
    /// changed. A paged state rewrites only those pages (and its skeleton if needed); anything
    /// else is written whole (the pages not loaded joined in first). The caller has noted the
    /// state as written (`Core::written`).
    pub fn set_state_touched(&mut self, tid: &Tid, ak: &Ak, f: Option<Fragment>, touch: &pages::Touch, shred: Shred) -> Result<()> {
        self.core.state_changed(tid, ak);
        let k = (*tid, ak.clone());
        if let (Some(st), Some(idx), Some(touch)) = (&f, self.core.pages.get_mut(&k), touch)
            && let Some(unit_state) = pages::write_touched(&mut self.txn, idx, tid, ak, st, touch, shred)?
        {
            if let Some(s) = unit_state {
                let mut unit = self.txn.get_aspect(tid, ak)?.unwrap_or_default();
                unit.state = s;
                self.txn.put_aspect(tid, ak, &unit, shred)?;
            }
            self.core.states.insert(k, f);
            return Ok(());
        }
        let mut f = f;
        if let (Some(st), Some(idx)) = (&mut f, self.core.pages.get_mut(&k)) {
            pages::load_all(&mut self.txn, tid, ak, idx, st)?;
        }
        self.set_state(tid, ak, f, shred, false)
    }

    /// Rewrites shredded what of the state of `(tid, ak)` may hold copies of a dropped body's
    /// writes (`bodies`: its deltas), and clears the undo buffer (spec/commits.md §5: dropping a
    /// body destroys every local copy; the state's content is unchanged). A paged state rewrites
    /// the pages holding the bodies' dots and its skeleton; anything else is rewritten whole.
    pub fn shred_bodies(&mut self, tid: &Tid, ak: &Ak, bodies: &[Fragment]) -> Result<()> {
        let done = self.rewrite_bodies(tid, ak, bodies, |txn, idx, f, touches| {
            for t in touches {
                if pages::write_touched(txn, idx, tid, ak, f, t, Shred::Yes)?.is_none() {
                    return Ok(false);
                }
            }
            pages::unindex(txn, idx, tid, ak, f, bodies)?;
            Ok(true)
        })?;
        if !done {
            self.load(tid, ak)?;
            let st = self.take_cached(tid, ak);
            self.set_state(tid, ak, st, Shred::Yes, true)?;
        }
        Ok(())
    }

    /// Holds value-less the writes of `(tid, ak)` that `owned` owns (a delta expired or
    /// purged, spec/crdt.md §4.7), shredding every copy of their values; `bodies` are the deltas
    /// owning them (where they lie). A paged state strips and rewrites only their pages and
    /// its skeleton; anything else is rewritten whole.
    pub fn strip_bodies(&mut self, tid: &Tid, ak: &Ak, bodies: &[Fragment], owned: &crate::engine::Owned) -> Result<()> {
        let pred = |d: &osis_crdt::Dot| owned.owns(d);
        let done = self.rewrite_bodies(tid, ak, bodies, |txn, idx, f, touches| pages::strip_touched(txn, idx, tid, ak, f, touches, &pred))?;
        if !done {
            self.load(tid, ak)?;
            if let Some(mut st) = self.take_cached(tid, ak) {
                st.strip(&pred);
                self.set_state(tid, ak, Some(st), Shred::Yes, true)?;
            }
        }
        Ok(())
    }

    /// For a paged state: loads the pages `bodies` touch, runs `rewrite` on them, then writes
    /// the skeleton with the undo buffer cleared, all shredded. `false`: not paged, or `rewrite`
    /// found it does not fit the pages (the caller writes whole).
    fn rewrite_bodies(&mut self, tid: &Tid, ak: &Ak, bodies: &[Fragment], rewrite: impl FnOnce(&mut Transaction<'_>, &mut pages::PageIndex, &mut Fragment, &[osis_crdt::PagedTouch]) -> Result<bool>) -> Result<bool> {
        self.load_lazy(tid, ak)?;
        let k = (*tid, ak.clone());
        let touches: Option<Vec<osis_crdt::PagedTouch>> = match self.core.pages.get(&k) {
            Some(idx) => bodies.iter().map(|d| pages::touch_of(d, Some(idx))).collect(),
            None => None,
        };
        let Some(touches) = touches else { return Ok(false) };
        for t in &touches {
            self.ensure_touch(tid, ak, &Some(t.clone()))?;
        }
        self.core.touch();
        self.core.wrote(k);
        let done = self.with_pages(tid, ak, |txn, idx, f| {
            if !rewrite(txn, idx, f, &touches)? {
                return Ok(false);
            }
            let mut unit = txn.get_aspect(tid, ak)?.unwrap_or_default();
            unit.state = pages::skeleton_unit(f, idx)?;
            unit.undo.clear();
            txn.put_aspect(tid, ak, &unit, Shred::Yes)?;
            Ok(true)
        })?;
        Ok(done == Some(true))
    }

    /// Takes the cached state of `(tid, ak)` out of the cache, to be written back (`set_state`
    /// notes it written first, so a failure evicts it).
    fn take_cached(&mut self, tid: &Tid, ak: &Ak) -> Option<Fragment> {
        self.core.states.get_mut(&(*tid, ak.clone())).and_then(Option::take)
    }

    pub fn unit(&mut self, tid: &Tid, ak: &Ak) -> Result<AspectUnit> {
        Ok(self.txn.get_aspect(tid, ak)?.unwrap_or_default())
    }

    /// Writes a commit record (`index::record_head`: received, origin, dropped parts; then its
    /// blob), and for a membership commit its `node/edges` row (`edges`: what the caller already
    /// read of `blob` with `edge_parts_of`, else decoded here).
    pub(crate) fn put_commit(&mut self, id: &CommitId, blob: &CommitBlob, meta: &Meta, shred: Shred, edges: Option<&crate::apply::validity::EdgeParts>) -> Result<()> {
        self.core.bodies.remove(id);
        self.core.mark_changed(*id);
        let v = [index::record_head(meta), blob.encode()].concat();
        self.txn.put_local(&records::commit_key(id), &v, shred)?;
        if meta.header.kind.is_membership() {
            // perm's reading of it, persisted beside the record (an open decodes no body)
            match edges {
                Some(p) => index::put_edges(self, id, p, shred)?,
                None => {
                    let p = crate::apply::edge_parts_of(self, id, &meta.header, blob.clone())?;
                    index::put_edges(self, id, &p, shred)?;
                }
            }
        }
        Ok(())
    }

    /// Removes a commit record (shredded) with what the index keeps beside it.
    pub fn remove_commit(&mut self, id: &CommitId) -> Result<()> {
        self.core.bodies.remove(id);
        self.txn.remove_local(&records::commit_key(id), Shred::Yes)?;
        index::remove_edges(self, id)
    }

    pub fn get_commit(&mut self, id: &CommitId) -> Result<Option<CommitBlob>> {
        let Some(v) = self.txn.get_local(&records::commit_key(id))? else { return Ok(None) };
        Ok(Some(decode_commit_record(&v)?.3))
    }

    /// Scans local records under `prefix` (keys returned without it).
    pub fn scan(&mut self, prefix: &[u8], mut f: impl FnMut(&[u8], Vec<u8>) -> Result<()>) -> Result<()> {
        let mut from: Vec<u8> = Vec::new();
        loop {
            let page = self.txn.scan_local(prefix, &from, SCAN_PAGE)?;
            let n = page.len();
            for (k, v) in page {
                let tail = k.get(prefix.len()..).unwrap_or_default();
                from = [tail, &[0]].concat();
                f(tail, v)?;
            }
            if n < SCAN_PAGE {
                return Ok(());
            }
        }
    }

    pub fn now(&self) -> WallMs {
        self.core.now()
    }
}

/// Rows read per store call by the scans.
const SCAN_PAGE: usize = 256;

/// Calls `f` on every row of table `t` from `start` up to `end` (exclusive), a page of rows
/// per store call.
pub(crate) fn scan_table(txn: &mut Transaction<'_>, t: osis_store::Table, start: &[u8], end: Option<&[u8]>, mut f: impl FnMut(Vec<u8>, Vec<u8>) -> Result<()>) -> Result<()> {
    let mut from = start.to_vec();
    loop {
        let rows = txn.table_range(t, &from, end, SCAN_PAGE)?;
        let n = rows.len();
        for (k, v) in rows {
            from = [k.as_slice(), &[0]].concat();
            f(k, v)?;
        }
        if n < SCAN_PAGE {
            return Ok(());
        }
    }
}

/// Removes every row of table `t` from `start` up to `end` (exclusive).
pub(crate) fn clear_table(txn: &mut Transaction<'_>, t: osis_store::Table, start: &[u8], end: &[u8], shred: Shred) -> Result<()> {
    loop {
        let rows = txn.table_range(t, start, Some(end), SCAN_PAGE)?;
        if rows.is_empty() {
            return Ok(());
        }
        for (k, _) in rows {
            txn.table_remove(t, &k, shred)?;
        }
    }
}

/// `(received, origin, dropped, blob)`.
pub(crate) fn decode_commit_record(v: &[u8]) -> Result<CommitRecord> {
    let (head, rest) = index::parse_head(v)?;
    let blob = CommitBlob::decode(rest).map_err(|_| Error::Corrupt("commit blob"))?;
    Ok((head.received, head.origin, head.dropped, blob))
}

/// One node's engine.
pub struct Engine {
    store: Store,
    store_rng: SeededRng,
    rng: Box<dyn CryptoRngCore + Send>,
    #[doc(hidden)]
    pub core: Core,
    clock: Arc<dyn Clock>,
    cfg: Config,
}

impl Engine {
    /// A new node over an empty backend: fresh identity, its node thing with `/created`,
    /// `/node` and `/keys` (spec/permissions.md §4 node card).
    pub fn create(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, cfg: Config, clock: Arc<dyn Clock>, mut rng: Box<dyn CryptoRngCore + Send>) -> Result<Engine> {
        let store = Store::create(backend, root, cfg.store, &mut *rng)?;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let store_rng = SeededRng::from_seed(seed);
        let id = Identity::generate(&mut *rng);
        let mut e = Engine { store, store_rng, rng, core: Core::new(id, clock.clone()), clock, cfg };
        let seed_bytes = e.core.id.seed().expose().to_vec();
        // a new store: its (empty) persisted index is current
        e.run(|tx| {
            tx.txn.put_local(records::SEED, &seed_bytes, Shred::No)?;
            index::write_all(tx)
        })?;
        e.bootstrap()?;
        Ok(e)
    }

    /// Opens an existing node and re-examines its pending commits.
    pub fn open(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, cfg: Config, clock: Arc<dyn Clock>, mut rng: Box<dyn CryptoRngCore + Send>) -> Result<Engine> {
        let mut store = Store::open(backend, root, cfg.store)?;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut store_rng = SeededRng::from_seed(seed);
        let s = {
            let mut txn = store.transaction(&mut store_rng)?;
            txn.get_local(records::SEED)?.ok_or(Error::Corrupt("no seed"))?
        };
        let s: [u8; 32] = s.as_slice().try_into().map_err(|_| Error::Corrupt("seed"))?;
        let id = Identity::from_seed(osis_crypto::Secret32::from_bytes(s));
        let mut e = Engine { store, store_rng, rng, core: Core::new(id, clock.clone()), clock, cfg };
        e.reload()?;
        e.reexamine()?;
        Ok(e)
    }

    /// The node thing's first commits: `/created` with `/node`, then `/keys` (its KEM key).
    fn bootstrap(&mut self) -> Result<()> {
        use osis_schema::core_types as ct;
        let node = self.tid();
        let mut m = Mutation::new();
        m.create(self.core.id.record().clone());
        m.set(node, &ct::NODE, &ct::NodeInfo { software: self.cfg.software.clone(), schemas: BTreeMap::new() })?;
        self.commit(m)?;
        let kem = self.core.id.keys().kem.public();
        let mut k = Mutation::new();
        k.set(node, &ct::KEYS, &ct::Keys { key: Some(ct::KemKey::X25519MlKem768(kem.as_bytes().to_vec())), ..Default::default() })?;
        self.commit(k)?;
        Ok(())
    }

    /// Registers an app schema: typed views for undo and default bounds for snapshots of its
    /// AKs (local writes through typed keys register theirs).
    pub fn register_schema(&mut self, s: Arc<osis_schema::Schema>) {
        self.core.schemas.insert(s.id, s);
    }

    /// A local record of the API layer (`osis`), never synced.
    pub fn app_record(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
        let k = [records::APP, name.as_bytes()].concat();
        self.run(|tx| Ok(tx.txn.get_local(&k)?))
    }

    /// Every key the store's current tree yields: what an attacker holding the device starts
    /// from. Shredding tests.
    #[doc(hidden)]
    pub fn forensic_keys(&mut self) -> Result<Vec<[u8; 32]>> {
        Ok(self.store.forensic_keys()?)
    }

    /// Writes a local record of the API layer.
    pub fn set_app_record(&mut self, name: &str, value: &[u8]) -> Result<()> {
        let k = [records::APP, name.as_bytes()].concat();
        self.run(|tx| Ok(tx.txn.put_local(&k, value, Shred::No)?))
    }

    /// Reports a diagnostic of the API layer (deduped and rate-limited like the engine's).
    pub fn report(&mut self, d: crate::events::Diagnostic) {
        let now = self.now();
        self.core.events.diagnostic(d, now);
    }

    /// The owner of `tid` (`None`: a key actor or an unknown thing).
    pub fn owner(&self, tid: &Tid) -> Option<Tid> {
        self.core.owner(tid)
    }

    /// This node's tid.
    pub fn tid(&self) -> Tid {
        self.core.id.tid()
    }

    pub fn identity(&self) -> &Identity {
        &self.core.id
    }

    /// The corrected wall clock.
    pub fn now(&self) -> WallMs {
        self.core.now()
    }

    /// About the bytes the pending commits' kept examinations hold (`apply::waits`).
    #[doc(hidden)]
    pub fn waits_bytes(&self) -> usize {
        self.core.waits.bytes()
    }

    /// The clock correction from node-sync (spec/sync.md §6).
    pub fn set_clock_offset(&mut self, ms: i64) {
        self.core.hlc.set_offset(ms);
        // pending commits were judged against the clock (drift, expiry)
        self.core.waits.clear();
    }

    /// A channel of engine events, sent after durability.
    pub fn subscribe(&mut self) -> Receiver<Event> {
        self.core.events.subscribe()
    }

    /// Installs node-sync's records (`Core::sync_records`).
    pub fn set_sync_records(&mut self, r: &'static dyn SyncRecords) {
        self.core.sync_records = Some(r);
    }

    /// What changed since the last call (`Core::changed`), keeping it from now on.
    pub fn take_changed(&mut self) -> Changed {
        self.core.changed.replace(Changed::default()).unwrap_or_default()
    }

    /// Runs `f` in one store transaction; events go out once it is durable.
    pub fn run<T>(&mut self, f: impl FnOnce(&mut Tx<'_>) -> Result<T>) -> Result<T> {
        let _s = crate::costs::span("tx");
        // changes made outside a transaction are not this one's to undo
        self.core.commit_journal();
        let stale_all = self.core.stale_all;
        let r = match self.store.transaction(&mut self.store_rng) {
            Ok(txn) => {
                let mut tx = Tx { txn, core: &mut self.core, rng: &mut *self.rng };
                // the persisted index follows the in-memory indexes in the same transaction
                let mut r = f(&mut tx);
                if r.is_ok() && tx.core.header_fault.load(std::sync::atomic::Ordering::Relaxed) {
                    r = Err(Error::Corrupt("commit record header"));
                }
                if r.is_ok() && !tx.core.defer_deaths && !tx.core.deaths_due.is_empty() {
                    r = r.and_then(|v| crate::retention::settle_due(&mut tx).map(|_| v));
                }
                // every validity change was judged before the index is persisted
                debug_assert!(r.is_err() || (tx.core.stale_things.is_empty() && tx.core.stale_commits.is_empty()), "stale validity left unjudged: {:?} {:?}", tx.core.stale_things, tx.core.stale_commits);
                let persisted = {
                    let _s = crate::costs::span("tx: persist index");
                    r.and_then(|v| index::persist(&mut tx).map(|_| v))
                };
                match persisted {
                    Ok(v) => {
                        let Tx { txn, .. } = tx;
                        let _s = crate::costs::span("tx: store commit");
                        txn.commit().map(|_| v).map_err(Error::from)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e.into()),
        };
        match r {
            Ok(v) => {
                if let Some(d) = self.core.walks_done.take() {
                    self.core.timelines.saved(d);
                }
                self.core.commit_journal();
                self.core.events.flush();
                Ok(v)
            }
            Err(e) => {
                self.core.walks_done = None;
                self.core.events.discard();
                self.core.rollback();
                self.core.stale_all = stale_all;
                Err(e)
            }
        }
    }

    /// A fresh `Core` loaded from the store (`rebuild`: ignoring the persisted index); whether
    /// it was rebuilt from the commit records.
    fn load_fresh(&mut self, rebuild: bool) -> Result<Option<Vec<(Tid, Ak)>>> {
        let id = Identity::from_seed(self.core.id.seed().clone());
        let mut fresh = Core::new(id, self.clock.clone());
        fresh.hlc = Hlc::new(self.clock.clone(), self.core.hlc.last());
        fresh.hlc.set_offset(self.core.hlc.offset());
        fresh.events = std::mem::take(&mut self.core.events);
        fresh.key_actors = std::mem::take(&mut self.core.key_actors);
        fresh.schemas = std::mem::take(&mut self.core.schemas);
        fresh.skip_writer_rules = self.core.skip_writer_rules;
        fresh.walk_cache_min = self.core.walk_cache_min;
        fresh.sync_records = self.core.sync_records;
        #[cfg(test)]
        {
            fresh.check_ingest = self.core.check_ingest;
        }
        self.core = fresh;
        let txn = self.store.transaction(&mut self.store_rng)?;
        let mut tx = Tx { txn, core: &mut self.core, rng: &mut *self.rng };
        let r = crate::apply::load(&mut tx, rebuild);
        self.core.commit_journal();
        r
    }

    /// Rebuilds every in-memory cache and index from the store (keeps identity, clock and
    /// subscribers).
    pub(crate) fn reload(&mut self) -> Result<()> {
        let rebuilt = match self.load_fresh(false) {
            Ok(r) => r,
            // a persisted index that does not decode is rebuilt from the commit records
            Err(Error::Corrupt(_)) => self.load_fresh(true)?,
            Err(e) => return Err(e),
        };
        if let Some(stale) = rebuilt {
            // states judged by other rules re-joined, then the index persisted for the next open
            self.run(|tx| {
                for (tid, ak) in &stale {
                    crate::apply::rejoin(tx, tid, ak)?;
                    // judged anew as after a validity flip (spec/crdt.md §4.8)
                    crate::retention::rejudge_deaths(tx, tid, ak)?;
                }
                index::write_all(tx)
            })?;
        } else if self.core.timelines.due(self.core.walk_cache_min) {
            // walks evaluated or continued at open saved for the next (a cache: a failure
            // leaves the open as it is)
            let _ = self.run(|_| Ok(()));
        }
        Ok(())
    }
}
