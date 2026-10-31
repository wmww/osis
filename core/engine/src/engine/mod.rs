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
mod testing;
pub mod write;

#[doc(hidden)]
pub use testing::{Carry, CommitDigest, IndexDigest, IndexField};
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
    /// Bytes of own ephemeral batches kept for undo (notes/ephemeral.md Bounds): older ones are
    /// not undoable.
    pub ephemeral_history: usize,
}

/// `Config::ephemeral_history` by default. Resource bound (notes/arbitrary-values.md), measured
/// by `Fragment::approx_bytes`: 0 nothing is undoable, infinity the log grows with every edit.
pub const DEFAULT_EPHEMERAL_HISTORY: usize = 16 << 20;

impl Default for Config {
    fn default() -> Config {
        Config { software: format!("osis-node {}", env!("CARGO_PKG_VERSION")), store: StoreConfig::default(), ephemeral_history: DEFAULT_EPHEMERAL_HISTORY }
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
    /// Aspects whose deltas were all dropped (purge, expiry, keep at most, compaction), with
    /// what each keeps: they count as held.
    pub dropped: BTreeMap<usize, Dropped>,
    /// Aspects none of whose deltas is held here (neither held nor dropped): a part that may
    /// still arrive late, or never, or one dropped under a cover since turned invalid
    /// (`retention::uncover`) (spec/permissions.md §5.2: a snapshot's copies of their writes
    /// count).
    pub missing: BTreeSet<usize>,
}

/// What a dropped part keeps in its commit record (spec/commits.md §5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dropped {
    /// The held valid snapshots that covered its body when it dropped: their copies of its
    /// writes are its writes (`apply::rebuild`); once none carries it, a part dropped as
    /// covered is missing again (`retention::uncover`).
    pub covered_by: BTreeSet<CommitId>,
    /// Dropped as covered (compaction, `Engine::drop_body`, with a coverer), not for its bounds,
    /// a purge or expiry: only these come back as missing.
    pub as_cover: bool,
    /// A compaction snapshot whose body had a write in the state when dropped (what it carried
    /// went with it; `retention::snapshot_live` starts from this).
    pub live: bool,
    /// A compaction snapshot dropped other than as covered (never with `as_cover`: a covered
    /// one's coverers reach them): the frontiers and `Absorbed` its body had (counters and IDs, no content), which count as received while the part is
    /// valid (`receipt::received`; indexed by `ix.dropped_snapshots`).
    pub gives: Option<Gives>,
    /// Its `rotation_role` and `grant_overreach` notes when it dropped: judgments the body made,
    /// kept so re-judging the part (and a rebuild) needs no body.
    pub role: Option<osis_base::Role>,
    pub overreach: bool,
    /// The epochs a membership `/keys` body keyed (`epoch_intro` candidates,
    /// `apply::keys::intro_epochs`): which commit introduced an epoch is a judgment the covers
    /// rule needs.
    pub intros: Vec<(osis_base::Role, osis_crypto::Epoch)>,
}

/// A snapshot part's frontiers and `Absorbed` (commit, author).
pub(crate) type Gives = (osis_crdt::Frontiers, Vec<(CommitId, Tid)>);

impl Meta {
    /// A commit's meta from its decoded header.
    pub(crate) fn new(header: Arc<Header>, valid: Vec<bool>, head: index::RecordHead, missing: BTreeSet<usize>) -> Meta {
        Meta { view: Arc::new(View::of(&header)), header: LazyHeader::ready(header), received: head.received, origin: head.origin, valid, dropped: head.dropped, missing }
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
        ephemeral: None,
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

/// Declares `Indexes` and its `Journaled` impl from one field list, so no journaled index can
/// be left out of commit or rollback.
macro_rules! indexes {
    ($($(#[$a:meta])* pub $f:ident: $t:ty,)*) => {
        /// `Core`'s journaled indexes (`journal`).
        #[doc(hidden)]
        #[derive(Default)]
        pub struct Indexes {
            $($(#[$a])* pub $f: $t,)*
        }

        impl Journaled for Indexes {
            fn commit(&mut self) {
                $(self.$f.commit();)*
            }
            fn rollback(&mut self) {
                $(self.$f.rollback();)*
            }
            #[cfg(test)]
            fn contents(&self) -> String {
                [$(format!("{} {}", stringify!($f), self.$f.contents()),)*].join("\n")
            }
        }
    };
}

indexes! {
    /// Perm inputs: applied membership commits, roster snapshots, `/created` records.
    pub held: held::Held,
    pub commits: JMap<CommitId, Meta>,
    /// Commits with a part invalid here, per aspect (`Core::index_validity`), so a join finds the
    /// writes to strip in O(invalid parts), not O(history).
    pub invalid: JSetMap<(Tid, Ak), CommitId>,
    /// Held deltas per aspect: (`ts`, commit).
    pub by_aspect: JSetMap<(Tid, Ak), (Ts, CommitId)>,
    /// Held imports per thing and origin: (thing, origin) -> import: the deltas owning the
    /// origin's writes there (spec/permissions.md §7).
    pub imports: JSetMap<(Tid, CommitId), CommitId>,
    /// Compaction snapshots held per aspect, with their frontiers and `Absorbed`: the bodies
    /// carrying a write besides its own (deaths, spec/commits.md §5); what valid ones count as
    /// received (`receipt::received`).
    pub snapshots: JMap<(Tid, Ak), Vec<HeldSnapshot>>,
    /// Snapshots per aspect whose dropped part kept its frontiers (`Dropped::gives`; derived at
    /// open, not persisted).
    pub dropped_snapshots: JSetMap<(Tid, Ak), CommitId>,
    /// Writes held snapshots carry whose own delta was never received, per aspect
    /// (`validity::Carried`).
    pub carried: JMap<(Tid, Ak), Vec<crate::apply::validity::Carried>>,
    /// Held commits per thing they hold a delta of (re-judging a thing's deltas).
    pub by_thing: JSetMap<Tid, CommitId>,
    /// The commits whose header lists each chunk blob (`View::chunks`).
    pub by_chunk: JSetMap<osis_base::BlobId, CommitId>,
    /// Node-form ranges per (tid, ak, node): lo -> (hi, commit).
    pub ranges: JNested<(Tid, Ak, Tid), u64, (u64, CommitId)>,
    pub pending: JMap<CommitId, Reason>,
    pub syncing: JSet<Tid>,
    pub void: JSet<CommitId>,
    /// Deltas whose value-carrying writes are held value-less (expired, purged).
    pub valueless: JMap<(Tid, Ak), Vec<Owned>>,
    /// Actors with secrets of their own whose epochs this node holds.
    pub secrets: JMap<Tid, ActorEpochs>,
    /// Things with secrets of their own here (`apply::keys::refresh_own_keys`): a held commit's
    /// valid `/keys` part wrote a keyset.
    pub own_keys: JSet<Tid>,
    /// Held commits whose `/keys` part on a thing wrote a keyset in its body, any validity
    /// (`records::OWN_KEYS`): thing -> commits.
    pub keyset_parts: JSetMap<Tid, CommitId>,
    /// Things with a `/label` delta held (`Engine::labeled_groups`).
    pub labeled: JSet<Tid>,
    /// Admin and write delete keys of things an inbox payload named (`[admin, write]` bytes),
    /// listed until their `/keys` arrives (spec/crypto.md §7, spec/wire.md §9): taken only from
    /// a commit that applied valid, by an admin of the thing, touching it; the first kept.
    pub delete_hints: JMap<Tid, osis_base::Value>,
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
    /// Roles `/secrets` and `/keys` deltas need (by commit and aspect index).
    pub rotation_role: JMap<(CommitId, usize), osis_base::Role>,
    /// `/secrets` parts of membership commits that write beyond their grantees' boxes (an invite
    /// grant may carry only those, spec/permissions.md §2).
    pub grant_overreach: JSet<(CommitId, usize)>,
    /// Keyed boxes per member: member -> (actor, box key), from `/secrets` entries seen.
    pub boxes_to: JSetMap<Tid, (Tid, osis_base::Value)>,
    /// The earliest valid held commit writing an epoch's keyset in `/keys` (its rotation):
    /// (actor, role, epoch) -> (`ts`, author node, actor acted for, commit). Absent: the
    /// introducer is unknown (`rotation`).
    pub epoch_intro: EpochIntro,
    /// The earliest noted commit writing a box: (actor, box key) -> its `ts`.
    pub box_written: JMap<(Tid, osis_schema::core_types::BoxKey), Ts>,
    /// The lost-access trigger's work list (`rotation::lost::LOST_DUE`).
    pub lost_due: JSet<Tid>,
    /// Aspects whose deaths wait for a recompute (`records::DEATHS_DUE`).
    pub deaths_due: JSet<(Tid, Ak)>,
    /// `rotation::departures` per actor with the time it holds until (an edge's `until`, a
    /// write's future `ts`); cleared by `membership_changed`.
    pub departures: JMap<Tid, (Vec<osis_keys::Departure>, Option<WallMs>)>,
    /// Hints of opened inbox payloads whose commit has not applied yet (not persisted).
    pub hint_candidates: JMap<CommitId, Vec<(Tid, osis_base::Value)>>,
    /// Things a roster snapshot of which was kept out of perm for a linked frontier not held
    /// here (`validity::add_membership`): no roster snapshot of them is written.
    pub frontier_unknown: JSet<Tid>,
}

/// A held compaction snapshot of an aspect: `ts`, ID, frontiers, `Absorbed` (commit, author).
pub(crate) type HeldSnapshot = (Ts, CommitId, osis_crdt::Frontiers, Vec<(CommitId, Tid)>);

/// A decoded commit record: its head (received, origin, dropped parts) and blob.
pub(crate) type CommitRecord = (index::RecordHead, CommitBlob);

/// In-memory state over the store: caches and indexes, rebuilt by `load`. The indexes are
/// journaled (`journal`): a failed transaction undoes its own changes to them.
#[doc(hidden)]
pub struct Core {
    /// The journaled indexes: a failed transaction undoes its own changes to them.
    pub ix: Indexes,
    pub id: Identity,
    pub hlc: Hlc,
    pub states: HashMap<(Tid, Ak), Option<Fragment>>,
    /// Page indexes of the cached states kept paged in the store.
    pub pages: HashMap<(Tid, Ak), pages::PageIndex>,
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
    /// Pending commits waiting for a record or for deltas, with what their examination read
    /// (`apply::waits`): `reexamine` leaves out those whose inputs did not change. A cache:
    /// dropped by a rollback that changed anything.
    pub(crate) waits: crate::apply::Waits,
    /// What validity may have changed for since the last `rejudge_all`: things whose timeline
    /// changed, commits whose other inputs changed (void, required roles, overreach), or
    /// everything (a rebuild at open).
    pub stale_things: BTreeSet<Tid>,
    pub stale_commits: BTreeSet<CommitId>,
    pub stale_all: bool,
    /// Linked tenure frontiers decoded (by link content hash) with their canonical size; content
    /// addressed, so never stale.
    pub frontiers: BTreeMap<[u8; 32], (Arc<osis_perm::Frontier>, usize)>,
    /// Schemas registered or written with here (`records::SCHEMAS`): typed views for undo and
    /// large-value write-back, also after a restart (snapshots need none).
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
    /// Deaths recomputes wait for `Engine::settle_deaths` instead of ending each transaction
    /// (node-sync, within a step).
    pub defer_deaths: bool,
    /// No keep-at-most drop (tests: an oracle holding every body, `Engine::keep_bodies`).
    pub keep_bodies: bool,
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
    /// Held snapshots' writes by dot (`validity::differing_copies`: deltas arriving after
    /// snapshots that copied their writes compare against it; `validity::vouched`). A snapshot never changes, so
    /// entries never go stale; all go past `COPY_CACHE_MAX` writes.
    pub copy_index: BTreeMap<(CommitId, Tid, Ak), Arc<osis_crdt::CopyIndex>>,
    /// Bumped whenever a transaction changes the indexes or a state, rolls back, or the caches
    /// reload (it never goes back): caches derived from them (the sync engine's) compare it.
    pub generation: u64,
    /// `Engine::labels_of` per group: dropped when its `/label` state is written (`wrote`) and
    /// on rollback.
    pub(crate) labels: BTreeMap<Tid, Vec<std::sync::Arc<crate::labeling::GroupLabel>>>,
    /// `Engine::published_under` for every actor, with the counts it was taken at (held
    /// records, `own_keys`, `labeled`).
    pub(crate) published: Option<Published>,
    /// `Engine::held_links`: dropped when a `/link/seed` state or index entry changes and on
    /// rollback.
    pub(crate) links: Option<std::sync::Arc<Vec<crate::flows::HeldLink>>>,
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
    /// Commits with a part dropped under a cover since turned invalid, missing again
    /// (`retention::uncover`): node-sync fetches its entries again.
    pub undropped: BTreeSet<CommitId>,
}

impl Changed {
    pub fn is_empty(&self) -> bool {
        self.commits.is_empty() && self.aspects.is_empty() && self.undropped.is_empty()
    }
}

/// (actor, role, epoch) -> the commit that introduced it: (ts, author node, actor, commit ID).
pub(crate) type EpochIntro = JMap<(Tid, osis_base::Role, osis_crypto::Epoch), (Ts, Tid, Tid, CommitId)>;

impl Core {
    /// The held aspects of `t` and their commits (a range of `by_aspect`).
    pub fn aspects_of(&self, t: &Tid) -> impl Iterator<Item = (&(Tid, Ak), &std::collections::BTreeSet<(Ts, CommitId)>)> {
        let t = *t;
        self.ix.by_aspect.range((t, Ak::MIN)..).take_while(move |((x, _), _)| *x == t)
    }

    /// Drops what is derived from rosters, `/secrets` and held epochs (the departures cache):
    /// called wherever those change.
    pub fn membership_changed(&mut self) {
        if !self.ix.departures.is_empty() {
            self.ix.departures.retain(|_, _| false);
        }
    }

    /// Re-evaluates the timelines around the things whose held inputs changed; the things of
    /// changed timelines wait for `rejudge_all`.
    pub fn update_timelines(&mut self) {
        let _s = crate::costs::span("timelines");
        let touched = self.ix.held.take_touched();
        if !touched.is_empty() {
            let changed = self.timelines.update_touched(&self.ix.held, &touched);
            self.stale_things.extend(changed.evaluated);
            // a walk that only went on changed authority only below what it touched
            let below = self.ix.held.reach(&changed.extended);
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
        let commits = &self.ix.commits;
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
        if k.1.as_str() == crate::flows::LINK_SEED {
            self.links = None;
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
        self.ix.commit();
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
            self.links = None;
            for k in std::mem::take(&mut self.written) {
                self.states.remove(&k);
                self.pages.remove(&k);
            }
        }
        self.ix.rollback();
        // the timelines follow the restored held set; validity flags are restored with `commits`
        let touched = self.ix.held.take_touched();
        if !touched.is_empty() {
            self.timelines.update_touched(&self.ix.held, &touched);
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
            timelines: Timelines::new(),
            walk_cache_min: index::WALK_CACHE_MIN,
            walks_done: None,
            stale_things: BTreeSet::new(),
            stale_commits: BTreeSet::new(),
            stale_all: true,
            dirty: false,
            key_salt,
            ix: Indexes::default(),
            waits: crate::apply::Waits::default(),
            frontiers: BTreeMap::new(),
            schemas: BTreeMap::new(),
            events: Events::default(),
            written: Vec::new(),
            skip_writer_rules: false,
            header_fault: Arc::default(),
            #[cfg(test)]
            check_ingest: false,
            key_actors: BTreeMap::new(),
            defer_deaths: false,
            keep_bodies: false,
            changed: None,
            sync_records: None,
            live_trees: BTreeMap::new(),
            bodies: BTreeMap::new(),
            live_bodies: BTreeMap::new(),
            copy_index: BTreeMap::new(),
            generation: 0,
            labels: BTreeMap::new(),
            published: None,
            links: None,
        }
    }

    pub fn now(&self) -> WallMs {
        self.hlc.wall()
    }

    /// Re-indexes which parts of commit `id` are invalid here (call after setting `Meta::valid`).
    pub fn index_validity(&mut self, id: &CommitId) {
        let Some(m) = self.ix.commits.get(id) else { return };
        for (ai, a) in m.view.aspects.iter().enumerate() {
            let k = (a.tid, a.ak.clone());
            if m.valid.get(ai).copied().unwrap_or(false) {
                self.ix.invalid.remove(&k, id);
            } else {
                self.ix.invalid.insert(k, *id);
            }
        }
    }

    /// The commit that wrote dot `d` on `(tid, ak)`, if held.
    pub fn commit_of(&self, tid: &Tid, ak: &Ak, d: &Dot) -> Option<CommitId> {
        let d = d.owner();
        match d.src.kind() {
            SourceKind::Commit(c) => Some(*c),
            SourceKind::Node(n) => {
                let m = self.ix.ranges.get(&(*tid, ak.clone(), *n))?;
                let (_, (hi, c)) = m.range(..=d.ctr).next_back()?;
                (d.ctr < *hi).then_some(*c)
            }
            SourceKind::Session(_) | SourceKind::Derived(_) => None,
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
            Some(u) if pages::is_paged(&u.state) => {
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

    /// Loads what `ops` on `(tid, ak)` read: the `paths` they address, else (ops by index into
    /// paged sequences, `edits`) the pages they attach to through the stored placements
    /// (`pages::attach_ops`), else the whole state. Whether they attached (`run_attached`).
    pub(crate) fn load_for_ops(&mut self, tid: &Tid, ak: &Ak, paths: Option<Vec<Vec<osis_crdt::PathSeg>>>, ops: &[osis_crdt::PathOp], edits: &[Option<large::ListEdit>]) -> Result<bool> {
        if let Some(paths) = paths {
            self.ensure_paths(tid, ak, &paths)?;
            return Ok(false);
        }
        self.load_lazy(tid, ak)?;
        if self.held_in_part(tid, ak) && self.with_pages(tid, ak, |txn, idx, f| pages::attach_ops(txn, tid, ak, idx, f, ops, edits))? == Some(true) {
            return Ok(true);
        }
        self.load(tid, ak)?;
        Ok(false)
    }

    /// `run` on the state of `(tid, ak)` as loaded; if the ops `attached` (`load_for_ops`), run
    /// again while it missed rows, chunks or pages (what it missed loaded, `pages::absorb`), at
    /// most `OP_RUNS` times, then on the whole state.
    pub(crate) fn run_attached<R>(&mut self, tid: &Tid, ak: &Ak, attached: bool, run: impl Fn(&Tx<'_>) -> R) -> Result<R> {
        let mut out = run(self);
        if !attached {
            return Ok(out);
        }
        for runs in 1.. {
            let more = self.with_pages(tid, ak, |txn, idx, f| pages::absorb(txn, tid, ak, idx, f))?.flatten();
            if more == Some(false) {
                break;
            }
            let whole = more.is_none() || runs >= pages::OP_RUNS;
            if whole {
                if more.is_some() {
                    let _s = crate::costs::span("paged op whole: runs");
                }
                self.load(tid, ak)?;
            }
            out = run(self);
            if whole {
                break;
            }
        }
        Ok(out)
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

    /// Writes a commit record (`index::record_head`: received, origin, dropped parts and what
    /// they keep; then its blob), and for a membership commit its `node/edges` row (`edges`: what the caller already
    /// read of `blob` with `edge_parts_of`, else decoded here).
    pub(crate) fn put_commit(&mut self, id: &CommitId, blob: &CommitBlob, meta: &Meta, shred: Shred, edges: Option<&crate::apply::validity::EdgeParts>) -> Result<()> {
        // a part is held, dropped or missing: never both of the last two (an open derives
        // missing as neither in the blob nor dropped)
        debug_assert!(meta.dropped.keys().all(|ai| !meta.missing.contains(ai)), "{id:?}: parts both dropped and missing: dropped {:?} missing {:?}", meta.dropped, meta.missing);
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
        Ok(Some(decode_commit_record(&v)?.1))
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

/// `(head, blob)`.
pub(crate) fn decode_commit_record(v: &[u8]) -> Result<CommitRecord> {
    let (head, rest) = index::parse_head(v)?;
    let blob = CommitBlob::decode(rest).map_err(|_| Error::Corrupt("commit blob"))?;
    Ok((head, blob))
}

/// One node's engine.
pub struct Engine {
    store: Store,
    store_rng: SeededRng,
    pub(crate) rng: Box<dyn CryptoRngCore + Send>,
    #[doc(hidden)]
    pub core: Core,
    /// Ephemeral things and aspects, in memory (`crate::ephemeral`).
    pub(crate) eph: crate::ephemeral::Eph,
    clock: Arc<dyn Clock>,
    pub(crate) cfg: Config,
}

/// A new session of node `node` for this open's ephemeral writes (spec/crdt.md §2.1).
fn session(node: Tid, rng: &mut dyn CryptoRngCore) -> crate::ephemeral::Eph {
    let mut nonce = [0u8; osis_crdt::SESSION_NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    crate::ephemeral::Eph::new(osis_crdt::Session { node, nonce })
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
        let eph = session(id.tid(), &mut *rng);
        let mut e = Engine { store, store_rng, rng, core: Core::new(id, clock.clone()), eph, clock, cfg };
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
        let eph = session(id.tid(), &mut *rng);
        let mut e = Engine { store, store_rng, rng, core: Core::new(id, clock.clone()), eph, clock, cfg };
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

    /// Registers an app schema: typed views of its AKs for undo and large-value write-back
    /// (local writes through typed keys register theirs). Kept in the store: an open
    /// knows every schema registered before.
    pub fn register_schema(&mut self, s: Arc<osis_schema::Schema>) -> Result<()> {
        self.run(|tx| crate::engine::write::keep_schema(tx, &s, true))
    }

    /// A local record of the API layer (`osis`), never synced.
    pub fn app_record(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
        let k = [records::APP, name.as_bytes()].concat();
        self.run(|tx| Ok(tx.txn.get_local(&k)?))
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
        self.core.owner(tid).or_else(|| match &self.ephemeral_thing(tid)?.record {
            osis_base::CreationRecord::Thing { owner, .. } => Some(*owner),
            osis_base::CreationRecord::KeyActor { .. } => None,
        })
    }

    /// `tid`, then its owners up the chain: at most `MAX_OWNER_DEPTH` owner links
    /// (spec/permissions.md §1), so a cycle ends too.
    pub fn owner_chain(&self, tid: &Tid) -> impl Iterator<Item = Tid> + '_ {
        std::iter::successors(Some(*tid), |t| self.owner(t)).take(osis_base::format::MAX_OWNER_DEPTH + 1)
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

    /// `subscribe` without `Event::Ephemeral`.
    pub fn subscribe_durable(&mut self) -> Receiver<Event> {
        self.core.events.subscribe_durable()
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
                if r.is_ok() && !tx.core.defer_deaths && !tx.core.ix.deaths_due.is_empty() {
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
        fresh.skip_writer_rules = self.core.skip_writer_rules;
        fresh.walk_cache_min = self.core.walk_cache_min;
        fresh.sync_records = self.core.sync_records;
        // caches keyed on it (the sync engine's labels and co-readers) never see an old value again
        fresh.generation = self.core.generation.wrapping_add(1);
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
    /// subscribers; tests call it for what an open reads).
    #[doc(hidden)]
    pub fn reload(&mut self) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::journal::Journaled;
    use crate::local_peer::{LocalPeer, Peer};
    use crate::Mutation;
    use osis_base::{Ak, Role, Tid, Value, WallMs};
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_schema::core_types as ct;
    use osis_schema::Codec;

    fn digest(p: &Peer) -> String {
        // headers decoded alike (decoding is a cache, not undone)
        p.engine.core.ix.commits.values().for_each(|m| drop(m.header.decoded()));
        format!("{}\n{}", p.engine.core.ix.contents(), p.engine.perm_digest(false))
    }

    /// Runs `f` with the store's next write failing and checks that every journaled index is as
    /// it was (counting the failures in `failed`), then reopens the store (a failed write
    /// leaves it broken) and runs `f` again.
    fn failing<T>(p: &mut Peer, failed: &mut usize, mut f: impl FnMut(&mut super::Engine) -> crate::Result<T>) -> T {
        let before = digest(p);
        p.backend.faults().at(0, osis_store::Fault::Fail);
        let r = f(&mut p.engine);
        p.backend.faults().revive();
        match r {
            Ok(v) => v,
            Err(_) => {
                *failed += 1;
                assert_eq!(digest(p), before, "a failed transaction changed the indexes");
                p.restart(*failed as u64).unwrap();
                f(&mut p.engine).unwrap()
            }
        }
    }

    fn member(t: Tid, m: Tid, role: Option<Role>) -> Mutation {
        let (path, op) = match role {
            Some(role) => (vec![PathSeg::Key(Value::Tid(m))], Op::Set(ct::Edge { role, until: None, invite: None, since: None, tied: None }.to_value())),
            None => (Vec::new(), Op::Remove(Value::Tid(m))),
        };
        let mut mu = Mutation::new();
        mu.op(t, &ct::MEMBERS, PathOp { path, op }).unwrap();
        mu
    }

    fn write(m: &mut Mutation, t: Tid, v: &str) {
        m.set(t, &Ak::new("/t/reg").unwrap(), &Value::Str(v.into())).unwrap();
    }

    // spec/commits.md §4 (one storage transaction per commit): a transaction whose store commit
    // fails leaves every journaled index (`Indexes`) and the timelines as they were, for local
    // commits and for received ones, applied or pending.
    #[test]
    fn failed_transaction_restores_indexes_spec_commits_4() {
        let mut lp = LocalPeer::new(3, 951, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a, b, c) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        let mut failed = 0;
        let new_thing = |e: &mut super::Engine, owner: Tid| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, owner);
            write(&mut m, t, "new");
            e.commit(m).map(|_| t)
        };
        let g = failing(&mut lp.peers[0], &mut failed, |e| new_thing(e, a));
        failing(&mut lp.peers[0], &mut failed, |e| e.commit(member(g, b, Some(Role::Write))));
        failing(&mut lp.peers[0], &mut failed, |e| e.commit(member(g, c, Some(Role::Admin))));
        lp.sync(0, 1).unwrap();
        lp.advance(1_000);
        failing(&mut lp.peers[1], &mut failed, |e| {
            let mut m = Mutation::new();
            write(&mut m, g, "b");
            e.commit(m)
        });
        lp.sync(1, 0).unwrap();
        lp.advance(1_000);
        failing(&mut lp.peers[0], &mut failed, |e| new_thing(e, g));
        failing(&mut lp.peers[0], &mut failed, |e| e.commit(member(g, b, None)));
        // received in reverse: most wait for what they depend on, then apply together
        let mut pks = lp.packages(0).unwrap();
        pks.reverse();
        for pk in &pks {
            failing(&mut lp.peers[2], &mut failed, |e| e.ingest(&pk.bytes, pk.blobs.clone()));
        }
        assert!(failed >= 6 + pks.len() / 2, "{failed} of {} failed", 6 + pks.len());
        assert_eq!(lp.peers[2].engine.core.ix.commits.len(), lp.peers[0].engine.core.ix.commits.len());
        assert!(lp.peers[2].engine.core.ix.pending.is_empty());
    }

    // spec/commits.md §4, §5: the same for compaction, keep-at-most drops and expiry by `tick`,
    // deferred death replays, a commit received a part at a time, and delete-key hints (a
    // failed promotion keeps its candidate).
    #[test]
    fn failed_transaction_restores_indexes_retention_spec_commits_4() {
        use osis_schema::{Bound, PurgeBy, Retention};
        let mut lp = LocalPeer::new(3, 952, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a, b) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let (reg, kept) = (Ak::new("/t/reg").unwrap(), Ak::new("/t/kept").unwrap());
        let mut failed = 0;
        let g = failing(&mut lp.peers[0], &mut failed, |e| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a);
            write(&mut m, t, "new");
            e.commit(m).map(|_| t)
        });
        failing(&mut lp.peers[0], &mut failed, |e| e.commit(member(g, b, Some(Role::Write))));
        lp.sync(0, 1).unwrap();
        lp.advance(10);
        // an older write by 1, delivered last: a replay of the aspect's deaths
        let mut m = Mutation::new();
        m.set(g, &kept, &Value::Str("v".into())).unwrap();
        let v = lp.peers[1].commit(m).unwrap().unwrap();
        lp.advance(10);
        let keep0 = Retention { by: PurgeBy::Writer, at_least: Bound::default(), at_most: Bound { abs: None, rel: Some(0) } };
        let now = lp.peers[0].engine.now();
        let two = failing(&mut lp.peers[0], &mut failed, |e| {
            // two aspects: received a part at a time below; one expires
            let mut m = Mutation::new();
            m.retention(g, &kept, keep0).unwrap();
            m.set(g, &kept, &Value::Str("w".into())).unwrap();
            write(&mut m, g, "w");
            m.expires(g, &reg, WallMs(now.0 + 60_000)).unwrap();
            e.commit(m).map(Option::unwrap)
        });
        lp.advance(10);
        failing(&mut lp.peers[0], &mut failed, |e| {
            let mut m = Mutation::new();
            m.set(g, &kept, &Value::Str("y".into())).unwrap();
            e.commit(m)
        });
        failing(&mut lp.peers[0], &mut failed, |e| e.snapshot(&g, &reg));
        let vpk = lp.packages(1).unwrap().into_iter().find(|p| p.id == v).unwrap();
        failing(&mut lp.peers[0], &mut failed, |e| e.ingest(&vpk.bytes, vpk.blobs.clone()));
        // peer 2: the two-aspect commit's parts one at a time, the rest with deaths deferred
        let pks = lp.packages(0).unwrap();
        let tpk = pks.iter().find(|p| p.id == two).unwrap().clone();
        let blob = osis_commit::CommitBlob::decode(&tpk.bytes).unwrap();
        let first = osis_commit::rewrite(&blob, |ai, _| ai != 0).encode();
        failing(&mut lp.peers[2], &mut failed, |e| e.defer_deaths(true));
        for pk in pks.iter().filter(|p| p.id != two) {
            failing(&mut lp.peers[2], &mut failed, |e| e.ingest(&pk.bytes, pk.blobs.clone()));
        }
        failing(&mut lp.peers[2], &mut failed, |e| e.ingest(&first, tpk.blobs.clone()));
        failing(&mut lp.peers[2], &mut failed, |e| e.ingest(&tpk.bytes, tpk.blobs.clone()));
        failing(&mut lp.peers[2], &mut failed, |e| e.ingest(&vpk.bytes, vpk.blobs.clone()));
        failing(&mut lp.peers[2], &mut failed, |e| e.defer_deaths(false));
        // past the grace and the expiry: drops and expiry run on both
        lp.advance(2 * 3_600_000);
        for i in [0, 2] {
            failing(&mut lp.peers[i], &mut failed, |e| e.tick());
        }
        let s = failing(&mut lp.peers[0], &mut failed, |e| e.snapshot(&g, &kept)).unwrap();
        let spk = lp.peers[0].engine.package(&s).unwrap().unwrap();
        failing(&mut lp.peers[2], &mut failed, |e| e.ingest(&spk.bytes, spk.blobs.clone()));
        assert!(failed >= 12, "{failed} failed");
        assert_eq!(lp.peers[2].engine.get(&g, &kept).unwrap(), lp.peers[0].engine.get(&g, &kept).unwrap());
        assert!(lp.peers[2].engine.core.ix.pending.is_empty());
    }

    // spec/wire.md §9: a transaction that promotes delete-key hints and then fails (here by an
    // error, which leaves the store usable: no reopen drops the candidates) keeps them.
    #[test]
    fn failed_promotion_keeps_hint_candidates_spec_wire_9() {
        let mut lp = LocalPeer::new(2, 953, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let a = lp.peers[0].engine.tid();
        let mut m = Mutation::new();
        let g = lp.peers[0].engine.new_thing(&mut m, a);
        write(&mut m, g, "new");
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let dk = osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([7; 32])).verifying_key();
        let hint = osis_label::InboxThing { tid: g, label: osis_base::LabelId([0; 16]), index: 0, servers: Vec::new(), delete_keys: Some((dk, dk)) };
        let e = &mut lp.peers[1].engine;
        e.note_delete_hints(c, &[hint]).unwrap();
        assert_eq!(e.core.ix.hint_candidates.len(), 1);
        lp.sync(0, 1).unwrap();
        let e = &mut lp.peers[1].engine;
        assert!(!e.core.ix.delete_hints.contains_key(&g) && !e.core.ix.own_keys.contains(&g));
        let r: crate::Result<()> = e.run(|tx| {
            tx.core.promote_hints();
            assert!(tx.core.ix.delete_hints.contains_key(&g));
            Err(crate::Error::Misuse("fails after promoting"))
        });
        assert!(r.is_err());
        assert!(!e.core.ix.delete_hints.contains_key(&g));
        assert_eq!(e.core.ix.hint_candidates.len(), 1, "the candidate went with the failed transaction");
        e.run(|tx| {
            tx.core.promote_hints();
            Ok(())
        })
        .unwrap();
        assert!(e.core.ix.delete_hints.contains_key(&g));
    }
}
