//! The engine: one node's local state over its `Store` (notes/architecture.md §2: the node
//! talks to `Store` only). Synchronous, no I/O of its own, time from a `Clock`, randomness
//! injected. Every mutating call runs in one store transaction; engine events are sent after
//! it is durable. A failed transaction undoes its changes to the in-memory indexes (`journal`)
//! and evicts the states it wrote.

pub(crate) mod acting;
pub(crate) mod blobs;
pub(crate) mod clock;
pub(crate) mod groups;
pub(crate) mod held;
pub mod listing;
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
pub use testing::{CommitDigest, IndexDigest, IndexField};
pub use large::LiveTrees;
pub use write::Mutation;

use crate::apply::Reason;
use crate::error::{Error, Result};
use crate::events::{Event, Events, Origin};
use crate::identity::Identity;
use clock::Hlc;
use osis_commit::{CommitBlob, Form, Header};
use osis_base::{Ak, Clock, CommitId, LabelId, Tid, Ts, WallMs};
use osis_crdt::{Dot, Fragment, SourceKind};
use osis_crypto::{CryptoRngCore, SeededRng};
use osis_keys::ActorEpochs;
use journal::{JMap, JNested, JSet, JSetMap, Journaled};
use osis_perm::{Point, Timelines};
use osis_store::{AspectUnit, Backend, RootStorage, Shred, Store, StoreConfig, Transaction};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::mpsc::Receiver;

/// Engine configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// `node.0` software version.
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
    /// Aspects whose deltas were all dropped (as covered, expired or purged), with
    /// what each keeps.
    pub dropped: BTreeMap<usize, Dropped>,
    /// Aspects held as their leftover (expired, purged, a body carrying a copy of such a value:
    /// `retention::make_leftover`, `retention::strip_carried`): read from `records::LEFTOVER` as
    /// the body. Held for the engine, no body for node-sync (`body_gone`).
    pub stripped: BTreeSet<usize>,
    /// Those of `stripped` held as their leftover only for the copies they carry, none of their own
    /// writes value-less (a snapshot, which has none, always). Such a leftover is a body like a
    /// whole one for keep bounds, covering and a purge naming it (`bare`;
    /// spec/commits.md §5 Dropping a body).
    pub valued: BTreeSet<usize>,
    /// Aspects none of whose deltas is held here (neither held nor dropped): a part that may
    /// still arrive late, or never, or one dropped under a cover since turned invalid
    /// (`retention::uncover`) (spec/permissions.md §5.2: a snapshot's copies of their writes
    /// count).
    pub missing: BTreeSet<usize>,
}

/// Why a part dropped, where that decides whether it can come back.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DropFor {
    /// For its bounds or expiry.
    #[default]
    Other,
    /// As covered (compaction, `Engine::drop_body`, with a coverer): it comes back as missing once
    /// no coverer carries it.
    Cover,
    /// While invalid, at the end of the transaction that judged it (`retention::drop_invalid`):
    /// it comes back as missing when it turns valid (`retention::valid_again`).
    Invalid,
}

/// What a dropped part keeps in its commit record (spec/commits.md §5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dropped {
    /// The held valid snapshots that covered its body when it dropped: their copies of its
    /// writes are its writes (`apply::rebuild`); once none carries it, a part dropped as
    /// covered is missing again (`retention::uncover`).
    pub covered_by: BTreeSet<CommitId>,
    pub why: DropFor,
    /// A compaction snapshot's part dropped other than as covered, held then or not: it still
    /// settles suspect flags (`receipt::settled`; indexed by `ix.dropped_snapshots`). One dropped
    /// as covered does not need to: a coverer is valid and stamped no earlier, so it settles all
    /// it did.
    pub stands_in: bool,
    /// Its `rotation_role` and `grant_overreach` notes when it dropped: judgments the body made,
    /// kept so re-judging the part (and a rebuild) needs no body.
    pub role: Option<osis_base::Role>,
    pub overreach: bool,
    /// The keysets a `keys.0` body wrote (`apply::keys::keysets_of`): a role commit's are
    /// `epoch_intro` candidates; every valid one's are held keysets (`keysets`, spec/crypto.md
    /// §4), and an invalid one's held invalid.
    pub keysets: Vec<KeysetRec>,
    /// What a role commit's `secrets.0` body showed for possession (`Indexes::shown`).
    pub shown: Option<Arc<Showing>>,
}

/// What a role commit's `secrets.0` part shows for possession (spec/crypto.md §4, Holder
/// actors), read from its bodies (`validity::note_required`): whether it rotates (its commit
/// writes a keyset of the actor, or it writes more than entries), the boxes it removes, and what
/// each box to a holder names and signs. A judgment of the body
/// alone; the keysets that verify it and the roles it is judged by are read when judging.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Showing {
    pub rotates: bool,
    /// (holder, role) of each box it removes.
    pub removed: Vec<(Tid, osis_base::Role)>,
    pub shown: Vec<osis_keys::possession::Shown>,
}

impl Dropped {
    pub(crate) fn as_cover(&self) -> bool {
        self.why == DropFor::Cover
    }
}

/// A keyset a `keys.0` body wrote: its role, epoch, the epochs its supersedes list names, its
/// KEM public key (`None`: another suite, or malformed: never sealed to) and its possession key
/// (`None`: malformed: verifies nothing).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeysetRec {
    pub role: osis_base::Role,
    pub epoch: osis_crypto::Epoch,
    pub lists: Vec<osis_crypto::Epoch>,
    pub kem: Option<Vec<u8>>,
    pub possession: Option<[u8; 32]>,
    /// The digest of the rotation's names it publishes (spec/crypto.md §4).
    pub names: osis_keys::NamesDigest,
}

/// A held valid keyset (`Indexes::keysets`): the epochs the supersedes lists of the bodies
/// writing it name, joined, its KEM key (the first such body's of suite 1 noted), and the
/// possession keys those bodies publish, joined (any of them verifies a possession signature,
/// spec/crypto.md §4: a body other than the keyset's rotation is a forgery, within its limit),
/// and the names digests they publish, each with its body's author (what binds a history entry
/// to a rotator, spec/crypto.md §4: a forger's body binds entries to the forger).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeldKeyset {
    pub lists: BTreeSet<osis_crypto::Epoch>,
    pub kem: Option<Vec<u8>>,
    pub possession: BTreeSet<[u8; 32]>,
    pub names: BTreeSet<(osis_keys::NamesDigest, Tid)>,
}

/// A snapshot part's frontiers and `Absorbed` (commit, author).
pub(crate) type Gives = (osis_crdt::Frontiers, Vec<(CommitId, Tid)>);

/// A snapshot's held part on one aspect, as `apply::each_held_piece` streams it: (snapshot, its
/// aspect index, the pieces, what it gives).
pub(crate) type CoverCache = (CommitId, usize, Vec<osis_crdt::Fragment>, Option<Option<Gives>>);

impl Meta {
    /// A commit's meta from its decoded header.
    pub(crate) fn new(header: Arc<Header>, valid: Vec<bool>, head: index::RecordHead, missing: BTreeSet<usize>) -> Meta {
        Meta { view: Arc::new(View::of(&header)), header: LazyHeader::ready(header), received: head.received, origin: head.origin, valid, dropped: head.dropped, stripped: head.stripped, valued: head.valued, missing }
    }
    /// The index of aspect `(tid, ak)` in the commit.
    pub(crate) fn aspect(&self, tid: &Tid, ak: &Ak) -> Option<usize> {
        self.view.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak)
    }
    /// Whether part `ai` is valid here.
    pub(crate) fn valid_at(&self, ai: usize) -> bool {
        self.valid.get(ai).copied().unwrap_or(false)
    }
    /// Whether part `ai` is held: neither dropped nor missing (a stripped one is, as its leftover).
    pub(crate) fn holds(&self, ai: usize) -> bool {
        !self.dropped.contains_key(&ai) && !self.missing.contains(&ai)
    }
    /// Whether part `ai` is held as a leftover for its own writes gone value-less (expired,
    /// purged): no values to keep, so no keep bounds.
    pub(crate) fn bare(&self, ai: usize) -> bool {
        self.stripped.contains(&ai) && !self.valued.contains(&ai)
    }
    /// Whether part `ai` has no body to upload or keep at hosts: dropped, or held as its leftover
    /// (spec/commits.md §5: purged, expired).
    pub fn body_gone(&self, ai: usize) -> bool {
        self.dropped.contains_key(&ai) || self.stripped.contains(&ai)
    }
    /// Whether part `ai` was dropped while invalid (`DropFor::Invalid`).
    pub fn dropped_invalid(&self, ai: usize) -> bool {
        self.dropped.get(&ai).is_some_and(|d| d.why == DropFor::Invalid)
    }
}

/// What the per-commit indexes (`apply::index_commit`, validity, the role filter) read of
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
    /// A memory commit (the ephemeral marker): held in memory, never durable to node-sync,
    /// receipts or demotion frontiers.
    pub memory: bool,
    pub aspects: Vec<AspectView>,
    /// A role commit's frontier (`validity::header_frontier`; perm's adaptation reads it
    /// for demotions); `None` on other kinds.
    pub frontier: Option<Arc<osis_perm::Frontier>>,
    /// The blobs of the chunk list (`Core::by_chunk`).
    pub chunks: Vec<osis_base::BlobId>,
    /// It carries a purge request (`retention::lasting`).
    pub purges: bool,
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
    /// Purge on replace (`retention::replace`).
    pub none: bool,
    /// A permanent delta (`AspectEntry::permanent`) of a durable commit.
    pub permanent: bool,
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
            memory: h.ephemeral.is_some(),
            aspects: h.aspects.iter().map(|a| AspectView { tid: a.tid, ak: a.ak.clone(), lo: a.lo, hi: a.hi, bounded: crate::retention::bounded(a), none: a.retention.history == Some(osis_schema::History::PurgeOnReplace), permanent: h.permanent(a) }).collect(),
            frontier: if h.kind == osis_commit::Kind::Role { crate::apply::validity::header_frontier(h) } else { None },
            chunks: h.chunks.iter().map(|c| c.blob).collect(),
            purges: !h.purge.is_empty(),
        }
    }
}

/// `Engine::point`.
pub type ReadPoint = (u64, u64, u64, u64);

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
        expires: None,
        aspects: v.aspects.iter().map(|a| osis_commit::AspectEntry { tid: a.tid, ak: a.ak.clone(), lo: a.lo, hi: a.hi, retention: Default::default(), keys: Vec::new(), hash: [0; 32] }).collect(),
        chunks: Vec::new(),
        purge: Vec::new(),
        undoes: None,
        blind: [0; 16],
        keys: Vec::new(),
        frontier: None,
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

/// The rebuild of one aspect `apply::run_batched` runs.
#[derive(Default, Clone)]
pub struct Batched {
    /// Asked in the memory class.
    pub memory: bool,
    /// Writes of forgotten memory commits to take off the value-less list once rebuilt
    /// (`apply::unindex_commit`): until then the rebuild strips their values.
    pub unlist: Vec<Owned>,
}

/// The writes one delta holds as its own: one delta of one node (`[lo, hi)`), a commit-form commit, or exact dots of
/// one node (writes snapshots carry, `ctrs` sorted).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Owned {
    /// Counters `lo..hi` of a session source (session form).
    Range { src: osis_crdt::Source, lo: u64, hi: u64 },
    Commit(CommitId),
    Dots { src: osis_crdt::Source, ctrs: Vec<u64> },
}

impl Owned {
    fn of_form(form: Form, author: Tid, id: &CommitId, lo: u64, hi: u64) -> Owned {
        match form {
            Form::Commit => Owned::Commit(*id),
            f => Owned::Range { src: f.own_source(author, *id), lo, hi },
        }
    }
    pub fn of(h: &Header, id: &CommitId, ai: usize) -> Option<Owned> {
        let a = h.aspects.get(ai)?;
        Some(Owned::of_form(h.form, h.author, id, a.lo, a.hi))
    }
    /// `of` from the commit's `View`.
    pub fn of_view(v: &View, id: &CommitId, ai: usize) -> Option<Owned> {
        let a = v.aspects.get(ai)?;
        Some(Owned::of_form(v.form, v.author, id, a.lo, a.hi))
    }
    /// Whether `d` (an origin dot, never `Derived`) belongs to this delta.
    pub fn owns(&self, d: &Dot) -> bool {
        match (self, d.src.kind()) {
            (Owned::Range { src, lo, hi }, _) => d.src == *src && *lo <= d.ctr && d.ctr < *hi,
            (Owned::Commit(c), SourceKind::Commit(x)) => c == x,
            (Owned::Dots { src, ctrs }, _) => d.src == *src && ctrs.binary_search(&d.ctr).is_ok(),
            _ => false,
        }
    }
    /// Whether a dot of `src` with a counter in `lo..hi` belongs to this delta.
    pub fn owns_range(&self, src: &osis_crdt::Source, lo: u64, hi: u64) -> bool {
        match (self, src.kind()) {
            (Owned::Range { src: s, lo: a, hi: b }, _) => s == src && lo < *b && *a < hi,
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

        /// A point in every index's journal (equal to a later one: nothing changed between).
        #[doc(hidden)]
        #[derive(PartialEq)]
        pub struct IndexesMark {
            $($f: <$t as Journaled>::Mark,)*
        }

        impl Journaled for Indexes {
            type Mark = IndexesMark;
            fn commit(&mut self) {
                $(self.$f.commit();)*
            }
            fn mark(&mut self) -> IndexesMark {
                IndexesMark { $($f: self.$f.mark(),)* }
            }
            fn rollback_to(&mut self, m: IndexesMark) {
                $(self.$f.rollback_to(m.$f);)*
            }
            #[cfg(test)]
            fn contents(&self) -> String {
                [$(format!("{} {}", stringify!($f), self.$f.contents()),)*].join("\n")
            }
        }
    };
}

indexes! {
    /// Perm inputs: applied role commits, `created.0` records.
    pub held: held::Held,
    pub commits: JMap<CommitId, Meta>,
    /// Commits with a part invalid here, per aspect (`Core::index_validity`), so a join finds the
    /// writes to strip in O(invalid parts), not O(history).
    pub invalid: JSetMap<(Tid, Ak), CommitId>,
    /// Held commits per aspect their header lists: (`ts`, commit), whatever the part's validity
    /// and whether its body is held. Invariant (also for `by_thing`): it finds
    /// commits, never decides anything alone, since any signer's header can list any aspect.
    /// What a thing has reads the state (`Tx::has_state`); what a commit counts for (a field's retention) reads its parts valid here
    /// (`Meta::valid_at`), body held or not.
    pub by_aspect: JSetMap<(Tid, Ak), (Ts, CommitId)>,
    /// Held parts with a relative keep bound per aspect (`Core::put_meta`), absent at 0:
    /// `retention::any_bounded` without walking the aspect.
    pub bounded_held: JMap<(Tid, Ak), u64>,
    /// Commits holding a purge-on-replace part with values per aspect (`Core::put_meta`): the
    /// bodies `retention::settle_none` judges.
    pub none_held: JSetMap<(Tid, Ak), CommitId>,
    /// Compaction snapshots held per aspect, with their frontiers and `Absorbed`: the bodies
    /// carrying a write besides its own (spec/commits.md §5); what settles suspect flags
    /// (`receipt::settled`).
    pub snapshots: JMap<(Tid, Ak), Vec<HeldSnapshot>>,
    /// Snapshots per aspect whose dropped part still stands in (`Dropped::stands_in`; derived at
    /// open, not persisted).
    pub dropped_snapshots: JSetMap<(Tid, Ak), CommitId>,
    /// Per aspect the newest `ts` of a memory commit forgotten here with a part on it
    /// (`apply::unindex_commit`): what stands for the forgotten parts an undo may have replaced
    /// (`undo::replaced_kept`). Memory only, so not persisted.
    pub forgotten: JMap<(Tid, Ak), Ts>,
    /// Held commits per thing they hold a delta of (re-judging a thing's deltas).
    pub by_thing: JSetMap<(Tid, Tid), CommitId>,
    /// Held commits per (header actor, author), where those differ: re-judging
    /// `validity::acts_for` when the actor's timeline changes, a demotion's frontier, the
    /// actors this node acts for (`Core::acting`).
    pub by_actor: JSetMap<(Tid, Tid), CommitId>,
    /// The commits whose header lists each chunk blob (`View::chunks`).
    pub by_chunk: JSetMap<osis_base::BlobId, CommitId>,
    /// Node- and session-form ranges per (tid, ak, own source): (lo, commit) -> hi. Keyed by
    /// commit too: equivocating commits of one range are all held (spec/commits.md §4).
    pub ranges: JNested<(Tid, Ak, osis_crdt::Source), (u64, CommitId), u64>,
    pub pending: JMap<CommitId, Reason>,
    /// What the node was asked to sync (`Core::syncs` adds what these groups hold).
    pub syncing: JSet<Tid>,
    /// Link keys this node keeps reading as, their seed forgotten (`Engine::keep_bearer`,
    /// spec/permissions.md §7, Bearer use).
    pub bearers: JSet<Tid>,
    pub void: JSet<CommitId>,
    /// Deltas whose value-carrying writes are held value-less (expired, purged).
    pub valueless: JMap<(Tid, Ak), Vec<Owned>>,
    /// Actors with secrets of their own whose epochs this node holds.
    pub secrets: JMap<Tid, ActorEpochs>,
    /// Things with secrets of their own here (`apply::keys::refresh_own_keys`): a held commit's
    /// valid `keys.0` part wrote a keyset.
    pub own_keys: JSet<Tid>,
    /// Held commits whose `keys.0` part on a thing wrote a keyset in its body, any validity
    /// (`records::OWN_KEYS`): thing -> commits.
    pub keyset_parts: JSetMap<Tid, CommitId>,
    /// Things with a `label.0` state (`Engine::labeled_groups`), kept with the state
    /// (`Tx::derive`).
    pub labeled: JSet<Tid>,
    /// Admin and write delete keys of things an inbox payload named (`[admin, write]` bytes),
    /// listed until their `keys.0` arrives (spec/crypto.md §7, spec/wire.md §9): taken only from
    /// a commit that applied valid, by an admin of the thing, touching it; the first kept.
    pub delete_hints: JMap<Tid, osis_base::Value>,
    /// `group.0` definitions and `groups.0` (thing -> groups containing it, transitively).
    pub groups: groups::Groups,
    /// Keyed `roles.0` entries seen: (target, entry dot) -> (holder, created value).
    pub holder_keys: JMap<(Tid, Dot), Tid>,
    /// Role commits whose removed keys are not known yet.
    pub unresolved: JSet<CommitId>,
    /// Roles `secrets.0` and `keys.0` deltas need (by commit and aspect index).
    pub rotation_role: JMap<(CommitId, usize), osis_base::Role>,
    /// What each held `required^.0` delta of a thing says, in key order (spec/commits.md §5).
    pub required: JMap<Tid, Vec<(Point, Arc<osis_schema::core_types::RequiredRules>)>>,
    /// `secrets.0` parts of role commits that write beyond their grantees' boxes (an invite
    /// grant may carry only those, spec/permissions.md §2).
    pub grant_overreach: JSet<(CommitId, usize)>,
    /// What held (or dropped, `Dropped::shown`) `secrets.0` parts of role commits show for
    /// possession, by commit and aspect index (`Showing`).
    pub shown: JMap<(CommitId, usize), Arc<Showing>>,
    /// Keyed boxes per holder: holder -> (actor, box key), from `secrets.0` entries seen.
    pub boxes_to: JSetMap<Tid, (Tid, osis_base::Value)>,
    /// Every held `addenda.0` delta (spec/permissions.md §5.2, Addenda), by (thing, commit):
    /// its author's write whether its body is held or not, with the entries its body says while
    /// held (`validity::note_addenda`, `validity::forget_addendum_body`).
    pub addenda: JMap<(Tid, CommitId), Arc<osis_perm::Addendum>>,
    /// Role commits with a frontier applied here and not yet answered with this node's addenda
    /// (`Engine::answer_removals`; `records::ADDENDA_DUE`).
    pub addenda_due: JSet<CommitId>,
    /// The earliest valid held commit writing an epoch's keyset in `keys.0` (its rotation):
    /// (actor, role, epoch) -> (`ts`, commit). Absent: unknown. What a box naming the keyset
    /// carries (spec/crypto.md §4, Carried) and a certificate of the actor's current keys.
    pub epoch_intro: EpochIntro,
    /// The held valid keysets (spec/crypto.md §4, held keyset): (actor, role, epoch) for each
    /// keyset a held valid `keys.0` body (a role commit's delta or a compaction snapshot; kept
    /// once dropped, `Dropped::keysets`) writes. `Core::keysets_of` reads one actor's.
    pub keysets: JMap<(Tid, osis_base::Role, osis_crypto::Epoch), HeldKeyset>,
    /// The lost-access trigger's work list (`rotation::lost::LOST_DUE`): tid -> when due
    /// (engine ms; 0: now).
    pub lost_due: JMap<Tid, u64>,
    /// The same, by time (a step asks for what is due without a scan).
    pub lost_due_at: JSet<(u64, Tid)>,
    /// Actors lost by an `until` passing alone, waiting for node-sync to hear their labels out
    /// (`rotation::lost::TIMED_LOST`): actor -> when first judged (engine ms).
    pub timed_lost: JMap<Tid, u64>,
    /// Kept copies (`rotation::lost`): each lost actor kept and the holders it hangs on.
    pub kept: JMap<Tid, BTreeSet<Tid>>,
    /// `rotation::departures` per actor; cleared by `role_changed`.
    pub departures: JMap<Tid, Vec<osis_keys::Departure>>,
    /// Hints of opened inbox payloads whose commit has not applied yet (not persisted).
    pub hint_candidates: JMap<CommitId, Vec<(Tid, osis_base::Value)>>,
}

/// The steps run inside a transaction, each applied fully or not at all (`Tx::step`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// One pending commit examined and applied again (`Engine::reexamine`).
    Commit,
    /// One part judged alone (`apply::examine`).
    Part,
    /// One removal answered with this node's addenda (`flows::addenda::answer_removals`).
    Answer,
}

/// Tests: after `skip` more steps of kind `site` run, every later one fails (`BadInput`), before
/// it runs or, `after`, once it ran in full.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct StepFault {
    pub site: Step,
    pub after: bool,
    pub skip: u32,
}

/// A point `Core::rollback_to` undoes back to: the journals' points, the lengths of the lists
/// that only grow within a transaction, and the work lists a step's start holds (a copy: they
/// are empty or small there).
pub(crate) struct CoreMark {
    ix: IndexesMark,
    sides: usize,
    schemas: usize,
    dropped: usize,
    reasons: BTreeMap<CommitId, MemoryDrop>,
    written: usize,
    events: usize,
    commits_named: usize,
    listed_before: usize,
    stale: (BTreeSet<Tid>, BTreeSet<Tid>, BTreeSet<Tid>, BTreeSet<CommitId>, bool),
    batched: Option<BTreeMap<(Tid, Ak), Batched>>,
    memory_tx: bool,
    dirty: bool,
}

/// A held compaction snapshot of an aspect: `ts`, ID, frontiers, `Absorbed` (commit, author).
pub(crate) type HeldSnapshot = (Ts, CommitId, osis_crdt::Frontiers, Vec<(CommitId, Tid)>);

impl MemoryDrop {
    /// The commits whose entries carry the dropped one's writes, if any.
    pub fn by(&self) -> Vec<CommitId> {
        match self {
            MemoryDrop::Covered { by } | MemoryDrop::Superseded { by } => by.iter().copied().collect(),
            MemoryDrop::Gone => Vec::new(),
        }
    }
}

/// Why a memory commit was forgotten (`MemorySync::dropped`): what node-sync does with its
/// entries at hosts (notes/ephemeral.md Memory commits).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemoryDrop {
    /// Every held body covered by held valid memory snapshots (spec/commits.md §5): a writer
    /// deletes its entries at a host once one of `by` is held there.
    Covered { by: BTreeSet<CommitId> },
    /// Superseded by its author's later expiring writes (spec/sync.md §9): its author deletes
    /// its entries once one of `by` is held there.
    Superseded { by: BTreeSet<CommitId> },
    /// Expired, freed with its things (forgotten or deleted here), or replaced by a coalescing
    /// snapshot of its own node's unsent writes (never uploaded): its entries, if any, are
    /// deleted at once.
    Gone,
}

/// What memory commits report to the ephemeral lane (node-sync) and to the local write path.
/// `dropped` grows inside transactions and is cut back to its length at the start of a
/// transaction or step that fails (`Core::rollback_to`); a reader checks a listed commit is still
/// held before acting.
#[derive(Default)]
pub struct MemorySync {
    /// Memory commits forgotten since the last take, with their header (node-sync deletes
    /// their entries at hosts by it) and why (`Engine::take_memory_drops`).
    pub dropped: Vec<(CommitId, Arc<osis_commit::Header>, MemoryDrop)>,
    /// Memory aspects a held memory snapshot turned invalid on since the last take
    /// (`Engine::take_memory_invalidated`).
    pub invalidated: BTreeSet<(Tid, Ak)>,
    /// Memory aspects changed since the compaction trigger last weighed them.
    pub dirty: BTreeSet<(Tid, Ak)>,
    /// Per aspect the snapshot cost last weighed (`Engine::memory_compactions`).
    pub weighed: BTreeMap<(Tid, Ak), usize>,
    /// Why the memory commits about to be forgotten go (`unindex_commit` reads and clears it;
    /// `Gone` when unsaid).
    pub reasons: BTreeMap<CommitId, MemoryDrop>,
}

impl MemorySync {
    fn commit(&mut self) {
        self.reasons.clear();
    }
}

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
    /// `flows::secrets_in` per actor: `secrets.0` decoded, until its state is written (`wrote`) or
    /// freed. A pass reads it many times and it grows with the roster.
    pub secrets_read: HashMap<Tid, Arc<osis_schema::core_types::Secrets>>,
    /// `Engine::head_keys` per (group, index, step): deriving them is some curve work per pass.
    /// Cleared by `role_changed` and any role-class write (`wrote`).
    pub head_keys: HashMap<(Tid, u64, osis_label::StepId), crate::labeling::HeadKeys>,
    /// `Engine::holders_named` per commit: an admin's pass reads it for every inbox copy, and it
    /// decodes role parts. Cleared with `head_keys`: a role-class write, `role_changed`.
    pub holders_named: HashMap<CommitId, Arc<BTreeMap<usize, BTreeSet<Tid>>>>,
    /// Actors whose re-seal trigger found no holder lacking a box (`rotation::reseal_candidates`):
    /// O(roster) a pass otherwise. Holds while `ix.departures` holds its entry (same roster);
    /// cleared with it.
    pub reseal_quiet: BTreeSet<Tid>,
    /// The keyless actor grants (target, holder) over those held (`rotation::members::key_access`):
    /// O(edges) to build. Cleared by `role_changed` and a rollback (the timelines move back).
    pub key_access: Option<Arc<BTreeSet<(Tid, Tid)>>>,
    /// `Engine::inbox_candidates`' answers by actor, and the things up their record chains those
    /// read through: a write there can move many answers (`inbox_moved`); a role change can end
    /// a record edge they go through (`role_changed`).
    pub inbox_labels: BTreeMap<Tid, Vec<LabelId>>,
    pub inbox_uppers: BTreeSet<Tid>,
    /// `acting` at this engine generation (both: memory commits are in `by_actor` too).
    acting_memo: Option<(u64, u64, Arc<Vec<Tid>>)>,
    /// `Engine::inbox_actors`.
    pub inbox_actors: Option<Arc<BTreeMap<LabelId, Vec<Tid>>>>,
    /// Page indexes of the cached states kept paged in the store.
    pub pages: HashMap<(Tid, Ak), pages::PageIndex>,
    pub timelines: Timelines,
    /// The sides taken in admin disputes (`crate::sides`), the walk's trust set; `detect`:
    /// dispute detection is on (after open: a held set loaded again has no arrivals).
    pub sides: crate::sides::Sides,
    pub detect: bool,
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
    /// Parts on `stale_under` by `stale_authors` wait for `rejudge_all` too.
    pub stale_authors: BTreeSet<Tid>,
    /// Whether this node answers removals with addenda (tests: an oracle checking that reads
    /// are a function of the received commits turns it off, `Engine::write_addenda`).
    pub addenda_on: bool,
    pub stale_under: BTreeSet<Tid>,
    pub stale_commits: BTreeSet<CommitId>,
    pub stale_all: bool,
    /// The local schema of each app AK, registered or written with here (`records::SCHEMAS`):
    /// typed views for undo and large-value write-back, also after a restart (snapshots need
    /// none). Never from the wire. Journaled: a failed transaction's registration goes with its
    /// record.
    pub schemas: JMap<String, Arc<osis_schema::Schema>>,
    pub events: Events,
    /// States the running transaction wrote (dropped from the cache on rollback).
    pub written: Vec<(Tid, Ak)>,
    /// Tests: let local commits break the writer-side role rules (to test receivers).
    pub skip_writer_rules: bool,
    /// Someone may listen to commit changes (`Engine::watch_commits`).
    pub(crate) commits_watched: bool,
    /// What `Core::commits_named` noted in the running transaction.
    commits_named: Vec<(Tid, Ak, CommitId)>,
    /// The things commit listeners are on (`Engine::listen_commits`).
    pub(crate) commit_listeners: Option<Arc<dyn Fn() -> Vec<Tid> + Send + Sync>>,
    /// What `commit_listeners` named, asked once per transaction.
    pub(crate) listened: Option<BTreeSet<Tid>>,
    /// Per listened aspect whose state the running transaction changed, the commits listed there
    /// by state before it (`listing::before_state_change`).
    pub(crate) listed_before: Vec<((Tid, Ak), BTreeSet<CommitId>)>,
    /// Commits to deliver again (`Engine::take_redeliver`). Not journaled: naming one a rollback undid
    /// costs a look.
    pub(crate) redeliver: BTreeSet<CommitId>,
    /// Aspects whose deltas `Engine::commit_forged` replaces by bytes that do not decode.
    pub(crate) forge_bad: BTreeSet<(Tid, Ak)>,
    /// Tests: the running transaction writes states no held body gives (`Engine::damage_index`:
    /// another build's rules), so the rebuild check (`apply::check_rebuilt`) skips it.
    #[cfg(debug_assertions)]
    pub(crate) unchecked_tx: bool,
    /// The blob `Engine::commit_forged` built (its own node drops the bad part).
    pub(crate) forged: Option<Vec<u8>>,
    /// Tests: `Engine::freeze_pending`.
    pub frozen_pending: bool,
    /// This open's session (spec/crdt.md §2.1): the own source of its content commits, durable
    /// and memory; its counters live in the store's memory overlay.
    pub session: osis_crdt::Session,
    /// This open's second session: the own source of its expiring memory commits (spec/crdt.md
    /// §2.1), so an expired commit, forgotten with its counters, leaves no gap in `session`'s
    /// ranges that a snapshot frontier could not pass (issues/eph-unify.md, decision 2).
    pub expiring: osis_crdt::Session,
    /// Sessions this open began after its first (`fresh_session`).
    pub later_sessions: u64,
    /// What memory commits and things report to the ephemeral lane and the local write path.
    pub memory: MemorySync,
    /// Set when a lazily held header failed to decode (`LazyHeader`): every later transaction
    /// fails (`Error::Corrupt`).
    pub header_fault: Arc<std::sync::atomic::AtomicBool>,
    /// Tests: after each per-entry `secrets.0` ingestion, check that ingesting the whole state
    /// learns nothing more (`apply::atomic::observe_secrets_keys`).
    #[cfg(test)]
    pub check_ingest: bool,
    /// Tests: apply every part decoded whole through the pre-streaming join (`apply::oracle`),
    /// the differential's oracle.
    #[cfg(test)]
    pub whole_apply: bool,
    /// Tests: the streamed apply fails after this many more pieces (`apply::atomic::each_piece`).
    #[cfg(test)]
    pub piece_fault: Option<usize>,
    /// Tests: steps of a kind fail (`Tx::step`).
    #[cfg(test)]
    pub(crate) step_fault: Option<StepFault>,
    /// Key actors other than the node whose seed this node holds for now (a recovery key from
    /// its card, a link key; role flows): they sign commits (`Mutation::sign_as`) and
    /// open their boxes. In memory only.
    pub key_actors: BTreeMap<Tid, Arc<Identity>>,
    /// No purge-on-replace cover or drop (tests: an oracle holding every body, `Engine::keep_bodies`).
    pub keep_bodies: bool,
    /// What `receipt::fit` fits a frontier to: `MAX_LIST_BYTES` (tests: `Engine::list_bound`).
    pub list_bound: usize,
    /// Value-less lists changed in this transaction, written at its end (`retention::persist_valueless`).
    pub valueless_dirty: BTreeSet<(Tid, Ak)>,
    /// While `Some` (a tick round's expiries): the rebuilds asked, one per aspect, run once
    /// when it ends (`apply::run_batched`).
    pub batched: Option<BTreeMap<(Tid, Ak), Batched>>,
    /// While a held snapshot is judged against many bodies (`retention::memory::drop_covered`
    /// for a new one): its held part, read once (`retention::covered`).
    pub(crate) cover_cache: Option<CoverCache>,
    /// What judging when bodies were replaced reads of aspects' held bodies
    /// (`retention::bounds::held_writes`), kept while nothing changes.
    pub(crate) held_writes: crate::retention::bounds::HeldWritesCache,
    /// At or before the earliest retention timer held (wall ms; `u64::MAX`: none): set by
    /// `tick` and at open, lowered by every timer put (`Engine::timers_due`).
    pub timer_floor: u64,
    /// Aspects whose purge-on-replace bodies `retention::settle_none` judges at the end of the
    /// transaction (`Core::index_none`).
    pub none_due: BTreeSet<(Tid, Ak)>,
    /// Commits with a part judged invalid this transaction (`Core::index_validity`): dropped at
    /// its end where held (`retention::drop_invalid`).
    pub drop_due: BTreeSet<CommitId>,
    /// What changed since node-sync last took it (`Engine::take_changed`; `None`: no
    /// node-sync, nothing kept). A mark from an aborted transaction stays: one extra judgment.
    pub changed: Option<Changed>,
    /// `Engine::live_trees` per thing, cleared by every transaction that changes the indexes or
    /// a state (`touch`, `rollback`) and when blobs arrive (`put_blobs`).
    pub live_trees: BTreeMap<Tid, LiveTrees>,
    /// Aspects (`None`) and commits' parts (`Some`, that change's) a read found a link of whose
    /// blob is not held (`Engine::missed_blob`): the next blob stored re-delivers them to watches
    /// (`Tx::store_blobs`: `Cause::Fetched`, `Event::Commits`). Bounded by the aspects and entries
    /// held. A link whose blob never comes stays noted while a watch re-reads it, so each blob
    /// stored costs a re-read of the watched aspects and entries holding one (an aspect's re-read
    /// already costs its size).
    pub missed: BTreeSet<(Tid, Ak, Option<CommitId>)>,
    /// `Engine::bodies` per commit without their plaintexts (the label pass's cost): dropped
    /// when the commit's record is written (late parts, drops), when a thing it touches gets
    /// its creation record, and all when an actor gets secrets of its own (reader actors move);
    /// only commits whose things' record chains are known are kept.
    pub bodies: BTreeMap<CommitId, Option<crate::labeling::Body>>,
    /// `Engine::body_live` per body, forgotten per aspect when its state changes (`forget_live`)
    /// and wholly on rollback.
    pub live_bodies: BTreeMap<CommitId, BTreeMap<(Tid, Ak), bool>>,
    /// Bodies judged for when they were replaced (`retention::bounds::replaced_at`), for cost
    /// tests (`Engine::replaced_reads`).
    pub replaced_reads: u64,
    /// Held parts walked for their winners judging deaths (`retention::bounds::winners_of`), for
    /// cost tests: a few per part judged, never per death.
    pub death_walks: u64,
    /// Aspect rebuilds run (`apply::rebuild`). Tests: what a validity change costs.
    pub rebuilds: u64,
    /// Held snapshots' writes by dot (`copies::vouched`), per commit.
    /// A commit's entries go whenever its stored body or leftover changes (`put_commit`,
    /// `remove_commit`, `leftover::put`/`remove`: a strip erases keys and values, a late part
    /// or an unstrip brings writes) and on rollback; all go past `COPY_CACHE_MAX` writes.
    pub copy_index: BTreeMap<CommitId, BTreeMap<(Tid, Ak), Arc<osis_crdt::CopyIndex>>>,
    /// Bumped whenever a transaction changes the indexes or a state, rolls back, or the caches
    /// reload (it never goes back): caches derived from them (the sync engine's) compare it.
    /// `Engine::unrouted`, until a role, label or placement is written.
    pub unrouted: Option<Arc<BTreeMap<Tid, Vec<Tid>>>>,
    pub generation: u64,
    /// `generation` for memory transactions (`Tx::set_memory`): what they change is in memory
    /// only, so durable-derived caches (node-sync's) keep theirs.
    pub memory_generation: u64,
    /// The running transaction is a memory one (`Tx::set_memory`).
    pub memory_tx: bool,
    /// Debug builds: the cache hits compared with a fresh read at this point of the store
    /// (`Engine::recheck`).
    #[cfg(debug_assertions)]
    pub(crate) rechecked: (ReadPoint, BTreeSet<String>),
    /// `Engine::labels_of` per group, with the records parsed: dropped when its `label.0` state is written (`wrote`) and
    /// on rollback.
    pub(crate) labels: BTreeMap<Tid, (Vec<std::sync::Arc<crate::labeling::GroupLabel>>, osis_schema::core_types::Labels)>,
    /// `Engine::published_under` for every actor, with the counts it was taken at (held
    /// records, `own_keys`, `labeled`).
    pub(crate) published: Option<Published>,
    /// `Engine::held_links`: dropped when a `link:seed.0` state or index entry changes and on
    /// rollback.
    pub(crate) links: Option<std::sync::Arc<Vec<crate::flows::HeldLink>>>,
    /// The sync records this engine's transactions write or drop (`SyncRecords`), set by
    /// node-sync (`Engine::set_sync_records`; `None`: no node-sync, no sync records).
    pub sync_records: Option<&'static dyn SyncRecords>,
    /// Aspects whose receipts came from headers alone in this run (`Engine::record_header`, a
    /// receipts-only read): a demotion's frontier reads them besides its scope's held aspects.
    pub header_receipts: BTreeSet<(Tid, Ak)>,
    /// Groups this node holds for receipts only (set by node sync,
    /// `SyncEngine::set_receipts_only`): what is here of them is behind (`readable_by`).
    pub receipts_only: BTreeSet<Tid>,
    /// Groups the handle reads and writes at another node (`osis` routes): what is here of them
    /// may be behind, syncing or not (`readable_by`).
    pub routed_away: BTreeSet<Tid>,
}

/// `Core::published`: the counts it was taken at, the published things per actor.
pub(crate) type Published = ((u64, u64, u64), BTreeMap<Tid, std::sync::Arc<BTreeSet<Tid>>>);

/// Node-sync's records that engine transactions touch: an inbox delivery a flow's commit owes
/// (`flows::edges`), its other deliveries (`flows::owe`) and what forgetting drops (`retention::forget`). Implemented by node-sync.
pub trait SyncRecords: Sync {
    /// Records the inbox delivery of `commit` to `holder` in the commit's own transaction, so
    /// a crash before node-sync carries it out loses none.
    fn note_unsent(&self, tx: &mut Tx<'_>, holder: Tid, commit: CommitId, things: Vec<Tid>, edge_only: bool) -> Result<()>;
    /// Records a flow's placement or direct send (`flows::owe`; not an inbox delivery) in the
    /// transaction that made it owed, or (`owed` false) drops that record: node-sync carries
    /// out what is recorded at start, so a crash before it carries `d` out loses nothing.
    fn owe(&self, tx: &mut Tx<'_>, d: &crate::flows::Delivery, owed: bool) -> Result<()>;
    /// Removes the sync records of what is forgotten (`labels`, `things`, `commits`, `parts`)
    /// and returns the blobs among those dropped and `extra` that no kept record names.
    fn forget(&self, tx: &mut Tx<'_>, labels: &BTreeSet<osis_base::LabelId>, things: &BTreeSet<Tid>, commits: &BTreeSet<CommitId>, parts: &BTreeMap<CommitId, BTreeSet<usize>>, extra: BTreeSet<osis_base::BlobId>) -> Result<BTreeSet<osis_base::BlobId>>;
}

/// What node-sync judges again (`Core::changed`).
#[derive(Debug, Default)]
pub struct Changed {
    /// Commits whose record, parts, validity, bodies, replacement or timers changed.
    pub commits: BTreeSet<CommitId>,
    /// Aspects whose state changed other than by a valid write's join (a validity flip, an
    /// un-merge, expiry, purge, a late delta): what waits on the state is judged again.
    pub aspects: BTreeSet<(Tid, Ak)>,
    /// Commits with a part missing again (a cover that no longer carries it, `retention::uncover`;
    /// a purge's fall, `purge::rejudge_purges`): node-sync fetches its entries again.
    pub undropped: BTreeSet<CommitId>,
    /// (holder, target) edges whose current value changed (`osis_perm::Changed::edges`).
    pub edges: BTreeSet<(Tid, Tid)>,
}

impl Changed {
    pub fn is_empty(&self) -> bool {
        self.commits.is_empty() && self.aspects.is_empty() && self.undropped.is_empty() && self.edges.is_empty()
    }
}

/// (actor, role, epoch) -> the commit that introduced it: (ts, commit ID).
pub(crate) type EpochIntro = JMap<(Tid, osis_base::Role, osis_crypto::Epoch), (Ts, CommitId)>;

impl Core {
    /// Whether the node syncs `t`: it was asked to, or a `group.0` it holds puts `t` in a group it
    /// was asked to (a function of held data, whenever it was learned; spec/sync.md §3).
    pub fn syncs(&self, t: &Tid) -> bool {
        let s = &self.ix.syncing;
        s.contains(t) || self.ix.groups.of.get(t).is_some_and(|gs| !gs.is_disjoint(s))
    }

    /// The held durable commits with a delta on `k` (`by_aspect` without memory commits).
    pub fn durable_on<'a>(&'a self, k: &(Tid, Ak)) -> impl Iterator<Item = CommitId> + 'a {
        self.ix.by_aspect.get(k).into_iter().flatten().map(|x| x.1).filter(|c| !self.ix.commits.get(c).is_some_and(|m| m.view.memory))
    }

    /// The held commits of either class with a delta on `k`.
    pub fn held_on<'a>(&'a self, k: &(Tid, Ak)) -> impl Iterator<Item = CommitId> + 'a {
        self.ix.by_aspect.get(k).into_iter().flatten().map(|x| x.1)
    }

    /// The held aspects of `t` and their commits (a range of `by_aspect`).
    pub fn aspects_of(&self, t: &Tid) -> impl Iterator<Item = (&(Tid, Ak), &std::collections::BTreeSet<(Ts, CommitId)>)> {
        let t = *t;
        self.ix.by_aspect.range((t, Ak::MIN)..).take_while(move |((x, _), _)| *x == t)
    }

    /// The held commits with a delta on `t`, by author.
    pub fn on_thing(&self, t: &Tid) -> impl Iterator<Item = CommitId> + '_ {
        let t = *t;
        self.ix.by_thing.range((t, Tid::from_bytes([0; 15]))..).take_while(move |((x, _), _)| *x == t).flat_map(|(_, s)| s.iter().copied())
    }

    /// Notes what a timeline update changed (`osis_perm::Changed`): a role at any point moves
    /// only for those upstream of a changed edge's holder or a new record, and only down from
    /// its target or that record; what is below a new record has a new record chain.
    pub(crate) fn timelines_changed(&mut self, c: osis_perm::Changed) {
        self.stale_things.extend(c.evaluated);
        self.stale_things.extend(self.ix.held.below(&c.created));
        // a write on a changed edge may have stopped or started applying, whoever signed it, and
        // an invite grant's boxes rest on that (`validity::valid_on`)
        let mut on_target: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
        for (h, t) in &c.edges {
            on_target.entry(*t).or_default().insert(*h);
        }
        for (t, hs) in &on_target {
            let on = self.ix.held.commits_on(t).iter().filter(|r| r.ops.iter().any(|o| o.target == *t && hs.contains(&o.holder)));
            self.stale_commits.extend(on.map(|r| r.id));
        }
        let holders: BTreeSet<Tid> = c.edges.iter().map(|p| p.0).chain(c.created.iter().copied()).collect();
        let targets: BTreeSet<Tid> = c.edges.iter().map(|p| p.1).chain(c.created.iter().copied()).collect();
        self.stale_authors.extend(self.ix.held.upstream(&holders));
        let under = self.ix.held.reach(&targets);
        // a role moved there, this node's maybe: a held purge-on-replace body may now be owed a
        // cover (`retention::settle_none`)
        for t in &under {
            self.none_due.extend(self.ix.none_held.range((*t, Ak::MIN)..).take_while(|((x, _), _)| x == t).map(|(k, _)| k.clone()));
        }
        self.stale_under.extend(under);
        if let Some(s) = &mut self.changed {
            s.edges.extend(c.edges);
        }
    }

    /// The commits of `index` (by (thing, author)) on `under` by `authors`: O(the things and their
    /// authors), not their product.
    fn by_authors<'a>(index: &'a JSetMap<(Tid, Tid), CommitId>, under: &'a BTreeSet<Tid>, authors: &'a BTreeSet<Tid>) -> impl Iterator<Item = CommitId> + 'a {
        under.iter().flat_map(move |t| {
            let t = *t;
            index.range((t, Tid::from_bytes([0; 15]))..).take_while(move |((x, _), _)| *x == t).filter(|((_, a), _)| authors.contains(a)).flat_map(|(_, s)| s.iter().copied())
        })
    }

    /// The commits on `under` by `authors` (`rejudge_once`), and those acting for one of `under`.
    pub(crate) fn authored_under<'a>(&'a self, under: &'a BTreeSet<Tid>, authors: &'a BTreeSet<Tid>) -> (impl Iterator<Item = CommitId> + 'a, impl Iterator<Item = CommitId> + 'a) {
        (Self::by_authors(&self.ix.by_thing, under, authors), Self::by_authors(&self.ix.by_actor, under, authors))
    }

    /// The held commits acting for `actor` by another author (a range of `by_actor`).
    pub fn acting_for(&self, actor: &Tid) -> impl Iterator<Item = CommitId> + '_ {
        let a = *actor;
        self.ix.by_actor.range((a, Tid::from_bytes([0; 15]))..).take_while(move |((x, _), _)| *x == a).flat_map(|(_, s)| s.iter().copied())
    }

    /// The actors this node has acted for in a held commit: its chain certificates for them go
    /// under every label it places in (spec/permissions.md §4). O(`by_actor` keys) when the engine
    /// moved, so a pass of a quiet node reads no index of every commit's author.
    pub fn acting(&mut self) -> Arc<Vec<Tid>> {
        let read = |c: &Core| -> Vec<Tid> {
            let me = c.id.tid();
            c.ix.by_actor.keys().filter(|(_, au)| *au == me).map(|(a, _)| *a).collect()
        };
        match &self.acting_memo {
            Some((g, m, v)) if (*g, *m) == (self.generation, self.memory_generation) => {
                debug_assert_eq!(**v, read(self), "acting cached");
                v.clone()
            }
            _ => {
                let v = Arc::new(read(self));
                self.acting_memo = Some((self.generation, self.memory_generation, v.clone()));
                v
            }
        }
    }

    /// Drops what is derived from rosters, `secrets.0` and held epochs (the departures cache):
    /// called wherever those change.
    /// The held valid keysets of actor `m`: (role, epoch, what is held of it).
    pub(crate) fn keysets_of(&self, m: &Tid) -> impl Iterator<Item = (osis_base::Role, osis_crypto::Epoch, &HeldKeyset)> {
        self.ix.keysets.range((*m, osis_base::Role::Read, osis_crypto::Epoch::ZERO)..).take_while(move |(k, _)| k.0 == *m).map(|(k, v)| (k.1, k.2, v))
    }

    pub fn role_changed(&mut self) {
        self.inbox_actors = None;
        self.inbox_labels.clear();
        self.inbox_uppers.clear();
        self.head_keys.clear();
        self.holders_named.clear();
        self.reseal_quiet.clear();
        self.key_access = None;
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
            self.unrouted = None;
            let changed = self.timelines.update_touched(&self.ix.held, &touched);
            self.timelines_changed(changed);
            if self.detect {
                crate::sides::after_update(self);
            }
        }
        self.role_changed();
    }

    /// Whether some validity waits for `rejudge_all`.
    pub fn stale(&self) -> bool {
        self.stale_all || !self.stale_things.is_empty() || !self.stale_commits.is_empty() || !self.stale_authors.is_empty()
    }

    /// Drops what is derived from the state of `(tid, ak)` (a write changes it).
    fn state_changed(&mut self, tid: &Tid, ak: &Ak) {
        self.forget_live(tid, ak);
        if osis_schema::core_types::is_role_class(ak.as_str()) {
            self.role_changed();
        }
    }

    /// Forgets the cached liveness of every body with a delta on `(tid, ak)` (its state
    /// changed): a body's liveness spans every aspect of its class, whichever one was asked.
    pub fn forget_live(&mut self, tid: &Tid, ak: &Ak) {
        let k = (*tid, ak.clone());
        // whichever is fewer: the commits on the aspect (a roster's, not a chat's messages) or
        // those with a cached answer
        if let Some(on) = self.ix.by_aspect.get(&k)
            && on.len() < self.live_bodies.len()
        {
            for (_, c) in on {
                self.live_bodies.remove(c);
            }
            return;
        }
        let commits = &self.ix.commits;
        self.live_bodies.retain(|c, m| {
            drop(crate::costs::span("live bodies: walked"));
            m.remove(&k);
            !m.is_empty() && !commits.get(c).is_some_and(|m| m.header.aspects.iter().any(|x| x.tid == *tid && x.ak == *ak))
        });
    }

    /// Marks commit `c` changed for node-sync (`changed`): its labels' passes judge it again
    /// (a memory commit's too: its bodies travel the same path, spec/sync.md §9).
    pub fn mark_changed(&mut self, c: CommitId) {
        if let Some(s) = &mut self.changed {
            s.commits.insert(c);
        }
    }

    /// Marks the state of `(tid, ak)` changed for node-sync (`changed`): the commits whose
    /// parts changed are marked on their own. Not in a memory transaction (a durable one
    /// touching a memory aspect marks it: one extra judgment).
    pub fn mark_aspect_changed(&mut self, tid: &Tid, ak: &Ak) {
        if self.memory_tx {
            return;
        }
        if let Some(s) = &mut self.changed {
            s.aspects.insert((*tid, ak.clone()));
        }
    }

    /// Drops what `Engine::inbox_candidates` knew through `t`'s `keys.0` or creation record.
    pub fn inbox_moved(&mut self, t: &Tid) {
        self.inbox_actors = None;
        if self.inbox_uppers.contains(t) {
            self.inbox_labels.clear();
            self.inbox_uppers.clear();
        } else {
            self.inbox_labels.remove(t);
        }
    }

    /// Notes that the running transaction writes the state of `k` (evicted on rollback).
    pub fn wrote(&mut self, k: (Tid, Ak)) {
        if k.1.as_str() == "keys.0" {
            self.inbox_moved(&k.0);
        }
        if k.1.as_str() == "label.0" {
            self.labels.remove(&k.0);
        }
        if k.1.as_str() == "secrets.0" {
            self.secrets_read.remove(&k.0);
        }
        // a holder's `node.0` decides its reader key and route (`flows::is_node`)
        if matches!(k.1.as_str(), "label.0" | "group.0" | "groups.0" | "node.0") || osis_schema::core_types::is_role_class(k.1.as_str()) {
            self.unrouted = None;
            self.head_keys.clear();
            self.holders_named.clear();
            self.reseal_quiet.clear();
        }
        if k.1.as_str() == crate::flows::LINK_SEED {
            self.links = None;
        }
        self.written.push(k);
    }

    /// Notes that the running transaction changes the indexes or a state (drops derived caches).
    pub fn touch(&mut self) {
        self.live_trees.clear();
        if self.memory_tx {
            self.memory_generation += 1;
        } else {
            self.generation += 1;
        }
        self.dirty = true;
    }

    /// The running transaction committed: its journal is forgotten.
    fn commit_journal(&mut self) {
        self.ix.commit();
        self.schemas.commit();
        self.memory.commit();
        self.sides.commit();
        self.written.clear();
        self.dirty = false;
    }

    /// A point to undo back to (`rollback_to`): the start of a transaction or of a step
    /// (`Tx::step`). Every held change is given to the timelines by then (each change of the held
    /// set runs `update_timelines` before returning): a rollback re-evaluates the timelines
    /// around what it restores, which would absorb an earlier change without marking what it
    /// moved.
    pub(crate) fn mark(&mut self) -> CoreMark {
        debug_assert!(self.ix.held.touched().is_empty(), "a mark with held changes the timelines lack");
        CoreMark {
            ix: self.ix.mark(),
            sides: self.sides.mark(),
            schemas: self.schemas.mark(),
            dropped: self.memory.dropped.len(),
            reasons: self.memory.reasons.clone(),
            written: self.written.len(),
            events: self.events.queued(),
            commits_named: self.commits_named.len(),
            listed_before: self.listed_before.len(),
            stale: (self.stale_things.clone(), self.stale_authors.clone(), self.stale_under.clone(), self.stale_commits.clone(), self.stale_all),
            batched: self.batched.clone(),
            memory_tx: self.memory_tx,
            dirty: self.dirty,
        }
    }

    /// Undoes every change to the indexes, the sides, the queued events and the work lists of the
    /// running transaction since `m`, and drops every cache (they stay when nothing was changed:
    /// a failed read keeps them). The timelines follow the restored held set. Each field's class
    /// is listed in `rollback_classes`.
    pub(crate) fn rollback_to(&mut self, m: CoreMark) {
        let sides_back = self.sides.journaled() > m.sides;
        self.sides.rollback_to(m.sides);
        if self.dirty || self.written.len() > m.written || self.ix.mark() != m.ix {
            self.waits.clear();
            self.live_trees.clear();
            self.live_bodies.clear();
            self.bodies.clear();
            self.copy_index.clear();
            self.cover_cache = None;
            self.held_writes = Default::default();
            self.published = None;
            if self.memory_tx {
                self.memory_generation += 1;
            } else {
                self.generation += 1;
            }
            self.role_changed();
            self.labels.clear();
            self.unrouted = None;
            self.links = None;
            for k in self.written.split_off(m.written) {
                if k.1.as_str() == "secrets.0" {
                    self.secrets_read.remove(&k.0);
                }
                self.states.remove(&k);
                self.pages.remove(&k);
            }
        }
        self.dirty = m.dirty;
        self.inbox_labels.clear();
        self.inbox_uppers.clear();
        self.inbox_actors = None;
        self.key_access = None;
        self.ix.rollback_to(m.ix);
        self.schemas.rollback_to(m.schemas);
        self.memory.dropped.truncate(m.dropped);
        self.memory.reasons = m.reasons;
        // the timelines follow the restored held set; validity flags are restored with `commits`
        let touched = self.ix.held.take_touched();
        if !touched.is_empty() {
            self.timelines.update_touched(&self.ix.held, &touched);
            crate::sides::discard(self);
        }
        if sides_back {
            crate::sides::restored(self);
        }
        (self.stale_things, self.stale_authors, self.stale_under, self.stale_commits, self.stale_all) = m.stale;
        self.events.truncate(m.events);
        self.commits_named.truncate(m.commits_named);
        self.listed_before.truncate(m.listed_before);
        self.batched = m.batched;
        self.memory_tx = m.memory_tx;
    }

    /// What `rollback_to` does with each field: fails to compile when a field is added, so every
    /// new one is classified. A cache filled from a restored field goes in the dropped class.
    #[allow(dead_code)]
    fn rollback_classes(c: &Core) {
        let Core {
            // restored to the mark: journaled (`ix`, `sides`, `schemas`; `timelines` follows `ix.held`)
            // or copied or cut back to its length
            ix: _,
            sides: _,
            schemas: _,
            timelines: _,
            events: _,
            commits_named: _,
            listed_before: _,
            written: _,
            memory: _,
            stale_things: _,
            stale_authors: _,
            stale_under: _,
            stale_commits: _,
            stale_all: _,
            batched: _,
            memory_tx: _,
            dirty: _,
            // caches, dropped when anything changed (`states` and `pages` per written aspect)
            states: _,
            pages: _,
            secrets_read: _,
            head_keys: _,
            holders_named: _,
            reseal_quiet: _,
            key_access: _,
            inbox_labels: _,
            inbox_uppers: _,
            inbox_actors: _,
            acting_memo: _,
            waits: _,
            live_trees: _,
            live_bodies: _,
            bodies: _,
            copy_index: _,
            cover_cache: _,
            held_writes: _,
            published: _,
            labels: _,
            unrouted: _,
            links: _,
            generation: _,
            memory_generation: _,
            // work lists and hints a superset of which is harmless (the consumer re-checks each
            // entry against the restored state), and what a step only moves forward
            drop_due: _,
            none_due: _,
            valueless_dirty: _,
            changed: _,
            redeliver: _,
            missed: _,
            timer_floor: _,
            hlc: _,
            session: _,
            expiring: _,
            later_sessions: _,
            replaced_reads: _,
            death_walks: _,
            rebuilds: _,
            // set outside steps: identity, configuration, node-sync's settings, test hooks, what
            // a transaction's end or a receipts-only read records
            walks_done: _,
            header_receipts: _,
            id: _,
            detect: _,
            walk_cache_min: _,
            key_salt: _,
            addenda_on: _,
            skip_writer_rules: _,
            commits_watched: _,
            commit_listeners: _,
            listened: _,
            forge_bad: _,
            forged: _,
            frozen_pending: _,
            header_fault: _,
            key_actors: _,
            keep_bodies: _,
            list_bound: _,
            sync_records: _,
            receipts_only: _,
            routed_away: _,
            #[cfg(debug_assertions)]
            unchecked_tx: _,
            #[cfg(debug_assertions)]
            rechecked: _,
            #[cfg(test)]
            check_ingest: _,
            #[cfg(test)]
            whole_apply: _,
            #[cfg(test)]
            piece_fault: _,
            #[cfg(test)]
            step_fault: _,
        } = c;
    }

    /// Begins new plain and expiring sessions (spec/crdt.md §2.1), once an own session-form
    /// write of the current ones turned invalid: a demotion's invalid body would stop every
    /// snapshot's frontier for its session below it for good (spec/sync.md §9), so what this
    /// node writes after a grant again starts a session with no such hole. The plain nonce's
    /// count steps by one (`nonce_count`, no random draw), so `own_plain` recognises every
    /// session of the open. Unique: within the open the first 8 bytes stay fixed (the flip tells
    /// plain from expiring) and the count is distinct below 2^64 steps; another open of this node
    /// collides only if its random first 8 bytes equal these (or their flip) and the count
    /// windows overlap, about steps/2^127 a pair. A step needs a fallen write under the current
    /// sessions, so steps never outnumber writes, and a session costs holders only through them.
    pub(crate) fn fresh_session(&mut self) {
        let mut n = self.session.nonce;
        let count = nonce_count(&n).wrapping_add(1);
        n[8..].copy_from_slice(&count.to_be_bytes());
        self.session.nonce = n;
        self.expiring.nonce = expiring_nonce(&n);
        self.later_sessions = self.later_sessions.saturating_add(1);
    }

    /// Whether `n` is the nonce of a plain session of this open (`fresh_session`).
    pub(crate) fn own_plain(&self, n: &Nonce) -> bool {
        let now = &self.session.nonce;
        n[..8] == now[..8] && nonce_count(now).wrapping_sub(nonce_count(n)) <= self.later_sessions
    }

    fn new(id: Identity, clock: Arc<dyn Clock>, session: osis_crdt::Session, expiring: osis_crdt::Session) -> Core {
        let key_salt = osis_base::hash::derive_key("osis node key index", id.seed().expose());
        Core {
            id,
            hlc: Hlc::new(clock, Ts::default()),
            states: HashMap::new(),
            secrets_read: HashMap::new(),
            head_keys: HashMap::new(),
            holders_named: HashMap::new(),
            reseal_quiet: BTreeSet::new(),
            key_access: None,
            inbox_labels: BTreeMap::new(),
            inbox_uppers: BTreeSet::new(),
            acting_memo: None,
            inbox_actors: None,
            pages: HashMap::new(),
            timelines: Timelines::new(),
            sides: crate::sides::Sides::default(),
            detect: false,
            walk_cache_min: index::WALK_CACHE_MIN,
            walks_done: None,
            stale_things: BTreeSet::new(),
            stale_authors: BTreeSet::new(),
            addenda_on: true,
            stale_under: BTreeSet::new(),
            stale_commits: BTreeSet::new(),
            stale_all: true,
            dirty: false,
            key_salt,
            ix: Indexes::default(),
            waits: crate::apply::Waits::default(),
            schemas: JMap::default(),
            events: Events::default(),
            written: Vec::new(),
            skip_writer_rules: false,
            commits_watched: false,
            commits_named: Vec::new(),
            commit_listeners: None,
            listened: None,
            listed_before: Vec::new(),
            redeliver: BTreeSet::new(),
            forge_bad: BTreeSet::new(),
            #[cfg(debug_assertions)]
            unchecked_tx: false,
            forged: None,
            frozen_pending: false,
            session,
            expiring,
            later_sessions: 0,
            memory: MemorySync::default(),
            header_fault: Arc::default(),
            #[cfg(test)]
            check_ingest: false,
            #[cfg(test)]
            whole_apply: false,
            #[cfg(test)]
            piece_fault: None,
            #[cfg(test)]
            step_fault: None,
            key_actors: BTreeMap::new(),
            keep_bodies: false,
            list_bound: osis_commit::MAX_LIST_BYTES,
            valueless_dirty: BTreeSet::new(),
            batched: None,
            cover_cache: None,
            held_writes: Default::default(),
            timer_floor: 0,
            none_due: BTreeSet::new(),
            drop_due: BTreeSet::new(),
            changed: None,
            sync_records: None,
            live_trees: BTreeMap::new(),
            missed: BTreeSet::new(),
            bodies: BTreeMap::new(),
            live_bodies: BTreeMap::new(),
            replaced_reads: 0,
            death_walks: 0,
            rebuilds: 0,
            copy_index: BTreeMap::new(),
            unrouted: None,
            generation: 0,
            memory_generation: 0,
            memory_tx: false,
            #[cfg(debug_assertions)]
            rechecked: Default::default(),
            labels: BTreeMap::new(),
            published: None,
            links: None,
            header_receipts: BTreeSet::new(),
            receipts_only: BTreeSet::new(),
            routed_away: BTreeSet::new(),
        }
    }

    pub fn now(&self) -> WallMs {
        self.hlc.wall()
    }

    /// Queues `changes` as a commit event, if anyone may listen.
    pub(crate) fn commits_touched(&mut self, changes: Vec<(Tid, Ak, CommitId)>) {
        if self.commits_watched && !changes.is_empty() {
            self.events.queue(crate::events::Event::Commits(Arc::new(changes.into_iter().map(|(t, a, id)| crate::events::CommitChange::held(t, a, id)).collect())));
        }
    }

    /// Queues ephemeral signal fires (`CommitChange::fired`), if anyone may listen, and sends
    /// them: no transaction to wait for.
    pub(crate) fn commits_fired(&mut self, fired: Vec<crate::events::CommitChange>) {
        if self.commits_watched && !fired.is_empty() {
            self.events.queue(crate::events::Event::Commits(Arc::new(fired)));
        }
        self.events.flush();
    }

    /// Commit `c`'s part on `(tid, ak)` reads otherwise, by a change its meta does not show (its
    /// part gone already, now purged): told at the end of the transaction, with `commit_changes`.
    pub(crate) fn commits_named(&mut self, tid: Tid, ak: Ak, c: CommitId) {
        if self.commits_watched {
            self.commits_named.push((tid, ak, c));
        }
    }

    /// At the end of a transaction: the commits it changed whose part on an aspect holds or is
    /// judged otherwise now (`Engine::commit_row`), per aspect, from the journal: O(commits
    /// changed), in one place, whichever path changed them. Nothing without a commit watch: a fall of an aspect
    /// would hold every commit of it here.
    fn commit_changes(&mut self) {
        if !self.commits_watched {
            return;
        }
        let state = |m: &Meta, ai: usize| (m.valid_at(ai), m.dropped.contains_key(&ai), m.stripped.contains(&ai), m.missing.contains(&ai));
        let mut out: BTreeSet<_> = std::mem::take(&mut self.commits_named).into_iter().collect();
        for (id, old) in self.ix.commits.before() {
            let new = self.ix.commits.get(id);
            let Some(m) = new.or(old) else { continue };
            for (ai, a) in m.view.aspects.iter().enumerate() {
                if old.map(|m| state(m, ai)) != new.map(|m| state(m, ai)) {
                    out.insert((a.tid, a.ak.clone(), *id));
                }
            }
        }
        self.commits_touched(out.into_iter().collect());
    }

    /// Sets `id`'s meta: every change to what a part holds goes through here or `take_meta`, so
    /// `ix.bounded_held` stays exact.
    pub(crate) fn put_meta(&mut self, id: CommitId, m: Meta) {
        self.count_bounded(&m, true);
        // a part held invalid (a late part joining, a leftover kept) goes at the transaction's end
        if (0..m.valid.len()).any(|ai| !m.valid_at(ai) && m.holds(ai)) {
            self.drop_due.insert(id);
        }
        let none = self.none_parts(&m, false);
        if let Some(old) = self.ix.commits.insert(id, m) {
            self.count_bounded(&old, false);
        }
        if !none.is_empty() {
            self.index_none(&id, none);
        }
    }

    pub(crate) fn take_meta(&mut self, id: &CommitId) -> Option<Meta> {
        let m = self.ix.commits.remove(id)?;
        self.count_bounded(&m, false);
        let none = self.none_parts(&m, true);
        if !none.is_empty() {
            self.index_none(id, none);
        }
        Some(m)
    }

    /// `ix.none_held` for commit `id` from its aspects `(tid, ak, none, held with values)` as its
    /// meta now stands, and the aspects `retention::settle_none` judges at the transaction's end:
    /// every aspect of a commit whose meta is put (it applied, joined, flipped or dropped) that
    /// holds a purge-on-replace body.
    fn index_none(&mut self, id: &CommitId, parts: Vec<(Tid, Ak, bool, bool)>) {
        for (tid, ak, none, held) in parts {
            let k = (tid, ak);
            if none {
                if held {
                    self.ix.none_held.insert(k.clone(), *id);
                } else {
                    self.ix.none_held.remove(&k, id);
                }
            }
            if self.ix.none_held.get(&k).is_some_and(|s| !s.is_empty()) {
                self.none_due.insert(k);
            }
        }
    }

    /// `index_none`'s input for meta `m` (`None` held: forgotten).
    fn none_parts(&self, m: &Meta, forgotten: bool) -> Vec<(Tid, Ak, bool, bool)> {
        let any = |a: &AspectView| a.none || self.ix.none_held.get(&(a.tid, a.ak.clone())).is_some_and(|s| !s.is_empty());
        m.view.aspects.iter().enumerate().filter(|(_, a)| any(a)).map(|(ai, a)| (a.tid, a.ak.clone(), a.none, !forgotten && m.holds(ai) && !m.bare(ai))).collect()
    }

    fn count_bounded(&mut self, m: &Meta, add: bool) {
        for (ai, a) in m.view.aspects.iter().enumerate() {
            // a bare leftover has no values to keep: no bound to judge (`bounds::bounded_part`)
            if !a.bounded || !m.holds(ai) || m.bare(ai) {
                continue;
            }
            let k = (a.tid, a.ak.clone());
            match self.ix.bounded_held.get(&k).copied().unwrap_or(0).saturating_add_signed(if add { 1 } else { -1 }) {
                0 => {
                    self.ix.bounded_held.remove(&k);
                }
                n => {
                    self.ix.bounded_held.insert(k, n);
                }
            }
        }
    }

    /// Re-indexes which parts of commit `id` are invalid here (call after setting `Meta::valid`).
    pub fn index_validity(&mut self, id: &CommitId) {
        let Some(m) = self.ix.commits.get(id) else { return };
        for (ai, a) in m.view.aspects.iter().enumerate() {
            let k = (a.tid, a.ak.clone());
            if m.valid_at(ai) {
                self.ix.invalid.remove(&k, id);
            } else {
                self.ix.invalid.insert(k.clone(), *id);
                if m.holds(ai) {
                    self.drop_due.insert(*id);
                }
            }
            // a flip may make a held purge-on-replace body replaced or covered
            if self.ix.none_held.get(&k).is_some_and(|s| !s.is_empty()) {
                self.none_due.insert(k);
            }
        }
    }

    /// The commit that wrote dot `d` on `(tid, ak)`, if held.
    pub fn commit_of(&self, tid: &Tid, ak: &Ak, d: &Dot) -> Option<CommitId> {
        let d = d.origin();
        match d.src.kind() {
            SourceKind::Commit(c) => Some(*c),
            SourceKind::Session(_) => {
                let m = self.ix.ranges.get(&(*tid, ak.clone(), d.src.clone()))?;
                let ((_, c), hi) = m.range(..=(d.ctr, CommitId([0xff; 32]))).next_back()?;
                (d.ctr < *hi).then_some(*c)
            }
            SourceKind::Derived(_) => None,
        }
    }

    /// The expiry of the delta that wrote dot `d` on `(tid, ak)` (its commit's header, kept past
    /// the body; spec/crdt.md §4.7): `None` if that commit is not known.
    pub fn write_expiry(&self, tid: &Tid, ak: &Ak, d: &Dot) -> Option<Option<u64>> {
        let m = self.ix.commits.get(&self.commit_of(tid, ak, d)?)?;
        m.header.aspects.iter().find(|x| x.tid == *tid && x.ak == *ak).map(|_| m.header.expires)
    }
}

/// One transaction with the engine's in-memory state.
pub struct Tx<'a> {
    pub txn: Transaction<'a>,
    pub core: &'a mut Core,
    pub rng: &'a mut dyn CryptoRngCore,
}

impl Tx<'_> {
    /// Makes this a memory transaction: every new row in the store's memory overlay, the
    /// change counter `memory_generation`, nothing marked for node-sync (`Core::changed`).
    pub fn set_memory(&mut self) {
        self.txn.set_memory(true);
        self.core.memory_tx = true;
    }

    /// Runs `f` as work on data of class `memory` (issues/eph-unify.md): rows it creates for a
    /// memory commit or aspect inside a durable transaction go to memory, and it neither steps
    /// `generation` nor marks node-sync's changes. A memory transaction stays memory.
    pub fn in_class<T>(&mut self, memory: bool, f: impl FnOnce(&mut Tx<'_>) -> Result<T>) -> Result<T> {
        let was = self.core.memory_tx;
        let on = was || memory;
        self.txn.set_memory(on);
        self.core.memory_tx = on;
        let r = f(self);
        self.txn.set_memory(was);
        self.core.memory_tx = was;
        r
    }

    /// Runs `f` as one step: applied fully or not at all. On error every change it made to the
    /// store and the in-memory state is undone (`Transaction::savepoint`, `Core::mark`) and the
    /// error returned, so a caller that goes on continues from exactly the state before it.
    pub(crate) fn step<T>(&mut self, site: Step, f: impl FnOnce(&mut Tx<'_>) -> Result<T>) -> Result<T> {
        let m = self.core.mark();
        let sp = self.txn.savepoint();
        #[cfg(test)]
        let r = match self.core.step_fault.as_mut().filter(|x| x.site == site) {
            Some(x) if x.skip > 0 => {
                x.skip -= 1;
                f(self)
            }
            Some(x) if x.after => f(self).and(Err(Error::BadInput("step fault (tests)"))),
            Some(_) => Err(Error::BadInput("step fault (tests)")),
            None => f(self),
        };
        #[cfg(not(test))]
        let r = {
            let _ = site;
            f(self)
        };
        match r {
            Ok(v) => {
                self.txn.release(sp)?;
                Ok(v)
            }
            Err(e) => {
                self.txn.rollback_to(sp);
                self.core.rollback_to(m);
                Err(e)
            }
        }
    }

    /// Whether commit `c` is a memory commit.
    pub fn is_memory_commit(&self, c: &CommitId) -> bool {
        self.core.ix.commits.get(c).is_some_and(|m| m.view.memory)
    }

    /// Writes the local record `records::aspect_key(prefix, tid, ak)`: memory for a memory
    /// aspect (as the store routes the aspect's own rows), whichever transaction writes it.
    pub(crate) fn put_aspect_local(&mut self, prefix: &[u8], tid: &Tid, ak: &Ak, val: &[u8]) -> Result<()> {
        let memory = self.txn.is_memory_aspect(tid, ak);
        self.in_class(memory, |tx| Ok(tx.txn.put_local(&records::aspect_key(prefix, tid, ak), val, Shred::No)?))
    }

    /// Sets a retention timer of commit `c`'s part `ai` at `t`: memory for a memory commit.
    pub(crate) fn put_timer(&mut self, t: u64, c: &CommitId, ai: usize, kind: u8) -> Result<()> {
        let memory = self.is_memory_commit(c);
        self.core.timer_floor = self.core.timer_floor.min(t);
        self.in_class(memory, |tx| Ok(tx.txn.put_local(&records::timer_key(t, c, ai), &[kind], Shred::No)?))
    }

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

    /// A joined state `st` of `(tid, ak)` as it is cached: `None` exactly when the whole state
    /// is empty, as a rebuild leaves it. A paged state whose loaded part is empty loads every
    /// page first: a page not loaded may hold elements below a record the skeleton drops (one
    /// holding only paged content, `PageSet::path`), and an emptied first page stays (rare: an
    /// un-merge emptying all that is loaded).
    pub fn kept(&mut self, tid: &Tid, ak: &Ak, mut st: osis_crdt::Fragment) -> Result<Option<osis_crdt::Fragment>> {
        if st.is_empty()
            && let Some(idx) = self.core.pages.get_mut(&(*tid, ak.clone()))
        {
            pages::load_all(&mut self.txn, tid, ak, idx, &mut st)?;
        }
        Ok((!st.is_empty()).then_some(st))
    }

    /// Drops the loaded pages of the cached state of `(tid, ak)`, keeping its skeleton
    /// (`pages::evict`).
    pub fn evict_pages(&mut self, tid: &Tid, ak: &Ak) {
        let k = (*tid, ak.clone());
        if let (Some(idx), Some(Some(f))) = (self.core.pages.get_mut(&k), self.core.states.get_mut(&k)) {
            pages::evict(idx, f);
        }
    }

    /// Joins `delta` into the paged state of `(tid, ak)` a page at a time where it may reset a
    /// paged collection or change its encoding (`pages::join_reset`); `None`: not paged, or it
    /// does not fit (join whole). The state is noted written.
    pub fn join_reset(&mut self, tid: &Tid, ak: &Ak, delta: &osis_crdt::Fragment) -> Result<Option<osis_crdt::Changes>> {
        let k = (*tid, ak.clone());
        if !self.core.pages.contains_key(&k) {
            return Ok(None);
        }
        // noted first: a failure midway evicts what it changed
        self.core.touch();
        self.core.wrote(k.clone());
        let (Some(idx), Some(Some(f))) = (self.core.pages.get_mut(&k), self.core.states.get(&k)) else { return Ok(None) };
        match pages::join_reset(&mut self.txn, tid, ak, idx, f, delta)? {
            pages::Reset::Whole => {
                let _s = crate::costs::span("reset: whole");
                Ok(None)
            }
            pages::Reset::Paged { skeleton, unit, changes } => {
                let _s = crate::costs::span("reset: by pages");
                self.core.state_changed(tid, ak);
                let mut u = self.txn.get_aspect(tid, ak)?.unwrap_or_default();
                u.state = unit;
                self.txn.put_aspect(tid, ak, &u, Shred::No)?;
                self.core.states.insert(k, Some(skeleton));
                Ok(Some(changes))
            }
            pages::Reset::Laid { state, changes } => {
                let _s = crate::costs::span("reset: laid out");
                self.set_state(tid, ak, state, Shred::No)?;
                Ok(Some(changes))
            }
        }
    }

    /// The cached state as loaded so far (after `load_lazy` and `ensure_*`).
    pub fn cached(&self, tid: &Tid, ak: &Ak) -> Option<&Fragment> {
        self.core.states.get(&(*tid, ak.clone())).and_then(Option::as_ref)
    }

    /// The part of the state of `(tid, ak)` a join of `f` meets: a paged state's skeleton and
    /// the pages holding `f`'s dots (`pages::touch_of`; all of them where `f` may reset a paged
    /// collection), dropped from the cache again (`evict_pages`), so reading a delta against
    /// the state a piece at a time holds about one page of it. `None`: the state is empty.
    pub fn state_at(&mut self, tid: &Tid, ak: &Ak, f: &Fragment) -> Result<Option<Fragment>> {
        self.load_lazy(tid, ak)?;
        let touch = pages::touch_of(f, self.core.pages.get(&(*tid, ak.clone())));
        self.ensure_touch(tid, ak, &touch)?;
        let out = self.cached(tid, ak).cloned();
        self.evict_pages(tid, ak);
        Ok(out)
    }

    /// The state of `(tid, ak)` at `f`'s positions (`Fragment::part_at`: what a join of `f` meets,
    /// the resets on its paths included), loading only the pages `f` touches: O(f), not a copy of
    /// the state.
    pub fn state_part_at(&mut self, tid: &Tid, ak: &Ak, f: &Fragment) -> Result<Option<Fragment>> {
        self.load_lazy(tid, ak)?;
        let touch = pages::touch_of(f, self.core.pages.get(&(*tid, ak.clone())));
        self.ensure_touch(tid, ak, &touch)?;
        let out = self.cached(tid, ak).map(|s| s.part_at(f));
        self.evict_pages(tid, ak);
        Ok(out)
    }

    /// Whether `(tid, ak)` has a state: a valid write on it applied here. What a thing has is
    /// read here (or from an index derived from states: `Indexes::labeled`, `groups`),
    /// never from `Indexes::by_aspect`, which any signer's header adds to.
    pub fn has_state(&mut self, tid: &Tid, ak: &Ak) -> Result<bool> {
        self.load_lazy(tid, ak)?;
        Ok(self.cached(tid, ak).is_some())
    }

    /// The whole state of `(tid, ak)`.
    pub fn state(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<&Fragment>> {
        self.load(tid, ak)?;
        Ok(self.cached(tid, ak))
    }

    /// Writes a whole state; `f` is the
    /// whole state.
    pub fn set_state(&mut self, tid: &Tid, ak: &Ak, f: Option<Fragment>, shred: Shred) -> Result<()> {
        listing::before_state_change(self, tid, ak)?;
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
        self.txn.put_aspect(tid, ak, &unit, shred)?;
        // the state-list row is the aspect's class (its key's marker), whatever the transaction
        if f.is_some() {
            self.put_aspect_local(records::ASPECTS, tid, ak, &[])?;
        } else {
            self.txn.remove_local(&records::aspect_key(records::ASPECTS, tid, ak), Shred::No)?;
        }
        self.derive(tid, ak, f.as_ref());
        self.core.states.insert((*tid, ak.clone()), f);
        Ok(())
    }

    /// Keeps the index derived from states at the state `f` of `(tid, ak)`, whatever wrote it:
    /// `Indexes::labeled`.
    fn derive(&mut self, tid: &Tid, ak: &Ak, f: Option<&Fragment>) {
        if ak.as_str() == "label.0" {
            match f {
                Some(_) => self.core.ix.labeled.insert(*tid),
                None => self.core.ix.labeled.remove(tid),
            };
        }
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
            self.derive(tid, ak, f.as_ref());
            self.core.states.insert(k, f);
            return Ok(());
        }
        let mut f = f;
        if let (Some(st), Some(idx)) = (&mut f, self.core.pages.get_mut(&k)) {
            pages::load_all(&mut self.txn, tid, ak, idx, st)?;
        }
        self.set_state(tid, ak, f, shred)
    }


    pub fn unit(&mut self, tid: &Tid, ak: &Ak) -> Result<AspectUnit> {
        Ok(self.txn.get_aspect(tid, ak)?.unwrap_or_default())
    }

    /// Writes a commit record (`index::record_head`: received, origin, dropped parts and what
    /// they keep; then its blob), and for a role commit its `node/edges` row (`edges`: what the caller already
    /// read of `blob` with `edge_parts_of`, else decoded here).
    pub(crate) fn put_commit(&mut self, id: &CommitId, blob: &CommitBlob, meta: &Meta, shred: Shred, edges: Option<&crate::apply::validity::EdgeParts>) -> Result<()> {
        // a part is held, dropped or missing: never both of the last two (an open derives
        // missing as neither in the blob nor dropped)
        debug_assert!(meta.dropped.keys().all(|ai| !meta.missing.contains(ai)), "{id:?}: parts both dropped and missing: dropped {:?} missing {:?}", meta.dropped, meta.missing);
        self.core.bodies.remove(id);
        self.core.copy_index.remove(id);
        self.core.mark_changed(*id);
        let v = [index::record_head(meta), blob.encode()].concat();
        self.txn.put_local(&records::commit_key(id), &v, shred)?;
        if meta.header.kind.is_role() {
            // perm's reading of it, persisted beside the record (an open decodes no body)
            match edges {
                Some(p) => index::put_edges(self, id, p, shred)?,
                None => {
                    let p = crate::apply::edge_parts_of(self, id, &meta.header, blob.clone())?;
                    index::put_edges(self, id, &p, shred)?;
                }
            }
        }
        // likewise what an addendum says (`validity::note_addenda` read it from the body)
        if meta.view.aspects.iter().any(|a| osis_schema::core_types::is_addenda(a.ak.as_str())) {
            let p = crate::apply::validity::AddendaParts::from_index(self.core, id, &meta.view.aspects);
            index::put_addenda(self, id, &p, shred)?;
        }
        Ok(())
    }

    /// Removes a commit record (shredded) with what the index keeps beside it.
    pub fn remove_commit(&mut self, id: &CommitId) -> Result<()> {
        self.core.bodies.remove(id);
        self.core.copy_index.remove(id);
        self.txn.remove_local(&records::commit_key(id), Shred::Yes)?;
        index::remove_edges(self, id)?;
        index::remove_addenda(self, id)
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
    let blob = CommitBlob::decode_stored(rest).map_err(|_| Error::Corrupt("commit blob"))?;
    Ok((head, blob))
}

/// One node's engine.
pub struct Engine {
    store: Store,
    store_rng: SeededRng,
    pub(crate) rng: Box<dyn CryptoRngCore + Send>,
    #[doc(hidden)]
    pub core: Core,
    /// The local ephemeral write path's own state (`crate::ephemeral`): the undo log,
    /// unsent ephemeral signals, delivered relay-only commits.
    pub(crate) eph: crate::ephemeral::Eph,
    clock: Arc<dyn Clock>,
    pub(crate) cfg: Config,
    /// Debug builds: this open's durable transactions that changed a state or a commit's
    /// parts, and those of them that changed more than valid joins (`check_index` runs when
    /// either count reaches a power of four).
    #[cfg(debug_assertions)]
    index_checks: [u64; 2],
    /// Tests: an index was edited in memory past the store, so `check_index` does not run.
    #[cfg(test)]
    pub(crate) index_poked: bool,
}

type Nonce = [u8; osis_crdt::SESSION_NONCE_LEN];

/// This open's two sessions of node `node` (spec/crdt.md §2.1): the plain writes' under a random
/// nonce, so no two opens of one store (a restored copy, two live copies) share a source, and
/// the expiring writes' under `expiring_nonce` of it (drawing a second nonce would move every
/// later draw).
fn sessions(node: Tid, rng: &mut dyn CryptoRngCore) -> (osis_crdt::Session, osis_crdt::Session) {
    let mut nonce = [0u8; osis_crdt::SESSION_NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    (osis_crdt::Session { node, nonce }, osis_crdt::Session { node, nonce: expiring_nonce(&nonce) })
}

/// The expiring session's nonce beside plain nonce `n`: `n` with its first bit flipped (distinct
/// from every plain nonce of the open, whose first bytes all equal `n`'s, and across opens as
/// `n` is).
fn expiring_nonce(n: &Nonce) -> Nonce {
    let mut x = *n;
    x[0] ^= 0x80;
    x
}

/// The count in plain nonce `n`'s last 8 bytes (`Core::fresh_session` steps it).
fn nonce_count(n: &Nonce) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&n[8..]);
    u64::from_be_bytes(b)
}

impl Engine {
    /// While this stands (no commit changed the store, the indexes stand, the clock stands) a
    /// read of the engine repeats itself.
    pub fn point(&self) -> ReadPoint {
        (self.store.changes(), self.core.generation, self.core.memory_generation, self.core.now().0)
    }

    /// Debug builds: whether a cache hit of `what` is worth comparing with a fresh read: one
    /// comparison per `point` checks all that can be checked (repeats held a quarter of the CPU of
    /// `osis`'s tests, notes/testing.md).
    #[cfg(debug_assertions)]
    pub fn recheck(&mut self, what: String) -> bool {
        let at = self.point();
        if self.core.rechecked.0 != at {
            self.core.rechecked = (at, BTreeSet::new());
        }
        self.core.rechecked.1.insert(what)
    }

    /// A new node over an empty backend: fresh identity, its node thing with `created.0`,
    /// `node.0` and `keys.0` (spec/permissions.md §4 node card).
    pub fn create(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, cfg: Config, clock: Arc<dyn Clock>, mut rng: Box<dyn CryptoRngCore + Send>) -> Result<Engine> {
        let store = Store::create(backend, root, cfg.store, &mut *rng)?;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let store_rng = SeededRng::from_seed(seed);
        let id = Identity::generate(&mut *rng);
        let (session, expiring) = sessions(id.tid(), &mut *rng);
        let mut e = Engine { store, store_rng, rng, core: Core::new(id, clock.clone(), session, expiring), eph: crate::ephemeral::Eph::default(), clock, cfg, #[cfg(debug_assertions)] index_checks: [0; 2], #[cfg(test)] index_poked: false };
        let seed_bytes = e.core.id.seed().expose().to_vec();
        // a new store: its (empty) persisted index is current
        e.run(|tx| {
            tx.txn.put_local(records::SEED, &seed_bytes, Shred::No)?;
            index::write_all(tx)
        })?;
        e.bootstrap()?;
        e.start_detection();
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
        let (session, expiring) = sessions(id.tid(), &mut *rng);
        let mut e = Engine { store, store_rng, rng, core: Core::new(id, clock.clone(), session, expiring), eph: crate::ephemeral::Eph::default(), clock, cfg, #[cfg(debug_assertions)] index_checks: [0; 2], #[cfg(test)] index_poked: false };
        e.reload()?;
        e.reexamine()?;
        e.core.timer_floor = e.next_timer()?.unwrap_or(u64::MAX);
        Ok(e)
    }

    /// The node thing's first commits: `created.0` with `node.0`, then `keys.0` (its KEM key).
    fn bootstrap(&mut self) -> Result<()> {
        use osis_schema::core_types as ct;
        let node = self.tid();
        let mut m = Mutation::new();
        m.create(self.core.id.record().clone());
        m.set(node, &ct::NODE, &ct::NodeInfo { software: self.cfg.software.clone() })?;
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

    /// The first admin of `tid` (`None`: a key actor or an unknown thing).
    pub fn first_admin(&self, tid: &Tid) -> Option<Tid> {
        self.core.first_admin(tid)
    }

    /// `tid`, then its first admins up the record chain: at
    /// most `MAX_CHAIN_DEPTH` links (`osis_base::record_chain`).
    pub fn record_chain(&self, tid: &Tid) -> impl Iterator<Item = Tid> + '_ {
        self.core.record_chain(tid).filter_map(|s| s.thing())
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
        self.core.memory_tx = false;
        self.core.listened = None;
        let start = self.core.mark();
        #[cfg(debug_assertions)]
        {
            self.core.unchecked_tx = false;
        }
        // debug builds: whether `check_index` runs after this transaction
        #[cfg(debug_assertions)]
        let mut sample = false;
        let r = match self.store.transaction(&mut self.store_rng) {
            Ok(txn) => {
                let mut tx = Tx { txn, core: &mut self.core, rng: &mut *self.rng };
                // the persisted index follows the in-memory indexes in the same transaction
                let mut r = f(&mut tx);
                // explicit demotions applied get this node's addenda (spec/permissions.md §5.2)
                if r.is_ok()
                    && !tx.txn.is_memory()
                    && let Err(e) = crate::flows::addenda::answer_removals(&mut tx)
                {
                    r = Err(e);
                }
                if r.is_ok() && tx.core.header_fault.load(std::sync::atomic::Ordering::Relaxed) {
                    r = Err(Error::Corrupt("commit record header"));
                }
                // a body judged invalid goes at the end of the transaction that judged it
                // (spec/permissions.md §6), after this node's addenda vouched for what they list;
                // a memory transaction writes no durable row (and memory parts stay)
                if !tx.txn.is_memory() {
                    if r.is_ok() && !tx.core.drop_due.is_empty() {
                        r = r.and_then(|v| crate::retention::drop_invalid(&mut tx).map(|_| v));
                    }
                    tx.core.drop_due.clear();
                }
                if r.is_ok() && !tx.core.none_due.is_empty() {
                    r = r.and_then(|v| crate::retention::settle_none(&mut tx).map(|_| v));
                }
                tx.core.none_due.clear();
                if r.is_ok() {
                    r = r.and_then(|v| crate::retention::persist_valueless(&mut tx).map(|_| v));
                }
                tx.core.valueless_dirty.clear();
                if r.is_ok() {
                    r = r.and_then(|v| listing::listing_moved(&mut tx).map(|_| v));
                }
                tx.core.listed_before.clear();
                if r.is_ok() {
                    tx.core.commit_changes();
                }
                // every validity change was judged before the index is persisted
                debug_assert!(r.is_err() || (tx.core.stale_things.is_empty() && tx.core.stale_authors.is_empty() && tx.core.stale_commits.is_empty()), "stale validity left unjudged: {:?} {:?} {:?}", tx.core.stale_things, tx.core.stale_authors, tx.core.stale_commits);
                #[cfg(debug_assertions)]
                if r.is_ok() && !tx.core.unchecked_tx {
                    match crate::apply::check_rebuilt(&mut tx) {
                        Ok(c) if c != crate::apply::TxChange::None && !tx.txn.is_memory() => {
                            let more = c == crate::apply::TxChange::More;
                            let n = &mut self.index_checks;
                            n[0] += 1;
                            n[1] += u64::from(more);
                            let quarter = |n: u64| n.is_power_of_two() && n.trailing_zeros().is_multiple_of(2);
                            sample = quarter(n[0]) || (more && quarter(n[1]));
                        }
                        Ok(_) => {}
                        Err(e) => r = Err(e),
                    }
                }
                let persisted = {
                    let _s = crate::costs::span("tx: persist index");
                    r.and_then(|v| crate::sides::persist(&mut tx).map(|_| v)).and_then(|v| index::persist(&mut tx).map(|_| v))
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
                self.core.memory_tx = false;
                self.core.events.flush();
                #[cfg(test)]
                let sample = sample && !self.index_poked;
                #[cfg(debug_assertions)]
                if sample {
                    self.check_index();
                }
                Ok(v)
            }
            Err(e) => {
                self.core.walks_done = None;
                self.core.rollback_to(start);
                Err(e)
            }
        }
    }

    /// A fresh `Core` loaded from the store (`rebuild`: ignoring the persisted index); whether
    /// it was rebuilt from the commit records.
    fn load_fresh(&mut self, rebuild: bool) -> Result<Option<Vec<(Tid, Ak)>>> {
        let mut fresh = self.blank_core();
        fresh.memory = std::mem::take(&mut self.core.memory);
        fresh.events = std::mem::take(&mut self.core.events);
        fresh.key_actors = std::mem::take(&mut self.core.key_actors);
        fresh.redeliver = std::mem::take(&mut self.core.redeliver);
        self.core = fresh;
        let r = {
            let txn = self.store.transaction(&mut self.store_rng)?;
            let mut tx = Tx { txn, core: &mut self.core, rng: &mut *self.rng };
            crate::apply::load(&mut tx, rebuild)
        };
        self.core.commit_journal();
        r
    }

    /// An empty `Core` with this one's identity, sessions, clock and settings.
    fn blank_core(&self) -> Core {
        let mut fresh = Core::new(self.core.id.clone(), self.clock.clone(), self.core.session, self.core.expiring);
        fresh.later_sessions = self.core.later_sessions;
        fresh.hlc = Hlc::new(self.clock.clone(), self.core.hlc.last());
        fresh.hlc.set_offset(self.core.hlc.offset());
        fresh.commits_watched = self.core.commits_watched;
        fresh.commit_listeners = self.core.commit_listeners.clone();
        fresh.skip_writer_rules = self.core.skip_writer_rules;
        fresh.frozen_pending = self.core.frozen_pending;
        fresh.walk_cache_min = self.core.walk_cache_min;
        fresh.sync_records = self.core.sync_records;
        // caches keyed on it (the sync engine's labels and co-readers) never see an old value again
        fresh.generation = self.core.generation.wrapping_add(1);
        #[cfg(test)]
        {
            fresh.check_ingest = self.core.check_ingest;
            fresh.whole_apply = self.core.whole_apply;
        }
        fresh
    }

    /// An open from the persisted index and a rebuild from the commit records each compute the
    /// indexes and role timelines this node holds (spec/permissions.md §5.1 step 5: validity is
    /// a function of the held set), the open decoding no header and judging every part as held.
    /// Both load in a transaction that is dropped, so the store is as it was. Panics with the
    /// difference. Debug builds run it after sampled transactions (`run`); tests call it where
    /// a reproducer's point is.
    #[doc(hidden)]
    pub fn check_index(&mut self) {
        let had = (self.core.index_digest(), self.core.perm_digest(false));
        for rebuild in [false, true] {
            let mut fresh = self.blank_core();
            fresh.key_actors = self.core.key_actors.clone();
            let mut rng = SeededRng::from_u64(0);
            let mut store_rng = SeededRng::from_u64(0);
            let load = || -> Result<bool> {
                let txn = self.store.transaction(&mut store_rng)?;
                let mut tx = Tx { txn, core: &mut fresh, rng: &mut rng };
                // a transaction that left the index stale (`index::invalidate`: commit records
                // changed outside the in-memory indexes) is followed by a reload
                if !index::current(&mut tx)? {
                    return Ok(false);
                }
                crate::apply::load(&mut tx, rebuild)?;
                Ok(true)
            };
            // its work is not the measured code's (scale checks count work)
            let r = crate::costs::paused(|| osis_perm::uncounted(load));
            let at = if rebuild { "rebuilt from the commit records" } else { "opened from the persisted index" };
            assert!(r.is_ok(), "{at}: {:?}", r.err());
            if !matches!(r, Ok(true)) {
                return;
            }
            let d = had.0.first_diff(&fresh.index_digest());
            assert!(d.is_none(), "{at}, the {}", d.unwrap_or_default());
            assert_eq!(fresh.perm_digest(false), had.1, "{at}: role timelines");
            if !rebuild {
                let decoded = fresh.ix.commits.values().filter(|m| !m.view.linked && m.header.is_decoded()).count();
                assert_eq!(decoded, 0, "{at}: headers decoded");
                assert_eq!(crate::apply::validity::misjudged(&fresh), None, "{at}: judged anew");
            }
        }
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
                }
                index::write_all(tx)
            })?;
        } else if self.core.timelines.due(self.core.walk_cache_min) {
            // walks evaluated or continued at open saved for the next (a cache: a failure
            // leaves the open as it is)
            let _ = self.run(|_| Ok(()));
        }
        self.start_detection();
        Ok(())
    }

    /// Dispute detection on, once the store is loaded (`crate::sides`): what arrives from here
    /// on may raise one.
    fn start_detection(&mut self) {
        self.core.detect = true;
        self.core.timelines.detect(true);
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

    // spec: none (costs, spec/requirements.md Scale): a write on an aspect with few commits (a
    // roster) forgets their cached liveness without walking the others' (a chat's messages).
    #[test]
    fn forget_live_walks_no_other_bodies() {
        let mut lp = LocalPeer::new(1, 953, WallMs(1_700_000_000_000)).unwrap();
        let core = &mut lp.peers[0].engine.core;
        let (t, roster, msg) = (core.id.tid(), Ak::new("roles.0").unwrap(), Ak::new("chat:msg~0").unwrap());
        let id = |i: u8| osis_base::CommitId([i; 32]);
        for i in 0..9 {
            core.live_bodies.entry(id(i)).or_default().insert((t, msg.clone()), true);
        }
        core.live_bodies.entry(id(9)).or_default().insert((t, roster.clone()), true);
        core.ix.by_aspect.insert((t, roster.clone()), (osis_base::Ts::default(), id(9)));
        crate::costs::take();
        core.forget_live(&t, &roster);
        assert!(!crate::costs::take().iter().any(|x| x.0 == "live bodies: walked"));
        assert_eq!(core.live_bodies.len(), 9);
    }

    fn holder(t: Tid, m: Tid, role: Option<Role>) -> Mutation {
        let (path, op) = match role {
            Some(role) => (vec![PathSeg::Key(Value::Tid(m))], Op::Set(ct::Edge { role, until: None, invite: None, tied: None }.to_value())),
            None => (Vec::new(), Op::Remove(Value::Tid(m))),
        };
        let mut mu = Mutation::new();
        mu.op(t, &ct::ROLES, PathOp { path, op }).unwrap();
        // an explicit removal: with no frontier it would be a finalize (spec/permissions.md §2)
        if role.is_none() {
            mu.frontier(ct::Frontier::default().to_value());
        }
        mu
    }

    fn write(m: &mut Mutation, t: Tid, v: &str) {
        m.set(t, &Ak::new("t:reg.0").unwrap(), &Value::Str(v.into())).unwrap();
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
        let new_thing = |e: &mut super::Engine, admin: Tid| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, admin);
            write(&mut m, t, "new");
            e.commit(m).map(|_| t)
        };
        let g = failing(&mut lp.peers[0], &mut failed, |e| new_thing(e, a));
        failing(&mut lp.peers[0], &mut failed, |e| e.commit(holder(g, b, Some(Role::Write))));
        failing(&mut lp.peers[0], &mut failed, |e| e.commit(holder(g, c, Some(Role::Admin))));
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
        failing(&mut lp.peers[0], &mut failed, |e| e.commit(holder(g, b, None)));
        // received in reverse: most wait for what they depend on, then apply together
        let mut pks = lp.packages(0).unwrap();
        pks.reverse();
        for pk in &pks {
            failing(&mut lp.peers[2], &mut failed, |e| e.ingest(&pk.bytes, pk.blobs.clone()));
        }
        assert!(failed >= 6 + pks.len() / 2, "{failed} of {} failed", 6 + pks.len());
        // every commit applied; beside them only peer 2's own (its addendum to the removal)
        let received = lp.peers[2].engine.core.ix.commits.values().filter(|m| m.view.author != c || m.view.aspects.iter().all(|a| a.ak.as_str() != "addenda.0")).count();
        assert_eq!(received, lp.peers[0].engine.core.ix.commits.len());
        assert!(lp.peers[2].engine.core.ix.pending.is_empty());
    }

    // spec/commits.md §4, §5: the same for compaction, purge-on-replace covers and expiry by `tick`,
    // a commit received a part at a time, and delete-key hints (a
    // failed promotion keeps its candidate).
    #[test]
    fn failed_transaction_restores_indexes_retention_spec_commits_4() {
        use osis_schema::{PurgeBy, Retention};
        let mut lp = LocalPeer::new(3, 952, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a, b) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let (reg, kept) = (Ak::new("t:reg.0").unwrap(), Ak::new("t:kept.0").unwrap());
        let mut failed = 0;
        let g = failing(&mut lp.peers[0], &mut failed, |e| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a);
            write(&mut m, t, "new");
            e.commit(m).map(|_| t)
        });
        failing(&mut lp.peers[0], &mut failed, |e| e.commit(holder(g, b, Some(Role::Write))));
        lp.sync(0, 1).unwrap();
        lp.advance(10);
        // an older write by 1, delivered last
        let mut m = Mutation::new();
        m.set(g, &kept, &Value::Str("v".into())).unwrap();
        let v = lp.peers[1].commit(m).unwrap().unwrap();
        lp.advance(10);
        let keep0 = Retention { by: PurgeBy::Writer, history: Some(osis_schema::History::PurgeOnReplace) };
        let now = lp.peers[0].engine.now();
        let two = failing(&mut lp.peers[0], &mut failed, |e| {
            // two aspects: received a part at a time below; both expire (one expiry per commit)
            let mut m = Mutation::new();
            m.retention(g, &kept, keep0).unwrap();
            m.set(g, &kept, &Value::Str("w".into())).unwrap();
            write(&mut m, g, "w");
            m.expires(g, &reg, WallMs(now.0 + 60_000)).unwrap();
            m.expires(g, &kept, WallMs(now.0 + 60_000)).unwrap();
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
        // peer 2: the two-aspect commit's parts one at a time
        let pks = lp.packages(0).unwrap();
        let tpk = pks.iter().find(|p| p.id == two).unwrap().clone();
        let blob = osis_commit::CommitBlob::decode(&tpk.bytes).unwrap();
        let first = osis_commit::rewrite(&blob, |ai| ai != 0).encode();
        for pk in pks.iter().filter(|p| p.id != two) {
            failing(&mut lp.peers[2], &mut failed, |e| e.ingest(&pk.bytes, pk.blobs.clone()));
        }
        failing(&mut lp.peers[2], &mut failed, |e| e.ingest(&first, tpk.blobs.clone()));
        failing(&mut lp.peers[2], &mut failed, |e| e.ingest(&tpk.bytes, tpk.blobs.clone()));
        failing(&mut lp.peers[2], &mut failed, |e| e.ingest(&vpk.bytes, vpk.blobs.clone()));
        // past the expiry: drops and expiry run on both
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
        let hint = osis_label::InboxThing { tid: g, label: None, delete_keys: Some((dk, dk)) };
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

    // spec: none (the local schema of an app AK, notes/data-model.md AKs): the highest
    // version registered or written with types it, also after a restart; a stale registration
    // never downgrades it; an equal version registered again replaces it.
    #[test]
    fn local_schema_keeps_highest_version() {
        let parse = |rev: u64, ty: &str| std::sync::Arc::new(osis_schema::parse("t.osis", &format!("revision {rev};\naspect t:a.0: {ty};\n")).unwrap());
        let rev = |p: &Peer| p.engine.core.schemas.get("t:a.0").map(|s| (s.revision, s.aspects["t:a.0"].ty.clone()));
        let mut p = Peer::new(954, WallMs(1_700_000_000_000)).unwrap();
        let (v2, v1, v2b) = (parse(2, "int"), parse(1, "string"), parse(2, "bool"));
        p.engine.register_schema(v2.clone()).unwrap();
        p.engine.register_schema(v1).unwrap();
        assert_eq!(rev(&p), Some((2, v2.aspects["t:a.0"].ty.clone())), "a lower version never replaces");
        p.restart(1).unwrap();
        assert_eq!(rev(&p), Some((2, v2.aspects["t:a.0"].ty.clone())), "kept in the store");
        p.engine.register_schema(v2b.clone()).unwrap();
        p.restart(2).unwrap();
        assert_eq!(rev(&p), Some((2, v2b.aspects["t:a.0"].ty.clone())), "an equal version registered again replaces");
        // a failed transaction's registration goes with its record, and a later one keeps it
        let v3 = parse(3, "int");
        let r: crate::Result<()> = p.engine.run(|tx| {
            crate::engine::write::keep_schema(tx, &v3, true)?;
            Err(crate::Error::Misuse("fails after registering"))
        });
        assert!(r.is_err());
        assert_eq!(rev(&p).map(|r| r.0), Some(2), "rolled back");
        p.engine.register_schema(v3).unwrap();
        p.restart(3).unwrap();
        assert_eq!(rev(&p).map(|r| r.0), Some(3), "registered again after a failed transaction");
    }
}
