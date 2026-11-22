//! The engine: one node's local state over its `Store` (notes/architecture.md §2: the node
//! talks to `Store` only). Synchronous, no I/O of its own, time from a `Clock`, randomness
//! injected. Every mutating call runs in one store transaction; engine events are sent after
//! it is durable. A failed transaction undoes its changes to the in-memory indexes (`journal`)
//! and evicts the states it wrote.

pub(crate) mod acting;
pub(crate) mod blobs;
pub(crate) mod clock;
pub(crate) mod commits;
pub use commits::{Commits, Meta};
pub(crate) mod decoded;
pub(crate) mod edits;
pub(crate) mod held;
pub(crate) use held::On;
pub mod listing;
pub(crate) mod index;
pub(crate) mod journal;
use osis_base::memo;
pub(crate) mod pages;
pub(crate) mod large;
pub(crate) mod read;
pub mod refs;
pub mod records;
pub(crate) mod secrets;
pub(crate) mod state;
pub(crate) mod tree_refs;
mod testing;
#[cfg(debug_assertions)]
mod explain;
pub mod write;

#[doc(hidden)]
pub use testing::{CommitDigest, IndexDigest, IndexField};
#[cfg(debug_assertions)]
#[doc(hidden)]
pub use explain::Row;
pub use large::Trees;
pub use write::Mutation;

use crate::apply::Reason;
use crate::error::{Error, Result};
use crate::events::{Event, Events};
use crate::identity::Identity;
use clock::Hlc;
use osis_commit::{CommitBlob, Form, Header};
use osis_base::{Ak, BlobId, Clock, CommitId, SyncId, Tid, Ts, WallMs};
use osis_crdt::{Dot, Fragment, SourceKind};
use osis_crypto::{CryptoRngCore, SeededRng};
use osis_keys::ActorEpochs;
use journal::{JMap, JNested, JSet, JSetMap, Journaled};
use osis_perm::Point;
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
        Config { software: format!("osis-engine {}", env!("CARGO_PKG_VERSION")), store: StoreConfig::default() }
    }
}


/// What a node holds of one part of an applied commit: one state, so no part is both dropped
/// and missing, or held as its leftover and dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hold {
    /// Its body. `whole`: a plain part whose delta replaces the aspect whole
    /// (`retention::snapshot::replaces`), what stands as an own replace (`Indexes::own_replaces`).
    Body { whole: bool },
    /// Its leftover (expired, purged, a body carrying a copy of such a value:
    /// `retention::make_leftover`, `retention::strip_carried`): read from `records::LEFTOVER` as
    /// the body. Held for the engine, no body for node-sync (`Meta::body_gone`). `valued`: held so
    /// only for the copies it carries, none of its own writes value-less (a snapshot, which has
    /// none, always); such a leftover is a body like a whole one for keep bounds, covering and a
    /// purge naming it (`Meta::bare`; spec/commits.md §5 Dropping a body). `whole` as for `Body`,
    /// judged on the leftover (which keeps every reset).
    Leftover { whole: bool, valued: bool },
    /// Every delta of it dropped (as covered, expired or purged), with what it keeps.
    Dropped(Dropped),
    /// None of its deltas held here: a part that may still arrive late, or never, or one dropped
    /// under a cover since turned invalid (`retention::uncover`) (spec/permissions.md §5.2: a
    /// snapshot's copies of their writes count).
    Missing(Missing),
}

/// Why a part is missing, where it matters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Missing {
    #[default]
    Plain,
    /// Reopened to be fetched again (`retention::reopen_to_fetch`: valid again, uncovered, a
    /// fall), memory class: a memory commit holding no part stays known while one is
    /// (`retention::kept_invalid`), so a superseded part beside it does not take the commit, and
    /// the part to come, with it (`retention::memory::forget_if_spent`).
    ToFetch,
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
    /// Its thing was destroyed (`retention::destroy`): as `Other`, but a value-less leftover goes too.
    Destroyed,
}

/// What a dropped part keeps in its commit record (spec/commits.md §5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dropped {
    /// The held valid snapshots that covered its body when it dropped (a forgotten one carries
    /// as the covers it dropped under do, `retention::handed`): their copies of its
    /// writes are its writes (`apply::rebuild`); once none carries it, a part dropped as
    /// covered is missing again (`retention::uncover`).
    pub covered_by: BTreeSet<CommitId>,
    pub why: DropFor,
    /// A part dropped as covered: the wall ms from which a right holder may delete its body at
    /// peers, `MAX_DRIFT` past its keep-at-least bound when it had one (0: at once). A local drop
    /// follows this node's clock alone; a delete at peers waits for every node's clock to agree
    /// (spec/commits.md §5 Keep bounds).
    pub hosts_from: u64,
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
    /// A memory part vanished as superseded (spec/sync-compaction.md §2): the later parts of its author's
    /// that superseded it (the lane's carriers once its commit is forgotten). Never stored:
    /// memory commits are not.
    pub superseded_by: BTreeSet<CommitId>,
}

/// The aspects of `m`'s parts not held (`Indexes::missing`).
fn missing_of(m: &Meta) -> BTreeSet<(Ak, Tid)> {
    m.view.aspects.iter().enumerate().filter(|(ai, _)| m.missing(*ai)).map(|(_, a)| (a.ak.clone(), a.tid)).collect()
}

/// The coverers the dropped parts of `m` name (`Dropped::covered_by`).
fn covers_of(m: &Meta) -> BTreeSet<CommitId> {
    m.dropped_parts().flat_map(|(_, d)| d.covered_by.iter().copied()).collect()
}

impl Dropped {
    pub(crate) fn as_cover(&self) -> bool {
        self.why == DropFor::Cover
    }
}

/// A keyset a `keys.0` body wrote: its role, epoch, the epochs its supersedes list names, its
/// KEM public key (`None`: another suite, or malformed: never sealed to) and the demotions it
/// carries (spec/crypto.md §4, Carried demotions).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeysetRec {
    pub role: osis_base::Role,
    pub epoch: osis_crypto::Epoch,
    pub lists: Vec<osis_crypto::Epoch>,
    pub kem: Option<osis_crypto::KemPublicKey>,
    /// The digest of the rotation's names it publishes (spec/crypto.md §4).
    pub names: osis_keys::NamesDigest,
    /// The keysets of holder actors it records its rotation left them out at (spec/crypto.md §4,
    /// Left out).
    pub left_out: Vec<(Tid, osis_crypto::Epoch)>,
    /// The commits whose demotions it carries: those it lists, and its rotation commit where it
    /// `demotes` (the commit its write names, `KeysBody::of`).
    pub demotions: Vec<CommitId>,
}

/// A valid keyset body noted (`Indexes::keysets`): the epochs the supersedes lists of the bodies
/// writing it name, joined, the key of its earliest body carrying a KEM key of suite 1 (the key
/// itself is read from that body when sealing to it, `apply::keys::keyset_kem`: an index row of
/// it would be its third copy; earliest, so two bodies naming different keys give every node
/// the same), the key of its
/// earliest body (Seal's order fallback and the order rule read it), the names digests they
/// publish, each with its body's author (what binds a history entry to a rotator,
/// spec/crypto.md §4: a forger's body binds entries to the forger), the left-out keysets they
/// record, joined (Seal reads them at the actor's current epochs), and the demotions they carry,
/// joined (spec/crypto.md §4, Carried demotions: its rotation commit among them where it demotes). Held
/// only once those are (`Core::keyset`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeldKeyset {
    pub lists: BTreeSet<osis_crypto::Epoch>,
    pub kem_in: Option<osis_perm::Point>,
    /// The key of its earliest valid body; `None` only before one is noted.
    pub since: Option<osis_perm::Point>,
    pub names: BTreeSet<(osis_keys::NamesDigest, Tid)>,
    pub left_out: BTreeMap<Tid, BTreeSet<osis_crypto::Epoch>>,
    pub demotions: BTreeSet<CommitId>,
}

/// A box record a `keys.0` body writes (spec/crypto.md §4, Stale): the actor's box of `role` at
/// `epoch` to holder actor `holder` names `keysets` of it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SealedRec {
    pub role: osis_base::Role,
    pub epoch: osis_crypto::Epoch,
    pub holder: Tid,
    pub keysets: Vec<osis_crypto::Epoch>,
}

/// The box records of one epoch of an actor noted from its valid `keys.0` bodies
/// (`Indexes::sealed`): per holder actor the keysets they name, joined (Stale reads them: a node
/// holding none of the actor's boxes judges its epoch so), and the commits whose bodies wrote
/// them (placed with the epoch's keyset, spec/crypto.md §4 Carried).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SealedAt {
    pub keysets: BTreeMap<Tid, BTreeSet<osis_crypto::Epoch>>,
    pub by: BTreeSet<CommitId>,
}

impl HeldKeyset {
    /// Whether a body of it is ordered before `p`.
    pub fn held_before(&self, p: &osis_perm::Point) -> bool {
        self.since.is_some_and(|s| s < *p)
    }
}

/// A snapshot part's frontiers and `Absorbed` (commit, signer).
pub(crate) type Gives = (osis_crdt::Frontiers, Vec<(CommitId, Tid)>, osis_crdt::Facts);

impl Hold {
    /// Part `ai` as stored: `head`'s dropped and stripped parts (its `Dropped` taken), then the
    /// meta row's `missing` and `whole` bits (`index::meta_row`).
    pub(crate) fn stored(ai: usize, head: &mut index::RecordHead, missing: bool, whole: bool) -> Hold {
        if let Some(d) = head.dropped.remove(&ai) {
            Hold::Dropped(d)
        } else if head.stripped.contains(&ai) {
            Hold::Leftover { whole, valued: head.valued.contains(&ai) }
        } else if missing {
            Hold::Missing(Missing::Plain)
        } else {
            Hold::Body { whole }
        }
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
    pub signer: Tid,
    /// Its one purge author (`Header::purge_author`), in the clear in either path form. Interim
    /// (notes/a1-spec/README.md step 3): the old walk reads it as the thing the commit acts for on
    /// every thing it writes.
    pub purge_author: Tid,
    /// In a split commit, what this node decided of each thing's path (`apply::paths::decided`:
    /// `true` known, `false` bad, absent while it opens nowhere here): a part on a thing not known
    /// is judged invalid. `None` where the path is in the clear.
    pub paths: Option<Arc<BTreeMap<Tid, bool>>>,
    /// Some list goes by link: the header is resolved from blobs at open (decoded there).
    pub linked: bool,
    /// A memory commit (the ephemeral marker): held in memory, never durable to node-sync,
    /// receipts or demotion frontiers.
    pub memory: bool,
    pub aspects: Vec<AspectView>,
    /// A role commit's frontier (`validity::header_frontier`; perm's adaptation reads it
    /// for demotions); `None` on other kinds.
    pub frontier: Option<Arc<osis_perm::Frontier>>,
    /// It carries a request, a purge or a release (`Header::requests`; `retention::lasting`).
    pub purges: bool,
    /// The epoch an account's commit is signed at (spec/wire.md §4): what the epoch rule reads
    /// (`Core::standing`); `None` for any other author.
    pub epoch: Option<CommitId>,
    /// The header's own-cover marker (spec/wire.md §4 field 18; `retention::others_own_cover`).
    pub own_cover: bool,
}

/// One aspect entry as `View` keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AspectView {
    pub tid: Tid,
    pub ak: Ak,
    pub lo: u64,
    pub hi: u64,
    /// The fire it claims to replace (spec/commits.md §5 Signals).
    pub replaces: Option<CommitId>,
    /// That fire's floor as its writer read it (`osis_commit::AspectEntry::original_floor`).
    pub original_floor: u64,
}

impl View {
    /// The view of `h`, the things of a split commit whose paths are known here `paths`.
    pub fn of(h: &Header, paths: Option<Arc<BTreeMap<Tid, bool>>>) -> View {
        // what `View::aspect` searches by (spec/wire.md §4)
        debug_assert!(h.aspects.is_sorted_by_key(|a| (a.tid, a.ak.as_str().len(), a.ak.as_str().as_bytes())), "aspects sorted");
        View {
            ts: h.ts,
            kind: h.kind,
            form: h.form,
            signer: h.signer,
            purge_author: h.purge_author(),
            paths,
            linked: h.links != osis_commit::Links::default(),
            memory: h.ephemeral.is_some(),
            aspects: h.aspects.iter().map(|a| AspectView { tid: a.tid, ak: a.ak.clone(), lo: a.lo, hi: a.hi, replaces: a.replaces, original_floor: a.original_floor }).collect(),
            frontier: if h.kind == osis_commit::Kind::Role { crate::apply::validity::header_frontier(h) } else { None },
            purges: !h.purge.is_empty(),
            epoch: h.epoch,
            own_cover: h.own_cover,
        }
    }

    /// Its purge author where that is not its signer.
    pub fn other_purge_author(&self) -> Option<Tid> {
        Some(self.purge_author).filter(|x| *x != self.signer)
    }

    /// Whether the path it states for thing `t` is known here and not bad (`paths`).
    pub fn path_known(&self, t: &Tid) -> bool {
        self.paths.as_ref().is_none_or(|p| p.get(t) == Some(&true))
    }

    /// The index of aspect `(tid, ak)` (`osis_commit::aspect_position`).
    pub fn aspect(&self, tid: &Tid, ak: &str) -> Option<usize> {
        osis_commit::aspect_position(&self.aspects, tid, ak, |a| (&a.tid, a.ak.as_str()))
    }

    /// The indexes of its aspects on `tid` (`osis_commit::aspects_on`).
    pub fn aspects_on(&self, tid: &Tid) -> std::ops::Range<usize> {
        osis_commit::aspects_on(&self.aspects, tid, |a| &a.tid)
    }
}

/// `Engine::point`.
pub type ReadPoint = (u64, u64, u64, u64);

/// A commit's header, decoded from its stored bytes on first use. The bytes hash to the commit
/// ID and were verified on arrival by a build with these rules (the index tag), so decoding
/// does not fail; if it does (a bug, damaged memory) the header reads as its view with every
/// other field empty, the running transaction fails (`Error::Corrupt`) and readers outside one
/// (`Engine::header`) see none (`decoded`).
pub struct LazyHeader(Lazy);

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

/// A clone shares the bytes; in a world copy (`osis_base::copying`) a header not decoded yet sets
/// the copy's fault flag (`Core::header_fault`), not the original's.
impl Clone for LazyHeader {
    fn clone(&self) -> LazyHeader {
        LazyHeader(match &self.0 {
            Lazy::Ready(h) => Lazy::Ready(h.clone()),
            Lazy::Stored(got, s) if got.get().is_none() && osis_base::copying::in_copy() => {
                let s = osis_base::copying::remap(s, |s| StoredHeader {
                    id: s.id,
                    bytes: s.bytes.clone(),
                    view: s.view.clone(),
                    fault: osis_base::copying::remap(&s.fault, |f| std::sync::atomic::AtomicBool::new(f.load(std::sync::atomic::Ordering::Relaxed))),
                });
                Lazy::Stored(std::sync::OnceLock::new(), s)
            }
            Lazy::Stored(got, s) => Lazy::Stored(got.clone(), s.clone()),
        })
    }
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

    /// Whether `o` holds this header's very value (shared bytes or decode): what an index write
    /// compares to tell a commit's fixed facts unchanged (`commits::Commits`).
    pub(crate) fn same(&self, o: &LazyHeader) -> bool {
        match (&self.0, &o.0) {
            (Lazy::Ready(a), Lazy::Ready(b)) => Arc::ptr_eq(a, b),
            (Lazy::Stored(_, a), Lazy::Stored(_, b)) => Arc::ptr_eq(a, b),
            _ => false,
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
            Some(h) => {
                // the persisted view is the header's (index check: an open from the index
                // equals a rebuild from the commit records)
                debug_assert_eq!(View::of(&h, self.view.paths.clone()), *self.view, "meta row of {:?} is stale", self.id);
                Ok(Arc::new(h))
            }
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
    Header::decode_stored(bytes).ok()
}

fn fallback_header(v: &View) -> Header {
    Header {
        signer: v.signer,
        path: osis_commit::Paths::default(),
        kind: v.kind,
        ts: v.ts,
        form: v.form,
        expires: None,
        aspects: v.aspects.iter().map(|a| osis_commit::AspectEntry { tid: a.tid, ak: a.ak.clone(), lo: a.lo, hi: a.hi, purge_by: Default::default(), keys: Vec::new(), hash: [0; 32], replaces: a.replaces, original_floor: a.original_floor }).collect(),
        purge: Vec::new(),
        undoes: None,
        blind: [0; 16],
        keys: Vec::new(),
        frontier: None,
        links: Default::default(),
        ephemeral: None,
        epoch: None,
        rotation: None,
        reseal: None, own_cover: v.own_cover, adminless: false,
        remains: None,
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
#[derive(Default, Clone, PartialEq)]
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
        Some(Owned::of_form(h.form, h.signer, id, a.lo, a.hi))
    }
    /// `of` from the commit's `View`.
    pub fn of_view(v: &View, id: &CommitId, ai: usize) -> Option<Owned> {
        let a = v.aspects.get(ai)?;
        Some(Owned::of_form(v.form, v.signer, id, a.lo, a.hi))
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
        #[derive(Clone, Default)]
        pub struct Indexes {
            $($(#[$a])* pub $f: $t,)*
        }

        /// Every index's name, in declaration order (the index check's coverage test).
        #[cfg(test)]
        pub(crate) const INDEX_NAMES: &[&str] = &[$(stringify!($f),)*];

        /// A point in every index's journal (equal to a later one: nothing changed between).
        #[doc(hidden)]
        #[derive(PartialEq)]
        pub struct IndexesMark {
            $($f: <$t as Journaled>::Mark,)*
        }

        impl Indexes {
            /// Each index's stamps named by its field.
            fn named(mut self) -> Self {
                $(self.$f.name(concat!("index: ", stringify!($f)));)*
                self
            }
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
    pub commits: Commits,
    /// Commits with a part invalid here, per aspect (`Core::index_validity`).
    pub invalid: JSetMap<(Tid, Ak), CommitId>,
    /// Held commits with a part not held (`Hold::Missing`), per aspect, AK first: among
    /// them the commits a removal of a reference there must cover (`write::seeing`).
    pub missing: JSetMap<(Ak, Tid), CommitId>,
    /// Held commits per aspect their header lists: (`ts`, commit), whatever the part's validity
    /// and whether its body is held. Invariant (also for `by_thing`): it finds
    /// commits, never decides anything alone, since any signer's header can list any aspect.
    /// What a thing has reads the state (`Tx::has_state`); what a commit counts for (a field's retention) reads its parts valid here
    /// (`Meta::valid_at`), body held or not.
    pub by_aspect: JSetMap<(Tid, Ak), (Ts, CommitId)>,
    /// `by_aspect`'s keys, aspect first: the things holding a commit on each aspect, read per
    /// aspect (the actors with a `secrets.0`, the link-seed things).
    pub aspect_things: JSetMap<Ak, Tid>,
    /// Per account, the sequence number of its last rotation held or dropped
    /// (`Core::note_rotation`): what `Core::account_view` is cached by.
    pub rotations: JMap<Tid, u64>,
    /// Accounts whose rotations held changed since their epochs were last judged
    /// (`Core::refresh_epochs`).
    pub epochs_due: JSet<Tid>,
    /// Per account with a rotation judged, what the epoch rule says of its commits
    /// (`JudgedEpochs`; `Core::refresh_epochs` re-judges what moved). Persisted.
    pub epochs: JMap<Tid, Arc<crate::flows::account::JudgedEpochs>>,
    /// Per account, its held commits at closed epochs that a counting thing list or listing
    /// names (`Core::refresh_epochs`): a row each, as the history it grows with. Persisted.
    pub named: JSetMap<Tid, CommitId>,
    /// Per held role commit at an epoch, its inner and merge signatures (spec/wire.md §4), read
    /// when the chain is built (`Core::account_view`; `note_role_sigs`). Not persisted: an open
    /// decodes them from the signature items it reads with each record's header bytes.
    pub role_sigs: JMap<CommitId, Arc<RoleSigs>>,
    /// Held commits of accounts per (account, epoch they are signed at).
    pub by_epoch: JSetMap<(Tid, CommitId), CommitId>,
    /// Held commits of accounts a thing list or listing may name otherwise since they were last
    /// judged (`flows::lists::due`; `refresh_epochs`).
    pub names_due: JSet<CommitId>,
    /// The places listing walks on a durable signal: every fire but the honored versions, valid
    /// or not (`edits`, persisted).
    pub originals: JSetMap<(Tid, Ak), (Ts, CommitId)>,
    /// A durable signal's valid parts claiming `replaces`, per (thing, aspect, named commit, actor):
    /// (`ts`, version). Forged claims are other actors' and are never read (`edits`).
    pub versions: JSetMap<(Tid, Ak, CommitId, Tid), (Ts, CommitId)>,
    /// Compaction snapshots held per aspect, with their frontiers and `Absorbed`: the bodies
    /// carrying a write besides its own (spec/commits.md §5); what settles suspect flags
    /// (`receipt::settled`).
    pub snapshots: JMap<(Tid, Ak), Vec<HeldSnapshot>>,
    /// Snapshots per aspect whose dropped part still stands in (`Dropped::stands_in`; derived at
    /// open, not persisted).
    pub dropped_snapshots: JSetMap<(Tid, Ak), CommitId>,
    /// The suspect flags per aspect (`retention::suspect`, rows `q/`): what sync follows per key,
    /// new keys by its `Feed`.
    pub suspects: JMap<(Tid, Ak), Arc<crate::retention::suspect::Flag>>,
    /// Per coverer, the commits with a dropped part naming it (`Dropped::covered_by`;
    /// derived, as `Core::put_meta` keeps it): what a coverer forgotten hands its own covers
    /// down to (`apply::unindex_commit`).
    pub covered_under: JSetMap<CommitId, CommitId>,
    /// Per forgotten coverer a held part still names, the covers its parts dropped under
    /// (`retention::handed`, `records::HANDED`): the chain of covers runs past it.
    pub handed: JMap<CommitId, Arc<crate::retention::handed::Handed>>,
    /// Per coverer, the forgotten coverers whose kept covers name it (derived from `handed`).
    pub handed_under: JSetMap<CommitId, CommitId>,
    /// Per aspect the newest `ts` of a commit forgotten here with a valid part on it
    /// (`apply::unindex_commit`): what stands for the forgotten parts an undo may have replaced
    /// (`undo::replaced_kept`). A durable commit's row persists (`records::FORGOTTEN`).
    pub forgotten: JMap<(Tid, Ak), Ts>,
    /// Per aspect, the commits forgotten here whose writes a held snapshot of it still carries,
    /// each with its stamp and purge facts from its header (`retention::names`,
    /// `records::NAMES`): what a purge names it by and judges it by.
    pub forgotten_names: JNested<(Tid, Ak), CommitId, crate::retention::names::Name>,
    /// Per (thing, aspect, author) the held parts of plain commits of a coverable aspect (`retention::snapshot::own_aspect`): what an own replace may cover, without
    /// walking the aspect (derived, as `Core::put_meta` keeps it).
    pub own_held: JSetMap<(Tid, Ak, Tid), (Ts, CommitId)>,
    /// `own_held`'s subset of whole replaces (spec/commits.md §5 Own replaces), any validity:
    /// the candidates that may cover an older commit of the author.
    pub own_replaces: JSetMap<(Tid, Ak, Tid), (Ts, CommitId)>,
    /// Held commits per thing they hold a delta of (re-judging a thing's deltas).
    pub by_thing: JSetMap<(Tid, Tid), CommitId>,
    /// Per thing, the chains its held commits' authors' chains are made of (spec/permissions.md
    /// §4, a commit's author's chain): (author, the thing) for each author of a commit with a
    /// delta on it, (author, actor) for each such commit acting for another actor (`acting_on`).
    /// Each goes under every sync ID carrying the thing (`Engine::sync_certificates`). Moves only
    /// as a chain comes or goes.
    pub chains_on: JSetMap<Tid, (Tid, Tid)>,
    /// Held commits per (thing, author, actor) with a delta on the thing whose actor is not their
    /// author: when the last goes, `chains_on` loses (author, actor).
    pub acting_on: JSetMap<(Tid, Tid, Tid), CommitId>,
    /// Held split commits with a thing whose path opens nowhere here yet (`View::paths`), opened
    /// again as role inputs move (`apply::paths::refresh`).
    pub paths_unknown: JSet<CommitId>,
    /// `by_thing` for role commits alone: what an account's chain reads of its role commits on
    /// its account root (`Core::devices_read`), so a content write on D (its `holds.0`, its tickets) moves no account's chain.
    pub role_on: JSetMap<(Tid, Tid), CommitId>,
    /// Held commits carrying a purge request, per thing they have a delta on (a request has one
    /// on each thing it names, spec/commits.md §5): what finds a thing's requests
    /// (`retention::destroy`) without reading its other commits.
    pub purges_on: JSetMap<Tid, CommitId>,
    /// Held commits per (acting thing, signer), where those differ: re-judging
    /// `validity::acts_for` when the actor's timeline changes, a demotion's frontier, the
    /// actors this node acts for (`Core::acting`).
    pub by_actor: JSetMap<(Tid, Tid), CommitId>,
    /// Node- and session-form ranges per (tid, ak, own source): (lo, commit) -> hi. Keyed by
    /// commit too: equivocating commits of one range are all held (spec/commits.md §4).
    pub ranges: JNested<(Tid, Ak, osis_crdt::Source), (u64, CommitId), u64>,
    /// Written only through `apply::waits::set_pending`, with `pend_on`.
    pub pending: JMap<CommitId, Reason>,
    /// Pending commits by what they await (`apply::waits::Wake`): an arrival examines only those
    /// parked under it. Derived from `pending`, never persisted.
    pub pend_on: JSetMap<crate::apply::Wake, CommitId>,
    /// `pend_on`'s keys per pending commit.
    pub pend_keys: JMap<CommitId, Arc<Vec<crate::apply::Wake>>>,
    /// Pending commits per thing they need held (`retention::needed`): each signer (author, and
    /// actor where it differs, from the header), as a held commit's, and the thing whose record
    /// or chain it awaits. Derived from `pending` with `pend_on`, never persisted.
    pub pend_by: JSetMap<Tid, CommitId>,
    /// `pend_by`'s keys per pending commit.
    pub pend_needs: JMap<CommitId, Arc<Vec<Tid>>>,
    pub void: JSet<CommitId>,
    /// Freed links judged freed, by (blob, thing) (`retention::freed`): what sync deletes.
    pub freed: JMap<(osis_base::BlobId, Tid), Arc<crate::retention::freed::Freed>>,
    /// The commit, parts and unopened sections each opened or sealed blob holds (`sync::bodies`).
    pub blob_parts: JMap<osis_base::BlobId, Arc<crate::sync::BlobOf>>,
    /// `blob_parts`' blobs per commit: they go with it (`sync::bodies::forget`).
    pub commit_blobs: JSetMap<CommitId, osis_base::BlobId>,
    /// The certificate blobs sealed here per (sync ID, kind: records or a rotation's lists),
    /// each with what it carries (`sync::certblobs`).
    pub cert_blobs: JMap<(SyncId, crate::sync::CertKind), Arc<crate::sync::CertBlobs>>,
    /// (thing, rotation) per thing list held here (`flows::lists`; kept for good, as the lists
    /// are): `sync::listed` follows its feed.
    pub lists_on: JSet<(Tid, CommitId)>,
    /// Fall marks per aspect (`sync::falls`, spec/sync-judgement.md §4): a count of events, not
    /// derived from the commits held, so no rebuild compares it.
    pub falls: JMap<(Tid, Ak), u64>,
    /// Self-removals waiting to be held elsewhere (`sync::held`).
    pub held_wait: JSet<CommitId>,
    /// Per pending commit, its carriers (`apply::carriers`, rows `pc/`): an event, not derived
    /// from the commits held, so no rebuild compares it.
    pub carriers: JSetMap<CommitId, crate::apply::carriers::Carrier>,
    /// `carriers` by fire and report: what each carries.
    pub carrying: JSetMap<crate::apply::carriers::Carrier, CommitId>,
    /// Per thing, the commits with an opening written under an epoch of it (`sync_ids::opened`,
    /// `records::OPENED_UNDER`): what goes with the thing.
    pub opened_under: JSetMap<Tid, CommitId>,
    /// Per sync ID, the place (`Core::place`) the last complete pass sync noted of it began at
    /// (`sync::held`): an event, not derived from the commits held, so no rebuild compares it.
    pub passes: JMap<SyncId, u64>,
    /// Per actor, the place (`Core::place`) the newest role commit on it (`roles.0`, `secrets.0`,
    /// `keys.0`) applied from elsewhere arrived at (`sync::held`): an event, as `passes`.
    pub role_arrivals: JMap<Tid, u64>,
    /// Per cause a rule waits a complete pass after (`sync::held::Cause`), the place (`Core::place`)
    /// this node first judged it at (`sync::held`): an event, as `passes`.
    pub cause_at: JMap<crate::sync::held::Cause, u64>,
    /// Per (thing, commit), the wait for a `retention^.0` part not received (`sync::setting`, rows
    /// `sw/`): an event, as `passes`.
    pub setting_waits: JMap<(Tid, CommitId), crate::sync::setting::Wait>,
    /// Per (actor, holder), a re-seal a stranded report asked for (`sync::stranded`, rows `rs/`):
    /// an event, so no rebuild compares it.
    pub reseal_asks: JMap<(Tid, Tid), crate::sync::stranded::Ask>,
    /// Deltas whose value-carrying writes are held value-less (expired, purged).
    pub valueless: JMap<(Tid, Ak), Vec<Owned>>,
    /// Independent things whose epochs this node holds.
    pub secrets: JMap<Tid, ActorEpochs>,
    /// Things held destroyed (`Core::destroyed`), rows `records::DESTROYED`: kept where a
    /// destruction lands or falls (`retention::destroy::apply_destructions`) and where a thing is
    /// released, derived from the mintings when the index is rebuilt. What
    /// `Engine::destroyed_upstream` walks.
    pub destroyed: JSet<Tid>,
    /// Things independent here (`apply::keys::refresh_independent`): a held commit's
    /// valid `keys.0` part wrote a keyset.
    pub independent: JSet<Tid>,
    /// Derived read epochs of things this node sealed a section under while the thing was dependent
    /// here, until a rotation of it carries them (`rotation::merge`; `records::DERIVED_WRITTEN`).
    /// A key emptied stays until the next open: removing it would move every memo that read an
    /// absent key (each actor's rotation run). `check_index` compares the non-empty keys.
    pub derived_written: JMap<Tid, BTreeSet<osis_crypto::Epoch>>,
    /// Held commits whose `keys.0` part on a thing wrote a keyset in its body, any validity
    /// (`records::OWN_SECRETS`): thing -> commits.
    pub keyset_parts: JSetMap<Tid, CommitId>,
    /// Things with a `sync.0` state (`Engine::things_with_sync_ids`), kept with the state
    /// (`Tx::derive`).
    pub sync_recorded: JSet<Tid>,
    /// The things whose `sync.0` state records each sync ID, owned there or not (`Tx::derive`):
    /// a sync ID finds its owner without a walk.
    pub sync_recorders: JSetMap<SyncId, Tid>,
    /// Per thing with a `sync.0` state, the sync IDs it records (`sync_recorders` inverted).
    pub sync_recorded_ids: JMap<Tid, BTreeSet<SyncId>>,
    /// Keyed `roles.0` entries seen: (target, entry dot) -> (holder, created value).
    pub holder_keys: JMap<(Tid, Dot), Tid>,
    /// Role commits whose removed keys are not known yet.
    pub unresolved: JSet<CommitId>,
    /// Roles `secrets.0` and `keys.0` deltas need (by commit and aspect index).
    pub rotation_role: JMap<(CommitId, usize), osis_base::Role>,
    /// Per value aspect whose bodies leave history in order (`retention::leaving`): each held
    /// valid part replaced there, by (replaced-at, commit), in history or not. Persisted
    /// (`records::LEAVING`).
    pub leaving: JSetMap<(Tid, Ak), (Ts, CommitId)>,
    /// `leaving` by part: (commit, thing, aspect) to its row's replaced-at (derived).
    pub dated: JMap<(CommitId, Tid, Ak), Ts>,
    /// Per aspect whose bodies leave history in order: (its timer's due wall ms, `u64::MAX`:
    /// none; the last place out of history). Persisted (`records::LEAVE_FROM`).
    pub leave_from: JMap<(Tid, Ak), crate::retention::leaving::From>,
    /// `leave_from`'s timers by due wall ms (derived).
    pub leave_due: JSetMap<u64, (Tid, Ak)>,
    /// What each held `retention^.0` delta of a thing reading as a setting says, in key order,
    /// valid or not (spec/commits.md §5 The setting; `validity::Judge::settings` takes the valid).
    pub retention: JMap<Tid, Vec<(Point, Arc<osis_schema::core_types::RetentionSetting>)>>,
    /// `secrets.0` parts of role commits that write beyond their grantees' boxes (an invite
    /// grant may carry only those, spec/permissions.md §2).
    pub grant_overreach: JSet<(CommitId, usize)>,
    /// Keyed boxes per holder: holder -> (actor, box key), from `secrets.0` entries seen.
    pub boxes_to: JSetMap<Tid, (Tid, osis_base::Value)>,
    /// Every held `addenda.0` delta (spec/permissions.md §5.2, Addenda), by (thing, commit):
    /// its author's write whether its body is held or not, with the entries its body says while
    /// held (`validity::note_addenda`, `validity::forget_addendum_body`).
    pub addenda: JMap<(Tid, CommitId), Arc<osis_perm::Addendum>>,
    /// `addenda` by the rotation or removal an entry is keyed by: (thing, addendum commit). A
    /// rotation joining or leaving an epoch's closers moves only the commits these list
    /// (`refresh_epochs`).
    pub addenda_keyed: JSetMap<CommitId, (Tid, CommitId)>,
    /// Removals whose addenda this node may owe, to judge at the end of the
    /// transaction (`flows::addenda`): every held one at an open, then those whose component
    /// changed.
    pub addenda_due: JSet<CommitId>,
    /// The removals judged by `flows::addenda`, by each thing whose roles for this node their
    /// judgement reads (`flows::addenda::Gathered::watched`): this node's roles moving there, or
    /// the thing's component walked anew, makes them due again.
    pub addenda_watch: JSetMap<Tid, CommitId>,
    /// The things each removal is filed under in `addenda_watch`.
    pub addenda_filed: JMap<CommitId, Arc<BTreeSet<Tid>>>,
    /// What each removal's judgement gathered (`flows::addenda::Gathered`), kept while it is
    /// filed or due: gathered anew only when what it reads may have changed. Memory only.
    pub addenda_gathered: JMap<CommitId, Arc<crate::flows::addenda::Gathered>>,
    /// The removals judged by `flows::addenda`, by the holders their edge writes name and their
    /// author: (party, the removal's `ts`, removal). A commit ordered no later than the removal,
    /// applying and reaching one (`Held::reach` from its author, its edge targets and everything
    /// upstream of its edge holders), makes it due again (`flows::addenda::wake`).
    pub addenda_wake: JSet<(Tid, osis_base::Ts, CommitId)>,
    /// `addenda_wake`'s removals by `ts`: a commit stamped after the newest wakes none.
    pub addenda_wake_ts: JSet<(osis_base::Ts, CommitId)>,
    /// Accounts' rotations applied and not yet answered with this node's listing or addenda
    /// (`flows::signing::answer_rotations`; `records::ROTATIONS_DUE`).
    pub rotations_due: JSet<CommitId>,
    /// The earliest valid held commit writing an epoch's keyset in `keys.0` (its rotation):
    /// (actor, role, epoch) -> (`ts`, commit). Absent: unknown. What a box naming the keyset
    /// carries (spec/crypto.md §4, Carried) and a certificate of the actor's current keys.
    pub epoch_intro: EpochIntro,
    /// The held valid keysets (spec/crypto.md §4, held keyset): (actor, role, epoch) for each
    /// keyset a held valid `keys.0` body (a role commit's delta or a compaction snapshot; kept
    /// once dropped, `Dropped::keysets`) writes. `Core::keysets_of` reads one actor's.
    pub keysets: JMap<(Tid, osis_base::Role, osis_crypto::Epoch), HeldKeyset>,
    /// The box records of each epoch (spec/crypto.md §4, Stale): (actor, role, epoch) for each
    /// epoch a held valid `keys.0` body (a role commit's delta or a compaction snapshot) records
    /// a box at.
    pub sealed: JMap<(Tid, osis_base::Role, osis_crypto::Epoch), SealedAt>,
    /// Actors lost by an `until` passing alone, waiting for node-sync to hear their sync IDs out
    /// (`rotation::lost::TIMED_LOST`): actor -> when first judged (engine ms).
    pub timed_lost: JMap<Tid, u64>,
    /// Kept copies (`rotation::lost`): each lost actor kept and the holders it hangs on.
    pub kept: JMap<Tid, BTreeSet<Tid>>,
    /// Things holding a purge-on-replace body this node would cover, an aspect the trigger owes
    /// a weighing (`compact::Trigger::owe`) or an owed re-snapshot (`resnapshots_owed`), but may
    /// not write on yet (`MayWrite::Later`: their minting or delete keys are not here), under
    /// every thing on their record chain: what may move them
    /// (`retention::replace::wake_covers`). Not persisted: an open judges every held
    /// purge-on-replace aspect again, owes the trigger's weighings again
    /// (`Engine::owe_unwritable_held`) and makes every owed re-snapshot due (`purge::load_owed`).
    pub cover_waits: JSetMap<Tid, Tid>,
    /// Aspects this node owes a re-snapshot after purge requests dropped something here, with the
    /// named bodies it had applied (spec/commits.md §5 Purge, `purge::owe_resnapshot`): written in
    /// the purge's transaction (`records::RESNAPSHOTS_OWED`), gone once the snapshot is written or
    /// no longer owed (`Engine::purge_resnapshots`).
    pub resnapshots_owed: JNested<Tid, Ak, BTreeSet<CommitId>>,
    /// The node closure (`sync::units`): derived, built again by an open.
    pub closure: crate::sync::units::Closure,
    /// Sealed fires this node owes until a peer takes one (`flows::inbox`, spec/sync-inbox.md §2),
    /// by fire ID: durable (`flows::inbox::FIRES`).
    pub fires: JMap<crate::flows::inbox::FireId, Arc<crate::flows::inbox::OwedFire>>,
}

/// The steps run inside a transaction, each applied fully or not at all (`Tx::step`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// One pending commit examined and applied again (`Engine::reexamine`).
    Commit,
    /// One part judged alone (`apply::examine`).
    Part,
    /// The addenda one removal owes written (`flows::addenda::write_owed`).
    Addenda,
    /// One purge-on-replace cover written (`retention::settle_none`).
    Cover,
    /// One re-snapshot owed after a purge written (`Engine::purge_resnapshots`).
    Resnapshot,
    /// One account rotation answered with this node's listing or addenda
    /// (`flows::signing::answer_rotations`).
    Rotation,
    /// This node's account's dial list rid of removed nodes' entries (`sync::dial::drop_departed`).
    Dial,
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

/// Whether a commit listener is on a thing (`Engine::listen_commits`).
pub type CommitListeners = Arc<dyn Fn(&Tid) -> bool + Send + Sync>;

/// Tests: faults the custody differential plants (`Core::faults`).
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Faults {
    pub custody_judged: bool,
    pub roster_bare: bool,
    pub merge_random: bool,
    /// Boxes to an account at a stale epoch (revoked, or not counting) stay shut, as if stale
    /// meant unread (`Core::account_keys`).
    pub stale_shut: bool,
}

/// A held role commit's signatures beyond its outer one (`Indexes::role_sigs`): its sealed
/// inner signature (which node made it, read by the account's nodes) and, a rotation, its merge
/// signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleSigs {
    pub inner: Option<[u8; osis_crypto::INNER_LEN]>,
    /// A rotation's inner signature sealed again (`osis_commit::Sigs::more`).
    pub more: Vec<[u8; osis_crypto::INNER_LEN]>,
    pub merge: Vec<osis_crypto::Signature>,
}

/// A point `Core::rollback_to` undoes back to: the journals' points, the lengths of the lists
/// that only grow within a transaction, and the work lists a step's start holds (a copy: they
/// are empty or small there).
pub(crate) struct CoreMark {
    ix: IndexesMark,
    sides: (usize, usize),
    schemas: usize,
    written: usize,
    events: usize,
    commits_named: usize,
    listed_before: usize,
    killed: usize,
    to_date: usize,
    /// `wrote_on`'s length: a write undone owes no holding.
    wrote_on: usize,
    stale: (BTreeSet<Tid>, BTreeSet<Tid>, BTreeSet<Tid>, BTreeSet<CommitId>, bool),
    batched: Option<BTreeMap<(Tid, Ak), Batched>>,
    memory_tx: bool,
    dirty: bool,
    /// `store_rows`: a row written alone (a commit record, a leftover) changes no index.
    records: u64,
    /// `reach_log`'s length.
    reached: usize,
    /// `walks`' log length (`Walks::forget_since`).
    walked: usize,
}

/// A held compaction snapshot of an aspect: `ts`, ID, frontiers, `Absorbed` (commit, signer),
/// and the bounds of what its held body carries valued and value-less (`retention::snapshot::Carried`).
pub(crate) type HeldSnapshot = (Ts, CommitId, osis_crdt::Frontiers, Vec<(CommitId, Tid)>, crate::retention::snapshot::Carried);

/// A decoded commit record: its head (received, origin, dropped parts) and blob.
pub(crate) type CommitRecord = (index::RecordHead, CommitBlob);

/// In-memory state over the store: caches and indexes, rebuilt by `load`. The indexes are
/// journaled (`journal`): a failed transaction undoes its own changes to them. Cloned only by
/// `test_copy`.
#[doc(hidden)]
#[derive(Clone)]
pub struct Core {
    /// The journaled indexes: a failed transaction undoes its own changes to them.
    pub ix: Indexes,
    pub id: Identity,
    pub hlc: Hlc,
    pub states: HashMap<(Tid, Ak), Option<Fragment>>,
    /// `flows::secrets_in` per actor (`memo`): `secrets.0` decoded once and patched by each
    /// join (`apply::atomic`, `Memo::amend`). A pass reads it many times and it grows with the
    /// roster.
    pub(crate) secrets_read: memo::Memo<Tid, Arc<osis_schema::core_types::Secrets>>,
    /// `Engine::head_keys` per (independent thing, step) (`memo`): deriving them is some curve work.
    pub(crate) head_keys: memo::Memo<(Tid, osis_blob::StepId), crate::sync_ids::HeadKeys>,
    /// `Engine::read_credentials` per sync ID (`memo`): sync reads them at each entry it judges,
    /// and they derive a key per held sync secret.
    pub(crate) read_credentials: memo::Memo<osis_base::SyncId, Option<Arc<crate::sync::ReadCredentials>>>,
    /// `Engine::sync_things` (`memo`): asked every sync step and every ephemeral write, built
    /// again only when a closure, the shared set or the sync root it read moved.
    pub(crate) sync_things: memo::Memo<(), Arc<BTreeSet<Tid>>>,
    /// `Engine::thing_sync` per thing and `Engine::sync_set` (`memo`): sync reads them every step.
    pub(crate) thing_sync: memo::Memo<Tid, crate::sync::ThingSync>,
    pub(crate) sync_set: memo::Memo<(), Arc<crate::sync::SyncSet>>,
    /// `Engine::dial_peers` per sync ID (`memo`): sync's dials read it at each move of what it read.
    pub(crate) dial_peers: memo::Memo<SyncId, Arc<Vec<osis_base::Address>>>,
    /// `Engine::roster_holders` per sync ID (`memo`): waits and leaving's peers read it per sync
    /// ID at each step.
    pub(crate) roster_holders: memo::Memo<SyncId, Arc<crate::sync::RosterHolders>>,
    /// This node's account's dial list entries of nodes removed from its account root
    /// (`sync::dial::drop_departed`), followed: settled at each transaction's end that moved what
    /// it read.
    pub(crate) dial_departed: memo::Effects<(), crate::sync::dial::Departed>,
    /// The held split commits waiting for a path to open (`apply::paths::Wait`): built again
    /// from `Indexes::paths_unknown` where `None` (an open, a rollback).
    pub(crate) paths_wait: Option<crate::apply::paths::Wait>,
    /// `Engine::holders_named` per commit (`memo`): an admin's pass reads it for every inbox
    /// copy, and it decodes role parts.
    pub(crate) holders_named: memo::Memo<CommitId, Arc<BTreeMap<usize, BTreeSet<Tid>>>>,
    /// What each read thing's certificates name, per commit (`sync::certified`): `sync_bodies`
    /// reads one commit's row.
    pub(crate) certified: crate::sync::certified::Certified,
    /// The thing lists each read thing's sync IDs carry, per rotation (`sync::listed`).
    pub(crate) listed: crate::sync::listed::Listed,
    /// The records each read thing's sync IDs carry as certificates (`sync::certblobs`).
    pub(crate) cert_records: crate::sync::certblobs::CertRecords,
    /// `rotation::departures` per actor (`memo`).
    pub(crate) departures: memo::Memo<Tid, Vec<osis_keys::Departure>>,
    /// The holders lacking a box of each actor (`rotation::reseal_candidates`, `memo`): O(roster)
    /// a pass otherwise.
    pub(crate) reseal_scans: memo::Memo<Tid, Vec<(Tid, BTreeSet<osis_base::Role>)>>,
    /// The store's row change count (`Store::row_changes`): what `rollback_to` drops the caches
    /// over the store for.
    pub(crate) store_rows: memo::Changes,
    /// `Core::epochs` per thing (`memo`).
    pub(crate) epochs_of: memo::Memo<Tid, Option<Arc<osis_keys::ActorEpochs>>>,
    /// Numbers `Indexes::rotations`; never rolled back.
    pub rotation_seq: u64,
    /// The pass place (`sync::held`): one strictly increasing count that both stamps a role
    /// commit's arrival from elsewhere and begins a complete pass, so the two never tie. Never
    /// rolled back; an open takes the highest place stored.
    pub place: u64,
    /// `Core::account_view` per account (`memo`).
    pub(crate) account_views: memo::Memo<Tid, Option<Arc<crate::flows::account::AccountView>>>,
    /// `Core::account_epochs` per account (`memo`).
    pub(crate) account_epochs_of: memo::Memo<Tid, Option<osis_keys::ActorEpochs>>,
    /// What this node's account's epochs were last judged from (`flows::account::refresh_epochs`);
    /// empty after an open, when the persisted judgment stands.
    pub(crate) epochs_judged_from: Option<crate::flows::account::JudgedFrom>,
    /// Per actor, each holder for keys at its role and its role with key access
    /// (`rotation::members::key_roles`; `memo`): a walk of its holders through destroyed actors.
    pub(crate) key_roles: memo::Memo<Tid, Arc<crate::rotation::members::KeyRoles>>,
    /// `Core::acting` (`memo`).
    acting_of: memo::Memo<(), Arc<Vec<Tid>>>,
    /// `Engine::wrap_blocked` per (actor, walk) (`memo::Cutoff`), refreshed by `Engine::follow`.
    pub(crate) wrap_blocks: memo::Cutoff<(Tid, crate::rotation::Walk), bool>,
    /// `Engine::read_facts` per (sync ID, commit) (`memo::Cutoff`), refreshed by
    /// `Engine::follow`: a body's judgement moves only when its facts do, not with every write on
    /// its aspects.
    pub(crate) read_facts: memo::Cutoff<(SyncId, CommitId), crate::sync::ReadFacts>,
    /// `Engine::held_fate` per commit (`memo::Cutoff`), refreshed by `Engine::follow`.
    pub(crate) held_fates: memo::Cutoff<CommitId, Option<crate::sync::HeldFate>>,
    /// Page indexes of the cached states kept paged in the store.
    pub pages: HashMap<(Tid, Ak), pages::StatePages>,
    pub timelines: held::Timelines,
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
    /// Tests: role commits state the Interim empty path (`Engine::interim_role_paths`).
    pub(crate) interim_role_paths: bool,
    /// The edge writes signed meanwhile may leave a thing adminless, marked (`Engine::leaving_adminless`).
    pub(crate) leave_adminless: bool,
    /// Someone may listen to commit changes (`Engine::watch_commits`).
    pub(crate) commits_watched: bool,
    /// Someone may listen to backlinks (`Engine::watch_references`).
    pub(crate) refs_watched: bool,
    /// What `Core::commits_named` noted in the running transaction.
    commits_named: Vec<(Tid, Ak, CommitId)>,
    /// Whether a commit listener is on a thing (`Engine::listen_commits`).
    pub(crate) commit_listeners: Option<CommitListeners>,
    /// Per listened aspect the running transaction rebuilt whole (a validity flip, an un-merge,
    /// a drop), the commits listed there by state before it (`listing::before_rebuild`).
    pub(crate) listed_before: Vec<((Tid, Ak), BTreeSet<CommitId>)>,
    /// Commits with a write a join of the running transaction superseded, on listened aspects
    /// (`listing::listing_moved`).
    pub(crate) killed: Vec<(Tid, Ak, CommitId)>,
    /// Parts on dated aspects whose replaced-at the running transaction may have moved (a kill, a
    /// rebuild, `retention::leaving::Dating`): their history rows are set again at its end
    /// (`retention::leaving::date_due`).
    pub(crate) to_date: Vec<(Tid, Ak, CommitId, crate::retention::leaving::Dating)>,
    /// Commits to deliver again (`Engine::take_redeliver`). Not journaled: naming one a rollback undid
    /// costs a look. A name goes with its commit (forgotten, or dropped from pending while not
    /// applied), so it holds at most one per commit held. Sync reads none of it.
    pub(crate) redeliver: BTreeSet<CommitId>,
    /// Aspects whose deltas `Engine::commit_forged` replaces by bytes that do not decode.
    pub(crate) forge_bad: BTreeSet<(Tid, Ak)>,
    /// Tests: the running transaction writes states no held body gives (`Engine::damage_index`:
    /// another build's rules), so the rebuild check (`apply::check_rebuilt`) skips it.
    #[cfg(debug_assertions)]
    pub(crate) unchecked_tx: bool,
    /// Debug builds: the aspects valid whole joins or covered drops changed since the rebuild
    /// check last read them (`apply::check_rebuilt`), checked at the end of the engine's history
    /// (`Engine::checked_states`). A copy starts empty: its original checks their shared past.
    #[cfg(debug_assertions)]
    pub(crate) unchecked_states: BTreeSet<(Tid, Ak)>,
    /// Debug builds: what a load from the commit records read of each role commit's edge writes
    /// (`apply::load`), for `Engine::check_index` to compare with the persisted rows.
    #[cfg(debug_assertions)]
    pub(crate) rebuilt_perm: BTreeMap<CommitId, crate::apply::validity::PermParts>,
    /// The blob `Engine::commit_forged` built (its own node drops the bad part).
    pub(crate) forged: Option<Vec<u8>>,
    /// This open's session (spec/crdt.md §2.1): the own source of its content commits, durable
    /// and memory; its counters live in the store's memory overlay.
    pub session: osis_crdt::Session,
    /// This open's second session: the own source of its expiring memory commits (spec/crdt.md
    /// §2.1), so an expired commit, forgotten with its counters, leaves no gap in `session`'s
    /// ranges that a snapshot frontier could not pass.
    pub expiring: osis_crdt::Session,
    /// Sessions this open began after its first (`fresh_session`).
    pub later_sessions: u64,
    /// The compaction trigger's state (spec/sync-compaction.md §1 trigger), in memory.
    pub compaction: crate::retention::compact::Trigger,
    /// Aspects a held valid memory compaction snapshot turned invalid on, whose fresh snapshot
    /// the next `Engine::tick` writes (`apply::memory::resnapshot_fallen`; `next_timer` is now
    /// while any waits).
    pub fallen: BTreeSet<(Tid, Ak)>,
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
    /// Tests: the facts this node's snapshots state, over the true ones (`snapshot::facts_of`).
    #[cfg(test)]
    pub(crate) lie_facts: Option<osis_crdt::Facts>,
    /// Tests: this node's snapshots of this aspect fail with a local error of their own
    /// (`Engine::snapshot`), as one it cannot encode would.
    #[cfg(test)]
    pub(crate) snapshot_fault: Option<(Tid, Ak)>,
    /// Tests: the original's floor this node's edits claim, over the true one (`commit_in`).
    #[cfg(test)]
    pub(crate) lie_floor: Option<u64>,
    /// Tests, faults the custody differential plants (roles-model `custody` controls): seeds held
    /// only from counting epochs (`custody_judged`), a held revocation acting on D's roster apart
    /// from its rotation (`roster_bare`), merges with fresh seeds (`merge_random`), stale boxes shut
    /// (`stale_shut`).
    #[cfg(test)]
    pub(crate) faults: Faults,
    /// Key actors other than the node whose seed this node holds for now: they sign commits
    /// (`Mutation::sign_as`) and open their boxes. Derived: each is held exactly while
    /// `held_keys` or a followed link names it (`Engine::settle_key_actor`). In memory only.
    pub key_actors: memo::Stamped<Tid, Arc<Identity>>,
    /// Key actors held by `Engine::hold_key_actor` until `drop_key_actor` (role flows, bearer use).
    pub(crate) held_keys: BTreeMap<Tid, Arc<Identity>>,
    /// Links this node redeems (`Engine::follow_link`): K to its sync ID from the link text and
    /// the link key L, held in `key_actors`. K's sync ID is in the sync set while followed
    /// (spec/sync-set.md §2). In memory only: sync holds the link durably and follows it again
    /// at a start.
    pub(crate) followed_links: crate::sync_ids::actors::FollowedLinks,
    /// The account this node belongs to: the author of its commits and
    /// the holder of its roles. `None` before it joins one.
    pub account: memo::Tracked<Option<Tid>>,
    /// The wall clock as memos read it (`memo::Clock`, wall ms): set at each transaction and by
    /// node-sync before it asks its memos; a memo reads it whole (`get`) or up to the next time
    /// that moves its answer (`until`, `Core::horizon`).
    pub time: memo::Clock,
    /// Accounts this node signs as, seeds from each one's account root (`Engine::hold_account`),
    /// retaken on every open.
    pub accounts: memo::Stamped<Tid, Arc<crate::flows::account::HeldAccount>>,
    /// The account this node was removed from and has not dropped what it read as it yet
    /// (`flows::signing::leave_if_removed`; the lost-access drop takes it).
    pub left: BTreeSet<Tid>,
    /// A commit of this node's account applied from elsewhere, or the engine opened (not
    /// durable): what it owes its signing chain is looked at at the end of the next complete
    /// pass of its account root's sync IDs (`Engine::pass_end`, `Engine::signing_due`).
    pub signing_due: bool,
    /// No purge-on-replace cover or drop (tests: an oracle holding every body, `Engine::keep_bodies`).
    pub keep_bodies: bool,
    /// The list bound, `MAX_LIST_BYTES` (tests: `Engine::list_bound`): what `receipt::fit` fits a
    /// frontier to and each listing is cut to; a thing list, written inline only, fits the smaller
    /// of it and `CHUNK_THRESHOLD`.
    pub list_bound: usize,
    /// Value-less lists changed in this transaction, written at its end (`retention::persist_valueless`).
    pub valueless_dirty: BTreeSet<(Tid, Ak)>,
    /// Things judged at the end of the transaction for whether a held thing still needs them
    /// (`retention::needed`): a release, `pass_due` at a pass end.
    pub needs_due: BTreeSet<Tid>,
    /// Things judged once the pass in flight ends (`Engine::settle_needs`, `retention::needed`):
    /// one arrived (a record learned or awaited). `None` after an open: every held record and
    /// awaited record is judged then.
    pub pass_due: Option<BTreeSet<Tid>>,
    /// Things that lost a need (a reference to it gone, a commit it signed left pending,
    /// a holder unnamed, an accepted ticket's strong gone): judged once the pass in flight ends,
    /// or at once with none in flight (`Engine::settle_lost`).
    pub lost_due: BTreeSet<Tid>,
    /// Records learned in this transaction (`apply::atomic::learn_record`): a strong newly
    /// reaching such a thing pulls nothing anew (`sync::units::refetch`).
    pub learned: BTreeSet<Tid>,
    /// The (context, thing) members entering the node closure since the last transaction's end
    /// (`apply::wake_entered`): what waits for a thing to be read whole is examined again (a thing
    /// kept unread read again enters a read context). `None` until the first such end, which
    /// reads every awaited thing.
    pub(crate) entered: Option<memo::Feed<(crate::sync::units::Ctx, Tid)>>,
    /// While `Some` (a tick round's expiries): the rebuilds asked, one per aspect, run once
    /// when it ends (`apply::run_batched`).
    pub batched: Option<BTreeMap<(Tid, Ak), Batched>>,
    /// Per aspect undo has checked, which held parts write each position (`undo::touch`).
    pub(crate) touches: crate::undo::touch::Touches,
    /// What judging when bodies were replaced reads of an aspect's held bodies, per aspect
    /// (`retention::bounds::held_writes`, `memo`).
    pub(crate) held_writes: memo::Memo<(Tid, Ak), Arc<crate::retention::bounds::HeldWrites>>,
    /// `held_writes` per aspect as a row (`memo::Cutoff`): a part's date reads the row, not the
    /// aspect's every body, so it copies one read where the memo would copy one per body.
    pub(crate) held_writes_rows: memo::Cutoff<(Tid, Ak), Arc<crate::retention::bounds::HeldWrites>>,
    /// When each held part was replaced, per (commit, aspect index)
    /// (`retention::bounds::dated_replaced_at`, `memo`).
    pub(crate) replaced_dates: memo::Memo<(CommitId, usize), Option<osis_base::Ts>>,
    /// What a waiting snapshot part carries, per (commit, aspect index), as a held snapshot's
    /// bound (`retention::snapshot::Carried`; `None`: no snapshot it can join): decoded once while
    /// its commit waits (`retention::pending`, `memo`).
    pub(crate) waiting_carried: memo::Memo<(CommitId, usize), Option<crate::retention::snapshot::Carried>>,
    /// `Engine::part_keeps` per commit but for the clock (`retention::bounds::commit_bounds`,
    /// `memo`).
    pub(crate) part_bounds: memo::Memo<CommitId, Arc<Vec<(u64, u64)>>>,
    /// The roots each source of a thing links (`Engine::tree_refs`, `memo`).
    pub(crate) tree_roots: memo::Memo<(Tid, tree_refs::Source), Arc<Vec<osis_base::Link>>>,
    /// The trees of each thing's sources, counted as their roots moved (`tree_refs::Reach`).
    pub(crate) tree_reach: HashMap<Tid, tree_refs::ThingReach>,
    /// The things whose `tree_reach` a question took since the transaction began: a failed step
    /// or transaction drops theirs (`forget_reach_since`), as it may have read blobs it held.
    pub(crate) reach_log: Vec<Tid>,
    /// At or before the earliest retention timer held (wall ms; `u64::MAX`: none): set by
    /// `tick` and at open, lowered by every timer put (`Engine::timers_due`).
    pub timer_floor: u64,
    /// Aspects whose purge-on-replace bodies `retention::settle_none` judges at the end of the
    /// transaction.
    pub none_due: BTreeSet<(Tid, Ak)>,
    /// Things whose `retention^.0` deltas arrived, flipped or dropped this transaction: what their
    /// settings judge is judged again at its end (`retention::settings_changed`).
    pub settings_due: BTreeSet<Tid>,
    /// Things whose `retention^.0` parts moved in `Indexes::missing` this transaction: their
    /// setting waits are judged at its end (`sync::setting::judge_due`).
    pub setting_waits_due: BTreeSet<Tid>,
    /// `Engine::rejudge_setting_waits` is running: the transactions it runs judge nothing again.
    pub setting_waits_judging: bool,
    /// Commits with a part judged invalid this transaction (`Core::index_validity`): dropped at
    /// its end where held (`retention::drop_invalid`).
    pub drop_due: BTreeSet<CommitId>,
    /// Parts on counted aspects whose hold, validity or body moved (`Core::note_kept`): their
    /// history's strongs judged at the next closure settle (`refs::kept::settle`).
    pub kept_due: BTreeSet<(Tid, Ak, CommitId, usize)>,
    /// Things whose settings moved: whether their history holds targets is judged at the next
    /// closure settle (`refs::kept::settle`).
    pub kept_things_due: BTreeSet<Tid>,
    /// Things this transaction's own commits minted with an account as admin and did not make independent yet:
    /// given them before a content write on them (`write::independent_first`), else at its end
    /// (`rotation::own_secrets_due`).
    pub own_secrets_due: BTreeSet<Tid>,
    /// Edges (holder, target) a role commit this transaction applied or joined writes: the
    /// removal notices their applied writes owe are judged at its end
    /// (`flows::inbox::owe_removal_notices`).
    pub notices_due: BTreeSet<(Tid, Tid)>,
    /// Things whose removal notices on this node's inbox are judged at its end
    /// (`flows::inbox::removals_due`): a notice naming one arrived, or its tickets were taken at a
    /// strong.
    pub removals_due: BTreeSet<Tid>,
    /// Freed rows (thing, blob) added this transaction: judged at its end, once their states are
    /// rebuilt (`retention::freed::settle_due`).
    pub freed_due: BTreeSet<(Tid, osis_base::BlobId)>,
    /// Commits whose carriers moved, that were taken, or that stopped pending this transaction:
    /// judged at its end (`apply::carriers::settle`).
    pub carriers_due: BTreeSet<CommitId>,
    /// Aspects with a forgotten commit's name (`Indexes::forgotten_names`) whose held snapshots moved this
    /// transaction: judged at its end (`retention::names::settle_due`).
    pub forgotten_names_due: BTreeSet<(Tid, Ak)>,
    /// Coverers that held parts named less this transaction, or held again: their kept covers
    /// (`Indexes::handed`) are judged at its end (`retention::handed::settle_due`).
    pub handed_due: BTreeSet<CommitId>,
    /// Freed rows (thing, blob) whose judgment waits for a node blob not held, by that blob:
    /// judged again once it is (`retention::freed`). Memory only: a start judges every row.
    pub freed_waits: BTreeMap<osis_base::BlobId, BTreeSet<(Tid, osis_base::BlobId)>>,
    /// The commits on durable signal aspects `edits::settle` refolds besides those the journal
    /// names: a keep bound passed with no meta changing (`edits::time_passed`).
    pub refold: BTreeSet<(Tid, Ak, CommitId)>,
    /// What brings back what the node could not judge, since a test peer last took it
    /// (`Engine::take_wakes`; `None`: nothing kept).
    pub wakes: Option<Wakes>,
    /// Owed re-snapshots to try at the next `Engine::purge_resnapshots`
    /// (`Indexes::resnapshots_owed`): newly owed, every one at open, and those on a thing that
    /// may be written on now (`replace::wake_covers`).
    pub resnapshots_due: BTreeSet<(Tid, Ak)>,
    /// Openings of sections not yet written beside their commit (`sync_ids::opened`): `ou/` rows
    /// by commit, written with its record (`Tx::put_commit`), read as rows until then; a commit
    /// never held (a relay-only one) is judged on them alone.
    pub openings: BTreeMap<CommitId, crate::sync_ids::opened::Rows>,
    /// Aspects (`None`) and commits' parts (`Some`, that change's) a read found a link of whose
    /// blob is not held (`Engine::missed_blob`): the next blob stored re-delivers them to watches
    /// (`Tx::store_blobs`: `Cause::Fetched`, `Event::Commits`). Bounded by the aspects and entries
    /// held. A link whose blob never comes stays noted while a watch re-reads it, so each blob
    /// stored costs a re-read of the watched aspects and entries holding one (an aspect's re-read
    /// already costs its size).
    pub missed: BTreeSet<(Tid, Ak, Option<CommitId>)>,
    /// `Engine::delta_live` per delta (`memo`).
    pub(crate) live_bodies: memo::Memo<(CommitId, Tid, Ak), bool>,
    /// `retention::snapshot::covered` per (cover, body, aspect) (`memo`).
    pub(crate) covers: memo::Memo<(CommitId, CommitId, Tid, Ak), Option<bool>>,
    /// `Engine::sync_body_now` per (sync ID, commit) (`memo`).
    pub(crate) sync_body: memo::Memo<(SyncId, CommitId), Option<crate::sync::BodyMeta>>,
    /// `Engine::sync_bodies` per commit (`memo`).
    pub(crate) sync_bodies: memo::Memo<CommitId, Arc<BTreeMap<SyncId, crate::sync::BodyMeta>>>,
    /// `Engine::state_digest` per aspect (`memo`): a suspect list's entries judged by lookup.
    pub(crate) state_digests: memo::Memo<(Tid, Ak), Option<[u8; 16]>>,
    /// `Engine::piece_below` per piece link (`memo`): a node's links, decoded once while held.
    pub(crate) pieces_below: memo::Memo<crate::sync::PieceLink, Option<Arc<Vec<crate::sync::PieceLink>>>>,
    /// Keep-bound judgments (`retention::bounds::part_keep`, `commit_bounds`: a commit's parts at once), for cost
    /// tests (`Engine::replaced_reads`).
    pub replaced_reads: u64,
    /// Held parts walked for their winners judging deaths (`retention::bounds::winners_of`), for
    /// cost tests: a few per part judged, never per death.
    pub death_walks: u64,
    /// Aspect rebuilds run (`apply::rebuild`). Tests: what a validity change costs.
    pub rebuilds: u64,
    /// Stored commit records and their parts, decoded once per write of the record
    /// (`decoded::DecodedCommits`).
    pub(crate) decoded: decoded::DecodedCommits,
    /// Bumped whenever a transaction changes the indexes or a state, rolls back, or the caches
    /// reload (it never goes back): caches derived from them (the sync engine's) compare it.
    pub generation: u64,
    /// `generation` for memory transactions (`Tx::set_memory`): what they change is in memory
    /// only, so durable-derived caches (node-sync's) keep theirs.
    pub memory_generation: u64,
    /// The running transaction is a memory one (`Tx::set_memory`).
    pub memory_tx: bool,
    /// The room node-sync gave the memory commit being ingested (spec/sync-compaction.md §2 caps,
    /// `apply::memory::memory_gate`); `None` outside `ingest_memory`/`apply_waiting_memory`.
    pub memory_room: Option<u64>,
    /// Pending commits known to be memory commits, which `reexamine` leaves to node-sync (a
    /// cache of what their stored copies say; pruned to the pending set at each reexamine).
    pub memory_waits: BTreeSet<CommitId>,
    /// The blob waits: kept walks of what waiting commits lack, indexed by blob (`reach::Walks`).
    pub(crate) walks: crate::apply::reach::Walks,
    /// `Engine::owned_sync_ids` per thing (`memo`).
    pub(crate) sync_ids: memo::Memo<Tid, Arc<Vec<crate::sync::OwnedSyncId>>>,
    /// The sync set per sync ID (`sync::rows`), followed per thing.
    pub(crate) sync_rows: crate::sync::rows::SyncRows,
    /// `Engine::pass_wanted` per sync ID asked (`memo::Cutoff`), refreshed by `follow`.
    pub(crate) pass_wanted: memo::Cutoff<SyncId, Option<u64>>,
    /// `Engine::read_things_of` per sync ID asked (`memo::Cutoff`), refreshed by `follow` and
    /// before the memos reading it.
    pub(crate) read_things: memo::Cutoff<SyncId, Arc<Vec<Tid>>>,
    /// `Engine::step_write_key` per (sync ID, step) asked (`memo::Cutoff`), refreshed by
    /// `follow`.
    pub(crate) step_write_keys: memo::Cutoff<(SyncId, osis_blob::StepId), crate::sync::set::WriteKey>,
    /// `Engine::setting_wants` (`memo`).
    pub(crate) setting_wants: memo::Memo<(), Arc<BTreeMap<SyncId, u64>>>,
    /// `Engine::published_under` for every actor, followed per thing with a sync ID
    /// (`sync_ids::published`).
    pub(crate) published: crate::sync_ids::published::Published,
    /// `Engine::own_commits` per sync ID asked, followed per candidate (`sync::own`).
    pub(crate) own_commits: crate::sync::own::OwnCommits,
    /// `Engine::held_links` (`memo`).
    pub(crate) links: memo::Memo<(), std::sync::Arc<Vec<crate::flows::HeldLink>>>,
    /// `Engine::caught_up` per sync unit (`memo`).
    pub(crate) caught_up: memo::Memo<Tid, bool>,
    /// The follower of the node closure's out-lists (`sync::units::settle`).
    pub(crate) closure_follow: crate::sync::units::Follow,
    /// `Engine::sync_unit` per thing (`memo`).
    pub(crate) unit_of: memo::Memo<Tid, Arc<BTreeSet<Tid>>>,
    /// This node's node root (spec/sync-set.md §1), from its first start (`records::NODE_ROOT`).
    pub(crate) node_root: Option<Tid>,
    /// The things the running transaction's own commits made or wrote: each must be in the node
    /// closure at its end (spec/sync-set.md §2 Writing).
    pub(crate) wrote_on: Vec<Tid>,
    /// Sync units the handle reads and writes at another node (`osis` sources): what is here of them
    /// may be behind, syncing or not (`readable_by`). `Engine::set_sourced` sets it.
    pub(crate) sourced_elsewhere: BTreeSet<Tid>,
}

impl Core {
    /// Tests only (`Engine::test_copy`): this state for a copy of the node on `clock`, inside a
    /// world copy (`osis_base::copying`). Commit listeners are not copied (their owner listens
    /// again); event subscribers neither (`Events`).
    pub(crate) fn test_copy(&self, clock: Arc<dyn Clock>) -> Core {
        let mut c = self.clone();
        c.hlc = Hlc::new(clock, self.hlc.last());
        c.commit_listeners = None;
        #[cfg(debug_assertions)]
        c.unchecked_states.clear();
        c.header_fault = osis_base::copying::remap(&self.header_fault, |f| std::sync::atomic::AtomicBool::new(f.load(std::sync::atomic::Ordering::Relaxed)));
        c
    }
}


/// What a test peer's fetch stand-in reads to fetch again what the engine kept nothing of
/// (`local_peer::Peer::receive`).
#[derive(Clone, Debug, Default)]
pub struct Wakes {
    /// Commits whose boxes the reading-only budget now has room for.
    pub reread: BTreeSet<CommitId>,
    /// Every awaiting entry is fetched again (a key actor taken up: boxes may open to it).
    pub reopen_awaits: bool,
    /// Sync IDs pulled anew (`flows::sync_ids::pull_anew`).
    pub pulled_anew: BTreeSet<osis_base::SyncId>,
}

/// (actor, role, epoch) -> the commit that introduced it: (ts, commit ID).
pub(crate) type EpochIntro = JMap<(Tid, osis_base::Role, osis_crypto::Epoch), (Ts, CommitId)>;

impl Core {
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
        run_of(&self.ix.by_thing, *t).flat_map(|(_, s)| s.iter().copied())
    }

    /// Notes what a timeline update changed (`osis_perm::Changed`): a role at any point moves
    /// only for those upstream of a changed edge's holder or a new record, and only down from
    /// its target or that record; what is below a new record has a new record chain.
    pub(crate) fn timelines_changed(&mut self, c: osis_perm::Changed) {
        // a removal whose own change in the walk differs (it started or stopped applying, or
        // lowers or audits otherwise: perm names every such commit, `Changed::commits`) is
        // judged again for addenda: the one input a removal not applying reads
        crate::flows::addenda::note_changed(self, &c.commits);
        crate::flows::addenda::note_evaluated(self, &c.evaluated);
        self.stale_things.extend(c.evaluated);
        self.stale_things.extend(self.ix.held.below(&c.created));
        // a write may have stopped or started applying with no role of its author moving, and an
        // invite grant's boxes rest on that (`validity::valid_on`)
        self.stale_commits.extend(c.commits);
        let holders: BTreeSet<Tid> = c.edges.iter().map(|p| p.0).chain(c.created.iter().copied()).collect();
        let targets: BTreeSet<Tid> = c.edges.iter().map(|p| p.1).chain(c.created.iter().copied()).collect();
        let moved = self.ix.held.upstream(&holders);
        let under = self.ix.held.reach(&targets);
        crate::flows::addenda::note_roles_moved(self, &moved, &under);
        self.stale_authors.extend(moved);
        // a role moved there, this node's maybe: a held purge-on-replace body may now be owed a
        // cover (`retention::settle_none`), an aspect weighed while this node could not write it
        // a weighing (`compact::Trigger::wake`)
        for t in &under {
            self.compaction.wake(t);
            let on: Vec<(Tid, Ak)> = self.aspects_of(t).map(|(k, _)| k.clone()).collect();
            for (x, ak) in on {
                if crate::retention::history::of(self, &x, &ak).purges() {
                    self.none_due.insert((x, ak));
                }
            }
        }
        self.stale_under.extend(under);
    }

    /// The commits of `index` (by (thing, author)) on `under` by `authors`: O(the things and their
    /// authors), not their product.
    fn by_authors<'a>(index: &'a JSetMap<(Tid, Tid), CommitId>, under: &'a BTreeSet<Tid>, authors: &'a BTreeSet<Tid>) -> impl Iterator<Item = CommitId> + 'a {
        under.iter().flat_map(move |t| run_of(index, *t).filter(|(a, _)| authors.contains(a)).flat_map(|(_, s)| s.iter().copied()))
    }

    /// The commits on `under` by `authors` (`rejudge_once`), and those acting for one of `under`.
    pub(crate) fn authored_under<'a>(&'a self, under: &'a BTreeSet<Tid>, authors: &'a BTreeSet<Tid>) -> (impl Iterator<Item = CommitId> + 'a, impl Iterator<Item = CommitId> + 'a) {
        (Self::by_authors(&self.ix.by_thing, under, authors), Self::by_authors(&self.ix.by_actor, under, authors))
    }

    /// The held commits acting for `actor` by another author (a range of `by_actor`).
    pub fn acting_for(&self, actor: &Tid) -> impl Iterator<Item = CommitId> + '_ {
        run_of(&self.ix.by_actor, *actor).flat_map(|(_, s)| s.iter().copied())
    }

    /// The actors this node has acted for in a held commit: its chain certificates for them go
    /// under every sync ID it places in (spec/permissions.md §4). O(`by_actor` keys) when the engine
    /// moved, so a pass of a quiet node reads no index of every commit's author.
    pub fn acting(&self) -> Arc<Vec<Tid>> {
        self.acting_of.get(&(), || {
            let me = self.me();
            Arc::new(self.ix.by_actor.keys_held().filter(|(_, au)| Some(*au) == me).map(|(a, _)| *a).collect())
        })
    }

    /// The held valid keysets of actor `m`: (role, epoch, what is held of it) (`keyset`).
    pub(crate) fn keysets_of(&self, m: &Tid) -> impl Iterator<Item = (osis_base::Role, osis_crypto::Epoch, &HeldKeyset)> {
        self.keysets_noted(m).filter(|(_, _, v)| self.carried_held(v))
    }

    /// Every keyset of actor `m` a valid body of which is noted (`Indexes::keysets`), held or not.
    pub(crate) fn keysets_noted(&self, m: &Tid) -> impl Iterator<Item = (osis_base::Role, osis_crypto::Epoch, &HeldKeyset)> {
        self.ix.keysets.run(actor_run(m), (*m, osis_base::Role::Sync, osis_crypto::Epoch::ZERO)..).take_while(move |(k, _)| k.0 == *m).map(|(k, v)| (k.1, k.2, v))
    }

    /// Every epoch of actor `a` a valid `keys.0` body records a box at (`Indexes::sealed`).
    pub(crate) fn sealed_noted(&self, a: &Tid) -> impl Iterator<Item = (osis_base::Role, osis_crypto::Epoch, &SealedAt)> {
        self.ix.sealed.run(actor_run(a), (*a, osis_base::Role::Sync, osis_crypto::Epoch::ZERO)..).take_while(move |(k, _)| k.0 == *a).map(|(k, v)| (k.1, k.2, v))
    }

    /// Held valid keyset `e` of role `r` of actor `m` (spec/crypto.md §4, Held keyset): a valid
    /// body of it noted (`Indexes::keysets`), and the demotions it carries held here (Carried
    /// demotions): until then it counts as not arrived, so nothing seals to it, finds a box
    /// stale by it, or descends through it.
    pub(crate) fn keyset(&self, m: &Tid, r: osis_base::Role, e: &osis_crypto::Epoch) -> Option<&HeldKeyset> {
        let k = (*m, r, *e);
        self.ix.keysets.get(&k).filter(|v| self.carried_held(v))
    }

    /// Whether this node holds the demotions keyset `v` carries: the edge writes of each commit
    /// it carries (`HeldKeyset::demotions`).
    fn carried_held(&self, v: &HeldKeyset) -> bool {
        v.demotions.iter().all(|c| self.ix.held.edge_commit(c).is_some())
    }

    /// Bounds the clock (`Clock::bound`) at the first time after now that a grant's `until` or a
    /// role commit's `ts` falls due on what reaches `actors`: until then the clock alone moves
    /// no role on them, so the roles at now a judgement reads while the guard lives
    /// (`Core::now`) hold to it. Read by the edges into each actor and what holds a role on it
    /// (`Timelines::roles_on`, `on`), so a change elsewhere in their components moves nothing
    /// here.
    pub fn bound_to_horizon(&self, actors: impl Iterator<Item = Tid>) -> osis_base::memo::Bound {
        self.time.bound(|now| self.horizon_at(now, actors))
    }

    /// `bound_to_horizon`'s deadline, after `now`.
    fn horizon_at(&self, now: u64, actors: impl Iterator<Item = Tid>) -> Option<u64> {
        let at = osis_perm::At::now(osis_base::Ts::make(WallMs(now), 0).unwrap_or_default());
        let mut seen: BTreeSet<Tid> = BTreeSet::new();
        let mut out: Option<u64> = None;
        let mut later = |t: u64| {
            if t > now {
                out = Some(out.map_or(t, |x| x.min(t)));
            }
        };
        for t in actors {
            let up = self.timelines.roles_on(&t, at, &BTreeSet::new());
            for x in std::iter::once(t).chain(up.keys().copied()) {
                if !seen.insert(x) {
                    continue;
                }
                let Some(on) = self.timelines.on(&x) else { continue };
                for (_, e) in on.holders() {
                    if let Some(u) = e.until {
                        later(u.0);
                    }
                }
                for (mc, _) in on.applied() {
                    later(mc.ts.wall_ms().0);
                }
            }
        }
        out
    }

    /// Whether `t` exists here: its record is held and it has not been destroyed. What may read a thing
    /// asks this; what judges commits on it asks `created`, a record being identity.
    pub fn exists(&self, t: &Tid) -> bool {
        self.created(t).is_some() && !self.destroyed(t)
    }

    /// Whether `t` takes writes here: it exists and, but for a key actor (its record is its
    /// creation's whole content, and only its own nodes see it end), a minting of it is held. A
    /// node that learned a thing's record raw (a record blob) cannot tell it was destroyed, and a write
    /// there would be one every node that saw the destruction ignores.
    pub fn writable(&self, t: &Tid) -> bool {
        self.exists(t) && (matches!(self.created(t), Some(osis_base::CreationRecord::KeyActor { .. })) || self.mintings(t).next().is_some())
    }

    /// The held mintings of `t`: its `created.0` deltas, each `(commit, delta index)`.
    pub(crate) fn mintings<'s>(&'s self, t: &Tid) -> impl Iterator<Item = (CommitId, usize)> + 's {
        let ak = Ak::new(osis_commit::retention::CREATED).ok();
        let held = ak.as_ref().and_then(|ak| self.ix.by_aspect.get(&(*t, ak.clone())));
        let t = *t;
        held.into_iter().flatten().filter_map(move |(_, c)| Some((*c, self.ix.commits.get(c)?.aspect(&t, ak.as_ref()?)?)))
    }

    /// Whether `t` is destroyed: a minting of it was held (`mintings`), and each is held value-less
    /// or dropped by a purge or the destruction (`retention::destroy`). One missing may yet come. A thing never held is unknown, not destroyed.
    pub fn destroyed(&self, t: &Tid) -> bool {
        let mut any = false;
        self.mintings(t).all(|(c, ai)| {
            any = true;
            self.minting_gone(&c, ai)
        }) && any
    }

    /// Whether minting `ai` of `c` is held value-less or dropped by a purge or the destruction.
    pub(crate) fn minting_gone(&self, c: &CommitId, ai: usize) -> bool {
        let Some(m) = self.ix.commits.get(c) else { return false };
        crate::retention::valueless(self, c, ai) || m.dropped(ai).is_some_and(|d| matches!(d.why, DropFor::Other | DropFor::Destroyed))
    }

    /// Re-evaluates the timelines around the things whose held inputs changed; the things of
    /// changed timelines wait for `rejudge_all`.
    pub fn update_timelines(&mut self) {
        let _s = osis_base::costs::span("timelines");
        let touched = self.ix.held.take_touched();
        if !touched.is_empty() {
            let changed = self.timelines.update_touched(&self.ix.held, &touched);
            let ever = self.ix.held.take_ever();
            self.timelines.ever_moved(&ever);
            self.timelines_changed(changed);
            if self.detect {
                crate::sides::after_update(self);
            }
        }
    }

    /// Whether some validity waits for `rejudge_all`.
    pub fn stale(&self) -> bool {
        self.stale_all || !self.stale_things.is_empty() || !self.stale_commits.is_empty() || !self.stale_authors.is_empty() || !self.ix.epochs_due.is_empty()
    }

    /// Notes that the running transaction writes the state of `k` (evicted on rollback).
    pub fn wrote(&mut self, k: (Tid, Ak)) {
        self.written.push(k);
    }

    /// Notes that the running transaction changes the indexes or a state (drops derived caches).
    pub fn touch(&mut self) {
        if self.memory_tx {
            self.memory_generation += 1;
        } else {
            self.generation += 1;
        }
        self.dirty = true;
    }

    /// The running transaction committed: its journal is forgotten.
    fn commit_journal(&mut self) {
        self.closure_follow.committed();
        self.ix.commit();
        self.schemas.commit();
        self.sides.commit();
        self.waits.retake_committed();
        self.written.clear();
        self.reach_log.clear();
        self.walks.committed();
        self.dirty = false;
    }

    /// Drops the `tree_reach` of every thing a question took since `n` (`reach_log`): what it
    /// read of a blob a failed step or transaction held is read anew.
    pub(crate) fn forget_reach_since(&mut self, n: usize) {
        for t in self.reach_log.split_off(n.min(self.reach_log.len())) {
            self.tree_reach.remove(&t);
        }
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
            written: self.written.len(),
            events: self.events.queued(),
            commits_named: self.commits_named.len(),
            listed_before: self.listed_before.len(),
            killed: self.killed.len(),
            to_date: self.to_date.len(),
            wrote_on: self.wrote_on.len(),
            stale: (self.stale_things.clone(), self.stale_authors.clone(), self.stale_under.clone(), self.stale_commits.clone(), self.stale_all),
            batched: self.batched.clone(),
            memory_tx: self.memory_tx,
            dirty: self.dirty,
            records: self.store_rows.get(),
            reached: self.reach_log.len(),
            walked: self.walks.mark(),
        }
    }

    /// Whether anything stored or indexed changed since `m` (what `rollback_to` drops every cache
    /// for).
    fn changed_since(&mut self, m: &CoreMark) -> bool {
        // a record written alone (`put_commit`, `leftover::put`) changes no index: its stamp says
        self.dirty || self.written.len() > m.written || self.ix.mark() != m.ix || self.store_rows.get() != m.records
    }

    /// What `rollback_to` would restore that moved since `m`, by name (`Engine::read`'s check).
    #[cfg(debug_assertions)]
    fn moved_since(&mut self, m: &CoreMark) -> Vec<&'static str> {
        let stale = (&self.stale_things, &self.stale_authors, &self.stale_under, &self.stale_commits, self.stale_all);
        [
            ("indexes", self.ix.mark() != m.ix),
            ("sides", self.sides.journaled() > m.sides.0 + m.sides.1),
            ("schemas", self.schemas.mark() != m.schemas),
            ("written", self.written.len() != m.written),
            ("events", self.events.queued() != m.events),
            ("commits_named", self.commits_named.len() != m.commits_named),
            ("listed_before", self.listed_before.len() != m.listed_before),
            ("killed", self.killed.len() != m.killed),
            ("to_date", self.to_date.len() != m.to_date),
            ("wrote_on", self.wrote_on.len() != m.wrote_on),
            ("stale", stale != (&m.stale.0, &m.stale.1, &m.stale.2, &m.stale.3, m.stale.4)),
            ("batched", self.batched != m.batched),
            ("memory_tx", self.memory_tx != m.memory_tx),
            ("dirty", self.dirty != m.dirty),
            ("records", self.store_rows.get() != m.records),
        ]
        .into_iter()
        .filter_map(|(f, moved)| moved.then_some(f))
        .collect()
    }

    /// Undoes every change to the indexes, the sides, the queued events and the work lists of the
    /// running transaction since `m`, and drops every cache (they stay when nothing was changed:
    /// a failed read keeps them). The timelines follow the restored held set. Each field's class
    /// is listed in `rollback_classes`.
    pub(crate) fn rollback_to(&mut self, m: CoreMark) {
        let sides_back = self.sides.journaled() > m.sides.0 + m.sides.1;
        self.sides.rollback_to(m.sides);
        if self.changed_since(&m) {
            // the node closure's follower, if it acted on what goes back (`sync::units::Follow`)
            self.closure_follow.rolled_back();
            self.touches.clear();
            // what it followed may have gone back: built again from the restored index
            self.paths_wait = None;
            // every cache goes (`dirty` is restored below)
            self.touch();
            for k in self.written.split_off(m.written) {
                self.states.remove(&k);
                self.pages.remove(&k);
            }
        }
        self.dirty = m.dirty;
        self.waits.retake_rolled_back();
        self.ix.rollback_to(m.ix);
        self.schemas.rollback_to(m.schemas);
        // the timelines follow the restored held set; validity flags are restored with `commits`
        let touched = self.ix.held.take_touched();
        if !touched.is_empty() {
            self.timelines.update_touched(&self.ix.held, &touched);
            let ever = self.ix.held.take_ever();
            self.timelines.ever_moved(&ever);
            crate::sides::discard(self);
        }
        if sides_back {
            crate::sides::restored(self);
        }
        (self.stale_things, self.stale_authors, self.stale_under, self.stale_commits, self.stale_all) = m.stale;
        self.events.truncate(m.events);
        self.commits_named.truncate(m.commits_named);
        self.listed_before.truncate(m.listed_before);
        self.killed.truncate(m.killed);
        self.to_date.truncate(m.to_date);
        self.wrote_on.truncate(m.wrote_on);
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
            killed: _,
            to_date: _,
            wrote_on: _,
            written: _,
            compaction: _,
            stale_things: _,
            stale_authors: _,
            stale_under: _,
            stale_commits: _,
            stale_all: _,
            batched: _,
            memory_tx: _,
            dirty: _,
            // taken by node-sync, kept: a flip rolled back only reports once more (one more
            // placement again, one more relist)
            fallen: _,
            // a call's parameter (`memory_room`) and caches true of the store whatever a
            // rollback undoes (`memory_waits`: a pending row's class never changes); `walks`
            // drops what a failed step or transaction touched (`Walks::forget_since`)
            memory_room: _,
            memory_waits: _,
            walks: _,
            // brought up to date from the roots at each question; a failed step or transaction
            // drops what it may have read of blobs it held (`forget_reach_since`)
            tree_reach: _,
            reach_log: _,
            // memos: each answer holds while what it read does (`memo`); the stamps of what a
            // rollback restores move
            epochs_of: _,
            live_bodies: _,
            covers: _,
            sync_body: _,
            sync_bodies: _,
            state_digests: _,
            pieces_below: _,
            account_views: _,
            account_epochs_of: _,
            secrets_read: _,
            published: _,
            own_commits: _,
            head_keys: _,
            read_credentials: _,
            sync_things: _,
            thing_sync: _,
            sync_set: _,
            dial_peers: _,
            roster_holders: _,
            dial_departed: _,
            // built again from the journaled `ix.paths_unknown` (`apply::paths::Wait`)
            paths_wait: _,
            holders_named: _,
            // followed (`Effects`): what a rollback restores moves its reads, so the next follow
            // indexes again
            certified: _,
            listed: _,
            cert_records: _,
            key_roles: _,
            wrap_blocks: _,
            read_facts: _,
            held_fates: _,
            held_writes_rows: _,
            acting_of: _,
            sync_ids: _,
            sync_rows: _,
            pass_wanted: _,
            read_things: _,
            step_write_keys: _,
            setting_wants: _,
            links: _,
            caught_up: _,
            unit_of: _,
            closure_follow: _,
            node_root: _,
            held_writes: _,
            replaced_dates: _,
            waiting_carried: _,
            part_bounds: _,
            tree_roots: _,
            departures: _,
            reseal_scans: _,
            // decodes of commit records kept at each record's stamp (`decoded`): an undo
            // stamps the rows it restores
            decoded: _,
            // caches, dropped when anything changed (`states` and `pages` per written aspect)
            states: _,
            pages: _,
            rotation_seq: _,
            place: _,
            epochs_judged_from: _,
            waits: _,
            touches: _,
            generation: _,
            // the store's count, read by `changed_since`
            store_rows: _,
            memory_generation: _,
            // work lists and hints a superset of which is harmless (the consumer re-checks each
            // entry against the restored state), and what a step only moves forward
            drop_due: _,
            kept_due: _,
            kept_things_due: _,
            own_secrets_due: _,
            notices_due: _,
            removals_due: _,
            freed_due: _,
            carriers_due: _,
            forgotten_names_due: _,
            handed_due: _,
            freed_waits: _,
            refold: _,
            none_due: _,
            settings_due: _,
            setting_waits_due: _,
            setting_waits_judging: _,
            valueless_dirty: _,
            needs_due: _,
            pass_due: _,
            lost_due: _,
            learned: _,
            entered: _,
            wakes: _,
            resnapshots_due: _,
            openings: _,
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
            // a transaction's end records
            walks_done: _,
            id: _,
            detect: _,
            walk_cache_min: _,
            key_salt: _,
            addenda_on: _,
            skip_writer_rules: _,
            interim_role_paths: _,
            leave_adminless: _,
            commits_watched: _,
            refs_watched: _,
            commit_listeners: _,
            forge_bad: _,
            forged: _,
            header_fault: _,
            key_actors: _,
            held_keys: _,
            followed_links: _,
            account: _,
            time: _,
            accounts: _,
            left: _,
            signing_due: _,
            keep_bodies: _,
            list_bound: _,
            sourced_elsewhere: _,
            #[cfg(debug_assertions)]
            unchecked_tx: _,
            #[cfg(debug_assertions)]
            unchecked_states: _,
            #[cfg(debug_assertions)]
            rebuilt_perm: _,
            #[cfg(debug_assertions)]
            #[cfg(test)]
            check_ingest: _,
            #[cfg(test)]
            whole_apply: _,
            #[cfg(test)]
            piece_fault: _,
            #[cfg(test)]
            step_fault: _,
            #[cfg(test)]
            lie_facts: _,
            #[cfg(test)]
            snapshot_fault: _,
            #[cfg(test)]
            lie_floor: _,
            #[cfg(test)]
            faults: _,
        } = c;
    }

    /// Begins new plain and expiring sessions (spec/crdt.md §2.1), once an own session-form
    /// write of the current ones turned invalid: a demotion's invalid body would stop every
    /// snapshot's frontier for its session below it for good (spec/sync-compaction.md §2), so what this
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

    /// The nonce `signer` writes under, given this open's session nonce `base`: the node's own
    /// for itself; for another signer one no reader can link to `base` or to another signer's
    /// (spec/crdt.md §2.2): its first half and an offset to the count keyed on the node's seed,
    /// `base`'s first half and the signer, so `own_plain` still tells the sessions of this open.
    pub(crate) fn nonce_as(&self, signer: &Tid, base: Nonce) -> Nonce {
        if *signer == self.id.tid() {
            return base;
        }
        let mut b = self.id.seed().expose().to_vec();
        b.extend_from_slice(&base[..8]);
        b.extend_from_slice(signer.as_bytes());
        let h = osis_base::hash::derive_key("osis session nonce", &b);
        let mut offset = [0u8; 8];
        offset.copy_from_slice(&h[8..16]);
        let mut n = base;
        n[..8].copy_from_slice(&h[..8]);
        n[8..].copy_from_slice(&u64::from_be_bytes(offset).wrapping_add(nonce_count(&base)).to_be_bytes());
        n
    }

    /// The nonces this node writes under now: its own sessions and, per account it signs as, that
    /// account's (what an own write falling starts anew, `fresh_session`).
    pub(crate) fn current_sessions(&self) -> BTreeSet<Nonce> {
        std::iter::once(self.id.tid()).chain(self.accounts.keys().copied()).flat_map(|a| [self.nonce_as(&a, self.session.nonce), self.nonce_as(&a, self.expiring.nonce)]).collect()
    }

    /// Whether `n` is the nonce of a plain session of `signer` of this open (`fresh_session`).
    pub(crate) fn own_plain(&self, signer: &Tid, n: &Nonce) -> bool {
        let now = self.nonce_as(signer, self.session.nonce);
        n[..8] == now[..8] && nonce_count(&now).wrapping_sub(nonce_count(n)) <= self.later_sessions
    }

    /// The account this node writes as and holds roles as; `None` before it has joined one (it
    /// then writes only its own card, `commit_in`).
    pub(crate) fn me(&self) -> Option<Tid> {
        self.account.get()
    }

    /// The account this node acts as: its own while it is a node of it (holds its seeds). A
    /// node removed from its account reads nothing as it (spec/permissions.md §3, Lost access).
    pub(crate) fn member(&self) -> Option<Tid> {
        self.account.get().filter(|p| self.accounts.contains_key(p))
    }

    /// Who writes on `t`: a node writes its own thing as itself, all else as its account.
    pub(crate) fn writer_for(&self, t: &Tid) -> Result<Tid> {
        if self.nodes_own(t) { Ok(self.id.tid()) } else { self.writer() }
    }

    /// Whether `t` is the node's own, written by it alone (spec/sync-set.md §1): its node thing,
    /// its node root and what is minted with it, whose record chain reaches the node (no
    /// account holds a role there).
    pub(crate) fn nodes_own(&self, t: &Tid) -> bool {
        let node = self.id.tid();
        *t == node || self.record_chain(t).any(|s| s == osis_base::ChainStep::Key(node))
    }

    /// Whether `t`, made among `creates`, is the node's own (`nodes_own`): it is the node, or its
    /// mint admin is the node's own, held or made beside it.
    pub(crate) fn made_nodes_own(&self, t: &Tid, creates: &write::Creates) -> bool {
        let mut at = *t;
        for _ in 0..=creates.len() {
            let Some(r) = creates.get(&at) else { return self.nodes_own(&at) };
            if at == self.id.tid() {
                return true;
            }
            let Some(a) = r.mint_admin() else { return false };
            at = a;
        }
        false
    }

    /// `me`, for what only an account may do.
    /// A node removed from its account writes nothing as it (`member`), nor one D's roster does
    /// not hold (one whose taken revocations remove it: spec/permissions.md §5.5, it signs
    /// nothing for P while it may still be a node of P), nor one not holding its preferred head's
    /// seed (it signs only there: spec/crypto.md §9, Custody), until it does.
    pub(crate) fn writer(&self) -> Result<Tid> {
        let p = self.account.get().ok_or(Error::Misuse("this node has joined no account"))?;
        self.member().ok_or(Error::Misuse("this node was removed from its account"))?;
        if !self.account_view(&p).is_some_and(|v| v.roster().contains(&self.id.tid())) {
            return Err(Error::Misuse("this node is off its account's roster: it signs nothing as it"));
        }
        self.account_signing(&p)?;
        Ok(p)
    }

    fn new(id: Identity, clock: Arc<dyn Clock>, session: osis_crdt::Session, expiring: osis_crdt::Session, store_rows: memo::Changes) -> Core {
        let key_salt = osis_base::hash::derive_key("osis node key index", id.seed().expose());
        let mut core = Core {
            id,
            hlc: Hlc::new(clock, Ts::default()),
            states: HashMap::new(),
            secrets_read: memo::Memo::new("secrets: decode"),
            head_keys: memo::Memo::new("head keys: derive"),
            read_credentials: memo::Memo::new("sync: read credentials"),
            sync_things: memo::Memo::new("sync: things"),
            thing_sync: memo::Memo::new("sync: thing sync"),
            sync_set: memo::Memo::new("sync: sync set"),
            dial_peers: memo::Memo::new("sync: dial peers"),
            roster_holders: memo::Memo::new("sync: roster holders"),
            dial_departed: memo::Effects::new("sync: dial list departed"),
            paths_wait: None,
            holders_named: memo::Memo::new("holders named: read"),
            certified: Default::default(),
            listed: Default::default(),
            cert_records: Default::default(),
            departures: memo::Memo::new("departures"),
            reseal_scans: memo::Memo::new("reseal: scan"),
            rotation_seq: 0,
            place: 0,
            account_views: memo::Memo::new("account view"),
            account_epochs_of: memo::Memo::new("account epochs"),
            epochs_judged_from: None,
            key_roles: memo::Memo::new("key roles"),
            acting_of: memo::Memo::new("acting"),
            wrap_blocks: memo::Cutoff::new("wrap blocked"),
            read_facts: memo::Cutoff::new("sync: read facts"),
            held_fates: memo::Cutoff::new("sync: held fate"),
            pages: HashMap::new(),
            timelines: held::Timelines::default(),
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
            ix: Indexes {
                keysets: JMap::by_run(|k| actor_run(&k.0)),
                sealed: JMap::by_run(|k| actor_run(&k.0)),
                by_thing: JSetMap::by_run(|k| actor_run(&k.0)),
                by_actor: JSetMap::by_run(|k| actor_run(&k.0)),
                ..Indexes::default()
            }
            .named(),
            waits: crate::apply::Waits::default(),
            schemas: JMap::default(),
            events: Events::default(),
            written: Vec::new(),
            skip_writer_rules: false,
            interim_role_paths: false,
            leave_adminless: false,
            commits_watched: false,
            refs_watched: false,
            commits_named: Vec::new(),
            commit_listeners: None,
            listed_before: Vec::new(),
            killed: Vec::new(),
            to_date: Vec::new(),
            redeliver: BTreeSet::new(),
            forge_bad: BTreeSet::new(),
            #[cfg(debug_assertions)]
            unchecked_tx: false,
            #[cfg(debug_assertions)]
            unchecked_states: BTreeSet::new(),
            #[cfg(debug_assertions)]
            rebuilt_perm: BTreeMap::new(),
            forged: None,
            session,
            expiring,
            later_sessions: 0,
            compaction: Default::default(),
            fallen: Default::default(),
            header_fault: Arc::default(),
            #[cfg(test)]
            check_ingest: false,
            #[cfg(test)]
            whole_apply: false,
            #[cfg(test)]
            piece_fault: None,
            #[cfg(test)]
            step_fault: None,
            #[cfg(test)]
            lie_facts: None,
            #[cfg(test)]
            snapshot_fault: None,
            #[cfg(test)]
            lie_floor: None,
            #[cfg(test)]
            faults: Faults::default(),
            key_actors: Default::default(),
            held_keys: Default::default(),
            followed_links: Default::default(),
            epochs_of: memo::Memo::new("epochs"),
            store_rows,
            account: Default::default(),
            time: Default::default(),
            left: BTreeSet::new(),
            // judged once after an open: a commit applied before a restart left it owed
            signing_due: true,
            accounts: Default::default(),
            keep_bodies: false,
            list_bound: osis_commit::MAX_LIST_BYTES,
            valueless_dirty: BTreeSet::new(),
            needs_due: BTreeSet::new(),
            // what arrived before the open but was not judged yet: all judged at the first settle
            pass_due: None,
            lost_due: BTreeSet::new(),
            learned: BTreeSet::new(),
            entered: None,
            batched: None,
            touches: Default::default(),
            held_writes: memo::Memo::new("held writes"),
            held_writes_rows: memo::Cutoff::new("held writes: rows"),
            replaced_dates: memo::Memo::new("replaced at"),
            waiting_carried: memo::Memo::new("waiting snapshot: bound"),
            part_bounds: memo::Memo::new("part bounds"),
            tree_roots: memo::Memo::new("tree roots"),
            tree_reach: HashMap::new(),
            reach_log: Vec::new(),
            timer_floor: 0,
            none_due: BTreeSet::new(),
            settings_due: BTreeSet::new(),
            setting_waits_due: BTreeSet::new(),
            setting_waits_judging: false,
            drop_due: BTreeSet::new(),
            kept_due: BTreeSet::new(),
            kept_things_due: BTreeSet::new(),
            own_secrets_due: BTreeSet::new(),
            notices_due: BTreeSet::new(),
            removals_due: BTreeSet::new(),
            freed_due: BTreeSet::new(),
            carriers_due: BTreeSet::new(),
            forgotten_names_due: BTreeSet::new(),
            handed_due: BTreeSet::new(),
            freed_waits: BTreeMap::new(),
            refold: BTreeSet::new(),
            wakes: None,
            resnapshots_due: BTreeSet::new(),
            openings: BTreeMap::new(),
            missed: BTreeSet::new(),
            live_bodies: memo::Memo::new("delta live"),
            covers: memo::Memo::new("covered"),
            sync_body: memo::Memo::new("sync body"),
            sync_bodies: memo::Memo::new("sync bodies"),
            state_digests: memo::Memo::new("state digest"),
            pieces_below: memo::Memo::new("pieces: below"),
            replaced_reads: 0,
            death_walks: 0,
            rebuilds: 0,
            decoded: Default::default(),
            generation: 0,
            memory_generation: 0,
            memory_tx: false,
            memory_room: None,
            memory_waits: BTreeSet::new(),
            walks: Default::default(),
            sync_ids: memo::Memo::new("sync IDs of"),
            sync_rows: Default::default(),
            pass_wanted: memo::Cutoff::new("sync: pass wanted"),
            read_things: memo::Cutoff::new("sync: read things"),
            step_write_keys: memo::Cutoff::new("sync: step write keys"),
            setting_wants: memo::Memo::new("sync: setting wants"),
            published: Default::default(),
            own_commits: Default::default(),
            links: memo::Memo::new("held links"),
            caught_up: memo::Memo::new("sync: caught up"),
            closure_follow: Default::default(),
            unit_of: memo::Memo::new("sync: unit of"),
            node_root: None,
            wrote_on: Vec::new(),
            sourced_elsewhere: BTreeSet::new(),
        };
        // the memo clock starts at the wall clock: a load judges at the time it runs
        let now = core.hlc.wall().0;
        core.time.set(now);
        core
    }

    /// The time. Inside a memo or `Effects` settle computing, the memo clock's (`Clock::now`:
    /// bounded by the `until` the judgement read, else a read of it whole), so a judgement
    /// moves when the time passes what it judged by; elsewhere the wall clock, which the memo
    /// clock follows (set at each transaction and read).
    pub fn now(&self) -> WallMs {
        if osis_base::memo::computing() {
            return WallMs(self.time.now());
        }
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
    fn commit_changes(tx: &mut Tx<'_>) -> Result<()> {
        if !tx.core.commits_watched {
            return Ok(());
        }
        let state = |m: &Meta, ai: usize| (m.valid_at(ai), m.is_dropped(ai), m.stripped(ai), m.missing(ai));
        let mut out: BTreeSet<_> = std::mem::take(&mut tx.core.commits_named).into_iter().collect();
        // each changed commit's view (its last if gone) and whether it was held when the
        // transaction began
        let mut views: BTreeMap<CommitId, (Arc<View>, bool)> = BTreeMap::new();
        for (id, old) in tx.core.ix.commits.before() {
            let new = tx.core.ix.commits.get(id);
            let Some(m) = new.or(old) else { continue };
            views.insert(*id, (m.view.clone(), old.is_some()));
            for (ai, a) in m.view.aspects.iter().enumerate() {
                if old.map(|m| state(m, ai)) != new.map(|m| state(m, ai)) {
                    out.insert((a.tid, a.ak.clone(), *id));
                }
            }
        }
        // an honored version reads only through its original, which `edits::settle` names when
        // the version changed: one shown alone neither before nor after is not told, so a
        // listener hears an edit once, under the original
        let start = tx.core.ix.originals.was_in();
        let mut told = Vec::with_capacity(out.len());
        for (t, ak, c) in out {
            let view = match views.get(&c) {
                Some((v, existed)) => Some((v.clone(), *existed)),
                None => tx.core.ix.commits.get(&c).map(|m| (m.view.clone(), true)),
            };
            if let Some((v, existed)) = view
                && edits::unheard(tx, &c, &v, &t, &ak, &start, existed)?
            {
                continue;
            }
            told.push((t, ak, c));
        }
        tx.core.commits_touched(told);
        Ok(())
    }


    /// A held commit changed: if it is a rotation, its account gets the next rotation number
    /// (`Indexes::rotations`: what `refresh_epochs` judges the account again by,
    /// `Core::judged_from`). `rotation_seq` never rolls back, so a number is never given twice.
    pub(crate) fn note_rotation(&mut self, m: &Meta) {
        // from the view: an open decodes no header. Every rotation writes its account's `keys.0`.
        if m.view.kind.is_role() && m.view.aspect(&m.view.signer, "keys.0").is_some() {
            self.rotation_seq = self.rotation_seq.saturating_add(1);
            self.ix.rotations.insert(m.view.signer, self.rotation_seq);
            self.ix.epochs_due.insert(m.view.signer);
        }
    }

    /// Sets `id`'s meta: every change to what a part holds goes through here or `take_meta`, so
    /// the indexes derived from it stay exact.
    pub(crate) fn put_meta(&mut self, id: CommitId, m: Meta) {
        self.note_kept(&id, &m);
        // scale checks: each call walks every part of the commit
        osis_base::costs::count("meta: parts indexed", m.view.aspects.len() as u64);
        let had = self.ix.commits.get(&id).map(missing_of).unwrap_or_default();
        let now = missing_of(&m);
        // the things it is on may be needed by nothing more once a part stops waiting
        // (`retention::needed`)
        if had.difference(&now).next().is_some() {
            self.note_on(&m);
        }
        self.index_missing(&id, &had, &now);
        self.index_own(&id, &m, true);
        // a setting held value-less (purged) is no setting (`validity::settings`)
        let bared: Vec<(Tid, BTreeSet<Ak>)> = m.view.aspects.iter().enumerate().filter(|(ai, a)| a.ak.as_str() == osis_commit::retention::RETENTION && self.ix.commits.get(&id).is_some_and(|o| o.bare(*ai) != m.bare(*ai))).map(|(_, a)| (a.tid, crate::apply::validity::enabled(self, &a.tid))).collect();
        let had = self.ix.commits.get(&id).map(covers_of).unwrap_or_default();
        self.index_covers(&id, &had, &covers_of(&m));
        // a part held invalid (a late part joining, a leftover kept) goes at the transaction's end
        if (0..m.parts()).any(|ai| !m.valid_at(ai) && m.holds(ai)) {
            self.drop_due.insert(id);
        }
        self.note_none(&m);
        self.note_rotation(&m);
        self.touches.note(&id, &m);
        // held again: its meta decides its covers from now on
        if self.ix.handed.contains_key(&id) {
            self.handed_due.insert(id);
        }
        self.ix.commits.insert(id, m);
        for (t, before) in bared {
            crate::apply::validity::setting_moved(self, &t, Some(before));
        }
    }

    /// `t` arrived: judged at the next `Engine::settle_needs`.
    pub(crate) fn note_pass_due(&mut self, t: Tid) {
        if let Some(a) = &mut self.pass_due {
            a.insert(t);
        }
    }

    /// The parts of `id` (meta `m`) whose history may hold its strongs' targets: judged at the
    /// next closure settle (`refs::kept`).
    pub(crate) fn note_kept(&mut self, id: &CommitId, m: &Meta) {
        let due = self.kept_parts(id, m);
        self.kept_due.extend(due);
    }

    /// `note_kept` of part `ai` of `c` alone, on `(tid, ak)` (its leftover written).
    pub(crate) fn note_kept_part(&mut self, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize) {
        if refs::kept::counted(ak) && refs::kept::holds_history(self, tid) {
            self.kept_due.insert((*tid, ak.clone(), *c, ai));
        }
    }

    fn kept_parts(&self, id: &CommitId, m: &Meta) -> Vec<(Tid, Ak, CommitId, usize)> {
        m.view.aspects.iter().enumerate().filter(|(_, a)| refs::kept::counted(&a.ak) && refs::kept::holds_history(self, &a.tid)).map(|(ai, a)| (a.tid, a.ak.clone(), *id, ai)).collect()
    }

    /// `t` lost a need: judged at the next `Engine::settle_needs` or `Engine::settle_lost`.
    pub(crate) fn note_lost(&mut self, t: Tid) {
        self.lost_due.insert(t);
    }

    pub(crate) fn take_meta(&mut self, id: &CommitId) -> Option<Meta> {
        let m = self.ix.commits.remove(id)?;
        osis_base::costs::count("meta: parts indexed", m.view.aspects.len() as u64);
        self.note_kept(id, &m);
        let had = missing_of(&m);
        if !had.is_empty() {
            self.note_on(&m);
        }
        self.index_missing(id, &had, &BTreeSet::new());
        self.note_rotation(&m);
        self.index_own(id, &m, false);
        self.index_covers(id, &covers_of(&m), &BTreeSet::new());
        self.note_none(&m);
        self.touches.note(id, &m);
        Some(m)
    }

    /// Notes every thing `m` is on for the pass's need judgement (`retention::needed`).
    fn note_on(&mut self, m: &Meta) {
        for a in &m.view.aspects {
            self.note_lost(a.tid);
        }
    }

    /// Moves commit `id` in `Indexes::missing` from aspects `was` to `now` (`missing_of`).
    fn index_missing(&mut self, id: &CommitId, was: &BTreeSet<(Ak, Tid)>, now: &BTreeSet<(Ak, Tid)>) {
        // a setting part's header, validity or body moved: its wait is judged again
        // (`sync::setting`); `was` and `now` both hold it when only its validity moved
        for (ak, t) in was.iter().chain(now) {
            if ak.as_str() == osis_commit::retention::RETENTION {
                self.setting_waits_due.insert(*t);
            }
        }
        for k in was.difference(now) {
            self.ix.missing.remove(k, id);
        }
        for k in now.difference(was) {
            self.ix.missing.insert(k.clone(), *id);
        }
    }

    /// Moves commit `id` in `Indexes::covered_under` from coverers `was` to `now` (`covers_of`).
    fn index_covers(&mut self, id: &CommitId, was: &BTreeSet<CommitId>, now: &BTreeSet<CommitId>) {
        for s in was.difference(now) {
            self.ix.covered_under.remove(s, id);
            if !self.ix.covered_under.contains_key(s) && self.ix.handed.contains_key(s) {
                self.handed_due.insert(*s);
            }
        }
        for s in now.difference(was) {
            self.ix.covered_under.insert(*s, *id);
        }
    }

    /// The aspects of meta `m` (put: it applied, joined, flipped or dropped; or forgotten) whose
    /// purge-on-replace bodies `retention::settle_none` judges at the transaction's end: those
    /// some setting of their thing purges on replace.
    fn note_none(&mut self, m: &Meta) {
        for a in &m.view.aspects {
            let k = (a.tid, a.ak.clone());
            if !self.none_due.contains(&k) && crate::retention::history::of(self, &a.tid, &a.ak).purges() {
                self.none_due.insert(k);
            }
        }
    }

    /// `ix.own_held` and `ix.own_replaces` for commit `id` as `m` now stands: a part is in them
    /// while held (`add`: false, gone with its commit).
    fn index_own(&mut self, id: &CommitId, m: &Meta, add: bool) {
        use osis_commit::Kind;
        if m.view.memory || m.view.kind != Kind::Content {
            return;
        }
        for (ai, a) in m.view.aspects.iter().enumerate() {
            if !crate::retention::snapshot::own_aspect(&a.ak) {
                continue;
            }
            let k = (a.tid, a.ak.clone(), m.view.signer);
            let e = (m.view.ts, *id);
            let held = add && m.holds(ai);
            if held {
                self.ix.own_held.insert(k.clone(), e);
            } else {
                self.ix.own_held.remove(&k, &e);
            }
            if held && m.whole(ai) {
                self.ix.own_replaces.insert(k, e);
            } else {
                self.ix.own_replaces.remove(&k, &e);
            }
        }
    }

    /// Re-indexes which parts of commit `id` are invalid here (call after setting `Meta::valid`).
    pub fn index_validity(&mut self, id: &CommitId) {
        let due = self.ix.commits.get(id).map(|m| self.kept_parts(id, m)).unwrap_or_default();
        self.kept_due.extend(due);
        let Some(m) = self.ix.commits.get(id) else { return };
        let mut settings = Vec::new();
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
            // a flip of a setting may move its thing's current setting (`validity::setting_moved`);
            // one not noted yet (a commit being applied) moves it when noted
            if a.ak.as_str() == osis_commit::retention::RETENTION {
                settings.push((a.tid, self.ix.retention.get(&a.tid).is_some_and(|l| l.iter().any(|x| x.0.commit == *id))));
            }
            // a flip may make a held purge-on-replace body replaced or covered
            if !self.none_due.contains(&k) && crate::retention::history::of(self, &a.tid, &a.ak).purges() {
                self.none_due.insert(k);
            }
        }
        for (t, noted) in settings {
            if noted {
                crate::apply::validity::setting_moved(self, &t, None);
            } else {
                self.settings_due.insert(t);
                self.kept_things_due.insert(t);
            }
        }
        edits::index_validity(self, id);
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
        m.aspect(tid, ak).map(|_| m.header.expires)
    }
}

/// One transaction with the engine's in-memory state.
pub struct Tx<'a> {
    pub txn: Transaction<'a>,
    /// Blob ciphertexts, in the node's one store (`blobs::Cipher`).
    pub blobs: blobs::Cipher<'a>,
    pub core: &'a mut Core,
    pub rng: &'a mut dyn CryptoRngCore,
    /// What a bounded read may still hold of the states it loads (`Engine::get_within`,
    /// `pages::charge`); `None` otherwise.
    pub(crate) bound: pages::Bound,
}

impl Tx<'_> {
    /// Makes this a memory transaction: every new row in the store's memory overlay, the
    /// change counter `memory_generation`.
    pub fn set_memory(&mut self) {
        self.txn.set_memory(true);
        self.core.memory_tx = true;
    }

    /// Runs `f` as work on data of class `memory`: rows it creates for a
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
        let held = self.blobs.mark();
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
                self.blobs.rollback_to(held);
                self.core.forget_reach_since(m.reached);
                self.core.walks.forget_since(m.walked);
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
        let memory = ak.ephemeral();
        self.in_class(memory, |tx| Ok(tx.txn.put_local(&records::aspect_key(prefix, tid, ak), val, Shred::No)?))
    }

    /// Sets a retention timer of commit `c`'s part `ai` at `t`: memory for a memory commit.
    pub(crate) fn put_timer(&mut self, t: u64, c: &CommitId, ai: usize, kind: u8) -> Result<()> {
        let memory = self.is_memory_commit(c);
        self.core.timer_floor = self.core.timer_floor.min(t);
        self.in_class(memory, |tx| {
            tx.txn.put_local(&records::timer_key(t, c, ai), &[kind], Shred::No)?;
            Ok(tx.txn.put_local(&records::timer_of_key(t, c, ai), &[], Shred::No)?)
        })
    }

    /// Removes timer `t` of commit `c`'s part `ai`.
    pub(crate) fn remove_timer(&mut self, t: u64, c: &CommitId, ai: usize) -> Result<()> {
        self.txn.remove_local(&records::timer_key(t, c, ai), Shred::No)?;
        self.txn.remove_local(&records::timer_of_key(t, c, ai), Shred::No)?;
        Ok(())
    }

    /// Removes every timer of commit `c` (`ai`: of that part alone), found by part
    /// (`records::TIMER_OF`): O(the commit's timers).
    pub(crate) fn remove_timers_of(&mut self, c: &CommitId, ai: Option<usize>) -> Result<()> {
        let mut found = Vec::new();
        self.scan(&[records::TIMER_OF, &c.0[..]].concat(), |k, _| {
            let mut r = records::Rd::new(k);
            found.push((r.u32()? as usize, r.u64()?));
            Ok(())
        })?;
        for (x, t) in found.into_iter().filter(|(x, _)| ai.is_none_or(|ai| ai == *x)) {
            self.remove_timer(t, c, x)?;
        }
        Ok(())
    }

    /// Loads the state of `(tid, ak)` into the cache: a paged state lazily (its skeleton; pages
    /// as `ensure_*` and `load` need them), a state stored as its body from that body's part in
    /// its commit record. The one reader of stored states.
    pub fn load_lazy(&mut self, tid: &Tid, ak: &Ak) -> Result<()> {
        let k = (*tid, ak.clone());
        self.txn.noted_aspect(tid, ak);
        if self.core.states.contains_key(&k) {
            return Ok(());
        }
        let b = self.txn.get_aspect(tid, ak)?.map(|u| u.state).unwrap_or_default();
        let mut bound = self.bound.take();
        let f = match state::stored(&b)? {
            state::Stored::Empty => None,
            state::Stored::Whole(b) => Some(pages::charge(&mut bound, b.len(), || state::decode(b))?),
            state::Stored::Paged(b) => {
                let mut idx = None;
                let f = pages::charge(&mut bound, b.len(), || {
                    let (f, i) = pages::open(b, &self.core.key_salt)?;
                    idx = Some(i);
                    Ok(f)
                })?;
                self.core.pages.extend(idx.map(|i| (k.clone(), i)));
                Some(f)
            }
            state::Stored::Body(c) => {
                let ai = self.core.ix.commits.get(&c).and_then(|m| m.aspect(tid, ak)).ok_or(Error::Corrupt("state body"))?;
                let len = self.get_commit(&c)?.and_then(|r| r.part(ai).map(|p| p.delta.len())).unwrap_or(0);
                Some(pages::charge(&mut bound, len, || crate::apply::stored_fragment(self, &c, ai)?.ok_or(Error::Corrupt("state body")))?)
            }
        };
        self.bound = bound;
        self.core.states.insert(k, f);
        Ok(())
    }

    /// Before parts `ais` of commit `id` leave its record: each state stored as one of them
    /// (`state::Stored::Body`) is read into the cache and noted written, so this transaction reads
    /// it as it was and `settle_states` stores it again (by then it is rewritten: a valid body's
    /// drop rebuilds its state, shredded).
    pub(crate) fn pin_states(&mut self, id: &CommitId, ais: &[usize]) -> Result<()> {
        let Some(h) = self.core.ix.commits.get(id).map(|m| m.view.clone()) else { return Ok(()) };
        for ai in ais {
            let Some(a) = h.aspects.get(*ai) else { continue };
            let k = (a.tid, a.ak.clone());
            let b = self.txn.get_aspect(&a.tid, &a.ak)?.map(|u| u.state).unwrap_or_default();
            if matches!(state::stored(&b)?, state::Stored::Body(c) if c == *id) {
                self.load_lazy(&a.tid, &a.ak)?;
                self.core.wrote(k);
            }
        }
        Ok(())
    }

    /// Transaction end: the placement of each paged sequence of a state written here that a
    /// write could not follow, or a read found missing or damaged, is laid out anew
    /// (`pages::unplaced`): the writer pays for it, and a read never writes.
    pub(crate) fn settle_placements(&mut self) -> Result<()> {
        let mut seen = BTreeSet::new();
        for k in self.core.written.clone() {
            if !seen.insert(k.clone()) {
                continue;
            }
            let Some(ps) = self.core.pages.get(&k).map(pages::unplaced).filter(|p| !p.is_empty()) else { continue };
            let (tid, ak) = (&k.0, &k.1);
            self.with_pages(tid, ak, |txn, idx, f| ps.iter().try_for_each(|p| pages::rebuild_placement(txn, tid, ak, idx, f, p)))?;
        }
        Ok(())
    }

    /// Transaction end: each unpaged state written here is stored as a body equal to it, held
    /// whole and valid (`state::Stored::Body`): the one it names already, else the aspect's
    /// newest; else whole. One rule for every writer (joins, rebuilds, drops, purges); equality
    /// makes the reference exact whatever normalised the state.
    pub(crate) fn settle_states(&mut self) -> Result<()> {
        let mut seen = BTreeSet::new();
        for k in self.core.written.clone() {
            if !seen.insert(k.clone()) || self.core.pages.contains_key(&k) {
                continue;
            }
            let Some(Some(st)) = self.core.states.get(&k) else { continue };
            let (tid, ak) = (&k.0, &k.1);
            let st = st.clone();
            let b = self.txn.get_aspect(tid, ak)?.map(|u| u.state).unwrap_or_default();
            let now = match state::stored(&b)? {
                state::Stored::Body(c) => Some(c),
                _ => None,
            };
            // the body it names already, then the newest held one
            let newest = self.core.ix.by_aspect.get(&k).and_then(|s| s.iter().next_back()).map(|x| x.1);
            let mut same = None;
            for c in now.into_iter().chain(newest.filter(|c| Some(*c) != now)) {
                let Some(ai) = self.core.ix.commits.get(&c).and_then(|m| m.aspect(tid, ak).filter(|ai| m.valid_at(*ai) && m.holds(*ai) && !m.stripped(*ai))) else { continue };
                if crate::apply::stored_fragment(self, &c, ai)?.is_some_and(|f| f == st) {
                    same = Some(c);
                    break;
                }
            }
            match same {
                Some(c) if now != Some(c) => self.txn.put_aspect(tid, ak, &AspectUnit { state: state::body(&c) }, Shred::No)?,
                None if now.is_some() => self.write_state(tid, ak, Some(st), Shred::No)?,
                _ => {}
            }
        }
        Ok(())
    }

    /// Whether the state of `(tid, ak)` is paged with some page not loaded.
    fn held_in_part(&self, tid: &Tid, ak: &Ak) -> bool {
        self.core.pages.get(&(*tid, ak.clone())).is_some_and(|i| !i.whole())
    }

    /// Runs `g` on the cached state of `(tid, ak)` (taken out of the cache meanwhile) and its page
    /// index; nothing for an unpaged state.
    fn with_pages<T>(&mut self, tid: &Tid, ak: &Ak, g: impl FnOnce(&mut Transaction<'_>, &mut pages::StatePages, &mut Fragment) -> Result<T>) -> Result<Option<T>> {
        let k = (*tid, ak.clone());
        let Some(idx) = self.core.pages.get_mut(&k) else { return Ok(None) };
        let Some(mut f) = self.core.states.get_mut(&k).and_then(Option::take) else { return Ok(None) };
        idx.bound = self.bound.take();
        let r = g(&mut self.txn, idx, &mut f);
        self.bound = idx.bound.take();
        self.core.states.insert(k, Some(f));
        r.map(Some)
    }

    /// Runs read `f` of `(tid, ak)` holding at most `max` bytes of the state as it loads it
    /// (`pages::charge`), then leaves the cache about as it found it: a state it loaded goes (as at
    /// a restart), one held in part before loses its loaded pages (`pages::evict`, which keeps a
    /// paged sequence's). So a read holds what it loads only while it runs.
    pub(crate) fn reading<T>(&mut self, tid: &Tid, ak: &Ak, max: Option<usize>, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let k = (*tid, ak.clone());
        let cached = self.core.states.contains_key(&k);
        let whole = !self.held_in_part(tid, ak);
        self.bound = max;
        let r = f(self);
        self.bound = None;
        if !cached {
            self.core.states.remove(&k);
            self.core.pages.remove(&k);
        } else if !whole {
            self.evict_pages(tid, ak);
        }
        r
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
    /// again while it missed rows, chunks or pages (what it missed loaded, `pages::absorb`) until
    /// the runs' work passes about one whole pass, then on the whole state.
    pub(crate) fn run_attached<R>(&mut self, tid: &Tid, ak: &Ak, attached: bool, run: impl Fn(&Tx<'_>) -> R) -> Result<R> {
        let mut out = run(self);
        if !attached {
            return Ok(out);
        }
        let mut work = 0;
        loop {
            match self.with_pages(tid, ak, |txn, idx, f| pages::absorb(txn, tid, ak, idx, f, &mut work))?.flatten() {
                Some(false) => break,
                Some(true) => out = run(self),
                None => {
                    self.load(tid, ak)?;
                    out = run(self);
                    break;
                }
            }
        }
        Ok(out)
    }

    /// The visible elements `r` (by index, clamped) of the sequence at `path` (op path segments):
    /// a paged one through its placement (`pages::seq_range`), loading only the pages holding
    /// them; else, or where the placement is missing or damaged (laid out anew by the next
    /// transaction writing the state, `settle_placements`), from the whole sequence. `None` if
    /// absent or not a sequence.
    pub fn read_range(&mut self, tid: &Tid, ak: &Ak, path: &[osis_crdt::PathSeg], r: std::ops::Range<usize>) -> Result<Option<osis_base::Value>> {
        self.load_lazy(tid, ak)?;
        if self.held_in_part(tid, ak)
            // an empty sequence reads whole (its presence)
            && let Some(pages::Ranged::Read(p, dots, total)) = self.with_pages(tid, ak, |txn, idx, f| pages::seq_range(txn, tid, ak, idx, f, path, r.clone()))?
            && total > 0
        {
            match self.cached(tid, ak).and_then(|f| f.at_steps(&p)).and_then(|s| s.read_elems(&dots)) {
                Some(v) => return Ok(Some(v)),
                // a placement naming what its pages lack
                None => {
                    if let Some(idx) = self.core.pages.get_mut(&(*tid, ak.clone())) {
                        pages::damaged(idx, &p);
                    }
                }
            }
        }
        self.ensure_paths(tid, ak, &[path.to_vec()])?;
        Ok(self.cached(tid, ak).and_then(|f| f.at(path)).filter(Fragment::present).and_then(|s| s.read_elems(&s.visible_range(r)?)))
    }

    /// Loads what joining a delta with this touch reads and rewrites (`pages::ensure_touch`;
    /// `None`: everything).
    pub fn ensure_touch(&mut self, tid: &Tid, ak: &Ak, touch: &pages::Touch) -> Result<()> {
        self.load_lazy(tid, ak)?;
        if !self.held_in_part(tid, ak) {
            return Ok(());
        }
        if let Some(t) = touch
            && self.with_pages(tid, ak, |txn, idx, f| pages::ensure_touch(txn, tid, ak, idx, f, t))? == Some(true)
        {
            return Ok(());
        }
        self.load(tid, ak)
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
    /// does not fit (join whole, nothing noted in `dead`). The state is noted written.
    pub(crate) fn join_reset(&mut self, tid: &Tid, ak: &Ak, delta: &osis_crdt::Fragment, dead: Option<&mut crate::retention::Killed>) -> Result<Option<osis_crdt::Changes>> {
        let k = (*tid, ak.clone());
        // an index derives from the whole state (`derive`): joined whole
        if !self.core.pages.contains_key(&k) || derives(ak) {
            return Ok(None);
        }
        // noted first: a failure midway evicts what it changed
        self.core.touch();
        self.core.wrote(k.clone());
        let (Some(idx), Some(Some(f))) = (self.core.pages.get_mut(&k), self.core.states.get(&k)) else { return Ok(None) };
        let mut moved = refs::Delta::default();
        match pages::join_reset(&mut self.txn, tid, ak, idx, f, delta, &mut moved, dead)? {
            pages::Reset::Whole => {
                let _s = osis_base::costs::span("reset: whole");
                Ok(None)
            }
            pages::Reset::Paged { skeleton, unit, changes } => {
                let _s = osis_base::costs::span("reset: by pages");
                let mut u = self.txn.get_aspect(tid, ak)?.unwrap_or_default();
                u.state = unit;
                self.txn.put_aspect(tid, ak, &u, Shred::No)?;
                self.core.states.insert(k, Some(skeleton));
                refs::note(self, tid, ak, None, moved)?;
                Ok(Some(changes))
            }
            pages::Reset::Laid { state, changes } => {
                let _s = osis_base::costs::span("reset: laid out");
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
        drop(osis_base::costs::span("state copied whole"));
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

    /// The pieces of the state of `(tid, ak)` as a read sees each, within the running read's
    /// bound (`reading`): an unpaged or wholly loaded state is one piece, a paged one its skeleton,
    /// then its pages one at a time, never joined into the cache (`pages::each_piece`; with `keys`
    /// each reads as the whole does there, and a collection paged inside another's elements reads
    /// whole, one piece). `each` returns whether to stop.
    pub(crate) fn each_piece(&mut self, tid: &Tid, ak: &Ak, keys: bool, each: &mut dyn FnMut(&Fragment) -> Result<bool>) -> Result<()> {
        self.load_lazy(tid, ak)?;
        if self.held_in_part(tid, ak) {
            let k = (*tid, ak.clone());
            let bound = self.bound.take();
            let r = match (self.core.pages.get_mut(&k), self.core.states.get(&k)) {
                (Some(idx), Some(Some(f))) => {
                    idx.bound = bound;
                    pages::each_piece(&mut self.txn, tid, ak, idx, f, keys, each)
                }
                _ => Ok(None),
            };
            self.bound = bound;
            if r?.is_some() {
                return Ok(());
            }
        }
        if let Some(f) = self.state(tid, ak)? {
            each(f)?;
        }
        Ok(())
    }

    /// Whether the state of `(tid, ak)` is present (`Fragment::present`), holding at most `max`
    /// of it (`reading`): its pieces up to the first present one (`each_piece`; a state is
    /// present iff a write in it survives, and each piece holds what prunes its writes).
    pub fn present_within(&mut self, tid: &Tid, ak: &Ak, max: Option<usize>) -> Result<bool> {
        self.reading(tid, ak, max, |tx| {
            let mut present = false;
            tx.each_piece(tid, ak, false, &mut |f| {
                present = f.present();
                Ok(present)
            })?;
            Ok(present)
        })
    }

    /// Whether `(tid, ak)` has a state: a valid write on it applied here. What a thing has is
    /// read here (or from an index derived from states: `Indexes::sync_recorded`),
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

    /// Writes a whole state; `f` is the whole state. The reference index follows it whole
    /// (`refs::resync`).
    pub fn set_state(&mut self, tid: &Tid, ak: &Ak, f: Option<Fragment>, shred: Shred) -> Result<()> {
        refs::resync(self, tid, ak, f.as_ref())?;
        self.write_state(tid, ak, f, shred)
    }

    /// `set_state` for a join, whose caller keeps the reference index (`refs::Delta::reach`).
    fn write_state(&mut self, tid: &Tid, ak: &Ak, f: Option<Fragment>, shred: Shred) -> Result<()> {
        self.core.touch();
        self.core.wrote((*tid, ak.clone()));
        let mut unit = self.txn.get_aspect(tid, ak)?.unwrap_or_default();
        let paged = matches!(state::stored(&unit.state)?, state::Stored::Paged(_));
        let (bytes, idx) = pages::write_full(&mut self.txn, tid, ak, f.as_ref(), paged, &self.core.key_salt)?;
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
    /// `Indexes::sync_recorded`.
    fn derive(&mut self, tid: &Tid, ak: &Ak, f: Option<&Fragment>) {
        if derives(ak) {
            let before = self.core.ix.sync_recorded_ids.get(tid).cloned().unwrap_or_default();
            let after = f.map(crate::sync::recorded_ids).unwrap_or_default();
            match after.is_empty() {
                true => self.core.ix.sync_recorded_ids.remove(tid),
                false => self.core.ix.sync_recorded_ids.insert(*tid, after.clone()),
            };
            for s in before.difference(&after) {
                self.core.ix.sync_recorders.remove(s, tid);
            }
            for s in after.difference(&before) {
                self.core.ix.sync_recorders.insert(*s, *tid);
            }
            match f {
                Some(_) => self.core.ix.sync_recorded.insert(*tid),
                None => self.core.ix.sync_recorded.remove(tid),
            };
        }
    }

    /// Writes a state a join changed: `touch` (`pages::touch_of` the delta) says what it
    /// changed. A paged state rewrites only those pages (and its skeleton if needed); anything
    /// else is written whole (the pages not loaded joined in first). The caller has noted the
    /// state as written (`Core::written`).
    pub fn set_state_touched(&mut self, tid: &Tid, ak: &Ak, f: Option<Fragment>, touch: &pages::Touch, shred: Shred) -> Result<()> {
        let k = (*tid, ak.clone());
        let mut f = f;
        // an index derives from the whole state (`derive`), never the pages loaded
        if derives(ak)
            && let (Some(st), Some(idx)) = (&mut f, self.core.pages.get_mut(&k))
        {
            pages::load_all(&mut self.txn, tid, ak, idx, st)?;
        }
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
        if let (Some(st), Some(idx)) = (&mut f, self.core.pages.get_mut(&k)) {
            pages::load_all(&mut self.txn, tid, ak, idx, st)?;
        }
        self.write_state(tid, ak, f, shred)
    }

    /// `m` as `id`'s meta, its stored record rewritten under it (the blob unchanged).
    pub(crate) fn put_meta_record(&mut self, id: &CommitId, m: Meta) -> Result<()> {
        if let Some(blob) = self.get_commit(id)? {
            self.put_commit(id, &blob, &m, Shred::No, None)?;
        }
        self.core.put_meta(*id, m);
        Ok(())
    }

    /// Writes a commit record (`index::record_head`: received, origin, dropped parts and what
    /// they keep; then its blob), and for a role commit its `node/perm` row (`edges`: what the caller already
    /// read of `blob` with `perm_parts_of`, else decoded here).
    pub(crate) fn put_commit(&mut self, id: &CommitId, blob: &CommitBlob, meta: &Meta, shred: Shred, edges: Option<&crate::apply::validity::PermParts>) -> Result<()> {
        // the bodies leaving the record: held whole as the index has it, absent from `blob`
        self.core.note_kept(id, meta);
        let leaving: Vec<usize> = self.core.ix.commits.get(id).map(|m| (0..m.view.aspects.len()).filter(|ai| m.holds(*ai) && !m.stripped(*ai) && blob.part(*ai).is_none()).collect()).unwrap_or_default();
        self.pin_states(id, &leaving)?;
        let v = [index::record_head(meta), blob.encode()].concat();
        self.txn.put_local(&records::commit_key(id), &v, shred)?;
        crate::sync_ids::opened::prune(self, id, meta)?;
        if meta.header.kind.is_role() {
            // perm's reading of it, persisted beside the record (an open decodes no body)
            match edges {
                Some(p) => index::put_perm(self, id, p, shred)?,
                None => {
                    let p = crate::apply::perm_parts_of(self, id, &meta.header, blob)?;
                    index::put_perm(self, id, &p, shred)?;
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
        self.txn.remove_local(&records::commit_key(id), Shred::Yes)?;
        crate::sync_ids::opened::forget(self, id)?;
        index::remove_perm(self, id)?;
        index::remove_addenda(self, id)
    }

    /// The blob of the stored record of commit `id`, decoded once per write of the record
    /// (`Core::decoded`).
    pub fn get_commit(&mut self, id: &CommitId) -> Result<Option<Arc<CommitBlob>>> {
        let key = records::commit_key(id);
        self.txn.noted_local(&key);
        let at = self.txn.local_stamp(&key);
        let txn = &mut self.txn;
        if let Some(b) = self.core.decoded.record(id, at, || osis_base::costs::paused(|| txn.get_local(&key)))? {
            return Ok(Some(b));
        }
        drop(osis_base::costs::span("commit read"));
        let Some(v) = self.txn.get_local(&key)? else { return Ok(None) };
        let b = Arc::new(decode_commit_record(&v)?.1);
        self.core.decoded.keep_record(*id, at, b.clone(), &v);
        Ok(Some(b))
    }

    /// `get_commit` for the bytes of the parts `keep` selects alone, read at those parts' holds
    /// in the index (`Meta::hold`) rather than at the record's row: a part's bytes are fixed by
    /// the commit's ID, and the record carries exactly the parts held as their bodies, so a reader
    /// of some parts moves with those parts alone, not with another part of the commit arriving or
    /// dropping. Mid-write (a hold set before its record is written, or after) the two disagree:
    /// the reader then reads the row too, so the write moves it whatever order it comes in.
    pub(crate) fn commit_for_parts(&mut self, id: &CommitId, keep: &dyn Fn(usize) -> bool) -> Result<Option<Arc<CommitBlob>>> {
        let Some(m) = self.core.ix.commits.get(id) else { return self.get_commit(id) };
        let bodies: Vec<(usize, bool)> = (0..m.parts()).filter(|ai| keep(*ai)).map(|ai| (ai, matches!(m.hold(ai), Some(Hold::Body { .. })))).collect();
        let blob = osis_base::memo::unrecorded(|| self.get_commit(id))?;
        if bodies.iter().any(|(ai, body)| *body != blob.as_ref().is_some_and(|b| b.part(*ai).is_some())) {
            self.txn.noted_local(&records::commit_key(id));
        }
        Ok(blob)
    }

    /// The change stamp of commit `id`'s record (`Transaction::local_stamp`): what `Core::decoded`
    /// keeps its decodes at.
    pub(crate) fn commit_stamp(&self, id: &CommitId) -> u64 {
        self.txn.local_stamp(&records::commit_key(id))
    }

    /// Every stored pending or parked copy, a page at a time.
    pub(crate) fn each_pending(&mut self, mut f: impl FnMut(CommitId, osis_store::Pending)) -> Result<()> {
        let mut after: Option<CommitId> = None;
        loop {
            let page = self.txn.pending(after.as_ref(), SCAN_PAGE)?;
            let n = page.len();
            for (id, p) in page {
                after = Some(id);
                f(id, p);
            }
            if n < SCAN_PAGE {
                return Ok(());
            }
        }
    }

    /// Removes, shredded, every local record under `prefix` whose key past it `pred` takes.
    pub(crate) fn remove_scanned(&mut self, prefix: &[u8], pred: impl Fn(&[u8]) -> Result<bool>) -> Result<()> {
        let mut gone = Vec::new();
        self.scan(prefix, |k, _| {
            if pred(k)? {
                gone.push([prefix, k].concat());
            }
            Ok(())
        })?;
        for k in gone {
            self.txn.remove_local(&k, Shred::Yes)?;
        }
        Ok(())
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

    /// The keys under `prefix`, each `N` bytes made a `T` by `of`; a key of another length is a
    /// corrupt `what` row.
    pub(crate) fn scan_keys<const N: usize, T>(&mut self, prefix: &[u8], what: &'static str, of: impl Fn([u8; N]) -> T) -> Result<Vec<T>> {
        let mut out = Vec::new();
        self.scan(prefix, |k, _| {
            out.push(of(k.try_into().map_err(|_| Error::Corrupt(what))?));
            Ok(())
        })?;
        Ok(out)
    }

    pub fn now(&self) -> WallMs {
        self.core.now()
    }
}

/// Rows read per store call by the scans.
pub(crate) const SCAN_PAGE: usize = 256;

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

/// The entries of `index` (keyed by thing, then another) on `t`, each with that other: a read
/// of `t`'s run alone (`actor_run`).
fn run_of(index: &JSetMap<(Tid, Tid), CommitId>, t: Tid) -> impl Iterator<Item = (Tid, &BTreeSet<CommitId>)> {
    index.run(actor_run(&t), (t, Tid::from_bytes([0; 15]))..).take_while(move |((x, _), _)| *x == t).map(|((_, a), s)| (*a, s))
}

/// The run of a thing's entries in a map keyed by thing first (`JMap::by_run`).
fn actor_run(a: &Tid) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    a.hash(&mut h);
    h.finish()
}

/// A stored commit record's `(head, blob)`, its header's linked lists filled from the head.
pub(crate) fn decode_commit_record(v: &[u8]) -> Result<CommitRecord> {
    let (head, rest) = index::parse_head(v)?;
    let mut blob = CommitBlob::decode_stored(rest).map_err(|_| Error::Corrupt("commit blob"))?;
    head.resolve(&mut blob.header)?;
    Ok((head, blob))
}

/// One node's engine.
pub struct Engine {
    store: Store,
    store_rng: SeededRng,
    /// The node's one store of ciphertext (`osis_store::Ciphertext`): every blob the engine
    /// holds, committed before the engine's own store.
    blobs: Arc<dyn osis_store::Ciphertext>,
    /// The next transaction's sequence in the ciphertext store's notes (`blobs::Cipher`).
    blob_seq: u64,
    /// Stamps what the engine holds of `blobs`, by blob (`blobs::Cipher`).
    blob_stamps: osis_base::memo::Stamps,
    /// A transaction's commit or its releases failed: `settle_blobs` runs before the next.
    pub(crate) blobs_unsettled: bool,
    /// The store's `Writes::failed` and `Writes::unknown` when this engine last read it whole
    /// (`load`): the next transaction reads it again once either moves (`reload_owed`).
    failed_seen: (u64, u64),
    /// A transaction acting on in-memory work taken outside it failed (`run_taken`): the next
    /// transaction reads the store again (`reload_owed`).
    taken_failed: bool,
    /// How many times the in-memory indexes were read from the store again (`load_fresh`): each
    /// replaces every memo stamp and feed a follower read (`Engine::loads`).
    loads: u64,
    pub(crate) rng: Box<dyn osis_crypto::NodeRng>,
    #[doc(hidden)]
    pub core: Core,
    /// The local ephemeral write path's own state (`crate::ephemeral`): the undo log,
    /// unsent ephemeral signals, delivered relay-only commits.
    pub(crate) eph: crate::ephemeral::Eph,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) cfg: Config,
    /// Debug builds: a durable transaction changed a state or a commit's parts since
    /// `check_index` last ran; it runs at the end of the engine's history (its drop). A copy
    /// starts clear: its original checks their shared past.
    #[cfg(debug_assertions)]
    index_unchecked: bool,
    /// Debug builds: a transaction ran since `checked_verdicts` last did; it runs at the end of
    /// the engine's history. A copy starts clear, as for `index_unchecked`.
    #[cfg(debug_assertions)]
    verdicts_unchecked: bool,
    /// Debug builds: the wall time the last transaction ran at, which the index is as of
    /// (`check_index`).
    #[cfg(debug_assertions)]
    last_tx_wall: Option<u64>,
    /// Debug builds: a load (`load`) began and has not finished, so the core is half loaded and
    /// the drop checks nothing.
    #[cfg(debug_assertions)]
    loading: bool,
    /// Tests: an index was edited in memory past the store, so `check_index` does not run.
    #[cfg(test)]
    pub(crate) index_poked: bool,
    /// Tests, set by hand: `check_index` after every transaction that changed something, not
    /// only at the end (to find the transaction that diverged).
    #[cfg(test)]
    pub(crate) check_every_tx: bool,
    /// Tests: the next round of `reexamine` fails before examining what it took, as a round
    /// erring does (`run_taken`).
    #[cfg(test)]
    pub(crate) fail_round: bool,
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

/// `r`, then `f` while `r` is `Ok` (`f`'s error in its place): a transaction's end work, a step at a time.
fn then<T, U>(r: Result<T>, f: impl FnOnce() -> Result<U>) -> Result<T> {
    r.and_then(|v| f().map(|_| v))
}

impl Engine {
    /// How many times the engine read its indexes from the store again (an open, a reload after
    /// a write of unknown outcome): a follower of its memos (sync's modules)
    /// follows them afresh when it moves, as the old stamps and feeds see no further write.
    pub fn loads(&self) -> u64 {
        self.loads
    }

    /// `Store::writes` of the engine's store.
    pub fn store_writes(&self) -> osis_store::Writes {
        self.store.writes()
    }

    /// A store write failed since the store was last read whole, or a transaction acting on work
    /// taken outside it (`run_taken`): the next transaction reads it again (`run`), and a tick is
    /// due (`next_timer`) so one runs with no other event.
    pub fn reload_owed(&self) -> bool {
        let w = self.store.writes();
        (w.failed, w.unknown) != self.failed_seen || self.taken_failed
    }

    /// `run` acting on in-memory work taken outside the transaction (what woke pending commits,
    /// `apply::waits::wake`; loose records come to be awaited, `waits::Loose::take_due`): the
    /// transaction failing, whatever failed (the store, or a round of examinations erring), owes a
    /// reload, so what it took is derived again as an open derives it, never lost while the node
    /// stays up (spec/commits.md §4: every arrival that applies examines again what waits for it).
    pub(crate) fn run_taken<T>(&mut self, f: impl FnOnce(&mut Tx<'_>) -> Result<T>) -> Result<T> {
        let r = self.run(f);
        self.taken_failed |= r.is_err();
        r
    }

    /// While this stands (no commit changed the store, the indexes stand, the clock stands) a
    /// read of the engine repeats itself.
    pub fn point(&self) -> ReadPoint {
        (self.store.changes(), self.core.generation, self.core.memory_generation, self.core.now().0)
    }

    /// The engine of node `id` over `store`, its indexes empty (`create` writes them, `open`
    /// loads them).
    fn over(store: Store, store_rng: SeededRng, blobs: Arc<dyn osis_store::Ciphertext>, cfg: Config, clock: Arc<dyn Clock>, mut rng: Box<dyn osis_crypto::NodeRng>, id: Identity) -> Engine {
        let (session, expiring) = sessions(id.tid(), &mut *rng);
        let rows = store.row_changes();
        Engine { store, store_rng, blobs, blob_stamps: Default::default(), blob_seq: 1, blobs_unsettled: false, failed_seen: (0, 0), taken_failed: false, loads: 0, rng, core: Core::new(id, clock.clone(), session, expiring, rows), eph: crate::ephemeral::Eph::default(), clock, cfg, #[cfg(debug_assertions)] index_unchecked: false, #[cfg(debug_assertions)] verdicts_unchecked: false, #[cfg(debug_assertions)] last_tx_wall: None, #[cfg(debug_assertions)] loading: false, #[cfg(test)] index_poked: false, #[cfg(test)] check_every_tx: false, #[cfg(test)] fail_round: false }
    }

    /// A new node over an empty backend: fresh identity, its node thing with `created.0`,
    /// `node.0` and `keys.0` (spec/permissions.md §4 node card).
    pub fn create(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, blobs: Arc<dyn osis_store::Ciphertext>, cfg: Config, clock: Arc<dyn Clock>, mut rng: Box<dyn osis_crypto::NodeRng>) -> Result<Engine> {
        let store = Store::create(backend, root, cfg.store, &mut *rng)?;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let store_rng = SeededRng::from_seed(seed);
        let id = Identity::generate(&mut *rng);
        let mut e = Engine::over(store, store_rng, blobs, cfg, clock, rng, id);
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
    pub fn open(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, blobs: Arc<dyn osis_store::Ciphertext>, cfg: Config, clock: Arc<dyn Clock>, mut rng: Box<dyn osis_crypto::NodeRng>) -> Result<Engine> {
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
        let node_root = {
            let mut txn = store.transaction(&mut store_rng)?;
            txn.get_local(records::NODE_ROOT)?.map(|b| <[u8; osis_base::format::TID_LEN]>::try_from(b.as_slice()).map(Tid::from_bytes).map_err(|_| Error::Corrupt("node root"))).transpose()?
        };
        let mut e = Engine::over(store, store_rng, blobs, cfg, clock, rng, id);
        e.core.node_root = node_root;
        e.load()?;
        Ok(e)
    }

    /// Reads the store whole, as an open does: at open, and in place once the store works again
    /// after a write whose outcome was unknown (`run`).
    fn load(&mut self) -> Result<()> {
        #[cfg(debug_assertions)]
        {
            self.loading = true;
        }
        self.settle_blobs()?;
        // the account first: judging what is held reads which commits are this node's own (an own
        // part judged invalid stays, `retention::goes_invalid`)
        if let Some((p, _)) = self.account()? {
            self.core.account.set(Some(p));
        }
        self.reload()?;
        self.take_account()?;
        self.reexamine()?;
        self.forget_gone_causes()?;
        self.rejudge_setting_waits()?;
        // a leftover held from before goes uncovered no longer than a quiet time from here
        // (spec/sync-compaction.md §1 trigger)
        let quiet = self.now().0.saturating_add(crate::retention::compact::QUIET_MS);
        let held: Vec<(Tid, Ak)> = self.core.ix.valueless.iter().filter(|(k, l)| !l.is_empty() && crate::retention::compact::compactable(&k.1)).map(|(k, _)| k.clone()).collect();
        for k in held {
            self.core.compaction.arm(k, quiet);
        }
        // what this node may not write could not be compacted: weighed once it may
        self.owe_unwritable_held()?;
        self.core.timer_floor = self.next_timer()?.unwrap_or(u64::MAX);
        #[cfg(debug_assertions)]
        {
            self.loading = false;
        }
        Ok(())
    }

    /// The ciphertext store's notes against this store (`blobs::Cipher`): a transaction this
    /// store committed (its sequence at most the one recorded) gets its forgotten blobs and releases, one it did not
    /// gets its holds released. Then the next sequence follows every one seen. At open, and after
    /// a commit whose outcome is unknown.
    fn settle_blobs(&mut self) -> Result<()> {
        let committed = {
            let mut txn = self.store.transaction(&mut self.store_rng)?;
            let v = txn.get_local(records::BLOB_SEQ)?;
            v.map(|b| <[u8; 8]>::try_from(b.as_slice()).map(u64::from_be_bytes).map_err(|_| Error::Corrupt("blob sequence"))).transpose()?.unwrap_or(0)
        };
        let mut t = self.blobs.begin();
        let notes = t.notes()?;
        let mut last = committed;
        for n in &notes {
            if n.seq <= committed {
                for id in &n.forgot {
                    t.forgot(id)?;
                }
            }
            let undo = if n.seq <= committed { &n.releases } else { &n.holds };
            for id in undo {
                t.release(id, false)?;
            }
            t.unnote(n.seq)?;
            last = last.max(n.seq);
        }
        t.commit()?;
        // holds and releases of transactions never committed went
        self.blob_stamps.wrote_all();
        self.blob_seq = self.blob_seq.max(last + 1);
        self.blobs_unsettled = false;
        Ok(())
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
        self.make_node_root()
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
        self.read(|tx| Ok(tx.txn.get_local(&k)?))
    }

    /// Writes a local record of the API layer.
    pub fn set_app_record(&mut self, name: &str, value: &[u8]) -> Result<()> {
        let k = [records::APP, name.as_bytes()].concat();
        self.run(|tx| Ok(tx.txn.put_local(&k, value, Shred::No)?))
    }

    /// Reports a diagnostic of the API layer (deduped and rate-limited like the engine's).
    pub fn report(&mut self, d: crate::events::Diagnostic) {
        self.core.events.diagnostic(d, self.core.hlc.mono());
    }

    /// `report`, rate-limited per `remote` it is about (a connection's address, or the kind of
    /// remote where none is known): one remote's flood leaves other remotes' reports.
    pub fn report_from(&mut self, d: crate::events::Diagnostic, remote: Vec<u8>) {
        self.core.events.diagnostic_from(d, remote, self.core.hlc.mono());
    }

    /// The mint admin of `tid` (`None`: a key actor or an unknown thing).
    pub fn mint_admin(&self, tid: &Tid) -> Option<Tid> {
        self.core.mint_admin(tid)
    }

    /// This node's tid.
    pub fn tid(&self) -> Tid {
        self.core.id.tid()
    }

    /// The account this node writes as. Panics on a node that has joined none: for tests and
    /// paths past joining; `account_tid` where that can be.
    #[track_caller]
    #[allow(clippy::expect_used)]
    pub fn me(&self) -> Tid {
        self.core.account.get().expect("this node has joined no account")
    }

    /// The account this node belongs to, once it has one.
    pub fn account_tid(&self) -> Option<Tid> {
        self.core.account.get()
    }

    pub fn identity(&self) -> &Identity {
        &self.core.id
    }

    /// The wall clock.
    pub fn now(&self) -> WallMs {
        self.core.now()
    }

    /// The monotonic clock (`osis_base::Mono`): what a driver's waits run on.
    pub fn mono(&self) -> osis_base::Mono {
        self.clock.mono()
    }

    /// A channel of engine events, sent after durability.
    pub fn subscribe(&mut self) -> Receiver<Event> {
        self.core.events.subscribe()
    }

    /// Tests only (world copies): a subscription whose receiver holds `pending` first
    /// (`Events::test_subscribe_with`).
    #[doc(hidden)]
    pub fn test_subscribe_with(&mut self, pending: Vec<Event>) -> Receiver<Event> {
        self.core.events.test_subscribe_with(pending)
    }

    /// What brings back what the node could not judge since the last call, keeping it from now
    /// on (a test peer's fetches again).
    #[doc(hidden)]
    pub fn take_wakes(&mut self) -> Wakes {
        self.core.wakes.replace(Wakes::default()).unwrap_or_default()
    }

    /// The first `limit` local records under `prefix`, read in a store transaction dropped after:
    /// a read of rows alone, for a caller that reads nothing else through a `Tx` (`next_timer`).
    pub(crate) fn scan_local(&mut self, prefix: &[u8], limit: usize) -> Result<Vec<osis_store::KeyValue>> {
        Ok(self.store.transaction(&mut self.store_rng)?.scan_local(prefix, &[], limit)?)
    }

    /// What `f` returns, run as a read: in a store transaction dropped after, and whatever `f`
    /// changed in memory undone (`Core::rollback_to`), so it changes nothing. A read does none
    /// of a transaction's end work (`run`): that work follows changes, and a read keeps none.
    /// Caches it filled stay (they hold what is stored). Only for an `f` that changes nothing it
    /// should keep: a change (a lazy take-up) would be undone, dropping every cache, at each call,
    /// so a debug build panics at one that changed anything it undoes, the store or blobs.
    pub(crate) fn read<T>(&mut self, f: impl FnOnce(&mut Tx<'_>) -> Result<T>) -> Result<T> {
        let _s = osis_base::costs::span("read");
        if self.blobs_unsettled {
            memo::unrecorded(|| self.settle_blobs())?;
        }
        let now = self.core.hlc.wall().0;
        self.core.time.set(now);
        let start = self.core.mark();
        let txn = self.store.transaction(&mut self.store_rng)?;
        let mut tx = Tx { txn, blobs: blobs::Cipher::new(&*self.blobs, &self.blob_stamps, self.blob_seq), core: &mut self.core, rng: &mut *self.rng, bound: None };
        let r = f(&mut tx);
        // a read that changed something would have its change undone, and every cache dropped, at
        // every call
        #[cfg(debug_assertions)]
        {
            let mut moved = tx.core.moved_since(&start);
            moved.extend(tx.txn.wrote().then_some("store"));
            moved.extend(tx.blobs.changed().then_some("blobs"));
            assert!(moved.is_empty(), "Engine::read changed {moved:?}");
        }
        drop(tx);
        self.core.rollback_to(start);
        r
    }

    /// Runs `f` in one store transaction; events go out once it is durable.
    #[cfg_attr(debug_assertions, track_caller)]
    pub fn run<T>(&mut self, f: impl FnOnce(&mut Tx<'_>) -> Result<T>) -> Result<T> {
        let _s = osis_base::costs::span("tx");
        // debug builds: what the transaction notes (`osis_base::trace`) is tagged if it rolls back
        #[cfg(debug_assertions)]
        let (trace_mark, caller) = (osis_base::trace::len(), std::panic::Location::caller());
        // a store write failed (the device staying up), or a transaction acting on work taken
        // outside it (`run_taken`): everything is read again as an open reads it, so nothing kept
        // in memory beside the store (work an operation took outside the transaction that failed:
        // wakes, due lists) differs from what a restart derives. One
        // whose outcome was unknown (its sync failed) may have landed after all: read once the
        // store works again, under a fresh session (that commit's counters may be taken)
        // a memo running `f` reads what `f` reads: the transaction's own work around it (settling,
        // its end's follow-ups, persisting, checks) is no part of `f`'s answer
        if self.reload_owed() {
            let w = self.store.writes();
            let seen = std::mem::replace(&mut self.failed_seen, (w.failed, w.unknown));
            let taken = std::mem::take(&mut self.taken_failed);
            if w.unknown != seen.1 {
                self.core.fresh_session();
            }
            if let Err(e) = memo::unrecorded(|| self.load()) {
                self.failed_seen = seen;
                self.taken_failed = taken;
                return Err(e);
            }
            // what it read is durable: subscribers read everything again
            self.core.events.queue(crate::events::Event::Reloaded);
            self.core.events.flush();
        }
        if self.blobs_unsettled {
            memo::unrecorded(|| self.settle_blobs())?;
        }
        let _after;
        let now = self.core.hlc.wall().0;
        self.core.time.set(now);
        #[cfg(debug_assertions)]
        {
            self.last_tx_wall = Some(now);
        }
        // changes made outside a transaction are not this one's to undo
        self.core.commit_journal();
        self.core.memory_tx = false;
        self.core.learned.clear();
        let start = self.core.mark();
        #[cfg(debug_assertions)]
        {
            self.core.unchecked_tx = false;
        }
        // debug builds: whether the transaction changed a state or a part
        #[cfg(debug_assertions)]
        let mut changed = false;
        // debug builds: whether the transaction was durable (`flows::addenda::missed` after it)
        #[cfg(debug_assertions)]
        let mut durable = false;
        // the blobs it held, once committed
        let mut newly_held: Vec<BlobId> = Vec::new();
        let r = match self.store.transaction(&mut self.store_rng) {
            Ok(txn) => {
                let mut tx = Tx { txn, blobs: blobs::Cipher::new(&*self.blobs, &self.blob_stamps, self.blob_seq), core: &mut self.core, rng: &mut *self.rng, bound: None };
                // the persisted index follows the in-memory indexes in the same transaction
                let mut r = f(&mut tx);
                _after = memo::Unrecorded::start();
                // a thing minted with an account as admin is independent by its creating transaction's end
                // (spec/permissions.md §3)
                if !tx.core.own_secrets_due.is_empty() {
                    r = then(r, || crate::rotation::own_secrets_due(&mut tx));
                }
                tx.core.own_secrets_due.clear();
                // explicit demotions applied get this node's addenda (spec/permissions.md §5.2),
                // on what the node closure holds as this transaction leaves it (a node writes only
                // what it holds, spec/sync-set.md §2 Writing). The flows' own writes may bring
                // things into the node closure (an addendum makes the content it vouches for
                // valid, strongs included): what waits for them joins and the flows run again,
                // until nothing enters.
                let mut flows = osis_base::loop_guard::LoopGuard::new("Engine::run (the flows' writes bringing things into the node closure)");
                while r.is_ok() && !tx.txn.is_memory() {
                    r = then(r, || crate::sync::units::settle(&mut tx));
                    // what waits to see a thing enter the node closure joins as it enters
                    // (spec/commits.md §4 Outside the node closure), the closure settled again
                    let mut guard = osis_base::loop_guard::LoopGuard::new("Engine::run (what waits for things entering the node closure)");
                    while r.is_ok() {
                        match crate::apply::wake_entered(&mut tx) {
                            Ok(0) => break,
                            Ok(n) => {
                                // each round wakes what things newly entered hold back
                                let pending = tx.core.ix.pending.len() as u64;
                                guard.round(n, || (pending + 2, format!("{pending} pending")));
                                r = then(r, || crate::sync::units::settle(&mut tx));
                            }
                            Err(e) => r = Err(e),
                        }
                    }
                    // a commit pends only while carried (spec/commits.md §4 Pending storage)
                    r = then(r, || crate::apply::carriers::settle(&mut tx));
                    r = then(r, || crate::flows::inbox::owe_removal_notices(&mut tx));
                    r = then(r, || crate::flows::addenda::write_owed(&mut tx));
                    r = then(r, || crate::flows::signing::leave_if_removed(&mut tx));
                    r = then(r, || crate::flows::signing::answer_rotations(&mut tx));
                    r = then(r, || crate::sync::dial::drop_departed(&mut tx));
                    r = then(r, || crate::sync::units::settle(&mut tx));
                    if r.is_err() || !crate::apply::entering(&tx) {
                        break;
                    }
                    // each round brings a thing in
                    flows.round((), || {
                        let held = tx.core.ix.closure.things().count() as u64;
                        (held + 2, format!("{held} things in the node closure"))
                    });
                }
                #[cfg(debug_assertions)]
                {
                    durable = !tx.txn.is_memory();
                }
                tx.core.notices_due.clear();
                tx.core.removals_due.clear();
                if r.is_ok() && tx.core.header_fault.load(std::sync::atomic::Ordering::Relaxed) {
                    r = Err(Error::Corrupt("commit record header"));
                }
                // a body judged invalid goes at the end of the transaction that judged it
                // (spec/permissions.md §6), after this node's addenda vouched for what they list;
                // a memory transaction drops memory parts only (`drop_invalid`)
                if !tx.core.drop_due.is_empty() {
                    r = then(r, || crate::retention::drop_invalid(&mut tx));
                }
                tx.core.drop_due.clear();
                if !tx.core.settings_due.is_empty() {
                    // the new timelines walk rows dated by this transaction's kills and
                    // validity changes: a row is never early (a superseder turning invalid moves
                    // its victims' rows later), so the walk tells no body early
                    r = then(r, || crate::retention::leaving::date_due(&mut tx));
                    r = then(r, || crate::retention::settings_changed(&mut tx));
                }
                tx.core.settings_due.clear();
                // a setting that left here moves which external fires are valid
                // (`validity::setting_moved`): judged, and what turned invalid goes, in this
                // transaction; a removal notice turned valid is taken as one arriving
                if tx.core.stale() {
                    r = then(r, || crate::apply::rejudged(&mut tx, false).and_then(|_| crate::retention::drop_invalid(&mut tx)));
                    if !tx.core.removals_due.is_empty() && !tx.txn.is_memory() {
                        r = then(r, || crate::flows::inbox::owe_removal_notices(&mut tx));
                    }
                }
                tx.core.drop_due.clear();
                tx.core.removals_due.clear();
                if !tx.core.setting_waits_due.is_empty() {
                    r = then(r, || crate::sync::setting::judge_due(&mut tx));
                }
                tx.core.setting_waits_due.clear();
                if !tx.core.ix.cover_waits.is_empty() && !tx.txn.is_memory() {
                    r = then(r, || crate::retention::replace::wake_covers(&mut tx));
                }
                if !tx.core.none_due.is_empty() {
                    r = then(r, || crate::retention::settle_none(&mut tx));
                }
                tx.core.none_due.clear();
                // destructions and what nothing held needs any more, each letting more go
                // (`retention::needed`), judged on the node closure as it stands
                while r.is_ok() && !tx.txn.is_memory() {
                    r = then(r, || crate::retention::destroy::apply_destructions(&mut tx));
                    if r.is_err() || tx.core.needs_due.is_empty() {
                        break;
                    }
                    r = then(r, || crate::sync::units::settle(&mut tx));
                    let mut went = false;
                    r = r.and_then(|v| crate::retention::needed::settle(&mut tx).map(|w| {
                        went = w;
                        v
                    }));
                    if !went {
                        break;
                    }
                }
                tx.core.needs_due.clear();
                r = then(r, || crate::retention::persist_valueless(&mut tx));
                tx.core.valueless_dirty.clear();
                r = then(r, || edits::settle(&mut tx));
                tx.core.refold.clear();
                // freed links judged once every rebuild ran: a judged one keeps no key here
                if !tx.core.freed_due.is_empty() {
                    r = then(r, || crate::retention::freed::settle_due(&mut tx));
                }
                tx.core.freed_due.clear();
                if !tx.core.forgotten_names_due.is_empty() {
                    r = then(r, || crate::retention::names::settle_due(&mut tx));
                }
                tx.core.forgotten_names_due.clear();
                if !tx.core.handed_due.is_empty() {
                    r = then(r, || crate::retention::handed::settle_due(&mut tx));
                }
                tx.core.handed_due.clear();
                r = then(r, || listing::listing_moved(&mut tx));
                tx.core.listed_before.clear();
                tx.core.killed.clear();
                r = then(r, || crate::retention::leaving::date_due(&mut tx));
                tx.core.to_date.clear();
                // the node closure follows every change above (spec/sync-set.md §2), and holds
                // what this transaction made
                r = then(r, || crate::sync::units::settle(&mut tx).and_then(|()| crate::sync::units::check_written(&mut tx)));
                tx.core.wrote_on.clear();
                // what stopped pending above loses its carriers
                if !tx.txn.is_memory() {
                    r = then(r, || crate::apply::carriers::settle(&mut tx));
                }
                tx.core.carriers_due.clear();
                // the blob waits of what pends no more go (`apply::reach::settle`)
                crate::apply::reach::settle(tx.core);
                // every state written above stored in its form (`Tx::settle_states`)
                r = then(r, || tx.settle_placements().and_then(|()| tx.settle_states()));
                r = then(r, || Core::commit_changes(&mut tx));
                // every validity change was judged before the index is persisted
                debug_assert!(r.is_err() || (tx.core.stale_things.is_empty() && tx.core.stale_authors.is_empty() && tx.core.stale_commits.is_empty() && tx.core.ix.epochs_due.is_empty()), "stale validity left unjudged: {:?} {:?} {:?} {:?}", tx.core.stale_things, tx.core.stale_authors, tx.core.stale_commits, *tx.core.ix.epochs_due);
                #[cfg(debug_assertions)]
                if r.is_ok() {
                    match crate::apply::check_rebuilt(&mut tx) {
                        Ok(c) => changed = c && !tx.txn.is_memory(),
                        Err(e) => r = Err(e),
                    }
                }
                let persisted = {
                    let _s = osis_base::costs::span("tx: persist index");
                    then(then(r, || crate::sides::persist(&mut tx)), || index::persist(&mut tx))
                };
                match persisted {
                    Ok(v) => {
                        let Tx { mut txn, mut blobs, .. } = tx;
                        let held: Vec<BlobId> = blobs.newly_held().copied().collect();
                        let _s = osis_base::costs::span("tx: store commit");
                        // add before, remove after: the ciphertext store's holds commit first,
                        // the engine's store records this transaction's sequence with its own
                        // commit, the releases follow it (`blobs::Cipher`)
                        let noted = blobs.noted();
                        // durable whatever the transaction's mode: settling reads it after a crash
                        let mode = txn.is_memory();
                        txn.set_memory(false);
                        let seq = if noted { txn.put_local(records::BLOB_SEQ, &self.blob_seq.to_be_bytes(), Shred::No).map_err(Error::from) } else { Ok(()) };
                        txn.set_memory(mode);
                        let r = seq
                            .and_then(|()| blobs.commit())
                            .and_then(|()| txn.commit().map_err(Error::from));
                        match r {
                            Ok(()) => {
                                if noted {
                                    self.blob_seq += 1;
                                }
                                newly_held = held;
                                // a failure leaves the note: the next settle finishes it
                                self.blobs_unsettled |= blobs.after().is_err();
                                Ok(v)
                            }
                            Err(e) => {
                                self.blobs_unsettled = true;
                                Err(e)
                            }
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e.into()),
        };
        match r {
            Ok(v) => {
                if let Some(d) = self.core.walks_done.take() {
                    self.core.timelines.aside().saved(d);
                }
                self.core.commit_journal();
                // the blob waits wanting what it held are due (`apply::reach::Walks`)
                for b in &newly_held {
                    self.core.walks.held(b);
                }
                self.core.memory_tx = false;
                self.core.events.flush();
                // what the transaction moved may end a setting wait or start one again
                // (`sync::setting`)
                if !self.core.setting_waits_judging && !self.core.ix.setting_waits.is_empty() {
                    self.core.setting_waits_judging = true;
                    let r = memo::unrecorded(|| self.rejudge_setting_waits());
                    self.core.setting_waits_judging = false;
                    r?;
                }
                #[cfg(debug_assertions)]
                {
                    self.index_unchecked |= changed;
                    self.verdicts_unchecked = true;
                }
                #[cfg(test)]
                if changed && self.check_every_tx && !self.index_poked {
                    self.check_index();
                }
                // no addendum trigger missed, at the end of every durable transaction (an
                // answer owed only mid-history escapes a check at the drop alone)
                #[cfg(debug_assertions)]
                if durable && !self.loading {
                    self.check_missed_wakes("after a transaction");
                    // no blob wait wants a blob held here unnoted (a lost wake)
                    if self.core.walks.any() {
                        let r = self.check_walks(false);
                        assert!(matches!(r, Ok(()) | Err(Error::Store(_))), "blob waits after a transaction: {:?}", r.err());
                    }
                }
                Ok(v)
            }
            Err(e) => {
                self.core.walks_done = None;
                self.core.forget_reach_since(start.reached);
                self.core.walks.forget_since(start.walked);
                self.core.rollback_to(start);
                #[cfg(debug_assertions)]
                {
                    osis_base::trace::mark_since(trace_mark, " (rolled back)");
                    osis_base::trace::note(|| format!("tx rolled back at {}:{}: {e:?} ({e})", caller.file().rsplit("src/").next().unwrap_or(caller.file()), caller.line()));
                }
                Err(e)
            }
        }
    }

    /// A fresh `Core` loaded from the store (`rebuild`: ignoring the persisted index); whether
    /// it was rebuilt from the commit records.
    fn load_fresh(&mut self, rebuild: bool) -> Result<Option<Vec<(Tid, Ak)>>> {
        self.loads = self.loads.wrapping_add(1);
        let mut fresh = self.blank_core(self.clock.clone());
        fresh.events = std::mem::take(&mut self.core.events);
        fresh.key_actors = std::mem::take(&mut self.core.key_actors);
        fresh.held_keys = std::mem::take(&mut self.core.held_keys);
        // links followed are this session's, as the key actors they hold
        fresh.followed_links = std::mem::take(&mut self.core.followed_links);
        // the pass place never goes back: passes under way began at places below it
        fresh.place = self.core.place;
        fresh.accounts = std::mem::take(&mut self.core.accounts);
        fresh.redeliver = std::mem::take(&mut self.core.redeliver);
        fresh.waits = std::mem::take(&mut self.core.waits);
        // the trigger's estimates and due aspects (in memory, an open starts them empty): a write
        // that failed counted more than landed, which costs a weighing at most
        fresh.compaction = std::mem::take(&mut self.core.compaction);
        // memory snapshots owed (a superset is harmless; no open derives them)
        fresh.fallen = std::mem::take(&mut self.core.fallen);
        fresh.wakes = self.core.wakes.take();
        // the sync units' sources are the handle's, set between transactions (`set_sourced`)
        fresh.sourced_elsewhere = std::mem::take(&mut self.core.sourced_elsewhere);
        fresh.node_root = self.core.node_root;
        // states loaded as stored: still unchecked
        #[cfg(debug_assertions)]
        {
            fresh.unchecked_states = std::mem::take(&mut self.core.unchecked_states);
        }
        // and so is what the sync set's walk takes no path through: the fresh closure is built cut
        fresh.ix.closure.set_cut(None, self.core.ix.closure.cut().iter().copied().collect())?;
        self.core = fresh;
        let r = {
            let txn = self.store.transaction(&mut self.store_rng)?;
            let mut tx = Tx { txn, blobs: blobs::Cipher::new(&*self.blobs, &self.blob_stamps, self.blob_seq), core: &mut self.core, rng: &mut *self.rng, bound: None };
            crate::apply::load(&mut tx, rebuild)
        };
        crate::apply::load_waits(&mut self.core);
        #[cfg(debug_assertions)]
        self.core.rebuilt_perm.clear();
        self.core.commit_journal();
        r
    }

    /// An empty `Core` on `clock` with this one's identity, sessions and settings.
    fn blank_core(&self, clock: Arc<dyn Clock>) -> Core {
        let mut fresh = Core::new(self.core.id.clone(), clock.clone(), self.core.session, self.core.expiring, self.store.row_changes());
        fresh.later_sessions = self.core.later_sessions;
        fresh.hlc = Hlc::new(clock, self.core.hlc.last());
        fresh.commits_watched = self.core.commits_watched;
        fresh.refs_watched = self.core.refs_watched;
        fresh.commit_listeners = self.core.commit_listeners.clone();
        fresh.skip_writer_rules = self.core.skip_writer_rules;
        fresh.walk_cache_min = self.core.walk_cache_min;
        fresh.account.set(self.core.account.get());
        // caches keyed on it (the sync engine's sync IDs and co-readers) never see an old value again
        fresh.generation = self.core.generation.wrapping_add(1);
        #[cfg(test)]
        {
            fresh.check_ingest = self.core.check_ingest;
            fresh.whole_apply = self.core.whole_apply;
            fresh.faults = self.core.faults;
        }
        fresh
    }

    /// An open from the persisted index and a rebuild from the commit records each compute the
    /// indexes and role timelines this node holds (spec/permissions.md §5.1 step 5: validity is
    /// a function of the held set), the open decoding no header, reading no blob (what a held
    /// record needs is in the store, whatever blobs expiry or a drop took) and judging every
    /// part as held. Both load in a transaction that is dropped, so the store is as it was. Panics with the
    /// difference. Debug builds run it at the end of the engine's history (its drop), with the
    /// verdicts (`checked_verdicts`) and states (`checked_states`) left unchecked; tests call it
    /// where a reproducer's point is.
    #[doc(hidden)]
    pub fn check_index(&mut self) {
        let r = self.checked_index();
        assert!(r.is_ok(), "check_index: {:?}", r.err());
    }

    /// `check_index`, a store failure returned (every other failure panics).
    fn checked_index(&mut self) -> Result<()> {
        #[cfg(debug_assertions)]
        {
            self.checked_verdicts();
            self.checked_states()?;
            self.index_unchecked = false;
        }
        // key actors are derived: held exactly while `hold_key_actor` or a followed link names them
        let named: BTreeSet<Tid> = self.core.held_keys.keys().chain(self.core.followed_links.all().values().map(|(_, l)| l)).copied().collect();
        assert_eq!(self.core.key_actors.keys().copied().collect::<BTreeSet<_>>(), named, "key actors: held or named by a followed link");
        match self.checked_closure() {
            Err(e @ Error::Store(_)) => return Err(e),
            r => assert!(r.is_ok(), "node closure walked afresh: {:?}", r.err()),
        }
        // the index is as of the last transaction: a timer due since has not run
        #[cfg(debug_assertions)]
        let clock: Arc<dyn Clock> = Arc::new(osis_base::ManualClock::new(WallMs(self.last_tx_wall.unwrap_or(self.now().0))));
        #[cfg(not(debug_assertions))]
        let clock = self.clock.clone();
        for rebuild in [false, true] {
            let mut fresh = self.blank_core(clock.clone());
            // the store's records decoded as this node keeps them: a decode is a function of
            // the record's bytes, compared at each hit (`decoded`), so judging is all redone
            fresh.decoded = std::mem::take(&mut self.core.decoded);
            fresh.key_actors = self.core.key_actors.clone();
            fresh.accounts = self.core.accounts.clone();
            let mut rng = SeededRng::from_u64(0);
            let mut store_rng = SeededRng::from_u64(0);
            let load = || -> Result<Option<u64>> {
                let txn = self.store.transaction(&mut store_rng)?;
                let mut tx = Tx { txn, blobs: blobs::Cipher::new(&*self.blobs, &self.blob_stamps, 0), core: &mut fresh, rng: &mut rng, bound: None };
                // a transaction that left the index stale (`index::invalidate`: commit records
                // changed outside the in-memory indexes) is followed by a reload
                if !index::current(&mut tx)? {
                    return Ok(None);
                }
                crate::apply::load(&mut tx, rebuild)?;
                // the persisted edges rows are what the role commits' records read, one each
                #[cfg(debug_assertions)]
                if rebuild {
                    let mut rows = index::load_perm(&mut tx)?;
                    for (id, parts) in std::mem::take(&mut tx.core.rebuilt_perm) {
                        assert_eq!(rows.remove(&id), Some(parts), "node/perm row of {id:?} is stale");
                    }
                    assert!(rows.is_empty(), "node/perm rows without a role commit: {:?}", rows.keys().collect::<Vec<_>>());
                }
                Ok(Some(tx.blobs.reads))
            };
            // its work is not the measured code's (scale checks count work)
            let r = osis_base::costs::paused(|| osis_perm::uncounted(load));
            // what it decoded is the store's as well (the load's transaction is dropped: a
            // record it wrote moved its stamp, so nothing it kept matches)
            self.core.decoded = std::mem::take(&mut fresh.decoded);
            let at = if rebuild { "rebuilt from the commit records" } else { "opened from the persisted index" };
            if let Err(e @ Error::Store(_)) = r {
                return Err(e);
            }
            assert!(r.is_ok(), "{at}: {:?}", r.err());
            let Ok(Some(reads)) = r else { return Ok(()) };
            assert!(rebuild || reads == 0, "{at}: {reads} blob reads");
            // compared typed; the digests' text only for the message
            if !self.core.same_index(&fresh) {
                let d = self.core.index_digest().first_diff(&fresh.index_digest());
                assert!(d.is_none(), "{at} (want: this node's live index, got: its store loaded afresh), the {}", d.unwrap_or_default());
                assert_eq!(fresh.perm_digest(false), self.core.perm_digest(false), "{at}: role timelines");
            }
            if !rebuild {
                let decoded = fresh.ix.commits.values().filter(|m| !m.view.linked && m.header.is_decoded()).count();
                assert_eq!(decoded, 0, "{at}: headers decoded");
                assert_eq!(crate::apply::validity::misjudged(&fresh), None, "{at}: judged anew");
            }
        }
        Ok(())
    }

    /// Debug builds: the whole verdict checks, run at the end of the history (not per
    /// transaction: each costs O(everything held)) when a transaction ran since they last did.
    /// Every held commit's flags are what judging it now gives (`validity::misjudged`: what was
    /// not re-judged has not changed), and every re-grant bound a timeline memoizes is what a
    /// search at every change finds (`Timeline::check_first_held`; after the judging, which asks
    /// for most of them). Panics with the first difference.
    #[cfg(debug_assertions)]
    fn checked_verdicts(&mut self) {
        if !std::mem::take(&mut self.verdicts_unchecked) {
            return;
        }
        let core = &self.core;
        osis_base::costs::paused(|| {
            osis_perm::uncounted(|| {
                memo::unrecorded(|| {
                    let d = crate::apply::validity::misjudged(core);
                    assert!(d.is_none(), "end of history: {} changed outside the re-judged set", d.unwrap_or_default());
                    core.timelines.check_first_held();
                })
            })
        });
    }

    /// Debug builds: each aspect valid joins or covered drops changed since the rebuild check
    /// last read it (`Core::unchecked_states`) holds exactly the join of its held bodies
    /// (`apply::check_states`), read in a transaction dropped after. Panics with the difference; a failing read returned.
    #[cfg(debug_assertions)]
    fn checked_states(&mut self) -> Result<()> {
        let aspects = std::mem::take(&mut self.core.unchecked_states);
        if aspects.is_empty() {
            return Ok(());
        }
        osis_base::costs::paused(|| osis_perm::uncounted(|| memo::unrecorded(|| self.read(|tx| crate::apply::check_states(tx, aspects)))))
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
        } else {
            // the node closure walked afresh (`sync::units::settle`), and walks evaluated or
            // continued at open saved for the next
            self.run(|_| Ok(()))?;
        }
        self.start_detection();
        Ok(())
    }

    /// Dispute detection on, once the store is loaded (`crate::sides`): what arrives from here
    /// on may raise one.
    fn start_detection(&mut self) {
        self.core.detect = true;
        self.core.timelines.aside().detect(true);
    }
}

/// Debug builds: the end of the engine's history checks what its transactions left unchecked
/// (`check_index`, `checked_states`), unless a panic is already unwinding.
#[cfg(debug_assertions)]
impl Drop for Engine {
    fn drop(&mut self) {
        // nor on a half-loaded core, nor when a write's outcome is unknown (the next transaction
        // would load the store again)
        if std::thread::panicking() || self.loading || self.store.writes().unknown != self.failed_seen.1 {
            return;
        }
        // a by-hand replay inspecting a failing world (`OSIS_NO_END_CHECKS=1`)
        if !osis_base::testenv::end_checks() {
            return;
        }
        #[cfg(test)]
        if self.index_poked {
            return;
        }
        let r = if self.index_unchecked {
            self.checked_index()
        } else {
            self.checked_verdicts();
            self.checked_states()
        };
        // a store that fails (a crash test's) has nothing to check
        assert!(matches!(r, Ok(()) | Err(Error::Store(_))), "end of history: {:?}", r.err());
        if r.is_ok() {
            self.check_missed_wakes("end of history");
            let r = self.check_walks(true);
            assert!(matches!(r, Ok(()) | Err(Error::Store(_))), "blob waits at the end of history: {:?}", r.err());
        }
    }
}

#[cfg(debug_assertions)]
impl Engine {
    /// Debug builds: no addendum trigger missed (`flows::addenda::missed`), and no
    /// waiting split path a fresh attempt opens (`apply::paths::missed`), counting nothing.
    fn check_missed_wakes(&mut self, when: &str) {
        let m = osis_base::costs::paused(|| osis_perm::uncounted(|| memo::unrecorded(|| self.read(crate::flows::addenda::missed))));
        assert!(matches!(m, Ok(None) | Err(Error::Store(_))), "{when}: an addenda trigger missed: {m:?}");
        let p = osis_base::costs::paused(|| osis_perm::uncounted(|| memo::unrecorded(|| self.read(crate::apply::paths::missed))));
        assert!(matches!(p, Ok(None) | Err(Error::Store(_))), "{when}: a split path's wake missed: {p:?}");
    }
}

/// Whether an index derives from the state of aspect `ak` (`Tx::derive`): `sync.0`'s recorded
/// sync IDs, read from the whole state.
fn derives(ak: &Ak) -> bool {
    ak.as_str() == "sync.0"
}

#[cfg(test)]
mod tests {
    use super::journal::Journaled;
    use crate::local_peer::{LocalPeer, Peer};
    use crate::Mutation;
    use osis_base::{Ak, Role, Tid, Value, WallMs};
    use std::collections::BTreeSet;

    // spec/commits.md §5 (Dropping a body): what each part state answers. One state per part, so
    // no part is both held and dropped or missing, and only a held one is a whole replace.
    #[test]
    fn each_part_state_answers_alone() {
        use super::{Dropped, Hold, Missing};
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let a = lp.peers[0].engine.me();
        let mut m = Mutation::new();
        lp.peers[0].engine.new_thing(&mut m, a);
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let mut meta = lp.peers[0].engine.core.ix.commits[&id].clone();
        meta = super::Meta::of(meta.view.clone(), meta.header.clone(), meta.received, meta.origin, None, meta.signed(), vec![true], vec![Hold::Body { whole: true }]);
        // (holds, body gone, leftover, valued, bare, whole, dropped, missing)
        let answers = |m: &super::Meta| (m.holds(0), m.body_gone(0), m.stripped(0), m.valued(0), m.bare(0), m.whole(0), m.is_dropped(0), m.missing(0));
        let cases = [
            (Hold::Body { whole: true }, (true, false, false, false, false, true, false, false)),
            (Hold::Body { whole: false }, (true, false, false, false, false, false, false, false)),
            (Hold::Leftover { whole: true, valued: true }, (true, true, true, true, false, true, false, false)),
            (Hold::Leftover { whole: false, valued: false }, (true, true, true, false, true, false, false, false)),
            (Hold::Dropped(Dropped::default()), (false, true, false, false, false, false, true, false)),
            (Hold::Missing(Missing::ToFetch), (false, false, false, false, false, false, false, true)),
        ];
        for (h, want) in cases {
            meta.set_hold(0, h.clone());
            assert_eq!(answers(&meta), want, "{h:?}");
        }
        // marking a part not held a whole replace changes nothing
        meta.set_hold(0, Hold::Missing(Missing::Plain));
        meta.set_whole(0);
        assert_eq!(meta.hold_all()[0], Hold::Missing(Missing::Plain));
        // no such part: nothing held, nothing set
        meta.set_hold(1, Hold::Body { whole: true });
        assert!(meta.parts() == 1 && !meta.holds(1) && !meta.missing(1));
    }

    fn digest(p: &Peer) -> String {
        // headers decoded alike (decoding is a cache, not undone)
        p.engine.core.ix.commits.values().for_each(|m| drop(m.header.decoded()));
        format!("{}\n{}", p.engine.core.ix.contents(), p.engine.perm_digest(false))
    }

    /// Runs `f` with the store's next write failing and checks that every journaled index is as
    /// it was and equals a fresh open's (`check_index`; counting the failures in `failed`), then
    /// runs `f` again on the same engine: the store recovered in place.
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
                p.engine.check_index();
                f(&mut p.engine).unwrap()
            }
        }
    }

    use crate::rotation::tests::edge;

    fn write(m: &mut Mutation, t: Tid, v: &str) {
        m.set(t, &Ak::new("t:reg.0").unwrap(), &Value::Str(v.into())).unwrap();
    }

    // spec: none (engine internals). A read changes nothing (`Engine::read`): one that writes is
    // caught (debug builds) rather than undone at every call.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Engine::read changed")]
    fn a_read_that_writes_is_caught() {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let p = &mut lp.peers[0];
        let a = p.engine.me();
        let mut m = Mutation::new();
        let t = p.engine.new_thing(&mut m, a);
        p.engine.commit(m).unwrap();
        let _ = p.engine.read(|tx| {
            let mut m = Mutation::new();
            write(&mut m, t, "read");
            super::Engine::commit_tx(tx, m)
        });
    }

    // spec/commits.md §4 (applies in one storage transaction): a transaction whose store commit
    // fails leaves every journaled index (`Indexes`) and the timelines as they were, for local
    // commits and for received ones, applied or pending.
    #[test]
    fn failed_transaction_restores_indexes_spec_commits_4() {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a, b, c) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let mut failed = 0;
        let new_thing = |e: &mut super::Engine, admin: Tid| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, admin);
            write(&mut m, t, "new");
            e.commit(m).map(|_| t)
        };
        let g = failing(&mut lp.peers[0], &mut failed, |e| new_thing(e, a));
        lp.hold(g);
        failing(&mut lp.peers[0], &mut failed, |e| e.grant(&g, &b, &edge(Role::Write)));
        failing(&mut lp.peers[0], &mut failed, |e| e.grant(&g, &c, &edge(Role::Admin)));
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
        failing(&mut lp.peers[0], &mut failed, |e| e.demote(&g, &crate::flows::Demotion { holder: b, new: None, retain: None }));
        // received in reverse: most wait for what they depend on, then apply together
        // what g's sync ID carries
        let mut pks = lp.packages_of(0, &g).unwrap();
        pks.retain(|p| !lp.peers[2].engine.core.ix.commits.contains_key(&p.id));
        pks.reverse();
        for pk in &pks {
            failing(&mut lp.peers[2], &mut failed, |e| e.ingest(&pk.bytes, pk.blobs.clone()));
        }
        // what waited comes again, as node-sync fetches it
        for pk in pks.iter().rev() {
            failing(&mut lp.peers[2], &mut failed, |e| e.ingest(&pk.bytes, pk.blobs.clone()));
        }
        assert!(failed >= 6 + pks.len() / 2, "{failed} of {} failed", 6 + pks.len());
        lp.sync(0, 2).unwrap();
        // every commit on g applied (what waited came again, then as node-sync fetches what it
        // lacks); beside them only peer 2's own (its addendum to the removal)
        let own = [c, lp.peers[2].engine.tid()];
        let others = |p: &Peer| p.engine.core.ix.commits.iter().filter(|(_, m)| !own.contains(&m.view.signer) && m.view.aspects.iter().any(|a| a.tid == g)).map(|(id, _)| *id).collect::<BTreeSet<_>>();
        assert_eq!(others(&lp.peers[2]), others(&lp.peers[0]));
        assert!(lp.peers[2].engine.core.ix.pending.is_empty());
    }

    // spec/commits.md §4, §5: the same for compaction, purge-on-replace covers and expiry by `tick`,
    // a commit received a part at a time, and delete-key hints (a
    // failed promotion keeps its candidate).
    #[test]
    fn failed_transaction_restores_indexes_retention_spec_commits_4() {
        use osis_schema::{PurgeBy};
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a, b) = (lp.peers[0].engine.me(), lp.peers[1].engine.me());
        let (reg, kept) = (Ak::new("t:reg.0").unwrap(), Ak::new("t:kept.0").unwrap());
        let mut failed = 0;
        let g = failing(&mut lp.peers[0], &mut failed, |e| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a);
            write(&mut m, t, "new");
            // `kept` purged on replace
            m.set(t, &osis_schema::core_types::RETENTION, &osis_schema::core_types::RetentionSetting::of(kept.clone(), osis_schema::History::PurgeOnReplace)).unwrap();
            e.commit(m).map(|_| t)
        });
        lp.hold(g);
        let c = lp.peers[2].engine.me();
        failing(&mut lp.peers[0], &mut failed, |e| e.grant(&g, &b, &edge(Role::Write)));
        failing(&mut lp.peers[0], &mut failed, |e| e.grant(&g, &c, &edge(Role::Read)));
        lp.sync(0, 1).unwrap();
        lp.sync(0, 2).unwrap();
        lp.advance(10);
        // an older write by 1, delivered last
        let mut m = Mutation::new();
        m.set(g, &kept, &Value::Str("v".into())).unwrap();
        let v = lp.peers[1].commit(m).unwrap().unwrap();
        lp.advance(10);
        let keep0 = PurgeBy::Writer;
        let now = lp.peers[0].engine.now();
        let two = failing(&mut lp.peers[0], &mut failed, |e| {
            // two aspects: received a part at a time below; both expire (one expiry per commit)
            let mut m = Mutation::new();
            m.purge_by(g, &kept, keep0).unwrap();
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
        let vpk = lp.packages_for(1, 0).unwrap().into_iter().find(|p| p.id == v).unwrap();
        failing(&mut lp.peers[0], &mut failed, |e| e.ingest(&vpk.bytes, vpk.blobs.clone()));
        // peer 2: what g's sync ID carries, the two-aspect commit's parts one at a time
        let pks = lp.packages_of(0, &g).unwrap();
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

    // spec: none (the local schema of an app AK, notes/data-model.md AKs): the highest
    // version registered or written with types it, also after a restart; a stale registration
    // never downgrades it; an equal version registered again replaces it.
    #[test]
    fn local_schema_keeps_highest_version() {
        let parse = |rev: u64, ty: &str| std::sync::Arc::new(osis_schema::parse("t.osis", &format!("revision {rev};\naspect t:a.0: {ty};\n")).unwrap());
        let rev = |p: &Peer| p.engine.core.schemas.get("t:a.0").map(|s| (s.revision, s.aspects["t:a.0"].ty.clone()));
        let mut p = Peer::new(0, WallMs(1_700_000_000_000)).unwrap();
        let (v2, v1, v2b) = (parse(2, "int"), parse(1, "string"), parse(2, "bool"));
        p.engine.register_schema(v2.clone()).unwrap();
        p.engine.register_schema(v1).unwrap();
        assert_eq!(rev(&p), Some((2, v2.aspects["t:a.0"].ty.clone())), "a lower version never replaces");
        p.restart(0).unwrap();
        assert_eq!(rev(&p), Some((2, v2.aspects["t:a.0"].ty.clone())), "kept in the store");
        p.engine.register_schema(v2b.clone()).unwrap();
        p.restart(0).unwrap();
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
        p.restart(0).unwrap();
        assert_eq!(rev(&p).map(|r| r.0), Some(3), "registered again after a failed transaction");
    }
}
