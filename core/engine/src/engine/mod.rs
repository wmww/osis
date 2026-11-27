//! The engine: one node's local state over its `Store` (notes/architecture.md §2: the node
//! talks to `Store` only). Synchronous, no I/O of its own, time from a `Clock`, randomness
//! injected. Every mutating call runs in one store transaction; engine events are sent after
//! it is durable. A failed transaction undoes its changes to the in-memory indexes (`journal`)
//! and evicts the states it wrote.

pub(crate) mod acting;
pub use acting::MintAdmin;
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
mod tx;
mod testing;
#[cfg(debug_assertions)]
mod explain;
pub mod write;

#[doc(hidden)]
pub use testing::{CommitDigest, IndexDigest, IndexField};
#[doc(hidden)]
pub use secrets::HandSecrets;
#[cfg(debug_assertions)]
#[doc(hidden)]
pub use explain::Row;
pub use large::Trees;
pub use write::Mutation;
pub use tx::Tx;
pub(crate) use tx::{clear_table, scan_table};

use crate::apply::Reason;
use crate::error::{Error, Result};
use crate::events::{Event, Events};
use crate::identity::Identity;
use crate::sync::units::Written;
use clock::Hlc;
use osis_commit::{CommitBlob, Form, Header};
use osis_base::{Ak, BlobId, Clock, CommitId, SyncId, Tid, Ts, WallMs};
use osis_crdt::{Dot, Fragment, SourceKind};
use osis_crypto::{CryptoRngCore, SeededRng};
use osis_keys::ActorEpochs;
use journal::{JMap, JNested, JSet, JSetMap, Journaled};
use osis_perm::Point;
use osis_store::{Backend, RootStorage, Shred, Store, StoreConfig};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::mpsc::Receiver;

/// Engine configuration.
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub store: StoreConfig,
}


/// What a node holds of one part of an applied commit: one state, so no part is both dropped
/// and missing, or held as its leftover and dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hold {
    /// Its body. `whole`: a plain part whose delta replaces the aspect whole
    /// (`retention::snapshot::replaces`), what stands as an own replace (`Indexes::own_replaces`).
    Body { whole: bool },
    /// Its leftover: the body without the writes gone here (expired, purged: its own, or copies
    /// it carries; `retention::make_leftover`, `retention::strip_carried`), read from
    /// `records::LEFTOVER` as the body. Held for the engine, no body for node-sync
    /// (`Meta::body_gone`). `own_live`: none of its own writes gone (a snapshot, which has none,
    /// always while unexpired), held so only for the copies it lost; such a leftover is a body
    /// like a whole one for keep bounds, covering and a purge naming it. Else its own writes are
    /// gone and it is held for the copies it carries (`Meta::own_gone`; spec/commits.md §5
    /// Dropping a body). `whole` as for `Body`, judged on the leftover (which keeps every reset).
    Leftover { whole: bool, own_live: bool },
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
    /// Its thing was destroyed (`retention::destroy`): as `Other`, but an own-gone leftover goes too.
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
    pub peer_delete_from: u64,
    /// Its `rotation_role` and `overreach` notes when it dropped: judgments the body made,
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
    /// A part dropped as covered that its blobs drop too (spec/sync-judgement.md §2 Per blob,
    /// `sync::bodies::strips`): set, for good, by the purge-on-replace re-judge of its aspect
    /// (`retention::replace::settle_none`) once a held valid snapshot reaches it by its tables
    /// while a setting purges on replace, or by a purge request standing on it
    /// (`retention::purge::purge_one`), so a strip is an event of the transaction making it true.
    pub strips: bool,
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
    /// The keysets of holder actors it records its rotation left them out at, each with its
    /// causes' commits (spec/crypto.md §4, Left out).
    pub left_out: Vec<(Tid, osis_crypto::Epoch, Vec<CommitId>)>,
    /// The commits whose demotions it carries: those it lists, and its rotation commit where it
    /// `demotes` (the commit its write names, `KeysBody::of`).
    pub demotions: Vec<CommitId>,
    /// A sync keyset's claim epoch (spec/crypto.md §3).
    pub claim: Option<osis_crypto::Epoch>,
}

/// A valid keyset body noted (`Indexes::keysets`): the epochs the supersedes lists of the bodies
/// writing it name, joined, the key of its earliest body carrying a KEM key of suite 1 (the key
/// itself is read from that body when sealing to it, `apply::keys::keyset_kem`: an index row of
/// it would be its third copy; earliest, so two bodies naming different keys give every node
/// the same), the key of its
/// earliest body (the order rule reads it), the names digests they
/// publish, each with its body's author (what binds a history entry to a rotator,
/// spec/crypto.md §4: a forger's body binds entries to the forger), the left-out keysets they
/// record with their causes, joined (spec/crypto.md §4, Left out: read at the actor's current
/// epochs), and the demotions they carry, joined (Carried demotions: its rotation commit among
/// them where it demotes). Held only once those demotions are (`Core::keyset`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeldKeyset {
    pub lists: BTreeSet<osis_crypto::Epoch>,
    pub kem_in: Option<osis_perm::Point>,
    /// The key of its earliest valid body; `None` only before one is noted.
    pub since: Option<osis_perm::Point>,
    pub names: BTreeSet<(osis_keys::NamesDigest, Tid)>,
    pub left_out: BTreeMap<Tid, BTreeMap<osis_crypto::Epoch, BTreeSet<CommitId>>>,
    pub demotions: BTreeSet<CommitId>,
    /// A sync keyset's claim epoch (spec/crypto.md §3), as its earliest valid body names it
    /// (`since`): every node reads the same one.
    pub claim: Option<osis_crypto::Epoch>,
}

/// A box record a `keys.0` body writes with the keyset of its epoch (spec/crypto.md §4 Box
/// records): the actor's box of `role` at `epoch` to holder actor `holder` names `keysets` of it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SealedRec {
    pub role: osis_base::Role,
    pub epoch: osis_crypto::Epoch,
    pub holder: Tid,
    pub keysets: Vec<osis_crypto::Epoch>,
}

/// The box records of one epoch of an actor noted from its valid `keys.0` bodies
/// (`Indexes::sealed`): per holder actor the keysets they name, joined (what makes the epoch
/// foreign, spec/crypto.md §4 Foreign).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SealedAt {
    pub keysets: BTreeMap<Tid, BTreeSet<osis_crypto::Epoch>>,
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
            Hold::Leftover { whole, own_live: head.own_live.contains(&ai) }
        } else if missing {
            Hold::Missing(Missing::Plain)
        } else {
            Hold::Body { whole }
        }
    }
}

/// What a node decided of the path a split commit states for each thing it writes
/// (`apply::paths::decided`): the path opened, `None` where its entry opens to a bad list, absent
/// while it opens nowhere here.
pub type Decided = BTreeMap<Tid, Option<osis_commit::Path>>;

/// What the per-commit indexes (`apply::index_commit`, validity, the role filter) read of
/// a header (`View::of`), with what this node decided of a split commit's paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    pub ts: Ts,
    pub kind: osis_commit::Kind,
    pub form: Form,
    pub signer: Tid,
    /// The key it names as its signing key (`Header::key`, the second form); `None`: its
    /// signer's record's.
    pub key: Option<osis_base::SignKey>,
    /// Its one purge author (`Header::purge_author`), in the clear in either path form: a member
    /// of the path of every thing it writes.
    pub purge_author: Tid,
    /// In a split commit, what this node decided of each thing's path (`Decided`): a part on a
    /// thing whose path is not known is judged invalid. `None` where the path is in the clear.
    pub paths: Option<Arc<Decided>>,
    /// A memory commit (the ephemeral marker): held in memory, never durable to node-sync,
    /// receipts or demotion frontiers.
    pub memory: bool,
    pub aspects: Vec<AspectView>,
    /// A role commit's frontier (`validity::header_frontier`; perm's adaptation reads it
    /// for demotions); `None` on other kinds.
    pub frontier: Option<Arc<osis_perm::Frontier>>,
    /// It carries a request, a purge or a release (`Header::purge`; `retention::lasting`).
    pub purges: bool,
    /// The header's own-cover marker (spec/wire.md §4 field 17; `retention::others_own_cover`).
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
    pub fn of(h: &Header, paths: Option<Arc<Decided>>) -> View {
        // what `View::aspect` searches by (spec/wire.md §4)
        debug_assert!(h.aspects.is_sorted_by_key(|a| (a.tid, a.ak.as_str().len(), a.ak.as_str().as_bytes())), "aspects sorted");
        View {
            ts: h.ts,
            kind: h.kind,
            form: h.form,
            signer: h.signer,
            key: h.key,
            purge_author: h.purge_author(),
            paths,
            memory: h.ephemeral.is_some(),
            aspects: h.aspects.iter().map(|a| AspectView { tid: a.tid, ak: a.ak.clone(), lo: a.lo, hi: a.hi, replaces: a.replaces, original_floor: a.original_floor }).collect(),
            frontier: if h.kind == osis_commit::Kind::Role { crate::apply::validity::header_frontier(h) } else { None },
            purges: !h.purge.is_empty(),
            own_cover: h.own_cover,
        }
    }

    /// Its purge author where that is not its signer.
    pub fn other_purge_author(&self) -> Option<Tid> {
        Some(self.purge_author).filter(|x| *x != self.signer)
    }

    /// Whether the path it states for thing `t` is known here and not bad (`paths`).
    pub fn path_known(&self, t: &Tid) -> bool {
        self.paths.as_ref().is_none_or(|p| p.get(t).is_some_and(Option::is_some))
    }

    /// The index of aspect `(tid, ak)`'s part, the first of its pieces
    /// (`osis_commit::aspect_position`): for its header fields, which pieces share; what is held
    /// or valid of each piece is per piece (`aspect_parts`).
    pub fn aspect(&self, tid: &Tid, ak: &str) -> Option<usize> {
        osis_commit::aspect_position(&self.aspects, tid, ak, |a| (&a.tid, a.ak.as_str()))
    }

    /// The indexes of its parts on aspect `(tid, ak)`: one, or its pieces (spec/wire.md §4
    /// Pieces); empty where it writes none.
    pub fn aspect_parts(&self, tid: &Tid, ak: &str) -> std::ops::Range<usize> {
        osis_commit::aspect_range(&self.aspects, tid, ak, |a| (&a.tid, a.ak.as_str()))
    }

    /// The indexes of its aspects on `tid` (`osis_commit::aspects_on`).
    pub fn aspects_on(&self, tid: &Tid) -> std::ops::Range<usize> {
        osis_commit::aspects_on(&self.aspects, tid, |a| &a.tid)
    }
}

/// Answers of `Engine::memo`, kept per engine: one memo shared by several engines (a harness's,
/// over its nodes) never gives one engine's answer for another's, whose own stamps may stand.
pub struct Kept<K, V>(memo::Memo<(u64, K), V>);

impl<K: std::hash::Hash + Eq + Clone, V: Clone + PartialEq + std::fmt::Debug> Kept<K, V> {
    pub fn new(name: &'static str) -> Self {
        Kept(memo::Memo::new(name))
    }
}

/// A copy keeps the answers inside a world copy, as `Memo` does.
impl<K: std::hash::Hash + Eq + Clone, V: Clone> Clone for Kept<K, V> {
    fn clone(&self) -> Self {
        Kept(self.0.clone())
    }
}

/// `Engine::instance`: one sequence for the process.
static INSTANCES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The header whose canonical bytes are `bytes`, if they hash to `id` and decode.
pub(crate) fn decode_stored_header(id: &CommitId, bytes: &[u8]) -> Option<Header> {
    if osis_base::hash::hash(bytes) != id.0 {
        return None;
    }
    Header::decode_stored(bytes).ok()
}

/// The rebuild of one aspect `apply::run_batched` runs.
#[derive(Default, Clone, PartialEq)]
pub struct Batched {
    /// Asked in the memory class.
    pub memory: bool,
    /// Writes of forgotten memory commits to take off the gone list once rebuilt
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
    /// `missing`'s keys, thing first: whether a thing holds a missing part is read per thing
    /// (`Engine::unit_settled`).
    pub missing_things: JSetMap<Tid, Ak>,
    /// Held commits per aspect their header lists: (`ts`, commit), whatever the part's validity
    /// and whether its body is held. Invariant (also for `by_thing`): it finds
    /// commits, never decides anything alone, since any signer's header can list any aspect.
    /// What a thing has reads the state (`Tx::state`); what a commit counts for (a field's retention) reads its parts valid here
    /// (`Meta::valid_at`), body held or not.
    pub by_aspect: JSetMap<(Tid, Ak), (Ts, CommitId)>,
    /// `by_aspect`'s keys, aspect first: the things holding a commit on each aspect, read per
    /// aspect (the actors with a `secrets.0`, the link-seed things).
    pub aspect_things: JSetMap<Ak, Tid>,
    /// The places listing walks on a durable signal: every fire but the honored versions, valid
    /// or not (`edits`, persisted).
    pub originals: JSetMap<(Tid, Ak), (Ts, CommitId)>,
    /// A durable signal's valid parts claiming `replaces`, per (thing, aspect, named commit, actor):
    /// (`ts`, version). Forged claims are other actors' and are never read (`edits`).
    pub versions: JSetMap<(Tid, Ak, CommitId, Tid), (Ts, CommitId)>,
    /// Compaction snapshots held per aspect, with their frontiers and `Absorbed`: the bodies
    /// carrying a write besides its own (spec/commits.md §5).
    pub snapshots: JMap<(Tid, Ak), Vec<HeldSnapshot>>,
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
    /// `records::FORGOTTEN_NAMES`): what a purge names it by and judges it by.
    pub forgotten_names: JNested<(Tid, Ak), CommitId, crate::retention::names::Name>,
    /// Per (thing, aspect, author) the held parts of plain commits of a coverable aspect (`retention::snapshot::own_aspect`): what an own replace may cover, without
    /// walking the aspect (derived, as `Core::put_meta` keeps it).
    pub own_held: JSetMap<(Tid, Ak, Tid), (Ts, CommitId)>,
    /// `own_held`'s subset of whole replaces (spec/commits.md §5 Own replaces), any validity:
    /// the candidates that may cover an older commit of the author.
    pub own_replaces: JSetMap<(Tid, Ak, Tid), (Ts, CommitId)>,
    /// Held commits per thing they hold a delta of (re-judging a thing's deltas).
    pub by_thing: JSetMap<(Tid, Tid), CommitId>,
    /// Held split commits with a thing whose path opens nowhere here yet (`View::paths`), opened
    /// again as role inputs move (`apply::paths::refresh`).
    pub paths_unknown: JSet<CommitId>,
    /// Held commits carrying a purge request, per thing they have a delta on (a request has one
    /// on each thing it names, spec/commits.md §5): what finds a thing's requests
    /// (`retention::destroy`) without reading its other commits.
    pub purges_on: JSetMap<Tid, CommitId>,
    /// Held commits per (purge author, signer), where those differ: each such thing is needed
    /// while one is held (`retention::needed::Need::Acting`). Interim
    /// (issues/stated-path-certificates.md).
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
    /// Per held commit, the things on which a delta of it lists a level-1 or level-3 delete key
    /// no step places before it (`sync_ids::steps`, spec/crypto.md §7 Checked keys): its deltas
    /// on that thing are invalid, its edge writes there read by nothing. Persisted with the
    /// commit's parts row; judged again as the steps or records it reads move
    /// (`Core::rekey`).
    pub miskeyed: JSet<(CommitId, Tid)>,
    /// Role commits whose `miskeyed` things moved: their edge writes are read again
    /// (`validity::resolve_unresolved`). Empty between transactions.
    pub rekeyed: JSet<CommitId>,
    /// Things whose record chain became known: the keys every commit on them lists are judged
    /// at the next re-judge (`validity::rejudge_once`), with the walk whole.
    pub keys_due: JSet<Tid>,
    /// Commits holding a valid `grant@~0` fire or stranded notice (`inbox::carries`), applied or
    /// turned valid here, whose carried commit or report is not yet taken
    /// (`Engine::take_carried`). Empty between follows.
    pub fires_due: JSet<CommitId>,
    /// Things whose cards, or cards naming them their inbox, are due a look: a card written there,
    /// or their `keys.0` moved (`Engine::take_cards`). Empty between follows; every card held
    /// after an open.
    pub cards_due: JSet<Tid>,
    /// Things whose cards were taken since the last pass end: due a refresh then
    /// (`Engine::refresh_cards`). Every card held after an open.
    pub cards_stale: JSet<Tid>,
    /// Freed links judged freed, by (blob, thing) (`retention::freed`): what sync deletes.
    pub freed: JMap<(osis_base::BlobId, Tid), Arc<crate::retention::freed::Freed>>,
    /// The commit, parts and unopened sections each opened or sealed blob holds (`sync::bodies`).
    pub blob_parts: JMap<osis_base::BlobId, Arc<crate::sync::BlobOf>>,
    /// `blob_parts`' blobs per commit: they go with it (`sync::bodies::forget`).
    pub commit_blobs: JSetMap<CommitId, osis_base::BlobId>,
    /// The sync-only cuts taken here by blob (`sync_ids::unread`, rows `su/`): a row goes with its
    /// blob's last entry.
    pub sync_cuts: JMap<osis_base::BlobId, crate::sync_ids::unread::HeldCut>,
    /// `sync_cuts`' blobs per thing they came under: what a sync ID of it logs.
    pub sync_cuts_under: JSetMap<Tid, osis_base::BlobId>,
    /// `sync_cuts`' blobs per thing they cut: the holders a cut of it came under (`cut_holders`).
    pub sync_cuts_of: JSetMap<Tid, osis_base::BlobId>,
    /// Per thing, the sync IDs `sync_cuts` give it: sync IDs it is followed by.
    pub sync_cut_ids: JSetMap<Tid, SyncId>,
    /// `sync_cut_ids` the other way: per sync ID, the things cuts give it.
    pub sync_cut_things: JSetMap<SyncId, Tid>,
    /// Per thing, each holder whose entry gave this node a sync secret of it, with the sync ID
    /// (`sync_ids::unread`, rows `se/`): a sync-only cut of it under that holder.
    pub entry_syncs: JSetMap<Tid, (Tid, SyncId)>,
    /// The certificate blobs sealed here per sync ID, each with what it carries
    /// (`sync::certblobs`).
    pub cert_blobs: JMap<SyncId, Arc<crate::sync::CertBlobs>>,
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
    /// Deltas whose value-carrying writes are gone (expired, purged).
    pub gone: JMap<(Tid, Ak), Vec<Owned>>,
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
    /// Per thing, the sync ID its `keys.0` state names (field `sync_id`): an index derived from the
    /// state (`Tx::derive`), read by the owner rule (`Core::named_sync_id`).
    pub keys_sync_id: JMap<Tid, SyncId>,
    /// Per thing with a `sync.0` state, the steps it places (`sync_ids::steps`, `Tx::derive`):
    /// what delete keys are listed from and checked against (spec/crypto.md §7).
    pub steps: JMap<Tid, Arc<crate::sync_ids::steps::Recorded>>,
    /// Keyed edge entries seen: (target, edge aspect, entry dot) -> holder.
    pub holder_keys: JMap<(Tid, crate::apply::validity::Grants, Dot), osis_base::Holder>,
    /// Role commits whose removed keys are not known yet.
    pub unresolved: JSet<CommitId>,
    /// Roles `secrets.0` and `keys.0` deltas need (by commit and part index).
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
    /// Parts writing beyond what their commit alone allows them, judged from the part and its
    /// header: `secrets.0` and `keys.0` parts of role commits beyond their grantees' boxes (a
    /// may-grant grant may carry only those, spec/permissions.md §2), and card aspect parts writing
    /// a card off their stated path (invalid, spec/permissions.md §5.2).
    pub overreach: JSet<(CommitId, usize)>,
    /// Keyed boxes per holder: holder -> (actor, box key), from `secrets.0` entries seen.
    pub boxes_to: JSetMap<Tid, (Tid, osis_base::Value)>,
    /// Every held `addenda.0` delta (spec/permissions.md §5.2, Addenda), by (thing, commit):
    /// its author's write whether its body is held or not, with the entries its body says while
    /// held (`validity::note_addenda`, `validity::forget_addendum_body`).
    pub addenda: JMap<(Tid, CommitId), Arc<crate::apply::validity::Addendum>>,
    /// `addenda` by the removal an entry is keyed by: (thing, addendum commit).
    pub addenda_keyed: JSetMap<CommitId, (Tid, CommitId)>,
    /// Removals to gather again at the end of the transaction (`flows::addenda`): every held
    /// one at an open, then those whose gathering a walk change or late part may have moved.
    pub addenda_due: JSet<CommitId>,
    /// What each held removal's judgement gathered (`flows::addenda::Gathered`): gathered anew
    /// only when what it reads may have changed (`addenda_due`), read by its decide
    /// (`Core::addenda_owed`). Memory only.
    pub addenda_gathered: JMap<CommitId, Arc<crate::flows::addenda::Gathered>>,
    /// The removals judged by `flows::addenda`, by the edges their writes are on: (target,
    /// holder, the removal's `ts`, removal). A walk change naming such an edge at or before the
    /// removal, or a delta stated through it, makes it due again (`flows::addenda::wake`).
    pub addenda_wake: JSet<(Tid, osis_base::Holder, osis_base::Ts, CommitId)>,
    /// The earliest valid held commit writing an epoch's keyset in `keys.0` (its rotation):
    /// (actor, role, epoch) -> (`ts`, commit). Absent: unknown. What a box naming the keyset
    /// carries (spec/crypto.md §4, Carried) and a certificate of the actor's current keys.
    pub epoch_intro: EpochIntro,
    /// The held valid keysets (spec/crypto.md §4, held keyset): (actor, role, epoch) for each
    /// keyset a held valid `keys.0` body (a role commit's delta or a compaction snapshot; kept
    /// once dropped, `Dropped::keysets`) writes. `Core::keysets_of` reads one actor's.
    pub keysets: JMap<(Tid, osis_base::Role, osis_crypto::Epoch), HeldKeyset>,
    /// The keysets invalid `keys.0` bodies write (held, or their records once dropped,
    /// `Dropped::keysets`), each with those bodies' commits: (actor, role, epoch) -> commits. A
    /// keyset here and not in `keysets` is held invalid (spec/crypto.md §4, Held keyset).
    pub keysets_invalid: JMap<(Tid, osis_base::Role, osis_crypto::Epoch), BTreeSet<CommitId>>,
    /// The box records of each epoch (spec/crypto.md §4 Box records): (actor, role, epoch) for
    /// each epoch a held valid `keys.0` body (a role commit's delta or a compaction snapshot)
    /// records a box at beside that epoch's keyset.
    pub sealed: JMap<(Tid, osis_base::Role, osis_crypto::Epoch), SealedAt>,
    /// The boxes of each epoch to holder actors (spec/crypto.md §4 Stale): (actor, role, epoch)
    /// for each epoch a held valid `secrets.0` body (a role commit's piece or a compaction
    /// snapshot) puts a box at, per holder the keysets they name, whatever later bodies write
    /// at its key.
    pub boxed: JMap<(Tid, osis_base::Role, osis_crypto::Epoch), SealedAt>,
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
    /// The fires of `fires` by the thing each fires on (its inbox): what goes as that thing is
    /// forgotten whole (`flows::inbox::drop_fires_on`). Loaded with `fires`.
    pub fires_on: JSetMap<Tid, crate::flows::inbox::FireId>,
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
    /// One dependent thing given secrets of its own at a pass end (`Engine::pass_end`).
    OwnSecrets,
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

/// A point `Core::rollback_to` undoes back to: the journals' points, the lengths of the lists
/// that only grow within a transaction, and the work lists a step's start holds (a copy: they
/// are empty or small there).
pub(crate) struct CoreMark {
    ix: IndexesMark,
    sides: usize,
    schemas: usize,
    written: usize,
    events: usize,
    commits_named: usize,
    listed_before: usize,
    killed: usize,
    to_date: usize,
    dates_moved: usize,
    bodies_rewritten: usize,
    died: usize,
    /// `wrote_on`'s length: a write undone owes no holding.
    wrote_on: usize,
    stale: (BTreeSet<Tid>, BTreeSet<Tid>, BTreeSet<Tid>, BTreeSet<CommitId>, bool),
    batched: Option<BTreeMap<(Tid, Ak), Batched>>,
    /// `fallen`: a snapshot a rolled-back flip owed is owed no more.
    fallen: BTreeSet<(Tid, Ak)>,
    memory_tx: bool,
    dirty: bool,
    /// `store_rows`: a row written alone (a commit record, a leftover) changes no index.
    records: u64,
    /// `reach_log`'s length.
    reached: usize,
    /// `walks`' log length (`reach::rolled_back`).
    walked: usize,
}

/// A held compaction snapshot of an aspect: `ts`, ID, frontiers, `Absorbed` (commit, signer),
/// joined over its held parts (a `secrets.0` snapshot's pieces), and the bounds of what each
/// held part carries (`retention::snapshot::PartsCarried`).
pub(crate) type HeldSnapshot = (Ts, CommitId, osis_crdt::Frontiers, Vec<(CommitId, Tid)>, crate::retention::snapshot::PartsCarried);

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
    /// `Engine::sync_set` (`memo`): sync reads it every step.
    pub(crate) sync_set: memo::Memo<(), Arc<crate::sync::SyncSet>>,
    /// `Engine::dial_peers` per sync ID (`memo`): sync's dials read it at each move of what it read.
    pub(crate) dial_peers: memo::Memo<SyncId, Arc<Vec<osis_base::Address>>>,
    /// `Engine::step_needs` of every recorded step per sync ID (`memo`): sync asks a step's or a
    /// role commit's at each role entry it judges.
    pub(crate) steps_needs: memo::Memo<SyncId, Arc<crate::sync::signing::StepsNeeds>>,
    /// `Engine::proven` per (claims, copies) digest (`memo`): opens reads a connection's per sync
    /// ID at each step.
    pub(crate) proven: memo::Memo<[u8; 32], Arc<Vec<crate::sync::ProvenThing>>>,
    /// What each gathered removal owes at this node and may write now (`flows::addenda::Decides`),
    /// followed: settled at each transaction's end that moved what it read.
    pub(crate) addenda_owed: crate::flows::addenda::Decides,
    /// This node's role on a thing now (`Core::role_now`) per thing (`memo::Cutoff`), a row while
    /// a removal's decide reads it (`flows::addenda::Decides`): a role change on the thing that
    /// leaves this node's role as it was moves no reader.
    pub(crate) own_roles: memo::Cutoff<Tid, Option<osis_base::Role>>,
    /// The held split commits waiting for a path to open (`apply::paths::Wait`): built again
    /// from `Indexes::paths_unknown` where `None` (an open, a rollback).
    pub(crate) paths_wait: Option<crate::apply::paths::Wait>,
    /// `Engine::holders_named` per commit (`memo`): an admin's pass reads it for every inbox
    /// copy, and it decodes role parts.
    pub(crate) holders_named: memo::Memo<CommitId, Arc<BTreeMap<usize, BTreeSet<Tid>>>>,
    /// What a record's going brings per record (`Engine::record_certificates`): every
    /// certificate's records closure merges these, so a change derives the records it moved.
    pub(crate) record_certs: memo::Memo<Tid, Arc<crate::sync_ids::Certs>>,
    /// What each read thing's certificates name, per commit (`sync::certified`): `sync_bodies`
    /// reads one commit's row.
    pub(crate) certified: crate::sync::certified::Certified,
    /// The evidence derivation over the held set (`evidence::kept`), which `certified` reads.
    pub(crate) evidence: crate::evidence::kept::Kept,
    /// The records each read thing's sync IDs carry as certificates (`sync::certblobs`).
    pub(crate) cert_records: crate::sync::certblobs::CertRecords,
    /// `rotation::departures` per actor (`memo`).
    pub(crate) departures: memo::Memo<Tid, Vec<osis_keys::Departure>>,
    /// `rotation::blocked_roles_of` per (who, actor, walk) (`memo`).
    pub(crate) blocked_roles: memo::Memo<(Tid, Tid, crate::rotation::Walk), BTreeSet<osis_base::Role>>,
    /// `rotation::rotation_due` per (who, actor, mode, roles kept) (`memo`).
    pub(crate) rotations_due: memo::Memo<(Tid, Tid, crate::rotation::Due, BTreeSet<osis_base::Role>), BTreeSet<osis_base::Role>>,
    /// The holders lacking a box of each actor (`rotation::reseal_candidates`, `memo`): O(roster)
    /// a pass otherwise.
    pub(crate) reseal_scans: memo::Memo<Tid, Vec<(Tid, BTreeSet<osis_base::Role>)>>,
    /// The store's row change count (`Store::row_changes`): what `rollback_to` drops the caches
    /// over the store for.
    pub(crate) store_rows: memo::Changes,
    /// `Core::epochs` per thing (`memo`).
    pub(crate) epochs_of: memo::Memo<Tid, Option<Arc<osis_keys::ActorEpochs>>>,
    /// `Core::held_sync_keys` per thing (`memo`).
    pub(crate) held_sync_keys: memo::Memo<Tid, Arc<BTreeSet<[u8; 32]>>>,
    /// `Core::role_key_epochs` per thing (`memo`).
    pub(crate) role_key_epochs: memo::Memo<Tid, Arc<crate::sync_ids::RoleKeyEpochs>>,
    /// `Core::own_epochs` per thing (`memo`).
    pub(crate) own_epochs_of: memo::Memo<Tid, Option<Arc<osis_keys::ActorEpochs>>>,
    pub(crate) unread_of: memo::Memo<Tid, Arc<crate::sync_ids::unread::Unread>>,
    /// `Core::listed_keys` per base (`memo`).
    pub(crate) listed_keys: memo::Memo<Tid, Option<[Option<osis_crypto::VerifyingKey>; 2]>>,
    /// The pass place (`sync::held`): one strictly increasing count that both stamps a role
    /// commit's arrival from elsewhere and begins a complete pass, so the two never tie. Never
    /// rolled back; an open takes the highest place stored.
    pub place: u64,
    /// `Engine::wrap_blocked` per (actor, walk) (`memo::Cutoff`), refreshed by `Engine::follow`.
    pub(crate) wrap_blocks: memo::Cutoff<(Tid, crate::rotation::Walk), bool>,
    /// `Engine::read_facts` per (sync ID, commit) (`memo::Cutoff`), refreshed by
    /// `Engine::follow`: a body's judgement moves only when its facts do, not with every write on
    /// its aspects.
    pub(crate) read_facts: memo::Cutoff<(SyncId, crate::sync::BodyId), crate::sync::ReadFacts>,
    /// `Engine::sync_bodies` per commit (`memo::Cutoff`), refreshed by `Engine::follow`: each
    /// reader of a commit's bodies (sync read's, `read_facts`) reads one row, not the ~13 reads
    /// of a derivation.
    pub(crate) sync_bodies: memo::Cutoff<CommitId, Arc<crate::sync::Bodies>>,
    /// `Engine::sync_body` per (commit, sync ID, thing) (`memo::Cutoff`), each of `sync_bodies`'
    /// row, refreshed by `Engine::follow`: a body's reader moves only when that body does, not
    /// when the commit comes to have a body under another sync ID (an account's certificates,
    /// copied under each sync ID).
    pub(crate) sync_body_rows: memo::Cutoff<(CommitId, SyncId, Option<Tid>), Option<crate::sync::BodyMeta>>,
    /// The per-thing facts every commit's bodies and their facts read (`memo::Cutoff`, refreshed
    /// first by `Engine::follow_thing_rows`): how a thing syncs (`Engine::thing_sync`, the one
    /// copy of it), its secret actor (`secret_actor_row`), whether an actor's keys open it
    /// (`opens_row`) and an actor's read floor (`read_floor_row`). Each body reads one row per
    /// thing, not the derivation's reads copied into every commit's.
    pub(crate) thing_syncs: memo::Cutoff<Tid, crate::sync::ThingSync>,
    pub(crate) secret_actors: memo::Cutoff<Tid, Option<Tid>>,
    pub(crate) keys_opens: memo::Cutoff<(Tid, Tid), bool>,
    pub(crate) read_floors: memo::Cutoff<Tid, Option<crate::rotation::floors::ReadFloor>>,
    /// `Engine::held_fate` per commit (`memo::Cutoff`), refreshed by `Engine::follow`.
    pub(crate) held_fates: memo::Cutoff<CommitId, Option<crate::sync::HeldFate>>,
    /// Page indexes of the cached states kept paged in the store.
    pub pages: HashMap<(Tid, Ak), pages::StatePages>,
    timelines: held::Timelines,
    /// The sides taken in admin disputes (`crate::sides`), the walk's trust set; `detect`:
    /// dispute detection is on (after open: a held set loaded again has no arrivals).
    pub sides: crate::sides::Sides,
    pub detect: bool,
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
    /// What the purge requests whose right moved name (`osis_perm::paths::Changed::purges`),
    /// until `rejudge_all` judges the purges they cover again.
    pub purges_moved: BTreeSet<osis_perm::paths::Scope>,
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
    /// Dated aspects whose every part's replaced-at the running transaction may have moved
    /// (`retention::leaving::ToDate`).
    pub(crate) to_date: crate::retention::leaving::ToDate,
    /// The bodies whose replaced-at the running transaction's changes of the held writes may
    /// have moved (`retention::bounds::settle_index`), for `date_due` to row.
    pub(crate) dates_moved: Vec<(Tid, Ak, CommitId)>,
    /// The parts whose leftover the running transaction wrote or removed (`leftover::put`): a
    /// body whose bytes may have changed under an unchanged form, joined again in its aspect's
    /// held writes (`retention::bounds::settle_index`).
    pub(crate) bodies_rewritten: Vec<(Tid, Ak, CommitId)>,
    /// Per aspect, how far the running transaction's changes are in its held writes
    /// (`retention::bounds::settle_index`): the lengths of the commits log and of
    /// `bodies_rewritten` then. Emptied by a rollback (every change is looked at again).
    pub(crate) index_settled: BTreeMap<(Tid, Ak), (usize, usize, usize, usize)>,
    /// The dated aspects on which a join of the running transaction superseded a write
    /// (`retention::mark_killed`): an aspect keeps held writes from its first death
    /// (`retention::bounds::settle_index`).
    pub(crate) died: Vec<(Tid, Ak)>,
    /// How many settles of held writes revived a write (`osis_crdt::Held::take_revived`), ever:
    /// a caller compares it before and after a change (an expiry stripping the state in place).
    pub(crate) revivals: u64,
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
    /// Debug builds: the aspects whose history rows a transaction wrote or should have written
    /// since the row check last read them (`retention::leaving::rows_exact`), checked at the end
    /// of the engine's history. A copy starts empty, as for `unchecked_states`.
    #[cfg(debug_assertions)]
    pub(crate) unchecked_rows: BTreeSet<(Tid, Ak)>,
    /// Debug builds: what a load from the commit records read of each role commit's edge writes
    /// (`apply::load`), for `Engine::check_index` to compare with the persisted rows.
    #[cfg(debug_assertions)]
    pub(crate) rebuilt_perm: BTreeMap<CommitId, crate::apply::validity::PermParts>,
    /// Each commit built past the writer's rules, as sent, by ID (`Engine::take_forged`): one
    /// transaction may build more than the commit asked for (a writer's compaction after it).
    pub(crate) forged: BTreeMap<CommitId, Vec<u8>>,
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
    /// Tests (osis-sync's too): applying this received commit faults every time, once it ran in
    /// full (`apply::ingest_blob`). Not carried over a reload.
    #[doc(hidden)]
    pub apply_fault: Option<CommitId>,
    /// Tests: a transaction doing this work (`EndFault`) faults at its end, every time, outside
    /// any step (as end work or a round's shared part erring would). Not carried over a reload.
    #[cfg(test)]
    pub(crate) end_fault: Option<EndFault>,
    /// Tests: this transaction did `end_fault`'s work (set where it does, read at its end).
    #[cfg(test)]
    pub(crate) end_fault_due: bool,
    /// The tick's units of work set aside for a fault (`Engine::take_units`): not run again
    /// until the next open, which starts it empty.
    pub(crate) ticks_aside: BTreeSet<crate::retention::TickUnit>,
    /// The running transaction takes one unit alone (`Engine::split_units`; an arrival tried
    /// again after a fault): the commits a thing entering the node closure wakes are left to
    /// the next round (`apply::wake_entered`), so a fault of theirs is theirs alone.
    pub(crate) alone: bool,
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
    /// Tests: boxes this node's next grant writes beside its grantee's (`flows::edges`): a
    /// hostile granter's junk.
    #[cfg(test)]
    pub(crate) junk_boxes: Option<osis_keys::SecretsWrite>,
    /// Tests: this node's `secrets.0` snapshots are written whole, not in pieces: a hostile
    /// writer's (`retention::snapshot::secrets_pieces`).
    #[cfg(test)]
    pub(crate) whole_secrets_snapshots: bool,
    /// Link keys whose seed this node holds for now: they sign commits (`Mutation::sign_as`) and
    /// open their boxes by their seed's secrets. Derived: each is held exactly while
    /// `held_link_keys` or a followed link names it (`Engine::settle_link_key`). In memory only.
    pub link_keys: memo::Stamped<Tid, Arc<Identity>>,
    /// Per sync ID, the path a Head answer gave (spec/sync-ids.md §6 Head: verified from genesis by
    /// sync, the answerer's word on its own head): the steps claims are computed at and entries
    /// found by where this node records no path of its own. In memory only.
    pub(crate) heard: memo::Stamped<SyncId, Arc<Vec<osis_blob::Step>>>,
    /// Link keys held by `Engine::hold_link_key` until `drop_link_key` (making a link, a redeem,
    /// bearer use).
    pub(crate) held_link_keys: BTreeMap<Tid, Arc<Identity>>,
    /// Links this node redeems (`Engine::follow_link`): K to its sync ID from the link text and
    /// the link key L, held in `link_keys`. K's sync ID is in the sync set while followed
    /// (spec/sync-set.md §2). In memory only: sync holds the link durably and follows it again
    /// at a start.
    pub(crate) followed_links: crate::sync_ids::actors::FollowedLinks,
    /// The wall clock as memos read it (`memo::Clock`, wall ms): set at each transaction and by
    /// node-sync before it asks its memos; a memo reads it whole (`get`) or up to the next time
    /// that moves its answer (`until`).
    pub time: memo::Clock,
    /// No purge-on-replace cover or drop (tests: an oracle holding every body, `Engine::keep_bodies`).
    pub keep_bodies: bool,
    /// The list bound, `MAX_LIST_BYTES` (tests: `Engine::list_bound`): what `receipt::fit` fits a
    /// frontier to and each listing is cut to; a thing list, written inline only, fits the smaller
    /// of it and `CHUNK_THRESHOLD`.
    pub list_bound: usize,
    /// Gone lists changed in this transaction, written at its end (`retention::persist_gone`).
    pub gone_dirty: BTreeSet<(Tid, Ak)>,
    /// Things judged at the end of the transaction for whether a held thing still needs them
    /// (`retention::needed`): a release, `pass_due` at a pass end.
    pub needs_due: BTreeSet<Tid>,
    /// A sealed fire is being opened or taken for what it carries (`Engine::bringing`): what
    /// arrives is the fire's, brought by no pass (`note_pass_due`).
    pub fire_brings: bool,
    /// Things judged once the pass in flight ends (`Engine::settle_needs`, `retention::needed`):
    /// one arrived (a record learned or awaited). `None` after an open: every held record and
    /// awaited record is judged then.
    pub pass_due: Option<BTreeSet<Tid>>,
    /// Things that lost a need (a reference to it gone, a commit it signed left pending,
    /// a holder unnamed): judged once the pass in flight ends,
    /// or at once with none in flight (`Engine::settle_lost`).
    pub lost_due: BTreeSet<Tid>,
    /// Things a minting of arrived while the node held none since the pass in flight began
    /// (`Core::note_brought`), nothing of them forgotten since: a strong newly reaching one pulls
    /// nothing anew (`sync::units::refetch`). Emptied at a pass end (`Engine::settle_needs`); a
    /// thing goes from it once anything of it is forgotten sooner (`retention::forget`: a
    /// release, lost access; `apply::unindex_unreceived`: a commit forgotten whole, its parts
    /// waiting on other things with it; `apply::unreceive_outside`; `apply::carriers::forget`: a
    /// waiting part's last carrier gone). In memory only: an open starts it empty, so a strong then pulls
    /// anew.
    pub brought: BTreeSet<Tid>,
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
    /// What a waiting snapshot part carries, per (commit, part index), as a held snapshot's
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
    /// `Engine::piece_below` per piece link (`memo`): a node's links, decoded once while held.
    pub(crate) pieces_below: memo::Memo<crate::sync::PieceLink, Option<Arc<Vec<crate::sync::PieceLink>>>>,
    /// `Engine::piece_roots` per (commit, parts) (`memo`): a body's links, decoded once while held.
    pub(crate) piece_roots: memo::Memo<(CommitId, crate::sync::PartSet), Arc<Vec<crate::sync::PieceLink>>>,
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
    /// The things the running transaction's own commits made or wrote, each held at its end as
    /// it says (spec/sync-set.md §2 Writing, Making a thing).
    pub(crate) wrote_on: Vec<Written>,
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
        #[cfg(debug_assertions)]
        c.unchecked_rows.clear();
        c
    }
}


/// What a test peer's fetch stand-in reads to fetch again what the engine kept nothing of
/// (`local_peer::Peer::receive`).
#[derive(Clone, Debug, Default)]
pub struct Wakes {
    /// Commits whose boxes the reading-only budget now has room for.
    pub reread: BTreeSet<CommitId>,
    /// Every awaiting entry is fetched again (a link key taken up: boxes may open to it).
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
        // the removals whose gathering it may move are due again for addenda; an edge write that
        // is new or whose status moved is judged again with its commit's other parts: a
        // may-grant grant's boxes rest on how it applies (`validity::Judge::by_path`)
        crate::flows::addenda::note_changed(self, &c);
        let commits: BTreeSet<CommitId> = c.ops.iter().map(|w| w.0).collect();
        self.stale_commits.extend(commits);
        // the deltas the walk's change reaches (`osis_perm::paths::Changed`)
        self.stale_commits.extend(c.reached.iter().map(|w| w.0));
        let below = self.ix.held.below(&c.created);
        // a key on a thing whose record chain was not known is checked once it is
        // (`Indexes::keys_due`)
        if !c.created.is_empty() {
            for t in &below {
                self.ix.keys_due.insert(*t);
            }
        }
        self.stale_things.extend(below);
        let holders: BTreeSet<Tid> = c.edges().map(|p| p.0).chain(c.created.iter().copied()).collect();
        let targets: BTreeSet<Tid> = c.edges().map(|p| p.1).chain(c.created.iter().copied()).collect();
        let moved = self.ix.held.upstream(&holders);
        let under = self.ix.held.reach(&targets);
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
        // what rests on a thing's roles besides validity (`rejudge_once` reads it for purges)
        self.stale_authors.extend(moved);
        self.stale_under.extend(under);
        // purge requests whose right moved: the deltas each names (`retention::rejudge_purges`)
        self.purges_moved.extend(c.walk.purges.iter().cloned());
    }

    /// The commits of `index` (by (thing, author)) on `under` by `authors`: O(the things and their
    /// authors), not their product.
    fn by_authors<'a>(index: &'a JSetMap<(Tid, Tid), CommitId>, under: &'a BTreeSet<Tid>, authors: &'a BTreeSet<Tid>) -> impl Iterator<Item = CommitId> + 'a {
        under.iter().flat_map(move |t| run_of(index, *t).filter(|(a, _)| authors.contains(a)).flat_map(|(_, s)| s.iter().copied()))
    }

    /// The commits on `under` by `authors` (`rejudge_once`), and those acting for one of `under`.
    pub(crate) fn authored_under<'a>(&'a self, under: &'a BTreeSet<Tid>, authors: &'a BTreeSet<Tid>) -> impl Iterator<Item = CommitId> + 'a {
        Self::by_authors(&self.ix.by_thing, under, authors)
    }

    /// The held commits acting for `actor` by another author (a range of `by_actor`).
    pub fn acting_for(&self, actor: &Tid) -> impl Iterator<Item = CommitId> + '_ {
        run_of(&self.ix.by_actor, *actor).flat_map(|(_, s)| s.iter().copied())
    }

    /// The held valid keysets of actor `m`: (role, epoch, what is held of it) (`keyset`).
    pub(crate) fn keysets_of(&self, m: &Tid) -> impl Iterator<Item = (osis_base::Role, osis_crypto::Epoch, &HeldKeyset)> {
        self.keysets_noted(m).filter(|(_, _, v)| self.carried_held(v))
    }

    /// Every keyset of actor `m` a valid body of which is noted (`Indexes::keysets`), held or not.
    pub(crate) fn keysets_noted(&self, m: &Tid) -> impl Iterator<Item = (osis_base::Role, osis_crypto::Epoch, &HeldKeyset)> {
        self.ix.keysets.run(actor_run(m), (*m, osis_base::Role::Sync, osis_crypto::Epoch::ZERO)..).take_while(move |(k, _)| k.0 == *m).map(|(k, v)| (k.1, k.2, v))
    }

    /// Every keyset of actor `m` an invalid `keys.0` body writes (`Indexes::keysets_invalid`).
    pub(crate) fn keysets_invalid_noted(&self, m: &Tid) -> impl Iterator<Item = (osis_base::Role, osis_crypto::Epoch, &BTreeSet<CommitId>)> {
        self.ix.keysets_invalid.run(actor_run(m), (*m, osis_base::Role::Sync, osis_crypto::Epoch::ZERO)..).take_while(move |(k, _)| k.0 == *m).map(|(k, v)| (k.1, k.2, v))
    }

    /// Whether keyset `e` of role `r` of `m` is held invalid (spec/crypto.md §4, Held keyset): an
    /// invalid body writes it and no valid one does.
    pub(crate) fn keyset_invalid(&self, m: &Tid, r: osis_base::Role, e: &osis_crypto::Epoch) -> bool {
        let k = (*m, r, *e);
        !self.ix.keysets.contains_key(&k) && self.ix.keysets_invalid.contains_key(&k)
    }

    /// Every epoch of actor `a` a valid `keys.0` body records a box at (`Indexes::sealed`).
    pub(crate) fn sealed_noted(&self, a: &Tid) -> impl Iterator<Item = (osis_base::Role, osis_crypto::Epoch, &SealedAt)> {
        self.ix.sealed.run(actor_run(a), (*a, osis_base::Role::Sync, osis_crypto::Epoch::ZERO)..).take_while(move |(k, _)| k.0 == *a).map(|(k, v)| (k.1, k.2, v))
    }

    /// Every epoch of actor `a` a valid `secrets.0` body puts a box at (`Indexes::boxed`).
    pub(crate) fn boxed_noted(&self, a: &Tid) -> impl Iterator<Item = (osis_base::Role, osis_crypto::Epoch, &SealedAt)> {
        self.ix.boxed.run(actor_run(a), (*a, osis_base::Role::Sync, osis_crypto::Epoch::ZERO)..).take_while(move |(k, _)| k.0 == *a).map(|(k, v)| (k.1, k.2, v))
    }

    /// Held valid keyset `e` of role `r` of actor `m` (spec/crypto.md §4, Held keyset): a valid
    /// body of it noted (`Indexes::keysets`), and the demotions it carries held here (Carried
    /// demotions; not the left-out causes it records, which count unheld): until then it counts
    /// as not arrived, so nothing seals to it, finds a box stale by it, or descends through it.
    pub(crate) fn keyset(&self, m: &Tid, r: osis_base::Role, e: &osis_crypto::Epoch) -> Option<&HeldKeyset> {
        let k = (*m, r, *e);
        self.ix.keysets.get(&k).filter(|v| self.carried_held(v))
    }

    /// Whether this node holds the demotions keyset `v` carries: the edge writes of each commit
    /// it carries (`HeldKeyset::demotions`).
    fn carried_held(&self, v: &HeldKeyset) -> bool {
        v.demotions.iter().all(|c| self.ix.held.edge_commit(c).is_some())
    }

    /// Whether this node holds left-out cause `c` (spec/crypto.md §4, Left out; Carried): its
    /// edge writes (a departure's or a grant's), or a `keys.0` part of it (a rotation commit's).
    pub(crate) fn cause_held(&self, c: &CommitId) -> bool {
        self.ix.held.edge_commit(c).is_some() || self.ix.commits.get(c).is_some_and(|m| m.view.aspects.iter().enumerate().any(|(ai, a)| a.ak.as_str() == "keys.0" && (m.holds(ai) || m.is_dropped(ai))))
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
            let up = self.timelines().roles_on(&t, at, &BTreeSet::new());
            for x in std::iter::once(t).chain(up.keys().copied()) {
                if !seen.insert(x) {
                    continue;
                }
                let Some(on) = self.timelines().on(&x) else { continue };
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

    /// Whether `t` takes writes here: it exists and a minting of it is held. A node that learned
    /// a thing's record raw (a record blob) cannot tell it was destroyed, and a write there would
    /// be one every node that saw the destruction ignores.
    pub fn writable(&self, t: &Tid) -> bool {
        self.exists(t) && self.mintings(t).next().is_some()
    }

    /// A minting of `t` arriving, not indexed yet: where the node holds none, nothing of `t` was
    /// forgotten (content on a thing counts as never received only while a minting of it is
    /// held, and forgetting keeps that commit known while a part of it may still bring the thing
    /// in), nor is before the pass in flight ends (content waiting on it counts as never received
    /// once that pass ends, spec/commits.md §4 Outside the node closure) unless it is forgotten
    /// sooner (a release, lost access), so `t` is `brought` until then (spec/sync-judgement.md §3
    /// Dropped bodies). Not judged on the arriving commit: a minting needs no authority, and any
    /// writer may mint a held thing again; one held already brings nothing.
    pub(crate) fn note_brought(&mut self, t: Tid) {
        if self.mintings(&t).next().is_none() {
            self.brought.insert(t);
        }
    }

    /// The held mintings of `t`: its `created.0` deltas, each `(commit, delta index)`.
    pub(crate) fn mintings<'s>(&'s self, t: &Tid) -> impl Iterator<Item = (CommitId, usize)> + 's {
        let ak = Ak::new(osis_commit::retention::CREATED).ok();
        let held = ak.as_ref().and_then(|ak| self.ix.by_aspect.get(&(*t, ak.clone())));
        let t = *t;
        held.into_iter().flatten().filter_map(move |(_, c)| Some((*c, self.ix.commits.get(c)?.aspect(&t, ak.as_ref()?)?)))
    }

    /// Whether `t` is destroyed: a minting of it was held (`mintings`), and each is gone
    /// or dropped by a purge or the destruction (`retention::destroy`). One missing may yet come. A thing never held is unknown, not destroyed.
    pub fn destroyed(&self, t: &Tid) -> bool {
        let mut any = false;
        self.mintings(t).all(|(c, ai)| {
            any = true;
            self.minting_gone(&c, ai)
        }) && any
    }

    /// Whether minting `ai` of `c` is gone or dropped by a purge or the destruction.
    pub(crate) fn minting_gone(&self, c: &CommitId, ai: usize) -> bool {
        let Some(m) = self.ix.commits.get(c) else { return false };
        crate::retention::is_gone(self, c, ai) || m.dropped(ai).is_some_and(|d| matches!(d.why, DropFor::Other | DropFor::Destroyed))
    }

    /// The walk over the held set (`held::Timelines`), the one way to read it. Every change of
    /// the held set is given to it before the change returns (`update_timelines`; a batch
    /// operation gives its changes at its end and reads no walk before): no read sees it behind.
    pub fn timelines(&self) -> &held::Timelines {
        debug_assert!(!self.ix.held.is_touched(), "the walk read behind the held set");
        &self.timelines
    }

    /// The first of `ids` the walk reads behind the index (`held::Timelines::behind`), uncounted.
    #[cfg(debug_assertions)]
    pub(crate) fn walk_behind<'a>(&self, ids: impl Iterator<Item = &'a CommitId>) -> Option<CommitId> {
        osis_base::costs::paused(|| osis_perm::uncounted(|| memo::unrecorded(|| self.timelines.behind(self, ids))))
    }

    /// The walk to change in place (`sides`), brought up to the held set first.
    pub(crate) fn timelines_mut(&mut self) -> &mut held::Timelines {
        self.update_timelines();
        &mut self.timelines
    }

    /// Gives the walk the held set's changes since it last took them: what moved, or `None`
    /// when nothing was touched.
    fn walk_held(&mut self) -> Option<osis_perm::Changed> {
        if !self.ix.held.is_touched() {
            return None;
        }
        let touched = self.ix.held.take_touched();
        let mut commits = self.ix.held.take_touched_commits();
        // a record that came or went moves whether the things below it have a held chain, an
        // input of the reading of every commit on them (`validity::too_deep`)
        let moved = self.timelines.records_moved(&self.ix.held, &touched);
        if !moved.is_empty() {
            for t in self.ix.held.below(&moved) {
                commits.extend(self.on_thing(&t));
            }
        }
        let mut tl = std::mem::take(&mut self.timelines);
        let changed = tl.update(&*self, &commits, &touched);
        self.timelines = tl;
        Some(changed)
    }

    /// Brings the walk up to the held set; what moved in it waits for `rejudge_all`.
    pub fn update_timelines(&mut self) {
        let _s = osis_base::costs::span("timelines");
        if let Some(changed) = self.walk_held() {
            let detect = self.detect.then(|| changed.clone());
            self.timelines_changed(changed);
            if let Some(c) = detect {
                crate::sides::after_update(self, &c);
            }
        }
    }

    /// Whether some validity waits for `rejudge_all`.
    pub fn stale(&self) -> bool {
        self.stale_all || !self.stale_things.is_empty() || !self.stale_commits.is_empty() || !self.stale_authors.is_empty() || !self.ix.keys_due.is_empty()
    }

    /// Notes that the running transaction writes the state of `k` (evicted on rollback).
    pub fn wrote(&mut self, k: (Tid, Ak)) {
        self.written.push(k);
    }

    /// Notes that the running transaction changes the indexes or a state (drops derived caches).
    pub fn touch(&mut self) {
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
    /// (`Tx::step`). The walk holds every held change made so far (`timelines`), so what is stale
    /// by it is in the mark: a rollback's update of the walk then only undoes (it reads again
    /// what was touched since, as the restored index has it), and what it reports is nothing a
    /// flag restored with the index rests on.
    pub(crate) fn mark(&mut self) -> CoreMark {
        debug_assert!(!self.ix.held.is_touched(), "a mark with the walk behind the held set");
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
            dates_moved: self.dates_moved.len(),
            bodies_rewritten: self.bodies_rewritten.len(),
            died: self.died.len(),
            wrote_on: self.wrote_on.len(),
            stale: (self.stale_things.clone(), self.stale_authors.clone(), self.stale_under.clone(), self.stale_commits.clone(), self.stale_all),
            batched: self.batched.clone(),
            fallen: self.fallen.clone(),
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
            ("sides", self.sides.journaled() > m.sides),
            ("schemas", self.schemas.mark() != m.schemas),
            ("written", self.written.len() != m.written),
            ("events", self.events.queued() != m.events),
            ("commits_named", self.commits_named.len() != m.commits_named),
            ("listed_before", self.listed_before.len() != m.listed_before),
            ("killed", self.killed.len() != m.killed),
            ("to_date", self.to_date.len() != m.to_date),
            ("dates_moved", self.dates_moved.len() != m.dates_moved),
            ("bodies_rewritten", self.bodies_rewritten.len() != m.bodies_rewritten),
            ("died", self.died.len() != m.died),
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
        let sides_back = self.sides.journaled() > m.sides;
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
        // the timelines follow the restored held set: back to what they were at the mark, which
        // took every change before it (`mark`); validity flags are restored with `commits`. The
        // walk's undo of the transaction's moves (its stamps are undoable)
        memo::undoing(|| {
            self.walk_held();
            if sides_back {
                crate::sides::restored(self);
            }
        });
        (self.stale_things, self.stale_authors, self.stale_under, self.stale_commits, self.stale_all) = m.stale;
        self.events.truncate(m.events);
        self.commits_named.truncate(m.commits_named);
        self.listed_before.truncate(m.listed_before);
        self.killed.truncate(m.killed);
        self.to_date.truncate(m.to_date);
        self.dates_moved.truncate(m.dates_moved);
        self.bodies_rewritten.truncate(m.bodies_rewritten);
        self.died.truncate(m.died);
        self.index_settled.clear();
        self.wrote_on.truncate(m.wrote_on);
        self.batched = m.batched;
        self.fallen = m.fallen;
        self.memory_tx = m.memory_tx;
    }

    /// What `rollback_to` does with each field: fails to compile when a field is added, so every
    /// new one is classified. A cache filled from a restored field goes in the dropped class.
    /// Returns the fields set outside transactions, which every transaction leaves as they were
    /// (debug builds compare them around each: one a transaction writes belongs in another class).
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    fn rollback_classes(c: &Core) -> String {
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
            dates_moved: _,
            bodies_rewritten: _,
            index_settled: _,
            died: _,
            revivals: _,
            wrote_on: _,
            written: _,
            stale_things: _,
            stale_authors: _,
            stale_under: _,
            purges_moved: _,
            stale_commits: _,
            stale_all: _,
            batched: _,
            fallen: _,
            memory_tx: _,
            dirty: _,
            // a call's parameter (`memory_room`) and caches true of the store whatever a
            // rollback undoes (`memory_waits`: a pending row's class never changes); `walks`
            // drops what a failed step or transaction touched (`reach::rolled_back`)
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
            held_sync_keys: _,
            role_key_epochs: _,
            own_epochs_of: _,
            unread_of: _,
            listed_keys: _,
            live_bodies: _,
            covers: _,
            pieces_below: _,
            piece_roots: _,
            secrets_read: _,
            own_commits: _,
            head_keys: _,
            read_credentials: _,
            sync_things: _,
            sync_set: _,
            dial_peers: _,
            steps_needs: _,
            proven: _,
            addenda_owed: _,
            // built again from the journaled `ix.paths_unknown` (`apply::paths::Wait`)
            paths_wait: _,
            holders_named: _,
            record_certs: _,
            // followed (`Effects`): what a rollback restores moves its reads, so the next follow
            // indexes again
            certified: _,
            evidence: _,
            cert_records: _,
            wrap_blocks: _,
            own_roles: _,
            read_facts: _,
            sync_bodies: _,
            sync_body_rows: _,
            thing_syncs: _,
            secret_actors: _,
            keys_opens: _,
            read_floors: _,
            held_fates: _,
            sync_ids: _,
            sync_rows: _,
            pass_wanted: _,
            read_things: _,
            step_write_keys: _,
            setting_wants: _,
            links: _,
            // heard paths: a Head answer's word, kept whatever is undone
            heard: _,
            caught_up: _,
            unit_of: _,
            closure_follow: _,
            node_root: _,
            waiting_carried: _,
            part_bounds: _,
            tree_roots: _,
            departures: _,
            blocked_roles: _,
            rotations_due: _,
            reseal_scans: _,
            // decodes of commit records kept at each record's stamp (`decoded`): an undo
            // stamps the rows it restores
            decoded: _,
            // caches, dropped when anything changed (`states` and `pages` per written aspect)
            states: _,
            pages: _,
            waits: _,
            touches: _,
            // the store's count, read by `changed_since`
            store_rows: _,
            // work lists and hints a superset of which is harmless (the consumer re-checks each
            // entry against the restored state), and what a step only moves forward
            place: _,
            // the trigger's estimates and arms: a failed write counted more than landed, which
            // costs a weighing at most
            compaction: _,
            drop_due: _,
            kept_due: _,
            kept_things_due: _,
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
            gone_dirty: _,
            needs_due: _,
            fire_brings: _,
            pass_due: _,
            lost_due: _,
            brought: _,
            entered: _,
            wakes: _,
            resnapshots_due: _,
            openings: _,
            redeliver: _,
            missed: _,
            timer_floor: _,
            // written between transactions only (`Engine::take_units`)
            ticks_aside: _,
            alone: _,
            hlc: _,
            session: _,
            expiring: _,
            later_sessions: _,
            replaced_reads: _,
            death_walks: _,
            rebuilds: _,
            // set at each transaction's start, and what its end records (taken at the commit,
            // dropped at a rollback)
            time: _,
            // set outside transactions: identity, configuration, node-sync's settings; checked
            // unchanged by every transaction (the value below, `Engine::run`)
            id,
            detect,
            key_salt,
            addenda_on,
            skip_writer_rules,
            leave_adminless,
            commits_watched,
            refs_watched,
            commit_listeners,
            forge_bad,
            link_keys,
            held_link_keys,
            followed_links,
            keep_bodies,
            list_bound,
            sourced_elsewhere,
            // test hooks and debug bookkeeping, set and taken anywhere
            forged: _,
            #[cfg(debug_assertions)]
            unchecked_tx: _,
            #[cfg(debug_assertions)]
            unchecked_states: _,
            #[cfg(debug_assertions)]
            unchecked_rows: _,
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
            apply_fault: _,
            #[cfg(test)]
            end_fault: _,
            #[cfg(test)]
            end_fault_due: _,
            #[cfg(test)]
            lie_facts: _,
            #[cfg(test)]
            snapshot_fault: _,
            #[cfg(test)]
            lie_floor: _,
            #[cfg(test)]
            junk_boxes: _,
            #[cfg(test)]
            whole_secrets_snapshots: _,
        } = c;
        let actors = |m: &mut dyn Iterator<Item = &Tid>| m.copied().collect::<Vec<_>>();
        format!(
            "{:?}",
            (
                (id.tid(), detect, key_salt, addenda_on, skip_writer_rules, leave_adminless),
                (commits_watched, refs_watched, commit_listeners.is_some(), forge_bad, keep_bodies, list_bound, sourced_elsewhere),
                (actors(&mut link_keys.keys()), actors(&mut held_link_keys.keys()), followed_links.all()),
            )
        )
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

    /// The nonces this node writes under now: its own sessions (what an own write falling starts
    /// anew, `fresh_session`).
    pub(crate) fn current_sessions(&self) -> BTreeSet<Nonce> {
        std::iter::once(self.id.tid()).flat_map(|a| [self.nonce_as(&a, self.session.nonce), self.nonce_as(&a, self.expiring.nonce)]).collect()
    }

    /// Whether `n` is the nonce of a plain session of `signer` of this open (`fresh_session`).
    pub(crate) fn own_plain(&self, signer: &Tid, n: &Nonce) -> bool {
        let now = self.nonce_as(signer, self.session.nonce);
        n[..8] == now[..8] && nonce_count(&now).wrapping_sub(nonce_count(n)) <= self.later_sessions
    }

    /// This node's tid: its node thing, which it writes as and holds roles as
    /// (spec/permissions.md §1, own things).
    pub(crate) fn tid(&self) -> Tid {
        self.id.tid()
    }

    /// Whether `t` is an own thing of this node (spec/sync-set.md §2 Own things): its node thing,
    /// a held link key.
    pub(crate) fn is_own(&self, t: &Tid) -> bool {
        *t == self.tid() || self.link_keys.contains_key(t)
    }

    /// The key this node signs as `thing` by (spec/permissions.md §1 Signed as), with the key the
    /// header names (`None`: `thing`'s record's, the first form): the record's key where this
    /// node holds it, else the first held key holding a grant on `thing` that is alive now. The
    /// walk judges what the grant gives; a key with none here is never used.
    pub(crate) fn key_for(&self, thing: &Tid) -> Option<(&osis_crypto::SigningSecret, Option<osis_base::SignKey>)> {
        let ids = || std::iter::once(&self.id).chain(self.link_keys.values().map(|i| &**i));
        // a record this node made it holds before any commit carries it
        if let Some(i) = ids().find(|i| i.tid() == *thing) {
            return Some((i.signing(), None));
        }
        let held = ids().map(|i| i.signing());
        let record = self.created(thing).and_then(osis_base::CreationRecord::key);
        let ts = crate::flows::now_ts(self);
        let mut granted = None;
        for s in held {
            let k = osis_base::SignKey(s.verifying_key().to_bytes());
            if Some(k) == record {
                return Some((s, None));
            }
            if granted.is_none() && self.timelines().key_grants(thing, Some(ts)).contains_key(&k) {
                granted = Some((s, Some(k)));
            }
        }
        granted
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
            sync_set: memo::Memo::new("sync: sync set"),
            dial_peers: memo::Memo::new("sync: dial peers"),
            steps_needs: memo::Memo::new("sync: steps needs"),
            proven: memo::Memo::new("sync: proven"),
            addenda_owed: crate::flows::addenda::Decides::default(),
            own_roles: memo::Cutoff::new("own roles"),
            paths_wait: None,
            holders_named: memo::Memo::new("holders named: read"),
            record_certs: memo::Memo::new("certificates: a record's"),
            certified: Default::default(),
            evidence: Default::default(),
            cert_records: Default::default(),
            departures: memo::Memo::new("departures"),
            blocked_roles: memo::Memo::new("blocked roles"),
            rotations_due: memo::Memo::new("rotation due"),
            reseal_scans: memo::Memo::new("reseal: scan"),
            place: 0,
            wrap_blocks: memo::Cutoff::new("wrap blocked"),
            read_facts: memo::Cutoff::new("sync: read facts"),
            sync_bodies: memo::Cutoff::new("sync: bodies"),
            sync_body_rows: memo::Cutoff::new("sync: body"),
            thing_syncs: memo::Cutoff::new("sync: thing sync"),
            secret_actors: memo::Cutoff::new("sync: secret actor"),
            keys_opens: memo::Cutoff::new("sync: keys open"),
            read_floors: memo::Cutoff::new("sync: read floor"),
            held_fates: memo::Cutoff::new("sync: held fate"),
            pages: HashMap::new(),
            timelines: held::Timelines::default(),
            sides: crate::sides::Sides::default(),
            detect: false,
            stale_things: BTreeSet::new(),
            stale_authors: BTreeSet::new(),
            addenda_on: true,
            stale_under: BTreeSet::new(),
            purges_moved: BTreeSet::new(),
            stale_commits: BTreeSet::new(),
            stale_all: true,
            dirty: false,
            key_salt,
            ix: Indexes {
                keysets: JMap::by_run(|k| actor_run(&k.0)),
                keysets_invalid: JMap::by_run(|k| actor_run(&k.0)),
                sealed: JMap::by_run(|k| actor_run(&k.0)),
                boxed: JMap::by_run(|k| actor_run(&k.0)),
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
            leave_adminless: false,
            commits_watched: false,
            refs_watched: false,
            commits_named: Vec::new(),
            commit_listeners: None,
            listed_before: Vec::new(),
            killed: Vec::new(),
            to_date: Default::default(),
            dates_moved: Vec::new(),
            bodies_rewritten: Vec::new(),
            index_settled: BTreeMap::new(),
            died: Vec::new(),
            revivals: 0,
            redeliver: BTreeSet::new(),
            forge_bad: BTreeSet::new(),
            #[cfg(debug_assertions)]
            unchecked_tx: false,
            #[cfg(debug_assertions)]
            unchecked_states: BTreeSet::new(),
            #[cfg(debug_assertions)]
            unchecked_rows: BTreeSet::new(),
            #[cfg(debug_assertions)]
            rebuilt_perm: BTreeMap::new(),
            forged: BTreeMap::new(),
            session,
            expiring,
            later_sessions: 0,
            compaction: Default::default(),
            fallen: Default::default(),
            #[cfg(test)]
            check_ingest: false,
            #[cfg(test)]
            whole_apply: false,
            #[cfg(test)]
            piece_fault: None,
            #[cfg(test)]
            step_fault: None,
            apply_fault: None,
            #[cfg(test)]
            end_fault: None,
            #[cfg(test)]
            end_fault_due: false,
            ticks_aside: Default::default(),
            alone: false,
            #[cfg(test)]
            lie_facts: None,
            #[cfg(test)]
            snapshot_fault: None,
            #[cfg(test)]
            lie_floor: None,
            #[cfg(test)]
            junk_boxes: None,
            #[cfg(test)]
            whole_secrets_snapshots: false,
            link_keys: Default::default(),
            heard: Default::default(),
            held_link_keys: Default::default(),
            followed_links: Default::default(),
            epochs_of: memo::Memo::new("epochs"),
            held_sync_keys: memo::Memo::new("held sync keys"),
            role_key_epochs: memo::Memo::new("role key epochs"),
            own_epochs_of: memo::Memo::new("own epochs"),
            unread_of: memo::Memo::new("unread"),
            listed_keys: memo::Memo::new("listed keys"),
            store_rows,
            time: Default::default(),
            // judged once after an open: a commit applied before a restart left it owed
            keep_bodies: false,
            list_bound: osis_commit::MAX_LIST_BYTES,
            gone_dirty: BTreeSet::new(),
            needs_due: BTreeSet::new(),
            fire_brings: false,
            // what arrived before the open but was not judged yet: all judged at the first settle
            pass_due: None,
            lost_due: BTreeSet::new(),
            brought: BTreeSet::new(),
            entered: None,
            batched: None,
            touches: Default::default(),
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
            pieces_below: memo::Memo::new("pieces: below"),
            piece_roots: memo::Memo::new("pieces: roots"),
            replaced_reads: 0,
            death_walks: 0,
            rebuilds: 0,
            decoded: Default::default(),
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
        // a setting gone (purged) is no setting (`validity::settings`)
        let gone_settings: Vec<(Tid, BTreeSet<Ak>)> = m.view.aspects.iter().enumerate().filter(|(ai, a)| a.ak.as_str() == osis_commit::retention::RETENTION && self.ix.commits.get(&id).is_some_and(|o| o.own_gone(*ai) != m.own_gone(*ai))).map(|(_, a)| (a.tid, crate::apply::validity::enabled(self, &a.tid))).collect();
        let had = self.ix.commits.get(&id).map(covers_of).unwrap_or_default();
        self.index_covers(&id, &had, &covers_of(&m));
        // a part held or missing invalid (a late part joining, a leftover kept, one reopened)
        // goes at the transaction's end if judged so (`retention::drop_invalid`)
        if (0..m.parts()).any(|ai| !m.valid_at(ai) && (m.holds(ai) || m.missing(ai))) {
            self.drop_due.insert(id);
        }
        self.note_none(&m);
        self.touches.note(&id, &m);
        // held again: its meta decides its covers from now on
        if self.ix.handed.contains_key(&id) {
            self.handed_due.insert(id);
        }
        let addenda: Vec<Tid> = m.view.aspects.iter().enumerate().filter(|(ai, a)| osis_schema::core_types::is_addenda(a.ak.as_str()) && self.ix.commits.get(&id).is_some_and(|o| o.valid_at(*ai)) != m.valid_at(*ai)).map(|(_, a)| a.tid).collect();
        self.ix.held.touch_commit(id);
        self.ix.commits.insert(id, m);
        self.addenda_moved(&id, &addenda);
        for (t, before) in gone_settings {
            crate::apply::validity::setting_moved(self, &t, Some(before));
        }
        self.update_timelines();
    }

    /// `t` arrived: judged at the next `Engine::settle_needs`. What a sealed fire brings
    /// (`fire_brings`) no pass brought: it came whole with the fire, its evidence with it, and
    /// is judged as a lost need is, at once with no pass in flight (`Engine::settle_lost`); a
    /// deposit is taken outside any pass, and none is wanted for it.
    pub(crate) fn note_pass_due(&mut self, t: Tid) {
        if self.fire_brings {
            self.lost_due.insert(t);
            return;
        }
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
        self.ix.held.touch_commit(*id);
        osis_base::costs::count("meta: parts indexed", m.view.aspects.len() as u64);
        self.note_kept(id, &m);
        let had = missing_of(&m);
        if !had.is_empty() {
            self.note_on(&m);
        }
        self.index_missing(id, &had, &BTreeSet::new());
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
            if !self.ix.missing.contains_key(k) {
                self.ix.missing_things.remove(&k.1, &k.0);
            }
        }
        for k in now.difference(was) {
            self.ix.missing.insert(k.clone(), *id);
            self.ix.missing_things.insert(k.1, k.0.clone());
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

    /// The verdicts of commit `id`'s addenda on `things` moved: what they list is touched and
    /// judged again. Whether any was.
    fn addenda_moved(&mut self, id: &CommitId, things: &[Tid]) -> bool {
        let listed: BTreeSet<CommitId> = things.iter().filter_map(|t| self.ix.addenda.get(&(*t, *id))).flat_map(|x| x.entries.iter().flat_map(|(_, l)| l.iter().copied())).filter(|c| self.ix.commits.contains_key(c)).collect();
        for c in &listed {
            self.ix.held.touch_commit(*c);
        }
        let any = !listed.is_empty();
        self.stale_commits.extend(listed);
        any
    }

    /// Re-indexes which parts of commit `id` are invalid here (call after setting `Meta::valid`).
    pub fn index_validity(&mut self, id: &CommitId) {
        let due = self.ix.commits.get(id).map(|m| self.kept_parts(id, m)).unwrap_or_default();
        self.kept_due.extend(due);
        let Some(m) = self.ix.commits.get(id) else { return };
        let mut settings = Vec::new();
        let mut addenda = Vec::new();
        for (ai, a) in m.view.aspects.iter().enumerate() {
            let k = (a.tid, a.ak.clone());
            let flipped = if m.valid_at(ai) { self.ix.invalid.remove(&k, id) } else { self.ix.invalid.insert(k.clone(), *id) };
            // an addendum's verdict is an input of the reading of what it lists against a
            // rotation (`validity::Judge::counts`)
            if flipped && osis_schema::core_types::is_addenda(a.ak.as_str()) {
                addenda.push(a.tid);
            }
            if !m.valid_at(ai) {
                // held or missing, it drops if judged invalid (`retention::drop_invalid`)
                if m.holds(ai) || m.missing(ai) {
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
        if self.addenda_moved(id, &addenda) {
            self.update_timelines();
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
    /// This engine among every one built in the process (`Kept`); a test copy keeps its
    /// original's, as it keeps its memos' answers.
    instance: u64,
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
    /// A transaction acting on in-memory work taken outside it failed (`take_units`): the next
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
    /// Debug builds: a durable transaction changed a state or a commit's parts, or a transaction
    /// rolled back, since `check_index` last ran; it runs at the end of the engine's history (its
    /// drop) or before a reload (`check_before_reload`). A copy starts clear: its original checks
    /// their shared past.
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
    /// Tests, set by hand: `check_index` after every transaction that changed something or
    /// rolled back, not only at the end (to find the transaction that diverged).
    #[cfg(test)]
    pub(crate) check_every_tx: bool,
}

/// Tests: the work whose transaction faults at its end (`Core::end_fault`).
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndFault {
    /// Examining this commit (`apply::ingest_blob`) or running a timer of it (`retention::run_timer`).
    Commit(CommitId),
    /// Learning this thing's record (`apply::learn_records_in`).
    Record(Tid),
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

/// The transaction's end, steps 1 and 2 (notes/engine.md): the flows while their writes bring
/// things into the node closure.
fn end_flows<T>(tx: &mut Tx<'_>, mut r: Result<T>) -> Result<T> {
    // explicit demotions applied get this node's addenda (spec/permissions.md §5.2),
    // on what the node closure holds as this transaction leaves it (a node writes only
    // what it holds, spec/sync-set.md §2 Writing). The flows' own writes may bring
    // things into the node closure (an addendum makes the content it vouches for
    // valid, strongs included): what waits for them joins and the flows run again,
    // until nothing enters.
    let mut flows = osis_base::loop_guard::LoopGuard::new("Engine::run (the flows' writes bringing things into the node closure)");
    while r.is_ok() && !tx.txn.is_memory() {
        r = then(r, || crate::sync::units::settle(tx));
        // what waits to see a thing enter the node closure joins as it enters
        // (spec/commits.md §4 Outside the node closure), the closure settled again
        let mut guard = osis_base::loop_guard::LoopGuard::new("Engine::run (what waits for things entering the node closure)");
        // each round wakes what things newly entered hold back, a thing entering as a commit
        // pending at the start applies: rounds by those, not by what is left pending
        let pending = tx.core.ix.pending.len() as u64;
        while r.is_ok() {
            match crate::apply::wake_entered(tx) {
                Ok(0) => break,
                Ok(n) => {
                    guard.round(n, || (pending + 2, format!("{pending} pending at the start")));
                    r = then(r, || crate::sync::units::settle(tx));
                }
                Err(e) => r = Err(e),
            }
        }
        // a commit pends only while carried (spec/commits.md §4 Pending storage)
        r = then(r, || crate::apply::carriers::settle(tx));
        r = then(r, || crate::flows::addenda::write_owed(tx));
        r = then(r, || crate::sync::units::settle(tx));
        if r.is_err() || !crate::apply::entering(tx) {
            break;
        }
        // each round brings a thing in
        flows.round((), || {
            let held = tx.core.ix.closure.things().count() as u64;
            (held + 2, format!("{held} things in the node closure"))
        });
    }
    r
}

/// The transaction's end, steps 3 and 4 (notes/engine.md): invalid bodies, settings, re-judging,
/// setting waits and covers; then destructions and what nothing held needs any more.
fn end_drops<T>(tx: &mut Tx<'_>, mut r: Result<T>) -> Result<T> {
    // a body judged invalid goes at the end of the transaction that judged it
    // (spec/permissions.md §6), after this node's addenda vouched for what they list;
    // a memory transaction drops memory parts only (`drop_invalid`)
    if !tx.core.drop_due.is_empty() {
        r = then(r, || crate::retention::drop_invalid(tx));
    }
    tx.core.drop_due.clear();
    if !tx.core.settings_due.is_empty() {
        // the new timelines walk rows dated by this transaction's joins and validity
        // changes (a superseder turning invalid moves its victims' rows later), so the
        // walk tells no body early
        r = then(r, || crate::retention::leaving::date_due(tx));
        r = then(r, || crate::retention::settings_changed(tx));
    }
    tx.core.settings_due.clear();
    // a setting that left here moves which external fires are valid
    // (`validity::setting_moved`): judged, and what turned invalid goes, in this
    // transaction
    if tx.core.stale() {
        r = then(r, || crate::apply::rejudged(tx, false).and_then(|_| crate::retention::drop_invalid(tx)));
    }
    tx.core.drop_due.clear();
    if !tx.core.setting_waits_due.is_empty() {
        r = then(r, || crate::sync::setting::judge_due(tx));
    }
    tx.core.setting_waits_due.clear();
    if !tx.core.ix.cover_waits.is_empty() && !tx.txn.is_memory() {
        r = then(r, || crate::retention::replace::wake_covers(tx));
    }
    if !tx.core.none_due.is_empty() {
        r = then(r, || crate::retention::settle_none(tx));
    }
    tx.core.none_due.clear();
    // destructions and what nothing held needs any more, each letting more go
    // (`retention::needed`), judged on the node closure as it stands
    while r.is_ok() && !tx.txn.is_memory() {
        r = then(r, || crate::retention::destroy::apply_destructions(tx));
        if r.is_err() || tx.core.needs_due.is_empty() {
            break;
        }
        r = then(r, || crate::sync::units::settle(tx));
        let mut went = false;
        r = r.and_then(|v| crate::retention::needed::settle(tx).map(|w| {
            went = w;
            v
        }));
        if !went {
            break;
        }
    }
    tx.core.needs_due.clear();
    // what the held changes above moved in the walk is judged here: a transaction leaves the
    // next nothing of its own to judge, a split path the steps above let open included
    // (`apply::paths::refresh`: a commit whose path opens turns stale)
    if r.is_ok() {
        crate::apply::paths::refresh(tx);
    }
    while r.is_ok() && tx.core.stale() {
        r = then(r, || crate::apply::rejudged(tx, false).and_then(|_| crate::retention::drop_invalid(tx)));
        tx.core.drop_due.clear();
    }
    r
}

/// The transaction's end, step 5 (notes/engine.md): what follows every change above, settled
/// and stored.
fn end_settle<T>(tx: &mut Tx<'_>, mut r: Result<T>) -> Result<T> {
    r = then(r, || crate::retention::persist_gone(tx));
    tx.core.gone_dirty.clear();
    r = then(r, || edits::settle(tx));
    tx.core.refold.clear();
    // freed links judged once every rebuild ran: a judged one keeps no key here
    if !tx.core.freed_due.is_empty() {
        r = then(r, || crate::retention::freed::settle_due(tx));
    }
    tx.core.freed_due.clear();
    if !tx.core.forgotten_names_due.is_empty() {
        r = then(r, || crate::retention::names::settle_due(tx));
    }
    tx.core.forgotten_names_due.clear();
    if !tx.core.handed_due.is_empty() {
        r = then(r, || crate::retention::handed::settle_due(tx));
    }
    tx.core.handed_due.clear();
    r = then(r, || listing::listing_moved(tx));
    tx.core.listed_before.clear();
    tx.core.killed.clear();
    // the node closure follows every change above (spec/sync-set.md §2), and holds
    // what this transaction made
    r = then(r, || crate::sync::units::settle(tx).and_then(|()| crate::sync::units::check_written(tx)));
    tx.core.wrote_on.clear();
    // what stopped pending above loses its carriers
    if !tx.txn.is_memory() {
        r = then(r, || crate::apply::carriers::settle(tx));
    }
    tx.core.carriers_due.clear();
    // the blob waits of what pends no more go (`apply::reach::settle`)
    crate::apply::reach::settle(tx.core);
    // the history rows follow every change of what is held above
    r = then(r, || crate::retention::leaving::date_due(tx));
    tx.core.to_date.clear();
    tx.core.dates_moved.clear();
    tx.core.bodies_rewritten.clear();
    tx.core.index_settled.clear();
    tx.core.died.clear();
    // every state written above stored in its form (`Tx::settle_states`)
    r = then(r, || tx.settle_placements().and_then(|()| tx.settle_states()));
    r = then(r, || Core::commit_changes(tx));
    #[cfg(test)]
    if std::mem::take(&mut tx.core.end_fault_due) {
        r = r.and(Err(Error::Corrupt("an end-work fault (tests)")));
    }
    r
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
    /// taken outside it (`take_units`): the next transaction reads it again (`run`), and a tick is
    /// due (`next_timer`) so one runs with no other event.
    pub fn reload_owed(&self) -> bool {
        let w = self.store.writes();
        (w.failed, w.unknown) != self.failed_seen || self.taken_failed
    }

    /// Takes `units` (the pieces of work a transaction does: a commit arriving or woken, a tick's
    /// timer, a record learned) in one transaction, `take` doing a list of them. A fault there
    /// (`Error::is_fault`: this build's, never a store failure) is a unit's: each is taken again
    /// alone, in a transaction of its own (`Core::alone`), and one that faults so is set aside (`aside`,
    /// given the fault): its work is left undone until the next open, and the app told. A fault
    /// no unit brings alone is told as well. The outputs of the transactions that committed.
    /// `taken`: the units were taken out of memory outside the transaction (what woke pending
    /// commits, `apply::waits::wake`; loose records come to be awaited): an error left from here
    /// (a store failure, an `aside` failing) owes a reload, so what was taken is derived again as
    /// an open derives it, never lost while the node stays up (spec/commits.md §4: every arrival
    /// that applies examines again what waits for it).
    pub(crate) fn take_units<U: Clone, T>(&mut self, units: Vec<U>, taken: bool, mut take: impl FnMut(&mut Tx<'_>, Vec<U>) -> Result<T>, aside: impl FnMut(&mut Engine, U, Error) -> Result<()>) -> Result<Vec<T>> {
        let r = match self.run(|tx| take(tx, units.clone())) {
            Err(e) if e.is_fault() => self.split_units(units, e, take, aside),
            r => r.map(|v| vec![v]),
        };
        self.taken_failed |= taken && r.is_err();
        r
    }

    /// `f` taking one unit alone (`Core::alone`).
    pub(crate) fn alone<T>(&mut self, f: impl FnOnce(&mut Engine) -> T) -> T {
        let was = std::mem::replace(&mut self.core.alone, true);
        let r = f(self);
        self.core.alone = was;
        r
    }

    /// `take_units` past a transaction taking `units` together that failed for `fault`: each
    /// taken alone (`alone`), set aside where that faults.
    pub(crate) fn split_units<U: Clone, T>(&mut self, units: Vec<U>, fault: Error, mut take: impl FnMut(&mut Tx<'_>, Vec<U>) -> Result<T>, mut aside: impl FnMut(&mut Engine, U, Error) -> Result<()>) -> Result<Vec<T>> {
        // one unit too: taken together it did the work of the commits it woke
        let mut out = Vec::new();
        let mut told = false;
        for u in units {
            match self.alone(|e| e.run(|tx| take(tx, vec![u.clone()]))) {
                Ok(v) => out.push(v),
                Err(e) if e.is_fault() => {
                    aside(self, u, e)?;
                    told = true;
                }
                Err(e) => return Err(e),
            }
        }
        if !told {
            crate::apply::tell_fault(&mut self.core, None, Vec::new(), &fault);
        }
        Ok(out)
    }

    /// `f`'s answer for `k`, kept in `memo` while everything it read stands (`osis_base::memo`):
    /// how a caller outside the engine keeps what it read of it. Outside a memo's computation the
    /// memo clock and the blobs are brought to now first, as a read does, so a kept answer never
    /// outlives an expiry or `until` it read.
    pub fn memo<K: std::hash::Hash + Eq + Clone, V: Clone + PartialEq + std::fmt::Debug>(&mut self, kept: &Kept<K, V>, k: &K, f: impl Fn(&mut Engine) -> Result<V>) -> Result<V> {
        if !memo::computing() {
            if self.blobs_unsettled {
                memo::unrecorded(|| self.settle_blobs())?;
            }
            let now = self.core.hlc.wall().0;
            self.core.time.set(now);
        }
        let k = (self.instance, k.clone());
        let mut at = (self, kept);
        memo::Memo::get_in(&mut at, |c| &c.1.0, &k, |c| f(&mut *c.0))
    }

    /// The engine of node `id` over `store`, its indexes empty (`create` writes them, `open`
    /// loads them).
    fn over(store: Store, store_rng: SeededRng, blobs: Arc<dyn osis_store::Ciphertext>, cfg: Config, clock: Arc<dyn Clock>, mut rng: Box<dyn osis_crypto::NodeRng>, id: Identity) -> Engine {
        let (session, expiring) = sessions(id.tid(), &mut *rng);
        let rows = store.row_changes();
        // its one writer is `run`, each transaction undone whole (`memo::Undoable`)
        let store = store.undoable();
        Engine { instance: INSTANCES.fetch_add(1, std::sync::atomic::Ordering::Relaxed), store, store_rng, blobs, blob_stamps: Default::default(), blob_seq: 1, blobs_unsettled: false, failed_seen: (0, 0), taken_failed: false, loads: 0, rng, core: Core::new(id, clock.clone(), session, expiring, rows), eph: crate::ephemeral::Eph::default(), clock, cfg, #[cfg(debug_assertions)] index_unchecked: false, #[cfg(debug_assertions)] verdicts_unchecked: false, #[cfg(debug_assertions)] last_tx_wall: None, #[cfg(debug_assertions)] loading: false, #[cfg(test)] index_poked: false, #[cfg(test)] check_every_tx: false }
    }

    /// A new node over an empty backend: a fresh signing key, its node thing and node root
    /// (`bootstrap`).
    pub fn create(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, blobs: Arc<dyn osis_store::Ciphertext>, cfg: Config, clock: Arc<dyn Clock>, mut rng: Box<dyn osis_crypto::NodeRng>) -> Result<Engine> {
        let store = Store::create(backend, root, cfg.store, &mut *rng)?;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let store_rng = SeededRng::from_seed(seed);
        let id = Identity::generate(&mut *rng);
        let mut e = Engine::over(store, store_rng, blobs, cfg, clock, rng, id);
        // the signing seed, then the node thing's creation nonce
        let seed_bytes = [e.core.id.seed().expose().as_slice(), e.core.id.record().nonce()].concat();
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
        let (s, nonce) = s.split_at_checked(32).ok_or(Error::Corrupt("seed"))?;
        let s: [u8; 32] = s.try_into().map_err(|_| Error::Corrupt("seed"))?;
        let nonce: [u8; 32] = nonce.try_into().map_err(|_| Error::Corrupt("seed"))?;
        let id = Identity::node(osis_crypto::Secret32::from_bytes(s), nonce);
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
        self.reload()?;
        self.run(crate::flows::reopen_all)?;
        self.run(crate::flows::cards::load)?;
        self.reexamine()?;
        self.forget_gone_causes()?;
        self.rejudge_setting_waits()?;
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
            // what the engine makes again: as its committed store says (a seal noted, or gone
            // with its bytes kept again)
            let made = if n.seq <= committed { &n.made } else { &n.unmade };
            for (id, len) in made {
                t.made(id, *len, false)?;
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

    /// The node's first start (`flows::roots::first_start`).
    fn bootstrap(&mut self) -> Result<()> {
        self.run(crate::flows::roots::first_start)
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

    /// The mint admin of `tid` (`None`: a thing minted with a key or an unknown thing).
    pub fn mint_admin(&self, tid: &Tid) -> Option<Tid> {
        self.core.mint_admin(tid)
    }

    /// This node's tid: its node thing, which it writes as.
    pub fn tid(&self) -> Tid {
        self.core.tid()
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
        let mut tx = Tx { txn, blobs: blobs::Cipher::new(&*self.blobs, &self.blob_stamps, self.blob_seq), core: &mut self.core, rng: &mut *self.rng, bound: None, held_pages: Default::default(), publishing: Vec::new() };
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
        // outside it (`take_units`): everything is read again as an open reads it, so nothing kept
        // in memory beside the store (work an operation took outside the transaction that failed:
        // wakes, due lists) differs from what a restart derives. One
        // whose outcome was unknown (its sync failed) may have landed after all: read once the
        // store works again, under a fresh session (that commit's counters may be taken)
        if self.reload_owed() {
            let w = self.store.writes();
            let seen = std::mem::replace(&mut self.failed_seen, (w.failed, w.unknown));
            let taken = std::mem::take(&mut self.taken_failed);
            // debug builds: what the reload replaces was what the store loads
            #[cfg(debug_assertions)]
            if w.unknown == seen.1 && self.index_unchecked {
                self.check_before_reload();
            }
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
        #[cfg(test)]
        {
            self.core.end_fault_due = false;
        }
        self.core.memory_tx = false;
        let start = self.core.mark();
        #[cfg(debug_assertions)]
        {
            self.core.unchecked_tx = false;
        }
        // debug builds: what is set outside transactions, which this one leaves as it is
        #[cfg(debug_assertions)]
        let outside = memo::unrecorded(|| Core::rollback_classes(&self.core));
        // debug builds: whether the transaction changed a state or a part
        #[cfg(debug_assertions)]
        let mut changed = false;
        // debug builds: whether the transaction was durable (`flows::addenda::missed` after it)
        #[cfg(debug_assertions)]
        let mut durable = false;
        // the blobs it held, once committed
        let mut newly_held: Vec<BlobId> = Vec::new();
        // a rolled-back transaction leaves what a computation running it read as it was
        // (`memo::Undoable`: the journaled indexes and the store are undone whole)
        let undoable = memo::Undoable::start();
        // the ciphertext store committed, or the engine's store tried to: a failure past here
        // undoes less than the transaction wrote, so it ends the stretch kept
        let mut committing = false;
        let r = match self.store.transaction(&mut self.store_rng) {
            Ok(txn) => {
                let mut tx = Tx { txn, blobs: blobs::Cipher::new(&*self.blobs, &self.blob_stamps, self.blob_seq), core: &mut self.core, rng: &mut *self.rng, bound: None, held_pages: Default::default(), publishing: Vec::new() };
                // the persisted index follows the in-memory indexes in the same transaction
                let mut r = f(&mut tx);
                // a memo running `f` reads what `f` reads: the transaction's own work around it
                // (its end's follow-ups, persisting, checks) is no part of `f`'s answer
                _after = memo::Unrecorded::start();
                r = end_flows(&mut tx, r);
                #[cfg(debug_assertions)]
                {
                    durable = !tx.txn.is_memory();
                }
                r = end_drops(&mut tx, r);
                r = end_settle(&mut tx, r);
                // every validity change was judged before the index is persisted
                debug_assert!(r.is_err() || (tx.core.stale_things.is_empty() && tx.core.stale_authors.is_empty() && tx.core.stale_commits.is_empty()), "stale validity left unjudged: {:?} {:?} {:?}", tx.core.stale_things, tx.core.stale_authors, tx.core.stale_commits);
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
                        committing = true;
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
                undoable.end(false);
                self.core.commit_journal();
                #[cfg(debug_assertions)]
                assert_eq!(memo::unrecorded(|| Core::rollback_classes(&self.core)), outside, "a transaction changed what is set outside transactions (`Core::rollback_classes`)");
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
                self.core.forget_reach_since(start.reached);
                let walked = start.walked;
                self.core.rollback_to(start);
                crate::apply::reach::rolled_back(&mut self.core, walked);
                undoable.end(!committing);
                #[cfg(debug_assertions)]
                {
                    assert_eq!(memo::unrecorded(|| Core::rollback_classes(&self.core)), outside, "a rolled-back transaction changed what is set outside transactions (`Core::rollback_classes`)");
                    osis_base::trace::mark_since(trace_mark, " (rolled back)");
                    osis_base::trace::note(|| format!("tx rolled back at {}:{}: {e:?} ({e})", caller.file().rsplit("src/").next().unwrap_or(caller.file()), caller.line()));
                    // memory must be what the store loads: checked at the end of history, or
                    // before a reload replaces it (`check_before_reload`)
                    self.index_unchecked = true;
                }
                #[cfg(all(test, debug_assertions))]
                if self.check_every_tx && !self.index_poked && self.store.writes().unknown == self.failed_seen.1 {
                    self.check_before_reload();
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
        fresh.link_keys = std::mem::take(&mut self.core.link_keys);
        fresh.held_link_keys = std::mem::take(&mut self.core.held_link_keys);
        // links followed are this session's, as the link keys they hold
        fresh.followed_links = std::mem::take(&mut self.core.followed_links);
        // the pass place never goes back: passes under way began at places below it
        fresh.place = self.core.place;
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
            fresh.unchecked_rows.extend(std::mem::take(&mut self.core.unchecked_rows));
        }
        // and so is what the sync set's walk takes no path through: the fresh closure is built cut
        fresh.ix.closure.set_cut(None, self.core.ix.closure.cut().iter().copied().collect())?;
        self.core = fresh;
        let r = {
            let txn = self.store.transaction(&mut self.store_rng)?;
            let mut tx = Tx { txn, blobs: blobs::Cipher::new(&*self.blobs, &self.blob_stamps, self.blob_seq), core: &mut self.core, rng: &mut *self.rng, bound: None, held_pages: Default::default(), publishing: Vec::new() };
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
        #[cfg(test)]
        {
            fresh.check_ingest = self.core.check_ingest;
            fresh.whole_apply = self.core.whole_apply;
        }
        fresh
    }

    /// An open from the persisted index and a rebuild from the commit records each compute the
    /// indexes and role timelines this node holds (spec/permissions.md §5.1 step 5: validity is
    /// a function of the held set), the open reading no blob (what a held
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

    /// `check_index`, a store failure returned (every other failure panics, naming the engine
    /// copy: `NamesCopy`).
    fn checked_index(&mut self) -> Result<()> {
        #[cfg(debug_assertions)]
        let _named = NamesCopy("index check");
        #[cfg(debug_assertions)]
        {
            self.checked_verdicts();
            // the walk reads every held commit as the index says now: an input moved untouched
            // leaves it behind for good
            let behind = self.core.walk_behind(self.core.ix.commits.keys());
            assert!(behind.is_none(), "check_index: the walk reads {behind:?} behind the index");
            self.checked_states()?;
            let rows = std::mem::take(&mut self.core.unchecked_rows);
            osis_base::costs::paused(|| osis_perm::uncounted(|| memo::unrecorded(|| self.read(|tx| crate::retention::leaving::rows_exact(tx, &rows)))))?;
            self.index_unchecked = false;
        }
        // link keys are derived: held exactly while `hold_link_key` or a followed link names them
        let named: BTreeSet<Tid> = self.core.held_link_keys.keys().chain(self.core.followed_links.all().values().filter_map(|(_, l)| l.as_ref())).copied().collect();
        assert_eq!(self.core.link_keys.keys().copied().collect::<BTreeSet<_>>(), named, "link keys: held or named by a followed link");
        // the node closure is as of the last transaction: a role ending at an `until` since moves
        // it at the next one (`Engine::tick`), and a walk afresh now reads the clock past it
        #[cfg(debug_assertions)]
        let settled = self.last_tx_wall.is_none_or(|w| w == self.core.hlc.wall().0);
        #[cfg(not(debug_assertions))]
        let settled = true;
        match if settled { self.checked_closure() } else { Ok(()) } {
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
            fresh.link_keys = self.core.link_keys.clone();
            // a link followed is synced, so its grants count (`rotation::role_here`)
            fresh.followed_links = self.core.followed_links.clone();
            let mut rng = SeededRng::from_u64(0);
            let mut store_rng = SeededRng::from_u64(0);
            let load = || -> Result<Option<u64>> {
                let txn = self.store.transaction(&mut store_rng)?;
                let mut tx = Tx { txn, blobs: blobs::Cipher::new(&*self.blobs, &self.blob_stamps, 0), core: &mut fresh, rng: &mut rng, bound: None, held_pages: Default::default(), publishing: Vec::new() };
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
                // Interim (issues/perm-eval-cost.md): an open reads every header to
                // give the walk its delta facts (`validity::reading`), until the walk's store is
                // the engine's index; then: no header of an unlinked commit is decoded
                assert_eq!(crate::apply::validity::misjudged(&fresh), None, "{at}: judged anew");
            }
        }
        Ok(())
    }

    /// Debug builds: the whole verdict checks, run at the end of the history (not per
    /// transaction: each costs O(everything held)) when a transaction ran since they last did.
    /// Every held commit's flags are what judging it now gives (`validity::misjudged`: what was
    /// not re-judged has not changed). Panics with the first difference.
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
            // every held blob with a seal is made again byte for byte (notes/slim-design.md B)
            let (_, failed) = self.check_seals();
            assert!(failed.is_empty(), "held blobs not made again from their seals at the end of history:\n{}", failed.join("\n"));
            // every strip due is written, but on an aspect whose re-judge waits (`Core::none_due`)
            let unwritten = self.unwritten_strips();
            assert!(unwritten.is_empty(), "strips due and not written at the end of history: {unwritten:?}");
        }
    }
}

/// Debug builds: a check failing past it prints which engine copy it failed in
/// (`osis_base::trace::copy()`), as the panic unwinds: copies of one node (a world played twice, a
/// shrink's candidates, the reference twins) share its tid and session.
#[cfg(debug_assertions)]
struct NamesCopy(&'static str);

#[cfg(debug_assertions)]
impl Drop for NamesCopy {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("{} failed in engine copy {}", self.0, osis_base::trace::copy());
        }
    }
}

#[cfg(debug_assertions)]
impl Engine {
    /// Debug builds, before a reload replaces memory (a write failed, or work taken outside a
    /// transaction that failed): memory is what the store loads (`check_index`: an open and a
    /// rebuild of it), so a field a rolled-back transaction left changed fails before the reload
    /// hides it. Every other rollback is checked at the end of history (the drop). Skipped as the
    /// drop's check is.
    fn check_before_reload(&mut self) {
        if std::thread::panicking() || self.loading || !osis_base::testenv::end_checks() {
            return;
        }
        #[cfg(test)]
        if self.index_poked {
            return;
        }
        // what the check's loads decode is not the history's (tests count decodes)
        let decoded = self.core.decoded.clone();
        let r = self.checked_index();
        self.core.decoded = decoded;
        assert!(matches!(r, Ok(()) | Err(Error::Store(_))), "before a reload: {:?}", r.err());
    }

    /// Debug builds: no addendum trigger missed (`flows::addenda::missed`), and no
    /// waiting split path a fresh attempt opens (`apply::paths::missed`), counting nothing.
    fn check_missed_wakes(&mut self, when: &str) {
        let m = osis_base::costs::paused(|| osis_perm::uncounted(|| memo::unrecorded(|| self.read(crate::flows::addenda::missed))));
        assert!(matches!(m, Ok(None) | Err(Error::Store(_))), "{when}: an addenda trigger missed: {m:?}");
        let p = osis_base::costs::paused(|| osis_perm::uncounted(|| memo::unrecorded(|| self.read(crate::apply::paths::missed))));
        assert!(matches!(p, Ok(None) | Err(Error::Store(_))), "{when}: a split path's wake missed: {p:?}");
    }
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
        let a = lp.peers[0].engine.tid();
        let mut m = Mutation::new();
        lp.peers[0].engine.new_thing(&mut m, a);
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let mut meta = lp.peers[0].engine.core.ix.commits[&id].clone();
        meta = super::Meta::of(meta.view.clone(), meta.header.clone(), meta.received, meta.origin, None, meta.signed(), vec![true], vec![Hold::Body { whole: true }]);
        // (holds, body gone, leftover, own live, bare, whole, dropped, missing)
        let answers = |m: &super::Meta| (m.holds(0), m.body_gone(0), m.stripped(0), m.own_live(0), m.own_gone(0), m.whole(0), m.is_dropped(0), m.missing(0));
        let cases = [
            (Hold::Body { whole: true }, (true, false, false, false, false, true, false, false)),
            (Hold::Body { whole: false }, (true, false, false, false, false, false, false, false)),
            (Hold::Leftover { whole: true, own_live: true }, (true, true, true, true, false, true, false, false)),
            (Hold::Leftover { whole: false, own_live: false }, (true, true, true, false, true, false, false, false)),
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
        let a = p.engine.tid();
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
        let (a, b, c) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
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
        let (a, b) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
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
        let c = lp.peers[2].engine.tid();
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
