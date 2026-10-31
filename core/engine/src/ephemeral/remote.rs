//! Synced ephemeral data (notes/ephemeral.md Synced ephemeral data): ordinary signed commits
//! with the header's ephemeral marker, of snapshot form (spec/commits.md §2), held in memory
//! (`Remote::held`, the ephemeral commit records) and never stored. Own writes on things in a
//! labeled closure collect in `unsent` and go out as ephemeral commits built here
//! (`take_ephemeral`); signal writes go as relay-only commits. Received ephemeral commits are
//! verified like any commit and judged like compaction snapshots (spec/permissions.md §5.2: a
//! part is valid iff its author could write the aspect at its `ts`, by commit ID); the writes a
//! part carries go with it. Valid parts join the ephemeral state; a held commit whose validity
//! flips rebuilds the aspects it touches from the own writes and the valid held parts (un-merge,
//! spec/crdt.md §4.6). Every ephemeral commit carries only its author's writes (and the records
//! they need); a receiver joins nothing else. A held commit is dropped once valid held commits
//! of its author and class list it as absorbed on every aspect it touches: only an author
//! compacts, its own commits into an own cover (`compact_own_ephemeral`; several commits, each
//! with part of the aspects, past inline header lists), so covers form one chain per author
//! and never race. Relay-only commits are delivered once (`delivered`, bounded)
//! and held by nobody. Presence commits carry an author's whole own state of its presence
//! aspects, each covering (absorbing) its author's earlier ones; they are covered at every
//! write and go (un-merged) at their lease
//! (`ts + MAX_LEASE`) or when the sync layer finds no server or peer holding them
//! (`drop_ephemeral_presence`); an author with live presence values sends a fresh one every
//! `KEEPALIVE`.

use super::{EphAspect, EphThing, in_ranges};
use crate::engine::Engine;
use crate::engine::secrets::{CommitSecrets, published_keys};
use crate::engine::write::{Creates, is_minting, mint_created, required_role, run_ops};
use crate::error::{Error, Result};
use crate::events::{ChangeId, Event, Origin};
use osis_base::format::{KEEPALIVE_MS, MAX_DRIFT_MS, MAX_LEASE_MS, MAX_OWNER_DEPTH};
use osis_base::{Ak, CommitId, CreationRecord, Tid, Ts, Value};
use osis_commit::{AspectWrite, CommitBlob, CommitBuilder, DELTA_PAST_BLOB, EphClass, Form, Header, Kind, MemoryBlobs};
use osis_crdt::{AnyView, Fragment, Frontiers, Interner, Op, PathOp, Snapshot, Source, SourceKind, Unpaged, Writer};
use osis_crypto::{DeleteSecret, VerifyingKey, dedup_secret};
use osis_perm::{Dots, Point, Validity};
use osis_schema::AspectKey;
use osis_schema::core_types::{CREATED, PLACED, is_membership_class};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

/// Relay-only commit IDs remembered as delivered (notes/ephemeral.md Bounds). Resource bound
/// against a hostile writer: past it the oldest is forgotten and its `ts` becomes its author's
/// floor, at or below which that author's relay-only commits are dropped, so none fires twice and
/// a flooding writer loses only its own (0: every relay-only commit older than its author's
/// newest delivered is dropped; infinity: memory grows with every signal of the replay window).
pub const MAX_DELIVERED: usize = 1 << 16;

/// An author covers its own held ephemeral commits once they cost more than this many times their
/// cover (spec/sync.md §9). Performance switch between correct strategies: 0 covers whenever two
/// own commits are held (at every write, as presence does), infinity never (bodies pile up to
/// the node and server caps, past which entries are refused). Rebuilds cost O(1) per byte written
/// for any value above 1; a server cap of this many times the sum of the authors' covers holds
/// every entry.
pub const COVER_FACTOR: usize = 2;

/// Bytes charged per held ephemeral commit besides its parts (`part_weight`) when an author
/// weighs its own held commits against their cover (spec/sync.md §9): about a server's per-entry
/// and log record overhead plus the commit header. Performance switch: 0 lets small writes pile up as entries
/// whose overhead dwarfs their bytes (a server's cap fills with overhead the trigger never sees),
/// infinity compacts at every write.
pub const ENTRY_CHARGE: usize = 1024;

/// Copies a holder keeps of a received part's writes, each counted by the node cap
/// (`ephemeral_charge`): the decoded part and the joined state.
const HELD_COPIES: usize = 2;

/// Bytes a holder spends per held part past its fragments (the part's and aspect's records, the
/// header's aspect entry), as the node cap counts it (`ephemeral_charge`). Resource estimate,
/// measured (`scale::eph_decoded_memory`, aspects shape: about 2.3 KiB of RSS per part with one
/// small write, release, x86-64): 0 leaves a commit of many small aspects counted at a tenth of
/// what it holds; infinity fills the cap with a label's first commit.
pub const PART_OVERHEAD: usize = 2048;

/// One delta of an ephemeral commit to build: thing, aspect, fragment, expiry.
type EphDelta = (Tid, Ak, Fragment, Option<u64>);

/// A held commit's part: commit, aspect index.
type PartId = (CommitId, usize);

/// Per aspect, the held commits a cover absorbs.
type Absorbs = BTreeMap<(Tid, Ak), BTreeSet<CommitId>>;

/// What one ephemeral commit build gave (`try_build`).
enum Attempt {
    Made(Box<EphCommit>),
    /// Nothing to carry.
    Empty,
    /// Header lists past the inline bound or a delta past a blob.
    Large,
    /// Another failure (reported).
    Failed,
}

/// Unsent own deltas of one aspect by (actor written for, expiry).
type Unsent = BTreeMap<(Tid, Option<u64>), Fragment>;

/// One held part of an ephemeral commit (in memory).
pub(crate) struct HeldPart {
    pub ai: usize,
    pub fragment: Fragment,
    /// Its encoded delta's length.
    pub bytes: usize,
    /// Its decoded fragment's heap size at decode (`Fragment::approx_bytes`; `ephemeral_charge`).
    pub heap: usize,
    /// The commits it lists as absorbed.
    pub absorbed: BTreeSet<CommitId>,
    /// Valid here (spec/permissions.md §5.2).
    pub valid: bool,
}

impl HeldPart {
    fn new(ai: usize, s: Snapshot, bytes: usize) -> HeldPart {
        let heap = s.fragment.approx_bytes();
        HeldPart { ai, fragment: s.fragment, bytes, heap, absorbed: s.absorbed.into_keys().collect(), valid: true }
    }

    /// Strips the writes but those of `author`'s sessions (an ephemeral commit carries its
    /// author's writes only, spec/sync.md §9).
    fn only_of(&mut self, author: Tid) {
        // a write under any other source (another node's session, a node's, a commit's) is not
        // its author's
        self.fragment.strip_copies(&|d| !own_session(d, author));
    }

    /// The writes that count here: none when invalid, else all.
    fn counted(&self) -> Option<Fragment> {
        self.valid.then(|| self.fragment.clone())
    }
}

/// A verified ephemeral commit none of whose parts was valid on arrival (`Remote::invalid`).
pub(crate) struct Invalid {
    pub blob: CommitBlob,
    /// The aspects of its decoded non-`/created` parts.
    pub ais: Vec<usize>,
    /// The records it carries.
    pub carried: BTreeMap<Tid, CreationRecord>,
    /// The most room it was given (`ingest_ephemeral_within`): what its retry may decode.
    pub room: u64,
}

/// A held ephemeral commit (in memory).
pub(crate) struct Held {
    pub header: Arc<Header>,
    pub parts: Vec<HeldPart>,
    /// Built by this node in this session (its writes are in the own state already).
    pub own: bool,
    /// The encoded bytes of its held parts' deltas.
    pub bytes: usize,
}

/// The synced side of the ephemeral state.
#[derive(Default)]
pub(crate) struct Remote {
    /// Own deltas not yet in an ephemeral commit, of things that sync: per aspect, per (actor
    /// they were written for, expiry).
    pub unsent: BTreeMap<(Tid, Ak), Unsent>,
    /// Signal writes not yet sent: (thing, aspect, value, `ts`, actor).
    pub signals: Vec<(Tid, Ak, Value, Ts, Tid)>,
    /// Things with ephemeral state (or ephemeral things) written while in no labeled closure:
    /// their own state goes once they enter one.
    pub local: BTreeSet<Tid>,
    /// The ephemeral commit records.
    pub held: BTreeMap<CommitId, Held>,
    /// Per commit ID some held commit's part lists as absorbed, the held commits listing it (kept
    /// exact by `index_lists`/`unindex_lists` around every change of `held`'s lists), so arrival
    /// and drop cost what the commit lists rather than every held commit.
    pub absorbers: BTreeMap<CommitId, BTreeSet<CommitId>>,
    /// Commits whose author's record, or a part's thing's, is not here yet, with the things
    /// whose records they wait for (bounded by the sync layer, which forgets what it drops),
    /// retried when one of those records arrives.
    pub pending: BTreeMap<CommitId, Waiting>,
    /// Commits whose parts were all invalid on arrival (`/created` ones aside): neither held nor
    /// counted, judged again when the held durable set changes (bounded like `pending`).
    pub invalid: BTreeMap<CommitId, Invalid>,
    /// Per actor, the cost of the own cover last weighed (plus the own held commits it could not
    /// absorb, over `COVER_FACTOR`): an own compaction is weighed again once the own held commits
    /// cost more than `COVER_FACTOR` times this (`compact_own_ephemeral`).
    pub cover_est: BTreeMap<Tid, usize>,
    /// Every synced label caught up once since start (the sync layer's word,
    /// `set_ephemeral_caught_up`): until then an own cover absorbs no earlier session's commit.
    pub caught_up: bool,
    /// Expiry times of held parts.
    pub timers: BTreeMap<u64, BTreeSet<(CommitId, usize)>>,
    /// Relay-only commits delivered, oldest first, with their `ts` (wall ms).
    pub delivered: VecDeque<(CommitId, u64, Tid)>,
    /// Per commit in `delivered`, the parts delivered (its projections go as several blobs).
    pub delivered_set: BTreeMap<CommitId, BTreeSet<usize>>,
    /// Per author, relay-only commits at or below this `ts` (wall ms) are dropped
    /// (`MAX_DELIVERED`; per author, so a writer flooding signals drops only its own).
    pub delivered_floor: BTreeMap<Tid, u64>,
    /// Aspects whose own delta did not fit a blob alone (a take or cover of it failed): their
    /// unsent writes wait, and a local write to one is refused unless the aspect's own state
    /// fits then (`check_full`), which clears it.
    pub full: BTreeSet<(Tid, Ak)>,
    /// `Core::generation` when held validity was last judged.
    pub judged_at: u64,
    /// Own presence aspects of things that sync, with the actor of their last write.
    pub presence: BTreeMap<(Tid, Ak), Tid>,
    /// Actors whose presence commit is due (a write, a keep-alive, a thing entering a closure).
    pub presence_dirty: BTreeSet<Tid>,
    /// Per actor, when its last presence commit was built (wall ms; keep-alive).
    pub presence_sent: BTreeMap<Tid, u64>,
    /// Held presence commits by the end of their lease (`ts + MAX_LEASE`).
    pub leases: BTreeMap<u64, BTreeSet<CommitId>>,
    /// Own writes, signals or keep-alives noted since the last `take_ephemeral_if` (what it held
    /// back goes when the sync layer's upload in flight is answered, not on a new local event).
    pub noted: bool,
}

impl Remote {
    /// Adds held commit `id`'s lists to `absorbers`.
    fn index_lists(&mut self, id: CommitId) {
        let Some(h) = self.held.get(&id) else { return };
        for c in h.parts.iter().flat_map(|p| p.absorbed.iter()) {
            self.absorbers.entry(*c).or_default().insert(id);
        }
    }

    /// Removes held commit `id`'s lists from `absorbers` (before they change or it goes).
    fn unindex_lists(&mut self, id: &CommitId) {
        let Some(h) = self.held.get(id) else { return };
        for c in h.parts.iter().flat_map(|p| p.absorbed.iter()) {
            if let Some(s) = self.absorbers.get_mut(c) {
                s.remove(id);
                if s.is_empty() {
                    self.absorbers.remove(c);
                }
            }
        }
    }

    /// Debug builds: `absorbers` is exactly what `held`'s lists say.
    fn check_index(&self) {
        if cfg!(debug_assertions) {
            let mut want: BTreeMap<CommitId, BTreeSet<CommitId>> = BTreeMap::new();
            for (id, h) in &self.held {
                for c in h.parts.iter().flat_map(|p| p.absorbed.iter()) {
                    want.entry(*c).or_default().insert(*id);
                }
            }
            debug_assert!(want == self.absorbers, "the absorbers index drifted from the held lists");
        }
    }

    /// The valid unexpiring parts of held commits of `h`'s author and class listing `id` as
    /// absorbed on aspect `on` of `h` (`h` held as `id`).
    fn listers(&self, id: &CommitId, h: &Header, on: &osis_commit::AspectEntry) -> Vec<PartId> {
        let mut out = Vec::new();
        for c in self.absorbers.get(id).into_iter().flatten() {
            let Some(x) = self.held.get(c).filter(|x| may_absorb(&x.header, h)) else { continue };
            for q in &x.parts {
                if q.valid && q.absorbed.contains(id) && x.header.aspects.get(q.ai).is_some_and(|a| a.expires.is_none() && a.tid == on.tid && a.ak == on.ak) {
                    out.push((*c, q.ai));
                }
            }
        }
        out
    }
}

/// A commit waiting for records (`Remote::pending`): every distinct copy of its signature and
/// parts not known to be junk is kept, since a copy cannot be checked before its record is here
/// (keeping the first copy let a junk one, the real header with junk parts, evict the real part).
pub(crate) struct Waiting {
    pub header: Header,
    /// Distinct signatures received (the author's record may not be here to check them).
    pub sigs: Vec<osis_crypto::Signature>,
    /// Distinct parts received: several per `(ai, di)` while their thing's record is missing.
    pub parts: Vec<osis_commit::Part>,
    /// The things whose records it waits for.
    pub needs: BTreeSet<Tid>,
    /// The most room a copy was given (`ingest_ephemeral_within`): what its retry may decode.
    pub room: u64,
}

/// Whether a cover `cover` may absorb `covered` (spec/sync.md §9): only its author's commits of
/// its class.
fn may_absorb(cover: &Header, covered: &Header) -> bool {
    cover.author == covered.author && cover.ephemeral == covered.ephemeral
}

/// What became of a received ephemeral commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EphIngest {
    /// Verified and held (new parts joined, or nothing new).
    Held { new: bool },
    /// A relay-only commit verified for the first time: its valid signals delivered (`fired`).
    Relayed { fired: bool },
    /// Waits for its author's record, a part's thing's record, or (every part invalid on
    /// arrival) a change of the held durable set; kept apart, `pending_ephemeral` (its parts
    /// verified meanwhile may be held: the blob as a whole is not checked yet).
    Pending,
    /// Not held: a relay-only duplicate or one outside its window, a commit more than
    /// `MAX_DRIFT` ahead, or a presence commit older than one held of its author and actor.
    Dropped,
    /// Not held: held commits of its author and class (these) contain it (`eph_containers`); a
    /// writer may delete its entry where it found it once they are there.
    Covered(BTreeSet<CommitId>),
    /// Not held nor kept apart: holding it could cost more than the room given
    /// (`ingest_ephemeral_within`), found before decoding past it.
    TooLarge,
}

/// An ephemeral commit built here: its ID, class and blob (header and parts).
#[derive(Clone, Debug)]
pub struct EphCommit {
    pub id: CommitId,
    pub class: EphClass,
    pub blob: CommitBlob,
}

impl Engine {
    /// Whether `tid` is in some labeled closure here: synced itself, or in a group that is, through
    /// either side of `/group`.
    pub fn ephemeral_synced(&self, tid: &Tid) -> bool {
        let s = &self.core.ix.syncing;
        s.contains(tid) || self.groups_of(tid).iter().any(|g| s.contains(g))
    }

    /// Whether `t` is in the closure of `g` (`Engine::closure` and the ephemeral things placed in
    /// it, transitively through the ephemeral side of `/group`), without walking it.
    pub fn in_ephemeral_closure(&self, g: &Tid, t: &Tid) -> bool {
        t == g || self.closure(g).contains(t) || self.groups_of(t).contains(g)
    }

    /// Whether own ephemeral writes or signals were noted since the last take, or a thing with
    /// ephemeral state entered a labeled closure (`take_ephemeral_if`).
    pub fn has_unsent(&self) -> bool {
        let r = &self.eph.remote;
        r.noted || r.local.iter().any(|t| self.ephemeral_synced(t))
    }

    /// Whether a local write of `delta` to `(tid, ak)` may go (spec/sync.md §9): refused only
    /// when an own delta of the aspect did not fit a blob (`Remote::full`) and its own state
    /// with `delta` still does not and is no smaller (a removal shrinking it goes, so it can be
    /// cut down step by step); `Some(true)` when it fits now (the caller clears the flag).
    pub(super) fn check_full(&self, tid: &Tid, ak: &Ak, delta: &Fragment) -> Option<bool> {
        if !self.eph.remote.full.contains(&(*tid, ak.clone())) {
            return Some(false);
        }
        let me = self.tid();
        let mut f = self.eph.aspects.get(tid).and_then(|m| m.get(ak)).map(|a| own_unexpiring(a, &self.eph.src)).unwrap_or_default();
        let before = delta_len(me, &f);
        f.join(delta.clone());
        let after = delta_len(me, &f);
        if fits_blob(after) {
            Some(true)
        } else {
            (after < before).then_some(false)
        }
    }

    /// Notes an own ephemeral write for sync: it joins `unsent` (a presence write marks its
    /// actor's presence commit due) when the thing syncs, else the thing waits in `local`.
    pub(super) fn note_written(&mut self, tid: &Tid, ak: &Ak, delta: &Fragment, expires: Option<u64>, presence: bool, actor: Tid) {
        if self.ephemeral_synced(tid) {
            let r = &mut self.eph.remote;
            r.noted = true;
            if presence {
                r.presence.insert((*tid, ak.clone()), actor);
                r.presence_dirty.insert(actor);
                return;
            }
            r.unsent.entry((*tid, ak.clone())).or_default().entry((actor, expires)).or_default().join(delta.clone());
        } else {
            self.eph.remote.local.insert(*tid);
        }
    }

    /// Notes an own signal write for sync (things in a labeled closure only).
    pub(super) fn note_signal(&mut self, tid: &Tid, ak: &Ak, v: &Value, ts: Ts, actor: Tid) {
        if self.ephemeral_synced(tid) {
            self.eph.remote.noted = true;
            self.eph.remote.signals.push((*tid, ak.clone(), v.clone(), ts, actor));
        }
    }

    /// Notes a new ephemeral thing: its record goes once it is in a labeled closure.
    pub(super) fn note_created(&mut self, tid: &Tid) {
        self.eph.remote.local.insert(*tid);
    }

    /// Builds the ephemeral commits of everything unsent (`take_ephemeral_if` holding nothing
    /// back).
    pub fn take_ephemeral(&mut self) -> Result<Vec<EphCommit>> {
        self.take_ephemeral_if(&BTreeSet::new(), &BTreeSet::new())
    }

    /// Builds the ephemeral commits of what is unsent: one relay-only commit per actor for the
    /// signals, one per actor and expiry for state (with the records of the ephemeral things they
    /// touch or place), and the whole own state of things that entered a labeled closure; the
    /// presence commits due. Each is held here. Held back (coalescing while the sync layer has an
    /// own ephemeral upload in flight, spec/sync.md §9): the plain writes of things in the closure
    /// of a group in `busy`, and the presence commits of the actors in `busy_presence`; they
    /// stay unsent, later writes join them (a presence commit carries the whole own state
    /// anyway), and they go with a later take. Signals are never held back.
    pub fn take_ephemeral_if(&mut self, busy: &BTreeSet<Tid>, busy_presence: &BTreeSet<Tid>) -> Result<Vec<EphCommit>> {
        self.eph.remote.noted = false;
        self.note_entered();
        let mut out = self.take_signals()?;
        let held_back = |e: &Engine, t: &Tid| busy.iter().any(|g| e.in_ephemeral_closure(g, t));
        let mut unsent = std::mem::take(&mut self.eph.remote.unsent);
        let full = &self.eph.remote.full;
        if !busy.is_empty() || !full.is_empty() {
            let (back, go): (BTreeMap<_, _>, BTreeMap<_, _>) = unsent.into_iter().partition(|(k, _)| full.contains(k) || held_back(self, &k.0));
            unsent = go;
            self.eph.remote.unsent = back;
        }
        let mut by_class: BTreeMap<(Tid, Option<u64>), Vec<EphDelta>> = BTreeMap::new();
        for ((tid, ak), m) in unsent {
            for ((actor, exp), f) in m {
                // an expiry already past: those writes are gone
                if exp.is_some_and(|t| t <= self.now().0) {
                    continue;
                }
                by_class.entry((actor, exp)).or_default().push((tid, ak.clone(), f, exp));
            }
        }
        for ((actor, _), deltas) in by_class {
            let mut left = Vec::new();
            self.build_fitting(actor, deltas, &BTreeMap::new(), &mut out, &mut left)?;
            // what could not be built stays unsent (a later cover or take may carry it); one
            // past a blob waits until a write makes it fit (`Remote::full`)
            for ((tid, ak, f, exp), large) in left {
                if large {
                    self.eph.remote.full.insert((tid, ak.clone()));
                }
                self.eph.remote.unsent.entry((tid, ak)).or_default().entry((actor, exp)).or_default().join(f);
            }
        }
        out.extend(self.take_presence(busy_presence)?);
        Ok(out)
    }

    /// Things with ephemeral state that entered a labeled closure: their own state (without
    /// expiring writes) joins `unsent`, their presence aspects make this node's presence due.
    fn note_entered(&mut self) {
        let entered: Vec<Tid> = self.eph.remote.local.iter().filter(|t| self.ephemeral_synced(t)).copied().collect();
        let me = self.tid();
        for t in entered {
            self.eph.remote.local.remove(&t);
            let src = &self.eph.src;
            // `None`: only expiring or expired writes (`unsent` has the former), whose records
            // `own_unexpiring` keeps value-less; a part of those would carry the thing's record
            // past their expiry
            let aspects: Vec<(Ak, Option<Fragment>, bool)> = self
                .eph
                .aspects
                .get(&t)
                .map(|m| m.iter().map(|(ak, a)| (ak.clone(), Some(own_unexpiring(a, src)).filter(|f| f.holds_dots(&|d| !in_ranges(d, src, &a.expired) && !a.expiring.values().any(|r| in_ranges(d, src, r)))), a.presence)).collect())
                .unwrap_or_default();
            let r = &mut self.eph.remote;
            for (ak, f, presence) in aspects {
                if presence {
                    r.presence.entry((t, ak)).or_insert(me);
                    r.presence_dirty.insert(me);
                } else if let Some(f) = f {
                    r.unsent.entry((t, ak)).or_default().entry((me, None)).or_default().join(f);
                }
            }
        }
    }

    /// The relay-only commits of the unsent signal writes: one per actor.
    fn take_signals(&mut self) -> Result<Vec<EphCommit>> {
        let mut by_actor: BTreeMap<Tid, Vec<EphDelta>> = BTreeMap::new();
        for (tid, ak, v, ts, actor) in std::mem::take(&mut self.eph.remote.signals) {
            let w = Writer::new(ts, self.eph.src.clone(), self.eph.ctr(&tid, &ak));
            if let Ok(Some((f, r))) = run_ops(&Fragment::default(), w, &[PathOp { path: Vec::new(), op: Op::Set(v) }], &AnyView) {
                self.eph.take_ctrs(&tid, &ak, r.hi);
                by_actor.entry(actor).or_default().push((tid, ak, f, None));
            }
        }
        let mut out = Vec::new();
        for (actor, deltas) in by_actor {
            out.extend(self.build_ephemeral(EphClass::Relay, actor, deltas, &BTreeMap::new())?);
        }
        Ok(out)
    }

    /// The own writes of `(t, ak)` alone (others' held parts left out).
    fn own_state(&self, t: &Tid, ak: &Ak) -> Option<Fragment> {
        Some(self.eph.aspects.get(t)?.get(ak)?.own_writes().clone())
    }

    /// Builds the due presence commits: per actor, one carrying this node's own state of every
    /// presence aspect last written for that actor (of things that sync), absorbing the presence
    /// commits this node authored for that actor before, so a holder keeps one per author.
    /// Actors in `busy` stay due.
    fn take_presence(&mut self, busy: &BTreeSet<Tid>) -> Result<Vec<EphCommit>> {
        let mut out = Vec::new();
        let (back, dirty): (BTreeSet<Tid>, BTreeSet<Tid>) = std::mem::take(&mut self.eph.remote.presence_dirty).into_iter().partition(|a| busy.contains(a));
        self.eph.remote.presence_dirty = back;
        if dirty.is_empty() {
            return Ok(out);
        }
        // a thing that left every labeled closure: its presence goes again when it enters one
        let left: Vec<(Tid, Ak)> = self.eph.remote.presence.keys().filter(|(t, _)| !self.ephemeral_synced(t)).cloned().collect();
        for (t, ak) in left {
            self.eph.remote.presence.remove(&(t, ak));
            self.eph.remote.local.insert(t);
        }
        let me = self.tid();
        let now = self.now().0;
        for actor in dirty {
            let keys: Vec<(Tid, Ak)> = self.eph.remote.presence.iter().filter(|(_, a)| **a == actor).map(|(k, _)| k.clone()).collect();
            // an aspect this node never wrote (it entered a closure holding others' presence
            // only) adds nothing: a commit of none of its own writes would be an entry for nobody
            let deltas: Vec<EphDelta> = keys.iter().filter_map(|(t, ak)| self.own_state(t, ak).filter(|f| !f.writes().is_empty()).map(|f| (*t, ak.clone(), f, None))).collect();
            if deltas.is_empty() {
                self.eph.remote.presence_sent.remove(&actor);
                continue;
            }
            let mut absorbed = Absorbs::new();
            for (id, h) in &self.eph.remote.held {
                if h.header.ephemeral == Some(EphClass::Presence) && h.header.author == me && h.header.actor == actor {
                    for a in h.parts.iter().filter_map(|p| h.header.aspects.get(p.ai)) {
                        absorbed.entry((a.tid, a.ak.clone())).or_default().insert(*id);
                    }
                }
            }
            out.extend(self.build_ephemeral(EphClass::Presence, actor, deltas, &absorbed)?);
            self.eph.remote.presence_sent.insert(actor, now);
        }
        Ok(out)
    }

    /// Keep-alives due by `now`: an actor with live own presence values gets a fresh presence
    /// commit (its lease starts over); one without stops being refreshed. Held presence commits
    /// past their lease go (un-merged).
    pub(super) fn tick_presence(&mut self, now: u64) {
        let due: Vec<Tid> = self.eph.remote.presence_sent.iter().filter(|(_, t)| t.saturating_add(KEEPALIVE_MS) <= now).map(|(a, _)| *a).collect();
        for actor in due {
            let live = self.eph.remote.presence.iter().filter(|(_, a)| **a == actor).any(|((t, ak), _)| self.own_state(t, ak).is_some_and(|f| f.present()));
            if live {
                self.eph.remote.presence_dirty.insert(actor);
                self.eph.remote.noted = true;
                // not again until it was sent
                self.eph.remote.presence_sent.insert(actor, now);
            } else {
                self.eph.remote.presence_sent.remove(&actor);
            }
        }
        while let Some(entry) = self.eph.remote.leases.first_entry() {
            if *entry.key() > now {
                break;
            }
            for id in entry.remove() {
                self.drop_ephemeral_presence(&id);
            }
        }
    }

    /// Drops held presence commit `id` (its lease ended, or no server or peer the sync layer syncs
    /// its labels with holds it any longer, spec/sync.md §9): its writes go (un-merge, the aspects
    /// rebuilt from the own writes and the other valid held parts, spec/crdt.md §4.6); queued for
    /// `take_dropped_ephemeral`. A remote change naming the commit fires for what it changed.
    pub fn drop_ephemeral_presence(&mut self, id: &CommitId) {
        let Some(h) = self.eph.remote.held.get(id) else { return };
        if h.header.ephemeral != Some(EphClass::Presence) {
            return;
        }
        let header = h.header.clone();
        let own = h.own;
        let aspects: Vec<(Tid, Ak)> = h.parts.iter().filter_map(|p| header.aspects.get(p.ai)).filter(|a| a.ak.as_str() != CREATED.ak()).map(|a| (a.tid, a.ak.clone())).collect();
        let recs = self.carried_tids(id);
        self.forget_held(id);
        let mut changed = Vec::new();
        for (t, ak) in aspects {
            let before = self.eph.state(&t, &ak).cloned();
            self.rebuild_aspect(&t, &ak);
            if self.eph.state(&t, &ak) != before.as_ref() {
                changed.push((t, ak));
            }
        }
        self.free_unused_records(recs);
        if !changed.is_empty() && !own {
            let received = self.now();
            self.core.events.queue(Event::Ephemeral { id: ChangeId::Commit(*id), origin: Origin::Remote, author: header.author, actor: header.actor, ts: header.ts, received, changed, signals: Vec::new() });
            self.core.events.flush();
        }
    }

    /// The valid held commits listing `id` as absorbed (the covers that took it in: several
    /// when an own cover was split by aspect, spec/sync.md §9).
    pub fn ephemeral_absorbers(&self, id: &CommitId) -> BTreeSet<CommitId> {
        let r = &self.eph.remote;
        r.absorbers.get(id).into_iter().flatten().filter(|c| r.held.get(c).is_some_and(|h| h.parts.iter().any(|p| p.valid && p.absorbed.contains(id)))).copied().collect()
    }

    /// Whether held ephemeral commit `id` is a presence commit.
    pub fn ephemeral_is_presence(&self, id: &CommitId) -> bool {
        self.eph.remote.held.get(id).is_some_and(|h| h.header.ephemeral == Some(EphClass::Presence))
    }

    /// The `/created` fragment of ephemeral thing `t`: a register write of its record under the
    /// session source, minted once.
    fn created_fragment(&mut self, t: &Tid) -> Option<Fragment> {
        let th = self.eph.things.get(t)?;
        if let Some(f) = &th.created {
            return Some(f.clone());
        }
        let cak = Ak::new(CREATED.ak()).ok()?;
        let (f, hi) = mint_created(&th.record, th.ts, self.eph.src.clone(), self.eph.ctr(t, &cak))?;
        self.eph.take_ctrs(t, &cak, hi);
        if let Some(th) = self.eph.things.get_mut(t) {
            th.created = Some(f.clone());
        }
        Some(f)
    }

    /// The ephemeral things of `recs` up their ephemeral owner chains: the things whose records
    /// (`/created`) an ephemeral commit about `recs` carries.
    fn record_chain(&self, recs: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        let mut chain: BTreeSet<Tid> = BTreeSet::new();
        for t in recs {
            let mut cur = *t;
            for _ in 0..=MAX_OWNER_DEPTH {
                let Some(th) = self.eph.things.get(&cur) else { break };
                if self.core.created(&cur).is_some() || !chain.insert(cur) {
                    break;
                }
                match &th.record {
                    CreationRecord::Thing { owner, .. } => cur = *owner,
                    CreationRecord::KeyActor { .. } => break,
                }
            }
        }
        chain
    }

    /// Builds, signs and holds one ephemeral commit of `deltas` (thing, aspect, fragment,
    /// expiry), carrying the records of the ephemeral things the deltas touch and of those its
    /// `/group` deltas place, with their ephemeral owner chains; `absorbed`: per aspect, the held
    /// commits it covers. Writes but this node's sessions' are not carried. `None` when it
    /// would carry nothing or cannot be built (a delete key not held: reported).
    fn build_ephemeral(&mut self, class: EphClass, actor: Tid, deltas: Vec<EphDelta>, absorbed: &Absorbs) -> Result<Option<EphCommit>> {
        self.build_ephemeral_with(class, actor, deltas, absorbed, false)
    }

    /// Builds plain ephemeral commits of `deltas` (`build_ephemeral`): one, or, while a commit's
    /// header lists do not fit inline or a delta does not fit a blob, the halves of its deltas
    /// (in aspect order) apart, each listing as absorbed what `absorbed` names on its own
    /// aspects (spec/sync.md §9). The commits go to `out`; the deltas that could not be built to
    /// `left`, each flagged when it does not fit a blob alone (reported).
    fn build_fitting(&mut self, actor: Tid, deltas: Vec<EphDelta>, absorbed: &Absorbs, out: &mut Vec<EphCommit>, left: &mut Vec<(EphDelta, bool)>) -> Result<()> {
        let mut copy = deltas.clone();
        match self.try_build(EphClass::Plain, actor, deltas, absorbed, false)? {
            Attempt::Made(c) => out.push(*c),
            Attempt::Empty => {}
            Attempt::Large if copy.len() > 1 => {
                let rest = copy.split_off(copy.len() / 2);
                self.build_fitting(actor, copy, absorbed, out, left)?;
                self.build_fitting(actor, rest, absorbed, out, left)?;
            }
            Attempt::Large => {
                let tids = copy.iter().map(|d| d.0).collect();
                self.report(crate::events::Diagnostic { kind: crate::events::DiagnosticKind::EphemeralRefused, tids, commit: None, peer: None, detail: "an ephemeral delta does not fit a blob: not sent".into() });
                left.extend(copy.into_iter().map(|d| (d, true)));
            }
            Attempt::Failed => left.extend(copy.into_iter().map(|d| (d, false))),
        }
        Ok(())
    }

    /// `build_ephemeral`, with `carry_all` also carrying the writes not this node's sessions'
    /// (tests: forging).
    fn build_ephemeral_with(&mut self, class: EphClass, actor: Tid, deltas: Vec<EphDelta>, absorbed: &Absorbs, carry_all: bool) -> Result<Option<EphCommit>> {
        Ok(match self.try_build(class, actor, deltas, absorbed, carry_all)? {
            Attempt::Made(c) => Some(*c),
            Attempt::Large => {
                self.report_eph("an ephemeral commit too large for a blob or inline header lists was not sent");
                None
            }
            Attempt::Empty | Attempt::Failed => None,
        })
    }

    /// One attempt of `build_ephemeral_with` (a failure other than size reported here).
    fn try_build(&mut self, class: EphClass, actor: Tid, deltas: Vec<EphDelta>, absorbed: &Absorbs, carry_all: bool) -> Result<Attempt> {
        let me = self.tid();
        // the records: of the things written and placed, up their ephemeral chains
        let mut recs: BTreeSet<Tid> = BTreeSet::new();
        for (t, ak, f, _) in &deltas {
            recs.insert(*t);
            if ak.as_str() == PLACED.ak()
                && let Some((items, subs)) = super::place::def_of(f)
            {
                recs.extend(items);
                recs.extend(subs);
            }
        }
        recs.retain(|t| self.eph.things.contains_key(t));
        let chain = self.record_chain(&recs);
        // a record left in (an own cover's join of what its commits carried, of a thing durable or
        // gone here now) goes as one minting: the copies can differ (a minter that sent two, a
        // restart between first sights) and receivers refuse a join
        let mut parts: Vec<EphDelta> = deltas
            .into_iter()
            .filter(|(t, ak, _, _)| !(chain.contains(t) && ak.as_str() == CREATED.ak()))
            .filter_map(|(t, ak, f, e)| if ak.as_str() == CREATED.ak() { one_minting(&f).map(|f| (t, ak, f, e)) } else { Some((t, ak, f, e)) })
            .collect();
        let cak = Ak::new(CREATED.ak()).map_err(|_| Error::Misuse("ak"))?;
        for t in &chain {
            if let Some(f) = self.created_fragment(t) {
                parts.push((*t, cak.clone(), f, None));
            }
        }
        if parts.is_empty() {
            return Ok(Attempt::Empty);
        }
        let ts = self.core.hlc.next();
        let creates: Creates = chain.iter().filter_map(|t| self.eph.things.get(t).map(|th| (*t, th.record.clone()))).collect();
        let cx = snapshot_ctx(ts, me);
        let mut writes = Vec::with_capacity(parts.len());
        for (tid, ak, mut fragment, expires) in parts {
            // only own writes are carried (spec/sync.md §9: receivers strip the rest), and records
            // whoever minted them (a record hashes to its tid)
            if !carry_all && ak.as_str() != CREATED.ak() && fragment.holds_dots(&|d| !own_session(d, me)) {
                fragment.strip_copies(&|d| !own_session(d, me));
                // what is left only for a join (an entry's creation alone) goes before encoding
                fragment.prune(None, &mut osis_crdt::Changes::new());
            }
            let absorbed_here: BTreeMap<CommitId, Tid> = absorbed.get(&(tid, ak.clone())).into_iter().flatten().filter_map(|c| self.eph.remote.held.get(c).map(|h| (*c, h.header.author))).collect();
            let mut nonce = [0u8; osis_crdt::NONCE_LEN];
            self.rng.fill_bytes(&mut nonce);
            let bytes = match osis_crdt::encode_snapshot(&Snapshot { nonce, fragment, frontiers: Frontiers::default(), absorbed: absorbed_here }, &cx, Some(&mut Unpaged)) {
                Ok(b) => b,
                Err(e) => {
                    self.report_eph(&format!("an ephemeral commit could not be built: {e}"));
                    return Ok(Attempt::Failed);
                }
            };
            let retention = osis_schema::Retention { by: osis_schema::PurgeBy::Writer, ..Default::default() };
            writes.push(AspectWrite { tid, ak, lo: 0, hi: 0, deltas: vec![bytes], retention, expires, schema: None, chunks: Vec::new() });
        }
        let things: Vec<Tid> = writes.iter().map(|w| w.tid).collect();
        let published = self.run(|tx| published_keys(tx, &creates, things))?;
        let mut b = CommitBuilder::new(Kind::ContentSnapshot, ts, me, actor, Form::Commit);
        b.aspects = writes;
        b.ephemeral = Some(class);
        let built = {
            let secrets = CommitSecrets { core: &self.core, actor, created: &creates, published: &published };
            let mut sink = MemoryBlobs::default();
            b.build(&self.core.id.keys().signing, &secrets, &mut sink, &mut *self.rng)
        };
        let built = match built {
            Ok(b) if b.list_blobs.is_empty() => b,
            // header lists past the inline bound (ephemeral commits link none) or a delta past
            // a blob (ephemeral deltas are not paged)
            Ok(_) | Err(osis_commit::Error::Build(DELTA_PAST_BLOB)) => return Ok(Attempt::Large),
            Err(e) => {
                self.report_eph(&format!("an ephemeral commit could not be built: {e}"));
                return Ok(Attempt::Failed);
            }
        };
        let blob = built.commit;
        let id = blob.id();
        if class != EphClass::Relay {
            let mut interner = Interner::new();
            let mut held_parts = Vec::new();
            let header = Arc::new(blob.header.clone());
            for p in &blob.parts {
                let cx = osis_commit::delta_ctx(&blob.header, &id, p.ai, &mut interner)?;
                let s = osis_crdt::decode_snapshot(&p.delta, &cx, &mut interner, Some(&mut Unpaged))?;
                // own parts are valid
                held_parts.push(HeldPart::new(p.ai, s, p.delta.len()));
            }
            let bytes = held_parts.iter().map(|p| p.bytes).sum();
            self.eph.remote.held.insert(id, Held { header, parts: held_parts, own: true, bytes });
            self.eph.remote.index_lists(id);
            let presence = class == EphClass::Presence;
            if presence {
                self.eph.remote.leases.entry(ts.wall_ms().0.saturating_add(MAX_LEASE_MS)).or_default().insert(id);
            }
            for (i, a) in blob.header.aspects.iter().enumerate() {
                if let Some(t) = a.expires {
                    self.eph.remote.timers.entry(t).or_default().insert((id, i));
                }
                let ea = self.eph.aspects.entry(a.tid).or_default().entry(a.ak.clone()).or_default();
                ea.parts.insert((id, i));
                ea.presence |= presence && a.ak.as_str() != CREATED.ak();
            }
            if !absorbed.is_empty() {
                self.drop_absorbed_of(absorbed.values().flatten().copied().collect());
            }
        }
        Ok(Attempt::Made(Box::new(EphCommit { id, class, blob })))
    }

    /// The cost of an own cover of `deltas`: each encoded delta (unpaged, with its `Sources`,
    /// which dominate small values) as a part (`part_weight`), plus `ENTRY_CHARGE`. Each lists one commit absorbed, as the
    /// next cover will (the cover itself: what it absorbs now goes with the next one), so a held
    /// cover weighs what its own cover would.
    fn cover_cost(&self, deltas: &[EphDelta]) -> usize {
        let me = self.tid();
        let ts = Ts::make(self.now(), 0).unwrap_or_default();
        let cx = snapshot_ctx(ts, me);
        let weight: usize = deltas
            .iter()
            .map(|(_, _, f, _)| {
                let absorbed = BTreeMap::from([(CommitId([0; 32]), me)]);
                let s = Snapshot { nonce: [0; osis_crdt::NONCE_LEN], fragment: f.clone(), frontiers: Frontiers::default(), absorbed };
                // unpaged encoding fails only on a malformed fragment: counted as nothing
                part_weight(osis_crdt::encode_snapshot(&s, &cx, Some(&mut Unpaged)).map_or(0, |b| b.len()))
            })
            .sum();
        weight + ENTRY_CHARGE
    }

    fn report_eph(&mut self, detail: &str) {
        self.report(crate::events::Diagnostic { kind: crate::events::DiagnosticKind::EphemeralRefused, tids: Vec::new(), commit: None, peer: None, detail: detail.into() });
    }

    /// The record of `t` as known here: durable, ephemeral, or carried by `carried`.
    fn record_of<'a>(&'a self, t: &Tid, carried: &'a BTreeMap<Tid, CreationRecord>) -> Option<&'a CreationRecord> {
        self.core.created(t).or_else(|| self.eph.things.get(t).map(|e| &e.record)).or_else(|| carried.get(t))
    }

    /// Whether part `ai` of ephemeral commit `h` is valid here (spec/permissions.md §5.2): judged
    /// as its author's snapshot delta at its `ts`, by commit ID. Membership-class aspects and
    /// the other core aspects but `/group` (spec/data-model.md §8) take no ephemeral part;
    /// `/created` is always valid (it must hash to its tid).
    fn eph_part_valid(&self, h: &Header, id: &CommitId, ai: usize, carried: &BTreeMap<Tid, CreationRecord>) -> bool {
        let Some(a) = h.aspects.get(ai) else { return false };
        let ak = a.ak.as_str();
        if ak == CREATED.ak() {
            return true;
        }
        if is_membership_class(ak) || (is_core_aspect(ak) && ak != PLACED.ak()) {
            return false;
        }
        self.eph_write_valid(&a.tid, ak, h.author, h.ts, id, carried)
    }

    /// Whether a write on `(tid, ak)` by `node` at `ts`, judged by commit ID `commit`, is valid
    /// here (spec/permissions.md §5.2); on an ephemeral thing, as a write on a new thing owned
    /// by its nearest durable thing (spec/permissions.md §1), an ephemeral owner that is `node`
    /// making it valid. Unknown records count as invalid until they arrive.
    fn eph_write_valid(&self, tid: &Tid, ak: &str, node: Tid, ts: Ts, commit: &CommitId, carried: &BTreeMap<Tid, CreationRecord>) -> bool {
        let mut cur = *tid;
        for _ in 0..=MAX_OWNER_DEPTH {
            if self.core.created(&cur).is_some() {
                if crate::apply::validity::too_deep(&self.core, &cur) {
                    return false;
                }
                let Some(tl) = self.core.timelines.get(&cur) else { return false };
                let point = Point { ts, node, commit: *commit };
                return tl.delta_valid(point, &cur, ak, Dots::Commit, required_role(ak)) == Validity::Valid;
            }
            match self.record_of(&cur, carried) {
                Some(CreationRecord::Thing { owner, .. }) if *owner == node => return true,
                Some(CreationRecord::Thing { owner, .. }) => cur = *owner,
                Some(CreationRecord::KeyActor { .. }) => return cur == node,
                None => return false,
            }
        }
        false
    }

    /// The held commits that make received commit `id` redundant, when on each of its parts
    /// `parts` but `/created` ones (one at least, none expiring) a valid unexpiring part of one
    /// held plain commit of its author contains the part's writes (`contains`) and either lists
    /// `id` as absorbed or, when `id` lists nothing (a take, not a cover), is a cover stamped
    /// later. A cover's chain contains whatever an earlier cover took in, so a replayed take
    /// from any depth is caught without transitive lists; a commit missing from a cover (its
    /// author did not hold it then) is not. Stamps do not order an author's sessions (a session
    /// after a restart may stamp below the last one's covers), so a cover is redundant only by a
    /// list: lists form no cycle, and two covers of equal content each taking the other for the
    /// later one would both be deleted at servers.
    fn eph_containers(&self, id: &CommitId, h: &Header, parts: &[HeldPart]) -> Option<BTreeSet<CommitId>> {
        if h.ephemeral != Some(EphClass::Plain) {
            return None;
        }
        let take = parts.iter().all(|p| p.absorbed.is_empty());
        let mut by = BTreeSet::new();
        for p in parts {
            let a = h.aspects.get(p.ai)?;
            if a.ak.as_str() == CREATED.ak() {
                continue;
            }
            if a.expires.is_some() {
                return None;
            }
            if !take {
                // only a cover listing it: the index names those
                let r = &self.eph.remote;
                let found = r.listers(id, h, a).into_iter().find(|(c, ai)| c != id && r.held.get(c).and_then(|x| x.parts.iter().find(|q| q.ai == *ai)).is_some_and(|q| contains(&q.fragment, &p.fragment)));
                by.insert(found?.0);
                continue;
            }
            let ea = self.eph.aspects.get(&a.tid).and_then(|m| m.get(&a.ak))?;
            let found = ea.parts.iter().find_map(|(c, ai)| {
                let x = self.eph.remote.held.get(c).filter(|x| c != id && may_absorb(&x.header, h))?;
                let q = x.parts.iter().find(|q| q.ai == *ai && q.valid)?;
                let later = !q.absorbed.is_empty() && x.header.ts > h.ts;
                let fits = x.header.aspects.get(*ai).is_some_and(|xa| xa.expires.is_none()) && (later || q.absorbed.contains(id));
                (fits && contains(&q.fragment, &p.fragment)).then_some(*c)
            });
            by.insert(found?);
        }
        (!by.is_empty()).then_some(by)
    }

    /// Receives an ephemeral commit blob (verified here; the blob's prefix was checked by the
    /// caller). Bad input is an error.
    pub fn ingest_ephemeral(&mut self, blob: CommitBlob) -> Result<EphIngest> {
        self.ingest_ephemeral_within(blob, true, u64::MAX)
    }

    /// `ingest_ephemeral`; `may_wait` false: a blob that would wait (`Pending`) is not kept
    /// apart nor any part of it held (the sync layer has no room for it), so what already waits
    /// stays as it was. A
    /// blob with a part that waits is `Pending` even when its other parts were verified and
    /// held: the blob is not fully checked, so it is neither kept nor spread until it is.
    /// `room`: what holding it may cost, as `ephemeral_charge` counts it; each part is decoded
    /// only while what the parts before it cost decoded and its own bound (`part_bound`) fit, so
    /// nothing is decoded past it (`TooLarge`: nothing of it held or kept apart). A blob kept
    /// apart is retried within the most room a copy of it was given.
    pub fn ingest_ephemeral_within(&mut self, blob: CommitBlob, may_wait: bool, room: u64) -> Result<EphIngest> {
        let id = blob.id();
        let h = blob.header.clone();
        let Some(class) = h.ephemeral else { return Err(Error::BadInput("not an ephemeral commit")) };
        let now = self.now().0;
        let at = h.ts.wall_ms().0;
        let first = !self.eph.remote.held.contains_key(&id);
        if class == EphClass::Relay {
            // its only replay window (notes/ephemeral.md Signals)
            let r = &self.eph.remote;
            if r.delivered_set.get(&id).is_some_and(|d| blob.parts.iter().all(|p| d.contains(&p.ai))) || r.delivered_floor.get(&h.author).is_some_and(|f| at <= *f) || at.saturating_add(MAX_DRIFT_MS) < now || at > now.saturating_add(MAX_DRIFT_MS) {
                return Ok(EphIngest::Dropped);
            }
        } else {
            // not held, nor spread (spec/sync.md §9); a presence commit past its lease neither
            if at > now.saturating_add(MAX_DRIFT_MS) || (class == EphClass::Presence && at.saturating_add(MAX_LEASE_MS) <= now) {
                return Ok(EphIngest::Dropped);
            }
            if let Some(held) = self.eph.remote.held.get(&id) {
                let have: BTreeSet<usize> = held.parts.iter().map(|p| p.ai).collect();
                if blob.parts.iter().all(|p| have.contains(&p.ai)) {
                    // another blob of a held commit: its signature and deltas are checked
                    // still, or a forged blob (the header with junk parts) would be kept and
                    // served on as this commit's
                    self.check_copy(&blob)?;
                    return Ok(EphIngest::Held { new: false });
                }
            } else {
                // a presence commit stands for its author's whole presence state for its actor:
                // an older one than the newest held is not held (the ID commits to the header)
                if class == EphClass::Presence && self.newer_presence(&h, &id) {
                    return Ok(EphIngest::Dropped);
                }
                if !live_parts(&h, now) {
                    // expired but for its records: nothing of it is held
                    return Ok(EphIngest::Dropped);
                }
            }
        }
        let author = match self.core.created(&h.author) {
            Some(CreationRecord::KeyActor { public_key, .. }) => VerifyingKey::from_slice(public_key)?,
            Some(_) => return Err(Error::BadInput("author is not a key actor")),
            None => {
                if class == EphClass::Relay {
                    return Ok(EphIngest::Dropped);
                }
                if may_wait {
                    self.wait_apart(id, blob, BTreeSet::from([h.author]), room);
                }
                return Ok(EphIngest::Pending);
            }
        };
        osis_commit::verify_signature(&id, &blob.signature, &author)?;
        h.validate()?;
        // what each part could cost decoded, from its bytes alone: none is decoded past `room`
        let bounds: Vec<u64> = blob.parts.iter().map(part_bound).collect::<Result<_>>()?;
        let created = |p: &osis_commit::Part| h.aspects.get(p.ai).is_some_and(|a| a.ak.as_str() == CREATED.ak());
        if blob.parts.iter().zip(&bounds).any(|(p, b)| created(p) && *b > room) {
            return Ok(EphIngest::TooLarge);
        }
        // records the commit carries (their parts are decoded first: a thing's dedup secret
        // comes from its record)
        let mut interner = Interner::new();
        let carried = carried_records(&blob, &id, &mut interner)?;
        let mut decoded = Vec::with_capacity(blob.parts.len());
        let mut spent = 0u64;
        // a part on a thing whose record is not here yet waits (`retry_waiting`: decoded then,
        // within the room given now)
        let mut waits: BTreeSet<Tid> = BTreeSet::new();
        for (p, bound) in blob.parts.iter().zip(&bounds) {
            let Some(a) = h.aspects.get(p.ai) else { continue };
            let Some(rec) = self.record_of(&a.tid, &carried) else {
                waits.insert(a.tid);
                continue;
            };
            if spent.saturating_add(*bound) > room {
                return Ok(EphIngest::TooLarge);
            }
            let dedup = dedup_secret(rec.nonce());
            match osis_commit::verify_part(&h, &id, p, &dedup, &mut interner, Some(&mut Unpaged))? {
                osis_commit::Decoded::Snapshot(s) => {
                    spent = spent.saturating_add(part_charge(s.fragment.approx_bytes(), p.delta.len()));
                    decoded.push((p.ai, s, p.delta.len()));
                }
                osis_commit::Decoded::Delta(_) => return Err(Error::BadInput("ephemeral commit with a writer delta")),
            }
        }
        if class == EphClass::Relay {
            return Ok(self.deliver_relay(id, &h, decoded, &carried, now));
        }
        // its new parts, judged (spec/permissions.md §5.2), others' writes stripped
        let (have, own): (BTreeSet<usize>, bool) = self.eph.remote.held.get(&id).map_or((BTreeSet::new(), false), |x| (x.parts.iter().map(|p| p.ai).collect(), x.own));
        let mut fresh: Vec<HeldPart> = Vec::new();
        for (ai, s, len) in decoded {
            if have.contains(&ai) || fresh.iter().any(|p| p.ai == ai) {
                continue;
            }
            let Some(a) = h.aspects.get(ai) else { continue };
            if a.expires.is_some_and(|t| t <= now) {
                continue;
            }
            let mut hp = HeldPart::new(ai, s, len);
            if a.ak.as_str() != CREATED.ak() {
                hp.only_of(h.author);
            }
            hp.valid = own || self.eph_part_valid(&h, &id, ai, &carried);
            fresh.push(hp);
        }
        let is_content = |p: &HeldPart| h.aspects.get(p.ai).is_some_and(|a| a.ak.as_str() != CREATED.ak());
        if !waits.is_empty() && (!may_wait || !fresh.iter().any(is_content)) {
            // nothing of it checked but records: it waits whole (holding it would keep and spread
            // a blob none of whose parts was verified); with no room to wait, nothing of it is
            // held either (its verified parts would be held uncounted: the sync layer keeps no
            // entry for it)
            if may_wait {
                self.wait_apart(id, blob, waits, room);
            }
            return Ok(EphIngest::Pending);
        }
        if first {
            // contained in held commits of its author (a replay of what a cover took in, at any
            // depth): not held (spec/sync.md §9)
            if waits.is_empty()
                && let Some(by) = self.eph_containers(&id, &h, &fresh)
            {
                return Ok(EphIngest::Covered(by));
            }
            // every part invalid on arrival: neither held nor counted until the held durable set
            // changes so that one is valid (`rejudge_ephemeral`)
            let content: Vec<usize> = fresh.iter().filter(|p| is_content(p)).map(|p| p.ai).collect();
            if !content.is_empty() && fresh.iter().all(|p| !p.valid || !content.contains(&p.ai)) {
                if !may_wait {
                    return Ok(EphIngest::Pending);
                }
                if !waits.is_empty() {
                    // judged again once those records are here
                    self.wait_apart(id, blob, waits, room);
                    return Ok(EphIngest::Pending);
                }
                match self.eph.remote.invalid.get_mut(&id) {
                    Some(x) => {
                        let mut more = blob.parts;
                        more.retain(|p| !x.blob.parts.iter().any(|q| (q.ai, q.di) == (p.ai, p.di)));
                        x.blob.parts.extend(more);
                        x.ais.extend(content);
                        x.carried.extend(carried);
                        x.room = x.room.max(room);
                    }
                    None => {
                        self.eph.remote.invalid.insert(id, Invalid { blob, ais: content, carried, room });
                    }
                }
                return Ok(EphIngest::Pending);
            }
        }
        // the records of ephemeral things it brings
        let received = self.now();
        for (t, rec) in &carried {
            if self.core.created(t).is_none() && !self.eph.things.contains_key(t) {
                let created = fresh.iter().find(|p| h.aspects.get(p.ai).is_some_and(|a| a.tid == *t && a.ak.as_str() == CREATED.ak())).map(|p| p.fragment.clone());
                self.eph.things.insert(*t, EphThing { record: rec.clone(), ts: h.ts, node: h.author, actor: h.actor, received, created, deleted: false });
                self.eph.records += 1;
            }
        }
        let header = Arc::new(h);
        let presence = class == EphClass::Presence;
        if presence && first {
            self.eph.remote.leases.entry(at.saturating_add(MAX_LEASE_MS)).or_default().insert(id);
        }
        // another blob of a held commit: an own one stays own
        self.eph.remote.unindex_lists(&id);
        let mut parts = self.eph.remote.held.remove(&id).map_or(Vec::new(), |x| x.parts);
        let mut changed = Vec::new();
        for hp in &fresh {
            let Some(a) = header.aspects.get(hp.ai) else { continue };
            if let Some(t) = a.expires {
                self.eph.remote.timers.entry(t).or_default().insert((id, hp.ai));
            }
            let counted = hp.counted();
            let src = self.eph.src.clone();
            let ea = self.eph.aspects.entry(a.tid).or_default().entry(a.ak.clone()).or_default();
            ea.parts.insert((id, hp.ai));
            ea.presence |= presence && a.ak.as_str() != CREATED.ak();
            if let Some(f) = counted
                && a.ak.as_str() != CREATED.ak()
            {
                if ea.own.is_none() {
                    ea.own = Some(ea.state.clone());
                }
                ea.state.join(f);
                strip_own_expired(ea, &src);
                if a.ak.as_str() == PLACED.ak() {
                    let (t, ak) = (a.tid, a.ak.clone());
                    self.refresh_def(&t, &ak);
                }
                changed.push((a.tid, a.ak.clone()));
            }
        }
        parts.extend(fresh);
        let bytes = parts.iter().map(|p| p.bytes).sum();
        let new = !changed.is_empty();
        // what it lists, and itself when held commits list it, are weighed for dropping
        let mut weigh: BTreeSet<CommitId> = parts.iter().flat_map(|p| p.absorbed.iter().copied()).collect();
        if self.eph.remote.absorbers.contains_key(&id) {
            weigh.insert(id);
        }
        self.eph.remote.held.insert(id, Held { header: header.clone(), parts, own, bytes });
        self.eph.remote.index_lists(id);
        // a part waits: its verified parts are held, the blob waits for the rest (another blob of
        // this commit may wait too: a commit past a blob splits)
        let waiting = !waits.is_empty();
        if waiting && may_wait {
            self.wait_apart(id, blob, waits, room);
        }
        if presence && first {
            // the older presence commits of its author and actor go (un-merge): this one carries
            // that whole presence state
            let older: Vec<CommitId> = self
                .eph
                .remote
                .held
                .iter()
                .filter(|(c, x)| x.header.ephemeral == Some(EphClass::Presence) && x.header.author == header.author && x.header.actor == header.actor && (x.header.ts, **c) < (header.ts, id))
                .map(|(c, _)| *c)
                .collect();
            for c in older {
                self.drop_ephemeral_presence(&c);
            }
        }
        if !weigh.is_empty() {
            self.drop_absorbed_of(weigh);
        }
        changed.sort();
        changed.dedup();
        if !changed.is_empty() {
            self.core.events.queue(Event::Ephemeral { id: ChangeId::Commit(id), origin: Origin::Remote, author: header.author, actor: header.actor, ts: header.ts, received, changed, signals: Vec::new() });
            self.core.events.flush();
        }
        // records it brought: what waited for them (another blob of this commit or of others)
        if !carried.is_empty() {
            self.retry_waiting();
        }
        Ok(if waiting { EphIngest::Pending } else { EphIngest::Held { new } })
    }

    /// Keeps `blob` of commit `id` waiting for the records of `needs` (`pending`), merged with
    /// the other copies of the commit waiting (a commit past a blob splits; a junk copy may come
    /// first): its signature and parts not held yet, but parts that fail their delta hash.
    fn wait_apart(&mut self, id: CommitId, blob: CommitBlob, needs: BTreeSet<Tid>, room: u64) {
        let parts: Vec<osis_commit::Part> = blob.parts.into_iter().filter(|p| self.part_matches(&blob.header, &id, p) != Some(false)).collect();
        let w = self.eph.remote.pending.entry(id).or_insert_with(|| Waiting { header: blob.header, sigs: Vec::new(), parts: Vec::new(), needs: BTreeSet::new(), room: 0 });
        w.room = w.room.max(room);
        if !w.sigs.contains(&blob.signature) {
            w.sigs.push(blob.signature);
        }
        for p in parts {
            if !w.parts.contains(&p) {
                w.parts.push(p);
            }
        }
        w.needs.extend(needs);
    }

    /// Whether part `p` of ephemeral commit `h` (ID `id`) matches its delta hash; `None` while
    /// its thing's record is not here (a `/created` part brings its own).
    fn part_matches(&self, h: &Header, id: &CommitId, p: &osis_commit::Part) -> Option<bool> {
        let Some(a) = h.aspects.get(p.ai) else { return Some(false) };
        let Some(want) = a.hashes.get(p.di) else { return Some(false) };
        let empty = BTreeMap::new();
        let rec = match self.record_of(&a.tid, &empty) {
            Some(r) => r.clone(),
            None if a.ak.as_str() == CREATED.ak() => match created_record(h, id, p, &mut Interner::new()) {
                Ok(r) => r,
                Err(_) => return Some(false),
            },
            None => return None,
        };
        Some(osis_crypto::delta_hash(&dedup_secret(rec.nonce()), &p.delta) == *want)
    }

    /// The copy of waiting commit `id` to ingest once a record it waits for is here: the first
    /// signature that verifies, and per `(ai, di)` the first part matching its delta hash (every
    /// copy of a part whose record is still missing); `None` when its author's record is still
    /// missing (it waits on, its parts sifted) or no signature verifies (dropped).
    fn sift_waiting(&mut self, id: CommitId, w: Waiting) -> Option<CommitBlob> {
        let key = match self.core.created(&w.header.author) {
            Some(CreationRecord::KeyActor { public_key, .. }) => VerifyingKey::from_slice(public_key).ok(),
            Some(_) => None,
            None => {
                let mut w = w;
                let parts = std::mem::take(&mut w.parts);
                w.parts = parts.into_iter().filter(|p| self.part_matches(&w.header, &id, p) != Some(false)).collect();
                let empty = BTreeMap::new();
                w.needs.retain(|t| self.record_of(t, &empty).is_none());
                self.eph.remote.pending.insert(id, w);
                return None;
            }
        };
        let Some(signature) = key.and_then(|k| w.sigs.iter().find(|s| osis_commit::verify_signature(&id, s, &k).is_ok()).copied()) else {
            self.report_eph(&format!("ephemeral commit {id:?}: no copy verifies"));
            return None;
        };
        let mut parts: Vec<osis_commit::Part> = Vec::new();
        for p in w.parts {
            match self.part_matches(&w.header, &id, &p) {
                Some(true) if !parts.iter().any(|q| (q.ai, q.di) == (p.ai, p.di)) => parts.push(p),
                None => parts.push(p),
                _ => {}
            }
        }
        parts.sort_by_key(|p| (p.ai, p.di));
        Some(CommitBlob { header: w.header, signature, parts })
    }

    /// Whether a held presence commit of `h`'s author and actor is newer than commit `id`.
    fn newer_presence(&self, h: &Header, id: &CommitId) -> bool {
        self.eph.remote.held.iter().any(|(c, x)| x.header.ephemeral == Some(EphClass::Presence) && x.header.author == h.author && x.header.actor == h.actor && (x.header.ts, *c) > (h.ts, *id))
    }

    /// Delivers the parts of verified relay-only commit `id` this blob carries once each:
    /// remembered as delivered (`MAX_DELIVERED`, per-author floors), its valid signal parts not
    /// delivered before fired (a commit whose parts have different readers goes as several blobs).
    fn deliver_relay(&mut self, id: CommitId, h: &Header, decoded: Vec<(usize, Snapshot, usize)>, carried: &BTreeMap<Tid, CreationRecord>, now: u64) -> EphIngest {
        let r = &mut self.eph.remote;
        let seen = match r.delivered_set.get_mut(&id) {
            Some(d) => std::mem::take(d),
            None => {
                r.delivered.push_back((id, h.ts.wall_ms().0, h.author));
                BTreeSet::new()
            }
        };
        let decoded: Vec<_> = decoded.into_iter().filter(|(ai, _, _)| !seen.contains(ai)).collect();
        let mut all = seen;
        all.extend(decoded.iter().map(|(ai, _, _)| *ai));
        r.delivered_set.insert(id, all);
        while r.delivered.len() > MAX_DELIVERED || r.delivered.front().is_some_and(|(_, t, _)| t.saturating_add(MAX_DRIFT_MS) < now) {
            if let Some((c, t, a)) = r.delivered.pop_front() {
                r.delivered_set.remove(&c);
                // past its window a commit is dropped anyway: no floor needed
                if t.saturating_add(MAX_DRIFT_MS) >= now {
                    let f = r.delivered_floor.entry(a).or_default();
                    *f = (*f).max(t);
                }
            }
        }
        r.delivered_floor.retain(|_, f| f.saturating_add(MAX_DRIFT_MS) >= now);
        let mut signals = Vec::new();
        for (ai, s, _) in decoded {
            let Some(a) = h.aspects.get(ai) else { continue };
            if a.ak.as_str() == CREATED.ak() || !self.eph_part_valid(h, &id, ai, carried) {
                continue;
            }
            if let Some(v) = s.fragment.read() {
                signals.push((a.tid, a.ak.clone(), v));
            }
        }
        let fired = !signals.is_empty();
        if fired {
            let received = self.now();
            self.core.events.queue(Event::Ephemeral { id: ChangeId::Commit(id), origin: Origin::Remote, author: h.author, actor: h.actor, ts: h.ts, received, changed: Vec::new(), signals });
            self.core.events.flush();
        }
        EphIngest::Relayed { fired }
    }

    /// Checks a blob of a held ephemeral commit: its author's signature and each part's delta
    /// hash (spec/commits.md §4).
    fn check_copy(&self, blob: &CommitBlob) -> Result<()> {
        let h = &blob.header;
        let Some(CreationRecord::KeyActor { public_key, .. }) = self.core.created(&h.author) else { return Err(Error::BadInput("author is not a key actor")) };
        osis_commit::verify_signature(&blob.id(), &blob.signature, &VerifyingKey::from_slice(public_key)?)?;
        let empty = BTreeMap::new();
        for p in &blob.parts {
            let a = h.aspects.get(p.ai).ok_or(Error::BadInput("part aspect index"))?;
            let rec = self.record_of(&a.tid, &empty).ok_or(Error::BadInput("part on a thing without a record"))?;
            let want = a.hashes.get(p.di).ok_or(Error::BadInput("part delta index"))?;
            if osis_crypto::delta_hash(&dedup_secret(rec.nonce()), &p.delta) != *want {
                return Err(Error::BadInput("part does not match its delta hash"));
            }
        }
        Ok(())
    }

    /// Drops held commits that valid held commits list as absorbed on every aspect they touch
    /// (a cover); their parts' writes stay in the state through the cover. A cover's part that
    /// does not contain the parts it lists (`contains`; an honest cover is their join) absorbs
    /// nothing: its list is cleared, so holders keep those commits and compute one join. Queued
    /// for `take_dropped_ephemeral`. Every held commit some held commit lists is weighed.
    fn drop_absorbed(&mut self) {
        let cands: BTreeSet<CommitId> = self.eph.remote.absorbers.keys().filter(|c| self.eph.remote.held.contains_key(c)).copied().collect();
        self.drop_absorbed_of(cands);
    }

    /// `drop_absorbed`, weighing only held commits `cands` (what an arriving commit lists, or the
    /// arriving commit when held commits list it): a commit drops only when a listing changes,
    /// and a cover part is judged bad (`contains`) over its own list, so the cost is what those
    /// lists hold, not every held commit.
    fn drop_absorbed_of(&mut self, cands: BTreeSet<CommitId>) {
        let r = &self.eph.remote;
        let is_created = |h: &Header, ai: usize| h.aspects.get(ai).is_none_or(|a| a.ak.as_str() == CREATED.ak());
        // per listing cover part judged: whether it fails to contain a held part it lists there
        let mut bad: BTreeMap<PartId, bool> = BTreeMap::new();
        let mut gone = Vec::new();
        for id in &cands {
            let Some(h) = r.held.get(id) else { continue };
            let mut all = true;
            let mut per_part = Vec::new();
            for p in &h.parts {
                let Some(a) = h.header.aspects.get(p.ai) else { all = false; break };
                let ls = r.listers(id, &h.header, a);
                if ls.is_empty() {
                    all = false;
                    break;
                }
                if !is_created(&h.header, p.ai) {
                    per_part.push(ls);
                }
            }
            if !all {
                // judged anyway: a cover that does not contain what it lists absorbs nothing
                for p in h.parts.iter().filter(|p| !is_created(&h.header, p.ai)) {
                    if let Some(a) = h.header.aspects.get(p.ai) {
                        for l in r.listers(id, &h.header, a) {
                            bad.entry(l).or_insert_with(|| self.cover_part_bad(l));
                        }
                    }
                }
                continue;
            }
            let mut drops = true;
            for ls in per_part {
                let mut any = false;
                for l in ls {
                    let b = *bad.entry(l).or_insert_with(|| self.cover_part_bad(l));
                    any |= !b;
                }
                drops &= any;
            }
            if drops {
                gone.push(*id);
            }
        }
        for ((c, ai), b) in bad {
            if !b {
                continue;
            }
            self.eph.remote.unindex_lists(&c);
            if let Some(p) = self.eph.remote.held.get_mut(&c).and_then(|h| h.parts.iter_mut().find(|p| p.ai == ai)) {
                p.absorbed.clear();
            }
            self.eph.remote.index_lists(c);
        }
        for id in gone {
            self.forget_held(&id);
        }
        self.eph.remote.check_index();
    }

    /// Whether held cover part `(c, ai)` fails to contain a held part it lists on its aspect (of
    /// a commit of its author and class).
    fn cover_part_bad(&self, (c, ai): PartId) -> bool {
        let r = &self.eph.remote;
        let Some(h) = r.held.get(&c) else { return false };
        let Some(cp) = h.parts.iter().find(|p| p.ai == ai) else { return false };
        let Some(a) = h.header.aspects.get(ai) else { return false };
        if a.ak.as_str() == CREATED.ak() {
            return false;
        }
        let mut j: Option<Fragment> = None;
        for x in &cp.absorbed {
            let Some(xh) = r.held.get(x).filter(|xh| may_absorb(&h.header, &xh.header)) else { continue };
            for xp in &xh.parts {
                if xh.header.aspects.get(xp.ai).is_some_and(|xa| xa.tid == a.tid && xa.ak == a.ak) {
                    j.get_or_insert_with(|| cp.fragment.clone()).join(xp.fragment.clone());
                }
            }
        }
        j.is_some_and(|j| j != cp.fragment)
    }

    /// Forgets held commit `id` (its writes stay in the state); queued for `take_dropped_ephemeral`.
    fn forget_held(&mut self, id: &CommitId) {
        if self.release_held(id) {
            self.eph.dropped.push(*id);
        }
    }

    /// Forgets held commit `id` without queueing it; whether it was held.
    fn release_held(&mut self, id: &CommitId) -> bool {
        self.eph.remote.unindex_lists(id);
        let Some(h) = self.eph.remote.held.remove(id) else { return false };
        if h.header.ephemeral == Some(EphClass::Presence) {
            let lease = h.header.ts.wall_ms().0.saturating_add(MAX_LEASE_MS);
            if let Some(s) = self.eph.remote.leases.get_mut(&lease) {
                s.remove(id);
                if s.is_empty() {
                    self.eph.remote.leases.remove(&lease);
                }
            }
        }
        for p in &h.parts {
            if let Some(a) = h.header.aspects.get(p.ai) {
                if let Some(ea) = self.eph.aspects.get_mut(&a.tid).and_then(|m| m.get_mut(&a.ak)) {
                    ea.parts.remove(&(*id, p.ai));
                }
                if let Some(t) = a.expires
                    && let Some(s) = self.eph.remote.timers.get_mut(&t)
                {
                    s.remove(&(*id, p.ai));
                }
            }
        }
        true
    }

    /// Whether every synced label has caught up once since start (reconciled, read to its end,
    /// nothing fetching or waiting): only then may an own cover absorb an earlier session's
    /// commits. Before, a thing's placements under some labels may not be back yet: the cover
    /// would go under the others only while the absorbed commit is deleted everywhere. Turning
    /// true weighs the own covers again.
    pub fn set_ephemeral_caught_up(&mut self, yes: bool) {
        if yes && !self.eph.remote.caught_up {
            self.eph.remote.cover_est.clear();
        }
        self.eph.remote.caught_up = yes;
    }

    /// The held ephemeral commits dropped since the last call (covered, expired, or presence gone
    /// from every source): the sync layer forgets their blobs and deletes them where it may.
    pub fn take_dropped_ephemeral(&mut self) -> Vec<CommitId> {
        std::mem::take(&mut self.eph.dropped)
    }

    /// The held ephemeral commits let go since the last call because every part turned invalid
    /// (a removal, a demotion): the sync layer forgets their blobs without deleting them anywhere
    /// and reconciles their labels, so they wait apart (`Remote::invalid`) until valid again.
    pub fn take_unheld_ephemeral(&mut self) -> Vec<CommitId> {
        std::mem::take(&mut self.eph.unheld)
    }

    /// Whether an ephemeral commit is held here.
    pub fn holds_ephemeral(&self, id: &CommitId) -> bool {
        self.eph.remote.held.contains_key(id)
    }

    /// The header of a held ephemeral commit.
    pub fn ephemeral_header(&self, id: &CommitId) -> Option<Arc<Header>> {
        self.eph.remote.held.get(id).map(|h| h.header.clone())
    }

    /// The reader actor of thing `t` (`Engine::reader_of`), through the records of ephemeral
    /// things up to the nearest durable one.
    pub fn ephemeral_reader(&self, t: &Tid) -> Tid {
        self.core.reader_of(&self.nearest_durable(t))
    }

    /// The nearest durable thing up `t`'s chain of ephemeral records (`t` when durable; where the
    /// chain stops otherwise).
    fn nearest_durable(&self, t: &Tid) -> Tid {
        let mut cur = *t;
        for _ in 0..=MAX_OWNER_DEPTH {
            if self.core.created(&cur).is_some() {
                break;
            }
            match self.eph.things.get(&cur).map(|e| &e.record) {
                Some(CreationRecord::Thing { owner, .. }) => cur = *owner,
                _ => break,
            }
        }
        cur
    }

    /// The delete secrets this node holds for delete keys `keys` of an ephemeral commit's part
    /// on `tid` acting for `actor` (spec/crypto.md §7): those of the chain of `tid`'s nearest
    /// durable thing.
    pub fn ephemeral_delete_secrets_for(&self, tid: &Tid, actor: &Tid, keys: &[osis_commit::DeleteKey]) -> Vec<(u8, DeleteSecret)> {
        let thing = self.core.delete_chain(&self.nearest_durable(tid));
        let author = self.core.delete_chain(actor);
        keys.iter().filter_map(|k| crate::engine::Core::delete_secret(k.level, &k.key, &thing, &author).map(|d| (k.level, d))).collect()
    }

    /// Ingests again the commits whose parts were all invalid on arrival once one of them is
    /// valid (the held durable set changed).
    fn retry_invalid(&mut self) {
        let ready: Vec<CommitId> = self.eph.remote.invalid.iter().filter(|(c, x)| x.ais.iter().any(|ai| self.eph_part_valid(&x.blob.header, c, *ai, &x.carried))).map(|(c, _)| *c).collect();
        for c in ready {
            if let Some(x) = self.eph.remote.invalid.remove(&c) {
                let r = self.ingest_ephemeral_within(x.blob, true, x.room);
                self.report_retry(&c, r);
            }
        }
    }

    /// Ingests again the commits waiting for a record that is held now (the rest costs nothing
    /// to keep waiting); one waiting again goes back.
    fn retry_waiting(&mut self) {
        let empty = BTreeMap::new();
        let ready: Vec<CommitId> = self.eph.remote.pending.iter().filter(|(_, w)| w.needs.iter().any(|t| self.record_of(t, &empty).is_some())).map(|(c, _)| *c).collect();
        for c in ready {
            let Some(w) = self.eph.remote.pending.remove(&c) else { continue };
            let room = w.room;
            if let Some(b) = self.sift_waiting(c, w) {
                let r = self.ingest_ephemeral_within(b, true, room);
                self.report_retry(&c, r);
            }
        }
    }

    /// Reports a retried commit that failed or did not fit the room it was given.
    fn report_retry(&mut self, c: &CommitId, r: Result<EphIngest>) {
        match r {
            Err(e) => self.report_eph(&format!("ephemeral commit {c:?}: {e}")),
            Ok(EphIngest::TooLarge) => self.report_eph(&format!("ephemeral commit {c:?}: past the room it was given, not held")),
            Ok(_) => {}
        }
    }

    /// Judges held ephemeral commits again when the held durable set changed (rights, records),
    /// rebuilds the aspects whose parts flipped (un-merge or re-merge, spec/crdt.md §4.6), retries
    /// commits waiting for their author's record and forgets ephemeral records of things that
    /// became durable.
    pub fn rejudge_ephemeral(&mut self) -> Result<()> {
        if self.eph.remote.judged_at == self.core.generation {
            return Ok(());
        }
        self.eph.remote.judged_at = self.core.generation;
        let durable: Vec<Tid> = self.eph.things.keys().filter(|t| self.core.created(t).is_some()).copied().collect();
        for t in durable {
            self.eph.things.remove(&t);
        }
        self.retry_waiting();
        self.retry_invalid();
        let empty = BTreeMap::new();
        let mut flips: BTreeSet<(Tid, Ak)> = BTreeSet::new();
        let ids: Vec<CommitId> = self.eph.remote.held.keys().copied().collect();
        for id in ids {
            let Some(mut h) = self.eph.remote.held.remove(&id) else { continue };
            for p in h.parts.iter_mut() {
                let before = p.valid;
                p.valid = h.own || self.eph_part_valid(&h.header, &id, p.ai, &empty);
                if p.valid != before
                    && let Some(a) = h.header.aspects.get(p.ai)
                {
                    flips.insert((a.tid, a.ak.clone()));
                }
            }
            self.eph.remote.held.insert(id, h);
        }
        let mut changed = Vec::new();
        for (t, ak) in flips {
            self.rebuild_aspect(&t, &ak);
            changed.push((t, ak));
        }
        if !changed.is_empty() {
            // received commits with every part but `/created` invalid now are not held (as one
            // received so would wait apart): neither counted nor served nor listed until valid
            let gone: Vec<CommitId> = self
                .eph
                .remote
                .held
                .iter()
                .filter(|(_, h)| {
                    let content: Vec<&HeldPart> = h.parts.iter().filter(|p| h.header.aspects.get(p.ai).is_some_and(|a| a.ak.as_str() != CREATED.ak())).collect();
                    !h.own && !content.is_empty() && content.iter().all(|p| !p.valid)
                })
                .map(|(c, _)| *c)
                .collect();
            for id in gone {
                let recs = self.carried_tids(&id);
                if self.release_held(&id) {
                    self.eph.unheld.push(id);
                }
                self.free_unused_records(recs);
            }
            self.drop_absorbed();
            self.core.events.queue(Event::Changed { cause: crate::events::Cause::Validity, changed });
            self.core.events.flush();
        }
        Ok(())
    }

    /// Rebuilds the ephemeral state of `(t, ak)`: the own writes joined with the valid held parts,
    /// own commits included (un-merge, spec/crdt.md §4.6).
    fn rebuild_aspect(&mut self, t: &Tid, ak: &Ak) {
        let r = &self.eph.remote;
        let Some(ea) = self.eph.aspects.get(t).and_then(|m| m.get(ak)) else { return };
        let mut f = ea.own.clone().unwrap_or_default();
        for (id, ai) in &ea.parts {
            // own held commits too: those of an earlier session are not in the own writes
            let Some(h) = r.held.get(id) else { continue };
            if let Some(c) = h.parts.iter().find(|p| p.ai == *ai).and_then(HeldPart::counted) {
                f.join(c);
            }
        }
        let src = self.eph.src.clone();
        if let Some(ea) = self.eph.aspects.get_mut(t).and_then(|m| m.get_mut(ak)) {
            ea.state = f;
            strip_own_expired(ea, &src);
        }
        if ak.as_str() == PLACED.ak() {
            self.refresh_def(t, ak);
        }
    }

    /// Runs the expiries of held parts due by the corrected clock: their writes are stripped
    /// (spec/crdt.md §4.7) and the parts dropped. Returns the aspects changed.
    pub(super) fn tick_remote(&mut self, now: u64) -> BTreeSet<(Tid, Ak)> {
        let mut changed = BTreeSet::new();
        let mut gone = Vec::new();
        while let Some(entry) = self.eph.remote.timers.first_entry() {
            if *entry.key() > now {
                break;
            }
            let (_, parts) = entry.remove_entry();
            for (id, ai) in parts {
                self.eph.remote.unindex_lists(&id);
                let Some(h) = self.eph.remote.held.get_mut(&id) else { continue };
                let Some(k) = h.parts.iter().position(|p| p.ai == ai) else {
                    self.eph.remote.index_lists(id);
                    continue;
                };
                let part = h.parts.remove(k);
                h.bytes = h.bytes.saturating_sub(part.bytes);
                let header = h.header.clone();
                let empty = h.parts.is_empty();
                if !empty {
                    self.eph.remote.index_lists(id);
                }
                let Some(a) = header.aspects.get(ai) else { continue };
                let dots: BTreeSet<osis_crdt::Dot> = part.fragment.writes().into_iter().map(|(d, _)| d).collect();
                if let Some(ea) = self.eph.aspects.get_mut(&a.tid).and_then(|m| m.get_mut(&a.ak)) {
                    ea.parts.remove(&(id, ai));
                    ea.state.strip(&|d| dots.contains(d));
                    if let Some(o) = &mut ea.own {
                        o.strip(&|d| dots.contains(d));
                    }
                }
                if a.ak.as_str() == PLACED.ak() {
                    let (t, ak) = (a.tid, a.ak.clone());
                    self.refresh_def(&t, &ak);
                }
                changed.insert((a.tid, a.ak.clone()));
                if empty {
                    self.eph.remote.held.remove(&id);
                    self.eph.dropped.push(id);
                } else if !live_parts(&header, now) {
                    // only its `/created` parts are left: dropped with their records' last use
                    gone.push(id);
                }
            }
        }
        for id in gone {
            self.forget_unused(&id);
        }
        self.eph.remote.check_index();
        changed
    }

    /// Forgets held commit `id`, then the records it carried that nothing here uses any more.
    fn forget_unused(&mut self, id: &CommitId) {
        let recs = self.carried_tids(id);
        self.forget_held(id);
        self.free_unused_records(recs);
    }

    /// The things whose `/created` held commit `id` carries.
    fn carried_tids(&self, id: &CommitId) -> BTreeSet<Tid> {
        let Some(h) = self.eph.remote.held.get(id) else { return BTreeSet::new() };
        h.parts.iter().filter_map(|p| h.header.aspects.get(p.ai)).filter(|a| a.ak.as_str() == CREATED.ak()).map(|a| a.tid).collect()
    }

    /// Frees the records of `cands`, ephemeral things received from others (not made by this
    /// session), that nothing here uses: no held part on the thing (a commit about it or placing
    /// it carries its record), no pending commit waiting for it, no state, no own write to send,
    /// no ephemeral thing it owns. Their content is gone (expired or its holder's tie ended), and
    /// a later commit about them brings the record again (notes/ephemeral.md Own covers).
    fn free_unused_records(&mut self, mut cands: BTreeSet<Tid>) {
        loop {
            let owners: BTreeSet<Tid> = self.eph.things.values().filter_map(|e| match &e.record {
                CreationRecord::Thing { owner, .. } => Some(*owner),
                CreationRecord::KeyActor { .. } => None,
            }).collect();
            let free: Vec<Tid> = cands.iter().filter(|t| !owners.contains(t) && self.record_unused(t)).copied().collect();
            if free.is_empty() {
                return;
            }
            for t in &free {
                cands.remove(t);
                if let Some(CreationRecord::Thing { owner, .. }) = self.eph.things.remove(t).map(|e| e.record) {
                    cands.insert(owner);
                }
                self.eph.aspects.remove(t);
                self.eph.defs.remove(t);
            }
            self.eph.log.forget(&|t| free.contains(t));
        }
    }

    fn record_unused(&self, t: &Tid) -> bool {
        let Some(th) = self.eph.things.get(t) else { return false };
        let r = &self.eph.remote;
        // made here this session: the app's own (its record minted under this session)
        let made_here = th.created.as_ref().is_none_or(|f| f.writes().first().is_none_or(|(d, _)| d.src == self.eph.src));
        !made_here
            && self.eph.aspects.get(t).is_none_or(|m| m.values().all(|a| a.parts.is_empty() && !a.state.present()))
            && !r.local.contains(t)
            && !r.unsent.keys().any(|(x, _)| x == t)
            && !r.presence.keys().any(|(x, _)| x == t)
            && !r.pending.values().any(|w| w.needs.contains(t))
    }

    /// The author's own compaction (spec/sync.md §9): per actor, when this node's held plain
    /// commits without expiry for it (`own_held`), two at least, cost more than `COVER_FACTOR`
    /// times their cover, one ephemeral commit joining them and the actor's unsent writes
    /// without expiry, listing them as absorbed; they are dropped here
    /// (`take_dropped_ephemeral`). `force` (tests): whenever there is something to cover. A
    /// cover is weighed only once the held commits cost more than `COVER_FACTOR` times the last
    /// cover weighed (`cover_est`), so rebuilds cost O(1) per byte written, amortized.
    pub fn compact_own_ephemeral(&mut self, force: bool) -> Result<Vec<EphCommit>> {
        let mut out = Vec::new();
        for (actor, ids) in self.own_held() {
            let cost: usize = ids.iter().map(|(_, c)| c).sum();
            if !force && cost <= COVER_FACTOR * self.eph.remote.cover_est.get(&actor).copied().unwrap_or(0) {
                continue;
            }
            let (ids, stuck) = self.coverable(ids);
            let held: usize = ids.iter().map(|(_, c)| c).sum();
            let ids: Vec<CommitId> = ids.into_iter().map(|(id, _)| id).collect();
            let (deltas, absorbed) = self.own_cover(actor, &ids);
            // what it cannot absorb (an aspect no longer writable here) does not make it weigh
            // again at every step
            let stuck = stuck / COVER_FACTOR.max(1);
            let cover = self.cover_cost(&deltas);
            self.eph.remote.cover_est.insert(actor, cover + stuck);
            // one commit is what its cover would be again
            if ids.is_empty() || (!force && (ids.len() < 2 || held <= COVER_FACTOR * cover)) {
                continue;
            }
            // header lists past the inline bound: several covers, each absorbing on its own
            // aspects; a delta that does not fit a blob alone (ephemeral deltas are not paged):
            // that aspect is not covered (reported), and the cover is weighed again once the
            // held commits double
            let keys: BTreeSet<(Tid, Ak)> = deltas.iter().map(|(t, ak, _, _)| (*t, ak.clone())).collect();
            let mut left = Vec::new();
            self.build_fitting(actor, deltas, &absorbed, &mut out, &mut left)?;
            self.eph.remote.full.retain(|k| !keys.contains(k));
            let mut kept = BTreeSet::new();
            for ((tid, ak, _, _), large) in left {
                if large {
                    self.eph.remote.full.insert((tid, ak.clone()));
                }
                kept.insert((tid, ak));
            }
            if !kept.is_empty() {
                self.eph.remote.cover_est.insert(actor, held + stuck);
            }
            // what is covered needs no separate send (kept when not covered: lost otherwise)
            for (k, m) in self.eph.remote.unsent.iter_mut() {
                if !kept.contains(k) {
                    m.remove(&(actor, None));
                }
            }
            self.eph.remote.unsent.retain(|_, m| !m.is_empty());
        }
        Ok(out)
    }

    /// Per actor, this node's own held plain commits without expiry (what an own cover absorbs),
    /// each with its cost: its delta bytes and `PART_OVERHEAD` per part (`part_weight`) plus
    /// `ENTRY_CHARGE`.
    fn own_held(&self) -> BTreeMap<Tid, Vec<(CommitId, usize)>> {
        let me = self.tid();
        let mut by: BTreeMap<Tid, Vec<(CommitId, usize)>> = BTreeMap::new();
        for (id, h) in &self.eph.remote.held {
            let own_plain = h.header.author == me && h.header.ephemeral == Some(EphClass::Plain);
            if own_plain && h.parts.iter().all(|p| h.header.aspects.get(p.ai).is_some_and(|a| a.expires.is_none())) {
                let weight: usize = h.parts.iter().map(|p| part_weight(p.bytes)).sum();
                by.entry(h.header.actor).or_default().push((*id, weight + ENTRY_CHARGE));
            }
        }
        by
    }

    /// Those of own held commits `ids` (with their costs) an own cover may absorb (every aspect
    /// writable here now, on a thing in a labeled closure here now; an earlier session's only once
    /// every label caught up, `set_ephemeral_caught_up`), and the cost of the rest. A thing in no
    /// closure here, or not yet in all of its (an earlier session's commit fetched back before the
    /// ones placing its thing), would have its cover's parts placed under those labels only while
    /// the commits it absorbs go, deleted where they were.
    fn coverable(&self, ids: Vec<(CommitId, usize)>) -> (Vec<(CommitId, usize)>, usize) {
        let me = self.tid();
        let ts = Ts::make(self.now(), 0).unwrap_or_default();
        let things = &self.eph.things;
        let records: crate::engine::write::Records<'_> = &|x| things.get(x).map(|e| &e.record);
        let writable = |id: &CommitId| {
            let Some(h) = self.eph.remote.held.get(id) else { return false };
            (h.own || self.eph.remote.caught_up) && h.parts.iter().filter_map(|p| h.header.aspects.get(p.ai)).filter(|a| a.ak.as_str() != CREATED.ak()).all(|a| self.ephemeral_synced(&a.tid) && crate::engine::write::check_authority_with(&self.core, me, records, &a.tid, a.ak.as_str(), ts).is_ok())
        };
        let (ok, stuck): (Vec<_>, Vec<_>) = ids.into_iter().partition(|(id, _)| writable(id));
        (ok, stuck.iter().map(|(_, c)| c).sum())
    }

    /// The cover of own held commits `ids` for `actor`: per aspect, the join of their parts and
    /// of the actor's unsent writes without expiry; per aspect, the commits it absorbs.
    fn own_cover(&self, actor: Tid, ids: &[CommitId]) -> (Vec<EphDelta>, Absorbs) {
        let mut joined: BTreeMap<(Tid, Ak), Fragment> = BTreeMap::new();
        let mut absorbed = Absorbs::new();
        for id in ids {
            let Some(h) = self.eph.remote.held.get(id) else { continue };
            for p in &h.parts {
                let Some(a) = h.header.aspects.get(p.ai) else { continue };
                let k = (a.tid, a.ak.clone());
                joined.entry(k.clone()).or_default().join(p.fragment.clone());
                absorbed.entry(k).or_default().insert(*id);
            }
        }
        for (k, m) in &self.eph.remote.unsent {
            if let Some(f) = m.get(&(actor, None)) {
                joined.entry(k.clone()).or_default().join(f.clone());
            }
        }
        (joined.into_iter().map(|((t, ak), f)| (t, ak, f, None)).collect(), absorbed)
    }

    /// Per actor, this node's own held plain commits without expiry: their cost (`own_held`), the cost of their cover, and the largest one's cost (tests: within
    /// `COVER_FACTOR` times the cover and one commit in flight after every step).
    pub fn own_ephemeral_load(&self) -> Vec<(Tid, usize, usize, usize)> {
        let mut out = Vec::new();
        for (actor, held) in self.own_held() {
            let ids: Vec<CommitId> = held.iter().map(|(id, _)| *id).collect();
            let (deltas, _) = self.own_cover(actor, &ids);
            let costs = held.iter().map(|(_, c)| *c);
            out.push((actor, costs.clone().sum(), self.cover_cost(&deltas), costs.max().unwrap_or(0)));
        }
        out
    }

    /// Tests: an ephemeral commit setting `(tid, ak)` to `v` with no rights check (a forged
    /// write, to test receivers).
    #[doc(hidden)]
    pub fn forge_ephemeral(&mut self, tid: Tid, ak: &Ak, v: Value) -> Result<Option<EphCommit>> {
        let src = self.eph.src.clone();
        self.forge_ephemeral_under(tid, ak, v, src)
    }

    /// Tests: `forge_ephemeral` with the write under a session of node `node` (a write passed
    /// off as another node's).
    #[doc(hidden)]
    pub fn forge_ephemeral_as_session(&mut self, tid: Tid, ak: &Ak, v: Value, node: Tid) -> Result<Option<EphCommit>> {
        let nonce = self.eph.session.nonce;
        self.forge_ephemeral_under(tid, ak, v, Source::session(osis_crdt::Session { node, nonce }))
    }

    /// Tests: `forge_ephemeral` with the write under node `node`'s source (a write passed off as
    /// another node's).
    #[doc(hidden)]
    pub fn forge_ephemeral_as_node(&mut self, tid: Tid, ak: &Ak, v: Value, node: Tid) -> Result<Option<EphCommit>> {
        self.forge_ephemeral_under(tid, ak, v, Source::node(node))
    }

    fn forge_ephemeral_under(&mut self, tid: Tid, ak: &Ak, v: Value, src: Source) -> Result<Option<EphCommit>> {
        let ts = self.core.hlc.next();
        let w = Writer::new(ts, src, self.eph.ctr(&tid, ak));
        let Some((f, r)) = run_ops(&Fragment::default(), w, &[PathOp { path: Vec::new(), op: Op::Set(v) }], &AnyView)? else { return Ok(None) };
        self.eph.take_ctrs(&tid, ak, r.hi);
        let me = self.tid();
        self.build_ephemeral_with(EphClass::Plain, me, vec![(tid, ak.clone(), f, None)], &BTreeMap::new(), true)
    }

    /// Tests: an ephemeral commit of class `class` by this node carrying the whole joined
    /// ephemeral state of `(tid, ak)`, others' writes included under their sessions (a forged
    /// cover of someone else's writes).
    #[doc(hidden)]
    pub fn forge_carrying(&mut self, class: EphClass, tid: Tid, ak: &Ak) -> Result<Option<EphCommit>> {
        let Some(f) = self.eph.state(&tid, ak).cloned() else { return Ok(None) };
        let me = self.tid();
        self.build_ephemeral_with(class, me, vec![(tid, ak.clone(), f, None)], &BTreeMap::new(), true)
    }

    /// Tests: `forge_ephemeral` listing `absorbed` as absorbed on `(tid, ak)` without carrying
    /// their writes (a writer's cover that is no join).
    #[doc(hidden)]
    pub fn forge_cover(&mut self, tid: Tid, ak: &Ak, v: Value, absorbed: &[CommitId]) -> Result<Option<EphCommit>> {
        let ts = self.core.hlc.next();
        let w = Writer::new(ts, self.eph.src.clone(), self.eph.ctr(&tid, ak));
        let Some((f, r)) = run_ops(&Fragment::default(), w, &[PathOp { path: Vec::new(), op: Op::Set(v) }], &AnyView)? else { return Ok(None) };
        self.eph.take_ctrs(&tid, ak, r.hi);
        let me = self.tid();
        // listed on every aspect of their parts, as an own cover lists them
        let mut abs = Absorbs::new();
        for c in absorbed {
            for a in self.eph.remote.held.get(c).into_iter().flat_map(|h| h.parts.iter().filter_map(|p| h.header.aspects.get(p.ai))) {
                abs.entry((a.tid, a.ak.clone())).or_default().insert(*c);
            }
        }
        self.build_ephemeral(EphClass::Plain, me, vec![(tid, ak.clone(), f, None)], &abs)
    }

    /// Tests: pads the `/created` ephemeral thing `t`'s commits carry with a losing write of
    /// `junk` (a writer's padding, to test receivers).
    #[doc(hidden)]
    pub fn pad_created(&mut self, t: &Tid, junk: Value) -> Option<()> {
        let mut f = self.created_fragment(t)?;
        let cak = Ak::new(CREATED.ak()).ok()?;
        let w = Writer::new(Ts::from_u64(1)?, self.eph.src.clone(), self.eph.ctr(t, &cak));
        let (pad, r) = run_ops(&Fragment::default(), w, &[PathOp { path: Vec::new(), op: Op::Set(junk) }], &AnyView).ok()??;
        self.eph.take_ctrs(t, &cak, r.hi);
        f.join(pad);
        self.eph.things.get_mut(t)?.created = Some(f);
        Some(())
    }

    /// Tests: makes ephemeral thing `t`'s next commits carry a new minting of its record (a copy
    /// unlike what its earlier ones carried, as after a restart between two copies).
    #[doc(hidden)]
    pub fn remint_created(&mut self, t: &Tid) -> Option<()> {
        self.eph.things.get_mut(t)?.created = None;
        Some(())
    }

    /// What held ephemeral commit `id`'s parts `ais` (all when empty) cost a holder in memory, as
    /// the node cap counts it: their decoded heap size in each copy kept (`HELD_COPIES`) and
    /// `PART_OVERHEAD` each. A blob of tiny map entries takes about 200 times its encoded size
    /// decoded (`scale::eph_decoded_memory`).
    pub fn ephemeral_charge(&self, id: &CommitId, ais: &[usize]) -> u64 {
        let Some(h) = self.eph.remote.held.get(id) else { return 0 };
        h.parts.iter().filter(|p| ais.is_empty() || ais.contains(&p.ai)).fold(0u64, |a, p| a.saturating_add(part_charge(p.heap, p.bytes)))
    }

    /// What the parts of `blob` could cost decoded (`part_bound`), from their bytes alone: (the
    /// sum, the largest), a part that is not one CBOR value counting `u64::MAX`. No part past
    /// the room given is decoded (`ingest_ephemeral_within`), so one whose bound passes a
    /// label's whole cap is never held under it.
    pub fn ephemeral_bound(blob: &CommitBlob) -> (u64, u64) {
        blob.parts.iter().map(|p| part_bound(p).unwrap_or(u64::MAX)).fold((0, 0), |(s, m), b| (s.saturating_add(b), m.max(b)))
    }

    /// The records ephemeral `blob` lacks here to be held without waiting apart: its author's,
    /// else those of its parts' things neither held here nor carried by its `/created` parts
    /// (empty: it waits for none).
    pub fn ephemeral_needs(&self, blob: &CommitBlob) -> BTreeSet<Tid> {
        let h = &blob.header;
        if self.core.created(&h.author).is_none() {
            return BTreeSet::from([h.author]);
        }
        let aspects = || blob.parts.iter().filter_map(|p| h.aspects.get(p.ai));
        let carried: BTreeSet<Tid> = aspects().filter(|a| a.ak.as_str() == CREATED.ak()).map(|a| a.tid).collect();
        let empty = BTreeMap::new();
        aspects().map(|a| a.tid).filter(|t| !carried.contains(t) && self.record_of(t, &empty).is_none()).collect()
    }

    /// Whether a record `ephemeral_needs` named is here now: durable, or an ephemeral thing's (an
    /// author's must be durable; an ephemeral key actor record never ends its wait, and counting
    /// it fetched a blob waiting for that author again at every change).
    pub fn has_record(&self, t: &Tid) -> bool {
        self.core.created(t).is_some() || self.eph.things.get(t).is_some_and(|e| matches!(e.record, CreationRecord::Thing { .. }))
    }

    /// Changes after which a record may be here that was not (`has_record`): the held durable
    /// set's generation and the ephemeral records added.
    pub fn records_seen(&self) -> (u64, u64) {
        (self.core.generation, self.eph.records)
    }

    /// Held ephemeral commits and their encoded delta bytes (tests, diagnostics).
    pub fn held_ephemeral(&self) -> Vec<(CommitId, usize, bool)> {
        self.eph.remote.held.iter().map(|(id, h)| (*id, h.bytes, h.own)).collect()
    }

    /// Whether blobs of an ephemeral commit wait apart (for a record, or for a part to become
    /// valid): not all checked yet, though its verified parts may be held.
    pub fn pending_ephemeral(&self, id: &CommitId) -> bool {
        self.eph.remote.pending.contains_key(id) || self.eph.remote.invalid.contains_key(id)
    }
}

/// What a held part costs (`ephemeral_charge`): its decoded heap size (`heap`, at least its
/// encoded `bytes`) in each copy kept, weighed as a part (`part_weight`).
fn part_charge(heap: usize, bytes: usize) -> u64 {
    part_weight(heap.max(bytes).saturating_mul(HELD_COPIES)) as u64
}

/// A part of `bytes` with the per-part overhead a holder's cap charges (`PART_OVERHEAD`). Shared
/// by the node cap (`part_charge`) and an author's cover trigger (`own_held`, `cover_cost`), so
/// the trigger weighs per part what holders are charged: else a holder of many small parts fills
/// its cap before the cover comes.
fn part_weight(bytes: usize) -> usize {
    bytes.saturating_add(PART_OVERHEAD)
}

/// An upper bound on `part_charge` of part `p` once decoded, from its bytes alone
/// (`osis_crdt::decoded_bound`): a part of tiny map entries decodes to about 200 times its size.
fn part_bound(p: &osis_commit::Part) -> Result<u64> {
    let heap = osis_crdt::decoded_bound(&p.delta).map_err(|_| Error::BadInput("ephemeral part not one CBOR value"))?;
    Ok(part_charge(heap, p.delta.len()))
}

/// The records ephemeral commit `blob` (ID `id`) carries in its `/created` parts, each checked:
/// it hashes to its tid and is exactly one minting (bad input otherwise).
fn carried_records(blob: &CommitBlob, id: &CommitId, interner: &mut Interner) -> Result<BTreeMap<Tid, CreationRecord>> {
    let h = &blob.header;
    let mut carried = BTreeMap::new();
    for p in &blob.parts {
        let Some(a) = h.aspects.get(p.ai) else { return Err(Error::BadInput("part aspect index")) };
        if a.ak.as_str() != CREATED.ak() {
            continue;
        }
        let rec = created_record(h, id, p, interner)?;
        carried.insert(a.tid, rec);
    }
    Ok(carried)
}

/// The record `/created` part `p` of commit `h` (ID `id`) carries, checked: it hashes to its tid
/// and is exactly one minting (bad input otherwise).
fn created_record(h: &Header, id: &CommitId, p: &osis_commit::Part, interner: &mut Interner) -> Result<CreationRecord> {
    let a = h.aspects.get(p.ai).ok_or(Error::BadInput("part aspect index"))?;
    let cx = osis_commit::delta_ctx(h, id, p.ai, interner)?;
    let s = osis_crdt::decode_snapshot(&p.delta, &cx, interner, Some(&mut Unpaged))?;
    let v = s.fragment.read().ok_or(Error::BadInput("empty /created"))?;
    let rec = CreationRecord::from_value(&v).ok_or(Error::BadInput("/created is not a creation record"))?;
    if rec.tid() != a.tid {
        return Err(Error::BadInput("/created does not hash to its tid"));
    }
    if !is_minted(&s.fragment, &rec) {
        return Err(Error::BadInput("/created is not one minting of its record"));
    }
    Ok(rec)
}

/// Whether `f` is exactly one minting of `rec` under a session source (spec/sync.md §9).
fn is_minted(f: &Fragment, rec: &CreationRecord) -> bool {
    f.writes().first().is_some_and(|(d, _)| matches!(d.src.kind(), SourceKind::Session(_))) && is_minting(f, rec)
}

/// Whether dot `d` is a write of one of `node`'s sessions (a `Derived` dot: its underlying
/// one's).
fn own_session(d: &osis_crdt::Dot, node: Tid) -> bool {
    matches!(d.src.author().kind(), SourceKind::Session(s) if s.node == node)
}

/// One minting of the record `f` reads out of `f`, a join of mintings of it: `f` if it is one,
/// else its first write's.
fn one_minting(f: &Fragment) -> Option<Fragment> {
    let rec = CreationRecord::from_value(&f.read()?)?;
    if is_minted(f, &rec) {
        return Some(f.clone());
    }
    let writes = f.writes();
    let (first, ts) = writes.first()?;
    let lo = writes.iter().filter(|(d, t)| d.src == first.src && t == ts).map(|(d, _)| d.ctr).min()?;
    let (m, _) = mint_created(&rec, (*ts)?, first.src.clone(), lo)?;
    let mut j = f.clone();
    j.join(m.clone());
    (j == *f && is_minted(&m, &rec)).then_some(m)
}

/// Whether `c` contains every write of `x` (joining `x` into it changes nothing), judged on the
/// piece of `c` at `x`'s positions (`Fragment::contains`: a replayed small commit costs about its
/// own size, not a copy of the whole cover). Debug builds check it against the whole join.
fn contains(c: &Fragment, x: &Fragment) -> bool {
    let yes = c.contains(x);
    if cfg!(debug_assertions) {
        let mut j = c.clone();
        j.join(x.clone());
        debug_assert!(!yes || j == *c, "a piece contains what the whole does not");
    }
    yes
}

/// The encoding context of an ephemeral commit's snapshot deltas by `me` at `ts`.
fn snapshot_ctx(ts: Ts, me: Tid) -> osis_crdt::DeltaCtx {
    let mut cx = osis_commit::writer_ctx(Kind::ContentSnapshot, ts, me, 0, 0);
    cx.own = Source::commit(CommitId([0; 32]));
    cx
}

/// The length of `f` encoded as an unpaged snapshot delta of an ephemeral commit by `me`.
fn delta_len(me: Tid, f: &Fragment) -> usize {
    let cx = snapshot_ctx(Ts::default(), me);
    let s = Snapshot { nonce: [0; osis_crdt::NONCE_LEN], fragment: f.clone(), frontiers: Frontiers::default(), absorbed: BTreeMap::new() };
    // unpaged encoding fails only on a malformed fragment: counted as nothing
    osis_crdt::encode_snapshot(&s, &cx, Some(&mut Unpaged)).map_or(0, |b| b.len())
}

/// Whether an own delta of one aspect of unpaged length `len` (`delta_len`) fits an ephemeral
/// commit's blob alone: within `MAX_BLOB` less room for a header with inline lists
/// (`CHUNK_THRESHOLD`).
fn fits_blob(len: usize) -> bool {
    len <= osis_base::format::MAX_BLOB.saturating_sub(osis_base::format::CHUNK_THRESHOLD)
}

/// The own writes of an aspect without the values of those that expire (a snapshot never
/// carries those, spec/crdt.md §8; an ephemeral commit carries only its author's writes).
fn own_unexpiring(a: &EphAspect, src: &Source) -> Fragment {
    let mut f = a.own_writes().clone();
    for ranges in a.expiring.values() {
        f.strip(&|d| in_ranges(d, src, ranges));
    }
    f
}

/// Strips own writes already expired from an aspect's state (a join may repeat their records).
fn strip_own_expired(a: &mut EphAspect, src: &Source) {
    let expired = &a.expired;
    if !expired.is_empty() && a.state.holds_dots(&|d| in_ranges(d, src, expired)) {
        a.state.strip(&|d| in_ranges(d, src, expired));
    }
}

/// Whether `ak` is a core aspect (one segment, spec/data-model.md §9) rather than a schema's.
/// Whether commit `h` has a part other than `/created` not expired at `now` (a commit's records
/// serve only its other parts).
fn live_parts(h: &Header, now: u64) -> bool {
    h.aspects.iter().any(|a| a.ak.as_str() != CREATED.ak() && !a.expires.is_some_and(|t| t <= now))
}

fn is_core_aspect(ak: &str) -> bool {
    ak.matches('/').count() == 1
}
