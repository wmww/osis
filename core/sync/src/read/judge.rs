//! The judgement of one body at S (`body`), of what it calls for at one source keeping S unread
//! (`toward`), from the ground's values alone. Pure reads: `Read`
//! runs these inside its effects and acts on what a new value adds.

use super::ground::{Facts, Ground, PieceAt, Seen, SrcView};
use super::{Verdict, Why};
use crate::inbox::Promotion;
use crate::store::{Source, Stand};
use crate::types::Result;
use osis_base::format::MAX_DRIFT_MS;
use osis_base::memo::{Clock, Stamped};
use osis_base::{BlobId, CommitId, SyncId, Tid};
use osis_engine::retention::Minting;
use osis_engine::sync::{BodyMeta, Loss, PieceLink, ReadCredentials};
use osis_blob::StepId;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// One thing read does (spec/sync-judgement.md §3-§5).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Act {
    /// The body into the own store (§3 Own store).
    Log,
    /// The body into the own store as a strip's rewrite (§2 per blob), then these entries, which
    /// it replaces, leave the own log.
    Rewrite(Vec<BlobId>),
    /// Entry `b` of the body in the own store stamped in place under S's head write key (same
    /// blob and wrap; §3 Own store), its own from then on.
    Restamp(BlobId),
    /// The entry leaves the own log (§3 Own store: must-not-hold, or covered and dropped).
    DropOwn(BlobId),
    /// The entry leaves the own log with no tombstone: judged outside S's required set
    /// (`outside`), a judgement the node may make wrongly while what it reads moves, or a body
    /// judged invalid here (`BodyFacts::invalid`: valid again, it is logged or pulled again).
    Unlog(BlobId),
    /// The body counts missing again: its own tombstone ends (§4, §3 Dropped bodies).
    Lift(BlobId),
    /// The body counts missing again: an entry of it held here is opened again from the store
    /// (§3 Dropped bodies: a body whose cover fell before its entry left, a purge's leftover).
    Take(BlobId),
    /// The body counts missing again: an entry of it a source's stream shows present is fetched
    /// there (§3 Dropped bodies), by streams.
    Fetch { at: Source, blob: BlobId },
    /// A Delete at a source keeping S unread, by its head's delete key (§3 Deletes); `full`: owed
    /// only while the source is full for S (a carrier it lacks counted as held, no role entry
    /// waited for), so it goes only on a connection the source told so.
    Delete { at: Source, head: StepId, blob: BlobId, full: bool },
    /// Logged again once past a delete at the source (§4), a fresh encryption: `old` leaves the
    /// own log; the stand records `head` and `fall`. `full`: as a Delete's.
    Again { at: Source, head: StepId, fall: u64, old: Vec<BlobId>, full: bool },
    /// The body given to a source this node does not stamp for (§3 Reader that is not a writer).
    Deposit { at: Source, blob: BlobId },
    /// A held piece of a must-hold body into the own store (§1: the same blob, a filler wrap).
    LogPiece(BlobId),
    /// A missing piece whose bytes the store holds (a peer's entry): taken by the engine.
    TakePiece(BlobId),
    /// A piece of an own body every source showing it deleted (spec/sync-ids.md §1 Repair).
    Repair(BlobId),
    /// An own entry of a blob naming no commit leaves: a freed link's (spec/sync-compaction.md §1
    /// Freed links).
    DropBlob(BlobId),
    /// A freed link deleted at a source keeping S unread whose stream shows it.
    DeleteFreed { at: Source, head: StepId, blob: BlobId, thing: Tid },
}

impl Act {
    /// The source an act is carried out toward, on its record's connection (`read/owed.rs`);
    /// `None`: an act on the own store or the engine, carried out at once.
    pub fn toward(&self) -> Option<Source> {
        match self {
            Act::Fetch { at, .. } | Act::Delete { at, .. } | Act::Again { at, .. } | Act::Deposit { at, .. } | Act::DeleteFreed { at, .. } => Some(*at),
            _ => None,
        }
    }

    /// Whether it goes only while the source is full for S.
    pub fn needs_full(&self) -> bool {
        matches!(self, Act::Delete { full: true, .. } | Act::Again { full: true, .. })
    }

    /// The same act owed only while the source is full.
    fn when_full(mut self) -> Act {
        if let Act::Delete { full, .. } | Act::Again { full, .. } = &mut self {
            *full = true;
        }
        self
    }
}

/// One body's judgement at S, and what it calls for in the own store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Judged {
    pub verdict: Verdict,
    /// An own role commit S must hold (what Role entries first waits for).
    pub role: bool,
    pub acts: BTreeSet<Act>,
    /// Nothing of the body is under S here or at a source: no longer followed.
    pub idle: bool,
    /// A must-hold body's links (`Engine::piece_roots`): where its pieces start.
    pub roots: Arc<Vec<PieceLink>>,
    /// An own body: its pieces are repaired, but those it encrypted afresh as a repair
    /// (`fresh`; spec/sync-ids.md §1).
    pub repairs: bool,
    pub fresh: Arc<BTreeSet<BlobId>>,
    /// Outside S's required set as judged now, but not past a complete pass of S begun after this
    /// pass place (`outside`): unjudged until one ends.
    pub wait: Option<u64>,
}

impl Default for Judged {
    fn default() -> Self {
        Judged { verdict: Verdict::Unjudged, role: false, acts: BTreeSet::new(), idle: false, roots: Arc::default(), repairs: false, fresh: Arc::default(), wait: None }
    }
}

/// One piece at S, linked by a must-hold body here: what it calls for, and what lies one step
/// below it (`Engine::piece_below`; nothing while it is missing).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PieceJudged {
    pub held: bool,
    pub acts: BTreeSet<Act>,
    pub kids: Arc<Vec<PieceLink>>,
}

/// What one body at S calls for at one source.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Toward {
    pub acts: BTreeSet<Act>,
    /// Nothing to do there and nothing of it shown there: no longer followed.
    pub idle: bool,
}

/// What a judgement reads of read's own state.
pub(crate) struct Mine<'a> {
    pub verdicts: &'a Stamped<(SyncId, CommitId), Verdict>,
    pub roles: &'a Stamped<SyncId, BTreeSet<CommitId>>,
    pub clock: &'a Clock,
    /// Each (S, commit)'s body at S, as `Read::bodies` last settled it.
    pub metas: &'a Stamped<(SyncId, CommitId), BodyMeta>,
    /// Per (S, minting, thing) the header-only copy's place among the thing's mintings, as
    /// `Read::mintings` last settled them.
    pub mints: &'a Stamped<(SyncId, CommitId, Tid), Mint>,
    /// Per (S, commit), the pass place an entry of it last came into the own store of S.
    pub arrived: &'a Stamped<(SyncId, CommitId), u64>,
    /// Per commit, the pass place what its bodies read (`Ground::bodies`) last moved.
    pub moved: &'a Stamped<CommitId, u64>,
}

/// A header-only copy of a minting under S whose closure lacks its thing, by its place among the
/// thing's held mintings (spec/commits.md §5 A thing's mintings travel with its record).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mint {
    /// The witness, with no entry under S holding another minting of its standing: logged.
    Log,
    /// Kept where held, not logged.
    Keep,
}

/// Each minting of `ms` (a thing's held mintings) under S where `held` says which have an entry
/// there: the witness is logged unless another minting of its standing is held there; the rest
/// are kept.
pub(crate) fn rank(ms: &[Minting], mut held: impl FnMut(&CommitId) -> Result<bool>) -> Result<BTreeMap<CommitId, Mint>> {
    let mut out = BTreeMap::new();
    let Some(w) = osis_engine::retention::highest(ms) else { return Ok(out) };
    let mut tie = false;
    for m in ms.iter().filter(|m| m.standing == w.standing && m.commit != w.commit) {
        tie |= held(&m.commit)?;
    }
    for m in ms {
        out.insert(m.commit, if m.commit == w.commit && !tie { Mint::Log } else { Mint::Keep });
    }
    Ok(out)
}

/// Thing `t`'s mintings whose header-only copy is in S's required set as a minting of `t`
/// (`BodyMeta::mints`), each by `rank` over every held minting of `t` and the own store of S.
/// Empty: none is (no longer followed).
pub(crate) fn mintings(g: &mut impl Ground, metas: &Stamped<(SyncId, CommitId), BodyMeta>, s: &SyncId, t: &Tid) -> Result<Arc<BTreeMap<CommitId, Mint>>> {
    osis_base::costs::count("read: mintings", 1);
    let ms = g.mintings(t);
    let mut ranked = rank(&ms, |c| Ok(!g.own(s, c)?.is_empty()))?;
    ranked.retain(|c, _| metas.get(&(*s, *c)).is_some_and(|m| m.mints.contains(t)));
    Ok(Arc::new(ranked))
}

/// A header-only minting copy's verdict from its places among its things' mintings (`Mint`): the
/// most any thing gives it; unjudged while a thing's is not settled.
fn minted(mine: &Mine, s: &SyncId, c: &CommitId, meta: &BodyMeta) -> Verdict {
    let mut v = Verdict::May;
    for t in &meta.mints {
        match mine.mints.get(&(*s, *c, *t)) {
            None => return Verdict::Unjudged,
            Some(Mint::Log) => v = Verdict::Must,
            Some(Mint::Keep) => {}
        }
    }
    v
}

impl Mine<'_> {
    /// Commit `c`'s body at `s` (`Ground::bodies`), a read of that pair alone: a body coming or
    /// going at another sync ID moves no judgement here.
    fn meta(&self, s: &SyncId, c: &CommitId) -> Option<&BodyMeta> {
        self.metas.get(&(*s, *c))
    }

    /// `t` has come (the answer moves when the clock reaches it).
    fn reached(&self, t: u64) -> bool {
        t <= self.clock.until(Some(t))
    }
}

/// Outside S's required set as this node judges it now (spec/sync-judgement.md §2): final only
/// past a complete pass of S begun after both an entry of it came and what its bodies read last
/// moved (§1 Unjudged blobs: what arrives in that pass may still put it inside), else unjudged,
/// with the place the wait runs from.
fn outside(g: &mut impl Ground, mine: &Mine, s: &SyncId, c: &CommitId) -> (Verdict, Option<u64>) {
    let since = mine.arrived.get(&(*s, *c)).copied().unwrap_or(0).max(mine.moved.get(c).copied().unwrap_or(0));
    match g.passed(s, since) {
        true => (Verdict::MustNot(Why::OutsideRequired), None),
        false => (Verdict::Unjudged, Some(since)),
    }
}

/// Held blob `b` of a commit whose body at S is a certificate (`meta`): a copy holding deltas, none
/// of them one S's certificates name, is outside S's required set by the deltas it holds
/// (spec/sync-judgement.md §2), whatever the body: an account's rotation past its current
/// `keys.0` is named for its header alone (spec/permissions.md §4).
fn unnamed_copy(g: &mut impl Ground, meta: &BodyMeta, b: &BlobId) -> Result<bool> {
    if !meta.certificate {
        return Ok(false);
    }
    Ok(g.blob(b)?.is_some_and(|i| i.copy && !i.parts.is_empty() && i.parts.is_disjoint(&meta.parts)))
}

/// Of `blobs` of `c`, the unnamed copies (`unnamed_copy`) and, while any is, whether the
/// judgement that they are outside is final (`outside`) and the wait otherwise.
fn unnamed_copies(g: &mut impl Ground, mine: &Mine, s: &SyncId, c: &CommitId, blobs: &BTreeSet<BlobId>) -> Result<(Vec<BlobId>, bool, Option<u64>)> {
    let Some(meta) = mine.meta(s, c) else { return Ok((Vec::new(), false, None)) };
    let mut out = Vec::new();
    for b in blobs {
        if unnamed_copy(g, meta, b)? {
            out.push(*b);
        }
    }
    if out.is_empty() {
        return Ok((out, false, None));
    }
    let (v, wait) = outside(g, mine, s, c);
    Ok((out, matches!(v, Verdict::MustNot(_)), wait))
}

/// spec/sync-judgement.md §2: what the body is at S, with the clause that decided it (a debug
/// trace's reason, `last_why`).
fn classify(mine: &Mine, f: &Facts, s: &SyncId, c: &CommitId, meta: &BodyMeta, later_held: bool) -> (Verdict, &'static str) {
    if let Some(w) = f.must_not {
        return (Verdict::MustNot(w), "its facts say must-not");
    }
    if meta.expires.is_some_and(|e| mine.reached(e.0)) {
        return (Verdict::MustNot(Why::Expired), "expired");
    }
    if !f.body.required {
        return (Verdict::MustNot(Why::OutsideRequired), "outside S's required set");
    }
    if !meta.mints.is_empty() {
        return (minted(mine, s, c, meta), "a minting copy, by its places among its things' mintings");
    }
    // judged invalid here: kept by none of must-hold's clauses, never logged (§3 Own store)
    if f.body.invalid {
        return (Verdict::May, "judged invalid here");
    }
    // not held here (dropped): kept by none of must-hold's clauses
    if f.body.dropped.is_some() {
        return (Verdict::May, "dropped here");
    }
    // a certificate, header-only or not: must-hold but a sole one (its author has no other blob)
    if meta.certificate || !f.body.closure {
        return if f.body.sole_certificate { (Verdict::May, "a sole certificate") } else { (Verdict::Must, if meta.certificate { "a certificate" } else { "outside the node closure, required" }) };
    }
    if meta.header_only {
        return if f.body.lasting_header { (Verdict::Must, "a lasting header") } else { (Verdict::May, "a header-only copy, not lasting") };
    }
    if f.body.kept {
        return (Verdict::Must, "kept by retention");
    }
    match f.body.covered {
        None => (Verdict::Unjudged, "coverage not settled"),
        Some(false) if !later_held => (Verdict::Must, "not covered, no later snapshot held"),
        Some(false) => (Verdict::May, "a later snapshot is held"),
        Some(true) => (Verdict::May, "covered by a held snapshot"),
    }
}

#[cfg(debug_assertions)]
thread_local! {
    static WHY: std::cell::Cell<&'static str> = const { std::cell::Cell::new("") };
}

/// Debug builds: the reason the last `body` judged gave for its verdict.
#[cfg(debug_assertions)]
pub(crate) fn last_why() -> &'static str {
    WHY.with(std::cell::Cell::get)
}

/// Covered and dropped where `held` says which commits are held (spec/sync-judgement.md §3,
/// spec/sync-compaction.md §1 Carriers): a may-hold body a held valid snapshot covers, past its
/// keep-at-least bound, each delta needing a carrier having one held there. A certificate but a
/// sole one (a lasting header has no delta to cover) is required whatever snapshot covers it:
/// never dropped as covered, may-hold only while this node may not log it (§2 Loggable: kept).
fn covered_dropped<G: Ground>(g: &mut G, s: &SyncId, c: &CommitId, v: &Verdict, f: &Facts, mut held: impl FnMut(&mut G, &CommitId) -> Result<bool>) -> Result<bool> {
    if *v != Verdict::May || f.body.covered != Some(true) || f.body.kept || (!f.body.closure && !f.body.sole_certificate) {
        return Ok(false);
    }
    for alternatives in g.carriers(s, c)? {
        let mut any = false;
        for c in &alternatives {
            if held(g, c)? {
                any = true;
                break;
            }
        }
        if !any {
            return Ok(false);
        }
    }
    Ok(true)
}

/// One body at S: its verdict and what it calls for in the own store.
pub(crate) fn body(g: &mut impl Ground, mine: &Mine, s: &SyncId, c: &CommitId) -> Result<Judged> {
    osis_base::costs::count("read: judged", 1);
    let mut j = Judged::default();
    if !g.reads(s) {
        #[cfg(debug_assertions)]
        WHY.with(|x| x.set("S is not read here"));
        j.idle = true;
        return Ok(j);
    }
    let own = g.own(s, c)?;
    // per blob (spec/sync-judgement.md §2): an entry carrying a part that strips here is
    // must-not-hold, whatever the body's verdict, and one losing to another held entry of it
    // leaves too: as needed (another carries a part only a blob carries that it lacks: a strict
    // loss, must-not-hold), or as spare (fewer sections this node did not open, or the same under
    // a lower ID). The body counts as unlogged until the rest is logged as the strip's rewrite
    let mut stale: Vec<BlobId> = own.iter().map(|e| e.blob).filter(|b| g.gone(b).is_some()).collect();
    let mut held: BTreeSet<BlobId> = own.iter().map(|e| e.blob).filter(|b| !stale.contains(b)).collect();
    // a certificate copy holding none of what S names of it leaves as outside, once final
    let (unnamed, unnamed_gone, unnamed_wait) = unnamed_copies(g, mine, s, c, &held)?;
    let unnamed: Vec<BlobId> = if unnamed_gone { unnamed } else { Vec::new() };
    held.retain(|b| !unnamed.contains(b));
    // only an entry that may stand as the body's log beats another as spare: one holding the
    // body, not a peer's deposit awaiting promotion
    let mut stands = BTreeSet::new();
    if let Some(meta) = mine.meta(s, c) {
        for e in own.iter().filter(|e| held.contains(&e.blob) && (e.own || !e.deposited)) {
            if g.holds_body(meta, &e.blob)? {
                stands.insert(e.blob);
            }
        }
    }
    let mut subsets = Vec::new();
    let mut spare = Vec::new();
    for b in &held {
        let mut lost = None;
        for o in held.iter().filter(|o| *o != b) {
            lost = lost.max(g.loses(s, b, o, (stands.contains(b), stands.contains(o)))?);
            if lost == Some(Loss::Needed) {
                break;
            }
        }
        match lost {
            Some(Loss::Needed) => subsets.push(*b),
            Some(Loss::Spare) => spare.push(*b),
            None => {}
        }
    }
    stale.extend(spare);
    held.retain(|b| !stale.contains(b));
    let live: Vec<BlobId> = held.iter().copied().filter(|b| !subsets.contains(b)).collect();
    #[allow(unused_assignments)]
    let mut why = "no body meta at S: its unit is not settled";
    let (f, verdict) = match mine.meta(s, c) {
        None if !g.unit_settled(s)? => (None, Verdict::Unjudged),
        None => {
            let (v, wait) = outside(g, mine, s, c);
            why = if wait.is_some() { "no body meta at S: outside, waiting for a complete pass" } else { "no body meta at S: outside S's required set" };
            j.wait = wait;
            (None, v)
        }
        Some(meta) => {
            let f = g.facts(s, c)?;
            let mut later_held = false;
            // one this node judged invalid does not count (never-quiet)
            for (snap, invalid) in &f.later_unheld {
                if !*invalid && (!g.own(s, snap)?.is_empty() || g.present_anywhere(s, snap)?) {
                    later_held = true;
                    break;
                }
            }
            let (mut v, w) = classify(mine, &f, s, c, meta, later_held);
            why = w;
            // must-hold only what this node may log under S (§2 Loggable): else may-hold, kept
            // if it arrives, never relayed, deposited or owed
            if v == Verdict::Must && !g.may_log(s, c)? {
                v = Verdict::May;
                why = "must-hold but not loggable here";
            }
            if v == Verdict::MustNot(Why::OutsideRequired) {
                let (x, wait) = outside(g, mine, s, c);
                if wait.is_some() {
                    why = "outside S's required set, waiting for a complete pass";
                }
                v = x;
                j.wait = wait;
            }
            (Some(f), v)
        }
    };
    #[cfg(debug_assertions)]
    WHY.with(|x| x.set(why));
    #[cfg(not(debug_assertions))]
    let _ = why;
    j.verdict = verdict.clone();
    j.role = verdict == Verdict::Must && f.as_ref().is_some_and(|f| f.own && f.role);
    // a body counting missing again: its own tombstones end, an entry of it held here is taken
    // again, and it is fetched again where a source shows another entry of it present (a source
    // joining or showing one judges it again)
    if f.as_ref().is_some_and(|f| f.missing) {
        j.acts.extend(g.own_tombstones(s, c)?.into_iter().map(Act::Lift));
        j.acts.extend(own.iter().filter(|e| !stale.contains(&e.blob)).map(|e| Act::Take(e.blob)));
        for at in g.reached(s) {
            for b in g.seen(&at, s, c)?.present {
                if !own.iter().any(|e| e.blob == b) {
                    j.acts.insert(Act::Fetch { at, blob: b });
                }
            }
        }
    }
    j.wait = j.wait.or(unnamed_wait);
    let present = g.present_anywhere(s, c)?;
    j.idle = mine.meta(s, c).is_none() && own.is_empty() && !present;
    // a wait matters only where something of it is held here or at a source
    if live.is_empty() && !present {
        j.wait = None;
    }
    j.acts.extend(stale.iter().chain(&subsets).map(|b| Act::DropOwn(*b)));
    j.acts.extend(unnamed.iter().map(|b| Act::Unlog(*b)));
    if verdict == Verdict::Unjudged {
        return Ok(j);
    }
    // own store (§3 Own store): it follows this node's judgement alone, no delete key needed;
    // carriers are read only where an entry would leave
    let dropped_here = match &f {
        Some(f) if !live.is_empty() => covered_dropped(g, s, c, &verdict, f, |g, x| Ok(!g.own(s, x)?.is_empty()))?,
        _ => false,
    };
    // judged invalid here, the body leaves the own store with no tombstone, so the node is no
    // refetch source of it and its commit becomes forgettable (spec/commits.md §5 Forgetting);
    // valid again, it counts missing and is fetched where shown, or pulled when a holder logs it
    // again (the author keeps its own and logs it once valid: invariant, every honest holder
    // judging it invalid drops its entry only while every holder judging it valid keeps it)
    let invalid = f.as_ref().is_some_and(|f| f.body.invalid);
    if verdict == Verdict::MustNot(Why::OutsideRequired) || (verdict == Verdict::May && invalid) {
        j.acts.extend(live.iter().map(|b| Act::Unlog(*b)));
    } else if matches!(verdict, Verdict::MustNot(_)) || dropped_here {
        j.acts.extend(live.iter().map(|b| Act::DropOwn(*b)));
    }
    // a body counting missing is logged once it is held again. Where this node writes S's head,
    // an entry stands as its log only stamped under that head (`Ground::stands`): each own entry
    // that does not is stamped in place, and with none of its own and none standing, the lowest
    // peer's stamped entry is (a head move restamps each body once; peers' duplicates are never
    // stamped). A peer's deposit is stamped in place only as promoted (spec/sync-inbox.md §4,
    // `Ground::promotion`), standing or not, and one promoted later holds the body back from a
    // log of its own meanwhile. Whether a reader can pull S (`pullable`) is read last, only
    // where there is something to log: a body standing reads no source flip.
    if verdict == Verdict::Must && !f.as_ref().is_some_and(|f| f.missing) {
        let mut stands = false;
        let mut restamp = Vec::new();
        let mut peer = None;
        let mut promoted = None;
        let mut waits = false;
        for e in own.iter().filter(|e| live.contains(&e.blob)) {
            // an entry of fewer parts (a certificate copy the body outgrew) is no log of it
            if !mine.meta(s, c).map_or(Ok(false), |m| g.holds_body(m, &e.blob))? {
                continue;
            }
            if e.deposited && !e.own {
                match g.promotion(s, c, &e.blob)? {
                    Promotion::Yes => promoted = promoted.or(Some(e.blob)),
                    Promotion::Wait => waits = true,
                    Promotion::No => {}
                }
            } else if g.stands(s, c, e)? {
                stands = true;
            } else if e.own {
                restamp.push(e.blob);
            } else {
                peer = peer.or(Some(e.blob));
            }
        }
        if !stands && restamp.is_empty() {
            restamp.extend(peer);
        }
        restamp.extend(promoted);
        let mut log = !stands && restamp.is_empty() && !waits;
        // another's body (or certificate) is logged here only once S's first sync here ended,
        // or a complete pass of S begun after what decides the body last moved did (none
        // connected to sync it from: at once): a source's entry of it, pulled, stands as the log
        // (spec/sync-judgement.md §3 Own store; spec/sync-streams.md §5), so a new reader logs no
        // copy of what its sources hold
        if log && !f.as_ref().is_some_and(|f| f.own) && !g.first_synced(s)? {
            let since = mine.arrived.get(&(*s, *c)).copied().unwrap_or(0).max(mine.moved.get(c).copied().unwrap_or(0));
            if !g.passed(s, since) {
                #[cfg(debug_assertions)]
                osis_base::trace::note(|| format!("log held back {s:?} {c:?}: first sync, a pass after {since}"));
                log = false;
                j.wait = j.wait.max(Some(since));
            }
        }
        if (log || !restamp.is_empty()) && g.pullable(s)? {
            if log {
                j.acts.insert(Act::Log);
            }
            j.acts.extend(restamp.into_iter().map(Act::Restamp));
        }
    }
    // a strip's rewrite is one act: the rest logged, then the entries it replaces leave (a log
    // already called for before the entries went stale is no new act)
    if !stale.is_empty() && j.acts.remove(&Act::Log) {
        for b in &stale {
            j.acts.remove(&Act::DropOwn(*b));
        }
        j.acts.insert(Act::Rewrite(stale.clone()));
    }
    if verdict == Verdict::Must {
        // the body's parts as its meta gives them (read's `bodies` effect), not `sync_bodies`
        // again: that reads every sync ID's body of `c`
        if let Some(meta) = mine.meta(s, c) {
            j.roots = g.piece_roots(c, &meta.parts)?;
        }
        j.repairs = f.as_ref().is_some_and(|f| f.own);
        j.fresh = f.as_ref().map(|f| f.repair_fresh.clone()).unwrap_or_default();
    }
    Ok(j)
}

/// One piece of the must-hold bodies at S (§1: their linked blobs go under S beside them): a held
/// one with no own entry is logged, a missing one is taken from a peer's entry here or fetched
/// where a source shows it. A held one some source shows deleted and none present is lost
/// (`Act::Repair`; spec/sync-ids.md §1 Repair), judged once S's sources are heard out; read
/// repairs it in the own bodies linking it that a repair did not write.
pub(crate) fn piece(g: &mut impl Ground, s: &SyncId, p: &PieceLink) -> Result<PieceJudged> {
    osis_base::costs::count("read: piece judged", 1);
    let b = p.blob();
    let mut j = PieceJudged::default();
    let Some(kids) = g.piece_below(p)? else {
        if g.piece(s, &b)? == PieceAt::Peer {
            j.acts.insert(Act::TakePiece(b));
            return Ok(j);
        }
        for at in g.reached(s) {
            if g.blob_shown(&at, s, &b) {
                j.acts.insert(Act::Fetch { at, blob: b });
            }
        }
        return Ok(j);
    };
    j.held = true;
    j.kids = kids;
    if !matches!(g.piece(s, &b)?, PieceAt::Own | PieceAt::Tombstoned) && g.pullable(s)? {
        j.acts.insert(Act::LogPiece(b));
    }
    // lost: some source reached now shows it deleted and none reached now shows it present, S's
    // sources heard out (every entry of S each can open applied; spec/sync-ids.md §1 Repair).
    // Whether a source is reached is read only past a deletion seen, so a reconnect judges no
    // piece no source deleted
    let sources = g.reached(s);
    let mut deleted = Vec::new();
    for at in &sources {
        if g.blob_deleted(at, s, &b)? {
            deleted.push(*at);
        }
    }
    if deleted.is_empty() {
        return Ok(j);
    }
    let up: Vec<Source> = sources.into_iter().filter(|at| g.connected(at).is_some()).collect();
    if up.iter().any(|at| g.blob_shown(at, s, &b)) || !deleted.iter().any(|at| up.contains(at)) {
        return Ok(j);
    }
    if g.heard_out(s)? {
        j.acts.insert(Act::Repair(b));
    }
    Ok(j)
}

/// A freed link's acts per sync ID, and whether an entry of it is still known here.
pub(crate) type Freed = (BTreeSet<(SyncId, Act)>, bool);

/// What freed link `b` of thing `t` calls for (spec/sync-compaction.md §1 Freed links): under each
/// sync ID read here carrying `t`, its own entry leaves and it is deleted at each source keeping
/// S unread whose stream shows it. `true` with the acts: an entry of it is still known here (own,
/// or at such a source).
pub(crate) fn freed(g: &mut impl Ground, b: &BlobId, t: &Tid) -> Result<Freed> {
    osis_base::costs::count("read: freed", 1);
    let mut acts = BTreeSet::new();
    let mut known = false;
    if !g.freed_link(b, t) {
        return Ok((acts, false));
    }
    for s in g.carrying(t)? {
        if !g.reads(&s) {
            continue;
        }
        if matches!(g.piece(&s, b)?, PieceAt::Own | PieceAt::Peer) {
            known = true;
            acts.insert((s, Act::DropBlob(*b)));
        }
        for src in g.sources(&s).iter() {
            // a reader judges its own entries: only a store's count
            if !src.store || !g.blob_shown(&src.at, &s, b) {
                continue;
            }
            known = true;
            if let Some(head) = src.head {
                acts.insert((s, Act::DeleteFreed { at: src.at, head, blob: *b, thing: *t }));
            }
        }
    }
    Ok((acts, known))
}

/// What a body at S calls for at the source at `at` (§3 At a source keeping S unread; §4).
/// Between readers nothing but streams: a source reading S calls for nothing.
///
/// What it owes there is judged from what that source's stream shows (`known`, kept while it is
/// away), whether it is up now or not: a delete owed stays owed until its stream no longer shows
/// the entry. Only a body owing something reads whether the source is up (to carry it out on
/// that connection), so a source coming back judges again what is owed there, nothing else.
pub(crate) fn toward(g: &mut impl Ground, mine: &Mine, s: &SyncId, c: &CommitId, at: &Source) -> Result<Toward> {
    osis_base::costs::count("read: toward", 1);
    let mut t = Toward::default();
    if !g.kept_at(s, at) {
        t.idle = true;
        return Ok(t);
    }
    let seen = g.seen(at, s, c)?;
    let verdict = mine.verdicts.get(&(*s, *c)).cloned().unwrap_or(Verdict::Unjudged);
    let creds = g.credentials(s)?;
    let head = g.head_at(s, at);
    let keys = head.and_then(|h| creds.as_ref()?.keys.get(&h).cloned());
    let writer = keys.as_ref().is_some_and(|k| k.write.is_some());
    let quiet = seen.present.is_empty() && seen.deleted.is_empty();
    t.idle = quiet && (writer || verdict != Verdict::Must);
    // unjudged calls for nothing yet but a strip's deletes: an entry gone here goes whatever the
    // body is judged (spec/sync-judgement.md §2 per blob)
    if verdict == Verdict::Unjudged && !seen.present.iter().any(|b| g.gone(b).is_some()) {
        return Ok(t);
    }
    let (Some(head), Some(creds)) = (head, creds.as_deref()) else { return Ok(t) };
    let f = match mine.meta(s, c).is_some() {
        true => Some(g.facts(s, c)?),
        false => None,
    };
    let calls = |g: &mut _, t: &mut Toward, src: &SrcView, full: bool| -> Result<()> {
        if f.is_some() {
            at_source(g, mine, t, src, full, &seen, s, c, &verdict, head, creds, writer, f.as_ref().is_some_and(|f| f.role))?;
        }
        if keys.is_some() && !seen.present.is_empty() {
            deletes(g, mine, t, src, full, &seen, s, c, f.as_ref(), &verdict, head, creds)?;
        }
        Ok(())
    };
    // owed there as if full (what full adds only lets more go): nothing owed reads nothing of
    // the source's membership
    let mut owed = Toward::default();
    calls(g, &mut owed, &SrcView { at: *at, store: true, head: Some(head), role_unheld: false }, true)?;
    if owed.acts.is_empty() {
        return Ok(t);
    }
    // a source of S, up or away (its record keeps it): what it is owed goes once it is connected
    // (`read/owed.rs`); one no longer a source stays followed while its stream shows the body
    let Some(src) = g.source(s, at) else { return Ok(t) };
    if !src.store {
        t.idle = true;
        return Ok(t);
    }
    // what is owed only while the source is full goes only on a connection it told so
    calls(g, &mut t, &src, false)?;
    let mut full = Toward::default();
    calls(g, &mut full, &src, true)?;
    let more: Vec<Act> = full.acts.difference(&t.acts).cloned().collect();
    t.acts.extend(more.into_iter().map(Act::when_full));
    t.idle &= t.acts.is_empty();
    Ok(t)
}

/// §3 Role entries first: the source, on this node's head, not full, lacks an own role commit
/// S must hold (not present there and not deleted there; one it refused included), read from the
/// own store and the source's stream, never from what was sent. `c` itself waits for no other
/// copy of itself.
fn role_wait(g: &mut impl Ground, mine: &Mine, src: &SrcView, full: bool, s: &SyncId, c: &CommitId, creds: &ReadCredentials) -> Result<bool> {
    let ours = creds.head.as_ref().map(|h| h.id());
    if full || src.head.is_none() || src.head != ours {
        return Ok(false);
    }
    let Some(roles) = mine.roles.get(s) else { return Ok(false) };
    for r in roles.iter().filter(|r| *r != c) {
        let own = g.own(s, r)?;
        let seen = g.seen(&src.at, s, r)?;
        if seen.present.is_empty() && !own.iter().any(|e| seen.deleted.contains(&e.blob)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Deletes at a source keeping S unread (§3 Deletes, Agreement of grounds; compaction §1
/// Carriers, Duplicates) of the entries this node can sign a Delete of, while no role entry of this node's is lacking there and its stream
/// shows no role commit this node does not hold.
#[allow(clippy::too_many_arguments)]
fn deletes(g: &mut impl Ground, mine: &Mine, t: &mut Toward, src: &SrcView, full: bool, seen: &Seen, s: &SyncId, c: &CommitId, f: Option<&Facts>, verdict: &Verdict, head: StepId, creds: &ReadCredentials) -> Result<()> {
    let why = match verdict {
        // an expired entry leaves every store by itself
        Verdict::MustNot(Why::Expired) => return Ok(()),
        Verdict::MustNot(_) => true,
        // a carrier it lacks counts as held at a full source: it takes it with the delete
        // and it waits `MAX_DRIFT` past its keep-at-least bound (spec/commits.md §5 Keep at
        // least: every node's clock agrees it left history)
        _ => match f {
            Some(f) => covered_dropped(g, s, c, verdict, f, |g, x| Ok(full || !g.seen(&src.at, s, x)?.present.is_empty()))? && mine.reached(f.body.hosts_from),
            None => false,
        },
    };
    // a body judged invalid is never deleted at a peer (spec/permissions.md §6)
    if f.is_some_and(|f| f.body.invalid || f.body.dropped == Some(osis_engine::engine::DropFor::Invalid)) {
        return Ok(());
    }
    let blobs: Vec<BlobId> = if why {
        seen.present.iter().copied().collect()
    } else {
        let copy = mine.meta(s, c).is_some_and(|m| m.copy);
        let judged = *verdict != Verdict::Unjudged;
        let mut out = if judged { duplicates(g, seen, copy)? } else { Vec::new() };
        // a copy holding none of what S names of it (§2), once final, and only beside another
        // entry of it there: the source never holds neither the old copy nor its replacement
        let (unnamed, gone, _) = if judged { unnamed_copies(g, mine, s, c, &seen.present)? } else { (Vec::new(), false, None) };
        let mut present = seen.present.clone();
        present.retain(|b| !gone || !unnamed.contains(b));
        if gone && !present.is_empty() {
            for b in unnamed {
                if !out.contains(&b) {
                    out.push(b);
                }
            }
        }
        // losing as needed to another entry of it there (§2 Per blob), which carries it there
        for b in present.iter().filter(|_| judged) {
            if out.contains(b) {
                continue;
            }
            for o in present.iter().filter(|o| *o != b) {
                if g.loses(s, b, o, (true, true))? == Some(Loss::Needed) {
                    out.push(*b);
                    break;
                }
            }
        }
        // a strip (§2 per blob): an entry carrying a part that strips here, once each part of it
        // held here has another entry there not gone carrying it, and each part it strips as
        // covered a snapshot reaching it there, `MAX_DRIFT` past its keep bound
        for b in &present {
            if out.contains(b) {
                continue;
            }
            let Some(st) = g.gone(b) else { continue };
            if !mine.reached(st.from) {
                continue;
            }
            let mut carried = true;
            for alt in &st.covers {
                let mut any = full;
                for x in alt {
                    if any {
                        break;
                    }
                    any = !g.seen(&src.at, s, x)?.present.is_empty();
                }
                carried &= any;
            }
            for ai in &st.live {
                let mut any = full;
                for x in present.iter().filter(|x| *x != b) {
                    if any {
                        break;
                    }
                    any = g.gone(x).is_none() && g.blob(x)?.is_some_and(|i| i.parts.contains(ai));
                }
                carried &= any;
            }
            if carried {
                out.push(*b);
            }
        }
        out
    };
    if blobs.is_empty() || src.role_unheld || role_wait(g, mine, src, full, s, c, creds)? {
        return Ok(());
    }
    // each by the delete key or the level keys held for it (spec/sync-ids.md §6 Delete); without
    // them nothing is sent
    for blob in blobs {
        if g.delete_item(s, &head, &blob)?.is_some() {
            t.acts.insert(Act::Delete { at: src.at, head, blob, full: false });
        }
    }
    Ok(())
}

/// spec/sync-compaction.md §1 Duplicates: of entries of one commit with the same delta set, both
/// copies or both not, all but the lowest blob ID go; where S's body is a per-sync-ID copy, a
/// shared blob beside a copy goes whatever its ID. The same delta set as this node checked it: the
/// same parts opened and the same unopened sections byte for byte. An entry whose bytes are not
/// held is none.
fn duplicates(g: &mut impl Ground, seen: &Seen, copy_body: bool) -> Result<Vec<BlobId>> {
    if seen.present.len() < 2 {
        return Ok(Vec::new());
    }
    let mut groups: BTreeMap<_, (Vec<BlobId>, Vec<BlobId>)> = BTreeMap::new();
    for b in &seen.present {
        if let Some(info) = g.blob(b)? {
            let (copies, shared) = groups.entry((info.parts, info.sealed)).or_default();
            if info.copy { copies } else { shared }.push(*b);
        }
    }
    let mut out = Vec::new();
    for (copies, shared) in groups.into_values() {
        out.extend(copies.iter().skip(1));
        if copy_body && !copies.is_empty() {
            out.extend(shared);
        } else {
            out.extend(shared.iter().skip(1));
        }
    }
    Ok(out)
}

/// A must-hold body the source lacks (§3 Reader that is not a writer; §4 Logged again once).
#[allow(clippy::too_many_arguments)]
fn at_source(g: &mut impl Ground, mine: &Mine, t: &mut Toward, src: &SrcView, full: bool, seen: &Seen, s: &SyncId, c: &CommitId, verdict: &Verdict, head: StepId, creds: &ReadCredentials, writer: bool, role: bool) -> Result<()> {
    // what the source holds of it carries the body (§3 Neither): nothing to relay
    if *verdict != Verdict::Must || (!seen.present.is_empty() && g.neither(s, c, &seen.present)?) {
        return Ok(());
    }
    let own = g.own(s, c)?;
    if let Some(e) = own.iter().find(|e| !seen.deleted.contains(&e.blob) && !seen.present.contains(&e.blob)) {
        // a writer's own store is pulled; a non-writer gives it, but not to a source on an
        // earlier step of the recorded path: the path is registered there first (spec/sync-ids.md
        // §6 Steps), and what this node holds stamped under a later step is taken as it is
        // once the source stands there. A role commit goes there all the same: registering
        // waits on the source holding the ones the step depends on, and a copy stamped under
        // its head may be held nowhere
        let behind = !role && creds.head.as_ref().is_some_and(|h| h.id() != head) && creds.keys.contains_key(&head);
        if !writer && !behind {
            t.acts.insert(Act::Deposit { at: src.at, blob: e.blob });
        }
        return Ok(());
    }
    if !own.iter().any(|e| seen.deleted.contains(&e.blob)) {
        return Ok(());
    }
    // every own entry of it was deleted there or is there short of what only a blob carries:
    // logged again once per change of ground, but not a
    // body expiring within MAX_DRIFT
    let expires = mine.meta(s, c).and_then(|m| m.expires);
    if expires.is_some_and(|e| mine.reached(e.0.saturating_sub(MAX_DRIFT_MS))) {
        return Ok(());
    }
    let fall = g.fall_mark(s, c);
    if g.stand(&src.at, s, c)?.is_some_and(|st: Stand| st.head == head && st.fall == fall) {
        return Ok(());
    }
    if role_wait(g, mine, src, full, s, c, creds)? {
        return Ok(());
    }
    t.acts.insert(Act::Again { at: src.at, head, fall, old: own.iter().map(|e| e.blob).collect(), full: false });
    Ok(())
}

/// What a held commit calls for in the engine (spec/commits.md §5 Covered, Forgetting).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum Local {
    /// Not held: no longer followed.
    #[default]
    Gone,
    /// Kept as it is.
    Kept,
    /// Parts to drop as covered (`Engine::covered_drops`).
    Drop(Arc<Vec<(Tid, osis_base::Ak)>>),
    /// Forgotten now.
    Forget,
}

/// What held commit `c` calls for in the engine: its parts covered now drop (spec/commits.md §5
/// Covered, Own replaces; spec/sync-compaction.md §1), and it is forgotten (§5 Forgetting) once
/// the engine would forget it (`Ground::forgettable`) and no entry of a blob of it is known here
/// under `at`, the sync IDs carrying a body of it (dropped parts included: `Ground::bodies`), or
/// any other holding an entry or tombstone of one (`Ground::known_under`: a body whose sync IDs
/// moved): none in the own store, no own tombstone (it ends `TOMBSTONE_LIFETIME` after the
/// delete), none a source's stream shows.
pub(crate) fn local(g: &mut impl Ground, c: &CommitId, at: &[SyncId]) -> Result<Local> {
    osis_base::costs::count("read: local judged", 1);
    match g.forgettable(c)? {
        None => return Ok(Local::Gone),
        Some(true) => {}
        Some(false) => {
            let drops = g.covered_drops(c)?;
            return Ok(if drops.is_empty() { Local::Kept } else { Local::Drop(Arc::new(drops)) });
        }
    }
    let mut under: BTreeSet<SyncId> = at.iter().copied().collect();
    under.extend(g.known_under(c)?);
    for s in &under {
        if !g.own(s, c)?.is_empty() || !g.own_tombstones(s, c)?.is_empty() || g.present_anywhere(s, c)? {
            return Ok(Local::Kept);
        }
    }
    Ok(Local::Forget)
}
