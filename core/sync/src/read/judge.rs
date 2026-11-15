//! The judgement of one body at S (`body`), of what it calls for at one source keeping S unread
//! (`toward`), and of S's destruction (`doom`), from the ground's values alone. Pure reads: `Read`
//! runs these inside its effects and acts on what a new value adds.

use super::ground::{Facts, Ground, PieceAt, Seen, SrcView};
use super::{Verdict, Why};
use crate::store::{Source, Stand};
use crate::types::{ConnId, Result};
use osis_base::format::MAX_DRIFT_MS;
use osis_base::memo::{Clock, Stamped};
use osis_base::{BlobId, CommitId, SyncId, Tid};
use osis_engine::retention::Minting;
use osis_engine::sync::{BodyMeta, PieceLink, ReadCredentials};
use osis_label::StepId;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// One thing read does (spec/sync-judgement.md §3-§5).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Act {
    /// The body into the own store (§3 Own store).
    Log,
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
    Fetch { at: Source, conn: ConnId, blob: BlobId },
    /// A Delete at a source keeping S unread, by its head's delete key (§3 Deletes, §5 Emptying).
    Delete { at: Source, conn: ConnId, head: StepId, blob: BlobId },
    /// The closing step of the head of a source keeping S unread, registered there (§5 Emptying,
    /// spec/wire.md §8).
    Close { at: Source, conn: ConnId, head: StepId },
    /// Logged again once past a delete at the source (§4), a fresh encryption: `old` leaves the
    /// own log; the stand records `head` and `fall`.
    Again { at: Source, conn: ConnId, head: StepId, fall: u64, old: Vec<BlobId> },
    /// The body given to a source this node does not stamp for (§3 Reader that is not a writer).
    Deposit { at: Source, conn: ConnId, blob: BlobId },
    /// §5: S left (emptied and heard out, no delete key, or untold): forget it, then the thing's
    /// secrets.
    Forget,
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
    DeleteFreed { at: Source, conn: ConnId, head: StepId, blob: BlobId, thing: Tid },
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

/// S's destruction as judged here (§5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum Doom {
    #[default]
    Alive,
    /// Destroyed, not told (yet): S syncs as any.
    Untold,
    /// Told: every entry but the destroying requests is must-not-hold.
    Told { requests: Arc<BTreeSet<CommitId>> },
}

/// What a judgement reads of read's own state.
pub(crate) struct Mine<'a> {
    pub verdicts: &'a Stamped<(SyncId, CommitId), Verdict>,
    pub roles: &'a Stamped<SyncId, BTreeSet<CommitId>>,
    pub told: &'a Stamped<SyncId, Arc<BTreeSet<CommitId>>>,
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

/// A header-only copy of a minting under S whose closure lacks its thing, by its standing among
/// the thing's held mintings (spec/commits.md §5 A thing's mintings travel with its record).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mint {
    /// The witness, with no entry under S holding another minting of its standing: logged.
    Log,
    /// Kept where held, not logged.
    Keep,
    /// Lower than the witness, where an entry under S holds a minting of the witness's standing
    /// that may stand in for it: must-not-hold.
    Gone,
}

/// Each minting of `ms` (a thing's held mintings) under S where `held` says which have an entry
/// there: the witness is logged unless another minting of its standing is held there; one
/// standing lower goes where a minting of the witness's standing that may stand in for it
/// (`Minting::stands_in_for`) is held there; the rest are kept. One lacking a request ranks a
/// minting no lower than one holding it does, so what is left reads the thing live while it is.
pub(crate) fn rank(ms: &[Minting], mut held: impl FnMut(&CommitId) -> Result<bool>) -> Result<BTreeMap<CommitId, Mint>> {
    let mut out = BTreeMap::new();
    let Some(w) = osis_engine::retention::highest(ms) else { return Ok(out) };
    let mut top = Vec::new();
    for m in ms.iter().filter(|m| m.standing == w.standing) {
        if held(&m.commit)? {
            top.push(*m);
        }
    }
    for m in ms {
        let v = if m.commit == w.commit {
            if top.iter().any(|x| x.commit != m.commit) { Mint::Keep } else { Mint::Log }
        } else if m.standing < w.standing && top.iter().any(|x| x.stands_in_for(m)) {
            Mint::Gone
        } else {
            Mint::Keep
        };
        out.insert(m.commit, v);
    }
    Ok(out)
}

/// Thing `t`'s mintings whose header-only copy is in S's required set as a minting of `t`
/// (`BodyMeta::mints`), each by `rank` over every held minting of `t` and the own store of S.
/// Empty: none is (no longer followed).
pub(crate) fn mintings(g: &mut impl Ground, metas: &Stamped<(SyncId, CommitId), BodyMeta>, s: &SyncId, t: &Tid) -> Result<Arc<BTreeMap<CommitId, Mint>>> {
    osis_base::costs::count("read: mintings", 1);
    let ms = g.mintings(t)?;
    let mut ranked = rank(&ms, |c| Ok(!g.own(s, c)?.is_empty()))?;
    ranked.retain(|c, _| metas.get(&(*s, *c)).is_some_and(|m| m.mints.contains(t)));
    Ok(Arc::new(ranked))
}

/// A header-only minting copy's verdict from its places among its things' mintings (`Mint`): the
/// most any thing gives it; unjudged while a thing's is not settled.
fn minted(mine: &Mine, s: &SyncId, c: &CommitId, meta: &BodyMeta) -> Verdict {
    let mut v = Verdict::MustNot(Why::Superseded);
    for t in &meta.mints {
        match mine.mints.get(&(*s, *c, *t)) {
            None => return Verdict::Unjudged,
            Some(Mint::Log) => v = Verdict::Must,
            Some(Mint::Keep) if v != Verdict::Must => v = Verdict::May,
            Some(_) => {}
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
fn outside(g: &mut impl Ground, mine: &Mine, s: &SyncId, c: &CommitId) -> Result<(Verdict, Option<u64>)> {
    let since = mine.arrived.get(&(*s, *c)).copied().unwrap_or(0).max(mine.moved.get(c).copied().unwrap_or(0));
    Ok(match g.passed(s, since)? {
        true => (Verdict::MustNot(Why::OutsideRequired), None),
        false => (Verdict::Unjudged, Some(since)),
    })
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
    let (v, wait) = outside(g, mine, s, c)?;
    Ok((out, matches!(v, Verdict::MustNot(_)), wait))
}

/// spec/sync-judgement.md §2: what the body is at S.
fn classify(mine: &Mine, f: &Facts, s: &SyncId, c: &CommitId, meta: &BodyMeta, later_held: bool) -> Verdict {
    if let Some(w) = f.must_not {
        return Verdict::MustNot(w);
    }
    if meta.expires.is_some_and(|e| mine.reached(e.0)) {
        return Verdict::MustNot(Why::Expired);
    }
    if !f.body.required {
        return Verdict::MustNot(Why::OutsideRequired);
    }
    if !meta.mints.is_empty() {
        return minted(mine, s, c, meta);
    }
    // judged invalid here: kept by none of must-hold's clauses, never logged (§3 Own store)
    if f.body.invalid {
        return Verdict::May;
    }
    // not held here (dropped): kept by none of must-hold's clauses
    if f.body.dropped.is_some() {
        return Verdict::May;
    }
    // a certificate, header-only or not: must-hold but a sole one (its author has no other blob)
    if meta.certificate || !f.body.closure {
        return if f.body.sole_certificate { Verdict::May } else { Verdict::Must };
    }
    if meta.header_only {
        return if f.body.lasting_header { Verdict::Must } else { Verdict::May };
    }
    if f.body.kept {
        return Verdict::Must;
    }
    match f.body.covered {
        None => Verdict::Unjudged,
        Some(false) if !later_held => Verdict::Must,
        Some(_) => Verdict::May,
    }
}

/// Covered and dropped where `held` says which commits are held (spec/sync-judgement.md §3,
/// spec/sync-compaction.md §1 Carriers): a may-hold body a held valid snapshot covers, past its
/// keep-at-least bound, each delta needing a carrier having one held there. A certificate but a
/// sole one (a lasting header has no delta to cover) is required whatever snapshot covers it:
/// never dropped as covered, may-hold only while this node may not log it (§2 Loggable: kept).
fn covered_dropped(v: &Verdict, f: &Facts, mut held: impl FnMut(&CommitId) -> Result<bool>) -> Result<bool> {
    if *v != Verdict::May || f.body.covered != Some(true) || f.body.kept || (!f.body.closure && !f.body.sole_certificate) {
        return Ok(false);
    }
    for alternatives in &f.carriers {
        let mut any = false;
        for c in alternatives {
            if held(c)? {
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
    if !g.reads(s)? {
        j.idle = true;
        return Ok(j);
    }
    let own = g.own(s, c)?;
    // a destroying request under S told destroyed stays until its expiry (§5 Emptying), its part
    // on the destroyed thing dropped or not
    let request = mine.told.get(s).is_some_and(|req| req.contains(c));
    // an entry whose blob holds a part dropped here for good is must-not-hold itself, whatever
    // the body's verdict (spec/sync-judgement.md §1): it leaves, and the body counts as unlogged
    let mut stale = Vec::new();
    for e in &own {
        if !request && g.dropped(&e.blob)? {
            stale.push(e.blob);
        }
    }
    // a strict subset of another entry of it held here leaves too (§2); the larger one stays
    let mut held: BTreeSet<BlobId> = own.iter().map(|e| e.blob).filter(|b| !stale.contains(b)).collect();
    // a certificate copy holding none of what S names of it leaves as outside, once final
    let (unnamed, unnamed_gone, unnamed_wait) = unnamed_copies(g, mine, s, c, &held)?;
    let unnamed: Vec<BlobId> = if unnamed_gone { unnamed } else { Vec::new() };
    held.retain(|b| !unnamed.contains(b));
    let mut subsets = Vec::new();
    for b in &held {
        if g.strict_subset(s, b, &held)? {
            subsets.push(*b);
        }
    }
    let live: Vec<BlobId> = held.iter().copied().filter(|b| !subsets.contains(b)).collect();
    let (f, verdict) = match mine.meta(s, c) {
        None if !g.closure_settled(s)? => (None, Verdict::Unjudged),
        None => {
            let (v, wait) = outside(g, mine, s, c)?;
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
            let mut v = classify(mine, &f, s, c, meta, later_held);
            // must-hold only what this node may log under S (§2 Loggable): else may-hold, kept
            // if it arrives, never relayed, deposited or owed
            if v == Verdict::Must && !g.may_log(s, c)? {
                v = Verdict::May;
            }
            if v == Verdict::MustNot(Why::OutsideRequired) {
                let (x, wait) = outside(g, mine, s, c)?;
                v = x;
                j.wait = wait;
            }
            if mine.told.get(s).is_some_and(|req| !req.contains(c)) {
                v = Verdict::MustNot(Why::Emptied);
            }
            (Some(f), v)
        }
    };
    let verdict = match request {
        true => Verdict::May,
        false => verdict,
    };
    j.verdict = verdict.clone();
    j.role = verdict == Verdict::Must && f.as_ref().is_some_and(|f| f.own && f.role);
    // a body counting missing again: its own tombstones end, an entry of it held here is taken
    // again, and it is fetched again where a source shows another entry of it present (a source
    // joining or showing one judges it again)
    if f.as_ref().is_some_and(|f| f.missing) {
        j.acts.extend(g.own_tombstones(s, c)?.into_iter().map(Act::Lift));
        j.acts.extend(own.iter().filter(|e| !stale.contains(&e.blob)).map(|e| Act::Take(e.blob)));
        for (at, conn) in g.reached(s)? {
            for b in g.seen(&at, s, c)?.present {
                if !own.iter().any(|e| e.blob == b) {
                    j.acts.insert(Act::Fetch { at, conn, blob: b });
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
    // own store (§3 Own store): it follows this node's judgement alone, no delete key needed
    let dropped_here = match &f {
        Some(f) => covered_dropped(&verdict, f, |x| Ok(!g.own(s, x)?.is_empty()))?,
        None => false,
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
    // peer's entry is (a head move restamps each body once; peers' duplicates are never stamped)
    if verdict == Verdict::Must && !f.as_ref().is_some_and(|f| f.missing) && g.pullable(s)? {
        let mut stands = false;
        let mut restamp = Vec::new();
        let mut peer = None;
        for e in own.iter().filter(|e| live.contains(&e.blob)) {
            if g.stands(s, c, e)? {
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
        if !stands && restamp.is_empty() {
            j.acts.insert(Act::Log);
        }
        j.acts.extend(restamp.into_iter().map(Act::Restamp));
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
        for (at, conn) in g.reached(s)? {
            if g.piece_shown(&at, s, &b)? {
                j.acts.insert(Act::Fetch { at, conn, blob: b });
            }
        }
        return Ok(j);
    };
    j.held = true;
    j.kids = kids;
    if !matches!(g.piece(s, &b)?, PieceAt::Own | PieceAt::Tombstoned) && g.pullable(s)? {
        j.acts.insert(Act::LogPiece(b));
    }
    // lost: some source shows it deleted and none present, S's sources heard out (every entry of
    // S each can open applied); deletes read only once no source shows it
    let sources = g.reached(s)?;
    for (at, _) in &sources {
        if g.piece_shown(at, s, &b)? {
            return Ok(j);
        }
    }
    for (at, _) in &sources {
        if g.piece_deleted(at, s, &b)? {
            if g.heard_out(s)? {
                j.acts.insert(Act::Repair(b));
            }
            break;
        }
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
    if !g.freed_link(b, t)? {
        return Ok((acts, false));
    }
    for s in g.carrying(t)? {
        if !g.reads(&s)? {
            continue;
        }
        if matches!(g.piece(&s, b)?, PieceAt::Own | PieceAt::Peer) {
            known = true;
            acts.insert((s, Act::DropBlob(*b)));
        }
        for src in g.sources(&s)?.iter() {
            // a reader judges its own entries: only a store's count
            if !src.store || !g.piece_shown(&src.at, &s, b)? {
                continue;
            }
            known = true;
            if let Some(head) = src.head {
                acts.insert((s, Act::DeleteFreed { at: src.at, conn: src.conn, head, blob: *b, thing: *t }));
            }
        }
    }
    Ok((acts, known))
}

/// What a body at S calls for at the source at `at` (§3 At a source keeping S unread; §4).
/// Between readers nothing but streams: a source reading S calls for nothing.
pub(crate) fn toward(g: &mut impl Ground, mine: &Mine, s: &SyncId, c: &CommitId, at: &Source) -> Result<Toward> {
    osis_base::costs::count("read: toward", 1);
    let mut t = Toward::default();
    let src = match g.source(s, at)? {
        Some(src) if src.store => src,
        _ => {
            t.idle = true;
            return Ok(t);
        }
    };
    let seen = g.seen(at, s, c)?;
    let verdict = mine.verdicts.get(&(*s, *c)).cloned().unwrap_or(Verdict::Unjudged);
    let creds = g.credentials(s)?;
    let keys = src.head.and_then(|h| creds.as_ref()?.keys.get(&h).cloned());
    let writer = keys.as_ref().is_some_and(|k| k.write.is_some());
    let quiet = seen.present.is_empty() && seen.deleted.is_empty();
    t.idle = quiet && (writer || verdict != Verdict::Must);
    // emptying is S's (`doom`); unjudged calls for nothing yet
    if matches!(verdict, Verdict::Unjudged | Verdict::MustNot(Why::Emptied)) {
        return Ok(t);
    }
    let (Some(head), Some(creds)) = (src.head, creds.as_deref()) else { return Ok(t) };
    let f = match mine.meta(s, c).is_some() {
        true => Some(g.facts(s, c)?),
        false => None,
    };
    if f.is_some() {
        at_source(g, mine, &mut t, &src, &seen, s, c, &verdict, head, creds, writer, f.as_ref().is_some_and(|f| f.role))?;
    }
    if keys.is_some_and(|k| k.delete.is_some()) && !seen.present.is_empty() {
        deletes(g, mine, &mut t, &src, &seen, s, c, f.as_ref(), &verdict, head, creds)?;
    }
    t.idle &= t.acts.is_empty();
    Ok(t)
}

/// §3 Role entries first: the source, on this node's head, not full, lacks an own role commit
/// S must hold (not present there and not deleted there; one it refused included), read from the
/// own store and the source's stream, never from what was sent. `c` itself waits for no other
/// copy of itself.
fn role_wait(g: &mut impl Ground, mine: &Mine, src: &SrcView, s: &SyncId, c: &CommitId, creds: &ReadCredentials) -> Result<bool> {
    let ours = creds.head.as_ref().map(|h| h.id());
    if src.full || src.head.is_none() || src.head != ours {
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
/// Carriers, Duplicates), while no role entry of this node's is lacking there and its stream
/// shows no role commit this node does not hold.
#[allow(clippy::too_many_arguments)]
fn deletes(g: &mut impl Ground, mine: &Mine, t: &mut Toward, src: &SrcView, seen: &Seen, s: &SyncId, c: &CommitId, f: Option<&Facts>, verdict: &Verdict, head: StepId, creds: &ReadCredentials) -> Result<()> {
    let why = match verdict {
        // an expired entry leaves every store by itself
        Verdict::MustNot(Why::Expired) => return Ok(()),
        Verdict::MustNot(_) => true,
        // a carrier it lacks counts as held at a full source: it takes it with the delete
        // and it waits `MAX_DRIFT` past its keep-at-least bound (spec/commits.md §5 Keep at
        // least: every node's clock agrees it left history)
        _ => match f {
            Some(f) => covered_dropped(verdict, f, |x| Ok(src.full || !g.seen(&src.at, s, x)?.present.is_empty()))? && mine.reached(f.body.hosts_from),
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
        let mut out = duplicates(g, seen, copy)?;
        // a copy holding none of what S names of it (§2), once final, and only beside another
        // entry of it there: the source never holds neither the old copy nor its replacement
        let (unnamed, gone, _) = unnamed_copies(g, mine, s, c, &seen.present)?;
        let mut present = seen.present.clone();
        present.retain(|b| !gone || !unnamed.contains(b));
        if gone && !present.is_empty() {
            for b in unnamed {
                if !out.contains(&b) {
                    out.push(b);
                }
            }
        }
        // a strict subset of another entry of it there (§2), which carries it there
        for b in &present {
            if !out.contains(b) && g.strict_subset(s, b, &present)? {
                out.push(*b);
            }
        }
        out
    };
    if blobs.is_empty() || src.role_unheld || role_wait(g, mine, src, s, c, creds)? {
        return Ok(());
    }
    t.acts.extend(blobs.into_iter().map(|blob| Act::Delete { at: src.at, conn: src.conn, head, blob }));
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
fn at_source(g: &mut impl Ground, mine: &Mine, t: &mut Toward, src: &SrcView, seen: &Seen, s: &SyncId, c: &CommitId, verdict: &Verdict, head: StepId, creds: &ReadCredentials, writer: bool, role: bool) -> Result<()> {
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
            t.acts.insert(Act::Deposit { at: src.at, conn: src.conn, blob: e.blob });
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
    let fall = g.fall_mark(s, c)?;
    if g.stand(&src.at, s, c)?.is_some_and(|st: Stand| st.head == head && st.fall == fall) {
        return Ok(());
    }
    if role_wait(g, mine, src, s, c, creds)? {
        return Ok(());
    }
    t.acts.insert(Act::Again { at: src.at, conn: src.conn, head, fall, old: own.iter().map(|e| e.blob).collect() });
    Ok(())
}

/// S's destruction (§5): told once an entry of each destroying request is held at a source (at
/// once for one by expiry alone), and from then on; untold past every request's expiry.
pub(crate) fn doom(g: &mut impl Ground, mine: &Mine, told_before: bool, s: &SyncId) -> Result<(Doom, BTreeSet<Act>)> {
    osis_base::costs::count("read: doom", 1);
    let mut acts = BTreeSet::new();
    let Some(d) = g.destruction(s)? else { return Ok((Doom::Alive, acts)) };
    let requests: BTreeSet<CommitId> = d.requests.iter().copied().collect();
    let mut over = true;
    for r in &requests {
        let exp = mine.meta(s, r).and_then(|m| m.expires);
        over &= exp.is_some_and(|e| mine.reached(e.0));
    }
    let sources = g.sources(s)?;
    // per source: the blobs of the requests it holds, when it holds each
    let mut holds_all: BTreeMap<Source, BTreeSet<BlobId>> = BTreeMap::new();
    for src in sources.iter() {
        let mut blobs = BTreeSet::new();
        let mut all = true;
        for r in &requests {
            let seen = g.seen(&src.at, s, r)?;
            all &= !seen.present.is_empty();
            blobs.extend(seen.present);
        }
        if all {
            holds_all.insert(src.at, blobs);
        }
    }
    // told stays told: its requests leave at their expiry
    let told = told_before || requests.is_empty() || !holds_all.is_empty();
    if !told {
        if over {
            acts.insert(Act::Forget);
        }
        return Ok((Doom::Untold, acts));
    }
    // everything under S but the requests leaves the own store, whatever it names: an entry of a
    // commit forgotten with a released thing (spec/commits.md §5 Forgetting) is judged by no body
    let mut kept = BTreeSet::new();
    for r in &requests {
        kept.extend(g.own(s, r)?.into_iter().map(|e| e.blob));
    }
    let own = g.own_all(s)?;
    acts.extend(own.iter().filter(|b| !kept.contains(*b)).map(|b| Act::DropBlob(*b)));
    let creds = g.credentials(s)?;
    let newest = creds.as_ref().and_then(|c| c.head.as_ref().map(|h| h.id()));
    let delete_key = |h: &StepId| creds.as_ref().and_then(|c| c.keys.get(h)).is_some_and(|k| k.delete.is_some());
    let holder = newest.is_some_and(|h| delete_key(&h));
    let mut empty = true;
    // a source keeping S unread at a head whose delete key this node holds: S is closed there
    // before it is forgotten here
    let mut closable = false;
    for src in sources.iter() {
        let all = g.seen_all(&src.at, s)?;
        empty &= all.is_empty();
        if let (true, Some(head)) = (src.store, src.head)
            && holder
            && delete_key(&head)
        {
            closable = true;
            // its stream shows nothing, the requests past their expiry: the closing step (§5)
            if all.is_empty() && over {
                acts.insert(Act::Close { at: src.at, conn: src.conn, head });
            }
        }
        // deleted where the source holds every request (told there first), or once the requests
        // are past their expiry (no reader can be told any more)
        let keep = match holds_all.get(&src.at) {
            Some(keep) => keep,
            None if over => &BTreeSet::new(),
            None => continue,
        };
        let (true, Some(head)) = (src.store, src.head) else { continue };
        if holder && delete_key(&head) {
            acts.extend(all.iter().filter(|b| !keep.contains(*b)).map(|blob| Act::Delete { at: src.at, conn: src.conn, head, blob: *blob }));
        }
    }
    if !holder || (empty && !closable && g.heard_out(s)? && !g.deletes_known(s)? && own.is_empty()) {
        acts.insert(Act::Forget);
    }
    Ok((Doom::Told { requests: Arc::new(requests) }, acts))
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
