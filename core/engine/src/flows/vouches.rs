//! Vouches (spec/permissions.md §5.1 Vouches, Writing): a node that received a removed party's
//! role write the remover had not keeps it with a vouch, written unasked by the state rule. For
//! each held removal R applying in its first walk as an explicit lowering of another's grant
//! (not at the node that wrote R, nor at one acting as a party in question at R), and each thing
//! N of R's component in its node closure: the commits in question at R with a role-class part
//! on N, ordered before R, received by R's `ts` and not listed by R's frontier are its
//! candidates; while one of them is one this node could write now and no counting vouch of its
//! own lists, it owes one vouch on N keyed by R listing every candidate (the writers' leaving out
//! applied).
//!
//! Invariant: what is owed is a function of the held set, the receipts and the trust set (the
//! first walk, the counting entries, the clock), never of what this node wrote before, so an
//! open re-derives it (`all_due`) and nothing about it is durable. Triggered per component: a
//! removal that may owe (`may_owe`, from the held set alone) is filed under its component
//! (`Indexes::vouch_watch`) once judged, and only a change of that component makes it due again
//! (`Core::timelines_changed`); one that may not is never judged again. A removal received
//! before its `ts` by the wall clock is judged again once as its `ts` passes (`vouch_wait`, a
//! wake), its receipts final then. So a removal owing
//! nothing costs nothing per step, and a node ingesting a history it received after it (a
//! joiner) judges each removal once.
//!
//! Who writes each input: R, the candidates and every vouch are their signers' word (a removed
//! party may sign any number, at any key and `ts`); the first walk judges them all. This node
//! writes only what it received and could write itself, so a forged vouch or a flood of a
//! removed party's commits makes it write nothing it would not write from the honest ones: a
//! removed party's commits after R are not candidates (ordered after R or received after its
//! `ts`).

use crate::engine::write::writable_split;
use crate::engine::{Core, Engine, Step, Tx};
use crate::error::Result;
use crate::events::{Diagnostic, DiagnosticKind, Origin};
use osis_base::{CommitId, Role, Tid, Ts, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_perm::Point;
use osis_schema::Codec;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// Notes removal `r` (a role commit with a frontier, applied here) as due.
pub(crate) fn note_due(core: &mut Core, r: &CommitId) {
    core.ix.vouches_due.insert(*r);
}

/// Every held removal due (an open: what is owed is re-derived, never kept).
pub(crate) fn all_due(core: &mut Core) {
    let rs: Vec<CommitId> = core.ix.commits.iter().filter(|(_, m)| m.view.kind.is_role() && m.view.frontier.is_some() && m.origin == Origin::Remote).map(|(id, _)| *id).collect();
    for r in rs {
        core.ix.vouches_due.insert(r);
    }
}

/// The removals waiting for their `ts` to pass by the wall clock (`Indexes::vouch_wait`) due
/// at `now` (wall ms): judged again once, their receipts final.
pub(crate) fn wake(core: &mut Core, now: u64) {
    let woke: Vec<(u64, CommitId)> = core.ix.vouch_wait.iter().take_while(|(at, _)| *at <= now).copied().collect();
    for w in woke {
        core.ix.vouch_wait.remove(&w);
        core.ix.vouches_due.insert(w.1);
    }
}

/// When the first removal waiting for its `ts` is due (wall ms).
pub(crate) fn next_at(core: &Core) -> Option<u64> {
    core.ix.vouch_wait.iter().next().map(|(at, _)| *at)
}

/// What a removal owes here (`owed`).
#[derive(Debug, Default)]
struct Owed {
    /// Its target's component as judged, to file it under; `None`: never owes (written here,
    /// not held, not a role commit with a frontier).
    component: Option<u64>,
    /// Per thing, the vouch owed there: the commits it lists, in the order received.
    on: BTreeMap<Tid, Vec<CommitId>>,
    /// Judged again once its `ts` has passed by the wall clock: what this node receives until
    /// then is received by it (and a vouch is positioned after it).
    later: bool,
}

/// Whether removal `r` (its edge commit `rc`, its record `m`) may ever owe a vouch at this node
/// (`me`), read off the held set alone, never the walk: a role commit perm reads, other than
/// `r`, by an author other than `r`'s and this node's among those that may be in question at
/// `r` (the holders its edge writes name and everything upstream of them, `Held::upstream`: a
/// superset of the walk's), stamped no later than `r`, received by `r`'s `ts` and not listed by
/// its frontier. Once this node's clock is past `r`'s `ts` no receipt can join it, so a removal
/// with none owes nothing for good: judged once, it is never judged again (`write_for`) but at an
/// open (issues/s3-vouches-build.md item 5). O(those authors' role commits before `r`).
fn may_owe(core: &Core, r: &CommitId, rc: &osis_perm::RoleCommit, frontier: &osis_perm::Frontier, me: Tid) -> bool {
    let wall = rc.ts.wall_ms().0;
    let named: BTreeSet<Tid> = rc.ops.iter().map(|o| o.holder).filter(|h| *h != rc.author).collect();
    let authors = core.ix.held.upstream(&named);
    authors.iter().filter(|a| **a != rc.author && **a != me).any(|a| core.ix.held.authored_by(a, rc.ts).any(|c| c != *r && !frontier.covers(&c) && core.ix.commits.get(&c).is_some_and(|cm| cm.received.0 <= wall)))
}

/// Writes every vouch owed for the due removals (`Indexes::vouches_due`), each removal once per
/// call, each in a step of its own (`Tx::step`): one that fails leaves nothing, is reported
/// (`DiagnosticKind::OwnWriteFailed`) and stays due. A removal owing a vouch on a thing this node
/// may write on only later (outside its node closure, keys not here) stays due, judged again at
/// the end of each transaction until written.
pub(crate) fn write_owed(tx: &mut Tx<'_>) -> Result<()> {
    if !tx.core.vouches_on || tx.core.ix.vouches_due.is_empty() {
        return Ok(());
    }
    let Some(me) = tx.core.member() else { return Ok(()) };
    let mut done: BTreeSet<CommitId> = BTreeSet::new();
    loop {
        // a vouch written moves its component: the removals filed there are due again, once
        let due: Vec<CommitId> = tx.core.ix.vouches_due.iter().filter(|r| !done.contains(r)).copied().collect();
        if due.is_empty() {
            return Ok(());
        }
        for r in due {
            done.insert(r);
            osis_base::costs::count("vouches: removals judged", 1);
            if let Err(e) = tx.step(Step::Vouch, |tx| write_for(tx, &r, me)) {
                tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::OwnWriteFailed, tids: Vec::new(), commit: Some(r), peer: None, detail: e.to_string() }, tx.core.hlc.mono());
            }
        }
    }
}

/// Writes the vouches removal `r` owes; takes it off the due set, filed under its component
/// (or waiting for its `ts`, `vouch_wait`), unless a vouch it owes waits.
fn write_for(tx: &mut Tx<'_>, r: &CommitId, me: Tid) -> Result<()> {
    let now = tx.core.hlc.peek();
    let o = owed(tx.core, r, me, now);
    let w = writable_split(tx, me, o.on, ct::VOUCHES_AK, Some(Role::Sync))?;
    for (n, lists) in &w.now {
        // a new entry of this delta's own (`put_new`, spec/data-model.md §9)
        let mut mu = crate::Mutation::new();
        let list = ct::Frontier { commits: lists.iter().copied().collect() };
        mu.op(*n, &ct::VOUCHES, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(list.to_value()) })?;
        Engine::commit_tx(tx, mu)?;
    }
    #[cfg(debug_assertions)]
    if !w.now.is_empty() {
        let again = owed(tx.core, r, me, tx.core.hlc.peek());
        debug_assert!(w.now.keys().all(|n| !again.on.contains_key(n)), "a vouch written here does not count here: {r:?} on {:?}", again.on.keys().collect::<Vec<_>>());
    }
    if w.later || !w.unheld.is_empty() {
        return Ok(());
    }
    tx.core.ix.vouches_due.remove(r);
    if o.later {
        // once more as its `ts` passes, at a wake (`Engine::tick`), never per transaction
        let at = tx.core.ix.held.edge_commit(r).map_or(0, |c| c.ts.wall_ms().0.saturating_add(1));
        tx.core.ix.vouch_wait.insert((at, *r));
        tx.core.timer_floor = tx.core.timer_floor.min(at);
        return Ok(());
    }
    // filed under its component as it stands after this node's own vouches
    let target = tx.core.ix.held.edge_commit(r).and_then(|c| c.ops.first().map(|o| o.target));
    if let Some(c) = o.component.and(target).and_then(|t| tx.core.timelines.component(&t)) {
        tx.core.ix.vouch_watch.insert(c, *r);
    }
    Ok(())
}

/// What removal `r` owes at this node (account `me`) at `now` (spec/permissions.md §5.1
/// Vouches, Writing).
fn owed(core: &Core, r: &CommitId, me: Tid, now: Ts) -> Owed {
    let mut out = Owed::default();
    // not at the node that wrote R
    let Some(m) = core.ix.commits.get(r).filter(|m| m.origin == Origin::Remote) else { return out };
    let Some(frontier) = m.view.frontier.clone() else { return out };
    let Some(rc) = core.ix.held.edge_commit(r) else { return out };
    let Some(target) = rc.ops.first().map(|o| o.target) else { return out };
    // what arrives until R's `ts` by the wall clock is received by it (spec/permissions.md
    // §5.1 Vouches, Writing: "as of its wall clock"): owed again then
    out.later = core.hlc.wall().0 <= rc.ts.wall_ms().0;
    if now <= rc.ts {
        // a vouch is positioned after R
        out.later = true;
        return out;
    }
    if !may_owe(core, r, rc, &frontier, me) {
        return out;
    }
    let Some(tl) = core.timelines.get(&target) else { return out };
    let comp = core.timelines.component(&target);
    // R applies in the first walk as an explicit lowering of another's grant (one that does not
    // may come to, the walk changing: judged again then); not at a node acting as one in
    // question at it
    let Some(in_question) = tl.in_question(r) else {
        out.component = comp;
        return out;
    };
    if in_question.contains(&me) || in_question.contains(&core.id.tid()) {
        return out;
    }
    let rp = rc.point();
    let wall = m.view.ts.wall_ms().0;
    // candidates per thing of R's component in the node closure, in the order received
    let mut cands: BTreeMap<Tid, Vec<(osis_base::WallMs, CommitId)>> = BTreeMap::new();
    for x in in_question {
        for c in core.ix.held.authored_by(x, rp.ts) {
            if c == *r || frontier.covers(&c) || core.ix.held.is_uncounted(&c) {
                continue;
            }
            let Some(cm) = core.ix.commits.get(&c).filter(|cm| cm.received.0 <= wall) else { continue };
            let edges = core.ix.held.edge_commit(&c);
            let at = edges.map_or(Point::start(cm.view.ts), |e| e.point());
            if at >= rp {
                continue;
            }
            let things: BTreeSet<Tid> = edges.into_iter().flat_map(|e| e.ops.iter().map(|o| o.target)).chain(core.ix.held.parts_of(&c).into_iter().flat_map(|p| p.parts.iter().map(|(t, _)| *t))).collect();
            for n in things {
                if core.timelines.component(&n) == comp && core.ix.closure.holds(&n) {
                    cands.entry(n).or_default().push((cm.received, c));
                }
            }
        }
    }
    // none: nothing is owed for good (its candidates are fixed once past its `ts`), unless what
    // is in question at it grows (issues/s3-vouches-build.md)
    if cands.is_empty() {
        return out;
    }
    out.component = comp;
    let own = tl.counted_by(&me, r);
    let parts = |c: &CommitId| core.ix.held.parts_of(c).map(|p| p.parts.clone()).unwrap_or_default();
    for (n, mut cs) in cands {
        cs.sort_unstable();
        let owes = |cs: &[CommitId]| cs.iter().any(|c| !own.contains(c) && tl.could_write(&me, c, &parts(c), now));
        let all: Vec<CommitId> = cs.into_iter().map(|(_, c)| c).collect();
        // a commit the leaving out drops owes nothing: the walk the leaving out needs only
        // where some candidate is owed at all
        if !owes(&all) {
            continue;
        }
        let lists = leaving_out(tl, r, all);
        if owes(&lists) {
            out.on.insert(n, lists);
        }
    }
    out
}

/// The writers' leaving out (spec/permissions.md §5.1 Vouches, Writing): where R, trusted, would
/// not apply in this node's walk with every one of `all` listed, they are taken in the order
/// received, each kept only where R still applies with those kept so far. A walk of the
/// component per commit only where the first check fails (rare: a listed write R rests on).
fn leaving_out(tl: &osis_perm::Timeline, r: &CommitId, all: Vec<CommitId>) -> Vec<CommitId> {
    if tl.stands_with(r, &all) {
        return all;
    }
    let mut kept = Vec::new();
    for c in all {
        kept.push(c);
        if !tl.stands_with(r, &kept) {
            kept.pop();
        }
    }
    kept
}
