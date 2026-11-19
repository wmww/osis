//! A witness's writes to a removal, by one state rule: vouches (spec/permissions.md §5.1 Vouches,
//! Writing) for a removed party's role writes and addenda (§5.2 Addenda, Writing) for its content,
//! which a node received and the remover had not, written unasked (`owed`: `vouches_owed`,
//! `addenda_owed`). Vouches: for
//! each held removal R applying in its first walk as an explicit lowering of another's grant
//! (not at the node that wrote R, nor at one acting as a party in question at R), and each thing
//! N of R's component in its node closure: the commits in question at R with a role-class part
//! on N, ordered before R, received in R's window (`window`: by its `ts` and before R) and not
//! listed by R's frontier are its
//! candidates; while one of them is one this node could write now and no counting vouch of its
//! own lists, it owes one vouch on N keyed by R listing every candidate (the writers' leaving out
//! applied).
//!
//! Addenda: for each explicit demotion R makes below write in this node's view (R's own node
//! included), the content commits of the demoted node in R's window, not listed by its frontier,
//! on each thing N it is demoted on (`addenda_owed`); owed while this node holds write on N and no
//! counting addendum of its own vouches for one of them.
//!
//! Invariant: what is owed is a function of the held set, the receipts and the trust set (the
//! first walk, the counting entries and addenda, the clock), never of what this node wrote
//! before (bar a leaving out kept, `leaving_out`), so an
//! open re-derives it (`all_due`) and nothing about it is durable. Triggered per component: a
//! removal with candidates (or not applying in this node's view: it may come to) is filed under
//! its component (`Indexes::vouch_watch`) once judged, and only a change of that component makes
//! it due again (`Core::timelines_changed`: a grant, a lowering, a vouch, this node's side); one
//! with none is never judged again (`may_owe` reads the held set alone for the vouches' part). The window (`window`)
//! closes at R's own arrival, so its candidates' receipts are final once R is held. So a
//! removal owing nothing costs nothing per step, and a node ingesting a history it received
//! after it (a joiner) judges each removal once.
//!
//! Who writes each input: R, the candidates and every vouch and addendum are their signers' word
//! (a removed party may sign any number, at any key and `ts`; any writer writes `addenda.0`); the
//! first walk and layer 2 judge them all. An addendum is content: it moves no component, so a
//! flood of them makes no removal due. This node
//! writes only what it received and could write itself, so a forged vouch or a flood of a
//! removed party's commits makes it write nothing it would not write from the honest ones: a
//! removed party's commits after R are not candidates (ordered after R, or received after its
//! `ts` or after R: a remover's clock running ahead lengthens nothing).

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
use std::sync::Arc;

/// Notes removal `r` (a role commit with a frontier, applied here) as due.
pub(crate) fn note_due(core: &mut Core, r: &CommitId) {
    core.ix.vouches_due.insert(*r);
}

/// Every held removal due (an open: what is owed is re-derived, never kept).
pub(crate) fn all_due(core: &mut Core) {
    let rs: Vec<CommitId> = core.ix.commits.iter().filter(|(_, m)| m.view.kind.is_role() && m.view.frontier.is_some()).map(|(id, _)| *id).collect();
    for r in rs {
        core.ix.vouches_due.insert(r);
    }
}

/// Whether a commit received at `got` is in removal R's window at this node (spec/permissions.md
/// §5.1 Vouches, Writing; §5.2 Addenda, Writing): received by R's `ts` and before R itself (R's
/// first arrival `r_got`, both by the wall clock; the same millisecond is not before). The second
/// bound keeps a remover's fast clock from lengthening the window past R's arrival: what arrives
/// after a witness holds R is never vouched for, however far R's `ts` is ahead.
pub(crate) fn window(got: osis_base::WallMs, r_ts: Ts, r_got: osis_base::WallMs) -> bool {
    got.0 <= r_ts.wall_ms().0 && got.0 < r_got.0
}

/// What a removal owes here (`owed`).
#[derive(Debug, Default)]
struct Owed {
    /// Its target's component as judged, to file it under; `None`: never owes (written here,
    /// not held, not a role commit with a frontier).
    component: Option<u64>,
    /// Per thing, the vouch owed there: the commits it lists, in the order received.
    on: BTreeMap<Tid, Vec<CommitId>>,
    /// Per thing, the addendum owed there: the commits it lists.
    addenda: BTreeMap<Tid, BTreeSet<CommitId>>,
    /// The leavings out taken anew, per thing (`Indexes::vouch_left`).
    left: Vec<(Tid, Arc<LeftOut>)>,
}

/// A leaving out taken (`leaving_out`): of the candidates `all` (in the order received) under
/// trust set `trust`, the `kept` with which R, trusted, applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeftOut {
    all: Vec<CommitId>,
    trust: BTreeSet<osis_perm::WriteId>,
    kept: Vec<CommitId>,
}

/// Whether removal `r` (its edge commit `rc`, first received at `r_got`) may ever owe a vouch at this node
/// (`me`), read off the held set alone, never the walk: a role commit perm reads, other than
/// `r`, by an author other than `r`'s and this node's among those that may be in question at
/// `r` (the holders its edge writes name and everything upstream of them, `Held::upstream`: a
/// superset of the walk's), stamped no later than `r`, received in its window (`window`) and
/// not listed by its frontier. Its window closes at its arrival, so a removal
/// with none owes nothing for good: judged once, it is never judged again (`write_for`) but at an
/// open (issues/s3-vouches-build.md item 5). O(those authors' role commits before `r`).
fn may_owe(core: &Core, r: &CommitId, rc: &osis_perm::RoleCommit, frontier: &osis_perm::Frontier, me: Tid, r_got: osis_base::WallMs) -> bool {
    let named: BTreeSet<Tid> = rc.ops.iter().map(|o| o.holder).filter(|h| *h != rc.author).collect();
    let authors = core.ix.held.upstream(&named);
    authors.iter().filter(|a| **a != rc.author && **a != me).any(|a| core.ix.held.authored_by(a, rc.ts).any(|c| c != *r && !frontier.covers(&c) && core.ix.commits.get(&c).is_some_and(|cm| window(cm.received, rc.ts, r_got))))
}

/// Writes every vouch owed for the due removals (`Indexes::vouches_due`), each removal once per
/// call, each in a step of its own (`Tx::step`): one that fails leaves nothing, is reported
/// (`DiagnosticKind::OwnWriteFailed`) and stays due. A removal owing a vouch on a thing this node
/// may write on only later (outside its node closure, keys not here) stays due, judged again at
/// the end of each transaction until written.
pub(crate) fn write_owed(tx: &mut Tx<'_>) -> Result<()> {
    if !(tx.core.vouches_on || tx.core.addenda_on) || tx.core.ix.vouches_due.is_empty() {
        return Ok(());
    }
    let Some(me) = tx.core.member() else { return Ok(()) };
    let mut done: BTreeSet<CommitId> = BTreeSet::new();
    loop {
        // a vouch written moves its component: the removals filed there are due again, once (an
        // addendum moves none)
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

/// Writes the vouches and addenda removal `r` owes; takes it off the due set, filed under its
/// component, unless one it owes waits.
fn write_for(tx: &mut Tx<'_>, r: &CommitId, me: Tid) -> Result<()> {
    let now = tx.core.hlc.peek();
    let o = owed(tx.core, r, me, now);
    for (n, l) in o.left {
        tx.core.ix.vouch_left.insert((*r, n), l);
    }
    let v = writable_split(tx, me, o.on, ct::VOUCHES_AK, Some(Role::Sync))?;
    for (n, lists) in &v.now {
        write_entry(tx, *n, &ct::VOUCHES, r, lists.iter().copied().collect())?;
    }
    let a = writable_split(tx, me, o.addenda, ct::ADDENDA_AK, Some(Role::Write))?;
    for (n, lists) in &a.now {
        write_entry(tx, *n, &ct::ADDENDA, r, lists.clone())?;
    }
    #[cfg(debug_assertions)]
    if !v.now.is_empty() || !a.now.is_empty() {
        let again = owed(tx.core, r, me, tx.core.hlc.peek());
        debug_assert!(v.now.keys().all(|n| !again.on.contains_key(n)), "a vouch written here does not count here: {r:?} on {:?}", again.on.keys().collect::<Vec<_>>());
        debug_assert!(a.now.keys().all(|n| !again.addenda.contains_key(n)), "an addendum written here does not count here: {r:?} on {:?}", again.addenda.keys().collect::<Vec<_>>());
    }
    if v.later || !v.unheld.is_empty() || a.later || !a.unheld.is_empty() {
        return Ok(());
    }
    tx.core.ix.vouches_due.remove(r);
    // filed under its component as it stands after this node's own writes
    if let Some(c) = o.component.and(target_of(tx.core, r)).and_then(|t| tx.core.timelines.component(&t)) {
        tx.core.ix.vouch_watch.insert(c, *r);
    }
    Ok(())
}

/// Writes one entry keyed by removal `r` listing `lists` on `n`'s aspect `ak` (`vouches.0` or
/// `addenda.0`): a new entry of this delta's own (`put_new`, spec/data-model.md §9), whatever
/// this node holds at the key (another's answer to `r`).
fn write_entry<K: osis_schema::RawKey>(tx: &mut Tx<'_>, n: Tid, ak: &K, r: &CommitId, lists: BTreeSet<CommitId>) -> Result<()> {
    let mut mu = crate::Mutation::new();
    mu.op(n, ak, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(ct::Frontier { commits: lists }.to_value()) })?;
    Engine::commit_tx(tx, mu)?;
    Ok(())
}

/// The thing removal `r`'s first edge write targets.
fn target_of(core: &Core, r: &CommitId) -> Option<Tid> {
    core.ix.held.edge_commit(r).and_then(|c| c.ops.first().map(|o| o.target))
}

/// What removal `r` owes at this node (account `me`) at `now`: vouches (spec/permissions.md
/// §5.1 Vouches, Writing) and addenda (§5.2 Addenda, Writing), by one rule.
fn owed(core: &Core, r: &CommitId, me: Tid, now: Ts) -> Owed {
    let mut out = Owed::default();
    let Some(m) = core.ix.commits.get(r) else { return out };
    let Some(frontier) = m.view.frontier.clone() else { return out };
    let Some(rc) = core.ix.held.edge_commit(r) else { return out };
    let Some(target) = rc.ops.first().map(|o| o.target) else { return out };
    let Some(tl) = core.timelines.get(&target) else { return out };
    // a vouch or addendum is positioned after R: applying R moved the clock past its `ts`
    // (`Hlc::observe`)
    debug_assert!(now > rc.ts, "the clock is past an applied removal's ts");
    let comp = core.timelines.component(&target);
    // R not applying (dropped, or its author's authority in dispute) may come to, the walk
    // changing: judged again then
    if !(0..rc.ops.len()).filter_map(|k| u32::try_from(k).ok()).any(|k| tl.is_applied(&osis_perm::WriteId(*r, k))) {
        out.component = comp;
        return out;
    }
    if core.addenda_on {
        addenda_owed(core, tl, r, m, &frontier, me, now, &mut out);
    }
    // vouches: not at the node that wrote R
    if core.vouches_on && m.origin == Origin::Remote && may_owe(core, r, rc, &frontier, me, m.received) {
        vouches_owed(core, tl, r, m, rc, &frontier, me, now, &mut out);
    }
    out
}

/// The vouches removal `r` owes (`owed`).
#[allow(clippy::too_many_arguments)]
fn vouches_owed(core: &Core, tl: &osis_perm::Timeline, r: &CommitId, m: &crate::engine::Meta, rc: &osis_perm::RoleCommit, frontier: &osis_perm::Frontier, me: Tid, now: Ts, out: &mut Owed) {
    let Some(target) = rc.ops.first().map(|o| o.target) else { return };
    let comp = core.timelines.component(&target);
    // R applies in the first walk as an explicit lowering of another's grant (one that does not
    // may come to, the walk changing: judged again then); not at a node acting as one in
    // question at it
    let Some(in_question) = tl.in_question(r) else {
        out.component = comp;
        return;
    };
    if in_question.contains(&me) || in_question.contains(&core.id.tid()) {
        return;
    }
    let rp = rc.point();
    // candidates per thing of R's component in the node closure, in the order received
    let mut cands: BTreeMap<Tid, Vec<(osis_base::WallMs, CommitId)>> = BTreeMap::new();
    for x in in_question {
        for c in core.ix.held.authored_by(x, rp.ts) {
            if c == *r || frontier.covers(&c) || core.ix.held.is_uncounted(&c) {
                continue;
            }
            let Some(cm) = core.ix.commits.get(&c).filter(|cm| window(cm.received, rc.ts, m.received)) else { continue };
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
    // none: nothing is owed for good (its candidates are fixed once R is held), unless what
    // is in question at it grows (issues/s3-vouches-build.md)
    if cands.is_empty() {
        return;
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
        let taken = core.ix.vouch_left.get(&(*r, n)).filter(|l| l.all == all && l.trust == *tl.trust());
        let (lists, new) = leaving_out(tl, r, all, taken.map(|l| &**l));
        if let Some(l) = new {
            out.left.push((n, l));
        }
        if owes(&lists) {
            out.on.insert(n, lists);
        }
    }
}

/// The addenda removal `r` (its record `m`) owes (`owed`; spec/permissions.md §5.2 Addenda,
/// Writing): for each explicit demotion R makes in this node's view of a node X other than this
/// one below write on a thing N, X's content commits on N or acting for N, ordered before R,
/// received in R's window and not listed by its frontier are its candidates (plain content: no
/// role-class or admin-only part, no snapshot, no purge request). While one of them is one an
/// addendum this node wrote now would vouch for (it holds write on N now) and no counting addendum
/// of its own vouches for, it owes one addendum on N keyed by R listing every candidate.
///
/// Who writes each input: R and the candidates are their signers' word, judged by the walk and
/// layer 2; every addendum on N (any writer's, a removed party's forged ones included) goes
/// through the least fixpoint (`validity::vouching_on`), so only this node's own counting ones
/// stop it owing.
#[allow(clippy::too_many_arguments)]
fn addenda_owed(core: &Core, tl: &osis_perm::Timeline, r: &CommitId, m: &crate::engine::Meta, frontier: &osis_perm::Frontier, me: Tid, now: Ts, out: &mut Owed) {
    let mut cands: BTreeMap<Tid, BTreeSet<CommitId>> = BTreeMap::new();
    for (x, n, below) in tl.demoted_by(r) {
        if *x == me || *below != Role::Write {
            continue;
        }
        let (x, n) = (*x, *n);
        let held = core.ix.by_thing.get(&(n, x)).into_iter().flatten().chain(core.ix.by_actor.get(&(n, x)).into_iter().flatten());
        for c in held {
            let Some(cm) = core.ix.commits.get(c) else { continue };
            let v = &cm.view;
            // ordered before R (at its `ts` or earlier, §5.2 Position); what the frontier lists
            // needs no witness
            if v.purges || v.kind != osis_commit::Kind::Content || frontier.covers(c) || v.ts > m.view.ts || !window(cm.received, m.view.ts, m.received) {
                continue;
            }
            if v.aspects.iter().any(|a| plain_ak(&a.ak) && (a.tid == n || v.actor == n)) {
                cands.entry(n).or_default().insert(*c);
            }
        }
    }
    if cands.is_empty() {
        return;
    }
    if let Some(t) = target_of(core, r) {
        out.component = core.timelines.component(&t);
    }
    for (n, cs) in cands {
        let Some(tn) = core.timelines.get(&n) else { continue };
        // an addendum written now vouches only as a writer's
        if tn.role(&me, &n, osis_perm::At::now(now)) < Some(Role::Write) {
            continue;
        }
        let own = crate::apply::validity::vouching_on(core, &n);
        let vouched = |c: &CommitId| {
            let Some(cm) = core.ix.commits.get(c) else { return false };
            let at = Point { ts: cm.view.ts, node: cm.view.author, commit: *c };
            own.as_ref().is_some_and(|v| v.witnesses(tn, at).any(|(w, _)| w == me))
        };
        if cs.iter().any(|c| !vouched(c)) {
            out.addenda.insert(n, cs);
        }
    }
}

/// Whether a part on `ak` is plain content an addendum may list (spec/permissions.md §5.2,
/// Addenda): no role-class or admin-only aspect, no creation record; another addendum is one.
pub(crate) fn plain_ak(ak: &osis_base::Ak) -> bool {
    let s = ak.as_str();
    !ct::is_role_class(s) && !ak.admin_only() && s != "created.0"
}

/// The writers' leaving out (spec/permissions.md §5.1 Vouches, Writing): where R, trusted, would
/// not apply in this node's walk with every one of `all` listed, they are taken in the order
/// received, each kept only where R still applies with those kept so far. A list taken before for
/// the same candidates and trust set (`taken`) is kept while R still applies with it and not with
/// all (the spec's "may keep"): two walks per judgement in a fight, whatever the number of
/// candidates the removed party made; taking anew walks once per candidate. Returns the list and
/// the leaving out to keep when taken anew.
///
/// Invariant: the list returned is one the rule allows in this walk: R, trusted, applies with
/// it, and where it is not all of them, not with all.
fn leaving_out(tl: &osis_perm::Timeline, r: &CommitId, all: Vec<CommitId>, taken: Option<&LeftOut>) -> (Vec<CommitId>, Option<Arc<LeftOut>>) {
    osis_base::costs::count("vouches: leaving-out walks", 1);
    if tl.stands_with(r, &all) {
        return (all, None);
    }
    if let Some(l) = taken {
        osis_base::costs::count("vouches: leaving-out walks", 1);
        if tl.stands_with(r, &l.kept) {
            return (l.kept.clone(), None);
        }
    }
    let mut kept = Vec::new();
    for c in &all {
        kept.push(*c);
        osis_base::costs::count("vouches: leaving-out walks", 1);
        if !tl.stands_with(r, &kept) {
            kept.pop();
        }
    }
    let left = LeftOut { all, trust: tl.trust().clone(), kept: kept.clone() };
    (kept, Some(Arc::new(left)))
}
