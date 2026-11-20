//! A witness's writes to a removal, by one state rule: vouches (spec/permissions.md §5.1 Vouches,
//! Writing) for a removed party's role writes and addenda (§5.2 Addenda, Writing) for its content,
//! which a node received and the remover had not, written unasked (`owed`: `vouches_owed`,
//! `addenda_owed`). Vouches: for
//! each held removal R applying in its first walk as an explicit lowering of another's grant
//! (not at the node that wrote R, nor at one acting as a party in question at R), and each thing
//! N of R's component (written once N is in its node closure, `note_entered`): the commits in
//! question at R with a role-class part
//! on N, ordered before R, received in R's window (`window`: by its `ts` and before R) and not
//! listed by R's frontier are its
//! candidates; while one of them is one this node could write now and no counting vouch of its
//! own lists, it owes one vouch on N keyed by R listing every candidate (the writers' leaving out
//! applied).
//!
//! Addenda: for each explicit demotion R makes below write (below admin, for admin-only content)
//! in this node's view (R's own node included), the content commits of the demoted node in R's
//! window, not listed by its frontier, on each thing N it is demoted on (`addenda_owed`); owed
//! while this node holds the role one needs on N and no counting addendum of its own vouches for
//! it.
//!
//! Invariant: what is owed is a function of the held set, the receipts and the trust set (the
//! first walk, the counting entries and addenda, the clock), never of what this node wrote
//! before (bar a leaving out kept, `leaving_out`), so an
//! open re-derives it (`all_due`) and nothing about it is durable. A judgement gathers (`gather`:
//! whether R applies, its candidates) and then decides (`owed`: this node's roles, its own
//! counting answers); the gathering is kept (`Gathered`) and a removal is due again only when
//! something it reads moves: R's own change in the walk (`note_changed`: the only input of one
//! not applying), its component walked anew (`note_evaluated`), a commit ordered no later than
//! it applying or changing its standing and reaching a party R names or R's author (`wake`,
//! filed per such party, `Indexes::vouch_wake`), this node's roles moving on a thing it is filed under
//! (`note_roles_moved`: decided again, the gathering kept), a thing it is filed under entering
//! the node closure (`note_entered`: likewise). Another party's role change, or a
//! removed party's commits that change no walk, judge nothing. The window (`window`)
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

/// Notes removal `r` (a role commit with a frontier, applied here) as due, gathered anew (its
/// late parts may change what it names).
pub(crate) fn note_due(core: &mut Core, r: &CommitId) {
    core.ix.vouches_due.insert(*r);
    core.ix.vouch_gathered.remove(r);
}

/// The walk changed: of `commits` (`osis_perm::Changed::commits`: every commit whose change in
/// the walk's history differs, so every one that started or stopped applying), the removals
/// are due again, gathered anew. A removal not applying reads nothing else (`owed`), so this is
/// its only trigger: no write elsewhere judges it, however many such removals are held.
pub(crate) fn note_changed(core: &mut Core, commits: &BTreeSet<CommitId>) {
    for r in commits {
        let Some(m) = core.ix.commits.get(r) else { continue };
        let (removal, signer, ts) = (m.view.kind.is_role() && m.view.frontier.is_some(), m.view.signer, m.view.ts);
        if removal {
            note_due(core, r);
        }
        // and a commit ordered before a removal whose standing changed may change what it reads
        wake(core, r, signer, ts);
    }
}

/// The components of `things` were walked anew (`osis_perm::Changed::evaluated`: anything about
/// them may have changed, the first walk of a second walk included): the removals filed under
/// one of them (`Indexes::vouch_watch`) are due again, gathered anew.
pub(crate) fn note_evaluated(core: &mut Core, things: &BTreeSet<Tid>) {
    for t in things {
        let rs: Vec<CommitId> = core.ix.vouch_watch.get(t).into_iter().flatten().copied().collect();
        for r in rs {
            note_due(core, &r);
        }
    }
}

/// Roles moved for the parties `moved` (`Held::upstream` of a changed edge's holder or a new
/// record) on the things `under` (`Held::reach` of its target or that record): where this node
/// is one of them, the removals filed under a thing of `under` are due again, their gathering
/// kept: what this node may write (the role an addendum needs, "could write" a vouch's commit)
/// and which of its own answers count read its roles, and nothing else they read moved. Another
/// party's role moving judges nothing.
pub(crate) fn note_roles_moved(core: &mut Core, moved: &BTreeSet<Tid>, under: &BTreeSet<Tid>) {
    if core.ix.vouch_watch.is_empty() || !(core.member().is_some_and(|m| moved.contains(&m)) || moved.contains(&core.id.tid())) {
        return;
    }
    for t in under {
        let rs: Vec<CommitId> = core.ix.vouch_watch.get(t).into_iter().flatten().copied().collect();
        for r in rs {
            core.ix.vouches_due.insert(r);
        }
    }
}

/// The things `came` may have entered the node closure (`apply::wake_entered`, from the closure's
/// own log of its members: every entry passes through it): where one now holds it, the removals
/// filed under it (`Indexes::vouch_watch`: every thing a candidate is on, held or not) are due
/// again, their gathering kept. A vouch or addendum owed on a thing outside the node closure
/// waits for it (spec/sync-set.md §2 Writing); nothing else it reads moved. Leaving the closure
/// owes nothing new.
pub(crate) fn note_entered(core: &mut Core, came: &BTreeSet<Tid>) {
    if core.ix.vouch_watch.is_empty() {
        return;
    }
    for t in came.iter().filter(|t| core.ix.closure.holds(t)) {
        let rs: Vec<CommitId> = core.ix.vouch_watch.get(t).into_iter().flatten().copied().collect();
        osis_base::costs::count("vouches: removals woken on entry", u64::try_from(rs.len()).unwrap_or(u64::MAX));
        for r in rs {
            core.ix.vouches_due.insert(r);
        }
    }
}

/// Commit `id` (header `h`) applied here (whole or by late parts): it may be a candidate of a
/// removal received in time that applied only now (pending meanwhile), or a grant bringing a
/// party into question at one (`wake`).
pub(crate) fn note_applied(core: &mut Core, id: &CommitId, h: &osis_commit::Header) {
    wake(core, id, h.signer, h.ts);
}

/// Commit `id` by `signer` stamped `ts` applied or changed its standing in the walk: the
/// removals stamped no earlier, filed under a party it reaches (`Indexes::vouch_wake`), are due
/// again, gathered anew. A party comes into question at R, falls at it or not, or a commit of
/// one becomes a candidate, only by a commit ordered no later than R moving a path of a party
/// that reaches a holder R names or R's author (`Held::reach` climbs to what a party holds): a
/// commit of its own, or an edge write whose holder it is or stands behind (`Held::upstream`):
/// a member joining a team R names, a named holder's or a member's other path to what R lowers
/// taken away, the remover's authority lowered. So the climb is from the signer, the edge writes'
/// targets and everything upstream of their holders. Live traffic (stamped after every filed
/// removal) costs a comparison, and a backdated or late commit that climb; one with no edge
/// write wakes only the removals it arrived before (`window`), so a removed party's backdated
/// content judges nothing.
///
/// Invariant: every input a kept gathering reads besides R's own change in the walk
/// (`note_changed`) and a re-walk of its component (`note_evaluated`) moves only by such a
/// commit: who is in question or demoted at R and whether R applies are read from the walk
/// before R; the candidates are commits held before R's arrival.
fn wake(core: &mut Core, id: &CommitId, signer: Tid, ts: Ts) {
    let Some(&(newest, _)) = core.ix.vouch_wake_ts.last() else { return };
    if ts > newest {
        return;
    }
    osis_base::costs::count("vouches: wake climbs", 1);
    let mut from: BTreeSet<Tid> = BTreeSet::from([signer]);
    let edges = core.ix.held.edge_commit(id);
    if let Some(rc) = edges {
        let holders: BTreeSet<Tid> = rc.ops.iter().map(|o| o.holder).collect();
        from.extend(core.ix.held.upstream(&holders));
        from.extend(rc.ops.iter().map(|o| o.target));
    }
    // one with no edge write moves no walk: it matters only as a candidate, received before R
    let got = core.ix.commits.get(id).map(|m| m.received);
    let edges = edges.is_some();
    let parties = core.ix.held.reach(&from);
    osis_base::costs::count("vouches: wake parties", u64::try_from(parties.len()).unwrap_or(u64::MAX));
    for t in parties {
        let lo = (t, ts, CommitId([0; 32]));
        let hi = (t, Ts::MAX, CommitId([0xff; 32]));
        let due: Vec<CommitId> = core.ix.vouch_wake.range(lo..=hi).map(|(_, _, r)| *r).filter(|r| edges || got.is_none_or(|g| core.ix.commits.get(r).is_none_or(|rm| g < rm.received))).collect();
        for r in due {
            osis_base::costs::count("vouches: removals woken", 1);
            note_due(core, &r);
        }
    }
}

/// Files removal `r` (its edge commit `rc`) under the parties a commit ordered before it must
/// reach to change what it reads (`wake`): the holders its edge writes name and its author. One
/// entry each, however many parties stand behind a holder (a team's members reach it).
fn file_wake(core: &mut Core, r: &CommitId) {
    let Some(rc) = core.ix.held.edge_commit(r) else { return };
    let ts = rc.ts;
    let parties: BTreeSet<Tid> = rc.ops.iter().map(|o| o.holder).chain(std::iter::once(rc.signer)).collect();
    for t in parties {
        if core.ix.vouch_wake.insert((t, ts, *r)) {
            osis_base::costs::count("vouches: wake entries", 1);
        }
    }
    core.ix.vouch_wake_ts.insert((ts, *r));
}

/// Every held removal due (an open: what is owed is re-derived, never kept).
pub(crate) fn all_due(core: &mut Core) {
    let rs: Vec<CommitId> = core.ix.commits.iter().filter(|(_, m)| m.view.kind.is_role() && m.view.frontier.is_some()).map(|(id, _)| *id).collect();
    for r in rs {
        note_due(core, &r);
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

/// What a judgement of removal R gathers (`gather`): whether it applies, and its candidates, read
/// off R's standing in the walk (applied, `in_question` in the first walk, `demoted_by`) and the
/// commits held before it with their receipts. Kept per removal (`Indexes::vouch_gathered`) and
/// gathered anew only when one of those may have changed: R's own change in the walk
/// (`note_changed`), its component walked anew (`note_evaluated`), a commit ordered no later
/// than it applying (`note_applied`), its late parts (`note_due`), an open. Receipts are final
/// once R is held (its window closes at its arrival), and a commit arriving after R is in no
/// window, so nothing else adds a candidate. Debug builds check a kept gathering against a fresh
/// one at each judgement.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Gathered {
    /// R applies in this node's walk.
    applies: bool,
    /// R applies but as no explicit lowering of another's grant in the first walk: it may come
    /// to, the walk changing.
    unsettled: bool,
    /// Addenda candidates per thing: each commit with the roles its listed parts need.
    addenda: BTreeMap<Tid, BTreeMap<CommitId, BTreeSet<Role>>>,
    /// Vouch candidates per thing, in the order received.
    vouches: BTreeMap<Tid, Vec<(osis_base::WallMs, CommitId)>>,
}

impl Gathered {
    /// The things a judgement of it is filed under (`Indexes::vouch_watch`): those of its
    /// candidates, and its target while it is unsettled. Nothing for one not applying (only its
    /// own change in the walk makes it due, `note_changed`) or with nothing to gather (only a
    /// commit ordered before it applying can bring one, `note_applied`).
    fn watched(&self, target: Tid) -> BTreeSet<Tid> {
        if !self.applies {
            return BTreeSet::new();
        }
        self.addenda.keys().chain(self.vouches.keys()).copied().chain(self.unsettled.then_some(target)).collect()
    }
}

/// What a removal owes here (`owed`).
#[derive(Debug, Default)]
struct Owed {
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
/// not listed by its frontier. O(those authors' role commits before `r`).
fn may_owe(core: &Core, r: &CommitId, rc: &osis_perm::RoleCommit, frontier: &osis_perm::Frontier, me: Tid, r_got: osis_base::WallMs) -> bool {
    let named: BTreeSet<Tid> = rc.ops.iter().map(|o| o.holder).filter(|h| *h != rc.signer).collect();
    let authors = core.ix.held.upstream(&named);
    authors.iter().filter(|a| **a != rc.signer && **a != me).any(|a| core.ix.held.authored_by(a, rc.ts).any(|c| c != *r && !frontier.covers(&c) && core.ix.commits.get(&c).is_some_and(|cm| window(cm.received, rc.ts, r_got))))
}

/// Writes every vouch owed for the due removals (`Indexes::vouches_due`), each removal once per
/// call, each in a step of its own (`Tx::step`): one that fails leaves nothing, is reported
/// (`DiagnosticKind::OwnWriteFailed`) and stays due. A removal owing a vouch on a thing this node
/// may write on only once its minting or keys arrive stays due, judged again at the end of each
/// transaction until written; one owed on a thing outside the node closure is filed under it and
/// judged again as it enters (`note_entered`).
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

/// Writes the vouches and addenda removal `r` owes; takes it off the due set, filed under the
/// things its judgement reads this node's roles on (`Gathered::watched`), unless one it owes
/// waits.
fn write_for(tx: &mut Tx<'_>, r: &CommitId, me: Tid) -> Result<()> {
    let now = tx.core.hlc.peek();
    let g = match tx.core.ix.vouch_gathered.get(r) {
        Some(g) => {
            #[cfg(debug_assertions)]
            debug_assert!(gather(tx.core, r, me, false).as_ref() == Some(&**g), "a kept gathering of {r:?} is what a fresh one gathers");
            g.clone()
        }
        None => {
            let Some(g) = gather(tx.core, r, me, true) else {
                tx.core.ix.vouches_due.remove(r);
                return Ok(());
            };
            let g = Arc::new(g);
            tx.core.ix.vouch_gathered.insert(*r, g.clone());
            g
        }
    };
    let o = owed(tx.core, r, &g, me, now);
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
    if (!v.now.is_empty() || !a.now.is_empty())
        && let Some(g) = gather(tx.core, r, me, false)
    {
        let again = owed(tx.core, r, &g, me, tx.core.hlc.peek());
        debug_assert!(v.now.keys().all(|n| !again.on.contains_key(n)), "a vouch written here does not count here: {r:?} on {:?}", again.on.keys().collect::<Vec<_>>());
        debug_assert!(a.now.keys().all(|n| !again.addenda.contains_key(n)), "an addendum written here does not count here: {r:?} on {:?}", again.addenda.keys().collect::<Vec<_>>());
    }
    // an answer on a thing outside the node closure waits for it to enter (`note_entered`: it is
    // a candidate's thing, so filed under it below)
    if v.later || a.later {
        return Ok(());
    }
    tx.core.ix.vouches_due.remove(r);
    // filed under the parties that may bring it a candidate later (a commit of one received in
    // time applying late, a late grant bringing one into question), whatever it owes now
    file_wake(tx.core, r);
    // filed under the things whose roles for this node it reads; the gathering kept while filed
    let old = tx.core.ix.vouch_filed.remove(r);
    for t in old.iter().flat_map(|s| s.iter()) {
        tx.core.ix.vouch_watch.remove(t, r);
    }
    let watched = target_of(tx.core, r).map(|t| g.watched(t)).unwrap_or_default();
    if watched.is_empty() {
        tx.core.ix.vouch_gathered.remove(r);
        return Ok(());
    }
    for t in &watched {
        tx.core.ix.vouch_watch.insert(*t, *r);
    }
    tx.core.ix.vouch_filed.insert(*r, Arc::new(watched));
    Ok(())
}

/// Debug builds, after every durable transaction and at an engine's drop: no trigger was
/// missed. Of every held removal not due, a
/// kept gathering is what a fresh one gathers, and a fresh judgement owes nothing this node may
/// write now: a stale gathering or an answer owed with no judgement due is a missed trigger, which
/// the check at each judgement (`write_for`) cannot see. `Some`: what differs.
#[cfg(debug_assertions)]
pub(crate) fn missed(tx: &mut Tx<'_>) -> Result<Option<String>> {
    if !(tx.core.vouches_on || tx.core.addenda_on) {
        return Ok(None);
    }
    let Some(me) = tx.core.member() else { return Ok(None) };
    let now = tx.core.hlc.peek();
    let rs: Vec<CommitId> = tx.core.ix.commits.iter().filter(|(id, m)| m.view.kind.is_role() && m.view.frontier.is_some() && !tx.core.ix.vouches_due.contains(id)).map(|(id, _)| *id).collect();
    for r in rs {
        let fresh = gather(tx.core, &r, me, false);
        if let Some(kept) = tx.core.ix.vouch_gathered.get(&r)
            && fresh.as_ref() != Some(&**kept)
        {
            return Ok(Some(format!("removal {r:?}: kept gathering {kept:?}, fresh {fresh:?}")));
        }
        let Some(g) = fresh else { continue };
        let o = owed(tx.core, &r, &g, me, now);
        let v = writable_split(tx, me, o.on, ct::VOUCHES_AK, Some(Role::Sync))?;
        let a = writable_split(tx, me, o.addenda, ct::ADDENDA_AK, Some(Role::Write))?;
        if !v.now.is_empty() || !a.now.is_empty() {
            return Ok(Some(format!("removal {r:?}, not due, owes vouches on {:?}, addenda on {:?}", v.now.keys().collect::<Vec<_>>(), a.now.keys().collect::<Vec<_>>())));
        }
    }
    Ok(None)
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

/// What a judgement of removal `r` at this node (account `me`) gathers (`Gathered`); `None`: it
/// never owes (not held, not a role commit with a frontier). `count`: counts the commits scanned.
fn gather(core: &Core, r: &CommitId, me: Tid, count: bool) -> Option<Gathered> {
    let mut out = Gathered::default();
    let m = core.ix.commits.get(r)?;
    let frontier = m.view.frontier.clone()?;
    let rc = core.ix.held.edge_commit(r)?;
    let target = rc.ops.first().map(|o| o.target)?;
    let tl = core.timelines.get(&target)?;
    // R not applying (dropped, or its author's authority in dispute) owes nothing; it may come
    // to apply, and then its change enters the walk's history: judged again then
    // (`note_changed`)
    out.applies = (0..rc.ops.len()).filter_map(|k| u32::try_from(k).ok()).any(|k| tl.is_applied(&osis_perm::WriteId(*r, k)));
    if !out.applies {
        return Some(out);
    }
    let scanned = |n: u64| {
        if count {
            osis_base::costs::count("vouches: commits scanned", n);
        }
    };
    if core.addenda_on {
        out.addenda = addenda_candidates(core, tl, r, m, &frontier, me, &scanned);
    }
    // vouches: not at the node that wrote R
    if core.vouches_on && m.origin == Origin::Remote && may_owe(core, r, rc, &frontier, me, m.received) {
        // R applies in the first walk as an explicit lowering of another's grant (one that does
        // not may come to, the walk changing); not at a node acting as one in question at it
        match tl.in_question(r) {
            None => out.unsettled = true,
            Some(q) if q.contains(&me) || q.contains(&core.id.tid()) => {}
            Some(q) => out.vouches = vouch_candidates(core, q, r, m, rc, &frontier, &scanned),
        }
    }
    Some(out)
}

/// What removal `r`, gathered as `g`, owes at this node (account `me`) at `now`: vouches
/// (spec/permissions.md §5.1 Vouches, Writing) and addenda (§5.2 Addenda, Writing), by one rule.
/// Reads, beside `g`, only what may change while `g` holds: this node's roles, its own counting
/// answers, the components, the epoch rule's counting and the commits still held (the node
/// closure is read where the answers are written, `writable_split`).
fn owed(core: &Core, r: &CommitId, g: &Gathered, me: Tid, now: Ts) -> Owed {
    let mut out = Owed::default();
    if !g.applies {
        return out;
    }
    let Some(target) = target_of(core, r) else { return out };
    let Some(tl) = core.timelines.get(&target) else { return out };
    // a vouch or addendum is positioned after R: applying R moved the clock past its `ts`
    // (`Hlc::observe`)
    debug_assert!(core.ix.commits.get(r).is_none_or(|m| now > m.view.ts), "the clock is past an applied removal's ts");
    addenda_owed(core, &g.addenda, me, now, &mut out);
    vouches_owed(core, tl, r, &g.vouches, target, me, now, &mut out);
    out
}

/// Removal `r`'s vouch candidates (`Gathered::vouches`): of the parties in question at it
/// (`in_question`), the commits with a role-class part on a thing, ordered before R, received in
/// R's window (by its `ts` and before R) and not listed by R's frontier, per thing, in the order
/// received.
fn vouch_candidates(core: &Core, in_question: &BTreeSet<Tid>, r: &CommitId, m: &crate::engine::Meta, rc: &osis_perm::RoleCommit, frontier: &osis_perm::Frontier, scanned: &dyn Fn(u64)) -> BTreeMap<Tid, Vec<(osis_base::WallMs, CommitId)>> {
    let rp = rc.point();
    let mut cands: BTreeMap<Tid, Vec<(osis_base::WallMs, CommitId)>> = BTreeMap::new();
    for x in in_question {
        for c in core.ix.held.authored_by(x, rp.ts) {
            scanned(1);
            if c == *r || frontier.covers(&c) {
                continue;
            }
            let Some(cm) = core.ix.commits.get(&c).filter(|cm| window(cm.received, rc.ts, m.received)) else { continue };
            let edges = core.ix.held.edge_commit(&c);
            let at = edges.map_or(Point::start(cm.view.ts), |e| e.point());
            if at >= rp {
                continue;
            }
            let things: BTreeSet<Tid> = edges.into_iter().flat_map(|e| e.ops.iter().map(|o| o.target)).chain(core.ix.held.parts_of(&c).into_iter().flat_map(|p| p.parts.iter().map(|(t, _)| *t).collect::<Vec<_>>())).collect();
            for n in things {
                cands.entry(n).or_default().push((cm.received, c));
            }
        }
    }
    for cs in cands.values_mut() {
        cs.sort_unstable();
    }
    cands
}

/// The vouches removal `r` owes (`owed`): on each thing N of R's component (written once N is
/// in the node closure: `writable_split`, `note_entered`),
/// while one of its candidates there that still counts (`Held::is_uncounted`) is one this node
/// could write now and no counting vouch of its own lists, one vouch listing every candidate (the
/// writers' leaving out applied).
#[allow(clippy::too_many_arguments)]
fn vouches_owed(core: &Core, tl: &osis_perm::Timeline, r: &CommitId, cands: &BTreeMap<Tid, Vec<(osis_base::WallMs, CommitId)>>, target: Tid, me: Tid, now: Ts, out: &mut Owed) {
    if cands.is_empty() {
        return;
    }
    let comp = core.timelines.component(&target);
    let own = tl.counted_by(&me, r);
    let parts = |c: &CommitId| core.ix.held.parts_of(c).map(|p| p.parts.clone()).unwrap_or_default();
    for (n, cs) in cands {
        // a thing outside the node closure is owed too, written as it enters (`writable_split`,
        // `note_entered`)
        if core.timelines.component(n) != comp {
            continue;
        }
        let owes = |cs: &[CommitId]| cs.iter().any(|c| !own.contains(c) && tl.could_write(&me, c, &parts(c), now));
        let all: Vec<CommitId> = cs.iter().map(|(_, c)| *c).filter(|c| core.ix.commits.contains_key(c) && !core.ix.held.is_uncounted(c)).collect();
        // a commit the leaving out drops owes nothing: the walk the leaving out needs only
        // where some candidate is owed at all
        if !owes(&all) {
            continue;
        }
        let taken = core.ix.vouch_left.get(&(*r, *n)).filter(|l| l.all == all && l.trust == *tl.trust());
        let (lists, new) = leaving_out(tl, r, all, taken.map(|l| &**l));
        if let Some(l) = new {
            out.left.push((*n, l));
        }
        if owes(&lists) {
            out.on.insert(*n, lists);
        }
    }
}

/// Removal `r`'s addenda candidates (`Gathered::addenda`; spec/permissions.md §5.2 Addenda,
/// Writing): for each explicit demotion R makes in this node's view of a node X other than this
/// one below write on a thing N, X's plain content commits on N or acting for N (no role-class or
/// admin-only part), and for each below admin, X's commits with admin-only content on N that is
/// not role-class, ordered before R, received in R's window and not listed by its frontier, no
/// snapshot or purge request, each with the role it needs.
#[allow(clippy::too_many_arguments)]
fn addenda_candidates(core: &Core, tl: &osis_perm::Timeline, r: &CommitId, m: &crate::engine::Meta, frontier: &osis_perm::Frontier, me: Tid, scanned: &dyn Fn(u64)) -> BTreeMap<Tid, BTreeMap<CommitId, BTreeSet<Role>>> {
    let mut cands: BTreeMap<Tid, BTreeMap<CommitId, BTreeSet<Role>>> = BTreeMap::new();
    for (x, n, below) in tl.demoted_by(r) {
        let (x, n, below) = (*x, *n, *below);
        if x == me {
            continue;
        }
        let held = core.ix.by_thing.get(&(n, x)).into_iter().flatten().chain(core.ix.by_actor.get(&(n, x)).into_iter().flatten());
        for c in held {
            scanned(1);
            let Some(cm) = core.ix.commits.get(c) else { continue };
            let v = &cm.view;
            // ordered before R (at its `ts` or earlier, §5.2 Position); what the frontier lists
            // needs no witness
            if v.purges || v.kind != osis_commit::Kind::Content || frontier.covers(c) || v.ts > m.view.ts || !window(cm.received, m.view.ts, m.received) {
                continue;
            }
            let listed = match below {
                // a plain part on N, or the Acting check for N
                Role::Write => v.aspects.iter().any(|a| plain_ak(&a.ak) && (a.tid == n || v.acting == n)),
                Role::Admin => v.aspects.iter().any(|a| a.tid == n && admin_listable_ak(&a.ak)),
                _ => false,
            };
            if listed {
                cands.entry(n).or_default().entry(*c).or_default().insert(below);
            }
        }
    }
    cands
}

/// The addenda owed for candidates `cands` (`owed`): while one of them is one an addendum this
/// node wrote now would vouch for (it holds the role it needs on N now) and no counting
/// addendum of its own vouches for, one addendum on N listing every candidate still held.
///
/// Who writes each input: R and the candidates are their signers' word, judged by the walk and
/// layer 2; every addendum on N (any writer's, a removed party's forged ones included) goes
/// through the least fixpoint (`validity::vouching_on`), so only this node's own counting ones
/// stop it owing.
fn addenda_owed(core: &Core, cands: &BTreeMap<Tid, BTreeMap<CommitId, BTreeSet<Role>>>, me: Tid, now: Ts, out: &mut Owed) {
    for (n, cs) in cands {
        let Some(tn) = core.timelines.get(n) else { continue };
        // an addendum written now vouches as a holder of the role a part needs
        let mine = tn.role(&me, n, osis_perm::At::now(now));
        if mine < Some(Role::Write) {
            continue;
        }
        let held: Vec<(&CommitId, &BTreeSet<Role>)> = cs.iter().filter(|(c, _)| core.ix.commits.contains_key(*c)).collect();
        let own = crate::apply::validity::vouching_on(core, n);
        let vouched = |c: &CommitId, q: Role| {
            let Some(cm) = core.ix.commits.get(c) else { return false };
            let at = Point { ts: cm.view.ts, node: cm.view.signer, commit: *c };
            own.as_ref().is_some_and(|v| v.witnesses(tn, at, q).any(|(w, _)| w == me))
        };
        if held.iter().any(|(c, qs)| qs.iter().any(|q| mine >= Some(*q) && !vouched(c, *q))) {
            out.addenda.insert(*n, held.into_iter().map(|(c, _)| *c).collect());
        }
    }
}

/// Whether a part on admin-only `ak` is content an addendum by a witness holding admin may list
/// (spec/permissions.md §5.2, Addenda: admin-only content that is not role-class).
pub(crate) fn admin_listable_ak(ak: &osis_base::Ak) -> bool {
    let s = ak.as_str();
    ak.admin_only() && !ct::is_role_class(s) && s != "created.0"
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
