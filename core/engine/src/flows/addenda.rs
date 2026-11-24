//! Addenda (spec/permissions.md §5.2 Addenda, Writing): a witness's writes to a removal for the
//! content of a demoted node it received and the remover had not, written unasked by one state
//! rule. For each explicit demotion R makes below write (below admin, for admin-only content) in
//! this node's view (R's own node included), the content commits of the demoted node in R's
//! window (`window`: received by R's `ts` and before R), not listed by its frontier, on each thing
//! N it is demoted on, are its candidates (`gather`); while one of them is one an
//! addendum this node wrote now would vouch for and no counting addendum of its own vouches for
//! it, it owes one addendum on N keyed by R listing every candidate (`unvouched`, `may_vouch`), written once
//! N is in its node closure and this node may write there (`decide`).
//!
//! Invariant: what is owed is a function of the held set, the receipts and the trust set (the
//! walk, the counting addenda, the clock), never of what this node wrote before, so an open
//! re-derives it (`all_due`) and nothing about it is durable. A judgement gathers (`gather`:
//! whether R applies, its candidates) and then decides (`decide`: this node's roles, its own
//! counting addenda, the node closure, whether it may write there). The gathering is kept
//! (`Gathered`, `Indexes::addenda_gathered`) and done again only when what it reads may have
//! moved: R's own status in the walk (`note_changed`: the only input of one not applying), the
//! history of an edge R writes changing at or before it, or a delta stated through such an edge,
//! ordered no later than R and received before it, coming (`wake`, filed per edge,
//! `Indexes::addenda_wake`), R's late parts (`note_due`). Another edge's change, or a removed
//! party's commits on edges R does not write, gather nothing, so a commit wakes in proportion to
//! the edges it names and the removals on them, never to what its author reaches. The window
//! closes at R's own arrival, so its candidates' receipts are final once R is held. The decide is
//! followed (`Core::addenda_owed`, `memo::Effects` per removal): settled again exactly where
//! something it read moved, so no input of it has a trigger to forget. It reads this node's role
//! on each thing with an unvouched candidate as a row (`Core::own_roles`), so a role change there
//! that leaves this node's role as it was decides nothing. So a removal owing nothing costs nothing per step,
//! and a node ingesting a history it received after it (a joiner) judges each removal once.
//!
//! Who writes each input: R, the candidates and every addendum are their signers' word (a
//! removed party may sign any number, at any key and `ts`; any writer writes `addenda.0`); the
//! walk and layer 2 judge them all. An addendum is content: it moves no component, so a flood of
//! them gathers nothing; one keyed by R decides R again, once per addendum. This node writes only
//! what it received and could vouch for itself, so a forged addendum or a flood of a removed
//! party's commits makes it write nothing it would not write from the honest ones: a removed
//! party's commits after R are not candidates (ordered after R, or received after its `ts` or
//! after R: a remover's clock running ahead lengthens nothing).

use crate::engine::write::{MayWrite, may_write_on, within_depth, writable_split};
use crate::engine::{Core, Engine, Step, Tx};
use crate::error::Result;
use crate::events::{Diagnostic, DiagnosticKind};
use osis_base::{CommitId, Role, Tid, Ts, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_schema::Codec;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What a removal owes at this node and may write now, per thing: the commits its addendum
/// there lists (`decide`).
pub(crate) type Owes = Arc<BTreeMap<Tid, BTreeSet<CommitId>>>;

/// Notes removal `r` (a role commit with a frontier, applied here) as due to gather again (its
/// late parts may change what it names).
pub(crate) fn note_due(core: &mut Core, r: &CommitId) {
    core.ix.addenda_due.insert(*r);
}

/// The walk changed (`osis_perm::Changed`): the removals whose gathering may have moved are due
/// again (`wake`). A removal not applying reads nothing else (`gather`), so its own edge write's
/// status moving is its only trigger: no write elsewhere gathers it, however many such removals
/// are held.
pub(crate) fn note_changed(core: &mut Core, c: &osis_perm::Changed) {
    for w in &c.ops {
        if core.ix.commits.get(&w.0).is_some_and(|m| m.view.kind.is_role() && m.view.frontier.is_some()) {
            note_due(core, &w.0);
        }
    }
    if core.ix.addenda_wake.is_empty() {
        return;
    }
    wake(core, c);
}

/// The removals a walk change `c` may have moved the gathering of (`gather`) are due again,
/// gathered anew; the work is per edge and delta `c` names, never per party behind them. A
/// gathering reads, besides R's own status (`note_changed`), only R's edge histories before R
/// (whether each write is a cut: the edge as restored before it) and the held deltas stated
/// through R's edges (`Paths::through`, `rests`: facts of their own commits). So R, filed under
/// each edge its writes are on (`file_wake`), is woken by an edge whose history changed at or
/// before R's `ts`, a record edge of its target coming or going, and a delta new in the walk
/// stated through its edge, stamped no later than R and received before it (`window`: a
/// removed party's backdated content judges nothing).
///
/// Invariant: every input a kept gathering reads besides R's own status moves only by such a
/// change: who R cuts and whether R applies are read from R's edges' histories, the
/// candidates are held deltas stated along R's edges.
fn wake(core: &mut Core, c: &osis_perm::Changed) {
    let mut due: BTreeSet<CommitId> = BTreeSet::new();
    let on = |core: &Core, (holder, target): (osis_base::Holder, Tid), from: Ts, due: &mut BTreeSet<CommitId>, got: Option<osis_base::WallMs>| {
        osis_base::costs::count("addenda: wake lookups", 1);
        let lo = (target, holder, from, CommitId([0; 32]));
        let hi = (target, holder, Ts::MAX, CommitId([0xff; 32]));
        due.extend(core.ix.addenda_wake.range(lo..=hi).map(|x| x.3).filter(|r| got.is_none_or(|g| core.ix.commits.get(r).is_none_or(|rm| g < rm.received))));
    };
    for (&e, k) in &c.walk.edges {
        on(core, e, k.ts, &mut due, None);
    }
    // a record edge coming or going moves every edge into its thing as restored
    for t in &c.created {
        osis_base::costs::count("addenda: wake lookups", 1);
        let (lo, hi) = (osis_base::Holder::Thing(Tid::from_bytes([0; osis_base::format::TID_LEN])), osis_base::Holder::Key(osis_base::SignKey([0xff; 32])));
        due.extend(core.ix.addenda_wake.range((*t, lo, Ts::ZERO, CommitId([0; 32]))..=(*t, hi, Ts::MAX, CommitId([0xff; 32]))).map(|x| x.3));
    }
    for w in &c.walk.parts {
        let Some((hops, k)) = core.timelines().paths().rests(w) else { continue };
        let got = core.ix.commits.get(&w.0).map(|m| m.received);
        for e in hops {
            on(core, e, k.ts, &mut due, got);
        }
    }
    for r in due {
        osis_base::costs::count("addenda: removals woken", 1);
        note_due(core, &r);
    }
}

/// Files removal `r` (its edge commit `rc`) under the edges its writes are on (`wake`): one
/// entry each, keyed (target, holder, `ts`, R).
fn file_wake(core: &mut Core, r: &CommitId) {
    let Some(rc) = core.ix.held.edge_commit(r) else { return };
    let ts = rc.ts;
    let edges: BTreeSet<(Tid, osis_base::Holder)> = rc.ops.iter().map(|o| (o.target, o.holder)).collect();
    for (target, holder) in edges {
        if core.ix.addenda_wake.insert((target, holder, ts, *r)) {
            osis_base::costs::count("addenda: wake entries", 1);
        }
    }
}

/// Every held removal due (an open: what is owed is re-derived, never kept).
pub(crate) fn all_due(core: &mut Core) {
    let rs: Vec<CommitId> = core.ix.commits.iter().filter(|(_, m)| m.view.kind.is_role() && m.view.frontier.is_some()).map(|(id, _)| *id).collect();
    for r in rs {
        note_due(core, &r);
    }
}

/// Whether a commit received at `got` is in removal R's window at this node (spec/permissions.md
/// §5.2 Addenda, Writing): received by R's `ts` and before R itself (R's first arrival `r_got`,
/// both by the wall clock; the same millisecond is not before). The second bound keeps a
/// remover's fast clock from lengthening the window past R's arrival: what arrives after a
/// witness holds R is never vouched for, however far R's `ts` is ahead.
pub(crate) fn window(got: osis_base::WallMs, r_ts: Ts, r_got: osis_base::WallMs) -> bool {
    got.0 <= r_ts.wall_ms().0 && got.0 < r_got.0
}

/// What a judgement of removal R gathers (`gather`): whether it applies, and its candidates, read
/// off R's standing in the walk (applied, the cuts it makes) and the commits held before it with their
/// receipts. Kept per removal (`Indexes::addenda_gathered`) and
/// gathered anew only when one of those may have changed: R's own status in the walk
/// (`note_changed`), an edge R writes changing at or before it or a delta stated through one
/// coming (`wake`), its late parts (`note_due`), an open. Receipts are final
/// once R is held (its window closes at its arrival), and a commit arriving after R is in no
/// window, so nothing else adds a candidate. Debug builds check every kept gathering against a
/// fresh one after each durable transaction (`missed`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Gathered {
    /// R applies in this node's walk.
    applies: bool,
    /// Candidates per thing: each commit with the roles its listed parts need.
    addenda: BTreeMap<Tid, BTreeMap<CommitId, BTreeSet<Role>>>,
}


/// The decides followed (`Core::addenda_owed`) and the own-role rows each last read
/// (`Core::own_roles`): a row is held while a followed decide's last settle read it, and goes
/// with the last such reader (one settled to read it no more, or no longer followed), so the
/// rows follow the removals that still need a role read, never every thing once read.
#[derive(Clone)]
pub(crate) struct Decides {
    fx: osis_base::memo::Effects<CommitId, Owes>,
    /// The things each followed removal's last settle read its role on.
    read: BTreeMap<CommitId, BTreeSet<Tid>>,
    /// The removals whose last settle read the role on each thing.
    readers: BTreeMap<Tid, BTreeSet<CommitId>>,
}

impl Default for Decides {
    fn default() -> Self {
        Decides { fx: osis_base::memo::Effects::new("addenda: owed"), read: BTreeMap::new(), readers: BTreeMap::new() }
    }
}

impl Decides {
    /// `r` read the roles on `things` at its last settle: the rows read by it alone before and
    /// not now go.
    fn note_read(&mut self, core: &Core, r: &CommitId, things: BTreeSet<Tid>) {
        let was = if things.is_empty() { self.read.remove(r) } else { self.read.insert(*r, things.clone()) };
        for t in was.iter().flatten().filter(|t| !things.contains(t)) {
            self.unread(core, r, t);
        }
        for t in things {
            self.readers.entry(t).or_default().insert(*r);
        }
    }

    fn unread(&mut self, core: &Core, r: &CommitId, t: &Tid) {
        let Some(rs) = self.readers.get_mut(t) else { return };
        rs.remove(r);
        if rs.is_empty() {
            self.readers.remove(t);
            core.own_roles.unfollow(t);
        }
    }

    /// Follows `r`'s decide no more: the rows it alone read go.
    fn unwant(&mut self, core: &Core, r: &CommitId) {
        self.fx.unwant(r);
        self.note_read(core, r, BTreeSet::new());
    }
}

/// Writes every addendum owed: gathers the removals due (`Indexes::addenda_due`), then decides
/// every followed removal whose reads moved (`Core::addenda_owed`) and writes what one owes, each
/// removal's addenda in a step of its own (`Tx::step`): one that fails leaves nothing, is
/// reported (`DiagnosticKind::OwnWriteFailed`) and is decided again at the next call. An addendum
/// owed on a thing outside the node closure, or one this node may write on only once its minting
/// or keys arrive, is decided again when that moves, as any other read of the decide.
pub(crate) fn write_owed(tx: &mut Tx<'_>) -> Result<()> {
    if !tx.core.addenda_on {
        return Ok(());
    }
    let me = tx.core.me();
    let mut ds = std::mem::take(&mut tx.core.addenda_owed);
    let due: Vec<CommitId> = tx.core.ix.addenda_due.iter().copied().collect();
    for r in due {
        gather_due(tx, &mut ds, &r, me);
    }
    // a decide reads its roles as rows: brought up to date before asking what moved
    refresh_roles(tx.core);
    let out = decide_due(tx, &mut ds);
    tx.core.addenda_owed = ds;
    out
}

/// Gathers removal `r` again (`gather`), keeping the gathering where it changed and following
/// its decide; one that never owes (not held, no frontier) is followed no more.
fn gather_due(tx: &mut Tx<'_>, ds: &mut Decides, r: &CommitId, me: Tid) {
    tx.core.ix.addenda_due.remove(r);
    let Some(g) = gather(tx.core, r, me, true) else {
        if tx.core.ix.addenda_gathered.contains_key(r) {
            tx.core.ix.addenda_gathered.remove(r);
        }
        ds.unwant(tx.core, r);
        return;
    };
    if tx.core.ix.addenda_gathered.get(r).is_none_or(|k| **k != g) {
        tx.core.ix.addenda_gathered.insert(*r, Arc::new(g));
    }
    // filed under the edges that may bring it a candidate later (a commit of one received in
    // time applying late, a late grant bringing one into question)
    file_wake(tx.core, r);
    ds.fx.want(*r);
}

/// Decides every followed removal whose reads moved and writes what it owes, until none moved
/// but those that failed: an addendum written moves its removal's decide (its own counting
/// addendum), which then owes nothing there.
fn decide_due(tx: &mut Tx<'_>, ds: &mut Decides) -> Result<()> {
    let (mut wrote, mut failed) = (BTreeSet::new(), BTreeSet::new());
    loop {
        let due: Vec<CommitId> = ds.fx.due().into_iter().filter(|r| !failed.contains(r)).collect();
        if due.is_empty() {
            break;
        }
        for r in due {
            osis_base::costs::count("addenda: removals judged", 1);
            let mut owes = None;
            let settled = ds.fx.try_settle(&r, || {
                let (v, read) = decide(tx, &r)?;
                owes = Some((v.clone(), read));
                Ok::<_, crate::Error>(v)
            });
            if let Err(e) = settled {
                report(tx, r, &e);
                failed.insert(r);
                continue;
            }
            let Some((owes, read)) = owes else { continue };
            ds.note_read(tx.core, &r, read);
            if owes.is_empty() {
                // a removal no longer held owes nothing again
                if !tx.core.ix.commits.contains_key(&r) {
                    ds.unwant(tx.core, &r);
                    if tx.core.ix.addenda_gathered.contains_key(&r) {
                        tx.core.ix.addenda_gathered.remove(&r);
                    }
                }
                continue;
            }
            debug_assert!(!wrote.contains(&r), "an addendum written here does not count here: {r:?} on {:?}", owes.keys().collect::<Vec<_>>());
            if !wrote.insert(r) {
                failed.insert(r);
                continue;
            }
            let written = tx.step(Step::Addenda, |tx| {
                for (n, lists) in owes.iter() {
                    write_entry(tx, *n, &r, lists.clone())?;
                }
                Ok(())
            });
            if let Err(e) = written {
                report(tx, r, &e);
                failed.insert(r);
            }
        }
    }
    // decided again at the next call
    for r in failed {
        ds.fx.unwant(&r);
        ds.fx.want(r);
    }
    Ok(())
}

/// Reports a judgement or write of removal `r`'s addenda failing.
fn report(tx: &mut Tx<'_>, r: CommitId, e: &crate::Error) {
    tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::OwnWriteFailed, tids: Vec::new(), commit: Some(r), peer: None, detail: e.to_string() }, tx.core.hlc.mono());
}

/// What removal `r` owes at this node and may write now (`Owes`; `Core::addenda_owed` follows
/// it), with the things whose role row it read: what its kept gathering leaves unvouched (`unvouched`), on the things in
/// the node closure this node may write `addenda.0` on now (`may_write`'s checks, the role read
/// as a row only where a candidate is unvouched). Every read is stamped, so it is decided again
/// exactly where one moves: this node's role on a thing with an unvouched candidate, its own
/// counting addenda (`Indexes::addenda_keyed` by R, their validity), the candidates still held,
/// a thing entering the node closure, its minting or keys arriving.
fn decide(tx: &mut Tx<'_>, r: &CommitId) -> Result<(Owes, BTreeSet<Tid>)> {
    let (mut out, mut read) = (BTreeMap::new(), BTreeSet::new());
    let me = tx.core.me();
    if !tx.core.ix.commits.contains_key(r) {
        return Ok((Arc::new(out), read));
    }
    let Some(g) = tx.core.ix.addenda_gathered.get(r).cloned() else { return Ok((Arc::new(out), read)) };
    for (n, (lists, needs)) in unvouched(tx.core, r, &g, me) {
        read.insert(n);
        if !may_vouch(own_role(tx.core, n), &needs) {
            continue;
        }
        let depth = tx.core.skip_writer_rules || within_depth(tx.core, &|_| None, &n);
        if tx.core.ix.closure.holds(&n) && depth && may_write_on(tx, &n)? == MayWrite::Yes {
            out.insert(n, lists);
        }
    }
    Ok((Arc::new(out), read))
}

/// This node's role on `n` now, as its row (`Core::own_roles`).
fn own_role(core: &mut Core, n: Tid) -> Option<Role> {
    match osis_base::memo::Cutoff::get_in(core, |c| &c.own_roles, &n, own_role_now) {
        Ok(r) => r,
        Err(e) => match e {},
    }
}

/// `Core::own_roles`' derivation.
fn own_role_now(core: &mut Core, n: &Tid) -> std::result::Result<Option<Role>, std::convert::Infallible> {
    Ok(core.role_now(&core.me(), n))
}

/// Brings `Core::own_roles` up to date.
fn refresh_roles(core: &mut Core) {
    let Ok(_) = osis_base::memo::Cutoff::refresh_in(core, |c| &c.own_roles, own_role_now);
}

/// Tests: whether removal `r`'s addenda are still to judge (gathered or decided).
#[cfg(test)]
pub(crate) fn owing(core: &Core, r: &CommitId) -> bool {
    core.ix.addenda_due.contains(r) || core.addenda_owed.fx.wants(r) && core.addenda_owed.fx.current(r).is_none()
}

/// Tests: the own-role rows held (`Core::own_roles`).
#[cfg(test)]
pub(crate) fn rows_held(core: &Core) -> usize {
    core.own_roles.rows_held()
}

/// Debug builds, after every durable transaction and at an engine's drop: no read of a judgement
/// went unseen. Of every held removal not due to gather, a kept gathering is what a fresh one
/// gathers, and a fresh judgement (roles read whole, `may_write` in full) owes nothing this node
/// may write now unless its decide is due: a stale gathering is a missed wake, an answer owed with
/// its decide settled a read the decide made unstamped. `Some`: what differs.
#[cfg(debug_assertions)]
pub(crate) fn missed(tx: &mut Tx<'_>) -> Result<Option<String>> {
    if !tx.core.addenda_on {
        return Ok(None);
    }
    let me = tx.core.me();
    // the decides read the rows as last refreshed: refreshed as the next judgement does
    refresh_roles(tx.core);
    let rs: Vec<CommitId> = tx.core.ix.commits.iter().filter(|(id, m)| m.view.kind.is_role() && m.view.frontier.is_some() && !tx.core.ix.addenda_due.contains(id)).map(|(id, _)| *id).collect();
    for r in rs {
        let fresh = gather(tx.core, &r, me, false);
        if let Some(kept) = tx.core.ix.addenda_gathered.get(&r)
            && fresh.as_ref() != Some(&**kept)
        {
            return Ok(Some(format!("removal {r:?}: kept gathering {kept:?}, fresh {fresh:?}")));
        }
        let Some(g) = fresh else { continue };
        let owes: BTreeMap<Tid, BTreeSet<CommitId>> = unvouched(tx.core, &r, &g, me).into_iter().filter(|(n, (_, needs))| may_vouch(tx.core.role_now(&me, n), needs)).map(|(n, (lists, _))| (n, lists)).collect();
        let a = writable_split(tx, me, owes, ct::ADDENDA_AK, Some(Role::Write))?;
        let due = tx.core.addenda_owed.fx.wants(&r) && tx.core.addenda_owed.fx.current(&r).is_none();
        if !a.now.is_empty() && !due {
            return Ok(Some(format!("removal {r:?}, its decide settled, owes addenda on {:?}", a.now.keys().collect::<Vec<_>>())));
        }
    }
    Ok(None)
}

/// Writes one `addenda.0` entry on `n` keyed by removal `r` listing `lists`: a new entry of this
/// delta's own (`put_new`, spec/data-model.md §9), whatever this node holds at the key (another's
/// addendum to `r`).
fn write_entry(tx: &mut Tx<'_>, n: Tid, r: &CommitId, lists: BTreeSet<CommitId>) -> Result<()> {
    let mut mu = crate::Mutation::new();
    mu.op(n, &ct::ADDENDA, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(ct::Frontier { commits: lists }.to_value()) })?;
    Engine::commit_tx(tx, mu)?;
    Ok(())
}

/// What a judgement of removal `r` at this node (account `me`) gathers (`Gathered`); `None`: it
/// never owes (not held, not a role commit with a frontier). `count`: counts the commits scanned.
/// The candidates (spec/permissions.md §5.2 Addenda, Writing): for each explicit demotion R makes
/// in this node's view of a node X other than this one below write on a thing N, X's plain
/// content commits on N or acting for N (no role-class or admin-only part), and for each below
/// admin, X's commits with admin-only content on N that is not role-class, ordered before R,
/// received in R's window and not listed by its frontier, no snapshot or purge request, each with
/// the role it needs.
fn gather(core: &Core, r: &CommitId, me: Tid, count: bool) -> Option<Gathered> {
    let mut out = Gathered::default();
    let m = core.ix.commits.get(r)?;
    let frontier = m.view.frontier.clone()?;
    let rc = core.ix.held.edge_commit(r)?;
    let tl = core.timelines().get(&rc.ops.first()?.target)?;
    // R not applying (dropped, or its author's authority in dispute) owes nothing; it may come
    // to apply, and then its change enters the walk's history: judged again then
    // (`note_changed`)
    out.applies = (0..rc.ops.len()).filter_map(|k| u32::try_from(k).ok()).any(|k| tl.is_applied(&osis_perm::WriteId(*r, k)));
    if !out.applies {
        return Some(out);
    }
    // each cut R makes (spec/permissions.md §5.2 Writing): an applied write taking its hop
    // below write, or below admin
    let paths = core.timelines().paths();
    for (k, op) in (0u32..).zip(&rc.ops) {
        let Some(a) = tl.applied(&osis_perm::WriteId(*r, k)) else { continue };
        // below write it cuts plain content, below admin admin-only content (a removal both)
        let cuts: Vec<Role> = [Role::Write, Role::Admin].into_iter().filter(|r| a.cuts(*r)).collect();
        if cuts.is_empty() {
            continue;
        }
        let hop = (op.holder, op.target);
        // the content commits with a delta stated along a path with that hop
        for c in paths.through(&hop.0, &hop.1) {
            if count {
                osis_base::costs::count("addenda: commits scanned", 1);
            }
            let Some(cm) = core.ix.commits.get(&c) else { continue };
            let v = &cm.view;
            // not made by itself; ordered before R (at its `ts` or earlier, §5.2 Position); what
            // the frontier lists needs no addendum
            if v.signer == me || v.purges || v.kind != osis_commit::Kind::Content || frontier.covers(&c) || v.ts > m.view.ts || !window(cm.received, m.view.ts, m.received) {
                continue;
            }
            for (ai, x) in (0u32..).zip(&v.aspects) {
                let below = if plain_ak(&x.ak) {
                    Role::Write
                } else if admin_listable_ak(&x.ak) {
                    Role::Admin
                } else {
                    continue;
                };
                if cuts.contains(&below) && paths.rests(&osis_perm::WriteId(c, ai)).is_some_and(|(hops, _)| hops.contains(&hop)) {
                    out.addenda.entry(x.tid).or_default().entry(c).or_default().insert(below);
                }
            }
        }
    }
    Some(out)
}

/// What removal `r`, gathered as `g`, may owe at this node (account `me`), per thing: where one
/// of its candidates still held is one no counting addendum of this node's vouches for, every
/// candidate still held (the addendum's list) and the roles those unvouched need. It is owed
/// where this node holds one of those roles now (`may_vouch`: an addendum written now vouches as
/// a holder of the role a part needs). Reads, beside `g`, its own addenda keyed by R and their
/// validity (the epoch rule's counting among it) and the commits still held.
///
/// Who writes each input: R and the candidates are their signers' word, judged by the walk and
/// layer 2; every addendum on N (any writer's, a removed party's forged ones included) is judged
/// by the walk's least fixpoint, and only this node's own valid ones stop it owing.
fn unvouched(core: &Core, r: &CommitId, g: &Gathered, me: Tid) -> BTreeMap<Tid, (BTreeSet<CommitId>, BTreeSet<Role>)> {
    let mut out = BTreeMap::new();
    if !g.applies {
        return out;
    }
    // an addendum is positioned after R: applying R moved the clock past its `ts` (`Hlc::observe`)
    debug_assert!(core.ix.commits.get(r).is_none_or(|m| core.hlc.peek() > m.view.ts), "the clock is past an applied removal's ts");
    for (n, cs) in &g.addenda {
        let held: Vec<(&CommitId, &BTreeSet<Role>)> = cs.iter().filter(|(c, _)| core.ix.commits.contains_key(c)).collect();
        // a valid addendum of this node's on N against R listing the commit, read by R
        // (`Indexes::addenda_keyed`), so another removal's addenda move nothing here
        let mine_on_n: Vec<CommitId> = core.ix.addenda_keyed.get(r).into_iter().flatten().filter(|(t, ac)| t == n && core.ix.commits.get(ac).is_some_and(|am| am.view.signer == me && am.view.aspect(n, ct::ADDENDA_AK).is_some_and(|ai| am.valid_at(ai)))).map(|(_, ac)| *ac).collect();
        let vouched = |c: &CommitId| mine_on_n.iter().any(|ac| core.ix.addenda.get(&(*n, *ac)).is_some_and(|x| x.entries.iter().any(|(removal, list)| removal == r && list.contains(c))));
        let needs: BTreeSet<Role> = held.iter().filter(|(c, _)| !vouched(c)).flat_map(|(_, qs)| qs.iter().copied()).collect();
        if !needs.is_empty() {
            out.insert(*n, (held.into_iter().map(|(c, _)| *c).collect(), needs));
        }
    }
    out
}

/// Whether an addendum by a holder of `mine` vouches for a candidate needing one of `needs`
/// (`unvouched`): it holds write, and one of them.
fn may_vouch(mine: Option<Role>, needs: &BTreeSet<Role>) -> bool {
    mine >= Some(Role::Write) && needs.iter().any(|q| mine >= Some(*q))
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
