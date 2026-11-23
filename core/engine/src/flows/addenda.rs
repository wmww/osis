//! Addenda (spec/permissions.md §5.2 Addenda, Writing): a witness's writes to a removal for the
//! content of a demoted node it received and the remover had not, written unasked by one state
//! rule. For each explicit demotion R makes below write (below admin, for admin-only content) in
//! this node's view (R's own node included), the content commits of the demoted node in R's
//! window (`window`: received by R's `ts` and before R), not listed by its frontier, on each thing
//! N it is demoted on, are its candidates (`gather`); while one of them is one an
//! addendum this node wrote now would vouch for and no counting addendum of its own vouches for
//! it, it owes one addendum on N keyed by R listing every candidate (`owed`), written once
//! N is in its node closure (`note_entered`).
//!
//! Invariant: what is owed is a function of the held set, the receipts and the trust set (the
//! walk, the counting addenda, the clock), never of what this node wrote before, so an open
//! re-derives it (`all_due`) and nothing about it is durable. A judgement gathers (`gather`:
//! whether R applies, its candidates) and then decides (`owed`: this node's roles, its own
//! counting addenda); the gathering is kept (`Gathered`) and a removal is due again only when
//! something it reads moves: R's own change in the walk (`note_changed`: the only input of one
//! not applying), a commit ordered no later than
//! it applying or changing its standing and reaching a party R names or R's author (`wake`,
//! filed per such party, `Indexes::addenda_wake`), this node's roles moving on a thing it is
//! filed under (`note_roles_moved`: decided again, the gathering kept), a thing it is filed under
//! entering the node closure (`note_entered`: likewise). Another party's role change, or a
//! removed party's commits that change no walk, judge nothing. The window closes at R's own
//! arrival, so its candidates' receipts are final once R is held. So a removal owing nothing
//! costs nothing per step, and a node ingesting a history it received after it (a joiner)
//! judges each removal once.
//!
//! Who writes each input: R, the candidates and every addendum are their signers' word (a
//! removed party may sign any number, at any key and `ts`; any writer writes `addenda.0`); the
//! walk and layer 2 judge them all. An addendum is content: it moves no component, so a flood of
//! them makes no removal due. This node writes only what it received and could vouch for itself,
//! so a forged addendum or a flood of a removed party's commits makes it write nothing it would
//! not write from the honest ones: a removed party's commits after R are not candidates (ordered
//! after R, or received after its `ts` or after R: a remover's clock running ahead lengthens
//! nothing).

use crate::engine::write::writable_split;
use crate::engine::{Core, Engine, Step, Tx};
use crate::error::Result;
use crate::events::{Diagnostic, DiagnosticKind};
use osis_base::{CommitId, Role, Tid, Ts, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_schema::Codec;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Notes removal `r` (a role commit with a frontier, applied here) as due, gathered anew (its
/// late parts may change what it names).
pub(crate) fn note_due(core: &mut Core, r: &CommitId) {
    core.ix.addenda_due.insert(*r);
    core.ix.addenda_gathered.remove(r);
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

/// Roles moved for the parties `moved` (`Held::upstream` of a changed edge's holder or a new
/// record) on the things `under` (`Held::reach` of its target or that record): where this node
/// is one of them, the removals filed under a thing of `under` are due again, their gathering
/// kept: what this node may write (the role an addendum needs) and which of its own addenda
/// count read its roles, and nothing else they read moved. Another party's role moving judges
/// nothing.
pub(crate) fn note_roles_moved(core: &mut Core, moved: &BTreeSet<Tid>, under: &BTreeSet<Tid>) {
    if core.ix.addenda_watch.is_empty() || !(core.member().is_some_and(|m| moved.contains(&m)) || moved.contains(&core.id.tid())) {
        return;
    }
    for t in under {
        let rs: Vec<CommitId> = core.ix.addenda_watch.get(t).into_iter().flatten().copied().collect();
        for r in rs {
            core.ix.addenda_due.insert(r);
        }
    }
}

/// The things `came` may have entered the node closure (`apply::wake_entered`, from the closure's
/// own log of its members: every entry passes through it): where one now holds it, the removals
/// filed under it (`Indexes::addenda_watch`: every thing a candidate is on, held or not) are due
/// again, their gathering kept. An addendum owed on a thing outside the node closure
/// waits for it (spec/sync-set.md §2 Writing); nothing else it reads moved. Leaving the closure
/// owes nothing new.
pub(crate) fn note_entered(core: &mut Core, came: &BTreeSet<Tid>) {
    if core.ix.addenda_watch.is_empty() {
        return;
    }
    for t in came.iter().filter(|t| core.ix.closure.holds(t)) {
        let rs: Vec<CommitId> = core.ix.addenda_watch.get(t).into_iter().flatten().copied().collect();
        osis_base::costs::count("addenda: removals woken on entry", u64::try_from(rs.len()).unwrap_or(u64::MAX));
        for r in rs {
            core.ix.addenda_due.insert(r);
        }
    }
}

/// Commit `id` (header `h`) applied here (whole or by late parts): it may be a candidate of a
/// removal received in time that applied only now (pending meanwhile), or a grant bringing a
/// party under one's demotion (`wake`).
pub(crate) fn note_applied(core: &mut Core, id: &CommitId, h: &osis_commit::Header) {
    wake(core, id, h.signer, h.ts);
}

/// Commit `id` by `signer` stamped `ts` applied or changed its standing in the walk: the
/// removals stamped no earlier, filed under a party it reaches (`Indexes::addenda_wake`), are due
/// again, gathered anew. A party comes to be demoted at R or not, or a commit of one becomes a
/// candidate, only by a commit ordered no later than R moving a path of a party
/// that reaches a holder R names or R's author (`Held::reach` climbs to what a party holds): a
/// commit of its own, or an edge write whose holder it is or stands behind (`Held::upstream`):
/// a member joining a holder R names, a named holder's or a member's other path to what R lowers
/// taken away, the remover's authority lowered. So the climb is from the signer, the edge writes'
/// targets and everything upstream of their holders. Live traffic (stamped after every filed
/// removal) costs a comparison, and a backdated or late commit that climb; one with no edge
/// write wakes only the removals it arrived before (`window`), so a removed party's backdated
/// content judges nothing.
///
/// Invariant: every input a kept gathering reads besides R's own change in the walk
/// (`note_changed`) moves only by such a
/// commit: who is demoted at R and whether R applies are read from the walk before R; the
/// candidates are commits held before R's arrival.
fn wake(core: &mut Core, id: &CommitId, signer: Tid, ts: Ts) {
    let Some(&(newest, _)) = core.ix.addenda_wake_ts.last() else { return };
    if ts > newest {
        return;
    }
    osis_base::costs::count("addenda: wake climbs", 1);
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
    osis_base::costs::count("addenda: wake parties", u64::try_from(parties.len()).unwrap_or(u64::MAX));
    for t in parties {
        let lo = (t, ts, CommitId([0; 32]));
        let hi = (t, Ts::MAX, CommitId([0xff; 32]));
        let due: Vec<CommitId> = core.ix.addenda_wake.range(lo..=hi).map(|(_, _, r)| *r).filter(|r| edges || got.is_none_or(|g| core.ix.commits.get(r).is_none_or(|rm| g < rm.received))).collect();
        for r in due {
            osis_base::costs::count("addenda: removals woken", 1);
            note_due(core, &r);
        }
    }
}

/// Files removal `r` (its edge commit `rc`) under the parties a commit ordered before it must
/// reach to change what it reads (`wake`): the holders its edge writes name and its author. One
/// entry each, however many parties stand behind a holder (a holder's members reach it).
fn file_wake(core: &mut Core, r: &CommitId) {
    let Some(rc) = core.ix.held.edge_commit(r) else { return };
    let ts = rc.ts;
    let parties: BTreeSet<Tid> = rc.ops.iter().map(|o| o.holder).chain(std::iter::once(rc.signer)).collect();
    for t in parties {
        if core.ix.addenda_wake.insert((t, ts, *r)) {
            osis_base::costs::count("addenda: wake entries", 1);
        }
    }
    core.ix.addenda_wake_ts.insert((ts, *r));
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
/// gathered anew only when one of those may have changed: R's own change in the walk
/// (`note_changed`), a commit ordered no later
/// than it applying (`note_applied`), its late parts (`note_due`), an open. Receipts are final
/// once R is held (its window closes at its arrival), and a commit arriving after R is in no
/// window, so nothing else adds a candidate. Debug builds check a kept gathering against a fresh
/// one at each judgement.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Gathered {
    /// R applies in this node's walk.
    applies: bool,
    /// Candidates per thing: each commit with the roles its listed parts need.
    addenda: BTreeMap<Tid, BTreeMap<CommitId, BTreeSet<Role>>>,
}

impl Gathered {
    /// The things a judgement of it is filed under (`Indexes::addenda_watch`): those of its
    /// candidates. Nothing for one not applying (only its own change in the walk makes it due,
    /// `note_changed`) or with nothing to gather (only a commit ordered before it applying can
    /// bring one, `note_applied`).
    fn watched(&self) -> BTreeSet<Tid> {
        if !self.applies {
            return BTreeSet::new();
        }
        self.addenda.keys().copied().collect()
    }
}

/// Writes every addendum owed for the due removals (`Indexes::addenda_due`), each removal once per
/// call, each in a step of its own (`Tx::step`): one that fails leaves nothing, is reported
/// (`DiagnosticKind::OwnWriteFailed`) and stays due. A removal owing an addendum on a thing this node
/// may write on only once its minting or keys arrive stays due, judged again at the end of each
/// transaction until written; one owed on a thing outside the node closure is filed under it and
/// judged again as it enters (`note_entered`).
pub(crate) fn write_owed(tx: &mut Tx<'_>) -> Result<()> {
    if !tx.core.addenda_on || tx.core.ix.addenda_due.is_empty() {
        return Ok(());
    }
    let Some(me) = tx.core.member() else { return Ok(()) };
    // an addendum is content: writing one moves no component, so makes no removal due here; the
    // content it makes valid may bring a thing into the node closure, and the transaction's end
    // runs this again for what that makes due (`note_entered`)
    let due: Vec<CommitId> = tx.core.ix.addenda_due.iter().copied().collect();
    for r in due {
        osis_base::costs::count("addenda: removals judged", 1);
        if let Err(e) = tx.step(Step::Addenda, |tx| write_for(tx, &r, me)) {
            tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::OwnWriteFailed, tids: Vec::new(), commit: Some(r), peer: None, detail: e.to_string() }, tx.core.hlc.mono());
        }
    }
    Ok(())
}

/// Writes the addenda removal `r` owes; takes it off the due set, filed under the
/// things its judgement reads this node's roles on (`Gathered::watched`), unless one it owes
/// waits.
fn write_for(tx: &mut Tx<'_>, r: &CommitId, me: Tid) -> Result<()> {
    let now = tx.core.hlc.peek();
    let g = match tx.core.ix.addenda_gathered.get(r) {
        Some(g) => {
            #[cfg(debug_assertions)]
            debug_assert!(gather(tx.core, r, me, false).as_ref() == Some(&**g), "a kept gathering of {r:?} is what a fresh one gathers");
            g.clone()
        }
        None => {
            let Some(g) = gather(tx.core, r, me, true) else {
                tx.core.ix.addenda_due.remove(r);
                return Ok(());
            };
            let g = Arc::new(g);
            tx.core.ix.addenda_gathered.insert(*r, g.clone());
            g
        }
    };
    let a = writable_split(tx, me, owed(tx.core, r, &g, me, now), ct::ADDENDA_AK, Some(Role::Write))?;
    for (n, lists) in &a.now {
        write_entry(tx, *n, r, lists.clone())?;
    }
    #[cfg(debug_assertions)]
    if !a.now.is_empty()
        && let Some(g) = gather(tx.core, r, me, false)
    {
        let again = owed(tx.core, r, &g, me, tx.core.hlc.peek());
        debug_assert!(a.now.keys().all(|n| !again.contains_key(n)), "an addendum written here does not count here: {r:?} on {:?}", again.keys().collect::<Vec<_>>());
    }
    // an addendum on a thing outside the node closure waits for it to enter (`note_entered`: it
    // is a candidate's thing, so filed under it below)
    if a.later {
        return Ok(());
    }
    tx.core.ix.addenda_due.remove(r);
    // filed under the parties that may bring it a candidate later (a commit of one received in
    // time applying late, a late grant bringing one into question), whatever it owes now
    file_wake(tx.core, r);
    // filed under the things whose roles for this node it reads; the gathering kept while filed
    let old = tx.core.ix.addenda_filed.remove(r);
    for t in old.iter().flat_map(|s| s.iter()) {
        tx.core.ix.addenda_watch.remove(t, r);
    }
    let watched = g.watched();
    if watched.is_empty() {
        tx.core.ix.addenda_gathered.remove(r);
        return Ok(());
    }
    for t in &watched {
        tx.core.ix.addenda_watch.insert(*t, *r);
    }
    tx.core.ix.addenda_filed.insert(*r, Arc::new(watched));
    Ok(())
}

/// Debug builds, after every durable transaction and at an engine's drop: no trigger was
/// missed. Of every held removal not due, a
/// kept gathering is what a fresh one gathers, and a fresh judgement owes nothing this node may
/// write now: a stale gathering or an answer owed with no judgement due is a missed trigger, which
/// the check at each judgement (`write_for`) cannot see. `Some`: what differs.
#[cfg(debug_assertions)]
pub(crate) fn missed(tx: &mut Tx<'_>) -> Result<Option<String>> {
    if !tx.core.addenda_on {
        return Ok(None);
    }
    let Some(me) = tx.core.member() else { return Ok(None) };
    let now = tx.core.hlc.peek();
    let rs: Vec<CommitId> = tx.core.ix.commits.iter().filter(|(id, m)| m.view.kind.is_role() && m.view.frontier.is_some() && !tx.core.ix.addenda_due.contains(id)).map(|(id, _)| *id).collect();
    for r in rs {
        let fresh = gather(tx.core, &r, me, false);
        if let Some(kept) = tx.core.ix.addenda_gathered.get(&r)
            && fresh.as_ref() != Some(&**kept)
        {
            return Ok(Some(format!("removal {r:?}: kept gathering {kept:?}, fresh {fresh:?}")));
        }
        let Some(g) = fresh else { continue };
        let a = writable_split(tx, me, owed(tx.core, &r, &g, me, now), ct::ADDENDA_AK, Some(Role::Write))?;
        if !a.now.is_empty() {
            return Ok(Some(format!("removal {r:?}, not due, owes addenda on {:?}", a.now.keys().collect::<Vec<_>>())));
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

/// What removal `r`, gathered as `g`, owes at this node (account `me`) at `now`, per thing: while
/// one of its candidates there is one an addendum this node wrote now would vouch for (it holds
/// the role it needs on N now) and no counting addendum of its own vouches for, one addendum on N
/// listing every candidate still held. Reads, beside `g`, only what may change while `g` holds:
/// this node's roles, its own counting addenda, the epoch rule's counting and the commits still
/// held (the node closure is read where the addenda are written, `writable_split`).
///
/// Who writes each input: R and the candidates are their signers' word, judged by the walk and
/// layer 2; every addendum on N (any writer's, a removed party's forged ones included) is judged
/// by the walk's least fixpoint, and only this node's own valid ones stop it owing.
fn owed(core: &Core, r: &CommitId, g: &Gathered, me: Tid, now: Ts) -> BTreeMap<Tid, BTreeSet<CommitId>> {
    let mut out = BTreeMap::new();
    if !g.applies {
        return out;
    }
    // an addendum is positioned after R: applying R moved the clock past its `ts` (`Hlc::observe`)
    debug_assert!(core.ix.commits.get(r).is_none_or(|m| now > m.view.ts), "the clock is past an applied removal's ts");
    for (n, cs) in &g.addenda {
        let Some(tn) = core.timelines().get(n) else { continue };
        // an addendum written now vouches as a holder of the role a part needs
        let mine = tn.role(&me, n, osis_perm::At::now(now));
        if mine < Some(Role::Write) {
            continue;
        }
        let held: Vec<(&CommitId, &BTreeSet<Role>)> = cs.iter().filter(|(c, _)| core.ix.commits.contains_key(c)).collect();
        // a valid addendum of this node's on N against R listing the commit
        let vouched = |c: &CommitId| {
            core.ix.addenda.range((*n, CommitId([0; 32]))..=(*n, CommitId([0xff; 32]))).any(|((_, ac), x)| {
                x.entries.iter().any(|(removal, list)| removal == r && list.contains(c))
                    && core.ix.commits.get(ac).is_some_and(|am| am.view.signer == me && am.view.aspect(n, ct::ADDENDA_AK).is_some_and(|ai| am.valid_at(ai)))
            })
        };
        if held.iter().any(|(c, qs)| qs.iter().any(|q| mine >= Some(*q)) && !vouched(c)) {
            out.insert(*n, held.into_iter().map(|(c, _)| *c).collect());
        }
    }
    out
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
