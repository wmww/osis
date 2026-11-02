//! Revert, an undo commit (spec/commits.md §7, spec/crdt.md §4.6): stacks, scopes and redo
//! live in the `osis` crate (`held_commits`); an undo commit's deltas come
//! from osis-crdt's `undo` against the current state and the undo buffer, which holds the
//! pre-commit state of this node's recent local commits (in the aspect's store unit, cleared
//! whenever a body of the aspect is dropped).

use crate::engine::records::{Rd, Wr};
use crate::engine::write::{CommitPlan, Resolved, build_and_apply};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_commit::{Decoded, Form, Kind};
use osis_base::{Ak, CommitId, Role, Tid, Ts, Value};
use osis_schema::AspectKey;
use osis_schema::core_types::GROUP;
use osis_crdt::{AnyView, CounterRange, Dot, Fragment, Op, PathOp, PathSeg, Stamp, UndoBuffer, Undone, Writer};
use osis_store::Shred;
use std::cell::OnceCell;
use std::collections::{BTreeMap, BTreeSet};

/// Local commits per aspect whose pre-commit state is kept.
pub const UNDO_DEPTH: usize = 16;

fn decode_buffer(b: &[u8]) -> Result<Vec<(CommitId, Vec<u8>)>> {
    let mut r = Rd::new(b);
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push((CommitId(r.arr()?), r.bytes()?.to_vec()));
    }
    Ok(out)
}

/// Joins into `acc` the part of the state of `(tid, ak)` that undoing `piece` of a delta reads
/// (`Fragment::footprint`; of a delta's pieces, their join is the delta's): a paged state loads
/// what the piece touches, then drops it again. `acc` stays `None` while there is no state.
pub(crate) fn footprint(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, piece: &Fragment, acc: &mut Option<Fragment>) -> Result<()> {
    tx.load_lazy(tid, ak)?;
    let touch = crate::engine::pages::touch_of(piece, tx.core.pages.get(&(*tid, ak.clone())));
    tx.ensure_touch(tid, ak, &touch)?;
    if let Some(f) = tx.cached(tid, ak) {
        let fp = f.footprint(piece);
        match acc {
            Some(a) => {
                a.join(fp);
            }
            None => *acc = Some(fp),
        }
    }
    tx.evict_pages(tid, ak);
    Ok(())
}

/// Records the state of `(tid, ak)` before local commit `id` applies: `pre`, the part undoing
/// its delta reads (`footprint`; `Some(None)`: there was no state), or all of it (`None`: not
/// one delta).
pub(crate) fn remember(tx: &mut Tx<'_>, id: &CommitId, tid: &Tid, ak: &Ak, pre: Option<Option<Fragment>>) -> Result<()> {
    let pre = match pre {
        Some(fp) => fp.as_ref().map(crate::engine::state::encode).transpose()?.unwrap_or_default(),
        None => {
            tx.load(tid, ak)?;
            tx.cached(tid, ak).map(crate::engine::state::encode).transpose()?.unwrap_or_default()
        }
    };
    let mut unit = tx.unit(tid, ak)?;
    let mut list = decode_buffer(&unit.undo)?;
    list.push((*id, pre));
    if list.len() > UNDO_DEPTH {
        list.remove(0);
    }
    let mut w = Wr::new();
    for (c, s) in &list {
        w = w.raw(&c.0).bytes(s);
    }
    unit.undo = w.take();
    tx.txn.put_aspect(tid, ak, &unit, Shred::No)?;
    Ok(())
}

/// The state before an undone commit and whether it is the whole of it (spec/crdt.md §4.6
/// "Absent before"): rebuilt from held bodies, it is not when one is gone.
pub(crate) struct Before {
    pub state: Fragment,
    pub complete: bool,
}

impl UndoBuffer for Before {
    fn before(&self, path: &[PathSeg]) -> Option<Fragment> {
        self.state.before(path)
    }
    fn complete(&self) -> bool {
        self.complete
    }
}

/// The undo delta of `undone` (spec/crdt.md §4.6) and its expiry. Invariant (§4.6, §4.7): an
/// undo never extends a value's lifetime past its original expiry. What it writes back from
/// `pre` (`Writer::copied`) takes the earliest expiry among the writes it copies (`expiry` of
/// an owner dot: `None` for none, or for a dot whose commit is not known; a header outlives its
/// body, so the commit of a write still held is known); content whose expiry is at
/// or before `wall` (the undo's `ts`) is stripped from `pre` and the undo run again, until it
/// copies no gone write not yet stripped, so none of it comes back.
#[allow(clippy::too_many_arguments)]
pub(crate) fn undo_expiring(mut w: Writer, undone: &Undone, state: &Fragment, mut pre: Before, schema: Option<&osis_schema::Schema>, ak: &Ak, wall: u64, expiry: &dyn Fn(&Dot) -> Option<u64>) -> Result<Option<(Fragment, CounterRange, Option<u64>)>> {
    let view = schema.and_then(|s| s.view(ak.as_str()));
    let start = w.clone();
    let run = |w: &mut Writer, pre: &Before| -> Result<Option<Fragment>> {
        Ok(match &view {
            Some(v) => osis_crdt::undo(w, undone, state, pre, v)?,
            None => osis_crdt::undo(w, undone, state, pre, &AnyView)?,
        })
    };
    let mut out = run(&mut w, &pre)?;
    // a rerun may copy other content in place of what was stripped (another entry at the key):
    // repeat while it copies a gone dot not yet stripped (a stripped one may still be copied:
    // `strip` takes values, `copy_from` notes every owner dot); `pre`'s dots are finite
    let mut gone: BTreeSet<Dot> = BTreeSet::new();
    loop {
        let before = gone.len();
        gone.extend(w.copied().iter().filter(|d| expiry(d).is_some_and(|t| t <= wall)).cloned());
        if gone.len() == before {
            break;
        }
        pre.state.strip(&|d| gone.contains(d));
        w = start.clone();
        out = run(&mut w, &pre)?;
    }
    let expires = w.copied().iter().filter_map(expiry).filter(|t| *t > wall).min();
    Ok(out.map(|f| (f, w.range(), expires)))
}

/// Builds and applies the undo commit of `target` (spec/crdt.md §4.6); of the things it
/// created, `keep` (drafts it saved) are not deleted. `confined`: every write it makes is held to
/// `actor`'s rights (`Engine::revert_as`).
pub(crate) fn undo_in(tx: &mut Tx<'_>, target: CommitId, actor: Tid, ts: Option<Ts>, keep: &BTreeSet<Tid>, confined: bool) -> Result<CommitId> {
    let m = tx.core.ix.commits.get(&target).cloned().ok_or(Error::UnknownCommit(target))?;
    let h = m.header.clone();
    if !matches!(h.kind, Kind::Content) {
        return Err(Error::Misuse("only content commits are undone here"));
    }
    let node = tx.core.id.tid();
    let ts = ts.unwrap_or_else(|| tx.core.hlc.next());
    let mut deltas = Vec::new();
    let made: BTreeSet<Tid> = made_by(&h, &m.valid).difference(keep).copied().collect();
    let mut unmade = unmake_ops(tx, &made, ts, node)?;
    // node form only on things whose counters this node is sure of (spec/crdt.md §2.1); in
    // commit form the counters run on across the commit's deltas
    let keys: Vec<(Tid, Ak)> = h.aspects.iter().map(|a| (a.tid, a.ak.clone())).chain(unmade.keys().cloned()).collect();
    let form = if crate::engine::write::node_form_ok(tx, &keys, &Default::default())? { Form::Node } else { Form::Commit };
    let mut next = 1u64;
    for (ai, a) in h.aspects.iter().enumerate() {
        // a commit whose body was dropped cannot be undone (spec/commits.md §7); a thing it
        // created is deleted below instead
        if m.dropped.contains_key(&ai) || !m.valid_at(ai) || a.ak.as_str() == "created.0" || a.ak.as_str() == osis_commit::retention::REQUIRED || made.contains(&a.tid) {
            continue;
        }
        let parts = crate::apply::held_parts(tx, &target, ai)?;
        let Some(Decoded::Delta(d)) = parts.into_iter().next() else { continue };
        let source = h.form.own_source(h.author, target);
        let buffer = decode_buffer(&tx.unit(&a.tid, &a.ak)?.undo)?.into_iter().find(|x| x.0 == target).map(|x| x.1);
        let pre = match buffer {
            Some(b) if !b.is_empty() => Before { state: crate::engine::state::decode(&b)?, complete: true },
            Some(_) => Before { state: Fragment::default(), complete: true },
            // not a recent local commit: the join of the held bodies ordered before it, whole
            // unless a body or part before it is gone or a later snapshot or import may stand
            // for bodies no longer listed
            None => {
                let held: Vec<(Ts, CommitId)> = tx.core.ix.by_aspect.get(&(a.tid, a.ak.clone())).into_iter().flatten().copied().collect();
                let mut f: Option<Fragment> = None;
                let mut complete = true;
                for (cts, c) in held {
                    let Some(m) = tx.core.ix.commits.get(&c) else { continue };
                    let Some(ci) = m.valid.iter().zip(&m.header.aspects).position(|(v, x)| *v && x.tid == a.tid && x.ak == a.ak) else { continue };
                    if (cts, c) > (h.ts, target) {
                        complete &= !matches!(m.header.kind, Kind::ContentSnapshot | Kind::RoleSnapshot | Kind::RosterSnapshot | Kind::Import);
                        continue;
                    }
                    if c == target {
                        continue;
                    }
                    complete &= !m.dropped.contains_key(&ci) && !m.missing.contains(&ci);
                    for d in crate::apply::held_parts(tx, &c, ci)? {
                        let d = d.into_fragment();
                        match &mut f {
                            Some(f) => {
                                f.join(d);
                            }
                            None => f = Some(d),
                        }
                    }
                }
                Before { state: f.unwrap_or_default(), complete }
            }
        };
        // the undo reads the current state along the delta's paths
        tx.load_lazy(&a.tid, &a.ak)?;
        let touch = crate::engine::pages::touch_of(&d.fragment, tx.core.pages.get(&(a.tid, a.ak.clone())));
        tx.ensure_touch(&a.tid, &a.ak, &touch)?;
        // a nested edit reads only its own entries (by dot: `osis_crdt::undo`), on the pages
        // holding the delta's dots; the pre-commit side comes from the buffer or held bodies
        let lo = match form {
            Form::Commit => next,
            _ => tx.txn.counter(&a.tid, &a.ak)?,
        };
        // read in place: the undo reads the current state along the delta's paths only
        let empty = Fragment::default();
        let state = tx.core.states.get(&(a.tid, a.ak.clone())).and_then(Option::as_ref).unwrap_or(&empty);
        let w = Writer::new(ts, form.own_source(node, CommitId([0; 32])), lo).keyed_removals(osis_schema::core_types::is_role_class(a.ak.as_str()));
        let schema = tx.core.schemas.get(a.ak.as_str()).cloned().or_else(|| osis_schema::core_types::is_core_key(a.ak.as_str()).then(|| std::sync::Arc::new(osis_schema::core_schema().clone())));
        // a write of an undo commit in effect, with every later change of the aspect undone:
        // undo steps back through it (spec/crdt.md §4.6); judged on first use
        let core = &*tx.core;
        let judge: OnceCell<(BTreeMap<CommitId, Vec<CommitId>>, bool)> = OnceCell::new();
        let restored = |s: &Stamp| {
            let (undoers, clear) = judge.get_or_init(|| chain_judge(core, &a.tid, &a.ak, (h.ts, target)));
            *clear && core.commit_of(&a.tid, &a.ak, &s.dot).and_then(|c| core.ix.commits.get(&c).map(|m| (c, m))).is_some_and(|(c, m)| m.view.undoes.is_some() && in_effect(&c, undoers))
        };
        let undone = Undone { delta: &d.fragment, source: &source, range: CounterRange { lo: a.lo, hi: a.hi }, restored: &restored };
        let expiry = |d: &Dot| core.write_expiry(&a.tid, &a.ak, d).flatten();
        if let Some((f, r, expires)) = undo_expiring(w, &undone, state, pre, schema.as_deref(), &a.ak, ts.wall_ms().0, &expiry)? {
            next = r.hi;
            deltas.push(Resolved { tid: a.tid, ak: a.ak.clone(), fragment: f, lo: r.lo, hi: r.hi, schema, retention: None, expires, frontiers: None, chunks: Vec::new(), split: false, records: Vec::new() });
            // joined into the delta just pushed, so its counters stay the last allocated
            if let Some(ops) = unmade.remove(&(a.tid, a.ak.clone())) {
                unmake_one(tx, (a.tid, a.ak.clone()), ops, ts, node, form, &mut next, &mut deltas)?;
            }
        }
    }
    for (k, ops) in unmade {
        unmake_one(tx, k, ops, ts, node, form, &mut next, &mut deltas)?;
    }
    if deltas.is_empty() {
        return Err(Error::Misuse("nothing to undo"));
    }
    for d in &deltas {
        crate::engine::write::check_authority(tx.core, tx.core.id.tid(), &Default::default(), &d.tid, d.ak.as_str(), ts)?;
    }
    crate::engine::write::check_acts(tx.core, tx.core.id.tid(), &|_| None, &actor, ts)?;
    if confined {
        crate::engine::acting::check_undo(tx, actor, &deltas, ts)?;
    }
    let plan = CommitPlan { kind: Kind::Content, ts, actor, form, creates: Default::default(), first: Default::default(), purge: Vec::new(), undoes: Some(target), frontier: None, origins: Vec::new(), signer: tx.core.id.tid(), blind: crate::engine::write::draw_blind(&mut *tx.rng) };
    build_and_apply(tx, plan, deltas)
}

/// The things content commit `m` created: those whose `created.0` it validly carries (a
/// thing's creation, or the save persisting an ephemeral one).
pub(crate) fn made_by(h: &osis_commit::Header, valid: &[bool]) -> BTreeSet<Tid> {
    if h.kind != Kind::Content {
        return BTreeSet::new();
    }
    h.aspects.iter().enumerate().filter(|(ai, a)| a.ak.as_str() == "created.0" && valid.get(*ai).copied().unwrap_or(false)).map(|(_, a)| a.tid).collect()
}

/// Undoing a creation deletes the thing (spec/crdt.md §4.6): `delete`'s writes for each of
/// `made`, its held aspects reset (not `created.0` or role-class ones) and its entries
/// removed from every `group.0` listing it that this node may write, each resolved after the
/// undo's own delta of that aspect and joined into it (`unmake_one`). `Permission` when this
/// node may not write one of `made` (`delete` would refuse; never a partial revert).
fn unmake_ops(tx: &mut Tx<'_>, made: &BTreeSet<Tid>, ts: Ts, node: Tid) -> Result<BTreeMap<(Tid, Ak), Vec<PathOp>>> {
    if made.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut ops: BTreeMap<(Tid, Ak), Vec<PathOp>> = BTreeMap::new();
    for x in made {
        if crate::engine::write::role_of(tx.core, &node, x, ts) < Some(Role::Write) {
            return Err(Error::Permission { tid: *x });
        }
        let prefix = [crate::engine::records::ASPECTS, x.as_bytes()].concat();
        let mut aks = Vec::new();
        tx.scan(&prefix, |k, _| {
            aks.push(Rd::new(k).ak()?);
            Ok(())
        })?;
        for ak in aks.into_iter().filter(|a| a.as_str() != "created.0" && !osis_schema::core_types::is_role_class(a.as_str())) {
            ops.entry((*x, ak)).or_default().push(PathOp { path: Vec::new(), op: Op::RemoveAspect });
        }
    }
    let gak = Ak::new(GROUP.ak()).map_err(|_| Error::Misuse("ak"))?;
    for (g, (items, subs)) in &tx.core.ix.groups.defs {
        if made.contains(g) || crate::engine::write::role_of(tx.core, &node, g, ts) < Some(Role::Write) {
            continue;
        }
        let rm = |field: u64, set: &BTreeSet<Tid>| set.intersection(made).map(|x| PathOp { path: vec![PathSeg::Field(field)], op: Op::Remove(Value::Tid(*x)) }).collect::<Vec<_>>();
        let v: Vec<PathOp> = [rm(crate::ephemeral::ITEMS, items), rm(crate::ephemeral::SUBGROUPS, subs)].concat();
        if !v.is_empty() {
            ops.entry((*g, gak.clone())).or_default().extend(v);
        }
    }
    Ok(ops)
}

/// Runs `unmake_ops`' ops on `k`, joined into the undo's delta of `k` when it is the last one
/// in `deltas` (its counters the last allocated: commit form runs on from `next`).
#[allow(clippy::too_many_arguments)]
fn unmake_one(tx: &mut Tx<'_>, (tid, ak): (Tid, Ak), ops: Vec<PathOp>, ts: Ts, node: Tid, form: Form, next: &mut u64, deltas: &mut Vec<Resolved>) -> Result<()> {
    let mut state = tx.state(&tid, &ak)?.cloned().unwrap_or_default();
    let joined = deltas.last().is_some_and(|d| d.tid == tid && d.ak == ak);
    // joined: one delta, so its commit-level writes keep that delta's stamp (spec/crdt.md §2.3)
    let (lo, resume) = match deltas.last() {
        Some(d) if joined => {
            state.join(d.fragment.clone());
            (d.lo, d.hi)
        }
        _ if form == Form::Commit => (*next, *next),
        _ => {
            let c = tx.txn.counter(&tid, &ak)?;
            (c, c)
        }
    };
    let schema = osis_schema::core_types::is_core_key(ak.as_str()).then(|| std::sync::Arc::new(osis_schema::core_schema().clone()));
    let view = schema.as_ref().and_then(|s| s.view(ak.as_str()));
    let w = Writer::new(ts, form.own_source(node, CommitId([0; 32])), lo).resume(resume).keyed_removals(osis_schema::core_types::is_role_class(ak.as_str()));
    let out = match &view {
        Some(v) => crate::engine::write::run_ops(&state, w, &ops, v)?,
        None => crate::engine::write::run_ops(&state, w, &ops, &AnyView)?,
    };
    let Some((f, r)) = out else { return Ok(()) };
    *next = r.hi;
    match deltas.last_mut() {
        Some(d) if joined => {
            d.fragment.join(f);
            d.hi = r.hi;
        }
        _ => deltas.push(Resolved { tid, ak, fragment: f, lo: r.lo, hi: r.hi, schema, retention: None, expires: None, frontiers: None, chunks: Vec::new(), split: false, records: Vec::new() }),
    }
    Ok(())
}

/// From the commits holding writes of `(tid, ak)`: who undoes whom, and whether every change
/// (a commit that is not an undo) ordered after `after` is out of effect (spec/crdt.md §4.6).
/// Being in effect is a property of the whole commit: its undoers are every held undo commit
/// naming it, wherever they write (`undone_by`), and theirs in turn.
fn chain_judge(core: &crate::engine::Core, tid: &Tid, ak: &Ak, after: (Ts, CommitId)) -> (BTreeMap<CommitId, Vec<CommitId>>, bool) {
    let held: Vec<(Ts, CommitId)> = core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().copied().collect();
    let mut undoers: BTreeMap<CommitId, Vec<CommitId>> = BTreeMap::new();
    let mut todo: Vec<CommitId> = held.iter().map(|x| x.1).collect();
    while let Some(c) = todo.pop() {
        if undoers.contains_key(&c) {
            continue;
        }
        let us: Vec<CommitId> = core.ix.undone_by.get(&c).into_iter().flatten().copied().collect();
        todo.extend(us.iter().copied());
        undoers.insert(c, us);
    }
    let clear = held.iter().filter(|x| **x > after).all(|(_, id)| core.ix.commits.get(id).is_some_and(|m| m.view.undoes.is_some()) || !in_effect(id, &undoers));
    (undoers, clear)
}

/// Whether commit `c` is in effect: no undo commit in effect undoes it. The undo relation is a
/// tree (an undo names an older commit by hash), walked without recursion.
pub(crate) fn in_effect<K: Ord + Copy>(c: &K, undoers: &BTreeMap<K, Vec<K>>) -> bool {
    let mut memo: BTreeMap<K, bool> = BTreeMap::new();
    let mut entered: BTreeSet<K> = BTreeSet::new();
    let mut stack = vec![(*c, false)];
    while let Some((x, done)) = stack.pop() {
        let us = undoers.get(&x).map(Vec::as_slice).unwrap_or_default();
        if done {
            let v = !us.iter().any(|u| memo.get(u).copied().unwrap_or(true));
            memo.insert(x, v);
        } else if entered.insert(x) {
            stack.push((x, true));
            stack.extend(us.iter().map(|u| (*u, false)));
        }
    }
    memo.get(c).copied().unwrap_or(true)
}

/// A held commit as the `osis` commit query reads it: its signed header and, per aspect it
/// validly touches, whether the body is still held.
#[derive(Clone, Debug)]
pub struct HeldCommit {
    pub id: CommitId,
    pub header: std::sync::Arc<osis_commit::Header>,
    pub received: osis_base::WallMs,
    /// `(tid, ak, body held)` of each valid aspect (in scope, when one is given).
    pub aspects: Vec<(Tid, Ak, bool)>,
}

impl Engine {
    /// Reverts `target` (any held content commit; spec/crdt.md §4.6: an undo commit). `None` if
    /// there is nothing to write.
    pub fn revert(&mut self, target: &CommitId) -> Result<Option<CommitId>> {
        let t = *target;
        let me = self.tid();
        match self.run(|tx| undo_in(tx, t, me, None, &BTreeSet::new(), false)) {
            Err(Error::Misuse("nothing to undo")) => Ok(None),
            r => r.map(Some),
        }
    }

    /// Held commits validly touching `scope` (every held commit with `None`: decodes every header),
    /// newest first by `(ts, ID)`. Commits valid on no aspect in scope are left out.
    pub fn held_commits(&self, scope: Option<&[(Tid, Ak)]>) -> Vec<HeldCommit> {
        let ids: BTreeSet<(Ts, CommitId)> = match scope {
            Some(sc) => sc.iter().flat_map(|k| self.core.ix.by_aspect.get(k).into_iter().flatten().copied()).collect(),
            None => self.core.ix.commits.iter().map(|(id, m)| (m.view.ts, *id)).collect(),
        };
        let keep: Option<BTreeSet<&(Tid, Ak)>> = scope.map(|sc| sc.iter().collect());
        ids.into_iter()
            .rev()
            .filter_map(|(_, id)| {
                let m = self.core.ix.commits.get(&id)?;
                let header = m.header.decoded()?;
                let aspects: Vec<(Tid, Ak, bool)> = header
                    .aspects
                    .iter()
                    .enumerate()
                    .filter(|(ai, a)| m.valid_at(*ai) && keep.as_ref().is_none_or(|k| k.contains(&(a.tid, a.ak.clone()))))
                    .map(|(ai, a)| (a.tid, a.ak.clone(), m.holds(ai)))
                    .collect();
                (!aspects.is_empty()).then_some(HeldCommit { id, header, received: m.received, aspects })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::in_effect;
    use osis_base::CommitId;
    use std::collections::BTreeMap;

    // spec/crdt.md §4.6: a commit is in effect while no undo in effect undoes it: an original
    // undone, then redone (the undo undone), then two undos of one commit with one undone.
    #[test]
    fn in_effect_chains_spec_crdt_4_6() {
        let (c, u, r, v, x) = (CommitId([1; 32]), CommitId([2; 32]), CommitId([3; 32]), CommitId([4; 32]), CommitId([5; 32]));
        let mut undoers = BTreeMap::from([(c, vec![u])]);
        assert!(!in_effect(&c, &undoers));
        assert!(in_effect(&u, &undoers));
        undoers.insert(u, vec![r]);
        assert!(in_effect(&c, &undoers));
        assert!(!in_effect(&u, &undoers));
        assert!(in_effect(&r, &undoers));
        // c undone by u (undone by r) and by v (in effect): c is out
        undoers.insert(c, vec![u, v]);
        assert!(!in_effect(&c, &undoers));
        undoers.insert(v, vec![x]);
        assert!(in_effect(&c, &undoers));
    }
}
