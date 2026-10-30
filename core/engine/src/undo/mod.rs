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
use osis_crdt::{AnyView, CounterRange, Fragment, Op, PathOp, PathSeg, Source, Stamp, UndoBuffer, Undone, View, Writer};
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

/// Records the state of `(tid, ak)` before local commit `id` applies: the part undoing `delta`
/// reads (`Fragment::footprint`), or all of it without one.
pub(crate) fn remember(tx: &mut Tx<'_>, id: &CommitId, tid: &Tid, ak: &Ak, delta: Option<&Fragment>) -> Result<()> {
    // a paged state loads what the delta touches (its footprint lies there)
    match delta {
        Some(d) => {
            tx.load_lazy(tid, ak)?;
            let touch = crate::engine::pages::touch_of(d, tx.core.pages.get(&(*tid, ak.clone())));
            tx.ensure_touch(tid, ak, &touch)?;
        }
        None => tx.load(tid, ak)?,
    }
    let pre = match (tx.core.states.get(&(*tid, ak.clone())).and_then(Option::as_ref), delta) {
        (Some(f), Some(d)) => crate::engine::state::encode(&f.footprint(d))?,
        (Some(f), None) => crate::engine::state::encode(f)?,
        (None, _) => Vec::new(),
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
struct Before {
    state: Fragment,
    complete: bool,
}

impl UndoBuffer for Before {
    fn before(&self, path: &[PathSeg]) -> Option<Fragment> {
        self.state.before(path)
    }
    fn complete(&self) -> bool {
        self.complete
    }
}

fn undo_delta<V: View>(w: &mut Writer, undone: &Undone, state: &Fragment, buf: &dyn UndoBuffer, view: &V) -> Result<Option<Fragment>> {
    Ok(osis_crdt::undo(w, undone, state, buf, view)?)
}

/// Builds and applies the undo commit of `target` (spec/crdt.md §4.6); of the things it
/// created, `keep` (drafts it saved) are not deleted.
pub(crate) fn undo_in(tx: &mut Tx<'_>, target: CommitId, actor: Tid, ts: Option<Ts>, keep: &BTreeSet<Tid>) -> Result<CommitId> {
    let m = tx.core.ix.commits.get(&target).cloned().ok_or(Error::UnknownCommit(target))?;
    let h = m.header.clone();
    if !matches!(h.kind, Kind::Content) {
        return Err(Error::Misuse("only content commits are undone here"));
    }
    let node = tx.core.id.tid();
    let ts = ts.unwrap_or_else(|| tx.core.hlc.next());
    let mut deltas = Vec::new();
    let made: BTreeSet<Tid> = made_by(&h, &m.valid).difference(keep).copied().collect();
    for (ai, a) in h.aspects.iter().enumerate() {
        // a commit whose body was dropped cannot be undone (spec/commits.md §7); a thing it
        // created is deleted below instead
        if m.dropped.contains_key(&ai) || !m.valid.get(ai).copied().unwrap_or(false) || a.ak.as_str() == "/created" || made.contains(&a.tid) {
            continue;
        }
        let parts = crate::apply::held_parts(tx, &target, ai)?;
        let Some(Decoded::Delta(d)) = parts.into_iter().next() else { continue };
        let source = match h.form {
            Form::Node => Source::node(h.author),
            Form::Commit => Source::commit(target),
        };
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
                        complete &= !matches!(m.header.kind, Kind::ContentSnapshot | Kind::MembershipSnapshot | Kind::RosterSnapshot | Kind::Import);
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
        let lo = tx.txn.counter(&a.tid, &a.ak)?;
        // read in place: the undo reads the current state along the delta's paths only
        let empty = Fragment::default();
        let state = tx.core.states.get(&(a.tid, a.ak.clone())).and_then(Option::as_ref).unwrap_or(&empty);
        let mut w = Writer::new(ts, Source::node(node), lo);
        let schema = a.schema.and_then(|i| h.schemas.get(i)).and_then(|(id, _)| tx.core.schemas.get(id).cloned()).or_else(|| a.ak.is_core().then(|| std::sync::Arc::new(osis_schema::core_schema().clone())));
        let view = schema.as_ref().and_then(|s| s.view(a.ak.as_str()));
        let buf: &dyn UndoBuffer = &pre;
        // a write of an undo commit in effect, with every later change of the aspect undone:
        // undo steps back through it (spec/crdt.md §4.6); judged on first use
        let core = &*tx.core;
        let judge: OnceCell<(BTreeMap<CommitId, Vec<CommitId>>, bool)> = OnceCell::new();
        let restored = |s: &Stamp| {
            let (undoers, clear) = judge.get_or_init(|| chain_judge(core, &a.tid, &a.ak, (h.ts, target)));
            *clear && core.commit_of(&a.tid, &a.ak, &s.dot).and_then(|c| core.ix.commits.get(&c).map(|m| (c, m))).is_some_and(|(c, m)| m.header.undoes.is_some() && in_effect(&c, undoers))
        };
        let undone = Undone { delta: &d.fragment, source: &source, range: CounterRange { lo: a.lo, hi: a.hi }, restored: &restored };
        let out = match &view {
            Some(v) => undo_delta(&mut w, &undone, state, buf, v)?,
            None => undo_delta(&mut w, &undone, state, buf, &AnyView)?,
        };
        if let Some(f) = out {
            let r = w.range();
            deltas.push(Resolved { tid: a.tid, ak: a.ak.clone(), fragment: f, lo: r.lo, hi: r.hi, schema, schema_ref: None, retention: None, expires: None, frontiers: None, chunks: Vec::new(), split: false });
        }
    }
    unmake(tx, &made, ts, node, &mut deltas)?;
    if deltas.is_empty() {
        return Err(Error::Misuse("nothing to undo"));
    }
    for d in &deltas {
        crate::engine::write::check_authority(tx.core, tx.core.id.tid(), &Default::default(), &d.tid, d.ak.as_str(), ts)?;
    }
    let plan = CommitPlan { kind: Kind::Content, ts, actor, form: Form::Node, creates: Default::default(), purge: Vec::new(), undoes: Some(target), frontier: None, origins: Vec::new(), signer: tx.core.id.tid(), blind: crate::engine::write::draw_blind(&mut *tx.rng) };
    build_and_apply(tx, plan, deltas)
}

/// The things content commit `m` created: those whose `/created` it validly carries (a
/// thing's creation, or the save persisting an ephemeral one).
pub(crate) fn made_by(h: &osis_commit::Header, valid: &[bool]) -> BTreeSet<Tid> {
    if h.kind != Kind::Content {
        return BTreeSet::new();
    }
    h.aspects.iter().enumerate().filter(|(ai, a)| a.ak.as_str() == "/created" && valid.get(*ai).copied().unwrap_or(false)).map(|(_, a)| a.tid).collect()
}

/// Undoing a creation deletes the thing (spec/crdt.md §4.6): `delete`'s writes for each of
/// `made`, its held aspects reset (not `/created` or membership-class ones) and its entries
/// removed from every `/group` listing it that this node may write, each resolved after the
/// undo's own delta of that aspect and joined into it. `Permission` when this node may not
/// write one of `made` (`delete` would refuse; never a partial revert).
fn unmake(tx: &mut Tx<'_>, made: &BTreeSet<Tid>, ts: Ts, node: Tid, deltas: &mut Vec<Resolved>) -> Result<()> {
    if made.is_empty() {
        return Ok(());
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
        for ak in aks.into_iter().filter(|a| a.as_str() != "/created" && !osis_schema::core_types::is_membership_class(a.as_str())) {
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
    for ((tid, ak), ops) in ops {
        let at = deltas.iter().position(|d| d.tid == tid && d.ak == ak);
        let mut state = tx.state(&tid, &ak)?.cloned().unwrap_or_default();
        let lo = match at.and_then(|i| deltas.get(i)) {
            Some(d) => {
                state.join(d.fragment.clone());
                d.hi
            }
            None => tx.txn.counter(&tid, &ak)?,
        };
        let schema = ak.is_core().then(|| std::sync::Arc::new(osis_schema::core_schema().clone()));
        let view = schema.as_ref().and_then(|s| s.view(ak.as_str()));
        let w = Writer::new(ts, Source::node(node), lo);
        let out = match &view {
            Some(v) => crate::engine::write::run_ops(&state, w, &ops, v)?,
            None => crate::engine::write::run_ops(&state, w, &ops, &AnyView)?,
        };
        let Some((f, r)) = out else { continue };
        match at.and_then(|i| deltas.get_mut(i)) {
            Some(d) => {
                d.fragment.join(f);
                d.hi = r.hi;
            }
            None => deltas.push(Resolved { tid, ak, fragment: f, lo: r.lo, hi: r.hi, schema, schema_ref: None, retention: None, expires: None, frontiers: None, chunks: Vec::new(), split: false }),
        }
    }
    Ok(())
}

/// From the commits holding writes of `(tid, ak)`: who undoes whom, and whether every change
/// (a commit that is not an undo) ordered after `after` is out of effect (spec/crdt.md §4.6).
fn chain_judge(core: &crate::engine::Core, tid: &Tid, ak: &Ak, after: (Ts, CommitId)) -> (BTreeMap<CommitId, Vec<CommitId>>, bool) {
    let held: Vec<(Ts, CommitId)> = core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().copied().collect();
    let mut undoers: BTreeMap<CommitId, Vec<CommitId>> = BTreeMap::new();
    for (_, id) in &held {
        if let Some(t) = core.ix.commits.get(id).and_then(|m| m.header.undoes) {
            undoers.entry(t).or_default().push(*id);
        }
    }
    let clear = held.iter().filter(|x| **x > after).all(|(_, id)| core.ix.commits.get(id).is_some_and(|m| m.header.undoes.is_some()) || !in_effect(id, &undoers));
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
        match self.run(|tx| undo_in(tx, t, me, None, &BTreeSet::new())) {
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
                    .filter(|(ai, a)| m.valid.get(*ai).copied().unwrap_or(false) && keep.as_ref().is_none_or(|k| k.contains(&(a.tid, a.ak.clone()))))
                    .map(|(ai, a)| (a.tid, a.ak.clone(), !m.dropped.contains_key(&ai) && !m.missing.contains(&ai)))
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
