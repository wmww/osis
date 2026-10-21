//! Undo and redo (spec/commits.md §7, spec/crdt.md §4.6; notes/crdt.md hints): the stack is
//! derived from the actor's own commits in scope, never stored; an undo commit's deltas come
//! from osis-crdt's `undo` against the current state and the undo buffer, which holds the
//! pre-commit state of this node's recent local commits (in the aspect's store unit, cleared
//! whenever a body of the aspect is dropped). Redo is an undo of the undo commit.

use crate::engine::records::{Rd, Wr};
use crate::engine::write::{CommitPlan, Resolved, build_and_apply};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_commit::{Decoded, Form, Kind};
use osis_core::{Ak, CommitId, Tid, Ts};
use osis_crdt::{AnyView, CounterRange, Fragment, PathSeg, Source, Stamp, UndoBuffer, Undone, View, Writer};
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

struct NoBuffer;

impl UndoBuffer for NoBuffer {
    fn before(&self, _: &[PathSeg]) -> Option<Fragment> {
        None
    }
}

fn undo_delta<V: View>(w: &mut Writer, undone: &Undone, state: &Fragment, buf: &dyn UndoBuffer, view: &V) -> Result<Option<Fragment>> {
    Ok(osis_crdt::undo(w, undone, state, buf, view)?)
}

/// Builds and applies the undo commit of `target` (spec/crdt.md §4.6).
pub(crate) fn undo_in(tx: &mut Tx<'_>, target: CommitId, actor: Tid) -> Result<CommitId> {
    let m = tx.core.commits.get(&target).cloned().ok_or(Error::UnknownCommit(target))?;
    let h = m.header.clone();
    if !matches!(h.kind, Kind::Content) {
        return Err(Error::Misuse("only content commits are undone here"));
    }
    let node = tx.core.id.tid();
    let ts = tx.core.hlc.next();
    let mut deltas = Vec::new();
    for (ai, a) in h.aspects.iter().enumerate() {
        // a commit whose body was dropped cannot be undone (spec/commits.md §7)
        if m.dropped.contains(&(ai, 0)) || !m.valid.get(ai).copied().unwrap_or(false) || a.ak.as_str() == "/created" {
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
            Some(b) if !b.is_empty() => Some(crate::engine::state::decode(&b)?),
            Some(_) => Some(Fragment::default()),
            // not a recent local commit: the join of the held bodies ordered before it
            None => {
                let before: Vec<CommitId> = tx.core.by_aspect.get(&(a.tid, a.ak.clone())).into_iter().flatten().filter(|x| **x < (h.ts, target)).map(|x| x.1).collect();
                let mut f: Option<Fragment> = None;
                for c in before {
                    let Some(ci) = tx.core.commits.get(&c).and_then(|m| m.valid.iter().zip(&m.header.aspects).position(|(v, x)| *v && x.tid == a.tid && x.ak == a.ak)) else { continue };
                    for d in crate::apply::held_parts(tx, &c, ci)? {
                        let d = match d {
                            Decoded::Delta(x) => x.fragment,
                            Decoded::Snapshot(x) => x.fragment,
                        };
                        match &mut f {
                            Some(f) => {
                                f.join(d);
                            }
                            None => f = Some(d),
                        }
                    }
                }
                f
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
        let buf: &dyn UndoBuffer = match &pre {
            Some(f) => f,
            None => &NoBuffer,
        };
        // a write of an undo commit in effect, with every later change of the aspect undone:
        // undo steps back through it (spec/crdt.md §4.6); judged on first use
        let core = &*tx.core;
        let judge: OnceCell<(BTreeMap<CommitId, Vec<CommitId>>, bool)> = OnceCell::new();
        let restored = |s: &Stamp| {
            let (undoers, clear) = judge.get_or_init(|| chain_judge(core, &a.tid, &a.ak, (h.ts, target)));
            *clear && core.commit_of(&a.tid, &a.ak, &s.dot).and_then(|c| core.commits.get(&c).map(|m| (c, m))).is_some_and(|(c, m)| m.header.undoes.is_some() && in_effect(&c, undoers))
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
    if deltas.is_empty() {
        return Err(Error::Misuse("nothing to undo"));
    }
    for d in &deltas {
        crate::engine::write::check_authority(tx.core, tx.core.id.tid(), &[], &d.tid, d.ak.as_str(), ts)?;
    }
    let plan = CommitPlan { kind: Kind::Content, ts, actor, form: Form::Node, creates: Vec::new(), purge: Vec::new(), undoes: Some(target), frontier: None, origins: Vec::new(), signer: tx.core.id.tid() };
    build_and_apply(tx, plan, deltas)
}

/// From the commits holding writes of `(tid, ak)`: who undoes whom, and whether every change
/// (a commit that is not an undo) ordered after `after` is out of effect (spec/crdt.md §4.6).
fn chain_judge(core: &crate::engine::Core, tid: &Tid, ak: &Ak, after: (Ts, CommitId)) -> (BTreeMap<CommitId, Vec<CommitId>>, bool) {
    let held: Vec<(Ts, CommitId)> = core.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().copied().collect();
    let mut undoers: BTreeMap<CommitId, Vec<CommitId>> = BTreeMap::new();
    for (_, id) in &held {
        if let Some(t) = core.commits.get(id).and_then(|m| m.header.undoes) {
            undoers.entry(t).or_default().push(*id);
        }
    }
    let clear = held.iter().filter(|x| **x > after).all(|(_, id)| core.commits.get(id).is_some_and(|m| m.header.undoes.is_some()) || !in_effect(id, &undoers));
    (undoers, clear)
}

/// Whether commit `c` is in effect: no undo commit in effect undoes it. The undo relation is a
/// tree (an undo names an older commit by hash), walked without recursion.
fn in_effect(c: &CommitId, undoers: &BTreeMap<CommitId, Vec<CommitId>>) -> bool {
    let mut memo: BTreeMap<CommitId, bool> = BTreeMap::new();
    let mut entered: BTreeSet<CommitId> = BTreeSet::new();
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

impl Engine {
    /// Undoes `target` (any held content commit; an admin may undo others' changes). `None` if
    /// there is nothing to write.
    pub fn undo(&mut self, target: &CommitId) -> Result<Option<CommitId>> {
        let t = *target;
        let me = self.tid();
        match self.run(|tx| undo_in(tx, t, me)) {
            Err(Error::Misuse("nothing to undo")) => Ok(None),
            r => r.map(Some),
        }
    }

    /// Every held content commit touching `scope`, newest first: (ID, author, actor, `ts`,
    /// `undoes`). The admin view of changes.
    pub fn changes(&self, scope: &[(Tid, Ak)]) -> Vec<(CommitId, Tid, Tid, Ts, Option<CommitId>)> {
        let mut ids: BTreeSet<(Ts, CommitId)> = BTreeSet::new();
        for k in scope {
            ids.extend(self.core.by_aspect.get(k).into_iter().flatten().copied());
        }
        ids.into_iter()
            .rev()
            .filter_map(|(_, c)| {
                let m = self.core.commits.get(&c)?;
                (m.header.kind == Kind::Content).then(|| (c, m.header.author, m.header.actor, m.header.ts, m.header.undoes))
            })
            .collect()
    }

    /// Undo stack of `actor` in `scope`, newest first: its commits not undone, undo commits
    /// excluded. Redo stack: its undo commits not undone themselves.
    pub fn undo_stack(&self, actor: &Tid, scope: &[(Tid, Ak)]) -> (Vec<CommitId>, Vec<CommitId>) {
        let all = self.changes(scope);
        let undone: BTreeSet<CommitId> = self.core.commits.values().filter_map(|m| m.header.undoes).collect();
        let mine = all.iter().filter(|c| c.2 == *actor && !undone.contains(&c.0));
        let undo = mine.clone().filter(|c| c.4.is_none()).map(|c| c.0).collect();
        let redo = mine.filter(|c| c.4.is_some()).map(|c| c.0).collect();
        (undo, redo)
    }
}

#[cfg(test)]
mod tests {
    use super::in_effect;
    use osis_core::CommitId;
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
