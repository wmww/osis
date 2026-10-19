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
use osis_crdt::{AnyView, CounterRange, Fragment, PathSeg, Source, UndoBuffer, Undone, View, Writer};
use osis_store::Shred;
use std::collections::BTreeSet;

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

/// Records the state of `(tid, ak)` before local commit `id` applies.
pub(crate) fn remember(tx: &mut Tx<'_>, id: &CommitId, tid: &Tid, ak: &Ak) -> Result<()> {
    tx.load(tid, ak)?;
    let pre = match tx.core.states.get(&(*tid, ak.clone())).cloned().flatten() {
        Some(f) => crate::engine::state::encode(&f)?,
        None => Vec::new(),
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
        let undone = Undone { delta: &d.fragment, source: &source, range: CounterRange { lo: a.lo, hi: a.hi } };
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
        tx.load(&a.tid, &a.ak)?;
        let state = tx.core.states.get(&(a.tid, a.ak.clone())).cloned().flatten().unwrap_or_default();
        let lo = tx.txn.counter(&a.tid, &a.ak)?;
        let mut w = Writer::new(ts, Source::node(node), lo);
        let schema = a.schema.and_then(|i| h.schemas.get(i)).and_then(|(id, _)| tx.core.schemas.get(id).cloned()).or_else(|| a.ak.is_core().then(|| std::sync::Arc::new(osis_schema::core_schema().clone())));
        let view = schema.as_ref().and_then(|s| s.view(a.ak.as_str()));
        let buf: &dyn UndoBuffer = match &pre {
            Some(f) => f,
            None => &NoBuffer,
        };
        let out = match &view {
            Some(v) => undo_delta(&mut w, &undone, &state, buf, v)?,
            None => undo_delta(&mut w, &undone, &state, buf, &AnyView)?,
        };
        if let Some(f) = out {
            let r = w.range();
            deltas.push(Resolved { tid: a.tid, ak: a.ak.clone(), fragment: f, lo: r.lo, hi: r.hi, schema, retention: None, expires: None, frontiers: None, chunks: Vec::new() });
        }
    }
    if deltas.is_empty() {
        return Err(Error::Misuse("nothing to undo"));
    }
    let plan = CommitPlan { kind: Kind::Content, ts, actor, form: Form::Node, creates: Vec::new(), purge: Vec::new(), undoes: Some(target), frontier: None, origins: Vec::new() };
    build_and_apply(tx, plan, deltas)
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
