//! The undo writer (spec/crdt.md §4.6, spec/commits.md §7): the commit a node writes to undo a
//! held commit, from its own judgment of what it holds. Each aspect the undone commit wrote is
//! written to read as it would had that commit never been written (crdt-model's structural diff,
//! spec/crdt.md §9), for the generator's aspects (`gen::ty`). No creation undo (`created.0` is not
//! modeled), no ephemeral undo, no check that the inverse restores only kept content.

use crate::gen::ty;
use crate::model::{evaluate, Dots};
use crate::types::*;
use crdt_model::death::{valued, winning};
use crdt_model::ops::{self, Writer};
use crdt_model::writes::writes;
use std::collections::{BTreeMap, BTreeSet};

/// The undo commit `id` at `ts` by `author` (acting for itself) of `target`, as node `h.me` writes
/// it; None when there is nothing to write.
pub fn undo(h: &Held, target: CommitId, id: CommitId, ts: u64, author: NodeId) -> Option<Commit> {
    let o = evaluate(h);
    let t = h.commits.iter().find(|c| c.id == target)?;
    // no creation undo (ASSUMPTIONS.md)
    if t.kind != CommitKind::Content || !o.applied.contains(&target) || crate::gen::creates(t) {
        return None;
    }
    // what the node holds as if `target` had not been written: its own body gone, and its writes
    // gone from every snapshot carrying them; values held value-less (expired by the undo's
    // `wall_ms(ts)`, purged) never written back (spec/crdt.md §4.6)
    let mut without = h.clone();
    without.now = h.now.max(wall(ts));
    without.commits.retain(|c| c.id != target);
    let dots = Dots::new(h);
    for c in &mut without.commits {
        for p in &mut c.parts {
            if let Body::Held(Delta::Writes(f)) = &mut p.body {
                let (th, a) = (p.thing, p.aspect);
                f.keep_writes(&|d| dots.commit(th, a, d) != Some(target));
            }
        }
    }
    let ow = evaluate(&without);
    let by_id: BTreeMap<CommitId, &Commit> = h.commits.iter().map(|c| (c.id, c)).collect();
    let mut w = Writer::new(commit_source(id), ts, 1);
    let mut parts = Vec::new();
    let mut copied: BTreeSet<CommitId> = BTreeSet::new();
    for (i, p) in t.parts.iter().enumerate() {
        // dropped originals and invalid writes are not undone; a signal reads absent before and
        // after any write: nothing to write back (spec/commits.md §7)
        if !matches!(p.body, Body::Held(Delta::Writes(_))) || o.valid.get(&(t.id, i)) != Some(&true) || p.aspect.signal {
            continue;
        }
        let (th, a) = (p.thing, p.aspect);
        let Some(ty) = ty(a) else { continue };
        let cur = o.states.get(&(th, a)).and_then(|s| s.slot(ty.enc())).filter(|s| s.present());
        let goal = ow.states.get(&(th, a)).cloned().unwrap_or_else(|| Frag::empty(0));
        let delta = match goal.read() {
            None if cur.is_some() => Some(ops::remove(&mut w, ty.enc())),
            None => None,
            Some(v) => crdt_model::diff::diff(&mut w, cur, &ty, &v),
        };
        let Some(delta) = delta else { continue };
        // the content written back: values winning in `goal` and not in the current state
        let wins = winning(&goal);
        let now_wins = o.states.get(&(th, a)).map(winning).unwrap_or_default();
        for (n, x) in writes(&goal) {
            let k = crdt_model::death::key(&n);
            if valued(&x) && wins.contains(&k) && !now_wins.contains(&k) {
                copied.extend(dots.commit(th, a, &crdt_model::death::stamp(&n).dot));
            }
        }
        parts.push(Part { thing: th, aspect: a, retention: p.retention, body: Body::Held(Delta::Writes(delta)), stripped: BTreeSet::new(), replaces: None });
        w.next_commit(ts);
    }
    if parts.is_empty() {
        return None;
    }
    // it expires with what it copies back (expiries still ahead); none while those differ
    let expiries: BTreeSet<Option<u64>> = copied.iter().map(|c| by_id.get(c).and_then(|c| c.expires)).filter(|x| x.is_none_or(|x| x > wall(ts))).collect();
    if expiries.len() > 1 {
        return None;
    }
    let expires = expiries.into_iter().next().flatten();
    Some(Commit { id, author, actor: author, ts, expires, kind: CommitKind::Content, parts, purge: vec![], frontier: None, undoes: Some(target) , boxes: vec![] })
}
