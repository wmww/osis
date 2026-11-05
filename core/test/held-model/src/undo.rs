//! The undo writer (spec/crdt.md §4.6, spec/commits.md §7): the commit a node writes to undo a
//! held commit, from its own judgment of what it holds. Register, map and text only; no creation
//! undo (`created.0` is not modeled) and no ephemeral undo.

use crate::crdt::{self, Read, State};
use crate::model::evaluate;
use crate::types::*;
use std::collections::{BTreeMap, BTreeSet};

/// Does commit `c` count on `(th, a)`: applied, with its part there valid.
fn counts(applied: &BTreeSet<CommitId>, valid: &BTreeMap<(CommitId, usize), bool>, c: &Commit, th: ThingId, a: Aspect) -> bool {
    applied.contains(&c.id) && c.parts.iter().enumerate().any(|(i, p)| p.thing == th && p.aspect == a && valid.get(&(c.id, i)) == Some(&true))
}

/// Is `c` in effect: no undo commit in effect counting on an aspect `c` lists undoes it.
pub fn in_effect(h: &Held, applied: &BTreeSet<CommitId>, valid: &BTreeMap<(CommitId, usize), bool>, c: CommitId) -> bool {
    let Some(target) = h.commits.iter().find(|x| x.id == c) else { return true };
    !h.commits.iter().any(|u| u.undoes == Some(c) && target.parts.iter().any(|p| counts(applied, valid, u, p.thing, p.aspect)) && in_effect(h, applied, valid, u.id))
}

fn before(c: &Commit, t: &Commit) -> bool {
    (c.ts, c.id) < (t.ts, t.id)
}

/// The undo buffer of each aspect: the state from the held commits ordered before `t` by
/// `(ts, ID)`, as this node judges them, the values it holds value-less (expired by `ts`, purged)
/// stripped.
fn buffer(h: &Held, t: &Commit, valueless: &BTreeSet<(CommitId, ThingId, Aspect)>, wall_ts: u64) -> BTreeMap<(ThingId, Aspect), State> {
    let mut b = h.clone();
    let keep: BTreeSet<CommitId> = h.commits.iter().filter(|c| c.is_role() || before(c, t)).map(|c| c.id).collect();
    b.commits.retain(|c| keep.contains(&c.id));
    b.own_state.retain(|s| h.commits.iter().any(|c| c.id == s.write.owner() && before(c, t)));
    let expired_by: BTreeSet<CommitId> = h.commits.iter().filter(|c| c.expires.is_some_and(|x| x <= wall_ts)).map(|c| c.id).collect();
    evaluate(&b)
        .states
        .into_iter()
        .map(|((th, a), ws)| {
            let mut ws = ws;
            for w in &mut ws {
                w.strip(|c| valueless.contains(&(c, th, a)) || expired_by.contains(&c));
            }
            ((th, a), crdt::join(ws.iter()))
        })
        .collect()
}

/// The undo commit `id` at `ts` by `author` (acting for itself) of `target`, as node `h.me` writes
/// it; None when there is nothing to write.
pub fn undo(h: &Held, target: CommitId, id: CommitId, ts: u64, author: NodeId) -> Option<Commit> {
    let o = evaluate(h);
    let t = h.commits.iter().find(|c| c.id == target)?;
    if t.kind != CommitKind::Content || !o.applied.contains(&target) {
        return None;
    }
    let bufs = buffer(h, t, &o.valueless, wall(ts));
    let effect = |c: CommitId| in_effect(h, &o.applied, &o.valid, c);
    let is_undo = |c: CommitId| h.commits.iter().any(|x| x.id == c && x.undoes.is_some());
    let by_id: BTreeMap<CommitId, &Commit> = h.commits.iter().map(|c| (c.id, c)).collect();
    let d = Stamp { ts, dot: Dot { commit: id, ctr: 1 } };
    let mut ctr = 0u32;
    let mut fresh = || {
        ctr += 1;
        Stamp { ts, dot: Dot { commit: id, ctr } }
    };
    let mut parts = Vec::new();
    let mut copied: BTreeSet<CommitId> = BTreeSet::new();
    for (i, p) in t.parts.iter().enumerate() {
        // dropped originals and invalid writes are not undone
        let Body::Held(Delta::Writes(ws)) = &p.body else { continue };
        if o.valid.get(&(t.id, i)) != Some(&true) {
            continue;
        }
        let (th, a) = (p.thing, p.aspect);
        let buf = bufs.get(&(th, a)).cloned().unwrap_or_default();
        let cur = crdt::join(o.states.get(&(th, a)).into_iter().flatten());
        let on_aspect = |c: &Commit| c.parts.iter().any(|q| q.thing == th && q.aspect == a);
        // step-back: every later non-undo commit counting on the aspect is out of effect
        let step_back = h.commits.iter().filter(|c| counts(&o.applied, &o.valid, c, th, a) && before(t, c) && c.undoes.is_none()).all(|c| !effect(c.id));
        let ours = |c: CommitId| c == t.id || (is_undo(c) && effect(c));
        let mut out: Vec<Write> = Vec::new();
        let read_buf = crdt::read(&buf, a.kind);
        // Absent before: the aspect root absent in the buffer, every valued write ours
        let complete = h.commits.iter().filter(|c| before(c, t) && on_aspect(c)).all(|c| {
            c.parts.iter().filter(|q| q.thing == th && q.aspect == a).all(|q| matches!(q.body, Body::Held(_)))
        }) && !h.commits.iter().any(|c| c.kind == CommitKind::Snapshot && before(t, c) && on_aspect(c));
        let valued_ours = cur.values().all(|w| {
            let deleted_creation = matches!(w.op, Op::Insert { .. }) && crdt::text_char(&cur, w.stamp.dot).is_none();
            deleted_creation || w.values().iter().all(|&(own, v)| v.is_none() || ours(own))
        });
        if complete && read_buf == Read::Absent && valued_ours && step_back {
            out.push(Write { stamp: d, op: Op::Reset });
        } else if ws.iter().any(|w| w.op == Op::Reset) && read_buf != Read::Absent {
            // a fragment reset: re-insert the pre-reset value with fresh dots (replace)
            out.push(Write { stamp: d, op: Op::Reset });
            for w in buf.values() {
                for (own, v) in w.values() {
                    if v.is_some() {
                        copied.insert(own);
                    }
                }
            }
            match read_buf {
                Read::Reg(v) => out.push(Write { stamp: d, op: Op::Set { value: Some(v) } }),
                Read::Map(m) => {
                    for (k, v) in m {
                        let s = fresh();
                        out.push(Write { stamp: s, op: Op::Create { key: Some(k) } });
                        out.push(Write { stamp: s, op: Op::SetIn { entry: s.dot, key: Some(k), value: Some(v) } });
                    }
                }
                Read::Text(cs) => {
                    let mut anchor = None;
                    for ch in cs {
                        let s = fresh();
                        out.push(Write { stamp: s, op: Op::Insert { anchor, ch: Some(ch) } });
                        anchor = Some(s.dot);
                    }
                }
                Read::Absent => {}
            }
        } else {
            for w in ws {
                match &w.op {
                    Op::Set { value } => {
                        let winner = cur.values().filter(|x| matches!(x.op, Op::Set { .. })).max_by_key(|x| x.stamp);
                        let ok = winner.is_some_and(|x| {
                            x.id() == w.id() || (ours(x.owner()) && x.owner() != t.id && value.is_some() && x.op == w.op && step_back)
                        });
                        let prev = buf.values().filter(|x| matches!(x.op, Op::Set { .. })).max_by_key(|x| x.stamp);
                        if let (true, Some(Write { op: Op::Set { value: Some(v) }, stamp })) = (ok, prev) {
                            copied.insert(stamp.dot.commit);
                            out.push(Write { stamp: d, op: Op::Set { value: Some(*v) } });
                        }
                    }
                    Op::Create { .. } => out.push(Write { stamp: d, op: Op::Remove { entry: w.stamp.dot } }),
                    Op::SetIn { entry, key, value } if entry.commit != t.id => {
                        let winner = cur.values().filter(|x| matches!(x.op, Op::SetIn { entry: e, .. } if e == *entry)).max_by_key(|x| x.stamp);
                        let same = |x: &Write| matches!(&x.op, Op::SetIn { value: v, .. } if v == value) && value.is_some();
                        let ok = winner.is_some_and(|x| x.id() == w.id() || (ours(x.owner()) && x.owner() != t.id && same(x) && step_back));
                        let prev = match (&read_buf, key) {
                            (Read::Map(m), Some(k)) => m.get(k).copied(),
                            _ => None,
                        };
                        if let (true, Some(v)) = (ok, prev) {
                            copied.extend(owners_of_key(&buf, key.unwrap_or_default()));
                            out.push(Write { stamp: d, op: Op::SetIn { entry: *entry, key: *key, value: Some(v) } });
                        }
                    }
                    Op::Remove { entry } => {
                        // re-add the key's removed records as one entry with a fresh dot
                        let k = buf.values().find_map(|x| match x.op {
                            Op::Create { key: Some(k) } if x.stamp.dot == *entry => Some(k),
                            _ => None,
                        });
                        let v = match (&read_buf, k) {
                            (Read::Map(m), Some(k)) => m.get(&k).copied(),
                            _ => None,
                        };
                        let done = out.iter().any(|x| matches!(x.op, Op::Create { key } if key == k));
                        if let (Some(k), Some(v), false) = (k, v, done) {
                            copied.extend(owners_of_key(&buf, k));
                            let s = fresh();
                            out.push(Write { stamp: s, op: Op::Create { key: Some(k) } });
                            out.push(Write { stamp: s, op: Op::SetIn { entry: s.dot, key: Some(k), value: Some(v) } });
                        }
                    }
                    Op::Insert { .. } => out.push(Write { stamp: d, op: Op::Delete { elem: w.stamp.dot } }),
                    Op::Delete { elem } => {
                        if let Some(ch) = crdt::text_char(&buf, *elem) {
                            copied.insert(elem.commit);
                            out.push(Write { stamp: d, op: Op::Undelete { elem: *elem, ch: Some(ch) } });
                        }
                    }
                    Op::Undelete { elem, .. } => {
                        let deleted = buf.values().any(|x| x.elem() == Some(*elem)) && crdt::text_char(&buf, *elem).is_none();
                        if deleted {
                            out.push(Write { stamp: d, op: Op::Delete { elem: *elem } });
                        }
                    }
                    _ => {}
                }
            }
        }
        if !out.is_empty() {
            parts.push(Part { thing: th, aspect: a, retention: p.retention, body: Body::Held(Delta::Writes(out)), stripped: BTreeSet::new() });
        }
    }
    if parts.is_empty() {
        return None;
    }
    // it expires at the earliest T among the deltas owning its copied writes
    let expires = copied.iter().filter_map(|c| by_id.get(c).and_then(|c| c.expires)).min();
    Some(Commit { id, author, actor: author, ts, expires, kind: CommitKind::Content, parts, purge: vec![], frontier: None, undoes: Some(target) })
}

/// The deltas owning a map key's live content in a state.
fn owners_of_key(s: &State, k: Val) -> Vec<CommitId> {
    let entries: Vec<Dot> = s
        .values()
        .filter_map(|w| match w.op {
            Op::Create { key: Some(x) } if x == k => Some(w.stamp.dot),
            _ => None,
        })
        .collect();
    s.values()
        .filter(|w| entries.contains(&w.stamp.dot) || matches!(w.op, Op::SetIn { entry, .. } if entries.contains(&entry)))
        .flat_map(|w| w.values().into_iter().filter(|(_, v)| v.is_some()).map(|(c, _)| c))
        .collect()
}
