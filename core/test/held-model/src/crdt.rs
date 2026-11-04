//! The minimal CRDT: join, prune to canonical form, read, supersede (spec/crdt.md §4, §5.1, §5.6, §5.7, §6).
//! A state is a set of writes keyed by identity; everything is recomputed from it.

use crate::types::*;
use std::collections::{BTreeMap, BTreeSet};

pub type State = BTreeMap<WriteId, Write>;

/// Union of writes, copies of one write joined field-wise (spec/crdt.md §4.1).
pub fn join<'a>(ws: impl IntoIterator<Item = &'a Write>) -> State {
    let mut s = State::new();
    for w in ws {
        s.entry(w.id()).and_modify(|x| x.join_copy(w)).or_insert_with(|| w.clone());
    }
    s
}

fn root_reset(s: &State) -> Option<Stamp> {
    s.values().filter(|w| w.op == Op::Reset).map(|w| w.stamp).max()
}

fn survives(st: Stamp, e: Option<Stamp>) -> bool {
    e.map_or(true, |e| st >= e)
}

/// The canonical state: what survives prune, only the winner of each register or flag, every
/// text record kept (a pruned creation as a bare anchor) (spec/crdt.md §3.3 rule 5, §4.2).
pub fn canon(s: &State, kind: AspectKind) -> State {
    let e = root_reset(s);
    let mut out: Vec<Write> = Vec::new();
    if let Some(r) = s.values().filter(|w| w.op == Op::Reset).max_by_key(|w| w.stamp) {
        out.push(r.clone());
    }
    match kind {
        AspectKind::Register => {
            if let Some(w) = s
                .values()
                .filter(|w| matches!(w.op, Op::Set { .. }) && survives(w.stamp, e))
                .max_by_key(|w| w.stamp)
            {
                out.push(w.clone());
            }
        }
        AspectKind::Map => {
            let mut entries = BTreeSet::new();
            for w in s.values() {
                match &w.op {
                    Op::Create { .. } => {
                        entries.insert(w.stamp.dot);
                    }
                    Op::SetIn { entry, .. } | Op::Remove { entry } => {
                        entries.insert(*entry);
                    }
                    _ => {}
                }
            }
            for d in entries {
                let rem = s
                    .values()
                    .filter(|w| w.op == Op::Remove { entry: d } && survives(w.stamp, e))
                    .max_by_key(|w| w.stamp);
                let ee = e.max(rem.map(|w| w.stamp));
                out.extend(rem.cloned());
                out.extend(
                    s.values()
                        .filter(|w| matches!(w.op, Op::Create { .. }) && w.stamp.dot == d && survives(w.stamp, ee))
                        .cloned(),
                );
                out.extend(
                    s.values()
                        .filter(|w| matches!(w.op, Op::SetIn { entry, .. } if entry == d) && survives(w.stamp, ee))
                        .max_by_key(|w| w.stamp)
                        .cloned(),
                );
            }
        }
        AspectKind::Text => {
            let elems: BTreeSet<Dot> = s.values().filter_map(|w| w.elem()).collect();
            for d in elems {
                let ins = s.values().find(|w| matches!(w.op, Op::Insert { .. }) && w.stamp.dot == d);
                match ins {
                    Some(w) if survives(w.stamp, e) => out.push(w.clone()),
                    _ => out.push(anchor(d)),
                }
                out.extend(
                    s.values()
                        .filter(|w| w.op == Op::Delete { elem: d } && survives(w.stamp, e))
                        .max_by_key(|w| w.stamp)
                        .cloned(),
                );
            }
        }
    }
    join(out.iter())
}

/// A bare anchor record for element `d`.
pub fn anchor(d: Dot) -> Write {
    Write { stamp: Stamp { ts: 0, dot: d }, op: Op::Anchor }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Read {
    Absent,
    Reg(Val),
    Map(BTreeMap<Val, Val>),
    Text(Vec<Val>),
}

/// Reads a canonical state (spec/crdt.md §4.3, §5.1, §5.6, §5.7, §6).
pub fn read(c: &State, kind: AspectKind) -> Read {
    match kind {
        AspectKind::Register => match c.values().find_map(|w| match w.op {
            Op::Set { value } => Some(value),
            _ => None,
        }) {
            Some(Some(v)) => Read::Reg(v),
            _ => Read::Absent,
        },
        AspectKind::Map => {
            let present = c.values().any(|w| match &w.op {
                Op::Create { key } => key.is_some(),
                Op::SetIn { value, .. } => value.is_some(),
                Op::Remove { .. } => true,
                _ => false,
            });
            if !present {
                return Read::Absent;
            }
            // per key: the greatest-stamped value among live entries
            let mut best: BTreeMap<Val, (Stamp, Val)> = BTreeMap::new();
            for w in c.values() {
                let Op::Create { key: Some(k) } = w.op else { continue };
                let d = w.stamp.dot;
                let Some((st, v)) = c.values().find_map(|x| match x.op {
                    Op::SetIn { entry, value: Some(v), .. } if entry == d => Some((x.stamp, v)),
                    _ => None,
                }) else {
                    continue;
                };
                // the winner of the entry must be valued; canon keeps only the winner, so a
                // value-less winner leaves no valued SetIn
                let b = best.entry(k).or_insert((st, v));
                if st > b.0 {
                    *b = (st, v);
                }
            }
            Read::Map(best.into_iter().map(|(k, (_, v))| (k, v)).collect())
        }
        AspectKind::Text => {
            let present = c.values().any(|w| match &w.op {
                Op::Insert { ch, .. } => ch.is_some(),
                Op::Delete { .. } => true,
                _ => false,
            });
            if !present {
                return Read::Absent;
            }
            Read::Text(linearize(c).into_iter().filter_map(|d| text_char(c, d)).collect())
        }
    }
}

fn text_char(c: &State, d: Dot) -> Option<Val> {
    if c.values().any(|w| w.op == Op::Delete { elem: d }) {
        return None;
    }
    c.values().find_map(|w| match w.op {
        Op::Insert { ch, .. } if w.stamp.dot == d => ch,
        _ => None,
    })
}

/// Placement order of every reachable record (spec/crdt.md §6): children by sibling key (the
/// creation stamp) greatest first, records without a surviving creation on END by dot ascending,
/// records anchored at an unknown dot hidden.
pub fn linearize(c: &State) -> Vec<Dot> {
    let records: BTreeSet<Dot> = c.values().filter_map(|w| w.elem()).collect();
    let mut kids: BTreeMap<Option<Dot>, Vec<(Stamp, Dot)>> = BTreeMap::new();
    let mut end = Vec::new();
    for &d in &records {
        let ins = c.values().find_map(|w| match w.op {
            Op::Insert { anchor, .. } if w.stamp.dot == d => Some((w.stamp, anchor)),
            _ => None,
        });
        match ins {
            Some((st, a)) => {
                if a.map_or(true, |a| records.contains(&a)) {
                    kids.entry(a).or_default().push((st, d));
                }
            }
            None => end.push(d),
        }
    }
    for v in kids.values_mut() {
        v.sort_by(|x, y| y.0.cmp(&x.0).then(x.1.cmp(&y.1)));
    }
    fn dfs(x: Option<Dot>, kids: &BTreeMap<Option<Dot>, Vec<(Stamp, Dot)>>, out: &mut Vec<Dot>) {
        if let Some(d) = x {
            out.push(d);
        }
        for &(_, k) in kids.get(&x).map(|v| v.as_slice()).unwrap_or(&[]) {
            dfs(Some(k), kids, out);
        }
    }
    let mut out = Vec::new();
    dfs(None, &kids, &mut out);
    for d in end {
        dfs(Some(d), &kids, &mut out);
    }
    out
}

/// Whether `s` supersedes `w` (spec/crdt.md §4.8): prunes it, beats it at its position, or deletes
/// its element.
pub fn supersedes(s: &Write, w: &Write) -> bool {
    if s.stamp <= w.stamp || w.op == Op::Anchor {
        return false;
    }
    if s.op == Op::Reset {
        return true;
    }
    match (&w.op, &s.op) {
        (Op::Set { .. }, Op::Set { .. }) => true,
        (Op::Create { .. }, Op::Remove { entry }) => *entry == w.stamp.dot,
        (Op::SetIn { entry: a, .. }, Op::Remove { entry: b }) => a == b,
        (Op::SetIn { entry: a, .. }, Op::SetIn { entry: b, .. }) => a == b,
        (Op::Remove { entry: a }, Op::Remove { entry: b }) => a == b,
        (Op::Insert { .. }, Op::Delete { elem }) => *elem == w.stamp.dot,
        (Op::Delete { elem: a }, Op::Delete { elem: b }) => a == b,
        _ => false,
    }
}

/// Whether the canonical state holds `w` by dot (spec/commits.md §5 live write): the write itself,
/// or for a text creation its element's record, a bare anchor included.
pub fn holds(c: &State, w: &Write) -> bool {
    match w.op {
        Op::Insert { .. } | Op::Anchor => c.values().any(|x| matches!(x.op, Op::Insert { .. } | Op::Anchor) && x.stamp.dot == w.stamp.dot),
        _ => c.contains_key(&w.id()),
    }
}

/// spec/commits.md §5 Covered: joining the body into the snapshot's fragment leaves it unchanged.
pub fn covers(snap: &[Write], body: &[Write], kind: AspectKind) -> bool {
    let s = canon(&join(snap.iter()), kind);
    let sb = canon(&join(snap.iter().chain(body.iter())), kind);
    s == sb
}
