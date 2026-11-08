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

/// The canonical state: what survives prune, only the winner of each register or flag; a text
/// record lives while a write on it does (spec/crdt.md §3.3 rule 5, §4.2).
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
            // the char is one register over the creation and the flag writes: a flag below the
            // creation is beaten (spec/crdt.md §5.7 Join)
            for d in elems {
                let ins = s.values().find(|w| matches!(w.op, Op::Insert { .. }) && w.stamp.dot == d && survives(w.stamp, e));
                out.extend(ins.cloned());
                let floor = ins.map(|w| w.stamp).max(e);
                out.extend(s.values().filter(|w| is_flag(w, d) && survives(w.stamp, floor)).max_by_key(|w| flag_order(w)).cloned());
            }
        }
    }
    join(out.iter())
}

/// A deleted-flag write on element `d` (delete or undelete).
fn is_flag(w: &Write, d: Dot) -> bool {
    matches!(w.op, Op::Delete { elem } | Op::Undelete { elem, .. } if elem == d)
}

/// Flag register order: stamp, then `true` over `false` (spec/crdt.md §5.7 Join).
fn flag_order(w: &Write) -> (Stamp, bool) {
    (w.stamp, matches!(w.op, Op::Delete { .. }))
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
            // per key: the greatest-stamped value among live entries. An entry shows while its creation is
            // held (valued or value-less) and its winning write is valued; its key is the creation's, else the
            // winning write's own (spec/crdt.md §5.6 Live)
            let mut best: BTreeMap<Val, (Stamp, Val)> = BTreeMap::new();
            for w in c.values() {
                let Op::Create { key: ck } = w.op else { continue };
                let d = w.stamp.dot;
                let Some((st, k, v)) = c.values().find_map(|x| match x.op {
                    Op::SetIn { entry, key, value: Some(v) } if entry == d => Some((x.stamp, ck.or(key)?, v)),
                    _ => None,
                }) else {
                    continue;
                };
                // canon keeps only the entry's winning write, so a value-less winner leaves no valued SetIn
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
                Op::Delete { .. } | Op::Undelete { .. } => true,
                _ => false,
            });
            if !present {
                return Read::Absent;
            }
            Read::Text(linearize(c).into_iter().filter_map(|d| text_char(c, d)).collect())
        }
    }
}

/// The char a text element shows (spec/crdt.md §5.7 Live): one register over the creation and
/// the flag writes, by stamp, a flag winning a tie. The creation winning: its char; an undelete:
/// that undelete's own (none when it carries none: expired, purged); a delete: none. None without
/// a surviving creation.
pub fn text_char(c: &State, d: Dot) -> Option<Val> {
    let (at, created) = c.values().find_map(|w| match w.op {
        Op::Insert { ch, .. } if w.stamp.dot == d => Some((w.stamp, ch)),
        _ => None,
    })?;
    match c.values().filter(|w| is_flag(w, d) && w.stamp >= at).max_by_key(|w| flag_order(w)).map(|w| &w.op) {
        Some(Op::Delete { .. }) => None,
        Some(Op::Undelete { ch, .. }) => *ch,
        _ => created,
    }
}

/// Placement order of every record (spec/crdt.md §6): children by sibling key (the creation
/// stamp) greatest first, then on END by dot ascending the records without a surviving creation
/// and the virtual anchors (dots anchored at with no record, §6.1: not output themselves).
pub fn linearize(c: &State) -> Vec<Dot> {
    let records: BTreeSet<Dot> = c.values().filter_map(|w| w.elem()).collect();
    let mut kids: BTreeMap<Option<Dot>, Vec<(Stamp, Dot)>> = BTreeMap::new();
    let mut end = BTreeSet::new();
    for &d in &records {
        let ins = c.values().find_map(|w| match w.op {
            Op::Insert { anchor, .. } if w.stamp.dot == d => Some((w.stamp, anchor)),
            _ => None,
        });
        match ins {
            Some((st, a)) => {
                end.extend(a.filter(|a| !records.contains(a)));
                kids.entry(a).or_default().push((st, d));
            }
            None => {
                end.insert(d);
            }
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
    out.retain(|d| records.contains(d));
    out
}

/// Whether `s` supersedes `w` (spec/crdt.md §4.8): prunes it, beats it at its position, or deletes
/// its element.
pub fn supersedes(s: &Write, w: &Write) -> bool {
    // a flag wins its element's char register from its creation on a tie (spec/crdt.md §5.7)
    let tie = s.stamp == w.stamp && matches!((&w.op, &s.op), (Op::Insert { .. }, Op::Delete { elem }) if *elem == w.stamp.dot);
    if s.stamp <= w.stamp && !tie {
        return false;
    }
    if s.op == Op::Reset {
        return true;
    }
    match (&w.op, &s.op) {
        // a register's later write implies a reset (spec/crdt.md §5.1), pruning a reset too
        (Op::Set { .. } | Op::Reset, Op::Set { .. }) => true,
        (Op::Create { .. }, Op::Remove { entry }) => *entry == w.stamp.dot,
        (Op::SetIn { entry: a, .. }, Op::Remove { entry: b }) => a == b,
        (Op::SetIn { entry: a, .. }, Op::SetIn { entry: b, .. }) => a == b,
        (Op::Remove { entry: a }, Op::Remove { entry: b }) => a == b,
        (Op::Insert { .. }, Op::Delete { elem }) => *elem == w.stamp.dot,
        // a flag below its element's creation loses the char register to it (spec/crdt.md §5.7)
        (Op::Delete { elem } | Op::Undelete { elem, .. }, Op::Insert { .. }) => *elem == s.stamp.dot,
        (Op::Delete { elem: a } | Op::Undelete { elem: a, .. }, Op::Delete { elem: b } | Op::Undelete { elem: b, .. }) => a == b,
        _ => false,
    }
}

/// Whether the canonical state holds `w` by dot (spec/commits.md §5 live write): the write itself,
/// or for a text creation its element's record (a write on it).
pub fn holds(c: &State, w: &Write) -> bool {
    match w.op {
        Op::Insert { .. } => c.values().any(|x| x.elem() == Some(w.stamp.dot)),
        _ => c.contains_key(&w.id()),
    }
}

/// spec/commits.md §5 Covered: joining the body into the snapshot's fragment leaves it unchanged.
pub fn covers(snap: &[Write], body: &[Write], kind: AspectKind) -> bool {
    let s = canon(&join(snap.iter()), kind);
    let sb = canon(&join(snap.iter().chain(body.iter())), kind);
    s == sb
}
