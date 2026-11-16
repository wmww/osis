//! The keyed list reconciler (notes/fast-design.md, notes/app.md Layers): which rows of a node's
//! lists changed, as remove and insert steps, so rows that stayed keep their widgets and one changed
//! row costs one row. Toolkit-free; `render` applies the steps to a `VirtualList`.

use super::Block;
use super::paged::ListRow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;

/// One step on a list, applied in order to the list as the previous steps left it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op<K> {
    /// Remove the row at the index.
    Remove(usize),
    /// Insert a row for the key at the index, which is its index in the new list.
    Insert(usize, K),
}

/// The longest strictly increasing subsequence of `seq` (indices into `seq`).
fn increasing(seq: &[usize]) -> Vec<usize> {
    let mut tails: Vec<usize> = Vec::new();
    let mut before: Vec<Option<usize>> = vec![None; seq.len()];
    for (i, x) in seq.iter().enumerate() {
        let at = tails.partition_point(|t| seq.get(*t).is_some_and(|v| v < x));
        if let Some(p) = before.get_mut(i) {
            *p = at.checked_sub(1).and_then(|a| tails.get(a).copied());
        }
        match tails.get_mut(at) {
            Some(t) => *t = i,
            None => tails.push(i),
        }
    }
    let mut out = Vec::with_capacity(tails.len());
    let mut at = tails.last().copied();
    while let Some(i) = at {
        out.push(i);
        at = before.get(i).copied().flatten();
    }
    out.reverse();
    out
}

/// Steps turning `old` into `new` (rows are `(key, value)`; keys should be unique, a duplicate
/// gets a row of its own, matched in order). The rows that stay are the longest run of rows with
/// the same key and value kept in order; every other old row is removed (back to front) and every
/// other new row inserted. So one row changing or moving is one remove and one insert, however
/// far it goes, and a row that changed is never kept in place of one that did not.
pub fn reconcile<K: Eq + Hash + Clone, V: PartialEq>(old: &[(K, V)], new: &[(K, V)]) -> Vec<Op<K>> {
    let mut at_old: HashMap<&K, VecDeque<usize>> = HashMap::new();
    for (i, (k, _)) in old.iter().enumerate() {
        at_old.entry(k).or_default().push_back(i);
    }
    // each new row's old row if it is unchanged, in new's order; the increasing run of those stays
    let matched: Vec<Option<usize>> = new
        .iter()
        .map(|(k, v)| at_old.get_mut(k).and_then(VecDeque::pop_front).filter(|o| old.get(*o).is_some_and(|(_, ov)| ov == v)))
        .collect();
    let present: Vec<usize> = matched.iter().flatten().copied().collect();
    let staying: HashSet<usize> = increasing(&present).into_iter().filter_map(|i| present.get(i).copied()).collect();
    let mut ops = Vec::new();
    for i in (0..old.len()).rev() {
        if !staying.contains(&i) {
            ops.push(Op::Remove(i));
        }
    }
    for (i, (k, _)) in new.iter().enumerate() {
        if !matched.get(i).copied().flatten().is_some_and(|o| staying.contains(&o)) {
            ops.push(Op::Insert(i, k.clone()));
        }
    }
    ops
}


/// For each block whose rows changed: its index and the steps on its rows.
pub type ListSteps = Vec<(usize, Vec<Op<String>>)>;

fn rows(p: &[ListRow]) -> Vec<(String, &ListRow)> {
    p.iter().map(|e| (e.key.clone(), e)).collect()
}

/// The row steps from `old` to `new`, or `None` if something other than rows differs and the
/// node must be rebuilt. The rows are a window, so this is bounded by the window whatever the
/// size of the list.
pub fn steps(old: &[Block], new: &[Block]) -> Option<ListSteps> {
    if old.len() != new.len() {
        return None;
    }
    let mut out = Vec::new();
    for (i, (a, b)) in old.iter().zip(new).enumerate() {
        if a == b {
            continue;
        }
        let (Block::List(x), Block::List(y)) = (a, b) else { return None };
        if !x.frame_eq(y) || x.is_empty() || y.is_empty() {
            return None;
        }
        out.push((i, reconcile(&rows(&x.rows), &rows(&y.rows))));
    }
    Some(out)
}
