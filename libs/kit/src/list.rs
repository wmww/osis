//! The keyed list reconciler (notes/app.md Layers): a changed list becomes insert/move/remove/update
//! steps on a list widget, so rows that stayed keep their widgets and one changed row costs one
//! row. `reconcile` is toolkit-free; `KeyedList` applies the steps to a `ListWidget`.

use masonry::core::{NewWidget, Widget, WidgetMut};
use masonry::widgets::Flex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;

/// One step on a list, applied in order to the list as the previous steps left it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op<K> {
    /// Remove the row at the index.
    Remove(usize),
    /// Insert a row for the key at the index.
    Insert(usize, K),
    /// The row at the index stays but its value changed.
    Update(usize),
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
/// gets a row of its own, matched in order). The rows that stay are the longest run kept in
/// order: every other old row is removed (back to front) and every other new row inserted, so
/// one row moving is one remove and one insert however far it goes. A kept row whose value
/// differs gets an `Update`.
pub fn reconcile<K: Eq + Hash + Clone, V: PartialEq>(old: &[(K, V)], new: &[(K, V)]) -> Vec<Op<K>> {
    let mut at_old: HashMap<&K, VecDeque<usize>> = HashMap::new();
    for (i, (k, _)) in old.iter().enumerate() {
        at_old.entry(k).or_default().push_back(i);
    }
    // each new row's old row, in new's order; the increasing run of those stays
    let matched: Vec<Option<usize>> = new.iter().map(|(k, _)| at_old.get_mut(k).and_then(VecDeque::pop_front)).collect();
    let present: Vec<usize> = matched.iter().flatten().copied().collect();
    let staying: HashSet<usize> = increasing(&present).into_iter().filter_map(|i| present.get(i).copied()).collect();
    let mut ops = Vec::new();
    for i in (0..old.len()).rev() {
        if !staying.contains(&i) {
            ops.push(Op::Remove(i));
        }
    }
    for (i, (k, v)) in new.iter().enumerate() {
        match matched.get(i).copied().flatten().filter(|o| staying.contains(o)) {
            Some(o) => {
                if old.get(o).is_none_or(|(_, ov)| ov != v) {
                    ops.push(Op::Update(i));
                }
            }
            None => ops.push(Op::Insert(i, k.clone())),
        }
    }
    ops
}

/// Applies `ops` to a plain vector of keys (what `reconcile` assumes of a list); for tests and
/// for mirrors of widget lists. `make` gives the element for an inserted key.
pub fn apply<K: Clone, T>(list: &mut Vec<T>, ops: &[Op<K>], mut make: impl FnMut(&K) -> T, mut update: impl FnMut(usize, &mut T)) {
    for op in ops {
        match op {
            Op::Remove(i) if *i < list.len() => {
                list.remove(*i);
            }
            Op::Insert(i, k) if *i <= list.len() => list.insert(*i, make(k)),
            Op::Update(i) => {
                if let Some(x) = list.get_mut(*i) {
                    update(*i, x);
                }
            }
            _ => {}
        }
    }
}

/// A widget whose children are a list `KeyedList` can keep (every child one row, in order, apart
/// from fixed children after the last row).
pub trait ListWidget: Widget + Sized {
    fn insert_row(this: &mut WidgetMut<'_, Self>, i: usize, row: NewWidget<dyn Widget>);
    fn remove_row(this: &mut WidgetMut<'_, Self>, i: usize);
}

impl ListWidget for Flex {
    fn insert_row(this: &mut WidgetMut<'_, Self>, i: usize, row: NewWidget<dyn Widget>) {
        Flex::insert_child(this, i, row);
    }
    fn remove_row(this: &mut WidgetMut<'_, Self>, i: usize) {
        Flex::remove_child(this, i);
    }
}

/// How a `KeyedList` builds its rows; `B` is what a row holds on to.
pub trait Rows<K, B> {
    /// A new row widget for `key`.
    fn make(&mut self, key: &K) -> (NewWidget<dyn Widget>, B);
    /// A row left: its widget is gone, this forgets what `make` registered.
    fn dropped(&mut self, _: B) {}
}

/// A list widget's rows, kept equal to a keyed list. Masonry cannot move a widget between slots,
/// so an update rebuilds that one row.
#[derive(Debug)]
pub struct KeyedList<K, B = ()> {
    rows: Vec<(K, B)>,
}

impl<K, B> Default for KeyedList<K, B> {
    fn default() -> Self {
        KeyedList { rows: Vec::new() }
    }
}

impl<K: Clone + Eq, B> KeyedList<K, B> {
    /// A row built by the widget's first build, in order.
    pub fn push(&mut self, key: K, row: B) {
        self.rows.push((key, row));
    }

    /// The keys shown, in order.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.rows.iter().map(|(k, _)| k)
    }

    /// What each row holds.
    pub fn rows(&self) -> impl Iterator<Item = &B> {
        self.rows.iter().map(|(_, b)| b)
    }

    /// Applies `ops` (from `reconcile` against `keys()`) to `list` and to the mirror.
    pub fn apply<W: ListWidget>(&mut self, list: &mut WidgetMut<'_, W>, ops: &[Op<K>], rows: &mut impl Rows<K, B>) {
        for op in ops {
            match op {
                Op::Remove(i) if *i < self.rows.len() => {
                    rows.dropped(self.rows.remove(*i).1);
                    W::remove_row(list, *i);
                }
                Op::Insert(i, k) if *i <= self.rows.len() => {
                    let (w, b) = rows.make(k);
                    self.rows.insert(*i, (k.clone(), b));
                    W::insert_row(list, *i, w);
                }
                Op::Update(i) if *i < self.rows.len() => {
                    let k = self.rows.remove(*i).0.clone();
                    W::remove_row(list, *i);
                    let (w, b) = rows.make(&k);
                    self.rows.insert(*i, (k, b));
                    W::insert_row(list, *i, w);
                }
                _ => {}
            }
        }
    }
}
