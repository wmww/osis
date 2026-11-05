//! The keyed list reconciler (notes/app.md Layers, Driver): a changed list (a group's items, later
//! a live query result) becomes insert/move/remove/update steps on a list widget, so rows that
//! stayed keep their widgets. `reconcile` is toolkit-free; `KeyedList` applies the steps to a
//! Masonry `Flex` and maps row widgets back to keys.

use masonry::core::{NewWidget, Widget, WidgetId, WidgetMut};
use masonry::widgets::Flex;

/// One step on a list, applied in order to the list as the previous steps left it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op<K> {
    /// Remove the row at the index.
    Remove(usize),
    /// Insert a row for the key at the index.
    Insert(usize, K),
    /// Take the row at `from` out and put it back at `to` (`to < from`).
    Move { from: usize, to: usize },
    /// The row at the index stays but its value changed.
    Update(usize),
}

/// Steps turning `old` into `new` (rows are `(key, value)`; keys should be unique, a duplicate
/// gets a row of its own). Removes first (back to front), then one pass in `new`'s order that
/// keeps, moves up or inserts each row; a row whose value differs gets an `Update`.
pub fn reconcile<K: PartialEq + Clone, V: PartialEq>(old: &[(K, V)], new: &[(K, V)]) -> Vec<Op<K>> {
    let mut ops = Vec::new();
    // the working list: (key, index into old)
    let mut cur: Vec<(K, usize)> = old.iter().enumerate().map(|(i, (k, _))| (k.clone(), i)).collect();
    for i in (0..cur.len()).rev() {
        if cur.get(i).is_some_and(|(k, _)| !new.iter().any(|(nk, _)| nk == k)) {
            cur.remove(i);
            ops.push(Op::Remove(i));
        }
    }
    for (i, (k, v)) in new.iter().enumerate() {
        let found = cur.iter().skip(i).position(|(ck, _)| ck == k).map(|p| p + i);
        match found {
            Some(j) => {
                if j != i {
                    let row = cur.remove(j);
                    cur.insert(i, row);
                    ops.push(Op::Move { from: j, to: i });
                }
                let changed = cur.get(i).and_then(|(_, oi)| old.get(*oi)).is_none_or(|(_, ov)| ov != v);
                if changed {
                    ops.push(Op::Update(i));
                }
            }
            None => {
                cur.insert(i, (k.clone(), usize::MAX));
                ops.push(Op::Insert(i, k.clone()));
            }
        }
    }
    // leftovers: duplicates of kept keys in `old`
    for i in (new.len()..cur.len()).rev() {
        ops.push(Op::Remove(i));
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
            Op::Move { from, to } if *from < list.len() && *to < list.len() => {
                let x = list.remove(*from);
                list.insert(*to, x);
            }
            Op::Update(i) => {
                if let Some(x) = list.get_mut(*i) {
                    update(*i, x);
                }
            }
            _ => {}
        }
    }
}

/// How a `KeyedList` builds and refreshes its rows.
pub trait Rows<K> {
    /// A new row widget for `key`.
    fn make(&mut self, key: &K) -> NewWidget<dyn Widget>;
    /// Refreshes the row of `key` in place (its value changed).
    fn update(&mut self, key: &K, row: WidgetMut<'_, dyn Widget>);
}

/// A `Flex` (column or row, children only, no spacers) kept equal to a keyed list. Masonry
/// cannot move a widget between slots, so a move rebuilds that one row.
#[derive(Debug)]
pub struct KeyedList<K> {
    rows: Vec<(K, WidgetId)>,
}

impl<K> Default for KeyedList<K> {
    fn default() -> Self {
        KeyedList { rows: Vec::new() }
    }
}

impl<K: Clone + PartialEq> KeyedList<K> {
    /// The keys shown, in order.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.rows.iter().map(|(k, _)| k)
    }

    /// The key whose row is `id` (a row's own widget id: a button press names it).
    pub fn key_of(&self, id: WidgetId) -> Option<&K> {
        self.rows.iter().find(|(_, w)| *w == id).map(|(k, _)| k)
    }

    /// The row widget of `key`.
    pub fn widget_of(&self, key: &K) -> Option<WidgetId> {
        self.rows.iter().find(|(k, _)| k == key).map(|(_, w)| *w)
    }

    /// Applies `ops` (from `reconcile` against `keys()`) to `flex` and to the mirror.
    pub fn apply(&mut self, flex: &mut WidgetMut<'_, Flex>, ops: &[Op<K>], rows: &mut impl Rows<K>) {
        for op in ops {
            match op {
                Op::Remove(i) if *i < self.rows.len() => {
                    self.rows.remove(*i);
                    Flex::remove_child(flex, *i);
                }
                Op::Insert(i, k) if *i <= self.rows.len() => {
                    let w = rows.make(k);
                    self.rows.insert(*i, (k.clone(), w.id()));
                    Flex::insert_child(flex, *i, w);
                }
                Op::Move { from, to } if *from < self.rows.len() && *to < self.rows.len() => {
                    let (k, _) = self.rows.remove(*from);
                    Flex::remove_child(flex, *from);
                    let w = rows.make(&k);
                    self.rows.insert(*to, (k, w.id()));
                    Flex::insert_child(flex, *to, w);
                }
                Op::Update(i) => {
                    if let Some((k, _)) = self.rows.get(*i)
                        && *i < flex.widget.len()
                        && let Some(child) = Flex::child_mut(flex, *i)
                    {
                        rows.update(k, child);
                    }
                }
                _ => {}
            }
        }
    }
}
