//! A derived map whose readers move per entry (`Spread`): early cutoff for a map cheapest
//! derived whole (an inverse over every key) but read an entry at a time.

use super::{Effects, Stamped, Unrecorded, recorded_frame};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::hash::Hash;

/// One derivation giving a map, kept per entry (`Stamped`) and derived again (`Effects`) when
/// what it read moved: a reader of one entry depends on that entry alone, so it moves only when
/// the entry does, and a rerun to an equal map moves nothing. An absent entry reads its hash
/// bucket's stamp, so asking for keys the map lacks keeps nothing. Brought up to date at each
/// `get`/`get_in` and `refresh`/`refresh_in`: a memo or `Effects` key reading an entry depends
/// on the value as last refreshed, so whoever checks such a reader without asking the spread
/// first (an `Effects` owner's `due`: sync's modules, `Engine::follow`) refreshes it before.
pub struct Spread<K, V> {
    /// Whether what the map read moved (one key, no value kept: the entries are the value).
    fx: RefCell<Effects<(), ()>>,
    values: RefCell<Stamped<K, V>>,
}

impl<K: Hash + Eq + Ord + Clone, V: Clone + PartialEq> Spread<K, V> {
    pub fn new(name: &'static str) -> Self {
        let mut fx = Effects::new(name);
        fx.want(());
        Spread { fx: RefCell::new(fx), values: RefCell::new(Stamped::default()) }
    }

    /// Derives the map again (by `f`, over all of `ctx`, which holds this spread at `me`) if
    /// what it read moved, writing the entries that changed: whether any did. Read by no memo.
    /// A failure leaves it due and is returned.
    pub fn refresh_in<C, E>(ctx: &mut C, me: impl Fn(&C) -> &Self, f: impl FnOnce(&mut C) -> Result<BTreeMap<K, V>, E>) -> Result<bool, E> {
        let _u = Unrecorded::start();
        if me(ctx).fx.borrow_mut().due().is_empty() {
            return Ok(false);
        }
        let _s = crate::costs::span(me(ctx).fx.borrow().name());
        let (out, frame) = recorded_frame(|| f(ctx));
        let this = me(ctx);
        let (now, out) = match out {
            Ok(now) => (now, Ok(())),
            Err(e) => (BTreeMap::new(), Err(e)),
        };
        this.fx.borrow_mut().settled(&(), out, frame)?;
        // against the entries kept, not the last map: a failed derivation in between kept none
        let mut values = this.values.borrow_mut();
        let gone: Vec<K> = values.keys().filter(|k| !now.contains_key(*k)).cloned().collect();
        let mut moved = !gone.is_empty();
        for k in gone {
            values.remove(&k);
        }
        for (k, v) in now {
            if values.get(&k) != Some(&v) {
                values.insert(k, v);
                moved = true;
            }
        }
        Ok(moved)
    }

    /// Entry `k` of the map, up to date (`refresh_in`): a read of it alone.
    pub fn get_in<C, E>(ctx: &mut C, me: impl Fn(&C) -> &Self, k: &K, f: impl FnOnce(&mut C) -> Result<BTreeMap<K, V>, E>) -> Result<Option<V>, E> {
        Self::refresh_in(ctx, &me, f)?;
        Ok(me(ctx).values.borrow().get(k).cloned())
    }

    /// `refresh_in` for a function of nothing outside.
    pub fn refresh(&self, f: impl FnOnce() -> BTreeMap<K, V>) -> bool {
        match Self::refresh_in(&mut &*self, |me| *me, |_| Ok::<_, std::convert::Infallible>(f())) {
            Ok(moved) => moved,
            Err(e) => match e {},
        }
    }

    /// `get_in` for a function of nothing outside.
    pub fn get(&self, k: &K, f: impl FnOnce() -> BTreeMap<K, V>) -> Option<V> {
        self.refresh(f);
        self.values.borrow().get(k).cloned()
    }
}

impl<K: Hash + Eq + Ord + Clone, V: Clone> Clone for Spread<K, V> {
    fn clone(&self) -> Self {
        Spread { fx: RefCell::new(self.fx.borrow().clone()), values: RefCell::new(Stamped::clone(&self.values.borrow())) }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Stamped;
    use super::*;

    // spec: none (internal: notes/engine.md, Derived values). A reader of a spread's entry moves
    // only when that entry does, not when what the map read moved to the same entry; a key the
    // map lacks keeps nothing however many are asked.
    #[test]
    fn readers_move_only_with_their_entry() {
        let mut m: Stamped<u8, u8> = Stamped::default();
        m.insert(1, 10);
        let s: Spread<u8, bool> = Spread::new("test spread");
        let all = |m: &Stamped<u8, u8>| (0..3u8).map(|k| (k, m.get(&k).copied().unwrap_or(0) > 5 || k == 2)).collect();
        let mut e: Effects<u8, Option<bool>> = Effects::new("test reader");
        e.want(1);
        e.want(2);
        for k in e.due() {
            e.settle(&k, || s.get(&k, || all(&m)));
        }
        m.insert(1, 20);
        assert!(!s.refresh(|| all(&m)), "no entry moved");
        assert!(e.due().is_empty(), "the entries stayed");
        m.insert(1, 2);
        assert!(s.refresh(|| all(&m)));
        assert_eq!(e.due(), [1], "key 1's entry moved, key 2's did not");
        for k in 100..200u8 {
            assert_eq!(s.get(&k, || all(&m)), None);
        }
        assert_eq!(s.values.borrow().len(), 3, "absent keys asked keep nothing");
    }

    // spec: none (internal). A failed derivation keeps the entries and stays due; the next one
    // writes what moved since the entries kept, removals included.
    #[test]
    fn a_failed_derivation_is_tried_again() {
        let mut m: Stamped<u8, u8> = Stamped::default();
        m.insert(1, 1);
        m.insert(2, 2);
        let s: Spread<u8, u8> = Spread::new("test spread failing");
        let all = |m: &Stamped<u8, u8>| m.iter().map(|(k, v)| (*k, *v)).collect::<BTreeMap<u8, u8>>();
        assert_eq!(s.get(&2, || all(&m)), Some(2));
        m.remove(&2);
        assert_eq!(Spread::refresh_in(&mut &s, |me| *me, |_| Err::<BTreeMap<u8, u8>, ()>(())), Err(()));
        assert_eq!(s.values.borrow().get(&2), Some(&2), "kept through the failure");
        assert_eq!(s.get(&2, || all(&m)), None, "removed once derived again");
    }
}
