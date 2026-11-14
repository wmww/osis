//! A derived value whose readers move only when it does (`Cutoff`): for a value that reads far
//! more than it is (a whole index walked to a small answer), so a memo reading it would move with
//! every write the walk saw.

use super::{Effects, Stamped, Unrecorded, recorded_frame};
use std::cell::RefCell;
use std::hash::Hash;

/// The value of a function per key, kept in a stamped map and derived again (`Effects`) when
/// what it read moved: a reader depends on the value alone, so a derivation giving the same
/// value moves nothing. Brought up to date at each `get_in` and `refresh_in`; a reader that
/// follows it from outside (`Effects`) needs a `refresh_in` before its `due`, else a move waits
/// for the next.
///
/// A key no longer asked for stays until the keys asked since the last sweep reach `SWEEP` times
/// what it kept (`super::SWEEP`, as `Memo`'s), so it holds a few times what is current: a reader
/// of a key swept moves, and asks again.
pub struct Cutoff<K, V> {
    fx: RefCell<Effects<K, V>>,
    values: RefCell<Stamped<K, V>>,
    /// Keys asked for since the last sweep, and how many the sweep kept.
    asked: RefCell<std::collections::HashSet<K>>,
    kept: std::cell::Cell<usize>,
}

impl<K: Hash + Eq + Ord + Clone, V: Clone + PartialEq> Cutoff<K, V> {
    pub fn new(name: &'static str) -> Self {
        Cutoff { fx: RefCell::new(Effects::new(name)), values: RefCell::new(Stamped::default()), asked: RefCell::default(), kept: std::cell::Cell::new(0) }
    }

    /// Drops the keys not asked for since the last sweep, once the asked have grown to
    /// `SWEEP` times what it kept.
    fn sweep(&self) {
        let mut asked = self.asked.borrow_mut();
        if asked.len() <= self.kept.get().max(1) * super::SWEEP {
            return;
        }
        let _u = Unrecorded::start();
        let mut fx = self.fx.borrow_mut();
        let mut values = self.values.borrow_mut();
        let gone: Vec<K> = values.keys().filter(|k| !asked.contains(*k)).cloned().collect();
        for k in gone {
            fx.unwant(&k);
            values.remove(&k);
        }
        self.kept.set(asked.len());
        asked.clear();
    }

    /// Derives again (by `f`, over all of `ctx`, which holds this cutoff at `me`) each key
    /// followed whose reads moved, writing those whose value changed. Read by no memo: what a
    /// reader reads is the values. A failure leaves its key due and is returned.
    pub fn refresh_in<C, E>(ctx: &mut C, me: impl Fn(&C) -> &Self, f: impl Fn(&mut C, &K) -> Result<V, E>) -> Result<(), E> {
        let _u = Unrecorded::start();
        let due = me(ctx).fx.borrow_mut().due();
        for k in due {
            let name = me(ctx).fx.borrow().name();
            let _s = crate::costs::span(name);
            let (out, frame) = recorded_frame(|| f(ctx, &k));
            let this = me(ctx);
            if let Some((_, v)) = this.fx.borrow_mut().settled(&k, out, frame)? {
                this.values.borrow_mut().insert(k, v);
            }
        }
        Ok(())
    }

    /// `k`'s value (`f`'s, followed from now on), up to date (`refresh_in`): a read of it alone.
    pub fn get_in<C, E>(ctx: &mut C, me: impl Fn(&C) -> &Self, k: &K, f: impl Fn(&mut C, &K) -> Result<V, E>) -> Result<V, E> {
        {
            let this = me(ctx);
            if this.asked.borrow_mut().insert(k.clone()) {
                this.sweep();
            }
            let mut fx = this.fx.borrow_mut();
            if !fx.wants(k) {
                fx.want(k.clone());
            }
        }
        Self::refresh_in(ctx, &me, &f)?;
        // a key's first settle writes its value: the fallback is never taken
        let v = me(ctx).values.borrow().get(k).cloned();
        match v {
            Some(v) => Ok(v),
            None => f(ctx, k),
        }
    }

    /// `get_in` for a function of the key alone.
    pub fn get(&self, k: &K, f: impl Fn(&K) -> V) -> V {
        match Self::get_in(&mut &*self, |me| *me, k, |_, k| Ok::<V, std::convert::Infallible>(f(k))) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// `refresh_in` for a function of the key alone.
    pub fn refresh(&self, f: impl Fn(&K) -> V) {
        match Self::refresh_in(&mut &*self, |me| *me, |_, k| Ok::<V, std::convert::Infallible>(f(k))) {
            Ok(()) => {}
            Err(e) => match e {},
        }
    }
}

impl<K: Hash + Eq + Ord + Clone, V: Clone> Clone for Cutoff<K, V> {
    fn clone(&self) -> Self {
        Cutoff { fx: RefCell::new(self.fx.borrow().clone()), values: RefCell::new(Stamped::clone(&self.values.borrow())), asked: RefCell::new(self.asked.borrow().clone()), kept: self.kept.clone() }
    }
}

/// One derivation giving a map, kept per entry (`Stamped`) and derived again (`Effects`) when
/// what it read moved: a reader of one entry moves only when that entry does. For a map that is
/// cheapest derived whole (an inverse over every key) but read an entry at a time. Brought up to
/// date as `Cutoff` is.
pub struct Spread<K, V> {
    fx: RefCell<Effects<(), std::sync::Arc<std::collections::BTreeMap<K, V>>>>,
    values: RefCell<Stamped<K, V>>,
}

impl<K: Hash + Eq + Ord + Clone, V: Clone + PartialEq> Spread<K, V> {
    pub fn new(name: &'static str) -> Self {
        let mut fx = Effects::new(name);
        fx.want(());
        Spread { fx: RefCell::new(fx), values: RefCell::new(Stamped::default()) }
    }

    /// Derives the map again (by `f`) if what it read moved, writing the entries that changed.
    /// Read by no memo.
    pub fn refresh(&self, f: impl FnOnce() -> std::collections::BTreeMap<K, V>) {
        let _u = Unrecorded::start();
        let mut fx = self.fx.borrow_mut();
        if fx.due().is_empty() {
            return;
        }
        let Some((was, now)) = fx.settle(&(), || std::sync::Arc::new(f())) else { return };
        let was = was.unwrap_or_default();
        let mut values = self.values.borrow_mut();
        for (k, v) in now.iter() {
            if was.get(k) != Some(v) {
                values.insert(k.clone(), v.clone());
            }
        }
        for k in was.keys().filter(|k| !now.contains_key(*k)) {
            values.remove(k);
        }
    }

    /// Entry `k` of the map, up to date (`refresh`): a read of it alone.
    pub fn get(&self, k: &K, f: impl FnOnce() -> std::collections::BTreeMap<K, V>) -> Option<V> {
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

    // spec: none (internal: notes/engine.md, Derived values). A reader of a cutoff's value moves
    // only when the value does, not when what it read moved to the same value; one of a spread's
    // entries only when that entry does.
    #[test]
    fn readers_move_only_with_the_value() {
        let mut m: Stamped<u8, u8> = Stamped::default();
        m.insert(1, 10);
        let c: Cutoff<u8, bool> = Cutoff::new("test cutoff");
        let s: Spread<u8, u8> = Spread::new("test spread");
        let big = |m: &Stamped<u8, u8>, k: &u8| m.get(k).copied().unwrap_or(0) > 5;
        let all = |m: &Stamped<u8, u8>| (0..3u8).map(|k| (k, u8::from(big(m, &k)) + m.get(&1).map_or(0, |_| 1))).collect();
        let mut e: Effects<u8, (bool, Option<u8>)> = Effects::new("test reader");
        e.want(1);
        e.want(2);
        for k in e.due() {
            e.settle(&k, || (c.get(&k, |k| big(&m, k)), s.get(&k, || all(&m))));
        }
        m.insert(1, 20);
        c.refresh(|k| big(&m, k));
        s.refresh(|| all(&m));
        assert!(e.due().is_empty(), "the values stayed");
        m.insert(1, 2);
        c.refresh(|k| big(&m, k));
        s.refresh(|| all(&m));
        assert_eq!(e.due(), [1], "key 1's value moved, key 2's did not");
    }

    // spec: none (internal). A key not asked for goes at a sweep (`SWEEP`, as a memo's): what
    // is kept is a few times what was asked lately, never every key ever asked.
    #[test]
    fn keys_not_asked_are_swept() {
        let c: Cutoff<u32, u32> = Cutoff::new("test sweep");
        for k in (0..1000).chain(5000..9000) {
            c.get(&k, |k| *k);
        }
        let values = c.values.borrow();
        assert!(values.len() < 5000 && !values.keys().any(|k| *k < 1000), "{}", values.len());
    }
}
