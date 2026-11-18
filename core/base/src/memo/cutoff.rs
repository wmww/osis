//! Early cutoff per key (`Cutoff`): a value derived per key whose readers move only when it
//! does, not when what it read moved to the same value.

use super::{Effects, Quiet, Stamped, Unrecorded, recorded_frame};
use std::cell::{Cell, RefCell};
use std::hash::Hash;

/// One derivation per key, kept as a stamped row (`Stamped`) and derived again (`Effects`) when
/// what it read moved: a reader of a key depends on its row alone, so a key whose inputs move
/// often to the same answer (an actor's whole timeline, read for one yes or no) moves none of its
/// readers. A key is followed from its first `get_in` on. Brought up to date at each `get_in`
/// (every key due, not only the one asked) and `refresh_in`: a memo or `Effects` key reading a
/// row depends on the row as last refreshed, so whoever checks such a reader without asking the
/// cutoff first (an `Effects` owner's `due`: sync's modules, through `Engine::follow`) refreshes
/// it before, as for `Spread`.
pub struct Cutoff<K, V> {
    fx: RefCell<Effects<K, V>>,
    rows: RefCell<Stamped<K, V>>,
    /// The refresh's fixed point.
    quiet: Cell<Quiet>,
}

impl<K: Hash + Eq + Ord + Clone + std::fmt::Debug, V: Clone + PartialEq + std::fmt::Debug> Cutoff<K, V> {
    pub fn new(name: &'static str) -> Self {
        Cutoff { fx: RefCell::new(Effects::new(name)), rows: RefCell::new(Stamped::named(name)), quiet: Cell::default() }
    }

    /// Derives again (by `f`, over all of `ctx`, which holds this cutoff at `me`) every key whose
    /// reads moved, writing the rows that changed: whether any did. Read by no memo. A failure
    /// leaves its key due and is returned once every other due key is derived.
    pub fn refresh_in<C, E>(ctx: &mut C, me: impl Fn(&C) -> &Self, f: impl Fn(&mut C, &K) -> Result<V, E>) -> Result<bool, E> {
        let this = me(ctx);
        if this.quiet.get().holds(this.fx.borrow().idle()) {
            return Ok(false);
        }
        let _u = Unrecorded::start();
        let from = Quiet::begin();
        let due = me(ctx).fx.borrow_mut().due();
        let (mut moved, mut failed) = (false, None);
        for k in due {
            let checking = me(ctx).fx.borrow().checking(&k);
            let mut run = || recorded_frame(|| f(ctx, &k));
            let (out, frame) = if checking { crate::costs::paused(run) } else { run() };
            match me(ctx).fx.borrow_mut().settled(&k, out, frame) {
                Ok(Some((_, now))) => {
                    me(ctx).rows.borrow_mut().insert(k, now);
                    moved = true;
                }
                Ok(None) => {}
                Err(e) => failed = failed.or(Some(e)),
            }
        }
        let mut quiet = me(ctx).quiet.get();
        quiet.ended(from, failed.is_none());
        me(ctx).quiet.set(quiet);
        failed.map_or(Ok(moved), Err)
    }

    /// The keys followed.
    pub fn len(&self) -> usize {
        super::unrecorded(|| self.rows.borrow().len())
    }

    /// Whether no key is followed.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Stops following `k`: its row goes (a reader of it moves), and a later `get_in` derives it
    /// anew.
    pub fn unfollow(&self, k: &K) {
        self.fx.borrow_mut().unwant(k);
        if super::unrecorded(|| self.rows.borrow().get(k).is_some()) {
            self.rows.borrow_mut().remove(k);
        }
    }

    /// Stops following every key `drop` names (`unfollow`).
    pub fn unfollow_where(&self, drop: impl Fn(&K) -> bool) {
        let keys = self.fx.borrow().followed_where(drop);
        for k in &keys {
            self.unfollow(k);
        }
    }

    /// Key `k`'s value, up to date (`refresh_in`, `k` followed from now on): a read of its row
    /// alone.
    pub fn get_in<C, E>(ctx: &mut C, me: impl Fn(&C) -> &Self, k: &K, f: impl Fn(&mut C, &K) -> Result<V, E>) -> Result<V, E> {
        me(ctx).fx.borrow_mut().want(k.clone());
        let failed = Self::refresh_in(ctx, &me, &f).err();
        let row = me(ctx).rows.borrow().get(k).cloned();
        match row {
            // a key just followed whose derivation failed has no row: its failure is the answer
            Some(v) if me(ctx).fx.borrow().settled_value(k) => Ok(v),
            _ => Err(failed.unwrap_or_else(|| unreachable!("a followed key settled without a row"))),
        }
    }
}

impl<K: Hash + Eq + Ord + Clone, V: Clone> Clone for Cutoff<K, V> {
    fn clone(&self) -> Self {
        Cutoff { fx: RefCell::new(self.fx.borrow().clone()), rows: RefCell::new(Stamped::clone(&self.rows.borrow())), quiet: self.quiet.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Stamped;
    use super::*;

    // spec: none (internal: notes/engine.md, Derived values). A reader of a key moves only when
    // that key's value does, not when what it read moved to the same value; a failed derivation
    // is the answer and is tried again.
    #[test]
    fn readers_move_only_with_their_key() {
        let mut m: Stamped<u8, u8> = Stamped::default();
        m.insert(1, 10);
        m.insert(2, 10);
        let c: Cutoff<u8, bool> = Cutoff::new("test cutoff");
        let big = |m: &Stamped<u8, u8>, k: &u8| -> Result<bool, ()> { m.get(k).map(|v| *v > 5).ok_or(()) };
        let mut e: Effects<u8, bool> = Effects::new("test reader");
        e.want(1);
        e.want(2);
        for k in e.due() {
            e.settle(&k, || Cutoff::get_in(&mut &m, |_| &c, &k, |m, k| big(m, k)).unwrap());
        }
        m.insert(1, 20);
        assert!(!Cutoff::refresh_in(&mut &m, |_| &c, |m, k| big(m, k)).unwrap(), "no row moved");
        assert!(e.due().is_empty(), "the rows stayed");
        m.insert(1, 2);
        assert!(Cutoff::refresh_in(&mut &m, |_| &c, |m, k| big(m, k)).unwrap());
        assert_eq!(e.due(), [1], "key 1's row moved, key 2's did not");
        assert_eq!(Cutoff::get_in(&mut &m, |_| &c, &3, |m, k| big(m, k)), Err(()), "no input: the failure");
        m.insert(3, 9);
        assert_eq!(Cutoff::get_in(&mut &m, |_| &c, &3, |m, k| big(m, k)), Ok(true), "tried again");
    }

    // spec: none (internal): a refresh at its fixed point (`Quiet`) returns at once, yet a key
    // wanted since is derived, and a write moves the rows again.
    #[test]
    fn a_quiet_cutoff_derives_what_came_since() {
        let mut m: Stamped<u8, u8> = Stamped::default();
        m.insert(1, 10);
        m.insert(2, 1);
        let c: Cutoff<u8, bool> = Cutoff::new("test cutoff");
        let big = |m: &Stamped<u8, u8>, k: &u8| -> Result<bool, ()> { m.get(k).map(|v| *v > 5).ok_or(()) };
        assert_eq!(Cutoff::get_in(&mut &m, |_| &c, &1, |m, k| big(m, k)), Ok(true));
        for _ in 0..2 {
            assert!(!Cutoff::refresh_in(&mut &m, |_| &c, |m, k| big(m, k)).unwrap());
        }
        assert_eq!(Cutoff::get_in(&mut &m, |_| &c, &2, |m, k| big(m, k)), Ok(false), "wanted since: derived");
        m.insert(1, 2);
        assert!(Cutoff::refresh_in(&mut &m, |_| &c, |m, k| big(m, k)).unwrap(), "written since: derived again");
        assert_eq!(Cutoff::get_in(&mut &m, |_| &c, &1, |m, k| big(m, k)), Ok(false));
    }
}
