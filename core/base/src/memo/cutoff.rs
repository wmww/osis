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
/// it before.
pub struct Cutoff<K, V> {
    fx: RefCell<Effects<K, V>>,
    rows: RefCell<Stamped<K, V>>,
    /// The refresh's fixed point.
    quiet: Cell<Quiet>,
    /// Debug builds: amends per key (`amend_check`).
    #[cfg(debug_assertions)]
    amends: RefCell<std::collections::HashMap<K, u64>>,
}

/// What an amend made of the value handed to it (`Cutoff::refresh_amended_in`).
pub enum Amended<V> {
    /// Brought up to date, and whether it differs from the value handed.
    Kept(V, bool),
    /// Not amendable from it: the value handed, back (`f` runs).
    Not(V),
}

impl<K: Hash + Eq + Ord + Clone + std::fmt::Debug, V: Clone + PartialEq + std::fmt::Debug> Cutoff<K, V> {
    pub fn new(name: &'static str) -> Self {
        Cutoff {
            fx: RefCell::new(Effects::new(name)),
            rows: RefCell::new(Stamped::named(name)),
            quiet: Cell::default(),
            #[cfg(debug_assertions)]
            amends: RefCell::default(),
        }
    }

    /// Derives again (by `f`, over all of `ctx`, which holds this cutoff at `me`) every key whose
    /// reads moved, writing the rows that changed: whether any did. Read by no memo. A failure
    /// leaves its key due and is returned once every other due key is derived.
    pub fn refresh_in<C, E>(ctx: &mut C, me: impl Fn(&C) -> &Self, f: impl Fn(&mut C, &K) -> Result<V, E>) -> Result<bool, E> {
        Self::refresh(ctx, &me, &f, None::<&fn(&mut C, &K, V) -> Result<Amended<V>, E>>)
    }

    /// `refresh_in` for values `amend` can bring up to date from the one kept, handed over owned
    /// (the cutoff holds no other copy meanwhile, so a shared value, `Arc::make_mut`, is edited,
    /// not copied). Its answer is kept if every read of the kept value that moved was only ever
    /// read inside `memo::accounted` and was read so again by this amend, or was made for a part
    /// the amend dropped (`memo::part`, `memo::release`); else `f` runs. So `amend` gives what `f`
    /// would wherever the inputs it reads inside `accounted` moved (an aspect's held bodies:
    /// `retention::bounds::held_writes`). Its other reads are recorded as any derivation's.
    /// Debug builds compare an amended value with a fresh run at the key's amends 1, 4, 16, ...
    pub fn refresh_amended_in<C, E>(ctx: &mut C, me: impl Fn(&C) -> &Self, f: impl Fn(&mut C, &K) -> Result<V, E>, amend: impl Fn(&mut C, &K, V) -> Result<Amended<V>, E>) -> Result<bool, E> {
        Self::refresh(ctx, &me, &f, Some(&amend))
    }

    fn refresh<C, E>(ctx: &mut C, me: &impl Fn(&C) -> &Self, f: &impl Fn(&mut C, &K) -> Result<V, E>, amend: Option<&impl Fn(&mut C, &K, V) -> Result<Amended<V>, E>>) -> Result<bool, E> {
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
            if let Some(amend) = amend.filter(|_| !checking) {
                match Self::amended(ctx, me, f, amend, &k) {
                    Ok(Some(m)) => {
                        moved |= m;
                        continue;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        failed = failed.or(Some(e));
                        continue;
                    }
                }
            }
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

    /// `k`'s kept value amended (`refresh_amended_in`): whether its row moved, `None` when `f`
    /// must run (no value kept, the amend declined, or a moved read it does not account for; the
    /// kept value is back in place then unless the amend changed it).
    fn amended<C, E>(ctx: &mut C, me: &impl Fn(&C) -> &Self, f: &impl Fn(&mut C, &K) -> Result<V, E>, amend: &impl Fn(&mut C, &K, V) -> Result<Amended<V>, E>, k: &K) -> Result<Option<bool>, E> {
        let Some(old) = me(ctx).fx.borrow_mut().take_value(k) else { return Ok(None) };
        // the row's copy: the same value
        drop(me(ctx).rows.borrow_mut().map.remove(k));
        let (out, mut frame) = {
            let _s = crate::costs::span("memo amend");
            recorded_frame(|| amend(ctx, k, old))
        };
        let put_back = |ctx: &mut C, v: V| {
            me(ctx).rows.borrow_mut().map.insert(k.clone(), v.clone());
            me(ctx).fx.borrow_mut().put_value(k, v);
        };
        let (value, changed) = match out {
            Err(e) => {
                // the row goes, as a failed derivation leaves none
                me(ctx).rows.borrow().stamps.wrote(k, false);
                let r = me(ctx).fx.borrow_mut().settled(k, Err(e), frame);
                return r.map(|_| None);
            }
            Ok(Amended::Not(old)) => {
                put_back(ctx, old);
                return Ok(None);
            }
            Ok(Amended::Kept(v, changed)) => (v, changed),
        };
        let old_deps = me(ctx).fx.borrow().deps(k);
        let again = |d: &super::Dep| d.accounted && frame.seen.get(&d.id()).and_then(|&i| frame.deps.get(i)).is_some_and(|n| n.accounted);
        let dropped = |d: &super::Dep| d.part.is_some_and(|p| frame.released.contains(&p));
        if !old_deps.iter().all(|d| d.holds() || again(d) || dropped(d)) {
            // a read it does not account for moved: derived anew (compared with the value kept
            // when the amend changed nothing)
            if !changed {
                put_back(ctx, value);
            }
            return Ok(None);
        }
        // the kept value's reads still rest under it but those of the parts it dropped
        let kept: Vec<super::Dep> = old_deps.into_iter().filter(|d| !dropped(d)).collect();
        for d in kept {
            frame.note(d.id(), d.accounted, d.part, || d.clone());
        }
        #[cfg(debug_assertions)]
        if me(ctx).amend_check(k) {
            let fresh = crate::costs::paused(|| super::unrecorded(|| super::comparing_run(|| f(ctx, k))));
            if let Ok(fresh) = fresh {
                assert!(fresh == value, "cutoff {}: amended {value:?}, a fresh run gives {fresh:?}", me(ctx).fx.borrow().name());
            }
        }
        #[cfg(not(debug_assertions))]
        let _ = f;
        let r = me(ctx).fx.borrow_mut().settled::<E>(k, Ok(value.clone()), frame);
        drop(r);
        let mut rows = me(ctx).rows.borrow_mut();
        if changed {
            rows.stamps.wrote(k, true);
        }
        rows.map.insert(k.clone(), value);
        Ok(Some(changed))
    }

    /// Debug builds: whether `k`'s amend now is one compared with a fresh run (its 1st, 4th,
    /// 16th, ...).
    #[cfg(debug_assertions)]
    fn amend_check(&self, k: &K) -> bool {
        let mut n = self.amends.borrow_mut();
        let n = n.entry(k.clone()).or_default();
        *n += 1;
        super::at_power(*n, 2)
    }

    /// Key `k`'s value, up to date (`refresh_amended_in`, `k` followed from now on): a read of
    /// its row alone.
    pub fn get_amended_in<C, E>(ctx: &mut C, me: impl Fn(&C) -> &Self, k: &K, f: impl Fn(&mut C, &K) -> Result<V, E>, amend: impl Fn(&mut C, &K, V) -> Result<Amended<V>, E>) -> Result<V, E> {
        me(ctx).fx.borrow_mut().want(k.clone());
        let failed = Self::refresh(ctx, &me, &f, Some(&amend)).err();
        Self::row(ctx, &me, k, failed)
    }

    /// Key `k`'s row after a refresh that failed with `failed`.
    fn row<C, E>(ctx: &mut C, me: &impl Fn(&C) -> &Self, k: &K, failed: Option<E>) -> Result<V, E> {
        let row = me(ctx).rows.borrow().get(k).cloned();
        match row {
            // a key just followed whose derivation failed has no row: its failure is the answer
            Some(v) if me(ctx).fx.borrow().settled_value(k) => Ok(v),
            _ => Err(failed.unwrap_or_else(|| unreachable!("a followed key settled without a row"))),
        }
    }

    /// How many rows it holds (unstamped: for counts of what it keeps).
    pub fn rows_held(&self) -> usize {
        self.rows.borrow().map.len()
    }

    /// Stops following `k`: its row goes (a reader of it moves), and a later `get_in` derives it
    /// anew.
    pub fn unfollow(&self, k: &K) {
        self.fx.borrow_mut().unwant(k);
        if super::unrecorded(|| self.rows.borrow().get(k).is_some()) {
            self.rows.borrow_mut().remove(k);
        }
    }

    /// Stops following every key with a row from `from` on while `within` holds (`unfollow`):
    /// O(those).
    pub fn unfollow_from(&self, from: &K, within: impl Fn(&K) -> bool) {
        let keys: Vec<K> = self.rows.borrow().map.range(from..).map(|(k, _)| k).take_while(|k| within(k)).cloned().collect();
        for k in &keys {
            self.unfollow(k);
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
        Self::row(ctx, &me, k, failed)
    }
}

impl<K: Hash + Eq + Ord + Clone, V: Clone> Clone for Cutoff<K, V> {
    fn clone(&self) -> Self {
        Cutoff {
            fx: RefCell::new(self.fx.borrow().clone()),
            rows: RefCell::new(Stamped::clone(&self.rows.borrow())),
            quiet: self.quiet.clone(),
            #[cfg(debug_assertions)]
            amends: RefCell::new(self.amends.borrow().clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Stamped;
    use super::*;
    use std::cell::Cell;

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

    /// The sum of the contents of the bodies listed, with each body's (`amended`).
    #[derive(Clone, Debug, PartialEq)]
    struct Summed {
        bodies: std::collections::BTreeMap<u8, u64>,
        sum: u64,
    }

    type World = (Stamped<u8, Vec<u8>>, Stamped<u8, u64>, Stamped<u8, u64>);

    // spec: none (internal: notes/engine.md, Derived values). A kept value no longer holding is
    // amended, handed over as the only copy, when each read of it that moved was only ever read
    // inside `accounted` and is again by the amend, or was read for a part the amend dropped; a
    // move of any other read derives it anew, as does an amend declining.
    #[test]
    fn an_amend_is_kept_only_over_what_it_accounts_for() {
        use std::sync::Arc;
        let c: Cutoff<u8, Arc<Summed>> = Cutoff::new("test amended");
        let (unique, runs) = (Cell::new(false), Cell::new(0u64));
        let ask = |w: &World| {
            Cutoff::get_amended_in(
                &mut &*w,
                |_| &c,
                &0,
                |w, _| {
                    if !super::super::comparing() {
                        runs.set(runs.get() + 1);
                    }
                    let ids = super::super::accounted(|| w.0.get(&0).cloned().unwrap_or_default());
                    let bodies: std::collections::BTreeMap<u8, u64> = ids.iter().map(|i| (*i, super::super::part(i, || w.1.get(i).copied().unwrap_or(0)))).collect();
                    let sum = bodies.values().sum::<u64>() + w.2.get(&0).copied().unwrap_or(0);
                    Ok::<_, std::convert::Infallible>(Arc::new(Summed { bodies, sum }))
                },
                |w, _, mut old| {
                    unique.set(Arc::get_mut(&mut old).is_some());
                    let ids = super::super::accounted(|| w.0.get(&0).cloned().unwrap_or_default());
                    if ids.is_empty() {
                        return Ok(Amended::Not(old));
                    }
                    let v = Arc::make_mut(&mut old);
                    let gone: Vec<u8> = v.bodies.keys().filter(|i| !ids.contains(i)).copied().collect();
                    for i in &gone {
                        super::super::release(i);
                        v.sum -= v.bodies.remove(i).unwrap_or(0);
                    }
                    let mut changed = !gone.is_empty();
                    let new: Vec<u8> = ids.iter().filter(|i| !v.bodies.contains_key(i)).copied().collect();
                    for i in &new {
                        let x = super::super::part(i, || w.1.get(i).copied().unwrap_or(0));
                        v.bodies.insert(*i, x);
                        v.sum += x;
                        changed = true;
                    }
                    Ok(Amended::Kept(old, changed))
                },
            )
            .unwrap()
            .sum
        };
        let ran = || {
            let amends = crate::costs::take().iter().filter(|x| x.0 == "memo amend").map(|x| x.2).sum::<u64>();
            [runs.replace(0), amends]
        };
        let mut w: World = Default::default();
        w.0.insert(0, vec![1]);
        w.1.insert(1, 5);
        w.1.insert(2, 7);
        w.2.insert(0, 100);
        crate::costs::take();
        assert_eq!(ask(&w), 105);
        assert_eq!(ran(), [1, 0]);
        w.0.insert(0, vec![1, 2]);
        assert_eq!(ask(&w), 112, "a body listed");
        assert_eq!(ran(), [0, 1]);
        assert!(unique.get(), "the amend held the only copy");
        w.0.insert(0, vec![2]);
        w.1.remove(&1);
        assert_eq!(ask(&w), 107, "a body gone, its own read moved with it");
        assert_eq!(ran(), [0, 1]);
        w.1.insert(2, 8);
        assert_eq!(ask(&w), 108, "a listed body's read moved");
        assert_eq!(ran(), [1, 1]);
        w.2.insert(0, 200);
        w.0.insert(0, vec![2, 3]);
        assert_eq!(ask(&w), 208, "a read not accounted for moved too");
        assert_eq!(ran(), [1, 1]);
        w.0.insert(0, Vec::new());
        assert_eq!(ask(&w), 200, "the amend declined");
        assert_eq!(ran(), [1, 1]);
    }
}
