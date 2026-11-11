//! Derived values that depend on exactly what they read (issues/derived-state-recomputed.md).
//!
//! Every mutable fact a derivation may read sits in a container that stamps its changes
//! (`Stamps`: the journaled indexes in `journal`, the held set and timelines in `held`,
//! `Stamped` maps, `Tracked` values). A read
//! through such a container while a `Memo` computes records the stamp it saw; the memo's answer
//! holds while every stamp it saw is the current one. So a memo has no key to pick and no
//! invalidation to call: a write anywhere reaches exactly the memos that read what it changed.
//! A container's `Deref` counts as a read of the whole container (any change of it moves the
//! memo), `get` and `contains` as a read of one key.
//!
//! What a memo's function reads elsewhere (a field of `Core` in no such container, the store)
//! must be immutable or stamped by hand (`Stamps::wrote`); debug builds compare a hit with a
//! fresh run to find a read that was missed.

use std::borrow::Borrow;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// The change stamps of one container: one per key present, one for every absent key, one for
/// the whole.
#[derive(Clone, Debug, Default)]
struct Table {
    /// Counts changes: the whole container's stamp.
    ver: u64,
    /// `ver` at the last removal: the stamp of every key absent (so an absent key costs nothing
    /// to keep; a removal moves what read any absent key).
    absent: u64,
    /// `ver` at the last write of each key present, by the key's hash. Two keys sharing a hash
    /// share a stamp: a write of one moves what read the other, never the reverse of that.
    keys: HashMap<u64, u64>,
}

impl Table {
    fn stamp(&self, key: Option<u64>) -> u64 {
        match key {
            None => self.ver,
            Some(h) => self.keys.get(&h).copied().unwrap_or(self.absent),
        }
    }
}

fn lock(t: &Mutex<Table>) -> MutexGuard<'_, Table> {
    t.lock().unwrap_or_else(|e| e.into_inner())
}

fn hash<Q: Hash + ?Sized>(k: &Q) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    k.hash(&mut h);
    h.finish()
}

/// A container's change stamps, owned by the container: its writes call `wrote`, its reads
/// `read`. Dropped with the container, after which nothing that read it holds.
#[derive(Debug, Default)]
pub struct Stamps(Arc<Mutex<Table>>);

impl Stamps {
    /// Key `k` was written (`present`) or removed.
    pub fn wrote<Q: Hash + ?Sized>(&mut self, k: &Q, present: bool) {
        let mut t = lock(&self.0);
        t.ver += 1;
        let v = t.ver;
        if present {
            t.keys.insert(hash(k), v);
        } else {
            // every removal moves the absent stamp: a key present with no stamp of its own (one
            // there before the stamps were, or since `wrote_all`) was read at it
            t.keys.remove(&hash(k));
            t.absent = v;
        }
    }

    /// The container changed, but no key's value: moves only what read it whole.
    pub fn moved(&mut self) {
        lock(&self.0).ver += 1;
    }

    /// The container changed in a way no key names.
    pub fn wrote_all(&mut self) {
        let mut t = lock(&self.0);
        t.ver += 1;
        t.absent = t.ver;
        t.keys.clear();
    }

    /// Counts the container's changes: equal at two times, nothing in it changed between.
    pub fn changes(&self) -> u64 {
        lock(&self.0).ver
    }

    /// Key `k` is read: the memo computing, if any, depends on it.
    pub fn read<Q: Hash + ?Sized>(&self, k: &Q) {
        if RECORDING.load(Ordering::Relaxed) != 0 {
            self.record(Some(hash(k)));
        }
    }

    /// The whole container is read.
    pub fn read_all(&self) {
        if RECORDING.load(Ordering::Relaxed) != 0 {
            self.record(None);
        }
    }

    fn record(&self, key: Option<u64>) {
        FRAMES.with(|f| {
            let mut f = f.borrow_mut();
            let Some(top) = f.last_mut() else { return };
            if top.seen.insert((Arc::as_ptr(&self.0) as usize, key)) {
                let seen = lock(&self.0).stamp(key);
                top.deps.push(Dep { table: self.0.clone(), key, seen });
            }
        });
    }
}

/// A table of the world being copied (`osis_base::copying`): the copy's one table for it, its
/// stamps as they are; outside a copy, a table of its own.
fn copied(t: &Arc<Mutex<Table>>) -> Arc<Mutex<Table>> {
    osis_base::copying::remap(t, |m| Mutex::new(lock(m).clone()))
}

/// A copy's stamps: the same stamps on a table of the copy's own (`copied`), so the copied memos
/// that read the original's hold in the copy exactly while they would in the original.
impl Clone for Stamps {
    fn clone(&self) -> Stamps {
        Stamps(copied(&self.0))
    }
}

impl Drop for Stamps {
    fn drop(&mut self) {
        let mut t = lock(&self.0);
        t.ver = u64::MAX;
        t.absent = u64::MAX;
        t.keys.clear();
    }
}

/// One thing a memo read, and the stamp it had.
#[derive(Clone, Debug)]
struct Dep {
    table: Arc<Mutex<Table>>,
    key: Option<u64>,
    seen: u64,
}

impl Dep {
    fn holds(&self) -> bool {
        lock(&self.table).stamp(self.key) == self.seen
    }
}

/// What the memo computing on this thread has read so far.
#[derive(Default)]
struct Frame {
    deps: Vec<Dep>,
    seen: HashSet<(usize, Option<u64>)>,
}

/// Memos computing, on any thread: reads look at their thread's frames only while it is not 0.
static RECORDING: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static FRAMES: RefCell<Vec<Frame>> = const { RefCell::new(Vec::new()) };
}

/// A frame of reads opened on this thread (`recorded`, `unrecorded`): reads while it is open
/// land in it. Dropped, it cuts the stack back to the frames below it, so an unwind through it
/// leaves no frame for a later read to land in.
struct Open(usize);

impl Open {
    fn start() -> Open {
        RECORDING.fetch_add(1, Ordering::Relaxed);
        Open(FRAMES.with(|fr| {
            let mut fr = fr.borrow_mut();
            fr.push(Frame::default());
            fr.len() - 1
        }))
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        RECORDING.fetch_sub(1, Ordering::Relaxed);
        FRAMES.with(|fr| fr.borrow_mut().truncate(self.0));
    }
}

/// While held, what this thread reads goes to no memo computing (`unrecorded`). With no memo
/// computing on this thread it opens nothing, so its reads cost what any read outside a memo does.
pub struct Unrecorded {
    _open: Option<Open>,
}

impl Unrecorded {
    pub fn start() -> Unrecorded {
        Unrecorded { _open: FRAMES.with(|fr| !fr.borrow().is_empty()).then(Open::start) }
    }
}

/// Runs `f` and returns what it read.
fn recorded<T>(f: impl FnOnce() -> T) -> (T, Arc<[Dep]>) {
    let _open = Open::start();
    let out = f();
    let frame = FRAMES.with(|fr| fr.borrow_mut().pop()).unwrap_or_default();
    (out, frame.deps.into())
}

/// Runs `f` without the memo computing, if any, depending on what it reads: for a debug check
/// beside a read, so the check's own reads do not cover a read the code missed, and for the
/// work a transaction does around its function (`Engine::run`), which a memo's answer is not.
pub fn unrecorded<T>(f: impl FnOnce() -> T) -> T {
    let _open = Unrecorded::start();
    f()
}

/// The memo computing on this thread, if any, depends on `deps` too (it read a memo's answer).
fn depend(deps: &[Dep]) {
    if RECORDING.load(Ordering::Relaxed) == 0 {
        return;
    }
    FRAMES.with(|f| {
        let mut f = f.borrow_mut();
        let Some(top) = f.last_mut() else { return };
        for d in deps {
            if top.seen.insert((Arc::as_ptr(&d.table) as usize, d.key)) {
                top.deps.push(d.clone());
            }
        }
    });
}

#[derive(Clone)]
struct Entry<V> {
    value: V,
    deps: Arc<[Dep]>,
    /// Debug builds: hits so far (`Memo::get` compares at powers of four).
    #[cfg(debug_assertions)]
    hits: u64,
}

/// A function of `K` and of what it reads through stamped containers, computed again only when
/// something it read changed. A memo read inside another's computation passes on what it read.
///
/// An answer no longer asked for stays until the memo has doubled since entries were last
/// checked (`SWEEP`), so a memo holds at most twice what is current plus what was asked since.
pub struct Memo<K, V> {
    /// Names the memo in costs (`costs::span`, one per computation) and failures.
    name: &'static str,
    entries: RefCell<HashMap<K, Entry<V>>>,
    /// Entries kept by the last sweep.
    kept: Cell<usize>,
}

/// A memo checks every entry and drops those that no longer hold when it has grown to `SWEEP`
/// times what the last check kept. Performance switch: at 1 every new entry checks them all;
/// at infinity an answer nobody asks for again is never dropped.
const SWEEP: usize = 2;

impl<K: Hash + Eq + Clone, V: Clone + PartialEq + std::fmt::Debug> Memo<K, V> {
    pub fn new(name: &'static str) -> Self {
        Memo { name, entries: RefCell::new(HashMap::new()), kept: Cell::new(0) }
    }

    /// The value of `f` for `k`: the one kept while nothing it read has changed.
    pub fn get(&self, k: &K, f: impl Fn() -> V) -> V {
        match Self::get_in(&mut &*self, |me| *me, k, |_| Ok::<V, std::convert::Infallible>(f())) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// `get` for a function that needs all of `ctx` and may fail (one running a transaction of
    /// the engine holding this memo, which `memo` finds in `ctx`). A failure is not kept.
    pub fn get_in<C, E>(ctx: &mut C, memo: impl Fn(&C) -> &Self, k: &K, f: impl Fn(&mut C) -> Result<V, E>) -> Result<V, E> {
        Self::get_checked_in(ctx, memo, k, &f, &f)
    }

    /// `get_in` whose debug comparison runs `fresh`, which gives what `f` gives and changes
    /// nothing: for an `f` with effects where its answer is not kept (one that writes when
    /// something is due and fails so, `SyncEngine::rotations`).
    pub fn get_checked_in<C, E>(ctx: &mut C, memo: impl Fn(&C) -> &Self, k: &K, f: impl Fn(&mut C) -> Result<V, E>, fresh: impl Fn(&mut C) -> Result<V, E>) -> Result<V, E> {
        if let Some((value, deps, check)) = memo(ctx).kept(k) {
            if check {
                // a fresh run that fails compares nothing
                if let Ok(fresh) = crate::costs::paused(|| unrecorded(|| fresh(ctx))) {
                    assert!(fresh == value, "memo {}: kept {value:?}, a fresh run gives {fresh:?} (a read no stamp covers)", memo(ctx).name);
                }
            }
            depend(&deps);
            return Ok(value);
        }
        let _s = crate::costs::span(memo(ctx).name);
        let (value, deps) = recorded(|| f(ctx));
        // what a failure read is read by whoever asked, too
        depend(&deps);
        let value = value?;
        memo(ctx).keep(k, &value, deps);
        Ok(value)
    }

    /// The answer kept for `k` while it holds, read by a writer about to change what it was read
    /// from (`amend`): nothing computing depends on it.
    pub fn held(&self, k: &K) -> Option<V> {
        self.entries.borrow().get(k).filter(|e| e.deps.iter().all(Dep::holds)).map(|e| e.value.clone())
    }

    /// Keeps `value` as `k`'s answer at the stamps of now. For a writer that held `k`'s answer
    /// (`held`), changed what it was read from and knows what a fresh run gives after that
    /// (a state decoded once and patched by each join costs the join, not the state). Nothing
    /// is kept if `k` has no entry. Debug builds compare it with a fresh run like any hit.
    pub fn amend(&self, k: &K, value: V) {
        if let Some(e) = self.entries.borrow_mut().get_mut(k) {
            e.value = value;
            e.deps = e.deps.iter().map(|d| Dep { table: d.table.clone(), key: d.key, seen: lock(&d.table).stamp(d.key) }).collect();
        }
    }

    /// The answer kept for `k` if it still holds, what it read, and whether to compare it with
    /// a fresh run (debug builds: at its hits 1, 4, 16, ...).
    fn kept(&self, k: &K) -> Option<(V, Arc<[Dep]>, bool)> {
        let mut entries = self.entries.borrow_mut();
        let e = entries.get_mut(k).filter(|e| e.deps.iter().all(Dep::holds))?;
        #[cfg(debug_assertions)]
        let check = {
            e.hits += 1;
            e.hits.is_power_of_two() && e.hits.trailing_zeros() % 2 == 0
        };
        #[cfg(not(debug_assertions))]
        let check = false;
        Some((e.value.clone(), e.deps.clone(), check))
    }

    fn keep(&self, k: &K, value: &V, deps: Arc<[Dep]>) {
        let mut entries = self.entries.borrow_mut();
        entries.insert(k.clone(), Entry {
            value: value.clone(),
            deps,
            #[cfg(debug_assertions)]
            hits: 0,
        });
        if entries.len() >= SWEEP.saturating_mul(self.kept.get().max(1)) {
            entries.retain(|_, e| e.deps.iter().all(Dep::holds));
            self.kept.set(entries.len());
        }
    }

    /// Entries held (tests).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.borrow().len()
    }
}

/// Inside a world copy (`osis_base::copying`) the copy keeps every answer, its reads moved to
/// the copy's tables, so it computes again exactly when the original would; outside one it
/// starts empty (its answers' reads are the original's).
impl<K: Hash + Eq + Clone, V: Clone> Clone for Memo<K, V> {
    fn clone(&self) -> Self {
        let entries = match osis_base::copying::in_copy() {
            true => self.entries.borrow().iter().map(|(k, e)| (k.clone(), Entry { deps: e.deps.iter().map(|d| Dep { table: copied(&d.table), key: d.key, seen: d.seen }).collect(), ..e.clone() })).collect(),
            false => HashMap::new(),
        };
        let kept = if osis_base::copying::in_copy() { self.kept.get() } else { 0 };
        Memo { name: self.name, entries: RefCell::new(entries), kept: Cell::new(kept) }
    }
}

/// A map outside the journal whose reads and writes are stamped (`Core::key_actors`,
/// `Core::accounts`).
#[derive(Debug)]
pub struct Stamped<K, V> {
    map: BTreeMap<K, V>,
    stamps: Stamps,
}

impl<K, V> Default for Stamped<K, V> {
    fn default() -> Self {
        Stamped { map: BTreeMap::new(), stamps: Stamps::default() }
    }
}

impl<K: Ord + Clone, V: Clone> Clone for Stamped<K, V> {
    fn clone(&self) -> Self {
        Stamped { map: self.map.clone(), stamps: self.stamps.clone() }
    }
}

impl<K, V> Deref for Stamped<K, V> {
    type Target = BTreeMap<K, V>;
    fn deref(&self) -> &BTreeMap<K, V> {
        self.stamps.read_all();
        &self.map
    }
}

impl<'a, K, V> IntoIterator for &'a Stamped<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = std::collections::btree_map::Iter<'a, K, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.stamps.read_all();
        self.map.iter()
    }
}

impl<K: Ord + Hash, V> Stamped<K, V> {
    pub fn get<Q: Ord + Hash + ?Sized>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        self.stamps.read(k);
        self.map.get(k)
    }
    pub fn contains_key<Q: Ord + Hash + ?Sized>(&self, k: &Q) -> bool
    where
        K: Borrow<Q>,
    {
        self.stamps.read(k);
        self.map.contains_key(k)
    }
    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        self.stamps.wrote(&k, true);
        self.map.insert(k, v)
    }
    pub fn remove(&mut self, k: &K) -> Option<V> {
        self.stamps.wrote(k, false);
        self.map.remove(k)
    }
}

/// A clock outside the journal (node-sync's time) whose readers say how long their answer
/// holds: `get` is a read of the time itself (any move of it moves the reader), `until(t)` of
/// the time only as far as `t` (the reader's answer holds while the clock is before `t`). A move
/// back moves every reader: an answer judged later need not hold earlier.
#[derive(Clone, Debug, Default)]
pub struct Clock {
    now: u64,
    stamps: Stamps,
    /// The `until` times read and not passed yet.
    ahead: RefCell<std::collections::BTreeSet<u64>>,
}

impl Clock {
    pub fn get(&self) -> u64 {
        self.stamps.read_all();
        self.now
    }

    /// The time, for a reader whose answer holds until `t` (`None`: at every later time).
    pub fn until(&self, t: Option<u64>) -> u64 {
        let k = t.unwrap_or(u64::MAX);
        self.stamps.read(&k);
        if t.is_some() {
            self.ahead.borrow_mut().insert(k);
        }
        self.now
    }

    pub fn set(&mut self, now: u64) {
        if now == self.now {
            return;
        }
        if now < self.now {
            self.stamps.wrote_all();
            self.ahead.get_mut().clear();
        } else {
            let later = self.ahead.get_mut().split_off(&now.saturating_add(1));
            for t in std::mem::replace(self.ahead.get_mut(), later) {
                self.stamps.wrote(&t, true);
            }
            // the time itself moved (`get`), and every `until` at or before `now` passed
            self.stamps.moved();
        }
        self.now = now;
    }
}

/// A value outside the journal whose reads (`get`) and changes (`set`) are stamped
/// (`Core::account`).
#[derive(Clone, Debug, Default)]
pub struct Tracked<T> {
    value: T,
    stamps: Stamps,
}

impl<T: Copy + PartialEq> Tracked<T> {
    pub fn get(&self) -> T {
        self.stamps.read_all();
        self.value
    }
    /// Sets the value; a change only if it differs.
    pub fn set(&mut self, value: T) {
        if self.value != value {
            self.stamps.wrote_all();
            self.value = value;
        }
    }
}

/// A set outside the journal whose reads and writes are stamped (node-sync's state).
#[derive(Clone, Debug)]
pub struct StampedSet<T> {
    set: std::collections::BTreeSet<T>,
    stamps: Stamps,
}

impl<T> Default for StampedSet<T> {
    fn default() -> Self {
        StampedSet { set: Default::default(), stamps: Stamps::default() }
    }
}

impl<T> Deref for StampedSet<T> {
    type Target = std::collections::BTreeSet<T>;
    fn deref(&self) -> &std::collections::BTreeSet<T> {
        self.stamps.read_all();
        &self.set
    }
}

impl<T: Ord + Hash> StampedSet<T> {
    pub fn contains(&self, t: &T) -> bool {
        self.stamps.read(t);
        self.set.contains(t)
    }
    pub fn insert(&mut self, t: T) -> bool {
        self.stamps.wrote(&t, true);
        self.set.insert(t)
    }
    pub fn remove(&mut self, t: &T) -> bool {
        self.stamps.wrote(t, false);
        self.set.remove(t)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::engine::journal::{JMap, JSet, Journaled};

    fn runs(name: &'static str) -> u64 {
        crate::costs::take().iter().filter(|x| x.0 == name).map(|x| x.2).sum()
    }

    // spec: none (internal: notes/engine.md, Derived values). A memo runs again exactly when
    // something it read changed: a key it read, present or absent, or any key of a container it
    // walked; an undo counts as a change; another key's write does not.
    #[test]
    fn a_memo_runs_again_only_when_what_it_read_changed() {
        let mut m: JMap<u8, u8> = JMap::default();
        let mut s: JSet<u8> = JSet::default();
        let memo: Memo<u8, Option<u8>> = Memo::new("test memo");
        let ask = |m: &JMap<u8, u8>, k: u8| memo.get(&k, || m.get(&k).copied());
        m.insert(1, 10);
        crate::costs::take();
        assert_eq!(ask(&m, 1), Some(10));
        assert_eq!(ask(&m, 2), None);
        assert_eq!(runs("test memo"), 2);
        assert_eq!((ask(&m, 1), ask(&m, 2)), (Some(10), None));
        assert_eq!(runs("test memo"), 0, "asked again, nothing changed");
        m.insert(3, 30);
        s.insert(1);
        assert_eq!((ask(&m, 1), ask(&m, 2)), (Some(10), None));
        assert_eq!(runs("test memo"), 0, "another key and another container changed");
        m.insert(2, 20);
        assert_eq!((ask(&m, 1), ask(&m, 2)), (Some(10), Some(20)));
        assert_eq!(runs("test memo"), 1, "an absent key read came");
        m.commit();
        let mark = m.mark();
        m.insert(1, 11);
        assert_eq!(ask(&m, 1), Some(11));
        m.rollback_to(mark);
        assert_eq!(ask(&m, 1), Some(10));
        assert_eq!(runs("test memo"), 2, "a write and its undo each move the key");
        m.remove(&3);
        assert_eq!(ask(&m, 1), Some(10));
        assert_eq!(runs("test memo"), 0, "another key left");
        // a walk reads the whole container
        let count: Memo<(), usize> = Memo::new("test count");
        let n = |s: &JSet<u8>| count.get(&(), || s.len());
        assert_eq!((n(&s), n(&s)), (1, 1));
        assert_eq!(runs("test count"), 1);
        s.insert(2);
        assert_eq!(n(&s), 2);
        assert_eq!(runs("test count"), 1);
    }

    // spec: none (internal). A key present with no stamp of its own (there before the stamps
    // were, or since the container was stamped whole) is read at the absent stamp: its removal
    // moves what read it.
    #[test]
    fn removing_a_key_without_a_stamp_moves_its_readers() {
        let mut stamps = Stamps::default();
        let there = std::cell::Cell::new(true);
        stamps.wrote_all();
        let memo: Memo<u8, bool> = Memo::new("test unstamped");
        let ask = |stamps: &Stamps| {
            memo.get(&1, || {
                stamps.read(&1u8);
                there.get()
            })
        };
        assert!(ask(&stamps));
        there.set(false);
        stamps.wrote(&1u8, false);
        assert!(!ask(&stamps), "the removal of a key read without a stamp");
    }

    // spec: none (internal). A clock read whole moves its reader at every move; read until `t`,
    // only when it reaches `t` (not a millisecond before); a move back moves every reader. A
    // forward move keeps no stamp of its own (a long run keeps no entry per time set).
    #[test]
    fn the_clock_moves_readers_whole_or_at_their_horizon() {
        let mut clock = Clock::default();
        clock.set(100);
        let (whole, until, ever): (Memo<(), u64>, Memo<(), u64>, Memo<(), u64>) = (Memo::new("test whole"), Memo::new("test until"), Memo::new("test ever"));
        let ask = |c: &Clock| (whole.get(&(), || c.get()), until.get(&(), || u64::from(c.until(Some(200)) >= 200)), ever.get(&(), || c.until(None).min(1)));
        let ran = || {
            let c = crate::costs::take();
            let n = |name: &str| c.iter().filter(|x| x.0 == name).map(|x| x.2).sum::<u64>();
            (n("test whole"), n("test until"), n("test ever"))
        };
        crate::costs::take();
        assert_eq!(ask(&clock), (100, 0, 1));
        clock.set(199);
        assert_eq!(ask(&clock), (199, 0, 1), "before its horizon an `until` reader holds");
        assert_eq!(ran(), (2, 1, 1));
        clock.set(200);
        assert_eq!(ask(&clock), (200, 1, 1), "at its horizon it moves");
        assert_eq!(ran(), (1, 1, 0));
        clock.set(150);
        assert_eq!(ask(&clock), (150, 0, 1), "a move back moves every reader");
        assert_eq!(ran(), (1, 1, 1));
        for t in 151..1000 {
            clock.set(t);
        }
        assert!(lock(&clock.stamps.0).keys.len() <= 1, "keys kept: {}", lock(&clock.stamps.0).keys.len());
    }

    // spec: none (internal). A memo read inside another passes on what it read; a container
    // dropped holds nothing that read it; a memo drops answers that no longer hold as it grows.
    #[test]
    fn memos_nest_and_forget() {
        let mut m: JMap<u8, u8> = JMap::default();
        m.insert(1, 1);
        let inner: Memo<u8, u8> = Memo::new("test inner");
        let outer: Memo<u8, u8> = Memo::new("test outer");
        let ask = |m: &JMap<u8, u8>| outer.get(&1, || inner.get(&1, || m.get(&1).copied().unwrap_or(0)) + 1);
        crate::costs::take();
        assert_eq!((ask(&m), ask(&m)), (2, 2));
        assert_eq!((runs("test outer"), ), (1, ));
        m.insert(1, 5);
        assert_eq!(ask(&m), 6);
        // the inner answer was kept when the outer one was asked again after a change elsewhere
        let mut other: JMap<u8, u8> = JMap::default();
        other.insert(1, 9);
        assert_eq!(ask(&m), 6);
        let fresh: JMap<u8, u8> = JMap::default();
        drop(m);
        assert_eq!(ask(&fresh), 1, "the container it read is gone");
        let grow: Memo<u8, u8> = Memo::new("test grow");
        let mut t: JMap<u8, u8> = JMap::default();
        for k in 0..100 {
            t.insert(k, k);
            grow.get(&k, || t.len() as u8);
        }
        assert!(grow.len() <= 2, "answers that no longer hold are dropped: {}", grow.len());
    }
}
