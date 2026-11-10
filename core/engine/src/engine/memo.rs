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
#[derive(Debug, Default)]
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
pub(crate) struct Stamps(Arc<Mutex<Table>>);

impl Stamps {
    /// Key `k` was written (`present`) or removed.
    pub(crate) fn wrote<Q: Hash + ?Sized>(&mut self, k: &Q, present: bool) {
        let mut t = lock(&self.0);
        t.ver += 1;
        let v = t.ver;
        if present {
            t.keys.insert(hash(k), v);
        } else if t.keys.remove(&hash(k)).is_some() {
            t.absent = v;
        }
    }

    /// The container changed in a way no key names.
    pub(crate) fn wrote_all(&mut self) {
        let mut t = lock(&self.0);
        t.ver += 1;
        t.absent = t.ver;
        t.keys.clear();
    }

    /// Key `k` is read: the memo computing, if any, depends on it.
    pub(crate) fn read<Q: Hash + ?Sized>(&self, k: &Q) {
        if RECORDING.load(Ordering::Relaxed) != 0 {
            self.record(Some(hash(k)));
        }
    }

    /// The whole container is read.
    pub(crate) fn read_all(&self) {
        if RECORDING.load(Ordering::Relaxed) != 0 {
            self.record(None);
        }
    }

    /// How many changes the container has seen.
    pub(crate) fn changes(&self) -> u64 {
        lock(&self.0).ver
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

/// Runs `f` and returns what it read.
fn recorded<T>(f: impl FnOnce() -> T) -> (T, Arc<[Dep]>) {
    struct Open;
    impl Drop for Open {
        fn drop(&mut self) {
            RECORDING.fetch_sub(1, Ordering::Relaxed);
        }
    }
    RECORDING.fetch_add(1, Ordering::Relaxed);
    let _open = Open;
    FRAMES.with(|fr| fr.borrow_mut().push(Frame::default()));
    // a panic leaves the frame: the thread's next memo records above it and pops its own
    let out = f();
    let frame = FRAMES.with(|fr| fr.borrow_mut().pop()).unwrap_or_default();
    (out, frame.deps.into())
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
pub(crate) struct Memo<K, V> {
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
    pub(crate) fn new(name: &'static str) -> Self {
        Memo { name, entries: RefCell::new(HashMap::new()), kept: Cell::new(0) }
    }

    /// The value of `f` for `k`: the one kept while nothing it read has changed.
    pub(crate) fn get(&self, k: &K, f: impl Fn() -> V) -> V {
        match Self::get_in(&mut &*self, |me| *me, k, |_| Ok::<V, std::convert::Infallible>(f())) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// `get` for a function that needs all of `ctx` and may fail (one running a transaction of
    /// the engine holding this memo, which `memo` finds in `ctx`). A failure is not kept.
    pub(crate) fn get_in<C, E>(ctx: &mut C, memo: impl Fn(&C) -> &Self, k: &K, f: impl Fn(&mut C) -> Result<V, E>) -> Result<V, E> {
        if let Some((value, deps, check)) = memo(ctx).kept(k) {
            if check {
                // a fresh run that fails compares nothing
                if let Ok(fresh) = crate::costs::paused(|| recorded(|| f(ctx)).0) {
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
        Stamped { map: self.map.clone(), stamps: Stamps::default() }
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

/// A value outside the journal whose reads (`get`) and changes (`set`) are stamped
/// (`Core::account`).
#[derive(Debug, Default)]
pub struct Tracked<T> {
    value: T,
    stamps: Stamps,
}

impl<T: Copy> Tracked<T> {
    pub fn get(&self) -> T {
        self.stamps.read_all();
        self.value
    }
    pub fn set(&mut self, value: T) {
        self.stamps.wrote_all();
        self.value = value;
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
