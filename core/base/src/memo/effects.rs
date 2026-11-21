//! Work in proportion to change (notes/engine.md, Derived values): `Effects` follows keys whose
//! values a function derives, and tells which may have moved from the containers' logs of their
//! writes (`Table::log`), never by asking every key; `Feed` is one reader's cursor over the keys
//! a container added.

#[cfg(debug_assertions)]
use super::at_power;
use super::{Dep, Ids, Logged, Table, bucket, copied, lock, recorded_frame};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

/// A function's value per followed key, acted on by its owner, with what each last value read.
/// `settle(k, f)` runs `f` recording its reads (a memo's answer read inside counts as what that
/// memo read) and indexes each (container, key) read to `k`; `due()` reads the logs of the
/// containers read since its last call and gives the followed keys whose last value read a stamp
/// written since. So `due` costs the writes since the last call times their readers here, never
/// the keys followed; a container nobody follows logs nothing.
pub struct Effects<K, V> {
    name: &'static str,
    followed: HashMap<K, Followed<V>>,
    /// Want order: `due` gives keys in it, so a run is the same whatever the hashes.
    seq: u64,
    /// Followed keys known due: wanted and not settled since, given by `due` and not settled
    /// since, or moved while their settle read.
    pending: HashSet<K>,
    /// What the followed keys' last values read, per container (`Arc::as_ptr` of its table).
    tables: HashMap<usize, Indexed<K>, Ids>,
    #[cfg(debug_assertions)]
    checks: Checks<K>,
}

/// Debug builds, on a thread that turned them on (`memo::check_effects`): keys `due` gives
/// though nothing they read moved, after the due ones, so their settle compares the value with
/// the one kept, to find a read the function made without its stamp (a field in no container,
/// the time read unstamped). Two schedules, by powers, as `Memo`'s comparison: a key whose
/// container's log named another key of it, at its 1st, 4th, 16th, ... such `due` (a missed
/// read that moves with a stamped one); every followed key at the 16th, 256th, ... `due` (one
/// that moves alone).
#[cfg(debug_assertions)]
#[derive(Clone)]
struct Checks<K> {
    /// `due` calls.
    calls: u64,
    /// The keys the last `due` gave to compare.
    keys: HashSet<K>,
}

#[cfg(debug_assertions)]
impl<K> Default for Checks<K> {
    fn default() -> Self {
        Checks { calls: 0, keys: HashSet::new() }
    }
}

struct Followed<V> {
    seq: u64,
    /// The value last settled (`None`: never since it was wanted).
    value: Option<V>,
    deps: Vec<Dep>,
    /// Debug builds: `due` calls that found a container it read written, its own reads not
    /// (`Checks`).
    #[cfg(debug_assertions)]
    moved: u64,
}

impl<V> Followed<V> {
    fn new(seq: u64, value: Option<V>, deps: Vec<Dep>) -> Self {
        Followed {
            seq,
            value,
            deps,
            #[cfg(debug_assertions)]
            moved: 0,
        }
    }
}

/// The followed keys that read one container, and this reader's mark in its log.
struct Indexed<K> {
    table: Arc<Mutex<Table>>,
    /// The log is read up to here (`Table::read_log`).
    at: u64,
    /// Keys that read the container whole.
    whole: HashSet<K>,
    /// Keys that read each key of it (by hash), and the hashes read at their bucket's absent
    /// stamp, by bucket: a removal moves those of its bucket.
    keys: HashMap<u64, HashSet<K>, Ids>,
    buckets: HashMap<usize, HashSet<u64, Ids>, Ids>,
    /// Reads indexed here: the mark goes with the last.
    reads: usize,
}

impl<K> Drop for Indexed<K> {
    fn drop(&mut self) {
        lock(&self.table).unmark(self.at);
    }
}

impl<K: Hash + Eq + Clone + std::fmt::Debug, V: Clone + PartialEq + std::fmt::Debug> Effects<K, V> {
    pub fn new(name: &'static str) -> Self {
        Effects {
            name,
            followed: HashMap::new(),
            seq: 0,
            pending: HashSet::new(),
            tables: HashMap::default(),
            #[cfg(debug_assertions)]
            checks: Checks::default(),
        }
    }

    /// Follows `k`: its next `settle` reports it (nothing was acted on yet). A key followed
    /// already stays as it is.
    pub fn want(&mut self, k: K) {
        if self.followed.contains_key(&k) {
            return;
        }
        self.seq += 1;
        self.followed.insert(k.clone(), Followed::new(self.seq, None, Vec::new()));
        self.pending.insert(k);
    }

    /// Stops following `k`: it is never due again until wanted again.
    pub fn unwant(&mut self, k: &K) {
        if let Some(f) = self.followed.remove(k) {
            self.unindex(k, &f.deps);
        }
        self.pending.remove(k);
    }

    /// Whether no key is known due (wanted and never settled, given by `due` and not settled
    /// since, or moved while its settle read): with nothing written since its last `due`, the
    /// next is empty.
    pub fn idle(&self) -> bool {
        self.pending.is_empty()
    }

    /// The keys followed that `pick` names.
    pub(super) fn followed_where(&self, pick: impl Fn(&K) -> bool) -> Vec<K> {
        self.followed.keys().filter(|k| pick(k)).cloned().collect()
    }

    /// Whether `k` is followed.
    pub fn wants(&self, k: &K) -> bool {
        self.followed.contains_key(k)
    }

    /// `k`'s value as last settled, when it holds now: followed, settled, not known due, and
    /// nothing it read written since (each read's stamp checked, no log read). `None`: settle it.
    pub fn current(&self, k: &K) -> Option<V> {
        let f = self.followed.get(k)?;
        if self.pending.contains(k) || !f.deps.iter().all(Dep::holds) {
            return None;
        }
        f.value.clone()
    }

    /// Whether `k` is followed with a value settled (none since a failed settle).
    pub(super) fn settled_value(&self, k: &K) -> bool {
        self.followed.get(k).is_some_and(|f| f.value.is_some())
    }

    /// The followed keys whose last value read a stamp written since, and those never settled,
    /// in want order. A key stays due until it is settled. Debug builds add, after them, keys
    /// whose settle compares with the value kept (`Checks`).
    pub fn due(&mut self) -> Vec<K> {
        let given = std::mem::take(&mut self.pending);
        let mut maybe: HashSet<K> = given.clone();
        // per container written since the marks, the keys written or removed (by hash) and
        // whether it changed whole
        let mut wrote: HashMap<usize, (HashSet<u64, Ids>, bool), Ids> = HashMap::default();
        for (p, ix) in self.tables.iter_mut() {
            let changes = lock(&ix.table).read_log(&mut ix.at);
            if changes.is_empty() {
                continue;
            }
            // any change moves what read it whole
            maybe.extend(ix.whole.iter().cloned());
            let (keys, all) = wrote.entry(*p).or_default();
            let mut buckets = HashSet::new();
            for c in changes {
                match c {
                    Logged::Key { h, .. } => {
                        keys.insert(h);
                        maybe.extend(ix.keys.get(&h).into_iter().flatten().cloned());
                    }
                    Logged::Bucket(h) => {
                        keys.insert(h);
                        maybe.extend(ix.keys.get(&h).into_iter().flatten().cloned());
                        buckets.insert(bucket(h));
                    }
                    Logged::Whole => {}
                    Logged::All => {
                        *all = true;
                        maybe.extend(ix.keys.values().flatten().cloned());
                    }
                }
            }
            for x in buckets.iter().filter_map(|b| ix.buckets.get(b)).flatten() {
                maybe.extend(ix.keys.get(x).into_iter().flatten().cloned());
            }
        }
        crate::costs::count("effects: candidates", maybe.len() as u64);
        // a logged write of a key read, before the read or by a key sharing its hash, moved
        // nothing: the stamps say which did. A key read at its bucket's absent stamp and written
        // by nothing since moved only with another key's pruned removal (`Table::prune`): its
        // value stands, read again at the bucket's stamp now. Not for a key given before: the
        // write that moved it may be in an earlier `due`'s log
        let bucket_only = |d: &Dep| -> bool {
            let Some(h) = d.key else { return false };
            let Some((keys, all)) = wrote.get(&(Arc::as_ptr(&d.table) as usize)) else { return false };
            !*all && !keys.contains(&h) && !lock(&d.table).keys.contains_key(&h)
        };
        let mut due: Vec<(u64, K)> = Vec::new();
        #[cfg(debug_assertions)]
        let mut check: Vec<(u64, K)> = Vec::new();
        for k in maybe {
            let Some(f) = self.followed.get_mut(&k) else { continue };
            let moved = f.value.is_none() || f.deps.iter().any(|d| !d.holds() && (given.contains(&k) || !bucket_only(d)));
            if moved {
                due.push((f.seq, k));
            } else {
                for d in f.deps.iter_mut() {
                    d.seen = lock(&d.table).stamp(d.key);
                }
                #[cfg(debug_assertions)]
                if super::effect_checks() {
                    f.moved += 1;
                    if at_power(f.moved, 2) {
                        check.push((f.seq, k));
                    }
                }
            }
        }
        if crate::costs::on() {
            self.count_causes(&due);
        }
        due.sort_by_key(|(s, _)| *s);
        self.pending.extend(due.iter().map(|(_, k)| k.clone()));
        #[allow(unused_mut)]
        let mut out: Vec<K> = due.into_iter().map(|(_, k)| k).collect();
        #[cfg(debug_assertions)]
        if super::effect_checks() {
            self.checks.calls += 1;
            if self.checks.calls > 1 && at_power(self.checks.calls, 4) {
                let given: HashSet<&K> = out.iter().chain(check.iter().map(|(_, k)| k)).collect();
                let rest: Vec<(u64, K)> = self.followed.iter().filter(|(k, f)| !given.contains(k) && !self.pending.contains(*k) && f.value.is_some()).map(|(k, f)| (f.seq, k.clone())).collect();
                check.extend(rest);
            }
            check.sort_by_key(|(s, _)| *s);
            self.checks.keys = check.iter().map(|(_, k)| k.clone()).collect();
            out.extend(check.into_iter().map(|(_, k)| k));
        }
        out
    }

    /// Whether `k`'s settle is a debug comparison (`Checks`): given by the last `due` though
    /// nothing it read moved, and still so. Always false in release builds.
    pub fn checking(&self, k: &K) -> bool {
        #[cfg(debug_assertions)]
        {
            self.checks.keys.contains(k) && self.followed.get(k).is_some_and(|f| f.value.is_some() && f.deps.iter().all(Dep::holds))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = k;
            false
        }
    }

    /// A debug comparison's end (`Checks`): the value settled now must be the one kept, since
    /// nothing it read moved.
    fn compared(&mut self, k: &K, checking: bool, now: &V) {
        if !checking {
            return;
        }
        #[cfg(debug_assertions)]
        {
            self.checks.keys.remove(k);
            let kept = self.followed.get(k).and_then(|f| f.value.as_ref());
            assert!(kept == Some(now), "effects {}: {k:?} kept {kept:?}, a settle with nothing it read written gives {now:?}: it read something unstamped", self.name);
        }
        #[cfg(not(debug_assertions))]
        let _ = (k, now);
    }

    /// `f`'s value for `k`, recorded as `k`'s: `Some((acted, now))` when it differs from the
    /// value last settled (`acted`, `None` for a key wanted since), `None` when it is the same.
    /// `k` is due again once something `f` read is written. A key not followed is not kept: its
    /// value is reported as new.
    pub fn settle(&mut self, k: &K, f: impl FnOnce() -> V) -> Option<(Option<V>, V)> {
        let checking = self.checking(k);
        let (now, frame) = self.run(checking, f);
        self.compared(k, checking, &now);
        self.record(k, now, frame)
    }

    /// `f` run recorded; a debug comparison's run counts no costs.
    fn run<T>(&self, checking: bool, f: impl FnOnce() -> T) -> (T, super::Frame) {
        if checking {
            return crate::costs::paused(|| recorded_frame(f));
        }
        let _s = crate::costs::span(self.name);
        recorded_frame(f)
    }

    /// `settle` with a function that may fail: on `Err` nothing is recorded and `k` stays due,
    /// its value forgotten (the next settle reports it as new), so a failed read is tried again
    /// at the next `due` with no retry kept by the caller.
    pub fn try_settle<E>(&mut self, k: &K, f: impl FnOnce() -> Result<V, E>) -> Result<Option<(Option<V>, V)>, E> {
        let checking = self.checking(k);
        let (out, frame) = self.run(checking, f);
        self.settled(k, out, frame)
    }

    /// `try_settle` of a value computed (with what it read, `frame`) while this was not borrowed:
    /// for an owner inside what the function reads (`Cutoff::refresh_in`, which runs a
    /// comparison's function with costs paused, `checking`).
    pub(super) fn settled<E>(&mut self, k: &K, out: Result<V, E>, frame: super::Frame) -> Result<Option<(Option<V>, V)>, E> {
        let checking = self.checking(k);
        match out {
            Ok(now) => {
                self.compared(k, checking, &now);
                Ok(self.record(k, now, frame))
            }
            Err(e) => {
                if let Some(old) = self.followed.get_mut(k) {
                    old.value = None;
                    let deps = std::mem::take(&mut old.deps);
                    self.unindex(k, &deps);
                    self.pending.insert(k.clone());
                }
                Err(e)
            }
        }
    }

    fn record(&mut self, k: &K, now: V, frame: super::Frame) -> Option<(Option<V>, V)> {
        let Some(old) = self.followed.get_mut(k) else { return Some((None, now)) };
        let was = old.value.replace(now.clone());
        let old_deps = std::mem::replace(&mut old.deps, frame.deps.clone());
        if old_deps.len() == frame.deps.len() && old_deps.iter().zip(&frame.deps).all(|(a, b)| a.id() == b.id()) {
            // the same reads again: the index holds `k` under each already
            self.reindex_buckets(&frame.deps);
        } else {
            self.unindex(k, &old_deps);
            self.index(k, &frame.deps);
        }
        self.pending.remove(k);
        // a write between a read and its index here is in no log this reader reads
        if !frame.deps.iter().all(Dep::holds) {
            self.pending.insert(k.clone());
        }
        (was.as_ref() != Some(&now)).then_some((was, now))
    }

    fn index(&mut self, k: &K, deps: &[Dep]) {
        for d in deps {
            let ix = self.tables.entry(Arc::as_ptr(&d.table) as usize).or_insert_with(|| {
                let mut t = lock(&d.table);
                let at = t.ver;
                t.mark(at);
                Indexed { table: d.table.clone(), at, whole: HashSet::new(), keys: HashMap::default(), buckets: HashMap::default(), reads: 0 }
            });
            ix.reads += 1;
            match d.key {
                None => {
                    ix.whole.insert(k.clone());
                }
                Some(h) => {
                    ix.keys.entry(h).or_default().insert(k.clone());
                    // only a key read at its bucket's absent stamp moves with another's removal
                    // (one read present has a stamp of its own: its own removal names it); a
                    // change since the read leaves `k` due at once (`settle`)
                    if !lock(&ix.table).keys.contains_key(&h) {
                        ix.buckets.entry(bucket(h)).or_default().insert(h);
                    }
                }
            }
        }
    }

    /// `index` for reads `k` is indexed under already: only a key read at its bucket's absent
    /// stamp now joins its bucket (one present at the earlier read was not in it).
    fn reindex_buckets(&mut self, deps: &[Dep]) {
        for d in deps {
            let Some(h) = d.key else { continue };
            let Some(ix) = self.tables.get_mut(&(Arc::as_ptr(&d.table) as usize)) else { continue };
            if !lock(&ix.table).keys.contains_key(&h) {
                ix.buckets.entry(bucket(h)).or_default().insert(h);
            }
        }
    }

    fn unindex(&mut self, k: &K, deps: &[Dep]) {
        for d in deps {
            let p = Arc::as_ptr(&d.table) as usize;
            let Some(ix) = self.tables.get_mut(&p) else { continue };
            match d.key {
                None => {
                    ix.whole.remove(k);
                }
                Some(h) => {
                    if let Some(s) = ix.keys.get_mut(&h) {
                        s.remove(k);
                        if s.is_empty() {
                            ix.keys.remove(&h);
                            if let Some(b) = ix.buckets.get_mut(&bucket(h)) {
                                b.remove(&h);
                                if b.is_empty() {
                                    ix.buckets.remove(&bucket(h));
                                }
                            }
                        }
                    }
                }
            }
            ix.reads = ix.reads.saturating_sub(1);
            if ix.reads == 0 {
                self.tables.remove(&p);
            }
        }
    }

    /// Counts, per due key, what made it due (`costs::count_by`, under this effects' name): never
    /// settled, or each container whose stamp a read of its last value saw moved.
    fn count_causes(&self, due: &[(u64, K)]) {
        for (_, k) in due {
            let Some(f) = self.followed.get(k) else { continue };
            if f.value.is_none() {
                crate::costs::count_by(self.name, "unsettled", 1);
                continue;
            }
            let mut moved = false;
            for d in f.deps.iter().filter(|d| !d.holds()) {
                let t = lock(&d.table);
                crate::costs::count_by(self.name, t.cause(d.key.is_none()), 1);
                moved = true;
            }
            if !moved {
                // given by an earlier `due` and not settled since
                crate::costs::count_by(self.name, "given before", 1);
            }
        }
    }

    /// Keys followed (tests).
    #[cfg(test)]
    pub(crate) fn marks(&self) -> usize {
        self.tables.len()
    }
}

/// A table of this reader's, as a clone holds it, marked at `at` for the clone: inside a world
/// copy (`crate::copying`) the copy's table (the original's log, none of its marks: a reader left
/// outside the copy holds none on it), outside one the same table.
fn cloned_table(t: &Arc<Mutex<Table>>, at: u64) -> Arc<Mutex<Table>> {
    let t = if crate::copying::in_copy() { copied(t) } else { t.clone() };
    lock(&t).mark(at);
    t
}

/// A clone follows what the original follows, each value at the reads it was settled at, and
/// reads the logs from where the original stands (inside a world copy, the copy's).
impl<K: Hash + Eq + Clone, V: Clone> Clone for Effects<K, V> {
    fn clone(&self) -> Self {
        let dep = |d: &Dep| Dep { table: if crate::copying::in_copy() { copied(&d.table) } else { d.table.clone() }, ..d.clone() };
        let followed = self.followed.iter().map(|(k, f)| (k.clone(), Followed { seq: f.seq, value: f.value.clone(), deps: f.deps.iter().map(dep).collect(), #[cfg(debug_assertions)] moved: f.moved })).collect();
        let tables = self
            .tables
            .values()
            .map(|ix| {
                let table = cloned_table(&ix.table, ix.at);
                (Arc::as_ptr(&table) as usize, Indexed { table, at: ix.at, whole: ix.whole.clone(), keys: ix.keys.clone(), buckets: ix.buckets.clone(), reads: ix.reads })
            })
            .collect();
        Effects {
            name: self.name,
            followed,
            seq: self.seq,
            pending: self.pending.clone(),
            tables,
            #[cfg(debug_assertions)]
            checks: self.checks.clone(),
        }
    }
}

/// A clone reads on from where the original stands (inside a world copy, the copy's log).
impl<K> Clone for Feed<K> {
    fn clone(&self) -> Self {
        Feed { table: cloned_table(&self.table, self.at), at: self.at, _k: PhantomData }
    }
}

/// One reader's cursor over the keys a container added (`Stamps::wrote_added`) since the
/// reader's mark: nobody drains it and nothing writes it by hand; the container's log keeps
/// what the oldest cursor has not read.
pub struct Feed<K> {
    table: Arc<Mutex<Table>>,
    at: u64,
    _k: PhantomData<fn() -> K>,
}

impl<K: Clone + 'static> Feed<K> {
    pub(super) fn new(table: Arc<Mutex<Table>>) -> Feed<K> {
        let at = {
            let mut t = lock(&table);
            let at = t.ver;
            t.mark(at);
            at
        };
        Feed { table, at, _k: PhantomData }
    }

    /// The keys added since the last call (or the feed's start), in the order added: a key
    /// removed and added again comes again.
    pub fn added(&mut self) -> Vec<K> {
        self.logged(true)
    }

    /// The keys logged with themselves since the last call, written (`present`) or removed.
    fn logged(&mut self, present: bool) -> Vec<K> {
        let changes = lock(&self.table).read_log(&mut self.at);
        changes
            .into_iter()
            .filter_map(|c| match c {
                Logged::Key { present: p, added: Some(k), .. } if p == present => k.downcast_ref::<K>().cloned(),
                _ => None,
            })
            .collect()
    }
}

/// One reader's cursor over the keys a container removed (`Stamps::wrote_removed`) since the
/// reader's mark, as `Feed` is over those added. A rollback restoring a key leaves it given: the
/// reader finds it present.
#[derive(Clone, Debug)]
pub struct Removals<K>(pub(super) Feed<K>);

impl<K: Clone + 'static> Removals<K> {
    /// The keys removed since the last call (or the cursor's start), in the order removed.
    pub fn removed(&mut self) -> Vec<K> {
        self.0.logged(false)
    }
}

impl<K> std::fmt::Debug for Feed<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Feed").field("at", &self.at).finish()
    }
}

impl<K> Drop for Feed<K> {
    fn drop(&mut self) {
        lock(&self.table).unmark(self.at);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::super::{Clock, Memo, Stamped, StampedSet, Stamps};
    use super::*;

    /// A key other than 100 whose stamp shares 100's bucket.
    fn bucket_mate() -> u8 {
        let b = bucket(super::super::hash(&100u8));
        (0..=255u8).find(|x| bucket(super::super::hash(x)) == b && *x != 100).unwrap()
    }

    /// `e` following key 1, settled once by `read`.
    fn settle_once<K: From<u8> + Hash + Eq + Clone + std::fmt::Debug, V: Clone + PartialEq + std::fmt::Debug>(e: &mut Effects<K, V>, read: impl FnOnce() -> V) {
        e.want(K::from(1));
        e.due();
        e.settle(&K::from(1), read);
    }

    // spec: none (internal: notes/engine.md, Derived values). A followed key is due when it was
    // wanted and not settled, or when something its last value read was written since, never
    // otherwise; settle reports a value only when it differs from the one last settled; an
    // unwanted key is never due; a memo read inside a settle counts as what the memo read.
    #[test]
    fn effects_are_due_exactly_when_what_they_read_moved() {
        let mut m: Stamped<u8, u8> = Stamped::default();
        let mut s: StampedSet<u8> = StampedSet::default();
        let memo: Memo<u8, u8> = Memo::new("test inner");
        let mut e: Effects<u8, u8> = Effects::new("test effects");
        let read = |m: &Stamped<u8, u8>, s: &StampedSet<u8>, k: u8| if k == 9 { s.len() as u8 } else { memo.get(&k, || m.get(&k).copied().unwrap_or(0)) };
        e.want(1);
        e.want(2);
        e.want(9);
        assert_eq!(e.due(), [1, 2, 9], "wanted, never settled");
        assert_eq!(e.due(), [1, 2, 9], "due until settled");
        for k in [1, 2, 9] {
            assert_eq!(e.settle(&k, || read(&m, &s, k)), Some((None, 0)));
        }
        assert_eq!(e.due(), Vec::<u8>::new());
        m.insert(3, 3);
        assert_eq!(e.due(), Vec::<u8>::new(), "a key nobody read");
        m.insert(2, 5);
        s.insert(4);
        assert_eq!(e.due(), [2, 9], "a key read through a memo, a container read whole");
        assert_eq!(e.settle(&2, || read(&m, &s, 2)), Some((Some(0), 5)));
        assert_eq!(e.due(), [9], "still due: not settled");
        assert_eq!(e.settle(&9, || read(&m, &s, 9)), Some((Some(0), 1)));
        m.insert(1, 0);
        assert_eq!(e.due(), [1], "written back to the same value: due");
        assert_eq!(e.settle(&1, || read(&m, &s, 1)), None, "settled to the value acted on");
        m.remove(&2);
        assert_eq!(e.due(), [2]);
        e.unwant(&2);
        assert_eq!(e.due(), Vec::<u8>::new(), "unwanted");
        m.insert(2, 7);
        assert_eq!(e.due(), Vec::<u8>::new(), "unwanted, then written");
        e.want(2);
        assert_eq!(e.due(), [2]);
        assert_eq!(e.settle(&2, || read(&m, &s, 2)), Some((None, 7)), "wanted again: reported anew");
        // a read of an absent key moves with its own removal alone, not another's of its bucket
        e.want(100);
        e.settle(&100, || read(&m, &s, 100));
        let removed = bucket_mate();
        m.insert(removed, 1);
        let _ = e.due();
        m.remove(&removed);
        assert_eq!(e.due(), Vec::<u8>::new(), "a removal in the bucket of an absent key read");
        m.insert(100, 1);
        m.remove(&100);
        assert_eq!(e.due(), [100], "the key read came and went");
        e.settle(&100, || read(&m, &s, 100));
        // a write logged before the settle that read it moved nothing since
        m.insert(1, 3);
        assert_eq!(e.settle(&1, || read(&m, &s, 1)), Some((Some(0), 3)));
        assert_eq!(e.due(), Vec::<u8>::new(), "settled after the write");
        // a write after the read, before the settle indexed it, in a container no key read yet
        let mut n: Stamped<u8, u8> = Stamped::default();
        e.settle(&1, || {
            let v = n.get(&1).copied().unwrap_or(0);
            n.insert(1, 4);
            v
        });
        assert_eq!(e.due(), [1], "written during its own settle");
    }

    // spec: none (internal). `current` is a followed key's value while nothing it read moved:
    // none before its first settle, once a read is written (before any `due`), while `due` gave
    // it and it is not settled since, and once unwanted.
    #[test]
    fn current_is_the_value_while_nothing_it_read_moved() {
        let mut m: Stamped<u8, u8> = Stamped::default();
        let mut e: Effects<u8, u8> = Effects::new("test current");
        e.want(1);
        assert_eq!(e.current(&1), None, "never settled");
        e.settle(&1, || m.get(&1).copied().unwrap_or(0));
        assert_eq!(e.current(&1), Some(0));
        m.insert(2, 2);
        assert_eq!(e.current(&1), Some(0), "a key it did not read");
        m.insert(1, 5);
        assert_eq!(e.current(&1), None, "written, no due read yet");
        assert_eq!(e.due(), [1]);
        m.insert(1, 0);
        assert_eq!(e.current(&1), None, "given by due, not settled since");
        e.settle(&1, || m.get(&1).copied().unwrap_or(0));
        assert_eq!(e.current(&1), Some(0));
        e.unwant(&1);
        assert_eq!(e.current(&1), None, "unwanted");
    }

    // spec: none (internal). A settle that reads the same keys again keeps its index, yet a key
    // read present before and absent now moves with its own changes alone; a key present with no
    // stamp of its own (since `wrote_all`) moves with its removal; a write reverted before `due`
    // still makes its reader due.
    #[test]
    fn a_key_read_again_absent_moves_with_its_own_changes() {
        let mut m: Stamped<u8, u8> = Stamped::default();
        let mut e: Effects<u8, u8> = Effects::new("test again");
        let read = |m: &Stamped<u8, u8>| m.get(&100).copied().unwrap_or(0);
        m.insert(100, 1);
        settle_once(&mut e, || read(&m));
        m.insert(100, 2);
        m.insert(100, 1);
        assert_eq!(e.due(), [1], "written and written back");
        assert_eq!(e.settle(&1, || read(&m)), None);
        m.remove(&100);
        assert_eq!(e.due(), [1]);
        e.settle(&1, || read(&m));
        let other = bucket_mate();
        m.insert(other, 1);
        m.remove(&other);
        assert_eq!(e.due(), Vec::<u8>::new(), "another key of its bucket came and went");
        m.insert(100, 1);
        m.stamps.wrote_all();
        assert_eq!(e.due(), [1], "everything moved");
        e.settle(&1, || read(&m));
        m.remove(&100);
        assert_eq!(e.due(), [1], "the key read present with no stamp of its own removed");
    }

    // spec: none (internal). Removal stamps stay as many as the keys stamped otherwise (at least
    // the buckets): past that they are pruned, which moves each pruned key's bucket. A reader of
    // an absent key nothing wrote moves not (its value stands); one of a key present with no
    // stamp of its own (since `wrote_all`) that was written, removed and pruned moves, at the
    // `due` after and at each later one until settled, whatever prunes came between.
    #[test]
    fn a_prune_moves_the_readers_of_what_it_pruned_alone() {
        let ab = super::super::ABSENT_BUCKETS as u16;
        // removes keys `from..` until a prune, stamps bounded throughout
        let churn = |m: &mut Stamped<u16, u8>, from: u16| {
            let was = lock(&m.stamps.0).absent;
            for k in from..from + 4 * ab {
                m.insert(k, 1);
                m.remove(&k);
                assert!(lock(&m.stamps.0).removed.len() <= ab as usize, "removal stamps bounded");
            }
            assert_ne!(lock(&m.stamps.0).absent, was, "a prune moved buckets");
        };
        let mut m: Stamped<u16, u8> = Stamped::default();
        let mut e: Effects<u16, u8> = Effects::new("test pruned");
        settle_once(&mut e, || m.get(&5000).copied().unwrap_or(0));
        let was = m.stamps.stamp(&5000u16);
        for i in 0..4 {
            churn(&mut m, 1000 * i);
            assert_eq!(e.due(), Vec::<u16>::new(), "nothing wrote the absent key read");
        }
        assert_ne!(m.stamps.stamp(&5000u16), was, "its bucket moved");
        m.insert(5000, 1);
        assert_eq!(e.due(), [1], "read again at its bucket's stamp: its own write moves it");
        let mut m: Stamped<u16, u8> = Stamped::default();
        let mut e: Effects<u16, u8> = Effects::new("test pruned present");
        m.insert(7, 1);
        m.stamps.wrote_all();
        settle_once(&mut e, || m.get(&7).copied().unwrap_or(0));
        m.insert(7, 2);
        m.remove(&7);
        churn(&mut m, 1000);
        assert!(!lock(&m.stamps.0).keys.contains_key(&super::super::hash(&7u16)), "its removal pruned");
        assert_eq!(e.due(), [1], "written, removed and pruned");
        churn(&mut m, 2000);
        assert_eq!(e.due(), [1], "given before, not settled since");
    }

    // spec: none (internal). Nothing reacts to what did not change: a reader of an absent key is
    // not moved by removing another absent key of its bucket, by `update` adding a key there and
    // editing it in place, nor by that key's removal.
    #[test]
    fn an_absent_key_moves_only_with_its_own_changes() {
        let mut m: Stamped<u8, u8> = Stamped::default();
        let mut e: Effects<u8, u8> = Effects::new("test absent");
        let read = |m: &Stamped<u8, u8>| m.get(&100).copied().unwrap_or(0);
        settle_once(&mut e, || read(&m));
        let other = bucket_mate();
        assert_eq!(m.remove(&other), None);
        m.update(other, |v| Some(v.unwrap_or(0) + 1));
        m.update(other, |v| Some(v.unwrap_or(0) + 1));
        m.update(other, |v| v);
        assert_eq!(m.get(&other), Some(&2));
        assert_eq!(e.due(), Vec::<u8>::new(), "nothing of its bucket changed");
        m.update(other, |_| None);
        assert_eq!(e.due(), Vec::<u8>::new(), "another key of its bucket removed");
    }

    // spec: none (internal). A settle that fails records nothing: the key stays due, its next
    // settle reports it anew, and nothing it read before keeps it.
    #[test]
    fn a_failed_settle_stays_due() {
        let mut m: Stamped<u8, u8> = Stamped::default();
        let mut e: Effects<u8, u8> = Effects::new("test try");
        e.want(1);
        assert_eq!(e.try_settle(&1, || Ok::<_, ()>(m.get(&1).copied().unwrap_or(0))), Ok(Some((None, 0))));
        m.insert(1, 2);
        assert_eq!(e.due(), [1]);
        assert_eq!(e.try_settle(&1, || m.get(&1).map_or(Err("failed"), |_| Err("failed"))), Err("failed"));
        assert_eq!(e.due(), [1], "due again after a failure");
        assert_eq!(e.try_settle(&1, || Ok::<_, ()>(m.get(&1).copied().unwrap_or(0))), Ok(Some((None, 2))), "reported anew");
        assert_eq!(e.due(), Vec::<u8>::new());
    }

    // spec: none (internal). Wanting a key followed already changes nothing: it is not due, and
    // its next settle compares with the value kept.
    #[test]
    fn a_key_wanted_again_stays_as_it_is() {
        let m: Stamped<u8, u8> = Stamped::default();
        let mut e: Effects<u8, u8> = Effects::new("test again");
        settle_once(&mut e, || m.get(&1).copied().unwrap_or(0));
        e.want(1);
        assert_eq!(e.due(), Vec::<u8>::new());
        assert_eq!(e.settle(&1, || 0), None, "the same value");
    }

    // spec: none (internal). The log is kept from the oldest live mark: a reader that reads
    // seldom still sees every write since its last read while another reads often, and a
    // container nobody follows (every reader gone) logs nothing.
    #[test]
    fn a_log_is_kept_for_its_oldest_reader() {
        let mut m: Stamped<u8, u8> = Stamped::default();
        let (mut often, mut seldom): (Effects<u8, u8>, Effects<u8, u8>) = (Effects::new("test often"), Effects::new("test seldom"));
        for e in [&mut often, &mut seldom] {
            settle_once(e, || m.get(&1).copied().unwrap_or(0));
        }
        m.insert(1, 1);
        for x in 2..20 {
            m.insert(x, x);
            assert_eq!(often.due(), if x == 2 { vec![1] } else { vec![] });
            often.settle(&1, || m.get(&1).copied().unwrap_or(0));
        }
        assert_eq!(seldom.due(), [1], "the write before the other reader's reads");
        seldom.settle(&1, || m.get(&1).copied().unwrap_or(0));
        assert_eq!(lock(&m.stamps.0).log.len(), 0, "both read it all");
        drop(often);
        seldom.unwant(&1);
        assert!(lock(&m.stamps.0).marks.is_empty());
        m.insert(1, 9);
        assert_eq!(lock(&m.stamps.0).log.len(), 0, "nobody follows it");
        assert_eq!(seldom.marks(), 0);
    }

    // spec: none (internal). A feed gives the keys added since its last read, in order, each
    // once per addition; a feed started later sees only what came after it; a write of a key
    // present or a removal adds nothing.
    #[test]
    fn a_feed_gives_each_key_added_since_its_mark() {
        let s = Stamps::default();
        let add = |k: u32| s.wrote_added(&k, true, true);
        let mut a: Feed<u32> = s.feed();
        add(1);
        add(2);
        s.wrote_added(&2u32, true, false);
        s.wrote_added(&1u32, false, false);
        let mut b: Feed<u32> = s.feed();
        add(1);
        assert_eq!(a.added(), [1, 2, 1]);
        assert_eq!(a.added(), Vec::<u32>::new());
        add(3);
        assert_eq!(b.added(), [1, 3]);
        assert_eq!(a.added(), [3]);
        drop((a, b));
        add(4);
        assert!(lock(&s.0).log.is_empty() && lock(&s.0).marks.is_empty());
    }

    // spec: none (internal). `due` costs the writes since its last call times their readers,
    // never the keys followed: a write, a removal of a key read, a removal of a key no one read
    // and a write of a key read whole make the same candidates at n and 10n keys followed.
    #[test]
    fn due_costs_the_writes_not_the_keys_followed() {
        let candidates = |n: u32| {
            let mut m: Stamped<u32, u32> = Stamped::default();
            let mut s: StampedSet<u32> = StampedSet::default();
            (0..n).for_each(|k| { m.insert(k, k); });
            let mut e: Effects<u32, u32> = Effects::new("test cost");
            // every key read present, and one absent key; one reader of `s` whole
            for k in (0..n).chain([n + 1, u32::MAX]) {
                e.want(k);
            }
            e.due();
            for k in (0..n).chain([n + 1]) {
                e.settle(&k, || m.get(&k).copied().unwrap_or(0));
            }
            e.settle(&u32::MAX, || s.len() as u32);
            fn step(e: &mut Effects<u32, u32>, m: &Stamped<u32, u32>, s: &StampedSet<u32>, due: Vec<u32>) -> u64 {
                crate::costs::take();
                let d = e.due();
                assert_eq!(d, due);
                let n = crate::costs::take().iter().filter(|x| x.0 == "effects: candidates").map(|x| x.2).sum::<u64>();
                for k in d {
                    e.settle(&k, || if k == u32::MAX { s.len() as u32 } else { m.get(&k).copied().unwrap_or(0) });
                }
                n
            }
            let mut out = Vec::new();
            m.insert(1, 7);
            out.push(step(&mut e, &m, &s, vec![1]));
            m.remove(&2);
            out.push(step(&mut e, &m, &s, vec![2]));
            m.insert(n + 2, 0);
            m.remove(&(n + 2));
            out.push(step(&mut e, &m, &s, vec![]));
            s.insert(1);
            out.push(step(&mut e, &m, &s, vec![u32::MAX]));
            out
        };
        let few = candidates(200);
        assert_eq!(few, candidates(2000), "candidates per step");
        assert!(few.iter().all(|c| *c <= 2), "{few:?}");
    }

    // spec: none (internal). A world copied without one of its readers holds no mark of that
    // reader: its log stays empty, while a reader copied with it reads on in the copy.
    #[test]
    fn a_copy_holds_only_its_own_readers_marks() {
        let m: Stamped<u8, u8> = Stamped::default();
        let mut e: Effects<u8, u8> = Effects::new("test copy");
        settle_once(&mut e, || m.get(&1).copied().unwrap_or(0));
        let mut alone = crate::copying::copying(|| m.clone());
        alone.insert(1, 1);
        assert!(lock(&alone.stamps.0).log.is_empty() && lock(&alone.stamps.0).marks.is_empty(), "the reader was not copied");
        let (mut both, mut ec) = crate::copying::copying(|| (m.clone(), e.clone()));
        both.insert(1, 2);
        assert_eq!(ec.due(), [1]);
        assert_eq!(e.due(), Vec::<u8>::new(), "the original's world did not move");
        drop(ec);
        assert!(lock(&both.stamps.0).marks.is_empty());
    }

    // spec: none (internal). A clone follows on from where the original stands, apart from it:
    // each sees the writes after the clone, and dropping one keeps the other's log.
    #[test]
    fn a_clone_follows_on_its_own() {
        let mut m: Stamped<u8, u8> = Stamped::default();
        let mut e: Effects<u8, u8> = Effects::new("test cloned");
        settle_once(&mut e, || m.get(&1).copied().unwrap_or(0));
        let f = m.stamps.feed::<u8>();
        let mut c = e.clone();
        let mut g = f.clone();
        m.insert(1, 1);
        m.stamps.wrote_added(&7u8, true, true);
        drop(e);
        drop(f);
        assert_eq!(c.due(), [1]);
        assert_eq!(g.added(), [7]);
    }

    // spec: none (internal). The clock's next wake is the earliest `until` read and not passed,
    // and a value read until then is due when the clock reaches it, not before.
    #[test]
    fn the_clock_wakes_at_its_earliest_horizon() {
        let mut c = Clock::default();
        c.set(10);
        assert_eq!(c.next(), None);
        let mut e: Effects<u8, bool> = Effects::new("test timed");
        settle_once(&mut e, || c.until(Some(30)) >= 30);
        c.until(Some(50));
        c.until(None);
        assert_eq!(c.next(), Some(30));
        c.set(29);
        assert_eq!(e.due(), Vec::<u8>::new());
        c.set(30);
        assert_eq!(e.due(), [1], "its horizon reached");
        assert_eq!(e.settle(&1, || c.until(None) >= 30), Some((Some(false), true)));
        assert_eq!(c.next(), Some(50));
        c.set(60);
        assert_eq!(c.next(), None);
        assert_eq!(e.due(), Vec::<u8>::new());
        c.set(40);
        assert_eq!(e.due(), [1], "the clock went back: every reader");
    }

    // spec: none (internal). The time a judgement reads (`Clock::now`) holds only as far as the
    // judgement bounded it: unbounded (outside every `at` and `bound`), any move of the clock
    // moves it; inside an `at` or while a `bound` lives, only reaching that deadline does.
    #[test]
    fn a_time_read_unbounded_moves_with_the_clock() {
        let mut c = Clock::default();
        c.set(10);
        let mut e: Effects<u8, u64> = Effects::new("test time");
        let read = |c: &Clock, k: u8| match k {
            1 => c.now() / 100,
            2 => c.at(|now| (now / 100, Some(100))),
            3 => {
                let _b = c.bound(|_| Some(100));
                c.now() / 100
            }
            _ => c.at(|now| (now / 100, Some(100))) + c.now() / 100,
        };
        for k in 1..=4 {
            e.want(k);
        }
        for k in e.due() {
            e.settle(&k, || read(&c, k));
        }
        c.set(11);
        assert_eq!(e.due(), [1, 4], "unbounded: every move; bounded: not before 100");
        for k in [1, 4] {
            e.settle(&k, || read(&c, k));
        }
        c.set(100);
        assert_eq!(e.due(), [1, 2, 3, 4]);
    }

    // spec: none (internal: notes/engine.md, Derived values). Debug builds with the comparison
    // on (`check_effects`): a settled value that read something unstamped (a plain cell) fails
    // at a comparison once that moved alone, never while it holds.
    #[cfg(debug_assertions)]
    #[test]
    fn a_read_without_its_stamp_fails_the_comparison() {
        super::super::check_effects(true);
        let m: Stamped<u8, u8> = Stamped::default();
        let plain = std::cell::Cell::new(1u8);
        let mut e: Effects<u8, u8> = Effects::new("test effects");
        e.want(1);
        e.want(2);
        let read = |k: u8| m.get(&k).copied().unwrap_or(0) + if k == 1 { plain.get() } else { 0 };
        let settle = |e: &mut Effects<u8, u8>| {
            for k in e.due() {
                e.settle(&k, || read(k));
            }
        };
        for _ in 0..20 {
            settle(&mut e);
        }
        plain.set(2);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for _ in 0..300 {
                settle(&mut e);
            }
        }));
        super::super::check_effects(false);
        let msg = caught.expect_err("the stale value is found").downcast::<String>().map(|s| *s).unwrap_or_default();
        assert!(msg.contains("test effects: 1 kept Some(1)") && msg.contains("unstamped"), "{msg}");
    }
}
