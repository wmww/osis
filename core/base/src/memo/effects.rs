//! Work in proportion to change (notes/engine.md, Derived values): `Effects` follows keys whose
//! values a function derives, and tells which may have moved from the containers' logs of their
//! writes (`Table::log`), never by asking every key; `Feed` is one reader's cursor over the keys
//! a container added.

use super::{Dep, Logged, Table, bucket, copied, lock, recorded_frame};
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
    tables: HashMap<usize, Indexed<K>>,
}

struct Followed<V> {
    seq: u64,
    /// The value last settled (`None`: never since it was wanted).
    value: Option<V>,
    deps: Vec<Dep>,
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
    keys: HashMap<u64, HashSet<K>>,
    buckets: HashMap<usize, HashSet<u64>>,
    /// Reads indexed here: the mark goes with the last.
    reads: usize,
}

impl<K> Drop for Indexed<K> {
    fn drop(&mut self) {
        lock(&self.table).unmark(self.at);
    }
}

impl<K: Hash + Eq + Clone, V: Clone + PartialEq> Effects<K, V> {
    pub fn new(name: &'static str) -> Self {
        Effects { name, followed: HashMap::new(), seq: 0, pending: HashSet::new(), tables: HashMap::new() }
    }

    /// Follows `k`: its next `settle` reports it (nothing was acted on yet). A key followed
    /// already stays as it is.
    pub fn want(&mut self, k: K) {
        if self.followed.contains_key(&k) {
            return;
        }
        self.seq += 1;
        self.followed.insert(k.clone(), Followed { seq: self.seq, value: None, deps: Vec::new() });
        self.pending.insert(k);
    }

    /// Stops following `k`: it is never due again until wanted again.
    pub fn unwant(&mut self, k: &K) {
        if let Some(f) = self.followed.remove(k) {
            self.unindex(k, &f.deps);
        }
        self.pending.remove(k);
    }

    /// Whether `k` is followed.
    pub fn wants(&self, k: &K) -> bool {
        self.followed.contains_key(k)
    }

    /// The followed keys whose last value read a stamp written since, and those never settled,
    /// in want order. A key stays due until it is settled.
    pub fn due(&mut self) -> Vec<K> {
        let mut maybe: HashSet<K> = std::mem::take(&mut self.pending);
        for ix in self.tables.values_mut() {
            let changes = lock(&ix.table).read_log(&mut ix.at);
            if changes.is_empty() {
                continue;
            }
            // any change moves what read it whole
            maybe.extend(ix.whole.iter().cloned());
            for c in changes {
                match c {
                    Logged::Key { h, present, .. } => {
                        maybe.extend(ix.keys.get(&h).into_iter().flatten().cloned());
                        if !present {
                            for x in ix.buckets.get(&bucket(h)).into_iter().flatten() {
                                maybe.extend(ix.keys.get(x).into_iter().flatten().cloned());
                            }
                        }
                    }
                    Logged::Whole => {}
                    Logged::All => maybe.extend(ix.keys.values().flatten().cloned()),
                }
            }
        }
        crate::costs::count("effects: candidates", maybe.len() as u64);
        // a logged write of a key read, before the read or by a key sharing its hash, moved
        // nothing: the stamps say which did
        let mut due: Vec<(u64, K)> = maybe.into_iter().filter_map(|k| self.followed.get(&k).filter(|f| f.value.is_none() || !f.deps.iter().all(Dep::holds)).map(|f| (f.seq, k))).collect();
        due.sort_by_key(|(s, _)| *s);
        self.pending.extend(due.iter().map(|(_, k)| k.clone()));
        due.into_iter().map(|(_, k)| k).collect()
    }

    /// `f`'s value for `k`, recorded as `k`'s: `Some((acted, now))` when it differs from the
    /// value last settled (`acted`, `None` for a key wanted since), `None` when it is the same.
    /// `k` is due again once something `f` read is written. A key not followed is not kept: its
    /// value is reported as new.
    pub fn settle(&mut self, k: &K, f: impl FnOnce() -> V) -> Option<(Option<V>, V)> {
        let _s = crate::costs::span(self.name);
        let (now, frame) = recorded_frame(f);
        let Some(old) = self.followed.get_mut(k) else { return Some((None, now)) };
        let was = old.value.replace(now.clone());
        let old_deps = std::mem::replace(&mut old.deps, frame.deps.clone());
        self.unindex(k, &old_deps);
        self.index(k, &frame.deps);
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
                Indexed { table: d.table.clone(), at, whole: HashSet::new(), keys: HashMap::new(), buckets: HashMap::new(), reads: 0 }
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
        let followed = self.followed.iter().map(|(k, f)| (k.clone(), Followed { seq: f.seq, value: f.value.clone(), deps: f.deps.iter().map(dep).collect() })).collect();
        let tables = self
            .tables
            .values()
            .map(|ix| {
                let table = cloned_table(&ix.table, ix.at);
                (Arc::as_ptr(&table) as usize, Indexed { table, at: ix.at, whole: ix.whole.clone(), keys: ix.keys.clone(), buckets: ix.buckets.clone(), reads: ix.reads })
            })
            .collect();
        Effects { name: self.name, followed, seq: self.seq, pending: self.pending.clone(), tables }
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
        let changes = lock(&self.table).read_log(&mut self.at);
        changes
            .into_iter()
            .filter_map(|c| match c {
                Logged::Key { added: Some(k), .. } => k.downcast_ref::<K>().cloned(),
                _ => None,
            })
            .collect()
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
        // a read of an absent key moves with a removal in its bucket, as its stamp does
        e.want(100);
        e.settle(&100, || read(&m, &s, 100));
        let removed = (0..=255u8).find(|x| super::super::bucket(super::super::hash(x)) == super::super::bucket(super::super::hash(&100u8)) && *x != 100).unwrap();
        m.insert(removed, 1);
        let _ = e.due();
        m.remove(&removed);
        assert_eq!(e.due(), [100], "a removal in the bucket of an absent key read");
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

    // spec: none (internal). The log is kept from the oldest live mark: a reader that reads
    // seldom still sees every write since its last read while another reads often, and a
    // container nobody follows (every reader gone) logs nothing.
    #[test]
    fn a_log_is_kept_for_its_oldest_reader() {
        let mut m: Stamped<u8, u8> = Stamped::default();
        let (mut often, mut seldom): (Effects<u8, u8>, Effects<u8, u8>) = (Effects::new("test often"), Effects::new("test seldom"));
        for e in [&mut often, &mut seldom] {
            e.want(1);
            e.due();
            e.settle(&1, || m.get(&1).copied().unwrap_or(0));
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
        e.want(1);
        e.due();
        e.settle(&1, || m.get(&1).copied().unwrap_or(0));
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
        e.want(1);
        e.due();
        e.settle(&1, || m.get(&1).copied().unwrap_or(0));
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
        e.want(1);
        e.due();
        e.settle(&1, || c.until(Some(30)) >= 30);
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
}
