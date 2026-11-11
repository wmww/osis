//! Journaled collections for the engine's in-memory indexes: every change records what it
//! replaced, so a failed transaction or step undoes exactly its own changes (O(changes)) instead
//! of restoring a copy of every index taken at its first change. Only the journaling methods
//! change the contents, and each change and undo stamps what it moved (`memo::Stamps`); a read
//! is stamped too: `get` and `contains` read one key, `Deref` the whole collection, so a `Memo`
//! computing depends on what it read here.

use super::memo::Stamps;
use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::Deref;

/// What a journaled collection does at the end of a transaction, and at a step's start and
/// failure (`Tx::step`).
pub(crate) trait Journaled {
    /// A point in the journal.
    type Mark;
    /// Forgets the journal (the transaction committed).
    fn commit(&mut self);
    /// The journal's current point.
    fn mark(&mut self) -> Self::Mark;
    /// Undoes every change journaled after `m`, newest first.
    fn rollback_to(&mut self, m: Self::Mark);
    /// The contents, without journal or counters (tests: a rollback restores them).
    #[cfg(test)]
    fn contents(&self) -> String;
}

/// A map journaling each key's previous value, once per transaction or step (a rollback restores
/// the first: a value changed many times in one transaction, as a value-less list growing by one
/// per expiry in a round, costs one copy, not one per change).
#[derive(Clone, Debug)]
pub struct JMap<K: Ord + Clone + Hash, V: Clone> {
    map: BTreeMap<K, V>,
    stamps: Stamps,
    log: Vec<(K, Option<V>)>,
    /// The keys `log` holds since the last mark.
    seen: BTreeSet<K>,
}

impl<K: Ord + Clone + Hash, V: Clone> Default for JMap<K, V> {
    fn default() -> Self {
        JMap { map: BTreeMap::new(), stamps: Stamps::default(), log: Vec::new(), seen: BTreeSet::new() }
    }
}

impl<K: Ord + Clone + Hash, V: Clone> Deref for JMap<K, V> {
    type Target = BTreeMap<K, V>;
    fn deref(&self) -> &BTreeMap<K, V> {
        self.stamps.read_all();
        &self.map
    }
}

impl<K: Ord + Clone + Hash, V: Clone> JMap<K, V> {
    /// Journals `k`'s value before this transaction's first change of it.
    fn note(&mut self, k: &K, old: impl FnOnce(&BTreeMap<K, V>) -> Option<V>) {
        if !self.seen.contains(k) {
            self.seen.insert(k.clone());
            self.log.push((k.clone(), old(&self.map)));
        }
    }
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
        self.note(&k, |m| m.get(&k).cloned());
        self.stamps.wrote(&k, true);
        self.map.insert(k, v)
    }
    pub fn remove(&mut self, k: &K) -> Option<V> {
        if self.map.contains_key(k) {
            self.note(k, |m| m.get(k).cloned());
            self.stamps.wrote(k, false);
        }
        self.map.remove(k)
    }
    /// What the running transaction changed, each key with its value before it.
    pub fn before(&self) -> BTreeMap<&K, Option<&V>> {
        let mut out = BTreeMap::new();
        for (k, v) in &self.log {
            out.entry(k).or_insert(v.as_ref());
        }
        out
    }
    /// The value to change in place (its previous value journaled).
    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        if !self.map.contains_key(k) {
            return None;
        }
        self.note(k, |m| m.get(k).cloned());
        self.stamps.wrote(k, true);
        self.map.get_mut(k)
    }
    /// The value of `k`, inserted from `default` if absent, to change in place.
    pub fn entry_or(&mut self, k: K, default: impl FnOnce() -> V) -> &mut V {
        self.note(&k, |m| m.get(&k).cloned());
        self.stamps.wrote(&k, true);
        self.map.entry(k).or_insert_with(default)
    }
    /// Changes the value of `k` (from `default` if absent) by `f`, journaled only if it changed.
    pub fn upsert(&mut self, k: K, default: impl FnOnce() -> V, f: impl FnOnce(&mut V))
    where
        V: PartialEq,
    {
        let old = self.map.get(&k).cloned();
        let mut v = old.clone().unwrap_or_else(default);
        f(&mut v);
        if old.as_ref() != Some(&v) {
            self.note(&k, |_| old);
            self.stamps.wrote(&k, true);
            self.map.insert(k, v);
        }
    }
    pub fn entry_or_default(&mut self, k: K) -> &mut V
    where
        V: Default,
    {
        self.entry_or(k, V::default)
    }
    /// Keeps the entries `f` accepts.
    pub fn retain(&mut self, mut f: impl FnMut(&K, &V) -> bool) {
        let gone: Vec<K> = self.map.iter().filter(|(k, v)| !f(k, v)).map(|(k, _)| k.clone()).collect();
        for k in gone {
            self.remove(&k);
        }
    }
    pub fn extend(&mut self, it: impl IntoIterator<Item = (K, V)>) {
        for (k, v) in it {
            self.insert(k, v);
        }
    }
    /// Whether the running transaction changed any key.
    pub fn changed(&self) -> bool {
        !self.log.is_empty()
    }
    /// The journal's length (a mark is one).
    pub fn journaled(&self) -> usize {
        self.log.len()
    }
    /// The keys the running transaction changed.
    pub fn logged(&self) -> Vec<K> {
        let s: std::collections::BTreeSet<&K> = self.log.iter().map(|(k, _)| k).collect();
        s.into_iter().cloned().collect()
    }
}

impl<K: Ord + Clone + Hash + Debug, V: Clone + Debug> Journaled for JMap<K, V> {
    #[cfg(test)]
    fn contents(&self) -> String {
        format!("{:?}", self.map)
    }
    type Mark = usize;
    fn commit(&mut self) {
        self.log.clear();
        self.seen.clear();
    }
    // a key changed after the mark is journaled again: its entry restores the value at the mark
    fn mark(&mut self) -> usize {
        self.seen.clear();
        self.log.len()
    }
    fn rollback_to(&mut self, m: usize) {
        self.seen.clear();
        while self.log.len() > m {
            let Some((k, old)) = self.log.pop() else { break };
            self.stamps.wrote(&k, old.is_some());
            match old {
                Some(v) => self.map.insert(k, v),
                None => self.map.remove(&k),
            };
        }
    }
}

/// A set journaling each change.
#[derive(Clone, Debug)]
pub struct JSet<T: Ord + Clone + Hash> {
    set: BTreeSet<T>,
    stamps: Stamps,
    log: Vec<(T, bool)>,
}

impl<T: Ord + Clone + Hash> Default for JSet<T> {
    fn default() -> Self {
        JSet { set: BTreeSet::new(), stamps: Stamps::default(), log: Vec::new() }
    }
}

impl<T: Ord + Clone + Hash> Deref for JSet<T> {
    type Target = BTreeSet<T>;
    fn deref(&self) -> &BTreeSet<T> {
        self.stamps.read_all();
        &self.set
    }
}

impl<T: Ord + Clone + Hash> JSet<T> {
    pub fn contains<Q: Ord + Hash + ?Sized>(&self, t: &Q) -> bool
    where
        T: Borrow<Q>,
    {
        self.stamps.read(t);
        self.set.contains(t)
    }
    pub fn insert(&mut self, t: T) -> bool {
        let new = self.set.insert(t.clone());
        if new {
            self.stamps.wrote(&t, true);
            self.log.push((t, false));
        }
        new
    }
    pub fn remove(&mut self, t: &T) -> bool {
        let was = self.set.remove(t);
        if was {
            self.stamps.wrote(t, false);
            self.log.push((t.clone(), true));
        }
        was
    }
    pub fn extend(&mut self, it: impl IntoIterator<Item = T>) {
        for t in it {
            self.insert(t);
        }
    }
    /// The items the running transaction changed.
    pub fn logged(&self) -> Vec<T> {
        let s: BTreeSet<&T> = self.log.iter().map(|(t, _)| t).collect();
        s.into_iter().cloned().collect()
    }
}

impl<T: Ord + Clone + Hash + Debug> Journaled for JSet<T> {
    #[cfg(test)]
    fn contents(&self) -> String {
        format!("{:?}", self.set)
    }
    type Mark = usize;
    fn commit(&mut self) {
        self.log.clear();
    }
    fn mark(&mut self) -> usize {
        self.log.len()
    }
    fn rollback_to(&mut self, m: usize) {
        while self.log.len() > m {
            let Some((t, was)) = self.log.pop() else { break };
            self.stamps.wrote(&t, was);
            if was {
                self.set.insert(t);
            } else {
                self.set.remove(&t);
            }
        }
    }
}

/// A map of sets journaling each element change (an emptied set is removed).
#[derive(Clone, Debug)]
pub struct JSetMap<K: Ord + Clone + Hash, T: Ord + Clone> {
    map: BTreeMap<K, BTreeSet<T>>,
    stamps: Stamps,
    log: Vec<(K, T, bool)>,
}

impl<K: Ord + Clone + Hash, T: Ord + Clone> Default for JSetMap<K, T> {
    fn default() -> Self {
        JSetMap { map: BTreeMap::new(), stamps: Stamps::default(), log: Vec::new() }
    }
}

impl<K: Ord + Clone + Hash, T: Ord + Clone> Deref for JSetMap<K, T> {
    type Target = BTreeMap<K, BTreeSet<T>>;
    fn deref(&self) -> &BTreeMap<K, BTreeSet<T>> {
        self.stamps.read_all();
        &self.map
    }
}

impl<K: Ord + Clone + Hash, T: Ord + Clone> JSetMap<K, T> {
    fn raw_insert(map: &mut BTreeMap<K, BTreeSet<T>>, k: K, t: T) -> bool {
        map.entry(k).or_default().insert(t)
    }
    fn raw_remove(map: &mut BTreeMap<K, BTreeSet<T>>, k: &K, t: &T) -> bool {
        let Some(s) = map.get_mut(k) else { return false };
        let was = s.remove(t);
        if s.is_empty() {
            map.remove(k);
        }
        was
    }
    /// The set of `k` (a read of that key: any change of its set moves it).
    pub fn get<Q: Ord + Hash + ?Sized>(&self, k: &Q) -> Option<&BTreeSet<T>>
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
    fn stamp(&mut self, k: &K) {
        self.stamps.wrote(k, self.map.contains_key(k));
    }
    pub fn insert(&mut self, k: K, t: T) -> bool {
        let new = Self::raw_insert(&mut self.map, k.clone(), t.clone());
        if new {
            self.stamp(&k);
            self.log.push((k, t, false));
        }
        new
    }
    pub fn remove(&mut self, k: &K, t: &T) -> bool {
        let was = Self::raw_remove(&mut self.map, k, t);
        if was {
            self.stamp(k);
            self.log.push((k.clone(), t.clone(), true));
        }
        was
    }
    /// Each element the running transaction changed, and whether it was in when it began.
    pub fn was_in(&self) -> BTreeMap<(K, T), bool> {
        let mut out = BTreeMap::new();
        for (k, t, was) in &self.log {
            out.entry((k.clone(), t.clone())).or_insert(*was);
        }
        out
    }

    /// The elements the running transaction changed.
    pub fn logged(&self) -> Vec<(K, T)> {
        let s: BTreeSet<(&K, &T)> = self.log.iter().map(|(k, t, _)| (k, t)).collect();
        s.into_iter().map(|(k, t)| (k.clone(), t.clone())).collect()
    }
}

impl<K: Ord + Clone + Hash + Debug, T: Ord + Clone + Debug> Journaled for JSetMap<K, T> {
    #[cfg(test)]
    fn contents(&self) -> String {
        format!("{:?}", self.map)
    }
    type Mark = usize;
    fn commit(&mut self) {
        self.log.clear();
    }
    fn mark(&mut self) -> usize {
        self.log.len()
    }
    fn rollback_to(&mut self, m: usize) {
        while self.log.len() > m {
            let Some((k, t, was)) = self.log.pop() else { break };
            if was {
                Self::raw_insert(&mut self.map, k.clone(), t);
            } else {
                Self::raw_remove(&mut self.map, &k, &t);
            }
            self.stamp(&k);
        }
    }
}

/// A map of maps journaling each inner entry's previous value (an emptied inner map is removed).
#[derive(Clone, Debug)]
pub struct JNested<K: Ord + Clone + Hash, K2: Ord + Clone, V: Clone> {
    map: BTreeMap<K, BTreeMap<K2, V>>,
    stamps: Stamps,
    log: Vec<(K, K2, Option<V>)>,
}

impl<K: Ord + Clone + Hash, K2: Ord + Clone, V: Clone> Default for JNested<K, K2, V> {
    fn default() -> Self {
        JNested { map: BTreeMap::new(), stamps: Stamps::default(), log: Vec::new() }
    }
}

impl<K: Ord + Clone + Hash, K2: Ord + Clone, V: Clone> Deref for JNested<K, K2, V> {
    type Target = BTreeMap<K, BTreeMap<K2, V>>;
    fn deref(&self) -> &BTreeMap<K, BTreeMap<K2, V>> {
        self.stamps.read_all();
        &self.map
    }
}

impl<K: Ord + Clone + Hash, K2: Ord + Clone, V: Clone> JNested<K, K2, V> {
    fn put(map: &mut BTreeMap<K, BTreeMap<K2, V>>, k: K, k2: K2, v: Option<V>) -> Option<V> {
        match v {
            Some(v) => map.entry(k).or_default().insert(k2, v),
            None => {
                let inner = map.get_mut(&k)?;
                let old = inner.remove(&k2);
                if inner.is_empty() {
                    map.remove(&k);
                }
                old
            }
        }
    }
    /// The inner map of `k` (a read of that key: any change of its entries moves it).
    pub fn get<Q: Ord + Hash + ?Sized>(&self, k: &Q) -> Option<&BTreeMap<K2, V>>
    where
        K: Borrow<Q>,
    {
        self.stamps.read(k);
        self.map.get(k)
    }
    fn stamp(&mut self, k: &K) {
        self.stamps.wrote(k, self.map.contains_key(k));
    }
    pub fn insert(&mut self, k: K, k2: K2, v: V) -> Option<V> {
        let old = Self::put(&mut self.map, k.clone(), k2.clone(), Some(v));
        self.stamp(&k);
        self.log.push((k, k2, old.clone()));
        old
    }
    pub fn remove(&mut self, k: &K, k2: &K2) -> Option<V> {
        let old = Self::put(&mut self.map, k.clone(), k2.clone(), None);
        if old.is_some() {
            self.stamp(k);
            self.log.push((k.clone(), k2.clone(), old.clone()));
        }
        old
    }
}

impl<K: Ord + Clone + Hash + Debug, K2: Ord + Clone + Debug, V: Clone + Debug> Journaled for JNested<K, K2, V> {
    #[cfg(test)]
    fn contents(&self) -> String {
        format!("{:?}", self.map)
    }
    type Mark = usize;
    fn commit(&mut self) {
        self.log.clear();
    }
    fn mark(&mut self) -> usize {
        self.log.len()
    }
    fn rollback_to(&mut self, m: usize) {
        while self.log.len() > m {
            let Some((k, k2, old)) = self.log.pop() else { break };
            Self::put(&mut self.map, k.clone(), k2, old);
            self.stamp(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/commits.md §4 (one storage transaction per commit): undoing the journal restores the
    // indexes as they were before the transaction, whatever mix of changes it made.
    #[test]
    fn rollback_restores_spec_commits_4() {
        let mut m: JMap<u8, Vec<u8>> = JMap::default();
        m.insert(1, vec![1]);
        m.commit();
        m.insert(2, vec![2]);
        m.get_mut(&1).unwrap().push(9);
        m.entry_or_default(3).push(3);
        m.remove(&1);
        m.retain(|k, _| *k != 2);
        m.rollback_to(0);
        assert_eq!(*m, BTreeMap::from([(1, vec![1])]));
        // each key journaled once per transaction: set, removed, set again, either way
        m.insert(4, vec![4]);
        m.remove(&4);
        m.insert(4, vec![5]);
        m.remove(&1);
        m.insert(1, vec![7]);
        m.get_mut(&1).unwrap().push(8);
        m.rollback_to(0);
        assert_eq!(*m, BTreeMap::from([(1, vec![1])]));
        // a rollback forgets what it journaled: the next transaction journals afresh
        m.insert(1, vec![2]);
        m.commit();
        m.insert(1, vec![3]);
        m.rollback_to(0);
        assert_eq!(*m, BTreeMap::from([(1, vec![2])]));
        let mut s: JSetMap<u8, u8> = JSetMap::default();
        s.insert(1, 1);
        s.commit();
        s.insert(1, 2);
        s.remove(&1, &1);
        s.insert(2, 2);
        s.rollback_to(0);
        assert_eq!(*s, BTreeMap::from([(1, BTreeSet::from([1]))]));
        let mut n: JNested<u8, u8, u8> = JNested::default();
        n.insert(1, 1, 1);
        n.commit();
        n.insert(1, 1, 2);
        n.insert(2, 1, 1);
        n.rollback_to(0);
        assert_eq!(*n, BTreeMap::from([(1, BTreeMap::from([(1, 1)]))]));
        let mut t: JSet<u8> = JSet::default();
        t.insert(1);
        t.commit();
        t.remove(&1);
        t.insert(2);
        t.rollback_to(0);
        assert_eq!(*t, BTreeSet::from([1]));
    }

    // spec: none (internal: notes/engine.md, Atomic steps). A rollback to a mark (a failed step, `Tx::step`) restores the contents at the mark: what
    // changed before it stays, also for a key changed both before and after it; a rollback to
    // the transaction's start still restores the first value.
    #[test]
    fn rollback_to_mark_keeps_earlier_changes() {
        let mut m: JMap<u8, u8> = JMap::default();
        m.insert(1, 1);
        m.commit();
        m.insert(1, 2);
        m.insert(2, 2);
        let mark = m.mark();
        m.insert(1, 3);
        m.remove(&2);
        m.insert(3, 3);
        m.rollback_to(mark);
        assert_eq!(*m, BTreeMap::from([(1, 2), (2, 2)]));
        m.insert(1, 4);
        m.rollback_to(0);
        assert_eq!(*m, BTreeMap::from([(1, 1)]));
        let mut s: JSetMap<u8, u8> = JSetMap::default();
        s.insert(1, 1);
        let mark = s.mark();
        s.remove(&1, &1);
        s.insert(2, 2);
        s.rollback_to(mark);
        assert_eq!(*s, BTreeMap::from([(1, BTreeSet::from([1]))]));
        let mut t: JSet<u8> = JSet::default();
        t.insert(1);
        let mark = t.mark();
        t.insert(2);
        t.rollback_to(mark);
        assert_eq!(*t, BTreeSet::from([1]));
    }
}
