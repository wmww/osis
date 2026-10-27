//! Journaled collections for the engine's in-memory indexes: every change records what it
//! replaced, so a failed transaction undoes exactly its own changes (O(changes)) instead of
//! restoring a copy of every index taken at its first change. Reads go through `Deref`; only the
//! journaling methods change the contents.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;

/// What a journaled collection does at the end of a transaction.
pub(crate) trait Journaled {
    /// Forgets the journal (the transaction committed).
    fn commit(&mut self);
    /// Undoes every journaled change, newest first.
    fn rollback(&mut self);
}

/// A map journaling each key's previous value.
#[derive(Debug)]
pub(crate) struct JMap<K: Ord + Clone, V: Clone> {
    map: BTreeMap<K, V>,
    log: Vec<(K, Option<V>)>,
}

impl<K: Ord + Clone, V: Clone> Default for JMap<K, V> {
    fn default() -> Self {
        JMap { map: BTreeMap::new(), log: Vec::new() }
    }
}

impl<K: Ord + Clone, V: Clone> Deref for JMap<K, V> {
    type Target = BTreeMap<K, V>;
    fn deref(&self) -> &BTreeMap<K, V> {
        &self.map
    }
}

impl<K: Ord + Clone, V: Clone> JMap<K, V> {
    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        let old = self.map.insert(k.clone(), v);
        self.log.push((k, old.clone()));
        old
    }
    pub fn remove(&mut self, k: &K) -> Option<V> {
        let old = self.map.remove(k);
        if old.is_some() {
            self.log.push((k.clone(), old.clone()));
        }
        old
    }
    /// The value to change in place (its previous value journaled).
    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        let old = self.map.get(k)?.clone();
        self.log.push((k.clone(), Some(old)));
        self.map.get_mut(k)
    }
    /// The value of `k`, inserted from `default` if absent, to change in place.
    pub fn entry_or(&mut self, k: K, default: impl FnOnce() -> V) -> &mut V {
        let old = self.map.get(&k).cloned();
        self.log.push((k.clone(), old));
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
            self.map.insert(k.clone(), v);
            self.log.push((k, old));
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
    /// The keys the running transaction changed.
    pub fn logged(&self) -> Vec<K> {
        let s: std::collections::BTreeSet<&K> = self.log.iter().map(|(k, _)| k).collect();
        s.into_iter().cloned().collect()
    }
}

impl<K: Ord + Clone, V: Clone> Journaled for JMap<K, V> {
    fn commit(&mut self) {
        self.log.clear();
    }
    fn rollback(&mut self) {
        while let Some((k, old)) = self.log.pop() {
            match old {
                Some(v) => self.map.insert(k, v),
                None => self.map.remove(&k),
            };
        }
    }
}

/// A set journaling each change.
#[derive(Debug)]
pub(crate) struct JSet<T: Ord + Clone> {
    set: BTreeSet<T>,
    log: Vec<(T, bool)>,
    /// Counts changes, rollbacks included (`changes`).
    changes: u64,
}

impl<T: Ord + Clone> Default for JSet<T> {
    fn default() -> Self {
        JSet { set: BTreeSet::new(), log: Vec::new(), changes: 0 }
    }
}

impl<T: Ord + Clone> Deref for JSet<T> {
    type Target = BTreeSet<T>;
    fn deref(&self) -> &BTreeSet<T> {
        &self.set
    }
}

impl<T: Ord + Clone> JSet<T> {
    pub fn insert(&mut self, t: T) -> bool {
        let new = self.set.insert(t.clone());
        if new {
            self.log.push((t, false));
            self.changes += 1;
        }
        new
    }
    pub fn remove(&mut self, t: &T) -> bool {
        let was = self.set.remove(t);
        if was {
            self.log.push((t.clone(), true));
            self.changes += 1;
        }
        was
    }
    /// A count that moves whenever the set may have changed (caches derived from it compare it).
    pub fn changes(&self) -> u64 {
        self.changes
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

impl<T: Ord + Clone> Journaled for JSet<T> {
    fn commit(&mut self) {
        self.log.clear();
    }
    fn rollback(&mut self) {
        if !self.log.is_empty() {
            self.changes += 1;
        }
        while let Some((t, was)) = self.log.pop() {
            if was {
                self.set.insert(t);
            } else {
                self.set.remove(&t);
            }
        }
    }
}

/// A map of sets journaling each element change (an emptied set is removed).
#[derive(Debug)]
pub(crate) struct JSetMap<K: Ord + Clone, T: Ord + Clone> {
    map: BTreeMap<K, BTreeSet<T>>,
    log: Vec<(K, T, bool)>,
}

impl<K: Ord + Clone, T: Ord + Clone> Default for JSetMap<K, T> {
    fn default() -> Self {
        JSetMap { map: BTreeMap::new(), log: Vec::new() }
    }
}

impl<K: Ord + Clone, T: Ord + Clone> Deref for JSetMap<K, T> {
    type Target = BTreeMap<K, BTreeSet<T>>;
    fn deref(&self) -> &BTreeMap<K, BTreeSet<T>> {
        &self.map
    }
}

impl<K: Ord + Clone, T: Ord + Clone> JSetMap<K, T> {
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
    pub fn insert(&mut self, k: K, t: T) -> bool {
        let new = Self::raw_insert(&mut self.map, k.clone(), t.clone());
        if new {
            self.log.push((k, t, false));
        }
        new
    }
    pub fn remove(&mut self, k: &K, t: &T) -> bool {
        let was = Self::raw_remove(&mut self.map, k, t);
        if was {
            self.log.push((k.clone(), t.clone(), true));
        }
        was
    }
    /// The elements the running transaction changed.
    pub fn logged(&self) -> Vec<(K, T)> {
        let s: BTreeSet<(&K, &T)> = self.log.iter().map(|(k, t, _)| (k, t)).collect();
        s.into_iter().map(|(k, t)| (k.clone(), t.clone())).collect()
    }
}

impl<K: Ord + Clone, T: Ord + Clone> Journaled for JSetMap<K, T> {
    fn commit(&mut self) {
        self.log.clear();
    }
    fn rollback(&mut self) {
        while let Some((k, t, was)) = self.log.pop() {
            if was {
                Self::raw_insert(&mut self.map, k, t);
            } else {
                Self::raw_remove(&mut self.map, &k, &t);
            }
        }
    }
}

/// A map of maps journaling each inner entry's previous value (an emptied inner map is removed).
#[derive(Debug)]
pub(crate) struct JNested<K: Ord + Clone, K2: Ord + Clone, V: Clone> {
    map: BTreeMap<K, BTreeMap<K2, V>>,
    log: Vec<(K, K2, Option<V>)>,
}

impl<K: Ord + Clone, K2: Ord + Clone, V: Clone> Default for JNested<K, K2, V> {
    fn default() -> Self {
        JNested { map: BTreeMap::new(), log: Vec::new() }
    }
}

impl<K: Ord + Clone, K2: Ord + Clone, V: Clone> Deref for JNested<K, K2, V> {
    type Target = BTreeMap<K, BTreeMap<K2, V>>;
    fn deref(&self) -> &BTreeMap<K, BTreeMap<K2, V>> {
        &self.map
    }
}

impl<K: Ord + Clone, K2: Ord + Clone, V: Clone> JNested<K, K2, V> {
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
    pub fn insert(&mut self, k: K, k2: K2, v: V) -> Option<V> {
        let old = Self::put(&mut self.map, k.clone(), k2.clone(), Some(v));
        self.log.push((k, k2, old.clone()));
        old
    }
}

impl<K: Ord + Clone, K2: Ord + Clone, V: Clone> Journaled for JNested<K, K2, V> {
    fn commit(&mut self) {
        self.log.clear();
    }
    fn rollback(&mut self) {
        while let Some((k, k2, old)) = self.log.pop() {
            Self::put(&mut self.map, k, k2, old);
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
        m.rollback();
        assert_eq!(*m, BTreeMap::from([(1, vec![1])]));
        let mut s: JSetMap<u8, u8> = JSetMap::default();
        s.insert(1, 1);
        s.commit();
        s.insert(1, 2);
        s.remove(&1, &1);
        s.insert(2, 2);
        s.rollback();
        assert_eq!(*s, BTreeMap::from([(1, BTreeSet::from([1]))]));
        let mut n: JNested<u8, u8, u8> = JNested::default();
        n.insert(1, 1, 1);
        n.commit();
        n.insert(1, 1, 2);
        n.insert(2, 1, 1);
        n.rollback();
        assert_eq!(*n, BTreeMap::from([(1, BTreeMap::from([(1, 1)]))]));
        let mut t: JSet<u8> = JSet::default();
        t.insert(1);
        t.commit();
        t.remove(&1);
        t.insert(2);
        t.rollback();
        assert_eq!(*t, BTreeSet::from([1]));
    }
}
