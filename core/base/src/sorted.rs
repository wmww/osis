//! `Value::Map` and `Value::Set`: sorted vectors by `Value`'s `Ord`, unique by construction. A
//! B-tree would cost one node per non-empty map or set however small; here a value's containers
//! hold just its items, which keeps a decode's memory proportional to its input (`cbor::decode`).
//! An insert in the middle moves what follows, so build a large one with `collect`.

use crate::value::Value;
use std::fmt;

/// Whether `s` is strictly increasing by `key`.
fn strictly_sorted<T>(s: &[T], key: impl Fn(&T) -> &Value) -> bool {
    s.windows(2).all(|w| matches!(w, [a, b] if key(a) < key(b)))
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct ValueMap(Vec<(Value, Value)>);

impl ValueMap {
    pub const fn new() -> ValueMap {
        ValueMap(Vec::new())
    }

    /// Entries as decoded: sorted by canonical bytes, which only a link can make differ from `Ord`.
    /// `None` when two keys are equal values (links of one content hash).
    pub(crate) fn from_decoded(mut entries: Vec<(Value, Value)>) -> Option<ValueMap> {
        if !strictly_sorted(&entries, |e| &e.0) {
            entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            if !strictly_sorted(&entries, |e| &e.0) {
                return None;
            }
        }
        Some(ValueMap(entries))
    }

    fn find(&self, k: &Value) -> Result<usize, usize> {
        self.0.binary_search_by(|e| e.0.cmp(k))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn get(&self, k: &Value) -> Option<&Value> {
        self.find(k).ok().and_then(|i| self.0.get(i)).map(|e| &e.1)
    }
    pub fn get_mut(&mut self, k: &Value) -> Option<&mut Value> {
        let i = self.find(k).ok()?;
        self.0.get_mut(i).map(|e| &mut e.1)
    }
    pub fn contains_key(&self, k: &Value) -> bool {
        self.find(k).is_ok()
    }
    /// Sets `k`'s value; returns the one it replaces (the key held stays, as in a `BTreeMap`).
    pub fn insert(&mut self, k: Value, v: Value) -> Option<Value> {
        if self.0.last().is_none_or(|e| e.0 < k) {
            self.0.push((k, v));
            return None;
        }
        match self.find(&k) {
            Ok(i) => self.0.get_mut(i).map(|e| std::mem::replace(&mut e.1, v)),
            Err(i) => {
                self.0.insert(i, (k, v));
                None
            }
        }
    }
    pub fn remove(&mut self, k: &Value) -> Option<Value> {
        self.find(k).ok().map(|i| self.0.remove(i).1)
    }
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&Value, &Value)> + ExactSizeIterator {
        self.0.iter().map(|e| (&e.0, &e.1))
    }
    pub fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = (&Value, &mut Value)> + ExactSizeIterator {
        self.0.iter_mut().map(|e| (&e.0, &mut e.1))
    }
    pub fn keys(&self) -> impl DoubleEndedIterator<Item = &Value> + ExactSizeIterator {
        self.0.iter().map(|e| &e.0)
    }
    pub fn values(&self) -> impl DoubleEndedIterator<Item = &Value> + ExactSizeIterator {
        self.0.iter().map(|e| &e.1)
    }
    pub fn values_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut Value> + ExactSizeIterator {
        self.0.iter_mut().map(|e| &mut e.1)
    }
    pub fn into_keys(self) -> impl DoubleEndedIterator<Item = Value> + ExactSizeIterator {
        self.0.into_iter().map(|e| e.0)
    }
    pub fn into_values(self) -> impl DoubleEndedIterator<Item = Value> + ExactSizeIterator {
        self.0.into_iter().map(|e| e.1)
    }
}

impl fmt::Debug for ValueMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

/// Of equal keys the last entry stays, as in a `BTreeMap`'s `collect`.
impl FromIterator<(Value, Value)> for ValueMap {
    fn from_iter<I: IntoIterator<Item = (Value, Value)>>(it: I) -> ValueMap {
        let mut entries: Vec<(Value, Value)> = it.into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries.dedup_by(|later, kept| {
            let same = later.0 == kept.0;
            if same {
                std::mem::swap(later, kept);
            }
            same
        });
        ValueMap(entries)
    }
}

impl Extend<(Value, Value)> for ValueMap {
    fn extend<I: IntoIterator<Item = (Value, Value)>>(&mut self, it: I) {
        for (k, v) in it {
            self.insert(k, v);
        }
    }
}

impl<const N: usize> From<[(Value, Value); N]> for ValueMap {
    fn from(a: [(Value, Value); N]) -> ValueMap {
        a.into_iter().collect()
    }
}

impl IntoIterator for ValueMap {
    type Item = (Value, Value);
    type IntoIter = std::vec::IntoIter<(Value, Value)>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

type RefPair<'a> = fn(&'a (Value, Value)) -> (&'a Value, &'a Value);

impl<'a> IntoIterator for &'a ValueMap {
    type Item = (&'a Value, &'a Value);
    type IntoIter = std::iter::Map<std::slice::Iter<'a, (Value, Value)>, RefPair<'a>>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter().map(|e| (&e.0, &e.1))
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct ValueSet(Vec<Value>);

impl ValueSet {
    pub const fn new() -> ValueSet {
        ValueSet(Vec::new())
    }

    /// Elements as decoded (`ValueMap::from_decoded`).
    pub(crate) fn from_decoded(mut items: Vec<Value>) -> Option<ValueSet> {
        if !strictly_sorted(&items, |e| e) {
            items.sort_unstable();
            if !strictly_sorted(&items, |e| e) {
                return None;
            }
        }
        Some(ValueSet(items))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// The held element equal to `v`.
    pub fn get(&self, v: &Value) -> Option<&Value> {
        self.0.binary_search(v).ok().and_then(|i| self.0.get(i))
    }
    pub fn contains(&self, v: &Value) -> bool {
        self.0.binary_search(v).is_ok()
    }
    /// Whether `v` was new (an equal element held stays, as in a `BTreeSet`).
    pub fn insert(&mut self, v: Value) -> bool {
        if self.0.last().is_none_or(|e| *e < v) {
            self.0.push(v);
            return true;
        }
        match self.0.binary_search(&v) {
            Ok(_) => false,
            Err(i) => {
                self.0.insert(i, v);
                true
            }
        }
    }
    pub fn remove(&mut self, v: &Value) -> bool {
        match self.0.binary_search(v) {
            Ok(i) => {
                self.0.remove(i);
                true
            }
            Err(_) => false,
        }
    }
    pub fn iter(&self) -> std::slice::Iter<'_, Value> {
        self.0.iter()
    }
    /// The elements of `self` not in `other`.
    pub fn difference<'a>(&'a self, other: &'a ValueSet) -> impl Iterator<Item = &'a Value> {
        self.iter().filter(|v| !other.contains(v))
    }
}

impl fmt::Debug for ValueSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

/// Of equal elements the last stays, as in a `BTreeSet`'s `collect`.
impl FromIterator<Value> for ValueSet {
    fn from_iter<I: IntoIterator<Item = Value>>(it: I) -> ValueSet {
        let mut items: Vec<Value> = it.into_iter().collect();
        items.sort();
        items.dedup_by(|later, kept| {
            let same = later == kept;
            if same {
                std::mem::swap(later, kept);
            }
            same
        });
        ValueSet(items)
    }
}

impl<const N: usize> From<[Value; N]> for ValueSet {
    fn from(a: [Value; N]) -> ValueSet {
        a.into_iter().collect()
    }
}

impl IntoIterator for ValueSet {
    type Item = Value;
    type IntoIter = std::vec::IntoIter<Value>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a ValueSet {
    type Item = &'a Value;
    type IntoIter = std::slice::Iter<'a, Value>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}
