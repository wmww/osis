//! `IdSet`: a set of small commit indices as a bitset, with the `BTreeSet<usize>` interface the
//! model uses (ascending iteration, the same `Ord`, `Debug` and `Hash`-by-members), at a fraction
//! of its cost: the searches spend most of their time building, walking and comparing such sets.

use std::cmp::Ordering;
use std::fmt;

/// Indices up to this are held; one past it panics (worlds hold a few dozen commits).
pub const MAX: usize = 4096;

/// Each index as a `&'static usize`, so iteration yields references as a `BTreeSet`'s does.
static IDS: [usize; MAX] = {
    let mut a = [0; MAX];
    let mut i = 0;
    while i < MAX {
        a[i] = i;
        i += 1;
    }
    a
};

/// Words of 64 members; no trailing zero word, so equal sets are equal vectors.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct IdSet {
    w: Vec<u64>,
}

impl IdSet {
    pub fn new() -> IdSet {
        IdSet { w: Vec::new() }
    }
    fn trim(&mut self) {
        while self.w.last() == Some(&0) {
            self.w.pop();
        }
    }
    pub fn len(&self) -> usize {
        self.w.iter().map(|x| x.count_ones() as usize).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.w.is_empty()
    }
    pub fn contains(&self, i: &usize) -> bool {
        self.w.get(i / 64).is_some_and(|x| x >> (i % 64) & 1 == 1)
    }
    pub fn insert(&mut self, i: usize) -> bool {
        assert!(i < MAX, "IdSet holds indices below {MAX}");
        if self.w.len() <= i / 64 {
            self.w.resize(i / 64 + 1, 0);
        }
        let (x, b) = (&mut self.w[i / 64], 1u64 << (i % 64));
        let new = *x & b == 0;
        *x |= b;
        new
    }
    pub fn remove(&mut self, i: &usize) -> bool {
        let Some(x) = self.w.get_mut(i / 64) else { return false };
        let b = 1u64 << (i % 64);
        let had = *x & b != 0;
        *x &= !b;
        self.trim();
        had
    }
    pub fn clear(&mut self) {
        self.w.clear();
    }
    pub fn iter(&self) -> Iter<'_> {
        Iter { w: &self.w, front: 0, back: self.w.len() * 64 }
    }
    pub fn first(&self) -> Option<&usize> {
        self.iter().next()
    }
    pub fn last(&self) -> Option<&usize> {
        self.iter().next_back()
    }
    pub fn pop_first(&mut self) -> Option<usize> {
        let i = *self.first()?;
        self.remove(&i);
        Some(i)
    }
    pub fn pop_last(&mut self) -> Option<usize> {
        let i = *self.last()?;
        self.remove(&i);
        Some(i)
    }
    pub fn retain(&mut self, mut f: impl FnMut(&usize) -> bool) {
        let gone: Vec<usize> = self.iter().copied().filter(|i| !f(i)).collect();
        for i in gone {
            self.remove(&i);
        }
    }
    fn word(&self, k: usize) -> u64 {
        self.w.get(k).copied().unwrap_or(0)
    }
    fn zip(&self, o: &IdSet, f: impl Fn(u64, u64) -> u64) -> IdSet {
        let mut s = IdSet { w: (0..self.w.len().max(o.w.len())).map(|k| f(self.word(k), o.word(k))).collect() };
        s.trim();
        s
    }
    pub fn difference<'a>(&'a self, o: &IdSet) -> IntoIter<'a> {
        self.zip(o, |a, b| a & !b).into_ids()
    }
    pub fn intersection<'a>(&'a self, o: &IdSet) -> IntoIter<'a> {
        self.zip(o, |a, b| a & b).into_ids()
    }
    pub fn union<'a>(&'a self, o: &IdSet) -> IntoIter<'a> {
        self.zip(o, |a, b| a | b).into_ids()
    }
    pub fn symmetric_difference<'a>(&'a self, o: &IdSet) -> IntoIter<'a> {
        self.zip(o, |a, b| a ^ b).into_ids()
    }
    pub fn is_subset(&self, o: &IdSet) -> bool {
        self.w.iter().enumerate().all(|(k, x)| x & !o.word(k) == 0)
    }
    pub fn is_superset(&self, o: &IdSet) -> bool {
        o.is_subset(self)
    }
    pub fn is_disjoint(&self, o: &IdSet) -> bool {
        self.w.iter().zip(&o.w).all(|(a, b)| a & b == 0)
    }
    pub fn append(&mut self, o: &mut IdSet) {
        self.extend(o.iter().copied());
        o.clear();
    }
    /// Members below `i` stay; those at or above it are returned.
    pub fn split_off(&mut self, i: &usize) -> IdSet {
        let hi: IdSet = self.iter().copied().filter(|x| x >= i).collect();
        self.retain(|x| x < i);
        hi
    }
    pub fn range<'a>(&'a self, r: impl std::ops::RangeBounds<usize> + 'a) -> impl DoubleEndedIterator<Item = &'a usize> + 'a {
        self.iter().filter(move |i| r.contains(i))
    }
}

/// Ascending members, from either end.
pub struct Iter<'a> {
    w: &'a [u64],
    /// Bits below `front` and at or above `back` are taken.
    front: usize,
    back: usize,
}

/// The lowest member in `front..back`, `front` moved past it (to `back` when none).
fn next_in(w: &[u64], front: &mut usize, back: usize) -> Option<&'static usize> {
    while *front < back {
        let k = *front / 64;
        let rest = w[k] >> (*front % 64);
        if rest == 0 {
            *front = (k + 1) * 64;
            continue;
        }
        let i = *front + rest.trailing_zeros() as usize;
        if i >= back {
            *front = back;
            return None;
        }
        *front = i + 1;
        return Some(&IDS[i]);
    }
    None
}

/// The highest member in `front..back`, `back` moved to it (to `front` when none).
fn next_back_in(w: &[u64], front: usize, back: &mut usize) -> Option<&'static usize> {
    while front < *back {
        let k = (*back - 1) / 64;
        let n = *back - k * 64;
        let rest = if n == 64 { w[k] } else { w[k] & ((1u64 << n) - 1) };
        if rest == 0 {
            *back = k * 64;
            continue;
        }
        let i = k * 64 + 63 - rest.leading_zeros() as usize;
        if i < front {
            *back = front;
            return None;
        }
        *back = i;
        return Some(&IDS[i]);
    }
    None
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a usize;
    fn next(&mut self) -> Option<&'a usize> {
        next_in(self.w, &mut self.front, self.back)
    }
}

impl<'a> DoubleEndedIterator for Iter<'a> {
    fn next_back(&mut self) -> Option<&'a usize> {
        next_back_in(self.w, self.front, &mut self.back)
    }
}

/// An owned set's members, ascending, as references living `'a` (a `BTreeSet`'s borrow's).
pub struct IntoIter<'a> {
    s: IdSet,
    front: usize,
    back: usize,
    at: std::marker::PhantomData<&'a usize>,
}

impl<'a> Iterator for IntoIter<'a> {
    type Item = &'a usize;
    fn next(&mut self) -> Option<&'a usize> {
        next_in(&self.s.w, &mut self.front, self.back)
    }
}

impl<'a> DoubleEndedIterator for IntoIter<'a> {
    fn next_back(&mut self) -> Option<&'a usize> {
        next_back_in(&self.s.w, self.front, &mut self.back)
    }
}

impl IdSet {
    fn into_ids<'a>(self) -> IntoIter<'a> {
        let back = self.w.len() * 64;
        IntoIter { s: self, front: 0, back, at: std::marker::PhantomData }
    }
}

/// By value: members as `usize`, as a `BTreeSet<usize>` gives them.
impl IntoIterator for IdSet {
    type Item = usize;
    type IntoIter = std::iter::Copied<IntoIter<'static>>;
    fn into_iter(self) -> Self::IntoIter {
        self.into_ids().copied()
    }
}

impl<'a> IntoIterator for &'a IdSet {
    type Item = &'a usize;
    type IntoIter = Iter<'a>;
    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl FromIterator<usize> for IdSet {
    fn from_iter<I: IntoIterator<Item = usize>>(it: I) -> IdSet {
        let mut s = IdSet::new();
        s.extend(it);
        s
    }
}

impl<'a> FromIterator<&'a usize> for IdSet {
    fn from_iter<I: IntoIterator<Item = &'a usize>>(it: I) -> IdSet {
        it.into_iter().copied().collect()
    }
}

impl Extend<usize> for IdSet {
    fn extend<I: IntoIterator<Item = usize>>(&mut self, it: I) {
        for i in it {
            self.insert(i);
        }
    }
}

impl<'a> Extend<&'a usize> for IdSet {
    fn extend<I: IntoIterator<Item = &'a usize>>(&mut self, it: I) {
        self.extend(it.into_iter().copied());
    }
}

impl<const N: usize> From<[usize; N]> for IdSet {
    fn from(a: [usize; N]) -> IdSet {
        a.into_iter().collect()
    }
}

/// As `BTreeSet`'s: the members compared in ascending order, a prefix first.
impl Ord for IdSet {
    fn cmp(&self, o: &IdSet) -> Ordering {
        self.iter().cmp(o.iter())
    }
}

impl PartialOrd for IdSet {
    fn partial_cmp(&self, o: &IdSet) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

/// As `BTreeSet`'s: `{1, 2}`.
impl fmt::Debug for IdSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::IdSet;
    use std::collections::BTreeSet;

    // spec: none (the model's set type): every operation agrees with `BTreeSet<usize>`.
    #[test]
    fn an_id_set_acts_as_a_btree_set() {
        let mut r = crate::Rng(7);
        for _ in 0..300 {
            let draw = |r: &mut crate::Rng| -> BTreeSet<usize> { (0..r.below(12)).map(|_| r.below(200)).collect() };
            let (a, b) = (draw(&mut r), draw(&mut r));
            let (x, y): (IdSet, IdSet) = (a.iter().collect(), b.iter().collect());
            assert_eq!(x.iter().copied().collect::<Vec<_>>(), a.iter().copied().collect::<Vec<_>>());
            assert_eq!(x.iter().rev().copied().collect::<Vec<_>>(), a.iter().rev().copied().collect::<Vec<_>>());
            assert_eq!(x.len(), a.len());
            assert_eq!(x.first(), a.first());
            assert_eq!(x.last(), a.last());
            assert_eq!(x.cmp(&y), a.cmp(&b));
            assert_eq!(x == y, a == b);
            assert_eq!(format!("{x:?}"), format!("{a:?}"));
            assert_eq!(x.is_subset(&y), a.is_subset(&b));
            assert_eq!(x.is_disjoint(&y), a.is_disjoint(&b));
            assert_eq!(x.difference(&y).copied().collect::<Vec<_>>(), a.difference(&b).copied().collect::<Vec<_>>());
            assert_eq!(x.intersection(&y).copied().collect::<Vec<_>>(), a.intersection(&b).copied().collect::<Vec<_>>());
            assert_eq!(x.union(&y).copied().collect::<Vec<_>>(), a.union(&b).copied().collect::<Vec<_>>());
            let k = r.below(200);
            let (mut x2, mut a2) = (x.clone(), a.clone());
            assert_eq!(x2.remove(&k), a2.remove(&k));
            assert_eq!(x2.insert(k + 1), a2.insert(k + 1));
            assert_eq!(x2.contains(&k), a2.contains(&k));
            assert_eq!(x2.into_iter().collect::<Vec<_>>(), a2.into_iter().collect::<Vec<_>>());
            let mut it = x.iter();
            let mut jt = a.iter();
            for s in 0..20 {
                if s % 3 == 0 {
                    assert_eq!(it.next_back(), jt.next_back());
                } else {
                    assert_eq!(it.next(), jt.next());
                }
            }
        }
    }
}
