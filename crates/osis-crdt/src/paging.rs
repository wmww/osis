//! Local paging hooks (notes/local-store.md, Units): a node keeps a large collection (map, set,
//! bag, list, text) at the root or in a field of a root struct as pages of consecutive elements
//! by dot, and rewrites only the pages a join touched. Element records are independent per dot
//! and struct fields per field (§4.1), so the join of the pages is the state.

use crate::fragment::{Bag, Fragment, Map, Meta, Set, Struct};
use crate::seq::Seq;
use crate::stamp::Dot;
use std::collections::BTreeMap;
use std::ops::Bound;

fn range<'a, T>(m: &'a BTreeMap<Dot, T>, lo: Option<&Dot>, hi: Option<&Dot>) -> std::collections::btree_map::Range<'a, Dot, T> {
    let lo = lo.map_or(Bound::Unbounded, Bound::Included);
    let hi = hi.map_or(Bound::Unbounded, Bound::Excluded);
    m.range::<Dot, _>((lo, hi))
}

fn sub<T: Clone>(m: &BTreeMap<Dot, T>, lo: Option<&Dot>, hi: Option<&Dot>) -> BTreeMap<Dot, T> {
    range(m, lo, hi).map(|(d, x)| (d.clone(), x.clone())).collect()
}

impl Fragment {
    /// The number of root elements of a pageable collection; `None` for other encodings.
    pub fn elem_count(&self) -> Option<usize> {
        Some(match self {
            Fragment::Map(m) => m.entries.len(),
            Fragment::Set(Set { elems, .. }) | Fragment::Bag(Bag { elems, .. }) => elems.len(),
            Fragment::Seq(s) => s.elems.len(),
            _ => return None,
        })
    }

    /// Dots of the root elements in `[lo, hi)` (unbounded where `None`), ascending.
    pub fn elem_dots(&self, lo: Option<&Dot>, hi: Option<&Dot>) -> Vec<Dot> {
        match self {
            Fragment::Map(m) => range(&m.entries, lo, hi).map(|(d, _)| d.clone()).collect(),
            Fragment::Set(Set { elems, .. }) | Fragment::Bag(Bag { elems, .. }) => range(elems, lo, hi).map(|(d, _)| d.clone()).collect(),
            Fragment::Seq(s) => range(&s.elems, lo, hi).map(|(d, _)| d.clone()).collect(),
            _ => Vec::new(),
        }
    }

    /// The same collection holding only its root elements in `[lo, hi)`, with the own reset and
    /// `W` iff `meta`; `None` for other encodings.
    pub fn elem_range(&self, lo: Option<&Dot>, hi: Option<&Dot>, meta: bool) -> Option<Fragment> {
        let m = |x: &Meta| if meta { x.clone() } else { Meta::default() };
        Some(match self {
            Fragment::Map(x) => Fragment::Map(Map::new(m(&x.meta), sub(&x.entries, lo, hi))),
            Fragment::Set(x) => Fragment::Set(Set { meta: m(&x.meta), elems: sub(&x.elems, lo, hi) }),
            Fragment::Bag(x) => Fragment::Bag(Bag { kind: x.kind, meta: m(&x.meta), elems: sub(&x.elems, lo, hi) }),
            Fragment::Seq(x) => Fragment::Seq(Seq { text: x.text, meta: m(&x.meta), elems: sub(&x.elems, lo, hi) }),
            _ => return None,
        })
    }

    /// What joining this delta can change in a pageable state of the same encoding: whether the
    /// own `W` (and so the meta) and which root elements by dot. `None` when it may change any
    /// element (a reset at the root, another encoding).
    pub fn touched_elems(&self) -> Option<(bool, Vec<Dot>)> {
        let meta = self.meta()?;
        if meta.reset.is_some() {
            return None;
        }
        let w = meta.w.is_some();
        Some(match self {
            Fragment::Map(m) => (w, m.entries.keys().cloned().collect()),
            Fragment::Set(Set { elems, .. }) | Fragment::Bag(Bag { elems, .. }) => (w, elems.keys().cloned().collect()),
            Fragment::Seq(s) => (w, s.elems.keys().cloned().collect()),
            _ => return None,
        })
    }

    /// A struct delta without a reset: whether it writes the own `W`, and its fields. `None`
    /// for anything else.
    pub fn touched_fields(&self) -> Option<(bool, Vec<(u64, &Fragment)>)> {
        match self {
            Fragment::Struct(s) if s.meta.reset.is_none() => Some((s.meta.w.is_some(), s.fields.iter().map(|(k, f)| (*k, f)).collect())),
            _ => None,
        }
    }

    /// Fields of a struct (none for other encodings).
    pub fn fields(&self) -> Vec<(u64, &Fragment)> {
        match self {
            Fragment::Struct(s) => s.fields.iter().map(|(k, f)| (*k, f)).collect(),
            _ => Vec::new(),
        }
    }

    /// A struct holding only `fields`, no reset or `W`.
    pub fn struct_of(fields: Vec<(u64, Fragment)>) -> Fragment {
        Fragment::Struct(Struct { meta: Meta::default(), fields: fields.into_iter().collect() })
    }

    /// A struct with its reset and `W` and every field, the fields in `bare` reduced to their
    /// collection's reset and `W` (dropped when that is nothing). `None` for other encodings.
    pub fn struct_skeleton(&self, bare: &dyn Fn(u64) -> bool) -> Option<Fragment> {
        let Fragment::Struct(s) = self else { return None };
        let fields = s
            .fields
            .iter()
            .filter_map(|(k, f)| match bare(*k) {
                true => f.elem_range_empty().filter(|x| !x.is_empty()).map(|x| (*k, x)),
                false => Some((*k, f.clone())),
            })
            .collect();
        Some(Fragment::Struct(Struct { meta: s.meta.clone(), fields }))
    }

    /// The collection with its reset and `W` and no elements.
    fn elem_range_empty(&self) -> Option<Fragment> {
        let m = |x: &Meta| x.clone();
        Some(match self {
            Fragment::Map(x) => Fragment::Map(Map::new(m(&x.meta), BTreeMap::new())),
            Fragment::Set(x) => Fragment::Set(Set { meta: m(&x.meta), elems: BTreeMap::new() }),
            Fragment::Bag(x) => Fragment::Bag(Bag { kind: x.kind, meta: m(&x.meta), elems: BTreeMap::new() }),
            Fragment::Seq(x) => Fragment::Seq(Seq { text: x.text, meta: m(&x.meta), elems: BTreeMap::new() }),
            _ => return None,
        })
    }
}
