//! Local paging hooks (notes/local-store.md, Units): a node keeps a large collection (map, set,
//! bag, list, text) at the root or in a field of a root struct as pages of consecutive elements
//! by dot, and rewrites only the pages a join touched. Element records are independent per dot
//! and struct fields per field (§4.1), so the join of the pages is the state.

use crate::fragment::{Bag, Fragment, Map, Meta, Set, Struct};
use crate::seq::Seq;
use crate::state::MemberRef;
use crate::stamp::{Dot, Stamp};
use osis_core::Value;
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
    /// The number of root element records of a pageable collection (a sequence's range record
    /// counts once); `None` for other encodings.
    pub fn elem_count(&self) -> Option<usize> {
        Some(match self {
            Fragment::Map(m) => m.entries.len(),
            Fragment::Set(Set { elems, .. }) | Fragment::Bag(Bag { elems, .. }) => elems.len(),
            Fragment::Seq(s) => s.elems().len(),
            _ => return None,
        })
    }

    /// Dots of the root elements in `[lo, hi)` (unbounded where `None`), ascending.
    pub fn elem_dots(&self, lo: Option<&Dot>, hi: Option<&Dot>) -> Vec<Dot> {
        match self {
            Fragment::Map(m) => range(&m.entries, lo, hi).map(|(d, _)| d.clone()).collect(),
            Fragment::Set(Set { elems, .. }) | Fragment::Bag(Bag { elems, .. }) => range(elems, lo, hi).map(|(d, _)| d.clone()).collect(),
            Fragment::Seq(s) => range(s.elems(), lo, hi).map(|(d, _)| d.clone()).collect(),
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
            Fragment::Seq(x) => Fragment::Seq(Seq::new(x.text, m(&x.meta), sub(x.elems(), lo, hi))),
            _ => return None,
        })
    }

    /// A sequence's placement (§6) as blocks of its visible elements in order (built on first
    /// use, then cached); `None` for other encodings.
    pub fn placement(&self) -> Option<Vec<crate::seq_lin::PlacedBlock>> {
        match self.chosen_member() {
            MemberRef::Frag(Fragment::Seq(s)) => Some(s.lin().p.blocks()),
            _ => None,
        }
    }

    /// The dots of a sequence's visible elements `r` (by index, clamped to its length), in
    /// order; `None` for other encodings.
    pub fn visible_range(&self, r: std::ops::Range<usize>) -> Option<Vec<Dot>> {
        match self.chosen_member() {
            MemberRef::Frag(Fragment::Seq(s)) => Some(s.lin().p.vis_range(r).into_iter().map(|x| x.dot.clone()).collect()),
            _ => None,
        }
    }

    /// What a sequence's elements `dots` read, in that order (§5.7 Read): a text's chars as one
    /// string, a list's element values. `None` if one is not a visible element here.
    pub fn read_elems(&self, dots: &[Dot]) -> Option<Value> {
        let MemberRef::Frag(Fragment::Seq(s)) = self.chosen_member() else { return None };
        let text = s.encoding() == crate::fragment::Encoding::Text;
        let mut chars = String::new();
        let mut vals = Vec::new();
        for d in dots {
            let e = s.elems().get(d)?;
            if !crate::seq::is_visible(e, text) {
                return None;
            }
            match &e.content {
                crate::seq::SeqContent::Char(c) => chars.push(*c),
                crate::seq::SeqContent::Frag(f) => vals.push(f.read()?),
                crate::seq::SeqContent::None => return None,
            }
        }
        Some(if text { Value::Str(chars) } else { Value::List(vals) })
    }

    /// What joining this delta can change in a pageable state of the same encoding: whether the
    /// own `W` (and so the meta) and which root elements by dot. `None` when it may change any
    /// element (a reset at the root, another encoding). For a sequence the dots come in pairs,
    /// the first and last element of each delta record (a range record covers the elements
    /// between); joining may split state records there and the records next to them.
    pub fn touched_elems(&self) -> Option<(bool, Vec<Dot>)> {
        let meta = self.meta()?;
        if meta.reset.is_some() {
            return None;
        }
        let w = meta.w.is_some();
        Some(match self {
            Fragment::Map(m) => (w, m.entries.keys().cloned().collect()),
            Fragment::Set(Set { elems, .. }) | Fragment::Bag(Bag { elems, .. }) => (w, elems.keys().cloned().collect()),
            Fragment::Seq(s) => (w, s.elems().iter().flat_map(|(d, e)| [d.clone(), crate::seq_span::nth(d, e.span - 1)]).collect()),
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
            Fragment::Seq(x) => Fragment::Seq(Seq::new(x.text, m(&x.meta), BTreeMap::new())),
            _ => return None,
        })
    }
}

/// A step from a fragment to a position inside it, for the node's paged states: a struct field,
/// an enum payload, or a map entry's content (by its dot).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    Field(u64),
    Case(u64),
    Entry(Dot),
}

/// A set of paths (a trie of steps): the paged collections of a state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Paths {
    /// A path ends here.
    pub here: bool,
    pub next: BTreeMap<Step, Paths>,
}

impl Paths {
    pub fn insert(&mut self, path: &[Step]) {
        match path.split_first() {
            None => self.here = true,
            Some((s, rest)) => self.next.entry(s.clone()).or_default().insert(rest),
        }
    }
    pub fn is_empty(&self) -> bool {
        !self.here && self.next.is_empty()
    }
    /// The subtrie below `path`.
    pub fn below(&self, path: &[Step]) -> Option<&Paths> {
        match path.split_first() {
            None => Some(self),
            Some((s, rest)) => self.next.get(s)?.below(rest),
        }
    }
}

/// What joining a delta can change in a paged state (`Fragment::touched_paths`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PagedTouch {
    /// Anything outside the paged collections' elements (the skeleton).
    pub skeleton: bool,
    /// Per paged collection, its root elements by dot (a sequence's as (first, last) pairs per
    /// delta record).
    pub elems: BTreeMap<Vec<Step>, Vec<Dot>>,
}

impl Fragment {
    /// The position one step down (no `Slots` member: a position with several encodings is a
    /// leaf here).
    pub fn step(&self, s: &Step) -> Option<&Fragment> {
        match (s, self) {
            (Step::Field(id), Fragment::Struct(x)) => x.fields.get(id),
            (Step::Case(id), Fragment::Enum(x)) => x.payloads.get(id),
            (Step::Entry(d), Fragment::Map(m)) => m.entries.get(d)?.frag.as_deref(),
            _ => None,
        }
    }

    pub fn at_steps(&self, path: &[Step]) -> Option<&Fragment> {
        match path.split_first() {
            None => Some(self),
            Some((s, rest)) => self.step(s)?.at_steps(rest),
        }
    }

    /// The key a map entry carries.
    pub fn entry_key(&self, d: &Dot) -> Option<&Value> {
        match self {
            Fragment::Map(m) => m.entries.get(d)?.key.as_ref(),
            _ => None,
        }
    }

    /// The creation stamp of entry `d` of a map (§5.6).
    pub fn entry_created(&self, d: &Dot) -> Option<&Stamp> {
        match self {
            Fragment::Map(m) => m.entries.get(d)?.created.as_ref(),
            _ => None,
        }
    }

    /// A fragment holding `inner` at `path` and nothing else; an entry step carries the entry's
    /// key and creation (so joining it alone restores the entry with them).
    pub fn wrap(path: &[(Step, Option<Value>, Option<Stamp>)], inner: Fragment) -> Fragment {
        let mut f = inner;
        for (s, key, created) in path.iter().rev() {
            f = match s {
                Step::Field(id) => Fragment::Struct(Struct { meta: Meta::default(), fields: BTreeMap::from([(*id, f)]) }),
                Step::Case(id) => Fragment::Enum(crate::fragment::Enum { meta: Meta::default(), case: None, payloads: BTreeMap::from([(*id, f)]) }),
                Step::Entry(d) => Fragment::Map(Map::new(Meta::default(), BTreeMap::from([(d.clone(), crate::fragment::Entry { reset: None, key: key.clone(), frag: Some(Box::new(f)), created: created.clone() })]))),
            };
        }
        f
    }

    /// A copy with the collections at `paths` (relative to this position) reduced to their own
    /// reset and `W`: O(what is kept), never descending into a reduced collection.
    pub fn reduced(&self, paths: &Paths) -> Fragment {
        if paths.here {
            return self.elem_range_empty().unwrap_or_default();
        }
        if paths.next.is_empty() {
            return self.clone();
        }
        let below = |s: &Step, f: &Fragment| -> Fragment {
            match paths.next.get(s) {
                Some(p) => f.reduced(p),
                None => f.clone(),
            }
        };
        match self {
            Fragment::Struct(x) => Fragment::Struct(Struct {
                meta: x.meta.clone(),
                fields: x.fields.iter().map(|(id, f)| (*id, below(&Step::Field(*id), f))).filter(|(_, f)| !f.is_empty()).collect(),
            }),
            Fragment::Enum(x) => Fragment::Enum(crate::fragment::Enum {
                meta: x.meta.clone(),
                case: x.case.clone(),
                payloads: x.payloads.iter().map(|(id, f)| (*id, below(&Step::Case(*id), f))).filter(|(_, f)| !f.is_empty()).collect(),
            }),
            Fragment::Map(m) => {
                let entries = m
                    .entries
                    .iter()
                    .map(|(d, e)| {
                        let frag = e.frag.as_ref().map(|f| Box::new(below(&Step::Entry(d.clone()), f))).filter(|f| !f.is_empty());
                        // an entry reduced to nothing keeps no key here: the pages below carry it
                        let (key, created) = if frag.is_some() { (e.key.clone(), e.created.clone()) } else { (None, None) };
                        (d.clone(), crate::fragment::Entry { reset: e.reset.clone(), key, frag, created })
                    })
                    .filter(|(_, e)| e.reset.is_some() || e.frag.is_some())
                    .collect();
                Fragment::Map(Map::new(m.meta.clone(), entries))
            }
            f => f.clone(),
        }
    }

    /// Every collection (map, set, bag, list, text) reachable through `Step`s, with its path,
    /// outermost first.
    pub fn collections(&self) -> Vec<(Vec<Step>, &Fragment)> {
        let mut out = Vec::new();
        let mut stack: Vec<(Vec<Step>, &Fragment)> = vec![(Vec::new(), self)];
        while let Some((p, f)) = stack.pop() {
            if f.elem_count().is_some() {
                out.push((p.clone(), f));
            }
            let mut kids: Vec<(Step, &Fragment)> = match f {
                Fragment::Struct(x) => x.fields.iter().map(|(id, f)| (Step::Field(*id), f)).collect(),
                Fragment::Enum(x) => x.payloads.iter().map(|(id, f)| (Step::Case(*id), f)).collect(),
                Fragment::Map(m) => m.entries.iter().filter_map(|(d, e)| Some((Step::Entry(d.clone()), e.frag.as_deref()?))).collect(),
                _ => Vec::new(),
            };
            kids.reverse();
            for (s, k) in kids {
                let mut q = p.clone();
                q.push(s);
                stack.push((q, k));
            }
        }
        out
    }

    /// What joining this delta can change in a state whose collections at `paged` are kept as
    /// pages of root elements: per paged collection its elements by dot, and whether anything
    /// else (the skeleton) may change. `None` when it may change a paged collection's elements
    /// beyond those (a reset at or above it, a case change above it, another encoding there).
    pub fn touched_paths(&self, paged: &Paths) -> Option<PagedTouch> {
        let mut out = PagedTouch::default();
        let mut path = Vec::new();
        touched_walk(self, paged, &mut path, &mut out)?;
        Some(out)
    }
}

fn touched_walk(d: &Fragment, t: &Paths, path: &mut Vec<Step>, out: &mut PagedTouch) -> Option<()> {
    if t.here {
        let (w, dots) = d.touched_elems()?;
        out.skeleton |= w;
        // elements holding paged collections below
        for (s, sub) in &t.next {
            let Step::Entry(e) = s else { return None };
            if let Some(f) = d.step(s) {
                if matches!(d, Fragment::Map(m) if m.entries.get(e).is_some_and(|x| x.reset.is_some())) {
                    return None;
                }
                path.push(s.clone());
                touched_walk(f, sub, path, out)?;
                path.pop();
            }
        }
        out.elems.entry(path.clone()).or_default().extend(dots);
        return Some(());
    }
    if t.next.is_empty() {
        out.skeleton = true;
        return Some(());
    }
    // a position above paged collections: no reset or case change may reach them
    if d.has_reset() {
        return None;
    }
    let kids: Vec<(Step, &Fragment)> = match d {
        Fragment::Struct(x) => {
            out.skeleton |= x.meta.w.is_some();
            x.fields.iter().map(|(id, f)| (Step::Field(*id), f)).collect()
        }
        Fragment::Enum(x) => {
            if x.case.is_some() {
                return None;
            }
            out.skeleton |= x.meta.w.is_some();
            x.payloads.iter().map(|(id, f)| (Step::Case(*id), f)).collect()
        }
        Fragment::Map(m) => {
            out.skeleton |= m.meta.w.is_some();
            let mut v = Vec::new();
            for (dot, e) in &m.entries {
                let s = Step::Entry(dot.clone());
                if t.next.contains_key(&s) && e.reset.is_some() {
                    return None;
                }
                match &e.frag {
                    Some(f) => v.push((s, &**f)),
                    None => out.skeleton = true,
                }
            }
            v
        }
        _ => return None,
    };
    for (s, f) in kids {
        match t.next.get(&s) {
            Some(sub) => {
                path.push(s);
                touched_walk(f, sub, path, out)?;
                path.pop();
            }
            None => out.skeleton = true,
        }
    }
    Some(())
}
