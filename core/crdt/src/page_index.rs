//! Which leaf pages of a streamed part hold a fragment's positions (`PageIndex`), so a read of
//! the part at those positions (`Fragment::part_at`) fetches only them (`stream_checked_some`).
//!
//! A paged collection's leaves ascend by element (spec/crdt.md §8): a dot for a sequence, set,
//! bag or map (a map's records by dot, a dot's records possibly straddling pages), a field ID for
//! a struct (the check's seams, `stream::Out`). Each leaf's first element bounds what it holds
//! from below; a sequence's runs bound it from above too, by the furthest dot any run up to the
//! leaf reaches (a run may cover dots another source's record sorts between, so a leaf's next
//! does not bound it). So the elements found once, one or two per leaf, name the leaves holding
//! any position. Where `part_at` takes a collection whole (below a map entry, an enum, a kind
//! the two do not share) every leaf is named.

use crate::fragment::{Encoding, Fragment};
use crate::paging::Step;
use crate::seq_span::nth;
use crate::stamp::Dot;
use crate::stream::{PageAt, Piece};
use std::collections::{BTreeMap, BTreeSet};

/// A leaf's first element.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum First {
    Dot(Dot),
    Field(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Leaf {
    at: PageAt,
    first: First,
    /// A sequence: the greatest dot the runs of this leaf and those before it cover.
    reach: Option<Dot>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Leaves {
    enc: Option<Encoding>,
    /// A leaf with no first element was seen: every leaf is named.
    empty: bool,
    /// In wire order.
    leaves: Vec<Leaf>,
}

/// The leaves of a streamed part's paged positions, by path, each with its first element:
/// built from every piece of one stream (`add`). Memory: one entry per leaf.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PageIndex {
    paths: BTreeMap<Vec<Step>, Leaves>,
}

/// The leaves a read at a fragment's positions fetches (`PageIndex::wanted`), by path: `None`
/// every leaf of it; a path not listed, none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Wanted(BTreeMap<Vec<Step>, Option<BTreeSet<PageAt>>>);

impl Wanted {
    /// Whether the leaf `at` of the collection at `path` is fetched; a root link (`at.1` none)
    /// is fetched when a leaf under it is (or it is that leaf).
    pub fn wants(&self, path: &[Step], at: PageAt) -> bool {
        match self.0.get(path) {
            None => false,
            Some(None) => true,
            Some(Some(set)) if at.1.is_some() => set.contains(&at),
            Some(Some(set)) => set.range((at.0, None)..).next().is_some_and(|x| x.0 == at.0),
        }
    }
}

/// What `part_at` takes of the collection at a path.
enum Reach<'f> {
    None,
    All,
    /// The body's fragment there, narrowed by element.
    At(&'f Fragment),
}

impl PageIndex {
    /// Notes a piece of the stream (a skeleton notes nothing).
    pub fn add(&mut self, p: &Piece) {
        let Piece::Page { path, at, fragment } = p else { return };
        let inner = path.iter().try_fold(fragment, |f, s| f.step(s));
        let l = self.paths.entry(path.clone()).or_default();
        l.enc = l.enc.or(inner.map(Fragment::encoding));
        let Some(first) = inner.and_then(first) else {
            l.empty = true;
            return;
        };
        let end = match inner {
            Some(Fragment::Seq(s)) => s.elems().iter().map(|(k, r)| nth(k, r.span.saturating_sub(1))).max(),
            _ => None,
        };
        let reach = l.leaves.last().and_then(|x| x.reach.clone()).into_iter().chain(end).max();
        l.leaves.push(Leaf { at: *at, first, reach });
    }

    /// About the bytes held (`Fragment::approx_bytes`'s measure).
    pub fn approx_bytes(&self) -> usize {
        self.paths.iter().map(|(p, l)| size_of::<Leaves>() + p.len() * size_of::<Step>() + l.leaves.len() * size_of::<Leaf>()).sum()
    }

    /// The leaves holding what `part_at(body)` takes of the part.
    pub fn wanted(&self, body: &Fragment) -> Wanted {
        let mut out = BTreeMap::new();
        for (path, l) in &self.paths {
            match reach(body, path) {
                Reach::None => {}
                Reach::All => drop(out.insert(path.clone(), None)),
                Reach::At(b) => drop(out.insert(path.clone(), l.holding(b))),
            }
        }
        Wanted(out)
    }
}

impl Leaves {
    /// The leaves holding the records `part_at(b)` takes here; `None`: every leaf.
    fn holding(&self, b: &Fragment) -> Option<BTreeSet<PageAt>> {
        if self.empty {
            return None;
        }
        // leaves whose first element is at most / below `k`
        let le = |k: &First| self.leaves.partition_point(|x| x.first <= *k);
        let lt = |k: &First| self.leaves.partition_point(|x| x.first < *k);
        let mut out = BTreeSet::new();
        // the leaves from the `lo`th through the one before the `hi`th
        let mut take = |lo: usize, hi: usize| out.extend(self.leaves.get(lo..hi).into_iter().flatten().map(|x| x.at));
        let dot = |d: &Dot| First::Dot(d.clone());
        match (self.enc?, b) {
            // the records holding a dot of the body's span: from the first leaf whose runs reach
            // its first dot through the last starting at most its last
            (e, Fragment::Seq(d)) if d.encoding() == e => {
                for (k, r) in d.elems() {
                    let lo = self.leaves.partition_point(|x| x.reach.as_ref().is_none_or(|x| x < k));
                    take(lo, le(&dot(&nth(k, r.span.saturating_sub(1)))));
                }
            }
            // every record of a dot the body holds
            (Encoding::Map, Fragment::Map(d)) => {
                for k in d.entries.keys().map(|x| &x.dot).collect::<BTreeSet<_>>() {
                    take(lt(&dot(k)).saturating_sub(1), le(&dot(k)));
                }
            }
            (Encoding::Set, Fragment::Set(crate::fragment::Set { elems, .. })) => elems.keys().for_each(|k| take(le(&dot(k)).saturating_sub(1), le(&dot(k)))),
            (e, Fragment::Bag(x)) if x.kind.encoding() == e => x.elems.keys().for_each(|k| take(le(&dot(k)).saturating_sub(1), le(&dot(k)))),
            (Encoding::Struct, Fragment::Struct(x)) => x.fields.keys().for_each(|k| take(le(&First::Field(*k)).saturating_sub(1), le(&First::Field(*k)))),
            _ => return None,
        }
        Some(out)
    }
}

/// What `part_at(body)` takes of the collection at `path` (`Fragment::part_at`): narrowed through
/// struct fields; a map's records of a dot the body holds whole; anything else whole.
fn reach<'f>(body: &'f Fragment, path: &[Step]) -> Reach<'f> {
    let mut f = body;
    for s in path {
        match (s, f) {
            (Step::Field(id), Fragment::Struct(x)) => match x.fields.get(id) {
                Some(n) => f = n,
                None => return Reach::None,
            },
            (Step::Entry(id), Fragment::Map(m)) => return if m.of_dot(&id.dot).next().is_some() { Reach::All } else { Reach::None },
            _ => return Reach::All,
        }
    }
    Reach::At(f)
}

/// A leaf's first element.
fn first(f: &Fragment) -> Option<First> {
    match f {
        Fragment::Seq(s) => s.elems().keys().next().cloned().map(First::Dot),
        Fragment::Set(crate::fragment::Set { elems, .. }) | Fragment::Bag(crate::fragment::Bag { elems, .. }) => elems.keys().next().cloned().map(First::Dot),
        Fragment::Map(m) => m.entries.keys().next().map(|e| First::Dot(e.dot.clone())),
        Fragment::Struct(crate::fragment::Struct { fields, .. }) | Fragment::Enum(crate::fragment::Enum { payloads: fields, .. }) => fields.keys().next().copied().map(First::Field),
        Fragment::Register(_) | Fragment::Slots(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seq::{Seq, SeqContent, SeqElem};
    use crate::stamp::{Session, Source};

    // A text page whose first record is another source's, sorting inside an earlier page's run
    // (a `Derived` dot right after the dot it derives from, spec/crdt.md §2.2), does not hide that
    // run: a read at a dot the run covers names its page (and the later one, harmless).
    #[test]
    fn a_run_reaching_past_the_next_pages_first_names_its_page_spec_crdt_8() {
        let s = Source::session(Session { node: osis_base::Tid::from_bytes([1; 15]), nonce: [0; crate::stamp::SESSION_NONCE_LEN] });
        let derived = Source::derived(Dot::new(s.clone(), 5)).unwrap();
        let rec = |span| SeqElem { created: None, content: SeqContent::None, pos: Vec::new(), deleted: None, undel: None, valueless: false, span };
        let seq = |d: Dot, span| Fragment::Seq(Seq::new(true, Default::default(), [(d, rec(span))].into()));
        let mut ix = PageIndex::default();
        ix.add(&Piece::Page { path: Vec::new(), at: (0, None), fragment: seq(Dot::new(s.clone(), 1), 10) });
        ix.add(&Piece::Page { path: Vec::new(), at: (1, None), fragment: seq(Dot::new(derived, 1), 1) });
        let w = ix.wanted(&seq(Dot::new(s.clone(), 7), 1));
        assert!(w.wants(&[], (0, None)), "the page whose run covers (s, 7): {w:?}");
        let w = ix.wanted(&seq(Dot::new(s, 11), 1));
        assert!(!w.wants(&[], (0, None)) && !w.wants(&[], (1, None)), "a dot no record holds: no page: {w:?}");
    }
}
