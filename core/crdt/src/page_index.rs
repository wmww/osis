//! Which leaf pages of a streamed part hold a fragment's positions (`PageIndex`), so a read of
//! the part at those positions (`Fragment::positions_at`) fetches only them (`stream_checked_some`).
//!
//! A paged collection's leaves ascend by element (spec/crdt.md §8): a dot for a sequence, set,
//! bag or map (a map's records by dot, a dot's records possibly straddling pages), a field ID for
//! a struct (the check's seams, `stream::Out`). Each leaf's first element bounds what it holds
//! from below; a sequence's runs bound it from above too, by the furthest dot any run up to the
//! leaf reaches (a run may cover dots another source's record sorts between, so a leaf's next
//! does not bound it). So the elements found once, one or two per leaf, name the leaves holding
//! any position. Where `positions_at` takes a collection whole (below a map entry, an enum, a kind
//! the two do not share) every leaf is named.

use crate::fragment::{Encoding, Fragment};
use crate::paging::Step;
use crate::seq_span::nth;
use crate::stamp::Dot;
use crate::codec::PageAt;
use crate::stream::Piece;
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
    /// Whether the page at `at` of the collection at `path` is fetched: a leaf named, or a link
    /// page above one (its place a prefix of the leaf's).
    pub fn wants(&self, path: &[Step], at: &[usize]) -> bool {
        match self.0.get(path) {
            None => false,
            Some(None) => true,
            Some(Some(set)) => set.range(at.to_vec()..).next().is_some_and(|x| x.starts_with(at)),
        }
    }
}

/// What `positions_at` takes of the collection at a path.
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
        l.leaves.push(Leaf { at: at.clone(), first, reach });
    }

    /// Whether the part has no paged collection: it streams as its skeleton alone.
    pub fn unpaged(&self) -> bool {
        self.paths.is_empty()
    }

    /// About the bytes held (`Fragment::approx_bytes`'s measure).
    pub fn approx_bytes(&self) -> usize {
        self.paths.iter().map(|(p, l)| size_of::<Leaves>() + p.len() * size_of::<Step>() + l.leaves.iter().map(|x| size_of::<Leaf>() + x.at.len() * size_of::<usize>()).sum::<usize>()).sum()
    }

    /// The leaves holding what `positions_at(body)` takes of the part.
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

impl PageIndex {
    /// Its stored form: a node keeps a paged part's index beside the part, so a read at
    /// positions in a later session streams no page to find its pages.
    pub fn to_bytes(&self) -> Vec<u8> {
        use crate::held::{put_dot, put_u64};
        let mut out = Vec::new();
        put_u64(&mut out, self.paths.len() as u64);
        for (path, l) in &self.paths {
            put_u64(&mut out, path.len() as u64);
            for s in path {
                match s {
                    Step::Field(n) => {
                        out.push(0);
                        put_u64(&mut out, *n);
                    }
                    Step::Case(n) => {
                        out.push(1);
                        put_u64(&mut out, *n);
                    }
                    Step::Entry(e) => {
                        out.push(2);
                        put_dot(&mut out, &e.dot);
                        match &e.key {
                            None => out.push(0),
                            Some(k) => {
                                out.push(1);
                                osis_base::cbor::encode_into(&k.0, &mut out);
                            }
                        }
                    }
                }
            }
            out.push(l.enc.map_or(0xff, Encoding::id));
            out.push(u8::from(l.empty));
            put_u64(&mut out, l.leaves.len() as u64);
            for x in &l.leaves {
                put_u64(&mut out, x.at.len() as u64);
                x.at.iter().for_each(|i| put_u64(&mut out, *i as u64));
                match &x.first {
                    First::Dot(d) => {
                        out.push(0);
                        put_dot(&mut out, d);
                    }
                    First::Field(n) => {
                        out.push(1);
                        put_u64(&mut out, *n);
                    }
                }
                match &x.reach {
                    None => out.push(0),
                    Some(d) => {
                        out.push(1);
                        put_dot(&mut out, d);
                    }
                }
            }
        }
        out
    }

    /// `to_bytes` read back.
    pub fn from_bytes(b: &[u8]) -> Result<PageIndex, crate::held::Corrupt> {
        use crate::held::{Corrupt, Rd};
        let bad = Corrupt("page index row");
        let mut r = Rd(b);
        let mut paths = BTreeMap::new();
        for _ in 0..r.u64()? {
            let mut path = Vec::new();
            for _ in 0..r.u64()? {
                path.push(match r.u8()? {
                    0 => Step::Field(r.u64()?),
                    1 => Step::Case(r.u64()?),
                    2 => {
                        let dot = r.dot()?;
                        let key = match r.u8()? {
                            0 => None,
                            _ => Some(r.value()?),
                        };
                        Step::Entry(crate::fragment::Eid::new(dot, key))
                    }
                    _ => return Err(bad),
                });
            }
            let enc = match r.u8()? {
                0xff => None,
                id => Some(Encoding::from_id(u64::from(id)).ok_or(bad)?),
            };
            let empty = r.u8()? != 0;
            let mut leaves = Vec::new();
            for _ in 0..r.u64()? {
                let mut at = Vec::new();
                for _ in 0..r.u64()? {
                    at.push(r.u64()? as usize);
                }
                let first = match r.u8()? {
                    0 => First::Dot(r.dot()?),
                    _ => First::Field(r.u64()?),
                };
                let reach = match r.u8()? {
                    0 => None,
                    _ => Some(r.dot()?),
                };
                leaves.push(Leaf { at, first, reach });
            }
            paths.insert(path, Leaves { enc, empty, leaves });
        }
        r.end()?;
        Ok(PageIndex { paths })
    }
}

impl Leaves {
    /// The leaves holding the records `positions_at(b)` takes here; `None`: every leaf.
    fn holding(&self, b: &Fragment) -> Option<BTreeSet<PageAt>> {
        if self.empty {
            return None;
        }
        // leaves whose first element is at most / below `k`
        let le = |k: &First| self.leaves.partition_point(|x| x.first <= *k);
        let lt = |k: &First| self.leaves.partition_point(|x| x.first < *k);
        let mut out = BTreeSet::new();
        // the leaves from the `lo`th through the one before the `hi`th
        let mut take = |lo: usize, hi: usize| out.extend(self.leaves.get(lo..hi).into_iter().flatten().map(|x| x.at.clone()));
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

/// What `positions_at(body)` takes of the collection at `path`: narrowed through struct fields;
/// a map's records of a dot the body holds whole; anything else whole.
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
        let rec = |span| SeqElem { created: None, content: SeqContent::None, pos: Vec::new(), deleted: None, undel: None, span, each: None };
        let seq = |d: Dot, span| Fragment::Seq(Seq::new(true, Default::default(), [(d, rec(span))].into()));
        let mut ix = PageIndex::default();
        ix.add(&Piece::Page { path: Vec::new(), at: vec![0], fragment: seq(Dot::new(s.clone(), 1), 10) });
        ix.add(&Piece::Page { path: Vec::new(), at: vec![1], fragment: seq(Dot::new(derived, 1), 1) });
        let w = ix.wanted(&seq(Dot::new(s.clone(), 7), 1));
        assert!(w.wants(&[], &[0]), "the page whose run covers (s, 7): {w:?}");
        let w = ix.wanted(&seq(Dot::new(s, 11), 1));
        assert!(!w.wants(&[], &[0]) && !w.wants(&[], &[1]), "a dot no record holds: no page: {w:?}");
    }
}
