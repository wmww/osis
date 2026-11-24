//! A stored paged state read a page at a time (`View`, spec/crdt.md §4.7, §8): the one reader of
//! a state kept as a skeleton and pages (notes/engine-paged.md), for what reads it in place (the
//! snapshot encoder, the sweep: `View::new`, `page`) and for what reads it a piece at a time
//! (presence, a snapshot's writes and stamps, tree roots: `each_piece`).
//!
//! Without the writes `gone` names. Each write sits in exactly one record (§5.6: a map dot's
//! records hold disjoint writes), so removing writes is local to the piece holding them: each
//! stored page is stripped on its own (`Fragment::remove_gone`), and the pages so stripped are
//! the stripped state's. What is not local is whether a record holding only paged content
//! survives: the stored skeleton and pages may drop such records. Read in place, each page (and
//! the skeleton) has the path to every collection paged directly below it that keeps an element
//! (`survives`: read from that collection's pages in order until one holds an element,
//! remembered per collection) grafted in, empty (`graft`): the encoder then reads that
//! collection's own pages there. A graft costs the path's bytes, which the node holds per paged
//! collection anyway, never an element: a page's range may hold any number of such records (one
//! dot under many keys). Read a piece at a time, a page keeping an element is grafted in at its
//! own path below what reading it alone depends on (`piece`).

use crate::error::Error;
use crate::fragment::{Encoding, Fragment};
use crate::page::{PageWalk, Paged};
use crate::paging::{Paths, Step};
use crate::stamp::Dot;
use osis_base::Value;
use std::collections::{BTreeMap, BTreeSet};

/// A `Paged` state as read.
pub(crate) struct View<'a> {
    pub(crate) paths: &'a Paths,
    pages: &'a mut dyn PageWalk,
    gone: &'a dyn Fn(&Dot) -> bool,
    /// Per paged collection looked for, its encoding if an element of it survives the strip.
    kept: BTreeMap<Vec<Step>, Option<Encoding>>,
    /// The skeleton's bytes, and those of the pages the encoder is inside (`approx_bytes`):
    /// what is held beside a page read (`costs`).
    beside: u64,
    pub(crate) held: u64,
}

impl<'a> View<'a> {
    /// The view of `p`, and its skeleton as read.
    pub(crate) fn new(p: Paged<'a>) -> Result<(View<'a>, Fragment), Error> {
        let (mut v, mut s) = View::open(p);
        v.graft_below(&mut s, &[], None)?;
        v.beside = s.approx_bytes() as u64;
        v.note(0);
        Ok((v, s))
    }

    /// The view of `p`, and its skeleton stripped.
    fn open(p: Paged<'a>) -> (View<'a>, Fragment) {
        let v = View { paths: p.paths, pages: p.pages, gone: p.gone, kept: BTreeMap::new(), beside: 0, held: 0 };
        let mut s = p.skeleton.clone();
        s.remove_gone(v.gone);
        (v, s)
    }

    /// How many pages the collection at `path` is kept as.
    pub(crate) fn pages(&mut self, path: &[Step]) -> Result<usize, Error> {
        self.pages.pages(path)
    }

    /// Page `i` of the collection at `path` as read: as stored, the collections paged directly
    /// below its elements present, stripped.
    pub(crate) fn page(&mut self, path: &[Step], i: usize) -> Result<Fragment, Error> {
        let pg = self.pages.page(path, i)?;
        let mut f = pg.frag;
        f.remove_gone(self.gone);
        self.graft_below(&mut f, path, Some((pg.lo.as_ref(), pg.hi.as_ref())))?;
        self.note(f.approx_bytes() as u64);
        Ok(f)
    }

    /// Notes what is held with `more` beside it.
    fn note(&mut self, more: u64) {
        let n = self.beside.saturating_add(self.held).saturating_add(more);
        // counted: tests read the most a snapshot's writer holds of a state
        osis_base::costs::peak("snapshot: state held", n);
    }

    /// The piece of page `i` of the collection at `path` (`each_piece`), `None` if it keeps no
    /// element: below its `context` (read once a page of it is, kept for the collection's
    /// next pages), the page with, given `keys`, the records on other pages of the keys or values
    /// its records hold, at its path.
    fn piece(&mut self, s: &Fragment, context: &mut Option<Fragment>, path: &[Step], i: usize, keys: bool) -> Result<Option<Fragment>, Error> {
        let pg = self.pages.page(path, i)?;
        let mut leaf = pg.frag;
        leaf.remove_gone(self.gone);
        if leaf.elem_count().is_none_or(|n| n == 0) {
            return Ok(None);
        }
        if keys {
            let inside = |d: &Dot| pg.lo.as_ref().is_none_or(|lo| d >= lo) && pg.hi.as_ref().is_none_or(|hi| d < hi);
            let vs: BTreeSet<Value> = leaf.elem_dots(None, None).iter().flat_map(|d| leaf.index_values(d)).collect();
            for v in &vs {
                for d in self.pages.dots_of(path, v)?.into_iter().filter(|d| !inside(d)) {
                    let mut other = self.pages.page_of(path, &d)?.frag;
                    other.remove_gone(self.gone);
                    if let Some(r) = other.key_records(&d, v) {
                        leaf.join(r);
                    }
                }
            }
        }
        let mut g = match context {
            Some(c) => c.clone(),
            None => context.insert(self.context(s, path)?).clone(),
        };
        graft(&mut g, &self.pages.keyed(path)?, leaf, self.gone);
        Ok(Some(g))
    }

    /// What a page of the collection at `p` is read below (`each_piece`): the spine along `p` of
    /// the skeleton `s` and of the page of each paged collection on the way holding the path's
    /// record, each at its path (what pruning, an enum's case and a record's creation there
    /// depend on, `Fragment::spine`).
    fn context(&mut self, s: &Fragment, p: &[Step]) -> Result<Fragment, Error> {
        let mut g = s.spine(p, None);
        for n in 1..p.len() {
            let (a, rest) = p.split_at(n);
            if !self.paths.below(a).is_some_and(|x| x.here) {
                continue;
            }
            let Some(Step::Entry(e)) = rest.first() else { return Err(Error::Mismatch("a collection paged below another's element")) };
            let mut pg = self.pages.page_of(a, &e.dot)?.frag;
            pg.remove_gone(self.gone);
            graft(&mut g, &self.pages.keyed(a)?, pg.spine(rest, None), self.gone);
        }
        Ok(g)
    }

    /// Whether a collection paged at or below `at` (none between) keeps an element.
    pub(crate) fn kept_below(&mut self, at: &[Step]) -> Result<bool, Error> {
        let Some(below) = self.paths.below(at) else { return Ok(false) };
        for c in heres(below, &mut at.to_vec()) {
            if self.survives(&c)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Grafts into `f` (at `path`, stripped) the path to each collection paged directly below
    /// it, of those in `range`, that keeps an element.
    fn graft_below(&mut self, f: &mut Fragment, path: &[Step], range: Option<(Option<&Dot>, Option<&Dot>)>) -> Result<(), Error> {
        for c in self.children(path, range) {
            if let Some(enc) = self.survives(&c)? {
                let keyed = self.pages.keyed(&c)?;
                graft(f, keyed.get(path.len()..).unwrap_or_default(), Fragment::empty(enc).unwrap_or_default(), self.gone);
            }
        }
        Ok(())
    }

    /// Whether an element of the collection at `q` survives the strip: its encoding if so.
    fn survives(&mut self, q: &[Step]) -> Result<Option<Encoding>, Error> {
        if let Some(k) = self.kept.get(q) {
            return Ok(*k);
        }
        let mut out = None;
        for i in 0..self.pages(q)? {
            let pg = self.page(q, i)?;
            if pg.elem_count().is_some_and(|n| n > 0) {
                out = Some(pg.encoding());
                break;
            }
        }
        self.kept.insert(q.to_vec(), out);
        Ok(out)
    }

    /// The paged collections directly below `p` (none between), of those whose step past `p` is
    /// an entry of a dot in `range` (`None`: any).
    fn children(&self, p: &[Step], range: Option<(Option<&Dot>, Option<&Dot>)>) -> Vec<Vec<Step>> {
        let Some(below) = self.paths.below(p) else { return Vec::new() };
        let mut out = Vec::new();
        for (s, rest) in &below.next {
            if let (Some((lo, hi)), Step::Entry(e)) = (range, s)
                && (lo.is_some_and(|lo| e.dot < *lo) || hi.is_some_and(|hi| e.dot >= *hi))
            {
                continue;
            }
            let mut at = p.to_vec();
            at.push(s.clone());
            out.extend(heres(rest, &mut at));
        }
        out
    }
}

/// The paths of the collections in `paths` (below `at`) with no paged collection between.
fn heres(paths: &Paths, at: &mut Vec<Step>) -> Vec<Vec<Step>> {
    if paths.here {
        return vec![at.clone()];
    }
    let mut out = Vec::new();
    for (s, rest) in &paths.next {
        at.push(s.clone());
        out.extend(heres(rest, at));
        at.pop();
    }
    out
}

/// The paths of every collection in `paths` (below `at`), into `out`.
fn every(paths: &Paths, at: &mut Vec<Step>, out: &mut Vec<Vec<Step>>) {
    if paths.here {
        out.push(at.clone());
    }
    for (s, rest) in &paths.next {
        at.push(s.clone());
        every(rest, at, out);
        at.pop();
    }
}

/// Grafts `rel` into `f` with `leaf` joined at its end, adding no write but an entry step's
/// creation where its record lacks one, the creation is not gone, and no reset of its dot here
/// reaches it (a creation stays on a set's path until its record's next write; the reset that
/// took it sits beside the record: notes/engine-paged.md). A stripped page keeps no record a
/// graft must not: what is grafted holds a surviving element.
fn graft(f: &mut Fragment, rel: &[(Step, Option<Value>, Option<crate::Stamp>)], leaf: Fragment, gone: &dyn Fn(&Dot) -> bool) {
    let Some(((step, _, created), rest)) = rel.split_first() else {
        if f.is_empty() {
            *f = leaf;
        } else {
            f.join(leaf);
        }
        return;
    };
    let kind = match step {
        Step::Field(_) => Encoding::Struct,
        Step::Case(_) => Encoding::Enum,
        Step::Entry(_) => Encoding::Map,
    };
    // a position stripped of every write reads as nothing: the graft gives it its shape again
    if f.is_empty() && f.encoding() != kind {
        *f = Fragment::empty(kind).unwrap_or_default();
    }
    let child = match (step, f) {
        (Step::Field(id), Fragment::Struct(x)) => x.fields.entry(*id).or_default(),
        (Step::Case(id), Fragment::Enum(x)) => x.payloads.entry(*id).or_default(),
        (Step::Entry(id), Fragment::Map(m)) => {
            let reset = m.of_dot(&id.dot).filter_map(|(_, e)| e.reset.clone()).max();
            let e = m.entries.entry(id.clone()).or_default();
            if e.created.is_none()
                && let Some(c) = created
                && !gone(c.dot.origin())
                && reset.is_none_or(|r| *c >= r)
            {
                e.created = Some(c.clone());
            }
            e.frag.get_or_insert_with(Box::default)
        }
        _ => return,
    };
    graft(child, rest, leaf, gone);
}

/// Each piece of the stored paged state `st` as a read of the whole sees it there, one at a time
/// (the reader holds the skeleton, a page with what it is read below, and the records it pulls):
/// the skeleton stripped, then, collection by collection, each page keeping an element after the
/// strip, grafted at its path below the skeleton's spine along it and the record of each paged
/// collection on the way (`View::context`). With `keys`, a page of a map or set also holds the
/// records of the keys or values its records hold that lie on other pages (a key reads as the
/// join of its records, §5.6; a value's records hide each other, §5.5), so each piece reads as
/// the whole does there; `Ok(None)` when a collection is paged inside another's elements (a key's
/// records then reach into pages below: the caller reads whole). `each` returns whether to stop;
/// the result is whether it did.
pub fn each_piece(st: Paged<'_>, keys: bool, each: &mut dyn FnMut(&Fragment) -> bool) -> Result<Option<bool>, Error> {
    let nested = every_path(st.paths).iter().any(|p| (1..p.len()).any(|n| st.paths.below(p.split_at(n).0).is_some_and(|x| x.here)));
    if keys && nested {
        return Ok(None);
    }
    let (mut v, s) = View::open(st);
    if each(&s) {
        return Ok(Some(true));
    }
    for p in every_path(v.paths) {
        let mut context = None;
        for i in 0..v.pages(&p)? {
            let Some(g) = v.piece(&s, &mut context, &p, i, keys)? else { continue };
            // counted: tests read the most a walk holds
            osis_base::costs::peak("paged state: piece held", g.approx_bytes() as u64);
            if each(&g) {
                return Ok(Some(true));
            }
        }
    }
    Ok(Some(false))
}

/// The paths of every collection in `paths`, outer before inner.
fn every_path(paths: &Paths) -> Vec<Vec<Step>> {
    let mut out = Vec::new();
    every(paths, &mut Vec::new(), &mut out);
    out
}
