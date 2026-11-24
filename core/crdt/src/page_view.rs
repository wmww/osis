//! A stored paged state read for its snapshot a page at a time (`Paged`, spec/crdt.md §4.7, §8).
//!
//! A snapshot carries the state without the writes `gone` names. Each write sits in exactly one
//! record (§5.6: a map dot's records hold disjoint writes), so removing writes is local to the
//! piece holding them: each stored page is stripped on its own (`Fragment::remove_gone`), and the
//! pages so stripped are the stripped state's. What is not local is whether a record holding
//! only paged content survives: the stored skeleton and pages may drop such records, so each page
//! (and the skeleton) is read with the path to every collection paged directly below it that
//! keeps an element (`survives`: read from that collection's pages in order until one holds an
//! element, remembered per collection) grafted in, empty (`graft`): the encoder then reads that
//! collection's own pages there. A graft costs the path's bytes, which the node holds per paged
//! collection anyway, never an element: a page's range may hold any number of such records (one
//! dot under many keys).

use crate::error::Error;
use crate::fragment::{Encoding, Fragment};
use crate::page::{PageWalk, Paged};
use crate::paging::{Paths, Step};
use crate::stamp::Dot;
use std::collections::BTreeMap;

/// A `Paged` state as read for its snapshot.
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
        let mut v = View { paths: p.paths, pages: p.pages, gone: p.gone, kept: BTreeMap::new(), beside: 0, held: 0 };
        let mut s = p.skeleton.clone();
        s.remove_gone(v.gone);
        v.graft_below(&mut s, &[], None)?;
        v.beside = s.approx_bytes() as u64;
        v.note(0);
        Ok((v, s))
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

    /// Each piece of the state as read: the skeleton (`skeleton`), then every page of every
    /// paged collection.
    pub(crate) fn each_piece(&mut self, skeleton: &Fragment, each: &mut dyn FnMut(&Fragment)) -> Result<(), Error> {
        each(skeleton);
        let mut all = Vec::new();
        every(self.paths, &mut Vec::new(), &mut all);
        for p in all {
            for i in 0..self.pages(&p)? {
                each(&self.page(&p, i)?);
            }
        }
        Ok(())
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
                graft(f, keyed.get(path.len()..).unwrap_or_default(), enc, self.gone);
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

/// Grafts `rel` into `f` with an empty collection of encoding `leaf` at its end, adding no write
/// but an entry step's creation where its record lacks one, the creation is not gone, and no
/// reset of its dot here reaches it (a creation stays on a set's path until its record's next
/// write; the reset that took it sits beside the record: notes/engine-paged.md). A stripped page
/// keeps no record a graft must not: what is grafted holds a surviving element.
fn graft(f: &mut Fragment, rel: &[(Step, Option<osis_base::Value>, Option<crate::Stamp>)], leaf: Encoding, gone: &dyn Fn(&Dot) -> bool) {
    let Some(((step, _, created), rest)) = rel.split_first() else { return };
    let fresh = || match rest.first() {
        None => Fragment::empty(leaf),
        Some((Step::Field(_), _, _)) => Fragment::empty(Encoding::Struct),
        Some((Step::Case(_), _, _)) => Fragment::empty(Encoding::Enum),
        Some((Step::Entry(_), _, _)) => Fragment::empty(Encoding::Map),
    }
    .unwrap_or_default();
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
        (Step::Field(id), Fragment::Struct(x)) => x.fields.entry(*id).or_insert_with(fresh),
        (Step::Case(id), Fragment::Enum(x)) => x.payloads.entry(*id).or_insert_with(fresh),
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
            e.frag.get_or_insert_with(|| Box::new(fresh()))
        }
        _ => return,
    };
    graft(child, rest, leaf, gone);
}
