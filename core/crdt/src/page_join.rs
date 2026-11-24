//! A stored paged state read with a fragment joined in, a page at a time (`Joined`, spec/crdt.md
//! §8 Values): what a snapshot of a state as it reads once some writes end reads (the stored state
//! without them, joined with what only they superseded).
//!
//! Each page is read without the writes `pre` names, then joined below the skeleton's and
//! `over`'s spines along its path with `over`'s elements in its range (`Fragment::spine`: all a
//! join's pruning there depends on), as a paged state joins a reset a page at a time (osis-engine
//! `pages::join_reset`): elements are independent per dot, and a position is pruned by the resets
//! on its path alone (§4.2). So the pages so read are the pages of `(stored − pre) ⊔ over`,
//! whose skeleton is `Joined::new`'s. Not for a collection paged inside another's elements, a
//! paged sequence (its range records may straddle a page's bounds), or `over` holding another
//! encoding on a paged collection's path: the caller reads those whole.

use crate::error::Error;
use crate::fragment::Fragment;
use crate::page::{KeyedPath, PageWalk, StoredPage};
use crate::paging::{Paths, Step};
use crate::stamp::Dot;
use osis_base::Value;

/// `inner` read as `(stored − pre) ⊔ over` (module doc).
pub struct Joined<'a> {
    inner: &'a mut dyn PageWalk,
    /// The stored skeleton without the writes `pre` names.
    base: Fragment,
    over: &'a Fragment,
    pre: &'a dyn Fn(&Dot) -> bool,
}

impl<'a> Joined<'a> {
    /// `inner`, a state stored as `skeleton` and pages at `paths`, read as joined with `over`
    /// after leaving out the writes `pre` names; and that state's skeleton.
    pub fn new(inner: &'a mut dyn PageWalk, skeleton: &Fragment, paths: &Paths, over: &'a Fragment, pre: &'a dyn Fn(&Dot) -> bool) -> (Joined<'a>, Fragment) {
        let mut base = skeleton.clone();
        base.remove_gone(pre);
        let mut j = base.clone();
        j.join(over.clone());
        (Joined { inner, base, over, pre }, j.reduced(paths))
    }

    /// Stored page `pg` of the collection at `path`, joined.
    fn joined(&mut self, path: &[Step], pg: StoredPage) -> Result<StoredPage, Error> {
        let StoredPage { lo, hi, mut frag } = pg;
        frag.remove_gone(self.pre);
        if !self.over.reaches(path) {
            return Ok(StoredPage { lo, hi, frag });
        }
        let keyed = self.keyed(path)?;
        let enc = frag.encoding();
        let mut g = self.base.spine(path, None);
        g.join(Fragment::wrap(&keyed, frag));
        g.join(self.over.spine(path, Some((lo.as_ref(), hi.as_ref()))));
        let frag = match g.at_steps(path).and_then(|x| x.slot(enc)) {
            Some(crate::state::SlotRef::Frag(c)) => c.elem_range(lo.as_ref(), hi.as_ref(), false),
            _ => Fragment::empty(enc).and_then(|e| e.emptied()),
        };
        Ok(StoredPage { frag: frag.ok_or(Error::Mismatch("a joined page of another encoding"))?, lo, hi })
    }
}

impl PageWalk for Joined<'_> {
    fn pages(&mut self, path: &[Step]) -> Result<usize, Error> {
        self.inner.pages(path)
    }
    fn page(&mut self, path: &[Step], i: usize) -> Result<StoredPage, Error> {
        let pg = self.inner.page(path, i)?;
        self.joined(path, pg)
    }
    /// The stored path without the creations `pre` names, each step's creation the later of
    /// that and `over`'s (as a join keeps it).
    fn keyed(&mut self, path: &[Step]) -> Result<KeyedPath, Error> {
        let mut k = self.inner.keyed(path)?;
        let mut at = Some(self.over);
        for (s, _, created) in &mut k {
            if created.as_ref().is_some_and(|c| (self.pre)(c.dot.origin())) {
                *created = None;
            }
            if let (Step::Entry(id), Some(f)) = (&*s, at)
                && let Some(c) = f.entry_created(id)
                && created.as_ref().is_none_or(|x| x < c)
            {
                *created = Some(c.clone());
            }
            at = at.and_then(|f| f.step(s));
        }
        Ok(k)
    }
    fn page_of(&mut self, path: &[Step], d: &Dot) -> Result<StoredPage, Error> {
        let pg = self.inner.page_of(path, d)?;
        self.joined(path, pg)
    }
    fn dots_of(&mut self, path: &[Step], k: &Value) -> Result<Vec<Dot>, Error> {
        let mut out = self.inner.dots_of(path, k)?;
        if let Some(c) = self.over.at_steps(path) {
            out.extend(c.elem_dots(None, None).into_iter().filter(|d| c.index_values(d).contains(k)));
        }
        Ok(out)
    }
}
