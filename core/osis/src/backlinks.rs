//! Backlinks (notes/api.md Backlinks): the things whose current values hold a thing's tid, read
//! from the engine's reference index (notes/engine-refs.md) a page at a time, as the acting actor
//! may read them, and live through the dispatcher as any value listener is. spec: none (a local
//! read; the port's rows: notes/client-port.md).

use crate::error::Result;
use crate::handle::{Osis, ReadOnly};
use crate::read::Reader;
use crate::track::thing_key;
use crate::watch::{Delivery, Filter, Subscription, Watch};
use osis_base::{Ak, Tid};

/// Backlinks a page holds when the query names no limit, and at most. Resource bound: 0 returns
/// nothing, infinity reads every backlink of a thing in one call under the node lock.
pub const BACKLINK_PAGE: usize = 256;

/// A thing whose current value on an aspect holds another thing's tid.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Backlink {
    /// The thing holding the tid.
    pub tid: Tid,
    /// The aspect whose value holds it.
    pub ak: Ak,
}

/// Which backlinks a page holds: in `Backlink` order (by thing, then aspect).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BacklinkQuery {
    /// Start past this one (`None`: at the first).
    pub after: Option<Backlink>,
    /// At most this many (`None`: as many as a page holds).
    pub limit: Option<usize>,
}

/// A page of backlinks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BacklinkPage {
    /// The backlinks, in order.
    pub backlinks: Vec<Backlink>,
    /// More lie past the last: page again with it as `after`.
    pub more: bool,
}

impl Reader<'_> {
    /// The page `q` of `target`'s backlinks: the index's rows from `q.after` on, skipping sources
    /// the acting actor may not read. O(page + skipped) rows read.
    pub(crate) fn backlinks(&mut self, target: Tid, q: &BacklinkQuery) -> Result<BacklinkPage> {
        let limit = q.limit.unwrap_or(BACKLINK_PAGE).min(BACKLINK_PAGE);
        let mut after = q.after.as_ref().map(|b| (b.tid, b.ak.clone()));
        let mut page = BacklinkPage::default();
        loop {
            // one past the page: whether there are more
            let want = limit + 1 - page.backlinks.len();
            let rows = self.e.references_page(&target, after.as_ref().map(|(t, a)| (t, a)), want)?;
            let n = rows.len();
            for (tid, ak) in rows {
                after = Some((tid, ak.clone()));
                if self.hidden(tid) {
                    continue;
                }
                if page.backlinks.len() == limit {
                    page.more = true;
                    return Ok(page);
                }
                page.backlinks.push(Backlink { tid, ak });
            }
            if n < want {
                return Ok(page);
            }
        }
    }
}

/// What may change `tid`'s backlinks as the handle reads them: a row naming it, and with an acting
/// actor what it may read.
fn watch(db: &ReadOnly, tid: Tid) -> Filter {
    Filter::Due(Watch::Backlinks(tid, db.acting.is_some()))
}

impl ReadOnly {
    /// The things whose current values reference `tid` (hold its tid, at any depth), each with the
    /// aspect, a page at a time. Only what this node holds and the handle may read counts, never
    /// history; a group listing `tid` is one (on `group.0`). `tid` itself need not be known here.
    pub fn backlinks(&self, tid: Tid, q: &BacklinkQuery) -> Result<BacklinkPage> {
        if let crate::sources::Source::Node(r) = self.source(tid) {
            self.untrackable("backlinks at a connected node")?;
            return self.node_backlinks(&r, tid, q);
        }
        if self.tracking.is_some() {
            self.engine(|e| e.watch_references());
        }
        let q2 = q.clone();
        self.read_answer(|| format!("{} {q:?}", thing_key("backlinks", tid)), watch(self, tid), move |r| r.backlinks(tid, &q2))
    }
}

impl Osis {
    /// Calls `f` with `backlinks(tid, q)` now (through the dispatcher), then each time it reads
    /// otherwise after a change, whatever caused it; an error always. Fails `Network` when `tid`
    /// is at a node that cannot be reached now; a live watch hears a lost connection as an `Err`,
    /// and the page again once it is back.
    pub fn on_backlinks_change(&self, tid: Tid, q: &BacklinkQuery, mut f: impl FnMut(&Osis, Result<BacklinkPage>) + Send + 'static) -> Result<Subscription> {
        if let crate::sources::Source::Node(r) = self.source(tid) {
            return self.node_on_backlinks_change(&r, tid, q, Box::new(f));
        }
        let (q, limit, actor) = (q.clone(), self.inner.limit, self.acting);
        let mut failed = None;
        let sub = self.subscribe(watch(self, tid), true, |r| {
            r.e.watch_references();
            let mut last = match r.backlinks(tid, &q) {
                Ok(p) => Some(p),
                Err(e) => {
                    failed = Some(e);
                    None
                }
            };
            let mut first = last.clone();
            Box::new(move |db, d| match d {
                Delivery::Initial => {
                    if let Some(p) = first.take() {
                        f(db, Ok(p));
                    }
                }
                Delivery::Due => match db.locked(|l| Reader { e: l.engine(), limit, actor }.backlinks(tid, &q)) {
                    Ok(p) if last.as_ref() == Some(&p) => {}
                    Ok(p) => {
                        last = Some(p.clone());
                        f(db, Ok(p));
                    }
                    Err(e) => {
                        last = None;
                        f(db, Err(e));
                    }
                },
                Delivery::Moved => f(db, Err(crate::sources::moved())),
                _ => {}
            })
        });
        match failed {
            Some(e) => Err(e),
            None => Ok(sub),
        }
    }
}
