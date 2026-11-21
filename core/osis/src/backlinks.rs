//! Backlinks (notes/api.md Backlinks): the things whose current values reference a thing, read
//! from the engine's reference index (notes/engine-refs.md) a page at a time, as the acting actor
//! may read them, and live through the dispatcher as any value listener is. spec: none (a local
//! read; the port's rows: notes/client-port.md).

use crate::error::Result;
use crate::handle::{Osis, ReadOnly};
use crate::read::Reader;
use crate::track::thing_key;
use crate::watch::{Delivery, Filter, Subscription, Watch};
use osis_base::{Ak, RefKind, Tid};
use crate::core::HOLDS;

/// Backlinks a page holds when the query names no limit, and at most. Resource bound: 0 returns
/// nothing, infinity reads every backlink of a thing in one call under the node lock.
pub const BACKLINK_PAGE: usize = 256;

/// A thing whose current value on an aspect references another thing.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Backlink {
    /// The aspect whose value holds it.
    pub ak: Ak,
    /// The thing holding the reference.
    pub tid: Tid,
    /// Whether it is a strong, a weak or a ticket.
    pub kind: RefKind,
}

/// Which backlinks a page holds: in `Backlink` order (by aspect, then thing, then kind).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BacklinkQuery {
    /// Only those on this aspect (`None`: on every aspect). A page and its listener then read
    /// and wake for this aspect's references alone.
    pub aspect: Option<Ak>,
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
        let mut after = q.after.as_ref().map(|b| (b.tid, b.ak.clone(), b.kind));
        let mut page = BacklinkPage::default();
        loop {
            // one past the page: whether there are more
            let want = limit + 1 - page.backlinks.len();
            let rows = self.e.references_page(&target, q.aspect.as_ref(), after.as_ref().map(|(t, a, k)| (t, a, *k)), want)?;
            let n = rows.len();
            for (tid, ak, kind) in rows {
                after = Some((tid, ak.clone(), kind));
                if self.hidden(tid) {
                    continue;
                }
                if page.backlinks.len() == limit {
                    page.more = true;
                    return Ok(page);
                }
                page.backlinks.push(Backlink { ak, tid, kind });
            }
            if n < want {
                return Ok(page);
            }
        }
    }
}

/// What may change `tid`'s backlinks on `on` as the handle reads them: a row naming it there,
/// and with an acting actor what it may read.
fn watch(db: &ReadOnly, tid: Tid, on: Option<&Ak>) -> Filter {
    Filter::Due(Watch::Backlinks(tid, on.cloned(), db.acting.is_some()))
}

impl ReadOnly {
    /// The things whose current values reference `tid` (a strong, a weak or a ticket, at any
    /// depth), each with the aspect and the kind, a page at a time. Only what this node holds and the handle may read counts, never
    /// history. `tid` itself need not be known here.
    pub fn backlinks(&self, tid: Tid, q: &BacklinkQuery) -> Result<BacklinkPage> {
        self.local_at(tid, "backlinks")?;
        if self.tracking.is_some() {
            self.engine(|e| e.watch_references());
        }
        let q2 = q.clone();
        self.read_answer(|| format!("{} {q:?}", thing_key("backlinks", tid)), watch(self, tid, q.aspect.as_ref()), move |r| r.backlinks(tid, &q2))
    }
}

impl ReadOnly {
    /// Whether `holder` holds `t`: a strong to `t` in `holder`'s `holds.0` (`Write::hold`). One
    /// reference looked up, never the whole set; a tracked read hears only a reference to `t` in a
    /// `holds.0` appearing or going. `false` when the handle may not read `holder`.
    pub fn holds(&self, holder: Tid, t: Tid) -> Result<bool> {
        self.local_at(holder, "holds")?;
        if self.tracking.is_some() {
            self.engine(|e| e.watch_references());
        }
        let on = HOLDS.name();
        let at = watch(self, t, Some(&on));
        self.read_answer(|| format!("holds {holder} {t}"), at, move |r| r.holds_strong(holder, t, &on))
    }
}

impl Reader<'_> {
    /// Whether `holder`'s `holds.0` holds a strong to `t`, as the acting actor reads it.
    fn holds_strong(&mut self, holder: Tid, t: Tid, on: &Ak) -> Result<bool> {
        if self.hidden(holder) {
            return Ok(false);
        }
        Ok(self.e.references(&t, &holder, on, RefKind::Strong)?)
    }
}

impl Osis {
    /// Calls `f` with `backlinks(tid, q)` now (through the dispatcher), then each time it reads
    /// otherwise after a change, whatever caused it; an error always. Fails `Network` when `tid`
    /// is at a node that cannot be reached now; a live watch hears a lost connection as an `Err`,
    /// and the page again once it is back.
    pub fn on_backlinks_change(&self, tid: Tid, q: &BacklinkQuery, mut f: impl FnMut(&Osis, Result<BacklinkPage>) + Send + 'static) -> Result<Subscription> {
        self.local_at(tid, "on_backlinks_change")?;
        let (q, limit, actor) = (q.clone(), self.inner.limit, self.acting);
        let mut failed = None;
        let sub = self.subscribe(watch(self, tid, q.aspect.as_ref()), true, |r| {
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
                _ => {}
            })
        });
        failed.map_or(Ok(sub), Err)
    }
}
