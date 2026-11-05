//! An aspect's history (notes/api.md History): the bodies this node holds, each with its verified
//! author, time and validity, paged by time from either end, and a change event per commit. Unlike
//! a read of the state, a superseded body reads as it was written; what is not here reads as what
//! it is, never as nothing.

use crate::commits::CommitKind;
use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::read::{AspectRef, Reader, ak_of, lenient};
use crate::sources::Route;
use crate::read::Stamp;
use crate::watch::{Delivery, Filter, Subscription};
use crate::commit_id::{CommitId, HistoryFrom, HistoryPos};
use osis_base::{Ak, Tid, Value};
use osis_node::engine::history::{HistoryRow, RowBody};
use osis_schema::AspectKey;

/// Entries of a page at most. Resource bound against a caller asking for everything at once under
/// the engine lock: past it a page ends early and says `more`. 0 would read nothing, infinity a
/// whole aspect in one call.
#[doc(hidden)]
pub const HISTORY_PAGE: usize = 256;

/// What is here of an entry's body.
#[derive(Clone, Debug, PartialEq)]
pub enum HistoryBody<T> {
    /// Its value (`None`: the write holds no whole value of the key's type, a removal or a path
    /// write, or it does not read as that type: a `Mismatch` diagnostic).
    Held(Option<T>),
    /// Held, and above `AppConfig::read_limit`.
    TooLarge {
        /// The limit it is above.
        limit: usize,
    },
    /// Purged, on every honest node: the entry stays to say so.
    Purged {
        /// The purge.
        by: CommitId,
        /// Who made it (`None`: not known here).
        actor: Option<Tid>,
    },
    /// Gone for another reason: it expired, passed `Retention::at_most` or was tidied up.
    Gone,
    /// Not on this node yet: known of, and still to arrive. Not an absence.
    NotFetched,
}

/// One commit's write on an aspect: `commit.actor` is verified exactly when `valid`.
#[derive(Clone, Debug, PartialEq)]
pub struct HistoryEntry<T> {
    /// Which commit, who wrote it and when.
    pub commit: Stamp,
    /// What kind of commit it is.
    pub kind: CommitKind,
    /// Valid here, now: it may change (the watch says when).
    pub valid: bool,
    /// What is here of what it wrote.
    pub body: HistoryBody<T>,
}

impl<T> HistoryEntry<T> {
    /// This entry's place, for `HistoryFrom::Before` and `After`.
    pub fn pos(&self) -> HistoryPos {
        self.commit.pos()
    }
}

/// A page of history, in the direction it was asked for.
#[derive(Clone, Debug, PartialEq)]
pub struct HistoryPage<T> {
    /// The entries, in the order asked for.
    pub entries: Vec<HistoryEntry<T>>,
    /// More entries lie that way here.
    pub more: bool,
    /// Every sync carrying the thing with a saved peer finished here, so past the last entry there
    /// is nothing this node knows of. `false`: entries may yet arrive anywhere in the history, older
    /// ones too (offline, syncing): not fetched, not absent. A group with no saved peer has no such
    /// pass to wait for and counts as finished, though a node that reads it may hold more.
    pub complete: bool,
}

/// What an `on_history` callback hears.
#[derive(Clone, Debug, PartialEq)]
pub enum HistoryEvent<T> {
    /// This commit's entry reads otherwise now: new (late ones too), turned valid or invalid, body
    /// arrived, purged, dropped. `None`: it has no entry any more (a memory commit gone).
    Commit {
        /// The commit.
        id: CommitId,
        /// Its entry as it reads now.
        entry: Option<HistoryEntry<T>>,
    },
    /// Events may have been missed: a connection to the node dropped or came back, or an entry
    /// did not fit. Read the pages shown again; the subscription goes on.
    Reread,
    /// The subscription is over (its group's source moved, or the node ended it): subscribe again.
    Ended(Error),
}

/// `row` as an API entry (`limit`: the bound its links materialize under). A link whose value
/// cannot be read here reads as not fetched, a store failure aside.
fn entry_of(r: &mut Reader<'_>, tid: &Tid, ak: &Ak, row: HistoryRow, limit: usize) -> Result<HistoryEntry<Value>> {
    let body = match row.body {
        RowBody::Held(None) => HistoryBody::Held(None),
        RowBody::Held(Some(v)) => match r.materialized(tid, ak, row.id, v, limit) {
            Ok(v) => HistoryBody::Held(Some(v)),
            Err(Error::TooLarge { .. }) => HistoryBody::TooLarge { limit },
            Err(e @ Error::Storage(_)) => return Err(e),
            Err(_) => HistoryBody::NotFetched,
        },
        RowBody::TooLarge => HistoryBody::TooLarge { limit },
        RowBody::Purged(by) => HistoryBody::Purged { by: CommitId::commit(by), actor: r.e.header(&by).map(|h| h.actor) },
        RowBody::Dropped => HistoryBody::Gone,
        RowBody::NotFetched => HistoryBody::NotFetched,
    };
    let kind = row.kind.map_or(CommitKind::Ephemeral, crate::commits::kind_of_commit);
    Ok(HistoryEntry { commit: Stamp::new(row.id.into(), row.actor, row.node, row.ts, row.received), kind, valid: row.valid, body })
}

/// `e` through the key's type.
pub(crate) fn typed<K: AspectKey>(db: &Osis, tid: Tid, ak: &Ak, key: &K, e: HistoryEntry<Value>) -> HistoryEntry<K::T> {
    let body = match e.body {
        HistoryBody::Held(v) => HistoryBody::Held(v.and_then(|v| lenient(tid, ak, key.decode(&v), |d| db.engine(|e| e.report(d))))),
        HistoryBody::TooLarge { limit } => HistoryBody::TooLarge { limit },
        HistoryBody::Purged { by, actor } => HistoryBody::Purged { by, actor },
        HistoryBody::Gone => HistoryBody::Gone,
        HistoryBody::NotFetched => HistoryBody::NotFetched,
    };
    HistoryEntry { commit: e.commit, kind: e.kind, valid: e.valid, body }
}

impl Osis {
    /// A page at this engine, at most `budget` bytes of bodies; what a thing the actor may not read
    /// gets is what an unknown tid gets.
    pub(crate) fn history_here(&self, tid: Tid, ak: &Ak, from: HistoryFrom, limit: usize, budget: usize) -> Result<HistoryPage<Value>> {
        let (mat, actor) = (self.inner.limit, self.acting);
        let budget = budget.min(mat);
        let cut = limit > HISTORY_PAGE;
        let limit = limit.min(HISTORY_PAGE);
        self.locked(|l| {
            let mut r = Reader { e: l.engine(), limit: mat, actor };
            if r.hidden(tid) {
                return Ok(HistoryPage { entries: Vec::new(), more: false, complete: true });
            }
            let (rows, mut more) = r.e.history(&tid, ak, from.into(), limit, budget)?;
            more |= cut && rows.len() == limit;
            let (n, mut used) = (rows.len(), 0usize);
            let mut entries = Vec::with_capacity(n);
            // links count once materialized: a page fits what a reply carries
            for (i, row) in rows.into_iter().enumerate() {
                let e = entry_of(&mut r, &tid, ak, row, budget)?;
                if let HistoryBody::Held(Some(v)) = &e.body {
                    used = used.saturating_add(osis_base::cbor::encode(v).len());
                }
                entries.push(e);
                if used > budget {
                    more |= i + 1 < n;
                    break;
                }
            }
            let complete = crate::share::fetched(l, tid);
            Ok(HistoryPage { entries, more, complete })
        })
    }

    /// The entry of `id` at this engine; what a callback or a Notify reads.
    pub(crate) fn history_entry_here(&self, tid: Tid, ak: &Ak, id: &CommitId) -> Result<Option<HistoryEntry<Value>>> {
        let (mat, actor) = (self.inner.limit, self.acting);
        self.locked(|l| {
            let mut r = Reader { e: l.engine(), limit: mat, actor };
            if r.hidden(tid) {
                return Ok(None);
            }
            let Some(row) = r.e.history_entry(&tid, ak, &id.0, mat)? else { return Ok(None) };
            entry_of(&mut r, &tid, ak, row, mat).map(Some)
        })
    }
}

impl<K: AspectKey> AspectRef<'_, K> {
    /// A page of the aspect's history here: at most `limit` entries from `from`, in its direction; it
    /// may end sooner, and `more` says so. A page costs its entries, however long the history. An
    /// unknown thing, or one the caller may not read, has none.
    pub fn history(&self, from: HistoryFrom, limit: usize) -> Result<HistoryPage<K::T>> {
        let ak = ak_of(&self.key)?;
        let page = match self.db.route(self.tid) {
            Route::Remote(r) => self.db.remote_history(&r, self.tid, &ak, from, limit)?,
            Route::Local => self.db.history_here(self.tid, &ak, from, limit, usize::MAX)?,
        };
        let entries = page.entries.into_iter().map(|e| typed(self.db, self.tid, &ak, &self.key, e)).collect();
        Ok(HistoryPage { entries, more: page.more, complete: page.complete })
    }
}

impl<K: AspectKey + Clone + Send + 'static> AspectRef<'_, K> {
    /// Calls `f` for each commit whose entry in the aspect's history reads otherwise, one call per
    /// commit, with the entry as it reads then: no recompute of the aspect, no re-read of a page.
    /// Subscribe first, then read pages: nothing after the subscription is missed, and an event
    /// repeating what a page showed is harmless.
    pub fn on_history(&self, mut f: impl FnMut(&Osis, HistoryEvent<K::T>) + Send + 'static) -> Result<Subscription> {
        let ak = ak_of(&self.key)?;
        let key = self.key.clone();
        let tid = self.tid;
        let ak2 = ak.clone();
        let typed_event = move |db: &Osis, ev: HistoryEvent<Value>| match ev {
            HistoryEvent::Commit { id, entry } => HistoryEvent::Commit { id, entry: entry.map(|e| typed(db, tid, &ak2, &key, e)) },
            HistoryEvent::Reread => HistoryEvent::Reread,
            HistoryEvent::Ended(e) => HistoryEvent::Ended(e),
        };
        let mut deliver = move |db: &Osis, ev: HistoryEvent<Value>| f(db, typed_event(db, ev));
        if let Route::Remote(r) = self.db.route(self.tid) {
            return self.db.remote_on_history(&r, self.tid, ak, Box::new(deliver));
        }
        let t = self.tid;
        // the dispatcher's handle acts for no one: read as this one does
        let acting = self.db.acting;
        Ok(self.db.subscribe(Filter::History(t, ak.clone()), false, move |_| {
            Box::new(move |db, d| match d {
                Delivery::History { tid, id } => match acting.map_or_else(|| db.history_entry_here(tid, &ak, &id), |a| db.act_as(a).history_entry_here(tid, &ak, &id)) {
                    Ok(entry) => deliver(db, HistoryEvent::Commit { id, entry }),
                    Err(e) => deliver(db, HistoryEvent::Ended(e)),
                },
                Delivery::Moved => deliver(db, HistoryEvent::Ended(crate::sources::moved())),
                _ => {}
            })
        }))
    }
}
