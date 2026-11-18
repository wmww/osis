//! What each source's stream showed (spec/sync-judgement.md §3 `known`), with what else a source
//! told on its stream: its head per sync ID, full, and the refusals it sent (spec/sync-streams.md
//! §4 Full, Refused). Every read and write is stamped, so a memo or `Effects` reading it is moved
//! by exactly the source, sync ID and entry that changed.
//!
//! A refusal stands only while its ground does: it goes when the entry is offered again to that
//! source (`Op::Lift`, from serving), when the source's stream shows the entry present, and with
//! every refusal of S there when the head its stream names moves. `full` is a fact of the
//! connection it was told on (spec/sync-streams.md §4 Full), kept under `Source::Conn` whatever
//! the source: it ends with `full` false, S leaving the connection, or the connection.
//!
//! A source is a peer's record, or the connection for a peer with none (`store::Source`). A
//! record's word is durable: rows of the record (`store::rows::tag` PRESENT, HEAD, KEPT, REFUSED),
//! written by the transaction that applies what showed it (`Op`, `write`), lost with the record
//! (a lost record is a first contact) and stamped by the store. A connection's is in memory and
//! goes with it; ephemeral entries are known only so (they have no log position and are lost at
//! a restart without an event), under `Source::Conn`.
//!
//! A read of a record's rows that the store fails answers as if nothing were shown, which only
//! ever holds back an act (nothing is judged held elsewhere, left or registered on it); the
//! one read whose absence would act, the presence a listing replaces, fails the step instead
//! (`list`).

use crate::store::Source;
use crate::store::Store;
use crate::store::rows::tag::{HEAD, KEPT, PRESENT, REFUSED};
use crate::types::{ConnId, RecordId};
use osis_base::memo::{Feed, Stamps};
use osis_base::{BlobId, SyncId};
use osis_blob::StepId;
use osis_proto::Code;
use osis_store::Transaction;
use std::collections::{BTreeMap, BTreeSet};

/// A change of what a source showed of S.
#[derive(Clone, Debug)]
pub(super) enum Op {
    Add(SyncId, BlobId),
    Remove(SyncId, BlobId),
    Head(SyncId, StepId),
    /// The source joined S keeping it unread (a store source, spec/sync-opens.md §4) or not.
    Kept(SyncId, bool),
    /// Told on a connection (under `Source::Conn` only).
    Full(SyncId, bool),
    Refused(SyncId, BlobId, Code),
    /// The source's refusal of one entry of S, or of every entry of S, ends: offered to it again.
    Lift(SyncId, Option<BlobId>),
    /// Everything shown of S goes.
    Forget(SyncId),
}

/// Writes `op` into record `rec`'s rows.
pub(super) fn write(t: &mut Transaction<'_>, rec: &RecordId, op: &Op) -> Result<(), osis_store::Error> {
    let lift_all = |t: &mut Transaction<'_>, s: &SyncId| -> Result<(), osis_store::Error> {
        for (k, _) in t.record_rows(rec, REFUSED, s, b"", usize::MAX)? {
            t.record_remove_row(rec, REFUSED, s, &k)?;
        }
        Ok(())
    };
    match op {
        Op::Add(s, b) => {
            t.record_remove_row(rec, REFUSED, s, &b.0)?;
            t.record_put_row(rec, PRESENT, s, &b.0, Vec::new())
        }
        Op::Remove(s, b) => t.record_remove_row(rec, PRESENT, s, &b.0).map(drop),
        // the same head named again writes nothing: what read it does not move as a stream
        // rejoins
        Op::Head(s, h) => match t.record_get_row(rec, HEAD, s, b"")? {
            Some(v) if v == h.0 => Ok(()),
            old => {
                if old.is_some() {
                    lift_all(t, s)?;
                }
                t.record_put_row(rec, HEAD, s, b"", h.0.to_vec())
            }
        },
        Op::Kept(s, k) => match t.record_get_row(rec, KEPT, s, b"")? {
            Some(v) if v == [*k as u8] => Ok(()),
            _ => t.record_put_row(rec, KEPT, s, b"", vec![*k as u8]),
        },
        Op::Full(..) => Ok(()),
        Op::Refused(s, b, c) => t.record_put_row(rec, REFUSED, s, &b.0, c.0.to_be_bytes().to_vec()),
        Op::Lift(s, Some(b)) => t.record_remove_row(rec, REFUSED, s, &b.0).map(drop),
        Op::Lift(s, None) => lift_all(t, s),
        Op::Forget(s) => {
            lift_all(t, s)?;
            for (k, _) in t.record_rows(rec, PRESENT, s, b"", usize::MAX)? {
                t.record_remove_row(rec, PRESENT, s, &k)?;
            }
            t.record_remove_row(rec, KEPT, s, b"")?;
            t.record_remove_row(rec, HEAD, s, b"").map(drop)
        }
    }
}

#[derive(Clone, Debug)]
pub struct Known {
    store: Store,
    by_src: BTreeMap<(Source, SyncId), BTreeSet<BlobId>>,
    by_blob: BTreeMap<(SyncId, BlobId), BTreeSet<Source>>,
    heads: BTreeMap<(Source, SyncId), StepId>,
    kept: BTreeMap<(Source, SyncId), bool>,
    full: BTreeSet<(Source, SyncId)>,
    /// Refusals kept in memory: a connection's source's, and an ephemeral entry's whatever the
    /// source (they go with the entry: none outlives a restart); by entry in `refused_by`.
    refused: BTreeMap<(Source, SyncId, BlobId), Code>,
    refused_by: BTreeMap<(SyncId, BlobId), BTreeSet<Source>>,
    /// The store's entries changed: a refusal of an entry no longer held goes (`settle`).
    entries: Feed<(SyncId, BlobId)>,
    stamps: Stamps,
    /// Every presence row written (shown present or removed, any source): `feed` readers take
    /// each (read, judging what a source showed of a commit).
    log: Stamps,
}

/// A presence row as `Known::feed` names it.
pub type Row = (Source, SyncId, BlobId);

impl Known {
    pub(super) fn new(store: Store) -> Known {
        let entries = store.entry_feed();
        Known { store, by_src: BTreeMap::new(), by_blob: BTreeMap::new(), heads: BTreeMap::new(), kept: BTreeMap::new(), full: BTreeSet::new(), refused: BTreeMap::new(), refused_by: BTreeMap::new(), entries, stamps: Stamps::named("streams: known"), log: Stamps::named("streams: known rows") }
    }

    /// Tests only (world copies): the copy's store.
    pub(super) fn set_store(&mut self, store: Store) {
        self.entries = store.entry_feed();
        self.store = store;
    }

    fn read<T: Default>(&self, f: impl FnOnce(&mut Transaction<'_>) -> Result<T, osis_store::Error>) -> T {
        self.store.with_read(f).unwrap_or_default()
    }

    fn wrote(&self, src: Source, s: &SyncId, b: &BlobId) {
        self.stamps.wrote(&("k", src, s, b), true);
        self.stamps.wrote(&("p", s, b), true);
        self.stamps.wrote(&("l", src, s), true);
    }

    /// `op` of `src` was applied (written durably, or in memory): a presence row goes to the feed.
    pub(super) fn logged(&self, src: Source, op: &Op) {
        if let Op::Add(s, b) | Op::Remove(s, b) = op {
            self.log.wrote_added(&(src, *s, *b), true, true);
        }
    }

    /// A cursor over the presence rows written from now on.
    pub fn feed(&self) -> osis_base::memo::Feed<Row> {
        self.log.feed()
    }

    /// Applies `ops` of a connection's source in memory (a record's go through `write`).
    pub(super) fn apply_conn(&mut self, src: Source, ops: &[Op]) {
        for op in ops {
            match op {
                Op::Add(s, b) => {
                    self.lift(src, *s, b);
                    if self.by_src.entry((src, *s)).or_default().insert(*b) {
                        self.by_blob.entry((*s, *b)).or_default().insert(src);
                        self.wrote(src, s, b);
                    }
                }
                Op::Remove(s, b) => self.remove_conn(src, *s, b),
                Op::Head(s, h) => match self.heads.insert((src, *s), *h) {
                    Some(old) if old == *h => {}
                    old => {
                        self.stamps.wrote(&("h", src, s), true);
                        if old.is_some() {
                            self.lift_all(src, *s);
                        }
                    }
                },
                Op::Kept(s, k) => {
                    if self.kept.insert((src, *s), *k) != Some(*k) {
                        self.stamps.wrote(&("u", src, s), true);
                    }
                }
                Op::Full(s, full) => {
                    let changed = if *full { self.full.insert((src, *s)) } else { self.full.remove(&(src, *s)) };
                    if changed {
                        self.stamps.wrote(&("f", src, s), *full);
                    }
                }
                Op::Refused(s, b, c) => self.refused_here(src, *s, *b, *c),
                Op::Lift(s, Some(b)) => self.lift(src, *s, b),
                Op::Lift(s, None) => self.lift_all(src, *s),
                Op::Forget(s) => self.forget_conn(src, *s),
            }
        }
    }

    /// A refusal kept in memory whatever the source (an ephemeral entry's: `refused`).
    pub(super) fn refused_here(&mut self, src: Source, s: SyncId, b: BlobId, c: Code) {
        if self.refused.insert((src, s, b), c).is_none() {
            self.refused_by.entry((s, b)).or_default().insert(src);
            self.stamps.wrote(&("rs", src, s), true);
        }
    }

    /// A record's `op` was written (`write`): its refusals kept in memory end as its rows do
    /// (`moved`: an `Op::Head` naming a head other than the one stored).
    pub(super) fn wrote_record(&mut self, src: Source, op: &Op, moved: bool) {
        match op {
            Op::Add(s, b) | Op::Lift(s, Some(b)) => self.lift(src, *s, b),
            Op::Lift(s, None) | Op::Forget(s) => self.lift_all(src, *s),
            Op::Head(s, _) if moved => self.lift_all(src, *s),
            _ => {}
        }
    }

    /// The refusals kept in memory of entries that left this node go (spec/sync-streams.md §4
    /// Refused: kept per entry held; a record's rows go with the entry, `store::entries::remove`).
    /// O(the entries changed).
    pub(super) fn settle(&mut self) {
        for (s, b) in self.entries.added() {
            if self.refused_by.contains_key(&(s, b)) && self.store.entry(&s, &b).ok().flatten().is_none() {
                for src in self.refused_by.get(&(s, b)).cloned().unwrap_or_default() {
                    self.lift(src, s, &b);
                }
            }
        }
    }

    fn remove_conn(&mut self, src: Source, s: SyncId, b: &BlobId) {
        let Some(set) = self.by_src.get_mut(&(src, s)) else { return };
        if !set.remove(b) {
            return;
        }
        if set.is_empty() {
            self.by_src.remove(&(src, s));
        }
        if let Some(srcs) = self.by_blob.get_mut(&(s, *b)) {
            srcs.remove(&src);
            if srcs.is_empty() {
                self.by_blob.remove(&(s, *b));
            }
        }
        self.wrote(src, &s, b);
    }

    fn forget_conn(&mut self, src: Source, s: SyncId) {
        for b in self.by_src.get(&(src, s)).cloned().unwrap_or_default() {
            self.remove_conn(src, s, &b);
        }
        if self.full.remove(&(src, s)) {
            self.stamps.wrote(&("f", src, s), false);
        }
        if self.heads.remove(&(src, s)).is_some() {
            self.stamps.wrote(&("h", src, s), false);
        }
        if self.kept.remove(&(src, s)).is_some() {
            self.stamps.wrote(&("u", src, s), false);
        }
        self.lift_all(src, s);
    }

    fn lift(&mut self, src: Source, s: SyncId, b: &BlobId) {
        if self.refused.remove(&(src, s, *b)).is_some() {
            if let Some(set) = self.refused_by.get_mut(&(s, *b)) {
                set.remove(&src);
                if set.is_empty() {
                    self.refused_by.remove(&(s, *b));
                }
            }
            self.stamps.wrote(&("rs", src, s), false);
        }
    }

    fn lift_all(&mut self, src: Source, s: SyncId) {
        let gone: Vec<_> = self.refused.range((src, s, BlobId([0; 32]))..=(src, s, BlobId([0xff; 32]))).map(|(k, _)| *k).collect();
        for (_, _, b) in gone {
            self.lift(src, s, &b);
        }
    }

    /// What every connection's source showed of S goes (S shredded here; a record's rows went
    /// with it). O(what connections showed in memory): S leaving is rare.
    pub(super) fn forget_conns(&mut self, s: &SyncId) {
        let srcs: BTreeSet<Source> = self.by_src.keys().filter(|(_, x)| x == s).map(|(src, _)| *src).chain(self.full.iter().filter(|(_, x)| x == s).map(|(src, _)| *src)).chain(self.heads.keys().filter(|(_, x)| x == s).map(|(src, _)| *src)).chain(self.kept.keys().filter(|(_, x)| x == s).map(|(src, _)| *src)).chain(self.refused.keys().filter(|(_, x, _)| x == s).map(|(src, ..)| *src)).collect();
        for src in srcs {
            self.forget_conn(src, *s);
        }
    }

    /// Everything a connection's source showed goes with it (its ephemeral entries and what a
    /// peer with no record showed).
    pub fn forget_source(&mut self, src: Source) {
        let ids: BTreeSet<SyncId> = self.by_src.range((src, SyncId([0; 16]))..=(src, SyncId([0xff; 16]))).map(|((_, s), _)| *s).chain(self.full.iter().filter(|(x, _)| *x == src).map(|(_, s)| *s)).chain(self.heads.keys().filter(|(x, _)| *x == src).map(|(_, s)| *s)).chain(self.kept.keys().filter(|(x, _)| *x == src).map(|(_, s)| *s)).chain(self.refused.keys().filter(|(x, ..)| *x == src).map(|(_, s, _)| *s)).collect();
        for s in ids {
            self.forget_conn(src, s);
        }
    }

    /// Whether `src`'s stream showed `b` present under S.
    pub fn knows(&self, src: Source, s: &SyncId, b: &BlobId) -> bool {
        match src {
            Source::Record(rec) => self.read(|t| Ok(t.record_get_row(&rec, PRESENT, s, &b.0)?.is_some())),
            Source::Conn(_) => {
                self.stamps.read(&("k", src, s, b));
                self.by_src.get(&(src, *s)).is_some_and(|x| x.contains(b))
            }
        }
    }

    /// Whether any source's stream showed `b` present under S.
    pub fn present(&self, s: &SyncId, b: &BlobId) -> bool {
        self.stamps.read(&("p", s, b));
        self.by_blob.contains_key(&(*s, *b)) || self.read(|t| t.records_any_row(s, PRESENT, &b.0))
    }

    /// Every presence row, of every source (a start judges what each shows; O(rows)).
    pub fn rows_all(&self) -> Result<Vec<Row>, osis_store::Error> {
        let mut out: Vec<Row> = self.by_src.iter().flat_map(|((src, s), bs)| bs.iter().map(move |b| (*src, *s, *b))).collect();
        let recs = self.store.with_read(|t| {
            let mut rows = Vec::new();
            for r in t.records_all()? {
                for (s, k, _) in t.record_tag_rows(&r.id, PRESENT)? {
                    if let Ok(b) = <[u8; 32]>::try_from(k.as_slice()) {
                        rows.push((Source::Record(r.id), s, BlobId(b)));
                    }
                }
            }
            Ok(rows)
        });
        out.extend(recs.map_err(|e| match e {
            crate::types::Error::Store(e) => e,
            _ => osis_store::Error::Corrupt("streams: known"),
        })?);
        Ok(out)
    }

    /// The sources whose stream showed `b` present under S.
    pub fn shown_at(&self, s: &SyncId, b: &BlobId) -> BTreeSet<Source> {
        self.stamps.read(&("p", s, b));
        let mut out = self.by_blob.get(&(*s, *b)).cloned().unwrap_or_default();
        out.extend(self.read(|t| t.records_with_row(s, PRESENT, &b.0, usize::MAX)).into_iter().map(Source::Record));
        out
    }

    /// What `src`'s stream showed present under S, or the store's failure: a listing replacing
    /// presence reads it, and a list read as empty would keep presence the listing proved gone.
    pub fn list(&self, src: Source, s: &SyncId) -> Result<Vec<BlobId>, osis_store::Error> {
        match src {
            Source::Record(rec) => self.store.with_read(|t| t.record_rows(&rec, PRESENT, s, b"", usize::MAX).map(|rows| rows.into_iter().filter_map(|(k, _)| Some(BlobId(k.try_into().ok()?))).collect())).map_err(|e| match e {
                crate::types::Error::Store(e) => e,
                _ => osis_store::Error::Corrupt("streams: known"),
            }),
            Source::Conn(_) => {
                self.stamps.read(&("l", src, s));
                Ok(self.by_src.get(&(src, *s)).map(|x| x.iter().copied().collect()).unwrap_or_default())
            }
        }
    }

    /// The source's step for S: the head its stream last named.
    pub fn head(&self, src: Source, s: &SyncId) -> Option<StepId> {
        match src {
            Source::Record(rec) => self.read(|t| Ok(t.record_get_row(&rec, HEAD, s, b"")?.and_then(|v| Some(StepId(v.try_into().ok()?))))),
            Source::Conn(_) => {
                self.stamps.read(&("h", src, s));
                self.heads.get(&(src, *s)).copied()
            }
        }
    }

    /// Whether the source keeps S unread, as it last joined S (`Op::Kept`): kept with what its
    /// stream showed, so it reads alike while the source is away and after a restart.
    pub fn kept(&self, src: Source, s: &SyncId) -> bool {
        match src {
            Source::Record(rec) => self.read(|t| Ok(t.record_get_row(&rec, KEPT, s, b"")? == Some(vec![1]))),
            Source::Conn(_) => {
                self.stamps.read(&("u", src, s));
                self.kept.get(&(src, *s)) == Some(&true)
            }
        }
    }

    /// Whether the peer on `conn` told on it that it is full for S.
    pub fn full(&self, conn: ConnId, s: &SyncId) -> bool {
        let src = Source::Conn(conn);
        self.stamps.read(&("f", src, s));
        self.full.contains(&(src, *s))
    }

    /// Whether a refusal the source sent of some entry of S stands (spec/sync-streams.md §4
    /// Refused): status names it among those that do not take S.
    pub fn refusing(&self, src: Source, s: &SyncId) -> bool {
        self.stamps.read(&("rs", src, s));
        self.refused.range((src, *s, BlobId([0; 32]))..=(src, *s, BlobId([0xff; 32]))).next().is_some()
            || matches!(src, Source::Record(rec) if self.read(|t| Ok(!t.record_rows(&rec, REFUSED, s, b"", 1)?.is_empty())))
    }

    /// The code of the source's standing refusal of entry `b` of S.
    pub fn refusal(&self, src: Source, s: &SyncId, b: &BlobId) -> Option<Code> {
        self.stamps.read(&("rs", src, *s));
        self.refused.get(&(src, *s, *b)).copied().or_else(|| match src {
            Source::Record(rec) => self.read(|t| Ok(t.record_get_row(&rec, REFUSED, s, &b.0)?.and_then(|v| Some(Code(u64::from_be_bytes(v.try_into().ok()?)))))),
            Source::Conn(_) => None,
        })
    }
}
