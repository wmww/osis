//! What each source's stream showed (spec/sync-judgement.md §3 `known`), with what else a source
//! told on its stream: its head per sync ID, full, and the refusals it sent (spec/sync-streams.md
//! §4 Full, Refused). Every read and write is stamped, so a memo or `Effects` reading it is moved
//! by exactly the source, sync ID and entry that changed.
//!
//! A source is a peer's record, or the connection for a peer with none (`store::Source`). A
//! record's word is durable: rows of the record (`store::rows::tag` PRESENT, HEAD, FULL, REFUSED),
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
use crate::store::rows::tag::{FULL, HEAD, PRESENT, REFUSED};
use crate::types::RecordId;
use osis_base::memo::Stamps;
use osis_base::{BlobId, SyncId};
use osis_label::StepId;
use osis_proto::{Code, Stamp};
use osis_store::Transaction;
use std::collections::{BTreeMap, BTreeSet};

/// A refusal a source sent for one entry, and the ground it holds on: the entry's stamp and the
/// source's head when it arrived (spec/sync-streams.md §4 Refused).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: Code,
    pub stamp: Option<Stamp>,
    pub head: Option<StepId>,
}

impl Refusal {
    fn encode(&self) -> Vec<u8> {
        let mut w = self.code.0.to_be_bytes().to_vec();
        match &self.stamp {
            Some(s) => {
                w.push(1);
                w.extend_from_slice(&s.0);
            }
            None => w.push(0),
        }
        match &self.head {
            Some(h) => {
                w.push(1);
                w.extend_from_slice(&h.0);
            }
            None => w.push(0),
        }
        w
    }

    fn decode(v: &[u8]) -> Option<Refusal> {
        let (code, rest) = v.split_first_chunk::<8>()?;
        let (stamp, rest) = match rest.split_first()? {
            (1, r) => {
                let (s, r) = r.split_first_chunk::<64>()?;
                (Some(osis_crypto::Signature(*s)), r)
            }
            (_, r) => (None, r),
        };
        let head = match rest.split_first()? {
            (1, r) => Some(StepId(*r.first_chunk::<32>()?)),
            _ => None,
        };
        Some(Refusal { code: Code(u64::from_be_bytes(*code)), stamp, head })
    }
}

/// A change of what a source showed of S.
#[derive(Clone, Debug)]
pub(super) enum Op {
    Add(SyncId, BlobId),
    Remove(SyncId, BlobId),
    Head(SyncId, StepId),
    Full(SyncId, bool),
    Refused(SyncId, BlobId, Refusal),
    /// Everything shown of S goes.
    Forget(SyncId),
}

/// Writes `op` into record `rec`'s rows.
pub(super) fn write(t: &mut Transaction<'_>, rec: &RecordId, op: &Op) -> Result<(), osis_store::Error> {
    match op {
        Op::Add(s, b) => t.record_put_row(rec, PRESENT, s, &b.0, Vec::new()),
        Op::Remove(s, b) => t.record_remove_row(rec, PRESENT, s, &b.0).map(drop),
        Op::Head(s, h) => t.record_put_row(rec, HEAD, s, b"", h.0.to_vec()),
        Op::Full(s, true) => t.record_put_row(rec, FULL, s, b"", Vec::new()),
        Op::Full(s, false) => t.record_remove_row(rec, FULL, s, b"").map(drop),
        Op::Refused(s, b, r) => t.record_put_row(rec, REFUSED, s, &b.0, r.encode()),
        Op::Forget(s) => {
            for tag in [PRESENT, REFUSED] {
                for (k, _) in t.record_rows(rec, tag, s, b"", usize::MAX)? {
                    t.record_remove_row(rec, tag, s, &k)?;
                }
            }
            t.record_remove_row(rec, HEAD, s, b"")?;
            t.record_remove_row(rec, FULL, s, b"").map(drop)
        }
    }
}

#[derive(Clone, Debug)]
pub struct Known {
    store: Store,
    by_src: BTreeMap<(Source, SyncId), BTreeSet<BlobId>>,
    by_blob: BTreeMap<(SyncId, BlobId), BTreeSet<Source>>,
    heads: BTreeMap<(Source, SyncId), StepId>,
    full: BTreeSet<(Source, SyncId)>,
    refused: BTreeMap<(Source, SyncId, BlobId), Refusal>,
    stamps: Stamps,
    /// Every presence row written (shown present or removed, any source): `feed` readers take
    /// each (read, judging what a source showed of a commit).
    log: Stamps,
}

/// A presence row as `Known::feed` names it.
pub type Row = (Source, SyncId, BlobId);

impl Known {
    pub(super) fn new(store: Store) -> Known {
        Known { store, by_src: BTreeMap::new(), by_blob: BTreeMap::new(), heads: BTreeMap::new(), full: BTreeSet::new(), refused: BTreeMap::new(), stamps: Stamps::default(), log: Stamps::default() }
    }

    /// Tests only (world copies): the copy's store.
    pub(super) fn set_store(&mut self, store: Store) {
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
                    if self.by_src.entry((src, *s)).or_default().insert(*b) {
                        self.by_blob.entry((*s, *b)).or_default().insert(src);
                        self.wrote(src, s, b);
                    }
                }
                Op::Remove(s, b) => self.remove_conn(src, *s, b),
                Op::Head(s, h) => {
                    if self.heads.insert((src, *s), *h) != Some(*h) {
                        self.stamps.wrote(&("h", src, s), true);
                    }
                }
                Op::Full(s, full) => {
                    let changed = if *full { self.full.insert((src, *s)) } else { self.full.remove(&(src, *s)) };
                    if changed {
                        self.stamps.wrote(&("f", src, s), *full);
                    }
                }
                Op::Refused(s, b, r) => {
                    self.stamps.wrote(&("r", (src, *s, *b)), true);
                    self.stamps.wrote(&("rs", src, *s), true);
                    self.refused.insert((src, *s, *b), r.clone());
                }
                Op::Forget(s) => self.forget_conn(src, *s),
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
        let gone: Vec<_> = self.refused.range((src, s, BlobId([0; 32]))..=(src, s, BlobId([0xff; 32]))).map(|(k, _)| *k).collect();
        for k in gone {
            self.refused.remove(&k);
            self.stamps.wrote(&("r", k), false);
            self.stamps.wrote(&("rs", k.0, k.1), false);
        }
    }

    /// Everything a connection's source showed goes with it (its ephemeral entries and what a
    /// peer with no record showed).
    pub fn forget_source(&mut self, src: Source) {
        let ids: BTreeSet<SyncId> = self.by_src.range((src, SyncId([0; 16]))..=(src, SyncId([0xff; 16]))).map(|((_, s), _)| *s).chain(self.full.iter().filter(|(x, _)| *x == src).map(|(_, s)| *s)).chain(self.heads.keys().filter(|(x, _)| *x == src).map(|(_, s)| *s)).chain(self.refused.keys().filter(|(x, ..)| *x == src).map(|(_, s, _)| *s)).collect();
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
        self.by_blob.contains_key(&(*s, *b)) || self.read(|t| Ok(!t.records_with_row(s, PRESENT, &b.0, 1)?.is_empty()))
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

    /// Whether the source told it is full for S.
    pub fn full(&self, src: Source, s: &SyncId) -> bool {
        match src {
            Source::Record(rec) => self.read(|t| Ok(t.record_get_row(&rec, FULL, s, b"")?.is_some())),
            Source::Conn(_) => {
                self.stamps.read(&("f", src, s));
                self.full.contains(&(src, *s))
            }
        }
    }

    /// Whether the source refused some entry of S it was offered (spec/sync-streams.md §4
    /// Refused): status names it among those that do not take S.
    pub fn refusing(&self, src: Source, s: &SyncId) -> bool {
        match src {
            Source::Record(rec) => self.read(|t| Ok(!t.record_rows(&rec, REFUSED, s, b"", 1)?.is_empty())),
            Source::Conn(_) => {
                self.stamps.read(&("rs", src, s));
                self.refused.range((src, *s, BlobId([0; 32]))..=(src, *s, BlobId([0xff; 32]))).next().is_some()
            }
        }
    }

    pub fn refusal(&self, src: Source, s: &SyncId, b: &BlobId) -> Option<Refusal> {
        match src {
            Source::Record(rec) => self.read(|t| Ok(t.record_get_row(&rec, REFUSED, s, &b.0)?.and_then(|v| Refusal::decode(&v)))),
            Source::Conn(_) => {
                self.stamps.read(&("r", (src, *s, *b)));
                self.refused.get(&(src, *s, *b)).cloned()
            }
        }
    }
}
