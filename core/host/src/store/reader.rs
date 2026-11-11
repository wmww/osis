//! Node sync's entries in the hub's store (issues/net-one-peer.md step 4): for the sync IDs the
//! node reads (`set_read`) node sync writes the entries whose bytes it holds as this store's
//! entry rows, so the node's ciphertext is held once and logged once, in this store's node log.
//! Admission, caps, budgets and rates govern only unread sync IDs: node sync's writes pass none
//! of them. Its bytes-less knowledge (entries announced and not fetched, tombstones) stays in the
//! engine's store. A read sync ID is neither replicated nor dropped when hosting stops.

use super::{HostStore, Row, Tx, Write, Writes, be, corrupt, key, read_arr};
use osis_base::{BlobId, LabelId};
use osis_crypto::Signature;
use osis_proto::msg::WRAP_LEN;
use osis_label::{ClaimSet, Step};
use osis_proto::{EntryMeta, LogRecord, StoreError};
use std::collections::BTreeSet;

/// An entry row as node sync wrote it: wrap and stamp.
pub type ReaderRow = ([u8; WRAP_LEN], Option<Signature>);

const REMOVE: u8 = 0;
const FORGET: u8 = 1;

impl HostStore {
    /// The sync IDs node sync reads.
    pub fn set_read(&mut self, labels: BTreeSet<LabelId>) {
        self.read = labels;
    }

    /// Whether something other than node sync changed a sync ID it reads since the last ask
    /// (an upload, a delete, the sweep): node sync reads the node log past what it applied.
    pub fn take_moved(&mut self) -> bool {
        std::mem::take(&mut self.moved)
    }

    /// `take_moved` without taking it.
    pub fn moved(&self) -> bool {
        self.moved
    }

    /// Runs node sync's own change `f`, which leaves `moved` as it was.
    fn own<R>(&mut self, f: impl FnOnce(&mut HostStore) -> R) -> R {
        let moved = self.moved;
        let r = f(self);
        self.moved = moved;
        r
    }

    /// Whether `label` is node sync's: it reads it, or wrote entry rows under it.
    pub fn reads(&self, label: &LabelId) -> bool {
        self.read.contains(label) || self.get(&key(b'n', &[&label.0])).ok().flatten().is_some()
    }

    /// Node sync holds entry `blob` of `label` with its bytes (held in this store's blob area):
    /// its row, blob reference and node log `Added`, written into the open transaction. Whether
    /// anything changed (a row with the same wrap and stamp is left alone).
    pub fn reader_put(&mut self, label: &LabelId, blob: &BlobId, wrap: [u8; WRAP_LEN], stamp: Option<Signature>) -> Result<bool, StoreError> {
        self.own(|s| s.own_put(label, blob, wrap, stamp))
    }

    fn own_put(&mut self, label: &LabelId, blob: &BlobId, wrap: [u8; WRAP_LEN], stamp: Option<Signature>) -> Result<bool, StoreError> {
        let (meta, new) = self.meta_or_new(label)?;
        let held = self.row(label, blob)?;
        if held.as_ref().is_some_and(|r| r.meta.wrap == wrap && r.meta.stamp == stamp) {
            return Ok(false);
        }
        let mut tx = Tx { label: *label, before: (meta.entries, meta.bytes, new), meta, batch: Writes::default() };
        // the label is node sync's (`reader_labels`: the reconcile at open walks these)
        if self.get(&key(b'n', &[&label.0]))?.is_none() {
            tx.batch.put(key(b'n', &[&label.0]), Vec::new());
        }
        let seq = tx.append(&LogRecord::Added(*blob));
        let l = label.0;
        let row = match held {
            Some(old) => {
                if old.meta.stamp.is_none() && stamp.is_some() {
                    tx.meta.dep_n = tx.meta.dep_n.saturating_sub(1);
                    tx.meta.dep_bytes = tx.meta.dep_bytes.saturating_sub(old.meta.size);
                }
                Row { meta: EntryMeta { wrap, stamp, add_seq: seq, ..old.meta }, expiry: old.expiry }
            }
            None => {
                let bytes = self.db.get_mut().run(|t, _| t.read_blob(blob, 0, usize::MAX)).map_err(super::err)?.ok_or_else(|| corrupt("reader entry without its bytes"))?;
                let size = bytes.len() as u64;
                tx.meta.entries += 1;
                tx.meta.bytes = tx.meta.bytes.saturating_add(size);
                if stamp.is_none() {
                    tx.meta.dep_n += 1;
                    tx.meta.dep_bytes = tx.meta.dep_bytes.saturating_add(size);
                }
                let (refs, _) = self.refs(blob)?;
                tx.batch.put(key(b'R', &[&blob.0]), [&be(refs + 1)[..], osis_label::prefix_bytes(&bytes)].concat());
                // no expiry: node sync judges when an entry of a sync ID it reads expires (its
                // pass removes the row), the one expiry path there
                Row { meta: EntryMeta { wrap, stamp, size, add_seq: seq }, expiry: None }
            }
        };
        tx.batch.put(key(b'E', &[&l, &blob.0]), row.encode());
        tx.batch.log(Write::LogAdded(*label, *blob));
        self.finish(tx)?;
        self.origins.remove(&(*label, *blob));
        Ok(true)
    }

    /// The steps of `label` node sync judged from its `label.0` (`path`: genesis to the head
    /// it serves, with claim sets where recorded): those past this store's head on the path are
    /// written, the last the head, each logged as `push_step` does; none when this store's head
    /// is not on it (a peer's child step not recorded yet, another branch). No admission, cap or
    /// rate. Whether any was written.
    pub fn reader_steps(&mut self, label: &LabelId, path: &[(Step, Option<ClaimSet>)]) -> Result<bool, StoreError> {
        self.own(|s| s.own_steps(label, path))
    }

    fn own_steps(&mut self, label: &LabelId, path: &[(Step, Option<ClaimSet>)]) -> Result<bool, StoreError> {
        use osis_proto::LabelStore;
        let from = match self.head(label)? {
            None => 0,
            Some(h) => match path.iter().position(|(s, _)| s.id() == h) {
                Some(i) => i + 1,
                None => return Ok(false),
            },
        };
        let Some(todo) = path.get(from..).filter(|t| !t.is_empty()) else { return Ok(false) };
        if self.get(&key(b'n', &[&label.0]))?.is_none() {
            let mut w = Writes::default();
            w.put(key(b'n', &[&label.0]), Vec::new());
            self.write(w)?;
        }
        for (step, claims) in todo {
            self.put_step(label, step.clone(), claims.clone(), false)?;
        }
        Ok(true)
    }

    /// Node sync no longer holds entry `blob` of `label` with its bytes (`tombstone`: deleted,
    /// so the store refuses it for its tombstone time): its row goes as any removal. Whether
    /// there was one.
    pub fn reader_remove(&mut self, label: &LabelId, blob: &BlobId, tombstone: bool) -> Result<bool, StoreError> {
        self.own(|s| s.own_remove(label, blob, tombstone))
    }

    fn own_remove(&mut self, label: &LabelId, blob: &BlobId, tombstone: bool) -> Result<bool, StoreError> {
        let Some(row) = self.row(label, blob)? else { return Ok(false) };
        let mut tx = self.tx(label)?;
        let now = self.now();
        self.remove(&mut tx, blob, &row, now, tombstone)?;
        self.finish(tx)?;
        Ok(true)
    }

    /// The labels node sync wrote entry rows under (`reader_put`), after `after`, at most `max`.
    pub fn reader_labels(&self, after: Option<&LabelId>, max: usize) -> Result<Vec<LabelId>, StoreError> {
        let start = match after {
            Some(a) => key(b'n', &[&a.0, &[0]]),
            None => vec![b'n'],
        };
        let rows = self.scan(&start, Some(b"o"), max)?;
        rows.iter().map(|(k, _)| Ok(LabelId(read_arr(k, 1)?))).collect()
    }

    /// Node sync's entry rows of `label` after `after`, at most `max`: blob, wrap, stamp.
    pub fn reader_rows(&self, label: &LabelId, after: Option<&BlobId>, max: usize) -> Result<Vec<(BlobId, ReaderRow)>, StoreError> {
        use osis_proto::LabelStore;
        Ok(self.live_by_id(label, after, max)?.into_iter().map(|(b, m)| (b, (m.wrap, m.stamp))).collect())
    }

    /// Node sync forgot `label` (the group is gone here): every row of it, shredded, its node log
    /// events with no deletion event, into the open transaction.
    pub fn reader_forget(&mut self, label: &LabelId) -> Result<(), StoreError> {
        self.own(|s| s.own_forget(label))
    }

    fn own_forget(&mut self, label: &LabelId) -> Result<(), StoreError> {
        self.read.remove(label);
        let mut w = Writes::default();
        w.0.push(Write::Unmark(key(b'n', &[&label.0])));
        self.write(w)?;
        self.drop_label(label)
    }

    /// A removal of node sync's entry row, applied after the engine's store commits
    /// (`osis_engine`'s `Cipher::defer`, `finish`): `reader_remove`.
    pub fn removal(label: &LabelId, blob: &BlobId, tombstone: bool) -> Vec<u8> {
        [&[REMOVE][..], &label.0, &blob.0, &[u8::from(tombstone)]].concat()
    }

    /// Node sync forgetting `label`, applied after the engine's store commits: `reader_forget`.
    pub fn forgetting(label: &LabelId) -> Vec<u8> {
        [&[FORGET][..], &label.0].concat()
    }

    /// Applies a removal made by `removal` or `forgetting`.
    pub(super) fn finish_removal(&mut self, op: &[u8]) -> Result<(), StoreError> {
        match op.split_first() {
            Some((&REMOVE, rest)) if rest.len() == 16 + 32 + 1 => {
                let l = LabelId(read_arr(rest, 0)?);
                let b = BlobId(read_arr(rest, 16)?);
                self.reader_remove(&l, &b, rest.get(48) == Some(&1)).map(drop)
            }
            Some((&FORGET, rest)) if rest.len() == 16 => self.reader_forget(&LabelId(read_arr(rest, 0)?)),
            _ => Err(corrupt("deferred removal")),
        }
    }

    /// Node sync's entry `blob` of `label` as this store holds it: wrap and stamp.
    pub fn reader_entry(&self, label: &LabelId, blob: &BlobId) -> Result<Option<ReaderRow>, StoreError> {
        Ok(self.row(label, blob)?.map(|r| (r.meta.wrap, r.meta.stamp)))
    }

    /// Runs `f` on the node log (osis-store's `log_*`) in the open transaction: reads, or, inside
    /// an engine transaction (`osis_store::CipherHost::begin`), writes committed with it.
    pub fn node_log<R>(&mut self, f: impl FnOnce(&mut osis_store::Transaction<'_>) -> Result<R, osis_store::Error>) -> Result<R, osis_store::Error> {
        self.db.get_mut().run(|t, _| f(t))
    }
}
