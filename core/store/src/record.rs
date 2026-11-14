//! Durable per-peer records (spec/sync-opens.md §3): one per peer node a node has shared
//! something with or whose known actor it has met, found by what the peer proves and the pair key
//! both hold, never by a node key.
//!
//! The rule: a record says only what need not be sent again, so losing one is a first contact.
//! The record itself is its pair key, the actors it names and its place in the LRU order; all
//! else is rows the modules of osis-sync keep in it (`record_put_row`), each module under its
//! own tags and each row written by the transaction that makes it true. A record and every row
//! of it go together (`records_evict`), and a sync ID leaving the node leaves every record
//! (`records_forget_label`).
//!
//! Rows, all catalog rows under `kind::RECORD`, keyed by a random ID so no row key holds r:
//! `m` meta (total bytes, LRU sequence); `c id` the record; `a actor id` the actor index;
//! `u seq id` least recently used first; `x id tag label key` a module's row about a sync ID
//! (a record-wide row names `NO_LABEL`); `X label tag key id` its index: what leaves with the
//! sync ID, and which records hold a row (`records_with_row`).

use crate::codec::{R, W};
use crate::store::{PAGE, Shred, Transaction, kind, tail};
use crate::Error;
use osis_base::{SyncId, Tid};
use osis_base::format::TID_LEN;
use std::collections::BTreeSet;

/// Total bytes of durable records a node keeps (spec/sync-opens.md §3). Resource bound: past it
/// the least recently used record not in use goes, which is that record's loss, a first contact.
/// 0: every connection a first contact (correct, more bytes); infinity: disk.
pub const RECORD_BUDGET: u64 = 256 * 1024 * 1024;

/// A record's row ID: random, stays in this store.
pub type RecordId = [u8; 16];

/// The label of a record-wide row (one about no sync ID): no sync ID is all zeros.
pub const NO_LABEL: SyncId = SyncId([0; 16]);

const META: &[u8] = &[kind::RECORD, b'm'];
const CORE: &[u8] = &[kind::RECORD, b'c'];
const ACTOR: &[u8] = &[kind::RECORD, b'a'];
const USED: &[u8] = &[kind::RECORD, b'u'];
const ROW: &[u8] = &[kind::RECORD, b'x'];
const ROW_INDEX: &[u8] = &[kind::RECORD, b'X'];

/// A module row of a record: its sync ID, key and value.
pub type RecordRow = (SyncId, Vec<u8>, Vec<u8>);

/// A record as held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub id: RecordId,
    /// The pair key: 32 bytes only the two nodes know.
    pub r: [u8; 32],
    /// The proven actors last seen. Only actors the session's proofs count (`Transaction::record_create`).
    pub actors: Vec<Tid>,
    /// Its place in the LRU order: higher is more recent.
    pub used: u64,
    /// Bytes of its module rows.
    row_bytes: u64,
}

fn core_key(id: &RecordId) -> Vec<u8> {
    [CORE, id].concat()
}
fn actor_key(a: &Tid, id: &RecordId) -> Vec<u8> {
    [ACTOR, a.as_bytes(), id].concat()
}
fn used_key(seq: u64, id: &RecordId) -> Vec<u8> {
    [USED, &seq.to_be_bytes(), id].concat()
}
fn row_key(id: &RecordId, tag: u8, l: &SyncId, key: &[u8]) -> Vec<u8> {
    [ROW, id, &[tag], &l.0, key].concat()
}
fn row_index_key(l: &SyncId, tag: u8, key: &[u8], id: &RecordId) -> Vec<u8> {
    [ROW_INDEX, &l.0, &[tag], key, id].concat()
}

/// A row key's parts after `ROW id`: its tag, label and key.
fn row_parts(rest: &[u8]) -> Result<(u8, SyncId, &[u8]), Error> {
    let (tag, rest) = rest.split_first().ok_or(Error::Corrupt("peer record row"))?;
    let (l, key) = rest.split_first_chunk::<16>().ok_or(Error::Corrupt("peer record row"))?;
    Ok((*tag, SyncId(*l), key))
}

impl Record {
    fn encode(&self) -> Vec<u8> {
        let mut w = W::new();
        w.raw(&self.r).u32(self.actors.len() as u32);
        for a in &self.actors {
            w.raw(a.as_bytes());
        }
        w.u64(self.used).u64(self.row_bytes);
        w.take()
    }

    fn decode(id: RecordId, b: &[u8]) -> Result<Record, Error> {
        let mut r = R::new(b);
        let key: [u8; 32] = r.array()?;
        let n = r.u32()? as usize;
        let mut actors = Vec::with_capacity(n.min(b.len() / TID_LEN));
        for _ in 0..n {
            actors.push(Tid::from_bytes(r.array()?));
        }
        let (used, row_bytes) = (r.u64()?, r.u64()?);
        r.end()?;
        Ok(Record { id, r: key, actors, used, row_bytes })
    }

    /// The bytes this record's rows take: what `RECORD_BUDGET` counts.
    fn cost(&self) -> u64 {
        let core = self.encode().len() + CORE.len() + 16;
        let actors = self.actors.len() * (ACTOR.len() + TID_LEN + 16);
        let used = USED.len() + 8 + 16;
        (core + actors + used) as u64 + self.row_bytes
    }
}

/// A row's share of the budget, its index row included.
fn row_bytes(key: &[u8], value: &[u8]) -> u64 {
    (2 * key.len() + value.len()) as u64
}

impl Transaction<'_> {
    fn record_meta(&mut self) -> Result<(u64, u64), Error> {
        let Some(v) = self.cat_get(META)? else { return Ok((0, 0)) };
        let mut r = R::new(&v);
        let m = (r.u64()?, r.u64()?);
        r.end()?;
        Ok(m)
    }

    fn record_put_meta(&mut self, total: u64, seq: u64) -> Result<(), Error> {
        self.cat_put_to(META, W::new().u64(total).u64(seq).take(), Shred::No, false)
    }

    /// Writes `rec` and its total, given what it cost before (0: new).
    fn record_store(&mut self, rec: &Record, before: u64) -> Result<(), Error> {
        self.cat_put_to(&core_key(&rec.id), rec.encode(), Shred::Yes, false)?;
        let (total, seq) = self.record_meta()?;
        self.record_put_meta(total.saturating_sub(before).saturating_add(rec.cost()), seq)
    }

    fn record_next_used(&mut self) -> Result<u64, Error> {
        let (total, seq) = self.record_meta()?;
        let seq = seq + 1;
        self.record_put_meta(total, seq)?;
        Ok(seq)
    }

    /// The record `id`.
    pub fn record(&mut self, id: &RecordId) -> Result<Option<Record>, Error> {
        self.cat_get(&core_key(id))?.map(|b| Record::decode(*id, &b)).transpose()
    }

    /// A new record with pair key `r` for `actors`, the most recently used. `actors` must be
    /// actors the session's proofs count: until accounts sign, key actors alone (`Proven`), never
    /// a chain-proved account, so a record cannot let one resume anything.
    pub fn record_create(&mut self, r: [u8; 32], actors: &[Tid]) -> Result<RecordId, Error> {
        let mut id = [0u8; 16];
        self.rng().fill_bytes(&mut id);
        let used = self.record_next_used()?;
        let rec = Record { id, r, actors: actors.to_vec(), used, row_bytes: 0 };
        for a in actors {
            self.cat_put_to(&actor_key(a, &id), Vec::new(), Shred::No, false)?;
        }
        self.cat_put_to(&used_key(used, &id), Vec::new(), Shred::No, false)?;
        self.record_store(&rec, 0)?;
        Ok(id)
    }

    /// Records naming any of `actors`, most recently used first. O(records naming them).
    pub fn records_of_actors(&mut self, actors: &[Tid]) -> Result<Vec<Record>, Error> {
        let mut ids = BTreeSet::new();
        for a in actors {
            self.cat_each(&[ACTOR, a.as_bytes()].concat(), |_, k, _| {
                ids.insert(tail(&k)?);
                Ok(())
            })?;
        }
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(rec) = self.record(&id)? {
                out.push(rec);
            }
        }
        out.sort_by_key(|r| std::cmp::Reverse(r.used));
        Ok(out)
    }

    /// `id` was taken by a connection: it becomes most recently used, naming `actors` from now on.
    pub fn record_used(&mut self, id: &RecordId, actors: &[Tid]) -> Result<(), Error> {
        let Some(mut rec) = self.record(id)? else { return Err(Error::Corrupt("peer record")) };
        let before = rec.cost();
        for a in &rec.actors {
            self.cat_remove(&actor_key(a, id), Shred::No)?;
        }
        for a in actors {
            self.cat_put_to(&actor_key(a, id), Vec::new(), Shred::No, false)?;
        }
        self.cat_remove(&used_key(rec.used, id), Shred::No)?;
        rec.used = self.record_next_used()?;
        rec.actors = actors.to_vec();
        self.cat_put_to(&used_key(rec.used, id), Vec::new(), Shred::No, false)?;
        self.record_store(&rec, before)
    }

    /// Module `tag`'s row `key` about sync ID `l` (`NO_LABEL`: about the record) in record `id`
    /// (one owner per tag), with its index row, in this transaction; counted in the record's
    /// bytes, gone with the record or with `l`. A record that is gone takes nothing: what it
    /// would say of the peer went with it.
    pub fn record_put_row(&mut self, id: &RecordId, tag: u8, l: &SyncId, key: &[u8], val: Vec<u8>) -> Result<(), Error> {
        let Some(mut rec) = self.record(id)? else { return Ok(()) };
        let before = rec.cost();
        let k = row_key(id, tag, l, key);
        if let Some(old) = self.cat_get(&k)? {
            rec.row_bytes = rec.row_bytes.saturating_sub(row_bytes(&k, &old));
        }
        rec.row_bytes += row_bytes(&k, &val);
        self.cat_put_to(&k, val, Shred::Yes, false)?;
        self.cat_put_to(&row_index_key(l, tag, key, id), Vec::new(), Shred::No, false)?;
        self.record_store(&rec, before)
    }

    pub fn record_get_row(&mut self, id: &RecordId, tag: u8, l: &SyncId, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.cat_get(&row_key(id, tag, l, key))
    }

    /// Removes module `tag`'s row `key` about `l` in record `id`; whether it was there.
    pub fn record_remove_row(&mut self, id: &RecordId, tag: u8, l: &SyncId, key: &[u8]) -> Result<bool, Error> {
        let k = row_key(id, tag, l, key);
        let Some(old) = self.cat_get(&k)? else { return Ok(false) };
        self.cat_remove(&k, Shred::Yes)?;
        self.cat_remove(&row_index_key(l, tag, key, id), Shred::No)?;
        if let Some(mut rec) = self.record(id)? {
            let before = rec.cost();
            rec.row_bytes = rec.row_bytes.saturating_sub(row_bytes(&k, &old));
            self.record_store(&rec, before)?;
        }
        Ok(true)
    }

    /// Module `tag`'s rows about `l` in record `id`, by key, from `from` on, at most `limit`.
    /// Costs what it returns.
    pub fn record_rows(&mut self, id: &RecordId, tag: u8, l: &SyncId, from: &[u8], limit: usize) -> Result<Vec<crate::KeyValue>, Error> {
        let prefix = [ROW, id, &[tag], &l.0].concat();
        Ok(self.cat_scan(&prefix, from, limit)?.into_iter().map(|(k, v)| (k.get(prefix.len()..).unwrap_or_default().to_vec(), v)).collect())
    }

    /// Module `tag`'s rows in record `id` about every sync ID, by sync ID and key. Costs what it
    /// returns.
    pub fn record_tag_rows(&mut self, id: &RecordId, tag: u8) -> Result<Vec<RecordRow>, Error> {
        let prefix = [ROW, id, &[tag]].concat();
        let mut out = Vec::new();
        self.cat_each(&prefix, |_, k, v| {
            let (_, l, key) = row_parts(k.get(ROW.len() + 16..).unwrap_or_default())?;
            out.push((l, key.to_vec(), v));
            Ok(())
        })?;
        Ok(out)
    }

    /// The records holding module `tag`'s row `key` about `l`, at most `limit`. Costs what it
    /// returns (the index is by sync ID, tag and key).
    pub fn records_with_row(&mut self, l: &SyncId, tag: u8, key: &[u8], limit: usize) -> Result<Vec<RecordId>, Error> {
        let prefix = [ROW_INDEX, &l.0, &[tag], key].concat();
        let mut out = Vec::new();
        let mut from = Vec::new();
        // a longer key under this prefix is another row: only exact keys count
        loop {
            let rows = self.cat_scan(&prefix, &from, PAGE)?;
            let n = rows.len();
            for (k, _) in rows {
                let rest = k.get(prefix.len()..).unwrap_or_default();
                from = [rest, &[0]].concat();
                if let Ok(id) = <RecordId>::try_from(rest) {
                    out.push(id);
                    if out.len() >= limit {
                        return Ok(out);
                    }
                }
            }
            if n < PAGE {
                return Ok(out);
            }
        }
    }

    /// The node stopped holding `l`: every module row about it leaves every record, in this one
    /// transaction. O(rows about it).
    pub(crate) fn records_forget_label(&mut self, l: &SyncId) -> Result<(), Error> {
        let prefix = [ROW_INDEX, &l.0].concat();
        self.cat_each(&prefix, |t, k, _| {
            let rest = k.get(prefix.len()..).ok_or(Error::Corrupt("peer record row index"))?;
            let (tag, rest) = rest.split_first().ok_or(Error::Corrupt("peer record row index"))?;
            let (key, id) = rest.split_last_chunk::<16>().ok_or(Error::Corrupt("peer record row index"))?;
            t.record_remove_row(id, *tag, l, key).map(drop)
        })
    }

    /// Removes a record and every row of it.
    fn record_delete(&mut self, rec: Record) -> Result<(), Error> {
        let before = rec.cost();
        let id = rec.id;
        self.cat_each(&[ROW, &id].concat(), |t, k, _| {
            let (tag, l, key) = row_parts(k.get(ROW.len() + 16..).unwrap_or_default())?;
            t.cat_remove(&row_index_key(&l, tag, key, &id), Shred::No)?;
            t.cat_remove(&k, Shred::Yes).map(drop)
        })?;
        for a in &rec.actors {
            self.cat_remove(&actor_key(a, &id), Shred::No)?;
        }
        self.cat_remove(&used_key(rec.used, &id), Shred::No)?;
        self.cat_remove(&core_key(&id), Shred::Yes)?;
        let (total, seq) = self.record_meta()?;
        self.record_put_meta(total.saturating_sub(before), seq)
    }

    /// Bytes of records kept (what `RECORD_BUDGET` bounds).
    pub fn records_total(&mut self) -> Result<u64, Error> {
        Ok(self.record_meta()?.0)
    }

    /// Drops least recently used records not in `in_use` until the total fits `budget`, each with
    /// every row of it. If every record left is in use the total stays over: a record in use is
    /// not dropped from under its connection. Returns the records that went (what their peers
    /// brought and that was charged to them goes too: the caller tells the owner, osis-sync's
    /// store `gone`). O(records dropped and skipped).
    pub fn records_evict(&mut self, budget: u64, in_use: &BTreeSet<RecordId>) -> Result<Vec<RecordId>, Error> {
        let mut evicted = Vec::new();
        let mut from: Vec<u8> = Vec::new();
        while self.record_meta()?.0 > budget {
            let rows = self.cat_scan(USED, &from, PAGE)?;
            let n = rows.len();
            let mut any = false;
            for (k, _) in rows {
                let (seq, id) = (k.get(2..10).and_then(|x| x.try_into().ok()).map(u64::from_be_bytes).ok_or(Error::Corrupt("peer record key"))?, tail(&k)?);
                from = [&seq.to_be_bytes()[..], &id, &[0]].concat();
                if in_use.contains(&id) {
                    continue;
                }
                any = true;
                if let Some(rec) = self.record(&id)? {
                    self.record_delete(rec)?;
                    evicted.push(id);
                }
                if self.record_meta()?.0 <= budget {
                    return Ok(evicted);
                }
            }
            if !any && n < PAGE {
                break;
            }
        }
        Ok(evicted)
    }
}
