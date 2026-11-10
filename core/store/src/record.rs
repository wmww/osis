//! Durable per-peer records (issues/net-reconnect.md, The record): one per peer node a node has
//! shared something with or whose known actor it has met, found by what the peer proves and the
//! pair key both hold, never by a node key.
//!
//! The rule: a record says only what need not be sent again, so losing one is a first contact.
//! A record's every row changes in the transaction that makes the change true: a cursor is stored
//! only by the transaction applying what it covers, a member and its index row go together.
//!
//! Rows, all catalog rows under `kind::RECORD`, keyed by a random ID so no row key holds r:
//! `m` meta (total bytes, LRU sequence); `c id` the record; `a actor id` the actor index;
//! `u seq id` least recently used first; `s id label` a member of S; `l label id` the member index;
//! `g id label` a stopped member's lag, beside S; `j label id` its index; `p id gen` one
//! generation of the peer's filter, as received (a whole one replaces every row before it).

use crate::codec::{R, W};
use crate::store::{Shred, Transaction, kind};
use crate::Error;
use osis_base::{LabelId, Tid};
use osis_base::format::TID_LEN;
use std::collections::BTreeSet;

/// Total bytes of durable records a node keeps (issues/net-reconnect.md, Picked values). Resource
/// bound: past it the least recently used record not in use goes, which is that record's loss, a
/// first contact. 0: every connection a first contact (correct, more bytes); infinity: disk.
pub const RECORD_BUDGET: u64 = 256 * 1024 * 1024;

/// A record's row ID: random, stays in this store.
pub type RecordId = [u8; 16];

/// Rows of a scan handled in one page.
const PAGE: usize = 256;

const META: &[u8] = &[kind::RECORD, b'm'];
const CORE: &[u8] = &[kind::RECORD, b'c'];
const ACTOR: &[u8] = &[kind::RECORD, b'a'];
const USED: &[u8] = &[kind::RECORD, b'u'];
const MEMBER: &[u8] = &[kind::RECORD, b's'];
const INDEX: &[u8] = &[kind::RECORD, b'l'];
const LAG: &[u8] = &[kind::RECORD, b'g'];
const LAG_INDEX: &[u8] = &[kind::RECORD, b'j'];
const FILTER: &[u8] = &[kind::RECORD, b'p'];

/// A record as held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub id: RecordId,
    /// The pair key: 32 bytes only the two nodes know.
    pub r: [u8; 32],
    /// The proven actors last seen. Only actors the session's proofs count (`Transaction::record_create`).
    pub actors: Vec<Tid>,
    /// Node log position below which nothing is pending for this peer.
    pub acked_pos: u64,
    /// Node log position up to which S was re-judged.
    pub judged_pos: u64,
    /// Opaque position in the peer's node log.
    pub cursor: Option<Vec<u8>>,
    /// This side's filter as sent to the peer (issues/net-shared-set.md, Messages).
    pub own: Filter,
    /// The peer's filter as stored: its rows are `Transaction::record_peer_filter`'s.
    pub peer: Filter,
    used: u64,
    member_bytes: u64,
}

/// One side's filter of a record: the last generation, its width, and the entries of its last
/// whole generation and of the additions since. For this side's own filter `generation` is the
/// last one sent and `acked` the last the peer acknowledged; for the peer's, both are the stored one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    pub generation: u64,
    pub acked: u64,
    pub f: u8,
    pub whole: u64,
    pub added: u64,
}

/// A member of S: the credential class this side opened it by and that credential's beacon
/// (none for an open by judgment), its end while being ended, and where it is in the stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub class: u8,
    pub beacon: Option<[u8; 32]>,
    /// Position at which it stops, while being ended.
    pub until: Option<u64>,
    pub at: At,
}

/// Where a member is in the record's stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum At {
    /// In the stream, at the record's cursor.
    Stream,
    /// Joining it from its own position (none: the start of the peer's log).
    Join(Option<Vec<u8>>),
}

fn meta_key() -> Vec<u8> {
    META.to_vec()
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
fn member_key(id: &RecordId, l: &LabelId) -> Vec<u8> {
    [MEMBER, id, &l.0].concat()
}
fn index_key(l: &LabelId, id: &RecordId) -> Vec<u8> {
    [INDEX, &l.0, id].concat()
}
fn lag_key(id: &RecordId, l: &LabelId) -> Vec<u8> {
    [LAG, id, &l.0].concat()
}
fn lag_index_key(l: &LabelId, id: &RecordId) -> Vec<u8> {
    [LAG_INDEX, &l.0, id].concat()
}

fn opt_bytes(w: &mut W, v: &Option<Vec<u8>>) {
    match v {
        Some(b) => {
            w.u8(1).bytes(b);
        }
        None => {
            w.u8(0);
        }
    }
}

fn read_opt_bytes(r: &mut R<'_>) -> Result<Option<Vec<u8>>, Error> {
    Ok(if r.u8()? == 1 { Some(r.bytes()?.to_vec()) } else { None })
}

impl Filter {
    fn encode(&self, w: &mut W) {
        w.u64(self.generation).u64(self.acked).u8(self.f).u64(self.whole).u64(self.added);
    }
    fn decode(r: &mut R<'_>) -> Result<Filter, Error> {
        Ok(Filter { generation: r.u64()?, acked: r.u64()?, f: r.u8()?, whole: r.u64()?, added: r.u64()? })
    }
}

impl Record {
    fn encode(&self) -> Vec<u8> {
        let mut w = W::new();
        w.raw(&self.r).u32(self.actors.len() as u32);
        for a in &self.actors {
            w.raw(a.as_bytes());
        }
        w.u64(self.acked_pos).u64(self.judged_pos).u64(self.used).u64(self.member_bytes);
        opt_bytes(&mut w, &self.cursor);
        self.own.encode(&mut w);
        self.peer.encode(&mut w);
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
        let (acked_pos, judged_pos, used, member_bytes) = (r.u64()?, r.u64()?, r.u64()?, r.u64()?);
        let cursor = read_opt_bytes(&mut r)?;
        let (own, peer) = (Filter::decode(&mut r)?, Filter::decode(&mut r)?);
        r.end()?;
        Ok(Record { id, r: key, actors, acked_pos, judged_pos, cursor, own, peer, used, member_bytes })
    }

    /// The bytes this record's rows take: what `RECORD_BUDGET` counts.
    fn cost(&self) -> u64 {
        let core = self.encode().len() + CORE.len() + 16;
        let actors = self.actors.len() * (ACTOR.len() + TID_LEN + 16);
        let used = USED.len() + 8 + 16;
        (core + actors + used) as u64 + self.member_bytes
    }
}

impl Member {
    fn encode(&self) -> Vec<u8> {
        let mut w = W::new();
        w.u8(self.class);
        match &self.beacon {
            Some(b) => {
                w.u8(1).raw(b);
            }
            None => {
                w.u8(0);
            }
        }
        match self.until {
            Some(p) => {
                w.u8(1).u64(p);
            }
            None => {
                w.u8(0);
            }
        }
        match &self.at {
            At::Stream => {
                w.u8(0);
            }
            At::Join(c) => {
                w.u8(1);
                opt_bytes(&mut w, c);
            }
        }
        w.take()
    }

    fn decode(b: &[u8]) -> Result<Member, Error> {
        let mut r = R::new(b);
        let class = r.u8()?;
        let beacon = if r.u8()? == 1 { Some(r.array()?) } else { None };
        let until = if r.u8()? == 1 { Some(r.u64()?) } else { None };
        let at = match r.u8()? {
            0 => At::Stream,
            1 => At::Join(read_opt_bytes(&mut r)?),
            _ => return Err(Error::Corrupt("peer record member")),
        };
        r.end()?;
        Ok(Member { class, beacon, until, at })
    }
}

/// A row's share of the budget.
fn row_bytes(key: &[u8], value: &[u8]) -> u64 {
    (key.len() + value.len()) as u64
}

fn tail_id(k: &[u8]) -> Result<RecordId, Error> {
    k.len().checked_sub(16).and_then(|at| k.get(at..)).and_then(|x| x.try_into().ok()).ok_or(Error::Corrupt("peer record key"))
}

fn tail_label(k: &[u8]) -> Result<LabelId, Error> {
    k.len().checked_sub(16).and_then(|at| k.get(at..)).and_then(|x| x.try_into().ok()).map(LabelId).ok_or(Error::Corrupt("peer record key"))
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
        self.cat_put_to(&meta_key(), W::new().u64(total).u64(seq).take(), Shred::No, false)
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
        let rec = Record { id, r, actors: actors.to_vec(), acked_pos: 0, judged_pos: 0, cursor: None, own: Filter::default(), peer: Filter::default(), used, member_bytes: 0 };
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
            let prefix = [ACTOR, a.as_bytes()].concat();
            let mut from = Vec::new();
            loop {
                let rows = self.cat_scan(&prefix, &from, PAGE)?;
                let n = rows.len();
                for (k, _) in rows {
                    let id = tail_id(&k)?;
                    ids.insert(id);
                    from = [id.as_slice(), &[0]].concat();
                }
                if n < PAGE {
                    break;
                }
            }
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

    /// `id` was used by a connection: it becomes most recently used, naming `actors` from now on.
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
        self.cat_put_to(&used_key(rec.used, id), Vec::new(), Shred::No, false)?;
        rec.actors = actors.to_vec();
        self.record_store(&rec, before)
    }

    /// Stores the peer's cursor. Called by the transaction that applies what it covers, so a
    /// cursor never runs ahead of its data (issues/net-reconnect.md, Restart and loss).
    pub fn record_set_cursor(&mut self, id: &RecordId, cursor: Option<Vec<u8>>) -> Result<(), Error> {
        let Some(mut rec) = self.record(id)? else { return Err(Error::Corrupt("peer record")) };
        let before = rec.cost();
        rec.cursor = cursor;
        self.record_store(&rec, before)
    }

    /// `acked_pos` rises to `pos` (a position below it leaves it: only re-marking lowers it).
    pub fn record_rise_acked(&mut self, id: &RecordId, pos: u64) -> Result<u64, Error> {
        let Some(mut rec) = self.record(id)? else { return Err(Error::Corrupt("peer record")) };
        if pos > rec.acked_pos {
            let before = rec.cost();
            rec.acked_pos = pos;
            self.record_store(&rec, before)?;
        }
        Ok(rec.acked_pos)
    }

    /// `judged_pos` rises to `pos`.
    pub fn record_rise_judged(&mut self, id: &RecordId, pos: u64) -> Result<(), Error> {
        let Some(mut rec) = self.record(id)? else { return Err(Error::Corrupt("peer record")) };
        if pos > rec.judged_pos {
            let before = rec.cost();
            rec.judged_pos = pos;
            self.record_store(&rec, before)?;
        }
        Ok(())
    }

    /// Opens `l` in S, or replaces its member row. Row and index in this one transaction.
    pub fn record_open(&mut self, id: &RecordId, l: LabelId, m: &Member) -> Result<(), Error> {
        let Some(mut rec) = self.record(id)? else { return Err(Error::Corrupt("peer record")) };
        let before = rec.cost();
        let key = member_key(id, &l);
        let index = index_key(&l, id);
        if let Some(old) = self.cat_get(&key)? {
            rec.member_bytes = rec.member_bytes.saturating_sub(row_bytes(&key, &old) + index.len() as u64);
        }
        let v = m.encode();
        rec.member_bytes += row_bytes(&key, &v) + index.len() as u64;
        self.cat_put_to(&key, v, Shred::No, false)?;
        self.cat_put_to(&index, Vec::new(), Shred::No, false)?;
        self.record_store(&rec, before)
    }

    /// S of `id`, by sync ID.
    pub fn record_members(&mut self, id: &RecordId) -> Result<Vec<(LabelId, Member)>, Error> {
        let prefix = [MEMBER, id].concat();
        let mut out = Vec::new();
        let mut from = Vec::new();
        loop {
            let rows = self.cat_scan(&prefix, &from, PAGE)?;
            let n = rows.len();
            for (k, v) in rows {
                let l = tail_label(&k)?;
                from = [l.0.as_slice(), &[0]].concat();
                out.push((l, Member::decode(&v)?));
            }
            if n < PAGE {
                return Ok(out);
            }
        }
    }

    /// Removes `l` from S, with its index row. No re-marking: the node stopped holding it, or it
    /// went with the record.
    fn record_drop_member(&mut self, rec: &mut Record, l: &LabelId) -> Result<bool, Error> {
        let key = member_key(&rec.id, l);
        let index = index_key(l, &rec.id);
        let Some(old) = self.cat_get(&key)? else { return Ok(false) };
        rec.member_bytes = rec.member_bytes.saturating_sub(row_bytes(&key, &old) + index.len() as u64);
        self.cat_remove(&key, Shred::No)?;
        self.cat_remove(&index, Shred::No)?;
        Ok(true)
    }

    /// A member closes for this record (a `Lost` sent or received, a digest difference): `l`
    /// leaves S and `acked_pos` becomes `min(self, changed_at - 1)`, so `l` is pending again for
    /// this record alone (issues/net-shared-set.md, Testing), whether or not it was a member: a
    /// digest difference re-marks on both sides. `stop`, a `Lost`'s cursor, is kept for the
    /// rejoin unless an older one is. Returns `acked_pos`.
    pub fn record_close(&mut self, id: &RecordId, l: &LabelId, changed_at: u64, stop: Option<Vec<u8>>) -> Result<u64, Error> {
        let Some(mut rec) = self.record(id)? else { return Err(Error::Corrupt("peer record")) };
        let before = rec.cost();
        self.record_drop_member(&mut rec, l)?;
        if let Some(c) = stop
            && self.cat_get(&lag_key(id, l))?.is_none()
        {
            rec.member_bytes += self.record_put_lag(id, l, c)?;
        }
        rec.acked_pos = rec.acked_pos.min(changed_at.saturating_sub(1));
        let acked = rec.acked_pos;
        self.record_store(&rec, before)?;
        Ok(acked)
    }

    /// Member `l` moved in the stream (`At`): its row changes if it is still a member, else
    /// nothing (a member closed since stays closed).
    pub fn record_member_at(&mut self, id: &RecordId, l: LabelId, at: At) -> Result<(), Error> {
        let Some(old) = self.cat_get(&member_key(id, &l))? else { return Ok(()) };
        let m = Member { at, ..Member::decode(&old)? };
        self.record_open(id, l, &m)
    }

    /// A member only one side of the record held (a digest difference, issues/net-reconnect.md
    /// Agreement): out of S with no lag kept, so its rejoin is a listing, and pending again as
    /// `record_close` re-marks. Returns `acked_pos`.
    pub fn record_drop(&mut self, id: &RecordId, l: &LabelId, changed_at: u64) -> Result<u64, Error> {
        let Some(mut rec) = self.record(id)? else { return Err(Error::Corrupt("peer record")) };
        let before = rec.cost();
        self.record_drop_member(&mut rec, l)?;
        rec.member_bytes = rec.member_bytes.saturating_sub(self.record_drop_lag(id, l)?);
        rec.acked_pos = rec.acked_pos.min(changed_at.saturating_sub(1));
        let acked = rec.acked_pos;
        self.record_store(&rec, before)?;
        Ok(acked)
    }

    /// Everything is pending again for this record (the session proved other actors than the
    /// record names: issues/net-reconnect.md, What a reconnect sends).
    pub fn record_pending_all(&mut self, id: &RecordId) -> Result<(), Error> {
        let Some(mut rec) = self.record(id)? else { return Err(Error::Corrupt("peer record")) };
        let before = rec.cost();
        rec.acked_pos = 0;
        self.record_store(&rec, before)
    }

    /// This side's filter as sent and acknowledged.
    pub fn record_set_own(&mut self, id: &RecordId, own: Filter) -> Result<(), Error> {
        let Some(mut rec) = self.record(id)? else { return Err(Error::Corrupt("peer record")) };
        let before = rec.cost();
        rec.own = own;
        self.record_store(&rec, before)
    }

    /// A generation of the peer's filter arrived whole: `rows` its encoded values (a whole one
    /// replaces every stored row; additions add one). `peer` the filter it makes.
    pub fn record_put_peer_filter(&mut self, id: &RecordId, whole: bool, peer: Filter, row: Vec<u8>) -> Result<(), Error> {
        let Some(mut rec) = self.record(id)? else { return Err(Error::Corrupt("peer record")) };
        let before = rec.cost();
        if whole {
            for (k, v) in self.record_filter_rows(id)? {
                rec.member_bytes = rec.member_bytes.saturating_sub(row_bytes(&k, &v));
                self.cat_remove(&k, Shred::No)?;
            }
        }
        let key = [FILTER, id, &peer.generation.to_be_bytes()].concat();
        rec.member_bytes += row_bytes(&key, &row);
        self.cat_put_to(&key, row, Shred::No, false)?;
        rec.peer = peer;
        self.record_store(&rec, before)
    }

    /// The peer's stored filter, one row per generation since its last whole one, in order.
    pub fn record_peer_filter(&mut self, id: &RecordId) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self.record_filter_rows(id)?.into_iter().map(|(_, v)| v).collect())
    }

    fn record_filter_rows(&mut self, id: &RecordId) -> Result<Vec<crate::KeyValue>, Error> {
        let prefix = [FILTER, id].concat();
        let mut out: Vec<crate::KeyValue> = Vec::new();
        let mut from = Vec::new();
        loop {
            let rows = self.cat_scan(&prefix, &from, PAGE)?;
            let n = rows.len();
            for (k, v) in rows {
                from = [k.get(prefix.len()..).unwrap_or_default(), &[0]].concat();
                out.push((k, v));
            }
            if n < PAGE {
                return Ok(out);
            }
        }
    }

    /// The lag kept for `l`'s rejoin.
    pub fn record_lag(&mut self, id: &RecordId, l: &LabelId) -> Result<Option<Vec<u8>>, Error> {
        self.cat_get(&lag_key(id, l))
    }

    fn record_put_lag(&mut self, id: &RecordId, l: &LabelId, c: Vec<u8>) -> Result<u64, Error> {
        let (key, index) = (lag_key(id, l), lag_index_key(l, id));
        let cost = row_bytes(&key, &c) + index.len() as u64;
        self.cat_put_to(&key, c, Shred::No, false)?;
        self.cat_put_to(&index, Vec::new(), Shred::No, false)?;
        Ok(cost)
    }

    /// Removes the lag of `l`, if any; the bytes it freed.
    fn record_drop_lag(&mut self, id: &RecordId, l: &LabelId) -> Result<u64, Error> {
        let (key, index) = (lag_key(id, l), lag_index_key(l, id));
        let Some(v) = self.cat_get(&key)? else { return Ok(0) };
        self.cat_remove(&key, Shred::No)?;
        self.cat_remove(&index, Shred::No)?;
        Ok(row_bytes(&key, &v) + index.len() as u64)
    }

    /// `l` rejoined: its lag is spent.
    pub fn record_take_lag(&mut self, id: &RecordId, l: &LabelId) -> Result<Option<Vec<u8>>, Error> {
        let Some(v) = self.cat_get(&lag_key(id, l))? else { return Ok(None) };
        let Some(mut rec) = self.record(id)? else { return Err(Error::Corrupt("peer record")) };
        let before = rec.cost();
        rec.member_bytes = rec.member_bytes.saturating_sub(self.record_drop_lag(id, l)?);
        self.record_store(&rec, before)?;
        Ok(Some(v))
    }

    /// The node stopped holding `l`: out of every record's S, every lag of it gone, in this one
    /// transaction (issues/net-reconnect.md, Changes). O(records holding it).
    pub(crate) fn records_forget_label(&mut self, l: &LabelId) -> Result<(), Error> {
        for (prefix, is_lag) in [(INDEX, false), (LAG_INDEX, true)] {
            let prefix = [prefix, &l.0].concat();
            loop {
                let rows = self.cat_scan(&prefix, b"", PAGE)?;
                let n = rows.len();
                for (k, _) in rows {
                    let id = tail_id(&k)?;
                    let Some(mut rec) = self.record(&id)? else {
                        self.cat_remove(&k, Shred::No)?;
                        continue;
                    };
                    let before = rec.cost();
                    if is_lag {
                        rec.member_bytes = rec.member_bytes.saturating_sub(self.record_drop_lag(&id, l)?);
                    } else {
                        self.record_drop_member(&mut rec, l)?;
                    }
                    self.record_store(&rec, before)?;
                }
                if n < PAGE {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Removes a record and every row of it.
    fn record_delete(&mut self, rec: Record) -> Result<(), Error> {
        let mut rec = rec;
        let before = rec.cost();
        for (l, _) in self.record_members(&rec.id)? {
            self.record_drop_member(&mut rec, &l)?;
        }
        let prefix = [LAG, &rec.id].concat();
        loop {
            let rows = self.cat_scan(&prefix, b"", PAGE)?;
            let n = rows.len();
            for (k, _) in rows {
                let l = tail_label(&k)?;
                self.record_drop_lag(&rec.id, &l)?;
            }
            if n < PAGE {
                break;
            }
        }
        for (k, _) in self.record_filter_rows(&rec.id)? {
            self.cat_remove(&k, Shred::No)?;
        }
        for a in &rec.actors {
            self.cat_remove(&actor_key(a, &rec.id), Shred::No)?;
        }
        self.cat_remove(&used_key(rec.used, &rec.id), Shred::No)?;
        self.cat_remove(&core_key(&rec.id), Shred::Yes)?;
        let (total, seq) = self.record_meta()?;
        self.record_put_meta(total.saturating_sub(before), seq)
    }

    /// Bytes of records kept (what `RECORD_BUDGET` bounds).
    pub fn records_total(&mut self) -> Result<u64, Error> {
        Ok(self.record_meta()?.0)
    }

    /// Drops least recently used records not in `in_use` until the total fits `budget`. If
    /// every record left is in use the total stays over: a record in use is not dropped from
    /// under its connection. Returns how many went. O(records dropped and skipped).
    pub fn records_evict(&mut self, budget: u64, in_use: &BTreeSet<RecordId>) -> Result<usize, Error> {
        let mut evicted = 0;
        let mut from: Vec<u8> = Vec::new();
        while self.record_meta()?.0 > budget {
            let rows = self.cat_scan(USED, &from, PAGE)?;
            let n = rows.len();
            let mut any = false;
            for (k, _) in rows {
                let (seq, id) = (k.get(2..10).and_then(|x| x.try_into().ok()).map(u64::from_be_bytes).ok_or(Error::Corrupt("peer record key"))?, tail_id(&k)?);
                from = [&seq.to_be_bytes()[..], &id, &[0]].concat();
                if in_use.contains(&id) {
                    continue;
                }
                any = true;
                if let Some(rec) = self.record(&id)? {
                    self.record_delete(rec)?;
                    evicted += 1;
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
