//! Pair keys and per-peer records on connections (issues/net-reconnect.md, Resume).
//!
//! What proves a record: the session's own proven key actors, those this node knows now (`Judge`
//! over the rosters it holds): the same set that gates the proof answer (spec/sync.md §10). Only
//! key actors proved by their own key count: a chain-proved or account-key-proved account proves
//! no removal it omits, so it finds no record and makes none until accounts sign
//! (issues/net-shared-set.md step 10; `Proven::accounts`). A record is honoured only while a
//! proven actor of this session is one of its actors and known here now, so a node removed from
//! every roster held here cannot use one. The tag binds r to this connection: its challenges and
//! the listener's static key, so a node between two holders of r cannot pass one's tag to the
//! other (the same reason the proof digest names the listener).
//!
//! r goes only inside the connection's own messages: the nonces of `Resume` and `Resumed`.

use super::proofs::Proven;
use super::{Action, ConnId, SyncEngine};
use crate::error::Result;
use osis_base::Tid;
use osis_crypto::kdf::{connection_order, pair_key, resume_tag, resumed_tag};
use crate::engine::Engine;
use osis_proto::{ClientInput, Command, MAX_RESUME_TAGS};
use osis_store::{RECORD_BUDGET, Record, RecordId};
use std::collections::{BTreeMap, BTreeSet};

/// A connection's working state of its record (issues/net-shared-set.md, Testing): the peer's last
/// ack and `tested_pos`, which last the connection; `acked_pos` is durable, in the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnRecord {
    pub id: RecordId,
    /// The peer's last acknowledged position on this connection.
    pub ack: u64,
    pub tested: u64,
    /// Offers from a test not answered yet.
    pub offers_unanswered: u32,
}

impl ConnRecord {
    pub fn new(id: RecordId, acked_pos: u64) -> ConnRecord {
        ConnRecord { id, ack: acked_pos, tested: acked_pos, offers_unanswered: 0 }
    }

    /// What `acked_pos` may rise to now: `min(ack, tested)`, or nothing with an Offer unanswered.
    pub fn rise_to(&self) -> Option<u64> {
        (self.offers_unanswered == 0).then_some(self.ack.min(self.tested))
    }

    /// A member closed for this record (issues/net-shared-set.md, Re-marking): `tested` goes
    /// below it as `acked_pos` does in `Transaction::record_close`. The peer's ack stands.
    pub fn remark(&mut self, changed_at: u64) {
        self.tested = self.tested.min(changed_at.saturating_sub(1));
    }
}

struct ResumeSent {
    nonce: [u8; 32],
    actors: Vec<Tid>,
    /// The answer tag of each record listed.
    expect: Vec<([u8; 32], RecordId)>,
}

/// Which record each connection has, and the Resumes waiting for their answer.
#[derive(Default)]
pub(crate) struct Records {
    bound: BTreeMap<ConnId, ConnRecord>,
    live: BTreeMap<RecordId, ConnId>,
    sent: BTreeMap<ConnId, ResumeSent>,
    /// Each connection's place among its record's (`connection_order`), and its shared set.
    order: BTreeMap<ConnId, [u8; 32]>,
    pub(super) shared: BTreeMap<ConnId, super::shared::Shared>,
    /// Records read for a Resume or its answer (tests count the work).
    pub lookups: u64,
}

impl Records {
    pub(crate) fn live(&self) -> BTreeSet<RecordId> {
        self.live.keys().copied().collect()
    }

    /// `conn` keeps its shared set but no longer its record: its actors are unknown here now.
    pub(crate) fn unbind(&mut self, conn: ConnId) {
        if let Some(b) = self.bound.remove(&conn)
            && self.live.get(&b.id) == Some(&conn)
        {
            self.live.remove(&b.id);
        }
    }

    /// `conn` ended.
    pub(crate) fn conn_gone(&mut self, conn: ConnId) {
        self.sent.remove(&conn);
        self.order.remove(&conn);
        self.shared.remove(&conn);
        if let Some(b) = self.bound.remove(&conn)
            && self.live.get(&b.id) == Some(&conn)
        {
            self.live.remove(&b.id);
        }
    }
}

/// The proven actors that count for a record now: key actors known here. Never an account
/// (`Proven::accounts`): a record cannot let a chain-proved account resume anything.
pub(super) fn counted_actors(engine: &Engine, proven: &Proven) -> Vec<Tid> {
    proven.key_actors.iter().copied().filter(|a| engine.core.judge([*a]).known()).collect()
}

/// The listener's part of a Resume: the nonce it answers and the tag of a record it holds, with
/// the record used or made, durably before the answer goes.
pub(super) fn answer_resume(engine: &mut Engine, actors: &[Tid], in_use: &BTreeSet<RecordId>, nonce: &[u8; 32], tags: &[[u8; 32]], (dialer, listener, key): (&[u8; 32], &[u8; 32], &[u8; 32])) -> Result<(osis_proto::ResumeAnswer, RecordId, u64)> {
    engine.run(|tx| {
        let records = tx.txn.records_of_actors(actors)?;
        let looked = records.len() as u64;
        let by_tag: BTreeMap<[u8; 32], &Record> = records.iter().map(|r| (resume_tag(&r.r, key, dialer, listener), r)).collect();
        let hit = tags.iter().find_map(|t| by_tag.get(t).copied());
        let mine = tx.txn.random32();
        if let Some(r) = hit {
            tx.txn.record_used(&r.id, actors)?;
            return Ok(((mine, Some(resumed_tag(&r.r, key, dialer, listener))), r.id, looked));
        }
        let r = pair_key(nonce, &mine);
        let id = tx.txn.record_create(*r.expose(), actors)?;
        let mut keep = in_use.clone();
        keep.insert(id);
        tx.txn.records_evict(RECORD_BUDGET, &keep)?;
        Ok(((mine, None), id, looked))
    })
}

impl SyncEngine {
    /// The peer's proofs are in: a dialer that met a known actor lists its records for it.
    pub(super) fn send_resume(&mut self, conn: ConnId, out: &mut Vec<Action>) -> Result<()> {
        let Some(c) = self.conns.get(&conn) else { return Ok(()) };
        if !c.peer {
            return Ok(());
        }
        let Some((dialer, listener, key)) = c.session.binding() else { return Ok(()) };
        let actors = counted_actors(&self.engine, &c.proven);
        if actors.is_empty() {
            // no record: the listener runs the connection's set if it knows this dialer, and this
            // side tests a filter it receives (first contact, issues/net-first-contact.md)
            let now = self.raw_now();
            if let Some(c) = self.conns.get_mut(&conn) {
                let o = c.session.handle(now, ClientInput::Command(Command::Shared(Box::new(osis_proto::Message::NoRecord { id: super::shared::NO_RECORD_ID }))));
                self.outputs(conn, o, out)?;
            }
            return self.shared_begin(conn, None, out);
        }
        let mut nonce = [0u8; 32];
        self.rng.fill_bytes(&mut nonce);
        let recs = self.engine.run(|tx| Ok(tx.txn.records_of_actors(&actors)?))?;
        self.records.lookups += recs.len() as u64;
        let tags = recs.iter().take(MAX_RESUME_TAGS).map(|r| resume_tag(&r.r, &key, &dialer, &listener)).collect();
        let expect = recs.iter().take(MAX_RESUME_TAGS).map(|r| (resumed_tag(&r.r, &key, &dialer, &listener), r.id)).collect();
        self.records.sent.insert(conn, ResumeSent { nonce, actors, expect });
        let now = self.raw_now();
        let Some(c) = self.conns.get_mut(&conn) else { return Ok(()) };
        let o = c.session.handle(now, ClientInput::Command(Command::Resume { nonce, tags }));
        self.outputs(conn, o, out)
    }

    /// The answer to this connection's Resume. A tag not one this node expected, or for a record
    /// gone since it was listed, finds nothing: a new record, whatever the peer claims.
    pub(super) fn resumed(&mut self, conn: ConnId, theirs: [u8; 32], tag: Option<[u8; 32]>, out: &mut Vec<Action>) -> Result<()> {
        let Some(sent) = self.records.sent.remove(&conn) else { return Ok(()) };
        let hit = tag.and_then(|t| sent.expect.iter().find(|(e, _)| *e == t).map(|(_, id)| *id));
        let mut in_use = self.records.live();
        let id = self.engine.run(|tx| match hit.map_or(Ok(None), |id| tx.txn.record(&id).map(|r| r.map(|_| id)))? {
            Some(id) => {
                tx.txn.record_used(&id, &sent.actors)?;
                Ok(id)
            }
            None => {
                let r = pair_key(&sent.nonce, &theirs);
                let id = tx.txn.record_create(*r.expose(), &sent.actors)?;
                in_use.insert(id);
                tx.txn.records_evict(RECORD_BUDGET, &in_use)?;
                Ok(id)
            }
        })?;
        self.bind_record(conn, id, out)
    }

    /// `conn` takes record `id`, and its shared set starts. Two connections of one record with
    /// one dialer: the smaller `connection_order` stays and the other closes, on both ends, whatever
    /// order the answers arrived in (a loser that was just dialed is not redialed). Opposite
    /// dialers both stay: each direction carries its dialer's pass until both sides pull on one
    /// connection (issues/net-reconnect.md).
    pub(super) fn bind_record(&mut self, conn: ConnId, id: RecordId, out: &mut Vec<Action>) -> Result<()> {
        let (acked, r) = self.engine.run(|tx| Ok(tx.txn.record(&id)?.map_or((0, [0; 32]), |r| (r.acked_pos, r.r))))?;
        let Some((dialer, listener)) = self.conns.get(&conn).and_then(|c| c.session.binding()).or_else(|| self.served_binding(conn)).map(|(d, l, _)| (d, l)) else { return Ok(()) };
        let order = connection_order(&r, &dialer, &listener);
        self.records.order.insert(conn, order);
        self.records.bound.insert(conn, ConnRecord::new(id, acked));
        let old = self.records.live.get(&id).copied().filter(|old| *old != conn);
        if let Some(old) = old
            && (self.conns.get(&old).zip(self.conns.get(&conn)).is_some_and(|(a, b)| a.host == b.host) || self.served_same_peer(old, conn))
        {
            let keep_new = self.records.order.get(&old).is_none_or(|o| order < *o);
            let lose = if keep_new { old } else { conn };
            self.records.bound.remove(&lose);
            if keep_new {
                self.records.live.insert(id, conn);
            }
            self.close_duplicate(lose, out);
            if !keep_new {
                return Ok(());
            }
        } else {
            self.records.live.insert(id, conn);
        }
        self.shared_begin(conn, Some(r), out)
    }

    fn close_duplicate(&mut self, conn: ConnId, out: &mut Vec<Action>) {
        if let Some(host) = self.conns.get(&conn).map(|c| c.host) {
            out.push(Action::Close { conn });
            self.lost(conn);
            self.retry.remove(&host);
        } else {
            self.close_served(conn, out);
        }
    }

    /// The record `conn` holds, if any.
    pub fn connection_record(&self, conn: ConnId) -> Option<RecordId> {
        self.records.bound.get(&conn).map(|b| b.id)
    }

    /// Records read for Resumes so far (a test's work count).
    pub fn record_lookups(&self) -> u64 {
        self.records.lookups
    }
}
