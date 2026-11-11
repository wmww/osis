//! Pair keys and per-peer records on connections (issues/net-reconnect.md, Resume).
//!
//! What proves a record: the session's own proven actors, those this node knows now (`Judge`
//! over the rosters it holds): the same set that gates the proof answer (spec/sync.md §10). A
//! record is honoured only while a
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
#[derive(Clone)]

struct ResumeSent {
    nonce: [u8; 32],
    actors: Vec<Tid>,
    /// The answer tag of each record listed.
    expect: Vec<([u8; 32], RecordId)>,
}

/// Which record each connection has, and the Resumes waiting for their answer.
#[derive(Clone, Default)]
pub(crate) struct Records {
    bound: BTreeMap<ConnId, ConnRecord>,
    live: BTreeMap<RecordId, ConnId>,
    sent: BTreeMap<ConnId, ResumeSent>,
    /// Each connection's place among its record's (`rank`), and its shared set.
    order: BTreeMap<ConnId, (bool, [u8; 32])>,
    /// Connections a relay carries (`SyncEngine::set_relayed`).
    relayed: BTreeSet<ConnId>,
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
        self.relayed.remove(&conn);
        self.shared.remove(&conn);
        if let Some(b) = self.bound.remove(&conn)
            && self.live.get(&b.id) == Some(&conn)
        {
            self.live.remove(&b.id);
        }
    }
}

/// The proven actors that count for a record now: those known here.
pub(super) fn counted_actors(engine: &Engine, proven: &Proven) -> Vec<Tid> {
    proven.all().iter().copied().filter(|a| engine.core.judge([*a]).known()).collect()
}

/// Whether a session proving `now` proves other actors than record `rec` names.
fn actors_moved(rec: &Record, now: &[Tid]) -> bool {
    rec.actors.iter().collect::<BTreeSet<_>>() != now.iter().collect::<BTreeSet<_>>()
}

/// The listener's nonce and the tag of a record it holds, answering a Resume.
pub(super) type ResumeAnswer = ([u8; 32], Option<[u8; 32]>);

/// The listener's part of a Resume: the nonce it answers and the tag of a record it holds, with
/// the record used or made, durably before the answer goes, and whether the record named other
/// actors than this session proves.
pub(super) fn answer_resume(engine: &mut Engine, actors: &[Tid], in_use: &BTreeSet<RecordId>, nonce: &[u8; 32], tags: &[[u8; 32]], (dialer, listener, key): (&[u8; 32], &[u8; 32], &[u8; 32])) -> Result<(ResumeAnswer, (RecordId, bool), u64)> {
    engine.run(|tx| {
        let records = tx.txn.records_of_actors(actors)?;
        let looked = records.len() as u64;
        let by_tag: BTreeMap<[u8; 32], &Record> = records.iter().map(|r| (resume_tag(&r.r, key, dialer, listener), r)).collect();
        let hit = tags.iter().find_map(|t| by_tag.get(t).copied());
        let mine = tx.txn.random32();
        if let Some(r) = hit {
            tx.txn.record_used(&r.id, actors)?;
            return Ok(((mine, Some(resumed_tag(&r.r, key, dialer, listener))), (r.id, actors_moved(r, actors)), looked));
        }
        let r = pair_key(nonce, &mine);
        let id = tx.txn.record_create(*r.expose(), actors)?;
        let mut keep = in_use.clone();
        keep.insert(id);
        tx.txn.records_evict(RECORD_BUDGET, &keep)?;
        Ok(((mine, None), (id, false), looked))
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
            let now = self.now();
            if let Some(c) = self.conns.get_mut(&conn) {
                let o = c.session.handle(now, ClientInput::Command(Command::Peer(Box::new(osis_proto::Message::NoRecord { id: super::shared::NO_RECORD_ID }))));
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
        let now = self.now();
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
        let bound = self.engine.run(|tx| match hit.map_or(Ok(None), |id| tx.txn.record(&id))? {
            Some(rec) => {
                tx.txn.record_used(&rec.id, &sent.actors)?;
                Ok((rec.id, actors_moved(&rec, &sent.actors)))
            }
            None => {
                let r = pair_key(&sent.nonce, &theirs);
                let id = tx.txn.record_create(*r.expose(), &sent.actors)?;
                in_use.insert(id);
                tx.txn.records_evict(RECORD_BUDGET, &in_use)?;
                Ok((id, false))
            }
        })?;
        self.bind_record(conn, bound, out)
    }

    /// The transport carries `conn` through a relay (the driver says so before the connection's
    /// first event): it ranks after a direct connection of its record (`bind_record`).
    pub fn set_relayed(&mut self, conn: ConnId) {
        self.records.relayed.insert(conn);
    }

    /// `conn` takes record `id` (and whether the session proves other actors than it names), and
    /// its stream and shared set start from it. Two connections of one
    /// record are one pair of nodes (r is known to the two alone), whoever dialed each: the one
    /// of smaller rank stays and the other closes, on both ends, whatever order the answers
    /// arrived in. The rank is the route first, a direct connection before a relayed one (both
    /// ends tell a relayed connection alike), then `connection_order`. A dialer whose connection
    /// lost to one the peer dialed does not dial the peer again while that one lasts
    /// (`stand_in`).
    pub(super) fn bind_record(&mut self, conn: ConnId, (id, moved): (RecordId, bool), out: &mut Vec<Action>) -> Result<()> {
        let (acked, r) = self.engine.run(|tx| Ok(tx.txn.record(&id)?.map_or((0, [0; 32]), |r| (r.acked_pos, r.r))))?;
        let Some((dialer, listener)) = self.conns.get(&conn).and_then(|c| c.session.binding()).or_else(|| self.served_binding(conn)).map(|(d, l, _)| (d, l)) else { return Ok(()) };
        let order = (self.records.relayed.contains(&conn), connection_order(&r, &dialer, &listener));
        self.records.order.insert(conn, order);
        self.records.bound.insert(conn, ConnRecord::new(id, acked));
        let old = self.records.live.get(&id).copied().filter(|old| *old != conn);
        if let Some(old) = old {
            let keep_new = self.records.order.get(&old).is_none_or(|o| order < *o);
            let (keep, lose) = if keep_new { (conn, old) } else { (old, conn) };
            self.records.bound.remove(&lose);
            self.records.live.insert(id, keep);
            self.close_duplicate(lose, keep, out);
            if !keep_new {
                return Ok(());
            }
        } else {
            self.records.live.insert(id, conn);
        }
        self.shared_begin(conn, Some((id, moved)), out)
    }

    /// Closes `conn`, the duplicate of `keep`. A dialed one is not dialed again at once: its
    /// peer is connected by `keep` (`stand_in` when the peer dialed it).
    fn close_duplicate(&mut self, conn: ConnId, keep: ConnId, out: &mut Vec<Action>) {
        if let Some(host) = self.conns.get(&conn).map(|c| c.host) {
            out.push(Action::Close { conn });
            self.lost(conn);
            self.retry.remove(&host);
            if self.served.contains_key(&keep) {
                self.stand_in.insert(host, keep);
            }
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
