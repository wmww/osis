//! Pair keys and per-peer records on connections (issues/net-reconnect.md, Resume).
//!
//! What proves a record: the session's own proven key actors, those this node knows now (`Judge`
//! over the rosters it holds): the same set that gates the proof answer (spec/sync.md §10). Only
//! key actors proved by their own key count: a chain-proved or account-key-proved account proves
//! no removal it omits, so it finds no record and makes none until accounts sign
//! (issues/net-shared-set.md step 10; `Proven::accounts`). A record is honoured only while a
//! proven actor of this session is one of its actors and known here now, so a node removed from
//! every roster held here cannot use one. The tag binds r to this connection's challenges.
//!
//! r goes only inside the connection's own messages: the nonces of `Resume` and `Resumed`.

use super::proofs::Proven;
use super::{Action, ConnId, SyncEngine};
use crate::error::Result;
use osis_base::Tid;
use osis_crypto::kdf::{pair_key, resume_tag, resumed_tag};
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
    /// Records read for a Resume or its answer (tests count the work).
    pub lookups: u64,
}

impl Records {
    pub(crate) fn live(&self) -> BTreeSet<RecordId> {
        self.live.keys().copied().collect()
    }

    /// `conn` ended.
    pub(crate) fn conn_gone(&mut self, conn: ConnId) {
        self.sent.remove(&conn);
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
pub(super) fn answer_resume(engine: &mut Engine, actors: &[Tid], in_use: &BTreeSet<RecordId>, nonce: &[u8; 32], tags: &[[u8; 32]], (dialer, listener): (&[u8; 32], &[u8; 32])) -> Result<(osis_proto::ResumeAnswer, RecordId, u64)> {
    engine.run(|tx| {
        let records = tx.txn.records_of_actors(actors)?;
        let looked = records.len() as u64;
        let by_tag: BTreeMap<[u8; 32], &Record> = records.iter().map(|r| (resume_tag(&r.r, dialer, listener), r)).collect();
        let hit = tags.iter().find_map(|t| by_tag.get(t).copied());
        let mine = tx.txn.random32();
        if let Some(r) = hit {
            tx.txn.record_used(&r.id, actors)?;
            return Ok(((mine, Some(resumed_tag(&r.r, dialer, listener))), r.id, looked));
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
        let Some(challenges) = c.session.challenges() else { return Ok(()) };
        let actors = counted_actors(&self.engine, &c.proven);
        if actors.is_empty() {
            return Ok(());
        }
        let mut nonce = [0u8; 32];
        self.rng.fill_bytes(&mut nonce);
        let recs = self.engine.run(|tx| Ok(tx.txn.records_of_actors(&actors)?))?;
        self.records.lookups += recs.len() as u64;
        let (dialer, listener) = challenges;
        let tags = recs.iter().take(MAX_RESUME_TAGS).map(|r| resume_tag(&r.r, &dialer, &listener)).collect();
        let expect = recs.iter().take(MAX_RESUME_TAGS).map(|r| (resumed_tag(&r.r, &dialer, &listener), r.id)).collect();
        self.records.sent.insert(conn, ResumeSent { nonce, actors, expect });
        let now = self.raw_now();
        let Some(c) = self.conns.get_mut(&conn) else { return Ok(()) };
        let o = c.session.handle(now, ClientInput::Command(Command::Resume { nonce, tags }));
        self.outputs(conn, o, out)
    }

    /// The answer to this connection's Resume. A tag not one this node expected finds nothing:
    /// a new record, whatever the peer claims.
    pub(super) fn resumed(&mut self, conn: ConnId, theirs: [u8; 32], tag: Option<[u8; 32]>, out: &mut Vec<Action>) -> Result<()> {
        let Some(sent) = self.records.sent.remove(&conn) else { return Ok(()) };
        let hit = tag.and_then(|t| sent.expect.iter().find(|(e, _)| *e == t).map(|(_, id)| *id));
        let mut in_use = self.records.live();
        let id = self.engine.run(|tx| match hit {
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

    /// `conn` takes record `id`; a connection that held it gives it up. The older closes when both
    /// have the same dialer. A pair of opposite dialers both stay open: today each direction
    /// carries only its dialer's pass (issues/net-sync-structure.md (a)), so closing one would
    /// change what syncs.
    pub(super) fn bind_record(&mut self, conn: ConnId, id: RecordId, out: &mut Vec<Action>) -> Result<()> {
        let acked = self.engine.run(|tx| Ok(tx.txn.record(&id)?.map_or(0, |r| r.acked_pos)))?;
        self.records.bound.insert(conn, ConnRecord::new(id, acked));
        let Some(old) = self.records.live.insert(id, conn) else { return Ok(()) };
        if old == conn {
            return Ok(());
        }
        self.records.bound.remove(&old);
        match (self.conns.get(&old), self.conns.get(&conn)) {
            (Some(a), Some(b)) if a.host == b.host => {
                let host = a.host;
                out.push(Action::Close { conn: old });
                self.lost(old);
                self.retry.remove(&host);
            }
            (None, None) if self.served_same_peer(old, conn) => self.close_served(old, out),
            _ => {}
        }
        Ok(())
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
