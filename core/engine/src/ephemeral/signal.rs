//! Ephemeral signals (notes/ephemeral.md Ephemeral signals, spec/sync-compaction.md §2 relay-only commits):
//! an ephemeral signal write is a delta in an ephemeral commit marked relay-only, built here from
//! one write's ephemeral signal writes, sealed per sync ID (`Engine::take_relays`), passed on by sync to every peer sharing it and
//! held by nobody. A received one is verified like any commit, its valid parts told to history
//! watches once (`Delivered`, bounded), and nothing of it kept.

use super::Engine;
use crate::engine::secrets::{CommitSecrets, published_keys};
use crate::engine::write::{Creates, check_role, run_ops};
use crate::error::{Error, Result};
use super::Written;
use crate::engine::listing::{CommitRow, PartBody, PartRow};
use crate::events::CommitChange;
use osis_base::{Ak, CommitId, Role, Tid, Ts, Value};
use osis_commit::{AspectWrite, CommitBlob, CommitBuilder, EphClass, Form, Kind, MemoryBlobs};
use osis_crdt::{AnyView, Fragment, Frontiers, Interner, Op, PathOp, Snapshot, Source, Unpaged, Writer};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Relay-only commit IDs remembered as delivered (notes/ephemeral.md Bounds). Resource bound
/// against a hostile writer: past it the oldest is forgotten and its `ts` becomes its author's
/// floor, at or below which that author's relay-only commits are dropped, so none fires twice and
/// a flooding writer loses only its own (0: every relay-only commit older than its author's
/// newest delivered is dropped; infinity: memory grows with every signal of the replay window).
pub const MAX_DELIVERED: usize = 1 << 16;

/// A relay-only commit built here: its ID and blob (header and parts).
#[derive(Clone, Debug)]
pub struct EphCommit {
    pub id: CommitId,
    pub blob: CommitBlob,
}

/// Relay-only commits delivered, oldest first, with their `ts` (wall ms) and author; per commit
/// the parts delivered; per author the floor.
#[derive(Clone, Default)]
pub(super) struct Delivered {
    order: VecDeque<(CommitId, u64, Tid)>,
    parts: BTreeMap<CommitId, BTreeSet<usize>>,
    floor: BTreeMap<Tid, u64>,
}

/// One signal delta of a relay-only commit: thing, aspect, fragment.
type Signal = (Tid, Ak, Fragment);

impl Engine {
    /// Fires `signals`, one write's ephemeral signal writes (spec/sync-compaction.md §2): one relay-only
    /// commit, built and signed now, so the write is named by it; queued for sync when a thing of
    /// it is in the closure of a sync ID; told to commit listeners here as it is (`CommitChange::fired`).
    pub(super) fn fire(&mut self, signals: Vec<(Tid, Ak, Value)>, ts: Ts, actor: Tid) -> Result<Written> {
        let src = Source::session(self.core.session);
        let mut deltas: Vec<Signal> = Vec::with_capacity(signals.len());
        for (tid, ak, v) in &signals {
            // never joined anywhere: any counter
            let w = Writer::new(ts, src.clone(), 1);
            if let Some((f, _)) = run_ops(&Fragment::default(), w, &[PathOp { path: Vec::new(), op: Op::Set(v.clone()) }], &AnyView)? {
                deltas.push((*tid, ak.clone(), f));
            }
        }
        let c = self.build_relay(actor, ts, deltas)?;
        let id = c.id;
        // relayed when N's closure holds a thing it writes (spec/sync-set.md §2)
        let mut synced = false;
        for (t, _, _) in &signals {
            if self.in_sync_things(t)? {
                synced = true;
                break;
            }
        }
        if synced {
            self.eph.signals.push(c);
        }
        let (node, received) = (self.core.tid(), self.now());
        let fired = fired(signals, id, node, actor, ts, received);
        self.core.commits_fired(fired);
        Ok(Written { id, ts })
    }

    /// The relay-only commits of own ephemeral signal writes not yet sent (`take_relays`).
    pub(crate) fn take_signals(&mut self) -> Vec<EphCommit> {
        std::mem::take(&mut self.eph.signals)
    }

    /// Builds and signs one relay-only commit of `deltas` for `actor` at `ts`.
    pub(crate) fn build_relay(&mut self, actor: Tid, ts: Ts, deltas: Vec<Signal>) -> Result<EphCommit> {
        let me = self.core.tid();
        self.run(|tx| {
            let cx = osis_commit::writer_ctx(Form::Commit, Kind::ContentSnapshot, ts, me, 0, 0);
            let (creates, minted) = (Creates::new(), Default::default());
            let mut writes = Vec::with_capacity(deltas.len());
            for (tid, ak, fragment) in deltas {
                let mut nonce = [0u8; osis_crdt::NONCE_LEN];
                tx.rng.fill_bytes(&mut nonce);
                let bytes = osis_crdt::encode_snapshot(&Snapshot { nonce, fragment, frontiers: Frontiers::default(), absorbed: BTreeMap::new(), facts: Default::default() }, &cx, Some(&mut Unpaged))?;
                writes.push(AspectWrite { tid, ak, lo: 0, hi: 0, delta: bytes, replaces: None, original_floor: 0, purge_by: osis_commit::retention::EPHEMERAL_PURGE_BY });
            }
            let things: Vec<Tid> = writes.iter().map(|w| w.tid).collect();
            let published = published_keys(tx, &creates, &minted, things)?;
            // the relayed snapshot is judged by no path (a signal valid by its key)
            let mut b = CommitBuilder::new(Kind::ContentSnapshot, ts, me, crate::engine::write::plain_path(me, actor), Form::Commit);
            b.aspects = writes;
            b.ephemeral = Some(EphClass::Relay);
            let keys = crate::engine::secrets::KeyCache::default();
            let secrets = CommitSecrets { core: tx.core, purge_author: actor, created: &creates, minted: &minted, published: &published, keys: &keys };
            let built = b.build(tx.core.id.signing(), &secrets, &mut MemoryBlobs::default(), &mut *tx.rng)?;
            Ok(EphCommit { id: built.commit.id(), blob: built.commit })
        })
    }

    /// Receives a relay-only commit (spec/sync-compaction.md §2): dropped unopened when outside its replay
    /// window or delivered before (`MAX_DELIVERED`, per-author floors); else verified like any
    /// commit, its valid signal parts not delivered before told to commit listeners once, and nothing
    /// of it kept. Whether it was new here (a co-reader peer passes a new one on). Bad input is
    /// an error.
    pub(crate) fn ingest_relay_blob(&mut self, blob: CommitBlob) -> Result<bool> {
        let id = blob.id();
        // passed on as it came (node-sync streams its blob), never sealed here again
        self.openings_done(&id);
        let h = &blob.header;
        if h.ephemeral != Some(EphClass::Relay) {
            return Err(Error::BadInput("not a relay-only commit"));
        }
        let now = self.now().0;
        let at = h.ts.wall_ms().0;
        let ended = |t: u64| osis_commit::relay_end(t) <= now;
        let r = &self.eph.relays;
        if r.parts.get(&id).is_some_and(|d| blob.parts.iter().all(|p| d.contains(&p.ai))) || r.floor.get(&h.signer).is_some_and(|f| at <= *f) || ended(at) || crate::apply::parked(crate::events::Origin::Remote, h.ts, osis_base::Time(now)) {
            return Ok(false);
        }
        // its author's record must be held here (a relay never waits)
        match crate::apply::signed_by_author(&self.core, &blob, &id, self.core.created(&h.signer), None) {
            Some(true) => {}
            Some(false) => return Err(crate::Error::BadInput("signature")),
            None => return Ok(false),
        }
        h.validate()?;
        let core = &self.core;
        let mut interner = Interner::new();
        let mut decoded = Vec::new();
        for p in &blob.parts {
            let Some(a) = h.aspects.get(p.ai) else { continue };
            let Some(dedup) = core.dedup(&a.tid) else { continue };
            match osis_commit::verify_part(h, &id, p, &dedup, &mut interner, Some(&mut Unpaged))? {
                osis_commit::Decoded::Snapshot(s) => decoded.push((p.ai, s)),
                osis_commit::Decoded::Delta(_) => return Err(Error::BadInput("relay-only commit with a writer delta")),
            }
        }
        // judged as its author's write at its `ts` (spec/permissions.md §5.2), on an ephemeral signal
        // key
        let mut signals = Vec::new();
        for (ai, s) in &decoded {
            let Some(a) = h.aspects.get(*ai) else { continue };
            let valid = a.ak.signal() && a.ak.ephemeral() && a.replaces.is_none() && check_role(core, h.signer, &|_| None, &a.tid, a.ak.as_str(), Role::Write, h.ts).is_ok();
            if valid && let Some(v) = s.fragment.read() {
                signals.push((a.tid, a.ak.clone(), v));
            }
        }
        // delivered once per part
        let r = &mut self.eph.relays;
        let seen = match r.parts.get_mut(&id) {
            Some(d) => std::mem::take(d),
            None => {
                r.order.push_back((id, at, h.signer));
                BTreeSet::new()
            }
        };
        signals.retain(|(t, ak, _)| !decoded.iter().any(|(ai, _)| seen.contains(ai) && h.aspects.get(*ai).is_some_and(|a| a.tid == *t && a.ak == *ak)));
        let mut all = seen;
        all.extend(decoded.iter().map(|(ai, _)| *ai));
        r.parts.insert(id, all);
        while r.order.len() > MAX_DELIVERED || r.order.front().is_some_and(|(_, t, _)| ended(*t)) {
            if let Some((c, t, a)) = r.order.pop_front() {
                r.parts.remove(&c);
                // past its window a commit is dropped anyway: no floor needed
                if !ended(t) {
                    let f = r.floor.entry(a).or_default();
                    *f = (*f).max(t);
                }
            }
        }
        r.floor.retain(|_, f| !ended(*f));
        let received = self.now();
        let fired = fired(signals, id, h.signer, h.purge_author(), h.ts, received);
        self.core.commits_fired(fired);
        Ok(true)
    }
}

/// A fired ephemeral signal commit as it arrived, told at each signal it fired: a fire is
/// content, though its relay-only commit is snapshot-encoded.
fn fired(signals: Vec<(Tid, Ak, Value)>, id: CommitId, node: Tid, purge_author: Tid, ts: Ts, received: osis_base::Time) -> Vec<CommitChange> {
    if signals.is_empty() {
        return Vec::new();
    }
    let parts: Vec<PartRow> = signals.into_iter().map(|(tid, ak, v)| PartRow { tid, ak, valid: true, version: None, body: PartBody::Held(Some(v)) }).collect();
    let row = CommitRow { id, kind: Kind::Content, undoes: None, purge_author, node, ts, received, parts };
    row.parts.iter().map(|p| CommitChange { tid: p.tid, ak: p.ak.clone(), id, fired: Some(row.clone()) }).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::Mutation;
    use crate::local_peer::LocalPeer;
    use osis_base::Time;
    use osis_schema::core_types as ct;

    /// Peer 0 administers a thing peer 1 holds with write; `fire` is a relay-only commit of
    /// peer 0's firing `x:ring+~0` on it now.
    fn world() -> (LocalPeer, Tid) {
        let mut lp = LocalPeer::fresh(2, Time(1_700_000_000_000));
        lp.sync_all().unwrap();
        let [a, b] = [0, 1].map(|i| lp.peers[i].engine.tid());
        let (t, _) = lp.peers[0].engine.create_with_admin(&a).unwrap();
        lp.hold(t);
        lp.peers[0].engine.grant(&t, &b, &ct::Grant { role: Role::Write, until: None, may_grant: false, retain: false, floor: None }).unwrap();
        lp.sync_all().unwrap();
        (lp, t)
    }

    fn fire(lp: &mut LocalPeer, t: Tid, v: i64) -> CommitBlob {
        lp.advance(10);
        let mut m = Mutation::new();
        m.set(t, &Ak::new("x:ring+~0").unwrap(), &Value::Int(v)).unwrap();
        lp.peers[0].engine.write(m).unwrap().unwrap();
        lp.peers[0].engine.take_signals().pop().unwrap().blob
    }

    // spec/sync-compaction.md §2 (Relay-only commits; Dropped unopened; Replay): a relay-only commit is delivered once; one
    // at or below its author's floor, or at or past its expiry, is dropped unopened.
    #[test]
    fn a_relay_only_commit_is_delivered_once_in_its_window_spec_sync_compaction_2() {
        let (mut lp, t) = world();
        let a = lp.peers[0].engine.tid();
        let first = fire(&mut lp, t, 1);
        let e = &mut lp.peers[1].engine;
        assert!(e.ingest_relay_blob(first.clone()).unwrap(), "new");
        assert!(!e.ingest_relay_blob(first).unwrap(), "delivered before");
        let second = fire(&mut lp, t, 2);
        let e = &mut lp.peers[1].engine;
        e.eph.relays.floor.insert(a, second.header.ts.wall_ms().0);
        assert!(!e.ingest_relay_blob(second.clone()).unwrap(), "at its author's floor");
        e.eph.relays.floor.clear();
        assert!(e.ingest_relay_blob(second).unwrap());
        // at its blob's expiry, `ts + MAX_DRIFT`, as a store drops it (spec/sync-ids.md §6)
        let old = fire(&mut lp, t, 3);
        let end = osis_commit::blob_expiry(&old.header).unwrap();
        lp.advance(end - lp.peers[1].engine.now().0);
        assert!(!lp.peers[1].engine.ingest_relay_blob(old).unwrap(), "at the end of its window");
    }

    // spec/sync-compaction.md §2 (Replay), notes/ephemeral.md Bounds: past `MAX_DELIVERED` remembered the
    // oldest is forgotten and its `ts` becomes its author's floor.
    #[test]
    fn past_max_delivered_the_oldest_becomes_its_authors_floor_spec_sync_compaction_2() {
        let (mut lp, t) = world();
        let blob = fire(&mut lp, t, 1);
        let e = &mut lp.peers[1].engine;
        let now = e.now().0;
        let x = Tid::from_bytes([9; 15]);
        for i in 0..MAX_DELIVERED as u64 {
            let mut c = [0; 32];
            c[..8].copy_from_slice(&i.to_be_bytes());
            e.eph.relays.order.push_back((CommitId(c), now - 1000 + i % 2, x));
        }
        assert!(e.ingest_relay_blob(blob).unwrap());
        let r = &e.eph.relays;
        assert_eq!(r.order.len(), MAX_DELIVERED);
        assert_eq!(r.floor.get(&x), Some(&(now - 1000)));
    }
}
