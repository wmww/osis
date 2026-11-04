//! Signals (notes/ephemeral.md Signals, spec/sync.md §9 Relay-only commits): a signal write is a
//! delta in an ephemeral commit marked relay-only, built here from the batch's signal writes (one
//! per actor), pushed by hosts to the label's current subscribers and held by nobody. A received
//! one is verified like any commit, its valid parts delivered to callbacks once (`Delivered`,
//! bounded), and nothing of it kept.

use super::Engine;
use crate::engine::secrets::{CommitSecrets, published_keys};
use crate::engine::write::{Creates, check_role_with, run_ops};
use crate::error::{Error, Result};
use crate::events::{ChangeId, Event, Origin};
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{Ak, CommitId, CreationRecord, Role, Tid, Ts, Value};
use osis_commit::{AspectWrite, CommitBlob, CommitBuilder, EphClass, Form, Kind, MemoryBlobs};
use osis_crdt::{AnyView, Fragment, Frontiers, Interner, Op, PathOp, Snapshot, Source, Unpaged, Writer};
use osis_crypto::{VerifyingKey, dedup_secret};
use osis_schema::Lifetime;
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
/// the parts delivered (its projections go as several blobs); per author the floor.
#[derive(Default)]
pub(super) struct Delivered {
    order: VecDeque<(CommitId, u64, Tid)>,
    parts: BTreeMap<CommitId, BTreeSet<usize>>,
    floor: BTreeMap<Tid, u64>,
}

impl Engine {
    /// Notes an own signal write for sync (things in a labeled closure only).
    pub(super) fn note_signal(&mut self, tid: &Tid, ak: &Ak, v: &Value, ts: Ts, actor: Tid) {
        if self.ephemeral_synced(tid) {
            self.eph.signals.push((*tid, ak.clone(), v.clone(), ts, actor));
        }
    }

    /// The relay-only commits of the unsent signal writes: one per actor, each part carrying
    /// the records of the ephemeral things it is on (spec/commits.md §2).
    pub fn take_signals(&mut self) -> Result<Vec<EphCommit>> {
        let mut by_actor: BTreeMap<Tid, Vec<(Tid, Ak, Fragment)>> = BTreeMap::new();
        let src = Source::session(self.core.session);
        for (tid, ak, v, ts, actor) in std::mem::take(&mut self.eph.signals) {
            // never joined anywhere: any counter
            let w = Writer::new(ts, src.clone(), 1);
            if let Ok(Some((f, _))) = run_ops(&Fragment::default(), w, &[PathOp { path: Vec::new(), op: Op::Set(v) }], &AnyView) {
                by_actor.entry(actor).or_default().push((tid, ak, f));
            }
        }
        let mut out = Vec::new();
        for (actor, deltas) in by_actor {
            match self.build_relay(actor, deltas) {
                Ok(c) => out.push(c),
                Err(e) => self.report(crate::events::Diagnostic { kind: crate::events::DiagnosticKind::EphemeralRefused, tids: Vec::new(), commit: None, peer: None, detail: format!("a signal could not be sent: {e}") }),
            }
        }
        Ok(out)
    }

    /// Builds and signs one relay-only commit of `deltas` for `actor`.
    fn build_relay(&mut self, actor: Tid, deltas: Vec<(Tid, Ak, Fragment)>) -> Result<EphCommit> {
        let me = self.tid();
        let ts = self.core.hlc.next();
        self.run(|tx| {
            let cx = osis_commit::writer_ctx(Form::Commit, Kind::ContentSnapshot, ts, me, 0, 0);
            let mut creates: Creates = BTreeMap::new();
            let mut writes = Vec::with_capacity(deltas.len());
            for (tid, ak, fragment) in deltas {
                let records = crate::engine::write::memory_records(tx.core, &tid, &ak, std::iter::empty());
                creates.extend(records.iter().map(|r| (r.tid(), r.clone())));
                let mut nonce = [0u8; osis_crdt::NONCE_LEN];
                tx.rng.fill_bytes(&mut nonce);
                let bytes = osis_crdt::encode_snapshot(&Snapshot { nonce, fragment, frontiers: Frontiers::default(), absorbed: BTreeMap::new() }, &cx, Some(&mut Unpaged))?;
                writes.push(AspectWrite { tid, ak, lo: 0, hi: 0, deltas: vec![bytes], retention: osis_commit::retention::EPHEMERAL_RETENTION, chunks: Vec::new(), records });
            }
            let things: Vec<Tid> = writes.iter().map(|w| w.tid).collect();
            let published = published_keys(tx, &creates, things)?;
            let mut b = CommitBuilder::new(Kind::ContentSnapshot, ts, me, actor, Form::Commit);
            b.aspects = writes;
            b.ephemeral = Some(EphClass::Relay);
            let secrets = CommitSecrets { core: tx.core, actor, created: &creates, first: &BTreeMap::new(), published: &published };
            let built = b.build(&tx.core.id.keys().signing, &secrets, &mut MemoryBlobs::default(), &mut *tx.rng)?;
            Ok(EphCommit { id: built.commit.id(), blob: built.commit })
        })
    }

    /// Receives a relay-only commit (spec/sync.md §9): dropped unopened when outside its replay
    /// window or delivered before (`MAX_DELIVERED`, per-author floors); else verified like any
    /// commit, its valid signal parts not delivered before fired to callbacks once, and nothing
    /// of it kept. Whether it was new here (a co-reader peer passes a new one on). Bad input is
    /// an error.
    pub fn ingest_relay(&mut self, blob: CommitBlob) -> Result<bool> {
        let id = blob.id();
        let h = &blob.header;
        if h.ephemeral != Some(EphClass::Relay) {
            return Err(Error::BadInput("not a relay-only commit"));
        }
        let now = self.now().0;
        let at = h.ts.wall_ms().0;
        let r = &self.eph.relays;
        if r.parts.get(&id).is_some_and(|d| blob.parts.iter().all(|p| d.contains(&p.ai))) || r.floor.get(&h.author).is_some_and(|f| at <= *f) || at.saturating_add(MAX_DRIFT_MS) < now || at > now.saturating_add(MAX_DRIFT_MS) {
            return Ok(false);
        }
        // its author's record must be durable here (an ephemeral key actor record never ends a
        // wait, and a relay never waits)
        let Some(CreationRecord::KeyActor { public_key, .. }) = self.core.durable_created(&h.author) else { return Ok(false) };
        osis_commit::verify_signature(&id, &blob.signature, &VerifyingKey::from_slice(public_key)?)?;
        h.validate()?;
        let carried: BTreeMap<Tid, CreationRecord> = blob.parts.iter().flat_map(|p| &p.records).map(|r| (r.tid(), r.clone())).collect();
        // the records of things not durable here: carried, or held memory ones (the role on a
        // durable one is its timeline's, `role_with`)
        let core = &self.core;
        let record = |t: &Tid| carried.get(t).or_else(|| self.memory_record(t));
        let mut interner = Interner::new();
        let mut decoded = Vec::new();
        for p in &blob.parts {
            let Some(a) = h.aspects.get(p.ai) else { continue };
            let Some(dedup) = core.dedup(&a.tid).or_else(|| carried.get(&a.tid).map(|r| dedup_secret(r.nonce()))) else { continue };
            match osis_commit::verify_part(h, &id, p, &dedup, &mut interner, Some(&mut Unpaged))? {
                osis_commit::Decoded::Snapshot(s) => decoded.push((p.ai, s)),
                osis_commit::Decoded::Delta(_) => return Err(Error::BadInput("relay-only commit with a writer delta")),
            }
        }
        // judged as its author's write at its `ts` (spec/permissions.md §5.2), on a signal key,
        // the author acting for its actor
        let acts = crate::apply::validity::acts_for(core, h, &id);
        let mut signals = Vec::new();
        for (ai, s) in &decoded {
            let Some(a) = h.aspects.get(*ai) else { continue };
            let valid = a.ak.lifetime() == Lifetime::Signal && acts && check_role_with(core, h.author, &record, &a.tid, a.ak.as_str(), Role::Write, h.ts).is_ok();
            if valid && let Some(v) = s.fragment.read() {
                signals.push((a.tid, a.ak.clone(), v));
            }
        }
        // delivered once per part
        let r = &mut self.eph.relays;
        let seen = match r.parts.get_mut(&id) {
            Some(d) => std::mem::take(d),
            None => {
                r.order.push_back((id, at, h.author));
                BTreeSet::new()
            }
        };
        signals.retain(|(t, ak, _)| !decoded.iter().any(|(ai, _)| seen.contains(ai) && h.aspects.get(*ai).is_some_and(|a| a.tid == *t && a.ak == *ak)));
        let mut all = seen;
        all.extend(decoded.iter().map(|(ai, _)| *ai));
        r.parts.insert(id, all);
        while r.order.len() > MAX_DELIVERED || r.order.front().is_some_and(|(_, t, _)| t.saturating_add(MAX_DRIFT_MS) < now) {
            if let Some((c, t, a)) = r.order.pop_front() {
                r.parts.remove(&c);
                // past its window a commit is dropped anyway: no floor needed
                if t.saturating_add(MAX_DRIFT_MS) >= now {
                    let f = r.floor.entry(a).or_default();
                    *f = (*f).max(t);
                }
            }
        }
        r.floor.retain(|_, f| f.saturating_add(MAX_DRIFT_MS) >= now);
        if !signals.is_empty() {
            let received = self.now();
            self.core.events.queue(Event::Ephemeral { id: ChangeId::Commit(id), origin: Origin::Remote, author: h.author, actor: h.actor, ts: h.ts, received, changed: Vec::new(), signals });
            self.core.events.flush();
        }
        Ok(true)
    }
}
