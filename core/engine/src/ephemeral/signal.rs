//! Ephemeral signals (notes/ephemeral.md Ephemeral signals, spec/sync.md §9 Relay-only commits):
//! an ephemeral signal write is a delta in an ephemeral commit marked relay-only, built here from
//! one write's ephemeral signal writes, pushed by hosts to the label's current subscribers and
//! held by nobody. A received one is verified like any commit, its valid parts told to history
//! watches once (`Delivered`, bounded), and nothing of it kept.

use super::Engine;
use crate::engine::secrets::{CommitSecrets, published_keys};
use crate::engine::write::{Creates, check_role_with, run_ops};
use crate::error::{Error, Result};
use super::Written;
use crate::engine::listing::{CommitRow, PartBody, PartRow};
use crate::events::CommitChange;
use osis_base::format::MAX_DRIFT_MS;
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
#[derive(Default)]
pub(super) struct Delivered {
    order: VecDeque<(CommitId, u64, Tid)>,
    parts: BTreeMap<CommitId, BTreeSet<usize>>,
    floor: BTreeMap<Tid, u64>,
}

/// One signal delta of a relay-only commit: thing, aspect, fragment.
type Signal = (Tid, Ak, Fragment);

impl Engine {
    /// Fires `signals`, one write's ephemeral signal writes (spec/sync.md §9): one relay-only
    /// commit, built and signed now, so the write is named by it; queued for sync when a thing of
    /// it is in a labeled closure; told to commit listeners here as it is (`CommitChange::fired`).
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
        if signals.iter().any(|(t, _, _)| self.core.syncs(t) || self.groups_of(t).iter().any(|g| self.core.syncs(g))) {
            self.eph.signals.push(c);
        }
        let (node, received) = (self.tid(), self.now());
        let fired = fired(signals, id, actor, node, ts, received);
        self.core.commits_fired(fired);
        Ok(Written { id, ts })
    }

    /// The relay-only commits of own ephemeral signal writes not yet sent.
    pub fn take_signals(&mut self) -> Vec<EphCommit> {
        std::mem::take(&mut self.eph.signals)
    }

    /// Builds and signs one relay-only commit of `deltas` for `actor` at `ts`.
    fn build_relay(&mut self, actor: Tid, ts: Ts, deltas: Vec<Signal>) -> Result<EphCommit> {
        let me = self.tid();
        self.run(|tx| {
            let cx = osis_commit::writer_ctx(Form::Commit, Kind::ContentSnapshot, ts, me, 0, 0);
            let creates = Creates::new();
            let mut writes = Vec::with_capacity(deltas.len());
            for (tid, ak, fragment) in deltas {
                let mut nonce = [0u8; osis_crdt::NONCE_LEN];
                tx.rng.fill_bytes(&mut nonce);
                let bytes = osis_crdt::encode_snapshot(&Snapshot { nonce, fragment, frontiers: Frontiers::default(), absorbed: BTreeMap::new() }, &cx, Some(&mut Unpaged))?;
                writes.push(AspectWrite { tid, ak, lo: 0, hi: 0, delta: bytes, retention: osis_commit::retention::EPHEMERAL_RETENTION, chunks: Vec::new() });
            }
            let things: Vec<Tid> = writes.iter().map(|w| w.tid).collect();
            let published = published_keys(tx, &creates, things)?;
            let mut b = CommitBuilder::new(Kind::ContentSnapshot, ts, me, actor, Form::Commit);
            b.aspects = writes;
            b.ephemeral = Some(EphClass::Relay);
            let secrets = CommitSecrets { core: tx.core, actor, created: &creates, published: &published };
            let built = b.build(&tx.core.id.keys().signing, &secrets, &mut MemoryBlobs::default(), &mut *tx.rng)?;
            Ok(EphCommit { id: built.commit.id(), blob: built.commit })
        })
    }

    /// Receives a relay-only commit (spec/sync.md §9): dropped unopened when outside its replay
    /// window or delivered before (`MAX_DELIVERED`, per-author floors); else verified like any
    /// commit, its valid signal parts not delivered before told to commit listeners once, and nothing
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
        // its author's record must be held here (a relay never waits)
        match crate::apply::signed_by_author(&self.core, &blob, &id, self.core.created(&h.author)) {
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
        // key, the author acting for its actor
        let acts = crate::apply::validity::acts_for(core, h, &id);
        let mut signals = Vec::new();
        for (ai, s) in &decoded {
            let Some(a) = h.aspects.get(*ai) else { continue };
            let valid = a.ak.signal() && a.ak.ephemeral() && acts && check_role_with(core, h.author, &|_| None, &a.tid, a.ak.as_str(), Role::Write, h.ts).is_ok();
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
        let received = self.now();
        let fired = fired(signals, id, h.actor, h.author, h.ts, received);
        self.core.commits_fired(fired);
        Ok(true)
    }
}

/// A fired ephemeral signal commit as it arrived, told at each signal it fired: a fire is
/// content, though its relay-only commit is snapshot-encoded.
fn fired(signals: Vec<(Tid, Ak, Value)>, id: CommitId, actor: Tid, node: Tid, ts: Ts, received: osis_base::WallMs) -> Vec<CommitChange> {
    let parts: Vec<PartRow> = signals.into_iter().map(|(tid, ak, v)| PartRow { tid, ak, valid: true, body: PartBody::Held(Some(v)) }).collect();
    let row = CommitRow { id, kind: Kind::Content, undoes: None, actor, node, ts, received, parts };
    row.parts.iter().map(|p| CommitChange { tid: p.tid, ak: p.ak.clone(), id, fired: Some(row.clone()) }).collect()
}
