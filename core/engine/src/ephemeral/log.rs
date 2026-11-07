//! The in-memory undo log of own ephemeral batches (notes/ephemeral.md Local engine, Undo): per
//! batch its memory commits' deltas and the pre-batch state of the positions they touched
//! (`footprint`, O(change)), copied from Core when the batch applies (what Core holds goes as
//! covered or expired; the log outlives it). A revert writes the inverse (spec/crdt.md §4.6)
//! against the current state as a new batch of memory commits. Bounded by
//! `Config::ephemeral_history` bytes: past it the oldest entries go, and an ephemeral-only batch
//! dropped so is remembered per aspect (newest only) so undo reports it instead of reaching past it.

use super::Written;
use crate::engine::write::{CommitPlan, Resolved as Delta, check_acts, check_authority, draw_blind, nonce_of};
use crate::engine::{Engine, Mutation, Tx};
use crate::error::{Error, Result};
use crate::events::{BatchId, EphemeralId};
use crate::undo::undo_expiring;
use osis_base::{Ak, CommitId, Tid, Ts, WallMs};
use osis_commit::{Form, Kind};
use osis_crdt::{CounterRange, Dot, Fragment, Source, Undone, Writer};
use osis_schema::core_types::CREATED;
use osis_schema::{RawKey, Schema};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;

/// One aspect of a logged batch.
#[derive(Clone, Debug)]
pub(super) struct LogAspect {
    pub tid: Tid,
    pub ak: Ak,
    pub delta: Fragment,
    pub range: CounterRange,
    /// The session the delta's writes are under (plain or expiring).
    pub src: Source,
    /// The touched positions before the batch (`Fragment::footprint`).
    pub pre: Fragment,
    pub schema: Option<Arc<Schema>>,
}

#[derive(Clone, Debug)]
pub(super) struct Entry {
    pub id: BatchId,
    pub reverts: Option<BatchId>,
    pub actor: Tid,
    pub ts: Ts,
    pub received: WallMs,
    pub aspects: Vec<LogAspect>,
    bytes: usize,
}

/// A logged own change, as the commit query lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoggedChange {
    /// The batch.
    pub id: BatchId,
    /// The change it reverts.
    pub reverts: Option<BatchId>,
    pub actor: Tid,
    pub ts: Ts,
    pub received: WallMs,
    /// Its ephemeral aspects.
    pub aspects: Vec<(Tid, Ak)>,
}

/// What a revert did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reverted {
    Written(Written),
    /// Nothing to write: everything it wrote was superseded since.
    Superseded,
    /// The ephemeral batch left the log (`Config::ephemeral_history`).
    Compacted,
}

#[derive(Default)]
pub(super) struct Log {
    pub(super) entries: VecDeque<Entry>,
    bytes: usize,
    /// Per aspect the newest ephemeral-only batch dropped from the log touching it, and
    /// whether it was a revert.
    dropped: HashMap<(Tid, Ak), (Ts, EphemeralId, bool)>,
}

impl Log {
    /// Logs a batch, then drops the oldest entries past `cap` bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn push(&mut self, id: BatchId, reverts: Option<BatchId>, actor: Tid, ts: Ts, received: WallMs, aspects: Vec<LogAspect>, cap: usize) {
        if aspects.is_empty() {
            return;
        }
        let bytes = aspects.iter().map(|a| a.delta.approx_bytes() + a.pre.approx_bytes() + a.ak.as_str().len()).sum::<usize>() + aspects.capacity() * size_of::<LogAspect>() + size_of::<Entry>() + 32;
        self.bytes += bytes;
        self.entries.push_back(Entry { id, reverts, actor, ts, received, aspects, bytes });
        while self.bytes > cap {
            let Some(e) = self.entries.pop_front() else { break };
            self.bytes -= e.bytes;
            if let BatchId::Ephemeral(x) = e.id {
                let v = (e.ts, x, e.reverts.is_some());
                for a in e.aspects {
                    let d = self.dropped.entry((a.tid, a.ak)).or_insert(v);
                    if d.0 < e.ts {
                        *d = v;
                    }
                }
            }
        }
    }

    pub fn find(&self, id: &BatchId) -> Option<usize> {
        self.entries.iter().position(|e| e.id == *id)
    }
}

/// An inverse write resolved for a revert's memory commit: the aspect's delta and what it copies
/// back (the revert's expiry, and so its session, follows).
struct Inverse {
    tid: Tid,
    ak: Ak,
    fragment: Fragment,
    range: CounterRange,
    /// The expiries of what it copies back (`undo_expiring`).
    copies: crate::undo::Copies,
    schema: Option<Arc<Schema>>,
}

impl Engine {
    /// This session's logged own changes, oldest first.
    pub fn ephemeral_log(&self) -> Vec<LoggedChange> {
        self.eph.log.entries.iter().map(|e| LoggedChange { id: e.id, reverts: e.reverts, actor: e.actor, ts: e.ts, received: e.received, aspects: e.aspects.iter().map(|a| (a.tid, a.ak.clone())).collect() }).collect()
    }

    /// The newest own ephemeral-only batch touching `scope` that left the undo log, and
    /// whether it was a revert.
    pub fn ephemeral_dropped(&self, scope: &[(Tid, Ak)]) -> Option<(Ts, BatchId, bool)> {
        scope.iter().filter_map(|k| self.eph.log.dropped.get(k)).max().map(|(ts, id, r)| (*ts, BatchId::Ephemeral(*id), *r))
    }

    /// Reverts change `id` acting as `actor`: a commit by an undo commit, an ephemeral batch from
    /// the log by a memory commit (spec/crdt.md §4.6). An ephemeral change this session never
    /// logged (remote, or from before a restart) is `Misuse`.
    pub fn revert_batch(&mut self, id: BatchId, actor: Tid) -> Result<Reverted> {
        self.revert_inner(id, actor, false)
    }

    /// `revert_batch`; `confined`: held to `actor`'s rights on every write it really makes
    /// (`Engine::revert_as`), before anything applies.
    pub(crate) fn revert_inner(&mut self, id: BatchId, actor: Tid, confined: bool) -> Result<Reverted> {
        match id {
            BatchId::Commit(c) => self.revert_commit(c, actor, confined),
            BatchId::Ephemeral(e) => self.revert_ephemeral(e, actor, confined),
        }
    }

    /// Reverts commit `c` by an undo commit. Undoing a creation deletes the thing (spec/crdt.md
    /// §4.6): the undo commit deletes it durably and its ephemeral state is dropped here, as a
    /// delete does (`retention::memory::drop_things`).
    fn revert_commit(&mut self, c: CommitId, actor: Tid, confined: bool) -> Result<Reverted> {
        let mut del: BTreeSet<Tid> = BTreeSet::new();
        if let Some(m) = self.core.ix.commits.get(&c)
            && let Some(h) = m.header.decoded()
        {
            del.extend(crate::undo::made_by(&h, &m.valid));
        }
        let ts = self.core.hlc.next();
        let node = self.tid();
        // who must hold write on all it does: this node (spec/crdt.md §4.6), a confined revert's
        // actor too; things it deletes count though no write is left to make
        let writers: &[Tid] = if confined { &[node, actor] } else { &[node] };
        let done = self.run(|tx| {
            if !del.is_empty() {
                let core = &*tx.core;
                check_acts(core, node, &|_| None, &actor, ts)?;
                for w in writers {
                    for t in &del {
                        check_authority(core, *w, &Default::default(), t, CREATED.ak(), ts)?;
                    }
                }
            }
            let mut m = Mutation::new();
            m.act_as(actor).undo(c);
            m.confined = confined;
            m.ts = Some(ts);
            let Some(u) = crate::engine::write::commit_in(tx, m)? else { return Ok(None) };
            let ts = tx.core.ix.commits.get(&u).map(|m| m.view.ts).unwrap_or(ts);
            Ok(Some((u, ts, crate::retention::memory::drop_things(tx, &del)?)))
        })?;
        let Some((u, ts, dropped)) = done else { return Ok(Reverted::Superseded) };
        self.dropped_event(u, actor, ts, dropped);
        Ok(Reverted::Written(Written { id: BatchId::Commit(u), ts }))
    }

    /// Reverts own ephemeral batch `e` from the log by one memory commit of its inverse writes.
    fn revert_ephemeral(&mut self, e: EphemeralId, actor: Tid, confined: bool) -> Result<Reverted> {
        let id = BatchId::Ephemeral(e);
        let Some(at) = self.eph.log.find(&id) else {
            return if self.core.own_plain(&e.session) && e.n <= self.eph.batches { Ok(Reverted::Compacted) } else { Err(Error::Misuse("no undo log for this ephemeral change (another node's, or from before a restart)")) };
        };
        let ts = self.core.hlc.next();
        let own = self.own_sources();
        let node = self.tid();
        let writers: &[Tid] = if confined { &[node, actor] } else { &[node] };
        // the log is read inside the transaction (and left as it was: `finish_batch` logs)
        let log = std::mem::take(&mut self.eph.log);
        let batch = self.run(|tx| {
            // the inverse writes (counters taken as they apply), under the plain session, or the
            // expiring one when what it copies back expires (one memory commit, one expiry:
            // refused while those differ, spec/crdt.md §4.7)
            let mut inverse = Vec::new();
            let mut expires = None;
            for src in &own {
                inverse = ephemeral_undo(tx, &log, at, ts, src)?;
                expires = crate::undo::copy_expiry(&inverse.iter().flat_map(|r| r.copies.iter().copied()).collect())?;
                if expires.is_none() {
                    break;
                }
            }
            if inverse.is_empty() {
                return Ok((Vec::new(), Vec::new()));
            }
            {
                let core = &*tx.core;
                check_acts(core, node, &|_| None, &actor, ts)?;
                for w in writers {
                    for r in &inverse {
                        check_authority(core, *w, &Default::default(), &r.tid, r.ak.as_str(), ts)?;
                    }
                }
            }
            let deltas: Vec<Delta> = inverse.iter().map(|r| Delta { tid: r.tid, ak: r.ak.clone(), fragment: r.fragment.clone(), lo: r.range.lo, hi: r.range.hi, schema: r.schema.clone(), retention: None, expires, frontiers: None, chunks: Vec::new() }).collect();
            // the session the inverse writes were stamped under (a fresh session begun
            // meanwhile, `Core::fresh_session`, takes the next batch)
            let [plain, exp] = &own;
            let nonce = if expires.is_some() { exp } else { plain }.as_session().map(|s| s.nonce).unwrap_or_default();
            let plan = CommitPlan { kind: Kind::Content, ts, actor, form: Form::Session(nonce), creates: Default::default(), purge: Vec::new(), undoes: None, frontier: None, signer: node, blind: draw_blind(&mut *tx.rng), expires: None, restores: false };
            let memory = vec![tx.in_class(true, |tx| crate::engine::write::build_one(tx, plan, deltas))?];
            let logged = super::log_aspects(tx, &memory)?;
            Ok((memory, logged))
        });
        self.eph.log = log;
        let w = self.finish_batch(batch?, Vec::new(), ts, actor, Some(id));
        Ok(w.map_or(Reverted::Superseded, Reverted::Written))
    }

    /// The expiry of the write dotted `d` in ephemeral `(tid, ak)`, for an undo copying its
    /// content (`undo_expiring`): its held commit's delta's; `Some(0)` when it is gone (expired
    /// or superseded: a session's write held nowhere vanished whole, spec/crdt.md §4.7); `None`
    /// for a write no held commit carries that no session wrote (a snapshot's copy: no expiry this
    /// node can tell).
    fn copied_expiry(core: &crate::engine::Core, tid: &Tid, ak: &Ak, d: &Dot) -> Option<u64> {
        if let Some(e) = core.write_expiry(tid, ak, d) {
            return e;
        }
        // no commit holds the write: a plain write of this open's sessions never expires (its
        // commit was covered by a snapshot, or reverted); any other session write whose commit
        // is gone expired or was superseded (spec/crdt.md §4.7)
        match d.src.author().kind() {
            osis_crdt::SourceKind::Session(s) if core.own_plain(&s.nonce) => None,
            osis_crdt::SourceKind::Session(_) => Some(0),
            _ => None,
        }
    }
}

/// The inverse writes of log entry `at` against the current state (spec/crdt.md §4.6), stamped
/// under session `src`.
fn ephemeral_undo(tx: &mut Tx<'_>, log: &Log, at: usize, ts: Ts, src: &Source) -> Result<Vec<Inverse>> {
    let Some(aspects) = log.entries.get(at).map(|e| e.aspects.clone()) else { return Ok(Vec::new()) };
    let nonce = nonce_of(Form::Session(src.as_session().map(|s| s.nonce).unwrap_or_default()));
    let mut out = Vec::new();
    for la in aspects {
        let state = tx.state(&la.tid, &la.ak)?.cloned().unwrap_or_default();
        let w = Writer::new(ts, src.clone(), tx.txn.counter(&la.tid, &la.ak, &nonce)?);
        let undone = Undone { delta: &la.delta, source: &la.src, range: la.range };
        let core = &*tx.core;
        let expiry = |d: &Dot| Engine::copied_expiry(core, &la.tid, &la.ak, d);
        if let Some((delta, r, copies)) = undo_expiring(w, &undone, &state, la.pre.clone(), la.schema.as_deref(), &la.ak, ts.wall_ms().0, &expiry)? {
            out.push(Inverse { tid: la.tid, ak: la.ak, fragment: delta, range: r, copies, schema: la.schema });
        }
    }
    Ok(out)
}
