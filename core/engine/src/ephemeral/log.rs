//! The in-memory undo log of own ephemeral batches (notes/ephemeral.md Local engine, Undo): per
//! batch its deltas and the pre-batch state of the positions they touched (`footprint`, O(change)),
//! captured at write time. A revert writes the inverse (spec/crdt.md §4.6) against the current
//! state as a new ephemeral batch. Bounded by `Config::ephemeral_history` bytes: past it the
//! oldest entries go, and an ephemeral-only batch dropped so is remembered per aspect (newest
//! only) so undo reports it instead of reaching past it.

use super::{Resolved, Written};
use crate::engine::{Engine, Mutation};
use crate::error::{Error, Result};
use crate::events::{ChangeId, EphemeralId};
use osis_base::{Ak, Tid, Ts, WallMs};
use osis_crdt::{AnyView, CounterRange, Fragment, Stamp, Undone, Writer};
use osis_schema::core_types::GROUP;
use osis_schema::{AspectKey, Schema};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

/// One aspect of a logged batch.
#[derive(Clone, Debug)]
pub(super) struct LogAspect {
    pub tid: Tid,
    pub ak: Ak,
    pub delta: Fragment,
    pub range: CounterRange,
    /// The touched positions before the batch (`Fragment::footprint`).
    pub pre: Fragment,
    pub schema: Option<Arc<Schema>>,
}

#[derive(Clone, Debug)]
pub(super) struct Entry {
    pub id: ChangeId,
    pub reverts: Option<ChangeId>,
    pub actor: Tid,
    pub ts: Ts,
    pub received: WallMs,
    pub aspects: Vec<LogAspect>,
    bytes: usize,
}

/// A logged own change, as the commit query lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoggedChange {
    /// The batch: its commit when it had a durable half.
    pub id: ChangeId,
    /// The change it reverts.
    pub reverts: Option<ChangeId>,
    pub actor: Tid,
    pub ts: Ts,
    pub received: WallMs,
    /// Its ephemeral aspects.
    pub aspects: Vec<(Tid, Ak)>,
}

/// What a revert did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reverted {
    Written(Written),
    /// Nothing to write: everything it wrote was superseded since.
    Superseded,
    /// The ephemeral batch left the log (`Config::ephemeral_history`).
    Compacted,
}

#[derive(Default)]
pub(super) struct Log {
    entries: VecDeque<Entry>,
    bytes: usize,
    /// Per aspect the newest ephemeral-only batch dropped from the log touching it, and
    /// whether it was a revert.
    dropped: HashMap<(Tid, Ak), (Ts, EphemeralId, bool)>,
}

fn size(f: &Fragment) -> usize {
    f.approx_bytes()
}

/// Whether `c` is in effect among the logged changes (`undo::in_effect`).
fn in_effect(c: &ChangeId, undoers: &BTreeMap<ChangeId, Vec<ChangeId>>) -> bool {
    crate::undo::in_effect(c, undoers)
}

impl Log {
    /// Logs a batch, then drops the oldest entries past `cap` bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn push(&mut self, id: ChangeId, reverts: Option<ChangeId>, actor: Tid, ts: Ts, received: WallMs, aspects: Vec<LogAspect>, cap: usize) {
        if aspects.is_empty() {
            return;
        }
        let bytes = aspects.iter().map(|a| size(&a.delta) + size(&a.pre) + a.ak.as_str().len()).sum::<usize>() + aspects.capacity() * size_of::<LogAspect>() + size_of::<Entry>() + 32;
        self.bytes += bytes;
        self.entries.push_back(Entry { id, reverts, actor, ts, received, aspects, bytes });
        while self.bytes > cap {
            let Some(e) = self.entries.pop_front() else { break };
            self.bytes -= e.bytes;
            if let ChangeId::Ephemeral(x) = e.id {
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

    pub fn find(&self, id: &ChangeId) -> Option<usize> {
        self.entries.iter().position(|e| e.id == *id)
    }

    /// Forgets everything about freed things.
    pub fn forget(&mut self, gone: &dyn Fn(&Tid) -> bool) {
        self.dropped.retain(|k, _| !gone(&k.0));
        let mut bytes = 0;
        for e in &mut self.entries {
            e.aspects.retain(|a| !gone(&a.tid));
            if e.aspects.is_empty() {
                e.bytes = 0;
            }
            bytes += e.bytes;
        }
        self.entries.retain(|e| !e.aspects.is_empty());
        self.bytes = bytes;
    }

    fn undoers(&self) -> BTreeMap<ChangeId, Vec<ChangeId>> {
        let mut out: BTreeMap<ChangeId, Vec<ChangeId>> = BTreeMap::new();
        for e in &self.entries {
            if let Some(t) = e.reverts {
                out.entry(t).or_default().push(e.id);
            }
        }
        out
    }

    /// Whether undo may step back through the write stamped `s` into `(tid, ak)` (spec/crdt.md
    /// §4.6, `Undone::restored`): written by a logged revert in effect, with every logged change
    /// of the aspect after entry `after` out of effect.
    fn restored(&self, s: &Stamp, src: &osis_crdt::Source, tid: &Tid, ak: &Ak, after: usize, undoers: &BTreeMap<ChangeId, Vec<ChangeId>>) -> bool {
        if s.dot.src != *src {
            return false;
        }
        let touches = |e: &Entry| e.aspects.iter().any(|a| a.tid == *tid && a.ak == *ak);
        let Some(by) = self.entries.iter().find(|e| e.aspects.iter().any(|a| a.tid == *tid && a.ak == *ak && a.range.contains(s.dot.ctr))) else { return false };
        by.reverts.is_some() && in_effect(&by.id, undoers) && self.entries.iter().skip(after + 1).filter(|e| touches(e)).all(|e| e.reverts.is_some() || !in_effect(&e.id, undoers))
    }
}

impl Engine {
    /// This session's logged own changes, oldest first.
    pub fn ephemeral_log(&self) -> Vec<LoggedChange> {
        self.eph
            .log
            .entries
            .iter()
            .map(|e| LoggedChange { id: e.id, reverts: e.reverts, actor: e.actor, ts: e.ts, received: e.received, aspects: e.aspects.iter().map(|a| (a.tid, a.ak.clone())).collect() })
            .collect()
    }

    /// The newest own ephemeral-only batch touching `scope` that left the undo log, and
    /// whether it was a revert.
    pub fn ephemeral_dropped(&self, scope: &[(Tid, Ak)]) -> Option<(Ts, ChangeId, bool)> {
        scope.iter().filter_map(|k| self.eph.log.dropped.get(k)).max().map(|(ts, id, r)| (*ts, ChangeId::Ephemeral(*id), *r))
    }

    /// The ephemeral keys `Scope::Thing` and `Scope::Group` cover (notes/ephemeral.md API delta,
    /// Undo): every aspect with ephemeral state of an ephemeral thing, and the ephemeral side of
    /// a durable thing's `/group`; not the ephemeral aspects of durable things.
    pub fn ephemeral_scope_keys(&self) -> Vec<(Tid, Ak)> {
        let mut out = Vec::new();
        for (t, m) in &self.eph.aspects {
            let eph = self.eph.things.contains_key(t);
            out.extend(m.keys().filter(|ak| eph || ak.as_str() == GROUP.ak()).map(|ak| (*t, ak.clone())));
        }
        out
    }

    /// Reverts change `id` acting as `actor`: its durable half by an undo commit (a commit's),
    /// its ephemeral half from the log by an ephemeral batch at the same `ts`. One change: the
    /// commit when there is one. An ephemeral change this session never logged (remote, or from
    /// before a restart) is `Misuse`.
    pub fn revert_change(&mut self, id: ChangeId, actor: Tid) -> Result<Reverted> {
        let at = self.eph.log.find(&id);
        if let ChangeId::Ephemeral(e) = id
            && at.is_none()
        {
            return if e.session == self.eph.session && e.n <= self.eph.batches { Ok(Reverted::Compacted) } else { Err(Error::Misuse("no undo log for this ephemeral change (another node's, or from before a restart)")) };
        }
        let ts = self.core.hlc.next();
        let first = self.eph.next;
        let resolved = match at {
            Some(i) => match self.ephemeral_undo(i, ts) {
                Ok(r) => r,
                Err(e) => {
                    self.eph.next = first;
                    return Err(e);
                }
            },
            None => Vec::new(),
        };
        let commit = match id {
            ChangeId::Commit(c) => {
                let mut m = Mutation::new();
                m.act_as(actor).undo(c);
                m.ts = Some(ts);
                match self.commit(m) {
                    Ok(c) => c,
                    Err(e) => {
                        self.eph.next = first;
                        return Err(e);
                    }
                }
            }
            ChangeId::Ephemeral(_) => None,
        };
        if commit.is_none() && resolved.is_empty() {
            self.eph.next = first;
            return Ok(Reverted::Superseded);
        }
        let ts = match commit {
            Some(c) => self.core.ix.commits.get(&c).map(|m| m.view.ts).unwrap_or(ts),
            None => ts,
        };
        let w = self.apply_ephemeral(commit, resolved, Default::default(), Vec::new(), false, ts, actor, Some(id));
        Ok(w.map_or(Reverted::Superseded, Reverted::Written))
    }

    /// The inverse writes of log entry `at` against the current state (spec/crdt.md §4.6).
    fn ephemeral_undo(&mut self, at: usize, ts: Ts) -> Result<Vec<Resolved>> {
        let Some(aspects) = self.eph.log.entries.get(at).map(|e| e.aspects.clone()) else { return Ok(Vec::new()) };
        let undoers = self.eph.log.undoers();
        let src = self.eph.src.clone();
        let mut out = Vec::new();
        for la in aspects {
            let state = match self.joined_state(&la.tid, &la.ak)? {
                Some(s) => s,
                None => self.durable_state(&la.tid, &la.ak)?.unwrap_or_default(),
            };
            let mut w = Writer::new(ts, src.clone(), self.eph.next);
            let log = &self.eph.log;
            let restored = |s: &Stamp| log.restored(s, &src, &la.tid, &la.ak, at, &undoers);
            let undone = Undone { delta: &la.delta, source: &src, range: la.range, restored: &restored };
            let view = la.schema.as_ref().and_then(|s| s.view(la.ak.as_str()));
            let delta = match &view {
                Some(v) => osis_crdt::undo(&mut w, &undone, &state, &la.pre, v)?,
                None => osis_crdt::undo(&mut w, &undone, &state, &la.pre, &AnyView)?,
            };
            if let Some(delta) = delta {
                let r = w.range();
                self.eph.next = r.hi;
                let pre = state.footprint(&delta);
                out.push(Resolved { tid: la.tid, ak: la.ak, delta, range: (r.lo, r.hi), expires: None, log: Some((pre, la.schema)) });
            }
        }
        Ok(out)
    }

    pub(super) fn log_push(&mut self, id: ChangeId, reverts: Option<ChangeId>, actor: Tid, ts: Ts, received: WallMs, aspects: Vec<LogAspect>) {
        let cap = self.cfg.ephemeral_history;
        self.eph.log.push(id, reverts, actor, ts, received, aspects, cap);
    }
}
