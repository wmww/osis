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
use crate::engine::write::run_ops;
use osis_crdt::{AnyView, CounterRange, Fragment, Op, PathOp, Stamp, Undone, Writer};
use osis_schema::core_types::{CREATED, GROUP, is_membership_class};
use osis_schema::{AspectKey, Schema};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
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
    /// The ephemeral things it made and deleted (`Making`).
    pub making: Making,
    bytes: usize,
}

/// The ephemeral things a batch brings into being (created, or their deletion reverted) and
/// deletes (their creation reverted: spec/crdt.md §4.6 Undoing a creation). A deleted one keeps
/// its record, so reverting the deletion brings it back; it reads unknown meanwhile.
#[derive(Clone, Debug, Default)]
pub(crate) struct Making {
    pub made: Vec<Tid>,
    pub unmade: Vec<Tid>,
}

impl Making {
    pub fn is_empty(&self) -> bool {
        self.made.is_empty() && self.unmade.is_empty()
    }
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
    /// Its ephemeral aspects, and `/created` of each ephemeral thing it made or deleted.
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
    pub fn push(&mut self, id: ChangeId, reverts: Option<ChangeId>, actor: Tid, ts: Ts, received: WallMs, aspects: Vec<LogAspect>, making: Making, cap: usize) {
        if aspects.is_empty() && making.is_empty() {
            return;
        }
        let bytes = aspects.iter().map(|a| size(&a.delta) + size(&a.pre) + a.ak.as_str().len()).sum::<usize>() + aspects.capacity() * size_of::<LogAspect>() + (making.made.len() + making.unmade.len()) * size_of::<Tid>() + size_of::<Entry>() + 32;
        self.bytes += bytes;
        self.entries.push_back(Entry { id, reverts, actor, ts, received, aspects, making, bytes });
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
            e.making.made.retain(|t| !gone(t));
            e.making.unmade.retain(|t| !gone(t));
            if e.aspects.is_empty() && e.making.is_empty() {
                e.bytes = 0;
            }
            bytes += e.bytes;
        }
        self.entries.retain(|e| !(e.aspects.is_empty() && e.making.is_empty()));
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

/// `/created`, the key a thing's creation and deletion are listed under.
fn created_ak() -> Ak {
    Ak::new(CREATED.ak()).unwrap_or_else(|_| unreachable!("a core key"))
}

impl Engine {
    /// This session's logged own changes, oldest first.
    pub fn ephemeral_log(&self) -> Vec<LoggedChange> {
        let created = created_ak();
        self.eph
            .log
            .entries
            .iter()
            .map(|e| {
                let mut aspects: Vec<(Tid, Ak)> = e.aspects.iter().map(|a| (a.tid, a.ak.clone())).collect();
                aspects.extend(e.making.made.iter().chain(&e.making.unmade).filter(|t| self.eph.things.contains_key(t)).map(|t| (*t, created.clone())));
                LoggedChange { id: e.id, reverts: e.reverts, actor: e.actor, ts: e.ts, received: e.received, aspects }
            })
            .collect()
    }

    /// The newest own ephemeral-only batch touching `scope` that left the undo log, and
    /// whether it was a revert.
    pub fn ephemeral_dropped(&self, scope: &[(Tid, Ak)]) -> Option<(Ts, ChangeId, bool)> {
        scope.iter().filter_map(|k| self.eph.log.dropped.get(k)).max().map(|(ts, id, r)| (*ts, ChangeId::Ephemeral(*id), *r))
    }

    /// The ephemeral keys `Scope::Thing` and `Scope::Group` cover (notes/ephemeral.md API delta,
    /// Undo): every aspect with ephemeral state of an ephemeral thing and its `/created` (what
    /// its creation and deletion touch), and the ephemeral side of a durable thing's `/group`;
    /// not the ephemeral aspects of durable things.
    pub fn ephemeral_scope_keys(&self) -> Vec<(Tid, Ak)> {
        let created = created_ak();
        let mut out: Vec<(Tid, Ak)> = self.eph.things.keys().map(|t| (*t, created.clone())).collect();
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
        // undoing a creation deletes the thing, undoing that brings it back (spec/crdt.md §4.6):
        // the things a commit created are deleted by its undo commit, their ephemeral side here
        let entry = at.and_then(|i| self.eph.log.entries.get(i));
        let is_eph = |t: &&Tid| self.eph.things.contains_key(t);
        let mut del: BTreeSet<Tid> = entry.map(|e| e.making.made.iter().filter(is_eph).copied().collect()).unwrap_or_default();
        let making = Making { made: entry.map(|e| e.making.unmade.iter().filter(is_eph).copied().collect()).unwrap_or_default(), unmade: del.iter().copied().collect() };
        if let ChangeId::Commit(c) = id
            && let Some(m) = self.core.ix.commits.get(&c)
            && let Some(h) = m.header.decoded()
        {
            del.extend(crate::undo::made_by(&h, &m.valid));
        }
        let ts = self.core.hlc.next();
        let first = self.eph.next;
        let resolved = match at {
            Some(i) => self.ephemeral_undo(i, ts, &del),
            None => Ok(Vec::new()),
        };
        let resolved = match resolved.and_then(|mut r| self.unmake_ephemeral(&del, ts, &mut r).map(|()| r)) {
            Ok(r) => r,
            Err(e) => {
                self.eph.next = first;
                return Err(e);
            }
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
        if commit.is_none() && resolved.is_empty() && making.is_empty() {
            self.eph.next = first;
            return Ok(Reverted::Superseded);
        }
        let ts = match commit {
            Some(c) => self.core.ix.commits.get(&c).map(|m| m.view.ts).unwrap_or(ts),
            None => ts,
        };
        let w = self.apply_ephemeral(commit, resolved, Default::default(), Vec::new(), making, ts, actor, Some(id));
        Ok(w.map_or(Reverted::Superseded, Reverted::Written))
    }

    /// The inverse writes of log entry `at` against the current state (spec/crdt.md §4.6), but
    /// for the aspects of `del` (deleted whole instead).
    fn ephemeral_undo(&mut self, at: usize, ts: Ts, del: &BTreeSet<Tid>) -> Result<Vec<Resolved>> {
        let Some(aspects) = self.eph.log.entries.get(at).map(|e| e.aspects.clone()) else { return Ok(Vec::new()) };
        let undoers = self.eph.log.undoers();
        let src = self.eph.src.clone();
        let mut out = Vec::new();
        for la in aspects.into_iter().filter(|a| !del.contains(&a.tid)) {
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
                out.push(Resolved { tid: la.tid, ak: la.ak, delta, range: (r.lo, r.hi), expires: None, presence: false, log: Some((pre, la.schema)) });
            }
        }
        Ok(out)
    }

    /// `delete`'s ephemeral writes for each of `del` (spec/crdt.md §4.6 Undoing a creation):
    /// its ephemeral aspects reset and its entries removed from the ephemeral side of every
    /// `/group` listing it, resolved against the ephemeral side after what `out` already writes
    /// there and joined into it.
    fn unmake_ephemeral(&mut self, del: &BTreeSet<Tid>, ts: Ts, out: &mut Vec<Resolved>) -> Result<()> {
        if del.is_empty() {
            return Ok(());
        }
        let mut ops: BTreeMap<(Tid, Ak), Vec<PathOp>> = BTreeMap::new();
        for x in del {
            for (ak, a) in self.eph.aspects.get(x).into_iter().flatten() {
                if a.state.present() && ak.as_str() != CREATED.ak() && !is_membership_class(ak.as_str()) {
                    ops.entry((*x, ak.clone())).or_default().push(PathOp { path: Vec::new(), op: Op::RemoveAspect });
                }
            }
        }
        for (g, (items, subs)) in &self.eph.defs {
            let v = super::place::unplace_ops(items, subs, del);
            let gak = self.eph.aspects.get(g).and_then(|m| m.keys().find(|k| k.as_str() == GROUP.ak()));
            if let Some(gak) = gak.filter(|_| !del.contains(g) && !v.is_empty()) {
                ops.entry((*g, gak.clone())).or_default().extend(v);
            }
        }
        let core = Arc::new(osis_schema::core_schema().clone());
        for ((tid, ak), ops) in ops {
            let Some(a) = self.eph.aspects.get(&tid).and_then(|m| m.get(&ak)) else { continue };
            let presence = a.presence;
            let at = out.iter().position(|r| r.tid == tid && r.ak == ak);
            let mut state = a.state.clone();
            if let Some(r) = at.and_then(|i| out.get(i)) {
                state.join(r.delta.clone());
            }
            let schema = (ak.as_str() == GROUP.ak()).then(|| core.clone());
            let view = schema.as_ref().and_then(|s| s.view(ak.as_str()));
            let w = Writer::new(ts, self.eph.src.clone(), self.eph.next);
            let res = match &view {
                Some(v) => run_ops(&state, w, &ops, v)?,
                None => run_ops(&state, w, &ops, &AnyView)?,
            };
            let Some((delta, r)) = res else { continue };
            self.eph.next = r.hi;
            let pre = a.state.footprint(&delta);
            match at.and_then(|i| out.get_mut(i)) {
                Some(x) => {
                    x.delta.join(delta);
                    x.range.1 = r.hi;
                    if let Some((p, _)) = &mut x.log {
                        p.join(pre);
                    }
                }
                None => out.push(Resolved { tid, ak, delta, range: (r.lo, r.hi), expires: None, presence, log: Some((pre, schema)) }),
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn log_push(&mut self, id: ChangeId, reverts: Option<ChangeId>, actor: Tid, ts: Ts, received: WallMs, aspects: Vec<LogAspect>, making: Making) {
        let cap = self.cfg.ephemeral_history;
        self.eph.log.push(id, reverts, actor, ts, received, aspects, making, cap);
    }
}
