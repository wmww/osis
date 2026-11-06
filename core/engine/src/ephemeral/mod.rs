//! Ephemeral data (notes/ephemeral.md Local engine): aspects whose key is `ephemeral` or
//! `signal`, always on durable things. Their commits, bodies and every row derived from them live
//! in Core's memory class (the store's overlay), forgotten at restart; everything else is as for
//! durable data. `Engine::write` splits a `Mutation` by key: a commit, durable or memory (plain
//! writes under this open's session, expiring ones under its second session, spec/crdt.md §2.1),
//! or `Clash` when it asks for both. A `delete`'s ephemeral resets go in a memory commit beside its
//! durable one, in one transaction. Signal writes go as relay-only commits (`signal`). Reads come
//! from Core as for any aspect. This module keeps only what belongs to the local write path: the
//! undo log of own batches (`log`), unsent signals and delivered relay-only commits.

mod history;
mod log;
mod signal;

pub use crate::apply::memory::{ENTRY_CHARGE, FACTOR};
pub use log::{LoggedChange, Reverted};
pub use signal::{EphCommit, MAX_DELIVERED};

use crate::engine::write::{AspectMut, check_authority, commit_in};
use crate::engine::{Engine, Mutation, Tx};
use crate::error::{Error, Result};
use crate::events::{BatchId, EphemeralId, Event, Origin};
use osis_base::{Ak, CommitId, Tid, Ts, Value};
use osis_crdt::{Fragment, Source};
use osis_schema::Lifetime;
use std::collections::BTreeMap;

/// The local ephemeral write path's own state (everything else is Core's).
#[derive(Default)]
pub struct Eph {
    /// Own ephemeral-only batches so far: their `EphemeralId`s.
    batches: u64,
    /// Own batches for undo.
    log: log::Log,
    /// Signal writes not yet sent: (thing, aspect, value, `ts`, actor).
    signals: Vec<(Tid, Ak, Value, Ts, Tid)>,
    /// Relay-only commits delivered (`signal`).
    relays: signal::Delivered,
}

/// A batch written by `Engine::write`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Written {
    /// Its commit, else its ephemeral batch.
    pub id: BatchId,
    pub ts: Ts,
}

impl Engine {
    /// This open's session (spec/crdt.md §2.1): the source of its plain writes.
    pub fn ephemeral_session(&self) -> osis_crdt::Session {
        self.core.session
    }

    /// The own sources of this open's writes: its session and its expiring session.
    pub(crate) fn own_sources(&self) -> [Source; 2] {
        [Source::session(self.core.session), Source::session(self.core.expiring)]
    }

    /// Whether changes wait for node-sync: commits marked changed (memory commits applied,
    /// `Core::changed`) or signals not sent (`take_signals`).
    pub fn has_memory_changes(&self) -> bool {
        self.core.changed.as_ref().is_some_and(|c| !c.is_empty()) || !self.eph.signals.is_empty()
    }

    /// Writes `m` as one commit, durable or memory. Two for a `delete` (`Mutation::deleting`) of
    /// a thing with ephemeral state: its ephemeral resets go in a second, memory commit under the
    /// durable one's `ts` (issues/commit-memory-half.md). `Clash` when the ops ask for both
    /// otherwise (a new thing's record is durable, so a `~` write on a thing created in the same
    /// batch is one), or signals beside either. When the commit or any op fails, nothing applies.
    /// `None` when nothing changes.
    pub fn write(&mut self, mut m: Mutation) -> Result<Option<Written>> {
        let node = self.tid();
        let actor = m.actor.unwrap_or(node);
        if m.confined {
            self.check_confined(&m, &actor)?;
        }
        if !m.unchecked {
            let ts = Ts::make(self.now(), 0).unwrap_or_default();
            crate::engine::write::check_acts(&self.core, node, &|t| m.creates.get(t), &actor, ts)?;
        }
        let mut eph_ops: Vec<(Tid, Ak, AspectMut)> = Vec::new();
        for ((tid, ak), a) in std::mem::take(&mut m.aspects) {
            if ak.lifetime().is_durable() {
                m.aspects.insert((tid, ak), a);
            } else {
                eph_ops.push((tid, ak, a));
            }
        }
        if eph_ops.is_empty() {
            // the common durable write: no ephemeral half
            let Some(id) = self.run(|tx| commit_in(tx, m))? else { return Ok(None) };
            let ts = self.core.ix.commits.get(&id).map(|c| c.view.ts).unwrap_or_default();
            return Ok(Some(Written { id: BatchId::Commit(id), ts }));
        }
        // a memory commit's writes and a durable commit's are not one (spec/commits.md §2): only
        // a delete's ephemeral resets may go as a second one
        let durable = m.aspects.keys().next().map(|(t, k)| format!("{t} {k}")).or_else(|| m.creates.keys().next().map(|t| format!("the creation of {t}")));
        let durable = durable.or_else(|| (!(m.purge.is_empty() && m.dead_resets.is_empty() && m.fresh_resets.is_empty() && m.undoes.is_none())).then(|| "the rest".to_string()));
        if let (Some(d), Some((t, k, _))) = (&durable, eph_ops.iter().find(|(t, k, _)| k.lifetime() == Lifetime::Signal || !m.deleting.contains(t))) {
            return Err(Error::Clash(format!("a commit is durable or ephemeral, and this write is both: {t} {k} is ephemeral, {d} is not. Write them as separate commits")));
        }
        let ts = self.core.hlc.next();
        let now = self.now();
        let mut signals = Vec::new();
        for (tid, ak, am) in &eph_ops {
            if self.core.created(tid).is_none() {
                return Err(Error::UnknownThing(*tid));
            }
            check_authority(&self.core, node, &Default::default(), tid, ak.as_str(), ts)?;
            if am.retention.is_some() {
                return Err(Error::Misuse("retention applies to durable writes only"));
            }
            if m.purge.iter().any(|p| matches!(p, osis_commit::PurgeItem::Aspect { tid: t, ak: a } if t == tid && a == ak)) {
                return Err(Error::Misuse("a purge applies to durable aspects only"));
            }
            if ak.lifetime() == Lifetime::Signal {
                match am.ops.as_slice() {
                    [op] if op.path.is_empty() && am.expires.is_none() => match &op.op {
                        osis_crdt::Op::Set(v) => signals.push((*tid, ak.clone(), v.clone())),
                        _ => return Err(Error::Misuse("a signal takes one set at the root")),
                    },
                    _ => return Err(Error::Misuse("a signal takes one set at the root")),
                }
            }
        }
        // a signal is a relay-only commit of its own (spec/sync.md §9)
        if let Some((t, k, _)) = (!signals.is_empty()).then(|| eph_ops.iter().find(|(_, k, _)| k.lifetime() != Lifetime::Signal)).flatten() {
            return Err(Error::Clash(format!("a signal is a commit of its own, and this write also writes {t} {k}. Write them as separate commits")));
        }
        // one memory commit (spec/sync.md §9; spec/crdt.md §2.1: plain writes under this open's
        // session, expiring ones under its second session, so an expired commit leaves no gap in
        // the plain writes' counters)
        let mut batches: BTreeMap<bool, Mutation> = BTreeMap::new();
        for (tid, ak, mut am) in eph_ops {
            if ak.lifetime() == Lifetime::Signal {
                continue;
            }
            let expires = am.expires.or_else(|| am.default_expiry.map(|d| ts.wall_ms().0.saturating_add(d)));
            if expires.is_some_and(|t| t <= now.0) {
                return Err(Error::Misuse("an expiry must be in the future"));
            }
            am.expires = expires;
            am.default_expiry = None;
            let target = batches.entry(expires.is_some()).or_insert_with(|| {
                let mut x = Mutation::new();
                x.act_as(actor);
                x.ts = Some(ts);
                x
            });
            match target.aspects.get_mut(&(tid, ak.clone())) {
                Some(e) => e.ops.extend(am.ops),
                None => {
                    target.aspects.insert((tid, ak), am);
                }
            }
        }
        if let (Some(p), Some(x)) = (batches.get(&false).and_then(|x| x.aspects.keys().next()), batches.get(&true).and_then(|x| x.aspects.keys().next())) {
            return Err(Error::Clash(format!("a commit has one expiry, and this write has two: {} {} does not expire, {} {} does. Write them as separate commits", p.0, p.1, x.0, x.1)));
        }
        let batch = self.run(|tx| {
            let commit = match durable {
                Some(_) => {
                    let mut m = m;
                    m.ts = Some(ts);
                    commit_in(tx, m)?
                }
                None => None,
            };
            let mut memory = Vec::new();
            for x in batches.into_values() {
                // a delta past what one unpaged delta may hold is refused (spec/commits.md §2)
                let c = tx.in_class(true, |tx| commit_in(tx, x)).map_err(|e| match e {
                    Error::Commit(osis_commit::Error::Delta(_)) => Error::Misuse("an ephemeral delta does not fit a blob"),
                    e => e,
                })?;
                memory.extend(c);
            }
            let logged = log_aspects(tx, &memory)?;
            Ok((commit, memory, logged))
        })?;
        Ok(self.finish_batch(batch, signals, ts, actor, None))
    }

    /// Ends a batch written by `write` or a revert (its commits applied): the undo log, the
    /// history and change events. Its id: the commit when it had a durable half, else a fresh
    /// `EphemeralId`; `None` when nothing changed.
    fn finish_batch(&mut self, (commit, memory, logged): (Option<CommitId>, Vec<CommitId>, Vec<log::LogAspect>), signals: Vec<(Tid, Ak, Value)>, ts: Ts, actor: Tid, reverts: Option<BatchId>) -> Option<Written> {
        let node = self.tid();
        let now = self.now();
        let mut changed: Vec<(Tid, Ak)> = logged.iter().map(|a| (a.tid, a.ak.clone())).collect();
        for (t, ak, v) in &signals {
            self.note_signal(t, ak, v, ts, actor);
        }
        changed.sort();
        changed.dedup();
        let id = match commit {
            Some(c) => BatchId::Commit(c),
            None if memory.is_empty() && signals.is_empty() => return None,
            None => {
                self.eph.batches += 1;
                BatchId::Ephemeral(EphemeralId { session: self.core.session.nonce, n: self.eph.batches })
            }
        };
        let cap = self.cfg.ephemeral_history;
        let entries: Vec<(Tid, Ak, BatchId)> = logged.iter().map(|a| (a.tid, a.ak.clone(), id)).collect();
        self.eph.log.push(id, reverts, actor, ts, now, logged, cap);
        self.memory_touched(entries);
        if !(changed.is_empty() && signals.is_empty()) {
            self.core.events.queue(Event::Ephemeral { id, origin: Origin::Local, author: node, actor, ts, received: now, changed, signals });
            self.core.events.flush();
        }
        Some(Written { id, ts })
    }

    /// Tests: an own memory commit of `m` (what `write` makes of a batch's ephemeral half; the
    /// batch's log, drafts and event aside).
    #[doc(hidden)]
    pub fn commit_in_memory(&mut self, mut m: Mutation) -> Result<Option<CommitId>> {
        m.commit_form = false;
        let actor = m.actor.unwrap_or(self.tid());
        let id = self.run(|tx| {
            tx.set_memory();
            commit_in(tx, m)
        })?;
        if let Some(c) = id
            && let Some(h) = self.header(&c)
        {
            let now = self.now();
            self.core.events.queue(Event::Ephemeral { id: BatchId::Commit(c), origin: Origin::Local, author: self.tid(), actor, ts: h.ts, received: now, changed: h.aspects.iter().map(|a| (a.tid, a.ak.clone())).collect(), signals: Vec::new() });
            self.core.events.flush();
        }
        Ok(id)
    }
}

/// The undo log's view of memory commits `ids` just applied: per aspect its delta (the held
/// part) and the pre-write footprint the apply remembered (`undo::remember`).
fn log_aspects(tx: &mut Tx<'_>, ids: &[CommitId]) -> Result<Vec<log::LogAspect>> {
    let mut out = Vec::new();
    for c in ids {
        let Some(m) = tx.core.ix.commits.get(c).cloned() else { continue };
        let h = m.header.clone();
        let src = h.form.own_source(h.author, *c);
        for (ai, a) in h.aspects.iter().enumerate() {
            let mut delta = Fragment::default();
            if let Some(f) = crate::apply::held_fragment(tx, c, ai)? {
                delta.join(f);
            }
            let pre = crate::undo::remembered(tx, c, &a.tid, &a.ak)?.unwrap_or_default();
            let schema = tx.core.schemas.get(a.ak.as_str()).cloned().or_else(|| osis_schema::core_types::is_core_key(a.ak.as_str()).then(|| std::sync::Arc::new(osis_schema::core_schema().clone())));
            out.push(log::LogAspect { tid: a.tid, ak: a.ak.clone(), delta, range: osis_crdt::CounterRange { lo: a.lo, hi: a.hi }, src: src.clone(), pre, schema });
        }
    }
    Ok(out)
}
