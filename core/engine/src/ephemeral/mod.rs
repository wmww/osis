//! Ephemeral data (notes/ephemeral.md Local engine): aspects whose key is marked `+`, values or
//! signals, always on durable things. Their commits, bodies and every row derived from them live
//! in Core's memory class (the store's overlay), forgotten at restart; everything else is as for
//! durable data. `Engine::write` splits a `Mutation` by key: a commit, durable or memory (plain
//! writes under this open's session, expiring ones under its second session, spec/crdt.md §2.1),
//! or `Clash` when it asks for both. A `delete` drops its things' ephemeral state here beside its
//! durable commit, writing none. Ephemeral signal writes go as relay-only commits (`signal`). Reads come
//! from Core as for any aspect, and an ephemeral commit is undone as a durable one is (`undo`). This
//! module keeps only what belongs to the local write path: unsent and delivered relay-only commits.

mod signal;

pub use crate::apply::memory::{ENTRY_CHARGE, FACTOR};
pub use crate::undo::Reverted;
pub use signal::{EphCommit, MAX_DELIVERED};

use crate::engine::write::{AspectMut, check_authority, commit_in};
use crate::engine::{Engine, Mutation};
use crate::error::{Error, Result};
use crate::events::{Event, Origin};
use osis_base::{Ak, CommitId, Tid, Ts};
use std::collections::BTreeMap;

/// The local ephemeral write path's own state (everything else is Core's).
#[derive(Default)]
pub struct Eph {
    /// Relay-only commits of own ephemeral signal writes not yet sent.
    signals: Vec<EphCommit>,
    /// Relay-only commits delivered (`signal`).
    relays: signal::Delivered,
}

/// A commit written by `Engine::write` or a revert.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Written {
    pub id: CommitId,
    pub ts: Ts,
}

impl Engine {
    /// This open's session (spec/crdt.md §2.1): the source of its plain writes.
    pub fn ephemeral_session(&self) -> osis_crdt::Session {
        self.core.session
    }

    /// Whether changes wait for node-sync: commits marked changed (memory commits applied,
    /// `Core::changed`) or ephemeral signal writes not sent (`take_signals`).
    pub fn has_memory_changes(&self) -> bool {
        self.core.changed.as_ref().is_some_and(|c| !c.is_empty()) || !self.eph.signals.is_empty()
    }

    /// Writes `m` as one commit, durable or memory. `Clash` when the ops ask for both (a new
    /// thing's record is durable, so a `+` write on a thing created in the same batch is one), or
    /// signals beside either. A delete (`Mutation::deleting`) drops its things' ephemeral state
    /// here with its durable commit and writes none (`retention::memory::drop_things`). When the
    /// commit or any op fails, nothing applies. `None` when nothing changes.
    pub fn write(&mut self, mut m: Mutation) -> Result<Option<Written>> {
        let node = self.me();
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
            if !ak.ephemeral() {
                m.aspects.insert((tid, ak), a);
            } else {
                eph_ops.push((tid, ak, a));
            }
        }
        if eph_ops.is_empty() {
            let deleting = m.deleting.clone();
            let Some((id, dropped)) = self.run(|tx| {
                let Some(id) = commit_in(tx, m)? else { return Ok(None) };
                Ok(Some((id, crate::retention::memory::drop_things(tx, &deleting)?)))
            })?
            else {
                return Ok(None);
            };
            let ts = self.core.ix.commits.get(&id).map(|c| c.view.ts).unwrap_or_default();
            self.dropped_event(id, actor, ts, dropped);
            return Ok(Some(Written { id, ts }));
        }
        // a memory commit's writes and a durable commit's are not one (spec/commits.md §2)
        let durable = m.aspects.keys().next().map(|(t, k)| format!("{t} {k}")).or_else(|| m.creates.keys().next().map(|t| format!("the creation of {t}")));
        let durable = durable.or_else(|| (!(m.purge.is_empty() && m.dead_resets.is_empty() && m.fresh_resets.is_empty() && m.undoes.is_none() && m.deleting.is_empty())).then(|| "the rest".to_string()));
        if let (Some(d), Some((t, k, _))) = (&durable, eph_ops.first()) {
            return Err(Error::Clash(format!("a commit is durable or ephemeral, and this write is both: {t} {k} is ephemeral, {d} is not. Write them as separate commits")));
        }
        let ts = self.core.hlc.next();
        let now = self.now();
        let mut signals = Vec::new();
        for (tid, ak, am) in &eph_ops {
            if !self.core.exists(tid) {
                return Err(Error::UnknownThing(*tid));
            }
            check_authority(&self.core, node, &Default::default(), tid, ak.as_str(), ts)?;
            if am.retention.is_some_and(|r| r.by != osis_base::PurgeBy::Writer || matches!(r.history, Some(osis_schema::History::PurgeOnReplace))) {
                return Err(Error::Misuse("an ephemeral write's retention is `writer`, keeping history or not"));
            }
            if ak.signal() {
                if am.expires.is_some() {
                    return Err(Error::Misuse("an ephemeral signal does not expire"));
                }
                match am.ops.as_slice() {
                    [op] if op.path.is_empty() => match &op.op {
                        osis_crdt::Op::Set(v) => signals.push((*tid, ak.clone(), v.clone())),
                        _ => return Err(Error::Misuse("a signal is fired once per commit: one set at the root")),
                    },
                    _ => return Err(Error::Misuse("a signal is fired once per commit: one set at the root")),
                }
            }
        }
        // an ephemeral signal is a relay-only commit of its own (spec/sync.md §9)
        if !signals.is_empty() {
            if let Some((t, k, _)) = eph_ops.iter().find(|(_, k, _)| !k.signal()) {
                return Err(Error::Clash(format!("an ephemeral signal is a commit of its own, and this write also writes {t} {k}. Write them as separate commits")));
            }
            return self.fire(signals, ts, actor).map(Some);
        }
        // one memory commit (spec/sync.md §9; spec/crdt.md §2.1: plain writes under this open's
        // session, expiring ones under its second session, so an expired commit leaves no gap in
        // the plain writes' counters)
        let mut batches: BTreeMap<bool, Mutation> = BTreeMap::new();
        for (tid, ak, mut am) in eph_ops {
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
        let id = self.run(|tx| {
            let mut memory = None;
            for x in batches.into_values() {
                // a delta past what one unpaged delta may hold is refused (spec/commits.md §2)
                let c = tx.in_class(true, |tx| commit_in(tx, x)).map_err(|e| match e {
                    Error::Commit(osis_commit::Error::Delta(_)) => Error::Misuse("an ephemeral delta does not fit a blob"),
                    e => e,
                })?;
                memory = memory.or(c);
            }
            Ok(memory)
        })?;
        Ok(id.map(|id| self.ephemeral_written(id, actor)))
    }

    /// Ends an own memory commit `id` written by `write` or a revert: its change event.
    pub(crate) fn ephemeral_written(&mut self, id: CommitId, actor: Tid) -> Written {
        let node = self.me();
        let now = self.now();
        let (ts, mut changed) = self.header(&id).map(|h| (h.ts, h.aspects.iter().map(|a| (a.tid, a.ak.clone())).collect::<Vec<_>>())).unwrap_or_default();
        changed.sort();
        changed.dedup();
        if !changed.is_empty() {
            self.core.events.queue(Event::Ephemeral { id, origin: Origin::Local, author: node, actor, ts, received: now, changed });
            self.core.events.flush();
        }
        Written { id, ts }
    }

    /// The change event of the ephemeral aspects durable commit `c` (a delete, an undone
    /// creation) dropped here (`retention::memory::drop_things`).
    pub(crate) fn dropped_event(&mut self, c: CommitId, actor: Tid, ts: Ts, changed: Vec<(Tid, Ak)>) {
        if changed.is_empty() {
            return;
        }
        let now = self.now();
        self.core.events.queue(Event::Ephemeral { id: c, origin: Origin::Local, author: self.me(), actor, ts, received: now, changed });
        self.core.events.flush();
    }

    /// Tests: an own memory commit of `m` (what `write` makes of an ephemeral write).
    #[doc(hidden)]
    pub fn commit_in_memory(&mut self, m: Mutation) -> Result<Option<CommitId>> {
        let actor = m.actor.unwrap_or(self.tid());
        let id = self.run(|tx| {
            tx.set_memory();
            commit_in(tx, m)
        })?;
        if let Some(c) = id
            && let Some(h) = self.header(&c)
        {
            let now = self.now();
            self.core.events.queue(Event::Ephemeral { id: c, origin: Origin::Local, author: self.me(), actor, ts: h.ts, received: now, changed: h.aspects.iter().map(|a| (a.tid, a.ak.clone())).collect() });
            self.core.events.flush();
        }
        Ok(id)
    }
}
