//! Ephemeral data (notes/ephemeral.md Local engine): things whose creation record is held as
//! memory class and aspects whose key is `ephemeral` or `signal`. Their commits, bodies and every
//! row derived from them live in Core's memory class (the store's overlay), forgotten at restart;
//! everything else is as for durable data (issues/eph-unify.md). `Engine::write` splits a
//! `Mutation` by key: a commit, durable or memory (plain writes under this open's session, expiring
//! ones under its second session, spec/crdt.md §2.1), or `Clash` when it asks for both. What only
//! follows a durable commit (a kept thing's memberships leaving `ephemeral_group.0~`, a deleted thing's
//! memory side) goes in a memory commit beside it, in one transaction. Signal writes go as relay-only
//! commits (`signal`). Reads come from Core as for any aspect. This module keeps only what
//! belongs to the local write path: the undo log of own batches (`log`), drafts again, things
//! deleted by undoing their creation, unsent signals and delivered relay-only commits.

mod history;
mod log;
mod membership;
mod signal;

pub use crate::apply::memory::{ENTRY_CHARGE, FACTOR};
pub use log::{LoggedChange, Reverted};
pub(crate) use membership::gains;
pub(crate) use membership::{ITEMS, SUBGROUPS, def_of};
pub use signal::{EphCommit, MAX_DELIVERED};

use crate::engine::write::{AspectMut, Records, check_authority_with, commit_in};
use crate::engine::{Engine, MemoryThing, Mutation, Tx};
use crate::error::{Error, Result};
use crate::events::{BatchId, Diagnostic, DiagnosticKind, EphemeralId, Event, Origin};
use osis_base::{Ak, CommitId, CreationRecord, Role, Tid, Ts, Value, WallMs};
use osis_crdt::{Fragment, Source};
use osis_schema::core_types::{CREATED, GROUP, EPHEMERAL_GROUP};
use osis_schema::{RawKey, Lifetime};
use std::collections::{BTreeMap, BTreeSet};

/// An ephemeral thing as this node holds it: its memory-class record and creation
/// (`Engine::creation`).
#[derive(Clone, Debug)]
pub struct EphThing {
    pub record: CreationRecord,
    pub ts: Ts,
    pub node: Tid,
    pub actor: Tid,
    pub received: WallMs,
    /// Made by this session (not received from another node).
    pub made_here: bool,
    /// Deleted by an undo of its creation (`log::Making`): it reads unknown until that is
    /// reverted.
    pub deleted: bool,
}

/// The local ephemeral write path's own state (everything else is Core's).
#[derive(Default)]
pub struct Eph {
    /// Own ephemeral-only batches so far: their `EphemeralId`s.
    batches: u64,
    /// Own batches for undo.
    log: log::Log,
    /// Drafts again: durable things whose save an undo reverted (`log::Making`), known and
    /// undone like the ephemeral things they were (scope, deletion by undoing their creation:
    /// the flag, like `deleted`) until saved again; in memory, like the draft. At most one entry
    /// per own undone save this session.
    drafts: BTreeMap<Tid, bool>,
    /// Memory things deleted by an undo of their creation, or deleted while a commit on them
    /// also touches a thing not freed (`apply::free`): they read unknown.
    deleted: BTreeSet<Tid>,
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

/// One ephemeral aspect write of a batch, before resolution.
pub(crate) struct EphOp {
    pub tid: Tid,
    pub ak: Ak,
    pub am: AspectMut,
}

impl Eph {
    /// An ephemeral thing, or a draft again (`drafts`).
    fn draft_like(&self, core: &crate::engine::Core, tid: &Tid) -> bool {
        core.ix.held.is_memory(tid) || self.drafts.contains_key(tid)
    }
}

impl Engine {
    /// The ephemeral thing `tid`, if it is one here (its record held as memory class).
    pub fn ephemeral_thing(&self, tid: &Tid) -> Option<EphThing> {
        if !self.core.ix.held.is_memory(tid) {
            return None;
        }
        let record = self.core.created(tid)?.clone();
        let now = self.now();
        let m = self.core.memory.things.get(tid).copied().unwrap_or(MemoryThing { ts: Ts::default(), node: self.tid(), actor: self.tid(), received: now, made_here: false });
        Some(EphThing { record, ts: m.ts, node: m.node, actor: m.actor, received: m.received, made_here: m.made_here, deleted: self.eph.deleted.contains(tid) })
    }

    /// The memory-class record of `t` (`Records` of the local write path).
    pub(crate) fn memory_record(&self, t: &Tid) -> Option<&CreationRecord> {
        self.core.created_for(t, true).filter(|_| self.core.ix.held.is_memory(t))
    }

    /// Whether `tid` is a draft again here (`Eph::drafts`), not deleted.
    pub fn is_draft_again(&self, tid: &Tid) -> bool {
        self.eph.drafts.get(tid) == Some(&false)
    }

    /// This open's session (spec/crdt.md §2.1): the source of its plain writes.
    pub fn ephemeral_session(&self) -> osis_crdt::Session {
        self.core.session
    }

    /// The own sources of this open's writes: its session and its expiring session.
    pub(crate) fn own_sources(&self) -> [Source; 2] {
        [Source::session(self.core.session), Source::session(self.core.expiring)]
    }

    /// Whether `tid` is in some labeled closure here: synced itself, or in a group that is, through
    /// either side of `group.0` (spec/sync.md §3).
    pub fn ephemeral_synced(&self, tid: &Tid) -> bool {
        self.core.syncs(tid) || self.groups_of(tid).iter().any(|g| self.core.syncs(g))
    }

    /// Node-sync kept a label entry of a memory commit on `things` here (made or received): a
    /// holder may have their writes from now on, so a delete of one is resets and tombstones
    /// (`MemorySync::synced`, `freeable`), and its aspects compact only while in a closure. A thing
    /// with no record held gets no row.
    pub fn note_memory_synced(&mut self, things: impl IntoIterator<Item = Tid>) {
        for t in things {
            if self.core.ix.held.is_memory(&t) {
                self.core.memory.synced.insert(t);
            }
        }
    }

    /// Whether a commit on memory thing `t` was ever a label entry here (tests, diagnostics).
    pub fn memory_synced(&self, t: &Tid) -> bool {
        self.core.memory.synced.contains(t)
    }

    /// Whether changes wait for node-sync: commits marked changed (memory commits applied,
    /// `Core::changed`) or signals not sent (`take_signals`).
    pub fn has_memory_changes(&self) -> bool {
        self.core.changed.as_ref().is_some_and(|c| !c.is_empty()) || !self.eph.signals.is_empty()
    }

    /// The reader actor of thing `t` (`Engine::reader_of`), through the records of ephemeral
    /// things up to the nearest durable one.
    pub fn ephemeral_reader(&self, t: &Tid) -> Tid {
        self.core.reader_of(t)
    }

    /// The nearest durable thing up `t`'s chain of ephemeral records (`t` when durable; where the
    /// chain stops otherwise).
    fn nearest_durable(&self, t: &Tid) -> Tid {
        self.core.owner_chain(t).filter_map(|s| s.thing()).find(|x| !self.core.ix.held.is_memory(x)).unwrap_or(*t)
    }

    /// The delete secrets this node holds for delete keys `keys` of an ephemeral commit's part
    /// on `tid` acting for `actor` (spec/crypto.md §7): those of the chain of `tid`'s nearest
    /// durable thing.
    pub fn ephemeral_delete_secrets_for(&self, tid: &Tid, actor: &Tid, keys: &[osis_commit::DeleteKey]) -> Vec<(u8, osis_crypto::DeleteSecret)> {
        let thing = self.core.delete_chain(&self.nearest_durable(tid));
        let author = self.core.delete_chain(actor);
        keys.iter().filter_map(|k| crate::engine::Core::delete_secret(k.level, &k.key, &thing, &author).map(|d| (k.level, d))).collect()
    }

    /// Writes `m` as one commit: durable (with the creation records of the ephemeral things it
    /// persists and their memberships made durable, spec/data-model.md §1, §8) or memory. Two
    /// when the durable one does something in memory nobody asked for (`ephemeral_group.0~` resets,
    /// `delete`'s ephemeral ones): a second, memory commit under its `ts`
    /// (issues/commit-memory-half.md). `Clash` when the ops ask for both, or signals beside either.
    /// When the commit or any op fails, nothing applies. `None` when nothing changes.
    pub fn write(&mut self, mut m: Mutation) -> Result<Option<Written>> {
        let node = self.tid();
        let actor = m.actor.unwrap_or(node);
        if m.confined {
            self.check_confined(&m, &actor)?;
        }
        if !m.unchecked {
            let ts = Ts::make(self.now(), 0).unwrap_or_default();
            crate::engine::write::check_acts(&self.core, node, &|t| m.creates.get(t).or_else(|| self.memory_record(t)), &actor, ts)?;
        }
        let mut eph_ops: Vec<EphOp> = Vec::new();
        let mut gops: Vec<(Tid, AspectMut)> = Vec::new();
        for ((tid, ak), a) in std::mem::take(&mut m.aspects) {
            let group = ak.as_str() == GROUP.ak();
            if ak.as_str() == EPHEMERAL_GROUP.ak() {
                return Err(Error::Misuse("ephemeral memberships are written through group ops only"));
            } else if group {
                gops.push((tid, a));
            } else if ak.lifetime().is_durable() {
                m.aspects.insert((tid, ak), a);
            } else {
                eph_ops.push(EphOp { tid, ak, am: a });
            }
        }
        // what the durable half persists: each ephemeral thing it writes, persists or adds to a group
        // durably, with its ephemeral owner chain (the durable set stays closed under owner),
        // and the groups its ephemeral memberships convert into
        let plan = self.membership_plan(&m, gops)?;
        let gak = membership::group_ak()?;
        for (g, am) in plan.durable {
            m.aspects.insert((g, gak.clone()), am);
        }
        // a memory commit's writes and a durable commit's are not one (spec/commits.md §2): only
        // what follows the durable commit may go as a second one
        let asked = eph_ops.iter().find(|o| o.ak.lifetime() == Lifetime::Signal || !m.free.contains(&o.tid)).map(|o| format!("{} {}", o.tid, o.ak)).or(plan.asked.map(|g| format!("the members of {g}")));
        if let (Some(a), Some(((t, k), _))) = (&asked, m.aspects.iter().next()) {
            return Err(Error::Clash(format!("a commit is durable or ephemeral, and this write is both: {a} is ephemeral, {t} {k} is not. Write them as separate commits")));
        }
        eph_ops.extend(plan.eph);
        let refused = plan.refused;
        m.synced.extend(plan.converted);
        let persisted = plan.persisted;
        // the drafts this batch saves: ephemeral things made before it that it persists, and
        // drafts again it writes durably
        let mut saved = plan.saved;
        for t in &persisted {
            if !m.creates.contains_key(t)
                && let Some(r) = self.memory_record(t)
            {
                m.creates.insert(*t, r.clone());
                saved.insert(*t);
            }
        }
        let fresh: BTreeMap<Tid, CreationRecord> = m.creates.iter().filter(|(t, _)| !persisted.contains(t)).map(|(t, r)| (*t, r.clone())).collect();
        // as a commit refuses it: a held record carried again would read as new (an ownerless
        // thing's first admin as in force, though since removed)
        if fresh.keys().any(|t| self.core.created(t).is_some()) {
            return Err(Error::Misuse("thing already exists"));
        }
        // an ownerless thing is a durable thing: its first admin's edge persists it at once
        if fresh.values().any(|r| matches!(r, CreationRecord::Ownerless { .. })) {
            return Err(Error::Misuse("an ownerless thing is created durably"));
        }
        m.creates.retain(|t, _| persisted.contains(t));
        let durable = !(m.creates.is_empty() && m.aspects.is_empty() && m.purge.is_empty() && m.dead_resets.is_empty() && m.fresh_resets.is_empty() && m.undoes.is_none());
        if eph_ops.is_empty() && fresh.is_empty() && m.free.is_empty() && refused.is_empty() && saved.is_empty() {
            // the common durable write: no ephemeral half
            let Some(id) = self.run(|tx| commit_in(tx, m))? else { return Ok(None) };
            let ts = self.core.ix.commits.get(&id).map(|c| c.view.ts).unwrap_or_default();
            return Ok(Some(Written { id: BatchId::Commit(id), ts }));
        }
        let ts = self.core.hlc.next();
        let now = self.now();
        let mut signals = Vec::new();
        {
            let creates = &m.creates;
            let records: Records<'_> = &|t| creates.get(t).or_else(|| fresh.get(t)).or_else(|| self.memory_record(t));
            // a new ephemeral thing needs what its creation would need
            for t in fresh.keys() {
                check_authority_with(&self.core, node, records, t, CREATED.ak(), ts)?;
            }
            for op in &eph_ops {
                let (tid, ak, am) = (&op.tid, &op.ak, &op.am);
                if records(tid).is_none() && self.core.created(tid).is_none() {
                    return Err(Error::UnknownThing(*tid));
                }
                check_authority_with(&self.core, node, records, tid, ak.as_str(), ts)?;
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
        }
        // the ephemeral things this batch frees: deleted, held as memory class and, after the
        // batch's own membership removals, in no labeled closure (a synced one keeps its record and
        // tombstones while held: an older copy elsewhere would revive the values), with the
        // ephemeral things they own
        let removed: BTreeSet<(Tid, Tid)> = eph_ops.iter().filter(|op| op.ak.as_str() == EPHEMERAL_GROUP.ak()).flat_map(|op| op.am.ops.iter().filter_map(|o| membership::member_removal(o).map(|x| (op.tid, x)))).chain(m.aspects.iter().filter(|((_, ak), _)| ak.as_str() == GROUP.ak()).flat_map(|((g, _), am)| am.ops.iter().filter_map(|o| membership::member_removal(o).map(|x| (*g, x))))).collect();
        let free = m.free.clone();
        let gone = self.freeable(&free, &removed);
        // a signal is a relay-only commit of its own (spec/sync.md §9)
        if let Some(op) = (!signals.is_empty()).then(|| eph_ops.iter().find(|o| o.ak.lifetime() != Lifetime::Signal)).flatten() {
            return Err(Error::Clash(format!("a signal is a commit of its own, and this write also writes {} {}. Write them as separate commits", op.tid, op.ak)));
        }
        // one memory commit (spec/sync.md §9; spec/crdt.md §2.1: plain writes under this open's
        // session, expiring ones under its second session, so an expired commit leaves no gap in
        // the plain writes' counters), so a deletion's resets ride with the membership removal that takes
        // the thing out of the closure; writes on things freed go with them (`apply::free` drops a
        // freed thing's parts)
        let mut batches: BTreeMap<bool, Mutation> = BTreeMap::new();
        fn batch(batches: &mut BTreeMap<bool, Mutation>, expiring: bool, actor: Tid, ts: Ts) -> &mut Mutation {
            batches.entry(expiring).or_insert_with(|| {
                let mut x = Mutation::new();
                x.act_as(actor);
                x.ts = Some(ts);
                x
            })
        }
        for op in eph_ops {
            let EphOp { tid, ak, mut am } = op;
            if ak.lifetime() == Lifetime::Signal || gone.contains(&tid) {
                continue;
            }
            let expires = am.expires.or_else(|| am.default_expiry.map(|d| ts.wall_ms().0.saturating_add(d)));
            if expires.is_some_and(|t| t <= now.0) {
                return Err(Error::Misuse("an expiry must be in the future"));
            }
            am.expires = expires;
            am.default_expiry = None;
            let target = batch(&mut batches, expires.is_some(), actor, ts);
            match target.aspects.get_mut(&(tid, ak.clone())) {
                Some(e) => e.ops.extend(am.ops),
                None => {
                    target.aspects.insert((tid, ak), am);
                }
            }
        }
        // their entries leave every `ephemeral_group.0~` listing them (a reset that goes with them
        // otherwise, at a group that stays)
        for (g, ops) in self.remove_freed_members(&gone) {
            let e = batch(&mut batches, false, actor, ts).aspects.entry((g, membership::ephemeral_group_ak()?)).or_insert_with(|| AspectMut { schema: Some(std::sync::Arc::new(osis_schema::core_schema().clone())), ..AspectMut::default() });
            e.ops.extend(ops);
        }
        if let (Some(p), Some(x)) = (batches.get(&false).and_then(|x| x.aspects.keys().next()), batches.get(&true).and_then(|x| x.aspects.keys().next())) {
            return Err(Error::Clash(format!("a commit has one expiry, and this write has two: {} {} does not expire, {} {} does. Write them as separate commits", p.0, p.1, x.0, x.1)));
        }
        // a new thing's record is held at once, whatever its first write's expiry: a memory commit
        // carries it beside its delta
        for (t, r) in fresh.iter().filter(|(t, _)| !gone.contains(t)) {
            batch(&mut batches, false, actor, ts).creates.insert(*t, r.clone());
        }
        // a deleted memory thing not freed at once (kept under a label) is marked deleted like
        // one unmade by an undo: it reads unknown while its record and tombstones stay
        let unmade = free.iter().filter(|t| !gone.contains(t) && self.core.ix.held.is_memory(t)).copied().collect();
        let making = log::Making { made: fresh.keys().filter(|t| !gone.contains(t)).copied().collect(), unmade, saved: saved.into_iter().collect(), ..Default::default() };
        let made_now: BTreeSet<Tid> = fresh.keys().copied().collect();
        // a freed thing's aspects change to absent (their rows go with it)
        let gone_aspects: Vec<(Tid, Ak)> = gone.iter().flat_map(|t| self.core.aspects_of(t).map(|(k, _)| k.clone())).collect();
        let batch = self.run(|tx| {
            let commit = if durable {
                let mut m = m;
                m.ts = Some(ts);
                commit_in(tx, m)?
            } else {
                None
            };
            let mut memory = Vec::new();
            // at most one with writes, the plain one only with records otherwise
            for x in batches.into_values() {
                // a delta past what one unpaged delta may hold is refused (spec/commits.md §2)
                let c = tx.in_class(true, |tx| commit_in(tx, x)).map_err(|e| match e {
                    Error::Commit(osis_commit::Error::Delta(_)) => Error::Misuse("an ephemeral delta does not fit a blob"),
                    e => e,
                })?;
                memory.extend(c);
            }
            if !gone.is_empty() {
                tx.in_class(true, |tx| crate::apply::free::free(tx, &gone))?;
            }
            let logged = log_aspects(tx, &memory)?;
            Ok((commit, memory, logged))
        })?;
        for t in &made_now {
            self.eph.deleted.remove(t);
        }
        // a deleted draft again is no draft any more (`knows` is false until its record is)
        for t in &free {
            self.eph.drafts.remove(t);
        }
        for (item, group) in refused {
            self.report(Diagnostic { kind: DiagnosticKind::MembershipNotSaved, tids: vec![item, group], commit: batch.0, peer: None, detail: "a persisted thing's membership stays ephemeral: this node may not write the group".into() });
        }
        Ok(self.finish_batch(batch, signals, making, &gone, gone_aspects, ts, actor, None))
    }

    /// Ends a batch written by `write` or a revert (its commits applied): drafts and deleted
    /// marks, the undo log, the history and change events. Its id: the commit when it had a
    /// durable half, else a fresh `EphemeralId`; `None` when nothing changed.
    #[allow(clippy::too_many_arguments)]
    fn finish_batch(&mut self, (commit, memory, mut logged): (Option<CommitId>, Vec<CommitId>, Vec<log::LogAspect>), signals: Vec<(Tid, Ak, Value)>, mut making: log::Making, gone: &BTreeSet<Tid>, gone_aspects: Vec<(Tid, Ak)>, ts: Ts, actor: Tid, reverts: Option<BatchId>) -> Option<Written> {
        let node = self.tid();
        let now = self.now();
        let mut changed: Vec<(Tid, Ak)> = logged.iter().map(|a| (a.tid, a.ak.clone())).collect();
        changed.extend(gone_aspects);
        for (t, ak, v) in &signals {
            self.note_signal(t, ak, v, ts, actor);
        }
        for (list, del) in [(&making.unmade, true), (&making.made, false)] {
            for t in list {
                if self.core.ix.held.is_memory(t) {
                    if del {
                        self.eph.deleted.insert(*t);
                    } else {
                        self.eph.deleted.remove(t);
                    }
                }
                if let Some(d) = self.eph.drafts.get_mut(t) {
                    *d = del;
                }
            }
        }
        for t in &making.saved {
            self.eph.drafts.remove(t);
        }
        self.eph.drafts.extend(making.unsaved.iter().map(|t| (*t, false)));
        // `delete` ends a draft again too (an undo of it restores content and memberships, which
        // convert at the next durable write); a freed thing still under a commit that touches
        // a thing not freed reads unknown until it goes (`apply::free`)
        for t in gone {
            self.eph.drafts.remove(t);
            self.eph.deleted.remove(t);
            if self.core.ix.freeing.contains(t) {
                self.eph.deleted.insert(*t);
            }
        }
        for t in gone {
            changed.push((*t, membership::ephemeral_group_ak().unwrap_or_else(|_| unreachable!("a core key"))));
        }
        logged.retain(|a| !gone.contains(&a.tid));
        making.made.retain(|t| !gone.contains(t));
        making.unmade.retain(|t| !gone.contains(t));
        changed.sort();
        changed.dedup();
        let id = match commit {
            Some(c) => BatchId::Commit(c),
            None if memory.is_empty() && signals.is_empty() && making.is_empty() && gone.is_empty() => return None,
            None => {
                self.eph.batches += 1;
                BatchId::Ephemeral(EphemeralId { session: self.core.session.nonce, n: self.eph.batches })
            }
        };
        let cap = self.cfg.ephemeral_history;
        let entries: Vec<(Tid, Ak, BatchId)> = logged.iter().map(|a| (a.tid, a.ak.clone(), id)).collect();
        self.eph.log.push(id, reverts, actor, ts, now, logged, making, cap);
        self.memory_touched(entries);
        if !(changed.is_empty() && signals.is_empty()) {
            self.core.events.queue(Event::Ephemeral { id, origin: Origin::Local, author: node, actor, ts, received: now, changed, signals });
            self.core.events.flush();
        }
        Some(Written { id, ts })
    }

    /// Of `free`, the ephemeral things this node may free at once: held as memory class, never
    /// a label entry here (`MemorySync::synced`: a holder may have its writes, so the resets
    /// must go and the record and tombstones stay until restart, as a durable delete's do) and
    /// in no labeled closure once the batch's removals `removed` (group, member) apply, with the
    /// ephemeral things they own, to a fixpoint.
    fn freeable(&self, free: &BTreeSet<Tid>, removed: &BTreeSet<(Tid, Tid)>) -> BTreeSet<Tid> {
        let synced = |t: &Tid| self.core.syncs(t) || self.core.memory.synced.contains(t) || self.groups_of(t).iter().any(|g| self.core.syncs(g) && !removed.contains(&(*g, *t)));
        let mut gone: BTreeSet<Tid> = free.iter().filter(|t| self.core.ix.held.is_memory(t) && !synced(t)).copied().collect();
        loop {
            let more: Vec<Tid> = gone.iter().flat_map(|t| self.core.ix.held.owned(t)).filter(|x| !gone.contains(x) && self.core.ix.held.is_memory(x) && !synced(x)).copied().collect();
            if more.is_empty() {
                return gone;
            }
            gone.extend(more);
        }
    }

    /// Per group that stays, the removals of `gone` from its `ephemeral_group.0~`.
    fn remove_freed_members(&self, gone: &BTreeSet<Tid>) -> Vec<(Tid, Vec<osis_crdt::PathOp>)> {
        if gone.is_empty() {
            return Vec::new();
        }
        self.core.ix.ephemeral_group.iter().filter(|(g, _)| !gone.contains(g)).map(|(g, (items, subs))| (*g, membership::removal_ops(items, subs, gone))).filter(|(_, ops)| !ops.is_empty()).collect()
    }

    /// The role this node has on an ephemeral thing: its role on a new thing owned by the
    /// nearest durable thing of its chain (spec/permissions.md §1).
    pub(crate) fn ephemeral_role(&self, tid: &Tid) -> Option<Role> {
        let ts = Ts::make(self.now(), 0).unwrap_or_default();
        crate::engine::write::role_with(&self.core, self.tid(), &|t| self.memory_record(t), tid, ts)
    }

    /// The value of a core aspect of an ephemeral thing (`Engine::get`): what its memory-class
    /// record gives, since no `created.0` or `roles.0` state is held for it.
    pub(crate) fn ephemeral_core_value(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<Option<Value>>> {
        let Some(th) = self.ephemeral_thing(tid) else { return Ok(None) };
        Ok(Some(match ak.as_str() {
            "created.0" => Some(th.record.to_value()),
            "roles.0" => None,
            _ => return Ok(None),
        }))
    }

    /// The read value of `ephemeral_group.0~` of `tid`: the group its items and subgroups make (its
    /// adds carry no presence of the struct).
    pub(crate) fn ephemeral_group_value(&self, tid: &Tid) -> Option<Value> {
        self.core.ix.ephemeral_group.get(tid).map(|(items, subgroups)| EPHEMERAL_GROUP.encode(&osis_schema::core_types::Group { items: items.clone(), subgroups: subgroups.clone() }))
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
