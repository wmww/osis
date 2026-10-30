//! Ephemeral data (notes/ephemeral.md Local engine): things whose creation record no durable
//! commit holds and aspects whose key is `ephemeral`, `presence` or `signal`, held in memory
//! beside `Core`, never in the store or the journaled indexes. A local ephemeral write is an HLC
//! tick, the ops resolved by `osis_crdt` against the joined state, a join and an event: no store
//! transaction, signature, hash or encryption. `Engine::write` splits a `Mutation` into its
//! durable half (committed first, carrying the creation records of the ephemeral things it
//! persists) and its ephemeral half (applied after; nothing applies if the commit fails).
//! Restart forgets everything here.

mod log;
mod place;
mod remote;

pub use log::{LoggedChange, Reverted};
pub(crate) use place::{ITEMS, SUBGROUPS};
pub use remote::{COVER_FACTOR, ENTRY_CHARGE, EphCommit, EphIngest, MAX_DELIVERED};

use crate::engine::write::{AspectMut, Records, check_authority_with, role_with, run_ops};
use crate::engine::{Engine, Mutation};
use crate::error::{Error, Result};
use crate::events::{Cause, ChangeId, Diagnostic, DiagnosticKind, EphemeralId, Event, Origin};
use osis_base::{Ak, CommitId, CreationRecord, Role, Tid, Ts, Value, WallMs};
use osis_crdt::{AnyView, CounterRange, Fragment, Op, PathOp, Source, Writer};
use osis_schema::core_types::{CREATED, GROUP};
use osis_schema::{AspectKey, Lifetime, Schema};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

/// An ephemeral thing: its creation record and the batch that made it (`Engine::creation`).
#[derive(Clone, Debug)]
pub struct EphThing {
    pub record: CreationRecord,
    pub ts: Ts,
    pub node: Tid,
    pub actor: Tid,
    pub received: WallMs,
    /// Its `/created` as an ephemeral commit carries it (minted when first sent, or received).
    pub created: Option<Fragment>,
    /// Deleted by an undo of its creation (`log::Making`): it reads unknown until that is
    /// reverted.
    pub deleted: bool,
}

/// One ephemeral aspect: its joined state and which of its writes expire when. Expiry classes
/// are kept as the counter ranges of this session's writes per expiry time (`strip` asks by
/// dot); a class past its time stays in `expired`, so a later join that repeats one of its
/// records is stripped again (spec/crdt.md §4.7).
#[derive(Clone, Debug, Default)]
struct EphAspect {
    state: Fragment,
    expiring: BTreeMap<u64, Vec<(u64, u64)>>,
    expired: Vec<(u64, u64)>,
    /// The own writes alone, kept once a held part of another commit joined (a rebuild starts
    /// from it, `remote::rebuild_aspect`).
    own: Option<Fragment>,
    /// Held ephemeral commit parts on this aspect: (commit, aspect index).
    parts: BTreeSet<(CommitId, usize)>,
    /// A presence aspect (written with that lifetime, or held from presence commits): its own
    /// writes go out as presence commits and it is never compacted.
    presence: bool,
}

/// The engine's ephemeral state.
pub struct Eph {
    session: [u8; 32],
    /// Source of every local ephemeral write: `Commit(session)` (spec/crdt.md §2.1).
    src: Source,
    /// The next session counter (dots are unique per session across aspects).
    next: u64,
    batches: u64,
    things: HashMap<Tid, EphThing>,
    aspects: HashMap<Tid, BTreeMap<Ak, EphAspect>>,
    /// Expiry times and the aspects with writes expiring then.
    timers: BTreeMap<u64, BTreeSet<(Tid, Ak)>>,
    /// The ephemeral side of each `/group` that has one, as read (`groups_of`).
    defs: BTreeMap<Tid, place::Def>,
    /// Own batches for undo.
    log: log::Log,
    /// Drafts again: durable things whose save an undo reverted (`log::Making`), known and
    /// undone like the ephemeral things they were (scope, deletion by undoing their creation:
    /// the flag, like `EphThing.deleted`) until saved again; in memory, like the draft. At most
    /// one entry per own undone save this session.
    drafts: BTreeMap<Tid, bool>,
    /// Synced ephemeral data: unsent writes, held ephemeral commits.
    remote: remote::Remote,
    /// Held ephemeral commits dropped (covered or expired), for the sync layer.
    dropped: Vec<CommitId>,
}

/// A batch written by `Engine::write`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Written {
    pub id: ChangeId,
    pub ts: Ts,
}

impl Eph {
    /// Empty, under a new random session.
    pub fn new(session: [u8; 32]) -> Eph {
        Eph { session, src: Source::commit(CommitId(session)), next: 1, batches: 0, things: HashMap::new(), aspects: HashMap::new(), timers: BTreeMap::new(), defs: BTreeMap::new(), log: log::Log::default(), drafts: BTreeMap::new(), remote: remote::Remote::default(), dropped: Vec::new() }
    }

    fn state(&self, tid: &Tid, ak: &Ak) -> Option<&Fragment> {
        self.aspects.get(tid)?.get(ak).map(|a| &a.state)
    }

    /// An ephemeral thing, or a draft again (`drafts`).
    fn draft_like(&self, tid: &Tid) -> bool {
        self.things.contains_key(tid) || self.drafts.contains_key(tid)
    }

    fn present(&self, tid: &Tid) -> Vec<Ak> {
        self.aspects.get(tid).map(|m| m.iter().filter(|(_, a)| a.state.present()).map(|(ak, _)| ak.clone()).collect()).unwrap_or_default()
    }
}

/// One ephemeral aspect write of a batch, before resolution.
pub(crate) struct EphOp {
    pub tid: Tid,
    pub ak: Ak,
    pub am: AspectMut,
    /// The reset of a placement made durable by this batch: resolved against the ephemeral
    /// side alone.
    pub conversion: bool,
}

/// One resolved ephemeral aspect write of a batch.
pub(crate) struct Resolved {
    tid: Tid,
    ak: Ak,
    delta: Fragment,
    range: (u64, u64),
    expires: Option<u64>,
    /// A write of a presence aspect.
    presence: bool,
    /// For the undo log: the touched positions before the write and the writer's schema.
    log: Option<(Fragment, Option<Arc<Schema>>)>,
}

impl Engine {
    /// The ephemeral thing `tid`, if it is one here.
    pub fn ephemeral_thing(&self, tid: &Tid) -> Option<&EphThing> {
        self.eph.things.get(tid)
    }

    /// Whether `tid` is a draft again here (`Eph::drafts`), not deleted.
    pub fn is_draft_again(&self, tid: &Tid) -> bool {
        self.eph.drafts.get(tid) == Some(&false)
    }

    /// Whether `(tid, ak)` has ephemeral state here.
    pub fn has_ephemeral(&self, tid: &Tid, ak: &Ak) -> bool {
        self.eph.state(tid, ak).is_some()
    }

    /// Whether `(tid, ak)` has ephemeral state and no durable delta held.
    pub fn only_ephemeral(&self, tid: &Tid, ak: &Ak) -> bool {
        self.has_ephemeral(tid, ak) && !self.has_durable(tid, ak)
    }

    /// Whether a durable delta of `(tid, ak)` is held.
    pub fn has_durable(&self, tid: &Tid, ak: &Ak) -> bool {
        self.core.ix.by_aspect.get(&(*tid, ak.clone())).is_some_and(|s| !s.is_empty())
    }

    /// The role this node has on an ephemeral thing: its role on a new thing owned by the
    /// nearest durable thing of its chain (notes/ephemeral.md Rights).
    pub(crate) fn ephemeral_role(&self, tid: &Tid) -> Option<Role> {
        let ts = osis_base::Ts::make(self.now(), 0).unwrap_or_default();
        let things = &self.eph.things;
        role_with(&self.core, self.tid(), &|t| things.get(t).map(|e| &e.record), tid, ts)
    }

    /// AKs with present ephemeral state on `tid`.
    pub(crate) fn ephemeral_aspects(&self, tid: &Tid) -> Vec<Ak> {
        self.eph.present(tid)
    }

    /// The read state of `(tid, ak)` when it has ephemeral state: the join with its durable
    /// state, which is loaded only when a durable delta of it is held. `None` without
    /// ephemeral state.
    pub(crate) fn joined_state(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<Fragment>> {
        let Some(e) = self.eph.state(tid, ak) else { return Ok(None) };
        let mut f = e.clone();
        if self.has_durable(tid, ak) {
            let (t, a) = (*tid, ak.clone());
            if let Some(d) = self.run(|tx| Ok(tx.state(&t, &a)?.cloned()))? {
                f.join(d);
            }
        }
        Ok(Some(f))
    }

    /// Writes `m`: its durable half as one commit (with the creation records of the ephemeral
    /// things it persists and their placements made durable, notes/ephemeral.md Persistence),
    /// then its ephemeral half in memory. Validated as a whole: when the commit or any op
    /// fails, nothing applies. `None` when nothing changes.
    pub fn write(&mut self, mut m: Mutation) -> Result<Option<Written>> {
        let node = self.tid();
        let actor = m.actor.unwrap_or(node);
        let mut eph_ops: Vec<EphOp> = Vec::new();
        let mut gops: Vec<(Tid, AspectMut)> = Vec::new();
        for ((tid, ak), a) in std::mem::take(&mut m.aspects) {
            let group = ak.as_str() == GROUP.ak();
            if a.lifetime.is_durable() {
                if group {
                    gops.push((tid, a));
                } else {
                    m.aspects.insert((tid, ak), a);
                }
            } else if group {
                return Err(Error::Misuse("/group takes ephemeral writes through group ops only"));
            } else {
                eph_ops.push(EphOp { tid, ak, am: a, conversion: false });
            }
        }
        // what the durable half persists: each ephemeral thing it writes, persists or places
        // durably, with its ephemeral owner chain (the durable set stays closed under owner),
        // and the groups its placements convert into
        let plan = self.place_plan(&m, gops)?;
        let gak = place::group_ak()?;
        for (g, am) in plan.durable {
            m.aspects.insert((g, gak.clone()), am);
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
                && let Some(e) = self.eph.things.get(t)
            {
                m.creates.insert(*t, e.record.clone());
                saved.insert(*t);
            }
        }
        let fresh: BTreeMap<Tid, CreationRecord> = m.creates.iter().filter(|(t, _)| !persisted.contains(t)).map(|(t, r)| (*t, r.clone())).collect();
        m.creates.retain(|t, _| persisted.contains(t));
        let durable = !(m.creates.is_empty() && m.aspects.is_empty() && m.purge.is_empty() && m.dead_resets.is_empty() && m.undoes.is_none());
        if eph_ops.is_empty() && fresh.is_empty() && m.free.is_empty() && refused.is_empty() && saved.is_empty() {
            // the common durable write: no ephemeral half
            let Some(id) = self.commit(m)? else { return Ok(None) };
            for t in &persisted {
                self.eph.things.remove(t);
            }
            let ts = self.core.ix.commits.get(&id).map(|c| c.view.ts).unwrap_or_default();
            return Ok(Some(Written { id: ChangeId::Commit(id), ts }));
        }
        let ts = self.core.hlc.next();
        let now = self.now();
        let first = self.eph.next;
        let mut resolved = Vec::new();
        let mut signals = Vec::new();
        {
            let things = &self.eph.things;
            let creates = &m.creates;
            let records: Records<'_> = &|t| creates.get(t).or_else(|| fresh.get(t)).or_else(|| things.get(t).map(|e| &e.record));
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
                if am.lifetime == Lifetime::Signal {
                    match am.ops.as_slice() {
                        [op] if op.path.is_empty() && am.expires.is_none() => match &op.op {
                            Op::Set(v) => signals.push((*tid, ak.clone(), v.clone())),
                            _ => return Err(Error::Misuse("a signal takes one set at the root")),
                        },
                        _ => return Err(Error::Misuse("a signal takes one set at the root")),
                    }
                }
            }
        }
        for op in &eph_ops {
            let (tid, ak, am) = (&op.tid, &op.ak, &op.am);
            if am.lifetime == Lifetime::Signal {
                continue;
            }
            let expires = am.expires.or_else(|| am.default_expiry.map(|d| ts.wall_ms().0.saturating_add(d)));
            if expires.is_some_and(|t| t <= now.0) {
                self.eph.next = first;
                return Err(Error::Misuse("an expiry must be in the future"));
            }
            // a presence value lives while its author is connected (notes/ephemeral.md Presence)
            if am.lifetime == Lifetime::Presence && expires.is_some() {
                self.eph.next = first;
                return Err(Error::Misuse("a presence write takes no expiry"));
            }
            // resolved against the joined state (a conversion's reset against the ephemeral
            // side); the ephemeral side alone (borrowed) when no durable delta is held
            let durable = match if op.conversion { Ok(None) } else { self.durable_state(tid, ak) } {
                Ok(d) => d,
                Err(e) => {
                    self.eph.next = first;
                    return Err(e);
                }
            };
            let empty = Fragment::default();
            let joined;
            let base = match (durable, self.eph.state(tid, ak)) {
                (None, e) => e.unwrap_or(&empty),
                (Some(mut d), e) => {
                    if let Some(e) = e {
                        d.join(e.clone());
                    }
                    joined = d;
                    &joined
                }
            };
            let w = Writer::new(ts, self.eph.src.clone(), self.eph.next);
            let view = am.schema.as_ref().and_then(|s| s.view(ak.as_str()));
            let out = match &view {
                Some(v) => run_ops(base, w, &am.ops, v),
                None => run_ops(base, w, &am.ops, &AnyView),
            };
            let out = match out {
                Ok(o) => o,
                Err(e) => {
                    self.eph.next = first;
                    return Err(e);
                }
            };
            if let Some((delta, r)) = out {
                let log = Some((base.footprint(&delta), am.schema.clone()));
                self.eph.next = r.hi;
                resolved.push(Resolved { tid: *tid, ak: ak.clone(), delta, range: (r.lo, r.hi), expires, presence: am.lifetime == Lifetime::Presence, log });
            }
        }
        let free = std::mem::take(&mut m.free);
        let commit = if durable {
            m.ts = Some(ts);
            match self.commit(m) {
                Ok(c) => c,
                Err(e) => {
                    self.eph.next = first;
                    return Err(e);
                }
            }
        } else {
            None
        };
        // the ephemeral half: cannot fail from here on
        for t in &persisted {
            self.eph.things.remove(t);
        }
        let making = log::Making { made: fresh.keys().copied().collect(), saved: saved.into_iter().collect(), ..Default::default() };
        for (t, record) in fresh {
            self.eph.things.insert(t, EphThing { record, ts, node, actor, received: now, created: None, deleted: false });
            self.note_created(&t);
        }
        for (item, group) in refused {
            self.report(Diagnostic { kind: DiagnosticKind::PlacementNotPersisted, tids: vec![item, group], commit, peer: None, detail: "a persisted thing's placement stays ephemeral: this node may not write the group".into() });
        }
        Ok(self.apply_ephemeral(commit, resolved, free, signals, making, ts, actor, None))
    }

    /// Applies a batch's resolved ephemeral writes (cannot fail), frees `free`, logs the batch
    /// for undo and queues its event. Its id: the commit when it had a durable half.
    #[allow(clippy::too_many_arguments)]
    fn apply_ephemeral(&mut self, commit: Option<CommitId>, resolved: Vec<Resolved>, free: BTreeSet<Tid>, signals: Vec<(Tid, Ak, Value)>, mut making: log::Making, ts: Ts, actor: Tid, reverts: Option<ChangeId>) -> Option<Written> {
        let node = self.tid();
        let now = self.now();
        let mut changed = Vec::new();
        let mut logged = Vec::new();
        let mut written = Vec::new();
        for r in resolved {
            let src = self.eph.src.clone();
            let a = self.eph.aspects.entry(r.tid).or_default().entry(r.ak.clone()).or_default();
            let expired = a.expired.clone();
            let strip = !expired.is_empty() && r.delta.holds_dots(&|d| d.src == src && expired.iter().any(|(lo, hi)| *lo <= d.ctr && d.ctr < *hi));
            if let Some((pre, schema)) = r.log {
                logged.push(log::LogAspect { tid: r.tid, ak: r.ak.clone(), delta: r.delta.clone(), range: CounterRange { lo: r.range.0, hi: r.range.1 }, pre, schema });
            }
            a.presence |= r.presence;
            written.push((r.tid, r.ak.clone(), r.delta.clone(), r.expires, a.presence));
            if let Some(o) = &mut a.own {
                o.join(r.delta.clone());
            }
            a.state.join(r.delta);
            if strip {
                a.state.strip(&|d| d.src == src && expired.iter().any(|(lo, hi)| *lo <= d.ctr && d.ctr < *hi));
            }
            if let Some(t) = r.expires {
                a.expiring.entry(t).or_default().push(r.range);
                self.eph.timers.entry(t).or_default().insert((r.tid, r.ak.clone()));
            }
            if r.ak.as_str() == GROUP.ak() {
                self.refresh_def(&r.tid, &r.ak);
            }
            changed.push((r.tid, r.ak));
        }
        for (t, ak, delta, expires, presence) in &written {
            self.note_written(t, ak, delta, *expires, *presence, actor);
        }
        for (t, ak, v) in &signals {
            self.note_signal(t, ak, v, ts, actor);
        }
        for (list, del) in [(&making.unmade, true), (&making.made, false)] {
            for t in list {
                if let Some(e) = self.eph.things.get_mut(t) {
                    e.deleted = del;
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
        // `delete` ends a draft again too (an undo of it restores content and placements, which
        // convert at the next durable write)
        for t in &free {
            self.eph.drafts.remove(t);
        }
        let gone = self.free_things(&free, ts, &mut changed);
        logged.retain(|a| !gone.contains(&a.tid));
        making.made.retain(|t| !gone.contains(t));
        making.unmade.retain(|t| !gone.contains(t));
        let id = match commit {
            Some(c) => ChangeId::Commit(c),
            None if changed.is_empty() && signals.is_empty() && making.is_empty() => return None,
            None => {
                self.eph.batches += 1;
                ChangeId::Ephemeral(EphemeralId { session: self.eph.session, n: self.eph.batches })
            }
        };
        self.log_push(id, reverts, actor, ts, now, logged, making);
        if !(changed.is_empty() && signals.is_empty()) {
            self.core.events.queue(Event::Ephemeral { id, origin: Origin::Local, author: node, actor, ts, received: now, changed, signals });
            self.core.events.flush();
        }
        Some(Written { id, ts })
    }

    /// The durable state of `(tid, ak)` when a delta of it is held (no store access otherwise).
    pub(crate) fn durable_state(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<Fragment>> {
        if !self.has_durable(tid, ak) {
            return Ok(None);
        }
        let (t, a) = (*tid, ak.clone());
        self.run(|tx| Ok(tx.state(&t, &a)?.cloned()))
    }

    /// Frees ephemeral things deleted by a batch, with the ephemeral things they own: records,
    /// states, timers, undo entries and their ephemeral placements go (resets at `ts`), the tids
    /// read unknown (notes/ephemeral.md Deletion). A thing in a labeled closure keeps its record
    /// and tombstones while held: an older copy elsewhere would revive the values.
    fn free_things(&mut self, free: &BTreeSet<Tid>, ts: Ts, changed: &mut Vec<(Tid, Ak)>) -> BTreeSet<Tid> {
        let mut gone: BTreeSet<Tid> = free.iter().filter(|t| self.eph.things.contains_key(t) && !self.ephemeral_synced(t)).copied().collect();
        if gone.is_empty() {
            return gone;
        }
        loop {
            let more: Vec<Tid> = self.eph.things.iter().filter(|(t, e)| !gone.contains(t) && !self.ephemeral_synced(t) && matches!(&e.record, CreationRecord::Thing { owner, .. } if gone.contains(owner))).map(|(t, _)| *t).collect();
            if more.is_empty() {
                break;
            }
            gone.extend(more);
        }
        for t in &gone {
            self.eph.things.remove(t);
            self.eph.remote.local.remove(t);
            self.eph.remote.presence.retain(|(x, _), _| x != t);
            self.eph.defs.remove(t);
            if let Some(m) = self.eph.aspects.remove(t) {
                for (ak, a) in m {
                    if a.state.present() {
                        changed.push((*t, ak));
                    }
                }
            }
        }
        self.eph.log.forget(&|t| gone.contains(t));
        // their ephemeral placements in groups that stay
        let unplace: Vec<(Tid, Vec<PathOp>)> = self
            .eph
            .defs
            .iter()
            .filter(|(g, _)| !gone.contains(g))
            .map(|(g, (items, subs))| (*g, place::unplace_ops(items, subs, &gone)))
            .filter(|(_, ops)| !ops.is_empty())
            .collect();
        let core = osis_schema::core_schema();
        let view = core.view(GROUP.ak());
        for (g, ops) in unplace {
            let Some((gak, a)) = self.eph.aspects.get_mut(&g).and_then(|m| m.iter_mut().find(|(k, _)| k.as_str() == GROUP.ak())) else { continue };
            let w = Writer::new(ts, self.eph.src.clone(), self.eph.next);
            let out = match &view {
                Some(v) => run_ops(&a.state, w, &ops, v),
                None => run_ops(&a.state, w, &ops, &AnyView),
            };
            if let Ok(Some((delta, r))) = out {
                self.eph.next = r.hi;
                if let Some(o) = &mut a.own {
                    o.join(delta.clone());
                }
                a.state.join(delta);
                let gak = gak.clone();
                self.refresh_def(&g, &gak);
                changed.push((g, gak));
            }
        }
        changed.sort();
        changed.dedup();
        gone
    }

    /// When the next ephemeral expiry is due (corrected wall ms).
    pub fn next_ephemeral_timer(&self) -> Option<u64> {
        let r = &self.eph.remote;
        let keepalive = r.presence_sent.values().min().map(|t| t.saturating_add(osis_base::format::KEEPALIVE_MS));
        [self.eph.timers.keys().next().copied(), r.timers.keys().next().copied(), r.leases.keys().next().copied(), keepalive].into_iter().flatten().min()
    }

    /// Runs the ephemeral expiries due by the corrected clock: their value-carrying writes are
    /// held value-less (spec/crdt.md §4.7), in memory.
    pub fn tick_ephemeral(&mut self) {
        let now = self.now().0;
        let mut changed = BTreeSet::new();
        while let Some(entry) = self.eph.timers.first_entry() {
            if *entry.key() > now {
                break;
            }
            let (t, keys) = entry.remove_entry();
            for (tid, ak) in keys {
                let src = self.eph.src.clone();
                let Some(a) = self.eph.aspects.get_mut(&tid).and_then(|m| m.get_mut(&ak)) else { continue };
                let Some(ranges) = a.expiring.remove(&t) else { continue };
                a.state.strip(&|d| d.src == src && ranges.iter().any(|(lo, hi)| *lo <= d.ctr && d.ctr < *hi));
                if let Some(o) = &mut a.own {
                    o.strip(&|d| d.src == src && ranges.iter().any(|(lo, hi)| *lo <= d.ctr && d.ctr < *hi));
                }
                a.expired.extend(ranges);
                if ak.as_str() == GROUP.ak() {
                    self.refresh_def(&tid, &ak);
                }
                changed.insert((tid, ak));
            }
        }
        changed.extend(self.tick_remote(now));
        self.tick_presence(now);
        if !changed.is_empty() {
            self.core.events.queue(Event::Changed { cause: Cause::Expiry, changed: changed.into_iter().collect() });
            self.core.events.flush();
        }
    }

    /// The value of an ephemeral thing's aspect, synthetic ones included (`Engine::get`).
    pub(crate) fn ephemeral_get(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<Value>> {
        let Some(th) = self.eph.things.get(tid) else { return Ok(None) };
        Ok(match ak.as_str() {
            "/tid" => Some(Value::Tid(*tid)),
            "/created" => Some(th.record.to_value()),
            "/aspects" => Some(Value::Set(self.eph.present(tid).into_iter().map(|a| Value::Str(a.as_str().to_string())).collect())),
            "/groups" => Some(Value::Set(self.groups_of(tid).into_iter().map(Value::Tid).collect())),
            "/members" => None,
            _ => self.eph.state(tid, ak).and_then(Fragment::read),
        })
    }
}
