//! Ephemeral data (notes/ephemeral.md Local engine): things whose creation record no durable
//! commit holds and aspects whose key is `ephemeral`, `presence` or `signal`, held in memory
//! beside `Core`, never in the store or the journaled indexes. A local ephemeral write is an HLC
//! tick, the ops resolved by `osis_crdt` against the joined state, a join and an event: no store
//! transaction, signature, hash or encryption. `Engine::write` splits a `Mutation` into its
//! durable half (committed first, carrying the creation records of the ephemeral things it
//! persists) and its ephemeral half (applied after; nothing applies if the commit fails).
//! Restart forgets everything here.

use crate::engine::write::{AspectMut, Records, check_authority_with, role_with, run_ops};
use crate::engine::{Engine, Mutation};
use crate::error::{Error, Result};
use crate::events::{Cause, ChangeId, EphemeralId, Event, Origin};
use osis_base::{Ak, CommitId, CreationRecord, Role, Tid, Ts, Value, WallMs};
use osis_crdt::{AnyView, Fragment, Op, Source, Writer};
use osis_schema::Lifetime;
use osis_schema::AspectKey;
use osis_schema::core_types::CREATED;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// An ephemeral thing: its creation record and the batch that made it (`Engine::creation`).
#[derive(Clone, Debug)]
pub struct EphThing {
    pub record: CreationRecord,
    pub ts: Ts,
    pub node: Tid,
    pub actor: Tid,
    pub received: WallMs,
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
        Eph { session, src: Source::commit(CommitId(session)), next: 1, batches: 0, things: HashMap::new(), aspects: HashMap::new(), timers: BTreeMap::new() }
    }

    fn state(&self, tid: &Tid, ak: &Ak) -> Option<&Fragment> {
        self.aspects.get(tid)?.get(ak).map(|a| &a.state)
    }

    fn present(&self, tid: &Tid) -> Vec<Ak> {
        self.aspects.get(tid).map(|m| m.iter().filter(|(_, a)| a.state.present()).map(|(ak, _)| ak.clone()).collect()).unwrap_or_default()
    }
}

/// One resolved ephemeral aspect write of a batch.
struct Resolved {
    tid: Tid,
    ak: Ak,
    delta: Fragment,
    range: (u64, u64),
    expires: Option<u64>,
}

impl Engine {
    /// The ephemeral thing `tid`, if it is one here.
    pub fn ephemeral_thing(&self, tid: &Tid) -> Option<&EphThing> {
        self.eph.things.get(tid)
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
    /// things it persists, notes/ephemeral.md Persistence), then its ephemeral half in memory.
    /// Validated as a whole: when the commit or any op fails, nothing applies. `None` when
    /// nothing changes.
    pub fn write(&mut self, mut m: Mutation) -> Result<Option<Written>> {
        let node = self.tid();
        let actor = m.actor.unwrap_or(node);
        let mut eph_ops: Vec<((Tid, Ak), AspectMut)> = Vec::new();
        for (k, a) in std::mem::take(&mut m.aspects) {
            if a.lifetime.is_durable() {
                m.aspects.insert(k, a);
            } else {
                eph_ops.push((k, a));
            }
        }
        // what the durable half persists: each ephemeral thing it writes or places, with its
        // ephemeral owner chain (the durable set stays closed under owner)
        let mut persisted: BTreeSet<Tid> = BTreeSet::new();
        let roots: BTreeSet<Tid> = m.aspects.keys().map(|k| k.0).chain(m.persist.iter().copied()).collect();
        for t in roots {
            let mut cur = t;
            while !persisted.contains(&cur) {
                let rec = match m.creates.get(&cur) {
                    Some(r) => r.clone(),
                    None => match self.eph.things.get(&cur) {
                        Some(e) => e.record.clone(),
                        None => break,
                    },
                };
                persisted.insert(cur);
                m.creates.insert(cur, rec.clone());
                match rec {
                    CreationRecord::Thing { owner, .. } => cur = owner,
                    CreationRecord::KeyActor { .. } => break,
                }
            }
        }
        let fresh: BTreeMap<Tid, CreationRecord> = m.creates.iter().filter(|(t, _)| !persisted.contains(t)).map(|(t, r)| (*t, r.clone())).collect();
        m.creates.retain(|t, _| persisted.contains(t));
        let durable = !(m.creates.is_empty() && m.aspects.is_empty() && m.purge.is_empty() && m.dead_resets.is_empty() && m.undoes.is_none());
        if eph_ops.is_empty() && fresh.is_empty() && m.free.is_empty() {
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
            for ((tid, ak), am) in &eph_ops {
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
        for ((tid, ak), am) in &eph_ops {
            if am.lifetime == Lifetime::Signal {
                continue;
            }
            let expires = am.expires.or_else(|| am.default_expiry.map(|d| ts.wall_ms().0.saturating_add(d)));
            if expires.is_some_and(|t| t <= now.0) {
                self.eph.next = first;
                return Err(Error::Misuse("an expiry must be in the future"));
            }
            // resolved against the joined state; the ephemeral side alone (borrowed) when no
            // durable delta of the aspect is held
            let durable = match self.durable_state(tid, ak) {
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
                self.eph.next = r.hi;
                resolved.push(Resolved { tid: *tid, ak: ak.clone(), delta, range: (r.lo, r.hi), expires });
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
        let created = !fresh.is_empty();
        for (t, record) in fresh {
            self.eph.things.insert(t, EphThing { record, ts, node, actor, received: now });
        }
        let mut changed = Vec::new();
        for r in resolved {
            let src = self.eph.src.clone();
            let a = self.eph.aspects.entry(r.tid).or_default().entry(r.ak.clone()).or_default();
            let expired = a.expired.clone();
            let strip = !expired.is_empty() && r.delta.holds_dots(&|d| d.src == src && expired.iter().any(|(lo, hi)| *lo <= d.ctr && d.ctr < *hi));
            a.state.join(r.delta);
            if strip {
                a.state.strip(&|d| d.src == src && expired.iter().any(|(lo, hi)| *lo <= d.ctr && d.ctr < *hi));
            }
            if let Some(t) = r.expires {
                a.expiring.entry(t).or_default().push(r.range);
                self.eph.timers.entry(t).or_default().insert((r.tid, r.ak.clone()));
            }
            changed.push((r.tid, r.ak));
        }
        self.free_things(&free, &mut changed);
        let id = match commit {
            Some(c) => ChangeId::Commit(c),
            None if changed.is_empty() && signals.is_empty() && !created => return Ok(None),
            None => {
                self.eph.batches += 1;
                ChangeId::Ephemeral(EphemeralId { session: self.eph.session, n: self.eph.batches })
            }
        };
        if !(changed.is_empty() && signals.is_empty()) {
            self.core.events.queue(Event::Ephemeral { id, origin: Origin::Local, author: node, actor, ts, received: now, changed, signals });
            self.core.events.flush();
        }
        Ok(Some(Written { id, ts }))
    }

    /// The durable state of `(tid, ak)` when a delta of it is held (no store access otherwise).
    fn durable_state(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<Fragment>> {
        if !self.has_durable(tid, ak) {
            return Ok(None);
        }
        let (t, a) = (*tid, ak.clone());
        self.run(|tx| Ok(tx.state(&t, &a)?.cloned()))
    }

    /// Frees ephemeral things deleted by a batch, with the ephemeral things they own: records,
    /// states and timers go, the tids read unknown (notes/ephemeral.md Deletion; nothing syncs
    /// ephemeral things yet, so no holder could revive them).
    fn free_things(&mut self, free: &BTreeSet<Tid>, changed: &mut Vec<(Tid, Ak)>) {
        let mut gone: BTreeSet<Tid> = free.iter().filter(|t| self.eph.things.contains_key(t)).copied().collect();
        if gone.is_empty() {
            return;
        }
        loop {
            let more: Vec<Tid> = self.eph.things.iter().filter(|(t, e)| !gone.contains(t) && matches!(&e.record, CreationRecord::Thing { owner, .. } if gone.contains(owner))).map(|(t, _)| *t).collect();
            if more.is_empty() {
                break;
            }
            gone.extend(more);
        }
        for t in &gone {
            self.eph.things.remove(t);
            if let Some(m) = self.eph.aspects.remove(t) {
                for (ak, a) in m {
                    if a.state.present() {
                        changed.push((*t, ak));
                    }
                }
            }
        }
        changed.sort();
        changed.dedup();
    }

    /// When the next ephemeral expiry is due (corrected wall ms).
    pub fn next_ephemeral_timer(&self) -> Option<u64> {
        self.eph.timers.keys().next().copied()
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
                a.expired.extend(ranges);
                changed.insert((tid, ak));
            }
        }
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
            "/groups" => Some(Value::Set(Default::default())),
            "/members" => None,
            _ => self.eph.state(tid, ak).and_then(Fragment::read),
        })
    }
}
