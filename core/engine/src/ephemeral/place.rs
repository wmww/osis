//! Ephemeral placements (notes/ephemeral.md Step 2 as built, spec/data-model.md §8): a group op
//! whose item stays ephemeral after the batch is an ephemeral write into the group's `placed.0~`
//! (the core ephemeral aspect read with `group.0`); one on a durable item is a durable write of
//! `group.0` and persists the group. When a thing persists, each of its ephemeral placements the node may write becomes a
//! durable add (with the placement's expiry) in the persisting commit and an ephemeral reset
//! removes the ephemeral element; a group it may not write keeps it ephemeral
//! (`PlacementNotPersisted`). A persisting thing that is a group ephemerally gets an empty
//! durable `group.0`.

use super::EphOp;
use crate::engine::write::{AspectMut, Records, check_authority_with};
use crate::engine::{Engine, Mutation, Owned};
use crate::error::{Error, Result};
use osis_base::{Ak, ChainStep, CreationRecord, Tid, Ts, Value};
use osis_crdt::{Fragment, Op, PathOp, PathSeg};
use osis_schema::core_types::{GROUP, Group, PLACED};
use osis_schema::AspectKey;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `group.0` field ids (spec/data-model.md §8).
pub(crate) const ITEMS: u64 = 0;
pub(crate) const SUBGROUPS: u64 = 1;

/// A `group.0` definition: (items, subgroups).
pub(crate) type Def = (BTreeSet<Tid>, BTreeSet<Tid>);

pub(super) fn group_ak() -> Result<Ak> {
    Ak::new(GROUP.ak()).map_err(|_| Error::Misuse("ak"))
}

pub(super) fn placed_ak() -> Result<Ak> {
    Ak::new(PLACED.ak()).map_err(|_| Error::Misuse("ak"))
}

/// A group op: (field, member, add).
fn member_op(op: &PathOp) -> Option<(u64, Tid, bool)> {
    let [PathSeg::Field(f)] = op.path.as_slice() else { return None };
    if *f != ITEMS && *f != SUBGROUPS {
        return None;
    }
    match &op.op {
        Op::Add(Value::Tid(x)) => Some((*f, *x, true)),
        Op::Remove(Value::Tid(x)) => Some((*f, *x, false)),
        _ => None,
    }
}

fn group_op(field: u64, x: Tid, add: bool) -> PathOp {
    let v = Value::Tid(x);
    PathOp { path: vec![PathSeg::Field(field)], op: if add { Op::Add(v) } else { Op::Remove(v) } }
}

/// Removals of the `gone` among a definition's items and subgroups.
pub(super) fn unplace_ops(items: &BTreeSet<Tid>, subs: &BTreeSet<Tid>, gone: &BTreeSet<Tid>) -> Vec<PathOp> {
    let i = items.intersection(gone).map(|t| group_op(ITEMS, *t, false));
    let s = subs.intersection(gone).map(|t| group_op(SUBGROUPS, *t, false));
    i.chain(s).collect()
}

/// The definition a `placed.0~` state holds: its items and subgroups read field by field (an add
/// carries no presence of the struct itself).
pub(crate) fn def_of(f: &Fragment) -> Option<Def> {
    let tids = |field: u64| -> BTreeSet<Tid> {
        match f.at(&[PathSeg::Field(field)]).and_then(|x| x.read()) {
            Some(Value::Set(s)) => s.into_iter().filter_map(|v| if let Value::Tid(t) = v { Some(t) } else { None }).collect(),
            _ => BTreeSet::new(),
        }
    };
    let present = f.present();
    let d = (tids(ITEMS), tids(SUBGROUPS));
    (present || !d.0.is_empty() || !d.1.is_empty()).then_some(d)
}

/// What `delta` newly lists when joined into a group's or placement's state `before`.
pub(crate) fn gains(before: Option<&Fragment>, delta: &Fragment) -> BTreeSet<Tid> {
    let def = |f: &Fragment| def_of(f).unwrap_or_default();
    let (items, subs) = before.map(def).unwrap_or_default();
    let mut after = before.cloned().unwrap_or_default();
    after.join(delta.clone());
    let (i, s) = def(&after);
    i.difference(&items).chain(s.difference(&subs)).copied().collect()
}

/// How a batch's group ops and the placements of the things it persists split.
pub(super) struct Placed {
    /// Ephemeral things (and new ones) the durable half persists, owner chains included.
    pub persisted: BTreeSet<Tid>,
    /// Drafts again (`Eph::drafts`) the durable half writes: saved again (their ephemeral
    /// placements convert like any durable thing's written durably).
    pub saved: BTreeSet<Tid>,
    /// Durable `group.0` writes by group.
    pub durable: BTreeMap<Tid, AspectMut>,
    /// `placed.0~` writes, conversions' resets included.
    pub eph: Vec<EphOp>,
    /// (item, group): placements of a persisted thing kept ephemeral (no write on the group).
    pub refused: Vec<(Tid, Tid)>,
    /// (item, group): item placements made durable by persisting (`Mutation::require_synced`).
    pub converted: Vec<(Tid, Tid)>,
}

impl Engine {
    /// Splits `gops` (the batch's durable-keyed `group.0` writes) and computes what the batch
    /// persists: the things its durable aspects and `persist` name, groups getting a durable
    /// add, and the groups each persisted thing's (or saved draft's) ephemeral placements
    /// convert into, each with its ephemeral owner chain, to a fixpoint.
    pub(super) fn place_plan(&mut self, m: &Mutation, gops: Vec<(Tid, AspectMut)>) -> Result<Placed> {
        let node = self.tid();
        let ts = Ts::make(self.now(), 0).unwrap_or_default();
        // the expiry each ephemeral placement converts with (read once: the states behind them)
        let expiries = self.placement_expiries()?;
        let creates = &m.creates;
        let records: Records<'_> = &|t| creates.get(t).or_else(|| self.memory_record(t));
        let chain = |roots: &BTreeSet<Tid>| {
            let mut out = BTreeSet::new();
            for t in roots {
                for step in osis_base::owner_chain(*t, |x| records(x).map(CreationRecord::owner_link)) {
                    let (ChainStep::Up { thing, .. } | ChainStep::Key(thing) | ChainStep::Ownerless { thing, .. }) = step else { break };
                    if !out.insert(thing) {
                        break;
                    }
                }
            }
            out
        };
        // a confined batch (`Mutation::confine`) converts placements by its actor's rights
        let placer = if m.confined { m.actor.unwrap_or(node) } else { node };
        let may_place = |g: &Tid| check_authority_with(&self.core, placer, records, g, GROUP.ak(), ts).is_ok();
        let gak = group_ak()?;
        let pak = placed_ak()?;
        // member removals of this batch: an unplace beside the persisting write wins over the
        // conversion of that placement
        let removed: BTreeSet<(Tid, u64, Tid)> = gops.iter().flat_map(|(g, am)| am.ops.iter().filter_map(|op| member_op(op).filter(|x| !x.2).map(|(f, x, _)| (*g, f, x)))).collect();
        // the expiry a placement converts with; `None` when it does not convert (unplaced by
        // this batch, or expired with its timer not yet run)
        let converts = |g: &Tid, field: u64, t: &Tid| if removed.contains(&(*g, field, *t)) { None } else { expiries.get(&(*g, field, *t)).copied().unwrap_or(Some(None)) };
        let mut roots: BTreeSet<Tid> = m.aspects.keys().map(|k| k.0).chain(m.persist.iter().copied()).collect();
        // the things whose ephemeral placements convert: the ephemeral things persisted, and
        // every durable thing written durably (a draft again, `Eph::drafts`, or one placed
        // ephemerally while it persisted elsewhere or before a restart); none without defs
        let placed = |persisted: &BTreeSet<Tid>, roots: &BTreeSet<Tid>| -> BTreeSet<Tid> {
            if self.core.ix.placed.is_empty() {
                return BTreeSet::new();
            }
            persisted.iter().filter(|t| self.core.ix.held.is_memory(t)).chain(roots.iter().filter(|t| records(t).is_none())).copied().collect()
        };
        let persisted = loop {
            let persisted = chain(&roots);
            let eph_after = |x: &Tid| records(x).is_some() && !persisted.contains(x);
            let mut grew = false;
            for (g, am) in &gops {
                for op in &am.ops {
                    if let Some((_, x, true)) = member_op(op)
                        && !eph_after(&x)
                    {
                        grew |= roots.insert(*g);
                    }
                }
            }
            for t in &placed(&persisted, &roots) {
                for (g, field) in self.ephemeral_placements(t) {
                    if converts(&g, field, t).is_some() && may_place(&g) {
                        grew |= roots.insert(g);
                    }
                }
            }
            if !grew {
                break persisted;
            }
        };
        let saved: BTreeSet<Tid> = roots.iter().filter(|t| self.eph.drafts.contains_key(t)).copied().collect();
        let converting = placed(&persisted, &roots);
        let eph_after = |x: &Tid| records(x).is_some() && !persisted.contains(x);
        let core_schema = || Some(Arc::new(osis_schema::core_schema().clone()));
        let mut out = Placed { persisted: BTreeSet::new(), saved: BTreeSet::new(), durable: BTreeMap::new(), eph: Vec::new(), refused: Vec::new(), converted: Vec::new() };
        for (g, am) in gops {
            let (mut d, mut e) = (Vec::new(), Vec::new());
            for op in &am.ops {
                let durable = match member_op(op) {
                    Some((_, x, true)) => !eph_after(&x),
                    Some((_, x, false)) => !eph_after(&x) && !eph_after(&g),
                    None => !eph_after(&g),
                };
                // a durable removal also removes an ephemeral placement of the item (a durable
                // thing placed ephemerally: see `placed`)
                let listed = || matches!(member_op(op), Some((f, x, false)) if self.core.ix.placed.get(&g).is_some_and(|(i, s)| if f == ITEMS { i.contains(&x) } else { s.contains(&x) }));
                if !durable || listed() {
                    e.push(op.clone());
                }
                if durable {
                    d.push(op.clone());
                }
            }
            if !e.is_empty() {
                out.eph.push(EphOp { tid: g, ak: pak.clone(), am: AspectMut { ops: e, retention: None, schema: core_schema(), ..am.clone() } });
            }
            if !d.is_empty() {
                out.durable.insert(g, AspectMut { ops: d, ..am });
            }
        }
        for t in &converting {
            for (g, field) in self.ephemeral_placements(t) {
                let exp = converts(&g, field, t);
                if !may_place(&g) {
                    // no write on the group: not even the reset (the timer or the unplace's own
                    // check deals with a placement that does not convert)
                    if exp.is_some() {
                        out.refused.push((*t, g));
                    }
                    continue;
                }
                let reset = EphOp { tid: g, ak: pak.clone(), am: AspectMut { ops: vec![group_op(field, *t, false)], schema: core_schema(), ..AspectMut::default() } };
                let Some(exp) = exp else {
                    out.eph.push(reset);
                    continue;
                };
                let d = out.durable.entry(g).or_insert_with(|| AspectMut { schema: core_schema(), expires: exp, ..AspectMut::default() });
                if d.expires != exp {
                    return Err(Error::Misuse("placements with different expiries persist into one group in one batch: persist them in separate batches"));
                }
                d.ops.push(group_op(field, *t, true));
                if field == ITEMS {
                    out.converted.push((*t, g));
                }
                out.eph.push(reset);
            }
        }
        for t in &converting {
            // a group ephemerally: its (empty) `group.0` persists, its ephemeral items do not;
            // after the conversions, whose expiry it takes: an empty group has no value for
            // expiry to remove (spec/crdt.md §4.7), so it stays a group
            if self.core.ix.placed.contains_key(t) && !self.core.ix.by_aspect.get(&(*t, gak.clone())).is_some_and(|s| !s.is_empty()) {
                let d = out.durable.entry(*t).or_insert_with(|| AspectMut { schema: core_schema(), ..AspectMut::default() });
                d.ops.insert(0, PathOp { path: Vec::new(), op: Op::Set(GROUP.encode(&Group::default())) });
            }
        }
        out.persisted = persisted;
        out.saved = saved;
        Ok(out)
    }

    /// (group, field) of each ephemeral placement of `t`.
    fn ephemeral_placements(&self, t: &Tid) -> Vec<(Tid, u64)> {
        let mut out = Vec::new();
        for (g, (items, subs)) in self.core.ix.placed.iter() {
            if items.contains(t) {
                out.push((*g, ITEMS));
            }
            if subs.contains(t) {
                out.push((*g, SUBGROUPS));
            }
        }
        out
    }

    /// Per ephemeral placement `(group, field, item)`, the expiry it converts with: `Some(None)`
    /// never, `None` already past (its timer has not run yet). With several writes placing it,
    /// the last to go counts: the held expiring memory commits' writes are stripped from the
    /// state in expiry order until the element goes.
    fn placement_expiries(&mut self) -> Result<BTreeMap<(Tid, u64, Tid), Option<Option<u64>>>> {
        let mut out = BTreeMap::new();
        if self.core.ix.placed.is_empty() {
            return Ok(out);
        }
        let pak = placed_ak()?;
        let now = self.now().0;
        let groups: Vec<(Tid, Def)> = self.core.ix.placed.iter().map(|(g, d)| (*g, d.clone())).collect();
        for (g, (items, subs)) in groups {
            let expiring: Vec<(u64, Owned)> = self
                .core
                .ix
                .by_aspect
                .get(&(g, pak.clone()))
                .into_iter()
                .flatten()
                .filter_map(|(_, c)| {
                    let m = self.core.ix.commits.get(c)?;
                    let ai = m.aspect(&g, &pak)?;
                    let t = m.header.aspects.get(ai)?.expires?;
                    Some((t, Owned::of(&m.header, c, ai)?))
                })
                .collect();
            let members = items.iter().map(|t| (ITEMS, *t)).chain(subs.iter().map(|t| (SUBGROUPS, *t)));
            if expiring.is_empty() {
                out.extend(members.map(|(f, t)| ((g, f, t), Some(None))));
                continue;
            }
            let Some(st) = self.state(&g, &pak)? else { continue };
            let holds = |f: &Fragment, field: u64, t: &Tid| f.at(&[PathSeg::Field(field)]).and_then(|x| x.read()).is_some_and(|v| matches!(v, Value::Set(s) if s.contains(&Value::Tid(*t))));
            let mut by_time: BTreeMap<u64, Vec<Owned>> = BTreeMap::new();
            for (t, o) in expiring {
                by_time.entry(t).or_default().push(o);
            }
            for (field, t) in members {
                let mut f = st.clone();
                let mut exp = Some(None);
                for (time, owned) in &by_time {
                    f.strip(&|d| owned.iter().any(|o| o.owns(d)));
                    if !holds(&f, field, &t) {
                        exp = (*time > now).then_some(Some(*time));
                        break;
                    }
                }
                out.insert((g, field, t), exp);
            }
        }
        Ok(out)
    }

    /// Groups containing the thing, transitively, through `group.0` and `placed.0~` (`groups.0`).
    pub fn groups_of(&self, tid: &Tid) -> BTreeSet<Tid> {
        let durable = self.durable_groups_of(tid);
        if self.core.ix.placed.is_empty() {
            return durable;
        }
        let defs = &self.core.ix.placed;
        let mut stack: Vec<Tid> = durable.into_iter().chain(defs.iter().filter(|(_, d)| d.0.contains(tid)).map(|(g, _)| *g)).collect();
        let mut out = BTreeSet::new();
        while let Some(g) = stack.pop() {
            if !out.insert(g) {
                continue;
            }
            stack.extend(self.core.ix.groups.parents_of(&g));
            stack.extend(defs.iter().filter(|(_, d)| d.1.contains(&g)).map(|(p, _)| *p));
        }
        out
    }

    /// What `g` holds, transitively, through `group.0` and `placed.0~`: `groups_of` the other way.
    pub fn closure_placed(&self, g: &Tid) -> BTreeSet<Tid> {
        let mut out = BTreeSet::new();
        let mut stack = vec![*g];
        while let Some(x) = stack.pop() {
            if !out.insert(x) {
                continue;
            }
            stack.extend(self.closure(&x).iter().copied());
            if let Some((items, subs)) = self.core.ix.placed.get(&x) {
                stack.extend(items.iter().chain(subs).copied());
            }
        }
        out
    }

    /// The groups whose `group.0` or `placed.0~` lists the thing directly: (as an item, as a
    /// subgroup). From the in-memory group index, rebuilt from the definitions at open.
    pub fn listed_in(&self, tid: &Tid) -> (BTreeSet<Tid>, BTreeSet<Tid>) {
        let ix = &self.core.ix.groups;
        // a group listing it as an item contains it: `of` is a superset of those
        let mut items: BTreeSet<Tid> = ix.of.get(tid).into_iter().flatten().filter(|g| ix.defs.get(g).is_some_and(|d| d.0.contains(tid))).copied().collect();
        let mut subs: BTreeSet<Tid> = ix.parents_of(tid).collect();
        for (g, d) in self.core.ix.placed.iter() {
            if d.0.contains(tid) {
                items.insert(*g);
            }
            if d.1.contains(tid) {
                subs.insert(*g);
            }
        }
        (items, subs)
    }

    /// Groups containing the thing through `group.0` only (the closure sync uses).
    pub fn durable_groups_of(&self, tid: &Tid) -> BTreeSet<Tid> {
        self.core.ix.groups.of.get(tid).cloned().unwrap_or_default()
    }
}
