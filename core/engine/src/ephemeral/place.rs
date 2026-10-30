//! Ephemeral placements (notes/ephemeral.md Ephemeral placements): `/group` is the one durable
//! aspect with an ephemeral side. A group op whose item stays ephemeral after the batch is an
//! ephemeral write into the group's `/group`; one on a durable item is durable and persists the
//! group. When a thing persists, each of its ephemeral placements the node may write becomes a
//! durable add (with the placement's expiry) in the persisting commit and an ephemeral reset
//! removes the ephemeral element; a group it may not write keeps it ephemeral
//! (`PlacementNotPersisted`). A persisting thing that is a group ephemerally gets an empty
//! durable `/group`.

use super::EphOp;
use crate::engine::write::{AspectMut, Records, check_authority_with};
use crate::engine::{Engine, Mutation};
use crate::error::{Error, Result};
use osis_base::{Ak, Tid, Ts, Value};
use osis_crdt::{Fragment, Op, PathOp, PathSeg};
use osis_schema::core_types::{GROUP, Group};
use osis_schema::{AspectKey, Lifetime};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `/group` field ids (spec/data-model.md §8).
pub(crate) const ITEMS: u64 = 0;
pub(crate) const SUBGROUPS: u64 = 1;

/// A `/group` definition: (items, subgroups).
pub(super) type Def = (BTreeSet<Tid>, BTreeSet<Tid>);

pub(super) fn group_ak() -> Result<Ak> {
    Ak::new(GROUP.ak()).map_err(|_| Error::Misuse("ak"))
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

/// The `/group` definition the ephemeral side holds: its items and subgroups read field by
/// field (an add into a durable group carries no presence of the struct itself).
pub(super) fn def_of(f: &Fragment) -> Option<Def> {
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

/// How a batch's group ops and the placements of the things it persists split.
pub(super) struct Placed {
    /// Ephemeral things (and new ones) the durable half persists, owner chains included.
    pub persisted: BTreeSet<Tid>,
    /// Drafts again (`Eph::drafts`) the durable half writes: saved again, their ephemeral
    /// placements converting like a persisted thing's.
    pub saved: BTreeSet<Tid>,
    /// Durable `/group` writes by group.
    pub durable: BTreeMap<Tid, AspectMut>,
    /// Ephemeral `/group` writes, conversions' resets included.
    pub eph: Vec<EphOp>,
    /// (item, group): placements of a persisted thing kept ephemeral (no write on the group).
    pub refused: Vec<(Tid, Tid)>,
    /// (item, group): item placements made durable by persisting (`Mutation::require_synced`).
    pub converted: Vec<(Tid, Tid)>,
}

impl Engine {
    /// Splits `gops` (the batch's durable-keyed `/group` writes) and computes what the batch
    /// persists: the things its durable aspects and `persist` name, groups getting a durable
    /// add, and the groups each persisted thing's (or saved draft's) ephemeral placements
    /// convert into, each with its ephemeral owner chain, to a fixpoint.
    pub(super) fn place_plan(&self, m: &Mutation, gops: Vec<(Tid, AspectMut)>) -> Result<Placed> {
        let node = self.tid();
        let ts = Ts::make(self.now(), 0).unwrap_or_default();
        let things = &self.eph.things;
        let creates = &m.creates;
        let records: Records<'_> = &|t| creates.get(t).or_else(|| things.get(t).map(|e| &e.record));
        let chain = |roots: &BTreeSet<Tid>| {
            let mut out = BTreeSet::new();
            for t in roots {
                let mut cur = *t;
                while !out.contains(&cur) {
                    let Some(rec) = records(&cur) else { break };
                    out.insert(cur);
                    match rec {
                        osis_base::CreationRecord::Thing { owner, .. } => cur = *owner,
                        osis_base::CreationRecord::KeyActor { .. } => break,
                    }
                }
            }
            out
        };
        let may_place = |g: &Tid| check_authority_with(&self.core, node, records, g, GROUP.ak(), ts).is_ok();
        let gak = group_ak()?;
        // member removals of this batch: an unplace beside the persisting write wins over the
        // conversion of that placement
        let removed: BTreeSet<(Tid, u64, Tid)> = gops.iter().flat_map(|(g, am)| am.ops.iter().filter_map(|op| member_op(op).filter(|x| !x.2).map(|(f, x, _)| (*g, f, x)))).collect();
        // the expiry a placement converts with; `None` when it does not convert (unplaced by
        // this batch, or expired with its timer not yet run)
        let converts = |g: &Tid, field: u64, t: &Tid| if removed.contains(&(*g, field, *t)) { None } else { self.placement_expiry(g, &gak, field, t) };
        let mut roots: BTreeSet<Tid> = m.aspects.keys().map(|k| k.0).chain(m.persist.iter().copied()).collect();
        let drafts = &self.eph.drafts;
        let persisted = loop {
            let persisted = chain(&roots);
            let saved: Vec<Tid> = roots.iter().filter(|t| drafts.contains(t)).copied().collect();
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
            for t in persisted.iter().filter(|t| things.contains_key(t)).chain(&saved) {
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
        let saved: BTreeSet<Tid> = roots.iter().filter(|t| drafts.contains(t)).copied().collect();
        let converting: BTreeSet<Tid> = persisted.iter().filter(|t| things.contains_key(t)).chain(&saved).copied().collect();
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
                if durable { d.push(op.clone()) } else { e.push(op.clone()) }
            }
            if !e.is_empty() {
                out.eph.push(EphOp { tid: g, ak: gak.clone(), am: AspectMut { ops: e, lifetime: Lifetime::Ephemeral, retention: None, ..am.clone() }, conversion: false });
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
                let reset = EphOp { tid: g, ak: gak.clone(), am: AspectMut { ops: vec![group_op(field, *t, false)], schema: core_schema(), lifetime: Lifetime::Ephemeral, ..AspectMut::default() }, conversion: true };
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
            // a group ephemerally: its (empty) `/group` persists, its ephemeral items do not;
            // after the conversions, whose expiry it takes: an empty group has no value for
            // expiry to remove (spec/crdt.md §4.7), so it stays a group
            if self.eph.defs.contains_key(t) && !self.has_durable(t, &gak) {
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
        for (g, (items, subs)) in &self.eph.defs {
            if items.contains(t) {
                out.push((*g, ITEMS));
            }
            if subs.contains(t) {
                out.push((*g, SUBGROUPS));
            }
        }
        out
    }

    /// The expiry of `t`'s ephemeral placement in `field` of `g`: `Some(None)` never, `None`
    /// already past (its timer has not run yet). With several, the last to go counts.
    fn placement_expiry(&self, g: &Tid, gak: &Ak, field: u64, t: &Tid) -> Option<Option<u64>> {
        let Some(a) = self.eph.aspects.get(g).and_then(|m| m.get(gak)) else { return Some(None) };
        if a.expiring.is_empty() {
            return Some(None);
        }
        let src = &self.eph.src;
        let holds = |f: &Fragment| f.at(&[PathSeg::Field(field)]).and_then(|x| x.read()).is_some_and(|v| matches!(v, Value::Set(s) if s.contains(&Value::Tid(*t))));
        let mut f = a.state.clone();
        for (time, ranges) in &a.expiring {
            f.strip(&|d| d.src == *src && ranges.iter().any(|(lo, hi)| *lo <= d.ctr && d.ctr < *hi));
            if !holds(&f) {
                return (*time > self.now().0).then_some(Some(*time));
            }
        }
        Some(None)
    }

    /// Re-reads the ephemeral side of `g`'s `/group` (`gak`; `groups_of`).
    pub(super) fn refresh_def(&mut self, g: &Tid, gak: &Ak) {
        match self.eph.state(g, gak).and_then(def_of) {
            Some(d) => self.eph.defs.insert(*g, d),
            None => self.eph.defs.remove(g),
        };
    }

    /// Groups containing the thing, transitively, through both sides of `/group` (`/groups`):
    /// the union of the durable and the ephemeral definitions (an ephemeral reset of a durable
    /// element, possible only through a raw path op, is not looked into).
    pub fn groups_of(&self, tid: &Tid) -> BTreeSet<Tid> {
        let durable = self.durable_groups_of(tid);
        if self.eph.defs.is_empty() {
            return durable;
        }
        let defs = &self.eph.defs;
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

    /// The groups whose `/group` lists the thing directly, through either side: (as an item,
    /// as a subgroup). From the in-memory group index, rebuilt from the definitions at open.
    pub fn listed_in(&self, tid: &Tid) -> (BTreeSet<Tid>, BTreeSet<Tid>) {
        let ix = &self.core.ix.groups;
        // a group listing it as an item contains it: `of` is a superset of those
        let mut items: BTreeSet<Tid> = ix.of.get(tid).into_iter().flatten().filter(|g| ix.defs.get(g).is_some_and(|d| d.0.contains(tid))).copied().collect();
        let mut subs: BTreeSet<Tid> = ix.parents_of(tid).collect();
        for (g, d) in &self.eph.defs {
            if d.0.contains(tid) {
                items.insert(*g);
            }
            if d.1.contains(tid) {
                subs.insert(*g);
            }
        }
        (items, subs)
    }

    /// Groups containing the thing through durable `/group` state only (the closure sync uses).
    pub fn durable_groups_of(&self, tid: &Tid) -> BTreeSet<Tid> {
        self.core.ix.groups.of.get(tid).cloned().unwrap_or_default()
    }
}
