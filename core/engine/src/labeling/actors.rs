//! Actors, entitlement and closure (spec/sync.md §2, §3): a thing's reader actor (the thing if it
//! has secrets of its own, else its owner), who may read it, a group's closure and its labels.

use crate::engine::{Core, Engine};
use crate::error::Result;
use osis_base::{CreationRecord, LabelId, Role, Tid};
use osis_label::{Address, ClaimSet, Step, StepId};
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Owner chains end at a key actor within `MAX_OWNER_DEPTH` links (spec/permissions.md §1).
const MAX_CHAIN: usize = osis_base::format::MAX_OWNER_DEPTH + 1;

/// A label of a group as its `/label` records it (spec/sync.md §2).
#[derive(Clone, Debug)]
pub struct GroupLabel {
    pub group: Tid,
    pub id: LabelId,
    pub index: u64,
    /// Steps by ID with their claim sets when recorded.
    pub steps: BTreeMap<StepId, (Step, Option<ClaimSet>)>,
    pub servers: Vec<Address>,
    pub replaced: bool,
}

impl GroupLabel {
    /// The tips of the step tree (the newest step of each branch).
    pub fn tips(&self) -> Vec<StepId> {
        let parents: BTreeSet<StepId> = self.steps.values().filter_map(|(s, _)| s.prev).collect();
        self.steps.keys().filter(|k| !parents.contains(k)).copied().collect()
    }

    /// The step's child on the label's tree, if recorded (the first by ID when forked).
    pub fn child_of(&self, id: &StepId) -> Option<&Step> {
        self.steps.values().map(|(s, _)| s).find(|s| s.prev == Some(*id))
    }
}

impl Core {
    /// The reader actor of `t`, the projection key of its deltas: `t` with secrets of its own,
    /// else the nearest owner-chain actor that has them (a key actor is its own).
    pub fn reader_of(&self, t: &Tid) -> Tid {
        // the actor whose secrets `t`'s derive from, up the owner chain
        self.secret_actor(t).unwrap_or(*t)
    }

    /// The actor whose secrets `t`'s derive from: up the owner chain to a thing with secrets of
    /// its own or a key actor.
    pub fn secret_actor(&self, t: &Tid) -> Option<Tid> {
        let mut cur = *t;
        for _ in 0..MAX_CHAIN {
            if self.own_keys.contains(&cur) || cur == self.id.tid() {
                return Some(cur);
            }
            match self.created(&cur)? {
                CreationRecord::Thing { owner, .. } => cur = *owner,
                CreationRecord::KeyActor { .. } => return Some(cur),
            }
        }
        None
    }

    /// Whether actor `x` may read thing `t` now: `t`'s secrets derive from `x`'s, or `x` holds
    /// read or above on the actor they derive from (spec/sync.md §3, entitlement).
    pub fn may_read(&self, x: &Tid, t: &Tid) -> bool {
        let Some(a) = self.secret_actor(t) else { return false };
        let mut cur = a;
        for _ in 0..MAX_CHAIN {
            if cur == *x {
                return true;
            }
            match self.created(&cur) {
                Some(CreationRecord::Thing { owner, .. }) => cur = *owner,
                _ => break,
            }
        }
        let ts = osis_base::Ts::make(self.now(), 0).unwrap_or_default();
        crate::engine::write::role_of(self, x, &a, ts) >= Some(Role::Read)
    }
}

impl Engine {
    /// A group's actor (spec/sync.md §3): the group if it has secrets of its own, else its
    /// owner.
    pub fn group_actor(&self, g: &Tid) -> Tid {
        self.core.reader_of(g)
    }

    /// Whether actor `x` may read thing `t` (entitlement, spec/sync.md §3).
    pub fn may_read(&self, x: &Tid, t: &Tid) -> bool {
        self.core.may_read(x, t)
    }

    /// The things of a group's closure: the group and every thing whose `/groups` holds it.
    /// The same `Arc` while it does not change (`Groups::closures`).
    pub fn closure(&self, g: &Tid) -> std::sync::Arc<BTreeSet<Tid>> {
        self.core.groups.closure(g)
    }

    /// Things with a `/label` held.
    pub fn labeled_groups(&self) -> Vec<Tid> {
        self.core.labeled.iter().copied().collect()
    }

    /// The labels `/label` of `g` records, replaced ones included; records that do not parse
    /// are skipped.
    pub fn group_labels(&mut self, g: &Tid) -> Result<Vec<GroupLabel>> {
        Ok(self.labels_of(g).iter().map(|l| (**l).clone()).collect())
    }

    /// `group_labels`, shared: decoded once per write of the `/label` (`Core::labels`).
    pub fn labels_of(&mut self, g: &Tid) -> Vec<Arc<GroupLabel>> {
        if self.core.created(g).is_none() {
            return Vec::new();
        }
        if let Some(v) = self.core.labels.get(g).cloned() {
            #[cfg(debug_assertions)]
            assert_eq!(format!("{:?}", self.decode_labels(g)), format!("{v:?}"), "labels_of({g}) cached");
            return v;
        }
        let out = self.decode_labels(g);
        self.core.labels.insert(*g, out.clone());
        out
    }

    fn decode_labels(&mut self, g: &Tid) -> Vec<Arc<GroupLabel>> {
        let Ok(Some(labels)) = self.get_typed(g, &ct::LABEL) else { return Vec::new() };
        let mut out = Vec::new();
        for (id, l) in labels {
            let Ok(steps) = osis_label::label_steps(&l) else { continue };
            out.push(Arc::new(GroupLabel { group: *g, id, index: l.index, steps, servers: l.servers, replaced: l.replaced }));
        }
        out
    }
}
