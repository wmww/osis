//! Actors, entitlement and closure (spec/sync.md §2, §3): a thing's reader actor (the thing if it
//! has secrets of its own, else its first admin), who may read it, a group's closure and its labels.

use crate::engine::{Core, Engine};
use crate::error::Result;
use osis_base::{ChainStep, LabelId, Role, Tid};
use osis_label::{Address, ClaimSet, Step, StepId};
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A label of a group as its `label.0` records it (spec/sync.md §2).
#[derive(Clone, Debug)]
pub struct GroupLabel {
    pub group: Tid,
    pub id: LabelId,
    pub index: u64,
    /// Steps by ID with their claim sets when recorded.
    pub steps: BTreeMap<StepId, (Step, Option<ClaimSet>)>,
    pub hosts: Vec<Address>,
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
    /// The reader actor of `t`, whose read role reads its deltas: `t` with secrets of its own,
    /// else the nearest record-chain actor that has them (a key actor is its own).
    pub fn reader_of(&self, t: &Tid) -> Tid {
        // the actor whose secrets `t`'s derive from, up the record chain
        self.secret_actor(t).unwrap_or(*t)
    }

    /// The actor whose secrets `t`'s derive from: up the record chain to a thing with secrets of
    /// its own or a key actor.
    pub fn secret_actor(&self, t: &Tid) -> Option<Tid> {
        for step in self.record_chain(t) {
            let cur = step.thing()?;
            if self.ix.own_keys.contains(&cur) || cur == self.id.tid() {
                return Some(cur);
            }
            match step {
                ChainStep::Up { .. } => {}
                ChainStep::Key(k) => return Some(k),
                _ => return None,
            }
        }
        None
    }

    /// Whether actor `x` may read thing `t` now: `t`'s secrets derive from `x`'s, or `x` holds
    /// read or above on the actor they derive from (spec/sync.md §3, entitlement).
    pub fn may_read(&self, x: &Tid, t: &Tid) -> bool {
        let Some(a) = self.secret_actor(t) else { return false };
        if self.record_chain(&a).filter_map(|s| s.thing()).any(|c| c == *x) {
            return true;
        }
        let ts = osis_base::Ts::make(self.now(), 0).unwrap_or_default();
        crate::engine::write::role_of(self, x, &a, ts) >= Some(Role::Read)
    }
}

impl Engine {
    /// A group's actor (spec/sync.md §3): the group if it has secrets of its own, else its base
    /// actor.
    pub fn group_actor(&self, g: &Tid) -> Tid {
        self.core.reader_of(g)
    }

    /// Whether actor `x` may read thing `t` (entitlement, spec/sync.md §3).
    pub fn may_read(&self, x: &Tid, t: &Tid) -> bool {
        self.core.may_read(x, t)
    }

    /// The things of a group's closure (spec/sync.md §3): the group and every thing it contains
    /// through `group.0`, transitively through subgroups. The same `Arc` while it does not change
    /// (`Groups::closures`), so node-sync reuses what it derived from it.
    pub fn closure(&self, g: &Tid) -> std::sync::Arc<BTreeSet<Tid>> {
        self.core.ix.groups.closure(g)
    }

    /// Things with a `label.0` state.
    pub fn labeled_groups(&self) -> Vec<Tid> {
        self.core.ix.labeled.iter().copied().collect()
    }

    /// The inbox of actor `a` (spec/sync.md §2): the sync ID its `keys.0` names.
    pub fn inbox(&mut self, a: &Tid) -> Option<LabelId> {
        self.get_typed(a, &ct::KEYS).ok().flatten().and_then(|k| k.inbox).map(|i| i.label)
    }

    /// The inboxes here (spec/sync.md §2): per sync ID, the actors with secrets held here whose
    /// `keys.0` names it. Usually one: an admin may write any sync ID there, and a blob is tried
    /// under each, so naming another actor's inbox hides nothing from it.
    pub fn inbox_actors(&mut self) -> Arc<BTreeMap<LabelId, Vec<Tid>>> {
        if let Some(m) = self.core.inbox_actors.clone() {
            #[cfg(debug_assertions)]
            if self.recheck("inbox_actors".to_string()) {
                assert_eq!(*m, *self.inbox_actors_read(), "inbox_actors cached");
            }
            return m;
        }
        let m = self.inbox_actors_read();
        self.core.inbox_actors = Some(m.clone());
        m
    }

    fn inbox_actors_read(&mut self) -> Arc<BTreeMap<LabelId, Vec<Tid>>> {
        let mut by: BTreeMap<LabelId, Vec<Tid>> = BTreeMap::new();
        for a in self.core.ix.secrets.keys().copied().collect::<Vec<_>>() {
            if let Some(l) = self.inbox(&a) {
                by.entry(l).or_default().push(a);
            }
        }
        Arc::new(by)
    }

    /// Whether `g` has a live (unreplaced) label here.
    pub fn labeled(&mut self, g: &Tid) -> bool {
        self.labels_of(g).iter().any(|l| !l.replaced)
    }

    /// The labels `label.0` of `g` records, replaced ones included; records that do not parse
    /// are skipped.
    pub fn group_labels(&mut self, g: &Tid) -> Result<Vec<GroupLabel>> {
        Ok(self.labels_of(g).iter().map(|l| (**l).clone()).collect())
    }

    /// `group_labels`, shared: decoded once per write of the `label.0` (`Core::labels`, which
    /// keeps the records it parsed: debug builds check them against the store, `recheck`).
    pub fn labels_of(&mut self, g: &Tid) -> Vec<Arc<GroupLabel>> {
        if self.core.created(g).is_none() {
            return Vec::new();
        }
        if let Some((v, _records)) = self.core.labels.get(g) {
            let v = v.clone();
            #[cfg(debug_assertions)]
            {
                let cached = _records.clone();
                if self.recheck(format!("labels_of {g}")) {
                    assert!(self.label_records(g) == cached, "labels_of({g}) cached");
                }
            }
            return v;
        }
        let records = self.label_records(g);
        let mut out = Vec::new();
        for (id, l) in &records {
            let Ok(steps) = osis_label::label_steps(l) else { continue };
            out.push(Arc::new(GroupLabel { group: *g, id: *id, index: l.index, steps, hosts: l.hosts.clone(), replaced: l.replaced }));
        }
        self.core.labels.insert(*g, (out.clone(), records));
        out
    }

    /// The `label.0` records of `g` (none if unreadable).
    fn label_records(&mut self, g: &Tid) -> ct::Labels {
        self.get_typed(g, &ct::LABEL).ok().flatten().unwrap_or_default()
    }
}
