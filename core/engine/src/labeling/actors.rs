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
    /// through `group.0` and `ephemeral_group.0~`, transitively through subgroups of either kind. The
    /// same `Arc` while it does not change (`Groups::closures` for the durable part; the rest
    /// cached by `Core::ephemeral_group_gen`), so node-sync reuses what it derived from it.
    pub fn closure(&self, g: &Tid) -> std::sync::Arc<BTreeSet<Tid>> {
        let durable = self.core.ix.groups.closure(g);
        if self.core.ix.ephemeral_group.is_empty() {
            return durable;
        }
        let at = self.core.ephemeral_group_gen;
        if let Some((d, n, full)) = self.core.full_closures.borrow().get(g)
            && std::sync::Arc::ptr_eq(d, &durable)
            && *n == at
        {
            return full.clone();
        }
        let mut out: BTreeSet<Tid> = (*durable).clone();
        let mut seen = BTreeSet::new();
        let mut stack = vec![*g];
        while let Some(x) = stack.pop() {
            if !seen.insert(x) {
                continue;
            }
            for d in [self.core.ix.groups.defs.get(&x), self.core.ix.ephemeral_group.get(&x)].into_iter().flatten() {
                out.extend(d.0.iter().copied());
                stack.extend(d.1.iter().copied());
            }
        }
        if out.len() == durable.len() {
            return durable;
        }
        let full = std::sync::Arc::new(out);
        self.core.full_closures.borrow_mut().insert(*g, (durable, at, full.clone()));
        full
    }

    /// Things with a `label.0` state.
    pub fn labeled_groups(&self) -> Vec<Tid> {
        self.core.ix.labeled.iter().copied().collect()
    }

    /// Every inbox a blob about actor `a` may come under (spec/sync.md §2): the `keys.0` inbox
    /// of each thing up `a`'s record chain through standing record edges, the nearest first. A
    /// sender uses the first it knows of (`flows::inbox_of`); one knowing less of `a` (its
    /// `keys.0` from before it named one) used one further up, so a reader opens under them all.
    pub fn inbox_candidates(&mut self, a: &Tid) -> Vec<LabelId> {
        if let Some(l) = self.core.inbox_labels.get(a).cloned() {
            #[cfg(debug_assertions)]
            if self.recheck(format!("inbox_candidates {a}")) {
                assert_eq!(l, self.inbox_candidates_read(a), "inbox_candidates({a}) cached");
            }
            return l;
        }
        let l = self.inbox_candidates_read(a);
        let uppers: Vec<Tid> = self.core.inbox_chain(a).into_iter().filter(|t| t != a).collect();
        self.core.inbox_uppers.extend(uppers);
        self.core.inbox_labels.insert(*a, l.clone());
        l
    }

    fn inbox_candidates_read(&mut self, a: &Tid) -> Vec<LabelId> {
        let mut out: Vec<LabelId> = self.core.inbox_chain(a).iter().filter_map(|t| self.get_typed(t, &ct::KEYS).ok().flatten().and_then(|k| k.inbox)).map(|i| i.label).collect();
        out.dedup();
        out
    }

    /// The inboxes here (spec/sync.md §2): per label, the actors with secrets held here a blob
    /// under it may be about (`inbox_candidates`), the topmost first (a blob is tried under each
    /// in turn, and most name a person, not one of its many things).
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
        let mut by: BTreeMap<LabelId, Vec<(usize, Tid)>> = BTreeMap::new();
        for a in self.core.ix.secrets.keys().copied().collect::<Vec<_>>() {
            let depth = self.core.inbox_chain(&a).len();
            for l in self.inbox_candidates(&a) {
                by.entry(l).or_default().push((depth, a));
            }
        }
        Arc::new(
            by.into_iter()
                .map(|(l, mut v)| {
                    v.sort();
                    (l, v.into_iter().map(|x| x.1).collect())
                })
                .collect(),
        )
    }

    /// Whether `g` has a live (unreplaced) label here.
    pub fn labeled(&mut self, g: &Tid) -> bool {
        self.labels_of(g).iter().any(|l| !l.replaced)
    }

    /// Whether the label of a group whose actor is `a` and whose closure is `c` carries `t` to
    /// holder `x`: `t` is in the closure and `a` may read it (else it is excluded: no writer of
    /// the label holds it there), and `x` reads the label, or is read through it (a subgroup's
    /// edge on its item: `a` holds `x`, so whoever reads `x` that way reads `t`).
    fn carries(&self, a: &Tid, c: &BTreeSet<Tid>, x: &Tid, t: &Tid) -> bool {
        // `a` itself is the usual holder: a thing shared into a group, its edge is what may read
        c.contains(t) && (x == a || (self.core.may_read(a, t) && (self.core.may_read(x, a) || self.core.may_read(a, x))))
    }

    /// Whether holder `x` of a role on `t` has a **route** to it (spec/sync.md §2): a live label
    /// it can open carries `t`: `t`'s own (every holder of `t` derives its sync key), or one of a
    /// group that carries it to `x` (`carries`). Labels as this node knows them: a label of a
    /// group it does not read is not counted, so another node may see a route this one does not.
    pub fn routed(&mut self, x: &Tid, t: &Tid) -> bool {
        if self.labeled(t) {
            return true;
        }
        let groups = self.labeled_groups();
        groups.into_iter().any(|g| g != *t && self.labeled(&g) && self.carries(&self.group_actor(&g), &self.closure(&g), x, t))
    }

    /// Per thing this node has a role on, whose roster this node holds and that has no live label
    /// of its own, its direct holders without a route (`routed`): the roster's actors and nodes,
    /// not its first admin (a thing in no group is local to its first admin by design), not a
    /// recovery or link key (a link always has its target's label), not an account's nodes (nodes
    /// on a thing whose first admin is a key actor: its home label is theirs, known only to them).
    /// Empty when every holder
    /// has one. A thing this node has no role on is no business of its status, and its labels are
    /// not known here: rosters arrive as a writer's chain, and stay after a removal. Every status
    /// asks, so kept until a role, label or placement is written: an edge expiring shows at the
    /// next such write.
    pub fn unrouted(&mut self) -> Arc<BTreeMap<Tid, Vec<Tid>>> {
        if let Some(u) = &self.core.unrouted {
            return u.clone();
        }
        let u = Arc::new(self.find_unrouted());
        self.core.unrouted = Some(u.clone());
        u
    }

    fn find_unrouted(&mut self) -> BTreeMap<Tid, Vec<Tid>> {
        let things: Vec<Tid> = self.core.timelines.things().copied().collect();
        let mut live: Vec<(Tid, Arc<BTreeSet<Tid>>)> = Vec::new();
        for g in self.labeled_groups() {
            if self.labeled(&g) {
                live.push((self.group_actor(&g), self.closure(&g)));
            }
        }
        let mut out = BTreeMap::new();
        for t in things {
            if self.labeled(&t) {
                continue;
            }
            let first = self.core.first_admin(&t);
            let person = first.is_some_and(|o| self.core.is_key_actor(&o));
            let mut holders = Vec::new();
            for (m, _, _) in self.core.current_holders(&t) {
                let skip = self.core.is_key_actor(&m) && (person || !self.is_node(&m).unwrap_or(false));
                if Some(m) != first && !skip && !live.iter().any(|(a, c)| self.carries(a, c, &m, &t)) {
                    holders.push(m);
                }
            }
            if !holders.is_empty() && self.role_on(&t).is_some() {
                out.insert(t, holders);
            }
        }
        out
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
