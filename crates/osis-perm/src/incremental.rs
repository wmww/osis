//! Incremental evaluation (notes/permissions.md Implementation): the timeline split into connected components of
//! things (edges join member, target and author; ownership joins a thing and its owner; a
//! roster snapshot joins its thing, author and every node it names), each evaluated from
//! scratch and cached by its exact inputs. A held-set change re-evaluates only the components
//! whose inputs changed. Components are independent: no write in one can change authority in
//! another, so the result equals one evaluation of the whole held set.

use crate::held::HeldSet;
use crate::timeline::Timeline;
use crate::types::{MembershipCommit, RosterSnapshot};
use osis_core::{CommitId, CreationRecord, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Union-find over tids.
#[derive(Default)]
struct Dsu {
    parent: BTreeMap<Tid, Tid>,
}

impl Dsu {
    fn find(&mut self, t: Tid) -> Tid {
        let mut root = t;
        while let Some(&p) = self.parent.get(&root) {
            if p == root {
                break;
            }
            root = p;
        }
        let mut cur = t;
        while cur != root {
            let next = self.parent.get(&cur).copied().unwrap_or(root);
            self.parent.insert(cur, root);
            cur = next;
        }
        self.parent.entry(root).or_insert(root);
        root
    }
    fn union(&mut self, a: Tid, b: Tid) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            let (lo, hi) = if ra < rb { (ra, rb) } else { (rb, ra) };
            self.parent.insert(hi, lo);
        }
    }
}

/// The held set of one component.
struct Part<'a> {
    held: &'a dyn HeldSet,
    things: &'a BTreeSet<Tid>,
}

impl HeldSet for Part<'_> {
    fn things(&self) -> Vec<Tid> {
        self.things.iter().copied().collect()
    }
    fn edge_commits(&self, thing: &Tid) -> Vec<Arc<MembershipCommit>> {
        if self.things.contains(thing) { self.held.edge_commits(thing) } else { Vec::new() }
    }
    fn roster_snapshots(&self, thing: &Tid) -> Vec<Arc<RosterSnapshot>> {
        if self.things.contains(thing) { self.held.roster_snapshots(thing) } else { Vec::new() }
    }
    fn created(&self, thing: &Tid) -> Option<CreationRecord> {
        if self.things.contains(thing) { self.held.created(thing) } else { None }
    }
}

/// A component's exact inputs: its things, the IDs of its commits and snapshots, and its
/// held `/created` records (by tid; a record's tid fixes its content).
type Inputs = (BTreeSet<Tid>, BTreeSet<CommitId>, BTreeSet<Tid>);

/// Which things' timelines an update changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Changed {
    /// Things of components evaluated from scratch: anything about them may have changed.
    pub evaluated: BTreeSet<Tid>,
    /// Things of components whose walk only went on: the targets of the commits added, and
    /// things added by a `/created` record alone (a new leaf). Authority changed only on what
    /// is reachable from them (owned things, targets of their edges).
    pub extended: BTreeSet<Tid>,
}

/// Timelines per component, cached across held-set changes.
#[derive(Default)]
pub struct Timelines {
    comps: BTreeMap<u64, (Inputs, Timeline)>,
    next: u64,
    of: BTreeMap<Tid, u64>,
}

/// The things `t`'s held inputs link it to (the unions of a partition).
fn links(held: &dyn HeldSet, t: &Tid) -> Vec<Tid> {
    let mut out = Vec::new();
    if let Some(CreationRecord::Thing { owner, .. }) = held.created(t) {
        out.push(owner);
    }
    for c in held.edge_commits(t) {
        out.push(c.author);
        for o in &c.ops {
            out.push(o.member);
            out.push(o.target);
        }
    }
    for s in held.roster_snapshots(t) {
        out.push(s.author);
        out.extend(s.roster.keys().copied());
        out.extend(s.ledger.iter().flat_map(|x| [x.member, x.until.node]));
    }
    out
}

impl Timelines {
    pub fn new() -> Self {
        Self::default()
    }

    /// Re-partitions `held` and evaluates each component whose inputs changed. Returns how
    /// many components were evaluated.
    pub fn update(&mut self, held: &dyn HeldSet) -> usize {
        let mut region: BTreeSet<Tid> = held.things().into_iter().collect();
        region.extend(self.of.keys().copied());
        for t in region.clone() {
            region.extend(links(held, &t));
        }
        let (evaluated, _) = self.update_region(held, region);
        evaluated
    }

    /// Re-partitions only around `touched` (things whose held inputs changed since the last
    /// update: a commit or snapshot on them added or removed, their `/created` recorded): their
    /// components and every component newly linked to them, so the cost follows the affected
    /// components, not the held set. Equal to `update`. Returns what changed.
    pub fn update_touched(&mut self, held: &dyn HeldSet, touched: &BTreeSet<Tid>) -> Changed {
        let mut region: BTreeSet<Tid> = BTreeSet::new();
        let mut queue: Vec<Tid> = touched.iter().copied().collect();
        while let Some(t) = queue.pop() {
            if !region.insert(t) {
                continue;
            }
            if let Some((inputs, _)) = self.of.get(&t).and_then(|c| self.comps.get(c)) {
                queue.extend(inputs.0.iter().filter(|x| !region.contains(x)).copied());
            }
            queue.extend(links(held, &t).into_iter().filter(|x| !region.contains(x)));
        }
        self.update_region(held, region).1
    }

    /// Re-partitions `region` (a union of whole components, old and new) and evaluates its
    /// components whose inputs changed: (how many, what changed).
    fn update_region(&mut self, held: &dyn HeldSet, region: BTreeSet<Tid>) -> (usize, Changed) {
        let mut cache: BTreeMap<Inputs, Timeline> = BTreeMap::new();
        let old: BTreeSet<u64> = region.iter().filter_map(|t| self.of.get(t).copied()).collect();
        for c in old {
            if let Some((inputs, tl)) = self.comps.remove(&c) {
                for t in &inputs.0 {
                    self.of.remove(t);
                }
                cache.insert(inputs, tl);
            }
        }
        let mut dsu = Dsu::default();
        let mut ids: BTreeMap<Tid, BTreeSet<CommitId>> = BTreeMap::new();
        let mut created: BTreeSet<Tid> = BTreeSet::new();
        for t in &region {
            dsu.find(*t);
            if let Some(rec) = held.created(t) {
                created.insert(*t);
                if let CreationRecord::Thing { owner, .. } = rec {
                    dsu.union(*t, owner);
                }
            }
            for c in held.edge_commits(t) {
                ids.entry(*t).or_default().insert(c.id);
                for o in &c.ops {
                    dsu.union(c.author, o.target);
                    dsu.union(o.member, o.target);
                }
            }
            for s in held.roster_snapshots(t) {
                ids.entry(*t).or_default().insert(s.id);
                dsu.union(s.author, s.thing);
                for m in s.roster.keys().chain(s.ledger.iter().flat_map(|x| [&x.member, &x.until.node])) {
                    dsu.union(*m, s.thing);
                }
            }
        }
        let mut groups: BTreeMap<Tid, Inputs> = BTreeMap::new();
        let all: Vec<Tid> = dsu.parent.keys().copied().collect();
        for t in all {
            let root = dsu.find(t);
            let g = groups.entry(root).or_default();
            g.0.insert(t);
            g.1.extend(ids.get(&t).into_iter().flatten().copied());
            if created.contains(&t) {
                g.2.insert(t);
            }
        }
        let mut evaluated = 0;
        let mut changed = Changed::default();
        for (_, inputs) in groups {
            let part = Part { held, things: &inputs.0 };
            let tl = match cache.remove(&inputs) {
                Some(tl) => tl,
                None => {
                    evaluated += 1;
                    // a component that only gained commits continues its walk when it can; one
                    // that only gained new leaves (`/created` of things nothing else names) too
                    let grown = cache.keys().find(|k| k.0 == inputs.0 && k.2 == inputs.2 && k.1.is_subset(&inputs.1)).cloned();
                    let leaves = || cache.keys().find(|k| k.1 == inputs.1 && k.0.is_subset(&inputs.0) && k.2.is_subset(&inputs.2) && inputs.2.difference(&k.2).eq(inputs.0.difference(&k.0))).cloned();
                    let (from, new) = match grown.or_else(leaves) {
                        Some(k) => {
                            let added: BTreeSet<CommitId> = inputs.1.difference(&k.1).copied().collect();
                            let mut new: BTreeSet<Tid> = inputs.0.difference(&k.0).copied().collect();
                            for t in &inputs.0 {
                                if held.edge_commits(t).iter().any(|c| added.contains(&c.id)) {
                                    new.insert(*t);
                                }
                            }
                            (cache.remove(&k), new)
                        }
                        None => (None, BTreeSet::new()),
                    };
                    match from.and_then(|tl| tl.extend(&part)) {
                        Some(tl) => {
                            changed.extended.extend(new);
                            tl
                        }
                        None => {
                            changed.evaluated.extend(inputs.0.iter().copied());
                            Timeline::evaluate(&part)
                        }
                    }
                }
            };
            let i = self.next;
            self.next += 1;
            for t in &inputs.0 {
                self.of.insert(*t, i);
            }
            self.comps.insert(i, (inputs, tl));
        }
        (evaluated, changed)
    }

    /// The timeline of the component holding `thing` (and every node with a path to it).
    pub fn get(&self, thing: &Tid) -> Option<&Timeline> {
        self.of.get(thing).and_then(|i| self.comps.get(i)).map(|(_, tl)| tl)
    }

    pub fn components(&self) -> usize {
        self.comps.len()
    }
}
