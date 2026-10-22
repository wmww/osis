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

use crate::cache::{self, Inputs};

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

/// One component's timeline.
struct Comp {
    inputs: Inputs,
    tl: Timeline,
    /// How many commits and snapshots the walk saved under the component's root (its first
    /// thing) covered, 0 if none was: what `to_save` measures growth against.
    basis: usize,
}

/// Timelines per component, cached across held-set changes.
#[derive(Default)]
pub struct Timelines {
    comps: BTreeMap<u64, Comp>,
    next: u64,
    of: BTreeMap<Tid, u64>,
    /// Things whose component the last update evaluated or continued.
    changed: BTreeSet<Tid>,
    /// Components evaluated or continued since `to_save` last looked.
    unsaved: BTreeSet<u64>,
    /// Roots whose saved walk no component uses any more.
    retired: BTreeSet<Tid>,
    /// Components the last update restored from a saved walk.
    restored: usize,
}

/// Walks to write to and delete from a node's cache, by component root (`Timelines::to_save`).
#[derive(Default)]
pub struct Saves {
    pub put: Vec<(Tid, Vec<u8>)>,
    pub delete: Vec<Tid>,
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
        let (evaluated, _) = self.update_region(held, region, &mut |_| None, &[]);
        evaluated
    }

    /// Re-partitions only around `touched` (things whose held inputs changed since the last
    /// update: a commit or snapshot on them added or removed, their `/created` recorded): their
    /// components and every component newly linked to them, so the cost follows the affected
    /// components, not the held set. Equal to `update`. Returns what changed.
    pub fn update_touched(&mut self, held: &dyn HeldSet, touched: &BTreeSet<Tid>) -> Changed {
        self.update_touched_cached(held, touched, &mut |_| None, &[])
    }

    /// `update_touched`, where a component with no timeline here first tries the walk
    /// `saved(root)` returns (`to_save` wrote it under the component's first thing; `salt` as
    /// given then): used when its tag shows it was walked over this component's inputs, or over
    /// fewer commits of it (then continued by `Timeline::extend`, else evaluated). Equal to
    /// `update_touched` whatever `saved` returns.
    pub fn update_touched_cached(&mut self, held: &dyn HeldSet, touched: &BTreeSet<Tid>, saved: &mut dyn FnMut(&Tid) -> Option<Vec<u8>>, salt: &[u8]) -> Changed {
        let mut region: BTreeSet<Tid> = BTreeSet::new();
        let mut queue: Vec<Tid> = touched.iter().copied().collect();
        while let Some(t) = queue.pop() {
            if !region.insert(t) {
                continue;
            }
            if let Some(c) = self.of.get(&t).and_then(|c| self.comps.get(c)) {
                queue.extend(c.inputs.0.iter().filter(|x| !region.contains(x)).copied());
            }
            queue.extend(links(held, &t).into_iter().filter(|x| !region.contains(x)));
        }
        self.update_region(held, region, saved, salt).1
    }

    /// Re-partitions `region` (a union of whole components, old and new) and evaluates its
    /// components whose inputs changed: (how many, what changed).
    fn update_region(&mut self, held: &dyn HeldSet, region: BTreeSet<Tid>, saved: &mut dyn FnMut(&Tid) -> Option<Vec<u8>>, salt: &[u8]) -> (usize, Changed) {
        // old components by their inputs: (timeline, basis, not saved since it changed)
        let mut cache: BTreeMap<Inputs, (Timeline, usize, bool)> = BTreeMap::new();
        let old: BTreeSet<u64> = region.iter().filter_map(|t| self.of.get(t).copied()).collect();
        for c in old {
            if let Some(comp) = self.comps.remove(&c) {
                for t in &comp.inputs.0 {
                    self.of.remove(t);
                }
                let dirty = self.unsaved.remove(&c);
                cache.insert(comp.inputs, (comp.tl, comp.basis, dirty));
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
                // an entry with a frontier is a demotion by its key's node (§6)
                let demoters = s.ledger.iter().filter(|x| x.frontier.is_some()).map(|x| &x.until.node);
                for m in s.roster.keys().chain(s.ledger.iter().map(|x| &x.member)).chain(demoters) {
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
        self.changed.clear();
        self.restored = 0;
        for (root, inputs) in groups {
            let part = Part { held, things: &inputs.0 };
            let (tl, basis, dirty) = match cache.remove(&inputs) {
                Some(x) => x,
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
                            // a walk saved under the old root stays a basis only under it
                            let from = cache.remove(&k).map(|(tl, basis, _)| (tl, if k.0.first() == Some(&root) { basis } else { self.retire(&k, basis) }));
                            (from, new)
                        }
                        None => (None, BTreeSet::new()),
                    };
                    let extended = match from {
                        Some((tl, basis)) => tl.extend(&part).map(|tl| (tl, basis)),
                        None => None,
                    };
                    self.changed.extend(inputs.0.iter().copied());
                    match extended {
                        Some((tl, basis)) => {
                            changed.extended.extend(new);
                            (tl, basis, true)
                        }
                        None => {
                            changed.evaluated.extend(inputs.0.iter().copied());
                            match self.restore(&root, &inputs, &part, saved, salt) {
                                Some((tl, basis)) => (tl, basis, true),
                                None => (Timeline::evaluate(&part), 0, true),
                            }
                        }
                    }
                }
            };
            let i = self.next;
            self.next += 1;
            for t in &inputs.0 {
                self.of.insert(*t, i);
            }
            if dirty {
                self.unsaved.insert(i);
            }
            self.comps.insert(i, Comp { inputs, tl, basis });
        }
        for (k, (_, basis, _)) in cache {
            self.retire(&k, basis);
        }
        (evaluated, changed)
    }

    /// Notes that the walk saved under `k`'s root (if `basis` says one was) is no longer used;
    /// returns the basis a component under another root starts from (none).
    fn retire(&mut self, k: &Inputs, basis: usize) -> usize {
        if basis > 0
            && let Some(r) = k.0.first()
        {
            self.retired.insert(*r);
        }
        0
    }

    /// The timeline of a component with no timeline here from the walk saved under its root,
    /// continued over the commits added since; and how many commits and snapshots it covered.
    fn restore(&mut self, root: &Tid, inputs: &Inputs, part: &Part<'_>, saved: &mut dyn FnMut(&Tid) -> Option<Vec<u8>>, salt: &[u8]) -> Option<(Timeline, usize)> {
        let bytes = saved(root)?;
        let got = cache::parse(&bytes).and_then(|s| {
            let k = &s.inputs;
            if k.0 != inputs.0 || k.2 != inputs.2 || !k.1.is_subset(&inputs.1) {
                return None;
            }
            let tl = cache::restore(&s, part, salt)?;
            let basis = k.1.len();
            if k.1 == inputs.1 { Some((tl, basis)) } else { tl.extend(part).map(|tl| (tl, basis)) }
        });
        match &got {
            Some(_) => self.restored += 1,
            // unusable: overwritten or deleted by the next `to_save`
            None => {
                self.retired.insert(*root);
            }
        }
        got
    }

    /// The walks a node's cache should hold now: components walked anew or continued since the
    /// last call whose commits and snapshots number at least `min` and grew by at least a
    /// quarter (and `min`) since their walk was last saved, encoded with `salt` (the rules);
    /// and the roots whose saved walk no component uses. `all`: the cache is empty (every
    /// component of at least `min` is saved). Saving amortizes to O(1) per added commit.
    pub fn to_save(&mut self, salt: &[u8], min: usize, all: bool) -> Saves {
        let ids: Vec<u64> = if all { self.comps.keys().copied().collect() } else { std::mem::take(&mut self.unsaved).into_iter().collect() };
        if all {
            self.unsaved.clear();
        }
        let mut out = Saves::default();
        let mut kept: BTreeSet<Tid> = BTreeSet::new();
        for i in ids {
            let Some(c) = self.comps.get_mut(&i) else { continue };
            let Some(root) = c.inputs.0.first().copied() else { continue };
            if Self::save_due(c, min, all)
                && let Some(bytes) = cache::save(&c.inputs, &c.tl, salt)
            {
                c.basis = c.inputs.1.len();
                kept.insert(root);
                out.put.push((root, bytes));
            }
        }
        let retired = std::mem::take(&mut self.retired);
        out.delete = retired.into_iter().filter(|r| !kept.contains(r)).filter(|r| !self.of.get(r).and_then(|i| self.comps.get(i)).is_some_and(|c| c.basis > 0 && c.inputs.0.first() == Some(r))).collect();
        out
    }

    fn save_due(c: &Comp, min: usize, all: bool) -> bool {
        let (n, b) = (c.inputs.1.len(), if all { 0 } else { c.basis });
        n >= min.max(1) && (n < b || n - b >= (b / 4).max(min))
    }

    /// Whether `to_save(_, min, false)` has something to write or delete.
    pub fn due(&self, min: usize) -> bool {
        !self.retired.is_empty() || self.unsaved.iter().filter_map(|i| self.comps.get(i)).any(|c| Self::save_due(c, min, false))
    }

    /// Components the last update restored from a saved walk.
    pub fn restored(&self) -> usize {
        self.restored
    }

    /// The timeline of the component holding `thing` (and every node with a path to it).
    pub fn get(&self, thing: &Tid) -> Option<&Timeline> {
        self.of.get(thing).and_then(|i| self.comps.get(i)).map(|c| &c.tl)
    }

    /// Things whose timeline the last `update` evaluated (or continued): every other thing's
    /// answers are unchanged.
    pub fn changed(&self) -> &BTreeSet<Tid> {
        &self.changed
    }

    pub fn components(&self) -> usize {
        self.comps.len()
    }
}
