//! Incremental evaluation (notes/permissions.md Implementation): the timeline split into connected components of
//! things (edges join member, target and author; ownership joins a thing and its owner; a
//! roster snapshot joins its thing, author and every node it names), each cached by its exact
//! inputs. A held-set change touches only the components whose inputs changed: continued in
//! place (`Timeline::append`, `add_leaves`), from the old walk (`Timeline::extend`), from a
//! saved walk, or evaluated. Components are independent: no write in one can change authority
//! in another, so the result equals one evaluation of the whole held set.

use crate::cache::{self, Inputs, Only};
use crate::held::HeldSet;
use crate::timeline::Timeline;
use crate::types::MembershipCommit;
use osis_base::{CommitId, CreationRecord, Tid};
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
    /// The commits and snapshots held under each thing (`Timelines::append`).
    per: BTreeMap<Tid, BTreeSet<CommitId>>,
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
    /// Components the last update continued by `Timeline::append` alone.
    appended: usize,
    /// Commits those placed without walking again.
    placed: usize,
    /// `append` off: every update takes the general path (tests compare the two).
    general_only: bool,
}

/// Walks to write to and delete from a node's cache, by component root (`Timelines::to_save`).
#[derive(Default)]
pub struct Saves {
    pub put: Vec<(Tid, Vec<u8>)>,
    pub delete: Vec<Tid>,
    /// For `Timelines::saved` once these are durable.
    pub done: SaveDone,
}

/// What a durable `Saves` changes in `Timelines`.
#[derive(Default, Debug)]
pub struct SaveDone {
    looked: Vec<u64>,
    based: Vec<(u64, usize)>,
    retired: Vec<Tid>,
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

    /// Turns `update_touched`'s fast path (`append`) off, for tests comparing it with the
    /// general path.
    #[doc(hidden)]
    pub fn set_general_only(&mut self, on: bool) {
        self.general_only = on;
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
        let fast = match if self.general_only { None } else { self.append(held, touched) } {
            Some((c, things, true)) => {
                self.changed = things;
                self.restored = 0;
                return c;
            }
            f => f,
        };
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
        let mut changed = self.update_region(held, region, saved, salt).1;
        // components `append` continued before one declined: cache hits there
        if let Some((c, things, _)) = fast {
            changed.extended.extend(c.extended);
            self.changed.extend(things);
        }
        changed
    }

    /// The common case of `update_touched` in O(what changed): every touched thing is in a
    /// component, with its `/created` and snapshots as before, and only gained membership
    /// commits that join nothing (author, members and targets in its component); each such
    /// component goes on by `Timeline::append`. Or it is a new leaf (only its `/created` names
    /// it) of a component that gained no commits: `Timeline::add_leaves`. `None`: the case does
    /// not apply, nothing done.
    /// Else what changed, the things of the components continued, and whether all of them
    /// were (else the general path must run: the ones continued are then cache hits).
    fn append(&mut self, held: &dyn HeldSet, touched: &BTreeSet<Tid>) -> Option<(Changed, BTreeSet<Tid>, bool)> {
        // (new commits, commits per touched thing, new nodes joining, new leaves)
        type Work = (BTreeMap<CommitId, Arc<MembershipCommit>>, BTreeMap<Tid, BTreeSet<CommitId>>, BTreeMap<Tid, Option<CreationRecord>>, Vec<(Tid, CreationRecord)>);
        let mut work: BTreeMap<u64, Work> = BTreeMap::new();
        // Nothing held of `x` but its `/created`, in no component or alone in one (`known`:
        // with that record already).
        let unseen = |x: &Tid, known: bool| {
            held.edge_commits(x).is_empty()
                && held.roster_snapshots(x).is_empty()
                && self.of.get(x).is_none_or(|j| self.comps.get(j).is_some_and(|c| c.inputs.0.len() == 1 && c.inputs.1.is_empty() && c.inputs.2.len() == usize::from(known)))
        };
        // A node new to every walk (nothing held of its own but its key actor's `/created`)
        // joins the one component whose new commits name it.
        let lone = |x: &Tid| -> Option<Option<CreationRecord>> {
            let rec = held.created(x);
            if rec.as_ref().is_some_and(|r| !matches!(r, CreationRecord::KeyActor { .. }) || r.tid() != *x) {
                return None;
            }
            unseen(x, rec.is_some()).then_some(rec)
        };
        // A thing whose `/created` is all that names it joins its owner's component.
        let leaf = |x: &Tid| held.created(x).filter(|r| matches!(r, CreationRecord::Thing { .. }) && unseen(x, false) && r.tid() == *x);
        let mut joining: BTreeMap<Tid, u64> = BTreeMap::new();
        let mut unplaced = Vec::new();
        let mut leaves = Vec::new();
        for t in touched {
            if let Some(rec) = leaf(t) {
                leaves.push((*t, rec));
                continue;
            }
            let Some(&i) = self.of.get(t) else {
                lone(t)?;
                unplaced.push(*t);
                continue;
            };
            let c = self.comps.get(&i)?;
            let old = c.per.get(t);
            if c.inputs.2.contains(t) != held.created(t).is_some() {
                return None;
            }
            let (mut kept, mut ids) = (0, BTreeSet::new());
            let w = work.entry(i).or_default();
            for s in held.roster_snapshots(t) {
                if ids.insert(s.id) {
                    // the same snapshot, its content too (a part may arrive late)
                    if !old.is_some_and(|p| p.contains(&s.id)) || (s.thing == *t && !c.tl.input.holds_snapshot(&s)) {
                        return None;
                    }
                    kept += 1;
                }
            }
            for m in held.edge_commits(t) {
                if !ids.insert(m.id) {
                    continue;
                }
                if old.is_some_and(|p| p.contains(&m.id)) {
                    if !c.tl.input.holds_commit(&m) {
                        return None;
                    }
                    kept += 1;
                } else if c.inputs.1.contains(&m.id) {
                    return None;
                } else {
                    let names = std::iter::once(&m.author).chain(m.ops.iter().flat_map(|o| [&o.member, &o.target]));
                    for x in names {
                        if c.inputs.0.contains(x) {
                            continue;
                        }
                        // (one below the root would move it: saved walks are under the root)
                        let rec = lone(x).filter(|_| c.inputs.0.first().is_some_and(|r| r < x))?;
                        if *joining.entry(*x).or_insert(i) != i {
                            return None;
                        }
                        w.2.insert(*x, rec);
                    }
                    w.0.insert(m.id, m);
                }
            }
            if kept != old.map_or(0, |p| p.len()) {
                return None;
            }
            w.1.insert(*t, ids);
        }
        if unplaced.iter().any(|t| !joining.contains_key(t)) {
            return None;
        }
        // each leaf in its owner's component, through owners that are new leaves too
        let new_leaves: BTreeSet<Tid> = leaves.iter().map(|l| l.0).collect();
        let mut at: BTreeMap<Tid, u64> = BTreeMap::new();
        while !leaves.is_empty() {
            let n = leaves.len();
            for (x, rec) in std::mem::take(&mut leaves) {
                let CreationRecord::Thing { owner, .. } = rec else { return None };
                let i = match at.get(&owner) {
                    Some(&i) => i,
                    None if new_leaves.contains(&owner) => {
                        leaves.push((x, rec));
                        continue;
                    }
                    // (an owner joining now moves components)
                    None if joining.contains_key(&owner) => return None,
                    None => *self.of.get(&owner)?,
                };
                let w = work.entry(i).or_default();
                // (one below the root would move it: saved walks are under the root)
                if !w.0.is_empty() || !self.comps.get(&i)?.inputs.0.first().is_some_and(|r| *r < x) {
                    return None;
                }
                at.insert(x, i);
                w.3.push((x, rec));
            }
            if leaves.len() == n {
                return None;
            }
        }
        self.appended = 0;
        self.placed = 0;
        let (mut changed, mut things) = (Changed::default(), BTreeSet::new());
        for (i, (new, per, join, leaves)) in work {
            let Some(mut c) = self.comps.remove(&i) else { continue };
            if !leaves.is_empty() {
                match c.tl.add_leaves(&leaves) {
                    Ok(tl) => c.tl = tl,
                    Err(tl) => {
                        c.tl = *tl;
                        self.comps.insert(i, c);
                        return Some((changed, things, false));
                    }
                }
                self.appended += 1;
                for (x, _) in leaves {
                    self.adopt(&mut c, i, x, true);
                    changed.extended.insert(x);
                }
                things.extend(c.inputs.0.iter().copied());
                self.unsaved.insert(i);
            }
            if !new.is_empty() {
                let list: Vec<Arc<MembershipCommit>> = new.values().cloned().collect();
                let keys: Vec<(Tid, CreationRecord)> = join.iter().filter_map(|(x, r)| r.clone().map(|r| (*x, r))).collect();
                match c.tl.append(&list, &keys) {
                    Ok(tl) => c.tl = tl,
                    Err(tl) => {
                        c.tl = *tl;
                        self.comps.insert(i, c);
                        return Some((changed, things, false));
                    }
                }
                self.appended += 1;
                self.placed += c.tl.placed;
                c.inputs.1.extend(new.keys().copied());
                for (x, rec) in join {
                    self.adopt(&mut c, i, x, rec.is_some());
                }
                changed.extended.extend(per.iter().filter(|(_, ids)| ids.iter().any(|x| new.contains_key(x))).map(|(t, _)| *t));
                things.extend(c.inputs.0.iter().copied());
                self.unsaved.insert(i);
                // held under every target, touched or not
                for m in new.values() {
                    for o in &m.ops {
                        c.per.entry(o.target).or_default().insert(m.id);
                        changed.extended.insert(o.target);
                    }
                }
            }
            c.per.extend(per);
            self.comps.insert(i, c);
        }
        Some((changed, things, true))
    }

    /// Puts `x` (in no component or alone in one) in component `c` (`i`, taken out of `comps`).
    fn adopt(&mut self, c: &mut Comp, i: u64, x: Tid, created: bool) {
        if let Some(j) = self.of.insert(x, i) {
            // its lone component
            self.comps.remove(&j);
            self.unsaved.remove(&j);
        }
        c.inputs.0.insert(x);
        if created {
            c.inputs.2.insert(x);
        }
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
        self.appended = 0;
        self.placed = 0;
        for (root, inputs) in groups {
            let part = Only { held, things: &inputs.0, created: None, ids: None };
            // the same IDs, and the same records under them (a part may arrive late)
            let hit = match cache.remove(&inputs) {
                Some((tl, basis, _)) if !tl.holds_same(&part, &inputs.0) => {
                    self.retire(&inputs, basis);
                    None
                }
                x => x,
            };
            let (tl, basis, dirty) = match hit {
                Some(x) => x,
                None => {
                    evaluated += 1;
                    // a component that only gained commits, things and `/created` records
                    // continues its walk when it can (`Timeline::extend`): the one with the most
                    // commits and snapshots
                    let grown = cache.keys().filter(|k| k.0.is_subset(&inputs.0) && k.1.is_subset(&inputs.1) && k.2.is_subset(&inputs.2)).max_by_key(|k| k.1.len()).cloned();
                    let (from, new) = match grown {
                        Some(k) => {
                            let added: BTreeSet<CommitId> = inputs.1.difference(&k.1).copied().collect();
                            let mut new: BTreeSet<Tid> = inputs.0.difference(&k.0).copied().collect();
                            new.extend(inputs.2.difference(&k.2).copied());
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
                        Some((tl, basis)) => {
                            let tl = tl.extend(&part);
                            if tl.is_none() && basis > 0 {
                                // the walk saved under the root is no basis for an evaluation
                                self.retired.insert(root);
                            }
                            tl.map(|tl| (tl, basis))
                        }
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
                            match self.restore(&inputs, &part, saved, salt) {
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
            let per = inputs.0.iter().filter_map(|t| ids.get(t).map(|s| (*t, s.clone()))).collect();
            self.comps.insert(i, Comp { inputs, tl, basis, per });
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

    /// The timeline of a component with no timeline here from a walk saved under one of its
    /// things (its root first; a component's root changes when a thing with a smaller tid
    /// joins it), continued as at run time: over the new leaves (things with only a
    /// `/created` record), then over the commits added since; and how many commits and
    /// snapshots the walk saved under its root covered (0 when saved under another thing).
    /// Every other walk saved under its things is retired: one under a root that moved
    /// before the next `to_save` (a restart in between) is found only here.
    fn restore(&mut self, inputs: &Inputs, part: &Only<'_>, saved: &mut dyn FnMut(&Tid) -> Option<Vec<u8>>, salt: &[u8]) -> Option<(Timeline, usize)> {
        let mut out = None;
        for (j, t) in inputs.0.iter().enumerate() {
            let Some(bytes) = saved(t) else { continue };
            if out.is_none()
                && let Some(s) = cache::parse(&bytes)
                && let Some(tl) = Self::resume(&s, inputs, part, salt)
            {
                self.restored += 1;
                out = Some((tl, if j == 0 { s.inputs.1.len() } else { 0 }));
                if j == 0 {
                    continue;
                }
            }
            // not under the root, unusable or not used: deleted or overwritten by the next `to_save`
            self.retired.insert(*t);
        }
        out
    }

    fn resume(s: &cache::Saved<'_>, inputs: &Inputs, part: &Only<'_>, salt: &[u8]) -> Option<Timeline> {
        let k = &s.inputs;
        // as `update_region` at run time: things, `/created` records and commits added
        if !(k.0.is_subset(&inputs.0) && k.2.is_subset(&inputs.2) && k.1.is_subset(&inputs.1)) {
            return None;
        }
        let tl = cache::restore(s, part, salt)?;
        if k == inputs {
            return Some(tl);
        }
        tl.extend(part)
    }

    /// The walks a node's cache should hold now: components walked anew or continued since the
    /// last `saved` whose commits and snapshots number at least `min` and grew by at least a
    /// quarter (and `min`) since their walk was last saved, encoded with `salt` (the rules);
    /// and the roots whose saved walk no component uses. `all`: the cache is empty (every
    /// component of at least `min` is saved). Saving amortizes to O(1) per added commit.
    /// Changes nothing here: once the writes are durable, pass `Saves::done` to `saved`.
    pub fn to_save(&self, salt: &[u8], min: usize, all: bool) -> Saves {
        let ids: Vec<u64> = if all { self.comps.keys().copied().collect() } else { self.unsaved.iter().copied().collect() };
        let mut out = Saves::default();
        let mut kept: BTreeSet<Tid> = BTreeSet::new();
        for i in &ids {
            let Some(c) = self.comps.get(i) else { continue };
            let Some(root) = c.inputs.0.first().copied() else { continue };
            if Self::save_due(c, min, all)
                && let Some(bytes) = cache::save(&c.inputs, &c.tl, salt)
            {
                kept.insert(root);
                out.put.push((root, bytes));
                out.done.based.push((*i, c.inputs.1.len()));
            }
        }
        let used = |r: &Tid| self.of.get(r).and_then(|i| self.comps.get(i)).is_some_and(|c| c.basis > 0 && c.inputs.0.first() == Some(r));
        out.delete = self.retired.iter().filter(|r| !kept.contains(*r) && !used(r)).copied().collect();
        out.done.looked = ids;
        out.done.retired = self.retired.iter().copied().collect();
        out
    }

    /// What `to_save` returned is durable.
    pub fn saved(&mut self, done: SaveDone) {
        for i in &done.looked {
            self.unsaved.remove(i);
        }
        for (i, n) in done.based {
            if let Some(c) = self.comps.get_mut(&i) {
                c.basis = n;
            }
        }
        for r in &done.retired {
            self.retired.remove(r);
        }
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

    /// Components the last update continued by `Timeline::append` alone (no re-partition, no
    /// held-set gathering).
    pub fn appended(&self) -> usize {
        self.appended
    }

    /// Commits the last update placed in a walk without walking again (`Timeline::append`).
    pub fn placed(&self) -> usize {
        self.placed
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
