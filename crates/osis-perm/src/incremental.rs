//! Incremental evaluation (plans/perm.md): the timeline split into connected components of
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

/// A component's exact inputs: its things and the IDs of its commits and snapshots.
type Inputs = (BTreeSet<Tid>, BTreeSet<CommitId>);

/// Timelines per component, cached across held-set changes.
#[derive(Default)]
pub struct Timelines {
    comps: Vec<(Inputs, Timeline)>,
    of: BTreeMap<Tid, usize>,
}

impl Timelines {
    pub fn new() -> Self {
        Self::default()
    }

    /// Re-partitions `held` and evaluates each component whose inputs changed. Returns how
    /// many components were evaluated.
    pub fn update(&mut self, held: &dyn HeldSet) -> usize {
        let things: BTreeSet<Tid> = held.things().into_iter().collect();
        let mut dsu = Dsu::default();
        let mut ids: BTreeMap<Tid, BTreeSet<CommitId>> = BTreeMap::new();
        for t in &things {
            dsu.find(*t);
            if let Some(CreationRecord::Thing { owner, .. }) = held.created(t) {
                dsu.union(*t, owner);
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
        }
        let mut cache: BTreeMap<Inputs, Timeline> = std::mem::take(&mut self.comps).into_iter().collect();
        let mut evaluated = 0;
        self.of.clear();
        for (_, inputs) in groups {
            let tl = match cache.remove(&inputs) {
                Some(tl) => tl,
                None => {
                    evaluated += 1;
                    Timeline::evaluate(&Part { held, things: &inputs.0 })
                }
            };
            let i = self.comps.len();
            for t in &inputs.0 {
                self.of.insert(*t, i);
            }
            self.comps.push((inputs, tl));
        }
        evaluated
    }

    /// The timeline of the component holding `thing` (and every node with a path to it).
    pub fn get(&self, thing: &Tid) -> Option<&Timeline> {
        self.of.get(thing).and_then(|&i| self.comps.get(i)).map(|(_, tl)| tl)
    }

    pub fn components(&self) -> usize {
        self.comps.len()
    }
}
