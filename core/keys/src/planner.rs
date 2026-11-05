//! The things an actor's roles open, over an abstract role graph: where a removal is placed
//! (spec/permissions.md §3) and what a node that lost access drops.

use osis_base::{Role, Tid};
use osis_perm::{At, Timeline};
use std::collections::{BTreeMap, BTreeSet};

/// The held role graph.
pub trait Graph {
    /// Things `actor` owns directly (its owner link gives it admin on them).
    fn owned(&self, actor: &Tid) -> Vec<Tid>;
    /// Targets of `holder`'s current edges, with the edge's role.
    fn edges(&self, holder: &Tid) -> Vec<(Tid, Role)>;
}

/// The things `x`'s roles open (owned things, targets of its edges, transitively), never
/// through `avoid`, in time linear in the graph.
pub fn reached(graph: &dyn Graph, x: Tid, avoid: Tid) -> BTreeSet<Tid> {
    let mut out = BTreeSet::new();
    let mut work = vec![x];
    while let Some(v) = work.pop() {
        let next = graph.owned(&v).into_iter().chain(graph.edges(&v).into_iter().map(|(t, _)| t));
        for t in next {
            if t != x && t != avoid && out.insert(t) {
                work.push(t);
            }
        }
    }
    out
}

/// What a node drops on losing read access to `actor` (spec/permissions.md §3): the actor and
/// every thing reached from it whose read it holds by no other path (`still_readable`). The store
/// erases those secrets and units.
pub fn lost_access(graph: &dyn Graph, actor: Tid, still_readable: &dyn Fn(&Tid) -> bool) -> Vec<Tid> {
    let mut out = vec![actor];
    out.extend(reached(graph, actor, actor).into_iter().filter(|t| !still_readable(t)));
    out
}

/// `Graph` over a perm timeline at a point.
pub struct PermGraph<'a> {
    pub timeline: &'a Timeline,
    pub at: At,
}

impl Graph for PermGraph<'_> {
    fn owned(&self, actor: &Tid) -> Vec<Tid> {
        self.timeline.owners().owned(actor).to_vec()
    }
    fn edges(&self, holder: &Tid) -> Vec<(Tid, Role)> {
        let edges = self.timeline.edges_at(self.at.point);
        edges.targets(holder).filter_map(|t| edges.get(holder, t).filter(|e| e.alive_at(self.at.ts)).map(|e| (*t, e.role))).collect()
    }
}

/// In-memory `Graph` for tests and the simulator.
#[derive(Clone, Debug, Default)]
pub struct MemoryGraph {
    pub owned: BTreeMap<Tid, Vec<Tid>>,
    pub edges: BTreeMap<Tid, Vec<(Tid, Role)>>,
}

impl Graph for MemoryGraph {
    fn owned(&self, actor: &Tid) -> Vec<Tid> {
        self.owned.get(actor).cloned().unwrap_or_default()
    }
    fn edges(&self, holder: &Tid) -> Vec<(Tid, Role)> {
        self.edges.get(holder).cloned().unwrap_or_default()
    }
}
