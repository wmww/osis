//! Rotation planner (spec/permissions.md §3): the role secrets a departure exposes, over an
//! abstract membership graph; what a node that lost access drops.

use crate::covers::Departure;
use crate::epoch::ROLES;
use osis_base::{Role, Tid};
use osis_perm::{At, Timeline};
use std::collections::{BTreeMap, BTreeSet};

/// The held membership graph as the planner needs it.
pub trait Graph {
    /// Things `actor` owns directly (its owner link gives it admin on them).
    fn owned(&self, actor: &Tid) -> Vec<Tid>;
    /// Targets of `member`'s current edges, with the edge's role.
    fn edges(&self, member: &Tid) -> Vec<(Tid, Role)>;
    /// Whether `thing` has secrets of its own (else it derives them from its owner).
    fn has_own_secrets(&self, thing: &Tid) -> bool;
}

/// One thing reached by a departure.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    /// The roles of the thing whose secrets the departed party could open.
    pub roles: BTreeSet<Role>,
    /// The departures its epochs must cover (spec/crypto.md §4), one per path: the member's own
    /// on the target, inside each chain of actors it was reached through.
    pub departures: BTreeSet<Departure>,
    /// Secrets of its own: it needs a rotation. A plain thing follows its owner's.
    pub own_secrets: bool,
    /// Hops from the departure (shortest path): rotations go in this order, top-down.
    pub depth: usize,
}

/// What a departure requires.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// The actor departed from.
    pub target: Option<Tid>,
    pub entries: BTreeMap<Tid, Entry>,
}

impl Plan {
    /// The target's rotation, carried by the removal or demotion commit itself
    /// (spec/permissions.md §3, spec/commits.md §2).
    pub fn immediate(&self) -> Option<(Tid, &BTreeSet<Role>)> {
        let t = self.target?;
        self.entries.get(&t).map(|e| (t, &e.roles))
    }

    /// Every (thing, entry) requiring a rotation (things with secrets of their own), top-down:
    /// an intermediate actor before the things reached through it (spec/permissions.md §3).
    pub fn required(&self) -> Vec<(&Tid, &Entry)> {
        let mut v: Vec<(&Tid, &Entry)> = self.entries.iter().filter(|(_, e)| e.own_secrets).collect();
        v.sort_by_key(|(t, e)| (e.depth, **t));
        v
    }

    /// The required rotations this node may make (`may_rotate`: perm's roles it may rotate,
    /// write and above rotates its role and below), top-down. Each is due before the node next
    /// encrypts under the secret it replaces (the covers rule, with the entry's departures); it
    /// may rotate eagerly. Where it may not rotate an intermediate, the things below stay
    /// uncovered and it does not encrypt under them.
    pub fn mine(&self, may_rotate: &dyn Fn(&Tid) -> BTreeSet<Role>) -> Vec<(Tid, BTreeSet<Role>)> {
        self.required()
            .into_iter()
            .filter_map(|(t, e)| {
                let r: BTreeSet<Role> = e.roles.intersection(&may_rotate(t)).copied().collect();
                (!r.is_empty()).then_some((*t, r))
            })
            .collect()
    }
}

/// The rotations required when `member` leaves roles `from` and above of `actor`, having held
/// `held` (spec/permissions.md §3): on the actor the roles it left; on every thing the actor's
/// roles open (owned things, targets of its edges, transitively) the roles the actor holds there
/// among those the roles it left open through it (per-role KEM keys).
pub fn plan_departure(graph: &dyn Graph, actor: Tid, member: Tid, from: Role, held: Role) -> Plan {
    let lost: BTreeSet<Role> = ROLES.into_iter().filter(|r| *r >= from && *r <= held).collect();
    if lost.is_empty() {
        return Plan { target: Some(actor), entries: BTreeMap::new() };
    }
    let mut plan = plan_inside(graph, actor, lost, Departure::member(member, from));
    plan.target = Some(actor);
    plan
}

/// The rotations required by `departure` (as seen from actor X) exposing roles `roles` of X:
/// X itself, then every thing X's roles open, transitively.
pub fn plan_inside(graph: &dyn Graph, x: Tid, roles: BTreeSet<Role>, departure: Departure) -> Plan {
    let first = Entry { roles: roles.clone(), departures: [departure.clone()].into_iter().collect(), own_secrets: graph.has_own_secrets(&x), depth: 0 };
    let mut plan = Plan { target: None, entries: [(x, first)].into_iter().collect() };
    let mut work = vec![(x, roles, departure)];
    while let Some((x, roles, dep)) = work.pop() {
        let mut next: Vec<(Tid, Role)> = graph.owned(&x).into_iter().map(|t| (t, Role::Admin)).collect();
        next.extend(graph.edges(&x));
        for (t, via) in next {
            let opened: BTreeSet<Role> = roles.iter().filter(|r| **r <= via).copied().collect();
            // A path through t already: a cycle.
            if opened.is_empty() || dep.via.contains(&t) || t == dep.member {
                continue;
            }
            let d = Departure::inside(x, &dep);
            let depth = d.via.len();
            let e = plan.entries.entry(t).or_insert_with(|| Entry { own_secrets: graph.has_own_secrets(&t), depth, ..Entry::default() });
            e.depth = e.depth.min(depth);
            let grew = opened.iter().any(|r| !e.roles.contains(r));
            e.roles.extend(opened);
            if e.departures.insert(d.clone()) || grew {
                work.push((t, e.roles.clone(), d));
            }
        }
    }
    plan
}

/// What a node drops on losing read access to `actor` (spec/permissions.md §3): the actor and
/// every thing reached from it whose read it holds by no other path (`still_readable`). The store
/// erases those secrets and units.
pub fn lost_access(graph: &dyn Graph, actor: Tid, still_readable: &dyn Fn(&Tid) -> bool) -> Vec<Tid> {
    let plan = plan_inside(graph, actor, ROLES.into_iter().collect(), Departure::member(actor, Role::Read));
    let mut out = vec![actor];
    out.extend(plan.entries.keys().filter(|t| **t != actor && !still_readable(t)).copied());
    out
}

/// `Graph` over a perm timeline at a point.
pub struct PermGraph<'a> {
    pub timeline: &'a Timeline,
    pub at: At,
    pub own_secrets: &'a dyn Fn(&Tid) -> bool,
}

impl Graph for PermGraph<'_> {
    fn owned(&self, actor: &Tid) -> Vec<Tid> {
        self.timeline.owners().owned(actor).to_vec()
    }
    fn edges(&self, member: &Tid) -> Vec<(Tid, Role)> {
        let edges = self.timeline.edges_at(self.at.point);
        edges.targets(member).filter_map(|t| edges.get(member, t).filter(|e| e.alive_at(self.at.ts)).map(|e| (*t, e.role))).collect()
    }
    fn has_own_secrets(&self, thing: &Tid) -> bool {
        (self.own_secrets)(thing)
    }
}

/// In-memory `Graph` for tests and the simulator.
#[derive(Clone, Debug, Default)]
pub struct MemoryGraph {
    pub owned: BTreeMap<Tid, Vec<Tid>>,
    pub edges: BTreeMap<Tid, Vec<(Tid, Role)>>,
    pub own_secrets: BTreeSet<Tid>,
}

impl Graph for MemoryGraph {
    fn owned(&self, actor: &Tid) -> Vec<Tid> {
        self.owned.get(actor).cloned().unwrap_or_default()
    }
    fn edges(&self, member: &Tid) -> Vec<(Tid, Role)> {
        self.edges.get(member).cloned().unwrap_or_default()
    }
    fn has_own_secrets(&self, thing: &Tid) -> bool {
        self.own_secrets.contains(thing)
    }
}
