//! Authority over one edge state (spec/permissions.md §1, §2, §5.1 step 3): effective role as
//! the widest path over membership edges and owner links, effective invite, authority class.

use crate::held::HeldSet;
use crate::types::Edge;
use osis_core::format::MAX_OWNER_DEPTH;
use osis_core::{CreationRecord, Role, Tid, Ts};
use std::collections::{BTreeMap, BTreeSet};

/// A thing's owner link, from its verified `/created` record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Owner {
    Actor(Tid),
    /// A key actor: owns itself.
    Key,
}

/// Authority class of a node on a thing (spec/permissions.md §5.1 step 3), ordered: owner
/// chain above edge admin above every invite level.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Class {
    None,
    Invite(Role),
    Edge,
    Chain,
}

/// A node's standing on a thing: its class and effective role.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Standing {
    pub class: Class,
    pub role: Option<Role>,
}

impl Standing {
    pub const NONE: Standing = Standing { class: Class::None, role: None };
    pub fn max(self, o: Standing) -> Standing {
        Standing { class: self.class.max(o.class), role: self.role.max(o.role) }
    }
}

/// Owner links of every thing with a verified `/created`.
#[derive(Clone, Debug, Default)]
pub struct Owners {
    owner: BTreeMap<Tid, Owner>,
    owned: BTreeMap<Tid, Vec<Tid>>,
}

impl Owners {
    /// From the held `/created` records; one that does not hash to its tid is ignored.
    pub fn from_held(held: &dyn HeldSet, things: &BTreeSet<Tid>) -> Owners {
        let mut o = Owners::default();
        for t in things {
            if let Some(rec) = held.created(t)
                && rec.tid() == *t
            {
                o.insert(*t, &rec);
            }
        }
        o
    }
    pub fn insert(&mut self, t: Tid, rec: &CreationRecord) {
        let link = match rec {
            CreationRecord::Thing { owner, .. } => Owner::Actor(*owner),
            CreationRecord::KeyActor { .. } => Owner::Key,
        };
        if let Owner::Actor(y) = link {
            self.owned.entry(y).or_default().push(t);
        }
        self.owner.insert(t, link);
    }
    pub fn owner(&self, t: &Tid) -> Option<Owner> {
        self.owner.get(t).copied()
    }
    pub fn is_key(&self, t: &Tid) -> bool {
        self.owner(t) == Some(Owner::Key)
    }
    pub fn owned(&self, t: &Tid) -> &[Tid] {
        self.owned.get(t).map_or(&[], |v| v.as_slice())
    }
    /// The owner actor of `t` when it is an ordinary thing.
    pub fn owner_actor(&self, t: &Tid) -> Option<Tid> {
        match self.owner(t) {
            Some(Owner::Actor(y)) => Some(y),
            _ => None,
        }
    }
    /// Strict ancestors of `t` by ownership, nearest first, and the key actor at the top if the
    /// chain reaches one (`t` itself for a key actor) within `MAX_OWNER_DEPTH` owner links
    /// (spec/permissions.md §1: a deeper thing has no owner chain). O(`MAX_OWNER_DEPTH`).
    pub fn chain(&self, t: &Tid) -> (Vec<Tid>, Option<Tid>) {
        let mut up = Vec::new();
        let mut seen = BTreeSet::from([*t]);
        let mut cur = *t;
        for _ in 0..=MAX_OWNER_DEPTH {
            match self.owner(&cur) {
                Some(Owner::Key) => return (up, Some(cur)),
                Some(Owner::Actor(y)) if seen.insert(y) => {
                    up.push(y);
                    cur = y;
                }
                _ => return (up, None),
            }
        }
        (up, None)
    }
}

/// An edge state: every current `/members` edge.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Edges {
    by_target: BTreeMap<Tid, BTreeMap<Tid, Edge>>,
    by_member: BTreeMap<Tid, BTreeSet<Tid>>,
}

impl Edges {
    pub fn get(&self, member: &Tid, target: &Tid) -> Option<&Edge> {
        self.by_target.get(target).and_then(|m| m.get(member))
    }
    pub fn set(&mut self, member: Tid, target: Tid, edge: Option<Edge>) {
        match edge {
            Some(e) => {
                self.by_target.entry(target).or_default().insert(member, e);
                self.by_member.entry(member).or_default().insert(target);
            }
            None => {
                if let Some(m) = self.by_target.get_mut(&target) {
                    m.remove(&member);
                    if m.is_empty() {
                        self.by_target.remove(&target);
                    }
                }
                if let Some(s) = self.by_member.get_mut(&member) {
                    s.remove(&target);
                    if s.is_empty() {
                        self.by_member.remove(&member);
                    }
                }
            }
        }
    }
    /// Edges on `target`, by member.
    pub fn members(&self, target: &Tid) -> impl Iterator<Item = (&Tid, &Edge)> {
        self.by_target.get(target).into_iter().flat_map(|m| m.iter())
    }
    /// Targets of `member`'s edges.
    pub fn targets(&self, member: &Tid) -> impl Iterator<Item = &Tid> {
        self.by_member.get(member).into_iter().flat_map(|s| s.iter())
    }
    pub fn iter(&self) -> impl Iterator<Item = (&Tid, &Tid, &Edge)> {
        self.by_target.iter().flat_map(|(t, m)| m.iter().map(move |(mem, e)| (mem, t, e)))
    }
}

/// Authority queries over owners and an edge state, with edges alive at `ts` (`None`: the end
/// of time).
pub struct View<'a> {
    pub owners: &'a Owners,
    pub edges: &'a Edges,
    pub ts: Option<Ts>,
}

impl View<'_> {
    /// Effective role of `x` on every thing it reaches (spec/permissions.md §1): the maximum
    /// over paths of the minimum role along the path; `x` is admin of itself, an owner of what
    /// it owns.
    pub fn roles_from(&self, x: &Tid) -> BTreeMap<Tid, Role> {
        let mut best: BTreeMap<Tid, Role> = BTreeMap::from([(*x, Role::Admin)]);
        for level in [Role::Admin, Role::Write, Role::Read] {
            let mut stack: Vec<Tid> = best.iter().filter(|&(_, &r)| r == level).map(|(t, _)| *t).collect();
            while let Some(e) = stack.pop() {
                let mut relax = |y: Tid, v: Role, stack: &mut Vec<Tid>| {
                    if best.get(&y).is_none_or(|&b| v > b) {
                        best.insert(y, v);
                        if v == level {
                            stack.push(y);
                        }
                    }
                };
                for &y in self.owners.owned(&e) {
                    relax(y, level, &mut stack);
                }
                for t in self.edges.targets(&e) {
                    if let Some(edge) = self.edges.get(&e, t)
                        && edge.alive_at(self.ts)
                    {
                        relax(*t, level.min(edge.role), &mut stack);
                    }
                }
            }
        }
        best
    }

    /// Effective invite on `n` given `x`'s roles (spec/permissions.md §2).
    pub fn invite(&self, best: &BTreeMap<Tid, Role>, n: &Tid) -> Option<Role> {
        let mut inv = None;
        for (m, e) in self.edges.members(n) {
            if let (Some(i), Some(&r), true) = (e.invite, best.get(m), e.alive_at(self.ts)) {
                inv = inv.max(Some(i.min(r).min(e.role)));
            }
        }
        inv
    }

    /// Standing of `x` on `n` given `x`'s roles.
    pub fn standing(&self, x: &Tid, best: &BTreeMap<Tid, Role>, n: &Tid) -> Standing {
        let role = best.get(n).copied();
        let (up, top) = self.owners.chain(n);
        let class = if top == Some(*x) || up.iter().any(|y| best.get(y) == Some(&Role::Admin)) {
            Class::Chain
        } else if role == Some(Role::Admin) {
            Class::Edge
        } else {
            self.invite(best, n).map_or(Class::None, Class::Invite)
        };
        Standing { class, role }
    }

    /// Things reachable from `start` (included) by owner links and edges of any role and
    /// `until`.
    pub fn reach_forward(&self, start: &Tid) -> BTreeSet<Tid> {
        let mut seen = BTreeSet::from([*start]);
        let mut stack = vec![*start];
        while let Some(e) = stack.pop() {
            for y in self.owners.owned(&e).iter().chain(self.edges.targets(&e)) {
                if seen.insert(*y) {
                    stack.push(*y);
                }
            }
        }
        seen
    }

    /// Entities from which admin flows to `start` (included): owner links and admin edges
    /// alive at `ts`.
    pub fn admin_reaching(&self, start: &Tid) -> BTreeSet<Tid> {
        let mut seen = BTreeSet::from([*start]);
        let mut stack = vec![*start];
        while let Some(e) = stack.pop() {
            let owner = self.owners.owner_actor(&e);
            let admins = self.edges.members(&e).filter(|(_, ed)| ed.role == Role::Admin && ed.alive_at(self.ts)).map(|(m, _)| *m);
            for y in admins.chain(owner) {
                if seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        seen
    }

    /// Entities that reach `start` (included) by owner links and edges of any role and `until`.
    pub fn reach_backward(&self, start: &Tid) -> BTreeSet<Tid> {
        let mut seen = BTreeSet::from([*start]);
        let mut stack = vec![*start];
        while let Some(e) = stack.pop() {
            let owner = self.owners.owner_actor(&e);
            for y in self.edges.members(&e).map(|(m, _)| *m).chain(owner) {
                if seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        seen
    }
}
