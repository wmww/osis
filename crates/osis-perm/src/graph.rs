//! Authority over one edge state (spec/permissions.md §1, §2, §5.1 step 3): effective role as
//! the widest path over membership edges and owner links, effective invite, authority class.

use crate::held::HeldSet;
use crate::types::Edge;
use osis_core::format::MAX_OWNER_DEPTH;
use osis_core::{CreationRecord, Role, Tid, Ts, WallMs};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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
    /// Every owner link, by thing.
    pub fn links(&self) -> impl Iterator<Item = (&Tid, &Owner)> {
        self.owner.iter()
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
        let mut cur = *t;
        for _ in 0..=MAX_OWNER_DEPTH {
            match self.owner(&cur) {
                Some(Owner::Key) => return (up, Some(cur)),
                Some(Owner::Actor(y)) if y != *t && !up.contains(&y) => {
                    up.push(y);
                    cur = y;
                }
                _ => return (up, None),
            }
        }
        (up, None)
    }
}

/// An edge state: every current `/members` edge. The per-target and per-member maps are
/// shared between clones until written (a kept state costs O(targets + members), not
/// O(edges)).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Edges {
    by_target: BTreeMap<Tid, Arc<BTreeMap<Tid, Edge>>>,
    by_member: BTreeMap<Tid, Arc<BTreeSet<Tid>>>,
}

impl Edges {
    pub fn get(&self, member: &Tid, target: &Tid) -> Option<&Edge> {
        self.by_target.get(target).and_then(|m| m.get(member))
    }
    pub fn set(&mut self, member: Tid, target: Tid, edge: Option<Edge>) {
        match edge {
            Some(e) => {
                if self.get(&member, &target) == Some(&e) {
                    return;
                }
                Arc::make_mut(self.by_target.entry(target).or_default()).insert(member, e);
                Arc::make_mut(self.by_member.entry(member).or_default()).insert(target);
            }
            None => {
                if self.get(&member, &target).is_none() {
                    return;
                }
                if let Some(m) = self.by_target.get_mut(&target) {
                    let m = Arc::make_mut(m);
                    m.remove(&member);
                    if m.is_empty() {
                        self.by_target.remove(&target);
                    }
                }
                if let Some(s) = self.by_member.get_mut(&member) {
                    let s = Arc::make_mut(s);
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

/// Edges set over a base edge state, both ways: an edge here replaces the base's (`None`:
/// removed).
#[derive(Clone, Debug, Default)]
pub struct Overlay {
    by_target: BTreeMap<Tid, BTreeMap<Tid, Option<Edge>>>,
    by_member: BTreeMap<Tid, BTreeMap<Tid, Option<Edge>>>,
}

impl Overlay {
    pub fn set(&mut self, member: Tid, target: Tid, edge: Option<Edge>) {
        self.by_target.entry(target).or_default().insert(member, edge);
        self.by_member.entry(member).or_default().insert(target, edge);
    }
    fn get(&self, member: &Tid, target: &Tid) -> Option<Option<Edge>> {
        self.by_member.get(member).and_then(|m| m.get(target)).copied()
    }
}

/// An edge state as a base state (a kept one) with an overlay of the changes since: a past
/// state without copying the base.
#[derive(Clone, Debug)]
pub struct EdgesAt<'a> {
    base: &'a Edges,
    over: Overlay,
}

impl<'a> EdgesAt<'a> {
    pub fn new(base: &'a Edges) -> EdgesAt<'a> {
        EdgesAt { base, over: Overlay::default() }
    }
    pub fn set(&mut self, member: Tid, target: Tid, edge: Option<Edge>) {
        self.over.set(member, target, edge);
    }
    pub fn get(&self, member: &Tid, target: &Tid) -> Option<&Edge> {
        match self.over.by_member.get(member).and_then(|m| m.get(target)) {
            Some(e) => e.as_ref(),
            None => self.base.get(member, target),
        }
    }
    /// Edges on `target`, by member.
    pub fn members(&self, target: &Tid) -> impl Iterator<Item = (&Tid, &Edge)> {
        let over = self.over.by_target.get(target);
        let base = self.base.members(target).filter(move |(m, _)| over.is_none_or(|o| !o.contains_key(*m)));
        base.chain(over.into_iter().flatten().filter_map(|(m, e)| e.as_ref().map(|e| (m, e))))
    }
    /// Targets of `member`'s edges.
    pub fn targets(&self, member: &Tid) -> impl Iterator<Item = &Tid> {
        let over = self.over.by_member.get(member);
        let base = self.base.targets(member).filter(move |t| over.is_none_or(|o| !o.contains_key(*t)));
        base.chain(over.into_iter().flatten().filter_map(|(t, e)| e.as_ref().map(|_| t)))
    }
    pub fn iter(&self) -> impl Iterator<Item = (&Tid, &Tid, &Edge)> {
        let over = &self.over;
        let base = self.base.iter().filter(move |(m, t, _)| over.get(m, t).is_none());
        base.chain(over.by_target.iter().flat_map(|(t, m)| m.iter().filter_map(move |(mem, e)| e.as_ref().map(|e| (mem, t, e)))))
    }
}

/// What a standing on a thing reads besides the node's roles: the thing's owner chain (and
/// the key actor at its top) and its members holding an invite (edges alive).
pub struct Reads {
    pub up: Vec<Tid>,
    pub top: Option<Tid>,
    pub invites: Vec<(Tid, Edge)>,
}

impl Reads {
    /// Standing of `x` on the thing `n` these are of, given `x`'s roles.
    pub fn standing(&self, x: &Tid, best: &BTreeMap<Tid, Role>, n: &Tid) -> Standing {
        let role = best.get(n).copied();
        let class = if self.top == Some(*x) || self.up.iter().any(|y| best.get(y) == Some(&Role::Admin)) {
            Class::Chain
        } else if role == Some(Role::Admin) {
            Class::Edge
        } else {
            let inv = self.invites.iter().filter_map(|(m, e)| Some(e.invite?.min(*best.get(m)?).min(e.role))).max();
            inv.map_or(Class::None, Class::Invite)
        };
        Standing { class, role }
    }
}

/// One edge set to a value over an edge state: (member, target, value).
pub type Patch = (Tid, Tid, Option<Edge>);

/// Authority queries over owners and an edge state (optionally a base with an overlay), with
/// edges alive at `ts` (`None`: the end of time), and optionally one edge patched.
pub struct View<'a> {
    pub owners: &'a Owners,
    edges: &'a Edges,
    over: Option<&'a Overlay>,
    pub ts: Option<Ts>,
    patch: Option<Patch>,
}

impl<'a> View<'a> {
    pub fn new(owners: &'a Owners, edges: &'a Edges, ts: Option<Ts>) -> View<'a> {
        View { owners, edges, over: None, ts, patch: None }
    }
    /// A view of a past edge state.
    pub fn at(owners: &'a Owners, edges: &'a EdgesAt<'a>, ts: Option<Ts>) -> View<'a> {
        let over = Some(&edges.over).filter(|o| !o.by_member.is_empty());
        View { owners, edges: edges.base, over, ts, patch: None }
    }
    /// The same view with edge (member, target) set to `edge`.
    pub fn patched(self, member: Tid, target: Tid, edge: Option<Edge>) -> View<'a> {
        View { patch: Some((member, target, edge)), ..self }
    }

    /// `f` on each edge of `member`: (target, value).
    fn each_target(&self, member: &Tid, mut f: impl FnMut(&Tid, &Edge)) {
        let patch = self.patch.as_ref().filter(|p| p.0 == *member);
        let over = self.over.and_then(|o| o.by_member.get(member));
        for t in self.edges.targets(member) {
            if patch.is_some_and(|p| p.1 == *t) || over.is_some_and(|o| o.contains_key(t)) {
                continue;
            }
            if let Some(e) = self.edges.get(member, t) {
                f(t, e);
            }
        }
        for (t, e) in over.into_iter().flatten() {
            if let Some(e) = e.as_ref().filter(|_| patch.is_none_or(|p| p.1 != *t)) {
                f(t, e);
            }
        }
        if let Some((_, t, Some(e))) = patch {
            f(t, e);
        }
    }

    /// `f` on each edge on `target`: (member, value).
    fn each_member(&self, target: &Tid, mut f: impl FnMut(&Tid, &Edge)) {
        let patch = self.patch.as_ref().filter(|p| p.1 == *target);
        let over = self.over.and_then(|o| o.by_target.get(target));
        for (m, e) in self.edges.members(target) {
            if patch.is_none_or(|p| p.0 != *m) && over.is_none_or(|o| !o.contains_key(m)) {
                f(m, e);
            }
        }
        for (m, e) in over.into_iter().flatten() {
            if let Some(e) = e.as_ref().filter(|_| patch.is_none_or(|p| p.0 != *m)) {
                f(m, e);
            }
        }
        if let Some((m, _, Some(e))) = patch {
            f(m, e);
        }
    }

    /// Effective role of `x` on every thing it reaches (spec/permissions.md §1): the maximum
    /// over paths of the minimum role along the path; `x` is admin of itself, an owner of what
    /// it owns.
    pub fn roles_from(&self, x: &Tid) -> BTreeMap<Tid, Role> {
        self.roles_expiring(x).0
    }

    /// `roles_from` and the earliest `until` of an edge it followed: the answer holds at any
    /// later ts before that, while no edge of a node it reaches changes.
    pub fn roles_expiring(&self, x: &Tid) -> (BTreeMap<Tid, Role>, Option<WallMs>) {
        let mut expires: Option<WallMs> = None;
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
                self.each_target(&e, |t, edge| {
                    if edge.alive_at(self.ts) {
                        if let Some(u) = edge.until {
                            expires = Some(expires.map_or(u, |e| e.min(u)));
                        }
                        relax(*t, level.min(edge.role), &mut stack);
                    }
                });
            }
        }
        (best, expires)
    }

    /// What `x`'s roles gain over `best`, its roles over edges this view dominates (every
    /// edge here at least as wide, alive at `ts`), where only edges out of `seeds` may be
    /// wider: the raised entries. `best` with them equals `roles_from` on this view.
    pub fn roles_raised(&self, best: &BTreeMap<Tid, Role>, seeds: &[Tid]) -> BTreeMap<Tid, Role> {
        self.roles_raised_expiring(best, seeds).0
    }

    /// `roles_raised` and the earliest `until` of an edge it followed.
    pub fn roles_raised_expiring(&self, best: &BTreeMap<Tid, Role>, seeds: &[Tid]) -> (BTreeMap<Tid, Role>, Option<WallMs>) {
        let mut expires: Option<WallMs> = None;
        let mut raised: BTreeMap<Tid, Role> = BTreeMap::new();
        let mut stack: Vec<Tid> = seeds.iter().filter(|s| best.contains_key(s)).copied().collect();
        while let Some(e) = stack.pop() {
            let Some(level) = raised.get(&e).or_else(|| best.get(&e)).copied() else { continue };
            let mut raise = |y: Tid, v: Role, stack: &mut Vec<Tid>| {
                if raised.get(&y).or_else(|| best.get(&y)).is_none_or(|&b| v > b) {
                    raised.insert(y, v);
                    stack.push(y);
                }
            };
            for &y in self.owners.owned(&e) {
                raise(y, level, &mut stack);
            }
            self.each_target(&e, |t, edge| {
                if edge.alive_at(self.ts) {
                    if let Some(u) = edge.until {
                        expires = Some(expires.map_or(u, |e| e.min(u)));
                    }
                    raise(*t, level.min(edge.role), &mut stack);
                }
            });
        }
        (raised, expires)
    }

    /// Every entity's effective role on `y` (`roles_from(x)[y]` for each `x`): the widest
    /// paths searched backward from `y`.
    pub fn roles_to(&self, y: &Tid) -> BTreeMap<Tid, Role> {
        self.roles_to_any(&[*y])
    }

    /// Every entity's highest effective role on any of `ys`.
    pub fn roles_to_any(&self, ys: &[Tid]) -> BTreeMap<Tid, Role> {
        let mut best: BTreeMap<Tid, Role> = ys.iter().map(|y| (*y, Role::Admin)).collect();
        let mut stack = ys.to_vec();
        while let Some(t) = stack.pop() {
            let Some(&level) = best.get(&t) else { continue };
            let mut up: Vec<(Tid, Role)> = self.owners.owner_actor(&t).map(|o| (o, level)).into_iter().collect();
            self.each_member(&t, |m, e| {
                if e.alive_at(self.ts) {
                    up.push((*m, level.min(e.role)));
                }
            });
            for (z, v) in up {
                if best.get(&z).is_none_or(|&b| v > b) {
                    best.insert(z, v);
                    stack.push(z);
                }
            }
        }
        best
    }

    /// Effective invite on `n` given `x`'s roles (spec/permissions.md §2).
    pub fn invite(&self, best: &BTreeMap<Tid, Role>, n: &Tid) -> Option<Role> {
        let mut inv = None;
        self.each_member(n, |m, e| {
            if let (Some(i), Some(&r), true) = (e.invite, best.get(m), e.alive_at(self.ts)) {
                inv = inv.max(Some(i.min(r).min(e.role)));
            }
        });
        inv
    }

    /// Standing of `x` on `n` given `x`'s roles.
    pub fn standing(&self, x: &Tid, best: &BTreeMap<Tid, Role>, n: &Tid) -> Standing {
        self.reads(n).standing(x, best, n)
    }

    /// What a standing on `n` reads besides the node's roles.
    pub fn reads(&self, n: &Tid) -> Reads {
        let (up, top) = self.owners.chain(n);
        let mut invites = Vec::new();
        self.each_member(n, |m, e| {
            if e.invite.is_some() && e.alive_at(self.ts) {
                invites.push((*m, *e));
            }
        });
        Reads { up, top, invites }
    }

    /// Standing on `n` from its parts: whether the node is admin on `n`'s owner chain, its role
    /// on `n`, and its roles on `n`'s members (for the invite).
    pub fn standing_from(&self, chain: bool, role: Option<Role>, best: &BTreeMap<Tid, Role>, n: &Tid) -> Standing {
        let class = if chain {
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
            for y in self.owners.owned(&e) {
                if seen.insert(*y) {
                    stack.push(*y);
                }
            }
            self.each_target(&e, |y, _| {
                if seen.insert(*y) {
                    stack.push(*y);
                }
            });
        }
        seen
    }

    /// Entities from which admin flows to `start` (included): owner links and admin edges
    /// alive at `ts`.
    pub fn admin_reaching(&self, start: &Tid) -> BTreeSet<Tid> {
        let mut seen = BTreeSet::from([*start]);
        let mut stack = vec![*start];
        while let Some(e) = stack.pop() {
            let mut up: Vec<Tid> = self.owners.owner_actor(&e).into_iter().collect();
            self.each_member(&e, |m, ed| {
                if ed.role == Role::Admin && ed.alive_at(self.ts) {
                    up.push(*m);
                }
            });
            for y in up {
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
            let mut up: Vec<Tid> = self.owners.owner_actor(&e).into_iter().collect();
            self.each_member(&e, |m, _| up.push(*m));
            for y in up {
                if seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        seen
    }
}
