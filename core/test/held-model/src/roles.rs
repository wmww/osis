//! Role timeline and validity (spec/permissions.md §5.1, §5.2, §6). Holders are actors (nodes or
//! things); effective roles are widest paths over edges (record edges included); authority classes, invites,
//! `until`, self-removals, finalizes and audits with the edge as restored; addenda (§5.2) as a
//! least fixpoint over the settled walk. Every query replays the settled walk.

use crate::types::*;
use std::collections::{BTreeMap, BTreeSet};

/// A standing edge value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Edge {
    pub role: Role,
    pub invite: Option<Role>,
    pub until: Option<u64>,
}

impl Edge {
    pub fn alive(&self, wall: u64) -> bool {
        self.until.map_or(true, |u| wall < u)
    }
    pub fn of(w: &EdgeWrite) -> Option<Edge> {
        w.role.map(|role| Edge { role, invite: w.invite, until: w.until })
    }
    /// Componentwise maximum, alive (spec/permissions.md §5.1 Edge as restored).
    fn join(a: Option<Edge>, b: Option<Edge>) -> Option<Edge> {
        match (a, b) {
            (None, x) | (x, None) => x.map(|e| Edge { until: None, ..e }),
            (Some(a), Some(b)) => Some(Edge { role: a.role.max(b.role), invite: a.invite.max(b.invite), until: None }),
        }
    }
}

/// `new` lowers `cur` (spec/permissions.md §2 Self-removal): a removal, or no component above.
fn lowers(new: Option<Edge>, cur: Option<Edge>) -> bool {
    let until_le = |a: Option<u64>, b: Option<u64>| match (a, b) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(a), Some(b)) => a <= b,
    };
    match (new, cur) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(n), Some(c)) => n.role <= c.role && n.invite <= c.invite && until_le(n.until, c.until),
    }
}

pub type Edges = BTreeMap<(ThingId, NodeId), Edge>;

/// Authority class (spec/permissions.md §5.1 step 3), weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    Invite(Role),
    EdgeAdmin,
}

/// The creation records known: first admins.
#[derive(Clone, Debug, Default)]
pub struct World {
    pub links: BTreeMap<ThingId, RecordLink>,
}

impl World {
    pub fn new(records: &[Record]) -> World {
        World { links: records.iter().map(|t| (t.id, t.link)).collect() }
    }
    pub fn known(&self, t: ThingId) -> bool {
        self.links.contains_key(&t)
    }
    pub fn first_admin(&self, t: ThingId) -> Option<NodeId> {
        match self.links.get(&t) {
            Some(RecordLink::Admin(o)) => Some(*o),
            _ => None,
        }
    }
    /// The record chain above `t`, nearest first (stops at a key actor, an unknown record or a
    /// cycle).
    pub fn chain_above(&self, t: ThingId) -> Vec<NodeId> {
        let mut v = Vec::new();
        let mut x = t;
        while let Some(o) = self.first_admin(x) {
            if o == t || v.contains(&o) {
                break;
            }
            v.push(o);
            x = o;
        }
        v
    }
    /// `t` and every thing below it by record chain.
    pub fn below(&self, t: ThingId) -> Vec<ThingId> {
        let mut v = vec![t];
        v.extend(self.links.keys().copied().filter(|&x| x != t && self.chain_above(x).contains(&t)));
        v
    }
    /// The walk's initial state: every thing's record edge.
    pub fn initial(&self) -> Edges {
        self.links
            .iter()
            .filter_map(|(&t, o)| match o {
                RecordLink::Admin(a) => Some(((t, *a), Edge { role: Role::Admin, invite: None, until: None })),
                RecordLink::Key => None,
            })
            .collect()
    }
    /// Effective roles of `x` on everything (widest paths over alive edges).
    pub fn reach(&self, edges: &Edges, x: NodeId, wall: u64) -> BTreeMap<NodeId, Role> {
        let mut best = BTreeMap::from([(x, Role::Admin)]);
        loop {
            let mut changed = false;
            let mut raise = |best: &mut BTreeMap<NodeId, Role>, t: NodeId, r: Role| {
                if best.get(&t).map_or(true, |&b| b < r) {
                    best.insert(t, r);
                    changed = true;
                }
            };
            for (&(t, h), e) in edges {
                if e.alive(wall) {
                    if let Some(&r) = best.get(&h) {
                        raise(&mut best, t, r.min(e.role));
                    }
                }
            }
            if !changed {
                return best;
            }
        }
    }
    pub fn role(&self, edges: &Edges, x: NodeId, n: ThingId, wall: u64) -> Option<Role> {
        self.reach(edges, x, wall).get(&n).copied()
    }
    /// X's authority class on N: edge admin, invite.
    pub fn class(&self, edges: &Edges, x: NodeId, n: ThingId, wall: u64) -> Option<Class> {
        let r = self.reach(edges, x, wall);
        let mut best = None;
        for (&(t, h), e) in edges {
            if t != n || !e.alive(wall) {
                continue;
            }
            let Some(&rh) = r.get(&h) else { continue };
            if e.role == Role::Admin && rh == Role::Admin {
                best = best.max(Some(Class::EdgeAdmin));
            }
            if let Some(i) = e.invite {
                best = best.max(Some(Class::Invite(rh.min(i))));
            }
        }
        best
    }
}

/// One edge write of an applied role commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeEv {
    pub key: Key,
    pub commit: CommitId,
    /// The part index.
    pub part: usize,
    pub thing: ThingId,
    pub author: NodeId,
    pub holder: NodeId,
    pub value: Option<Edge>,
    pub frontier: Option<BTreeSet<CommitId>>,
}

/// Every edge write held in a role commit of `commits`, in walk order.
pub fn edge_events<'a>(commits: impl IntoIterator<Item = &'a Commit>) -> Vec<EdgeEv> {
    let mut evs = Vec::new();
    for c in commits {
        if c.kind != CommitKind::Role {
            continue;
        }
        let frontier: Option<BTreeSet<CommitId>> = c.frontier.as_ref().map(|f| f.iter().copied().collect());
        for (i, p) in c.parts.iter().enumerate() {
            if let Body::Held(Delta::Edge(e)) = &p.body {
                evs.push(EdgeEv {
                    key: c.key(),
                    commit: c.id,
                    part: i,
                    thing: p.thing,
                    author: c.author,
                    holder: e.holder,
                    value: Edge::of(e),
                    frontier: frontier.clone(),
                });
            }
        }
    }
    evs.sort_by(|a, b| (a.key, a.holder, a.part).cmp(&(b.key, b.holder, b.part)));
    evs
}

/// One applied edge write in the settled walk.
#[derive(Clone, Debug)]
pub struct Applied {
    pub ev: EdgeEv,
    pub class: Option<Class>,
    /// Attributed to edge-admin authority (spec/permissions.md §5.1 step 2).
    pub explicit: bool,
    /// The thing it counts as a write on (a self-removal through actor M: M).
    pub on: ThingId,
    /// The state before it, its edge as restored when explicit.
    pub before: Edges,
    pub after: Edges,
}

pub struct Timeline {
    pub world: World,
    pub initial: Edges,
    pub applied: Vec<Applied>,
    /// The addenda that count (`vouch`): valid, their author held write on the thing at their key.
    pub counting: Vec<Addendum>,
    /// The valid addenda: (commit, thing).
    pub valid_addenda: BTreeSet<(CommitId, ThingId)>,
}

/// An `addenda.0` delta of a content commit acting for its author (spec/permissions.md §5.2
/// Addenda): per entry the removal it names and the commits it lists, none without its body.
#[derive(Clone, Debug)]
pub struct Addendum {
    pub commit: CommitId,
    pub key: Key,
    pub author: NodeId,
    pub thing: ThingId,
    pub entries: Vec<(CommitId, Vec<CommitId>)>,
}

/// Every addendum among the applied commits `view`.
pub fn addenda<'a>(view: impl IntoIterator<Item = &'a Commit>) -> Vec<Addendum> {
    let mut out = Vec::new();
    for c in view {
        if c.kind != CommitKind::Content || c.actor != c.author {
            continue;
        }
        for p in c.parts.iter().filter(|p| p.aspect == Aspect::ADDENDA) {
            let entries = match &p.body {
                Body::Held(Delta::Addenda(es)) => es.clone(),
                _ => Vec::new(),
            };
            out.push(Addendum { commit: c.id, key: c.key(), author: c.author, thing: p.thing, entries });
        }
    }
    out
}

const LAST: Key = (u64::MAX, NodeId::MAX, CommitId::MAX);

impl Timeline {
    /// The edge as restored on (n, h) before the walk's current point.
    fn restored(initial: &Edges, applied: &[Applied], n: ThingId, h: NodeId) -> Option<Edge> {
        let on: Vec<&Applied> = applied.iter().filter(|p| p.ev.thing == n && p.ev.holder == h).collect();
        let from = on.iter().rposition(|p| p.explicit);
        let mut v = if from.is_none() { initial.get(&(n, h)).copied().map(|e| Edge { until: None, ..e }) } else { None };
        for p in &on[from.unwrap_or(0)..] {
            v = Edge::join(v, p.ev.value);
        }
        v
    }

    /// The settled walk over `evs` (in walk order) from the things' record edges
    /// (spec/permissions.md §5.1 steps 1-5).
    pub fn walk(world: World, evs: Vec<EdgeEv>) -> Timeline {
        let actors: BTreeSet<NodeId> = world.links.keys().copied().chain(evs.iter().flat_map(|e| [e.author, e.holder])).collect();
        let initial = world.initial();
        let mut dropped: BTreeSet<(CommitId, usize)> = BTreeSet::new();
        'restart: loop {
            let mut edges = initial.clone();
            let mut applied: Vec<Applied> = Vec::new();
            // one commit's writes are judged against the state before the commit
            for group in evs.chunk_by(|a, b| a.key == b.key) {
                let pre = edges.clone();
                let wall_ = wall(group[0].key.0);
                for ev in group {
                    if dropped.contains(&(ev.commit, ev.part)) {
                        continue;
                    }
                    let (n, h, a) = (ev.thing, ev.holder, ev.author);
                    if h == n {
                        continue;
                    }
                    let Some((class, explicit, on)) = decide(&world, &pre, ev, wall_) else { continue };
                    let mut before = edges.clone();
                    if explicit {
                        match Timeline::restored(&initial, &applied, n, h) {
                            Some(e) => before.insert((n, h), e),
                            None => before.remove(&(n, h)),
                        };
                    }
                    match ev.value {
                        Some(v) => edges.insert((n, h), v),
                        None => edges.remove(&(n, h)),
                    };
                    // step 4: audits by an explicit write
                    if explicit {
                        let mut added = false;
                        for &x in actors.iter().filter(|&&x| x != a) {
                            for m in world.below(n) {
                                let cb = world.class(&before, x, m, wall_);
                                let ca = world.class(&edges, x, m, wall_);
                                if ca >= cb {
                                    continue;
                                }
                                for p in &applied {
                                    let fell_through = p.class.is_some_and(|c| Some(c) > ca && Some(c) <= cb);
                                    let listed = ev.frontier.as_ref().is_some_and(|f| f.contains(&p.ev.commit));
                                    if p.ev.author == x && p.on == m && fell_through && p.ev.key < ev.key && !listed {
                                        added |= dropped.insert((p.ev.commit, p.ev.part));
                                    }
                                }
                            }
                        }
                        if added {
                            continue 'restart;
                        }
                    }
                    applied.push(Applied { ev: ev.clone(), class, explicit, on, before, after: edges.clone() });
                }
            }
            return Timeline { world, initial, applied, counting: Vec::new(), valid_addenda: BTreeSet::new() };
        }
    }

    pub fn applied_part(&self, c: CommitId, part: usize) -> bool {
        self.applied.iter().any(|e| e.ev.commit == c && e.ev.part == part)
    }

    /// The edge state just before `key`.
    pub fn state_at(&self, key: Key) -> &Edges {
        self.applied.iter().rev().find(|p| p.ev.key < key).map_or(&self.initial, |p| &p.after)
    }

    /// X's effective role on the thing just before `key` (edges' `until` judged at its ts).
    pub fn role_at(&self, thing: ThingId, x: NodeId, key: Key) -> Option<Role> {
        self.world.role(self.state_at(key), x, thing, wall(key.0))
    }

    /// The final state, every edge with an `until` counted as removed (spec/permissions.md §5.2).
    fn final_role(&self, thing: ThingId, x: NodeId) -> Option<Role> {
        let mut s = self.state_at(LAST).clone();
        s.retain(|_, e| e.until.is_none());
        self.world.role(&s, x, thing, 0)
    }

    /// Valid explicit demotions of X below `need` on the thing: explicit writes by another author
    /// taking X's role there, the edge as restored, from `need` or above to below it.
    pub fn demotions(&self, thing: ThingId, x: NodeId, need: Role) -> Vec<&Applied> {
        self.applied
            .iter()
            .filter(|p| {
                let w = wall(p.ev.key.0);
                p.explicit
                    && p.ev.author != x
                    && self.world.role(&p.before, x, thing, w).is_some_and(|r| r >= need)
                    && !self.world.role(&p.after, x, thing, w).is_some_and(|r| r >= need)
            })
            .collect()
    }

    /// The first point X held `need` or above (spec/permissions.md §5.2 re-grant).
    fn first_hold(&self, thing: ThingId, x: NodeId, need: Role) -> Option<Key> {
        if self.world.role(&self.initial, x, thing, 0).is_some_and(|r| r >= need) {
            return Some((0, 0, 0));
        }
        self.applied.iter().find(|p| self.world.role(&p.after, x, thing, wall(p.ev.key.0)).is_some_and(|r| r >= need)).map(|p| p.ev.key)
    }

    /// spec/permissions.md §5.2: would a delta by X on the thing, needing `need`, in commit `c` at
    /// `key`, be valid.
    pub fn valid_as(&self, x: NodeId, thing: ThingId, need: Role, key: Key, c: CommitId) -> bool {
        let held = self.role_at(thing, x, key).is_some_and(|r| r >= need);
        let demos = self.demotions(thing, x, need);
        if held && !demos.iter().any(|d| d.ev.key > key) {
            return true;
        }
        // a frontier is what its demoter had received: any demotion's, whatever the order
        if demos.iter().any(|d| d.ev.frontier.as_ref().is_some_and(|f| f.contains(&c))) {
            return true;
        }
        // re-grant: holding the role in the final state revives writes since it first held it
        if self.final_role(thing, x).is_some_and(|r| r >= need) {
            if let Some(k) = self.first_hold(thing, x, need) {
                return key >= k;
            }
        }
        false
    }

    /// The least fixpoint of the addenda (spec/permissions.md §5.2 Addenda): an addendum is valid
    /// as its author's plain delta on its thing, by `valid_as` or vouched for by a counting one;
    /// it counts while valid and its author held write on the thing just before its key.
    pub fn vouch(&mut self, addenda: Vec<Addendum>) {
        let mut valid: BTreeSet<usize> = BTreeSet::new();
        loop {
            let counting: Vec<&Addendum> = valid.iter().map(|&i| &addenda[i]).filter(|a| self.writes_at(a)).collect();
            let next: BTreeSet<usize> = (0..addenda.len())
                .filter(|&i| {
                    let a = &addenda[i];
                    valid.contains(&i) || self.valid_as(a.author, a.thing, Role::Write, a.key, a.commit) || self.vouched_by(&counting, a.thing, a.author, a.key, a.commit)
                })
                .collect();
            if next == valid {
                break;
            }
            valid = next;
        }
        self.valid_addenda = valid.iter().map(|&i| (addenda[i].commit, addenda[i].thing)).collect();
        self.counting = valid.into_iter().map(|i| addenda[i].clone()).filter(|a| self.writes_at(a)).collect();
    }

    fn writes_at(&self, a: &Addendum) -> bool {
        self.role_at(a.thing, a.author, a.key).is_some_and(|r| r >= Role::Write)
    }

    /// A counting addendum of `counting` on the thing names an explicit demotion of X below
    /// write there ordered after `key` and before the addendum, and lists `c`.
    fn vouched_by(&self, counting: &[&Addendum], thing: ThingId, x: NodeId, key: Key, c: CommitId) -> bool {
        let demos = self.demotions(thing, x, Role::Write);
        counting.iter().filter(|a| a.thing == thing).any(|a| {
            a.entries.iter().any(|(removal, lists)| lists.contains(&c) && demos.iter().any(|d| d.ev.commit == *removal && key < d.ev.key && d.ev.key < a.key))
        })
    }

    fn vouched(&self, thing: ThingId, x: NodeId, key: Key, c: CommitId) -> bool {
        self.vouched_by(&self.counting.iter().collect::<Vec<_>>(), thing, x, key, c)
    }

    /// Commit `c`'s delta on `aspect` of the thing (spec/permissions.md §5.2): judged by its
    /// author's authority, or for plain content (a content commit carrying no purge request, an
    /// aspect neither role-class nor admin-only) vouched for by an addendum; an addendum by the
    /// fixpoint (`vouch`). A header actor other than the author needs the author's write on it,
    /// or an addendum on the actor vouching for the commit (Acting).
    pub fn valid_delta(&self, c: &Commit, thing: ThingId, aspect: Aspect) -> bool {
        let (x, key) = (c.author, c.key());
        let plain = c.kind == CommitKind::Content && c.purge.is_empty();
        let acts = c.actor == x || self.valid_as(x, c.actor, Role::Write, key, c.id) || plain && self.vouched(c.actor, x, key, c.id);
        if aspect == Aspect::ADDENDA {
            return acts && self.valid_addenda.contains(&(c.id, thing));
        }
        let need = need(aspect);
        acts && (self.valid_as(x, thing, need, key, c.id) || plain && need == Role::Write && aspect != Aspect::ROLES && self.vouched(thing, x, key, c.id))
    }

    /// spec/permissions.md §6: does a request (author `q`, actor `qa`, commit `qc` at `qkey`) hold
    /// the right over a delta purgeable by `by`, of header actor `actor`, on the thing.
    #[allow(clippy::too_many_arguments)]
    pub fn right(&self, q: NodeId, qa: NodeId, qkey: Key, qc: CommitId, by: PurgeBy, actor: NodeId, thing: ThingId) -> bool {
        let both = |need: Role| self.valid_as(q, thing, need, qkey, qc) && (qa == q || self.valid_as(qa, thing, need, qkey, qc));
        let admin = || both(Role::Admin);
        // `author`: the delta's actor while it holds write on the thing, held by it and by any
        // node with write on it; each signer holds it on its own
        let on_actor = |x: NodeId| x == actor || self.valid_as(x, actor, Role::Write, qkey, qc);
        let auth = || on_actor(q) && on_actor(qa) && self.valid_as(actor, thing, Role::Write, qkey, qc);
        match by {
            PurgeBy::Nobody => false,
            PurgeBy::Admin => admin(),
            PurgeBy::Author => auth(),
            PurgeBy::AuthorOrAdmin => admin() || auth(),
            PurgeBy::Writer => both(Role::Write),
        }
    }

}

/// Step 2: does an edge write apply, with its class, whether it is explicit and the thing it
/// counts as a write on.
fn decide(world: &World, pre: &Edges, ev: &EdgeEv, wall_: u64) -> Option<(Option<Class>, bool, ThingId)> {
    let (n, h, a) = (ev.thing, ev.holder, ev.author);
    let cur = pre.get(&(n, h)).copied();
    let ra = world.reach(pre, a, wall_);
    let on_n = ra.get(&n).copied();
    let admin_on_h = ra.get(&h) == Some(&Role::Admin);
    let ca = world.class(pre, a, n, wall_);
    let removal = ev.value.map_or(true, |v| v.until == Some(0));
    // self-removal: lowering one's own edge, or an edge of a holder one is admin of when that is
    // the only authority (no edge-admin authority on the target with the holder's edge there
    // disregarded: authority through the holder does not count, a record edge's included)
    let without = || {
        let mut e = pre.clone();
        e.remove(&(n, h));
        world.class(&e, a, n, wall_)
    };
    if lowers(ev.value, cur) && (h == a || (admin_on_h && without() < Some(Class::EdgeAdmin))) {
        return Some(if h == a { (ca, false, n) } else { (world.class(pre, a, h, wall_), false, h) });
    }
    // finalize: any other frontier-less removal of another holder's edge
    if removal && ev.frontier.is_none() && lowers(ev.value, cur) {
        let ok = cur.is_some_and(|c| !c.alive(wall_) && on_n >= Some(Role::Write) && on_n >= Some(c.role));
        return ok.then_some((None, false, n));
    }
    if ca >= Some(Class::EdgeAdmin) {
        return Some((ca, true, n));
    }
    if let Some(Class::Invite(inv)) = ca {
        let fresh = cur.map_or(true, |c| !c.alive(wall_));
        if let Some(v) = ev.value {
            if fresh && v.alive(wall_) && v.role <= inv && v.invite.map_or(true, |i| i <= inv) {
                return Some((ca, false, n));
            }
        }
    }
    None
}

/// A role naming: (thing, signer, holder, role).
pub type Naming = (ThingId, NodeId, NodeId, Role);

pub fn namings<'a>(commits: impl IntoIterator<Item = &'a Commit>) -> Vec<Naming> {
    let mut out = Vec::new();
    for c in commits {
        for p in &c.parts {
            if let (CommitKind::Role, Body::Held(Delta::Edge(EdgeWrite { holder, role: Some(r), .. }))) = (c.kind, &p.body) {
                out.push((p.thing, c.author, *holder, *r));
            }
        }
    }
    out
}

/// The role a delta on `aspect` needs.
pub fn need(a: Aspect) -> Role {
    if a.admin_only {
        Role::Admin
    } else {
        Role::Write
    }
}
