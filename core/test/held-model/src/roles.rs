//! Role timeline and validity (spec/permissions.md §5.1, §5.2, §6, §7). Holders are actors (nodes or
//! things); effective roles are widest paths over edges and owner links; authority classes, invites,
//! `until`, self-removals, finalizes, audits with the edge as restored, and roster snapshots with
//! epoch starts chosen in rounds. Every query replays the settled walk.

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
    Owner,
}

/// The creation records: ownership and first admins.
#[derive(Clone, Debug, Default)]
pub struct World {
    pub owners: BTreeMap<ThingId, Owner>,
}

impl World {
    pub fn new(things: &[Thing]) -> World {
        World { owners: things.iter().map(|t| (t.id, t.owner)).collect() }
    }
    pub fn known(&self, t: ThingId) -> bool {
        self.owners.contains_key(&t)
    }
    pub fn owner(&self, t: ThingId) -> Option<NodeId> {
        match self.owners.get(&t) {
            Some(Owner::Actor(o)) => Some(*o),
            _ => None,
        }
    }
    /// The owners above `t`, nearest first (stops at a key actor, an ownerless thing, an unknown
    /// record or a cycle).
    pub fn chain_above(&self, t: ThingId) -> Vec<NodeId> {
        let mut v = Vec::new();
        let mut x = t;
        while let Some(o) = self.owner(x) {
            if o == t || v.contains(&o) {
                break;
            }
            v.push(o);
            x = o;
        }
        v
    }
    /// `t` and every thing below it by ownership.
    pub fn below(&self, t: ThingId) -> Vec<ThingId> {
        let mut v = vec![t];
        v.extend(self.owners.keys().copied().filter(|&x| x != t && self.chain_above(x).contains(&t)));
        v
    }
    /// The walk's initial state: ownerless things' record edges.
    pub fn initial(&self) -> Edges {
        self.owners
            .iter()
            .filter_map(|(&t, o)| match o {
                Owner::Ownerless { first_admin } => Some(((t, *first_admin), Edge { role: Role::Admin, invite: None, until: None })),
                _ => None,
            })
            .collect()
    }
    /// Effective roles of `x` on everything (widest paths over alive edges and owner links).
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
            for (&t, o) in &self.owners {
                if let Owner::Actor(a) = o {
                    if let Some(&r) = best.get(a) {
                        raise(&mut best, t, r);
                    }
                }
            }
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
    /// X's authority class on N: owner chain (on it, or admin of an actor on it), edge admin, invite.
    pub fn class(&self, edges: &Edges, x: NodeId, n: ThingId, wall: u64) -> Option<Class> {
        let r = self.reach(edges, x, wall);
        if self.chain_above(n).iter().any(|a| r.get(a) == Some(&Role::Admin)) {
            return Some(Class::Owner);
        }
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

/// One edge write of an applied role commit, or one a roster snapshot's start stands for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeEv {
    pub key: Key,
    /// Order inside a key: 0 for a commit's writes, 1 for a roster value taking effect after it.
    pub sub: u8,
    pub commit: CommitId,
    /// The part index; `usize::MAX` for a value of an epoch start's roster or ledger.
    pub part: usize,
    pub thing: ThingId,
    pub author: NodeId,
    pub holder: NodeId,
    pub value: Option<Edge>,
    pub frontier: Option<BTreeSet<CommitId>>,
}

/// A roster snapshot as held (spec/permissions.md §6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roster {
    pub key: Key,
    pub commit: CommitId,
    pub thing: ThingId,
    pub author: NodeId,
    pub edges: Vec<(NodeId, Option<Edge>, Option<Key>)>,
    pub tenures: Vec<(NodeId, Role, Option<Key>, Key, Option<BTreeSet<CommitId>>)>,
}

/// Every edge write held in a role commit of `commits` (roster snapshots apart), in walk order.
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
                    sub: 0,
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
    evs.sort_by(|a, b| (a.key, a.sub, a.holder, a.part).cmp(&(b.key, b.sub, b.holder, b.part)));
    evs
}

/// Every roster snapshot held in `commits`, from its held parts on its one thing. A snapshot whose
/// held parts name one holder twice in `roles.0` takes no part in the walk (spec/permissions.md §6).
pub fn rosters<'a>(commits: impl IntoIterator<Item = &'a Commit>) -> Vec<Roster> {
    let mut out = Vec::new();
    for c in commits {
        if c.kind != CommitKind::Roster {
            continue;
        }
        let Some(thing) = c.parts.first().map(|p| p.thing) else { continue };
        let mut r = Roster { key: c.key(), commit: c.id, thing, author: c.author, edges: vec![], tenures: vec![] };
        for p in c.parts.iter().filter(|p| p.thing == thing) {
            match &p.body {
                Body::Held(Delta::Roster(RosterItem::Edge { edge, since })) => r.edges.push((edge.holder, Edge::of(edge), *since)),
                Body::Held(Delta::Roster(RosterItem::Tenure { holder, role, since, until, frontier })) => {
                    r.tenures.push((*holder, *role, *since, *until, frontier.as_ref().map(|f| f.iter().copied().collect())))
                }
                _ => {}
            }
        }
        let holders: BTreeSet<NodeId> = r.edges.iter().map(|e| e.0).collect();
        if holders.len() == r.edges.len() {
            out.push(r);
        }
    }
    out
}

/// One applied edge write in the settled walk.
#[derive(Clone, Debug)]
pub struct Applied {
    pub ev: EdgeEv,
    pub class: Option<Class>,
    /// Attributed to owner-chain or edge-admin authority (spec/permissions.md §5.1 step 2).
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
    /// Roster snapshots that applied in the settled walk, and the epoch starts.
    pub rosters_applied: BTreeSet<CommitId>,
    pub starts: BTreeMap<ThingId, CommitId>,
}

const LAST: Key = (u64::MAX, NodeId::MAX, CommitId::MAX);

/// What one walk step does.
enum Step<'a> {
    Write(&'a EdgeEv),
    Judge(&'a Roster),
    Start(&'a Roster),
}

impl Timeline {
    /// Epoch starts chosen in rounds (spec/permissions.md §6), each round a settled walk.
    pub fn settle(world: World, evs: Vec<EdgeEv>, rosters: Vec<Roster>) -> Timeline {
        let things: BTreeSet<ThingId> = rosters.iter().map(|r| r.thing).collect();
        let t = things.len();
        let mut excluded: BTreeSet<CommitId> = BTreeSet::new();
        let mut starts: BTreeMap<ThingId, CommitId> = BTreeMap::new();
        let mut round = 0;
        loop {
            round += 1;
            let tl = Timeline::walk(&world, &evs, &rosters, &starts);
            let mut new: BTreeMap<ThingId, CommitId> = BTreeMap::new();
            for r in &rosters {
                if tl.rosters_applied.contains(&r.commit) && !excluded.contains(&r.commit) {
                    let newer = new.get(&r.thing).map_or(true, |c| rosters.iter().find(|x| x.commit == *c).is_some_and(|x| x.key < r.key));
                    if newer {
                        new.insert(r.thing, r.commit);
                    }
                }
            }
            if new == starts {
                return tl;
            }
            if round == t + 1 {
                // every snapshot a start in exactly one of the current and the new starts
                for (&th, &c) in starts.iter().chain(new.iter()) {
                    if starts.get(&th) != new.get(&th) {
                        excluded.insert(c);
                    }
                }
                starts.clear();
                round = 0;
                continue;
            }
            starts = new;
        }
    }

    /// The edge as restored on (n, h) before the walk's current point.
    fn restored(initial: &Edges, applied: &[Applied], n: ThingId, h: NodeId) -> Option<Edge> {
        let on: Vec<&Applied> = applied.iter().filter(|p| p.ev.thing == n && p.ev.holder == h && p.ev.part != usize::MAX - 1).collect();
        let from = on.iter().rposition(|p| p.explicit);
        let mut v = if from.is_none() { initial.get(&(n, h)).copied().map(|e| Edge { until: None, ..e }) } else { None };
        for p in &on[from.unwrap_or(0)..] {
            v = Edge::join(v, p.ev.value);
        }
        v
    }

    /// One settled walk under the given starts (spec/permissions.md §5.1 steps 1-5).
    fn walk(world: &World, evs: &[EdgeEv], rosters: &[Roster], starts: &BTreeMap<ThingId, CommitId>) -> Timeline {
        let start_of = |t: ThingId| starts.get(&t).and_then(|c| rosters.iter().find(|r| r.commit == *c));
        // the roster's word before its start: values at their keys, just after the commit there
        let mut synth: Vec<EdgeEv> = Vec::new();
        for r in starts.values().filter_map(|c| rosters.iter().find(|r| r.commit == *c)) {
            let ev = |key: Key, holder: NodeId, value: Option<Edge>, author: NodeId, frontier: Option<BTreeSet<CommitId>>| EdgeEv {
                key,
                sub: 1,
                commit: r.commit,
                part: usize::MAX,
                thing: r.thing,
                author,
                holder,
                value,
                frontier,
            };
            for (h, role, since, until, f) in &r.tenures {
                let since = since.unwrap_or((0, 0, 0));
                if since < r.key {
                    synth.push(ev(since, *h, Some(Edge { role: *role, invite: None, until: None }), r.author, None));
                }
                if *until < r.key {
                    synth.push(ev(*until, *h, None, until.1, f.clone()));
                }
            }
            for (h, e, since) in &r.edges {
                let since = since.unwrap_or((0, 0, 0));
                if since < r.key {
                    synth.push(ev(since, *h, *e, r.author, None));
                }
            }
        }
        // at one key a tenure's end comes before the next one's start (a role change ends one
        // tenure and starts another at its key, spec/permissions.md §6)
        synth.sort_by_key(|e| e.value.is_some());
        let mut steps: Vec<(Key, u8, u8, NodeId, usize, Step)> = Vec::new();
        for e in evs {
            if start_of(e.thing).is_some_and(|s| e.key < s.key) {
                continue;
            }
            steps.push((e.key, e.sub, 0, e.holder, e.part, Step::Write(e)));
        }
        for e in &synth {
            steps.push((e.key, e.sub, 0, e.holder, e.part, Step::Write(e)));
        }
        for r in rosters {
            steps.push((r.key, 0, 1, 0, 0, Step::Judge(r)));
            if start_of(r.thing).is_some_and(|s| s.commit == r.commit) {
                steps.push((r.key, 0, 2, 0, 0, Step::Start(r)));
            }
        }
        steps.sort_by(|a, b| (a.0, a.1, a.2, a.3, a.4).cmp(&(b.0, b.1, b.2, b.3, b.4)));
        let actors: BTreeSet<NodeId> = world
            .owners
            .keys()
            .copied()
            .chain(evs.iter().flat_map(|e| [e.author, e.holder]))
            .chain(synth.iter().flat_map(|e| [e.author, e.holder]))
            .collect();
        let initial = world.initial();
        let mut dropped: BTreeSet<(CommitId, usize)> = BTreeSet::new();
        'restart: loop {
            let mut edges = initial.clone();
            let mut applied: Vec<Applied> = Vec::new();
            let mut rosters_applied = BTreeSet::new();
            let mut i = 0;
            while i < steps.len() {
                // one commit's writes are judged against the state before the commit
                let key = steps[i].0;
                let sub = steps[i].1;
                let pre = edges.clone();
                let mut j = i;
                while j < steps.len() && steps[j].0 == key && steps[j].1 == sub {
                    j += 1;
                }
                for (_, _, _, _, _, step) in &steps[i..j] {
                    let wall_ = wall(key.0);
                    match step {
                        Step::Judge(r) => {
                            if dropped.contains(&(r.commit, usize::MAX - 1)) {
                                continue;
                            }
                            if world.class(&pre, r.author, r.thing, wall_) == Some(Class::Owner) {
                                rosters_applied.insert(r.commit);
                                let ev = EdgeEv {
                                    key: r.key,
                                    sub: 0,
                                    commit: r.commit,
                                    part: usize::MAX - 1,
                                    thing: r.thing,
                                    author: r.author,
                                    holder: NodeId::MAX,
                                    value: None,
                                    frontier: None,
                                };
                                applied.push(Applied { ev, class: Some(Class::Owner), explicit: false, on: r.thing, before: edges.clone(), after: edges.clone() });
                            }
                        }
                        Step::Start(r) => {
                            let before = edges.clone();
                            edges.retain(|&(t, _), _| t != r.thing);
                            for (h, e, _) in &r.edges {
                                if let Some(e) = e {
                                    if *h != r.thing && world.owner(r.thing) != Some(*h) {
                                        edges.insert((r.thing, *h), *e);
                                    }
                                }
                            }
                            let ev = EdgeEv {
                                key: r.key,
                                sub: 0,
                                commit: r.commit,
                                part: usize::MAX - 2,
                                thing: r.thing,
                                author: r.author,
                                holder: NodeId::MAX,
                                value: None,
                                frontier: None,
                            };
                            applied.push(Applied { ev, class: None, explicit: false, on: r.thing, before, after: edges.clone() });
                        }
                        Step::Write(ev) => {
                            if dropped.contains(&(ev.commit, ev.part)) {
                                continue;
                            }
                            let (n, h, a) = (ev.thing, ev.holder, ev.author);
                            if h == n || world.owner(n) == Some(h) {
                                continue;
                            }
                            let decision = if ev.part == usize::MAX {
                                // a value of the start's roster or ledger: the roster's word
                                Some((None, ev.frontier.is_some(), n))
                            } else {
                                decide(world, &pre, ev, wall_)
                            };
                            let Some((class, explicit, on)) = decision else { continue };
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
                                            if p.ev.author == x && p.on == m && fell_through && p.ev.key < ev.key && !listed && p.ev.part != usize::MAX {
                                                added |= dropped.insert((p.ev.commit, p.ev.part));
                                            }
                                        }
                                    }
                                }
                                if added {
                                    continue 'restart;
                                }
                            }
                            applied.push(Applied { ev: (*ev).clone(), class, explicit, on, before, after: edges.clone() });
                        }
                    }
                }
                i = j;
            }
            let starts = starts.clone();
            return Timeline { world: world.clone(), initial, applied, rosters_applied, starts };
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
    /// taking X's role there, the edge as restored, from `need` or above to below it (ledger
    /// entries with a frontier included).
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
        if let Some(newest) = demos.iter().max_by_key(|d| (d.ev.key, d.ev.sub)) {
            if newest.ev.frontier.as_ref().is_some_and(|f| f.contains(&c)) {
                return true;
            }
        }
        // re-grant: holding the role in the final state revives writes since it first held it
        if self.final_role(thing, x).is_some_and(|r| r >= need) {
            if let Some(k) = self.first_hold(thing, x, need) {
                return key >= k;
            }
        }
        false
    }

    /// A delta of commit `c` (author, header actor) on the thing: the author judged by §5.2, and an
    /// actor other than the author only while the author could write on it (§5.2 Acting).
    pub fn valid_delta(&self, author: NodeId, actor: NodeId, thing: ThingId, need: Role, key: Key, c: CommitId) -> bool {
        // judged by the author's authority; acting needs the author's write on the actor
        self.valid_as(author, thing, need, key, c) && (actor == author || self.valid_as(author, actor, Role::Write, key, c))
    }

    /// The fall of an invalid delta (spec/commits.md §5): the ts of the newest valid explicit
    /// demotion of its author below its need, no earlier than its own ts.
    pub fn fall(&self, x: NodeId, thing: ThingId, need: Role, ts: u64) -> u64 {
        self.demotions(thing, x, need).iter().map(|d| wall(d.ev.key.0)).max().unwrap_or(ts).max(ts)
    }

    /// spec/permissions.md §7: does a request (author `q`, actor `qa`, commit `qc` at `qkey`) hold
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
    // the only authority (no owner-chain or edge-admin authority on the target)
    if lowers(ev.value, cur) && (h == a || (admin_on_h && ca < Some(Class::EdgeAdmin))) {
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

/// Possible admins and writers of each thing (spec/commits.md §4), from every edge write and
/// roster entry of an applied role commit, any validity.
pub struct Possible {
    pub admins: BTreeMap<ThingId, BTreeSet<NodeId>>,
    pub writers: BTreeMap<ThingId, BTreeSet<NodeId>>,
}

/// A role naming: (thing, signer, holder, role).
pub type Naming = (ThingId, NodeId, NodeId, Role);

pub fn namings<'a>(commits: impl IntoIterator<Item = &'a Commit>) -> Vec<Naming> {
    let mut out = Vec::new();
    for c in commits {
        for p in &c.parts {
            match &p.body {
                Body::Held(Delta::Edge(e)) if c.kind == CommitKind::Role => {
                    if let Some(r) = e.role {
                        out.push((p.thing, c.author, e.holder, r));
                    }
                }
                Body::Held(Delta::Roster(RosterItem::Edge { edge, .. })) if c.kind == CommitKind::Roster => {
                    if let Some(r) = edge.role {
                        out.push((p.thing, c.author, edge.holder, r));
                    }
                }
                Body::Held(Delta::Roster(RosterItem::Tenure { holder, role, .. })) if c.kind == CommitKind::Roster => {
                    out.push((p.thing, c.author, *holder, *role));
                }
                _ => {}
            }
        }
    }
    out
}

impl Possible {
    pub fn new(world: &World, ns: &[Naming]) -> Possible {
        let things: BTreeSet<ThingId> = world.owners.keys().copied().chain(ns.iter().flat_map(|n| [n.0, n.2])).collect();
        let pa = |t: ThingId| -> BTreeSet<NodeId> {
            let mut a: BTreeSet<NodeId> = BTreeSet::from([t]);
            loop {
                let n = a.len();
                for m in a.clone() {
                    match world.owners.get(&m) {
                        Some(Owner::Actor(o)) => {
                            a.insert(*o);
                        }
                        Some(Owner::Ownerless { first_admin }) => {
                            a.insert(*first_admin);
                        }
                        _ => {}
                    }
                    for &(th, s, h, r) in ns {
                        if th == m && r == Role::Admin && a.contains(&s) {
                            a.insert(h);
                        }
                    }
                }
                if a.len() == n {
                    return a;
                }
            }
        };
        let admins: BTreeMap<ThingId, BTreeSet<NodeId>> = things.iter().map(|&t| (t, pa(t))).collect();
        let mut writers = BTreeMap::new();
        for &t in &things {
            let mut w = admins[&t].clone();
            loop {
                let n = w.len();
                for m in w.clone().into_iter().chain([t]) {
                    let pm = admins.get(&m).cloned().unwrap_or_else(|| pa(m));
                    w.extend(pm.iter().copied());
                    for &(th, s, h, r) in ns {
                        if th == m && r >= Role::Write && pm.contains(&s) {
                            w.insert(h);
                        }
                    }
                }
                if w.len() == n {
                    break;
                }
            }
            writers.insert(t, w);
        }
        Possible { admins, writers }
    }
    pub fn admin(&self, t: ThingId, x: NodeId) -> bool {
        self.admins.get(&t).is_some_and(|s| s.contains(&x))
    }
    pub fn writer(&self, t: ThingId, x: NodeId) -> bool {
        self.writers.get(&t).is_some_and(|s| s.contains(&x))
    }
    pub fn holder(&self, t: ThingId, x: NodeId, need: Role) -> bool {
        if need == Role::Admin {
            self.admin(t, x)
        } else {
            self.writer(t, x)
        }
    }
    /// spec/commits.md §4 Purged: could each of the request's author and actor hold the right of
    /// a delta (header actor `actor`) by any role ever given.
    pub fn right(&self, q: NodeId, qa: NodeId, by: PurgeBy, actor: NodeId, t: ThingId) -> bool {
        let one = |x: NodeId| {
            let auth = (x == actor || self.writer(actor, x)) && self.writer(t, actor);
            match by {
                PurgeBy::Nobody => false,
                PurgeBy::Admin => self.admin(t, x),
                PurgeBy::Author => auth,
                PurgeBy::AuthorOrAdmin => self.admin(t, x) || auth,
                PurgeBy::Writer => self.writer(t, x),
            }
        };
        one(q) && one(qa)
    }
}

/// The role a delta on `aspect` needs.
pub fn need(a: Aspect) -> Role {
    if a.admin_only {
        Role::Admin
    } else {
        Role::Write
    }
}
