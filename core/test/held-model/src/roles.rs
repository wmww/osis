//! Role timeline and validity (spec/permissions.md §5.1, §5.2, §7), single level: holders are nodes,
//! things are owned by nodes, no invites, `until`, self-removals, roster snapshots or acting-for.

use crate::types::*;
use std::collections::{BTreeMap, BTreeSet};

/// One edge write of an applied role commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeEv {
    pub key: Key,
    pub commit: CommitId,
    pub part: usize,
    pub thing: ThingId,
    pub author: NodeId,
    pub holder: NodeId,
    pub role: Option<Role>,
    pub frontier: BTreeSet<CommitId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Owner,
    EdgeAdmin,
}

pub struct Timeline {
    pub owners: BTreeMap<ThingId, NodeId>,
    /// Edge writes that applied in the settled walk, in walk order.
    pub applied: Vec<EdgeEv>,
}

/// Every edge write held in a commit of `commits`, in walk order (key, then holder).
pub fn edge_events<'a>(commits: impl IntoIterator<Item = &'a Commit>) -> Vec<EdgeEv> {
    let mut evs = Vec::new();
    for c in commits {
        if c.kind != CommitKind::Role {
            continue;
        }
        let frontier: BTreeSet<CommitId> = c.frontier.iter().flatten().copied().collect();
        for (i, p) in c.parts.iter().enumerate() {
            if let Body::Held(Delta::Edge(e)) = &p.body {
                evs.push(EdgeEv {
                    key: c.key(),
                    commit: c.id,
                    part: i,
                    thing: p.thing,
                    author: c.author,
                    holder: e.holder,
                    role: e.role,
                    frontier: frontier.clone(),
                });
            }
        }
    }
    evs.sort_by(|a, b| (a.key, a.holder, a.part).cmp(&(b.key, b.holder, b.part)));
    evs
}

impl Timeline {
    /// The settled walk (spec/permissions.md §5.1 steps 1-5) over the edge writes of applied commits.
    pub fn walk(owners: BTreeMap<ThingId, NodeId>, evs: Vec<EdgeEv>) -> Timeline {
        let mut dropped: BTreeSet<(CommitId, usize)> = BTreeSet::new();
        'restart: loop {
            let mut edges: BTreeMap<(ThingId, NodeId), Role> = BTreeMap::new();
            let mut applied: Vec<(EdgeEv, Class)> = Vec::new();
            for ev in &evs {
                if dropped.contains(&(ev.commit, ev.part)) {
                    continue;
                }
                let owner = owners.get(&ev.thing).copied();
                // an edge on the thing's owner is not applied (spec/permissions.md §1)
                if owner == Some(ev.holder) {
                    continue;
                }
                let class = |edges: &BTreeMap<(ThingId, NodeId), Role>, x: NodeId| {
                    if owner == Some(x) {
                        Some(Class::Owner)
                    } else if edges.get(&(ev.thing, x)) == Some(&Role::Admin) {
                        Some(Class::EdgeAdmin)
                    } else {
                        None
                    }
                };
                let Some(ac) = class(&edges, ev.author) else { continue };
                let before = class(&edges, ev.holder);
                match ev.role {
                    Some(r) => edges.insert((ev.thing, ev.holder), r),
                    None => edges.remove(&(ev.thing, ev.holder)),
                };
                let after = class(&edges, ev.holder);
                applied.push((ev.clone(), ac));
                // step 4: an edge-admin class falling audits the holder's earlier edge-admin writes
                if ev.author != ev.holder && before == Some(Class::EdgeAdmin) && after.is_none() {
                    let mut added = false;
                    for (p, pc) in &applied {
                        if p.author == ev.holder
                            && p.thing == ev.thing
                            && *pc == Class::EdgeAdmin
                            && p.key < ev.key
                            && !ev.frontier.contains(&p.commit)
                        {
                            added |= dropped.insert((p.commit, p.part));
                        }
                    }
                    if added {
                        continue 'restart;
                    }
                }
            }
            return Timeline { owners, applied: applied.into_iter().map(|(e, _)| e).collect() };
        }
    }

    pub fn applied_part(&self, c: CommitId, part: usize) -> bool {
        self.applied.iter().any(|e| e.commit == c && e.part == part)
    }

    /// X's role on the thing just before `key`.
    pub fn role_at(&self, thing: ThingId, x: NodeId, key: Key) -> Option<Role> {
        if self.owners.get(&thing) == Some(&x) {
            return Some(Role::Admin);
        }
        let mut r = None;
        for e in &self.applied {
            if e.key < key && e.thing == thing && e.holder == x {
                r = e.role;
            }
        }
        r
    }

    fn final_role(&self, thing: ThingId, x: NodeId) -> Option<Role> {
        self.role_at(thing, x, (u64::MAX, NodeId::MAX, CommitId::MAX))
    }

    /// Valid explicit demotions of X below `need` on the thing: applied edge writes by another
    /// author taking X from `need` or above to below it.
    pub fn demotions(&self, thing: ThingId, x: NodeId, need: Role) -> Vec<&EdgeEv> {
        if self.owners.get(&thing) == Some(&x) {
            return vec![];
        }
        let mut cur: Option<Role> = None;
        let mut out = Vec::new();
        for e in &self.applied {
            if e.thing != thing || e.holder != x {
                continue;
            }
            let was = cur.is_some_and(|r| r >= need);
            cur = e.role;
            if was && !cur.is_some_and(|r| r >= need) && e.author != x {
                out.push(e);
            }
        }
        out
    }

    /// The first point X held `need` or above (spec/permissions.md §5.2 re-grant).
    fn first_hold(&self, thing: ThingId, x: NodeId, need: Role) -> Option<Key> {
        if self.owners.get(&thing) == Some(&x) {
            return Some((0, 0, 0));
        }
        self.applied.iter().find(|e| e.thing == thing && e.holder == x && e.role.is_some_and(|r| r >= need)).map(|e| e.key)
    }

    /// spec/permissions.md §5.2: would a delta by X on the thing, needing `need`, in commit `c` at
    /// `key`, be valid.
    pub fn valid_as(&self, x: NodeId, thing: ThingId, need: Role, key: Key, c: CommitId) -> bool {
        let held = self.role_at(thing, x, key).is_some_and(|r| r >= need);
        let demos = self.demotions(thing, x, need);
        if held && !demos.iter().any(|d| d.key > key) {
            return true;
        }
        if let Some(newest) = demos.iter().max_by_key(|d| d.key) {
            if newest.frontier.contains(&c) {
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

    /// The fall of an invalid delta (spec/commits.md §5): the ts of the newest valid explicit
    /// demotion of its author below its need, no earlier than its own ts.
    pub fn fall(&self, x: NodeId, thing: ThingId, need: Role, ts: u64) -> u64 {
        self.demotions(thing, x, need).iter().map(|d| wall(d.key.0)).max().unwrap_or(ts).max(ts)
    }

    /// spec/permissions.md §7: does a request by `q` (commit `qc` at `qkey`) hold the right over a
    /// delta purgeable by `by`, written by `author`, on the thing.
    pub fn right(&self, q: NodeId, qkey: Key, qc: CommitId, by: PurgeBy, author: NodeId, thing: ThingId) -> bool {
        let admin = || self.valid_as(q, thing, Role::Admin, qkey, qc);
        let auth = || q == author && self.valid_as(q, thing, Role::Write, qkey, qc);
        match by {
            PurgeBy::Nobody => false,
            PurgeBy::Admin => admin(),
            PurgeBy::Author => auth(),
            PurgeBy::AuthorOrAdmin => admin() || auth(),
            PurgeBy::Writer => self.valid_as(q, thing, Role::Write, qkey, qc),
        }
    }
}

/// Possible admins and writers of each thing from every held edge write, any validity
/// (spec/commits.md §4).
pub struct Possible {
    pub admins: BTreeMap<ThingId, BTreeSet<NodeId>>,
    pub writers: BTreeMap<ThingId, BTreeSet<NodeId>>,
}

impl Possible {
    pub fn new(owners: &BTreeMap<ThingId, NodeId>, evs: &[EdgeEv]) -> Possible {
        let mut admins: BTreeMap<ThingId, BTreeSet<NodeId>> = BTreeMap::new();
        let mut writers: BTreeMap<ThingId, BTreeSet<NodeId>> = BTreeMap::new();
        let things: BTreeSet<ThingId> = owners.keys().copied().chain(evs.iter().map(|e| e.thing)).collect();
        for t in things {
            let mut a: BTreeSet<NodeId> = owners.get(&t).into_iter().copied().collect();
            loop {
                let n = a.len();
                for e in evs {
                    if e.thing == t && e.role == Some(Role::Admin) && a.contains(&e.author) {
                        a.insert(e.holder);
                    }
                }
                if a.len() == n {
                    break;
                }
            }
            let mut w = a.clone();
            for e in evs {
                if e.thing == t && e.role.is_some_and(|r| r >= Role::Write) && a.contains(&e.author) {
                    w.insert(e.holder);
                }
            }
            admins.insert(t, a);
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
    /// spec/commits.md §4 Purged: could the request's author hold the right by any role ever given.
    pub fn right(&self, q: NodeId, by: PurgeBy, author: NodeId, t: ThingId) -> bool {
        let auth = q == author && self.writer(t, q);
        match by {
            PurgeBy::Nobody => false,
            PurgeBy::Admin => self.admin(t, q),
            PurgeBy::Author => auth,
            PurgeBy::AuthorOrAdmin => self.admin(t, q) || auth,
            PurgeBy::Writer => self.writer(t, q),
        }
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
