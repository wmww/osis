//! Layer 1: the joint walk over every held edge write (spec/permissions.md §5.1) with epoch
//! starts and their ledgers (§6). From scratch, deterministic, a pure function of the held set.
//!
//! Readings of the spec (notes/permissions.md, "Implementation"):
//! - R demotes X on N when R is an explicit write (applied, not a self-removal, not an invite
//!   grant; or a ledger tenure end with a frontier) on edge (M, T), X is M or reaches M, N is T
//!   or reachable from T (edges of any role and `until`, owner links), and X's class on N after
//!   R is below its class with the edge restored ("as if the member still held the role"): the
//!   join (componentwise maximum, alive) of its values since the last explicit write on it,
//!   plus, for a node that demoted itself by an explicit write on it, its values before that.
//! - A's chain writes: the writes that set the admin edges on A's admin paths to R's target.
//! - Epoch starts: the newest snapshot found applicable at its position in a walk becomes N's
//!   epoch start and the walk restarts; one found inapplicable or dropped while chosen is
//!   rejected until an epoch start changes on a thing authority on N may come through
//!   (owners, members of what is above, at any time). D is rebuilt whenever
//!   the epoch starts change, so writes a start ignores leave no drops.
//! - Before its epoch start S, N's edges follow S's roster and ledger as virtual writes placed
//!   at their keys (before real writes with that key); a ledger tenure end with a frontier
//!   audits like the demotion it records.

use crate::content::{overlapping, Range};
use crate::graph::{Class, Edges, Owners, Standing, View};
use crate::held::HeldSet;
use crate::types::{lowers, Dots, Edge, EdgeKey, Frontier, MembershipCommit, Point, RosterSnapshot, WriteId, MEMBERS};
use osis_core::{CommitId, Role, Tid, Ts};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// How an applied edge write was attributed (spec/permissions.md §5.1 step 3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Attr {
    /// By the author's authority class; audited when it falls.
    By(Class),
    /// A self-removal: never audited.
    SelfRemoval,
}

/// An applied edge write.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Applied {
    pub author: Tid,
    pub target: Tid,
    pub point: Point,
    pub attr: Attr,
    pub dots: Dots,
}

/// An explicit demotion of a node on a thing below `below` (layer 2 uses these, §5.2): a
/// valid write of the timeline, or a ledger tenure end with a frontier (`ledger`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Demotion {
    pub point: Point,
    pub below: Role,
    pub frontier: Option<Arc<Frontier>>,
    pub ledger: bool,
}

/// Inputs gathered from the held set.
pub(crate) struct Input {
    pub owners: Owners,
    pub commits: BTreeMap<CommitId, Arc<MembershipCommit>>,
    pub snaps: BTreeMap<CommitId, Arc<RosterSnapshot>>,
    /// Key actors and every author: who can hold a class.
    pub nodes: BTreeSet<Tid>,
    /// Every member any held write or roster names, per target (edges at any time).
    pub ever_members: BTreeMap<Tid, BTreeSet<Tid>>,
}

impl Input {
    /// Things authority on `t` may come through, at any time: its owners and the members of
    /// anything on the way, transitively (`t` excluded).
    pub fn above(&self, t: &Tid) -> BTreeSet<Tid> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![*t];
        while let Some(e) = stack.pop() {
            let up = self.owners.owner_actor(&e).into_iter().chain(self.ever_members.get(&e).into_iter().flatten().copied());
            for y in up {
                if y != *t && seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        seen
    }

    pub fn gather(held: &dyn HeldSet) -> Input {
        let things: BTreeSet<Tid> = held.things().into_iter().collect();
        let owners = Owners::from_held(held, &things);
        let mut commits = BTreeMap::new();
        let mut snaps = BTreeMap::new();
        for t in &things {
            for c in held.edge_commits(t) {
                commits.entry(c.id).or_insert(c);
            }
            for s in held.roster_snapshots(t) {
                if s.thing == *t {
                    snaps.entry(s.id).or_insert(s);
                }
            }
        }
        // Overlapping node-form ranges on `/members` void both commits (spec/commits.md §4);
        // the node voids commits overlapping on its other aspects before handing them over.
        let ranges = commits
            .values()
            .flat_map(|c| c.ops.iter().map(move |o| (c.id, c.author, o.target, o.dots)))
            .chain(snaps.values().map(|s| (s.id, s.author, s.thing, s.dots)))
            .filter_map(|(commit, node, tid, d)| match d {
                Dots::Node { lo, hi } => Some(Range { commit, node, tid, ak: MEMBERS.to_string(), lo, hi }),
                Dots::Commit => None,
            });
        let void = overlapping(ranges);
        commits.retain(|id, _| !void.contains(id));
        snaps.retain(|id, _| !void.contains(id));
        // Who can hold a class: key actors, authors, and members that may be nodes.
        let mut nodes: BTreeSet<Tid> = things.iter().filter(|t| owners.is_key(t)).copied().collect();
        nodes.extend(commits.values().map(|c| c.author));
        nodes.extend(snaps.values().map(|s| s.author));
        let members = commits
            .values()
            .flat_map(|c| c.ops.iter().map(|o| o.member))
            .chain(snaps.values().flat_map(|s| s.roster.keys().copied().chain(s.ledger.iter().map(|t| t.member))));
        nodes.extend(members.filter(|m| owners.owner_actor(m).is_none()).collect::<Vec<_>>());
        let mut ever_members: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
        for c in commits.values() {
            for o in &c.ops {
                ever_members.entry(o.target).or_default().insert(o.member);
            }
        }
        for s in snaps.values() {
            ever_members.entry(s.thing).or_default().extend(s.roster.keys().chain(s.ledger.iter().map(|t| &t.member)).copied());
        }
        Input { owners, commits, snaps, nodes, ever_members }
    }
}

/// One change to the edge state in the final walk, for time queries.
#[derive(Clone, Debug)]
pub(crate) struct Change {
    pub point: Point,
    pub member: Tid,
    pub target: Tid,
    pub edge: Option<Edge>,
    /// An explicit write (may demote, §5.1 step 4) with its frontier.
    pub explicit: Option<Option<Arc<Frontier>>>,
}

/// Result of the final walk.
pub(crate) struct Walked {
    pub initial: Edges,
    pub history: Vec<Change>,
    pub edges: Edges,
    pub applied: BTreeMap<WriteId, Applied>,
    pub demotions: BTreeMap<(Tid, Tid), Vec<Demotion>>,
}

pub(crate) struct Outcome {
    pub walked: Walked,
    pub dropped: BTreeMap<WriteId, Point>,
    pub epoch_starts: BTreeMap<Tid, CommitId>,
    pub passes: usize,
    pub converged: bool,
}

/// A write placed by an epoch start's roster and ledger.
#[derive(Clone, Debug)]
struct Virtual {
    thing: Tid,
    member: Tid,
    edge: Option<Edge>,
    point: Point,
    /// A tenure end with a frontier: the demoter node and the frontier.
    audit: Option<(Tid, Arc<Frontier>)>,
}

enum Item {
    Commit(Arc<MembershipCommit>),
    Snap(Arc<RosterSnapshot>),
    Virtual(Virtual),
}

/// What an explicit demotion's frontier and exceptions cover.
struct Auditor<'a> {
    author: Option<Tid>,
    frontier: Option<&'a Frontier>,
    chain: BTreeSet<WriteId>,
    commit: Option<CommitId>,
    point: Point,
    ledger: bool,
    frontier_arc: Option<Arc<Frontier>>,
}

/// Edge state of `s.thing` before `s` by its roster and ledger (spec/permissions.md §6): the
/// values at the beginning and the changes at keys before `s`.
fn ledger_writes(s: &RosterSnapshot) -> (Vec<(Tid, Edge)>, Vec<Virtual>) {
    let skey = s.point().key();
    let mut members: BTreeSet<Tid> = s.roster.keys().copied().collect();
    members.extend(s.ledger.iter().map(|t| t.member));
    let mut initial = Vec::new();
    let mut out = Vec::new();
    for m in members {
        let tenures: Vec<_> = s.ledger.iter().filter(|t| t.member == m).collect();
        let roster = s.roster.get(&m);
        // The value just after key `b` (`None`: the beginning); `with_roster: false` counts
        // the roster edge only where it starts at `b` itself.
        let value = |b: Option<EdgeKey>, with_roster: bool| -> Option<Edge> {
            let inside = tenures
                .iter()
                .filter(|t| match (t.since, b) {
                    (None, _) => b.is_none_or(|b| b < t.until),
                    (Some(_), None) => false,
                    (Some(s), Some(b)) => s <= b && b < t.until,
                })
                .map(|t| t.role)
                .max();
            if let Some(role) = inside {
                return Some(Edge::new(role));
            }
            let r = roster.filter(|r| with_roster || (r.since.is_some() && r.since == b))?;
            let started = match (r.since, b) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(s), Some(b)) => s <= b,
            };
            let after_tenures = match b {
                None => tenures.is_empty(),
                Some(b) => tenures.iter().all(|t| t.until <= b),
            };
            (started && after_tenures).then_some(Edge { since: None, ..*r })
        };
        let mut keys: BTreeSet<EdgeKey> = tenures.iter().flat_map(|t| t.since.into_iter().chain([t.until])).collect();
        keys.extend(roster.and_then(|r| r.since));
        let mut prev = value(None, true);
        if let Some(e) = prev {
            initial.push((m, e));
        }
        for b in keys.into_iter().filter(|b| *b < skey) {
            let point = Point::first_at(b);
            // A tenure end with a frontier audits like the demotion it records, even where the
            // roster edge takes over at once: end the tenure, then re-grant.
            let ending = tenures.iter().find(|t| t.until == b && t.frontier.is_some()).and_then(|t| t.frontier.clone());
            if let Some(f) = ending {
                let end = value(Some(b), false);
                if end != prev {
                    out.push(Virtual { thing: s.thing, member: m, edge: end, point, audit: Some((b.node, f)) });
                    prev = end;
                }
            }
            let v = value(Some(b), true);
            if v != prev {
                out.push(Virtual { thing: s.thing, member: m, edge: v, point, audit: None });
                prev = v;
            }
        }
    }
    (initial, out)
}

/// Componentwise maximum of two edge values, alive: what a member held across them.
fn join(a: Option<Edge>, b: Edge) -> Edge {
    match a {
        None => Edge { until: None, since: None, ..b },
        Some(a) => Edge { role: a.role.max(b.role), invite: a.invite.max(b.invite), until: None, since: None },
    }
}

/// Does restoring `r` give more than `new` at `ts` (role, invite or life)? If not, an explicit
/// write of `new` demotes nobody.
fn exceeds(r: Option<Edge>, new: Option<Edge>, ts: Ts) -> bool {
    match (r, new) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(r), Some(n)) => !n.alive_at(Some(ts)) || n.role < r.role || n.invite < r.invite || n.until.is_some(),
    }
}

enum PassResult {
    Done(Walked),
    Restart,
}

struct Pass<'a> {
    input: &'a Input,
    epoch: &'a BTreeMap<Tid, CommitId>,
    dropped: &'a mut BTreeMap<WriteId, Point>,
    edges: Edges,
    initial: Edges,
    /// Per edge lowered or expired without an explicit write since: its value before, which
    /// the next explicit write on it restores to judge falls (§5.1: as if the member still
    /// held the role).
    prior: BTreeMap<(Tid, Tid), Edge>,
    /// Edges whose current value was already expired when written.
    dead: BTreeSet<(Tid, Tid)>,
    /// The same for one node that demoted itself by an explicit write on the edge.
    prior_node: BTreeMap<(Tid, Tid), BTreeMap<Tid, Edge>>,
    applied: BTreeMap<WriteId, Applied>,
    by_author_target: BTreeMap<(Tid, Tid), Vec<WriteId>>,
    setter: BTreeMap<(Tid, Tid), WriteId>,
    history: Vec<Change>,
    demotions: BTreeMap<(Tid, Tid), Vec<Demotion>>,
}

impl Pass<'_> {
    fn view(&self, ts: Ts) -> View<'_> {
        View { owners: &self.input.owners, edges: &self.edges, ts: Some(ts) }
    }

    /// Epoch start of `thing`, if one is chosen.
    fn start_of(&self, thing: &Tid) -> Option<&Arc<RosterSnapshot>> {
        self.epoch.get(thing).and_then(|id| self.input.snaps.get(id))
    }

    /// Sets edge (member, target); an explicit write (`auditor`) then audits what it took
    /// away. Returns whether D grew.
    fn change(&mut self, point: Point, (member, target): (Tid, Tid), edge: Option<Edge>, by: Option<WriteId>, auditor: Option<&Auditor>) -> bool {
        let key = (member, target);
        // A value already expired when written never conferred anything.
        let old = self.edges.get(&member, &target).copied().filter(|_| !self.dead.contains(&key));
        if edge.is_some_and(|e| !e.alive_at(Some(point.ts))) {
            self.dead.insert(key);
        } else {
            self.dead.remove(&key);
        }
        // Before the change: does the author reach the member (a demotion of itself)?
        let own = auditor.and_then(|a| a.author).filter(|a| self.view(point.ts).reach_backward(&member).contains(a));
        self.edges.set(member, target, edge);
        match by {
            Some(w) => self.setter.insert(key, w),
            None => self.setter.remove(&key),
        };
        let explicit = auditor.map(|a| a.frontier_arc.clone());
        self.history.push(Change { point, member, target, edge, explicit });
        let Some(aud) = auditor else {
            // No audit (self-removal, invite grant, epoch start, ledger end without a frontier):
            // everyone below keeps the standing it had, for the next explicit write.
            if let Some(o) = old {
                let p = self.prior.remove(&key);
                self.prior.insert(key, join(p, o));
            }
            return false;
        };
        let all = self.prior.remove(&key);
        let mine: BTreeMap<Tid, Edge> = std::mem::take(self.prior_node.entry(key).or_default());
        let base = match (all, old) {
            (Some(a), Some(o)) => Some(join(Some(a), o)),
            (a, o) => a.or(o),
        };
        let lowered = exceeds(mine.values().fold(base, |r, e| Some(join(r, *e))), edge, point.ts);
        let grew = lowered && self.audit_fall(key, base, &mine, point.ts, aud);
        if let Some(a) = own {
            // The author demoted itself: its own standing is kept for the next explicit write.
            if let Some(b) = base {
                let r = join(mine.get(&a).copied(), b);
                self.prior_node.entry(key).or_default().insert(a, r);
            }
        }
        grew
    }

    /// Could an explicit write of `new` on `key` demote anyone: does the edge it restores
    /// exceed `new` in role, invite or life?
    fn may_lower(&self, key: (Tid, Tid), new: Option<Edge>, ts: Ts) -> bool {
        let mut r = self.prior.get(&key).copied();
        if let Some(o) = self.edges.get(&key.0, &key.1).filter(|_| !self.dead.contains(&key)) {
            r = Some(join(r, *o));
        }
        for e in self.prior_node.get(&key).into_iter().flat_map(|m| m.values()) {
            r = Some(join(r, *e));
        }
        exceeds(r, new, ts)
    }

    fn record(&mut self, id: WriteId, a: Applied) {
        self.by_author_target.entry((a.author, a.target)).or_default().push(id);
        self.applied.insert(id, a);
    }

    /// A's chain writes (spec/permissions.md §5.1): the writes that set the admin edges on
    /// A's admin paths to `target`.
    fn chain_writes(&self, best: &BTreeMap<Tid, Role>, target: &Tid, ts: Ts) -> BTreeSet<WriteId> {
        let view = self.view(ts);
        let to = view.admin_reaching(target);
        let on_path = |m: &Tid, t: &Tid| {
            best.get(m) == Some(&Role::Admin)
                && to.contains(t)
                && self.edges.get(m, t).is_some_and(|e| e.role == Role::Admin && e.alive_at(Some(ts)))
        };
        self.setter.iter().filter(|((m, t), _)| on_path(m, t)).map(|(_, w)| *w).collect()
    }

    /// An explicit write changed edge `(member, target)`: every node X reaching the member
    /// whose standing on a thing N reachable from the target is lower than with the edge
    /// `restored` (its value before, alive) was demoted by it (§5.1 step 4): record the
    /// demotion for layer 2 and audit the classes X fell through. Returns whether D grew.
    fn audit_fall(&mut self, (member, target): (Tid, Tid), base: Option<Edge>, mine: &BTreeMap<Tid, Edge>, ts: Ts, aud: &Auditor) -> bool {
        let view = self.view(ts);
        let xs: Vec<Tid> = view.reach_backward(&member).into_iter().filter(|x| self.input.nodes.contains(x) && aud.author != Some(*x)).collect();
        let ns = view.reach_forward(&target);
        let mut grew = false;
        let mut shared = self.edges.clone();
        if let Some(b) = base {
            shared.set(member, target, Some(Edge { until: None, since: None, ..b }));
        }
        for x in xs {
            let mut own;
            let was = match (base, mine.get(&x)) {
                (b, Some(m)) => {
                    own = self.edges.clone();
                    own.set(member, target, Some(join(b, *m)));
                    &own
                }
                (Some(_), None) => &shared,
                (None, None) => continue,
            };
            let view = self.view(ts);
            let before = View { owners: &self.input.owners, edges: was, ts: Some(ts) };
            let (best, best_was) = (view.roles_from(&x), before.roles_from(&x));
            let pairs: Vec<(Tid, Standing, Standing)> = ns.iter().map(|n| (*n, view.standing(&x, &best, n), before.standing(&x, &best_was, n))).collect();
            for (n, now, held) in pairs {
                for below in [Role::Write, Role::Admin] {
                    if held.role >= Some(below) && now.role < Some(below) {
                        let d = Demotion { point: aud.point, below, frontier: aud.frontier_arc.clone(), ledger: aud.ledger };
                        self.demotions.entry((x, n)).or_default().push(d);
                    }
                }
                if now.class < held.class {
                    grew |= self.audit(&x, &n, now.class, held.class, aud);
                }
            }
        }
        grew
    }

    /// Drops x's earlier applied writes on n attributed to a class in (now, held] that the
    /// auditor does not cover.
    fn audit(&mut self, x: &Tid, n: &Tid, now: Class, held: Class, aud: &Auditor) -> bool {
        let mut grew = false;
        for id in self.by_author_target.get(&(*x, *n)).cloned().unwrap_or_default() {
            let Some(a) = self.applied.get(&id) else { continue };
            let Attr::By(c) = a.attr else { continue };
            if !(now < c && c <= held) {
                continue;
            }
            let covered = aud.commit == Some(id.commit())
                || aud.chain.contains(&id)
                || aud.frontier.is_some_and(|f| f.covers(n, MEMBERS, x, a.dots, &id.commit()));
            if !covered && !self.dropped.contains_key(&id) {
                self.dropped.insert(id, aud.point);
                grew = true;
            }
        }
        grew
    }

    /// How op `k` of `c` applies against the state before `c` (§5.1 step 2, §2).
    fn judge(&self, c: &MembershipCommit, k: usize, best: &BTreeMap<Tid, Role>) -> Option<Attr> {
        let op = c.ops.get(k)?;
        let (a, m, t) = (c.author, op.member, op.target);
        if m == t || self.input.owners.owner_actor(&t) == Some(m) || op.edge.is_some_and(|e| !e.well_formed()) {
            return None;
        }
        let view = self.view(c.ts);
        let old = self.edges.get(&m, &t);
        let new = op.edge.map(|e| Edge { since: None, ..e });
        let st = view.standing(&a, best, &t);
        // Self-removal (§2): lowering one's own edge, or an edge of a member one is admin of
        // when that is the only authority one has (no owner-chain or edge-admin authority on
        // the target); otherwise the write is an explicit demotion by its class there.
        let authority_on_target = matches!(st.class, Class::Chain | Class::Edge);
        if lowers(new.as_ref(), old) && (m == a || (best.get(&m) == Some(&Role::Admin) && !authority_on_target)) {
            // A single-use redemption's self-removal is attributed like its grant (§5.1).
            if let (true, Class::Invite(l)) = (m == a, st.class)
                && c.ops.iter().any(|o| o.member != a)
            {
                return Some(Attr::By(Class::Invite(l)));
            }
            return Some(Attr::SelfRemoval);
        }
        match st.class {
            Class::Chain | Class::Edge => Some(Attr::By(st.class)),
            Class::Invite(l) => {
                let free = old.is_none_or(|o| !o.alive_at(Some(c.ts)));
                let ok = new.is_some_and(|e| e.role <= l) && free;
                ok.then_some(Attr::By(Class::Invite(l)))
            }
            Class::None => None,
        }
    }

    fn commit(&mut self, c: &MembershipCommit) -> bool {
        let point = c.point();
        let best = self.view(c.ts).roles_from(&c.author);
        let mut judged = Vec::new();
        for (k, op) in c.ops.iter().enumerate() {
            let Ok(k32) = u32::try_from(k) else { continue };
            let id = WriteId::Op(c.id, k32);
            if self.dropped.contains_key(&id) || self.start_of(&op.target).is_some_and(|s| point < s.point()) {
                continue;
            }
            if let Some(attr) = self.judge(c, k, &best) {
                let new = op.edge.map(|e| Edge { since: None, ..e });
                let chain = match attr {
                    Attr::By(Class::Chain | Class::Edge) if self.may_lower((op.member, op.target), new, c.ts) => Some(self.chain_writes(&best, &op.target, c.ts)),
                    Attr::By(Class::Chain | Class::Edge) => Some(BTreeSet::new()),
                    _ => None,
                };
                judged.push((k, id, attr, chain));
            }
        }
        let mut grew = false;
        for (k, id, attr, chain) in judged {
            let Some(op) = c.ops.get(k) else { continue };
            let new = op.edge.map(|e| Edge { since: None, ..e });
            self.record(id, Applied { author: c.author, target: op.target, point, attr, dots: op.dots });
            let auditor = chain.map(|chain| Auditor {
                author: Some(c.author),
                frontier: c.frontier.as_deref(),
                chain,
                commit: Some(c.id),
                point,
                ledger: false,
                frontier_arc: c.frontier.clone(),
            });
            grew |= self.change(point, (op.member, op.target), new, Some(id), auditor.as_ref());
        }
        grew
    }

    /// A roster snapshot at its position: `Err(())` asks for a restart (the chosen epoch start
    /// is inapplicable). A newer applicable one becomes a candidate (`choose`).
    fn snapshot(&mut self, s: &RosterSnapshot, rejected: &mut BTreeSet<CommitId>, choose: &mut BTreeMap<Tid, CommitId>) -> Result<(), ()> {
        let id = WriteId::Snapshot(s.id);
        if self.dropped.contains_key(&id) || rejected.contains(&s.id) {
            return Ok(());
        }
        let view = self.view(s.ts);
        let best = view.roles_from(&s.author);
        let chain = view.standing(&s.author, &best, &s.thing).class == Class::Chain;
        match self.start_of(&s.thing).map(|e| (e.id, e.point())) {
            Some((e, _)) if e == s.id => {
                if !chain {
                    rejected.insert(s.id);
                    return Err(());
                }
            }
            Some((_, p)) if s.point() < p => return Ok(()),
            _ => {
                if chain {
                    choose.insert(s.thing, s.id);
                }
                return Ok(());
            }
        }
        // The epoch start itself: N's edges become its roster.
        let point = s.point();
        let old: Vec<Tid> = self.edges.members(&s.thing).map(|(m, _)| *m).collect();
        for m in old {
            if !s.roster.contains_key(&m) {
                self.change(point, (m, s.thing), None, None, None);
            }
        }
        for (m, e) in &s.roster {
            let e = Edge { since: None, ..*e };
            if *m == s.thing || self.input.owners.owner_actor(&s.thing) == Some(*m) || !e.well_formed() {
                continue;
            }
            if self.edges.get(m, &s.thing) != Some(&e) {
                self.change(point, (*m, s.thing), Some(e), Some(id), None);
            } else {
                self.setter.insert((*m, s.thing), id);
            }
        }
        self.record(id, Applied { author: s.author, target: s.thing, point, attr: Attr::By(Class::Chain), dots: s.dots });
        Ok(())
    }

    fn virtual_write(&mut self, v: &Virtual) -> bool {
        let auditor = v.audit.as_ref().map(|(node, f)| Auditor {
            // A tenure with a frontier counts as an explicit demotion (§6). Its ending node may
            // be a self-remover whose tenure a later demotion audited, so nobody is exempt;
            // the ending node's chain writes count.
            author: None,
            frontier: Some(f.as_ref()),
            chain: {
                let best = self.view(v.point.ts).roles_from(node);
                self.chain_writes(&best, &v.thing, v.point.ts)
            },
            commit: None,
            point: v.point,
            ledger: true,
            frontier_arc: Some(f.clone()),
        });
        self.change(v.point, (v.member, v.thing), v.edge, None, auditor.as_ref())
    }
}

/// Evaluates the timeline from scratch: walks until a walk adds nothing to D (§5.1 step 5).
pub(crate) fn run(input: &Input) -> Outcome {
    let mut dropped: BTreeMap<WriteId, Point> = BTreeMap::new();
    let mut epoch: BTreeMap<Tid, CommitId> = BTreeMap::new();
    let mut rejected: BTreeSet<CommitId> = BTreeSet::new();
    let ns = input.snaps.len();
    let writes = input.commits.values().map(|c| c.ops.len()).sum::<usize>() + ns;
    // Safety net: D grows between epoch changes; epoch changes stop except where authority
    // paths cycle through mutual membership, where this bound ends the evaluation.
    let cap = (writes + 2).saturating_mul(ns.saturating_mul(ns + 2) + 1).saturating_mul(4);
    let mut passes = 0;
    loop {
        passes += 1;
        let mut changed: Vec<Tid> = Vec::new();
        // A dropped epoch start is rejected.
        for (thing, s) in &epoch {
            if dropped.contains_key(&WriteId::Snapshot(*s)) {
                rejected.insert(*s);
                changed.push(*thing);
            }
        }
        epoch.retain(|_, s| !rejected.contains(s));
        let mut choose = BTreeMap::new();
        let before: BTreeSet<CommitId> = rejected.clone();
        let res = pass(input, &epoch, &mut dropped, &mut rejected, &mut choose);
        for s in rejected.difference(&before) {
            if let Some(sn) = input.snaps.get(s) {
                changed.push(sn.thing);
            }
        }
        epoch.retain(|_, s| !rejected.contains(s));
        for (thing, s) in &choose {
            epoch.insert(*thing, *s);
            changed.push(*thing);
        }
        if !changed.is_empty() {
            // A rejected start gets another chance when a start changes anywhere authority on
            // its thing may come from (owners, members of what is above, at any time); D is
            // rebuilt, so writes a new start ignores leave no drops behind.
            rejected.retain(|s| {
                input.snaps.get(s).is_none_or(|sn| {
                    let above = input.above(&sn.thing);
                    !changed.iter().any(|c| above.contains(c))
                })
            });
            dropped.clear();
        }
        match res {
            PassResult::Done(walked) if changed.is_empty() => {
                return Outcome { walked, dropped, epoch_starts: epoch, passes, converged: true };
            }
            _ if passes >= cap => {
                let walked = match pass(input, &epoch, &mut dropped.clone(), &mut rejected.clone(), &mut BTreeMap::new()) {
                    PassResult::Done(w) => w,
                    PassResult::Restart => Walked { initial: Edges::default(), history: vec![], edges: Edges::default(), applied: BTreeMap::new(), demotions: BTreeMap::new() },
                };
                return Outcome { walked, dropped, epoch_starts: epoch, passes, converged: false };
            }
            _ => {}
        }
    }
}

fn pass(
    input: &Input,
    epoch: &BTreeMap<Tid, CommitId>,
    dropped: &mut BTreeMap<WriteId, Point>,
    rejected: &mut BTreeSet<CommitId>,
    choose: &mut BTreeMap<Tid, CommitId>,
) -> PassResult {
    let mut items: Vec<(Point, u8, Tid, Tid, Item)> = Vec::new();
    let zero = Tid::from_bytes([0; 15]);
    let mut initial = Edges::default();
    for (thing, sid) in epoch {
        let Some(s) = input.snaps.get(sid) else { continue };
        let (init, virt) = ledger_writes(s);
        for (m, e) in init {
            if m != *thing && input.owners.owner_actor(thing) != Some(m) && e.well_formed() {
                initial.set(m, *thing, Some(e));
            }
        }
        for v in virt {
            // The filters real writes get: no self edge, no owner edge, invite at most the role.
            if v.member == *thing || input.owners.owner_actor(thing) == Some(v.member) || v.edge.is_some_and(|e| !e.well_formed()) {
                continue;
            }
            items.push((v.point, 0, v.thing, v.member, Item::Virtual(v)));
        }
    }
    for c in input.commits.values() {
        items.push((c.point(), 1, zero, zero, Item::Commit(c.clone())));
    }
    for s in input.snaps.values() {
        items.push((s.point(), 1, zero, zero, Item::Snap(s.clone())));
    }
    items.sort_by_key(|a| (a.0, a.1, a.2, a.3));
    let mut p = Pass {
        input,
        epoch,
        dropped,
        edges: initial.clone(),
        initial,
        prior: BTreeMap::new(),
        prior_node: BTreeMap::new(),
        dead: BTreeSet::new(),
        applied: BTreeMap::new(),
        by_author_target: BTreeMap::new(),
        setter: BTreeMap::new(),
        history: Vec::new(),
        demotions: BTreeMap::new(),
    };
    for (_, _, _, _, item) in &items {
        let restart = match item {
            Item::Commit(c) => p.commit(c),
            Item::Snap(s) => p.snapshot(s, rejected, choose).is_err(),
            Item::Virtual(v) => p.virtual_write(v),
        };
        if restart {
            return PassResult::Restart;
        }
    }
    PassResult::Done(Walked { initial: p.initial, history: p.history, edges: p.edges, applied: p.applied, demotions: p.demotions })
}
