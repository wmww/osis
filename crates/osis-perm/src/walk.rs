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
//!   at their keys (before real writes with that key); an entry with a frontier is the
//!   explicit demotion it records, by its key's node (exempt as the author), audit-only
//!   entries (`since` = `until`) included.

use crate::content::{overlapping, Range};
use crate::graph::{Class, Edges, Owners, Standing, View};
use crate::held::HeldSet;
use crate::types::{lowers, Dots, Edge, EdgeKey, Frontier, MembershipCommit, Point, RosterSnapshot, WriteId, MEMBERS};
use osis_core::{CommitId, Role, Tid, Ts, WallMs};
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
    /// An explicit write that lowered the edge as restored (§5.1 step 4): the restored role
    /// it audited from.
    pub audited: Option<Role>,
}

/// Result of the final walk.
pub(crate) struct Walked {
    pub initial: Edges,
    pub history: Vec<Change>,
    pub edges: Edges,
    pub applied: BTreeMap<WriteId, Applied>,
    pub demotions: BTreeMap<(Tid, Tid), Vec<Demotion>>,
    /// The rest of the walk's state, to continue it past its last write (`Timeline::extend`).
    pub rest: Rest,
}

/// Walk state beyond what queries read (see `Pass`), and the undo log that rolls it back.
#[derive(Default)]
pub(crate) struct Rest {
    prior: BTreeMap<(Tid, Tid), Edge>,
    dead: BTreeSet<(Tid, Tid)>,
    prior_node: BTreeMap<(Tid, Tid), BTreeMap<Tid, Edge>>,
    by_author_target: BTreeMap<(Tid, Tid), Vec<WriteId>>,
    setter: BTreeMap<(Tid, Tid), WriteId>,
    log: Vec<Undo>,
    /// Per walked item: the log and history lengths before it.
    marks: Vec<(usize, usize)>,
}

/// The inverse of one change to the walk state.
enum Undo {
    Edge(Tid, Tid, Option<Edge>),
    Dead((Tid, Tid), bool),
    Setter((Tid, Tid), Option<WriteId>),
    Prior((Tid, Tid), Option<Edge>),
    PriorNode((Tid, Tid), Option<BTreeMap<Tid, Edge>>),
    Applied(WriteId, Option<Applied>),
    ByAuthorTarget((Tid, Tid)),
    Demotion((Tid, Tid)),
}

pub(crate) struct Outcome {
    pub walked: Walked,
    pub dropped: BTreeMap<WriteId, Point>,
    pub epoch_starts: BTreeMap<Tid, CommitId>,
    pub passes: usize,
    pub converged: bool,
    /// Whether the epoch starts ever changed (the rejection rule then read `Input::above`).
    pub epoch_changed: bool,
    /// Rejected epoch starts, as the final walk began.
    pub rejected: BTreeSet<CommitId>,
    /// The furthest point a walk other than the final one reached (where it restarted, or its
    /// last item): a walk is the final one's prefix up to here only.
    pub reach: Option<Point>,
}

/// A converged evaluation to continue: its outcome, and the earliest point of the commits
/// added since.
pub(crate) struct Resume {
    pub walked: Walked,
    pub dropped: BTreeMap<WriteId, Point>,
    pub epoch_starts: BTreeMap<Tid, CommitId>,
    pub rejected: BTreeSet<CommitId>,
    pub passes: usize,
    pub epoch_changed: bool,
    pub reach: Option<Point>,
    pub from: Point,
}

/// A write placed by an epoch start's roster and ledger.
#[derive(Clone, Debug)]
struct Virtual {
    thing: Tid,
    member: Tid,
    edge: Option<Edge>,
    point: Point,
    /// An explicit demotion recorded by the ledger (§6): the demoter node and its frontier.
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
            // An entry with a frontier records an explicit demotion by `b`'s node, even where
            // the roster edge takes over at once (end the tenure, then re-grant) or nothing
            // changes (an audit-only entry).
            if let Some(f) = tenures.iter().find(|t| t.until == b && t.frontier.is_some()).and_then(|t| t.frontier.clone()) {
                let end = value(Some(b), false);
                out.push(Virtual { thing: s.thing, member: m, edge: end, point, audit: Some((b.node, f)) });
                prev = end;
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

/// How setting edge `(member, target)` from `old` to `new` at `ts` changes the widest-path
/// roles `best` (§1).
fn widest_changes(best: &BTreeMap<Tid, Role>, (member, target): (Tid, Tid), old: Option<Edge>, new: Option<Edge>, ts: Ts) -> Widest {
    let Some(&rm) = best.get(&member) else { return Widest::Same };
    let alive = |e: Option<Edge>| e.filter(|e| e.alive_at(Some(ts)));
    let (o, n) = (alive(old).map(|e| rm.min(e.role)), alive(new).map(|e| rm.min(e.role)));
    let cur = best.get(&target).copied();
    if alive(new).is_some_and(|e| e.until.is_some()) || (o > n && o == cur) {
        // `best`'s expiry does not know the new `until`; or the old edge may have been the
        // only path that wide
        Widest::Unknown
    } else if n > cur {
        Widest::Raised
    } else {
        Widest::Same
    }
}

enum Widest {
    Same,
    /// Only raised, from the edge's member on.
    Raised,
    Unknown,
}

struct Pass<'a> {
    input: &'a Input,
    epoch: BTreeMap<Tid, CommitId>,
    dropped: BTreeMap<WriteId, Point>,
    /// Writes this walk added to D.
    fresh: Vec<WriteId>,
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
    /// `roles_from` per node over the current edges: the answer, the ts it was computed at
    /// and the earliest `until` it followed. Dropped when an edge of a node it reaches changes.
    roles: BTreeMap<Tid, Roles>,
    log: Vec<Undo>,
    marks: Vec<(usize, usize)>,
}

type Roles = (Arc<BTreeMap<Tid, Role>>, Ts, Option<WallMs>);

impl<'a> Pass<'a> {
    /// `x`'s roles over the current edges at `ts` (cached: the walk's ts never decreases).
    fn roles(&mut self, x: Tid, ts: Ts) -> Arc<BTreeMap<Tid, Role>> {
        if let Some((b, at, exp)) = self.roles.get(&x)
            && *at <= ts
            && exp.is_none_or(|u| ts.wall_ms() < u)
        {
            return b.clone();
        }
        let (b, exp) = self.view(ts).roles_expiring(&x);
        let b = Arc::new(b);
        self.roles.insert(x, (b.clone(), ts, exp));
        b
    }

    fn new(input: &'a Input, epoch: BTreeMap<Tid, CommitId>, dropped: BTreeMap<WriteId, Point>, initial: Edges) -> Pass<'a> {
        Pass::resume(input, epoch, dropped, Walked { edges: initial.clone(), initial, history: Vec::new(), applied: BTreeMap::new(), demotions: BTreeMap::new(), rest: Rest::default() })
    }

    fn resume(input: &'a Input, epoch: BTreeMap<Tid, CommitId>, dropped: BTreeMap<WriteId, Point>, w: Walked) -> Pass<'a> {
        let Walked { initial, history, edges, applied, demotions, rest } = w;
        let Rest { prior, dead, prior_node, by_author_target, setter, log, marks } = rest;
        Pass { input, epoch, dropped, fresh: Vec::new(), edges, initial, prior, dead, prior_node, applied, by_author_target, setter, history, demotions, roles: BTreeMap::new(), log, marks }
    }

    fn finish(self) -> (Walked, BTreeMap<WriteId, Point>) {
        let rest = Rest { prior: self.prior, dead: self.dead, prior_node: self.prior_node, by_author_target: self.by_author_target, setter: self.setter, log: self.log, marks: self.marks };
        (Walked { initial: self.initial, history: self.history, edges: self.edges, applied: self.applied, demotions: self.demotions, rest }, self.dropped)
    }

    /// Back to the state before item `i`.
    fn rollback(&mut self, i: usize) {
        let Some(&(l, h)) = self.marks.get(i) else { return };
        while self.log.len() > l {
            let Some(u) = self.log.pop() else { break };
            match u {
                Undo::Edge(m, t, e) => self.edges.set(m, t, e),
                Undo::Dead(k, on) => {
                    if on {
                        self.dead.insert(k);
                    } else {
                        self.dead.remove(&k);
                    }
                }
                Undo::Setter(k, w) => {
                    match w {
                        Some(w) => self.setter.insert(k, w),
                        None => self.setter.remove(&k),
                    };
                }
                Undo::Prior(k, e) => {
                    match e {
                        Some(e) => self.prior.insert(k, e),
                        None => self.prior.remove(&k),
                    };
                }
                Undo::PriorNode(k, m) => {
                    match m {
                        Some(m) => self.prior_node.insert(k, m),
                        None => self.prior_node.remove(&k),
                    };
                }
                Undo::Applied(id, a) => {
                    match a {
                        Some(a) => self.applied.insert(id, a),
                        None => self.applied.remove(&id),
                    };
                }
                Undo::ByAuthorTarget(k) => {
                    if let Some(v) = self.by_author_target.get_mut(&k) {
                        v.pop();
                        if v.is_empty() {
                            self.by_author_target.remove(&k);
                        }
                    }
                }
                Undo::Demotion(k) => {
                    if let Some(v) = self.demotions.get_mut(&k) {
                        v.pop();
                        if v.is_empty() {
                            self.demotions.remove(&k);
                        }
                    }
                }
            }
        }
        self.history.truncate(h);
        self.marks.truncate(i);
        self.roles.clear();
    }

    fn set_edge(&mut self, m: Tid, t: Tid, e: Option<Edge>) {
        self.log.push(Undo::Edge(m, t, self.edges.get(&m, &t).copied()));
        self.edges.set(m, t, e);
    }

    fn set_dead(&mut self, k: (Tid, Tid), on: bool) {
        let was = if on { !self.dead.insert(k) } else { self.dead.remove(&k) };
        self.log.push(Undo::Dead(k, was));
    }

    fn set_setter(&mut self, k: (Tid, Tid), w: Option<WriteId>) {
        let was = match w {
            Some(w) => self.setter.insert(k, w),
            None => self.setter.remove(&k),
        };
        self.log.push(Undo::Setter(k, was));
    }

    fn set_prior(&mut self, k: (Tid, Tid), e: Option<Edge>) -> Option<Edge> {
        let was = match e {
            Some(e) => self.prior.insert(k, e),
            None => self.prior.remove(&k),
        };
        self.log.push(Undo::Prior(k, was));
        was
    }

    fn take_prior_node(&mut self, k: (Tid, Tid)) -> BTreeMap<Tid, Edge> {
        let was = self.prior_node.remove(&k);
        self.log.push(Undo::PriorNode(k, was.clone()));
        was.unwrap_or_default()
    }

    fn insert_prior_node(&mut self, k: (Tid, Tid), node: Tid, e: Edge) {
        let was = self.prior_node.get(&k).cloned();
        self.log.push(Undo::PriorNode(k, was));
        self.prior_node.entry(k).or_default().insert(node, e);
    }

    fn view(&self, ts: Ts) -> View<'_> {
        View::new(&self.input.owners, &self.edges, Some(ts))
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
        self.set_dead(key, edge.is_some_and(|e| !e.alive_at(Some(point.ts))));
        // Before the change: does the author reach the member (a demotion of itself)?
        let own = auditor.and_then(|a| a.author).filter(|a| self.view(point.ts).reach_backward(&member).contains(a));
        let was = self.edges.get(&member, &target).copied();
        let mut raise = Vec::new();
        self.roles.retain(|x, (b, _, _)| match widest_changes(b, (member, target), was, edge, point.ts) {
            Widest::Same => true,
            Widest::Raised => {
                raise.push(*x);
                true
            }
            Widest::Unknown => false,
        });
        self.set_edge(member, target, edge);
        for x in raise {
            let view = View::new(&self.input.owners, &self.edges, Some(point.ts));
            if let Some((b, _, exp)) = self.roles.get_mut(&x) {
                let (raised, e) = view.roles_raised_expiring(b, &[member]);
                Arc::make_mut(b).extend(raised);
                *exp = match (*exp, e) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
            }
        }
        self.set_setter(key, by);
        let explicit = auditor.map(|a| a.frontier_arc.clone());
        let Some(aud) = auditor else {
            // No audit (self-removal, invite grant, epoch start, ledger end without a frontier):
            // everyone below keeps the standing it had, for the next explicit write.
            self.history.push(Change { point, member, target, edge, explicit, audited: None });
            if let Some(o) = old {
                let p = self.prior.get(&key).copied();
                self.set_prior(key, Some(join(p, o)));
            }
            return false;
        };
        let all = self.set_prior(key, None);
        let mine: BTreeMap<Tid, Edge> = self.take_prior_node(key);
        let base = match (all, old) {
            (Some(a), Some(o)) => Some(join(Some(a), o)),
            (a, o) => a.or(o),
        };
        let restored = mine.values().fold(base, |r, e| Some(join(r, *e)));
        let lowered = exceeds(restored, edge, point.ts);
        let audited = restored.filter(|_| lowered).map(|r| r.role);
        self.history.push(Change { point, member, target, edge, explicit, audited });
        let grew = lowered && self.audit_fall(key, base, &mine, point.ts, aud);
        if let Some(a) = own {
            // The author demoted itself: its own standing is kept for the next explicit write.
            if let Some(b) = base {
                let r = join(mine.get(&a).copied(), b);
                self.insert_prior_node(key, a, r);
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
        self.log.push(Undo::ByAuthorTarget((a.author, a.target)));
        let was = self.applied.insert(id, a);
        self.log.push(Undo::Applied(id, was));
    }

    /// A's chain writes (spec/permissions.md §5.1): the writes that set the admin edges on
    /// A's admin paths to `target`.
    fn chain_writes(&self, best: &BTreeMap<Tid, Role>, target: &Tid, ts: Ts) -> BTreeSet<WriteId> {
        let mut out = BTreeSet::new();
        for t in self.view(ts).admin_reaching(target) {
            for (m, e) in self.edges.members(&t) {
                if e.role == Role::Admin && e.alive_at(Some(ts)) && best.get(m) == Some(&Role::Admin)
                    && let Some(w) = self.setter.get(&(*m, t))
                {
                    out.insert(*w);
                }
            }
        }
        out
    }

    /// An explicit write changed edge `(member, target)`: every node X reaching the member
    /// whose standing on a thing N reachable from the target is lower than with the edge
    /// `restored` (its value before, alive) was demoted by it (§5.1 step 4): record the
    /// demotion for layer 2 and audit the classes X fell through. Returns whether D grew.
    fn audit_fall(&mut self, (member, target): (Tid, Tid), base: Option<Edge>, mine: &BTreeMap<Tid, Edge>, ts: Ts, aud: &Auditor) -> bool {
        let view = self.view(ts);
        let xs: Vec<Tid> = view.reach_backward(&member).into_iter().filter(|x| self.input.nodes.contains(x) && aud.author != Some(*x)).collect();
        let ns = view.reach_forward(&target);
        let cur = self.edges.get(&member, &target).copied().filter(|e| e.alive_at(Some(ts)));
        // Every x's roles on what its standing on the target reads (the member, the target,
        // members with an invite, admin anywhere on its owner chain), by backward searches.
        let mut keys: BTreeSet<Tid> = BTreeSet::from([member, target]);
        keys.extend(self.edges.members(&target).filter(|(_, e)| e.invite.is_some()).map(|(m, _)| *m));
        let to: BTreeMap<Tid, BTreeMap<Tid, Role>> = keys.iter().map(|k| (*k, view.roles_to(k))).collect();
        let role_on = |x: &Tid, k: &Tid| to.get(k).and_then(|m| m.get(x)).copied();
        let (up, top) = self.input.owners.chain(&target);
        let on_chain = view.roles_to_any(&up);
        let mut grew = false;
        for x in xs {
            let restored = match (base, mine.get(&x)) {
                (b, Some(m)) => join(b, *m),
                (Some(b), None) => Edge { until: None, since: None, ..b },
                (None, None) => continue,
            };
            // An edge x does not reach (alive) confers nothing on x either way.
            let Some(on_member) = role_on(&x, &member) else { continue };
            // The restored edge (alive) is usually at least as wide as the current one; when
            // it raises nothing (not wider than x's role on the target), only the invite on the
            // target can differ.
            let wider = cur.is_none_or(|c| c.role <= restored.role);
            let pairs: Vec<(Tid, Standing, Standing)> = if wider && Some(on_member.min(restored.role)) <= role_on(&x, &target) {
                let small: BTreeMap<Tid, Role> = keys.iter().filter_map(|k| role_on(&x, k).map(|r| (*k, r))).collect();
                let chain = top == Some(x) || on_chain.get(&x) == Some(&Role::Admin);
                let role = role_on(&x, &target);
                let view = self.view(ts);
                let before = self.view(ts).patched(member, target, Some(restored));
                vec![(target, view.standing_from(chain, role, &small, &target), before.standing_from(chain, role, &small, &target))]
            } else {
                let best = self.roles(x, ts);
                let view = self.view(ts);
                let before = self.view(ts).patched(member, target, Some(restored));
                let best_was = if wider {
                    let mut b = (*best).clone();
                    b.extend(before.roles_raised(&best, &[member]));
                    b
                } else {
                    before.roles_from(&x)
                };
                ns.iter().map(|n| (*n, view.standing(&x, &best, n), before.standing(&x, &best_was, n))).collect()
            };
            for (n, now, held) in pairs {
                for below in [Role::Write, Role::Admin] {
                    if held.role >= Some(below) && now.role < Some(below) {
                        let d = Demotion { point: aud.point, below, frontier: aud.frontier_arc.clone(), ledger: aud.ledger };
                        self.demotions.entry((x, n)).or_default().push(d);
                        self.log.push(Undo::Demotion((x, n)));
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
                self.fresh.push(id);
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
        let best = self.roles(c.author, c.ts);
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
        let best = self.roles(s.author, s.ts);
        let chain = self.view(s.ts).standing(&s.author, &best, &s.thing).class == Class::Chain;
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
                self.set_setter((*m, s.thing), Some(id));
            }
        }
        self.record(id, Applied { author: s.author, target: s.thing, point, attr: Attr::By(Class::Chain), dots: s.dots });
        Ok(())
    }

    fn virtual_write(&mut self, v: &Virtual) -> bool {
        let chain = v.audit.as_ref().map(|(node, _)| {
            let best = self.roles(*node, v.point.ts);
            self.chain_writes(&best, &v.thing, v.point.ts)
        });
        let auditor = v.audit.as_ref().zip(chain).map(|((node, f), chain)| Auditor {
            // A ledger entry with a frontier counts as an explicit demotion by its key's node
            // (§6): that node is exempt as from its own write, and its chain writes count.
            author: Some(*node),
            frontier: Some(f.as_ref()),
            chain,
            commit: None,
            point: v.point,
            ledger: true,
            frontier_arc: Some(f.clone()),
        });
        self.change(v.point, (v.member, v.thing), v.edge, None, auditor.as_ref())
    }
}

/// The items of a walk in order under epoch starts `epoch`, and the index of each commit
/// and snapshot.
struct Items {
    initial: Edges,
    list: Vec<(Point, u8, Tid, Tid, Item)>,
    at: BTreeMap<CommitId, usize>,
}

fn items(input: &Input, epoch: &BTreeMap<Tid, CommitId>) -> Items {
    let mut list: Vec<(Point, u8, Tid, Tid, Item)> = Vec::new();
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
            list.push((v.point, 0, v.thing, v.member, Item::Virtual(v)));
        }
    }
    for c in input.commits.values() {
        list.push((c.point(), 1, zero, zero, Item::Commit(c.clone())));
    }
    for s in input.snaps.values() {
        list.push((s.point(), 1, zero, zero, Item::Snap(s.clone())));
    }
    list.sort_by_key(|a| (a.0, a.1, a.2, a.3));
    let mut at = BTreeMap::new();
    for (i, it) in list.iter().enumerate() {
        match &it.4 {
            Item::Commit(c) => at.insert(c.id, i),
            Item::Snap(s) => at.insert(s.id, i),
            Item::Virtual(_) => None,
        };
    }
    Items { initial, list, at }
}

enum Step {
    Done,
    /// D grew: walk again from this item (the first one D now skips more of).
    Restart(usize),
    /// The chosen epoch start is inapplicable.
    Reject,
}

impl Pass<'_> {
    /// Walks `items` from item `from` (rolled back to the state before it). A walk with a
    /// larger D is this one up to the first write D now skips, so a restart resumes there.
    fn walk(&mut self, items: &Items, from: usize, rejected: &mut BTreeSet<CommitId>, choose: &mut BTreeMap<Tid, CommitId>) -> Step {
        self.rollback(from);
        self.fresh.clear();
        for (_, _, _, _, item) in items.list.iter().skip(from) {
            self.marks.push((self.log.len(), self.history.len()));
            let restart = match item {
                Item::Commit(c) => self.commit(c),
                Item::Snap(s) => {
                    if self.snapshot(s, rejected, choose).is_err() {
                        return Step::Reject;
                    }
                    false
                }
                Item::Virtual(v) => self.virtual_write(v),
            };
            if restart {
                let first = self.fresh.iter().filter_map(|w| items.at.get(&w.commit())).min();
                return Step::Restart(first.copied().unwrap_or(0));
            }
        }
        Step::Done
    }
}

/// Evaluates the timeline from scratch: walks until a walk adds nothing to D (§5.1 step 5).
pub(crate) fn run(input: &Input) -> Outcome {
    drive(input, None)
}

/// Continues a converged evaluation over `input`, which adds membership commits at or after
/// `r.from` (and nothing else): equal to `run` provided no walk but the final one reached
/// `r.from` (`r.reach` before it), since every walk then reaches it as before.
pub(crate) fn resume(input: &Input, r: Resume) -> Outcome {
    drive(input, Some(r))
}

fn drive(input: &Input, resume: Option<Resume>) -> Outcome {
    let ns = input.snaps.len();
    let writes = input.commits.values().map(|c| c.ops.len()).sum::<usize>() + ns;
    // Safety net: D grows between epoch changes; epoch changes stop except where authority
    // paths cycle through mutual membership, where this bound ends the evaluation.
    let cap = (writes + 2).saturating_mul(ns.saturating_mul(ns + 2) + 1).saturating_mul(4);
    let (mut epoch, mut rejected, mut passes, mut epoch_changed, mut reach, mut it, mut p, mut from);
    match resume {
        None => {
            epoch = BTreeMap::new();
            rejected = BTreeSet::new();
            (passes, epoch_changed, reach) = (0, false, None);
            it = items(input, &epoch);
            p = Pass::new(input, epoch.clone(), BTreeMap::new(), it.initial.clone());
            from = 0;
        }
        Some(r) => {
            (epoch, rejected, passes, epoch_changed, reach) = (r.epoch_starts, r.rejected, r.passes, r.epoch_changed, r.reach);
            it = items(input, &epoch);
            from = it.list.partition_point(|x| x.0 < r.from);
            p = Pass::resume(input, epoch.clone(), r.dropped, r.walked);
        }
    }
    let mut fresh = false;
    loop {
        passes += 1;
        let mut changed: Vec<Tid> = Vec::new();
        // A dropped epoch start is rejected.
        for (thing, s) in &epoch {
            if p.dropped.contains_key(&WriteId::Snapshot(*s)) {
                rejected.insert(*s);
                changed.push(*thing);
            }
        }
        epoch.retain(|_, s| !rejected.contains(s));
        if fresh || !changed.is_empty() {
            it = items(input, &epoch);
            p = Pass::new(input, epoch.clone(), std::mem::take(&mut p.dropped), it.initial.clone());
            from = 0;
        }
        let mut choose = BTreeMap::new();
        let before: BTreeSet<CommitId> = rejected.clone();
        let step = p.walk(&it, from, &mut rejected, &mut choose);
        // where this walk stopped, should it not be the final one
        let stop = match step {
            Step::Done => it.list.last().map(|x| x.0),
            Step::Restart(_) | Step::Reject => p.marks.len().checked_sub(1).and_then(|i| it.list.get(i)).map(|x| x.0),
        };
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
            epoch_changed = true;
            // A rejected start gets another chance when a start changes anywhere authority on
            // its thing may come from (owners, members of what is above, at any time); D is
            // rebuilt, so writes a new start ignores leave no drops behind.
            rejected.retain(|s| {
                input.snaps.get(s).is_none_or(|sn| {
                    let above = input.above(&sn.thing);
                    !changed.iter().any(|c| above.contains(c))
                })
            });
            p.dropped.clear();
        }
        match step {
            Step::Done if changed.is_empty() => {
                let (walked, dropped) = p.finish();
                return Outcome { walked, dropped, epoch_starts: epoch, passes, converged: true, epoch_changed, rejected, reach };
            }
            _ if passes >= cap => {
                let it = items(input, &epoch);
                let mut q = Pass::new(input, epoch.clone(), p.dropped.clone(), it.initial.clone());
                let walked = match q.walk(&it, 0, &mut rejected.clone(), &mut BTreeMap::new()) {
                    Step::Done => q.finish().0,
                    _ => Pass::new(input, BTreeMap::new(), BTreeMap::new(), Edges::default()).finish().0,
                };
                return Outcome { walked, dropped: p.dropped, epoch_starts: epoch, passes, converged: false, epoch_changed, rejected, reach: None };
            }
            _ => {}
        }
        reach = reach.max(stop);
        fresh = !changed.is_empty();
        if let Step::Restart(i) = step {
            from = i;
        }
    }
}
