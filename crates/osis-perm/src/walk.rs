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
//! - Only R's frontier and R itself cover X's writes (§5.1): writes on A's own chain too (the
//!   writer lists its chain certificates by commit ID), so a removed admin's backdated write on
//!   its remover's edge drops.
//! - Epoch starts (§6), by iteration: under the current starts the walk runs until D settles
//!   (from scratch), judging every snapshot at its position like an owner-chain edge write
//!   (`candidates`: a later demotion's audit may drop it); then each thing's start becomes its
//!   newest snapshot that applied, and so on until the starts settle (`drive` argues
//!   termination). Only settled walks choose, so the starts are a function of the held set.
//! - Before its epoch start S, N's edges follow S's roster and ledger as virtual writes placed
//!   at their keys (just after the commit at that point); an entry with a frontier is the
//!   explicit demotion it records, by its key's node (exempt as the author), audit-only
//!   entries (`since` = `until`) included.

use crate::content::{overlapping, Range};
use crate::graph::{Class, Edges, EdgesAt, Owners, Reads, Standing, View};
use crate::held::HeldSet;
use crate::types::{lowers, Dots, Edge, Frontier, MembershipCommit, Point, RosterSnapshot, WriteId, MEMBERS};
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

/// A class fall whose audit ran (§5.1 step 4): the demoting write's point and the node's
/// class on the thing after and before it; writes attributed to a class in (now, held] drop.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fall {
    pub point: Point,
    pub now: Class,
    pub held: Class,
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
    /// Every member any held write, roster or ledger gives admin, per target (edges at any
    /// time): owner-chain authority comes only through admin edges.
    pub ever_admins: BTreeMap<Tid, BTreeSet<Tid>>,
    /// The earliest held write (edge op or roster snapshot) per (author, target).
    pub first_write: BTreeMap<(Tid, Tid), Point>,
    /// Node-form `/members` ranges of every gathered commit and snapshot, voided ones
    /// included, by (node, thing), with their largest end: what `can_append` checks against.
    pub ranges: BTreeMap<(Tid, Tid), (Spans, u64)>,
    /// Every edge any held write, roster or ledger can set (any role, any time), member to
    /// targets and target to members: what any reach in any walk follows besides owner links.
    pub ever: Ever,
    /// The commits and snapshots voided by overlapping ranges, as held (`holds_same`).
    pub voided: (BTreeMap<CommitId, Arc<MembershipCommit>>, BTreeMap<CommitId, Arc<RosterSnapshot>>),
}

/// Edges at any time, both ways (`Input::ever`).
#[derive(Default)]
pub(crate) struct Ever {
    pub targets: BTreeMap<Tid, BTreeSet<Tid>>,
    pub members: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Members of an edge with an invite.
    pub invites: BTreeSet<Tid>,
}

impl Ever {
    fn add(&mut self, member: Tid, target: Tid, e: &Edge) {
        self.targets.entry(member).or_default().insert(target);
        self.members.entry(target).or_default().insert(member);
        if e.invite.is_some() {
            self.invites.insert(member);
        }
    }
}

/// Node-form ranges `[lo, hi)` with their commits.
pub(crate) type Spans = Vec<(u64, u64, CommitId)>;

impl Input {
    /// Whether owner-chain authority on some thing with a roster snapshot may come through that
    /// thing itself (mutual membership): through its owners and the members with an admin edge
    /// of anything on the way, transitively, at any time. Otherwise the epoch starts have a
    /// unique fixed point (`drive`).
    pub fn cyclic(&self) -> bool {
        self.cyclic_with(&[])
    }

    /// `cyclic` with the admin edges `extra` (target, member) also held.
    fn cyclic_with(&self, extra: &[(Tid, Tid)]) -> bool {
        let things: BTreeSet<Tid> = self.snaps.values().map(|s| s.thing).collect();
        things.iter().any(|t| {
            let mut seen = BTreeSet::new();
            let mut stack = vec![*t];
            while let Some(e) = stack.pop() {
                let more = extra.iter().filter(|x| x.0 == e).map(|x| x.1);
                let up = self.owners.owner_actor(&e).into_iter().chain(self.ever_admins.get(&e).into_iter().flatten().copied()).chain(more);
                for y in up {
                    if y == *t {
                        return true;
                    }
                    if seen.insert(y) {
                        stack.push(y);
                    }
                }
            }
            false
        })
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
        let ranges: Vec<Range> = commits
            .values()
            .flat_map(|c| c.ops.iter().map(move |o| (c.id, c.author, o.target, o.dots)))
            .chain(snaps.values().map(|s| (s.id, s.author, s.thing, s.dots)))
            .filter_map(|(commit, node, tid, d)| match d {
                Dots::Node { lo, hi } => Some(Range { commit, node, tid, ak: MEMBERS.to_string(), lo, hi }),
                Dots::Commit => None,
            })
            .collect();
        let mut by_key: BTreeMap<(Tid, Tid), (Spans, u64)> = BTreeMap::new();
        for r in ranges.iter().filter(|r| r.lo < r.hi) {
            let e = by_key.entry((r.node, r.tid)).or_default();
            e.0.push((r.lo, r.hi, r.commit));
            e.1 = e.1.max(r.hi);
        }
        let void = overlapping(ranges);
        let voided = (commits.iter().filter(|(id, _)| void.contains(*id)).map(|(id, c)| (*id, c.clone())).collect(), snaps.iter().filter(|(id, _)| void.contains(*id)).map(|(id, s)| (*id, s.clone())).collect());
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
        // An invite of admin needs an admin edge, so admin edges carry all admin authority.
        let mut ever_admins: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
        for c in commits.values() {
            for o in c.ops.iter().filter(|o| o.edge.is_some_and(|e| e.role == Role::Admin)) {
                ever_admins.entry(o.target).or_default().insert(o.member);
            }
        }
        for s in snaps.values() {
            let roster = s.roster.iter().filter(|(_, e)| e.role == Role::Admin).map(|(m, _)| *m);
            let ledger = s.ledger.iter().filter(|t| t.role == Role::Admin).map(|t| t.member);
            ever_admins.entry(s.thing).or_default().extend(roster.chain(ledger));
        }
        let mut ever = Ever::default();
        for c in commits.values() {
            for o in &c.ops {
                if let Some(e) = &o.edge {
                    ever.add(o.member, o.target, e);
                }
            }
        }
        for s in snaps.values() {
            for (m, e) in &s.roster {
                ever.add(*m, s.thing, e);
            }
            for t in &s.ledger {
                ever.add(t.member, s.thing, &Edge::new(t.role));
            }
        }
        let mut first_write: BTreeMap<(Tid, Tid), Point> = BTreeMap::new();
        let writes = commits.values().flat_map(|c| c.ops.iter().map(move |o| (c.author, o.target, c.point()))).chain(snaps.values().map(|s| (s.author, s.thing, s.point())));
        for (a, t, p) in writes {
            let e = first_write.entry((a, t)).or_insert(p);
            *e = (*e).min(p);
        }
        Input { owners, commits, snaps, nodes, ever_admins, first_write, ranges: by_key, ever, voided }
    }

    /// Whether `c` is held here with this content (a record can grow under its ID: a part
    /// that arrives late).
    pub fn holds_commit(&self, c: &MembershipCommit) -> bool {
        self.commits.get(&c.id).or_else(|| self.voided.0.get(&c.id)).is_some_and(|o| o.same_input(c))
    }

    /// `holds_commit` for a roster snapshot.
    pub fn holds_snapshot(&self, s: &RosterSnapshot) -> bool {
        self.snaps.get(&s.id).or_else(|| self.voided.1.get(&s.id)).is_some_and(|o| o.same_input(s))
    }

    /// Whether every record held here is held in `other` with the same content.
    pub fn kept_in(&self, other: &Input) -> bool {
        let commits = self.commits.values().chain(self.voided.0.values());
        let snaps = self.snaps.values().chain(self.voided.1.values());
        commits.into_iter().all(|c| other.holds_commit(c)) && snaps.into_iter().all(|s| other.holds_snapshot(s))
    }

    /// What reaches any of `seeds` (included) at any time: owner links and `ever` edges.
    fn ever_back(&self, seeds: impl IntoIterator<Item = Tid>) -> BTreeSet<Tid> {
        let mut seen: BTreeSet<Tid> = seeds.into_iter().collect();
        let mut stack: Vec<Tid> = seen.iter().copied().collect();
        while let Some(e) = stack.pop() {
            let up = self.owners.owner_actor(&e).into_iter().chain(self.ever.members.get(&e).into_iter().flatten().copied());
            for y in up.collect::<Vec<_>>() {
                if seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        seen
    }

    /// What any of `seeds` (included) reaches at any time.
    fn ever_forward(&self, seeds: impl IntoIterator<Item = Tid>) -> BTreeSet<Tid> {
        let mut seen: BTreeSet<Tid> = seeds.into_iter().collect();
        let mut stack: Vec<Tid> = seen.iter().copied().collect();
        while let Some(e) = stack.pop() {
            let down = self.owners.owned(&e).iter().chain(self.ever.targets.get(&e).into_iter().flatten()).copied();
            for y in down.collect::<Vec<_>>() {
                if seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        seen
    }

    /// Whether a node (author, or member that may be one) can join with the commits naming it:
    /// one here already, or one that reaches nothing here (no edge of it as member, it owns
    /// nothing), so before those commits no walk meets it (it is in no audit's reach).
    fn may_be_node(&self, t: &Tid) -> bool {
        self.nodes.contains(t) || (self.owners.owner(t).is_none() && self.owners.owned(t).is_empty() && !self.ever.targets.contains_key(t))
    }

    /// Whether `new` (commits not held here) can join this input without changing anything but
    /// the commits and new nodes that reach nothing here (`append`): no thing without an owner
    /// link here becoming owned, no overlapping node-form range (a void, spec/commits.md §4),
    /// and with an epoch start ever changed, no membership cycle (`Timeline::extend`'s
    /// conditions).
    pub fn can_append(&self, new: &[Arc<MembershipCommit>], epoch_changed: bool) -> bool {
        let mut mine: BTreeMap<(Tid, Tid), Spans> = BTreeMap::new();
        let mut admins = Vec::new();
        for c in new {
            if self.commits.contains_key(&c.id) || !self.may_be_node(&c.author) {
                return false;
            }
            for o in &c.ops {
                if self.owners.owner_actor(&o.member).is_none() && !self.may_be_node(&o.member) {
                    return false;
                }
                if o.edge.is_some_and(|e| e.role == Role::Admin) {
                    admins.push((o.target, o.member));
                }
                let Dots::Node { lo, hi } = o.dots else { continue };
                if lo >= hi {
                    continue;
                }
                let k = (c.author, o.target);
                let clash = |v: &[(u64, u64, CommitId)]| v.iter().any(|&(l, h, x)| x != c.id && l < hi && lo < h);
                if self.ranges.get(&k).is_some_and(|(v, max)| *max > lo && clash(v)) || mine.get(&k).is_some_and(|v| clash(v)) {
                    return false;
                }
                mine.entry(k).or_default().push((lo, hi, c.id));
            }
        }
        !(epoch_changed && self.cyclic_with(&admins))
    }

    /// Adds `new`, which `can_append` accepted.
    pub fn append(&mut self, new: &[Arc<MembershipCommit>]) {
        for c in new {
            self.nodes.insert(c.author);
            for o in &c.ops {
                if self.owners.owner_actor(&o.member).is_none() {
                    self.nodes.insert(o.member);
                }
                if self.owners.is_key(&o.target) {
                    self.nodes.insert(o.target);
                }
                if let Some(e) = &o.edge {
                    self.ever.add(o.member, o.target, e);
                }
                if o.edge.is_some_and(|e| e.role == Role::Admin) {
                    self.ever_admins.entry(o.target).or_default().insert(o.member);
                }
                let e = self.first_write.entry((c.author, o.target)).or_insert(c.point());
                *e = (*e).min(c.point());
                if let Dots::Node { lo, hi } = o.dots
                    && lo < hi
                {
                    let r = self.ranges.entry((c.author, o.target)).or_default();
                    r.0.push((lo, hi, c.id));
                    r.1 = r.1.max(hi);
                }
            }
            self.commits.insert(c.id, c.clone());
        }
    }
}

/// At most this many nodes to audit read their roles forward (`Pass::roles`), more by
/// backward searches from what their standings read (a cost choice: the values are equal).
const FORWARD_MAX: usize = 4;

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
    /// Class falls (§5.1 step 4) by (node, thing) where the node has an earlier held write
    /// on the thing, in walk order. None on a leaf (no write names it), so not aliased.
    pub falls: BTreeMap<(Tid, Tid), Vec<Fall>>,
    /// The rest of the walk's state, to continue it past its last write (`Timeline::extend`).
    pub rest: Rest,
}

/// What `Walked::insert` did with a commit new to the walk.
pub(crate) enum Placement {
    /// Not exact here: walk again from the commit.
    Declined,
    /// It applies nothing: only its mark was added.
    Idle,
    /// Its changes were placed in the history from this index on.
    Inserted(usize),
}

impl Walked {
    /// Places `c`, a commit `input` now holds, at item `i = items.place(c)` of the walk (`items`
    /// not yet listing it) without walking again, when exact: `at` is the edge state before
    /// item `i`, `early` whether its author held an earlier write on each target (so no later
    /// class fall the walk records changes, `falls`), `fresh` the nodes it brings. Exact when
    /// no drop was found at or after it (an earlier walk of the round may see it apply), its
    /// explicit writes audit nothing (restore no more than they set), its author's class on
    /// their targets falls nowhere later (an audit there would read it), and no later item
    /// reads what it changes: with (M, T) its edges, the new values change roles only of what
    /// reaches some M at any time (A) on what some T reaches (F), and reaches only from A or
    /// to F; so a later item depends on it only by writing such an edge, by an author in A
    /// on or for something in F, or, applied explicit on (m, t), by `m` in F (its reach back),
    /// `t` in A (its reach forward), or `m` reached from A and `t` reaching into F (a node in
    /// A audited on a thing in F), or `m` reached from a fresh node (which no audit met).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn insert(&mut self, input: &Input, items: &Items, dropped: &BTreeMap<WriteId, Point>, epoch: &BTreeMap<Tid, CommitId>, c: &MembershipCommit, at: &mut EdgesAt<'_>, early: bool, fresh: &BTreeSet<Tid>) -> Placement {
        let p = c.point();
        if !early || dropped.values().any(|d| *d >= p) {
            return Placement::Declined;
        }
        let i = items.place(c);
        let (l, h) = self.rest.marks.get(i).copied().unwrap_or((self.rest.log.len(), self.history.len()));
        let mut placed = Vec::new();
        {
            let view = View::at(&input.owners, at, Some(c.ts));
            let best = view.roles_from(&c.author);
            for (k, o) in c.ops.iter().enumerate() {
                let before_start = epoch.get(&o.target).and_then(|s| input.snaps.get(s)).is_some_and(|s| p < s.point());
                let Ok(k32) = u32::try_from(k) else { continue };
                if before_start {
                    continue;
                }
                if let Some(attr) = judge(&view, at.get(&o.member, &o.target), c, k, &best) {
                    placed.push((k32, o, attr));
                }
            }
        }
        if placed.is_empty() {
            self.rest.marks.insert(i, (l, h));
            return Placement::Idle;
        }
        let keys: BTreeSet<(Tid, Tid)> = placed.iter().map(|(_, o, _)| (o.member, o.target)).collect();
        if keys.len() < placed.len() {
            return Placement::Declined;
        }
        for (_, o, attr) in &placed {
            let key = (o.member, o.target);
            let explicit = matches!(attr, Attr::By(Class::Chain | Class::Edge));
            let new = o.edge.map(|e| Edge { since: None, ..e });
            if explicit && exceeds(self.restored(key), new, p.ts) {
                return Placement::Declined;
            }
            if self.falls.get(&(c.author, o.target)).is_some_and(|v| v.iter().any(|f| f.point >= p)) {
                return Placement::Declined;
            }
        }
        // the widest role and whether an invite the new values or the old ones (at `p`) hold
        let olds = placed.iter().map(|(_, o, _)| at.get(&o.member, &o.target).copied());
        let vals: Vec<Edge> = olds.chain(placed.iter().map(|(_, o, _)| o.edge)).flatten().collect();
        let level = vals.iter().map(|e| e.role).max().unwrap_or(Role::Read);
        let invite = vals.iter().any(|e| e.invite.is_some());
        if !self.independent(input, items, i, &keys, fresh, level, invite) {
            return Placement::Declined;
        }
        let (mut log, mut hist) = (Vec::new(), Vec::new());
        for (k, o, attr) in placed {
            let key = (o.member, o.target);
            let id = WriteId::Op(c.id, k);
            let new = o.edge.map(|e| Edge { since: None, ..e });
            // as `Pass::record`, at its place in walk order
            let pos = self.rest.by_author_target.get(&(c.author, o.target)).map_or(0, |v| v.partition_point(|w| self.write_point(w).is_none_or(|q| q <= p)));
            self.rest.by_author_target.entry((c.author, o.target)).or_default().insert(pos, id);
            log.push(Undo::ByAuthorTarget((c.author, o.target)));
            let was = self.applied.insert(id, Applied { author: c.author, target: o.target, point: p, attr, dots: o.dots });
            log.push(Undo::Applied(id, was));
            // as `Pass::change` with no audit: the key's state at the end is its state here
            let old = self.edges.get(&o.member, &o.target).copied().filter(|_| !self.rest.dead.contains(&key));
            let was = if new.is_some_and(|e| !e.alive_at(Some(p.ts))) { !self.rest.dead.insert(key) } else { self.rest.dead.remove(&key) };
            log.push(Undo::Dead(key, was));
            let explicit = matches!(attr, Attr::By(Class::Chain | Class::Edge));
            let restores = old.is_some() || self.rest.prior.contains_key(&key);
            let own = explicit && restores && View::at(&input.owners, at, Some(p.ts)).reach_backward(&o.member).contains(&c.author);
            log.push(Undo::Edge(o.member, o.target, self.edges.get(&o.member, &o.target).copied()));
            self.edges.set(o.member, o.target, new);
            at.set(o.member, o.target, new);
            let was = self.rest.setter.insert(key, id);
            log.push(Undo::Setter(key, was));
            if !explicit {
                hist.push(Change { point: p, member: o.member, target: o.target, edge: new, explicit: None, audited: None });
                if let Some(o) = old {
                    let pr = self.rest.prior.get(&key).copied();
                    let was = self.rest.prior.insert(key, join(pr, o));
                    log.push(Undo::Prior(key, was));
                }
                continue;
            }
            let all = self.rest.prior.remove(&key);
            log.push(Undo::Prior(key, all));
            let mine = self.rest.prior_node.remove(&key);
            log.push(Undo::PriorNode(key, mine.clone()));
            let base = match (all, old) {
                (Some(a), Some(o)) => Some(join(Some(a), o)),
                (a, o) => a.or(o),
            };
            hist.push(Change { point: p, member: o.member, target: o.target, edge: new, explicit: Some(c.frontier.clone()), audited: None });
            if let (true, Some(b)) = (own, base) {
                let r = join(mine.as_ref().and_then(|m| m.get(&c.author)).copied(), b);
                log.push(Undo::PriorNode(key, None));
                self.rest.prior_node.entry(key).or_default().insert(c.author, r);
            }
        }
        let (nl, nh) = (log.len(), hist.len());
        self.rest.log.splice(l..l, log);
        self.history.splice(h..h, hist);
        for m in self.rest.marks.iter_mut().skip(i) {
            m.0 += nl;
            m.1 += nh;
        }
        self.rest.marks.insert(i, (l, h));
        Placement::Inserted(h)
    }

    /// The point of an applied write or applied snapshot.
    fn write_point(&self, w: &WriteId) -> Option<Point> {
        match w {
            WriteId::Snapshot(s) => self.rest.candidates.get(s).map(|a| a.point),
            WriteId::Op(..) => self.applied.get(w).map(|a| a.point),
        }
    }

    /// The edge `key` as an explicit write on it now restores (§5.1 step 4), as `Pass::change`.
    fn restored(&self, key: (Tid, Tid)) -> Option<Edge> {
        let old = self.edges.get(&key.0, &key.1).copied().filter(|_| !self.rest.dead.contains(&key));
        let base = match (self.rest.prior.get(&key).copied(), old) {
            (Some(a), Some(o)) => Some(join(Some(a), o)),
            (a, o) => a.or(o),
        };
        self.rest.prior_node.get(&key).into_iter().flatten().fold(base, |r, (_, e)| Some(join(r, *e)))
    }

    /// Whether no item from `i` on reads what setting edges `keys` changes (`insert`): `level`
    /// the widest role among their values before and after, `invite` whether one has an
    /// invite. A path through them is at most `level` wide, so roles change only up to it:
    /// classes (admin on the chain or the thing, invites) change only through an admin value
    /// or an invite, met there or on a member in F; the role thresholds demotions record
    /// (write, admin) only through a value of write or more. What reaches what changes
    /// whatever the roles: an explicit write on (m, t) with `m` in F asks whether its author
    /// reaches `m` (the standing it keeps).
    #[allow(clippy::too_many_arguments)]
    fn independent(&self, input: &Input, items: &Items, i: usize, keys: &BTreeSet<(Tid, Tid)>, fresh: &BTreeSet<Tid>, level: Role, invite: bool) -> bool {
        let rest = items.list.get(i..).unwrap_or_default();
        if rest.is_empty() {
            return true;
        }
        let a = input.ever_back(keys.iter().map(|k| k.0));
        let f = input.ever_forward(keys.iter().map(|k| k.1));
        let things: BTreeSet<Tid> = keys.iter().map(|k| k.1).collect();
        let classes = level == Role::Admin || invite || f.iter().any(|t| input.ever.invites.contains(t));
        let roles = classes || level >= Role::Write;
        let (mut fa, mut bf): (Option<BTreeSet<Tid>>, Option<BTreeSet<Tid>>) = (None, None);
        let fresh_reach = input.ever_forward(fresh.iter().copied());
        let mut explicit_ok = |m: &Tid, t: &Tid| {
            if f.contains(m) {
                return false;
            }
            if !roles {
                return true;
            }
            if a.contains(t) || fresh_reach.contains(m) {
                return false;
            }
            let fa = fa.get_or_insert_with(|| input.ever_forward(a.iter().copied()));
            !fa.contains(m) || !bf.get_or_insert_with(|| input.ever_back(f.iter().copied())).contains(t)
        };
        for (_, _, _, _, item) in rest {
            match item {
                Item::Commit(d) => {
                    if d.ops.iter().any(|o| keys.contains(&(o.member, o.target))) {
                        return false;
                    }
                    if classes && a.contains(&d.author) && d.ops.iter().any(|o| f.contains(&o.target) || f.contains(&o.member)) {
                        return false;
                    }
                    for (k, o) in d.ops.iter().enumerate() {
                        let Ok(k) = u32::try_from(k) else { continue };
                        let applied = self.applied.get(&WriteId::Op(d.id, k));
                        if applied.is_some_and(|x| matches!(x.attr, Attr::By(Class::Chain | Class::Edge))) && !explicit_ok(&o.member, &o.target) {
                            return false;
                        }
                    }
                }
                Item::Snap(s) => {
                    if things.contains(&s.thing) || (classes && a.contains(&s.author) && f.contains(&s.thing)) {
                        return false;
                    }
                }
                Item::Virtual(v) => {
                    if keys.contains(&(v.member, v.thing)) || (v.audit.is_some() && !explicit_ok(&v.member, &v.thing)) {
                        return false;
                    }
                }
            }
        }
        true
    }
    /// New leaves (thing, owner): things no edge write names, so every node's role on one is
    /// its role on its owner at every point and a from-scratch walk records on it exactly the
    /// owner's demotions, in the same items. Copies them and their undo entries. `None`: an
    /// owner neither known nor a new leaf (cycle).
    pub(crate) fn alias_leaves(&mut self, leaves: &[(Tid, Tid)], nodes: &BTreeSet<Tid>) -> Option<()> {
        if leaves.is_empty() {
            return Some(());
        }
        let pending: BTreeSet<Tid> = leaves.iter().map(|l| l.0).collect();
        let mut deps: BTreeMap<Tid, Vec<Tid>> = BTreeMap::new();
        for (l, o) in leaves {
            deps.entry(*o).or_default().push(*l);
        }
        // top-down: owners before their leaves
        let mut done: BTreeSet<Tid> = BTreeSet::new();
        let mut order = Vec::new();
        while order.len() < leaves.len() {
            let before = order.len();
            for (l, o) in leaves {
                if !done.contains(l) && (!pending.contains(o) || done.contains(o)) {
                    done.insert(*l);
                    order.push((*l, *o));
                }
            }
            if order.len() == before {
                return None;
            }
        }
        for (l, o) in &order {
            for x in nodes {
                if let Some(v) = self.demotions.get(&(*x, *o)).cloned() {
                    self.demotions.insert((*x, *l), v);
                }
            }
        }
        let has = self.rest.log.iter().any(|u| matches!(u, Undo::Demotion((_, n)) if deps.contains_key(n)));
        if !has {
            return Some(());
        }
        let old = std::mem::take(&mut self.rest.log);
        let mut at = Vec::with_capacity(old.len() + 1);
        let mut log = Vec::with_capacity(old.len());
        for u in old {
            at.push(log.len());
            let k = if let Undo::Demotion(k) = &u { Some(*k) } else { None };
            log.push(u);
            if let Some((x, n)) = k {
                let mut stack: Vec<Tid> = deps.get(&n).cloned().unwrap_or_default();
                while let Some(l) = stack.pop() {
                    log.push(Undo::Demotion((x, l)));
                    stack.extend(deps.get(&l).into_iter().flatten().copied());
                }
            }
        }
        at.push(log.len());
        for m in &mut self.rest.marks {
            m.0 = at.get(m.0).copied().unwrap_or(log.len());
        }
        self.rest.log = log;
        Some(())
    }
}

/// Walk state beyond what queries read (see `Pass`), and the undo log that rolls it back.
#[derive(Default)]
pub(crate) struct Rest {
    pub prior: BTreeMap<(Tid, Tid), Edge>,
    pub dead: BTreeSet<(Tid, Tid)>,
    pub prior_node: BTreeMap<(Tid, Tid), BTreeMap<Tid, Edge>>,
    pub by_author_target: BTreeMap<(Tid, Tid), Vec<WriteId>>,
    pub setter: BTreeMap<(Tid, Tid), WriteId>,
    pub candidates: BTreeMap<CommitId, Applied>,
    pub log: Vec<Undo>,
    /// Per walked item: the log and history lengths before it.
    pub marks: Vec<(usize, usize)>,
    /// D in the order the walks of the final round found it (`resume` keeps the drops found
    /// before the first found at or after its point).
    pub found: Vec<WriteId>,
}

/// The inverse of one change to the walk state.
pub(crate) enum Undo {
    Edge(Tid, Tid, Option<Edge>),
    Dead((Tid, Tid), bool),
    Setter((Tid, Tid), Option<WriteId>),
    Prior((Tid, Tid), Option<Edge>),
    PriorNode((Tid, Tid), Option<BTreeMap<Tid, Edge>>),
    Applied(WriteId, Option<Applied>),
    Candidate(CommitId, Option<Applied>),
    ByAuthorTarget((Tid, Tid)),
    Demotion((Tid, Tid)),
    Fall((Tid, Tid)),
}

pub(crate) struct Outcome {
    pub walked: Walked,
    pub dropped: BTreeMap<WriteId, Point>,
    pub epoch_starts: BTreeMap<Tid, CommitId>,
    /// Walks this evaluation (or continuation) made.
    pub passes: usize,
    /// Whether the epoch starts ever changed.
    pub epoch_changed: bool,
    /// The furthest point a walk under the final starts other than the final walk reached
    /// (where it restarted): a walk is the final one's prefix up to here only.
    pub reach: Option<Point>,
    /// The final walk's items (`None`: not built, `items` builds them).
    pub items: Option<Items>,
    /// For a continued walk that kept its initial state: how many history changes it shares
    /// with the walk it continued, and the point of that walk's first change not shared
    /// (`None`: it shares them all).
    pub common: Option<(usize, Option<Point>)>,
}

/// A converged evaluation to continue: its outcome, and the earliest point of the commits
/// added since.
pub(crate) struct Resume {
    pub walked: Walked,
    pub dropped: BTreeMap<WriteId, Point>,
    pub epoch_starts: BTreeMap<Tid, CommitId>,
    pub epoch_changed: bool,
    pub from: Point,
    /// The walk's items over `input`, when kept (else built).
    pub items: Option<Items>,
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
    commit: Option<CommitId>,
    point: Point,
    ledger: bool,
    frontier_arc: Option<Arc<Frontier>>,
}

/// Edge state of `s.thing` before `s` by its roster and ledger (spec/permissions.md §6): the
/// values at the beginning and the changes at keys before `s`.
fn ledger_writes(s: &RosterSnapshot) -> (Vec<(Tid, Edge)>, Vec<Virtual>) {
    let skey = s.point();
    let mut members: BTreeSet<Tid> = s.roster.keys().copied().collect();
    members.extend(s.ledger.iter().map(|t| t.member));
    let mut initial = Vec::new();
    let mut out = Vec::new();
    for m in members {
        let tenures: Vec<_> = s.ledger.iter().filter(|t| t.member == m).collect();
        let roster = s.roster.get(&m);
        // The value just after key `b` (`None`: the beginning); `with_roster: false` counts
        // the roster edge only where it starts at `b` itself.
        let value = |b: Option<Point>, with_roster: bool| -> Option<Edge> {
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
        let mut keys: BTreeSet<Point> = tenures.iter().flat_map(|t| t.since.into_iter().chain([t.until])).collect();
        keys.extend(roster.and_then(|r| r.since));
        let mut prev = value(None, true);
        if let Some(e) = prev {
            initial.push((m, e));
        }
        for b in keys.into_iter().filter(|b| *b < skey) {
            // An entry with a frontier records an explicit demotion by `b`'s node, even where
            // the roster edge takes over at once (end the tenure, then re-grant) or nothing
            // changes (an audit-only entry).
            if let Some(f) = tenures.iter().find(|t| t.until == b && t.frontier.is_some()).and_then(|t| t.frontier.clone()) {
                let end = value(Some(b), false);
                out.push(Virtual { thing: s.thing, member: m, edge: end, point: b, audit: Some((b.node, f)) });
                prev = end;
            }
            let v = value(Some(b), true);
            if v != prev {
                out.push(Virtual { thing: s.thing, member: m, edge: v, point: b, audit: None });
                prev = v;
            }
        }
    }
    (initial, out)
}

/// Componentwise maximum of two edge values, alive: what a member held across them.
pub(crate) fn join(a: Option<Edge>, b: Edge) -> Edge {
    match a {
        None => Edge { until: None, since: None, ..b },
        Some(a) => Edge { role: a.role.max(b.role), invite: a.invite.max(b.invite), until: None, since: None },
    }
}

/// Does restoring `r` give more than `new` at `ts` (role, invite or life)? If not, an explicit
/// write of `new` demotes nobody.
pub(crate) fn exceeds(r: Option<Edge>, new: Option<Edge>, ts: Ts) -> bool {
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
    /// Snapshots that applied at their position (owner-chain authority, not dropped), the
    /// epoch starts among them: each thing's newest is its next start (`choose`).
    candidates: BTreeMap<CommitId, Applied>,
    history: Vec<Change>,
    demotions: BTreeMap<(Tid, Tid), Vec<Demotion>>,
    falls: BTreeMap<(Tid, Tid), Vec<Fall>>,
    /// `roles_from` per node over the current edges: the answer, the ts it was computed at
    /// and the earliest `until` it followed. Dropped when an edge of a node it reaches changes.
    roles: BTreeMap<Tid, Roles>,
    log: Vec<Undo>,
    marks: Vec<(usize, usize)>,
    /// A continued walk: how many history changes are still the continued walk's, and that
    /// walk's changes after them (moved out by `rollback`).
    untouched: Option<(usize, Vec<Change>)>,
    found: Vec<WriteId>,
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
        Pass::resume(input, epoch, dropped, Walked { edges: initial.clone(), initial, history: Vec::new(), applied: BTreeMap::new(), demotions: BTreeMap::new(), falls: BTreeMap::new(), rest: Rest::default() })
    }

    fn resume(input: &'a Input, epoch: BTreeMap<Tid, CommitId>, dropped: BTreeMap<WriteId, Point>, w: Walked) -> Pass<'a> {
        let Walked { initial, history, edges, applied, demotions, falls, rest } = w;
        let Rest { prior, dead, prior_node, by_author_target, setter, candidates, log, marks, found } = rest;
        Pass { input, epoch, dropped, fresh: Vec::new(), edges, initial, prior, dead, prior_node, applied, by_author_target, setter, candidates, history, demotions, falls, roles: BTreeMap::new(), log, marks, untouched: None, found }
    }

    /// `Outcome::common` of this walk.
    fn common(&self) -> Option<(usize, Option<Point>)> {
        let (n, stash) = self.untouched.as_ref()?;
        let same = |a: &Change, b: &Change| (a.point, a.member, a.target, a.edge) == (b.point, b.member, b.target, b.edge);
        let k = self.history.get(*n..).unwrap_or_default().iter().zip(stash).take_while(|(a, b)| same(a, b)).count();
        Some((n + k, stash.get(k).map(|c| c.point)))
    }

    fn finish(self) -> (Walked, BTreeMap<WriteId, Point>) {
        let rest = Rest { prior: self.prior, dead: self.dead, prior_node: self.prior_node, by_author_target: self.by_author_target, setter: self.setter, candidates: self.candidates, log: self.log, marks: self.marks, found: self.found };
        (Walked { initial: self.initial, history: self.history, edges: self.edges, applied: self.applied, demotions: self.demotions, falls: self.falls, rest }, self.dropped)
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
                Undo::Candidate(c, a) => {
                    match a {
                        Some(a) => self.candidates.insert(c, a),
                        None => self.candidates.remove(&c),
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
                Undo::Fall(k) => {
                    if let Some(v) = self.falls.get_mut(&k) {
                        v.pop();
                        if v.is_empty() {
                            self.falls.remove(&k);
                        }
                    }
                }
            }
        }
        match &mut self.untouched {
            Some((n, stash)) if h < *n => {
                let mut tail = self.history.split_off(h);
                tail.truncate(*n - h);
                tail.append(stash);
                *stash = tail;
                *n = h;
            }
            _ => self.history.truncate(h),
        }
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
        // Before the change: does the author reach the member (a demotion of itself)? Only
        // asked when the edge restores something.
        let restores = old.is_some() || self.prior.contains_key(&key);
        let own = auditor.and_then(|a| a.author).filter(|a| restores && self.view(point.ts).reach_backward(&member).contains(a));
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

    fn record(&mut self, id: WriteId, a: Applied) {
        self.by_author_target.entry((a.author, a.target)).or_default().push(id);
        self.log.push(Undo::ByAuthorTarget((a.author, a.target)));
        let was = self.applied.insert(id, a);
        self.log.push(Undo::Applied(id, was));
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
        // members with an invite, admin anywhere on its owner chain): by backward searches, or
        // for a few x by their (cached) forward roles, the same values.
        let mut keys: BTreeSet<Tid> = BTreeSet::from([member, target]);
        keys.extend(self.edges.members(&target).filter(|(_, e)| e.invite.is_some()).map(|(m, _)| *m));
        let (up, top) = self.input.owners.chain(&target);
        let forward = xs.len() <= FORWARD_MAX;
        let (to, on_chain): (BTreeMap<Tid, BTreeMap<Tid, Role>>, _) = if forward {
            (BTreeMap::new(), BTreeMap::new())
        } else {
            (keys.iter().map(|k| (*k, view.roles_to(k))).collect(), view.roles_to_any(&up))
        };
        // what standings on each thing read, for every x
        let reads: BTreeMap<Tid, Reads> = ns.iter().map(|n| (*n, view.reads(n))).collect();
        let mut grew = false;
        for x in xs {
            let restored = match (base, mine.get(&x)) {
                (b, Some(m)) => join(b, *m),
                (Some(b), None) => Edge { until: None, since: None, ..b },
                (None, None) => continue,
            };
            let fwd = forward.then(|| self.roles(x, ts));
            let role_on = |x: &Tid, k: &Tid| match &fwd {
                Some(b) => b.get(k).copied(),
                None => to.get(k).and_then(|m| m.get(x)).copied(),
            };
            let chain_admin = match &fwd {
                Some(b) => up.iter().filter_map(|y| b.get(y)).max().copied(),
                None => on_chain.get(&x).copied(),
            } == Some(Role::Admin);
            // An edge x does not reach (alive) confers nothing on x either way.
            let Some(on_member) = role_on(&x, &member) else { continue };
            // The restored edge (alive) is usually at least as wide as the current one; when
            // it raises nothing (not wider than x's role on the target), only the invite on the
            // target can differ.
            let wider = cur.is_none_or(|c| c.role <= restored.role);
            let pairs: Vec<(Tid, Standing, Standing)> = if wider && Some(on_member.min(restored.role)) <= role_on(&x, &target) {
                let small: BTreeMap<Tid, Role> = keys.iter().filter_map(|k| role_on(&x, k).map(|r| (*k, r))).collect();
                let chain = top == Some(x) || chain_admin;
                let role = role_on(&x, &target);
                let view = self.view(ts);
                let before = self.view(ts).patched(member, target, Some(restored));
                vec![(target, view.standing_from(chain, role, &small, &target), before.standing_from(chain, role, &small, &target))]
            } else {
                let best = self.roles(x, ts);
                let before = self.view(ts).patched(member, target, Some(restored));
                let (best_was, raised) = if wider {
                    let raised = before.roles_raised(&best, &[member]);
                    let mut b = (*best).clone();
                    b.extend(raised.iter().map(|(t, r)| (*t, *r)));
                    (b, Some(raised))
                } else {
                    (before.roles_from(&x), None)
                };
                // A standing reads the role on the thing, on its owner chain and on its members
                // with an invite; only the target's members differ between the views.
                let target_before = before.reads(&target);
                let reads_raised = |n: &Tid, rd: &Reads| {
                    raised.as_ref().is_none_or(|r| *n == target || r.contains_key(n) || rd.up.iter().any(|y| r.contains_key(y)) || rd.invites.iter().any(|(m, _)| r.contains_key(m)))
                };
                let reads = ns.iter().filter_map(|n| reads.get(n).map(|rd| (n, rd))).filter(|(n, rd)| reads_raised(n, rd));
                reads.map(|(n, rd)| (*n, rd.standing(&x, &best, n), if *n == target { &target_before } else { rd }.standing(&x, &best_was, n))).collect()
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
                    if self.input.first_write.get(&(x, n)).is_some_and(|p| *p < aud.point) {
                        self.falls.entry((x, n)).or_default().push(Fall { point: aud.point, now: now.class, held: held.class });
                        self.log.push(Undo::Fall((x, n)));
                    }
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
            let a = match id {
                WriteId::Snapshot(s) => self.candidates.get(&s),
                WriteId::Op(..) => self.applied.get(&id),
            };
            let Some(a) = a else { continue };
            let Attr::By(c) = a.attr else { continue };
            if !(now < c && c <= held) {
                continue;
            }
            let covered = aud.commit == Some(id.commit())
                || aud.frontier.is_some_and(|f| f.covers(n, MEMBERS, x, a.dots, &id.commit()));
            if !covered && !self.dropped.contains_key(&id) {
                self.dropped.insert(id, aud.point);
                self.fresh.push(id);
                self.found.push(id);
                grew = true;
            }
        }
        grew
    }

    /// How op `k` of `c` applies against the state before `c` (§5.1 step 2, §2).
    fn judge(&self, c: &MembershipCommit, k: usize, best: &BTreeMap<Tid, Role>) -> Option<Attr> {
        let op = c.ops.get(k)?;
        judge(&self.view(c.ts), self.edges.get(&op.member, &op.target), c, k, best)
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
                judged.push((k, id, attr));
            }
        }
        let mut grew = false;
        for (k, id, attr) in judged {
            let Some(op) = c.ops.get(k) else { continue };
            let new = op.edge.map(|e| Edge { since: None, ..e });
            self.record(id, Applied { author: c.author, target: op.target, point, attr, dots: op.dots });
            let explicit = matches!(attr, Attr::By(Class::Chain | Class::Edge));
            let auditor = explicit.then(|| Auditor {
                author: Some(c.author),
                frontier: c.frontier.as_deref(),
                commit: Some(c.id),
                point,
                ledger: false,
                frontier_arc: c.frontier.clone(),
            });
            grew |= self.change(point, (op.member, op.target), new, Some(id), auditor.as_ref());
        }
        grew
    }

    /// A roster snapshot at its position (§6): applies like an owner-chain edge write
    /// (`candidates`, audited like one); the epoch start's roster becomes N's edges whether it
    /// applies or not (the next round of `drive` then chooses again).
    fn snapshot(&mut self, s: &RosterSnapshot) {
        let id = WriteId::Snapshot(s.id);
        let start = self.epoch.get(&s.thing) == Some(&s.id);
        if !self.dropped.contains_key(&id) {
            let best = self.roles(s.author, s.ts);
            if self.view(s.ts).standing(&s.author, &best, &s.thing).class == Class::Chain {
                let a = Applied { author: s.author, target: s.thing, point: s.point(), attr: Attr::By(Class::Chain), dots: s.dots };
                if start {
                    self.record(id, a);
                } else {
                    self.by_author_target.entry((a.author, a.target)).or_default().push(id);
                    self.log.push(Undo::ByAuthorTarget((a.author, a.target)));
                }
                let was = self.candidates.insert(s.id, a);
                self.log.push(Undo::Candidate(s.id, was));
            }
        }
        if !start {
            return;
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
    }

    /// Each thing's newest snapshot that applied in this walk, `banned` ones aside.
    fn choose(&self, banned: &BTreeSet<CommitId>) -> BTreeMap<Tid, CommitId> {
        let mut out: BTreeMap<Tid, (Point, CommitId)> = BTreeMap::new();
        for (c, a) in self.candidates.iter().filter(|(c, _)| !banned.contains(c)) {
            let e = out.entry(a.target).or_insert((a.point, *c));
            if a.point > e.0 {
                *e = (a.point, *c);
            }
        }
        out.into_iter().map(|(t, (_, c))| (t, c)).collect()
    }

    fn virtual_write(&mut self, v: &Virtual) -> bool {
        let auditor = v.audit.as_ref().map(|(node, f)| Auditor {
            // A ledger entry with a frontier counts as an explicit demotion by its key's node
            // (§6): that node is exempt as from its own write.
            author: Some(*node),
            frontier: Some(f.as_ref()),
            commit: None,
            point: v.point,
            ledger: true,
            frontier_arc: Some(f.clone()),
        });
        self.change(v.point, (v.member, v.thing), v.edge, None, auditor.as_ref())
    }
}

/// How op `k` of `c` applies against `view` (edges before `c`, at its `ts`), `old` the
/// edge it writes there and `best` its author's roles (§5.1 step 2, §2).
pub(crate) fn judge(view: &View<'_>, old: Option<&Edge>, c: &MembershipCommit, k: usize, best: &BTreeMap<Tid, Role>) -> Option<Attr> {
    let op = c.ops.get(k)?;
    let (a, m, t) = (c.author, op.member, op.target);
    if m == t || view.owners.owner_actor(&t) == Some(m) || op.edge.is_some_and(|e| !e.well_formed()) {
        return None;
    }
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

/// The items of a walk in order under epoch starts `epoch`, and the index of each commit
/// and snapshot.
pub(crate) struct Items {
    initial: Edges,
    list: Vec<(Point, u8, Tid, Tid, Item)>,
    at: BTreeMap<CommitId, usize>,
}

impl Items {
    /// Where commit `c` goes in the list.
    pub fn place(&self, c: &MembershipCommit) -> usize {
        let k = (c.point(), 1, Tid::from_bytes([0; 15]), Tid::from_bytes([0; 15]));
        self.list.partition_point(|a| (a.0, a.1, a.2, a.3) < k)
    }

    /// Adds commits not yet listed, in order: O(log n) each at the end, else O(n).
    pub fn add(&mut self, new: &[Arc<MembershipCommit>]) {
        let zero = Tid::from_bytes([0; 15]);
        let mut moved = false;
        for c in new {
            let k = (c.point(), 1, zero, zero);
            let i = self.place(c);
            moved |= i < self.list.len();
            self.list.insert(i, (k.0, 1, zero, zero, Item::Commit(c.clone())));
            self.at.insert(c.id, i);
        }
        if moved {
            self.reindex();
        }
    }

    fn reindex(&mut self) {
        self.at.clear();
        for (i, it) in self.list.iter().enumerate() {
            match &it.4 {
                Item::Commit(c) => self.at.insert(c.id, i),
                Item::Snap(s) => self.at.insert(s.id, i),
                Item::Virtual(_) => None,
            };
        }
    }
}

pub(crate) fn items(input: &Input, epoch: &BTreeMap<Tid, CommitId>) -> Items {
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
            // just after the commit its key names (whose writes on the thing S ignores), so
            // that commit's writes on other things are judged as in the full history
            list.push((v.point, 2, v.thing, v.member, Item::Virtual(v)));
        }
    }
    for c in input.commits.values() {
        list.push((c.point(), 1, zero, zero, Item::Commit(c.clone())));
    }
    for s in input.snaps.values() {
        list.push((s.point(), 1, zero, zero, Item::Snap(s.clone())));
    }
    list.sort_by_key(|a| (a.0, a.1, a.2, a.3));
    let mut out = Items { initial, list, at: BTreeMap::new() };
    out.reindex();
    out
}

enum Step {
    Done,
    /// D grew: walk again from this item (the first one D now skips more of).
    Restart(usize),
}

impl Pass<'_> {
    /// Walks `items` from item `from` (rolled back to the state before it). A walk with a
    /// larger D is this one up to the first write D now skips, so a restart resumes there.
    fn walk(&mut self, items: &Items, from: usize) -> Step {
        self.rollback(from);
        self.fresh.clear();
        for (_, _, _, _, item) in items.list.iter().skip(from) {
            self.marks.push((self.log.len(), self.history.len()));
            let restart = match item {
                Item::Commit(c) => self.commit(c),
                Item::Snap(s) => {
                    self.snapshot(s);
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
/// `r.from` (and nothing else): equal to `run`, since the drops found before the first one
/// found at or after `r.from` are found again in the same order (see `drive`).
pub(crate) fn resume(input: &Input, r: Resume) -> Outcome {
    drive(input, Some(r))
}

/// Epoch starts in rounds (spec/permissions.md §6). A walk under fixed starts restarts only
/// when D grew, and D only grows, so a round settles within one walk per write. A round maps
/// starts E to F(E): each thing's newest snapshot that applied in the settled walk under E,
/// excluded ones aside. Every snapshot is judged at its position whatever its thing's own
/// start is (one ordered before the start too), by authority through what is above its thing
/// (owners, members with an admin edge of anything on the way, at any time), and E acts on
/// the walk only through each start's own thing. So unless owner-chain authority on N may
/// come through N itself (`Input::cyclic`), F(E) on N depends only on E above N: from any E
/// the rounds settle from the top down, at the unique fixed point, by round T+1 (T things
/// with snapshots, at most T levels). That is why `Timeline::extend` may go on from the old
/// starts. Through mutual membership a start can withdraw its own author's authority, and
/// the rounds need not settle: if round T+1 since the last restart has not settled, the
/// snapshots that are a start in exactly one of its starts and the next are excluded (at
/// least one: the two differ and neither holds an excluded snapshot) and the rounds restart
/// from none. Exclusions are never lifted, so at most one restart per snapshot plus one, each
/// of at most T+1 rounds: the evaluation terminates and no start is accepted and rejected
/// forever.
fn drive(input: &Input, resume: Option<Resume>) -> Outcome {
    let limit = input.snaps.values().map(|s| s.thing).collect::<BTreeSet<_>>().len() + 1;
    let (mut epoch, mut epoch_changed, mut reach, mut it, mut p, mut from);
    match resume {
        None => {
            epoch = BTreeMap::new();
            (epoch_changed, reach) = (false, None);
            it = items(input, &epoch);
            p = Pass::new(input, epoch.clone(), BTreeMap::new(), it.initial.clone());
            from = 0;
        }
        Some(r) => {
            (epoch, epoch_changed) = (r.epoch_starts, r.epoch_changed);
            it = r.items.unwrap_or_else(|| items(input, &epoch));
            from = it.list.partition_point(|x| x.0 < r.from);
            let (mut walked, mut dropped) = (r.walked, r.dropped);
            // The drops found before the first found by a write at or after `r.from` are found
            // again from scratch (every walk up to them saw only items before `r.from`); the
            // rest may not be: forget them and go back to the first write they dropped (the
            // final walk is the walk under the drops kept up to there).
            let cut = walked.rest.found.iter().position(|w| dropped.get(w).is_none_or(|p| *p >= r.from));
            if let Some(j) = cut {
                for w in walked.rest.found.split_off(j) {
                    dropped.remove(&w);
                    from = from.min(it.at.get(&w.commit()).copied().unwrap_or(0));
                }
            }
            reach = dropped.values().max().copied();
            let n = walked.history.len();
            p = Pass::resume(input, epoch.clone(), dropped, walked);
            p.untouched = Some((n, Vec::new()));
        }
    }
    let (mut passes, mut round) = (0, 0);
    let mut excluded: BTreeSet<CommitId> = BTreeSet::new();
    loop {
        round += 1;
        // §5.1 step 5 under `epoch`
        loop {
            passes += 1;
            match p.walk(&it, from) {
                Step::Done => break,
                Step::Restart(i) => {
                    reach = reach.max(p.marks.len().checked_sub(1).and_then(|k| it.list.get(k)).map(|x| x.0));
                    from = i;
                }
            }
        }
        let next = p.choose(&excluded);
        if next == epoch {
            let common = p.common();
            let (walked, dropped) = p.finish();
            return Outcome { walked, dropped, epoch_starts: epoch, passes, epoch_changed, reach, items: Some(it), common };
        }
        if round >= limit {
            let (a, b): (BTreeSet<CommitId>, BTreeSet<CommitId>) = (epoch.values().copied().collect(), next.values().copied().collect());
            excluded.extend(a.symmetric_difference(&b));
            epoch = BTreeMap::new();
            round = 0;
        } else {
            epoch = next;
        }
        epoch_changed = true;
        it = items(input, &epoch);
        // D is rebuilt, so writes a new start ignores leave no drops behind
        p = Pass::new(input, epoch.clone(), BTreeMap::new(), it.initial.clone());
        from = 0;
        reach = None;
    }
}
