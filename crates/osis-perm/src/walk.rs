//! Layer 1: the joint walk over every held edge write (spec/permissions.md §5.1) with epoch
//! starts and their ledgers (§6). From scratch, deterministic, a pure function of the held set.
//!
//! Readings of the spec (notes/permissions.md, "Implementation"):
//! - R demotes X on N when R is an explicit write (applied, not a self-removal, not an invite
//!   grant; or a ledger tenure end with a frontier) changing edge (M, T), X is M or reaches M,
//!   N is T or reachable from T (edges of any role and `until`, owner links), and X's class on
//!   N after R is below its held class: the highest since X's last audit there, kept across
//!   `until` expiry and self-removal.
//! - A's chain writes: the writes that set the admin edges on A's admin paths to R's target.
//! - Epoch starts: the newest snapshot found applicable at its position in a walk becomes N's
//!   epoch start and the walk restarts; one found inapplicable or dropped while chosen is
//!   rejected until an epoch start of a strict ancestor of N changes. D is rebuilt whenever
//!   the epoch starts change, so writes a start ignores leave no drops.
//! - Before its epoch start S, N's edges follow S's roster and ledger as virtual writes placed
//!   at their keys (before real writes with that key); a ledger tenure end with a frontier
//!   audits like the demotion it records.

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
}

impl Input {
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
        let mut nodes: BTreeSet<Tid> = things.iter().filter(|t| owners.is_key(t)).copied().collect();
        nodes.extend(commits.values().map(|c| c.author));
        nodes.extend(snaps.values().map(|s| s.author));
        Input { owners, commits, snaps, nodes }
    }
}

/// One change to the edge state in the final walk, for time queries.
#[derive(Clone, Debug)]
pub(crate) struct Change {
    pub point: Point,
    pub member: Tid,
    pub target: Tid,
    pub edge: Option<Edge>,
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
        // The value just after key `b` (`None`: the beginning); `roster: false` leaves out the
        // roster edge.
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
            let r = roster.filter(|_| with_roster)?;
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
    init_best: BTreeMap<Tid, BTreeMap<Tid, Role>>,
    held: BTreeMap<(Tid, Tid), Standing>,
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

    fn set_edge(&mut self, point: Point, member: Tid, target: Tid, edge: Option<Edge>, by: Option<WriteId>) {
        self.edges.set(member, target, edge);
        match by {
            Some(w) => self.setter.insert((member, target), w),
            None => self.setter.remove(&(member, target)),
        };
        self.history.push(Change { point, member, target, edge });
    }

    fn record(&mut self, id: WriteId, a: Applied) {
        self.by_author_target.entry((a.author, a.target)).or_default().push(id);
        self.applied.insert(id, a);
    }

    fn init_standing(&mut self, x: &Tid, n: &Tid) -> Standing {
        let view = View { owners: &self.input.owners, edges: &self.initial, ts: Some(Ts::default()) };
        let best = self.init_best.entry(*x).or_insert_with(|| view.roles_from(x));
        view.standing(x, best, n)
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

    /// After a change of edge (member, target) at `ts`: update held standings of everyone it
    /// concerns and, for an explicit demotion, audit class falls (§5.1 step 4). Returns whether
    /// the drop set grew.
    fn after_change(&mut self, member: &Tid, target: &Tid, ts: Ts, auditor: Option<&Auditor>) -> bool {
        let view = self.view(ts);
        let xs: Vec<Tid> = view.reach_backward(member).into_iter().filter(|x| self.input.nodes.contains(x)).collect();
        let ns = view.reach_forward(target);
        let mut grew = false;
        for x in xs {
            let view = self.view(ts);
            let best = view.roles_from(&x);
            let nows: Vec<(Tid, Standing)> = ns.iter().map(|n| (*n, view.standing(&x, &best, n))).collect();
            for (n, now) in nows {
                let held = match self.held.get(&(x, n)) {
                    Some(h) => *h,
                    None => self.init_standing(&x, &n),
                };
                let explicit = auditor.filter(|a| a.author != Some(x));
                let Some(aud) = explicit else {
                    self.held.insert((x, n), held.max(now));
                    continue;
                };
                let mut next = held.max(now);
                for below in [Role::Write, Role::Admin] {
                    if held.role >= Some(below) && now.role < Some(below) {
                        let d = Demotion { point: aud.point, below, frontier: aud.frontier_arc.clone(), ledger: aud.ledger };
                        self.demotions.entry((x, n)).or_default().push(d);
                        next.role = now.role;
                    }
                }
                if now.class < held.class {
                    grew |= self.audit(&x, &n, now.class, held.class, aud);
                    next.class = now.class;
                }
                self.held.insert((x, n), next);
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
        if lowers(new.as_ref(), old) && (m == a || best.get(&m) == Some(&Role::Admin)) {
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
            let id = WriteId::Op(c.id, k as u32);
            if self.dropped.contains_key(&id) || self.start_of(&op.target).is_some_and(|s| point < s.point()) {
                continue;
            }
            if let Some(attr) = self.judge(c, k, &best) {
                let chain = match attr {
                    Attr::By(Class::Chain | Class::Edge) => Some(self.chain_writes(&best, &op.target, c.ts)),
                    _ => None,
                };
                judged.push((k, id, attr, chain));
            }
        }
        let mut grew = false;
        for (k, id, attr, chain) in judged {
            let Some(op) = c.ops.get(k) else { continue };
            let new = op.edge.map(|e| Edge { since: None, ..e });
            self.set_edge(point, op.member, op.target, new, Some(id));
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
            grew |= self.after_change(&op.member, &op.target, c.ts, auditor.as_ref());
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
        let mut changed: BTreeSet<Tid> = BTreeSet::new();
        for m in old {
            if !s.roster.contains_key(&m) {
                self.set_edge(point, m, s.thing, None, None);
                changed.insert(m);
            }
        }
        for (m, e) in &s.roster {
            let e = Edge { since: None, ..*e };
            if *m == s.thing || self.input.owners.owner_actor(&s.thing) == Some(*m) || !e.well_formed() {
                continue;
            }
            if self.edges.get(m, &s.thing) != Some(&e) {
                self.set_edge(point, *m, s.thing, Some(e), Some(id));
                changed.insert(*m);
            } else {
                self.setter.insert((*m, s.thing), id);
            }
        }
        self.record(id, Applied { author: s.author, target: s.thing, point, attr: Attr::By(Class::Chain), dots: s.dots });
        for m in changed {
            self.after_change(&m, &s.thing, s.ts, None);
        }
        Ok(())
    }

    fn virtual_write(&mut self, v: &Virtual) -> bool {
        self.set_edge(v.point, v.member, v.thing, v.edge, None);
        let auditor = v.audit.as_ref().map(|(_, f)| Auditor {
            // A tenure with a frontier counts as an explicit demotion, whoever ended it (§6).
            author: None,
            frontier: Some(f.as_ref()),
            chain: BTreeSet::new(),
            commit: None,
            point: v.point,
            ledger: true,
            frontier_arc: Some(f.clone()),
        });
        self.after_change(&v.member, &v.thing, v.point.ts, auditor.as_ref())
    }
}

/// Evaluates the timeline from scratch: walks until a walk adds nothing to D (§5.1 step 5).
pub(crate) fn run(input: &Input) -> Outcome {
    let mut dropped: BTreeMap<WriteId, Point> = BTreeMap::new();
    let mut epoch: BTreeMap<Tid, CommitId> = BTreeMap::new();
    let mut rejected: BTreeSet<CommitId> = BTreeSet::new();
    let ns = input.snaps.len();
    let writes = input.commits.values().map(|c| c.ops.len()).sum::<usize>() + ns;
    // Safety net only: D grows between epoch changes, and epoch changes stop by induction on
    // ownership depth (a rejection is undone only by a change at a strict ancestor).
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
            // Starts below a changed thing get another chance; D is rebuilt, so writes a new
            // start ignores leave no drops behind.
            rejected.retain(|s| input.snaps.get(s).is_none_or(|sn| !changed.iter().any(|c| input.owners.chain(&sn.thing).0.contains(c))));
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
        init_best: BTreeMap::new(),
        held: BTreeMap::new(),
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
