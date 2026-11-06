//! Layer 1: the joint walk over every held edge write (spec/permissions.md §5.1). From
//! scratch, deterministic, a pure function of the held set.
//!
//! Readings of the spec (notes/permissions.md, "Implementation"):
//! - R demotes X on N when R is an explicit write (applied, not a self-removal, finalize or
//!   invite grant) on edge (M, T), X is M or reaches M, N is T
//!   or reachable from T (edges of any role and `until`, owner links), and X's class on N after
//!   R is below its class with the edge restored ("as if the holder still held the role"): the
//!   join (componentwise maximum, alive) of its values since the last explicit write on it,
//!   plus, for a node that demoted itself by an explicit write on it, its values before that.
//! - Only R's frontier and R itself cover X's writes (§5.1): writes on A's own chain too (the
//!   writer lists its chain certificates by commit ID), so a removed admin's backdated write on
//!   its remover's edge drops.

use crate::graph::{Class, Dense, Edges, Owners, Reads, Standing, View};
use crate::held::HeldSet;
use crate::types::{earliest, lowers, mark, pop, put, Edge, EdgeOp, Frontier, RoleCommit, Point, WriteId};
use osis_base::{CommitId, Role, Tid, Ts, WallMs};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// How an applied edge write was attributed (spec/permissions.md §5.1 step 3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Attr {
    /// By the author's authority class on the target; audited when it falls.
    By(Class),
    /// A self-removal (§2), audited when the author's class `.0` on `.1` falls: the holder
    /// it is admin of, or the target for its own edge.
    SelfRemoval(Class, Tid),
    /// A finalize (§2): no explicit write, attributed to no class, so never audited.
    Finalize,
}

impl Attr {
    /// The class audited and the thing whose fall audits it (`target`: the write's target).
    pub fn audited(&self, target: Tid) -> (Class, Tid) {
        match *self {
            Attr::By(c) => (c, target),
            Attr::SelfRemoval(c, on) => (c, on),
            Attr::Finalize => (Class::None, target),
        }
    }
}

/// An applied edge write.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Applied {
    pub author: Tid,
    pub target: Tid,
    pub point: Point,
    pub attr: Attr,
}

/// A class fall whose audit ran (§5.1 step 4): the demoting write's point and the node's
/// class on the thing after and before it; writes attributed to a class in (now, held] drop.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fall {
    pub point: Point,
    pub now: Class,
    pub held: Class,
}

/// An explicit demotion of a node on a thing below `below` by a valid write of the timeline
/// (layer 2 uses these, §5.2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Demotion {
    pub point: Point,
    pub below: Role,
    pub frontier: Option<Arc<Frontier>>,
}

/// Inputs gathered from the held set.
#[derive(Clone)]
pub(crate) struct Input {
    pub owners: Owners,
    pub commits: BTreeMap<CommitId, Arc<RoleCommit>>,
    /// Key actors and every author: who can hold a class.
    pub nodes: BTreeSet<Tid>,
    /// The earliest held edge write per (author, target).
    pub first_write: BTreeMap<(Tid, Tid), Point>,
    /// Every edge any held write or first admin record can set (any role, any time), holder to
    /// targets and target to holders: what any reach in any walk follows besides owner links.
    pub ever: Ever,
}

/// Edges at any time, both ways (`Input::ever`).
#[derive(Clone, Default)]
pub(crate) struct Ever {
    pub targets: BTreeMap<Tid, BTreeSet<Tid>>,
    pub holders: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Holders of an edge with an invite.
    pub invites: BTreeSet<Tid>,
}

impl Ever {
    fn add(&mut self, holder: Tid, target: Tid, e: &Edge) {
        self.targets.entry(holder).or_default().insert(target);
        self.holders.entry(target).or_default().insert(holder);
        if e.invite.is_some() {
            self.invites.insert(holder);
        }
    }
}

/// The things a commit's edge writes are on, for `Input::first_write`: their targets, and
/// their holders other than the author (a self-removal through a holder is audited there).
pub(crate) fn written_on(c: &RoleCommit) -> impl Iterator<Item = Tid> + '_ {
    c.ops.iter().flat_map(|o| std::iter::once(o.target).chain((o.holder != c.author).then_some(o.holder)))
}

impl Input {
    pub fn gather(held: &dyn HeldSet) -> Input {
        let things: BTreeSet<Tid> = held.things().into_iter().collect();
        let owners = Owners::from_held(held, &things);
        let mut commits = BTreeMap::new();
        for t in &things {
            for c in held.edge_commits(t) {
                commits.entry(c.id).or_insert(c);
            }
        }
        // Who can hold a class: key actors, authors, and holders that may be nodes (the
        // commits' by `append`).
        let mut nodes: BTreeSet<Tid> = things.iter().filter(|t| owners.is_key(t)).copied().collect();
        let mut ever = Ever::default();
        // an ownerless thing's first admin edge, there from the start (`items`)
        for (m, t) in owners.genesis() {
            if owners.owner_actor(&m).is_none() {
                nodes.insert(m);
            }
            ever.add(m, t, &Edge::new(Role::Admin));
        }
        let mut input = Input { owners, commits: BTreeMap::new(), nodes, first_write: BTreeMap::new(), ever };
        input.append(&commits.into_values().collect::<Vec<_>>());
        input
    }

    /// Whether `c` is held here with this content (a record can grow under its ID: a part
    /// that arrives late).
    pub fn holds_commit(&self, c: &RoleCommit) -> bool {
        self.commits.get(&c.id).is_some_and(|o| o.same_input(c))
    }

    /// Whether every record held here is held in `other` with the same content.
    pub fn kept_in(&self, other: &Input) -> bool {
        self.commits.values().all(|c| other.holds_commit(c))
    }

    /// What reaches any of `seeds` (included) at any time: owner links and `ever` edges.
    pub(crate) fn ever_back(&self, seeds: impl IntoIterator<Item = Tid>) -> BTreeSet<Tid> {
        self.ever_reach(seeds, false)
    }

    /// What any of `seeds` (included) reaches at any time.
    pub(crate) fn ever_forward(&self, seeds: impl IntoIterator<Item = Tid>) -> BTreeSet<Tid> {
        self.ever_reach(seeds, true)
    }

    fn ever_reach(&self, seeds: impl IntoIterator<Item = Tid>, forward: bool) -> BTreeSet<Tid> {
        let mut seen: BTreeSet<Tid> = seeds.into_iter().collect();
        let mut stack: Vec<Tid> = seen.iter().copied().collect();
        while let Some(e) = stack.pop() {
            let next: Vec<Tid> = if forward {
                self.owners.owned(&e).iter().chain(self.ever.targets.get(&e).into_iter().flatten()).copied().collect()
            } else {
                self.owners.owner_actor(&e).into_iter().chain(self.ever.holders.get(&e).into_iter().flatten().copied()).collect()
            };
            for y in next {
                if seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        seen
    }

    /// Whether a node (author, or holder that may be one) can join with the commits naming it:
    /// one here already, or one that reaches nothing here (no edge of it as holder, it owns
    /// nothing), so before those commits no walk meets it (it is in no audit's reach).
    fn may_be_node(&self, t: &Tid) -> bool {
        self.nodes.contains(t) || (self.owners.owner(t).is_none() && self.owners.owned(t).is_empty() && !self.ever.targets.contains_key(t))
    }

    /// Whether `new` (commits not held here) can join this input without changing anything but
    /// the commits and new nodes that reach nothing here (`append`): no thing without an owner
    /// link here becoming owned (`Timeline::extend`'s conditions).
    pub fn can_append(&self, new: &[Arc<RoleCommit>]) -> bool {
        new.iter().all(|c| !self.commits.contains_key(&c.id) && self.may_be_node(&c.author) && c.ops.iter().all(|o| self.owners.owner_actor(&o.holder).is_some() || self.may_be_node(&o.holder)))
    }

    /// Adds role commits `new` not held here (all of `gather`'s, or ones `can_append`
    /// accepted); the nodes they bring.
    pub fn append(&mut self, new: &[Arc<RoleCommit>]) -> BTreeSet<Tid> {
        let mut fresh = BTreeSet::new();
        let mut node = |n: Tid| {
            if self.nodes.insert(n) {
                fresh.insert(n);
            }
        };
        for c in new {
            node(c.author);
            for t in written_on(c) {
                let e = self.first_write.entry((c.author, t)).or_insert(c.point());
                *e = (*e).min(c.point());
            }
            for o in &c.ops {
                if self.owners.owner_actor(&o.holder).is_none() {
                    node(o.holder);
                }
                if self.owners.is_key(&o.target) {
                    node(o.target);
                }
                if let Some(e) = &o.edge {
                    self.ever.add(o.holder, o.target, e);
                }
            }
            self.commits.insert(c.id, c.clone());
        }
        fresh
    }
}

/// At most this many nodes to audit whose roles are not cached read their roles forward
/// (`Pass::roles`), more by backward searches from what their standings read (a cost choice:
/// the values are equal).
const FORWARD_MAX: usize = 4;

/// A late write is placed by re-judging later items (`Walked::place_shadowed`) only when at
/// most 1/`SHADOW_SHARE` of the later items (512 or more) need it; else the walk goes on from it.
const SHADOW_SHARE: usize = 8;

#[cfg(debug_assertions)]
thread_local! {
    static SHADOW_GUARD: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Debug builds, this thread: `Some(true)` declines every placement that would walk later
/// items in a shadow, `Some(false)` never declines one for its cost, `None` the `SHADOW_SHARE`
/// rule (a test walks both paths over the same inputs).
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn force_shadow_guard(on: Option<bool>) {
    SHADOW_GUARD.with(|g| g.set(on));
}

/// Whether the cost guard declines a shadow placement re-judging `n` of `rest` later items.
fn too_costly(n: usize, rest: usize) -> bool {
    #[cfg(debug_assertions)]
    if let Some(on) = SHADOW_GUARD.with(|g| g.get()) {
        return on;
    }
    rest >= 512 && n * SHADOW_SHARE > rest
}

/// One change to the edge state in the final walk, for time queries.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Change {
    pub point: Point,
    pub holder: Tid,
    pub target: Tid,
    pub edge: Option<Edge>,
    /// An explicit write (may demote, §5.1 step 4) with its frontier.
    pub explicit: Option<Option<Arc<Frontier>>>,
    /// An explicit write that lowered the edge as restored (§5.1 step 4): the restored role
    /// it audited from.
    pub audited: Option<Role>,
}

/// A walk's state and records (`Pass`): the final walk's are what queries read; the edge
/// and write records, the undo log and the marks continue it past its last write
/// (`Timeline::extend`).
#[derive(Clone, Default)]
pub(crate) struct Walked {
    pub initial: Edges,
    pub history: Vec<Change>,
    pub edges: Edges,
    pub applied: BTreeMap<WriteId, Applied>,
    pub demotions: BTreeMap<(Tid, Tid), Vec<Demotion>>,
    /// Class falls (§5.1 step 4) by (node, thing) where the node has an earlier held write
    /// on the thing, in walk order. None on a leaf (no write names it), so not aliased.
    pub falls: BTreeMap<(Tid, Tid), Vec<Fall>>,
    /// Per edge lowered or expired without an explicit write since: its value before, which
    /// the next explicit write on it restores to judge falls (§5.1: as if the holder still
    /// held the role).
    pub prior: BTreeMap<(Tid, Tid), Edge>,
    /// Edges whose current value was already expired when written.
    pub dead: BTreeSet<(Tid, Tid)>,
    /// The same for one node that demoted itself by an explicit write on the edge.
    pub prior_node: BTreeMap<(Tid, Tid), BTreeMap<Tid, Edge>>,
    pub by_author_target: BTreeMap<(Tid, Tid), Vec<WriteId>>,
    pub setter: BTreeMap<(Tid, Tid), WriteId>,
    pub log: Vec<Undo>,
    /// Per walked item: the log and history lengths before it.
    pub marks: Vec<(usize, usize)>,
    /// D in the order the walks found it (`resume` keeps the drops found
    /// before the first found at or after its point).
    pub found: Vec<WriteId>,
}

/// A commit `c` to place in a walk (`Walked::insert`) and what the walk is over: `input`
/// (holding `c`), its `items` (not yet listing `c`) and D.
#[derive(Clone, Copy)]
pub(crate) struct Place<'a> {
    pub input: &'a Input,
    pub items: &'a Items,
    pub dropped: &'a BTreeMap<WriteId, Point>,
    pub c: &'a RoleCommit,
}

/// The later items that may read a placed commit's edges (`Walked::dependents`): `dep`, and
/// `audited`, those that may only through an audit of a node of `a` (what reaches a holder
/// of its edges) on a thing of `f` (what a target of them reaches).
#[derive(Default)]
struct Readers {
    dep: BTreeSet<usize>,
    audited: BTreeSet<usize>,
    a: BTreeSet<Tid>,
    f: BTreeSet<Tid>,
}

/// What `Walked::insert` did with a commit new to the walk.
#[derive(Clone, Copy)]
pub(crate) enum Placement {
    /// Not exact here: walk again from the commit.
    Declined,
    /// It applies nothing: only its mark was added.
    Idle,
    /// Its changes were placed in the history from this index on.
    Inserted(usize),
    /// Its changes were placed from this index on, and the walk is exact up to the item at this
    /// point (a later item that read it does otherwise, or drops more): walk again from there.
    From(usize, Point),
}

/// What one item did to the walk state (`Pass::effects` in a shadow, `Walked::recorded` in
/// the walk): its edge changes, undo entries (which hold every other state it changed, the
/// value before), its writes as applied, and the demotions and falls it recorded.
#[derive(PartialEq, Debug)]
struct Effects {
    history: Vec<Change>,
    /// Its undo entries but those of demotions and falls, which `records` holds by key, sorted
    /// (their order within an item is not kept: `alias_leaves`, falls placed later).
    log: Vec<Undo>,
    records: Records,
    applied: Vec<Option<Applied>>,
    demotions: BTreeMap<(Tid, Tid), Vec<Demotion>>,
    falls: BTreeMap<(Tid, Tid), Vec<Fall>>,
}

/// Demotion (false) and fall (true) undo entries by key.
type Records = Vec<(bool, (Tid, Tid))>;

/// `log` split into its entries but demotions and falls, and those by key, sorted.
fn split_log(log: &[Undo]) -> (Vec<Undo>, Records) {
    let mut records = Vec::new();
    let mut rest = Vec::new();
    for u in log {
        match u {
            Undo::Demotion(k) => records.push((false, *k)),
            Undo::Fall(k) => records.push((true, *k)),
            _ => rest.push(u.clone()),
        }
    }
    records.sort();
    (rest, records)
}

/// How each write of a commit applied (`Effects::applied`).
fn item_applied(d: &RoleCommit, applied: &BTreeMap<WriteId, Applied>) -> Vec<Option<Applied>> {
    (0..d.ops.len()).filter_map(|k| u32::try_from(k).ok()).map(|k| applied.get(&WriteId(d.id, k)).copied()).collect()
}

impl Walked {
    /// Places `c`, a commit `input` now holds, at item `i = items.place(c)` of the walk (`items`
    /// not yet listing it) without walking again, when exact: `before` is the edge state before
    /// item `i`, `first` its author's first held write on each target before it (`falls` are
    /// recorded only after one), `fresh` the nodes it brings. Exact when no drop was found at
    /// or after it (an earlier walk may see it apply) and no later item writes an edge it sets,
    /// and then the walk with it is
    /// this one with its own effects added, provided each later item that may read it does
    /// the same with it as without it: with (M, T) its edges, the new values change roles
    /// only of what reaches some M at any time (A) on what some T reaches (F), and reaches
    /// only from A or to F; so a later item may read it only by an author in A on or for
    /// something in F, or, applied explicit on (m, t), by `m` in F (its reach back), `t` in A
    /// (its reach forward), or `m` reached from A and `t` reaching into F (a node in A audited
    /// on a thing in F), or `m` reached from a fresh node (which no audit met); a later fall of
    /// its author on its target (that audit reads it); a fall of its author on a target where
    /// its first write moves to `p`, up to the old first one (now recorded). Those items are
    /// walked again in a shadow at their place, with and without its edges (`place_shadowed`);
    /// with none and nothing audited by it, its changes are spliced in directly (`place_plain`).
    pub(crate) fn insert(&mut self, cx: &Place, before: Edges, first: &BTreeMap<Tid, Option<Point>>, fresh: &BTreeSet<Tid>) -> Placement {
        let Place { input, items, dropped, c } = *cx;
        let p = c.point();
        if dropped.values().any(|d| *d >= p) {
            return Placement::Declined;
        }
        let i = items.place(c);
        let mut placed = Vec::new();
        {
            let view = View::new(&input.owners, &before, Some(c.ts));
            let best = view.roles_from(&c.author);
            for (k, o) in c.ops.iter().enumerate() {
                let Ok(k32) = u32::try_from(k) else { continue };
                if let Some(attr) = judge(&view, before.get(&o.holder, &o.target), c, k, &best) {
                    placed.push((k32, o, attr));
                }
            }
        }
        let keys: BTreeSet<(Tid, Tid)> = placed.iter().map(|(_, o, _)| (o.holder, o.target)).collect();
        // (a self-removal through a holder is listed on the holder: walked again, rare)
        if keys.len() < placed.len() || placed.iter().any(|(_, o, attr)| attr.audited(o.target).1 != o.target) {
            return Placement::Declined;
        }
        let mut r = Readers::default();
        if !placed.is_empty() {
            // the widest role and whether an invite the new values or the old ones (at `p`) hold
            let olds = placed.iter().map(|(_, o, _)| before.get(&o.holder, &o.target).copied());
            let vals: Vec<Edge> = olds.chain(placed.iter().map(|(_, o, _)| o.edge)).flatten().collect();
            let level = vals.iter().map(|e| e.role).max().unwrap_or(Role::Read);
            let invite = vals.iter().any(|e| e.invite.is_some());
            let Some(x) = self.dependents(cx, i, &keys, fresh, level, invite) else {
                return Placement::Declined;
            };
            r = x;
        }
        // later falls of its author on what it applies on: their audits read it
        for (_, o, _) in &placed {
            for f in self.falls.get(&(c.author, o.target)).into_iter().flatten().filter(|f| f.point >= p) {
                r.dep.extend(items.at(f.point));
            }
        }
        // targets where its author's first held write moves to `p`: falls there up to the old
        // first write were not recorded; an audit of its author on one may find one
        let moved: BTreeMap<Tid, Option<Point>> = written_on(c).map(|t| (t, first.get(&t).copied().flatten())).filter(|(_, q)| q.is_none_or(|q| q > p)).collect();
        if !moved.is_empty() {
            let reach = input.ever_forward([c.author]);
            // (the top of a thing's owner chain holds the chain class on it throughout)
            for (t, q) in moved.iter().filter(|(t, _)| input.owners.chain(t).1 != Some(c.author)) {
                let back = input.ever_back([*t]);
                let end = q.map_or(items.list.len(), |q| items.list.partition_point(|a| a.point <= q));
                for (j, x) in items.list.iter().enumerate().take(end).skip(i) {
                    let audits = x.commit.ops.iter().enumerate().any(|(k, o)| {
                        let explicit = u32::try_from(k).is_ok_and(|k| self.applied.get(&WriteId(x.commit.id, k)).is_some_and(|a| matches!(a.attr, Attr::By(Class::Chain | Class::Edge))));
                        explicit && reach.contains(&o.holder) && back.contains(&o.target)
                    });
                    if audits {
                        r.dep.insert(j);
                    }
                }
            }
        }
        if placed.is_empty() && r.dep.is_empty() && r.audited.is_empty() {
            let m = self.marks.get(i).copied().unwrap_or((self.log.len(), self.history.len()));
            self.marks.insert(i, m);
            return Placement::Idle;
        }
        // an explicit write that restores more than it sets audits (no later write on its edge,
        // so its state there is its state at the end)
        let audits = placed.iter().any(|(_, o, attr)| matches!(attr, Attr::By(Class::Chain | Class::Edge)) && exceeds(self.restored((o.holder, o.target)), o.edge, p.ts));
        if !audits && r.dep.is_empty() && r.audited.is_empty() {
            return self.place_plain(input, c, i, placed, before);
        }
        // (a cost choice: the items re-judged are the costly ones to walk, mostly audits of
        // many nodes; past an eighth of a long rest, walking on from `c` is cheaper)
        if too_costly(r.dep.len() + r.audited.len(), items.list.len().saturating_sub(i)) {
            return Placement::Declined;
        }
        self.place_shadowed(cx, i, &keys, before, &moved, &r)
    }

    /// `insert` of `c`'s `placed` writes when nothing later reads them and they audit nothing:
    /// its changes, undo entries and mark spliced in as `Pass::commit` would make them there.
    fn place_plain(&mut self, input: &Input, c: &RoleCommit, i: usize, placed: Vec<(u32, &EdgeOp, Attr)>, mut at: Edges) -> Placement {
        let p = c.point();
        let (l, h) = self.marks.get(i).copied().unwrap_or((self.log.len(), self.history.len()));
        // logged apart, then spliced in at the mark
        let (log, hist) = (std::mem::take(&mut self.log), std::mem::take(&mut self.history));
        for (k, o, attr) in placed {
            let key = (o.holder, o.target);
            let id = WriteId(c.id, k);
            let new = o.edge;
            // as `Pass::record`, at its place in walk order
            self.list_write((c.author, o.target), id, p);
            self.log.push(Undo::ByAuthorTarget((c.author, o.target)));
            let was = self.applied.insert(id, Applied { author: c.author, target: o.target, point: p, attr });
            self.log.push(Undo::Applied(id, was));
            // as `Pass::change` (no audit: `insert`): the key's state at the end is its state here
            let old = self.set_alive(p, key, new);
            let explicit = matches!(attr, Attr::By(Class::Chain | Class::Edge));
            let own = explicit && self.restores(key, old) && View::new(&input.owners, &at, Some(p.ts)).reach_backward(&o.holder).contains(&c.author);
            self.set_edge(key, new);
            at.set(o.holder, o.target, new);
            if let Some((base, mine, _)) = self.record_change(p, key, old, new, Some(id), explicit.then(|| c.frontier.clone()))
                && own
            {
                self.keep_own(key, c.author, base, &mine);
            }
        }
        let (log, hist) = (std::mem::replace(&mut self.log, log), std::mem::replace(&mut self.history, hist));
        let (nl, nh) = (log.len(), hist.len());
        self.log.splice(l..l, log);
        self.history.splice(h..h, hist);
        for m in self.marks.iter_mut().skip(i) {
            m.0 += nl;
            m.1 += nh;
        }
        self.marks.insert(i, (l, h));
        Placement::Inserted(h)
    }

    /// `insert` of `c` by walking it and the later items `dep` again in a shadow (`Pass`
    /// over the edge state at each place, the walk's own records read through `outer`): `c`
    /// at its place, then each item of `dep` with `c`'s edges and without; `c`'s effects are
    /// spliced in, with the falls of its author the new first write brings (on targets in
    /// `moved`, up to the old first write) at the items checked; when `c` itself drops
    /// anything new, declined; when an item drops more or does otherwise with `c`, the walk
    /// is exact up to it (`From`).
    fn place_shadowed(&mut self, cx: &Place, i: usize, keys: &BTreeSet<(Tid, Tid)>, before: Edges, moved: &BTreeMap<Tid, Option<Point>>, r: &Readers) -> Placement {
        let Place { input, items, dropped, c } = *cx;
        let Readers { dep, audited, a, f } = r;
        let p = c.point();
        let end = (self.log.len(), self.history.len());
        let (_, h) = self.marks.get(i).copied().unwrap_or(end);
        let olds: Vec<((Tid, Tid), Option<Edge>)> = keys.iter().map(|k| (*k, before.get(&k.0, &k.1).copied())).collect();
        let (own, own_edges, extra, stop) = {
            let mut sh = Pass::shadow(input, dropped.clone(), before, self);
            // its edges' state at `p` is theirs at the end (no later item writes them)
            sh.w.copy_records(self, keys);
            sh.w.marks.push((0, 0));
            if sh.commit(c) || !sh.fresh.is_empty() {
                return Placement::Declined;
            }
            // `c`'s effects; the shadow goes on with its edges and writes (audits read them)
            let mut own = std::mem::take(&mut sh.w);
            sh.w = Walked { edges: std::mem::take(&mut own.edges), applied: own.applied.clone(), by_author_target: own.by_author_target.clone(), ..Walked::default() };
            let own_edges: Vec<((Tid, Tid), Option<Edge>)> = keys.iter().map(|k| (*k, sh.w.edges.get(&k.0, &k.1).copied())).collect();
            let mut extra: Vec<(usize, (Tid, Tid), Fall)> = Vec::new();
            let mut at = h;
            let mut stop = None;
            let a_nodes: Vec<Tid> = a.iter().filter(|x| input.nodes.contains(x)).copied().collect();
            for &j in dep.union(audited) {
                let (lj, hj) = self.marks.get(j).copied().unwrap_or(end);
                let lj1 = self.marks.get(j + 1).map_or(end.0, |m| m.0);
                for ch in self.history.get(at..hj).unwrap_or_default() {
                    sh.set_tracked(ch.holder, ch.target, ch.edge, ch.point.ts);
                }
                at = hj;
                // an item that may read it only by auditing a node of A on a thing of F: it
                // does not when, either way, no node of A reaches the holder it audits from or
                // its target reaches nothing in F (a standing there reads roles only on what
                // the thing's owner chain and holders reach, all in F if any is)
                if !dep.contains(&j) {
                    let Some(d) = items.list.get(j).map(|x| &x.commit) else { continue };
                    let Some((m, t)) = d.ops.first().map(|o| (o.holder, o.target)) else { continue };
                    let ts = d.ts;
                    let reached = |sh: &Pass<'_>| {
                        let view = View::new(&input.owners, &sh.w.edges, Some(ts));
                        let back = view.reach_backward(&m);
                        a_nodes.iter().any(|x| back.contains(x)) && view.reach_forward(&t).iter().any(|y| f.contains(y))
                    };
                    let mut far = !reached(&sh);
                    if far && !keys.is_empty() {
                        for (k, e) in &olds {
                            sh.set_tracked(k.0, k.1, *e, ts);
                        }
                        far = !reached(&sh);
                        for (k, e) in &own_edges {
                            sh.set_tracked(k.0, k.1, *e, ts);
                        }
                    }
                    if far {
                        continue;
                    }
                }
                sh.load(self.log.get(lj..lj1).unwrap_or_default());
                let Some(mut with) = sh.effects(items, j) else {
                    stop = Some(j);
                    break;
                };
                // the falls of its author where its first write moved: not in the walk yet
                let q = items.list.get(j).map_or(p, |x| x.point);
                let new_fall = |k: &(Tid, Tid)| k.0 == c.author && moved.get(&k.1).is_some_and(|f| f.is_none_or(|f| q <= f));
                with.records.retain(|(fall, k)| !(*fall && new_fall(k)));
                let found: Vec<((Tid, Tid), Vec<Fall>)> = with.falls.iter().filter(|(k, _)| new_fall(k)).map(|(k, v)| (*k, v.clone())).collect();
                with.falls.retain(|k, _| !new_fall(k));
                if with != self.recorded(items, j) {
                    stop = Some(j);
                    break;
                }
                for (k, v) in found {
                    extra.extend(v.into_iter().map(|f| (j, k, f)));
                }
            }
            (own, own_edges, extra, stop.and_then(|j| items.list.get(j)).map(|x| x.point))
        };
        // the falls `moved` brings: before every recorded one (none was up to the old first
        // write), undo entries at the end of their items' log segments
        let mut extra_log: BTreeMap<usize, Vec<Undo>> = BTreeMap::new();
        let mut front: BTreeMap<(Tid, Tid), Vec<Fall>> = BTreeMap::new();
        for (j, k, f) in extra {
            extra_log.entry(j).or_default().push(Undo::Fall(k));
            front.entry(k).or_default().push(f);
        }
        for (k, v) in front {
            let cur = self.falls.entry(k).or_default();
            cur.splice(0..0, v);
        }
        self.copy_records(&own, keys);
        let nh = own.history.len();
        let mut c_log = own.log;
        let old = std::mem::take(&mut self.log);
        let n = self.marks.len();
        let mut log = Vec::with_capacity(old.len() + c_log.len() + extra_log.len());
        let mut marks = Vec::with_capacity(n + 1);
        let mut it = old.into_iter();
        let first = self.marks.first().map_or(0, |m| m.0);
        log.extend(it.by_ref().take(first));
        for k in 0..=n {
            if k == i {
                marks.push((log.len(), h));
                log.append(&mut c_log);
            }
            let Some(&(lk, hk)) = self.marks.get(k) else { break };
            let lk1 = self.marks.get(k + 1).map_or(end.0, |m| m.0);
            marks.push((log.len(), if k >= i { hk + nh } else { hk }));
            log.extend(it.by_ref().take(lk1 - lk));
            if let Some(v) = extra_log.remove(&k) {
                log.extend(v);
            }
        }
        self.log = log;
        self.marks = marks;
        self.history.splice(h..h, own.history);
        for (id, a) in own.applied {
            if id.commit() != c.id {
                continue;
            }
            self.applied.insert(id, a);
        }
        for (k, ids) in own.by_author_target {
            for id in ids.into_iter().filter(|w| w.commit() == c.id) {
                self.list_write(k, id, p);
            }
        }
        // its demotions and falls after those recorded before its point
        for (k, v) in own.demotions {
            let cur = self.demotions.entry(k).or_default();
            let at = cur.partition_point(|d| d.point < p);
            cur.splice(at..at, v);
        }
        for (k, v) in own.falls {
            let cur = self.falls.entry(k).or_default();
            let at = cur.partition_point(|f| f.point < p);
            cur.splice(at..at, v);
        }
        for (k, e) in own_edges {
            self.edges.set(k.0, k.1, e);
        }
        if let Some(q) = stop {
            return Placement::From(h, q);
        }
        #[cfg(debug_assertions)]
        self.check_scratch(input, dropped);
        if nh == 0 { Placement::Idle } else { Placement::Inserted(h) }
    }

    /// Debug builds, small inputs: this walk is the one from scratch (`run`) over `input`.
    #[cfg(debug_assertions)]
    pub(crate) fn check_scratch(&self, input: &Input, dropped: &BTreeMap<WriteId, Point>) {
        if input.commits.len() > 400 {
            return;
        }
        let o = run(input);
        let w = &o.walked;
        debug_assert!(o.dropped == *dropped, "D");
        debug_assert!(w.history == self.history, "history");
        debug_assert!(w.applied == self.applied, "applied");
        debug_assert!(w.demotions == self.demotions, "demotions");
        debug_assert!(w.falls == self.falls, "falls");
        debug_assert!(w.edges == self.edges, "edges");
        let (a, b) = (w, self);
        debug_assert!(a.prior == b.prior && a.dead == b.dead && a.prior_node == b.prior_node && a.setter == b.setter, "edge records");
        debug_assert!(a.by_author_target == b.by_author_target && a.found == b.found, "write records");
        // the same undo entries per item (their order within one does not matter but per
        // edge, which the same code keeps)
        debug_assert!(a.marks == b.marks && a.log.len() == b.log.len(), "undo log");
        let seg = |log: &[Undo], k: usize| {
            let (l, e) = (a.marks.get(k).map_or(0, |m| m.0), a.marks.get(k + 1).map_or(log.len(), |m| m.0));
            let mut v: Vec<String> = log.get(l..e).unwrap_or_default().iter().map(|u| format!("{u:?}")).collect();
            v.sort();
            v
        };
        for k in 0..a.marks.len() {
            debug_assert!(seg(&a.log, k) == seg(&b.log, k), "undo entries of item {k}");
        }
    }

    /// What item `j` of `items` did in this walk (`Effects`): the demotions and falls of each
    /// key it logged are those at its point.
    fn recorded(&self, items: &Items, j: usize) -> Effects {
        let end = (self.log.len(), self.history.len());
        let (l, h) = self.marks.get(j).copied().unwrap_or(end);
        let (l1, h1) = self.marks.get(j + 1).copied().unwrap_or(end);
        let log = self.log.get(l..l1).unwrap_or_default();
        let Some(Entry { point: q, commit }) = items.list.get(j) else {
            return Effects { history: Vec::new(), log: Vec::new(), records: Vec::new(), applied: Vec::new(), demotions: BTreeMap::new(), falls: BTreeMap::new() };
        };
        // (demotions, falls) each key got here: those at its point (one item per point)
        let mut here: BTreeMap<(Tid, Tid), (usize, usize)> = BTreeMap::new();
        for u in log {
            match u {
                Undo::Demotion(k) => here.entry(*k).or_default().0 += 1,
                Undo::Fall(k) => here.entry(*k).or_default().1 += 1,
                _ => {}
            }
        }
        let (mut demotions, mut falls) = (BTreeMap::new(), BTreeMap::new());
        for (k, (d, f)) in &here {
            if *d > 0 {
                let v = self.demotions.get(k).map(|v| v.iter().filter(|x| x.point == *q).take(*d).cloned().collect()).unwrap_or_default();
                demotions.insert(*k, v);
            }
            if *f > 0 {
                let v = self.falls.get(k).map(|v| v.iter().filter(|x| x.point == *q).take(*f).copied().collect()).unwrap_or_default();
                falls.insert(*k, v);
            }
        }
        let applied = item_applied(commit, &self.applied);
        let (log, records) = split_log(log);
        Effects { history: self.history.get(h..h1).unwrap_or_default().to_vec(), log, records, applied, demotions, falls }
    }

    /// The point of an applied write.
    fn write_point(&self, w: &WriteId) -> Option<Point> {
        self.applied.get(w).map(|a| a.point)
    }

    /// Lists `id` (at `p`) among the writes by author on target `k`, in walk order.
    fn list_write(&mut self, k: (Tid, Tid), id: WriteId, p: Point) {
        let pos = self.by_author_target.get(&k).map_or(0, |v| v.partition_point(|w| self.write_point(w).is_none_or(|q| q <= p)));
        self.by_author_target.entry(k).or_default().insert(pos, id);
    }

    /// The edge `key` as an explicit write on it now restores (§5.1 step 4), as `Pass::change`.
    fn restored(&self, key: (Tid, Tid)) -> Option<Edge> {
        let old = self.edges.get(&key.0, &key.1).copied().filter(|_| !self.dead.contains(&key));
        let base = restore_base(self.prior.get(&key).copied(), old);
        self.prior_node.get(&key).into_iter().flatten().fold(base, |r, (_, e)| Some(join(r, *e)))
    }

    /// `from`'s edge records (dead, prior, prior per node, setter) of edges `keys`.
    fn copy_records(&mut self, from: &Walked, keys: &BTreeSet<(Tid, Tid)>) {
        for k in keys {
            mark(&mut self.dead, *k, from.dead.contains(k));
            put(&mut self.prior, *k, from.prior.get(k).copied());
            put(&mut self.prior_node, *k, from.prior_node.get(k).cloned());
            put(&mut self.setter, *k, from.setter.get(k).copied());
        }
    }

    /// Sets edge `key` (logged; `Pass::set_edge` also keeps its graph).
    fn set_edge(&mut self, (m, t): (Tid, Tid), e: Option<Edge>) {
        self.log.push(Undo::Edge(m, t, self.edges.get(&m, &t).copied()));
        self.edges.set(m, t, e);
    }

    /// Before a write at `point` sets edge `key` to `edge`: its value (alive: a value already
    /// expired when written never conferred anything), `key` marked dead when `edge` is.
    fn set_alive(&mut self, point: Point, key: (Tid, Tid), edge: Option<Edge>) -> Option<Edge> {
        let old = self.edges.get(&key.0, &key.1).copied().filter(|_| !self.dead.contains(&key));
        let was = mark(&mut self.dead, key, edge.is_some_and(|e| !e.alive_at(Some(point.ts))));
        self.log.push(Undo::Dead(key, was));
        old
    }

    fn set_setter(&mut self, k: (Tid, Tid), w: Option<WriteId>) {
        let was = put(&mut self.setter, k, w);
        self.log.push(Undo::Setter(k, was));
    }

    fn set_prior(&mut self, k: (Tid, Tid), e: Option<Edge>) -> Option<Edge> {
        let was = put(&mut self.prior, k, e);
        self.log.push(Undo::Prior(k, was));
        was
    }

    /// The records of a write at `point` by `by` that set edge `key` from `old` (`set_alive`) to
    /// `edge`, the edge itself set: its setter and history change, and the standings kept for
    /// the next explicit write. `explicit`: an explicit write's frontier (§5.1 step 4); it
    /// takes the kept standings and returns them (the base it restores, those of single nodes)
    /// and whether it lowered the edge as restored (then `keep_own`, after its audit).
    fn record_change(&mut self, point: Point, key: (Tid, Tid), old: Option<Edge>, edge: Option<Edge>, by: Option<WriteId>, explicit: Option<Option<Arc<Frontier>>>) -> Option<(Option<Edge>, BTreeMap<Tid, Edge>, bool)> {
        let (holder, target) = key;
        self.set_setter(key, by);
        let Some(frontier) = explicit else {
            // No audit (self-removal, finalize, invite grant):
            // everyone below keeps the standing it had, for the next explicit write.
            self.history.push(Change { point, holder, target, edge, explicit: None, audited: None });
            if let Some(o) = old {
                let p = self.prior.get(&key).copied();
                self.set_prior(key, Some(join(p, o)));
            }
            return None;
        };
        let all = self.set_prior(key, None);
        let mine = self.prior_node.remove(&key);
        self.log.push(Undo::PriorNode(key, mine.clone()));
        let mine = mine.unwrap_or_default();
        let base = restore_base(all, old);
        let restored = mine.values().fold(base, |r, e| Some(join(r, *e)));
        let lowered = exceeds(restored, edge, point.ts);
        let audited = restored.filter(|_| lowered).map(|r| r.role);
        self.history.push(Change { point, holder, target, edge, explicit: Some(frontier), audited });
        Some((base, mine, lowered))
    }

    /// After an explicit write on `key` by `author` that demoted itself (`record_change`
    /// returned `base` and `mine`): its own standing is kept for the next explicit write.
    /// (A standing it kept from an earlier explicit write is kept on, even when the edge itself
    /// restores nothing: a removal of an absent edge.)
    fn keep_own(&mut self, key: (Tid, Tid), author: Tid, base: Option<Edge>, mine: &BTreeMap<Tid, Edge>) {
        let kept = match (base, mine.get(&author)) {
            (Some(b), m) => join(m.copied(), b),
            (None, Some(m)) => *m,
            (None, None) => return,
        };
        self.log.push(Undo::PriorNode(key, self.prior_node.get(&key).cloned()));
        self.prior_node.entry(key).or_default().insert(author, kept);
    }

    /// Whether an explicit write on `key` over its value `old` restores anything (§5.1 step 4):
    /// the value, standings taken away without audit, or standings kept by authors.
    fn restores(&self, key: (Tid, Tid), old: Option<Edge>) -> bool {
        old.is_some() || self.prior.contains_key(&key) || self.prior_node.contains_key(&key)
    }

    /// The items from `i` on that may read what setting edges `keys` changes (`insert`), with
    /// A (what reaches a holder of `keys`) and F (what a target of `keys` reaches); `None` when
    /// one writes such an edge. `level` is the widest role among their values
    /// before and after, `invite` whether one has an invite. A path through them is at most
    /// `level` wide, so roles change only up to it: classes (admin on the chain or the thing,
    /// invites) change only through an admin value or an invite, met there or on a holder in
    /// F; the role thresholds demotions record (write, admin) only through a value of write or
    /// more. What reaches what changes whatever the roles: an explicit write on (m, t) with
    /// `m` in F asks whether its author reaches `m` (the standing it keeps).
    fn dependents(&self, cx: &Place, i: usize, keys: &BTreeSet<(Tid, Tid)>, fresh: &BTreeSet<Tid>, level: Role, invite: bool) -> Option<Readers> {
        let Place { input, items, .. } = *cx;
        let rest = items.list.get(i..).unwrap_or_default();
        if rest.is_empty() {
            return Some(Readers::default());
        }
        let (a, f) = (input.ever_back(keys.iter().map(|k| k.0)), input.ever_forward(keys.iter().map(|k| k.1)));
        let (mut dep, mut audited) = (BTreeSet::new(), BTreeSet::new());
        let classes = level == Role::Admin || invite || f.iter().any(|t| input.ever.invites.contains(t));
        let roles = classes || level >= Role::Write;
        let (mut fa, mut bf): (Option<BTreeSet<Tid>>, Option<BTreeSet<Tid>>) = (None, None);
        let fresh_reach = input.ever_forward(fresh.iter().copied());
        // how an explicit write on (m, t) may read them: 0 not, 1 only by auditing a node of A
        // on a thing of F, 2 otherwise
        let mut explicit = |m: &Tid, t: &Tid| -> u8 {
            if f.contains(m) {
                return 2;
            }
            if !roles {
                return 0;
            }
            if a.contains(t) || fresh_reach.contains(m) {
                return 2;
            }
            let fa = fa.get_or_insert_with(|| input.ever_forward(a.iter().copied()));
            u8::from(fa.contains(m) && bf.get_or_insert_with(|| input.ever_back(f.iter().copied())).contains(t))
        };
        for (j, Entry { commit: d, .. }) in rest.iter().enumerate() {
            if d.ops.iter().any(|o| keys.contains(&(o.holder, o.target))) {
                return None;
            }
            let author = classes && a.contains(&d.author) && d.ops.iter().any(|o| f.contains(&o.target) || f.contains(&o.holder));
            let ops = d.ops.iter().enumerate().map(|(k, o)| {
                let r = explicit(&o.holder, &o.target);
                let applied = || u32::try_from(k).ok().and_then(|k| self.applied.get(&WriteId(d.id, k)));
                if r > 0 && applied().is_some_and(|x| matches!(x.attr, Attr::By(Class::Chain | Class::Edge))) { r } else { 0 }
            });
            let r = ops.max().unwrap_or(0);
            // (several ops: their changes may reach each other's holders)
            let reads = if author || r == 2 || (r == 1 && d.ops.len() > 1) { 2 } else { r };
            match reads {
                2 => {
                    dep.insert(i + j);
                }
                1 => {
                    audited.insert(i + j);
                }
                _ => {}
            }
        }
        Some(Readers { dep, audited, a, f })
    }
    /// Things (thing, owner) whose owner link is new, none named by the walk's items before
    /// log position `cut` (the walk goes on from there, or `cut` is the log's end): before it
    /// every node's role on one is its role on its owner at every point (it has no edges), so
    /// a from-scratch walk records on it there exactly the owner's demotions, in the same
    /// items. Sets each one's demotions to its owner's recorded before `cut`, with their undo
    /// entries, and forgets those recorded on it from `cut` on (the walk goes on before them).
    /// `None`: one has a demotion before `cut`, or an owner neither known nor one of them
    /// (cycle).
    pub(crate) fn alias_leaves(&mut self, leaves: &[(Tid, Tid)], nodes: &BTreeSet<Tid>, cut: usize) -> Option<()> {
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
        // how many demotions each owner outside them has before `cut`
        let mut count: BTreeMap<(Tid, Tid), usize> = BTreeMap::new();
        for u in self.log.get(..cut).unwrap_or_default() {
            if let Undo::Demotion((x, n)) = u {
                if pending.contains(n) {
                    return None;
                }
                if deps.contains_key(n) {
                    *count.entry((*x, *n)).or_default() += 1;
                }
            }
        }
        self.demotions.retain(|(_, n), _| !pending.contains(n));
        for (l, o) in &order {
            for x in nodes {
                let v = self.demotions.get(&(*x, *o)).map(|v| {
                    let n = if pending.contains(o) { v.len() } else { count.get(&(*x, *o)).copied().unwrap_or(0) };
                    v.get(..n).unwrap_or_default().to_vec()
                });
                if let Some(v) = v.filter(|v| !v.is_empty()) {
                    self.demotions.insert((*x, *l), v);
                }
            }
        }
        let has = self.log.iter().any(|u| matches!(u, Undo::Demotion((_, n)) if deps.contains_key(n) || pending.contains(n)));
        if !has {
            return Some(());
        }
        let old = std::mem::take(&mut self.log);
        let mut at = Vec::with_capacity(old.len() + 1);
        let mut log = Vec::with_capacity(old.len());
        for (i, u) in old.into_iter().enumerate() {
            at.push(log.len());
            let k = if let Undo::Demotion(k) = &u { Some(*k) } else { None };
            if k.is_some_and(|(_, n)| pending.contains(&n)) {
                continue;
            }
            log.push(u);
            if let Some((x, n)) = k
                && i < cut
                && nodes.contains(&x)
            {
                let mut stack: Vec<Tid> = deps.get(&n).cloned().unwrap_or_default();
                while let Some(l) = stack.pop() {
                    log.push(Undo::Demotion((x, l)));
                    stack.extend(deps.get(&l).into_iter().flatten().copied());
                }
            }
        }
        at.push(log.len());
        for m in &mut self.marks {
            m.0 = at.get(m.0).copied().unwrap_or(log.len());
        }
        self.log = log;
        Some(())
    }
}

/// The inverse of one change to the walk state.
#[derive(Clone, PartialEq, Debug)]
pub(crate) enum Undo {
    Edge(Tid, Tid, Option<Edge>),
    Dead((Tid, Tid), bool),
    Setter((Tid, Tid), Option<WriteId>),
    Prior((Tid, Tid), Option<Edge>),
    PriorNode((Tid, Tid), Option<BTreeMap<Tid, Edge>>),
    Applied(WriteId, Option<Applied>),
    ByAuthorTarget((Tid, Tid)),
    Demotion((Tid, Tid)),
    Fall((Tid, Tid)),
}

pub(crate) struct Outcome {
    pub walked: Walked,
    pub dropped: BTreeMap<WriteId, Point>,
    /// Walks this evaluation (or continuation) made.
    pub passes: usize,
    /// The furthest point a walk other than the final walk reached (where it restarted): a
    /// walk is the final one's prefix up to here only.
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
    pub from: Point,
    /// The walk's items over `input`, when kept (else built).
    pub items: Option<Items>,
}

/// An explicit demotion auditing what it took away: its author (exempt), its frontier and
/// commit, which cover writes.
struct Auditor {
    author: Tid,
    frontier: Option<Arc<Frontier>>,
    commit: CommitId,
    point: Point,
}

/// Componentwise maximum of two edge values, alive: what a holder held across them.
fn join(a: Option<Edge>, b: Edge) -> Edge {
    match a {
        None => Edge { until: None, ..b },
        Some(a) => Edge { role: a.role.max(b.role), invite: a.invite.max(b.invite), until: None, tied: b.tied },
    }
}

/// What an explicit write on an edge restores before the per-node standings (§5.1 step 4):
/// its value before the write (`old`, unless written expired) joined with `prior`.
fn restore_base(prior: Option<Edge>, old: Option<Edge>) -> Option<Edge> {
    match (prior, old) {
        (Some(a), Some(o)) => Some(join(Some(a), o)),
        (a, o) => a.or(o),
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

/// How setting an edge from `old` to `new` at `ts` changes widest-path roles (§1) that are
/// `(rm, cur)` on its holder and its target.
fn widest_changes((rm, cur): (Option<Role>, Option<Role>), old: Option<Edge>, new: Option<Edge>, ts: Ts) -> Widest {
    let Some(rm) = rm else { return Widest::Same };
    let alive = |e: Option<Edge>| e.filter(|e| e.alive_at(Some(ts)));
    let (o, n) = (alive(old).map(|e| rm.min(e.role)), alive(new).map(|e| rm.min(e.role)));
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
    /// Only raised, from the edge's holder on.
    Raised,
    Unknown,
}

struct Pass<'a> {
    input: &'a Input,
    dropped: BTreeMap<WriteId, Point>,
    /// Writes this walk added to D.
    fresh: Vec<WriteId>,
    w: Walked,
    /// `roles_from` per node over the current edges (`Roles`). Dropped when an edge of a node
    /// it reaches changes.
    roles: BTreeMap<Tid, Roles>,
    /// The edge state by dense index (`edges` mirrored).
    graph: Dense,
    /// A continued walk: how many history changes are still the continued walk's, and that
    /// walk's changes after them (moved out by `rollback`).
    untouched: Option<(usize, Vec<Change>)>,
    /// A shadow walk (`Walked::insert`): the walk whose records before each point audits also
    /// read.
    outer: Option<&'a Walked>,
}

/// A node's cached roles (`Pass::roles`): the answer, also by dense index (`Pass::ids`, for
/// the check every change makes), the ts it was computed at and the earliest `until` it
/// followed.
#[derive(Clone)]
struct Roles {
    best: Arc<BTreeMap<Tid, Role>>,
    dense: Vec<Option<Role>>,
    at: Ts,
    exp: Option<WallMs>,
}

impl Roles {
    fn new(best: BTreeMap<Tid, Role>, ids: &BTreeMap<Tid, usize>, at: Ts, exp: Option<WallMs>) -> Roles {
        let mut dense = vec![None; ids.len()];
        for (t, r) in &best {
            if let Some(d) = ids.get(t).and_then(|i| dense.get_mut(*i)) {
                *d = Some(*r);
            }
        }
        Roles { best: Arc::new(best), dense, at, exp }
    }

    fn raise(&mut self, ids: &BTreeMap<Tid, usize>, raised: BTreeMap<Tid, Role>) {
        for (t, r) in &raised {
            if let Some(d) = ids.get(t).and_then(|i| self.dense.get_mut(*i)) {
                *d = Some(*r);
            }
        }
        Arc::make_mut(&mut self.best).extend(raised);
    }

    /// The role on `t`, `i` its dense index if it has one.
    fn on(&self, t: &Tid, i: Option<usize>) -> Option<Role> {
        match i {
            Some(i) => self.dense.get(i).copied().flatten(),
            None => self.best.get(t).copied(),
        }
    }

    fn fresh(&self, ts: Ts) -> bool {
        self.at <= ts && self.exp.is_none_or(|u| ts.wall_ms() < u)
    }
}

impl Input {
    /// `Dense` over every entity a role can be held on: nodes, things with an owner link or
    /// owning one, both ends of every edge any held write can set.
    pub(crate) fn dense(&self, edges: &Edges) -> Dense {
        let mut all: BTreeSet<Tid> = self.nodes.clone();
        for (t, _) in self.owners.links() {
            all.insert(*t);
            all.extend(self.owners.owned(t));
        }
        all.extend(self.ever.targets.keys().copied());
        all.extend(self.ever.holders.keys().copied());
        Dense::new(&self.owners, all, edges)
    }
}

impl<'a> Pass<'a> {
    /// `x`'s roles over the current edges at `ts` (cached: the walk's ts never decreases).
    fn roles(&mut self, x: Tid, ts: Ts) -> Arc<BTreeMap<Tid, Role>> {
        if let Some(r) = self.roles.get(&x).filter(|r| r.fresh(ts)) {
            return r.best.clone();
        }
        let r = match self.graph.roles(&x, ts) {
            Some((dense, mut reached, exp)) => {
                reached.sort_unstable();
                let best: BTreeMap<Tid, Role> = reached.iter().filter_map(|i| Some((*self.graph.tids.get(*i)?, dense.get(*i).copied().flatten()?))).collect();
                debug_assert!(self.view(ts).roles_expiring(&x) == (best.clone(), exp));
                Roles { best: Arc::new(best), dense, at: ts, exp }
            }
            None => {
                let (b, exp) = self.view(ts).roles_expiring(&x);
                Roles::new(b, &self.graph.ids, ts, exp)
            }
        };
        let b = r.best.clone();
        self.roles.insert(x, r);
        b
    }

    fn new(input: &'a Input, dropped: BTreeMap<WriteId, Point>, initial: Edges) -> Pass<'a> {
        Pass::resume(input, dropped, Walked { edges: initial.clone(), initial, ..Walked::default() })
    }

    fn resume(input: &'a Input, dropped: BTreeMap<WriteId, Point>, w: Walked) -> Pass<'a> {
        let graph = input.dense(&w.edges);
        Pass { input, dropped, fresh: Vec::new(), w, roles: BTreeMap::new(), graph, untouched: None, outer: None }
    }

    /// A shadow of `outer` at edge state `edges` (`Walked::insert`): no records of its own
    /// yet, its audits also reading `outer`'s before their point.
    fn shadow(input: &'a Input, dropped: BTreeMap<WriteId, Point>, edges: Edges, outer: &'a Walked) -> Pass<'a> {
        Pass { outer: Some(outer), ..Pass::resume(input, dropped, Walked { edges, ..Walked::default() }) }
    }

    /// The state of the edges an item writes before it, from its undo entries (the first one of
    /// each kind per edge holds the value before the item; an item reads no edge record it
    /// does not log).
    fn load(&mut self, log: &[Undo]) {
        self.w.prior.clear();
        self.w.dead.clear();
        self.w.prior_node.clear();
        self.w.setter.clear();
        let mut seen: BTreeSet<(u8, (Tid, Tid))> = BTreeSet::new();
        for u in log {
            let (kind, k) = match u {
                Undo::Dead(k, _) => (0, k),
                Undo::Prior(k, _) => (1, k),
                Undo::PriorNode(k, _) => (2, k),
                Undo::Setter(k, _) => (3, k),
                _ => continue,
            };
            if !seen.insert((kind, *k)) {
                continue;
            }
            match u {
                Undo::Dead(k, true) => {
                    self.w.dead.insert(*k);
                }
                Undo::Prior(k, Some(e)) => {
                    self.w.prior.insert(*k, *e);
                }
                Undo::PriorNode(k, Some(m)) => {
                    self.w.prior_node.insert(*k, m.clone());
                }
                Undo::Setter(k, Some(w)) => {
                    self.w.setter.insert(*k, *w);
                }
                _ => {}
            }
        }
    }

    /// Walks item `j` of `items` here and back again: what it did (`None`: D grew).
    fn effects(&mut self, items: &Items, j: usize) -> Option<Effects> {
        let m = self.w.marks.len();
        let (l, h) = (self.w.log.len(), self.w.history.len());
        // (the roles cached before it hold again once it is undone)
        let roles = self.roles.clone();
        let c = &items.list.get(j)?.commit;
        if self.step(c) || !self.fresh.is_empty() {
            return None;
        }
        let applied = item_applied(c, &self.w.applied);
        let (log, records) = split_log(self.w.log.get(l..).unwrap_or_default());
        let e = Effects {
            history: self.w.history.get(h..).unwrap_or_default().to_vec(),
            log,
            records,
            applied,
            demotions: self.w.demotions.clone(),
            falls: self.w.falls.clone(),
        };
        self.rollback(m);
        self.roles = roles;
        Some(e)
    }

    /// `Outcome::common` of this walk.
    fn common(&self) -> Option<(usize, Option<Point>)> {
        let (n, stash) = self.untouched.as_ref()?;
        let same = |a: &Change, b: &Change| (a.point, a.holder, a.target, a.edge) == (b.point, b.holder, b.target, b.edge);
        let k = self.w.history.get(*n..).unwrap_or_default().iter().zip(stash).take_while(|(a, b)| same(a, b)).count();
        Some((n + k, stash.get(k).map(|c| c.point)))
    }

    fn finish(self) -> (Walked, BTreeMap<WriteId, Point>) {
        (self.w, self.dropped)
    }

    /// Back to the state before item `i`.
    fn rollback(&mut self, i: usize) {
        let Some(&(l, h)) = self.w.marks.get(i) else { return };
        while self.w.log.len() > l {
            let Some(u) = self.w.log.pop() else { break };
            match u {
                Undo::Edge(m, t, e) => {
                    self.graph.set(&m, &t, e);
                    self.w.edges.set(m, t, e);
                }
                Undo::Dead(k, on) => {
                    mark(&mut self.w.dead, k, on);
                }
                Undo::Setter(k, w) => {
                    put(&mut self.w.setter, k, w);
                }
                Undo::Prior(k, e) => {
                    put(&mut self.w.prior, k, e);
                }
                Undo::PriorNode(k, m) => {
                    put(&mut self.w.prior_node, k, m);
                }
                Undo::Applied(id, a) => {
                    put(&mut self.w.applied, id, a);
                }
                Undo::ByAuthorTarget(k) => pop(&mut self.w.by_author_target, &k),
                Undo::Demotion(k) => pop(&mut self.w.demotions, &k),
                Undo::Fall(k) => pop(&mut self.w.falls, &k),
            }
        }
        match &mut self.untouched {
            Some((n, stash)) if h < *n => {
                let mut tail = self.w.history.split_off(h);
                tail.truncate(*n - h);
                tail.append(stash);
                *stash = tail;
                *n = h;
            }
            _ => self.w.history.truncate(h),
        }
        self.w.marks.truncate(i);
        self.roles.clear();
    }

    fn set_edge(&mut self, m: Tid, t: Tid, e: Option<Edge>) {
        self.graph.set(&m, &t, e);
        self.w.set_edge((m, t), e);
    }

    fn view(&self, ts: Ts) -> View<'_> {
        View::new(&self.input.owners, &self.w.edges, Some(ts))
    }

    /// Sets edge (holder, target) at `ts`, keeping the cached roles (`Pass::roles`) right:
    /// dropped where the change may narrow them, raised in place where it widens them.
    fn set_tracked(&mut self, holder: Tid, target: Tid, edge: Option<Edge>, ts: Ts) {
        let was = self.w.edges.get(&holder, &target).copied();
        let mut raise = Vec::new();
        let (mi, ti) = (self.graph.ids.get(&holder).copied(), self.graph.ids.get(&target).copied());
        self.roles.retain(|x, r| match widest_changes((r.on(&holder, mi), r.on(&target, ti)), was, edge, ts) {
            Widest::Same => true,
            Widest::Raised => {
                raise.push(*x);
                true
            }
            Widest::Unknown => false,
        });
        self.set_edge(holder, target, edge);
        for x in raise {
            if let Some(r) = self.roles.get_mut(&x) {
                #[cfg(debug_assertions)]
                let old = r.best.clone();
                let e = match self.graph.raise(&mut r.dense, &holder, ts) {
                    Some((raised, e)) => {
                        let best = Arc::make_mut(&mut r.best);
                        for i in raised {
                            if let (Some(t), Some(Some(v))) = (self.graph.tids.get(i), r.dense.get(i)) {
                                best.insert(*t, *v);
                            }
                        }
                        #[cfg(debug_assertions)]
                        {
                            let (raised, until) = View::new(&self.input.owners, &self.w.edges, Some(ts)).roles_raised_expiring(&old, &[holder]);
                            let mut want = (*old).clone();
                            want.extend(raised);
                            debug_assert!(*r.best == want && e == until, "raised roles of {x:?}");
                        }
                        e
                    }
                    None => {
                        let view = View::new(&self.input.owners, &self.w.edges, Some(ts));
                        let (raised, e) = view.roles_raised_expiring(&r.best, &[holder]);
                        r.raise(&self.graph.ids, raised);
                        e
                    }
                };
                r.exp = earliest(r.exp, e);
            }
        }
    }

    /// Sets edge (holder, target); an explicit write (`auditor`) then audits what it took
    /// away. Returns whether D grew.
    fn change(&mut self, point: Point, (holder, target): (Tid, Tid), edge: Option<Edge>, by: Option<WriteId>, auditor: Option<&Auditor>) -> bool {
        let key = (holder, target);
        let old = self.w.set_alive(point, key, edge);
        // Before the change: does the author reach the holder (a demotion of itself)? Only
        // asked when the edge restores something.
        let restores = self.w.restores(key, old);
        let own = auditor.map(|a| a.author).filter(|a| restores && self.view(point.ts).reach_backward(&holder).contains(a));
        self.set_tracked(holder, target, edge, point.ts);
        let (Some(aud), Some((base, mine, lowered))) = (auditor, self.w.record_change(point, key, old, edge, by, auditor.map(|a| a.frontier.clone()))) else {
            return false;
        };
        let grew = lowered && self.audit_fall(key, base, &mine, point.ts, aud);
        if let Some(a) = own {
            self.w.keep_own(key, a, base, &mine);
        }
        grew
    }

    fn record(&mut self, id: WriteId, a: Applied) {
        self.list_write(id, &a);
        let was = self.w.applied.insert(id, a);
        self.w.log.push(Undo::Applied(id, was));
    }

    /// Lists `id` among its author's writes on its target (audits read them).
    fn list_write(&mut self, id: WriteId, a: &Applied) {
        let k = (a.author, a.attr.audited(a.target).1);
        self.w.by_author_target.entry(k).or_default().push(id);
        self.w.log.push(Undo::ByAuthorTarget(k));
    }

    /// An explicit write changed edge `(holder, target)`: every node X reaching the holder
    /// whose standing on a thing N reachable from the target is lower than with the edge
    /// `restored` (its value before, alive) was demoted by it (§5.1 step 4): record the
    /// demotion for layer 2 and audit the classes X fell through. Returns whether D grew.
    fn audit_fall(&mut self, (holder, target): (Tid, Tid), base: Option<Edge>, mine: &BTreeMap<Tid, Edge>, ts: Ts, aud: &Auditor) -> bool {
        let view = self.view(ts);
        let xs: Vec<Tid> = view.reach_backward(&holder).into_iter().filter(|x| self.input.nodes.contains(x) && aud.author != *x).collect();
        let cur = self.w.edges.get(&holder, &target).copied().filter(|e| e.alive_at(Some(ts)));
        // Every x's roles on what its standing on the target reads (the holder, the target,
        // holders with an invite, admin anywhere on its owner chain): from their forward roles
        // (`Pass::roles`, cached) when at most `FORWARD_MAX` are not cached, else by backward
        // searches, the same values.
        let mut keys: BTreeSet<Tid> = BTreeSet::from([holder, target]);
        keys.extend(self.w.edges.holders(&target).filter(|(_, e)| e.invite.is_some()).map(|(m, _)| *m));
        let (up, top) = self.input.owners.chain(&target);
        let forward = xs.iter().filter(|x| !self.roles_fresh(x, ts)).count() <= FORWARD_MAX;
        let (to, on_chain): (BTreeMap<Tid, BTreeMap<Tid, Role>>, _) = if forward {
            (BTreeMap::new(), BTreeMap::new())
        } else {
            (keys.iter().map(|k| (*k, view.roles_to(k))).collect(), view.roles_to_any(&up))
        };
        // what the target reaches and what standings on each of those read, for every x (only
        // when some x's standings there may change)
        // (and which of those things read each entity's roles)
        type Reach = (BTreeSet<Tid>, BTreeMap<Tid, Reads>, BTreeMap<Tid, BTreeSet<Tid>>);
        let mut reach: Option<Reach> = None;
        let mut grew = false;
        for x in xs {
            let restored = match (base, mine.get(&x)) {
                (b, Some(m)) => join(b, *m),
                (Some(b), None) => Edge { until: None, ..b },
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
            let Some(on_holder) = role_on(&x, &holder) else { continue };
            // The restored edge (alive) is usually at least as wide as the current one; when
            // it raises nothing (not wider than x's role on the target), only the invite on the
            // target can differ.
            let wider = cur.is_none_or(|c| c.role <= restored.role);
            let pairs: Vec<(Tid, Standing, Standing)> = if wider && Some(on_holder.min(restored.role)) <= role_on(&x, &target) {
                let small: BTreeMap<Tid, Role> = keys.iter().filter_map(|k| role_on(&x, k).map(|r| (*k, r))).collect();
                let chain = top == Some(x) || chain_admin;
                let role = role_on(&x, &target);
                let view = self.view(ts);
                let before = self.view(ts).patched(holder, target, Some(restored));
                vec![(target, view.standing_from(chain, role, &small, &target), before.standing_from(chain, role, &small, &target))]
            } else {
                let (ns, reads, readers) = reach.get_or_insert_with(|| {
                    let view = self.view(ts);
                    let ns = view.reach_forward(&target);
                    let reads: BTreeMap<Tid, Reads> = ns.iter().map(|n| (*n, view.reads(n))).collect();
                    let mut readers: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
                    for (n, rd) in &reads {
                        for k in std::iter::once(n).chain(&rd.up).chain(rd.invites.iter().map(|(m, _)| m)) {
                            readers.entry(*k).or_default().insert(*n);
                        }
                    }
                    (ns, reads, readers)
                });
                let best = self.roles(x, ts);
                let raised = if wider { self.raised_with(x, (holder, target), restored, ts) } else { None };
                let before = self.view(ts).patched(holder, target, Some(restored));
                let (best_was, raised) = if wider {
                    let raised = raised.unwrap_or_else(|| before.roles_raised(&best, &[holder]));
                    debug_assert!(raised == before.roles_raised(&best, &[holder]));
                    let mut b = (*best).clone();
                    b.extend(raised.iter().map(|(t, r)| (*t, *r)));
                    (b, Some(raised))
                } else {
                    (before.roles_from(&x), None)
                };
                // A standing reads the role on the thing, on its owner chain and on its holders
                // with an invite; only the target's holders differ between the views.
                let target_before = before.reads(&target);
                // only the things whose reads the raise reaches (and the target) can differ
                let mut affected: BTreeSet<Tid> = BTreeSet::new();
                let ns = match &raised {
                    Some(r) => {
                        affected.extend(ns.get(&target));
                        affected.extend(r.keys().filter_map(|k| readers.get(k)).flatten());
                        &affected
                    }
                    None => &*ns,
                };
                let reads = ns.iter().filter_map(|n| reads.get(n).map(|rd| (n, rd)));
                reads.map(|(n, rd)| (*n, rd.standing(&x, &best, n), if *n == target { &target_before } else { rd }.standing(&x, &best_was, n))).collect()
            };
            for (n, now, held) in pairs {
                for below in [Role::Write, Role::Admin] {
                    if held.role >= Some(below) && now.role < Some(below) {
                        let d = Demotion { point: aud.point, below, frontier: aud.frontier.clone() };
                        self.w.demotions.entry((x, n)).or_default().push(d);
                        self.w.log.push(Undo::Demotion((x, n)));
                    }
                }
                if now.class < held.class {
                    if self.input.first_write.get(&(x, n)).is_some_and(|p| *p < aud.point) {
                        self.w.falls.entry((x, n)).or_default().push(Fall { point: aud.point, now: now.class, held: held.class });
                        self.w.log.push(Undo::Fall((x, n)));
                    }
                    grew |= self.audit(&x, &n, now.class, held.class, aud);
                }
            }
        }
        grew
    }

    /// What x's cached roles (fresh at `ts`) gain with edge (holder, target) set to `restored`
    /// (`roles_raised` over the patched view), by `Dense`.
    fn raised_with(&mut self, x: Tid, (holder, target): (Tid, Tid), restored: Edge, ts: Ts) -> Option<BTreeMap<Tid, Role>> {
        if !(self.graph.ids.contains_key(&holder) && self.graph.ids.contains_key(&target)) {
            return None;
        }
        let mut d = self.roles.get(&x).filter(|r| r.fresh(ts))?.dense.clone();
        let cur = self.w.edges.get(&holder, &target).copied();
        self.graph.set(&holder, &target, Some(restored));
        let r = self.graph.raise(&mut d, &holder, ts);
        self.graph.set(&holder, &target, cur);
        let (raised, _) = r?;
        Some(raised.into_iter().filter_map(|i| Some((*self.graph.tids.get(i)?, d.get(i).copied().flatten()?))).collect())
    }

    /// Whether `roles(x, ts)` is cached.
    fn roles_fresh(&self, x: &Tid, ts: Ts) -> bool {
        self.roles.get(x).is_some_and(|r| r.fresh(ts))
    }

    /// Drops x's earlier applied writes on n attributed to a class in (now, held] that the
    /// auditor does not cover.
    fn audit(&mut self, x: &Tid, n: &Tid, now: Class, held: Class, aud: &Auditor) -> bool {
        let mut grew = false;
        let mut ids = self.w.by_author_target.get(&(*x, *n)).cloned().unwrap_or_default();
        if let Some(o) = self.outer {
            // a shadow: the walk's writes before this point too
            ids.extend(o.by_author_target.get(&(*x, *n)).into_iter().flatten().filter(|w| o.write_point(w).is_some_and(|q| q <= aud.point)));
        }
        let outer = self.outer;
        for id in ids {
            let a = self.w.applied.get(&id).or_else(|| outer.and_then(|o| o.applied.get(&id)));
            let Some(a) = a else { continue };
            let (c, _) = a.attr.audited(a.target);
            if !(now < c && c <= held) {
                continue;
            }
            let covered = aud.commit == id.commit()
                || aud.frontier.as_ref().is_some_and(|f| f.covers(&id.commit()));
            if !covered && !self.dropped.contains_key(&id) {
                self.dropped.insert(id, aud.point);
                self.fresh.push(id);
                self.w.found.push(id);
                grew = true;
            }
        }
        grew
    }

    /// How op `k` of `c` applies against the state before `c` (§5.1 step 2, §2).
    fn judge(&self, c: &RoleCommit, k: usize, best: &BTreeMap<Tid, Role>) -> Option<Attr> {
        let op = c.ops.get(k)?;
        judge(&self.view(c.ts), self.w.edges.get(&op.holder, &op.target), c, k, best)
    }

    fn commit(&mut self, c: &RoleCommit) -> bool {
        let point = c.point();
        let best = self.roles(c.author, c.ts);
        let mut judged = Vec::new();
        for k in 0..c.ops.len() {
            let Ok(k32) = u32::try_from(k) else { continue };
            let id = WriteId(c.id, k32);
            if self.dropped.contains_key(&id) {
                continue;
            }
            if let Some(attr) = self.judge(c, k, &best) {
                judged.push((k, id, attr));
            }
        }
        let mut grew = false;
        for (k, id, attr) in judged {
            let Some(op) = c.ops.get(k) else { continue };
            let new = op.edge;
            self.record(id, Applied { author: c.author, target: op.target, point, attr });
            let explicit = matches!(attr, Attr::By(Class::Chain | Class::Edge));
            let auditor = explicit.then(|| Auditor { author: c.author, frontier: c.frontier.clone(), commit: c.id, point });
            grew |= self.change(point, (op.holder, op.target), new, Some(id), auditor.as_ref());
        }
        grew
    }

}

/// How op `k` of `c` applies against `view` (edges before `c`, at its `ts`), `old` the
/// edge it writes there and `best` its author's roles (§5.1 step 2, §2).
pub(crate) fn judge(view: &View<'_>, old: Option<&Edge>, c: &RoleCommit, k: usize, best: &BTreeMap<Tid, Role>) -> Option<Attr> {
    let op = c.ops.get(k)?;
    let (a, m, t) = (c.author, op.holder, op.target);
    if m == t || view.owners.owner_actor(&t) == Some(m) {
        return None;
    }
    let new = op.edge;
    let st = view.standing(&a, best, &t);
    // Self-removal (§2): lowering one's own edge, or an edge of a holder one is admin of
    // when that is the only authority one has: no owner-chain or edge-admin authority on
    // the target with the holder's edge there disregarded (authority through the holder
    // does not count); otherwise the write is an explicit demotion by its class there.
    let authority_on_target = || {
        let v = view.clone().patched(m, t, None);
        let b = v.roles_from(&a);
        matches!(v.standing(&a, &b, &t).class, Class::Chain | Class::Edge)
    };
    if lowers(new.as_ref(), old) && (m == a || (best.get(&m) == Some(&Role::Admin) && !authority_on_target())) {
        // Attributed to the author's class on the holder it is admin of, or on the target
        // for its own edge (a single-use redemption's: like its grant), §5.1 step 3.
        let class = if m == a { st.class } else { view.standing(&a, best, &m).class };
        return Some(Attr::SelfRemoval(class, if m == a { t } else { m }));
    }
    // A finalize (§2): a removal of another holder's edge carrying no frontier. Invariants:
    // it applies only to an edge past its `until` at the write's `ts` (as the timeline orders
    // it, a renewal placed before it included), so a removal of an unended edge does nothing;
    // only by an author with write whose role there is at least the edge's (an ended admin
    // edge needs an admin); judged from held writes and stamps alone, no reader's clock.
    if c.frontier.is_none() && new.is_none_or(|e| e.says_retain()) && lowers(new.as_ref(), old) {
        let ended = old.is_some_and(|o| o.until.is_some() && !o.alive_at(Some(c.ts)));
        let may = st.role >= Some(Role::Write) && old.is_some_and(|o| st.role >= Some(o.role));
        return (ended && may).then_some(Attr::Finalize);
    }
    match st.class {
        Class::Chain | Class::Edge => Some(Attr::By(st.class)),
        Class::Invite(l) => {
            let free = old.is_none_or(|o| !o.alive_at(Some(c.ts)));
            // an invite grants: a value gone when written would stand for how an edge ended (§2)
            let ok = new.is_some_and(|e| e.role <= l && e.alive_at(Some(c.ts))) && free;
            ok.then_some(Attr::By(Class::Invite(l)))
        }
        Class::None => None,
    }
}

/// The commits of a walk in order, and the initial edges (first admins' record edges, §1).
#[derive(Clone)]
pub(crate) struct Items {
    initial: Edges,
    list: Vec<Entry>,
}

/// A commit of a walk at its point.
#[derive(Clone)]
struct Entry {
    point: Point,
    commit: Arc<RoleCommit>,
}

impl Items {
    /// The item at point `q`, if any (points are unique).
    fn at(&self, q: Point) -> Option<usize> {
        let i = self.list_before(q);
        (self.list.get(i)?.point == q).then_some(i)
    }

    /// How many items are before point `q`.
    pub fn list_before(&self, q: Point) -> usize {
        self.list.partition_point(|a| a.point < q)
    }

    /// Whether the initial edges name one of `ts`.
    pub fn initial_names(&self, ts: &BTreeSet<Tid>) -> bool {
        self.initial.iter().any(|(m, t, _)| ts.contains(m) || ts.contains(t))
    }

    /// The point of the first item before `until` that names one of `ts` (author, holder,
    /// target).
    pub fn first_naming(&self, ts: &BTreeSet<Tid>, until: Option<Point>) -> Option<Point> {
        let names = |c: &RoleCommit| ts.contains(&c.author) || c.ops.iter().any(|o| ts.contains(&o.holder) || ts.contains(&o.target));
        self.list.iter().take_while(|a| until.is_none_or(|u| a.point < u)).find(|a| names(&a.commit)).map(|a| a.point)
    }

    /// Where commit `c` goes in the list.
    pub fn place(&self, c: &RoleCommit) -> usize {
        self.list_before(c.point())
    }

    /// The index of commit `id` of `input` (points are unique, so it is where its point goes).
    pub fn index(&self, input: &Input, id: &CommitId) -> Option<usize> {
        let i = self.list_before(input.commits.get(id)?.point());
        (self.list.get(i)?.commit.id == *id).then_some(i)
    }

    /// Adds commits not yet listed, in order: O(log n) each at the end, else O(n) (a move).
    pub fn add(&mut self, new: &[Arc<RoleCommit>]) {
        for c in new {
            let i = self.place(c);
            self.list.insert(i, Entry { point: c.point(), commit: c.clone() });
        }
    }
}

pub(crate) fn items(input: &Input) -> Items {
    // an ownerless thing's first admin edge (spec/permissions.md §1)
    let mut initial = Edges::default();
    for (m, t) in input.owners.genesis() {
        initial.set(m, t, Some(Edge::new(Role::Admin)));
    }
    let mut list: Vec<Entry> = input.commits.values().map(|c| Entry { point: c.point(), commit: c.clone() }).collect();
    list.sort_by_key(|a| a.point);
    Items { initial, list }
}

impl Pass<'_> {
    /// Walks one commit after a mark: whether D grew.
    fn step(&mut self, c: &RoleCommit) -> bool {
        self.w.marks.push((self.w.log.len(), self.w.history.len()));
        self.commit(c)
    }
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
        for e in items.list.iter().skip(from) {
            if self.step(&e.commit) {
                let first = self.fresh.iter().filter_map(|w| items.index(self.input, &w.commit())).min();
                return Step::Restart(first.unwrap_or(0));
            }
        }
        Step::Done
    }
}

/// Evaluates the timeline from scratch: walks until a walk adds nothing to D (§5.1 step 5).
pub(crate) fn run(input: &Input) -> Outcome {
    drive(input, None)
}

/// Continues a converged evaluation over `input`, which adds role commits at or after
/// `r.from` (and nothing else): equal to `run`, since the drops found before the first one
/// found at or after `r.from` are found again in the same order (see `drive`).
pub(crate) fn resume(input: &Input, r: Resume) -> Outcome {
    drive(input, Some(r))
}

/// Walks until a walk adds nothing to D. A walk restarts only when D grew, and D only grows,
/// so it settles within one walk per write.
fn drive(input: &Input, resume: Option<Resume>) -> Outcome {
    let (mut reach, it, mut p, mut from);
    match resume {
        None => {
            reach = None;
            it = items(input);
            p = Pass::new(input, BTreeMap::new(), it.initial.clone());
            from = 0;
        }
        Some(r) => {
            it = r.items.unwrap_or_else(|| items(input));
            from = it.list.partition_point(|x| x.point < r.from);
            let (mut walked, mut dropped) = (r.walked, r.dropped);
            // The drops found before the first found by a write at or after `r.from` are found
            // again from scratch (every walk up to them saw only items before `r.from`); the
            // rest may not be: forget them and go back to the first write they dropped (the
            // final walk is the walk under the drops kept up to there).
            let cut = walked.found.iter().position(|w| dropped.get(w).is_none_or(|p| *p >= r.from));
            if let Some(j) = cut {
                for w in walked.found.split_off(j) {
                    dropped.remove(&w);
                    from = from.min(it.index(input, &w.commit()).unwrap_or(0));
                }
            }
            reach = dropped.values().max().copied();
            let n = walked.history.len();
            p = Pass::resume(input, dropped, walked);
            p.untouched = Some((n, Vec::new()));
        }
    }
    let mut passes = 0;
    loop {
        passes += 1;
        match p.walk(&it, from) {
            Step::Done => break,
            Step::Restart(i) => {
                reach = reach.max(p.w.marks.len().checked_sub(1).and_then(|k| it.list.get(k)).map(|x| x.point));
                from = i;
            }
        }
    }
    let common = p.common();
    let (walked, dropped) = p.finish();
    Outcome { walked, dropped, passes, reach, items: Some(it), common }
}
