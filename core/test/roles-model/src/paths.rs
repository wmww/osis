//! Stated paths and signers as members (notes/write-path-design.md §1-§2, §5,
//! notes/account-membership-design.md §2, §4; not built, not in spec): an oracle of those notes,
//! greenfield, sharing nothing with `joint` (whose authority is a maximum over every path).
//! Findings: notes/path-model-findings.md. README.md, Paths: what is assumed where the notes are
//! open, sizes, how to run.
//!
//! The rule under test.
//! - **Things and edges.** Signers and independent things share one namespace; an edge is
//!   (holder, target) with a role and an optional `until`; record edges stand at the start.
//!   Dependent things are not modelled (a descent of one step is the direct edge).
//! - **Commits.** One signer, a `ts`, the thing written (`on`) and a stated path [A1..Ak]: the
//!   commit uses the edges joining [signer, A1, .., Ak, on] and no other. Kinds: content, an
//!   edge write (setting a holder's edge on `on`; a lowering carries a frontier, a leaf of commit
//!   IDs per thing; it may name the remaining admin it relies on, or carry the mark that lets
//!   its thing go adminless), an addendum (plain content naming a removal and commits it
//!   vouches for), a vouch (the same for role writes: `Vouch`).
//! - **Edges in time.** An edge gives its role at `ts` while its `until` is later; a write
//!   giving no role at its own `ts` (none, or an `until` passed) is a removal.
//! - **Hops.** Consecutive members of [signer, A1..Ak, end] are joined by descent (the record
//!   edges down the mint chain) where the first is a mint ancestor of the second, else by their
//!   direct edge. The end is the thing written, except for an edge write whose path ends at the
//!   holder of the edge it sets: a **self-removal**, needing admin on the holder (a signer
//!   leaving by itself states no hop).
//! - **Walk** (§5.1 along one path). Edge-class commits (edge writes, vouches) in key order
//!   (`ts`, signer, ID), skipping the drop set D. One applies iff every edge of its path gives
//!   admin at its `ts`; a self-removal only lowers. An applied explicit write taking an edge h
//!   from admin, **as restored** (the highest role since the last explicit write on h, values an
//!   `until` or a self-removal took included), to below puts in question every earlier applied
//!   edge-class commit whose path holds h; those its list does not name (`listed`) join D and the
//!   walk restarts. A self-removal audits nothing. D only grows until a pass adds nothing.
//! - **What no list keeps** (`Rules::list_own`): an entry of a lowering R's list (its frontier
//!   or a counting vouch against it) naming a write that lowers an edge of R's own stated path
//!   below admin is read as absent.
//! - **Last admin** (`Rules::last_admin`): an unmarked write taking a **standing** admin edge
//!   (admin, no `until`) of T to anything else applies only where the remaining admin it relies
//!   on is, as the walk stands, a standing admin edge of T other than the one it lowers: the
//!   last edge of its own path where that is one, else the edge of the holder it names.
//! - **Content.** A commit on T with path P is valid iff every edge of P gave write just before
//!   its position (the start of its `ts`) and no applied lowering of an edge of P below write is
//!   ordered after it; else iff such a lowering's list names it, a valid addendum by a writer
//!   of T against such a lowering ordered between them lists it (least fixpoint), or P is
//!   re-granted (every edge gives write in the final state, every `until` counted removed) and
//!   the commit is ordered after the first point P gave write (`Regrant`).
//! - **Trust sets.** A trusted lowering R of edge h seeds D with the held edge-class commits
//!   ordered before R whose path holds h and R's list does not name; a trusted write the
//!   settled walk does not apply is void and loses its seeds, all void ones at once, and the
//!   walk is redone.
//! - **Leaves.** A node sees a frontier's leaf for a thing only where its view says so
//!   (`View::leaves`); an entry in a leaf it does not see is not listed for it.
//! - **Evidence** (`evidence`): the least set holding a unit's commits, every edge write on an
//!   edge of a held commit's path or on the edge a held lowering names as the admin it relies
//!   on, and the vouches against held removals.
//!
//! `Sim` plays the stolen-node story over that rule (parties, ticks, honest writing and the
//! properties: `Sim::build`, `check`); `rotations` is a small keys layer for A's epochs under a
//! standing dispute.

use crate::{Rng, Role};
use std::collections::{BTreeMap, BTreeSet};

pub type Thing = u8;
pub type Id = usize;
pub type Edge = (Thing, Thing);
pub type Set = BTreeSet<Id>;
pub type Key = (u32, Thing, Id);
pub type Things = BTreeSet<Thing>;
/// An edge's value: its role and its `until`.
pub type Val = (Role, Option<u32>);

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    Content,
    Edge {
        holder: Thing,
        role: Role,
        until: Option<u32>,
        frontier: BTreeMap<Thing, Set>,
        /// The holder of the remaining admin edge this write relies on (notes/write-path-design.md
        /// §5, The last admin); read only where its own path's last edge is not one.
        relies: Option<Thing>,
        /// The mark that lets the thing go adminless.
        adminless: bool,
    },
    Addendum { removal: Id, list: Set },
    Vouch { removal: Id, list: Set },
}

impl Kind {
    /// An edge write setting `holder`'s edge to `role`, standing, listing nothing.
    pub fn set(holder: Thing, role: Role) -> Kind {
        Kind::Edge { holder, role, until: None, frontier: BTreeMap::new(), relies: None, adminless: false }
    }
    fn with(mut self, f: impl FnOnce(&mut Option<u32>, &mut BTreeMap<Thing, Set>, &mut Option<Thing>, &mut bool)) -> Kind {
        if let Kind::Edge { until, frontier, relies, adminless, .. } = &mut self {
            f(until, frontier, relies, adminless);
        }
        self
    }
    pub fn until(self, t: u32) -> Kind {
        self.with(|u, _, _, _| *u = Some(t))
    }
    pub fn listing(self, f: BTreeMap<Thing, Set>) -> Kind {
        self.with(|_, l, _, _| *l = f)
    }
    pub fn relying(self, n: Thing) -> Kind {
        self.with(|_, _, r, _| *r = Some(n))
    }
}

#[derive(Clone, Debug)]
pub struct Commit {
    pub signer: Thing,
    pub ts: u32,
    pub path: Vec<Thing>,
    pub on: Thing,
    pub kind: Kind,
    /// The edges the stated path uses (`World::hops`).
    hops: Vec<Edge>,
    /// The path names no thing twice.
    well: bool,
    /// An edge write whose path ends at its holder: a self-removal.
    leave: bool,
}

/// How role writes a removal does not list are vouched for (issues/actors-one-mechanism.md,
/// "Role writes of a removed node must be kept on the same terms as its content").
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Vouch {
    /// Nothing vouches for a role write.
    Off,
    /// The simplest reading: a vouch counts when its path gives admin on its thing at its key
    /// in the walk it changes.
    SameWalk,
    /// A vouch counts when its path gives admin on its thing at its key in the walk with no
    /// vouch counting.
    BaseWalk,
}

/// Where a re-granted path's writes count from.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Regrant {
    /// spec/permissions.md §5.2: the first point the settled walk gave the role.
    FirstApplied,
    /// notes/account-membership-design.md §1 (the collateral grantee): the first chained grant
    /// of each edge (spec/permissions.md §4 Chained writes), dropped or not.
    FirstChained,
}

/// Which entries of a lowering's list (frontier or vouch) are read as absent
/// (notes/account-membership-design.md §4, What no list keeps).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ListOwn {
    /// None: an entry keeps whatever it names.
    Kept,
    /// The rule: an entry naming a write that lowers an edge of the listing write's own stated
    /// path below admin.
    Hops,
    /// Control: also an edge of the path of any held grant giving admin on such an edge, closed
    /// (`chain`): "rests on" read from the held writes, whether they apply or not.
    Chain,
    /// Control: an entry naming any lowering.
    AnyLowering,
}

/// What a lowering of an admin edge must leave (notes/write-path-design.md §5, The last admin).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LastAdmin {
    Off,
    /// Control (the first round's reading): a lowering from admin that would leave its target no
    /// admin edge alive, of all the walk holds, does not apply unless marked.
    AnyEdge,
    /// The rule: the remaining admin it relies on (its path's last edge, else the one it names)
    /// is a standing admin edge (admin, no `until`) other than the lowered one.
    Named,
    /// Control: as `Named`, a timed admin edge alive at the write counting as standing.
    NamedTimed,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rules {
    pub vouch: Vouch,
    pub regrant: Regrant,
    /// spec/permissions.md §5.1 "R never demotes its own author", read along paths: a lowering
    /// never puts in question an edge write setting an edge of its own path, nor one such a
    /// write's path rests on.
    pub own_chain_exempt: bool,
    pub last_admin: LastAdmin,
    /// An addendum vouches for no commit of its own signer (spec/permissions.md §5.2 Addenda
    /// asks only that its writer holds write on the thing, by any path).
    pub no_own_addendum: bool,
    /// A vouch counts for no commit of its own signer.
    pub no_own_vouch: bool,
    pub list_own: ListOwn,
    /// A node sees a frontier's leaf for every thing an edge write it holds as evidence is on,
    /// besides the things it syncs (finding 5).
    pub evidence_leaves: bool,
    /// Honest writing in `Sim` (a policy, not a judging rule): the state-based rule, writing
    /// whenever the node's own walk shows an owed commit it could write named by nothing of its
    /// own that counts; false, a node answers only the first time its walk applies a removal.
    pub rewrite: bool,
    /// A self-removal of edge h is put in question by a lowering of h like a write through h
    /// (finding 14): else the removed node's backdated leave, which no audit reaches, voids its
    /// own role writes ordered after it.
    pub leave_in_question: bool,
}

impl Rules {
    /// The first round's reading of the notes, simplest: the findings are its failures.
    pub fn design() -> Rules {
        Rules {
            vouch: Vouch::Off,
            regrant: Regrant::FirstApplied,
            own_chain_exempt: false,
            last_admin: LastAdmin::AnyEdge,
            no_own_addendum: false,
            no_own_vouch: false,
            list_own: ListOwn::Kept,
            evidence_leaves: false,
            rewrite: false,
            leave_in_question: false,
        }
    }
    /// With every fix the notes now state.
    pub fn fixed() -> Rules {
        Rules {
            vouch: Vouch::BaseWalk,
            regrant: Regrant::FirstChained,
            own_chain_exempt: true,
            last_admin: LastAdmin::Named,
            no_own_addendum: true,
            no_own_vouch: true,
            list_own: ListOwn::Hops,
            evidence_leaves: true,
            rewrite: true,
            leave_in_question: true,
        }
    }
}

/// The role a value gives at `ts`.
pub fn alive(v: Val, ts: u32) -> Role {
    if v.1.is_some_and(|u| u <= ts) {
        Role::None
    } else {
        v.0
    }
}

/// A standing admin edge's value: admin, no `until` (`timed`: or an `until` later than `ts`).
fn standing(v: Option<Val>, ts: u32, timed: bool) -> bool {
    v.is_some_and(|v| v.0 == Role::Admin && if timed { alive(v, ts) == Role::Admin } else { v.1.is_none() })
}

#[derive(Clone, Debug, Default)]
pub struct World {
    pub records: Vec<Edge>,
    pub commits: Vec<Commit>,
}

impl World {
    /// Record edges, each admin.
    pub fn new(records: &[Edge]) -> World {
        World { records: records.to_vec(), commits: vec![] }
    }
    /// A commit; its hops are read from its stated path once, here (`World::hops`).
    pub fn push(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, kind: Kind) -> Id {
        let mut all = vec![signer];
        all.extend(path);
        // the path's end decides the class: an edge write whose path ends at the holder is a
        // self-removal; any other ends at the thing written
        let leave = matches!(&kind, Kind::Edge { holder, .. } if all.last() == Some(holder));
        if !leave {
            all.push(on);
        }
        let well = all.iter().collect::<BTreeSet<_>>().len() == all.len();
        let hops = if well { all.windows(2).flat_map(|p| self.joins(p[0], p[1])).collect() } else { vec![] };
        self.commits.push(Commit { signer, ts, path: path.to_vec(), on, kind, hops, well, leave });
        self.commits.len() - 1
    }
    /// The mint admin of `t`: the holder of its record edge.
    fn mint_of(&self, t: Thing) -> Option<Thing> {
        self.records.iter().find(|e| e.1 == t).map(|e| e.0)
    }
    /// The edges joining consecutive path members `p`, `q`: by descent (the record edges down the
    /// mint chain) where `p` is a mint ancestor of `q`, else their direct edge.
    fn joins(&self, p: Thing, q: Thing) -> Vec<Edge> {
        let mut down = vec![];
        let mut t = q;
        while let Some(m) = self.mint_of(t) {
            down.push((m, t));
            if m == p {
                down.reverse();
                return down;
            }
            if down.len() > self.records.len() {
                break;
            }
            t = m;
        }
        vec![(p, q)]
    }
    pub fn content(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing) -> Id {
        self.push(signer, ts, path, on, Kind::Content)
    }
    /// A frontier listing `ids`, cut per thing.
    pub fn cut(&self, ids: &[Id]) -> BTreeMap<Thing, Set> {
        let mut f: BTreeMap<Thing, Set> = BTreeMap::new();
        for &i in ids {
            f.entry(self.commits[i].on).or_default().insert(i);
        }
        f
    }
    /// An edge write setting `holder`'s edge on `on`, standing; `frontier` is cut per thing.
    pub fn edge(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, holder: Thing, role: Role, frontier: &[Id]) -> Id {
        let f = self.cut(frontier);
        self.push(signer, ts, path, on, Kind::Edge { holder, role, until: None, frontier: f, relies: None, adminless: false })
    }
    pub fn addendum(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, removal: Id, list: &[Id]) -> Id {
        self.push(signer, ts, path, on, Kind::Addendum { removal, list: list.iter().copied().collect() })
    }
    pub fn vouch(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, removal: Id, list: &[Id]) -> Id {
        self.push(signer, ts, path, on, Kind::Vouch { removal, list: list.iter().copied().collect() })
    }
    fn edit(&mut self, i: Id, f: impl FnOnce(Kind) -> Kind) {
        let k = std::mem::replace(&mut self.commits[i].kind, Kind::Content);
        self.commits[i].kind = f(k);
    }
    pub fn mark_adminless(&mut self, i: Id) {
        self.edit(i, |k| k.with(|_, _, _, a| *a = true));
    }
    pub fn set_until(&mut self, i: Id, t: u32) {
        self.edit(i, |k| k.until(t));
    }
    /// Names `holder` as the remaining admin edge write `i` relies on.
    pub fn rely(&mut self, i: Id, holder: Thing) {
        self.edit(i, |k| k.relying(holder));
    }
    pub fn key(&self, i: Id) -> Key {
        (self.commits[i].ts, self.commits[i].signer, i)
    }
    /// A content-class commit's position: the start of its `ts`.
    pub fn pos(&self, i: Id) -> Key {
        (self.commits[i].ts, 0, 0)
    }
    /// The edges a commit's stated path uses; none for a path naming a thing twice (bad input).
    pub fn hops(&self, i: Id) -> &[Edge] {
        &self.commits[i].hops
    }
    /// A path naming no thing twice (else bad input: the commit applies nowhere).
    pub fn well(&self, i: Id) -> bool {
        self.commits[i].well
    }
    /// A self-removal: an edge write whose stated path ends at the holder of the edge it sets.
    pub fn leave(&self, i: Id) -> bool {
        self.commits[i].leave
    }
    pub fn edge_class(&self, i: Id) -> bool {
        matches!(self.commits[i].kind, Kind::Edge { .. } | Kind::Vouch { .. })
    }
    /// The edge an edge write sets.
    pub fn sets(&self, i: Id) -> Option<Edge> {
        match &self.commits[i].kind {
            Kind::Edge { holder, .. } => Some((*holder, self.commits[i].on)),
            _ => None,
        }
    }
    /// An edge write setting its edge to below admin at its own `ts`.
    pub fn lowers(&self, i: Id) -> Option<Edge> {
        match &self.commits[i].kind {
            Kind::Edge { holder, role, until, .. } if alive((*role, *until), self.commits[i].ts) < Role::Admin => Some((*holder, self.commits[i].on)),
            _ => None,
        }
    }
    fn in_frontier(&self, r: Id, j: Id) -> bool {
        match &self.commits[r].kind {
            Kind::Edge { frontier, .. } => frontier.get(&self.commits[j].on).is_some_and(|l| l.contains(&j)),
            _ => false,
        }
    }
    /// The honest frontier of a lowering of `edge`: every commit through it that `received`.
    pub fn through(&self, edge: Edge, received: impl Fn(Id) -> bool) -> Vec<Id> {
        (0..self.commits.len()).filter(|&i| received(i) && self.hops(i).contains(&edge)).collect()
    }
}

/// What a node judges from: the commits it holds, the frontier leaves it sees (None: every
/// leaf), its trust set.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct View {
    pub held: Set,
    pub leaves: Option<Things>,
    pub trust: Set,
}

impl View {
    pub fn all(w: &World) -> View {
        View { held: (0..w.commits.len()).collect(), leaves: None, trust: Set::new() }
    }
    pub fn trusting(mut self, t: &[Id]) -> View {
        self.trust = t.iter().copied().collect();
        self
    }
    pub fn without(mut self, drop: &[Id]) -> View {
        for i in drop {
            self.held.remove(i);
        }
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Reading {
    /// Edge-class commits the settled walk applies.
    pub applied: Set,
    /// Applied edge writes that lowered their edge.
    pub lowered: Set,
    /// Valid content-class commits.
    pub valid: Set,
    /// Final roles, every `until` counted removed.
    pub roles: BTreeMap<Edge, Role>,
    /// The settled walk's edge values, and the first walk's (no vouch counting).
    pub state: BTreeMap<Edge, Val>,
    pub first: BTreeMap<Edge, Val>,
    /// Vouches counting (applied in the first walk after their removal), addenda vouching
    /// (valid, their writer holding write at their key).
    pub counting: Set,
    pub vouching: Set,
    pub dropped: Set,
    /// Trusted writes the settled walk does not apply.
    pub void: Set,
    /// Dropped by the audit of a write the settled walk does not apply.
    pub stray: Set,
    /// The vouch iteration did not settle (`Vouch::SameWalk`).
    pub circle: bool,
}

impl Reading {
    pub fn role(&self, holder: Thing, target: Thing) -> Role {
        self.roles.get(&(holder, target)).copied().unwrap_or(Role::None)
    }
    /// A commit shows: valid content, or an applied edge-class commit.
    pub fn shows(&self, i: Id) -> bool {
        self.valid.contains(&i) || self.applied.contains(&i)
    }
}

#[derive(Clone, Debug)]
struct Low {
    id: Id,
    /// An explicit write (it audits, and cuts the content through its edge before it).
    explicit: bool,
    edge: Edge,
    before: Role,
    after: Role,
}

#[derive(Default)]
struct Pass {
    state: BTreeMap<Edge, Val>,
    /// The edge as restored: the highest role each edge held since the last explicit write on it
    /// (values an `until` or a self-removal took included).
    restored: BTreeMap<Edge, Role>,
    hist: BTreeMap<Edge, Vec<(Key, Val)>>,
    applied: Vec<Id>,
    lows: Vec<Low>,
}

impl Pass {
    fn at(&self, e: Edge, ts: u32) -> Role {
        self.state.get(&e).map_or(Role::None, |&v| alive(v, ts))
    }
}

struct Walk {
    pass: Pass,
    dropped: Set,
    dropper: BTreeMap<Id, Id>,
}

type Vouched = BTreeSet<(Id, Id)>;

/// R's list names `j` (its frontier, in a leaf the node sees, or a counting vouch against it),
/// and `j` is not what no list keeps.
fn listed(w: &World, rules: &Rules, v: &View, vouched: &Vouched, r: Id, j: Id) -> bool {
    let seen = v.leaves.as_ref().is_none_or(|l| l.contains(&w.commits[j].on));
    ((seen && w.in_frontier(r, j)) || vouched.contains(&(r, j))) && !unlistable(w, rules, &v.held, r, j)
}

fn unlistable(w: &World, rules: &Rules, held: &Set, r: Id, j: Id) -> bool {
    let Some(e) = w.lowers(j) else { return false };
    match rules.list_own {
        ListOwn::Kept => false,
        ListOwn::Hops => w.hops(r).contains(&e),
        ListOwn::Chain => w.hops(r).contains(&e) || chain(w, held, r).iter().any(|&g| w.hops(g).contains(&e)),
        ListOwn::AnyLowering => true,
    }
}

/// The grants R's own authority rests on, as the held writes give them: those giving admin on
/// an edge of its path, and so on along their paths.
fn chain(w: &World, held: &Set, r: Id) -> Set {
    let mut edges: BTreeSet<Edge> = w.hops(r).iter().copied().collect();
    let mut out = Set::new();
    loop {
        let gives = |j: Id| matches!(&w.commits[j].kind, Kind::Edge { role: Role::Admin, .. });
        let more: Vec<Id> = held.iter().copied().filter(|&j| !out.contains(&j) && w.key(j) < w.key(r) && gives(j) && w.sets(j).is_some_and(|e| edges.contains(&e))).collect();
        if more.is_empty() {
            return out;
        }
        for j in more {
            edges.extend(w.hops(j));
            out.insert(j);
        }
    }
}

/// Whether a lowering of edge `e` puts commit `j` in question: its path holds `e`, or (with
/// `leave_in_question`) it is a self-removal of `e`.
fn rests_on(w: &World, rules: &Rules, j: Id, e: Edge) -> bool {
    w.hops(j).contains(&e) || (rules.leave_in_question && w.leave(j) && w.sets(j) == Some(e))
}

fn order(w: &World, held: &Set) -> Vec<Id> {
    let mut o: Vec<Id> = held.iter().copied().filter(|&i| w.edge_class(i)).collect();
    o.sort_by_key(|&i| w.key(i));
    o
}

/// Whether the last-admin rule refuses edge write `i` setting `e` to `new` against `p`.
fn refused(w: &World, rules: &Rules, p: &Pass, i: Id, e: Edge, new: Val) -> bool {
    let c = &w.commits[i];
    let Kind::Edge { relies, adminless, .. } = &c.kind else { return false };
    if *adminless {
        return false;
    }
    let old = p.state.get(&e).copied();
    match rules.last_admin {
        LastAdmin::Off => false,
        LastAdmin::AnyEdge => {
            p.at(e, c.ts) == Role::Admin && alive(new, c.ts) < Role::Admin && !p.state.keys().any(|&k| k.1 == c.on && k != e && p.at(k, c.ts) == Role::Admin)
        }
        LastAdmin::Named | LastAdmin::NamedTimed => {
            let timed = rules.last_admin == LastAdmin::NamedTimed;
            if !standing(old, c.ts, timed) || standing(Some(new), c.ts, timed) {
                return false;
            }
            let ok = |x: Edge| x != e && standing(p.state.get(&x).copied(), c.ts, timed);
            let last = (*c.path.last().unwrap_or(&c.signer), c.on);
            !(ok(last) || relies.is_some_and(|n| ok((n, c.on))))
        }
    }
}

fn walk(w: &World, rules: &Rules, v: &View, d0: &Set, vouched: &Vouched) -> Walk {
    let order = order(w, &v.held);
    let mut dropped = d0.clone();
    let mut dropper = BTreeMap::new();
    loop {
        let mut p = Pass::default();
        for &e in &w.records {
            p.state.insert(e, (Role::Admin, None));
            p.restored.insert(e, Role::Admin);
        }
        let mut again = false;
        for &i in &order {
            if dropped.contains(&i) {
                continue;
            }
            let c = &w.commits[i];
            if !w.well(i) || !w.hops(i).iter().all(|&e| p.at(e, c.ts) == Role::Admin) {
                continue;
            }
            let Kind::Edge { holder, role, until, .. } = &c.kind else {
                p.applied.push(i);
                continue;
            };
            let e = (*holder, c.on);
            let new = (*role, *until);
            if refused(w, rules, &p, i, e, new) {
                continue;
            }
            let leave = w.leave(i);
            let old = p.state.get(&e).copied().unwrap_or((Role::None, None));
            // a self-removal only lowers: no component above the grant's
            if leave && (new.0 > old.0 || old.1.is_some_and(|u| new.1.is_none_or(|n| n > u))) {
                continue;
            }
            let restored = p.restored.get(&e).copied().unwrap_or(Role::None).max(p.at(e, c.ts));
            let (before, after) = (if leave { p.at(e, c.ts) } else { restored }, alive(new, c.ts));
            // an explicit write audits against the edge as restored; a self-removal audits nothing
            let falls = !leave && before == Role::Admin && after < Role::Admin;
            let mut q = vec![];
            if falls {
                let exempt = if rules.own_chain_exempt { chain(w, &v.held, i) } else { Set::new() };
                q = p.applied.iter().copied().filter(|&j| rests_on(w, rules, j, e) && !exempt.contains(&j) && !listed(w, rules, v, vouched, i, j)).collect();
            }
            p.state.insert(e, new);
            if !leave {
                p.restored.insert(e, new.0);
            }
            p.hist.entry(e).or_default().push((w.key(i), new));
            p.applied.push(i);
            if after < before {
                p.lows.push(Low { id: i, explicit: !leave, edge: e, before, after });
            }
            if !q.is_empty() {
                for j in q {
                    dropped.insert(j);
                    dropper.insert(j, i);
                }
                again = true;
                break;
            }
        }
        if !again {
            return Walk { pass: p, dropped, dropper };
        }
    }
}

fn seeds(w: &World, rules: &Rules, v: &View, active: &Set, vouched: &Vouched) -> Set {
    let mut d = Set::new();
    for &r in active {
        let Some(h) = w.sets(r) else { continue };
        let exempt = if rules.own_chain_exempt { chain(w, &v.held, r) } else { Set::new() };
        for &j in &v.held {
            if w.edge_class(j) && w.key(j) < w.key(r) && rests_on(w, rules, j, h) && !exempt.contains(&j) && !listed(w, rules, v, vouched, r, j) {
                d.insert(j);
            }
        }
    }
    d
}

/// The vouches a walk applies after their removal, and the (removal, role write) pairs they
/// name.
fn counting(w: &World, rules: &Rules, wk: &Walk) -> (Set, Vouched) {
    let (mut ids, mut out) = (Set::new(), Vouched::new());
    for &i in &wk.pass.applied {
        if let Kind::Vouch { removal, list } = &w.commits[i].kind {
            if w.key(*removal) < w.key(i) {
                ids.insert(i);
                let own = |j: Id| rules.no_own_vouch && w.commits[j].signer == w.commits[i].signer;
                out.extend(list.iter().filter(|&&j| w.edge_class(j) && w.commits[j].on == w.commits[i].on && !own(j)).map(|&j| (*removal, j)));
            }
        }
    }
    (ids, out)
}

/// The settled walk under the active trusted writes, the first walk's state, the counting
/// vouches, and whether the vouches settled.
fn settle(w: &World, rules: &Rules, v: &View, active: &Set) -> (Walk, Set, BTreeMap<Edge, Val>, Set, bool) {
    let none = Vouched::new();
    let run = |vouched: &Vouched| {
        let d0 = seeds(w, rules, v, active, vouched);
        (walk(w, rules, v, &d0, vouched), d0)
    };
    match rules.vouch {
        Vouch::Off => {
            let (wk, d0) = run(&none);
            let first = wk.pass.state.clone();
            (wk, d0, first, Set::new(), false)
        }
        Vouch::BaseWalk => {
            let base = run(&none).0;
            let (ids, vouched) = counting(w, rules, &base);
            let (wk, d0) = run(&vouched);
            (wk, d0, base.pass.state, ids, false)
        }
        Vouch::SameWalk => {
            let mut seen = vec![none.clone()];
            let mut vouched = none;
            loop {
                let (wk, d0) = run(&vouched);
                let (ids, next) = counting(w, rules, &wk);
                if next == vouched || seen.contains(&next) {
                    let circle = next != vouched;
                    let first = wk.pass.state.clone();
                    return (wk, d0, first, ids, circle);
                }
                seen.push(next.clone());
                vouched = next;
            }
        }
    }
}

fn role_at(w: &World, p: &Pass, e: Edge, pos: Key) -> Role {
    let rec = if w.records.contains(&e) { (Role::Admin, None) } else { (Role::None, None) };
    alive(p.hist.get(&e).and_then(|h| h.iter().rev().find(|(k, _)| *k < pos)).map_or(rec, |x| x.1), pos.0)
}

/// The first key after which every edge gives write in the settled walk (KEY0: from the start).
fn first_applied(w: &World, p: &Pass, edges: &[Edge]) -> Option<Key> {
    let mut keys: Vec<Key> = vec![(0, 0, 0)];
    keys.extend(edges.iter().filter_map(|e| p.hist.get(e)).flatten().map(|x| x.0));
    keys.sort();
    keys.into_iter().find(|k| edges.iter().all(|&e| role_at(w, p, e, (k.0, k.1, k.2 + 1)) >= Role::Write))
}

/// Per edge, the key of the first chained write giving it write or above (spec/permissions.md
/// §4 Chained writes, along the write's stated path, `until` disregarded).
fn first_chained(w: &World, held: &Set) -> BTreeMap<Edge, Key> {
    let mut max: BTreeMap<Edge, Role> = w.records.iter().map(|&e| (e, Role::Admin)).collect();
    let mut first: BTreeMap<Edge, Key> = w.records.iter().map(|&e| (e, (0, 0, 0))).collect();
    for i in order(w, held) {
        let hops = w.hops(i);
        let (Some(e), Kind::Edge { role, .. }) = (w.sets(i), &w.commits[i].kind) else { continue };
        // a self-removal sets no edge here (spec/permissions.md §4 Chained writes)
        if !w.well(i) || w.leave(i) || !hops.iter().all(|h| max.get(h) == Some(&Role::Admin)) {
            continue;
        }
        if *role >= Role::Write {
            first.entry(e).or_insert(w.key(i));
        }
        let m = max.entry(e).or_insert(Role::None);
        *m = (*m).max(*role);
    }
    first
}

/// The final role of each edge, every `until` counted removed.
fn finals(p: &Pass) -> BTreeMap<Edge, Role> {
    p.state.iter().map(|(&e, &(r, u))| (e, if u.is_some() { Role::None } else { r })).collect()
}

/// Valid content-class commits, and the addenda among them that vouch.
fn content(w: &World, rules: &Rules, v: &View, p: &Pass) -> (Set, Set) {
    let chained = first_chained(w, &v.held);
    let fin = finals(p);
    let none = Vouched::new();
    let vouches = |a: Id| w.hops(a).iter().all(|&e| role_at(w, p, e, w.pos(a)) >= Role::Write);
    let mut valid = Set::new();
    loop {
        let mut next = Set::new();
        for &i in v.held.iter().filter(|&&i| !w.edge_class(i)) {
            let hops = w.hops(i);
            if !w.well(i) {
                continue;
            }
            let pos = w.pos(i);
            let cuts: Vec<&Low> = p.lows.iter().filter(|l| l.explicit && hops.contains(&l.edge) && l.before >= Role::Write && l.after < Role::Write).collect();
            let held = hops.iter().all(|&e| role_at(w, p, e, pos) >= Role::Write);
            let ok = (held && !cuts.iter().any(|l| w.key(l.id) > pos))
                || cuts.iter().any(|l| listed(w, rules, v, &none, l.id, i))
                || valid.iter().any(|&a| match &w.commits[a].kind {
                    Kind::Addendum { removal, list } => {
                        w.commits[a].on == w.commits[i].on
                            && list.contains(&i)
                            && !(rules.no_own_addendum && w.commits[a].signer == w.commits[i].signer)
                            && cuts.iter().any(|l| l.id == *removal && w.key(l.id) > pos && w.key(l.id) < w.pos(a))
                            && vouches(a)
                    }
                    _ => false,
                })
                || (hops.iter().all(|e| fin.get(e).is_some_and(|r| *r >= Role::Write)) && {
                    let from = match rules.regrant {
                        Regrant::FirstApplied => first_applied(w, p, &hops),
                        Regrant::FirstChained => hops.iter().map(|e| chained.get(e).copied()).collect::<Option<Vec<Key>>>().and_then(|k| k.into_iter().max()),
                    };
                    from.is_some_and(|k| k == (0, 0, 0) || pos > k)
                });
            if ok {
                next.insert(i);
            }
        }
        if next == valid {
            let vouching = valid.iter().copied().filter(|&a| matches!(w.commits[a].kind, Kind::Addendum { .. }) && vouches(a)).collect();
            return (valid, vouching);
        }
        valid = next;
    }
}

/// A node's reading: a function of the world's rules, what it holds, the leaves it sees and
/// its trust set.
pub fn judge(w: &World, rules: &Rules, v: &View) -> Reading {
    let mut active: Set = v.trust.iter().copied().filter(|i| v.held.contains(i) && w.sets(*i).is_some()).collect();
    let mut void = Set::new();
    loop {
        let (wk, d0, first, counting, circle) = settle(w, rules, v, &active);
        let applied: Set = wk.pass.applied.iter().copied().collect();
        let gone: Vec<Id> = active.iter().copied().filter(|r| !applied.contains(r)).collect();
        if !gone.is_empty() {
            for r in gone {
                active.remove(&r);
                void.insert(r);
            }
            continue;
        }
        let stray = wk.dropper.iter().filter(|(j, r)| !d0.contains(j) && !applied.contains(r)).map(|(j, _)| *j).collect();
        let (valid, vouching) = content(w, rules, v, &wk.pass);
        return Reading {
            lowered: wk.pass.lows.iter().map(|l| l.id).collect(),
            valid,
            roles: finals(&wk.pass),
            state: wk.pass.state.clone(),
            first,
            counting,
            vouching,
            applied,
            dropped: wk.dropped,
            void,
            stray,
            circle,
        };
    }
}

/// Disputes (spec/permissions.md §5.1): held lowerings of another holder's edge that the
/// settled walk does not apply, no seed dropped, and that apply once trusted.
pub fn disputes(w: &World, rules: &Rules, v: &View) -> Vec<Id> {
    let rd = judge(w, rules, v);
    let mut out = vec![];
    for &r in &v.held {
        let Kind::Edge { holder, .. } = &w.commits[r].kind else { continue };
        if *holder == w.commits[r].signer || rd.applied.contains(&r) || rd.dropped.contains(&r) || v.trust.contains(&r) {
            continue;
        }
        let mut t = v.clone();
        t.trust.insert(r);
        if judge(w, rules, &t).lowered.contains(&r) {
            out.push(r);
        }
    }
    out
}

/// The edges whose edge writes are evidence of commit `i`: its path's, and the remaining admin
/// edge it names.
fn evidence_edges(w: &World, i: Id) -> Vec<Edge> {
    let mut e = w.hops(i).to_vec();
    if let Kind::Edge { relies: Some(n), .. } = &w.commits[i].kind {
        e.push((*n, w.commits[i].on));
    }
    e
}

/// The evidence closure of `unit` over `avail` (notes/write-path-design.md §2): the commits in
/// `unit`, every available edge write on an edge of a held commit's path or on the remaining
/// admin edge a held lowering names, every available vouch against a held removal.
pub fn evidence(w: &World, unit: &Set, avail: &Set) -> Set {
    let mut s = unit.clone();
    loop {
        let edges: BTreeSet<Edge> = s.iter().flat_map(|&i| evidence_edges(w, i)).collect();
        let more: Vec<Id> = avail
            .iter()
            .copied()
            .filter(|i| !s.contains(i))
            .filter(|&i| match &w.commits[i].kind {
                Kind::Edge { .. } => w.sets(i).is_some_and(|e| edges.contains(&e)),
                Kind::Vouch { removal, .. } => s.contains(removal),
                _ => false,
            })
            .collect();
        if more.is_empty() {
            return s;
        }
        s.extend(more);
    }
}

// ---- The keys layer: A's epochs under a standing dispute (spec/crypto.md §4) ----

/// What one node's reading gives the keys layer: A's admins and the departures it knows.
#[derive(Clone, Debug, PartialEq)]
pub struct Side {
    pub node: Thing,
    pub admins: Things,
    pub departures: Set,
}

impl Side {
    pub fn of(w: &World, rd: &Reading, node: Thing, a: Thing) -> Side {
        Side {
            node,
            admins: rd.roles.iter().filter(|(e, r)| e.1 == a && **r == Role::Admin).map(|(e, _)| e.0).collect(),
            departures: rd.lowered.iter().copied().filter(|&i| w.commits[i].on == a).collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Withdraw {
    /// spec/crypto.md §4 as written: a valid rotation is current whatever it covers; the
    /// knowing re-key answers a current epoch not covering a known departure; a node withdraws
    /// an epoch not current whose maker may not rotate.
    AsWritten,
    /// The fix: an epoch covering a departure the node's walk does not apply is the other
    /// side's: it is read, never current, supersedes nothing and is not answered.
    SideOnly,
}

#[derive(Clone, Debug)]
pub struct Epoch {
    pub maker: Thing,
    pub covers: Set,
    pub boxes: Things,
    pub supersedes: BTreeSet<usize>,
}

/// Every node holds every epoch; each pass, each node in turn rotates A when the rule says so.
/// Returns the epochs (0 the first, valid everywhere) and the rotations made per pass.
pub fn rotations(passes: usize, rule: Withdraw, sides: impl Fn(usize) -> Vec<Side>) -> (Vec<Epoch>, Vec<usize>) {
    let mut eps = vec![Epoch { maker: 0, covers: Set::new(), boxes: Things::new(), supersedes: BTreeSet::new() }];
    let mut per = vec![];
    for pass in 0..passes {
        let mut made = 0;
        for s in sides(pass) {
            let cur = current(&eps, &s, rule);
            let counted = |i: usize| counts(&eps, i, &s, rule);
            let superseded = |i: usize| (0..eps.len()).any(|f| counted(f) && eps[f].supersedes.contains(&i));
            let withdrawn: Vec<usize> = (1..eps.len()).filter(|&i| !counted(i) && !superseded(i) && (eps[i].maker == s.node || !s.admins.contains(&eps[i].maker))).collect();
            if !s.admins.contains(&s.node) || (!cur.is_empty() && cur.iter().all(|&i| eps[i].covers.is_superset(&s.departures)) && withdrawn.is_empty()) {
                continue;
            }
            let supersedes = cur.into_iter().chain(withdrawn).collect();
            eps.push(Epoch { maker: s.node, covers: s.departures.clone(), boxes: s.admins.clone(), supersedes });
            made += 1;
        }
        per.push(made);
    }
    (eps, per)
}

fn counts(eps: &[Epoch], i: usize, s: &Side, rule: Withdraw) -> bool {
    i == 0 || (s.admins.contains(&eps[i].maker) && (rule == Withdraw::AsWritten || eps[i].covers.is_subset(&s.departures)))
}

/// The epochs current at a node: counting, superseded by no counting epoch.
pub fn current(eps: &[Epoch], s: &Side, rule: Withdraw) -> Vec<usize> {
    (0..eps.len()).filter(|&i| counts(eps, i, s, rule) && !(0..eps.len()).any(|f| counts(eps, f, s, rule) && eps[f].supersedes.contains(&i))).collect()
}

mod story;
pub use story::*;

#[cfg(test)]
mod tests;
