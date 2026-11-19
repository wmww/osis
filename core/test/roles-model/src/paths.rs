//! Stated paths and signers as members (notes/write-path-design.md §1-§2,
//! notes/account-membership-design.md §2, §4; not built, not in spec): an oracle of those notes,
//! greenfield, sharing nothing with `joint` (whose authority is a maximum over every path).
//! Findings: notes/path-model-findings.md. README.md, Paths: what is assumed where the notes are
//! open, sizes, how to run.
//!
//! The rule under test.
//! - **Things and edges.** Signers and independent things share one namespace; an edge is
//!   (holder, target) with a role; record edges stand at the start. Dependent things are not
//!   modelled (a descent of one step is the direct edge).
//! - **Commits.** One signer, a `ts`, the thing written (`on`) and a stated path [A1..Ak]: the
//!   commit uses the edges joining [signer, A1, .., Ak, on] and no other. Kinds: content, an
//!   edge write (setting a holder's edge on `on`; a lowering carries a frontier, a leaf of commit
//!   IDs per thing), an addendum (plain content naming a removal and commits it vouches for), a
//!   vouch (the same for role writes: the fix reading, `Vouch`).
//! - **Walk** (§5.1 along one path). Edge-class commits (edge writes, vouches) in key order
//!   (`ts`, signer, ID), skipping the drop set D. One applies iff every edge of its path gives
//!   admin there. An applied write taking an edge h from admin to below puts in question every
//!   earlier applied edge-class commit whose path holds h; those its frontier does not list (and
//!   no counting vouch names) join D and the walk restarts. D only grows until a pass adds
//!   nothing.
//! - **Last admin** (`Rules::last_admin`): a lowering of an admin edge that would leave its
//!   target no admin edge, as the walk stands, does not apply unless marked.
//! - **Content.** A commit on T with path P is valid iff every edge of P gave write just before
//!   its position (the start of its `ts`) and no applied lowering of an edge of P below write is
//!   ordered after it; else iff such a lowering's frontier lists it, a valid addendum by a writer
//!   of T against such a lowering ordered between them lists it (least fixpoint), or P is
//!   re-granted (every edge gives write in the final state) and the commit is ordered after the
//!   first point P gave write (`Regrant`).
//! - **Trust sets.** A trusted lowering R of edge h seeds D with the held edge-class commits
//!   ordered before R whose path holds h and R does not list; a trusted write the settled walk
//!   does not apply is void and loses its seeds, all void ones at once, and the walk is redone.
//! - **Leaves.** A node sees a frontier's leaf for a thing only where its view says so
//!   (`View::leaves`); an entry in a leaf it does not see is not listed for it.
//! - **Evidence** (`evidence`): the least set holding a unit's commits, every edge write on an
//!   edge of a held commit's path, and the vouches against held removals.
//!
//! `Sim` plays the stolen-node story over that rule (parties, ticks, honest policy and the
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

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    Content,
    Edge { holder: Thing, role: Role, frontier: BTreeMap<Thing, Set>, adminless: bool },
    Addendum { removal: Id, list: Set },
    Vouch { removal: Id, list: Set },
}

#[derive(Clone, Debug)]
pub struct Commit {
    pub signer: Thing,
    pub ts: u32,
    pub path: Vec<Thing>,
    pub on: Thing,
    pub kind: Kind,
}

/// How role writes a removal does not list are vouched for (issues/actors-one-mechanism.md,
/// "Role writes of a removed node must be kept on the same terms as its content").
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Vouch {
    /// As the notes on main state: nothing vouches for a role write.
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rules {
    pub vouch: Vouch,
    pub regrant: Regrant,
    /// spec/permissions.md §5.1 "R never demotes its own author", read along paths: a lowering
    /// never puts in question an edge write setting an edge of its own path, nor one such a
    /// write's path rests on. notes/write-path-design.md §1 removes the rule (false).
    pub own_chain_exempt: bool,
    pub last_admin: bool,
    /// An addendum vouches for no commit of its own signer (spec/permissions.md §5.2 Addenda
    /// asks only that its writer holds write on the thing, by any path).
    pub no_own_addendum: bool,
}

impl Rules {
    /// The notes on main, simplest reading.
    pub fn design() -> Rules {
        Rules { vouch: Vouch::Off, regrant: Regrant::FirstApplied, own_chain_exempt: false, last_admin: true, no_own_addendum: false }
    }
    /// With the fixes the notes propose and the ones this model adds.
    pub fn fixed() -> Rules {
        Rules { vouch: Vouch::BaseWalk, regrant: Regrant::FirstChained, own_chain_exempt: true, last_admin: true, no_own_addendum: true }
    }
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
    pub fn push(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, kind: Kind) -> Id {
        self.commits.push(Commit { signer, ts, path: path.to_vec(), on, kind });
        self.commits.len() - 1
    }
    pub fn content(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing) -> Id {
        self.push(signer, ts, path, on, Kind::Content)
    }
    /// An edge write setting `holder`'s edge on `on`; `frontier` is cut per thing.
    pub fn edge(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, holder: Thing, role: Role, frontier: &[Id]) -> Id {
        let mut f: BTreeMap<Thing, Set> = BTreeMap::new();
        for &i in frontier {
            f.entry(self.commits[i].on).or_default().insert(i);
        }
        self.push(signer, ts, path, on, Kind::Edge { holder, role, frontier: f, adminless: false })
    }
    pub fn addendum(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, removal: Id, list: &[Id]) -> Id {
        self.push(signer, ts, path, on, Kind::Addendum { removal, list: list.iter().copied().collect() })
    }
    pub fn vouch(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, removal: Id, list: &[Id]) -> Id {
        self.push(signer, ts, path, on, Kind::Vouch { removal, list: list.iter().copied().collect() })
    }
    pub fn mark_adminless(&mut self, i: Id) {
        if let Kind::Edge { adminless, .. } = &mut self.commits[i].kind {
            *adminless = true;
        }
    }
    pub fn key(&self, i: Id) -> Key {
        (self.commits[i].ts, self.commits[i].signer, i)
    }
    /// A content-class commit's position: the start of its `ts`.
    pub fn pos(&self, i: Id) -> Key {
        (self.commits[i].ts, 0, 0)
    }
    /// The edges a commit's stated path uses; none for a path naming a thing twice (bad input).
    pub fn hops(&self, i: Id) -> Vec<Edge> {
        let c = &self.commits[i];
        let mut all = vec![c.signer];
        all.extend(&c.path);
        all.push(c.on);
        if all.iter().collect::<BTreeSet<_>>().len() != all.len() {
            return vec![];
        }
        all.windows(2).map(|p| (p[0], p[1])).collect()
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
    /// Final roles.
    pub roles: BTreeMap<Edge, Role>,
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
    edge: Edge,
    before: Role,
    after: Role,
}

#[derive(Default)]
struct Pass {
    state: BTreeMap<Edge, Role>,
    hist: BTreeMap<Edge, Vec<(Key, Role)>>,
    applied: Vec<Id>,
    lows: Vec<Low>,
}

impl Pass {
    fn role(&self, e: Edge) -> Role {
        self.state.get(&e).copied().unwrap_or(Role::None)
    }
}

struct Walk {
    pass: Pass,
    dropped: Set,
    dropper: BTreeMap<Id, Id>,
}

type Vouched = BTreeSet<(Id, Id)>;

fn listed(w: &World, v: &View, vouched: &Vouched, r: Id, j: Id) -> bool {
    let seen = v.leaves.as_ref().is_none_or(|l| l.contains(&w.commits[j].on));
    (seen && w.in_frontier(r, j)) || vouched.contains(&(r, j))
}

/// The grants R's own authority rests on: those giving admin on an edge of its path, and so on
/// along their paths.
fn chain(w: &World, held: &Set, r: Id) -> Set {
    let mut edges: BTreeSet<Edge> = w.hops(r).into_iter().collect();
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

fn order(w: &World, held: &Set) -> Vec<Id> {
    let mut o: Vec<Id> = held.iter().copied().filter(|&i| w.edge_class(i)).collect();
    o.sort_by_key(|&i| w.key(i));
    o
}

fn walk(w: &World, rules: &Rules, v: &View, d0: &Set, vouched: &Vouched) -> Walk {
    let order = order(w, &v.held);
    let mut dropped = d0.clone();
    let mut dropper = BTreeMap::new();
    loop {
        let mut p = Pass::default();
        for &e in &w.records {
            p.state.insert(e, Role::Admin);
        }
        let mut again = false;
        for &i in &order {
            if dropped.contains(&i) {
                continue;
            }
            let hops = w.hops(i);
            if hops.is_empty() || !hops.iter().all(|&e| p.role(e) == Role::Admin) {
                continue;
            }
            let c = &w.commits[i];
            let Kind::Edge { holder, role, adminless, .. } = &c.kind else {
                p.applied.push(i);
                continue;
            };
            let e = (*holder, c.on);
            let before = p.role(e);
            let falls = before == Role::Admin && *role < Role::Admin;
            if rules.last_admin && falls && !adminless && !p.state.iter().any(|(k, r)| k.1 == c.on && *k != e && *r == Role::Admin) {
                continue;
            }
            let mut q = vec![];
            if falls {
                let exempt = if rules.own_chain_exempt { chain(w, &v.held, i) } else { Set::new() };
                q = p.applied.iter().copied().filter(|&j| w.hops(j).contains(&e) && !exempt.contains(&j) && !listed(w, v, vouched, i, j)).collect();
            }
            p.state.insert(e, *role);
            p.hist.entry(e).or_default().push((w.key(i), *role));
            p.applied.push(i);
            if *role < before {
                p.lows.push(Low { id: i, edge: e, before, after: *role });
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
            if w.edge_class(j) && w.key(j) < w.key(r) && w.hops(j).contains(&h) && !exempt.contains(&j) && !listed(w, v, vouched, r, j) {
                d.insert(j);
            }
        }
    }
    d
}

/// The (removal, role write) pairs the vouches applied in a walk name.
fn counting(w: &World, wk: &Walk) -> Vouched {
    let mut out = Vouched::new();
    for &i in &wk.pass.applied {
        if let Kind::Vouch { removal, list } = &w.commits[i].kind {
            if w.key(*removal) < w.key(i) {
                out.extend(list.iter().filter(|&&j| w.edge_class(j) && w.commits[j].on == w.commits[i].on).map(|&j| (*removal, j)));
            }
        }
    }
    out
}

/// The settled walk under the active trusted writes, and whether the vouches settled.
fn settle(w: &World, rules: &Rules, v: &View, active: &Set) -> (Walk, Set, bool) {
    let none = Vouched::new();
    let run = |vouched: &Vouched| {
        let d0 = seeds(w, rules, v, active, vouched);
        (walk(w, rules, v, &d0, vouched), d0)
    };
    match rules.vouch {
        Vouch::Off => {
            let (wk, d0) = run(&none);
            (wk, d0, false)
        }
        Vouch::BaseWalk => {
            let vouched = counting(w, &run(&none).0);
            let (wk, d0) = run(&vouched);
            (wk, d0, false)
        }
        Vouch::SameWalk => {
            let mut seen = vec![none.clone()];
            let mut vouched = none;
            loop {
                let (wk, d0) = run(&vouched);
                let next = counting(w, &wk);
                if next == vouched {
                    return (wk, d0, false);
                }
                if seen.contains(&next) {
                    return (wk, d0, true);
                }
                seen.push(next.clone());
                vouched = next;
            }
        }
    }
}

fn role_at(w: &World, p: &Pass, e: Edge, pos: Key) -> Role {
    let rec = if w.records.contains(&e) { Role::Admin } else { Role::None };
    p.hist.get(&e).and_then(|h| h.iter().rev().find(|(k, _)| *k < pos)).map_or(rec, |x| x.1)
}

/// The first key after which every edge gives write in the settled walk (KEY0: from the start).
fn first_applied(w: &World, p: &Pass, edges: &[Edge]) -> Option<Key> {
    let mut keys: Vec<Key> = vec![(0, 0, 0)];
    keys.extend(edges.iter().filter_map(|e| p.hist.get(e)).flatten().map(|x| x.0));
    keys.sort();
    keys.into_iter().find(|k| edges.iter().all(|&e| role_at(w, p, e, (k.0, k.1, k.2 + 1)) >= Role::Write))
}

/// Per edge, the key of the first chained write giving it write or above (spec/permissions.md
/// §4 Chained writes, along the write's stated path).
fn first_chained(w: &World, held: &Set) -> BTreeMap<Edge, Key> {
    let mut max: BTreeMap<Edge, Role> = w.records.iter().map(|&e| (e, Role::Admin)).collect();
    let mut first: BTreeMap<Edge, Key> = w.records.iter().map(|&e| (e, (0, 0, 0))).collect();
    for i in order(w, held) {
        let hops = w.hops(i);
        let (Some(e), Kind::Edge { role, .. }) = (w.sets(i), &w.commits[i].kind) else { continue };
        if hops.is_empty() || !hops.iter().all(|h| max.get(h) == Some(&Role::Admin)) {
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

fn content(w: &World, rules: &Rules, v: &View, p: &Pass) -> Set {
    let chained = first_chained(w, &v.held);
    let none = Vouched::new();
    let mut valid = Set::new();
    loop {
        let mut next = Set::new();
        for &i in v.held.iter().filter(|&&i| !w.edge_class(i)) {
            let hops = w.hops(i);
            if hops.is_empty() {
                continue;
            }
            let pos = w.pos(i);
            let cuts: Vec<&Low> = p.lows.iter().filter(|l| hops.contains(&l.edge) && l.before >= Role::Write && l.after < Role::Write).collect();
            let held = hops.iter().all(|&e| role_at(w, p, e, pos) >= Role::Write);
            let ok = (held && !cuts.iter().any(|l| w.key(l.id) > pos))
                || cuts.iter().any(|l| listed(w, v, &none, l.id, i))
                || valid.iter().any(|&a| match &w.commits[a].kind {
                    Kind::Addendum { removal, list } => {
                        w.commits[a].on == w.commits[i].on
                            && list.contains(&i)
                            && !(rules.no_own_addendum && w.commits[a].signer == w.commits[i].signer)
                            && cuts.iter().any(|l| l.id == *removal && w.key(l.id) > pos && w.key(l.id) < w.pos(a))
                            && w.hops(a).iter().all(|&e| role_at(w, p, e, w.pos(a)) >= Role::Write)
                    }
                    _ => false,
                })
                || (hops.iter().all(|&e| p.role(e) >= Role::Write) && {
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
            return valid;
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
        let (wk, d0, circle) = settle(w, rules, v, &active);
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
        return Reading {
            lowered: wk.pass.lows.iter().map(|l| l.id).collect(),
            valid: content(w, rules, v, &wk.pass),
            roles: wk.pass.state.clone(),
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

/// The evidence closure of `unit` over `avail` (notes/write-path-design.md §2): the commits in
/// `unit`, every available edge write on an edge of a held commit's path, every available vouch
/// against a held removal.
pub fn evidence(w: &World, unit: &Set, avail: &Set) -> Set {
    let mut s = unit.clone();
    loop {
        let edges: BTreeSet<Edge> = s.iter().flat_map(|&i| w.hops(i)).collect();
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

// ---- The stolen-node story ----

pub const H: Thing = 1;
pub const B: Thing = 2;
pub const X: Thing = 3;
pub const N5: Thing = 4;
pub const K: Thing = 5;
pub const Z: Thing = 6;
pub const N6: Thing = 7;
pub const A: Thing = 10;
pub const A2: Thing = 11;
pub const ORG: Thing = 12;
pub const T1: Thing = 13;
pub const T2: Thing = 14;
/// Readers outside A (nodes, not signers): of T1's unit, of T2's.
pub const RD: Thing = 20;
pub const RD2: Thing = 21;

const SETTLE: u32 = 11;
const AFTER: u32 = 12;
/// The tick of H's removal of X.
const REMOVAL: u32 = 6;

/// Account A (minted by H's key), the collaborator's account A2 (K's), ORG and T1 minted with A,
/// T2 minted with ORG: a path to T2 has two hops above the signer's.
pub fn account() -> World {
    World::new(&[(H, A), (K, A2), (A, ORG), (ORG, T2), (A, T1)])
}

/// One world of the family (`Sim::build`).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Setup {
    /// The remover syncs T1, T2.
    pub h_t1: bool,
    pub h_t2: bool,
    /// B is offline from tick 4 to the settle.
    pub b_offline: bool,
    /// A2's write on T1 is granted by X (else by B).
    pub sharer_x: bool,
    /// 0: no N5; 1: X paired N5 and H received the grant before its removal; 2: H did not.
    pub n5: u8,
    /// X's role write before the theft. 0: none; 1: demotes B to write on A; 2: removes A2 from
    /// T1 (when B shared it); 3: grants A2 admin on T2.
    pub x_role: u8,
    /// H received it before its removal.
    pub x_role_seen: bool,
    /// 0: X holds nothing on A2; 1: write on A2; 2: write, and K removes it as H does.
    pub x_a2: u8,
    /// B sides with X's removal of H until its user switches at the settle.
    pub b_side_x: bool,
    /// After the settle H grants N5 again and B grants A2 write on T1 again.
    pub regrant: bool,
}

/// One move of the thief after the removal: `kind` indexes `MOVES`, stamped `ts`, made at `made`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Move {
    pub kind: usize,
    pub ts: u32,
    pub made: u32,
}

pub const MOVES: usize = 19;

#[derive(Clone, Debug)]
pub struct Sim {
    pub w: World,
    pub setup: Setup,
    pub made: Vec<u32>,
    /// When each node received each commit (absent: not before the final reading).
    pub recv: Vec<BTreeMap<Thing, u32>>,
    pub sync: BTreeMap<Thing, Things>,
    /// H's removal of X; K's of X from A2; X's removal of H that B sides with.
    pub r: Id,
    pub r2: Option<Id>,
    pub rx: Option<Id>,
    pub gs: Id,
    pub g5: Option<Id>,
    pub xrole: Option<Id>,
    /// Removals and the further units they are logged under.
    pub logged: BTreeMap<Id, Things>,
}

fn role_path(n: Thing, on: Thing) -> Option<Vec<Thing>> {
    match (n, on) {
        (H | B | X | N5 | Z, A) | (K, A2) => Some(vec![]),
        (H | B | X | N5 | Z, T1 | ORG) | (K, T1) if n != K => Some(vec![A]),
        (K, T1) => Some(vec![A2]),
        (H | B | X | N5 | Z, T2) => Some(vec![A, ORG]),
        _ => None,
    }
}

impl Sim {
    fn put(&mut self, c: (Thing, u32, &[Thing], Thing, Kind), made: u32, rng: &mut Rng, hostile: bool) -> Id {
        let (signer, ts, path, on, kind) = c;
        let i = self.w.push(signer, ts, path, on, kind);
        self.made.push(made);
        let mut units = Things::from([on]);
        units.extend(self.logged.get(&i).into_iter().flatten());
        let mut recv = BTreeMap::new();
        for (&n, syncs) in &self.sync {
            if !syncs.iter().any(|u| units.contains(u)) {
                continue;
            }
            let t = if n == signer || n == X {
                made
            } else if (self.setup.b_offline && n == B && made >= 4) || (hostile && rng.below(2) == 0) {
                SETTLE.max(made)
            } else {
                made + rng.below(2) as u32
            };
            recv.insert(n, t);
        }
        self.recv.push(recv);
        i
    }
    fn got(&self, i: Id, n: Thing, by: u32) -> bool {
        self.recv[i].get(&n).is_some_and(|t| *t <= by)
    }
    /// The story. Ticks 1-4: A's nodes are paired, T1 is shared, X's role write, content.
    /// 5: X is stolen and writes. 6: H removes X (K too where X holds on A2). 7-10: the thief's
    /// moves and honest content; each node answers the removal as it receives it. 11: the
    /// settle, every node receives everything in the units it syncs. 12: re-grants, B's switch.
    pub fn build(setup: &Setup, rules: &Rules, moves: &[Move], rng: &mut Rng) -> Sim {
        let s = *setup;
        let mut sync: BTreeMap<Thing, Things> = BTreeMap::new();
        let mut hs = Things::from([A, ORG]);
        if s.h_t1 {
            hs.insert(T1);
        }
        if s.h_t2 {
            hs.insert(T2);
        }
        sync.insert(H, hs);
        sync.insert(B, Things::from([A, ORG, T1, T2]));
        sync.insert(X, Things::from([A, A2, ORG, T1, T2]));
        if s.n5 > 0 {
            sync.insert(N5, Things::from([A, ORG, T1, T2]));
        }
        sync.insert(K, Things::from([A2, T1]));
        sync.insert(RD, Things::from([T1]));
        sync.insert(RD2, Things::from([T2]));
        let mut m = Sim { w: account(), setup: s, made: vec![], recv: vec![], sync, r: 0, r2: None, rx: None, gs: 0, g5: None, xrole: None, logged: BTreeMap::new() };
        let grant = |holder, role| Kind::Edge { holder, role, frontier: BTreeMap::new(), adminless: false };
        m.put((H, 1, &[], A, grant(X, Role::Admin)), 1, rng, false);
        m.put((H, 1, &[], A, grant(B, Role::Admin)), 1, rng, false);
        if s.x_a2 > 0 {
            m.put((K, 1, &[], A2, grant(X, Role::Write)), 1, rng, false);
        }
        let sharer = if s.sharer_x { X } else { B };
        m.gs = m.put((sharer, 2, &[A], T1, grant(A2, Role::Write)), 2, rng, false);
        if s.n5 > 0 {
            let g = m.put((X, 2, &[], A, grant(N5, Role::Admin)), 2, rng, false);
            m.recv[g].insert(H, if s.n5 == 1 { 2 } else { SETTLE });
            m.g5 = Some(g);
        }
        let x_role = if s.x_role == 2 && s.sharer_x { 0 } else { s.x_role };
        if x_role > 0 {
            let (path, on, holder, role): (&[Thing], _, _, _) = match x_role {
                1 => (&[], A, B, Role::Write),
                2 => (&[A], T1, A2, Role::None),
                _ => (&[A, ORG], T2, A2, Role::Admin),
            };
            let n = m.w.commits.len();
            let f = m.w.through((holder, on), |_| true);
            let g = m.w.edge(X, 3, path, on, holder, role, &f);
            let c = m.w.commits.pop().unwrap();
            debug_assert_eq!(g, n);
            let g = m.put((c.signer, c.ts, &c.path, c.on, c.kind), 3, rng, false);
            if m.sync[&H].contains(&on) {
                m.recv[g].insert(H, if s.x_role_seen { 3 } else { SETTLE });
            }
            m.xrole = Some(g);
        }
        for tick in [3, 4, 5, 8, 9] {
            let writers: &[Thing] = if tick < 5 { &[H, B, X, K, N5] } else if tick == 5 { &[X] } else { &[H, B, K, N5] };
            for &n in writers {
                for on in [T1, T2] {
                    if m.sync.get(&n).is_some_and(|u| u.contains(&on)) && rng.below(2) == 0 {
                        if let Some(p) = role_path(n, on) {
                            m.put((n, tick, &p, on, Kind::Content), tick, rng, false);
                        }
                    }
                }
            }
            if tick == 5 {
                m.remove(rules, rng);
            }
        }
        for mv in moves {
            m.thief(mv, rng);
        }
        if s.b_side_x {
            let f = m.w.through((H, A), |i| i != m.r);
            let n = m.w.edge(X, 5, &[], A, H, Role::None, &f);
            let c = m.w.commits.pop().unwrap();
            debug_assert_eq!(n, m.w.commits.len());
            m.rx = Some(m.put((c.signer, c.ts, &c.path, c.on, c.kind), 7, rng, false));
        }
        // the settle: whatever exists reaches every node syncing its unit
        for i in 0..m.w.commits.len() {
            let on = m.w.commits[i].on;
            let mut units = Things::from([on]);
            units.extend(m.logged.get(&i).into_iter().flatten());
            for (&n, syncs) in &m.sync {
                if syncs.iter().any(|u| units.contains(u)) {
                    let t = m.recv[i].entry(n).or_insert(SETTLE);
                    *t = (*t).min(SETTLE.max(m.made[i]));
                }
            }
        }
        if s.regrant {
            if s.n5 > 0 {
                m.put((H, AFTER, &[], A, grant(N5, Role::Admin)), AFTER, rng, false);
            }
            m.put((B, AFTER, &[A], T1, grant(A2, Role::Write)), AFTER, rng, false);
        }
        if s.b_side_x {
            m.answer(B, AFTER, rules, rng);
        }
        m
    }
    /// The removals at tick 6, and each honest node's answers as it receives them.
    fn remove(&mut self, rules: &Rules, rng: &mut Rng) {
        let s = self.setup;
        let f = self.w.through((X, A), |i| self.got(i, H, REMOVAL - 1));
        let n = self.w.edge(H, REMOVAL, &[], A, X, Role::None, &f);
        let c = self.w.commits.pop().unwrap();
        self.logged.insert(n, Things::from([ORG, T1, T2]));
        self.r = self.put((c.signer, c.ts, &c.path, c.on, c.kind), REMOVAL, rng, false);
        if s.x_a2 == 2 {
            let f = self.w.through((X, A2), |i| self.got(i, K, REMOVAL - 1));
            let n = self.w.edge(K, REMOVAL, &[], A2, X, Role::None, &f);
            let c = self.w.commits.pop().unwrap();
            self.logged.insert(n, Things::from([T1]));
            self.r2 = Some(self.put((c.signer, c.ts, &c.path, c.on, c.kind), REMOVAL, rng, false));
        }
        for n in [H, B, N5, K] {
            if self.sync.contains_key(&n) && !(n == B && s.b_side_x) {
                let at = self.recv[self.r].get(&n).copied();
                if let Some(at) = at {
                    self.answer(n, at.max(REMOVAL + 1), rules, rng);
                }
            }
        }
    }
    /// A node's addenda (and vouches, where the rules have them) against each removal: per
    /// thing it syncs and may write, the commits through the removed edge it had received by
    /// the removal's `ts` that the removal does not list.
    fn answer(&mut self, n: Thing, at: u32, rules: &Rules, rng: &mut Rng) {
        for r in [Some(self.r), self.r2].into_iter().flatten() {
            let h = self.w.sets(r).unwrap();
            for on in [A, ORG, T1, T2] {
                let Some(path) = role_path(n, on) else { continue };
                if !self.sync[&n].contains(&on) {
                    continue;
                }
                let mine = |edge: bool| -> Set {
                    (0..self.w.commits.len())
                        .filter(|&i| i != r && self.w.commits[i].on == on && self.w.edge_class(i) == edge && self.w.hops(i).contains(&h) && self.got(i, n, REMOVAL) && self.made[i] <= REMOVAL && !self.w.in_frontier(r, i))
                        .collect()
                };
                let (plain, role) = (mine(false), mine(true));
                if !plain.is_empty() && (on == T1 || on == T2) {
                    self.put((n, at, &path, on, Kind::Addendum { removal: r, list: plain }), at, rng, false);
                }
                if !role.is_empty() && rules.vouch != Vouch::Off && n != K {
                    self.put((n, at, &path, on, Kind::Vouch { removal: r, list: role }), at, rng, false);
                }
            }
        }
    }
    /// One move of the thief: any `ts`, any path, as X or as the made-up key Z.
    fn thief(&mut self, mv: &Move, rng: &mut Rng) {
        let grant = |holder, role| Kind::Edge { holder, role, frontier: BTreeMap::new(), adminless: false };
        let mine = |m: &Sim, on: Thing, edge: bool| -> Set { (0..m.w.commits.len()).filter(|&i| m.w.commits[i].signer == X && m.w.commits[i].on == on && m.w.edge_class(i) == edge && m.w.hops(i).contains(&(X, A))).collect() };
        let c: (Thing, &[Thing], Thing, Kind) = match mv.kind {
            0 | 18 => (X, &[A], T1, Kind::Content),
            1 => (X, &[A, ORG], T2, Kind::Content),
            2 => (X, &[A2], T1, Kind::Content),
            3 => (X, &[ORG], T1, Kind::Content),
            4 => (X, &[], A, grant(Z, Role::Admin)),
            5 => (X, &[A], T1, grant(Z, Role::Write)),
            6 => (X, &[A, ORG], T2, grant(Z, Role::Admin)),
            7 => (Z, &[A], T1, Kind::Content),
            8 => (Z, &[], T1, Kind::Content),
            9 => (Z, &[], T2, Kind::Content),
            10 => (Z, &[], A, grant(H, Role::None)),
            11 => (X, &[], A, grant(H, Role::None)),
            12 => (X, &[], A, grant(B, Role::None)),
            13 => (X, &[A2], T1, Kind::Addendum { removal: self.r, list: mine(self, T1, false) }),
            14 => (X, &[], A, Kind::Vouch { removal: self.r, list: mine(self, A, true) }),
            15 => (Z, &[], A, grant(X, Role::Admin)),
            16 => (Z, &[], A, Kind::Vouch { removal: self.r, list: mine(self, A, true) }),
            _ => (X, &[], A, grant(N5, Role::None)),
        };
        let ts = if mv.kind == 18 { 20 } else { mv.ts };
        self.put((c.0, ts, c.1, c.2, c.3), mv.made, rng, true);
    }
    /// What a node holds at the final reading: its units' commits, the removals logged there,
    /// and their evidence.
    pub fn held(&self, n: Thing) -> Set {
        let all: Set = (0..self.w.commits.len()).collect();
        let unit: Set = all.iter().copied().filter(|i| self.recv[*i].contains_key(&n)).collect();
        evidence(&self.w, &unit, &all)
    }
    /// The node's view: `own_leaf`, a frontier's leaves only for the things it syncs
    /// (notes/account-membership-design.md §4); else also for every thing a held edge write is on.
    pub fn view(&self, n: Thing, own_leaf: bool) -> View {
        let held = self.held(n);
        let mut leaves = self.sync[&n].clone();
        if !own_leaf {
            leaves.extend(held.iter().filter(|&&i| self.w.edge_class(i)).map(|&i| self.w.commits[i].on));
        }
        View { held, leaves: Some(leaves), trust: [Some(self.r), self.r2].into_iter().flatten().collect() }
    }
    pub fn honest(&self) -> Vec<Thing> {
        [H, B, N5, K, RD, RD2].into_iter().filter(|n| self.sync.contains_key(n)).collect()
    }
    fn hostile(&self, i: Id) -> bool {
        self.w.commits[i].signer == Z || (self.w.commits[i].signer == X && self.made[i] > REMOVAL)
    }
}

/// Failures by property, and what is counted without being one.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub worlds: u64,
    pub fails: BTreeMap<&'static str, u64>,
    pub first: BTreeMap<&'static str, String>,
    /// A thief's write through the cut path showing by its own addendum along a path it still
    /// holds (`Rules::no_own_addendum` off).
    pub thief_addendum: u64,
    /// Checks made of each kind (a dead check shows as 0).
    pub checked: BTreeMap<&'static str, u64>,
}

impl crate::Tally for Stats {
    fn merge(&mut self, o: Stats) {
        self.worlds += o.worlds;
        self.thief_addendum += o.thief_addendum;
        for (k, n) in o.fails {
            *self.fails.entry(k).or_default() += n;
        }
        for (k, n) in o.checked {
            *self.checked.entry(k).or_default() += n;
        }
        for (k, s) in o.first {
            self.first.entry(k).or_insert(s);
        }
    }
}

impl Stats {
    pub fn failures(&self) -> u64 {
        self.fails.values().sum()
    }
    pub fn print(&self, name: &str) {
        println!("{name}: {} worlds, checks {:?}, failing checks {:?}; counted: thief's own addendum {}", self.worlds, self.checked, self.fails, self.thief_addendum);
        for (k, s) in &self.first {
            println!("FAIL {k}: {s}");
        }
    }
    fn fail(&mut self, prop: &'static str, m: &Sim, what: String) {
        *self.fails.entry(prop).or_default() += 1;
        self.first.entry(prop).or_insert_with(|| format!("{what}\n{:?}\n{}", m.setup, trace(m)));
    }
    fn count(&mut self, k: &'static str) {
        *self.checked.entry(k).or_default() += 1;
    }
}

pub fn trace(m: &Sim) -> String {
    let name = |t: &Thing| ["?", "H", "B", "X", "N5", "K", "Z", "N6", "?", "?", "A", "A2", "ORG", "T1", "T2"].get(*t as usize).copied().unwrap_or("?");
    let mut s = String::new();
    for (i, c) in m.w.commits.iter().enumerate() {
        let path: Vec<&str> = c.path.iter().map(name).collect();
        let kind = match &c.kind {
            Kind::Content => "content".to_string(),
            Kind::Edge { holder, role, frontier, .. } => format!("{} := {role:?} frontier {:?}", name(holder), frontier.values().flatten().collect::<Vec<_>>()),
            Kind::Addendum { removal, list } => format!("addendum against {removal} {list:?}"),
            Kind::Vouch { removal, list } => format!("vouch against {removal} {list:?}"),
        };
        let recv: Vec<String> = m.recv[i].iter().filter(|(n, _)| **n != X && **n != c.signer).map(|(n, t)| format!("{}@{t}", if *n == RD { "RD" } else if *n == RD2 { "RD2" } else { name(n) })).collect();
        s += &format!("  {i}: {} ts {} made {} [{}] on {}: {kind}; recv {}\n", name(&c.signer), c.ts, m.made[i], path.join(","), name(&c.on), recv.join(" "));
    }
    s
}

/// The properties, at every honest node's final reading. The oracle is the wanted behaviour
/// (issues/actors-one-mechanism.md: a removed node's role writes are kept on the same terms as
/// its content), computed from the story, never from a reading.
pub fn check(m: &Sim, rules: &Rules, own_leaf: bool, st: &mut Stats) {
    st.worlds += 1;
    let (w, s) = (&m.w, &m.setup);
    let nodes = m.honest();
    let rds: BTreeMap<Thing, (View, Reading)> = nodes
        .iter()
        .map(|&n| {
            let v = m.view(n, own_leaf);
            let rd = judge(w, rules, &v);
            (n, (v, rd))
        })
        .collect();
    let in_r = |i: Id| w.in_frontier(m.r, i);
    // who may vouch: A's admins by a chain not through X
    let mut admins = vec![H];
    if !(s.x_role == 1 && m.xrole.is_some_and(in_r)) {
        admins.push(B);
    }
    if m.g5.is_some_and(in_r) {
        admins.push(N5);
    }
    let saved = |g: Id| in_r(g) || admins.iter().any(|&n| m.sync.get(&n).is_some_and(|u| u.contains(&w.commits[g].on)) && m.got(g, n, REMOVAL) && !(n == B && s.b_offline && m.recv[m.r].get(&B) != Some(&SETTLE)));
    let regrant_n5 = s.regrant && s.n5 > 0;
    let x_removed_a2 = s.x_role == 2 && m.xrole.is_some();
    // B grants again only while it is an admin: X's demotion of it may stand
    let b_admin = !(s.x_role == 1 && m.xrole.is_some_and(saved));
    let stands = |n: Thing| match n {
        H | B => true,
        N5 => m.g5.is_some_and(saved) || regrant_n5,
        K => !x_removed_a2 && (!s.sharer_x || saved(m.gs) || (s.regrant && b_admin)),
        _ => false,
    };
    // whose addendum vouches: a writer holding write at its addendum's key (a later re-grant
    // makes the addendum valid, not its writer a holder then: spec/permissions.md §5.2 Addenda)
    let wrote = |n: Thing| match n {
        H | B => true,
        N5 => m.g5.is_some_and(saved),
        K => !x_removed_a2 && (!s.sharer_x || saved(m.gs)),
        _ => false,
    };
    for (&n, (v, rd)) in &rds {
        if rd.circle {
            st.fail("settles", m, format!("node {n}: the vouches do not settle"));
        }
        if !rd.stray.is_empty() {
            st.fail("stray", m, format!("node {n}: {:?} dropped by a write that does not apply", rd.stray));
        }
        if !rd.void.is_empty() {
            st.fail("removal", m, format!("node {n}: its trusted removal {:?} is void", rd.void));
        }
        // safety
        let x_keeps_a2 = s.x_a2 == 1;
        for &i in v.held.iter().filter(|&&i| m.hostile(i)) {
            st.count("safety");
            let c = &w.commits[i];
            let by_right = c.signer == X && x_keeps_a2 && c.path == [A2] && !w.edge_class(i);
            let by_thief = rd.valid.iter().any(|&a| m.hostile(a) && matches!(&w.commits[a].kind, Kind::Addendum { list, .. } if list.contains(&i)));
            if rd.shows(i) && !by_right {
                if by_thief && x_keeps_a2 && !rules.no_own_addendum {
                    st.thief_addendum += 1;
                } else {
                    st.fail("safety", m, format!("node {n}: the thief's commit {i} shows"));
                }
            }
        }
        for (e, r) in &rd.roles {
            let x_holds = e.0 == X && (e.1 == A || (e.1 == A2 && !x_keeps_a2));
            if *r > Role::None && (e.0 == Z || x_holds) {
                st.fail("safety", m, format!("node {n}: {e:?} ends {r:?}"));
            }
        }
        if x_removed_a2 && !s.regrant && m.xrole.is_some_and(saved) {
            st.count("removal kept");
            if rd.role(A2, T1) > Role::None {
                st.fail("removal kept", m, format!("node {n}: A2 holds on T1 again"));
            }
        }
        // liveness
        for &i in v.held.iter().filter(|&&i| !m.hostile(i)) {
            let c = &w.commits[i];
            let honest_now = c.signer != X;
            let want = match &c.kind {
                Kind::Content if honest_now => stands(c.signer) && !(c.signer == K && x_removed_a2),
                Kind::Content => {
                    in_r(i)
                        || [H, B, N5, K].iter().any(|&a| {
                            m.sync.get(&a).is_some_and(|u| u.contains(&c.on)) && wrote(a) && m.got(i, a, REMOVAL) && m.recv[m.r].contains_key(&a)
                        })
                }
                Kind::Edge { .. } if honest_now => c.signer == H || c.signer == K || i == m.gs || (m.made[i] == AFTER && b_admin),
                Kind::Edge { .. } => saved(i),
                _ => false,
            };
            if want {
                st.count("liveness");
                if !rd.shows(i) {
                    st.fail("liveness", m, format!("node {n}: commit {i} does not show"));
                }
            }
        }
    }
    // alike: two nodes read a commit they both hold in a unit they both sync alike
    for (&n, (vn, rn)) in &rds {
        for (&o, (vo, ro)) in rds.range(n + 1..) {
            for &i in vn.held.intersection(&vo.held) {
                if m.sync[&n].contains(&w.commits[i].on) && m.sync[&o].contains(&w.commits[i].on) {
                    st.count("alike");
                    if rn.shows(i) != ro.shows(i) {
                        st.fail("alike", m, format!("nodes {n} and {o} read commit {i} otherwise"));
                    }
                }
            }
        }
    }
}

pub fn random_world(rng: &mut Rng, rules: &Rules) -> Sim {
    let b = |rng: &mut Rng| rng.below(2) == 0;
    let s = Setup {
        h_t1: b(rng),
        h_t2: b(rng),
        b_offline: b(rng),
        sharer_x: b(rng),
        n5: rng.below(3) as u8,
        x_role: rng.below(4) as u8,
        x_role_seen: b(rng),
        x_a2: rng.below(3) as u8,
        b_side_x: rng.below(4) == 0,
        regrant: b(rng),
    };
    let moves: Vec<Move> = (0..rng.below(5)).map(|_| Move { kind: rng.below(MOVES), ts: 1 + rng.below(10) as u32, made: 7 + rng.below(4) as u32 }).collect();
    Sim::build(&s, rules, &moves, rng)
}

/// The small family: every setup, each with one move of the thief stamped before or after the
/// removal. `i` in `0..FAMILY`.
pub const FAMILY: usize = 2 * 2 * 2 * 2 * 3 * 4 * 2 * 3 * 2 * 2 * MOVES * 2;

pub fn family(mut i: usize, rules: &Rules) -> Sim {
    let mut take = |n: usize| {
        let v = i % n;
        i /= n;
        v
    };
    let s = Setup {
        h_t1: take(2) == 1,
        h_t2: take(2) == 1,
        b_offline: take(2) == 1,
        sharer_x: take(2) == 1,
        n5: take(3) as u8,
        x_role: take(4) as u8,
        x_role_seen: take(2) == 1,
        x_a2: take(3) as u8,
        b_side_x: take(2) == 1,
        regrant: take(2) == 1,
    };
    let mv = Move { kind: take(MOVES), ts: if take(2) == 1 { 3 } else { 8 }, made: 7 };
    Sim::build(&s, rules, &[mv], &mut Rng(0))
}

/// `-- N paths` (random worlds under the fixed rules), `-- 0 paths-exh` (the small family),
/// `-- N paths-design` (random worlds under the notes' rules: the failing checks are the
/// findings). Returns the failing checks.
pub fn run(samples: u64, mode: &str) -> u64 {
    let (rules, own_leaf) = if mode == "paths-design" { (Rules::design(), true) } else { (Rules::fixed(), false) };
    let st = crate::on_every_core(|th, threads, st: &mut Stats| {
        if mode == "paths-exh" {
            for i in (th..FAMILY).step_by(threads) {
                check(&family(i, &rules), &rules, own_leaf, st);
            }
        } else {
            let mut rng = Rng::thread(0x9a7b, th);
            for _ in 0..samples / threads as u64 {
                check(&random_world(&mut rng, &rules), &rules, own_leaf, st);
            }
        }
    });
    st.print(mode);
    st.failures()
}

#[cfg(test)]
mod tests;
