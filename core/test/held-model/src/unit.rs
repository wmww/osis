//! Greenfield model of the sync unit as one independent thing and its dependents
//! (notes/sync-unit-scope.md, notes/sync-unit-design.md §2-§4, §6), beside `closure`, which models
//! the readable-closure unit the spec states today and which the sync differential reads. Plain
//! data and pure functions; properties in tests/it/spec_unit.rs, readings and findings in
//! notes/closure-model.md (The unit model).
//!
//! Readings (where the notes leave a choice, the simplest):
//! - A unit is an independent thing H and every thing whose mint-admin chain first reaches an
//!   independent thing at H (`View::ind`), whatever the strongs: S(H) carries all of them.
//! - A node entering a unit holds the unit whole, so "the units a reader's closure needs" are
//!   whole units (the design's "what its strongs reach there" read as the unit).
//! - Grants: holders and targets are independent things; a holder's role on a target is the best
//!   chain of grants, the lowest role along it (no keyless grants: cycles of grants are allowed
//!   and change nothing).
//! - A role commit on H naming holder W travels under S(H) and S(W) (Bootstrap, the design's
//!   shrunk "role changes travel"), with H's boxes to W: a node reading S(W) gets H's read secret
//!   when W holds read on H. `Secrets::Chain` keeps today's rule as a variant (also under the unit
//!   of every thing whose read reaches W); `Secrets::Steps` puts read secrets in steps' entry
//!   boxes too (Tess kept them out in this change).
//! - Sync secrets reach holders through steps: H's step lists every holder with sync or above,
//!   with an entry box, so a node holding W's sync secret holds H's while W holds sync on H, at
//!   any depth, holding no unit on the way. Steps are current (an admin issued one after every
//!   role change): credentials are judged on every commit written.
//! - Member blobs of S(G) (`View::members`): one per independent H ≠ G that a live strong from a
//!   thing of G's unit targets (H or a dependent of H), where G holds sync or above on H
//!   (`Member::Role`, the design) or for every such H (`Member::Any`, a variant). Records are
//!   known: whoever holds a strong knows its target's independent and sync ID.
//!
//! Left out: promotion (brief 2: `Kind` can flip by a commit later; `View` already derives kinds
//! per holding), validity, keyless grants, epochs and rotation, public things, caps, tickets other
//! than a root's, the wire.
use crate::closure::{Kind, Role, Set, C, T};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Add(T),
    /// Removes these adds (on the same thing).
    Remove(BTreeSet<C>),
    /// Sets the role record entry naming this holder on the commit's thing (`None`: removed).
    Role(T, Option<Role>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub on: T,
    pub op: Op,
}

/// Which independent things a unit lists as members.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Member {
    /// The design: those G holds sync or above on.
    Role,
    /// Every independent thing a strong from G's unit targets.
    Any,
}

/// Where a node finds read secrets of other units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Secrets {
    /// The design: H's box to W in S(H) and S(W) only.
    Holder,
    /// Today's rule kept: also under S(F) for each F holding read on W.
    Chain,
    /// Read secrets in steps' entry boxes, as sync secrets.
    Steps,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rules {
    pub member: Member,
    pub secrets: Secrets,
}

impl Rules {
    pub const DESIGN: Rules = Rules { member: Member::Role, secrets: Secrets::Holder };
}

/// What a set of commits says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    pub kinds: Vec<Kind>,
    pub grants: BTreeMap<(T, T), Role>,
    pub strongs: BTreeSet<(T, T)>,
}

impl View {
    /// The view of `held` (indices into `all`): adds no held remove names, role entries last
    /// commit wins.
    pub fn of(kinds: &[Kind], all: &[Commit], held: &BTreeSet<C>) -> View {
        let removed: BTreeSet<C> = held
            .iter()
            .filter_map(|&c| match &all[c].op {
                Op::Remove(r) => Some(r.iter().copied()),
                _ => None,
            })
            .flatten()
            .collect();
        let mut v = View { kinds: kinds.to_vec(), grants: BTreeMap::new(), strongs: BTreeSet::new() };
        for &c in held {
            match all[c].op {
                Op::Add(to) if !removed.contains(&c) => {
                    v.strongs.insert((all[c].on, to));
                }
                Op::Role(g, Some(r)) => {
                    v.grants.insert((g, all[c].on), r);
                }
                Op::Role(g, None) => {
                    v.grants.remove(&(g, all[c].on));
                }
                _ => {}
            }
        }
        v
    }
    pub fn all(kinds: &[Kind], all: &[Commit]) -> View {
        View::of(kinds, all, &(0..all.len()).collect())
    }
    /// The independent thing whose unit holds `x`.
    pub fn ind(&self, mut x: T) -> T {
        while let Kind::Dependent(a) = self.kinds[x] {
            x = a;
        }
        x
    }
    pub fn independents(&self) -> Set {
        (0..self.kinds.len()).filter(|&x| self.kinds[x] == Kind::Independent).collect()
    }
    pub fn unit(&self, h: T) -> Set {
        (0..self.kinds.len()).filter(|&x| self.ind(x) == h).collect()
    }
    /// `g`'s role on each independent thing: the best chain of grants, the lowest role along it.
    pub fn roles_from(&self, g: T) -> BTreeMap<T, Role> {
        let mut best = BTreeMap::from([(g, Role::Admin)]);
        loop {
            let mut changed = false;
            for (&(a, b), &r) in &self.grants {
                if let Some(&ra) = best.get(&a) {
                    let v = ra.min(r);
                    if best.get(&b).is_none_or(|&o| o < v) {
                        best.insert(b, v);
                        changed = true;
                    }
                }
            }
            if !changed {
                return best;
            }
        }
    }
    /// The things reached from `from` by grants of at least `r`, `from` included.
    pub fn reach_by(&self, from: &Set, r: Role) -> Set {
        let mut out = from.clone();
        loop {
            let n = out.len();
            for (&(a, b), &g) in &self.grants {
                if g >= r && out.contains(&a) {
                    out.insert(b);
                }
            }
            if out.len() == n {
                return out;
            }
        }
    }
    /// The independent things other than `g` that a strong from a thing of `g`'s unit enters:
    /// its target's unit.
    pub fn refs(&self, g: T) -> Set {
        self.strongs.iter().filter(|&&(x, y)| self.ind(x) == g && self.ind(y) != g).map(|&(_, y)| self.ind(y)).collect()
    }
    /// S(g)'s member blobs: the targets its required set lists.
    pub fn members(&self, g: T, m: Member) -> Set {
        let mut out = self.refs(g);
        if m == Member::Role {
            let roles = self.roles_from(g);
            out.retain(|h| roles.contains_key(h));
        }
        out
    }
    /// The units a role commit on `h` naming holder `w` travels under (with `h`'s boxes to `w`).
    pub fn grant_units(&self, w: T, h: T, s: Secrets) -> Set {
        let mut u = Set::from([h, w]);
        if s == Secrets::Chain {
            u.extend(self.independents().into_iter().filter(|&f| self.roles_from(f).get(&w).is_some_and(|&r| r >= Role::Read)));
        }
        u
    }
    /// The units commit `c` goes under.
    pub fn under(&self, c: &Commit, s: Secrets) -> Set {
        match c.op {
            Op::Role(w, _) => self.grant_units(w, c.on, s),
            _ => Set::from([self.ind(c.on)]),
        }
    }
}

/// The units a node enters, read and kept unread.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entered {
    pub read: Set,
    pub unread: Set,
}

impl Entered {
    pub fn units(&self) -> Set {
        self.read.union(&self.unread).copied().collect()
    }
}

/// A reader of `root` (notes/sync-unit-design.md §4): it holds `root`'s read secret and no other
/// ticket. Within a unit it read-enters, at every strong into another unit H, it enters H read by
/// a read secret held for H, else kept unread by a sync secret, else not; a unit kept unread is
/// followed by its member blobs (`listed`), by the same choice. Read secrets come from boxes in
/// units entered read (`Secrets::Holder`, `Chain`) or from steps (`Steps`); sync secrets from
/// steps. The least fixpoint: the walk again from scratch while the read secrets grow.
pub fn reader(v: &View, root: T, r: Rules, listed: &dyn Fn(T) -> Set) -> Entered {
    let mut rs = Set::from([root]);
    loop {
        let ss = v.reach_by(&rs, Role::Sync);
        let e = walk(&Set::from([root]), &rs, &ss, &|g| v.refs(g), listed);
        let next = match r.secrets {
            Secrets::Steps => v.reach_by(&Set::from([root]), Role::Read),
            _ => {
                let mut k = rs.clone();
                loop {
                    let n = k.len();
                    for (&(w, h), &g) in &v.grants {
                        if g >= Role::Read && k.contains(&w) && !v.grant_units(w, h, r.secrets).is_disjoint(&e.read) {
                            k.insert(h);
                        }
                    }
                    if k.len() == n {
                        break k;
                    }
                }
            }
        };
        if next == rs {
            return e;
        }
        rs = next;
    }
}

/// The walk from `roots` (entered read where `rs` holds them, else kept unread): a unit entered
/// read is left by `out_read`, one kept unread by `out_unread`; a target is entered read where
/// `rs` holds it, else kept unread where `ss` does.
fn walk(roots: &Set, rs: &Set, ss: &Set, out_read: &dyn Fn(T) -> Set, out_unread: &dyn Fn(T) -> Set) -> Entered {
    let mut e = Entered::default();
    let mut todo: Vec<T> = roots.iter().copied().collect();
    let mut seen = roots.clone();
    while let Some(g) = todo.pop() {
        let out = if rs.contains(&g) {
            e.read.insert(g);
            out_read(g)
        } else {
            e.unread.insert(g);
            out_unread(g)
        };
        for h in out {
            if (rs.contains(&h) || ss.contains(&h)) && seen.insert(h) {
                todo.push(h);
            }
        }
    }
    e
}

/// How a node keeping units unread decides what it keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keep {
    /// The design: reachability from its roots over the member blobs of kept units, entering a
    /// listed unit only by a credential it holds.
    Reach,
    /// Negative control: every listed unit, credential or not.
    Listed,
    /// Negative control: today's rule, the walk stops at a unit kept unread.
    Stop,
}

/// A node keeping `roots` unread (it holds their sync secrets): the units it keeps.
pub fn keeper(v: &View, roots: &Set, keep: Keep, listed: &dyn Fn(T) -> Set) -> Set {
    let ss = match keep {
        Keep::Listed => v.independents(),
        _ => v.reach_by(roots, Role::Sync),
    };
    let none = |_| Set::new();
    let out: &dyn Fn(T) -> Set = if keep == Keep::Stop { &none } else { listed };
    walk(roots, &Set::new(), &ss, &none, out).unread
}

// ---- Stores, writers and keepers over time ----

/// Nodes holding commits and visiting the stores of the units they sync, where member blobs live
/// (store operations: a log adds a blob, a delete removes one, no tombstone).
#[derive(Clone, Debug)]
pub struct Net {
    pub kinds: Vec<Kind>,
    pub commits: Vec<Commit>,
    /// Per writer: the units it syncs (reads and writes) and the commits it holds.
    pub syncs: Vec<Set>,
    pub has: Vec<BTreeSet<C>>,
    /// Member blobs: (unit, blob ID) -> listed unit.
    pub store: BTreeMap<(T, usize), T>,
    pub next_id: usize,
    pub rules: Rules,
    /// Of two blobs for one member the lower ID stays (off: a negative control).
    pub lowest_wins: bool,
    /// A writer deletes blobs outside the required set as it sees it (off: a negative control).
    pub deletes: bool,
    /// Per keeper: its roots and what it keeps (by `pass`).
    pub roots: Vec<Set>,
    pub kept: Vec<Set>,
    /// Store operations and keeper changes.
    pub churn: usize,
}

impl Net {
    pub fn new(kinds: Vec<Kind>, rules: Rules, syncs: Vec<Set>, roots: Vec<Set>) -> Net {
        let w = syncs.len();
        Net {
            kinds,
            commits: vec![],
            syncs,
            has: vec![BTreeSet::new(); w],
            store: BTreeMap::new(),
            next_id: 0,
            rules,
            lowest_wins: true,
            deletes: true,
            kept: roots.clone(),
            roots,
            churn: 0,
        }
    }
    pub fn truth(&self) -> View {
        View::all(&self.kinds, &self.commits)
    }
    /// A commit written (held by nobody yet: `deliver` hands it out).
    pub fn write(&mut self, c: Commit) -> C {
        self.commits.push(c);
        self.commits.len() - 1
    }
    /// Hands `c` to writer `w` if a unit it syncs carries it (by the commits written so far).
    pub fn deliver(&mut self, w: usize, c: C) {
        if !self.truth().under(&self.commits[c], self.rules.secrets).is_disjoint(&self.syncs[w]) {
            self.has[w].insert(c);
        }
    }
    pub fn deliver_all(&mut self) {
        for w in 0..self.has.len() {
            for c in 0..self.commits.len() {
                self.deliver(w, c);
            }
        }
    }
    pub fn view(&self, w: usize) -> View {
        View::of(&self.kinds, &self.commits, &self.has[w])
    }
    pub fn listed(&self, g: T) -> Set {
        self.store.iter().filter(|(&(u, _), _)| u == g).map(|(_, &h)| h).collect()
    }
    /// What writer `w` would do at the stores of the units it syncs, given the store as it is:
    /// log a blob for each member it requires that none lists; delete each blob listing a unit
    /// outside what it requires, and each but the lowest of several for one member.
    pub fn look(&self, w: usize) -> (Vec<(T, T)>, Vec<(T, usize)>) {
        let v = self.view(w);
        let (mut logs, mut dels) = (vec![], vec![]);
        for &g in &self.syncs[w] {
            let req = v.members(g, self.rules.member);
            let mut by: BTreeMap<T, Vec<usize>> = BTreeMap::new();
            for (&(u, id), &h) in &self.store {
                if u == g {
                    by.entry(h).or_default().push(id);
                }
            }
            for &h in &req {
                if !by.contains_key(&h) {
                    logs.push((g, h));
                }
            }
            for (h, ids) in by {
                if !req.contains(&h) {
                    if self.deletes {
                        dels.extend(ids.iter().map(|&id| (g, id)));
                    }
                } else if self.lowest_wins {
                    dels.extend(ids[1..].iter().map(|&id| (g, id)));
                }
            }
        }
        (logs, dels)
    }
    pub fn act(&mut self, (logs, dels): (Vec<(T, T)>, Vec<(T, usize)>)) {
        for (g, h) in logs {
            self.store.insert((g, self.next_id), h);
            self.next_id += 1;
            self.churn += 1;
        }
        for k in dels {
            if self.store.remove(&k).is_some() {
                self.churn += 1;
            }
        }
    }
    pub fn visit(&mut self, w: usize) {
        let a = self.look(w);
        self.act(a);
    }
    /// Every writer looks at the same store, then all act.
    pub fn visit_together(&mut self) {
        let acts: Vec<_> = (0..self.has.len()).map(|w| self.look(w)).collect();
        for a in acts {
            self.act(a);
        }
    }
    /// Keeper `k` at the stores of what it keeps: credentials by steps over every commit written;
    /// `Keep::Reach` recomputes from its roots, `count` keeps a unit while a kept unit lists it
    /// (a negative control: the count of referrers).
    pub fn pass(&mut self, k: usize, count: bool) {
        let t = self.truth();
        let next = if count {
            let ss = t.reach_by(&self.roots[k], Role::Sync);
            let mut kept = self.kept[k].clone();
            loop {
                let mut n: Set = kept.iter().flat_map(|&g| self.listed(g)).filter(|h| ss.contains(h)).collect();
                n.extend(&self.roots[k]);
                n.retain(|h| self.roots[k].contains(h) || kept.iter().any(|&g| self.listed(g).contains(h)));
                if n == kept {
                    break kept;
                }
                kept = n;
            }
        } else {
            keeper(&t, &self.roots[k], Keep::Reach, &|g| self.listed(g))
        };
        self.churn += self.kept[k].symmetric_difference(&next).count();
        self.kept[k] = next;
    }
    /// Every writer visits (together), then every keeper passes, until a round changes nothing:
    /// the rounds it took, or `None` within `max`.
    pub fn settle(&mut self, max: usize, count: bool) -> Option<usize> {
        for i in 1..=max {
            let before = self.churn;
            self.visit_together();
            for k in 0..self.roots.len() {
                self.pass(k, count);
            }
            if self.churn == before {
                return Some(i);
            }
        }
        None
    }
    /// Where the stores and keepers differ from what every commit written says: per unit the
    /// blobs it should list and does not, lists and should not, or lists twice; per keeper the
    /// units it should keep and does not or the other way round.
    pub fn wrong(&self) -> Vec<String> {
        let t = self.truth();
        let mut out = vec![];
        for g in t.independents() {
            let want = t.members(g, self.rules.member);
            let got: Vec<T> = self.store.iter().filter(|(&(u, _), _)| u == g).map(|(_, &h)| h).collect();
            let gs: Set = got.iter().copied().collect();
            if gs != want || got.len() != gs.len() {
                out.push(format!("S({g}) lists {got:?}, wants {want:?}"));
            }
        }
        for k in 0..self.roots.len() {
            let want = keeper(&t, &self.roots[k], Keep::Reach, &|g| t.members(g, self.rules.member));
            if self.kept[k] != want {
                out.push(format!("keeper {k} keeps {:?}, wants {want:?}", self.kept[k]));
            }
        }
        out
    }
}
