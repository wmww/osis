//! Greenfield model of the sync unit as one independent thing and the dependents it reaches
//! (notes/sync-unit-scope.md, notes/sync-unit-design.md §2-§4, §6), beside `closure`, which models
//! the readable-closure unit the spec states today and which the sync differential reads. Plain
//! data and pure functions; properties in tests/it/spec_unit.rs, readings, counts and findings in
//! notes/closure-model.md (The unit model).
//!
//! Readings (where the notes leave a choice, the simplest):
//! - A unit (`Unit::Reach`) is an independent thing H and the dependents of H (mint-admin chain
//!   first meeting an independent thing at H) reached from H by strongs whose sources are in the
//!   unit. A dependent outside it is in no unit: nobody holds it and its strongs list nothing.
//! - Grants are between independent things. H's step lists H and every thing with a direct grant
//!   on H (every grant here is sync or above); a node holds the sync secret of each unit it entered
//!   and of nothing else. H's read secret comes from H's boxes to W, under S(W) (Bootstrap), to a
//!   node reading W.
//! - Member blobs (`Blob`): S(G) requires one per thing outside G's unit that a live strong from
//!   G's unit targets, naming the target's independent's unit (`Member::Target`). A writer names a
//!   target only by `View::can_name`: it reads the target's unit (holding a dependent target's
//!   record chain there), or the target is independent and it reads a unit whose independent
//!   holds a direct grant on it. Rules 1-3 of design §2 judge blobs at stores (`Net::look`).
//! - The walk (`walk`), one function for readers and nodes keeping units unread: a unit named by a
//!   blob of a followed unit is entered while the node holds a secret its step lists, read when the
//!   node reads a unit with a direct read grant on it. A reader also names the targets of the units
//!   it reads by its own `can_name` (design §3). With `Paths::Via` a blob carries holder chains
//!   (design §4); their units are entered for keys and not followed.
//! - Steps are current (an admin issued one after every role change).
//!
//! Left out: promotion (brief 2: kinds are per `View`, so a promotion can flip one), validity,
//! keyless grants, epochs and rotation (no blob is sealed per epoch), public things, caps,
//! tickets other than a root's, the wire.
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

/// Which things a unit carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    /// The design (§6): H and the dependents of H reached from H through things of the unit.
    Reach,
    /// Control: every dependent of H, reached or not.
    All,
    /// Control: also every dependent of H a strong the node holds targets from another unit.
    Held,
}

/// Which targets a unit lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Member {
    /// The design (§2): every thing outside the unit a live strong of the unit targets.
    Target,
    /// Control: only those whose independent the unit's thing holds sync or above on, any chain.
    Role,
}

/// How a named unit is entered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enter {
    /// The design: by the secret of a thing on its step, held through a unit entered.
    Steps,
    /// Control: by sync secrets reached through grants at any depth, units on the way unentered.
    Deep,
    /// Control: with no secret.
    Free,
}

/// Key paths (design §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Paths {
    /// The plan's first build.
    None,
    /// A blob carries the holder chains from G to the target's unit where G holds no direct grant.
    Via,
    /// Control: path units entered as listed units, followed by their blobs.
    Followed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rules {
    pub unit: Unit,
    pub member: Member,
    pub enter: Enter,
    pub paths: Paths,
    /// Control off: the walk stops at a unit kept unread (today's keeper).
    pub follow_unread: bool,
}

impl Rules {
    pub const DESIGN: Rules =
        Rules { unit: Unit::Reach, member: Member::Target, enter: Enter::Steps, paths: Paths::None, follow_unread: true };
    pub const VIA: Rules = Rules { paths: Paths::Via, ..Rules::DESIGN };
}

/// A member blob of some S(G): the target thing (its tag), the unit it names and its key paths.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Blob {
    pub tag: T,
    pub unit: T,
    pub paths: BTreeSet<Vec<T>>,
}

impl Blob {
    /// Rule 2's order: names the same unit and every path of `o`.
    pub fn covers(&self, o: &Blob) -> bool {
        self.tag == o.tag && self.unit == o.unit && self.paths.is_superset(&o.paths)
    }
}

/// What a set of commits says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    pub kinds: Vec<Kind>,
    pub grants: BTreeMap<(T, T), Role>,
    pub strongs: BTreeSet<(T, T)>,
    /// The unit each thing is in, by the view's `Unit` rule.
    pub in_unit: Vec<Option<T>>,
}

impl View {
    /// The view of `held` (indices into `all`): adds no held remove names, role entries last
    /// commit wins.
    pub fn of(kinds: &[Kind], all: &[Commit], held: &BTreeSet<C>, unit: Unit) -> View {
        let removed: BTreeSet<C> = held
            .iter()
            .filter_map(|&c| match &all[c].op {
                Op::Remove(r) => Some(r.iter().copied()),
                _ => None,
            })
            .flatten()
            .collect();
        let mut v = View { kinds: kinds.to_vec(), grants: BTreeMap::new(), strongs: BTreeSet::new(), in_unit: vec![] };
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
        v.in_unit = v.units_by(unit);
        v
    }
    pub fn all(kinds: &[Kind], all: &[Commit], unit: Unit) -> View {
        View::of(kinds, all, &(0..all.len()).collect(), unit)
    }
    fn units_by(&self, u: Unit) -> Vec<Option<T>> {
        let n = self.kinds.len();
        let dep = |x: T| self.kinds[x] != Kind::Independent;
        let mut out: Vec<Option<T>> = (0..n).map(|x| if !dep(x) || u == Unit::All { Some(self.ind(x)) } else { None }).collect();
        if u == Unit::Held {
            for &(a, b) in &self.strongs {
                if dep(b) && self.ind(a) != self.ind(b) {
                    out[b] = Some(self.ind(b));
                }
            }
        }
        loop {
            let mut changed = false;
            for &(a, b) in &self.strongs {
                if out[b].is_none() && out[a] == Some(self.ind(b)) {
                    out[b] = out[a];
                    changed = true;
                }
            }
            if !changed {
                return out;
            }
        }
    }
    /// The independent thing whose unit a dependent `x` belongs to by its mint-admin chain.
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
        (0..self.kinds.len()).filter(|&x| self.in_unit[x] == Some(h)).collect()
    }
    /// `g`'s role on each independent thing: the best chain of grants, the lowest role along it.
    pub fn roles_from(&self, g: T) -> BTreeMap<T, Role> {
        self.roles_through(g, &|_| true)
    }
    /// The same over chains whose holders (every thing but the last) satisfy `via`.
    pub fn roles_through(&self, g: T, via: &dyn Fn(T) -> bool) -> BTreeMap<T, Role> {
        let mut best = BTreeMap::from([(g, Role::Admin)]);
        loop {
            let mut changed = false;
            for (&(a, b), &r) in &self.grants {
                if let Some(&ra) = best.get(&a).filter(|_| via(a)) {
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
    /// The things outside `g`'s unit a live strong from a thing of the unit targets.
    pub fn targets(&self, g: T, m: Member) -> Set {
        let mut out: Set =
            self.strongs.iter().filter(|&&(a, b)| self.in_unit[a] == Some(g) && self.in_unit[b] != Some(g)).map(|&(_, b)| b).collect();
        if m == Member::Role {
            let roles = self.roles_from(g);
            out.retain(|&x| roles.contains_key(&self.ind(x)));
        }
        out
    }
    /// H's step: H and every thing with a direct grant on H.
    pub fn on_step(&self, w: T, h: T) -> bool {
        w == h || self.grants.contains_key(&(w, h))
    }
    /// Whether a node reading the units `reads` holds the name of `x`'s unit.
    pub fn can_name(&self, reads: &Set, x: T) -> bool {
        let h = self.ind(x);
        if x == h {
            reads.contains(&h) || reads.iter().any(|&w| self.grants.contains_key(&(w, h)))
        } else {
            reads.contains(&h) && self.in_unit[x] == Some(h)
        }
    }
    /// The key paths from `g` to `h` a node reading `reads` sees: the holders of every chain of
    /// grants whose grants it sees (one shows in the holder's unit and the target's), where `g`
    /// holds no direct grant on `h`.
    pub fn chains(&self, g: T, h: T, reads: &Set) -> BTreeSet<Vec<T>> {
        let mut out = BTreeSet::new();
        if self.grants.contains_key(&(g, h)) || g == h {
            return out;
        }
        let shown = |a: T, b: T| self.grants.contains_key(&(a, b)) && (reads.contains(&a) || reads.contains(&b));
        let mut stack = vec![vec![g]];
        while let Some(p) = stack.pop() {
            let last = *p.last().unwrap();
            if p.len() > 1 && shown(last, h) {
                out.insert(p[1..].to_vec());
            }
            for w in self.independents() {
                if w != h && !p.contains(&w) && shown(last, w) {
                    let mut q = p.clone();
                    q.push(w);
                    stack.push(q);
                }
            }
        }
        out
    }
    /// The blob a node reading `reads` logs (or names for itself) for target `x` of S(g).
    pub fn blob(&self, g: T, x: T, reads: &Set, paths: Paths) -> Option<Blob> {
        if !self.can_name(reads, x) {
            return None;
        }
        let h = self.ind(x);
        let paths = if paths == Paths::None { BTreeSet::new() } else { self.chains(g, h, reads) };
        Some(Blob { tag: x, unit: h, paths })
    }
    /// The units commit `c` goes under: a role commit under its thing's and its holder's; any
    /// other under its thing's unit, if any.
    pub fn under(&self, c: &Commit) -> Set {
        match c.op {
            Op::Role(w, _) => Set::from([c.on, w]),
            _ => self.in_unit[c.on].into_iter().collect(),
        }
    }
}

/// The units a node entered: read, kept unread, and of those the ones entered for keys only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entered {
    pub read: Set,
    pub unread: Set,
    pub keys: Set,
}

impl Entered {
    pub fn units(&self) -> Set {
        self.read.union(&self.unread).copied().collect()
    }
    /// The units entered as members, followed by their blobs.
    pub fn followed(&self) -> Set {
        self.units().difference(&self.keys).copied().collect()
    }
}

/// The walk of a node that reads `read_roots` and keeps `unread_roots` unread (design §3): the
/// least fixpoint of entering each unit named by a blob of a followed unit (`listed`, and with
/// `resolve` what the node names itself for the units it reads) while a unit it entered is on that
/// unit's step; read where a unit it reads holds a direct read grant on it.
pub fn walk(v: &View, read_roots: &Set, unread_roots: &Set, r: Rules, listed: &dyn Fn(T) -> Vec<Blob>, resolve: bool) -> Entered {
    let roots: Set = read_roots.union(unread_roots).copied().collect();
    let deep = v.reach_by(&roots, Role::Sync);
    let start = Entered { read: read_roots.clone(), unread: unread_roots.difference(read_roots).copied().collect(), keys: Set::new() };
    let mut e = start.clone();
    loop {
        let (mut fol, mut key) = (Set::new(), Set::new());
        for g in e.followed() {
            if !r.follow_unread && !e.read.contains(&g) {
                continue;
            }
            let mut bs = listed(g);
            if resolve && e.read.contains(&g) {
                bs.extend(v.targets(g, r.member).into_iter().filter_map(|x| v.blob(g, x, &e.read, r.paths)));
            }
            for b in bs {
                fol.insert(b.unit);
                key.extend(b.paths.into_iter().flatten());
            }
        }
        if r.paths == Paths::Followed {
            fol.append(&mut key);
        }
        key.retain(|h| !fol.contains(h));
        let held = e.units();
        let mut next = start.clone();
        for &h in fol.iter().chain(&key) {
            if roots.contains(&h) {
                continue;
            }
            let enters = match r.enter {
                Enter::Steps => held.iter().any(|&w| v.on_step(w, h)),
                Enter::Deep => deep.contains(&h),
                Enter::Free => true,
            };
            if !enters {
                continue;
            }
            if e.read.iter().any(|&w| v.grants.get(&(w, h)).is_some_and(|&g| g >= Role::Read)) {
                next.read.insert(h);
            } else {
                next.unread.insert(h);
            }
            if key.contains(&h) {
                next.keys.insert(h);
            }
        }
        if next == e {
            return e;
        }
        e = next;
    }
}

/// Who has logged the member blobs of a static world.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Writers {
    /// A writer seeing every grant and reading every unit: each target listed, every path.
    Full,
    /// S(G)'s only writer is a reader of G alone, walking its own closure.
    Own,
}

/// Settled member blobs of a static world: per unit, the blobs its writers logged.
pub fn listing(v: &View, r: Rules, w: Writers) -> BTreeMap<T, Vec<Blob>> {
    let ind = v.independents();
    let mut l: BTreeMap<T, Vec<Blob>> = BTreeMap::new();
    loop {
        let mut n = BTreeMap::new();
        for &g in &ind {
            let reads = match w {
                Writers::Full => ind.clone(),
                Writers::Own => walk(v, &Set::from([g]), &Set::new(), r, &|u| l.get(&u).cloned().unwrap_or_default(), true).read,
            };
            let bs: Vec<Blob> = v.targets(g, r.member).into_iter().filter_map(|x| v.blob(g, x, &reads, r.paths)).collect();
            n.insert(g, bs);
        }
        if n == l || w == Writers::Full {
            return n;
        }
        l = n;
    }
}

// ---- Stores, writers and keepers over time ----

/// What a writer does at the stores of the units it syncs.
#[derive(Clone, Debug, Default)]
pub struct Acts {
    pub logs: Vec<(T, Blob)>,
    pub dels: Vec<(T, usize)>,
    pub body_logs: Vec<(T, C)>,
    pub body_dels: Vec<(T, C)>,
}

/// Nodes holding commits and visiting the stores of the units they sync, where member blobs and
/// body entries live (store operations: a log adds an entry, a delete removes one, no tombstone).
#[derive(Clone, Debug)]
pub struct Net {
    pub kinds: Vec<Kind>,
    pub commits: Vec<Commit>,
    /// Per writer: the units it reads and writes, and the commits it holds.
    pub syncs: Vec<Set>,
    pub has: Vec<BTreeSet<C>>,
    /// Member blobs: (unit, blob ID) -> blob.
    pub store: BTreeMap<(T, usize), Blob>,
    /// Body entries: (unit, commit) for strong adds and removes.
    pub bodies: BTreeSet<(T, C)>,
    pub next_id: usize,
    pub rules: Rules,
    /// Of two blobs for one target naming the same, the lower ID stays (off: a negative control).
    pub lowest_wins: bool,
    /// A writer deletes entries outside the required set as it sees it (off: a negative control).
    pub deletes: bool,
    /// Control: a writer also deletes blobs for targets it cannot name.
    pub delete_unnamed: bool,
    /// Per keeper: its roots (kept unread) and what it keeps (by `pass`).
    pub roots: Vec<Set>,
    pub kept: Vec<Entered>,
    /// Store operations and keeper changes; blob operations alone.
    pub churn: usize,
    pub blob_ops: usize,
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
            bodies: BTreeSet::new(),
            next_id: 0,
            rules,
            lowest_wins: true,
            deletes: true,
            delete_unnamed: false,
            kept: roots.iter().map(|r| Entered { unread: r.clone(), ..Entered::default() }).collect(),
            roots,
            churn: 0,
            blob_ops: 0,
        }
    }
    pub fn truth(&self) -> View {
        View::all(&self.kinds, &self.commits, self.rules.unit)
    }
    /// A commit written (held by nobody yet: `deliver` hands it out).
    pub fn write(&mut self, c: Commit) -> C {
        self.commits.push(c);
        self.commits.len() - 1
    }
    /// Hands `c` to writer `w` if a unit it syncs carries it (by the commits written so far).
    pub fn deliver(&mut self, w: usize, c: C) {
        if !self.truth().under(&self.commits[c]).is_disjoint(&self.syncs[w]) {
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
        View::of(&self.kinds, &self.commits, &self.has[w], self.rules.unit)
    }
    pub fn listed(&self, g: T) -> Vec<Blob> {
        self.store.iter().filter(|(&(u, _), _)| u == g).map(|(_, b)| b.clone()).collect()
    }
    fn body(&self, c: C) -> bool {
        !matches!(self.commits[c].op, Op::Role(..))
    }
    /// What writer `w` would do at the stores of the units it syncs, given the stores as they are
    /// (design §2, rules 1-3, and the body entries of its view of each unit).
    pub fn look(&self, w: usize) -> Acts {
        let v = self.view(w);
        let reads = &self.syncs[w];
        let mut a = Acts::default();
        // Rule 3: the unit named is judged by a writer that can name the target; a path stands by
        // this writer's data unless a grant on it whose data it holds (it reads the holder's or
        // the target's unit) is absent.
        let judged_wrong = |g: T, b: &Blob| {
            (v.can_name(reads, b.tag) && b.unit != v.ind(b.tag))
                || b.paths.iter().any(|p| {
                    let mut hops: Vec<T> = vec![g];
                    hops.extend(p);
                    hops.push(b.unit);
                    hops.windows(2).any(|s| (reads.contains(&s[0]) || reads.contains(&s[1])) && !v.grants.contains_key(&(s[0], s[1])))
                })
        };
        for &g in reads {
            let targets = v.targets(g, self.rules.member);
            let mut live: Vec<(usize, &Blob)> = vec![];
            for (&(u, id), b) in &self.store {
                if u != g {
                    continue;
                }
                let gone = if !targets.contains(&b.tag) {
                    self.deletes
                } else {
                    judged_wrong(g, b) || (self.delete_unnamed && !v.can_name(reads, b.tag))
                };
                if gone {
                    a.dels.push((g, id));
                } else {
                    live.push((id, b));
                }
            }
            for &(id, b) in &live {
                if live.iter().any(|&(o, ob)| o != id && ob.covers(b) && (ob.paths != b.paths || (self.lowest_wins && o < id))) {
                    a.dels.push((g, id));
                }
            }
            for x in targets {
                if let Some(mine) = v.blob(g, x, reads, self.rules.paths) {
                    if !live.iter().any(|(_, b)| b.covers(&mine)) {
                        a.logs.push((g, mine));
                    }
                }
            }
            for &c in &self.has[w] {
                if self.body(c) && v.in_unit[self.commits[c].on] == Some(g) && !self.bodies.contains(&(g, c)) {
                    a.body_logs.push((g, c));
                }
            }
            if self.deletes {
                for &(u, c) in &self.bodies {
                    if u == g && v.in_unit[self.commits[c].on] != Some(g) {
                        a.body_dels.push((u, c));
                    }
                }
            }
        }
        a
    }
    pub fn act(&mut self, a: Acts) {
        for (g, b) in a.logs {
            self.store.insert((g, self.next_id), b);
            self.next_id += 1;
            self.churn += 1;
            self.blob_ops += 1;
        }
        for k in a.dels {
            if self.store.remove(&k).is_some() {
                self.churn += 1;
                self.blob_ops += 1;
            }
        }
        for e in a.body_logs {
            self.churn += self.bodies.insert(e) as usize;
        }
        for e in a.body_dels {
            self.churn += self.bodies.remove(&e) as usize;
        }
    }
    pub fn visit(&mut self, w: usize) {
        let a = self.look(w);
        self.act(a);
    }
    /// Every writer looks at the same stores, then all act.
    pub fn visit_together(&mut self) {
        let acts: Vec<_> = (0..self.has.len()).map(|w| self.look(w)).collect();
        for a in acts {
            self.act(a);
        }
    }
    /// Keeper `k` at the stores of what it keeps, steps current: the walk from its roots over the
    /// stored blobs; with `count` (a negative control) a unit stays while a kept unit lists it.
    pub fn pass(&mut self, k: usize, count: bool) {
        let t = self.truth();
        let next = if count {
            let mut kept = self.kept[k].units();
            loop {
                let mut n = self.roots[k].clone();
                for &g in &kept {
                    n.extend(self.listed(g).into_iter().map(|b| b.unit).filter(|&h| kept.iter().any(|&w| t.on_step(w, h))));
                }
                if n == kept {
                    break Entered { unread: kept, ..Entered::default() };
                }
                kept = n;
            }
        } else {
            walk(&t, &Set::new(), &self.roots[k], self.rules, &|g| self.listed(g), false)
        };
        self.churn += self.kept[k].units().symmetric_difference(&next.units()).count();
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
    /// The blob each writer syncing `g` would log for target `x` by its own view.
    fn namers(&self, g: T, x: T) -> Vec<Blob> {
        (0..self.syncs.len())
            .filter(|&w| self.syncs[w].contains(&g))
            .filter_map(|w| self.view(w).blob(g, x, &self.syncs[w], self.rules.paths))
            .collect()
    }
    /// Where the stores and keepers differ from what every commit written says, given who visits:
    /// per unit some writer syncs, the targets some such writer can name each listed by blobs
    /// naming the target's unit, none dominating another, with every path such writers see and no
    /// other blob; the body entries of the unit's things; per keeper, the walk over those blobs.
    pub fn wrong(&self) -> Vec<String> {
        let t = self.truth();
        let mut out = vec![];
        let mut want_listed: BTreeMap<T, Vec<Blob>> = BTreeMap::new();
        for g in t.independents() {
            if !self.syncs.iter().any(|s| s.contains(&g)) {
                continue;
            }
            let got = self.listed(g);
            let mut want = vec![];
            for x in t.targets(g, self.rules.member) {
                let mine = self.namers(g, x);
                if mine.is_empty() {
                    continue;
                }
                let paths: BTreeSet<Vec<T>> = mine.iter().flat_map(|b| b.paths.iter().cloned()).collect();
                want.push(Blob { tag: x, unit: t.ind(x), paths });
            }
            let ok = want.iter().all(|w| {
                let of: Vec<&Blob> = got.iter().filter(|b| b.tag == w.tag).collect();
                let paths: BTreeSet<Vec<T>> = of.iter().flat_map(|b| b.paths.iter().cloned()).collect();
                !of.is_empty()
                    && paths == w.paths
                    && of.iter().all(|b| b.unit == w.unit)
                    && of.iter().enumerate().all(|(i, b)| of.iter().enumerate().all(|(j, o)| i == j || !o.covers(b)))
            }) && got.iter().all(|b| want.iter().any(|w| w.tag == b.tag));
            if !ok {
                out.push(format!("S({g}) lists {got:?}, wants {want:?}"));
            }
            want_listed.insert(g, want);
            let bodies: BTreeSet<C> = self.bodies.iter().filter(|e| e.0 == g).map(|e| e.1).collect();
            let want_bodies: BTreeSet<C> = (0..self.commits.len()).filter(|&c| self.body(c) && t.in_unit[self.commits[c].on] == Some(g)).collect();
            if bodies != want_bodies {
                out.push(format!("S({g}) holds bodies {bodies:?}, wants {want_bodies:?}"));
            }
        }
        for k in 0..self.roots.len() {
            let want = walk(&t, &Set::new(), &self.roots[k], self.rules, &|g| want_listed.get(&g).cloned().unwrap_or_default(), false);
            if self.kept[k] != want {
                out.push(format!("keeper {k} keeps {:?}, wants {want:?}", self.kept[k]));
            }
        }
        out
    }
}
