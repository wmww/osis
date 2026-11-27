//! First entry under stubs (notes/stub-rewrite.md §2; notes/stubs.md), a greenfield model: what a
//! node holds when a grant is its target's data, a node finds what it cares about by references,
//! and the only way in from outside is a held signal (signal → reference → sync → permissions).
//! Properties and hand worlds in tests/it/spec_entry.rs.
//!
//! A unit is a thing's unit or a node's local part (its node root's references, in its own store;
//! the root is a dependent of the node thing, read by that node alone). What a unit `u` carries
//! (`carry`, rule 2), judged from `u`'s own data alone: the role entries of every thing it carries
//! (whole or as a stub) tell `u`'s keys and roles (its owner's effective role over those grants,
//! the public's read and sync on a thing whose entries it carries, never through holders).
//! - A strong to X that `u`'s keys open brings X whole (the walk goes on from it), a weak its
//!   stub; a reference to an X they do not open, where `u`'s owner holds sync or above on it,
//!   its stub; otherwise nothing.
//! - Each holder on a chain by which `u`'s keys open a thing `u` carries is a stub in `u`.
//! - Carriers: X is under `u` only as some node reading `u` logged it there, holding X's role
//!   entries (`Net::logged`): X whole or as a stub at that node. What nobody logged is not
//!   carried. A logged entry stays while the rule carries it (`settle`), being followed.
//!
//! A node reads its node thing, its local part, and every thing a unit it reads carries whole
//! (and that thing's own unit); it holds every stub those units carry. A held signal (rule 4, a
//! value: its target, sync ID, entry credential, peer hints) gives its target's stub where the
//! node reaches it (held directly, as pairing hands one over, or in a thing it reads whole) and
//! opens its holder (a thing it reads, or one its units' keys open): the entry credential opens X's sync ID
//! and the entry box, sealed to the holder, gives the secrets to read X's role entries.
//!
//! The model checks the rule's step at a fixpoint: `settle` logs what every node holding role
//! entries may log, drops what the rule no longer carries, and repeats until nothing moves
//! (`Fix::Least`, from the history passed in; `Fix::Greatest`, from everything logged, is the
//! self-supporting control).
//!
//! Abstracted: a reference to a dependent of another independent thing counts as one to that
//! thing (its data is under that thing's sync ID; bridges are left out); every node follows the
//! stubs it holds, so the grants it knows are the world's current ones; the key-access graph has
//! no cycles (`keyless_of`), so a chain is any path of grants giving read; boxes, validity,
//! rotation, timing and the wire are left out (`box_cut`, `copy_cut` and `evidence` cut and judge
//! what a stub holds).
use super::{Kind, Role, Set, World, T};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct Node {
    /// The node thing: independent, the node's own.
    pub thing: T,
    /// The node root: `Kind::Dependent(thing)`, local; its references are the local part.
    pub root: T,
}

/// Where a signal is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum At {
    /// In a thing's held history (an inbox): every node reading it holds the value.
    Thing(T),
    /// At one node, handed over directly (pairing).
    Node(usize),
}

/// A grant signal's value: the target X and the holder whose entry box it opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Signal {
    pub at: At,
    pub holder: T,
    pub target: T,
}

#[derive(Clone, Debug, Default)]
pub struct Net {
    /// Kinds, grants (the targets' role entries), keyless grants, the public's.
    pub w: World,
    pub strongs: BTreeSet<(T, T)>,
    pub weaks: BTreeSet<(T, T)>,
    pub nodes: Vec<Node>,
    /// The signals held now.
    pub signals: BTreeSet<Signal>,
    /// `(u, x)`: X's stub logged under unit `u` (a thing, or a node root for its local part).
    /// History: `settle` keeps what the rule still carries and adds what nodes log.
    pub logged: BTreeSet<(T, T)>,
    /// `Rule::keep_fetched` (control): `(node, x)` stubs a node fetched by a signal and keeps.
    pub kept: BTreeSet<(usize, T)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fix {
    Least,
    Greatest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chains {
    /// The holders on a path of grants giving read from the unit's owner to a thing it carries
    /// and opens.
    Spec,
    /// Control: every holder the grants of a thing the unit carries name (the walk up from the
    /// carried things, whether or not the owner reaches it).
    Up,
}

/// The rule and its controls, each breaking one property (`Rule::SPEC` is the design).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub fix: Fix,
    pub chains: Chains,
    /// Control: a unit's carriage judged from every role entry its judge holds (else from the
    /// unit's own data).
    pub reader_view: bool,
    /// Off (control): nodes log only into their local part.
    pub log_units: bool,
    /// Control: a node reading H holds the stub of every thing H holds a role on (entry driven by grants).
    pub by_grants: bool,
    /// Control: a stub fetched by a signal stays with the node once the signal is gone.
    pub keep_fetched: bool,
    /// The engine's reading of a strong (`Rule::BUILT`).
    pub by_role: bool,
}

impl Rule {
    pub const SPEC: Rule = Rule { fix: Fix::Least, chains: Chains::Spec, reader_view: false, log_units: true, by_grants: false, keep_fetched: false, by_role: false };
    /// As built (notes/stub-rewrite.md, R2 built: strongs enter by the node's role): a strong to
    /// X that a unit carries as a stub (its owner at sync or above, its keys not opening X) brings
    /// X by the node's own role over the role entries it holds: whole at read or above, kept
    /// unread at sync (its store, `Held::unread`), a stub below.
    pub const BUILT: Rule = Rule { by_role: true, ..Rule::SPEC };
    /// Control: what a node fetched stays with it and is logged nowhere but its local part.
    pub const PRIVATE: Rule = Rule { log_units: false, keep_fetched: true, ..Rule::SPEC };
}

/// What a unit carries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Carried {
    /// Every thing carried whole (dependents among them).
    pub whole: Set,
    /// The independent things carried as a stub, by a reference or as chain holders.
    pub stubs: Set,
    /// The chain holders among `stubs` that no reference brings.
    pub chain: Set,
    /// The things among `stubs` a strong brings.
    pub strong: Set,
    /// The opened things carried (whole independents and opened stubs): a chain ends at one.
    pub opened: Set,
}

/// What a node holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Held {
    /// The independent things it reads.
    pub whole: Set,
    /// Every thing it holds whole, dependents among them.
    pub members: Set,
    /// The independent things it holds as a stub alone.
    pub stubs: Set,
    /// `Rule::by_role`: the independent things it keeps unread (a strong brings them, the node
    /// holding sync on them and no more).
    pub unread: Set,
    /// The independent things its units' keys open (it holds their read secrets).
    pub opened: Set,
    /// The units it reads: its root, its node thing, every independent thing it reads.
    pub units: Set,
    /// The signals it holds that gave a stub.
    pub fetched: BTreeSet<Signal>,
}

impl Held {
    /// The independent things whose role entries the node holds.
    pub fn entries(&self) -> Set {
        self.whole.iter().chain(&self.stubs).chain(&self.unread).copied().collect()
    }
}

impl Net {
    pub fn indep(&self, x: T) -> T {
        match self.w.kinds[x] {
            Kind::Independent => x,
            Kind::Dependent(k) => k,
        }
    }

    /// The units: every independent thing and every node root.
    pub fn units(&self) -> Set {
        (0..self.w.kinds.len()).filter(|&x| self.w.independent(x)).chain(self.nodes.iter().map(|n| n.root)).collect()
    }

    /// The references from `m`, strong or weak (`true`: strong).
    fn refs(&self, m: T) -> Vec<(T, bool)> {
        let s = self.strongs.range((m, 0)..=(m, T::MAX)).map(|&(_, y)| (y, true));
        let w = self.weaks.range((m, 0)..=(m, T::MAX)).map(|&(_, y)| (y, false));
        s.chain(w).collect()
    }

    /// `from`'s role on each thing over the grants on `known` things (keyed, best chain, lowest
    /// hop), then the public's read and sync on `known` things. A dependent thing's role entries
    /// are its independent's data: known with it (a chain through a dependent admin, such as a
    /// thing minted with a dependent, is read where its independent is).
    pub fn roles(&self, from: T, known: &Set) -> BTreeMap<T, Role> {
        let mut best = BTreeMap::from([(from, Role::Admin)]);
        loop {
            let mut changed = false;
            for (&(a, b), &r) in &self.w.grants {
                if self.w.keyless.contains(&(a, b)) || !known.contains(&self.indep(b)) {
                    continue;
                }
                if let Some(&ra) = best.get(&a) {
                    let v = ra.min(r);
                    if best.get(&b).is_none_or(|&o| o < v) {
                        best.insert(b, v);
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        for (set, r) in [(&self.w.public, Role::Read), (&self.w.public_sync, Role::Sync)] {
            for &x in set.iter().filter(|x| known.contains(x)) {
                if best.get(&x).is_none_or(|&o| o < r) {
                    best.insert(x, r);
                }
            }
        }
        best
    }

    /// The things reachable from `from` over keyed grants giving read on `known` things
    /// (`back`: the things reaching `from`).
    fn reach(&self, from: &Set, known: &Set, back: bool) -> Set {
        let mut seen = from.clone();
        loop {
            let more: Vec<T> = self
                .w
                .grants
                .iter()
                .filter(|&(&(a, b), &r)| r >= Role::Read && known.contains(&b) && !self.w.keyless.contains(&(a, b)))
                .filter_map(|(&(a, b), _)| match back {
                    false => (seen.contains(&a) && !seen.contains(&b)).then_some(b),
                    true => (seen.contains(&b) && !seen.contains(&a)).then_some(a),
                })
                .collect();
            if more.is_empty() {
                return seen;
            }
            seen.extend(more);
        }
    }

    /// What unit `u` carries with `logged` (`view`: the judge's other role entries, read only
    /// under `Rule::reader_view`).
    pub fn carry_with(&self, rule: Rule, u: T, logged: &BTreeSet<(T, T)>, view: &Set) -> Carried {
        let o = self.indep(u);
        let logs: Set = logged.range((u, 0)..=(u, T::MAX)).map(|&(_, x)| x).collect();
        let mut c = Carried { whole: Set::from([u]), ..Carried::default() };
        loop {
            let before = c.clone();
            let mut known: Set = c.whole.iter().map(|&x| self.indep(x)).chain(c.stubs.iter().copied()).chain(logs.iter().copied()).collect();
            known.insert(o);
            if rule.reader_view {
                known.extend(view);
            }
            let roles = self.roles(o, &known);
            let at = |x: T, r: Role| roles.get(&x).is_some_and(|&v| v >= r);
            for m in c.whole.clone() {
                for (y, strong) in self.refs(m) {
                    let x = self.indep(y);
                    if x == o {
                        if strong {
                            c.whole.insert(y);
                        }
                        continue;
                    }
                    if !logs.contains(&x) {
                        continue;
                    }
                    if strong && at(x, Role::Read) {
                        c.whole.extend([x, y]);
                    } else if at(x, Role::Sync) {
                        c.stubs.insert(x);
                        if strong {
                            c.strong.insert(x);
                        }
                    }
                }
            }
            c.opened = c.whole.iter().map(|&x| self.indep(x)).chain(c.stubs.iter().copied()).filter(|&x| x != o && at(x, Role::Read)).collect();
            let ends = match rule.chains {
                Chains::Spec => self.reach(&c.opened, &known, true).intersection(&self.reach(&Set::from([o]), &known, false)).copied().collect(),
                Chains::Up => self.w.grants.keys().filter(|(_, b)| c.opened.contains(b)).map(|&(a, _)| a).collect::<Set>(),
            };
            for &h in ends.iter().filter(|&&h| h != o && logs.contains(&h) && self.w.independent(h)) {
                if !c.whole.contains(&h) && c.stubs.insert(h) {
                    c.chain.insert(h);
                }
            }
            c.stubs.retain(|x| !c.whole.contains(x));
            c.chain.retain(|x| c.stubs.contains(x));
            c.strong.retain(|x| c.stubs.contains(x));
            if c == before {
                return c;
            }
        }
    }

    pub fn carry(&self, rule: Rule, u: T, view: &Set) -> Carried {
        self.carry_with(rule, u, &self.logged, view)
    }

    /// What node `i` holds with what is logged now.
    pub fn held(&self, rule: Rule, i: usize) -> Held {
        let n = &self.nodes[i];
        let mut h = Held { whole: Set::from([n.thing]), members: Set::from([n.thing, n.root]), units: Set::from([n.thing, n.root]), ..Held::default() };
        loop {
            let before = h.clone();
            let view = h.entries();
            let own = if rule.by_role { self.roles(n.thing, &view) } else { BTreeMap::new() };
            for u in h.units.clone() {
                let c = self.carry(rule, u, &view);
                for &x in c.strong.iter().filter(|_| rule.by_role) {
                    match own.get(&x) {
                        Some(&r) if r >= Role::Read => {
                            h.whole.insert(x);
                            h.members.insert(x);
                            h.units.insert(x);
                        }
                        Some(_) => drop(h.unread.insert(x)),
                        None => {}
                    }
                }
                for &x in &c.whole {
                    h.members.insert(x);
                    if self.w.independent(x) {
                        h.whole.insert(x);
                        h.units.insert(x);
                    }
                }
                h.stubs.extend(c.stubs);
                h.opened.extend(c.opened);
            }
            for s in &self.signals {
                let reached = match s.at {
                    At::Node(j) => j == i,
                    At::Thing(t) => h.members.contains(&t),
                };
                if reached && (h.whole.contains(&s.holder) || h.opened.contains(&s.holder)) {
                    h.stubs.insert(s.target);
                    h.fetched.insert(*s);
                }
            }
            h.stubs.extend(self.kept.iter().filter(|&&(j, _)| j == i).map(|&(_, x)| x));
            if rule.by_grants {
                let named: Vec<T> = self.w.grants.keys().filter(|(a, _)| h.whole.contains(a)).map(|&(_, b)| b).collect();
                h.stubs.extend(named);
            }
            let whole = h.whole.clone();
            h.unread.retain(|x| !whole.contains(x));
            let unread = h.unread.clone();
            h.stubs.retain(|x| !whole.contains(x) && !unread.contains(x));
            if h == before {
                return h;
            }
        }
    }

    /// What node `i`, holding `h`, logs: under each unit it reads (its local part alone without
    /// `Rule::log_units`), each thing whose role entries it holds that the unit would carry were
    /// they logged there.
    pub fn logs(&self, rule: Rule, i: usize, h: &Held) -> BTreeSet<(T, T)> {
        let entries = h.entries();
        let mut out = BTreeSet::new();
        for &u in h.units.iter().filter(|&&u| rule.log_units || u == self.nodes[i].root) {
            let mut with = self.logged.clone();
            with.extend(entries.iter().map(|&x| (u, x)));
            let c = self.carry_with(rule, u, &with, &entries);
            out.extend(c.whole.iter().map(|&x| self.indep(x)).chain(c.stubs).filter(|x| *x != self.indep(u) && entries.contains(x)).map(|x| (u, x)));
        }
        out
    }

    /// What every unit carries as far as `logged` goes: each logged entry the rule no longer
    /// carries dropped, until none is.
    fn kept_by_rule(&self, rule: Rule, mut logged: BTreeSet<(T, T)>) -> BTreeSet<(T, T)> {
        loop {
            let keep: BTreeSet<(T, T)> = logged
                .iter()
                .copied()
                .filter(|&(u, x)| {
                    let c = self.carry_with(rule, u, &logged, &Set::new());
                    c.stubs.contains(&x) || c.whole.iter().any(|&y| self.indep(y) == x)
                })
                .collect();
            if keep == logged {
                return logged;
            }
            logged = keep;
        }
    }

    /// Every node logs and the units keep what the rule carries, until nothing moves. Under
    /// `Fix::Greatest` the start is everything logged, and an entry stays only while some node
    /// logs it again.
    pub fn settle(&mut self, rule: Rule) {
        if rule.fix == Fix::Greatest {
            let units = self.units();
            let all: Set = (0..self.w.kinds.len()).filter(|&x| self.w.independent(x)).collect();
            self.logged = units.iter().flat_map(|&u| all.iter().map(move |&x| (u, x))).collect();
        }
        for _ in 0..8 * self.w.kinds.len() + 8 {
            let held: Vec<Held> = (0..self.nodes.len()).map(|i| self.held(rule, i)).collect();
            let mut next: BTreeSet<(T, T)> = (0..self.nodes.len()).flat_map(|i| self.logs(rule, i, &held[i])).collect();
            if rule.fix == Fix::Least {
                next.extend(self.logged.iter().copied());
            } else {
                next.retain(|e| self.logged.contains(e));
            }
            let next = self.kept_by_rule(rule, next);
            if rule.keep_fetched {
                for (i, h) in held.iter().enumerate() {
                    self.kept.extend(h.fetched.iter().map(|s| (i, s.target)));
                }
            }
            if next == self.logged {
                return;
            }
            self.logged = next;
        }
        panic!("logging does not settle under {rule:?}");
    }

    // ---- Oracles: independent of logging and of the rule's walk ----

    /// The independent things node `i` could find at all: what references reach from its root and
    /// node thing, and what held signals name and their references reach, whatever the keys; with
    /// the holders on a path of grants giving read between two of them.
    pub fn findable(&self, i: usize) -> Set {
        let n = &self.nodes[i];
        let mut seen = Set::from([n.thing, n.root]);
        loop {
            let before = seen.len();
            for m in seen.clone() {
                seen.extend(self.refs(m).into_iter().flat_map(|(y, _)| [y, self.indep(y)]));
            }
            for s in &self.signals {
                if match s.at {
                    At::Node(j) => j == i,
                    At::Thing(t) => seen.contains(&t),
                } {
                    seen.insert(s.target);
                }
            }
            let all: Set = (0..self.w.kinds.len()).collect();
            let found: Set = seen.iter().map(|&x| self.indep(x)).collect();
            seen.extend(self.reach(&found, &all, false).intersection(&self.reach(&found, &all, true)));
            if seen.len() == before {
                return seen.into_iter().filter(|&x| self.w.independent(x)).collect();
            }
        }
    }

    /// The holders on the simple paths of keyed grants giving read from `o` to a thing of `ends`,
    /// `o` and the ends aside: enumerated path by path (the chain oracle).
    pub fn on_paths(&self, o: T, ends: &Set) -> Set {
        let mut out = Set::new();
        let mut path = vec![o];
        self.extend_paths(ends, &mut path, &mut out);
        out
    }

    fn extend_paths(&self, ends: &Set, path: &mut Vec<T>, out: &mut Set) {
        let Some(&at) = path.last() else { return };
        for (&(a, b), &r) in &self.w.grants {
            if a != at || r < Role::Read || path.contains(&b) || self.w.keyless.contains(&(a, b)) {
                continue;
            }
            if ends.contains(&b) {
                out.extend(path[1..].iter().copied());
            }
            path.push(b);
            self.extend_paths(ends, path, out);
            path.pop();
        }
    }
}

// ---- Properties ----

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fail {
    pub prop: &'static str,
    pub node: usize,
    pub thing: T,
}

/// The properties at one settled state (`net.settle(rule)` first), each a list of failures:
/// - `readers agree`: a unit's carriage is the same for a judge holding only the unit as for one
///   holding every role entry.
/// - `no grant-driven entry`: a node holds nothing of a thing it could not find (`findable`),
///   whatever roles it holds.
/// - `siblings`: two nodes reading one account through their roots alone (their node things
///   referencing nothing), holding the same signals, hold the same.
/// - `chains`: with every allowed stub logged, each unit's chain holders are the holders on its
///   simple paths (`on_paths`) not otherwise carried.
/// - `signal lifetime`: a node holds a stub only where a unit it reads carries it or a signal it
///   holds gives it.
/// `founded` is a property of a world, not a state: `founded`.
pub fn check(net: &Net, rule: Rule) -> Vec<Fail> {
    let mut out = vec![];
    let held: Vec<Held> = (0..net.nodes.len()).map(|i| net.held(rule, i)).collect();
    let all: Set = (0..net.w.kinds.len()).filter(|&x| net.w.independent(x)).collect();
    for u in net.units() {
        let (alone, knowing) = (net.carry(rule, u, &Set::new()), net.carry(rule, u, &all));
        if alone != knowing {
            out.push(Fail { prop: "readers agree", node: usize::MAX, thing: u });
        }
    }
    for (i, h) in held.iter().enumerate() {
        let f = net.findable(i);
        for &x in h.entries().iter().filter(|x| !f.contains(x)) {
            out.push(Fail { prop: "no grant-driven entry", node: i, thing: x });
        }
        let carried: Set = h.units.iter().flat_map(|&u| net.carry(rule, u, &h.entries()).stubs).chain(h.fetched.iter().map(|s| s.target)).collect();
        for &x in h.stubs.iter().filter(|x| !carried.contains(x)) {
            out.push(Fail { prop: "signal lifetime", node: i, thing: x });
        }
    }
    for i in 0..net.nodes.len() {
        for j in i + 1..net.nodes.len() {
            let (a, b) = (&net.nodes[i], &net.nodes[j]);
            let roots = |r: T| net.refs(r).into_iter().map(|(y, _)| y).collect::<Vec<T>>();
            let (ra, rb) = (roots(a.root), roots(b.root));
            let quiet = net.refs(a.thing).is_empty() && net.refs(b.thing).is_empty();
            if !quiet || ra.len() != 1 || ra != rb || !held[i].whole.contains(&ra[0]) || !held[j].whole.contains(&ra[0]) || held[i].fetched != held[j].fetched {
                continue;
            }
            let own = |x: &T| *x != a.thing && *x != b.thing;
            let strip = |h: &Held| -> (Set, Set) { (h.whole.iter().copied().filter(own).collect(), h.stubs.iter().copied().filter(own).collect()) };
            if strip(&held[i]) != strip(&held[j]) {
                out.push(Fail { prop: "siblings", node: j, thing: ra[0] });
            }
        }
    }
    let mut ideal = net.clone();
    let units = net.units();
    ideal.logged = units.iter().flat_map(|&u| all.iter().map(move |&x| (u, x))).collect();
    for u in units {
        let c = ideal.carry(rule, u, &Set::new());
        let o = net.indep(u);
        let by_refs: Set = c.whole.iter().map(|&x| net.indep(x)).chain(c.stubs.difference(&c.chain).copied()).collect();
        let oracle: Set = net.on_paths(o, &c.opened).into_iter().filter(|x| !by_refs.contains(x) && *x != o).collect();
        if c.chain != oracle {
            out.push(Fail { prop: "chains", node: usize::MAX, thing: u });
        }
    }
    out
}

/// Founded: with no signal and nothing logged before, settling leaves every node holding its own
/// node thing alone (`Fix::Greatest` lets entries support themselves).
pub fn founded(net: &Net, rule: Rule) -> Vec<Fail> {
    let mut bare = net.clone();
    bare.signals.clear();
    bare.logged.clear();
    bare.kept.clear();
    bare.settle(rule);
    (0..bare.nodes.len())
        .flat_map(|i| {
            let h = bare.held(rule, i);
            let own = bare.nodes[i].thing;
            h.entries().into_iter().filter(move |&x| x != own).map(move |x| Fail { prop: "founded", node: i, thing: x })
        })
        .collect()
}

// ---- Random worlds and histories ----

/// A small xorshift.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    pub fn below(&mut self, m: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % m
    }
    pub fn pick<X: Copy>(&mut self, xs: &[X]) -> X {
        xs[self.below(xs.len() as u64) as usize]
    }
}

/// A step of a random history.
#[derive(Clone, Copy, Debug)]
pub enum Step {
    Strong(T, T),
    Weak(T, T),
    Unref(T, T),
    Grant(T, T, Role),
    Revoke(T, T),
    Signal(Signal),
    Expire(Signal),
}

/// A random world from `seed`: an account A (thing 0) with `nodes` nodes (node things granted
/// write on A, roots strongly referencing A), shared things (some dependent), a thing granted to
/// holders and referenced by nothing, the public's grants; nothing logged, no signal.
pub fn world(seed: u64, nodes: usize, things: usize) -> Net {
    let mut r = Rng::new(seed);
    let mut kinds = vec![Kind::Independent];
    let mut net = Net::default();
    for _ in 0..nodes {
        let t = kinds.len();
        kinds.extend([Kind::Independent, Kind::Dependent(t)]);
        net.nodes.push(Node { thing: t, root: t + 1 });
    }
    for _ in 0..things {
        let ind: Vec<T> = (0..kinds.len()).filter(|&y| kinds[y] == Kind::Independent && !net.nodes.iter().any(|n| n.thing == y)).collect();
        kinds.push(if r.below(4) == 0 { Kind::Dependent(r.pick(&ind)) } else { Kind::Independent });
    }
    // the lonely thing: granted to holders, referenced and signalled by nothing
    kinds.push(Kind::Independent);
    net.w.kinds = kinds;
    let n = net.w.kinds.len();
    let ind: Vec<T> = (0..n).filter(|&x| net.w.independent(x)).collect();
    let mut order = vec![];
    for n in &net.nodes {
        net.w.grants.insert((n.thing, 0), Role::Write);
        order.push((n.thing, 0));
        net.strongs.insert((n.root, 0));
    }
    let roles = [Role::Sync, Role::Read, Role::Write];
    for _ in 0..things + 2 {
        let (h, x) = (r.pick(&ind), r.pick(&ind));
        if h != x {
            net.w.grants.insert((h, x), r.pick(&roles));
            order.push((h, x));
        }
    }
    let lonely = n - 1;
    for _ in 0..2 {
        let h = r.pick(&ind);
        if h != lonely {
            net.w.grants.insert((h, lonely), r.pick(&roles));
            order.push((h, lonely));
        }
    }
    net.w.keyless = super::keyless_of(&order);
    for &x in &ind[1..] {
        match r.below(8) {
            0 => {
                net.w.public.insert(x);
            }
            1 => {
                net.w.public_sync.insert(x);
            }
            _ => {}
        }
    }
    net.w.public.remove(&lonely);
    net.w.public_sync.remove(&lonely);
    net
}

/// A random step on `net` (`lonely`, the last thing, stays unreferenced and unsignalled).
pub fn step(net: &Net, r: &mut Rng) -> Step {
    let n = net.w.kinds.len();
    let lonely = n - 1;
    let froms: Vec<T> = (0..lonely).filter(|&x| !net.nodes.iter().any(|m| m.root == x) || r.below(4) == 0).collect();
    let tos: Vec<T> = (0..lonely).filter(|&x| !net.nodes.iter().any(|m| m.root == x)).collect();
    let ind: Vec<T> = (0..n).filter(|&x| net.w.independent(x)).collect();
    let tos_ind: Vec<T> = tos.iter().copied().filter(|&x| net.w.independent(x)).collect();
    loop {
        let (a, b) = (r.pick(&froms), r.pick(&tos));
        let s = match r.below(9) {
            0 | 1 => Step::Strong(a, b),
            2 => Step::Weak(a, b),
            3 => match net.strongs.iter().chain(&net.weaks).nth(r.below(net.strongs.len() as u64 + net.weaks.len() as u64 + 1) as usize) {
                Some(&(a, b)) if !(b == 0 && net.nodes.iter().any(|m| m.root == a)) => Step::Unref(a, b),
                _ => continue,
            },
            4 => Step::Grant(r.pick(&ind), r.pick(&ind), r.pick(&[Role::Sync, Role::Read, Role::Write])),
            5 => match net.w.grants.keys().nth(r.below(net.w.grants.len() as u64) as usize) {
                Some(&(h, x)) if x != 0 => Step::Revoke(h, x),
                _ => continue,
            },
            6 | 7 => {
                let at = if r.below(2) == 0 { At::Node(r.below(net.nodes.len() as u64) as usize) } else { At::Thing(r.pick(&tos)) };
                let holder = r.pick(&ind);
                Step::Signal(Signal { at, holder, target: r.pick(&tos_ind) })
            }
            _ => match net.signals.iter().nth(r.below(net.signals.len() as u64 + 1) as usize) {
                Some(&s) => Step::Expire(s),
                None => continue,
            },
        };
        if let Step::Strong(a, b) | Step::Weak(a, b) = s {
            if a == b || net.w.kinds[a] == Kind::Dependent(b) {
                continue;
            }
        }
        if let Step::Grant(h, x, _) = s {
            if h == x || x == lonely || h == lonely {
                continue;
            }
        }
        return s;
    }
}

impl Net {
    /// Applies a step (a grant that would close a key-access cycle is keyless).
    pub fn apply(&mut self, s: Step) {
        match s {
            Step::Strong(a, b) => {
                self.strongs.insert((a, b));
            }
            Step::Weak(a, b) => {
                self.weaks.insert((a, b));
            }
            Step::Unref(a, b) => {
                self.strongs.remove(&(a, b));
                self.weaks.remove(&(a, b));
            }
            Step::Grant(h, x, role) => {
                let fresh = self.w.grants.insert((h, x), role).is_none();
                if fresh {
                    let mut keyed: Vec<(T, T)> = self.w.grants.keys().copied().filter(|e| !self.w.keyless.contains(e) && *e != (h, x)).collect();
                    keyed.push((h, x));
                    if super::keyless_of(&keyed).contains(&(h, x)) {
                        self.w.keyless.insert((h, x));
                    }
                }
            }
            Step::Revoke(h, x) => {
                self.w.grants.remove(&(h, x));
                self.w.keyless.remove(&(h, x));
            }
            Step::Signal(s) => {
                self.signals.insert(s);
            }
            Step::Expire(s) => {
                self.signals.remove(&s);
            }
        }
    }
}

/// Runs a random history of `len` steps on `world(seed, ..)` under `rule`, checking every
/// settled state: the failures, first one per property.
pub fn history(seed: u64, len: usize, rule: Rule) -> Vec<(usize, Fail)> {
    let mut net = world(seed, 2 + (seed % 2) as usize, 4 + (seed % 3) as usize);
    let mut r = Rng::new(seed ^ 0x5157);
    let mut out: Vec<(usize, Fail)> = founded(&net, rule).into_iter().map(|f| (0, f)).collect();
    // pairing: each node is handed A's values, takes A in, and the value is gone
    let pair: Vec<Signal> = (0..net.nodes.len()).map(|i| Signal { at: At::Node(i), holder: net.nodes[i].thing, target: 0 }).collect();
    for s in &pair {
        net.apply(Step::Signal(*s));
    }
    net.settle(rule);
    for s in &pair {
        net.apply(Step::Expire(*s));
    }
    for k in 0..len {
        let s = step(&net, &mut r);
        net.apply(s);
        net.settle(rule);
        for f in check(&net, rule) {
            if !out.iter().any(|(_, g)| g.prop == f.prop) {
                out.push((k + 1, f));
            }
        }
    }
    out
}
