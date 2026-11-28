//! First entry under stubs (notes/stubs.md; spec/sync-set.md §2), a greenfield model: what a
//! node holds when a grant is its target's data, a node finds what it cares about by references,
//! and nothing from outside reaches a node but a held signal (signal → reference → sync → permissions).
//! Properties and hand worlds in tests/it/spec_entry.rs.
//!
//! A unit is a thing's unit or a node's local part (its node root's references, in its own store;
//! the root is a dependent of the node thing, read by that node alone). What a unit `u` carries
//! (`carry`, rule 2), judged from `u`'s own data alone: the grants it teaches (`Know`) tell `u`'s
//! keys and roles (its owner's effective role over those grants, the public's read and sync on a
//! thing whose sync ID it holds, never through holders): the role entries of what it carries whole
//! or opens, its owner's own grants (its entries) on what it names, and the chain grants a cut
//! logged by a reader of the target's role entries names; a thing logged by entries alone
//! (`Net::entry_only`) teaches only the owner's grant.
//! - A strong to X that `u`'s keys open brings X whole (the walk goes on from it), a weak its
//!   stub; a reference to an X they do not open, where `u`'s owner holds sync or above on it,
//!   its stub; otherwise nothing.
//! - Each holder on a chain by which `u`'s owner holds its role on a thing `u` carries (read
//!   grants where `u`'s keys open it, else sync or above) is a stub in `u`.
//! - Carriers: X is under `u` only as some node reading `u` logged it there, holding X's role
//!   entries (`Net::logged`): X whole or as a stub at that node. What nobody logged is not
//!   carried. A logged entry stays while the rule carries it (`settle`), being followed.
//!
//! A node reads its node thing, its local part, and every thing a unit it reads carries whole
//! (and that thing's own unit); it holds every stub those units carry. A held signal (rule 4, a
//! value: its target, sync ID, holder, peer hints) gives its target's stub where the node
//! reaches it (held directly, as pairing hands one over, or in a thing it reads whole), followed
//! where the node reads its holder (a thing it reads, or one its units' keys open): the holder's
//! entry in the commit granting it opens X's sync ID and gives the secrets to read X's role
//! entries.
//!
//! The model checks the rule's step at a fixpoint: `settle` logs what every node holding role
//! entries may log, drops what the rule no longer carries, and repeats until nothing moves
//! (`Fix::Least`, from the history passed in; `Fix::Greatest`, from everything logged, is the
//! self-supporting control).
//!
//! Abstracted: a reference to a dependent of another independent thing counts as one to that
//! thing (its data is under that thing's sync ID; bridges are left out); every node follows the
//! stubs it holds, so the grants it can learn of a thing are the world's current ones (a cut a
//! roster reader logged stays current); the key-access graph has
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

/// A grant signal's value: the target X and its holder.
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
    /// The entries of `logged` that only nodes holding X by entries alone logged (none reading
    /// X's role entries): a sync-only cut naming no chain holder, so `u`'s readers learn of X's
    /// grants only `u`'s owner's own (its entry).
    pub entry_only: BTreeSet<(T, T)>,
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
    /// The holders on a path of grants from the unit's owner to a thing it carries: giving read
    /// where it opens the thing, else sync.
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
}

impl Rule {
    /// The design: a strong to X that a unit carries as a stub (its owner at sync or above, its
    /// keys not opening X) brings X by the node's own role over the role entries it holds: whole
    /// at read or above, kept unread at sync (`Held::unread`), a stub below.
    pub const SPEC: Rule = Rule { fix: Fix::Least, chains: Chains::Spec, reader_view: false, log_units: true, by_grants: false, keep_fetched: false };
    /// Control: what a node fetched stays with it and is logged nowhere but its local part.
    pub const PRIVATE: Rule = Rule { log_units: false, keep_fetched: true, ..Rule::SPEC };
}

/// The grants a judge can learn (spec/sync-set.md §2: a thing's grants count where its role
/// entries are held; spec/permissions.md §4 Stub): every grant on a thing of `full` (its roster
/// read), each grant of `edges` (an entry of its holder taken, or a sync-only cut naming its holder
/// on the judge's chain), and the public's on a thing of `ids` (its sync ID held: the public's
/// entry is at the head).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Know {
    pub full: Set,
    pub edges: BTreeSet<(T, T)>,
    pub ids: Set,
}

impl Know {
    /// Knowing every grant on `known` things.
    pub fn all(known: &Set) -> Know {
        Know { full: known.clone(), edges: BTreeSet::new(), ids: known.clone() }
    }

    fn grant(&self, net: &Net, a: T, b: T) -> bool {
        self.full.contains(&net.indep(b)) || self.edges.contains(&(a, net.indep(b)))
    }

    fn extend(&mut self, other: &Know) {
        self.full.extend(&other.full);
        self.edges.extend(&other.edges);
        self.ids.extend(&other.ids);
    }
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
    /// The things among `stubs` a strong naming them brings.
    pub strong: Set,
    /// The things among `stubs` a reference names (not only a dependent of it) or a chain holds:
    /// those the unit's readers can name, with the opened ones.
    pub named: Set,
    /// The opened things carried (whole independents and opened stubs): a chain ends at one.
    pub opened: Set,
    /// The grants the unit's readers learn from it (`Know`).
    pub know: Know,
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
    /// The independent things it keeps unread (a strong brings them, the node
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
    /// The independent things the node holds (their role entries, or by entries alone).
    pub fn entries(&self) -> Set {
        self.whole.iter().chain(&self.stubs).chain(&self.unread).copied().collect()
    }
}

impl Net {
    /// The things whose role entries node `h` reads: what it holds whole, a stub its units' keys
    /// open, and a signal's target its holder reads (its entry gives the secrets to read the
    /// target's role entries).
    pub fn rosters(&self, h: &Held) -> Set {
        let signalled = h.fetched.iter().filter(|s| self.w.grants.get(&(s.holder, s.target)).is_some_and(|&r| r >= Role::Read)).map(|s| s.target);
        h.whole.iter().copied().chain(h.stubs.intersection(&h.opened).copied()).chain(signalled).collect()
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

    /// `from`'s role on each thing over the grants `known` learns (keyed, best chain, lowest
    /// hop), then the public's read and sync on the things whose sync IDs it holds. A dependent
    /// thing's role entries are its independent's data: known with it (a chain through a
    /// dependent admin, such as a thing minted with a dependent, is read where its independent is).
    pub fn roles(&self, from: T, known: &Know) -> BTreeMap<T, Role> {
        let mut best = BTreeMap::from([(from, Role::Admin)]);
        loop {
            let mut changed = false;
            for (&(a, b), &r) in &self.w.grants {
                if self.w.keyless.contains(&(a, b)) || !known.grant(self, a, b) {
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
            for &x in set.iter().filter(|x| known.ids.contains(x)) {
                if best.get(&x).is_none_or(|&o| o < r) {
                    best.insert(x, r);
                }
            }
        }
        best
    }

    /// The things reachable from `from` over keyed grants giving `min` or above on `known` things
    /// (`back`: the things reaching `from`).
    fn reach(&self, from: &Set, known: &Know, back: bool, min: Role) -> Set {
        let mut seen = from.clone();
        loop {
            let more: Vec<T> = self
                .w
                .grants
                .iter()
                .filter(|&(&(a, b), &r)| r >= min && known.grant(self, a, b) && !self.w.keyless.contains(&(a, b)))
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

    /// The grants on `x` a cut logged by a reader of its roster names for owner `o`: `o`'s and
    /// those of each holder on `o`'s chains (`o` reaching it at sync or above), as that reader
    /// holds them.
    fn chain_edges(&self, o: T, x: T) -> BTreeSet<(T, T)> {
        let all: Set = (0..self.w.kinds.len()).collect();
        let on = self.reach(&Set::from([o]), &Know::all(&all), false, Role::Sync);
        self.w.grants.iter().filter(|&(&(a, b), &r)| r >= Role::Sync && b == x && on.contains(&a) && !self.w.keyless.contains(&(a, b))).map(|(&e, _)| e).collect()
    }

    /// What unit `u` carries with `logged`, of which `entry_only` were logged by entries alone
    /// (`view`: the judge's other role entries, read only under `Rule::reader_view`).
    pub fn carry_with(&self, rule: Rule, u: T, logged: &BTreeSet<(T, T)>, entry_only: &BTreeSet<(T, T)>, view: &Set) -> Carried {
        let o = self.indep(u);
        let logs: Set = logged.range((u, 0)..=(u, T::MAX)).map(|&(_, x)| x).collect();
        let cut_edges: BTreeSet<(T, T)> = logs.iter().filter(|&&x| !entry_only.contains(&(u, x))).flat_map(|&x| self.chain_edges(o, x)).collect();
        let mut c = Carried { whole: Set::from([u]), ..Carried::default() };
        loop {
            let before = c.clone();
            // what `u`'s readers learn: the rosters of what it carries whole and what its keys
            // open, its owner's own grants (its entries) on what it names, and the chain grants
            // a cut logged by a roster reader names
            let ids: Set = c.whole.iter().map(|&x| self.indep(x)).chain(c.stubs.iter().copied()).chain(logs.iter().copied()).chain([o]).collect();
            let mut known = Know { full: c.whole.iter().map(|&x| self.indep(x)).chain(c.opened.iter().copied()).chain([o]).collect(), edges: ids.iter().map(|&x| (o, x)).collect(), ids };
            known.edges.extend(cut_edges.iter().copied());
            if rule.reader_view {
                known.full.extend(view);
                known.ids.extend(view);
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
                        if y == x {
                            c.named.insert(x);
                        }
                        // by role only by a strong naming X: one to a dependent of X tells
                        // `u`'s readers nothing of X (spec/sync-ids.md §2 What a sync holder learns)
                        if strong && y == x {
                            c.strong.insert(x);
                        }
                    }
                }
            }
            c.opened = c.whole.iter().map(|&x| self.indep(x)).chain(c.stubs.iter().copied()).filter(|&x| x != o && at(x, Role::Read)).collect();
            let ends = match rule.chains {
                // the chains giving `o` its role on each carried thing: read where its keys open
                // it, else sync (spec/sync-set.md §2 Stubs)
                Chains::Spec => {
                    let syncs: Set = c.stubs.difference(&c.opened).copied().collect();
                    let on = |ends: &Set, min: Role| -> Set { self.reach(ends, &known, true, min).intersection(&self.reach(&Set::from([o]), &known, false, min)).copied().collect() };
                    on(&c.opened, Role::Read).union(&on(&syncs, Role::Sync)).copied().collect()
                }
                Chains::Up => self.w.grants.keys().filter(|(_, b)| c.opened.contains(b)).map(|&(a, _)| a).collect::<Set>(),
            };
            for &h in ends.iter().filter(|&&h| h != o && logs.contains(&h) && self.w.independent(h)) {
                if !c.whole.contains(&h) && c.stubs.insert(h) {
                    c.chain.insert(h);
                    c.named.insert(h);
                }
            }
            c.stubs.retain(|x| !c.whole.contains(x));
            c.chain.retain(|x| c.stubs.contains(x));
            c.strong.retain(|x| c.stubs.contains(x));
            c.named.retain(|x| c.stubs.contains(x));
            c.know = known;
            if c == before {
                return c;
            }
        }
    }

    pub fn carry(&self, rule: Rule, u: T, view: &Set) -> Carried {
        self.carry_with(rule, u, &self.logged, &self.entry_only, view)
    }

    /// What node `i` holds with what is logged now.
    pub fn held(&self, rule: Rule, i: usize) -> Held {
        let n = &self.nodes[i];
        let mut h = Held { whole: Set::from([n.thing]), members: Set::from([n.thing, n.root]), units: Set::from([n.thing, n.root]), ..Held::default() };
        let mut know = Know::default();
        loop {
            let before = (h.clone(), know.clone());
            let view = h.entries();
            // the node's own role over the grants its units teach it and its held signals' entries
            let mut k = know.clone();
            k.full.extend(self.rosters(&h));
            k.full.insert(n.thing);
            k.ids.extend(view.iter().copied());
            let own = self.roles(n.thing, &k);
            know = Know::default();
            know.edges.extend(h.fetched.iter().map(|s| (s.holder, s.target)));
            for u in h.units.clone() {
                let c = self.carry(rule, u, &view);
                know.extend(&c.know);
                for &x in &c.strong {
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
            if (h.clone(), know.clone()) == before {
                return h;
            }
        }
    }

    /// What node `i`, holding `h`, logs: under each unit it reads (its local part alone without
    /// `Rule::log_units`), each thing it holds (its role entries, or by entries alone, unread or a
    /// sync-only stub) that the unit would carry were they logged there; `true` where it reads the
    /// thing's role entries (whole, or a stub its units' keys open).
    pub fn logs(&self, rule: Rule, i: usize, h: &Held) -> BTreeMap<(T, T), bool> {
        let entries = h.entries();
        let roster = self.rosters(h);
        let mut out = BTreeMap::new();
        for &u in h.units.iter().filter(|&&u| rule.log_units || u == self.nodes[i].root) {
            let mut with = self.logged.clone();
            let mut eo = self.entry_only.clone();
            for &x in &entries {
                if with.insert((u, x)) && !roster.contains(&x) {
                    eo.insert((u, x));
                }
                if roster.contains(&x) {
                    eo.remove(&(u, x));
                }
            }
            let c = self.carry_with(rule, u, &with, &eo, &entries);
            out.extend(c.whole.iter().map(|&x| self.indep(x)).chain(c.stubs).filter(|x| *x != self.indep(u) && entries.contains(x)).map(|x| ((u, x), roster.contains(&x))));
        }
        out
    }

    /// What every unit carries as far as `logged` goes: each logged entry the rule no longer
    /// carries dropped, until none is.
    fn kept_by_rule(&self, rule: Rule, mut logged: BTreeSet<(T, T)>, entry_only: &BTreeSet<(T, T)>) -> BTreeSet<(T, T)> {
        loop {
            let keep: BTreeSet<(T, T)> = logged
                .iter()
                .copied()
                .filter(|&(u, x)| {
                    let c = self.carry_with(rule, u, &logged, entry_only, &Set::new());
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
            let logs: Vec<BTreeMap<(T, T), bool>> = (0..self.nodes.len()).map(|i| self.logs(rule, i, &held[i])).collect();
            let mut next: BTreeSet<(T, T)> = logs.iter().flat_map(|l| l.keys().copied()).collect();
            // entry-only while no roster reader logs it
            let rostered: BTreeSet<(T, T)> = logs.iter().flat_map(|l| l.iter().filter(|(_, r)| **r).map(|(e, _)| *e)).collect();
            let mut eo: BTreeSet<(T, T)> = next.iter().copied().filter(|e| !self.logged.contains(e) || self.entry_only.contains(e)).collect();
            if rule.fix == Fix::Least {
                next.extend(self.logged.iter().copied());
                eo.extend(self.entry_only.iter().copied());
            } else {
                next.retain(|e| self.logged.contains(e));
            }
            eo.retain(|e| !rostered.contains(e) && next.contains(e));
            let next = self.kept_by_rule(rule, next, &eo);
            eo.retain(|e| next.contains(e));
            if rule.keep_fetched {
                for (i, h) in held.iter().enumerate() {
                    self.kept.extend(h.fetched.iter().map(|s| (i, s.target)));
                }
            }
            if next == self.logged && eo == self.entry_only {
                return;
            }
            self.logged = next;
            self.entry_only = eo;
        }
        panic!("logging does not settle under {rule:?}");
    }

    // ---- Oracles: independent of logging and of the rule's walk ----

    /// The independent things node `i` could find at all: what references reach from its root and
    /// node thing, and what held signals name and their references reach, whatever the keys; with
    /// the holders on a path of grants between two of them.
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
            seen.extend(self.reach(&found, &Know::all(&all), false, Role::Sync).intersection(&self.reach(&found, &Know::all(&all), true, Role::Sync)));
            if seen.len() == before {
                return seen.into_iter().filter(|&x| self.w.independent(x)).collect();
            }
        }
    }

    /// The holders on the simple paths of keyed grants giving `min` or above from `o` to a thing
    /// of `ends`, `o` and the ends aside: enumerated path by path (the chain oracle).
    pub fn on_paths(&self, o: T, ends: &Set, min: Role) -> Set {
        let mut out = Set::new();
        let mut path = vec![o];
        self.extend_paths(ends, min, &mut path, &mut out);
        out
    }

    fn extend_paths(&self, ends: &Set, min: Role, path: &mut Vec<T>, out: &mut Set) {
        let Some(&at) = path.last() else { return };
        for (&(a, b), &r) in &self.w.grants {
            if a != at || r < min || path.contains(&b) || self.w.keyless.contains(&(a, b)) {
                continue;
            }
            if ends.contains(&b) {
                out.extend(path[1..].iter().copied());
            }
            path.push(b);
            self.extend_paths(ends, min, path, out);
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
///   simple paths (`on_paths`: of read grants to what it opens, of sync or above to the stubs it
///   holds only sync on) not otherwise carried.
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
    ideal.entry_only.clear();
    for u in units {
        let c = ideal.carry(rule, u, &Set::new());
        let o = net.indep(u);
        let by_refs: Set = c.whole.iter().map(|&x| net.indep(x)).chain(c.stubs.difference(&c.chain).copied()).collect();
        let syncs: Set = c.stubs.difference(&c.opened).copied().collect();
        let paths = net.on_paths(o, &c.opened, Role::Read).into_iter().chain(net.on_paths(o, &syncs, Role::Sync));
        let oracle: Set = paths.filter(|x| !by_refs.contains(x) && *x != o).collect();
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
