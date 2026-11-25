//! First entry and the node thing / node root split (spec/sync-set.md §1, §2; spec/permissions.md
//! §4 Key part, §8 Accounts), a greenfield model: what a node holds when it enters a thing only by
//! a unit it syncs carrying it, an edge piece in a key part it holds, or an offer. Properties and
//! hand worlds in tests/it/spec_entry.rs; findings in notes/accounts-switch-brief.md (Models).
//!
//! A node is its node thing (independent, minted with its key: its unit is itself) and its node
//! root (a dependent of the node thing, local, holding the node's strongs). The node's role on a
//! thing is its node thing's effective role over the grants that count at the node (spec/sync-set.md
//! §2 Own things): those of the things it syncs or holds an offer of, and, up from them, of each
//! holder with a role (key access) on a thing whose grants count.
//!
//! The rule is a monotone step on a node's state (`S`: read, kept unread, key parts held); the
//! node holds the step's least fixpoint (`Fix::Least`: keys found from a synced thing up, every
//! entry founded on data). `Fix::Greatest` (an entry may support itself through the key part it
//! brings in: a walk down the key parts of everything the node opens) and `settle` from an earlier
//! state (a node following changes and keeping what still supports itself) are the other readings.
//!
//! Carriers (`Rule::carriers`, spec/sync-set.md §2 What a sync ID carries): T's sync ID carries
//! only what a node holding it logs there. A node reading T holds a thing of T's sync unit only
//! where T's sync ID carries it in fact: an independent thing (its own sync ID carries it), a
//! dependent of T (made by a reader of T), or a dependent of another independent thing that a node
//! reading T holds otherwise (a bridge). A stub of X under T is carried only where a node reading T
//! holds one of its edge pieces otherwise: T's own (T's key part), another stub holder's whose key
//! part it holds, or any where it reads X. Both are `Net::logged`, the least fixpoint over every
//! node (`Net::held_all`). The walk goes on only from a thing held. What the public reads opens T's
//! keys only by a public piece under T's sync ID (`Net::pieces`), logged by a node reading T that
//! holds the public's grant otherwise: it syncs the thing, or reads another unit carrying the piece
//! (`logs_pieces`); a caller following a history passes in the pieces logged before (they outlive
//! their carrier).
//!
//! Abstracted: every edge piece the spec indexes is logged under its holder's sync ID (ideal
//! delivery), as is what a carrier holds (a bridge's carriage stands while it does: carriage that
//! outlived its bridge is history, not modelled); grants sit on independent things; a box exists for every keyed edge; validity,
//! rotation, timing and the wire are left out. An edge piece is the current grant's: a removal's
//! piece carries nothing, since a loss is carried out at once here (the engine's carries until
//! the node's read secrets go, spec/sync-set.md §2 First entry).
use super::{targets, unit_with, Edges, Kind, Role, Set, World, T};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default)]
pub struct Node {
    /// The node thing: independent, the node's own thing.
    pub thing: T,
    /// The node root: `Kind::Dependent(thing)`, local.
    pub root: T,
    /// Offers the node holds (spec/sync-inbox.md §5): the things offered.
    pub offers: Set,
}

#[derive(Clone, Debug, Default)]
pub struct Net {
    /// Kinds, grants (record edges among them, as admin) and keyless grants.
    pub w: World,
    /// The grants that are record edges (`(mint admin, thing)`): no edge write made them.
    pub records: BTreeSet<(T, T)>,
    /// Every strong, the node roots' among them (a root's strongs are read only by its node).
    pub strongs: Edges,
    pub nodes: Vec<Node>,
    /// `(t, x)`: what a node reading `t` logs under `t`'s sync ID, holding it otherwise than
    /// through that sync ID: a dependent `x` of another independent thing in `t`'s unit (a bridge),
    /// or the stub of independent `x` outside it (`held_all` computes them, `logs`).
    pub logged: Edges,
    /// `(t, x)`: the public's edge pieces on independent `x` that `t`'s sync ID carries, logged by
    /// a node reading `t` that held them (spec/sync-set.md §2 Public pieces): with `carriers`, `t`'s
    /// keys open what the public reads only by these (`keys`). Logged once, they stay: a caller
    /// tracking a history passes in what was logged before (`held_all` adds what is logged now).
    pub pieces: Edges,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fix {
    Least,
    Greatest,
}

/// The rule and its variants. `Rule::SPEC` is the spec (spec/sync-set.md §2 First entry);
/// `Rule::DRAFT` the control without the three fixes the model found (`record_pieces`,
/// `stubs_at_sync`, `founded_pieces`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub fix: Fix,
    /// First entry checked (off: the walk enters by role alone, the rule removed).
    pub first_entry: bool,
    /// A key part's edge pieces are indexed by every edge its holder holds, the record edge
    /// included (off: by edge writes only).
    pub record_pieces: bool,
    /// A read unit carries the stub of an independent thing a strong of it reaches where the unit's
    /// thing holds sync or above on it (off: only where its keys open it, notes/stubs.md rule 2).
    pub stubs_at_sync: bool,
    /// First entry by an edge piece only in the key part of an own or read thing (off: of any key
    /// part held, a holder held for keys for another synced thing among them).
    pub founded_pieces: bool,
    /// The node root's strongs on the node thing itself (the split undone: a control).
    pub merged: bool,
    /// A read unit's thing or stub held only where its sync ID carries it (`logged`), and what the
    /// public reads opened by T's keys only by a public piece T's sync ID carries (`pieces`; off:
    /// every thing and stub of the unit and every public read, ideal delivery, the control).
    pub carriers: bool,
    /// At a strong from a held thing of read unit T to a dependent D of another independent thing
    /// X that T's keys open (through X's grants: the public's, or T's role on X), the walk enters
    /// X's unit, read: X's sync ID carries D where X's unit holds it, with no bridge (off: D only
    /// as a bridge logs it under T, the control).
    pub dep_entry: bool,
}

impl Rule {
    pub const DRAFT: Rule = Rule { fix: Fix::Least, first_entry: true, record_pieces: false, stubs_at_sync: false, founded_pieces: false, merged: false, carriers: false, dep_entry: false };
    pub const SPEC: Rule = Rule { record_pieces: true, stubs_at_sync: true, founded_pieces: true, carriers: true, dep_entry: true, ..Rule::DRAFT };
}

/// A node's state: the independent things it reads, keeps unread, and whose key parts it holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct S {
    pub read: Set,
    pub kept: Set,
    pub keyparts: Set,
    /// The independent things the walk reached by a strong (entered or not).
    pub reach: Set,
}

/// What a node holds, with the state it came from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Held {
    pub s: S,
    /// Every thing held: the local part, the read units, the things kept unread.
    pub held: Set,
    /// The sync IDs it syncs: read and kept unread things, and holders held for keys.
    pub sync_set: Set,
}

impl Net {
    /// The strongs as the shared world has them: a merged node's root strongs sit on its node thing.
    pub fn edges(&self, rule: Rule) -> Edges {
        if !rule.merged {
            return self.strongs.clone();
        }
        let root_of: BTreeMap<T, T> = self.nodes.iter().map(|n| (n.root, n.thing)).collect();
        self.strongs.iter().map(|&(x, y)| (root_of.get(&x).copied().unwrap_or(x), y)).collect()
    }

    /// The keys of `t` (`World::keys_of`): with `carriers`, what the public reads only where `t`'s
    /// sync ID carries its piece (`pieces`).
    pub fn keys(&self, rule: Rule, t: T) -> Set {
        let mut keys = self.w.keys_of(t);
        if rule.carriers {
            keys.retain(|x| !self.w.public.contains(x) || self.pieces.contains(&(t, *x)) || self.w.roles_from(t).get(x).is_some_and(|&r| r >= Role::Read));
        }
        keys
    }

    /// What a node reading every thing in `reads` holds keys for (`World::ring` by `keys`).
    pub fn ring(&self, rule: Rule, reads: &Set) -> Set {
        reads.iter().flat_map(|&r| self.keys(rule, r)).collect()
    }

    /// T's sync unit (`closure::unit`) by `keys`.
    pub fn unit(&self, rule: Rule, t: T, e: &Edges) -> Set {
        unit_with(&self.w, t, &self.keys(rule, t), e)
    }

    /// What a node reading `t` holds of `t`'s sync unit: with `carriers`, the walk from `t` over
    /// the unit's things its sync ID carries (an independent thing, a dependent of `t`, a logged
    /// one), going on only from those; else the unit.
    pub fn held_unit(&self, rule: Rule, t: T, e: &Edges) -> Set {
        let u = self.unit(rule, t, e);
        if !rule.carriers {
            return u;
        }
        let carried = |x: T| match self.w.kinds[x] {
            Kind::Independent => true,
            Kind::Dependent(k) => k == t || self.logged.contains(&(t, x)),
        };
        let mut seen = Set::from([t]);
        let mut stack = vec![t];
        while let Some(x) = stack.pop() {
            for y in targets(e, x) {
                if u.contains(&y) && carried(y) && seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        seen
    }

    /// Every node's held set under `rule`, with what they log (`logged`, `pieces`): the least
    /// fixpoint, from `self`'s, so everything logged is founded on what some node held before it.
    pub fn held_all(&self, rule: Rule) -> (Vec<Held>, Edges, Edges) {
        let mut net = self.clone();
        loop {
            let held: Vec<Held> = (0..net.nodes.len()).map(|i| net.held_alone(i, rule)).collect();
            let (mut more, mut pieces) = (net.logged.clone(), net.pieces.clone());
            for h in &held {
                more.extend(net.logs(rule, h));
                pieces.extend(net.logs_pieces(rule, h));
            }
            if more == net.logged && pieces == net.pieces {
                return (held, more, pieces);
            }
            (net.logged, net.pieces) = (more, pieces);
        }
    }

    /// The public pieces a node holding `h` logs (spec/sync-set.md §2 Public pieces): `(t, x)` for
    /// each thing `t` it reads and independent `x` the public reads, a strong from a thing it holds
    /// of `t`'s unit reaching `x` or a dependent of it, where it holds the public's grant on `x`: it
    /// syncs `x` (read, kept unread or for keys) or reads a thing whose sync ID carries the piece.
    pub fn logs_pieces(&self, rule: Rule, h: &Held) -> Edges {
        let e = self.edges(rule);
        let holds = |x: T| h.sync_set.contains(&x) || h.s.read.iter().any(|&t| self.pieces.contains(&(t, x)));
        let mut out = Edges::new();
        for &t in &h.s.read {
            let u = self.held_unit(rule, t, &e);
            for &(m, y) in &e {
                let x = match self.w.kinds[y] {
                    Kind::Independent => y,
                    Kind::Dependent(k) => k,
                };
                if u.contains(&m) && self.w.public.contains(&x) && holds(x) {
                    out.insert((t, x));
                }
            }
        }
        out
    }

    /// What a node holding `h` logs, for each thing `t` it reads: `(t, x)` for a dependent `x` of
    /// another independent thing in `t`'s unit that it holds (a bridge), and for each stub `x` of
    /// `t`'s unit (`stub`) one of whose edge pieces it holds: of a holder `g` that `t` holds sync
    /// or above on (`t` itself among them) whose key part it holds, or any where it reads `x`.
    pub fn logs(&self, rule: Rule, h: &Held) -> Edges {
        let e = self.edges(rule);
        let mut out = Edges::new();
        for &t in &h.s.read {
            let u = self.unit(rule, t, &e);
            out.extend(h.held.iter().filter(|&&x| u.contains(&x) && matches!(self.w.kinds[x], Kind::Dependent(k) if k != t)).map(|&x| (t, x)));
            let roles = self.w.roles_from(t);
            let holds_piece = |x: T| h.s.read.contains(&x) || h.s.keyparts.iter().any(|&g| roles.get(&g).is_some_and(|&r| r >= Role::Sync) && self.piece(rule, g, x));
            out.extend(self.stubs(rule, t, &e).into_iter().filter(|&x| holds_piece(x)).map(|x| (t, x)));
        }
        out
    }

    /// The stubs `t`'s unit carries (spec/sync-set.md §2 Stub): each independent thing outside the
    /// unit held of it that a strong of it reaches and `t` holds sync or above on.
    fn stubs(&self, rule: Rule, t: T, e: &Edges) -> Set {
        let u = self.held_unit(rule, t, e);
        let roles = self.w.roles_from(t);
        e.iter().filter(|&&(m, x)| u.contains(&m) && !u.contains(&x) && self.w.independent(x) && roles.get(&x).is_some_and(|&r| r >= Role::Sync)).map(|&(_, x)| x).collect()
    }

    /// The best role `from` holds on each thing over the grants whose target is in `counting`.
    fn roles(&self, from: T, counting: &Set) -> BTreeMap<T, Role> {
        let mut best = BTreeMap::from([(from, Role::Admin)]);
        loop {
            let mut changed = false;
            for (&(a, b), &r) in &self.w.grants {
                if self.w.keyless.contains(&(a, b)) || !counting.contains(&b) {
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
                return best;
            }
        }
    }

    /// Whether `h`'s key part holds an edge piece on `x`.
    fn piece(&self, rule: Rule, h: T, x: T) -> bool {
        self.w.grants.contains_key(&(h, x)) && (rule.record_pieces || !self.records.contains(&(h, x)))
    }

    /// The node's local part: its root and the dependents of its node thing the root reaches.
    fn local(&self, rule: Rule, n: &Node, e: &Edges) -> Set {
        let start = if rule.merged { n.thing } else { n.root };
        let mut seen = Set::from([start]);
        let mut stack = vec![start];
        while let Some(x) = stack.pop() {
            for y in targets(e, x) {
                if self.w.kinds[y] == Kind::Dependent(n.thing) && seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        seen
    }

    /// One step of node `i`'s rule from state `s`.
    pub fn step(&self, i: usize, rule: Rule, s: &S) -> S {
        let n = &self.nodes[i];
        let w = &self.w;
        let e = self.edges(rule);
        // Whether a unit the node syncs carries `x`, or the node holds an offer of it.
        let carried = |x: T| {
            n.offers.contains(&x)
                || s.read.iter().any(|&t| self.held_unit(rule, t, &e).contains(&x))
                || s.keyparts.iter().any(|&h| (!rule.founded_pieces || h == n.thing || s.read.contains(&h)) && self.piece(rule, h, x))
                || rule.stubs_at_sync && s.read.iter().any(|&t| (!rule.carriers || self.logged.contains(&(t, x))) && self.stubs(rule, t, &e).contains(&x))
        };
        // The grants that count: of what the node syncs, holds an offer of, or reaches by a held
        // strong where something it syncs carries it; and up from them.
        let mut counting: Set = s.read.iter().chain(&s.kept).chain(&s.keyparts).chain(&n.offers).copied().collect();
        counting.insert(n.thing);
        counting.extend(s.reach.iter().copied().filter(|&x| !rule.first_entry || carried(x)));
        loop {
            let up: Set = w.grants.keys().filter(|&&(h, t)| !w.keyless.contains(&(h, t)) && counting.contains(&t) && !counting.contains(&h)).map(|&(h, _)| h).collect();
            if up.is_empty() {
                break;
            }
            counting.extend(up);
        }
        // the node's role: its own thing's, and the public's (every party's, spec/sync-set.md §2
        // Own things), at most read, through holders as any holder's, from the things it reads
        // (holding their grants; a public piece shows the public's grant on its thing alone)
        let mut role = self.roles(n.thing, &counting);
        for &x in w.public.iter().filter(|x| s.read.contains(x)) {
            for (y, r) in self.roles(x, &counting) {
                let v = r.min(Role::Read);
                if role.get(&y).is_none_or(|&o| o < v) {
                    role.insert(y, v);
                }
            }
        }
        let at =|x: T, r: Role| role.get(&x).is_some_and(|&v| v >= r);
        // The walk: strongs from the local part and from read units to independent things.
        let mut out = S::default();
        let mut todo: Vec<T> = vec![n.thing];
        for x in self.local(rule, n, &e) {
            todo.extend(targets(&e, x).filter(|&y| w.independent(y)));
        }
        let mut done = Set::new();
        // the independents entered at a strong to a dependent of theirs (`dep_entry`): by the
        // unit's keys, which open them
        let mut by_dep = Set::new();
        while let Some(t) = todo.pop() {
            if !done.insert(t) {
                continue;
            }
            let own = t == n.thing;
            if !own && !by_dep.contains(&t) && !(at(t, Role::Sync) && (!rule.first_entry || carried(t))) {
                continue;
            }
            if own || by_dep.contains(&t) || at(t, Role::Read) {
                let u = self.held_unit(rule, t, &e);
                out.read.extend(u.iter().copied().filter(|&x| w.independent(x)));
                let whole = self.unit(rule, t, &e);
                for &m in &u {
                    todo.extend(targets(&e, m).filter(|&y| w.independent(y) && !u.contains(&y)));
                    if rule.dep_entry {
                        for y in targets(&e, m).filter(|y| whole.contains(y)) {
                            let Kind::Dependent(x) = w.kinds[y] else { continue };
                            if x != t && w.independent(x) && by_dep.insert(x) {
                                done.remove(&x);
                                todo.push(x);
                            }
                        }
                    }
                }
            } else {
                out.kept.insert(t);
            }
        }
        out.reach = done;
        // Key parts: the read things' (own among them), and the holders held for keys, found up
        // from each synced thing (spec/sync-set.md §2 Held for keys).
        out.keyparts = out.read.clone();
        let mut up: Vec<(T, bool)> = out.read.iter().chain(&out.kept).map(|&x| (x, true)).collect();
        while let Some((x, synced)) = up.pop() {
            for (&(h, t), &r) in &w.grants {
                let hop = t == x && !w.keyless.contains(&(h, t)) && (synced || r >= Role::Read);
                if hop && at(h, Role::Read) && out.keyparts.insert(h) {
                    up.push((h, false));
                }
            }
        }
        out
    }

    fn top(&self) -> S {
        let all: Set = (0..self.w.kinds.len()).filter(|&x| self.w.independent(x)).collect();
        S { read: all.clone(), kept: all.clone(), keyparts: all.clone(), reach: all }
    }

    /// Iterates the step from `s` until it stops changing.
    pub fn settle(&self, i: usize, rule: Rule, mut s: S) -> S {
        for _ in 0..4 * self.w.kinds.len() + 8 {
            let next = self.step(i, rule, &s);
            if next == s {
                return s;
            }
            s = next;
        }
        panic!("node {i} does not settle under {rule:?}");
    }

    /// What node `i` holds under `rule`: with `carriers`, as what every node logs leaves it
    /// (`held_all`).
    pub fn held(&self, i: usize, rule: Rule) -> Held {
        if !rule.carriers {
            return self.held_alone(i, rule);
        }
        let (mut all, ..) = self.held_all(rule);
        all.swap_remove(i)
    }

    /// What node `i` holds under `rule`, what is logged `self.logged`.
    pub fn held_alone(&self, i: usize, rule: Rule) -> Held {
        let start = match rule.fix {
            Fix::Least => S::default(),
            Fix::Greatest => self.top(),
        };
        let s = self.settle(i, rule, start);
        self.held_from(i, rule, s)
    }

    /// What node `i` holds in state `s`.
    pub fn held_from(&self, i: usize, rule: Rule, s: S) -> Held {
        let n = &self.nodes[i];
        let e = self.edges(rule);
        let mut held = self.local(rule, n, &e);
        for &t in &s.read {
            held.extend(self.held_unit(rule, t, &e));
        }
        held.extend(&s.kept);
        let sync_set = s.read.iter().chain(&s.kept).chain(&s.keyparts).copied().collect();
        Held { s, held, sync_set }
    }
}
