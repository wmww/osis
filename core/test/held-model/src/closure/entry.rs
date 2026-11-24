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
//! Abstracted: every edge piece the spec indexes is logged under its holder's sync ID (ideal
//! delivery); grants sit on independent things; a box exists for every keyed edge; validity,
//! rotation, timing and the wire are left out. An edge piece is the current grant's: a removal's
//! piece carries nothing, since a loss is carried out at once here (the engine's carries until
//! the node's read secrets go, spec/sync-set.md §2 First entry).
use super::{targets, unit, Edges, Kind, Role, Set, World, T};
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fix {
    Least,
    Greatest,
}

/// The rule and its variants. `Rule::SPEC` is the spec as written; `Rule::FIXED` the design with
/// the fixes the model found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub fix: Fix,
    /// First entry checked (off: the walk enters by role alone, the rule removed).
    pub first_entry: bool,
    /// A key part's edge pieces are indexed by every edge its holder holds, the record edge
    /// included (off: by edge writes only, spec/permissions.md §4 Key part as written).
    pub record_pieces: bool,
    /// A read unit carries the stub of an independent thing a strong of it reaches where the unit's
    /// thing holds sync or above on it (off: only where its keys open it, notes/stubs.md rule 2).
    pub stubs_at_sync: bool,
    /// First entry by an edge piece only in the key part of an own or read thing (off: of any key
    /// part held, a holder held for keys for another synced thing among them).
    pub founded_pieces: bool,
    /// The node root's strongs on the node thing itself (the split undone: a control).
    pub merged: bool,
}

impl Rule {
    pub const SPEC: Rule = Rule { fix: Fix::Least, first_entry: true, record_pieces: false, stubs_at_sync: false, founded_pieces: false, merged: false };
    pub const FIXED: Rule = Rule { record_pieces: true, stubs_at_sync: true, founded_pieces: true, ..Rule::SPEC };
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
                || s.read.iter().any(|&t| unit(w, t, &e).contains(&x))
                || s.keyparts.iter().any(|&h| (!rule.founded_pieces || h == n.thing || s.read.contains(&h)) && self.piece(rule, h, x))
                || rule.stubs_at_sync
                    && s.read.iter().any(|&t| {
                        let u = unit(w, t, &e);
                        u.iter().any(|&m| e.contains(&(m, x))) && w.roles_from(t).get(&x).is_some_and(|&r| r >= Role::Sync)
                    })
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
        let role = self.roles(n.thing, &counting);
        let at = |x: T, r: Role| role.get(&x).is_some_and(|&v| v >= r);
        // The walk: strongs from the local part and from read units to independent things.
        let mut out = S::default();
        let mut todo: Vec<T> = vec![n.thing];
        for x in self.local(rule, n, &e) {
            todo.extend(targets(&e, x).filter(|&y| w.independent(y)));
        }
        let mut done = Set::new();
        while let Some(t) = todo.pop() {
            if !done.insert(t) {
                continue;
            }
            let own = t == n.thing;
            if !own && !(at(t, Role::Sync) && (!rule.first_entry || carried(t))) {
                continue;
            }
            if own || at(t, Role::Read) {
                let u = unit(w, t, &e);
                out.read.extend(u.iter().copied().filter(|&x| w.independent(x)));
                for &m in &u {
                    todo.extend(targets(&e, m).filter(|&y| w.independent(y) && !u.contains(&y)));
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

    /// What node `i` holds under `rule`.
    pub fn held(&self, i: usize, rule: Rule) -> Held {
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
            held.extend(unit(&self.w, t, &e));
        }
        held.extend(&s.kept);
        let sync_set = s.read.iter().chain(&s.kept).chain(&s.keyparts).copied().collect();
        Held { s, held, sync_set }
    }
}
