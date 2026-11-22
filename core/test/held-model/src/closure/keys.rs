//! Holder access (notes/holder-access-study.md, The direction; results there under The model): a role on a
//! thing through holders, used without the holders' content. Properties in
//! tests/it/spec_holders.rs, findings in the study.
//!
//! **The oracle** (`oracle`): a node's role on a thing it syncs is its own actors' effective role
//! over the world's grants; what it syncs is the walk from its root strongs with read-ness by that
//! role (roles never feed what syncs: a role opens no thing no strong reaches); `for_keys` is every
//! holder on every path of grants from an own actor to a synced thing, less what is held whole.
//!
//! **The key part** of a thing (`Keys`): its edges (the grants naming it as target), one keyset
//! per epoch and one box per holder per epoch. Revoking a grant on a thing rotates it at once
//! (a new epoch, boxed to the holders left, each at its current epoch) and leaves every thing below
//! it stale; a stale thing rotates when next written (`rotate`). A grant boxes the target's
//! current epoch to the holder.
//!
//! **A node** (`Node`) finds its paths by a `Search`, fetches from a `Source` and counts every
//! item it fetches once (`Item`, `Ledger`): edge writes and keysets (role entries), boxes, list
//! entries and keyed lookups of the search, content. `Rule` names the design and its controls.
//!
//! Abstracted: every thing is independent; an own actor's secrets are the node's; holding a
//! thing's epoch `e` gives every earlier one; a thing's rotation is readable under the epoch
//! before (its own sync ID gives every box but the first); a holder's part is readable by a node
//! holding the holder's current epoch, an own actor's by the node; a keyless grant
//! (`World::keyless`) is on no path. Left out: validity (roles-model `paths`), which path a write
//! states, sealing, the wire.
use super::{keyless_of, walk_with, Closure, Edges, Kind, NodeView, Role, Set, Walk, World, T};
use std::collections::{BTreeMap, BTreeSet};

/// The best role any of `own` holds on each thing over `w`'s grants.
pub fn roles_of(w: &World, own: &Set) -> BTreeMap<T, Role> {
    let mut out = BTreeMap::new();
    for &a in own {
        for (t, r) in w.roles_from(a) {
            let e = out.entry(t).or_insert(r);
            *e = (*e).max(r);
        }
    }
    out
}

/// The things on a path of `edges` from one of `own` to one of `targets` with a hop after them
/// (holders: no own actor), and the edges on such paths.
pub fn on_paths(edges: &BTreeSet<(T, T)>, own: &Set, targets: &Set) -> (Set, BTreeSet<(T, T)>) {
    let reach = |from: &Set, fwd: bool| {
        let mut seen = from.clone();
        let mut todo: Vec<T> = from.iter().copied().collect();
        while let Some(x) = todo.pop() {
            for &(a, b) in edges {
                let (s, d) = if fwd { (a, b) } else { (b, a) };
                if s == x && seen.insert(d) {
                    todo.push(d);
                }
            }
        }
        seen
    };
    let (fwd, back) = (reach(own, true), reach(targets, false));
    let on: BTreeSet<(T, T)> = edges.iter().copied().filter(|(a, b)| fwd.contains(a) && back.contains(b)).collect();
    let holders = on.iter().map(|&(a, _)| a).filter(|a| !own.contains(a)).collect();
    (holders, on)
}

/// The edges of one path per target: the shortest among those giving the role `roles` names
/// (what a write picks). The control of (iv).
fn chosen(edges: &BTreeMap<(T, T), Role>, own: &Set, targets: &Set, roles: &BTreeMap<T, Role>) -> (Set, BTreeSet<(T, T)>) {
    let mut on = BTreeSet::new();
    for &t in targets {
        let Some(&need) = roles.get(&t) else { continue };
        let mut parent: BTreeMap<T, T> = BTreeMap::new();
        let mut seen = own.clone();
        let mut level: Vec<T> = own.iter().copied().collect();
        while !level.is_empty() && !seen.contains(&t) {
            let mut next = vec![];
            for &x in &level {
                for (&(a, b), &r) in edges.range((x, 0)..=(x, T::MAX)) {
                    if r >= need && seen.insert(b) {
                        parent.insert(b, a);
                        next.push(b);
                    }
                }
            }
            level = next;
        }
        let mut x = t;
        while let Some(&p) = parent.get(&x) {
            on.insert((p, x));
            x = p;
        }
    }
    let holders = on.iter().map(|&(a, _)| a).filter(|a| !own.contains(a)).collect();
    (holders, on)
}

/// The walk from `roots` reading by `roles`, where `has` says the node holds a thing's secrets.
fn walk(w: &World, e: &Edges, roots: &Set, roles: &BTreeMap<T, Role>, has: impl Fn(T) -> bool) -> Closure {
    let ring: Set = roles.iter().filter(|&(&x, &r)| r >= Role::Read && has(x)).map(|(&x, _)| x).collect();
    let sync: Set = roles.keys().copied().filter(|&x| has(x)).collect();
    let mut c = walk_with(w, e, &NodeView { roots: roots.clone(), tickets: BTreeMap::new() }, Walk::Units, &ring, &sync);
    (c.keys, c.synced) = (ring, sync);
    c
}

/// What a node shows: its closure (`for_keys` included) and its role on each thing it syncs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    pub closure: Closure,
    pub roles: BTreeMap<T, Role>,
}

impl Seen {
    pub fn synced(&self) -> Set {
        self.closure.read.union(&self.closure.stored).copied().collect()
    }
}

/// The direction's definition: what a node with own actors `own` and root strongs to `roots`
/// syncs, holds for keys and may do, as a function of the world alone.
pub fn oracle(k: &Keys, own: &Set, roots: &Set) -> Seen {
    let all = roles_of(&k.world, own);
    let mut closure = walk(&k.world, &k.strongs, roots, &all, |_| true);
    let synced: Set = closure.read.union(&closure.stored).copied().collect();
    let (holders, _) = on_paths(&k.keyed_edges(), own, &synced);
    closure.for_keys = holders.difference(&closure.held).copied().collect();
    let roles = all.into_iter().filter(|(t, _)| synced.contains(t)).collect();
    Seen { closure, roles }
}

// ---- The world's key parts ----

#[derive(Clone, Debug, Default)]
pub struct Keys {
    pub world: World,
    /// The strongs inside things.
    pub strongs: Edges,
    /// Per strong inside a thing, the holders its maker names (p3).
    pub hints: BTreeMap<(T, T), Set>,
    pub epoch: Vec<u32>,
    /// `(x, e, h, eh)`: `x`'s epoch `e` boxed to holder `h` at its epoch `eh`.
    pub boxes: BTreeSet<(T, u32, T, u32)>,
    /// How many times each edge was written.
    pub ver: BTreeMap<(T, T), u32>,
    pub content: Vec<u32>,
    /// The things owing a rotation: a thing above them rotated.
    pub stale: Set,
    /// The grants standing, in the order made (which of a cycle's is keyless).
    pub order: Vec<(T, T)>,
    /// Every role commit made.
    pub log: Vec<(T, T, Option<Role>)>,
    /// A control of the fixpoint: no grant is keyless, so holders may form cycles.
    pub raw_cycles: bool,
}

impl Keys {
    pub fn new(things: usize) -> Keys {
        Keys { world: World { kinds: vec![Kind::Independent; things], ..World::default() }, epoch: vec![0; things], content: vec![0; things], ..Keys::default() }
    }
    pub fn thing(&mut self) -> T {
        self.world.kinds.push(Kind::Independent);
        self.epoch.push(0);
        self.content.push(0);
        self.epoch.len() - 1
    }
    /// The role of a grant with key access.
    pub fn keyed(&self, h: T, x: T) -> Option<Role> {
        self.world.grants.get(&(h, x)).copied().filter(|_| !self.world.keyless.contains(&(h, x)))
    }
    pub fn keyed_edges(&self) -> BTreeSet<(T, T)> {
        self.world.grants.keys().copied().filter(|e| !self.world.keyless.contains(e)).collect()
    }
    fn rekey(&mut self) {
        if !self.raw_cycles {
            self.world.keyless = keyless_of(&self.order);
        }
        for (g, t) in self.keyed_edges() {
            if !self.boxes.range((t, self.epoch[t], g, 0)..=(t, self.epoch[t], g, u32::MAX)).any(|_| true) {
                self.boxes.insert((t, self.epoch[t], g, self.epoch[g]));
            }
        }
    }
    pub fn grant(&mut self, g: T, t: T, r: Role) {
        if self.world.grants.insert((g, t), r).is_none() {
            self.order.push((g, t));
        }
        *self.ver.entry((g, t)).or_default() += 1;
        self.log.push((g, t, Some(r)));
        self.rekey();
    }
    /// Removes `g`'s grant on `t`: `t` rotates, everything below it is stale.
    pub fn revoke(&mut self, g: T, t: T) -> bool {
        if self.world.grants.remove(&(g, t)).is_none() {
            return false;
        }
        self.order.retain(|&e| e != (g, t));
        *self.ver.entry((g, t)).or_default() += 1;
        self.log.push((g, t, None));
        self.rekey();
        let below = self.world.keys_of(t);
        self.rotate(t);
        self.stale.extend(below.into_iter().filter(|&x| x != t));
        true
    }
    /// A new epoch of `x`, boxed to each holder at its current epoch.
    pub fn rotate(&mut self, x: T) {
        self.epoch[x] += 1;
        for (g, t) in self.keyed_edges() {
            if t == x {
                self.boxes.insert((x, self.epoch[x], g, self.epoch[g]));
            }
        }
        self.stale.remove(&x);
    }
    /// Every stale thing rotates, those above first (a thing is boxed to its holders' new epochs).
    pub fn rotate_stale(&mut self) {
        while let Some(&x) = self.stale.iter().find(|&&x| !self.stale.iter().any(|&y| y != x && self.world.keys_of(y).contains(&x))).or(self.stale.iter().next()) {
            self.rotate(x);
        }
    }
    pub fn edit(&mut self, x: T) {
        self.content[x] += 1;
    }
    pub fn strong(&mut self, from: T, to: T, hint: &Set) {
        self.strongs.insert((from, to));
        self.hints.insert((from, to), hint.clone());
    }
    pub fn unstrong(&mut self, from: T, to: T) {
        self.strongs.remove(&(from, to));
        self.hints.remove(&(from, to));
    }
    /// The holders of every simple path of keyed grants from one of `own` to `t`, the path a
    /// write would pick first (best role, then shortest).
    pub fn paths(&self, own: &Set, t: T) -> Vec<Vec<T>> {
        fn go(k: &Keys, own: &Set, t: T, at: T, role: Role, path: &mut Vec<T>, out: &mut Vec<(Role, Vec<T>)>) {
            for (&(_, b), &r) in k.world.grants.range((at, 0)..=(at, T::MAX)) {
                if k.world.keyless.contains(&(at, b)) || own.contains(&b) || path.contains(&b) {
                    continue;
                }
                if b == t {
                    out.push((role.min(r), path.clone()));
                } else {
                    path.push(b);
                    go(k, own, t, b, role.min(r), path, out);
                    path.pop();
                }
            }
        }
        let mut out = vec![];
        for &a in own {
            go(self, own, t, a, Role::Admin, &mut vec![], &mut out);
        }
        out.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.len().cmp(&b.1.len())).then(a.1.cmp(&b.1)));
        out.into_iter().map(|x| x.1).collect()
    }
}

// ---- A node ----

/// How a node finds the holders on its paths (the study's Open: finding the paths).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Search {
    /// (p1) Reads the edge list of every holder its own actors reach by grants, fetches key
    /// parts only for holders on a path.
    Lists,
    /// (p3) alone: keyed lookups among its own actors, the holders a strong names and the
    /// strong's target.
    Hint,
    /// (p2) alone: keyed lookups from what it has opened to the holders the rosters of the things
    /// it reads name.
    Roster,
    /// The lean: (p3), then (p2).
    HintRoster,
    /// The lean, reading also the roster of every holder on a path found.
    HintRosterDeep,
    /// Backward by rosters: reads the roster of every thing on a chain of grants ending at a thing
    /// its strongs reach, opened or not (so it needs a holder's roster readable by the readers of
    /// what the holder has a role on), fetches key parts only for holders on a path.
    Back,
    /// Control of (ii): follows every grant naming an own actor or a holder so reached.
    Follow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Paths {
    /// Every holder on every path.
    All,
    /// Control of (iv): the holders of the path a write picks.
    Chosen,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boxes {
    /// The boxes the node opens.
    Own,
    /// Control of (v): every box of a rotation it fetches, and of every thing a holder it holds
    /// has a role on.
    Whole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RolesBy {
    /// Over the edges of the paths found, each as its holder's part gives it.
    Chains,
    /// Control of (i): over every role commit held, certificates that arrived for another reason
    /// included.
    HeldEdges,
    /// Control of (iii): the rule before (`World::roles_from_reached`): an own actor's grant
    /// counts only on a thing a strong reaches.
    Reached,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub search: Search,
    pub paths: Paths,
    pub boxes: Boxes,
    pub roles: RolesBy,
}

impl Rule {
    pub fn with(search: Search) -> Rule {
        Rule { search, paths: Paths::All, boxes: Boxes::Own, roles: RolesBy::Chains }
    }
}

/// One fetched thing; a node's ledger is the set of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Item {
    /// Role entry: the edge write of `(holder, target)` at its version.
    Edge(T, T, u32),
    /// Role entry: a thing's keyset at an epoch.
    Keyset(T, u32),
    /// A thing's epoch boxed to a holder.
    Box(T, u32, T),
    /// A keyed lookup of `(holder, target)` in the holder's part, hit or miss.
    Probe(T, T, u32),
    /// An entry of a holder's edge list (or, searching backward, of a target's roster) read by a
    /// list search.
    List(T, T, u32),
    Content(T, u32),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    pub edges: usize,
    pub keysets: usize,
    pub boxes: usize,
    pub probes: usize,
    pub lists: usize,
    pub content: usize,
}

impl Ledger {
    pub fn of<'a>(items: impl IntoIterator<Item = &'a Item>) -> Ledger {
        let mut l = Ledger::default();
        for i in items {
            match i {
                Item::Edge(..) => l.edges += 1,
                Item::Keyset(..) => l.keysets += 1,
                Item::Box(..) => l.boxes += 1,
                Item::Probe(..) => l.probes += 1,
                Item::List(..) => l.lists += 1,
                Item::Content(..) => l.content += 1,
            }
        }
        l
    }
}

/// What a node can reach in one sync: the sync IDs served whole (kept read or unread) and the
/// holders whose key part is served (`None`: all). A sync ID served whole serves its key part.
#[derive(Clone, Debug, Default)]
pub struct Source {
    pub units: Option<Set>,
    pub parts: Option<Set>,
}

impl Source {
    pub fn all() -> Source {
        Source::default()
    }
    pub fn unit(&self, x: T) -> bool {
        self.units.as_ref().is_none_or(|u| u.contains(&x))
    }
    pub fn part(&self, h: T) -> bool {
        self.parts.as_ref().is_none_or(|p| p.contains(&h)) || self.units.as_ref().is_some_and(|u| u.contains(&h))
    }
}

#[derive(Clone, Debug, Default)]
pub struct Node {
    pub own: Set,
    /// The node root's strongs: target, and the holders the strong names (p3).
    pub roots: BTreeMap<T, Set>,
    /// The edges held, each as last fetched: the pieces of its paths and the rosters of what it reads.
    pub edges: BTreeMap<(T, T), Role>,
    /// The newest epoch held of each thing whose secrets it holds.
    pub have: BTreeMap<T, u32>,
    /// The strongs of each thing read, as last fetched, with their hints.
    pub inner: BTreeMap<T, BTreeMap<T, Set>>,
    /// Role commits held for another reason (evidence copies, certificates): the grants they show.
    pub certs: BTreeMap<(T, T), Role>,
    /// Everything fetched.
    pub got: BTreeSet<Item>,
    pub seen: Seen,
    /// A sync that did not settle (never, by the properties).
    pub unsettled: bool,
}

impl Node {
    pub fn new(own: &Set) -> Node {
        Node { own: own.clone(), ..Node::default() }
    }
    pub fn ledger(&self) -> Ledger {
        Ledger::of(&self.got)
    }
    fn open(&self, k: &Keys, h: T) -> bool {
        self.own.contains(&h) || self.have.get(&h) == Some(&k.epoch[h])
    }
    /// Whether a write of `t` by this node applies: write or above, sealed to `t`'s current epoch.
    pub fn can_write(&self, k: &Keys, t: T) -> bool {
        self.seen.roles.get(&t).is_some_and(|&r| r >= Role::Write) && self.open(k, t)
    }
    /// Receives the edge write of `(h, x)` as it stands, from whoever made it.
    pub fn hear(&mut self, k: &Keys, h: T, x: T) {
        self.piece(k, h, x);
    }
    /// Fetches the edge `(h, x)` as the world has it.
    fn piece(&mut self, k: &Keys, h: T, x: T) {
        self.got.insert(Item::Edge(h, x, k.ver.get(&(h, x)).copied().unwrap_or(0)));
        match k.keyed(h, x) {
            Some(r) => self.edges.insert((h, x), r),
            None => self.edges.remove(&(h, x)),
        };
    }
    /// Opens every newer epoch a held edge's boxes give: from the holder's part, or (not the
    /// first) from the thing's own rotation, read under the epoch before.
    fn advance(&mut self, k: &Keys, src: &Source) {
        loop {
            let mut moved = false;
            for (h, x) in self.edges.keys().copied().collect::<Vec<_>>() {
                if self.own.contains(&x) {
                    continue;
                }
                let hh = match (self.own.contains(&h), self.have.get(&h)) {
                    (true, _) => k.epoch[h],
                    (_, Some(&e)) => e,
                    _ => continue,
                };
                let cur = self.have.get(&x).copied();
                let via_h = src.part(h) && self.open(k, h);
                let own_next = |e: u32| src.part(x) && cur.is_some_and(|c| e == c + 1);
                let best = k
                    .boxes
                    .range((x, 0, 0, 0)..=(x, u32::MAX, T::MAX, u32::MAX))
                    .filter(|b| b.2 == h && b.3 <= hh && cur.is_none_or(|c| b.1 > c) && (via_h || own_next(b.1)))
                    .map(|b| b.1)
                    .max();
                if let Some(e) = best {
                    self.have.insert(x, e);
                    self.got.extend([Item::Box(x, e, h), Item::Keyset(x, e)]);
                    moved = true;
                }
            }
            if !moved {
                return;
            }
        }
    }
    /// The closure by the roles the node computes, those roles, and the things its strongs reach.
    fn judge(&self, k: &Keys, rule: &Rule) -> (Closure, BTreeMap<T, Role>, Set) {
        let has = |x: T| self.own.contains(&x) || self.have.contains_key(&x);
        let mut grants = self.edges.clone();
        if rule.roles == RolesBy::HeldEdges {
            for (&e, &r) in &self.certs {
                grants.entry(e).or_insert(r);
            }
        }
        let kinds = k.world.kinds.clone();
        let opened = World { kinds: kinds.clone(), grants: self.edges.iter().filter(|(e, _)| has(e.1)).map(|(&e, &r)| (e, r)).collect(), keyless: BTreeSet::new() };
        let all = World { kinds, grants, keyless: BTreeSet::new() };
        let roots: Set = self.roots.keys().copied().collect();
        let strongs: Edges = self.inner.iter().flat_map(|(&x, ts)| ts.keys().map(move |&y| (x, y))).collect();
        let reached_by = |c: &Closure| -> Set { roots.iter().copied().chain(strongs.iter().filter(|(x, _)| c.read.contains(x)).map(|&(_, y)| y)).collect() };
        if rule.roles != RolesBy::Reached {
            let roles = roles_of(&all, &self.own);
            let c = walk(&opened, &strongs, &roots, &roles, has);
            let reached = reached_by(&c);
            return (c, roles, reached);
        }
        let mut reached = roots.clone();
        loop {
            let mut roles = BTreeMap::new();
            for &a in &self.own {
                for (t, r) in all.roles_from_reached(a, &reached) {
                    let e = roles.entry(t).or_insert(r);
                    *e = (*e).max(r);
                }
            }
            let c = walk(&opened, &strongs, &roots, &roles, has);
            let next = reached_by(&c);
            if next == reached {
                return (c, roles, reached);
            }
            reached = next;
        }
    }
    fn search(&mut self, k: &Keys, rule: &Rule, src: &Source, c: &Closure, reached: &Set) {
        let known: BTreeSet<(T, T)> = self.edges.keys().copied().collect();
        let synced: Set = c.read.union(&c.stored).copied().collect();
        let mut fwd = self.own.clone();
        let mut todo: Vec<T> = fwd.iter().copied().collect();
        while let Some(x) = todo.pop() {
            for &(_, b) in known.range((x, 0)..=(x, T::MAX)) {
                if fwd.insert(b) {
                    todo.push(b);
                }
            }
        }
        let opened: Vec<T> = fwd.iter().copied().filter(|&h| self.open(k, h) && src.part(h)).collect();
        let ver = |h: T, x: T| k.ver.get(&(h, x)).copied().unwrap_or(0);
        match rule.search {
            Search::Lists => {
                let mut listed = BTreeSet::new();
                let mut seen = self.own.clone();
                let mut todo: Vec<T> = seen.iter().copied().collect();
                while let Some(h) = todo.pop() {
                    if !src.part(h) {
                        continue;
                    }
                    for (&(_, x), _) in k.world.grants.range((h, 0)..=(h, T::MAX)) {
                        if k.world.keyless.contains(&(h, x)) {
                            continue;
                        }
                        self.got.insert(Item::List(h, x, ver(h, x)));
                        listed.insert((h, x));
                        if seen.insert(x) {
                            todo.push(x);
                        }
                    }
                }
                for (h, x) in on_paths(&listed, &self.own, reached).1 {
                    if opened.contains(&h) {
                        self.piece(k, h, x);
                    }
                }
            }
            Search::Back => {
                let mut listed = BTreeSet::new();
                let mut seen = reached.clone();
                let mut todo: Vec<T> = seen.iter().copied().collect();
                while let Some(x) = todo.pop() {
                    if self.own.contains(&x) || !src.part(x) {
                        continue;
                    }
                    for (g, _) in k.keyed_edges().into_iter().filter(|e| e.1 == x) {
                        self.got.insert(Item::List(g, x, ver(g, x)));
                        listed.insert((g, x));
                        if seen.insert(g) {
                            todo.push(g);
                        }
                    }
                }
                for (h, x) in on_paths(&listed, &self.own, reached).1 {
                    if opened.contains(&h) {
                        self.piece(k, h, x);
                    }
                }
            }
            Search::Follow => {
                for &h in &opened {
                    for (h, x) in k.world.grants.range((h, 0)..=(h, T::MAX)).map(|(&e, _)| e).collect::<Vec<_>>() {
                        self.piece(k, h, x);
                    }
                }
            }
            Search::Hint | Search::Roster | Search::HintRoster | Search::HintRosterDeep => {
                let mut wanted = reached.clone();
                if rule.search != Search::Roster {
                    wanted.extend(self.roots.values().flatten());
                    wanted.extend(self.inner.iter().filter(|(x, _)| c.read.contains(x)).flat_map(|(_, ts)| ts.values().flatten()));
                }
                if rule.search != Search::Hint {
                    wanted.extend(known.iter().filter(|(_, x)| c.read.contains(x)).map(|&(g, _)| g));
                }
                if rule.search == Search::HintRosterDeep {
                    for h in on_paths(&known, &self.own, &synced).0 {
                        if opened.contains(&h) {
                            for g in k.keyed_edges().into_iter().filter(|e| e.1 == h).map(|e| e.0).collect::<Vec<_>>() {
                                self.piece(k, g, h);
                                wanted.insert(g);
                            }
                        }
                    }
                }
                for &h in &opened {
                    for &x in &wanted {
                        if x != h && !self.own.contains(&x) {
                            self.got.insert(Item::Probe(h, x, ver(h, x)));
                            if k.keyed(h, x).is_some() {
                                self.piece(k, h, x);
                            }
                        }
                    }
                }
            }
        }
    }
    /// One sync against `src`, to its end: refreshes what it holds, searches, fetches, then lets
    /// go of what is on no path to a thing it syncs.
    pub fn sync(&mut self, k: &Keys, rule: &Rule, src: &Source) -> &Seen {
        self.unsettled = true;
        for _ in 0..4 * (k.epoch.len() + 4) {
            let before = (self.edges.clone(), self.have.clone(), self.inner.clone());
            for (h, x) in self.edges.keys().copied().collect::<Vec<_>>() {
                if src.part(h) && self.open(k, h) {
                    self.piece(k, h, x);
                }
            }
            self.advance(k, src);
            let (c, _, reached) = self.judge(k, rule);
            for &x in &c.read {
                if src.unit(x) && self.open(k, x) {
                    for (g, _) in self.edges.keys().copied().filter(|e| e.1 == x).collect::<Vec<_>>() {
                        self.piece(k, g, x);
                    }
                    for (g, _) in k.keyed_edges().into_iter().filter(|e| e.1 == x) {
                        self.piece(k, g, x);
                    }
                    let strongs = k.strongs.range((x, 0)..=(x, T::MAX)).map(|&(_, y)| (y, k.hints.get(&(x, y)).cloned().unwrap_or_default())).collect();
                    self.inner.insert(x, strongs);
                    self.got.insert(Item::Content(x, k.content[x]));
                }
            }
            for &x in &c.stored {
                if src.unit(x) {
                    self.got.insert(Item::Content(x, k.content[x]));
                }
            }
            self.inner.retain(|x, _| c.read.contains(x));
            self.search(k, rule, src, &c, &reached);
            if before == (self.edges.clone(), self.have.clone(), self.inner.clone()) {
                self.unsettled = false;
                break;
            }
        }
        let (c, roles, _) = self.judge(k, rule);
        let synced: Set = c.read.union(&c.stored).copied().collect();
        let known: BTreeSet<(T, T)> = self.edges.keys().copied().collect();
        let (holders, on) = match (rule.search, rule.paths) {
            (Search::Follow, _) => (known.iter().flat_map(|&(a, b)| [a, b]).filter(|x| !self.own.contains(x)).collect(), known.clone()),
            (_, Paths::All) => on_paths(&known, &self.own, &synced),
            (_, Paths::Chosen) => chosen(&self.edges, &self.own, &synced, &roles),
        };
        self.edges.retain(|e, _| on.contains(e) || c.read.contains(&e.1));
        self.have.retain(|x, _| synced.contains(x) || holders.contains(x));
        self.inner.retain(|x, _| c.read.contains(x));
        if rule.boxes == Boxes::Whole {
            let all = |x: T, e: u32| k.boxes.range((x, e, 0, 0)..=(x, e, T::MAX, u32::MAX)).map(|b| Item::Box(b.0, b.1, b.2)).collect::<Vec<_>>();
            for i in self.got.clone() {
                if let Item::Keyset(x, e) = i {
                    self.got.extend(all(x, e));
                }
            }
            for &h in holders.iter().chain(&c.read) {
                if self.open(k, h) && src.part(h) {
                    for (&(_, x), _) in k.world.grants.range((h, 0)..=(h, T::MAX)) {
                        self.got.extend(all(x, k.epoch[x]));
                    }
                }
            }
        }
        let (mut closure, roles, _) = self.judge(k, rule);
        closure.for_keys = holders.difference(&closure.held).copied().collect();
        let synced = closure.read.union(&closure.stored).copied().collect::<Set>();
        self.seen = Seen { closure, roles: roles.into_iter().filter(|(t, _)| synced.contains(t)).collect() };
        &self.seen
    }
}
