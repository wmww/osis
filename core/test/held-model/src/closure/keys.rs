//! Holder access (notes/holder-access-study.md, The direction; results there under The model): a role on a
//! thing through holders, used without the holders' content. Properties in
//! tests/it/spec_holders.rs, findings in the study.
//!
//! **Taken grants** (direction 2, 3): a grant naming holder `h` is in its target's roster
//! whoever wrote it. `h` takes it, and it sits under `h`'s own sync ID, iff a writer of `h` wrote it
//! (`From::Writer`: `h`'s data) or `h`'s admins enabled grants from outside (`Keys::grantable`, the
//! current setting) and it came from outside (`From::Outside`: an external signal). Only taken
//! grants give roles, lie on paths and are listed in a holder's key part.
//!
//! **The oracle** (`oracle`): a node's role on a thing it syncs is its own actors' effective role
//! over the world's taken grants; what it syncs is the walk from its root strongs with read-ness by
//! that role (roles never feed what syncs: a role opens no thing no strong reaches); `for_keys` is
//! every holder on every path of taken grants from an own actor to a synced thing, less what is
//! held whole.
//!
//! **The key part** of a thing (`Keys`): its taken grants, one keyset per epoch and one box per
//! holder per epoch. Revoking a grant on a thing rotates it at once (a new epoch, boxed to the
//! holders left, each at its current epoch) and leaves every thing below it stale; a stale thing
//! rotates when next written (`rotate`). A grant boxes the target's current epoch to the holder.
//!
//! **A node** (`Node`) finds its paths down from its own actors' taken grants (the lists of the
//! holders it opens: `Search::Lists` of the study), fetches from a `Source` and counts every item it
//! fetches once (`Item`, `Ledger`): edge writes and keysets (role entries), boxes, list entries,
//! content. `Rule` names the design and its controls.
//!
//! Abstracted: every thing is independent; an own actor's secrets are the node's; holding a
//! thing's epoch `e` gives every earlier one; a thing's rotation is readable under the epoch
//! before (its own sync ID gives every box but the first); a holder's part is readable by a node
//! holding the holder's current epoch, an own actor's by the node; a keyless grant
//! (`World::keyless`, over the taken grants) is on no path. Left out: validity (roles-model
//! `paths`; joined in `evidence::joint`), which path a write states, sealing, the wire.
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
    let taken = k.taken_world();
    let all = roles_of(&taken, own);
    let mut closure = walk(&taken, &k.strongs, roots, &all, |_| true);
    let synced: Set = closure.read.union(&closure.stored).copied().collect();
    let (holders, _) = on_paths(&k.keyed_edges(), own, &synced);
    closure.for_keys = holders.difference(&closure.held).copied().collect();
    let roles = all.into_iter().filter(|(t, _)| synced.contains(t)).collect();
    Seen { closure, roles }
}

// ---- The world's key parts ----

/// Who wrote a grant, as its holder judges it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum From {
    /// A writer of the holder: the holder's data.
    Writer,
    /// Anyone else: an external signal of the holder, taken only while its admins enable it.
    Outside,
}

#[derive(Clone, Debug, Default)]
pub struct Keys {
    /// Every grant written: the targets' rosters. `World::keyless` is over the taken ones.
    pub world: World,
    /// The grants written from outside their holder.
    pub outside: BTreeSet<(T, T)>,
    /// The holders whose admins enable grants from outside.
    pub grantable: Set,
    /// The strongs inside things.
    pub strongs: Edges,
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
    /// Whether the holder takes the grant `(h, x)` standing.
    pub fn taken(&self, h: T, x: T) -> bool {
        self.world.grants.contains_key(&(h, x)) && (!self.outside.contains(&(h, x)) || self.grantable.contains(&h))
    }
    /// The world of taken grants.
    pub fn taken_world(&self) -> World {
        World { kinds: self.world.kinds.clone(), grants: self.world.grants.iter().filter(|(e, _)| self.taken(e.0, e.1)).map(|(&e, &r)| (e, r)).collect(), keyless: self.world.keyless.clone() }
    }
    fn taken_order(&self) -> Vec<(T, T)> {
        self.order.iter().copied().filter(|e| self.taken(e.0, e.1)).collect()
    }
    /// The role of a taken grant with key access.
    pub fn keyed(&self, h: T, x: T) -> Option<Role> {
        self.world.grants.get(&(h, x)).copied().filter(|_| self.taken(h, x) && !self.world.keyless.contains(&(h, x)))
    }
    pub fn keyed_edges(&self) -> BTreeSet<(T, T)> {
        self.world.grants.keys().copied().filter(|e| self.keyed(e.0, e.1).is_some()).collect()
    }
    /// The grants boxed: every grant written that is not keyless (taken or not).
    fn boxed_edges(&self) -> BTreeSet<(T, T)> {
        self.world.grants.keys().copied().filter(|e| !self.world.keyless.contains(e)).collect()
    }
    fn rekey(&mut self) {
        if !self.raw_cycles {
            self.world.keyless = keyless_of(&self.taken_order());
        }
        for (g, t) in self.boxed_edges() {
            if !self.boxes.range((t, self.epoch[t], g, 0)..=(t, self.epoch[t], g, u32::MAX)).any(|_| true) {
                self.boxes.insert((t, self.epoch[t], g, self.epoch[g]));
            }
        }
    }
    /// A grant by a writer of `g`.
    pub fn grant(&mut self, g: T, t: T, r: Role) {
        self.grant_from(g, t, r, From::Writer);
    }
    pub fn grant_from(&mut self, g: T, t: T, r: Role, from: From) {
        if self.world.grants.insert((g, t), r).is_none() {
            self.order.push((g, t));
        }
        match from {
            From::Writer => self.outside.remove(&(g, t)),
            From::Outside => self.outside.insert((g, t)),
        };
        *self.ver.entry((g, t)).or_default() += 1;
        self.rekey();
    }
    /// Removes `g`'s grant on `t`: `t` rotates, everything below it is stale.
    pub fn revoke(&mut self, g: T, t: T) -> bool {
        if self.world.grants.remove(&(g, t)).is_none() {
            return false;
        }
        self.order.retain(|&e| e != (g, t));
        self.outside.remove(&(g, t));
        *self.ver.entry((g, t)).or_default() += 1;
        self.rekey();
        let below = self.taken_world().keys_of(t);
        self.rotate(t);
        self.stale.extend(below.into_iter().filter(|&x| x != t));
        true
    }
    /// `h`'s admins enable or disable grants from outside (its setting: nothing rotates at the
    /// targets, whose rosters are unchanged).
    pub fn set_grantable(&mut self, h: T, on: bool) {
        match on {
            true => self.grantable.insert(h),
            false => self.grantable.remove(&h),
        };
        self.rekey();
    }
    /// A new epoch of `x`, boxed to each holder at its current epoch.
    pub fn rotate(&mut self, x: T) {
        self.epoch[x] += 1;
        for (g, t) in self.boxed_edges() {
            if t == x {
                self.boxes.insert((x, self.epoch[x], g, self.epoch[g]));
            }
        }
        self.stale.remove(&x);
    }
    /// Every stale thing rotates, those above first (a thing is boxed to its holders' new epochs).
    pub fn rotate_stale(&mut self) {
        let w = self.taken_world();
        while let Some(&x) = self.stale.iter().find(|&&x| !self.stale.iter().any(|&y| y != x && w.keys_of(y).contains(&x))).or(self.stale.iter().next()) {
            self.rotate(x);
        }
    }
    pub fn edit(&mut self, x: T) {
        self.content[x] += 1;
    }
    pub fn strong(&mut self, from: T, to: T) {
        self.strongs.insert((from, to));
    }
    pub fn unstrong(&mut self, from: T, to: T) {
        self.strongs.remove(&(from, to));
    }
}

// ---- A node ----

/// Which grants a node follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Taking {
    /// The design: the taken grants of the holders it opens.
    Taken,
    /// Control of (ii): every grant naming a holder it opens, taken or not (no taking: the
    /// study's rejected "roles from every grant naming the account").
    Every,
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub taking: Taking,
    pub paths: Paths,
    pub boxes: Boxes,
    pub roles: RolesBy,
}

impl Rule {
    /// The design.
    pub const DESIGN: Rule = Rule { taking: Taking::Taken, paths: Paths::All, boxes: Boxes::Own, roles: RolesBy::Chains };
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
    /// An entry of a holder's list of taken grants, read by the search.
    List(T, T, u32),
    Content(T, u32),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    pub edges: usize,
    pub keysets: usize,
    pub boxes: usize,
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
    /// The node root's strongs.
    pub roots: Set,
    /// The edges held, each as last fetched: the pieces of its paths and the rosters of what it reads.
    pub edges: BTreeMap<(T, T), Role>,
    /// The newest epoch held of each thing whose secrets it holds.
    pub have: BTreeMap<T, u32>,
    /// The strongs of each thing read, as last fetched.
    pub inner: BTreeMap<T, Set>,
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
    pub fn hear(&mut self, k: &Keys, rule: &Rule, h: T, x: T) {
        self.piece(k, rule, h, x);
    }
    /// The role a followed grant gives: a taken keyed one's (any keyed one's under `Taking::Every`).
    fn follows(k: &Keys, rule: &Rule, h: T, x: T) -> Option<Role> {
        match rule.taking {
            Taking::Taken => k.keyed(h, x),
            Taking::Every => k.world.grants.get(&(h, x)).copied().filter(|_| !k.world.keyless.contains(&(h, x))),
        }
    }
    /// Fetches the edge `(h, x)` as the world has it.
    fn piece(&mut self, k: &Keys, rule: &Rule, h: T, x: T) {
        self.got.insert(Item::Edge(h, x, k.ver.get(&(h, x)).copied().unwrap_or(0)));
        match Self::follows(k, rule, h, x) {
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
        let strongs: Edges = self.inner.iter().flat_map(|(&x, ts)| ts.iter().map(move |&y| (x, y))).collect();
        let roles = roles_of(&all, &self.own);
        let c = walk(&opened, &strongs, &self.roots, &roles, has);
        let reached = self.roots.iter().copied().chain(strongs.iter().filter(|(x, _)| c.read.contains(x)).map(|&(_, y)| y)).collect();
        (c, roles, reached)
    }
    /// Down from the own actors: reads the list of every holder they reach by followed grants,
    /// fetches the pieces of the paths to what the strongs reach from holders it opens.
    fn search(&mut self, k: &Keys, rule: &Rule, src: &Source, reached: &Set) {
        let ver = |h: T, x: T| k.ver.get(&(h, x)).copied().unwrap_or(0);
        let mut listed = BTreeSet::new();
        let mut seen = self.own.clone();
        let mut todo: Vec<T> = seen.iter().copied().collect();
        while let Some(h) = todo.pop() {
            if !src.part(h) {
                continue;
            }
            for (&(_, x), _) in k.world.grants.range((h, 0)..=(h, T::MAX)) {
                if Self::follows(k, rule, h, x).is_none() {
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
            if self.open(k, h) && src.part(h) {
                self.piece(k, rule, h, x);
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
                    self.piece(k, rule, h, x);
                }
            }
            self.advance(k, src);
            let (c, _, reached) = self.judge(k, rule);
            for &x in &c.read {
                if src.unit(x) && self.open(k, x) {
                    // the roster: every grant on it, taken or not
                    let roster: Vec<(T, T)> = self.edges.keys().copied().filter(|e| e.1 == x).chain(k.world.grants.keys().copied().filter(|e| e.1 == x)).collect();
                    for (g, _) in roster {
                        self.piece(k, rule, g, x);
                    }
                    self.inner.insert(x, k.strongs.range((x, 0)..=(x, T::MAX)).map(|&(_, y)| y).collect());
                    self.got.insert(Item::Content(x, k.content[x]));
                }
            }
            for &x in &c.stored {
                if src.unit(x) {
                    self.got.insert(Item::Content(x, k.content[x]));
                }
            }
            self.inner.retain(|x, _| c.read.contains(x));
            self.search(k, rule, src, &reached);
            if before == (self.edges.clone(), self.have.clone(), self.inner.clone()) {
                self.unsettled = false;
                break;
            }
        }
        let (c, roles, _) = self.judge(k, rule);
        let synced: Set = c.read.union(&c.stored).copied().collect();
        let known: BTreeSet<(T, T)> = self.edges.keys().copied().collect();
        let (holders, on) = match rule.paths {
            Paths::All => on_paths(&known, &self.own, &synced),
            Paths::Chosen => chosen(&self.edges, &self.own, &synced, &roles),
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
