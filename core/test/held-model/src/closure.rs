//! Greenfield model of the reference graph (spec/data-model.md §8, spec/sync-set.md), written
//! from its rules before any code existed: sync units, carrying under
//! sync IDs with per-sync-ID stores, the node closure, release at a pass's end, and the
//! spanning-tree structure for removing a strong. Plain data and pure functions; properties in
//! tests/it/spec_closure.rs, findings in notes/closure-model.md.
//!
//! Abstracted: a strong's place inside a value is an OR-set of edges per source thing (an add is
//! a commit, a remove names the adds its writer saw), so what a set of commits says is a function
//! of the set. An independent thing's tid is its sync ID. A dependent thing's kind names the independent thing its
//! secrets derive from (through any chain of dependent mint admins). A grant `(g, t)`
//! with a role is an entry of `t`'s role record naming the actor `g`, last commit wins.
//!
//! Left out: validity (every commit is valid and its writer allowed), admin disputes, key
//! rotation, the wire, sealing, `@` signals and the inbox, purge and expiry, storage rows. Sync is
//! reduced to its outcome: a pass hands over every commit on a thing both sides hold or one side
//! wants (`Net`), or, per sync ID, every commit the sender carries there (`Sync`).
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub mod keys;

pub type T = usize;
/// A commit's index in its world's list.
pub type C = usize;
pub type Set = BTreeSet<T>;
pub type Edges = BTreeSet<(T, T)>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Independent: a sync ID.
    Independent,
    /// Dependent, its secrets deriving from this independent thing's.
    Dependent(T),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Sync,
    Read,
    Write,
    Admin,
}

#[derive(Clone, Debug, Default)]
pub struct World {
    pub kinds: Vec<Kind>,
    /// `(g, t) -> r`: the actor `g` holds role `r` on `t`.
    pub grants: BTreeMap<(T, T), Role>,
    /// The keyless grants `(g, t)` (spec/crypto.md §4 Key access, `keyless_of`): a role all the
    /// same, but read nothing through it.
    pub keyless: BTreeSet<(T, T)>,
}

/// The keyless grants among actor grants `(g, t)` (holder `g` on target `t`) taken in `order`
/// (record edges first, then by the write starting each standing; spec/crypto.md §4 Key access):
/// a grant is keyless when `t`'s key already yields `g`'s over the grants given key access before
/// it (`t` holds, through such grants, one on `g`), so it would close a cycle.
pub fn keyless_of(order: &[(T, T)]) -> BTreeSet<(T, T)> {
    let mut keyed: Vec<(T, T)> = Vec::new();
    let mut out = BTreeSet::new();
    for &(g, t) in order {
        let mut seen = BTreeSet::from([t]);
        let mut todo = vec![t];
        while let Some(x) = todo.pop() {
            for &(h, y) in &keyed {
                if h == x && seen.insert(y) {
                    todo.push(y);
                }
            }
        }
        match seen.contains(&g) {
            true => {
                out.insert((g, t));
            }
            false => keyed.push((g, t)),
        }
    }
    out
}

impl World {
    pub fn independent(&self, x: T) -> bool {
        self.kinds[x] == Kind::Independent
    }
    /// The role `g` holds on each independent thing for keys, by grants with key access followed
    /// transitively: a chain of actors gives the lowest role along it, and the best chain counts.
    /// `g` is admin of itself.
    pub fn roles_from(&self, g: T) -> BTreeMap<T, Role> {
        let mut best = BTreeMap::from([(g, Role::Admin)]);
        loop {
            let mut changed = false;
            for (&(a, b), &r) in &self.grants {
                if self.keyless.contains(&(a, b)) {
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
    /// The keys of `t`: the independent things `t` holds read or above on, itself included.
    pub fn keys_of(&self, t: T) -> Set {
        self.roles_from(t).into_iter().filter(|&(_, r)| r >= Role::Read).map(|(u, _)| u).collect()
    }
    /// What a node reading every thing in `reads` holds keys for.
    pub fn ring(&self, reads: &Set) -> Set {
        reads.iter().flat_map(|&r| self.keys_of(r)).collect()
    }
    /// The independent things a node reading every thing in `reads` holds a sync secret of: those they
    /// hold sync or above on.
    pub fn sync_ring(&self, reads: &Set) -> Set {
        reads.iter().flat_map(|&r| self.roles_from(r).into_keys().filter(|&u| self.independent(u))).collect()
    }
    /// Whether `keys` open `x`: its secrets come from an independent thing among them.
    pub fn opens(&self, keys: &Set, x: T) -> bool {
        match self.kinds[x] {
            Kind::Independent => keys.contains(&x),
            Kind::Dependent(k) => keys.contains(&k),
        }
    }
    /// This world with the role commits of `held` applied over its grants, the latest per entry.
    pub fn with_roles(&self, all: &[Commit], held: &BTreeSet<C>) -> World {
        let mut w = self.clone();
        for &c in held {
            if let Op::Role(g, r) = all[c].op {
                match r {
                    Some(r) => w.grants.insert((g, all[c].from), r),
                    None => w.grants.remove(&(g, all[c].from)),
                };
            }
        }
        w
    }
}

pub fn targets(e: &Edges, x: T) -> impl Iterator<Item = T> + '_ {
    e.range((x, 0)..=(x, T::MAX)).map(|&(_, y)| y)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Add(T),
    /// Removes these adds (on the same source).
    Remove(BTreeSet<C>),
    /// Sets the role record entry of the actor named here, on the commit's thing (`None`: revoked).
    Role(T, Option<Role>),
}

#[derive(Clone, Debug)]
pub struct Commit {
    pub from: T,
    pub op: Op,
    /// In an ephemeral aspect: counts while held, lost by a restart.
    pub ephemeral: bool,
}

/// The strongs `held` says are present: adds no held remove names.
pub fn edges(all: &[Commit], held: &BTreeSet<C>) -> Edges {
    let removed: BTreeSet<C> = held
        .iter()
        .filter_map(|&c| match &all[c].op {
            Op::Remove(r) => Some(r.iter().copied()),
            _ => None,
        })
        .flatten()
        .collect();
    held.iter()
        .filter(|c| !removed.contains(c))
        .filter_map(|&c| match all[c].op {
            Op::Add(to) => Some((all[c].from, to)),
            _ => None,
        })
        .collect()
}

// ---- Sync units ----

/// The sync unit walk from independent `t`: a thing reached by a strong is in it, and followed, iff `keys`
/// open it; any other stops the walk and is not in it. `sync unit` passes `t`'s keys; any other
/// `keys` is a variant.
pub fn unit_with(w: &World, t: T, keys: &Set, e: &Edges) -> Set {
    let mut seen = Set::from([t]);
    let mut stack = vec![t];
    while let Some(x) = stack.pop() {
        for y in targets(e, x) {
            if w.opens(keys, y) && seen.insert(y) {
                stack.push(y);
            }
        }
    }
    seen
}

/// T's sync unit: what T's sync ID carries.
pub fn unit(w: &World, t: T, e: &Edges) -> Set {
    unit_with(w, t, &w.keys_of(t), e)
}

/// T's sync unit as a node reading every thing in `reads` (T among them) computes it: it sees a
/// thing's strongs only where its keys open the thing.
pub fn unit_seen(w: &World, t: T, reads: &Set, e: &Edges) -> Set {
    let ring = w.ring(reads);
    let seen: Edges = e.iter().copied().filter(|&(x, _)| w.opens(&ring, x)).collect();
    unit(w, t, &seen)
}

// ---- Carrying under sync IDs ----

/// What one node's view says sync ID `s` carries.
pub struct Carry {
    pub unit: Set,
    pub keys: Set,
    pub certify_revokes: bool,
}

impl Carry {
    /// Whether commit `c` goes under the sync ID: a commit on a thing of the sync unit; a role commit
    /// on a thing whose keys the sync ID holds (a certificate of its reach); with
    /// `certify_revokes`, also a role commit naming an actor whose keys it holds (itself included),
    /// so a revocation travels where the grant took the thing.
    pub fn carries(&self, c: &Commit) -> bool {
        match c.op {
            Op::Role(g, _) => {
                self.unit.contains(&c.from) || self.keys.contains(&c.from) || self.certify_revokes && self.keys.contains(&g)
            }
            _ => self.unit.contains(&c.from),
        }
    }
}

/// Nodes exchanging commits per sync ID and logging them in a store per sync ID. A node syncs
/// each independent thing it reads (`subs`) and each independent thing their sync units hold; it holds the
/// commits some sync ID it syncs carries by its own view, and drops the rest (unsynced writes
/// included). Nothing is lost in transit.
#[derive(Clone, Debug)]
pub struct Sync {
    pub world: World,
    pub commits: Vec<Commit>,
    /// Per node: the independent things it syncs.
    pub subs: Vec<Set>,
    pub has: Vec<BTreeSet<C>>,
    /// Per sync ID: the entries logged there.
    pub store: BTreeMap<T, BTreeSet<C>>,
    /// Per node: the sync IDs whose delete key it holds.
    pub delete_key: Vec<Set>,
    pub certify_revokes: bool,
    /// What exchanges and store visits changed: commits a node holds and entries a store holds,
    /// counted as the difference between before and after each (fetching an entry and dropping
    /// it again in one visit changes nothing).
    pub churn: usize,
}

impl Sync {
    pub fn new(world: World, subs: Vec<Set>, certify_revokes: bool) -> Sync {
        let n = subs.len();
        Sync { world, commits: vec![], subs, has: vec![BTreeSet::new(); n], store: BTreeMap::new(), delete_key: vec![Set::new(); n], certify_revokes, churn: 0 }
    }
    pub fn view(&self, n: usize) -> (World, Edges) {
        (self.world.with_roles(&self.commits, &self.has[n]), edges(&self.commits, &self.has[n]))
    }
    pub fn carried(&self, n: usize, s: T) -> Set {
        let (w, e) = self.view(n);
        unit(&w, s, &e)
    }
    pub fn syncs(&self, n: usize) -> Set {
        let (w, e) = self.view(n);
        self.subs[n].iter().flat_map(|&s| unit(&w, s, &e)).filter(|&x| w.independent(x)).collect()
    }
    pub fn carry(&self, n: usize, s: T) -> Carry {
        let (w, e) = self.view(n);
        Carry { unit: unit(&w, s, &e), keys: w.keys_of(s), certify_revokes: self.certify_revokes }
    }
    /// What `n` holds of what `s` carries.
    pub fn under(&self, n: usize, s: T) -> BTreeSet<C> {
        let cr = self.carry(n, s);
        self.has[n].iter().copied().filter(|&c| cr.carries(&self.commits[c])).collect()
    }
    /// Writes a commit at node `n`.
    pub fn write(&mut self, n: usize, c: Commit) -> C {
        self.commits.push(c);
        let id = self.commits.len() - 1;
        self.has[n].insert(id);
        id
    }
    /// Drops what no sync ID `n` syncs carries by its view, to a fixpoint.
    pub fn prune(&mut self, n: usize) {
        loop {
            let keep: BTreeSet<C> = self.syncs(n).iter().flat_map(|&s| self.under(n, s)).collect();
            if keep == self.has[n] {
                return;
            }
            self.has[n] = keep;
        }
    }
    fn give(&mut self, a: usize, b: usize) -> bool {
        let out: BTreeSet<C> = self.syncs(a).intersection(&self.syncs(b)).flat_map(|&s| self.under(a, s)).collect();
        let n = self.has[b].len();
        self.has[b].extend(out);
        self.has[b].len() != n
    }
    /// A pass between `a` and `b`: both ways until nothing moves, then each drops what left.
    pub fn exchange(&mut self, a: usize, b: usize) {
        let before = (self.has[a].clone(), self.has[b].clone());
        while self.give(a, b) | self.give(b, a) {}
        self.prune(a);
        self.prune(b);
        self.churn += before.0.symmetric_difference(&self.has[a]).count() + before.1.symmetric_difference(&self.has[b]).count();
    }
    /// `n` at the stores of what it syncs: fetches every entry, drops what its view does not
    /// carry, logs what it holds that its view carries, and where it holds the delete key
    /// deletes the entries its view does not carry.
    pub fn store_round(&mut self, n: usize) {
        let before = (self.has[n].clone(), self.store.clone());
        for s in self.syncs(n) {
            let got = self.store.get(&s).cloned().unwrap_or_default();
            self.has[n].extend(got);
        }
        self.prune(n);
        for s in self.syncs(n) {
            let cr = self.carry(n, s);
            let logged = self.under(n, s);
            let st = self.store.entry(s).or_default();
            st.extend(logged);
            if self.delete_key[n].contains(&s) {
                st.retain(|&c| cr.carries(&self.commits[c]));
            }
        }
        self.churn += before.0.symmetric_difference(&self.has[n]).count();
        for (s, st) in &self.store {
            self.churn += st.symmetric_difference(before.1.get(s).unwrap_or(&BTreeSet::new())).count();
        }
    }
    /// Every pair exchanges, then every node visits its stores.
    pub fn round(&mut self) {
        let n = self.has.len();
        for a in 0..n {
            for b in a + 1..n {
                self.exchange(a, b);
            }
        }
        for a in 0..n {
            self.store_round(a);
        }
    }
    /// Rounds until one moves nothing (no commit taken or dropped, no entry logged or deleted):
    /// the rounds it took, or `None` within `max`.
    pub fn settle(&mut self, max: usize) -> Option<usize> {
        for i in 1..=max {
            let before = self.churn;
            self.round();
            if self.churn == before {
                return Some(i);
            }
        }
        None
    }
    /// Where nodes disagree with what is still held anywhere: per node, the sync IDs it syncs
    /// that it should not or the other way round, and the commits it lacks of what each sync ID
    /// it should sync carries, both over every commit any node or store still holds.
    pub fn missing(&self) -> Vec<(usize, Set, BTreeSet<C>)> {
        let all: BTreeSet<C> = self.has.iter().flatten().chain(self.store.values().flatten()).copied().collect();
        let (w, e) = (self.world.with_roles(&self.commits, &all), edges(&self.commits, &all));
        (0..self.has.len())
            .map(|n| {
                let mine: Set = self.subs[n].iter().flat_map(|&s| unit(&w, s, &e)).filter(|&x| w.independent(x)).collect();
                let lacks = mine
                    .iter()
                    .flat_map(|&s| {
                        let cr = Carry { unit: unit(&w, s, &e), keys: w.keys_of(s), certify_revokes: self.certify_revokes };
                        all.iter().copied().filter(move |&c| cr.carries(&self.commits[c]))
                    })
                    .filter(|c| !self.has[n].contains(c))
                    .collect();
                (n, self.syncs(n).symmetric_difference(&mine).copied().collect(), lacks)
            })
            .filter(|(_, s, c): &(usize, Set, BTreeSet<C>)| !s.is_empty() || !c.is_empty())
            .collect()
    }
    pub fn agrees(&self) -> bool {
        self.missing().is_empty()
    }
}

// ---- The node closure ----

/// What a node brings to its closure: its node root's strongs and its own actors (its account,
/// itself, the key actors it holds: spec/sync-set.md §2 Own actors).
#[derive(Clone, Debug, Default)]
pub struct NodeView {
    pub roots: Set,
    pub own: Set,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Closure {
    /// Independent things read: entered at the node's role of read or above, or in a sync unit
    /// entered so.
    pub read: Set,
    /// Independent things kept unread: entered at the node's role of sync, and not read; each
    /// holds its sync unit unread and the walk stops at it.
    pub stored: Set,
    /// Every thing the node holds.
    pub held: Set,
    /// What some way of obtaining covers: the sync units entered and the local sync unit (the node
    /// root's strongs walked by the node's keys).
    pub carried: Set,
    /// The node's keys: the things its role is read or above on.
    pub keys: Set,
    /// The things the node's role gives a sync secret of (sync or above).
    pub synced: Set,
    /// Holders held for keys alone (`keys::for_keys`: notes/holder-access-study.md). Empty from
    /// `closure`.
    pub for_keys: Set,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Walk {
    /// Sync unit by sync unit: within a sync unit by its strongs; into an independent thing the sync unit's keys cannot
    /// open only by the node's role on it; a dependent thing the sync unit's keys cannot open
    /// stops the walk.
    Units,
    /// The words "the node closure walks strongs": every thing the node can open is followed.
    Literal,
}

/// The node closure (spec/sync-set.md §2): the walk below by the node's role, its own actors'
/// effective role over `w`'s grants (spec/sync-set.md §2 Own actors). A function of the world: no
/// role waits for a strong.
pub fn closure(w: &World, e: &Edges, n: &NodeView, walk: Walk) -> Closure {
    let roles = keys::roles_of(w, &n.own);
    let ring: Set = roles.iter().filter(|&(_, &r)| r >= Role::Read).map(|(&x, _)| x).collect();
    let sync: Set = roles.keys().copied().collect();
    let mut c = walk_with(w, e, &n.roots, walk, &ring, &sync);
    (c.keys, c.synced) = (ring, sync);
    c
}

/// The walk from `roots` with keys `ring` and sync secrets `sync`: an independent thing reached
/// is read where `ring` holds its keys, else kept unread where `sync` holds its sync secret.
pub(crate) fn walk_with(w: &World, e: &Edges, roots: &Set, walk: Walk, ring: &Set, sync: &Set) -> Closure {
    let opened = |k: &T| ring.contains(k);
    let synced = |k: &T| sync.contains(k);
    let mut c = Closure::default();
    let mut independents = vec![];
    let mut stack = vec![];
    for &r in roots {
        if w.independent(r) {
            independents.push(r);
        } else if w.opens(ring, r) && c.held.insert(r) {
            stack.push(r);
        }
    }
    match walk {
        Walk::Units => {
            // The local sync unit.
            while let Some(x) = stack.pop() {
                for y in targets(e, x) {
                    if w.independent(y) {
                        independents.push(y);
                    } else if w.opens(ring, y) && c.held.insert(y) {
                        stack.push(y);
                    }
                }
            }
            c.carried = c.held.clone();
            let mut done = Set::new();
            while let Some(k) = independents.pop() {
                let open = opened(&k);
                if !(open || synced(&k)) || !done.insert(k) {
                    continue;
                }
                let p = unit(w, k, e);
                if open {
                    c.read.extend(p.iter().copied().filter(|&x| w.independent(x)));
                    for &m in &p {
                        independents.extend(targets(e, m).filter(|&y| w.independent(y) && !p.contains(&y)));
                    }
                    c.held.extend(&p);
                } else {
                    // kept unread: its strongs unread, so the walk stops at it and holds it alone
                    // (spec/sync-set.md §2), its sync unit carried under its sync ID
                    c.stored.insert(k);
                    c.held.insert(k);
                }
                c.carried.extend(p);
            }
            c.stored.retain(|x| !c.read.contains(x));
        }
        Walk::Literal => {
            let mut stack: Vec<T> = stack.into_iter().chain(independents).collect();
            let mut seen: Set = stack.iter().copied().collect();
            while let Some(x) = stack.pop() {
                let follow = if w.independent(x) {
                    if opened(&x) {
                        c.read.insert(x);
                        c.held.insert(x);
                        true
                    } else if synced(&x) {
                        c.stored.insert(x);
                        c.held.insert(x);
                        false
                    } else {
                        false
                    }
                } else {
                    c.held.insert(x);
                    true
                };
                if follow {
                    for y in targets(e, x) {
                        if (w.opens(ring, y) || w.independent(y)) && seen.insert(y) {
                            stack.push(y);
                        }
                    }
                }
            }
            c.carried = walk_with(w, e, roots, Walk::Units, ring, sync).carried;
            for &k in c.read.iter().chain(&c.stored) {
                c.carried.extend(unit(w, k, e));
            }
        }
    }
    c
}

/// The making rule: a new thing `m` may be made only if the commit making it leaves it in the
/// node closure (`e` is the strongs after that commit).
pub fn may_make(w: &World, e: &Edges, n: &NodeView, m: T) -> bool {
    closure(w, e, n, Walk::Units).held.contains(&m)
}

// ---- Holding and release over time ----

/// Nodes holding things and the commits on them; node `i`'s root is thing `i` (local: its commits
/// never leave the node). Shared things are numbered from the node count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeState {
    pub held: Set,
    pub has: BTreeSet<C>,
}

#[derive(Clone, Debug)]
pub struct Net {
    pub commits: Vec<Commit>,
    pub nodes: Vec<NodeState>,
    pub things: usize,
}

impl Net {
    pub fn new(nodes: usize) -> Net {
        Net { commits: vec![], nodes: vec![NodeState { held: Set::new(), has: BTreeSet::new() }; nodes], things: nodes }
    }
    pub fn shared(&self) -> std::ops::Range<T> {
        self.nodes.len()..self.things
    }
    /// Node `n`'s closure (root excluded): what its held strongs reach.
    pub fn closure(&self, n: usize) -> Set {
        let e = edges(&self.commits, &self.nodes[n].has);
        let mut seen = Set::new();
        let mut stack = vec![n];
        while let Some(x) = stack.pop() {
            for y in targets(&e, x) {
                if y != n && seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        seen
    }
    pub fn can_write(&self, n: usize, from: T) -> bool {
        from == n || self.nodes[n].held.contains(&from)
    }
    fn commit(&mut self, n: usize, c: Commit) -> C {
        assert!(self.can_write(n, c.from));
        self.commits.push(c);
        let id = self.commits.len() - 1;
        self.nodes[n].has.insert(id);
        id
    }
    /// Makes a thing, strongly referenced from `from`.
    pub fn create(&mut self, n: usize, from: T) -> T {
        let x = self.things;
        self.things += 1;
        self.nodes[n].held.insert(x);
        self.commit(n, Commit { from, op: Op::Add(x), ephemeral: false });
        x
    }
    /// A strong to any tid: a strong grants nothing and needs nothing held.
    pub fn add(&mut self, n: usize, from: T, to: T, ephemeral: bool) -> C {
        self.commit(n, Commit { from, op: Op::Add(to), ephemeral })
    }
    /// The adds of `from -> to` node `n` sees.
    pub fn visible(&self, n: usize, from: T, to: T) -> BTreeSet<C> {
        let has = &self.nodes[n].has;
        let removed: BTreeSet<C> = has.iter().filter_map(|&c| match &self.commits[c].op {
            Op::Remove(r) => Some(r.iter().copied()),
            _ => None,
        }).flatten().collect();
        has.iter().copied().filter(|c| !removed.contains(c) && self.commits[*c].from == from && self.commits[*c].op == Op::Add(to)).collect()
    }
    pub fn remove(&mut self, n: usize, from: T, to: T) -> Option<C> {
        let v = self.visible(n, from, to);
        if v.is_empty() {
            return None;
        }
        Some(self.remove_adds(n, from, v))
    }
    /// A remove naming exactly `adds` (on `from`).
    pub fn remove_adds(&mut self, n: usize, from: T, adds: BTreeSet<C>) -> C {
        self.commit(n, Commit { from, op: Op::Remove(adds), ephemeral: false })
    }
    fn give(&mut self, src: usize, dst: usize, x: T) -> bool {
        let cs: Vec<C> = self.nodes[src].has.iter().copied().filter(|&c| self.commits[c].from == x).collect();
        let d = &mut self.nodes[dst];
        let mut changed = d.held.insert(x);
        for c in cs {
            changed |= d.has.insert(c);
        }
        changed
    }
    /// A sync pass of `n` with `peers` connected, to its end: each side hands over the commits on
    /// what both hold and what the other's closure wants, until nothing moves. Then `n` drops what
    /// is outside its closure (no peers: at once). Returns what `n` dropped.
    pub fn pass(&mut self, n: usize, peers: &[usize]) -> Set {
        loop {
            let mut changed = false;
            for &p in peers {
                let (wn, wp) = (self.closure(n), self.closure(p));
                for x in self.shared() {
                    let (hn, hp) = (self.nodes[n].held.contains(&x), self.nodes[p].held.contains(&x));
                    if hp && (hn || wn.contains(&x)) {
                        changed |= self.give(p, n, x);
                    }
                    if hn && (hp || wp.contains(&x)) {
                        changed |= self.give(n, p, x);
                    }
                }
            }
            if !changed {
                break;
            }
        }
        let keep = self.closure(n);
        let drop: Set = self.nodes[n].held.difference(&keep).copied().collect();
        let commits = &self.commits;
        let s = &mut self.nodes[n];
        s.held.retain(|x| keep.contains(x));
        s.has.retain(|&c| commits[c].from == n || keep.contains(&commits[c].from));
        drop
    }
    /// A restart: ephemeral values are lost.
    pub fn restart(&mut self, n: usize) {
        let commits = &self.commits;
        self.nodes[n].has.retain(|&c| !commits[c].ephemeral);
    }
    /// Every node passes with every other until nothing changes.
    pub fn quiesce(&mut self) {
        let all: Vec<usize> = (0..self.nodes.len()).collect();
        loop {
            let before = self.nodes.clone();
            for n in 0..all.len() {
                let peers: Vec<usize> = all.iter().copied().filter(|&p| p != n).collect();
                self.pass(n, &peers);
            }
            if self.nodes == before {
                return;
            }
        }
    }
    /// Things some node's closure reaches and no node holds: strongs that read as not held.
    pub fn dangling(&self) -> Set {
        let held: Set = self.nodes.iter().flat_map(|s| s.held.iter().copied()).collect();
        (0..self.nodes.len()).flat_map(|n| self.closure(n)).filter(|x| !held.contains(x)).collect()
    }
}

// ---- Removing a strong cheaply ----

pub const ROOT: T = 0;

/// The plan's structure for one node's held set: each held thing but the root records one strong
/// towards the root (`parent`), a spanning tree of the held set; removing a tree edge marks the
/// target's subtree, re-attaches each member a held referrer outside it still reaches and what
/// those reach, and drops the rest. `work` counts edges examined and tree steps.
#[derive(Clone, Debug, Default)]
pub struct Tree {
    pub out: BTreeMap<T, Set>,
    pub inn: BTreeMap<T, Set>,
    pub parent: BTreeMap<T, T>,
    pub children: BTreeMap<T, Set>,
    pub held: Set,
    pub work: u64,
    /// Mutation: no re-attach step (a tree edge's target with no referrer outside its subtree
    /// drops the whole subtree).
    pub naive: bool,
    /// Before marking the subtree, try the target's other referrers by walking each one's parent
    /// chain (cost: depth); off, a removed tree edge always marks the subtree (cost: its size).
    pub ancestor_step: bool,
}

impl Tree {
    pub fn new(naive: bool, ancestor_step: bool) -> Tree {
        Tree { held: Set::from([ROOT]), naive, ancestor_step, ..Tree::default() }
    }
    fn set_parent(&mut self, x: T, p: T) {
        if let Some(old) = self.parent.insert(x, p) {
            self.children.get_mut(&old).unwrap().remove(&x);
        }
        self.children.entry(p).or_default().insert(x);
        self.held.insert(x);
    }
    fn reach_from(&mut self, x: T) {
        let mut q = VecDeque::from([x]);
        while let Some(x) = q.pop_front() {
            for y in self.out.get(&x).cloned().unwrap_or_default() {
                self.work += 1;
                if !self.held.contains(&y) {
                    self.set_parent(y, x);
                    q.push_back(y);
                }
            }
        }
    }
    pub fn add(&mut self, u: T, v: T) {
        self.work += 1;
        if !self.out.entry(u).or_default().insert(v) {
            return;
        }
        self.inn.entry(v).or_default().insert(u);
        if self.held.contains(&u) && !self.held.contains(&v) {
            self.set_parent(v, u);
            self.reach_from(v);
        }
    }
    /// Whether `w`'s parent chain meets `v` (detached) before the root.
    fn below(&mut self, mut w: T, v: T) -> bool {
        loop {
            self.work += 1;
            if w == v {
                return true;
            }
            if w == ROOT {
                return false;
            }
            w = self.parent[&w];
        }
    }
    pub fn remove(&mut self, u: T, v: T) {
        self.work += 1;
        if !self.out.get_mut(&u).is_some_and(|s| s.remove(&v)) {
            return;
        }
        self.inn.get_mut(&v).unwrap().remove(&u);
        if self.parent.get(&v) != Some(&u) {
            return;
        }
        self.parent.remove(&v);
        self.children.get_mut(&u).unwrap().remove(&v);
        if self.ancestor_step {
            for w in self.inn[&v].clone() {
                self.work += 1;
                if self.held.contains(&w) && !self.below(w, v) {
                    self.set_parent(v, w);
                    return;
                }
            }
        }
        // The subtree hanging off v.
        let mut sub = Set::from([v]);
        let mut stack = vec![v];
        while let Some(x) = stack.pop() {
            for c in self.children.get(&x).cloned().unwrap_or_default() {
                self.work += 1;
                if sub.insert(c) {
                    stack.push(c);
                }
            }
        }
        let mut rest = sub.clone();
        if !self.naive {
            // Re-attach: members with a held referrer outside, then what they reach inside.
            let mut q = VecDeque::new();
            for &x in &sub {
                for &w in self.inn.get(&x).into_iter().flatten() {
                    self.work += 1;
                    if self.held.contains(&w) && !sub.contains(&w) {
                        q.push_back((x, w));
                        break;
                    }
                }
            }
            for &(x, _) in &q {
                rest.remove(&x);
            }
            while let Some((x, w)) = q.pop_front() {
                self.set_parent(x, w);
                for y in self.out.get(&x).cloned().unwrap_or_default() {
                    self.work += 1;
                    if rest.remove(&y) {
                        q.push_back((y, x));
                    }
                }
            }
        }
        for x in rest {
            self.held.remove(&x);
            if let Some(p) = self.parent.remove(&x) {
                if let Some(ch) = self.children.get_mut(&p) {
                    ch.remove(&x);
                }
            }
            self.children.remove(&x);
        }
    }
    /// From-scratch reachability, the oracle.
    pub fn reach(&self) -> Set {
        let mut seen = Set::from([ROOT]);
        let mut stack = vec![ROOT];
        while let Some(x) = stack.pop() {
            for &y in self.out.get(&x).into_iter().flatten() {
                if seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        seen
    }
    /// The tree is a spanning tree of `held`: each held thing's parent is held, the parent's
    /// strong to it is present, and its chain ends at the root.
    pub fn consistent(&self) -> bool {
        self.held.iter().all(|&x| {
            let mut y = x;
            for _ in 0..=self.held.len() {
                if y == ROOT {
                    return true;
                }
                let Some(&p) = self.parent.get(&y) else { return false };
                if !self.held.contains(&p) || !self.out.get(&p).is_some_and(|s| s.contains(&y)) {
                    return false;
                }
                y = p;
            }
            false
        }) && self.parent.keys().all(|x| self.held.contains(x))
    }
}
