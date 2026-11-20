//! The evidence a sync ID requires (notes/evidence-derivation.md; draft notes/a2-spec/permissions.md
//! §4 Evidence of a commit, Evidence of a sync ID, with OPEN 10's proposal: chained writes along
//! joined paths). Built unused beside `sync/certified.rs`: nothing reads it yet.
//!
//! A function of the copies (commit, thing) a node holds and of each sync ID's unit: the least set
//! the closure rules give over them. Changes come in by call (`add`, `forget`, `set_chained`,
//! `open_path`, `join`, `leave`); each extends the closure from what it adds, or closes again from
//! the sync ID's seeds where it can shrink it. `from_scratch` is the same closure from nothing.
//! Generic over the thing (`T`), commit (`C`) and key (`K`) types so it runs over held-model's
//! worlds as over the engine's.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::ops::Bound;

/// An edge: (holder, target).
pub type Edge<T> = (T, T);
/// A copy: a commit's parts on one thing, (commit ID, thing).
pub type CopyId<C, T> = (C, T);

/// A sync ID's evidence: each copy with the reason it is in it.
pub type Required<C, T> = BTreeMap<CopyId<C, T>, Reason<C, T>>;

/// Vouches waiting for a member on their thing, each with the lowering it is keyed by.
type Pending<C, T> = BTreeMap<T, BTreeMap<CopyId<C, T>, CopyId<C, T>>>;

/// One edge of a stated path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hop<T> {
    pub edge: Edge<T>,
    /// A record edge (the mint admin's): no grant joins it, none needed.
    pub record: bool,
}

/// An edge write's facts (its edge is (holder, the copy's thing)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Write<C, T> {
    pub holder: T,
    /// It sets a role above none (no self-removal, no finalize): it can join a path.
    pub grant: bool,
    /// (A3's reach) It gives below write at its own `ts`, and is no finalize.
    pub removal: bool,
    /// (A3's reach) It gives write or above (any `until`).
    pub gives_write: bool,
    /// The remaining admin its header names.
    pub relies: Option<T>,
    /// The creation of the entry it resets, as its reset names it (spec/permissions.md §2).
    pub creation: Option<CopyId<C, T>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind<C, T> {
    Content,
    Write(Write<C, T>),
    /// A vouch keyed by the lowering on that copy.
    Vouch { keyed: CopyId<C, T> },
}

/// One part of a held copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part<C, T, K> {
    pub kind: Kind<C, T>,
    /// The edges of the path its commit states for the thing; `None` while that path is not
    /// known here (a split entry that has not opened): it brings nothing.
    pub hops: Option<Vec<Hop<T>>>,
    /// Its place as a verdict reads it: its key for an edge-class part, the start of its `ts`
    /// for content. "Ordered before" is a key below it.
    pub pos: K,
    /// A chained write (draft §4 Chained writes), as the walk judges it over the held set.
    pub chained: bool,
}

/// Why a copy is in a sync ID's evidence (the first reason found).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reason<C, T> {
    /// A chained write on an edge the set uses.
    Edge(Edge<T>),
    /// The creation of an entry this member's reset names.
    Creation(CopyId<C, T>),
    /// A vouch keyed by this member lowering.
    Vouch(CopyId<C, T>),
    /// A chained write naming the sync ID's actor (Role changes travel).
    Actor,
    /// (A3) This removal, or a grant of its reach.
    Reach(CopyId<C, T>),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    /// Vouches against a member lowering are evidence.
    pub vouches: bool,
}

/// Work done, by kind (count tests: notes/evidence-derivation.md, Incremental).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Atom counts moved (a body's edges in a sync ID).
    pub atoms: usize,
    /// Edges a closure took in.
    pub edges: usize,
    /// Copies a closure looked at.
    pub visits: usize,
    /// Parts whose joined-ness was computed again.
    pub rechecks: usize,
    /// (A3) Grants and removals a reach computation read.
    pub reach: usize,
    /// Closures computed again from seeds.
    pub closes: usize,
    /// Bodies read (taken in or out of a sync ID).
    pub bodies: usize,
}

#[derive(Clone, Debug)]
struct Held<C, T, K> {
    parts: Vec<Part<C, T, K>>,
    joined: Vec<bool>,
}

/// Parts by key: (copy, part index).
type ByKey<C, T, K> = BTreeMap<K, BTreeSet<(CopyId<C, T>, usize)>>;

/// The held copies and what the closure looks them up by.
#[derive(Clone, Debug)]
struct Ix<C, T, K> {
    copies: BTreeMap<CopyId<C, T>, Held<C, T, K>>,
    on_thing: BTreeMap<T, BTreeSet<C>>,
    /// Copies with a chained write on the edge.
    taken_on: BTreeMap<Edge<T>, BTreeSet<CopyId<C, T>>>,
    /// Chained grants on the edge, by key: the first decides which parts the edge joins.
    grants: BTreeMap<Edge<T>, ByKey<C, T, K>>,
    /// Parts whose known path uses the edge (no record edge), by `pos`.
    resting: BTreeMap<Edge<T>, ByKey<C, T, K>>,
    /// Copies with a chained write naming the holder.
    by_holder: BTreeMap<T, BTreeSet<CopyId<C, T>>>,
    /// Copies with a chained vouch keyed by the copy.
    vouches_by: BTreeMap<CopyId<C, T>, BTreeSet<CopyId<C, T>>>,
    /// Copies with a write whose reset names the copy as its entry's creation.
    resetters: BTreeMap<CopyId<C, T>, BTreeSet<CopyId<C, T>>>,
    /// (A3) Chained parts giving write, and chained removals.
    reach_grants: BTreeSet<(CopyId<C, T>, usize)>,
    reach_removals: BTreeSet<(CopyId<C, T>, usize)>,
}

/// A sync ID's closure over its seeds.
#[derive(Clone, Debug)]
struct Closure<C, T> {
    members: Required<C, T>,
    /// Members per thing (a vouch needs a member on its thing).
    on: BTreeMap<T, usize>,
    edges: BTreeSet<Edge<T>>,
    pending: Pending<C, T>,
}

impl<C, T> Default for Closure<C, T> {
    fn default() -> Self {
        Closure { members: BTreeMap::new(), on: BTreeMap::new(), edges: BTreeSet::new(), pending: BTreeMap::new() }
    }
}

#[derive(Clone, Debug)]
struct Sid<C, T> {
    actor: T,
    unit: BTreeSet<T>,
    /// Per edge, the bodies bringing it.
    atoms: BTreeMap<Edge<T>, usize>,
    /// Copies that are seeds by themselves: writes naming the actor, (A3) removals with their reach.
    seeds: Required<C, T>,
    closure: Closure<C, T>,
}

enum Item<C, T> {
    Edge(Edge<T>),
    Copy(CopyId<C, T>, Reason<C, T>),
    /// A chained vouch, keyed by a lowering in the set.
    Vouch(CopyId<C, T>, CopyId<C, T>),
}

/// What an update leaves to do: closures to extend, sync IDs to close again, seeds to recompute.
struct Todo<C, T> {
    work: BTreeMap<T, Vec<Item<C, T>>>,
    dirty: BTreeSet<T>,
    seeds: BTreeSet<T>,
    reach: bool,
}

impl<C, T> Default for Todo<C, T> {
    fn default() -> Self {
        Todo { work: BTreeMap::new(), dirty: BTreeSet::new(), seeds: BTreeSet::new(), reach: false }
    }
}

impl<C: Ord + Clone, T: Ord + Clone> Todo<C, T> {
    fn push(&mut self, sid: &T, item: Item<C, T>) {
        self.work.entry(sid.clone()).or_default().push(item);
    }
}

/// The evidence of every sync ID registered, over one node's held copies.
#[derive(Clone, Debug)]
pub struct Evidence<C, T, K> {
    cfg: Config,
    ix: Ix<C, T, K>,
    sids: BTreeMap<T, Sid<C, T>>,
    edge_sids: BTreeMap<Edge<T>, BTreeSet<T>>,
    member_sids: BTreeMap<CopyId<C, T>, BTreeSet<T>>,
    thing_sids: BTreeMap<T, BTreeSet<T>>,
    actor_sids: BTreeMap<T, BTreeSet<T>>,
    counts: Counts,
}

fn first<K: Ord + std::marker::Copy, V>(m: Option<&BTreeMap<K, V>>) -> Option<K> {
    m.and_then(|m| m.keys().next().copied())
}

impl<C, T, K> Evidence<C, T, K>
where
    C: Ord + std::marker::Copy + Debug,
    T: Ord + std::marker::Copy + Debug,
    K: Ord + std::marker::Copy + Debug,
{
    pub fn new(cfg: Config) -> Self {
        let ix = Ix {
            copies: BTreeMap::new(),
            on_thing: BTreeMap::new(),
            taken_on: BTreeMap::new(),
            grants: BTreeMap::new(),
            resting: BTreeMap::new(),
            by_holder: BTreeMap::new(),
            vouches_by: BTreeMap::new(),
            resetters: BTreeMap::new(),
            reach_grants: BTreeSet::new(),
            reach_removals: BTreeSet::new(),
        };
        Evidence { cfg, ix, sids: BTreeMap::new(), edge_sids: BTreeMap::new(), member_sids: BTreeMap::new(), thing_sids: BTreeMap::new(), actor_sids: BTreeMap::new(), counts: Counts::default() }
    }

    pub fn counts(&self) -> Counts {
        self.counts
    }

    /// The copies S's evidence holds (things outside its unit), each with a reason.
    pub fn required(&self, sid: &T) -> Option<&Required<C, T>> {
        self.sids.get(sid).map(|s| &s.closure.members)
    }

    /// The edges S's evidence uses.
    pub fn edges(&self, sid: &T) -> Option<&BTreeSet<Edge<T>>> {
        self.sids.get(sid).map(|s| &s.closure.edges)
    }

    /// The edges S's bodies bring and how many bring each.
    pub fn atoms(&self, sid: &T) -> Option<&BTreeMap<Edge<T>, usize>> {
        self.sids.get(sid).map(|s| &s.atoms)
    }

    pub fn holds(&self, c: &CopyId<C, T>) -> bool {
        self.ix.copies.contains_key(c)
    }

    /// S's evidence computed from nothing over the held copies (the same closure).
    pub fn from_scratch(&self, sid: &T) -> Option<Required<C, T>> {
        self.from_scratch_counted(sid).map(|r| r.0)
    }

    /// `from_scratch` with the work it did.
    pub fn from_scratch_counted(&self, sid: &T) -> Option<(Required<C, T>, Counts)> {
        let s = self.sids.get(sid)?;
        let mut counts = Counts::default();
        let mut atoms = BTreeMap::new();
        let mut work = vec![];
        for t in &s.unit {
            for c in self.ix.on_thing.get(t).into_iter().flatten() {
                let copy = (*c, *t);
                for e in self.body_edges(&copy) {
                    *atoms.entry(e).or_insert(0) += 1;
                }
                counts.bodies += 1;
            }
        }
        work.extend(atoms.keys().map(|e| Item::Edge(*e)));
        work.extend(self.seeds_for(s, &mut counts).into_iter().map(|(c, r)| Item::Copy(c, r)));
        work.extend(self.body_vouches(&s.unit));
        let mut cl = Closure::default();
        close(&self.ix, self.cfg, &s.unit, &mut cl, work, &mut counts);
        Some((cl.members, counts))
    }

    /// Registers sync ID `sid` with actor `actor` and an empty unit.
    pub fn add_sid(&mut self, sid: T, actor: T) {
        if self.sids.contains_key(&sid) {
            return;
        }
        self.sids.insert(sid, Sid { actor, unit: BTreeSet::new(), atoms: BTreeMap::new(), seeds: BTreeMap::new(), closure: Closure::default() });
        self.actor_sids.entry(actor).or_default().insert(sid);
        let mut todo = Todo::default();
        todo.seeds.insert(sid);
        self.settle(todo);
    }

    /// `t` joins S's unit.
    pub fn join(&mut self, sid: &T, t: T) {
        let Some(s) = self.sids.get_mut(sid) else { return };
        if !s.unit.insert(t) {
            return;
        }
        let had = s.closure.on.get(&t).is_some_and(|n| *n > 0);
        self.thing_sids.entry(t).or_default().insert(*sid);
        let mut todo = Todo::default();
        for c in self.ix.on_thing.get(&t).cloned().unwrap_or_default() {
            self.body_add(sid, &(c, t), &mut todo);
        }
        // copies on t are bodies now; the reach under the new unit
        if had {
            todo.dirty.insert(*sid);
        }
        todo.seeds.insert(*sid);
        self.settle(todo);
    }

    /// `t` leaves S's unit.
    pub fn leave(&mut self, sid: &T, t: T) {
        let Some(s) = self.sids.get_mut(sid) else { return };
        if !s.unit.remove(&t) {
            return;
        }
        if let Some(x) = self.thing_sids.get_mut(&t) {
            x.remove(sid);
        }
        let mut todo = Todo::default();
        for c in self.ix.on_thing.get(&t).cloned().unwrap_or_default() {
            self.body_remove(sid, &(c, t), &mut todo);
        }
        // what the bodies on t still need becomes copies
        todo.dirty.insert(*sid);
        todo.seeds.insert(*sid);
        self.settle(todo);
    }

    /// A copy held from now on (a copy already held is taken again with these facts).
    pub fn add(&mut self, c: CopyId<C, T>, parts: Vec<Part<C, T, K>>) {
        if self.ix.copies.contains_key(&c) {
            self.forget(&c);
        }
        let mut todo = Todo::default();
        let n = parts.len();
        self.ix.copies.insert(c, Held { parts, joined: vec![false; n] });
        self.ix.on_thing.entry(c.1).or_default().insert(c.0);
        let held = self.ix.copies.get(&c).map(|h| h.parts.clone()).unwrap_or_default();
        for (i, p) in held.iter().enumerate() {
            if let Kind::Write(w) = &p.kind
                && let Some(cr) = w.creation
            {
                self.ix.resetters.entry(cr).or_default().insert(c);
            }
            if let Some(hops) = &p.hops {
                for h in hops.iter().filter(|h| !h.record) {
                    self.ix.resting.entry(h.edge).or_default().entry(p.pos).or_default().insert((c, i));
                }
            }
        }
        // a body where its thing is in a unit (no part joined yet: its paths' edges come with
        // each part's joined-ness below)
        for sid in self.thing_sids.get(&c.1).cloned().unwrap_or_default() {
            self.body_add(&sid, &c, &mut todo);
        }
        // what its chained parts move (their grants join others, its own parts too), then its
        // own parts' joined-ness
        for (i, p) in held.iter().enumerate() {
            if p.chained {
                self.chained_on(&c, i, &mut todo);
            }
        }
        for i in 0..n {
            self.recheck(&c, i, &mut todo);
        }
        // the creation of a member's entry
        for r in self.ix.resetters.get(&c).cloned().unwrap_or_default() {
            for sid in self.member_sids.get(&r).cloned().unwrap_or_default() {
                todo.push(&sid, Item::Copy(c, Reason::Creation(r)));
            }
        }
        self.settle(todo);
    }

    /// A copy no longer held.
    pub fn forget(&mut self, c: &CopyId<C, T>) {
        let Some(h) = self.ix.copies.get(c).cloned() else { return };
        let mut todo = Todo::default();
        for sid in self.thing_sids.get(&c.1).cloned().unwrap_or_default() {
            self.body_remove(&sid, c, &mut todo);
        }
        for sid in self.member_sids.get(c).cloned().unwrap_or_default() {
            todo.dirty.insert(sid);
        }
        // its own parts leave the resting index first: what its grants unjoin is others' only
        for (i, p) in h.parts.iter().enumerate() {
            if let Some(hops) = &p.hops {
                for hp in hops.iter().filter(|hp| !hp.record) {
                    remove_by_key(&mut self.ix.resting, &hp.edge, &p.pos, &(*c, i));
                }
            }
        }
        for (i, p) in h.parts.iter().enumerate() {
            if p.chained {
                self.chained_off(c, i, &mut todo);
            }
            if let Kind::Write(w) = &p.kind
                && let Some(cr) = w.creation
                && let Some(s) = self.ix.resetters.get_mut(&cr)
            {
                s.remove(c);
                if s.is_empty() {
                    self.ix.resetters.remove(&cr);
                }
            }
        }
        self.ix.copies.remove(c);
        if let Some(s) = self.ix.on_thing.get_mut(&c.1) {
            s.remove(&c.0);
            if s.is_empty() {
                self.ix.on_thing.remove(&c.1);
            }
        }
        self.settle(todo);
    }

    /// Part `i` of copy `c` is chained (or no longer is).
    pub fn set_chained(&mut self, c: &CopyId<C, T>, i: usize, chained: bool) {
        let Some(p) = self.ix.copies.get_mut(c).and_then(|h| h.parts.get_mut(i)) else { return };
        if p.chained == chained {
            return;
        }
        p.chained = chained;
        let mut todo = Todo::default();
        if chained {
            self.chained_on(c, i, &mut todo);
        } else {
            for sid in self.member_sids.get(c).cloned().unwrap_or_default() {
                todo.dirty.insert(sid);
            }
            self.chained_off(c, i, &mut todo);
        }
        self.settle(todo);
    }

    /// Part `i` of copy `c` now knows its path (its split entry opened here).
    pub fn open_path(&mut self, c: &CopyId<C, T>, i: usize, hops: Vec<Hop<T>>) {
        let Some(p) = self.ix.copies.get_mut(c).and_then(|h| h.parts.get_mut(i)) else { return };
        if p.hops.is_some() {
            return;
        }
        let pos = p.pos;
        for h in hops.iter().filter(|h| !h.record) {
            self.ix.resting.entry(h.edge).or_default().entry(pos).or_default().insert((*c, i));
        }
        p.hops = Some(hops);
        let mut todo = Todo::default();
        self.recheck(c, i, &mut todo);
        self.settle(todo);
    }

    // ---- what a change moves ----

    /// Indexes a chained part of a held copy and queues what it brings where.
    fn chained_on(&mut self, c: &CopyId<C, T>, i: usize, todo: &mut Todo<C, T>) {
        let Some(p) = self.part(c, i) else { return };
        match &p.kind {
            Kind::Content => {}
            Kind::Vouch { keyed } => {
                self.ix.vouches_by.entry(*keyed).or_default().insert(*c);
                if self.cfg.vouches {
                    let mut sids = self.member_sids.get(keyed).cloned().unwrap_or_default();
                    if self.ix.copies.contains_key(keyed) {
                        sids.extend(self.thing_sids.get(&keyed.1).into_iter().flatten().copied());
                    }
                    for sid in sids {
                        todo.push(&sid, Item::Vouch(*c, *keyed));
                    }
                }
            }
            Kind::Write(w) => {
                let e = (w.holder, c.1);
                self.ix.taken_on.entry(e).or_default().insert(*c);
                for sid in self.edge_sids.get(&e).cloned().unwrap_or_default() {
                    todo.push(&sid, Item::Copy(*c, Reason::Edge(e)));
                }
                self.ix.by_holder.entry(w.holder).or_default().insert(*c);
                todo.seeds.extend(self.actor_sids.get(&w.holder).into_iter().flatten().copied());
                if w.gives_write {
                    self.ix.reach_grants.insert((*c, i));
                    todo.reach = true;
                }
                if w.removal {
                    self.ix.reach_removals.insert((*c, i));
                    todo.reach = true;
                }
                if w.grant {
                    let before = first(self.ix.grants.get(&e));
                    self.ix.grants.entry(e).or_default().entry(p.pos).or_default().insert((*c, i));
                    if before.is_none_or(|b| p.pos < b) {
                        self.rejoin(&e, Some(p.pos), before, todo);
                    }
                }
            }
        }
    }

    /// Takes a chained part (no longer chained, or forgotten) out of the indexes; the sync IDs
    /// it may have brought something into close again.
    fn chained_off(&mut self, c: &CopyId<C, T>, i: usize, todo: &mut Todo<C, T>) {
        let Some(p) = self.part(c, i) else { return };
        match &p.kind {
            Kind::Content => {}
            Kind::Vouch { keyed } => {
                if let Some(s) = self.ix.vouches_by.get_mut(keyed) {
                    s.remove(c);
                    if s.is_empty() {
                        self.ix.vouches_by.remove(keyed);
                    }
                }
            }
            Kind::Write(w) => {
                let e = (w.holder, c.1);
                // another chained part of the copy may set the same edge
                let still = self.ix.copies.get(c).is_some_and(|h| h.parts.iter().enumerate().any(|(j, q)| j != i && q.chained && matches!(&q.kind, Kind::Write(x) if x.holder == w.holder)));
                if !still {
                    remove_from(&mut self.ix.taken_on, &e, c);
                    remove_from(&mut self.ix.by_holder, &w.holder, c);
                }
                todo.seeds.extend(self.actor_sids.get(&w.holder).into_iter().flatten().copied());
                if self.ix.reach_grants.remove(&(*c, i)) | self.ix.reach_removals.remove(&(*c, i)) {
                    todo.reach = true;
                }
                if w.grant {
                    let before = first(self.ix.grants.get(&e));
                    remove_by_key(&mut self.ix.grants, &e, &p.pos, &(*c, i));
                    let after = first(self.ix.grants.get(&e));
                    if after != before {
                        self.unjoin(&e, before, after, todo);
                    }
                }
            }
        }
    }

    fn part(&self, c: &CopyId<C, T>, i: usize) -> Option<Part<C, T, K>> {
        self.ix.copies.get(c).and_then(|h| h.parts.get(i)).cloned()
    }

    /// The first chained grant on `e` moved earlier, from `old` to `new`: the parts resting on
    /// `e` ordered after `new` and not after `old` may be joined now.
    fn rejoin(&mut self, e: &Edge<T>, new: Option<K>, old: Option<K>, todo: &mut Todo<C, T>) {
        let Some(new) = new else { return };
        let hi = old.map_or(Bound::Unbounded, Bound::Included);
        let parts: Vec<(CopyId<C, T>, usize)> = self.ix.resting.get(e).map(|r| r.range((Bound::Excluded(new), hi)).flat_map(|(_, s)| s.iter().copied()).collect()).unwrap_or_default();
        for (c, i) in parts {
            self.recheck(&c, i, todo);
        }
    }

    /// The first chained grant on `e` moved later or went, from `old` to `new`: the parts resting
    /// on `e` ordered after `old` and not after `new` are no longer joined.
    fn unjoin(&mut self, e: &Edge<T>, old: Option<K>, new: Option<K>, todo: &mut Todo<C, T>) {
        let Some(old) = old else { return };
        let hi = new.map_or(Bound::Unbounded, Bound::Included);
        let parts: Vec<(CopyId<C, T>, usize)> = self.ix.resting.get(e).map(|r| r.range((Bound::Excluded(old), hi)).flat_map(|(_, s)| s.iter().copied()).collect()).unwrap_or_default();
        for (c, i) in parts {
            self.recheck(&c, i, todo);
        }
    }

    /// Computes part `i`'s joined-ness again; where it moved, moves what it brings in each sync
    /// ID holding its copy (a body's atoms; a member's closure).
    fn recheck(&mut self, c: &CopyId<C, T>, i: usize, todo: &mut Todo<C, T>) {
        self.counts.rechecks += 1;
        let Some(p) = self.part(c, i) else { return };
        let now = self.joined(&p);
        let Some(was) = self.ix.copies.get_mut(c).and_then(|h| h.joined.get_mut(i)) else { return };
        if *was == now {
            return;
        }
        *was = now;
        let edges = p.hops.iter().flatten().map(|h| h.edge);
        if !now {
            for sid in self.thing_sids.get(&c.1).cloned().unwrap_or_default() {
                self.atoms_out(&sid, edges.clone(), todo);
            }
            for sid in self.member_sids.get(c).cloned().unwrap_or_default() {
                todo.dirty.insert(sid);
            }
            return;
        }
        for sid in self.thing_sids.get(&c.1).cloned().unwrap_or_default() {
            self.atoms_in(&sid, edges.clone(), todo);
        }
        for sid in self.member_sids.get(c).cloned().unwrap_or_default() {
            for e in edges.clone() {
                todo.push(&sid, Item::Edge(e));
            }
        }
    }

    /// A part's path is joined: each edge that is no record edge holds a held chained grant
    /// ordered before the part.
    fn joined(&self, p: &Part<C, T, K>) -> bool {
        p.hops.as_ref().is_some_and(|hops| hops.iter().filter(|h| !h.record).all(|h| first(self.ix.grants.get(&h.edge)).is_some_and(|f| f < p.pos)))
    }

    /// The edges body `c` brings: each joined part's path edges, each edge write's remaining
    /// admin edge.
    fn body_edges(&self, c: &CopyId<C, T>) -> Vec<Edge<T>> {
        let Some(h) = self.ix.copies.get(c) else { return vec![] };
        let mut out = vec![];
        for (p, j) in h.parts.iter().zip(&h.joined) {
            if *j {
                out.extend(p.hops.iter().flatten().map(|h| h.edge));
            }
            if let Kind::Write(w) = &p.kind
                && let Some(n) = w.relies
            {
                out.push((n, c.1));
            }
        }
        out
    }

    /// The chained vouches keyed by a body of a unit (`unit`'s held copies).
    fn body_vouches(&self, unit: &BTreeSet<T>) -> Vec<Item<C, T>> {
        if !self.cfg.vouches {
            return vec![];
        }
        self.ix.vouches_by.iter().filter(|(r, _)| unit.contains(&r.1) && self.ix.copies.contains_key(r)).flat_map(|(r, vs)| vs.iter().map(|v| Item::Vouch(*v, *r))).collect()
    }

    fn atoms_in(&mut self, sid: &T, edges: impl Iterator<Item = Edge<T>>, todo: &mut Todo<C, T>) {
        let Some(s) = self.sids.get_mut(sid) else { return };
        for e in edges {
            self.counts.atoms += 1;
            let n = s.atoms.entry(e).or_insert(0);
            *n += 1;
            if *n == 1 {
                todo.push(sid, Item::Edge(e));
            }
        }
    }

    fn atoms_out(&mut self, sid: &T, edges: impl Iterator<Item = Edge<T>>, todo: &mut Todo<C, T>) {
        let Some(s) = self.sids.get_mut(sid) else { return };
        for e in edges {
            self.counts.atoms += 1;
            if let Some(n) = s.atoms.get_mut(&e) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    s.atoms.remove(&e);
                    todo.dirty.insert(*sid);
                }
            }
        }
    }

    fn body_add(&mut self, sid: &T, c: &CopyId<C, T>, todo: &mut Todo<C, T>) {
        self.counts.bodies += 1;
        let edges = self.body_edges(c);
        self.atoms_in(sid, edges.into_iter(), todo);
        if self.cfg.vouches {
            for v in self.ix.vouches_by.get(c).into_iter().flatten() {
                todo.push(sid, Item::Vouch(*v, *c));
            }
        }
    }

    fn body_remove(&mut self, sid: &T, c: &CopyId<C, T>, todo: &mut Todo<C, T>) {
        self.counts.bodies += 1;
        let edges = self.body_edges(c);
        self.atoms_out(sid, edges.into_iter(), todo);
        if self.ix.vouches_by.contains_key(c) {
            todo.dirty.insert(*sid);
        }
    }

    /// The copies that are seeds of S by themselves: chained writes naming its actor, and (A3)
    /// each chained removal of an edge on a thing outside the unit joined to it by chained write
    /// grants (its reach), with that reach.
    fn seeds_for(&self, s: &Sid<C, T>, counts: &mut Counts) -> Required<C, T> {
        let mut out: Required<C, T> = BTreeMap::new();
        for c in self.ix.by_holder.get(&s.actor).into_iter().flatten() {
            out.entry(*c).or_insert(Reason::Actor);
        }
        if self.ix.reach_removals.is_empty() {
            return out;
        }
        let grants: Vec<(Edge<T>, CopyId<C, T>)> = self.ix.reach_grants.iter().filter_map(|(c, i)| match self.ix.copies.get(c)?.parts.get(*i)?.kind {
            Kind::Write(ref w) => Some(((w.holder, c.1), *c)),
            _ => None,
        }).collect();
        counts.reach += grants.len() + self.ix.reach_removals.len();
        // the things holding write or above on a unit thing, through chained grants
        let mut back = s.unit.clone();
        loop {
            let n = back.len();
            back.extend(grants.iter().filter(|(e, _)| back.contains(&e.1)).map(|(e, _)| e.0).collect::<Vec<_>>());
            if back.len() == n {
                break;
            }
        }
        for (r, _) in &self.ix.reach_removals {
            let t = r.1;
            if s.unit.contains(&t) {
                continue;
            }
            let mut fwd = BTreeSet::from([t]);
            loop {
                let n = fwd.len();
                fwd.extend(grants.iter().filter(|(e, _)| fwd.contains(&e.0)).map(|(e, _)| e.1).collect::<Vec<_>>());
                if fwd.len() == n {
                    break;
                }
            }
            if !fwd.iter().any(|x| s.unit.contains(x)) {
                continue;
            }
            out.entry(*r).or_insert(Reason::Reach(*r));
            for (e, g) in &grants {
                if fwd.contains(&e.0) && back.contains(&e.1) {
                    out.entry(*g).or_insert(Reason::Reach(*r));
                }
            }
        }
        out
    }

    // ---- settling ----

    fn settle(&mut self, mut todo: Todo<C, T>) {
        if todo.reach {
            todo.seeds.extend(self.sids.keys().copied());
        }
        for sid in std::mem::take(&mut todo.seeds) {
            let Some(s) = self.sids.get(&sid) else { continue };
            let mut counts = Counts::default();
            let new = self.seeds_for(s, &mut counts);
            self.counts.reach += counts.reach;
            let lost = s.seeds.keys().any(|c| !new.contains_key(c));
            for (c, r) in &new {
                if !s.seeds.contains_key(c) {
                    todo.push(&sid, Item::Copy(*c, *r));
                }
            }
            if lost {
                todo.dirty.insert(sid);
            }
            if let Some(s) = self.sids.get_mut(&sid) {
                s.seeds = new;
            }
        }
        for sid in std::mem::take(&mut todo.dirty) {
            todo.work.remove(&sid);
            self.reclose(&sid);
        }
        for (sid, work) in std::mem::take(&mut todo.work) {
            self.extend(&sid, work);
        }
    }

    /// Extends S's closure by `work` and indexes what it added.
    fn extend(&mut self, sid: &T, work: Vec<Item<C, T>>) {
        let Some(s) = self.sids.get_mut(sid) else { return };
        let (edges, members) = close(&self.ix, self.cfg, &s.unit, &mut s.closure, work, &mut self.counts);
        for e in edges {
            self.edge_sids.entry(e).or_default().insert(*sid);
        }
        for m in members {
            self.member_sids.entry(m).or_default().insert(*sid);
        }
    }

    /// Closes S again from its atoms and seeds.
    fn reclose(&mut self, sid: &T) {
        let Some(s) = self.sids.get_mut(sid) else { return };
        self.counts.closes += 1;
        let old = std::mem::take(&mut s.closure);
        for e in &old.edges {
            remove_from(&mut self.edge_sids, e, sid);
        }
        for m in old.members.keys() {
            remove_from(&mut self.member_sids, m, sid);
        }
        let Some(s) = self.sids.get(sid) else { return };
        let mut work: Vec<Item<C, T>> = s.atoms.keys().map(|e| Item::Edge(*e)).collect();
        work.extend(s.seeds.iter().map(|(c, r)| Item::Copy(*c, *r)));
        work.extend(self.body_vouches(&s.unit));
        self.extend(sid, work);
    }
}

/// Removes `v` from the set at `k`, dropping an emptied set.
fn remove_from<A: Ord, B: Ord>(m: &mut BTreeMap<A, BTreeSet<B>>, k: &A, v: &B) {
    if let Some(s) = m.get_mut(k) {
        s.remove(v);
        if s.is_empty() {
            m.remove(k);
        }
    }
}

fn remove_by_key<E: Ord, K: Ord, V: Ord>(m: &mut BTreeMap<E, BTreeMap<K, BTreeSet<V>>>, e: &E, k: &K, v: &V) {
    if let Some(byk) = m.get_mut(e) {
        remove_from(byk, k, v);
        if byk.is_empty() {
            m.remove(e);
        }
    }
}

/// The closure step (draft §4 Evidence of a commit), from `work` over the held copies: an edge
/// brings every held copy with a chained write on it; a copy (outside the unit) brings its joined
/// parts' path edges, its writes' remaining admin edges and the creations their resets name, and
/// (`vouches`) the chained vouches keyed by it on a thing some member is on. Returns the edges
/// and members it added.
fn close<C, T, K>(ix: &Ix<C, T, K>, cfg: Config, unit: &BTreeSet<T>, cl: &mut Closure<C, T>, mut work: Vec<Item<C, T>>, counts: &mut Counts) -> (Vec<Edge<T>>, Vec<CopyId<C, T>>)
where
    C: Ord + std::marker::Copy,
    T: Ord + std::marker::Copy,
    K: Ord + std::marker::Copy,
{
    let mut edges = vec![];
    let mut members = vec![];
    while let Some(item) = work.pop() {
        match item {
            Item::Edge(e) => {
                if !cl.edges.insert(e) {
                    continue;
                }
                counts.edges += 1;
                edges.push(e);
                work.extend(ix.taken_on.get(&e).into_iter().flatten().map(|c| Item::Copy(*c, Reason::Edge(e))));
            }
            Item::Copy(c, why) => {
                counts.visits += 1;
                if unit.contains(&c.1) || cl.members.contains_key(&c) {
                    continue;
                }
                let Some(h) = ix.copies.get(&c) else { continue };
                cl.members.insert(c, why);
                members.push(c);
                let n = cl.on.entry(c.1).or_insert(0);
                *n += 1;
                if *n == 1
                    && let Some(p) = cl.pending.remove(&c.1)
                {
                    work.extend(p.into_iter().map(|(v, r)| Item::Copy(v, Reason::Vouch(r))));
                }
                for (p, j) in h.parts.iter().zip(&h.joined) {
                    if *j {
                        work.extend(p.hops.iter().flatten().map(|h| Item::Edge(h.edge)));
                    }
                    if let Kind::Write(w) = &p.kind {
                        if let Some(n) = w.relies {
                            work.push(Item::Edge((n, c.1)));
                        }
                        if let Some(cr) = w.creation {
                            work.push(Item::Copy(cr, Reason::Creation(c)));
                        }
                    }
                }
                if cfg.vouches {
                    work.extend(ix.vouches_by.get(&c).into_iter().flatten().map(|v| Item::Vouch(*v, c)));
                }
            }
            Item::Vouch(v, r) => {
                if unit.contains(&v.1) || cl.members.contains_key(&v) {
                    continue;
                }
                if cl.on.get(&v.1).is_some_and(|n| *n > 0) {
                    work.push(Item::Copy(v, Reason::Vouch(r)));
                } else {
                    cl.pending.entry(v.1).or_default().insert(v, r);
                }
            }
        }
    }
    (edges, members)
}
