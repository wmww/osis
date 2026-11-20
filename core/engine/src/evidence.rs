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
//!
//! Two seed relations are graphs over things, kept as indexes so a change reaches only the sync IDs
//! it can move (notes/evidence-derivation.md, Reach and keys-open travel): **reach** (`Config::reach`)
//! over chained write grants, from a removal's target into a unit; **keys-open travel**
//! (`Config::keys_open`) over chained grants giving read, from a sync ID's actor to the holders whose
//! role changes travel under it.

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

/// A part of a held copy: (copy, part index).
type PartId<C, T> = (CopyId<C, T>, usize);

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
    /// (reach) It gives below write at its own `ts`, and is no finalize: a self-removal and a
    /// grant of read are removals, a demotion from admin to write is not.
    pub removal: bool,
    /// (reach) It gives write or above (any `until`): a step of a reach.
    pub gives_write: bool,
    /// (keys-open travel) It gives read or above (any `until`) and is no self-removal: a step by
    /// which keys open.
    pub gives_read: bool,
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
    /// A chained write naming this holder, whose role changes travel under the sync ID: its
    /// actor, or (`keys_open`) a thing the actor's keys open (Role changes travel).
    Travels(T),
    /// (reach) A chained removal whose reach under the sync ID is held.
    Removal,
    /// (reach) A chained write grant on this edge of a held removal's reach.
    Reach(Edge<T>),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    /// Vouches against a member lowering are evidence.
    pub vouches: bool,
    /// (A3) A removal with its reach is a seed (draft §4 Evidence of a sync ID): on for brief 3's
    /// switch (notes/a2-spec/README.md OPEN 14).
    pub reach: bool,
    /// Role changes travel's keys-open half: a chained write naming a holder the actor holds read
    /// or above on, through chained grants at any time, is a seed (held-model `Rule::keys_open`).
    /// Off: only writes naming the actor.
    pub keys_open: bool,
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
    /// (reach) Things and edges a reach computation walked.
    pub reach: usize,
    /// (reach) Seeds a reach computation gave (a copy or edge per sync ID, new or not).
    pub reach_seeds: usize,
    /// (keys-open) Things and edges a keys-open computation walked.
    pub opened: usize,
    /// Closures computed again from seeds.
    pub closes: usize,
    /// Bodies read (taken in or out of a sync ID).
    pub bodies: usize,
    /// Writes naming a travelling holder a seed computation from nothing read.
    pub seeds: usize,
}

#[derive(Clone, Debug)]
struct Held<C, T, K> {
    parts: Vec<Part<C, T, K>>,
    joined: Vec<bool>,
}

/// Parts by key: (copy, part index).
type ByKey<C, T, K> = BTreeMap<K, BTreeSet<PartId<C, T>>>;

/// A graph over things: per edge the chained parts setting it, and its adjacency both ways.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Graph<C, T> {
    parts: BTreeMap<Edge<T>, BTreeSet<PartId<C, T>>>,
    out: BTreeMap<T, BTreeSet<T>>,
    inn: BTreeMap<T, BTreeSet<T>>,
}

impl<C: Ord + Copy, T: Ord + Copy> Graph<C, T> {
    fn new() -> Self {
        Graph { parts: BTreeMap::new(), out: BTreeMap::new(), inn: BTreeMap::new() }
    }
    /// True when the edge is new.
    fn insert(&mut self, e: Edge<T>, p: PartId<C, T>) -> bool {
        let s = self.parts.entry(e).or_default();
        let new = s.is_empty();
        s.insert(p);
        if new {
            self.out.entry(e.0).or_default().insert(e.1);
            self.inn.entry(e.1).or_default().insert(e.0);
        }
        new
    }
    /// True when the edge is gone.
    fn remove(&mut self, e: &Edge<T>, p: &PartId<C, T>) -> bool {
        let Some(s) = self.parts.get_mut(e) else { return false };
        if !s.remove(p) || !s.is_empty() {
            return false;
        }
        self.parts.remove(e);
        remove_from(&mut self.out, &e.0, &e.1);
        remove_from(&mut self.inn, &e.1, &e.0);
        true
    }
    fn next(&self, fwd: bool, x: T) -> impl Iterator<Item = T> + '_ {
        if fwd { &self.out } else { &self.inn }.get(&x).into_iter().flatten().copied()
    }
}

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
    /// (reach) Chained parts giving write, by edge.
    writes: Graph<C, T>,
    /// (reach) Chained removals, by the thing they are on (the target of their edge).
    removals_on: BTreeMap<T, BTreeSet<PartId<C, T>>>,
    /// (keys-open travel) Chained parts giving read, by edge.
    reads: Graph<C, T>,
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

/// A sync ID's reach: its removals with their reach (seeds outside the unit), and the edges of
/// those reaches.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Reach<C, T> {
    seeds: Required<C, T>,
    ways: BTreeSet<Edge<T>>,
}

impl<C, T> Default for Reach<C, T> {
    fn default() -> Self {
        Reach { seeds: BTreeMap::new(), ways: BTreeSet::new() }
    }
}

/// The holders whose role changes travel under a sync ID, and the writes naming them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Travel<C, T> {
    /// The actor and (`keys_open`) what it holds read or above on through chained grants.
    open: BTreeSet<T>,
    /// Chained writes naming a holder in `open`.
    seeds: Required<C, T>,
}

#[derive(Clone, Debug)]
struct Sid<C, T> {
    actor: T,
    unit: BTreeSet<T>,
    /// Per edge, the bodies bringing it.
    atoms: BTreeMap<Edge<T>, usize>,
    travel: Travel<C, T>,
    reach: Reach<C, T>,
    closure: Closure<C, T>,
}

impl<C: Ord + Copy, T: Ord + Copy> Sid<C, T> {
    fn seeds(&self) -> impl Iterator<Item = (&CopyId<C, T>, &Reason<C, T>)> {
        self.travel.seeds.iter().chain(&self.reach.seeds)
    }
    fn seeded(&self, c: &CopyId<C, T>) -> bool {
        self.travel.seeds.contains_key(c) || self.reach.seeds.contains_key(c)
    }
}

enum Item<C, T> {
    Edge(Edge<T>),
    Copy(CopyId<C, T>, Reason<C, T>),
    /// A chained vouch, keyed by a lowering in the set.
    Vouch(CopyId<C, T>, CopyId<C, T>),
}

/// What an update leaves to do: closures to extend, sync IDs to close again, seeds to compute
/// again from nothing (`reach`, `travel`).
struct Todo<C, T> {
    work: BTreeMap<T, Vec<Item<C, T>>>,
    dirty: BTreeSet<T>,
    reach: BTreeSet<T>,
    travel: BTreeSet<T>,
}

impl<C, T> Default for Todo<C, T> {
    fn default() -> Self {
        Todo { work: BTreeMap::new(), dirty: BTreeSet::new(), reach: BTreeSet::new(), travel: BTreeSet::new() }
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
    /// Thing → sync IDs whose `open` holds it.
    open_sids: BTreeMap<T, BTreeSet<T>>,
    /// (reach) Copy → sync IDs whose reach seeds hold it; edge → sync IDs whose reach ways hold it.
    reach_sids: BTreeMap<CopyId<C, T>, BTreeSet<T>>,
    way_sids: BTreeMap<Edge<T>, BTreeSet<T>>,
    counts: Counts,
}

fn first<K: Ord + std::marker::Copy, V>(m: Option<&BTreeMap<K, V>>) -> Option<K> {
    m.and_then(|m| m.keys().next().copied())
}

/// Breadth-first from `from` (included) by `next`: the things reached and every edge walked (as
/// (holder, target): `fwd` walks holder to target). Each thing and edge counts one in `n`.
fn bfs<T: Ord + Copy, I: IntoIterator<Item = T>>(from: impl IntoIterator<Item = T>, fwd: bool, next: impl Fn(T) -> I, n: &mut usize) -> (BTreeSet<T>, Vec<Edge<T>>) {
    let mut seen = BTreeSet::new();
    let mut todo = vec![];
    for x in from {
        if seen.insert(x) {
            todo.push(x);
        }
    }
    let mut edges = vec![];
    while let Some(x) = todo.pop() {
        *n += 1;
        for y in next(x) {
            *n += 1;
            edges.push(if fwd { (x, y) } else { (y, x) });
            if seen.insert(y) {
                todo.push(y);
            }
        }
    }
    (seen, edges)
}

/// The adjacency of `edges`, holder to targets (`fwd`) or target to holders.
fn adjacency<T: Ord + Copy>(edges: &[Edge<T>], fwd: bool) -> BTreeMap<T, Vec<T>> {
    let mut m: BTreeMap<T, Vec<T>> = BTreeMap::new();
    for &(a, b) in edges {
        if fwd {
            m.entry(a).or_default().push(b);
        } else {
            m.entry(b).or_default().push(a);
        }
    }
    m
}

fn within<T: Ord + Copy>(m: &BTreeMap<T, Vec<T>>, x: T) -> impl Iterator<Item = T> + '_ {
    m.get(&x).into_iter().flatten().copied()
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
            writes: Graph::new(),
            removals_on: BTreeMap::new(),
            reads: Graph::new(),
        };
        Evidence { cfg, ix, sids: BTreeMap::new(), edge_sids: BTreeMap::new(), member_sids: BTreeMap::new(), thing_sids: BTreeMap::new(), open_sids: BTreeMap::new(), reach_sids: BTreeMap::new(), way_sids: BTreeMap::new(), counts: Counts::default() }
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

    /// (reach) How many reach seeds S keeps, and how many edges of their reaches (memory counts).
    pub fn reach_size(&self, sid: &T) -> Option<(usize, usize)> {
        self.sids.get(sid).map(|s| (s.reach.seeds.len(), s.reach.ways.len()))
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
        let travel = self.travel_of(s.actor, &mut counts);
        let reach = self.reach_of(&s.unit, &mut counts);
        work.extend(travel.seeds.iter().chain(&reach.seeds).map(|(c, r)| Item::Copy(*c, *r)));
        work.extend(self.body_vouches(&s.unit));
        let mut cl = Closure::default();
        close(&self.ix, self.cfg, &s.unit, &mut cl, work, &mut counts);
        Some((cl.members, counts))
    }

    /// Checks the incremental state against itself built from nothing (tests, at teardown or every
    /// step): per sync ID its evidence, atoms, travelling holders and reach equal from scratch, the
    /// reach and keys-open graphs hold exactly the held chained parts, and the reverse indexes
    /// (edge, member, thing, open thing, reach copy and way → sync IDs) hold exactly what the sync
    /// IDs do.
    pub fn check(&self) -> Result<(), String> {
        let mut edge_sids: BTreeMap<Edge<T>, BTreeSet<T>> = BTreeMap::new();
        let mut member_sids: BTreeMap<CopyId<C, T>, BTreeSet<T>> = BTreeMap::new();
        let mut thing_sids: BTreeMap<T, BTreeSet<T>> = BTreeMap::new();
        let mut open_sids: BTreeMap<T, BTreeSet<T>> = BTreeMap::new();
        let mut reach_sids: BTreeMap<CopyId<C, T>, BTreeSet<T>> = BTreeMap::new();
        let mut way_sids: BTreeMap<Edge<T>, BTreeSet<T>> = BTreeMap::new();
        let (writes, removals_on, reads) = self.graphs();
        if writes != self.ix.writes || removals_on != self.ix.removals_on || reads != self.ix.reads {
            return Err("a reach or keys-open graph does not hold exactly the chained parts".into());
        }
        for (sid, s) in &self.sids {
            // the same copies (each with the first reason found, which may differ)
            let scratch = self.from_scratch(sid).unwrap_or_default();
            if scratch.keys().ne(s.closure.members.keys()) {
                return Err(format!("sid {sid:?}: incremental {:?} from scratch {scratch:?}", s.closure.members));
            }
            let mut atoms: BTreeMap<Edge<T>, usize> = BTreeMap::new();
            for t in &s.unit {
                for c in self.ix.on_thing.get(t).into_iter().flatten() {
                    for e in self.body_edges(&(*c, *t)) {
                        *atoms.entry(e).or_insert(0) += 1;
                    }
                }
            }
            if atoms != s.atoms {
                return Err(format!("sid {sid:?}: atoms {:?}, counted {atoms:?}", s.atoms));
            }
            let travel = self.travel_of(s.actor, &mut Counts::default());
            if travel.open != s.travel.open || travel.seeds.keys().ne(s.travel.seeds.keys()) {
                return Err(format!("sid {sid:?}: travel {:?}, computed {travel:?}", s.travel));
            }
            let reach = self.reach_of(&s.unit, &mut Counts::default());
            if reach.ways != s.reach.ways || reach.seeds.keys().ne(s.reach.seeds.keys()) {
                return Err(format!("sid {sid:?}: reach {:?}, computed {reach:?}", s.reach));
            }
            for e in &s.closure.edges {
                edge_sids.entry(*e).or_default().insert(*sid);
            }
            for m in s.closure.members.keys() {
                member_sids.entry(*m).or_default().insert(*sid);
            }
            for t in &s.unit {
                thing_sids.entry(*t).or_default().insert(*sid);
            }
            for t in &s.travel.open {
                open_sids.entry(*t).or_default().insert(*sid);
            }
            for c in s.reach.seeds.keys() {
                reach_sids.entry(*c).or_default().insert(*sid);
            }
            for e in &s.reach.ways {
                way_sids.entry(*e).or_default().insert(*sid);
            }
        }
        // `leave` may leave a thing's set empty
        let things: BTreeMap<T, BTreeSet<T>> = self.thing_sids.iter().filter(|(_, s)| !s.is_empty()).map(|(k, v)| (*k, v.clone())).collect();
        if edge_sids != self.edge_sids || member_sids != self.member_sids || thing_sids != things || open_sids != self.open_sids || reach_sids != self.reach_sids || way_sids != self.way_sids {
            return Err("a reverse index (edge, member, thing, open thing, reach copy or way → sync IDs) is stale".into());
        }
        Ok(())
    }

    /// The reach and keys-open graphs built from nothing over the held copies.
    #[allow(clippy::type_complexity)]
    fn graphs(&self) -> (Graph<C, T>, BTreeMap<T, BTreeSet<PartId<C, T>>>, Graph<C, T>) {
        let (mut writes, mut removals_on, mut reads) = (Graph::new(), BTreeMap::new(), Graph::new());
        for (c, h) in &self.ix.copies {
            for (i, p) in h.parts.iter().enumerate() {
                if let Kind::Write(w) = &p.kind
                    && p.chained
                {
                    let e = (w.holder, c.1);
                    if w.gives_write {
                        writes.insert(e, (*c, i));
                    }
                    if w.gives_read {
                        reads.insert(e, (*c, i));
                    }
                    if w.removal {
                        removals_on.entry(c.1).or_insert_with(BTreeSet::new).insert((*c, i));
                    }
                }
            }
        }
        (writes, removals_on, reads)
    }

    /// Registers sync ID `sid` with actor `actor` and an empty unit.
    pub fn add_sid(&mut self, sid: T, actor: T) {
        if self.sids.contains_key(&sid) {
            return;
        }
        let travel = Travel { open: BTreeSet::new(), seeds: BTreeMap::new() };
        self.sids.insert(sid, Sid { actor, unit: BTreeSet::new(), atoms: BTreeMap::new(), travel, reach: Reach::default(), closure: Closure::default() });
        let mut todo = Todo::default();
        todo.travel.insert(sid);
        self.settle(todo);
    }

    /// `t` joins S's unit.
    pub fn join(&mut self, sid: &T, t: T) {
        self.retag(sid, t, true);
    }

    /// `t` leaves S's unit.
    pub fn leave(&mut self, sid: &T, t: T) {
        self.retag(sid, t, false);
    }

    /// `t` joins S's unit (`joins`) or leaves it: copies on t become bodies, or what the bodies on
    /// t still need becomes copies; S's reach is computed again under the new unit.
    fn retag(&mut self, sid: &T, t: T, joins: bool) {
        let Some(s) = self.sids.get_mut(sid) else { return };
        let moved = if joins { s.unit.insert(t) } else { s.unit.remove(&t) };
        if !moved {
            return;
        }
        let had = s.closure.on.get(&t).is_some_and(|n| *n > 0);
        if joins {
            self.thing_sids.entry(t).or_default().insert(*sid);
        } else if let Some(x) = self.thing_sids.get_mut(&t) {
            x.remove(sid);
        }
        let mut todo = Todo::default();
        for c in self.ix.on_thing.get(&t).cloned().unwrap_or_default() {
            if joins {
                self.body_add(sid, &(c, t), &mut todo);
            } else {
                self.body_remove(sid, &(c, t), &mut todo);
            }
        }
        if had || !joins {
            todo.dirty.insert(*sid);
        }
        todo.reach.insert(*sid);
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
        self.forget_all([*c]);
    }

    /// Copies no longer held, settled once (a compaction dropping many bodies closes each sync ID
    /// it shrinks once, not once per body). A forget only shrinks: it queues closes again, never
    /// closure work, so the copies' order is free.
    pub fn forget_all(&mut self, cs: impl IntoIterator<Item = CopyId<C, T>>) {
        let mut todo = Todo::default();
        for c in cs {
            self.forget_one(&c, &mut todo);
        }
        self.settle(todo);
    }

    fn forget_one(&mut self, c: &CopyId<C, T>, todo: &mut Todo<C, T>) {
        let Some(h) = self.ix.copies.get(c).cloned() else { return };
        for sid in self.thing_sids.get(&c.1).cloned().unwrap_or_default() {
            self.body_remove(&sid, c, todo);
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
                self.chained_off(c, i, todo);
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
        // a travel seed it was leaves with it
        let holders: BTreeSet<T> = h.parts.iter().filter_map(|p| if let Kind::Write(w) = &p.kind { Some(w.holder) } else { None }).collect();
        for hd in holders {
            for sid in self.open_sids.get(&hd).cloned().unwrap_or_default() {
                if self.sids.get_mut(&sid).is_some_and(|s| s.travel.seeds.remove(c).is_some()) && !self.sids.get(&sid).is_some_and(|s| s.seeded(c)) {
                    todo.dirty.insert(sid);
                }
            }
        }
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
                // a seed of each sync ID its holder's role changes travel under
                for sid in self.open_sids.get(&w.holder).cloned().unwrap_or_default() {
                    if let Some(s) = self.sids.get_mut(&sid)
                        && !s.travel.seeds.contains_key(c)
                    {
                        s.travel.seeds.insert(*c, Reason::Travels(w.holder));
                        todo.push(&sid, Item::Copy(*c, Reason::Travels(w.holder)));
                    }
                }
                if w.gives_read && self.ix.reads.insert(e, (*c, i)) {
                    self.read_edge(e, todo);
                }
                if w.gives_write {
                    if self.ix.writes.insert(e, (*c, i)) {
                        self.write_edge(e, todo);
                    } else {
                        // the edge is a way already: the part goes where the edge does
                        for sid in self.way_sids.get(&e).cloned().unwrap_or_default() {
                            self.reach_add(&sid, vec![*c], vec![], Reason::Reach(e), todo);
                        }
                    }
                }
                if w.removal {
                    self.ix.removals_on.entry(c.1).or_default().insert((*c, i));
                    self.removal_on(c, todo);
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
                    // a travel seed stays while another chained part names a travelling holder
                    for sid in self.open_sids.get(&w.holder).cloned().unwrap_or_default() {
                        let Some(s) = self.sids.get(&sid) else { continue };
                        let other = self.ix.copies.get(c).and_then(|h| h.parts.iter().enumerate().find_map(|(j, q)| match &q.kind {
                            Kind::Write(x) if j != i && q.chained && s.travel.open.contains(&x.holder) => Some(x.holder),
                            _ => None,
                        }));
                        if let Some(s) = self.sids.get_mut(&sid) {
                            match other {
                                Some(h) => {
                                    s.travel.seeds.insert(*c, Reason::Travels(h));
                                }
                                None => {
                                    if s.travel.seeds.remove(c).is_some() && !s.seeded(c) {
                                        todo.dirty.insert(sid);
                                    }
                                }
                            }
                        }
                    }
                }
                // a shrink of a graph: the sync IDs it can move compute theirs again
                if w.gives_read && self.ix.reads.remove(&e, &(*c, i)) {
                    let (a, b) = (self.open_sids.get(&e.0), self.open_sids.get(&e.1));
                    if let (Some(a), Some(b)) = (a, b) {
                        todo.travel.extend(a.intersection(b).copied());
                    }
                }
                if w.gives_write || w.removal {
                    todo.reach.extend(self.reach_sids.get(c).into_iter().flatten().copied());
                }
                if w.gives_write && self.ix.writes.remove(&e, &(*c, i)) {
                    todo.reach.extend(self.way_sids.get(&e).into_iter().flatten().copied());
                }
                if w.removal {
                    remove_from(&mut self.ix.removals_on, &c.1, &(*c, i));
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

    // ---- keys-open travel ----

    /// The holders whose role changes travel under a sync ID with actor `actor`, and the chained
    /// writes naming them, from nothing.
    fn travel_of(&self, actor: T, counts: &mut Counts) -> Travel<C, T> {
        let open = if self.cfg.keys_open { bfs([actor], true, |x| self.ix.reads.next(true, x), &mut counts.opened).0 } else { BTreeSet::from([actor]) };
        let mut seeds = BTreeMap::new();
        for h in &open {
            for c in self.ix.by_holder.get(h).into_iter().flatten() {
                counts.seeds += 1;
                seeds.entry(*c).or_insert(Reason::Travels(*h));
            }
        }
        Travel { open, seeds }
    }

    /// A new chained edge giving read: each sync ID whose open things hold its holder opens what
    /// its target leads to, and takes the writes naming each thing it opens.
    fn read_edge(&mut self, e: Edge<T>, todo: &mut Todo<C, T>) {
        if !self.cfg.keys_open {
            return;
        }
        for sid in self.open_sids.get(&e.0).cloned().unwrap_or_default() {
            let Some(s) = self.sids.get(&sid) else { continue };
            if s.travel.open.contains(&e.1) {
                continue;
            }
            let open = &s.travel.open;
            let (new, _) = bfs([e.1], true, |x| self.ix.reads.next(true, x).filter(|y| !open.contains(y)), &mut self.counts.opened);
            for t in new {
                self.open_sids.entry(t).or_default().insert(sid);
                let writes = self.ix.by_holder.get(&t).cloned().unwrap_or_default();
                let Some(s) = self.sids.get_mut(&sid) else { continue };
                s.travel.open.insert(t);
                for c in writes {
                    if let std::collections::btree_map::Entry::Vacant(v) = s.travel.seeds.entry(c) {
                        v.insert(Reason::Travels(t));
                        todo.push(&sid, Item::Copy(c, Reason::Travels(t)));
                    }
                }
            }
        }
    }

    // ---- reach ----

    /// S's reach from nothing (draft §4 Evidence of a sync ID, (A3)): each chained removal on a
    /// thing t outside `unit` from which chained write grants lead into it, and each chained write
    /// grant on an edge of such a way (a way from a removal's target into the unit, through any
    /// things); the seeds on things outside the unit. Walks the things leading into the unit and
    /// their edges once: O(the things that can write the unit, and their write grants).
    fn reach_of(&self, unit: &BTreeSet<T>, counts: &mut Counts) -> Reach<C, T> {
        if !self.cfg.reach || self.ix.removals_on.is_empty() {
            return Reach::default();
        }
        let g = &self.ix.writes;
        let (back, edges) = bfs(unit.iter().copied(), false, |x| g.next(false, x), &mut counts.reach);
        let targets: Vec<T> = back.iter().filter(|t| !unit.contains(t) && self.ix.removals_on.contains_key(t)).copied().collect();
        if targets.is_empty() {
            return Reach::default();
        }
        // the edges walked are those into things leading into the unit: from the targets along
        // them, every edge walked is a way
        let fwd = adjacency(&edges, true);
        let (_, ways) = bfs(targets.iter().copied(), true, |x| within(&fwd, x), &mut counts.reach);
        let mut out = Reach::default();
        self.emit(unit, &targets, &ways, &mut out, counts);
        out
    }

    /// Adds to `out` the removals on `targets` and the write grants on `ways` (seeds on things
    /// outside `unit`), and the ways.
    fn emit(&self, unit: &BTreeSet<T>, targets: &[T], ways: &[Edge<T>], out: &mut Reach<C, T>, counts: &mut Counts) {
        for t in targets {
            for (c, _) in self.ix.removals_on.get(t).into_iter().flatten() {
                counts.reach_seeds += 1;
                out.seeds.entry(*c).or_insert(Reason::Removal);
            }
        }
        for e in ways {
            counts.reach_seeds += 1;
            out.ways.insert(*e);
            if unit.contains(&e.1) {
                continue;
            }
            for (c, _) in self.ix.writes.parts.get(e).into_iter().flatten() {
                counts.reach_seeds += 1;
                out.seeds.entry(*c).or_insert(Reason::Reach(*e));
            }
        }
    }

    /// The sync IDs whose units hold a thing of `things`, each with those things.
    fn units_among(&self, things: &BTreeSet<T>) -> BTreeMap<T, Vec<T>> {
        let mut out: BTreeMap<T, Vec<T>> = BTreeMap::new();
        for x in things {
            for sid in self.thing_sids.get(x).into_iter().flatten() {
                out.entry(*sid).or_default().push(*x);
            }
        }
        out
    }

    /// A chained removal `c` arrived on thing t = `c.1`: each sync ID whose unit t's write grants
    /// lead into (t outside it) takes it with the ways from t. Walks what t leads to once, then per
    /// such sync ID only the ways into it: O(what t can write + the seeds it gives), never the
    /// other sync IDs.
    fn removal_on(&mut self, c: &CopyId<C, T>, todo: &mut Todo<C, T>) {
        if !self.cfg.reach {
            return;
        }
        let t = c.1;
        let mut n = 0;
        let g = &self.ix.writes;
        let (below, edges) = bfs([t], true, |x| g.next(true, x), &mut n);
        let back = adjacency(&edges, false);
        let mut adds = vec![];
        for (sid, starts) in self.units_among(&below) {
            let Some(s) = self.sids.get(&sid) else { continue };
            if s.unit.contains(&t) {
                continue;
            }
            let (_, ways) = bfs(starts, false, |x| within(&back, x), &mut n);
            let mut out = Reach::default();
            let mut counts = Counts::default();
            self.emit(&s.unit, &[t], &ways, &mut out, &mut counts);
            self.counts.reach_seeds += counts.reach_seeds;
            adds.push((sid, out));
        }
        self.counts.reach += n;
        for (sid, out) in adds {
            self.reach_merge(&sid, out, todo);
        }
    }

    /// A new chained edge (a, b) giving write: each sync ID whose unit b leads into takes the
    /// removals on things leading to a (outside its unit) with the ways from them through (a, b).
    /// Walks what leads to a and, where a removal is among it, what b leads to: O(those, and the
    /// seeds they give: removals above × sync IDs below).
    fn write_edge(&mut self, e: Edge<T>, todo: &mut Todo<C, T>) {
        if !self.cfg.reach || self.ix.removals_on.is_empty() {
            return;
        }
        let (a, b) = e;
        let mut n = 0;
        let g = &self.ix.writes;
        let (above, ea) = bfs([a], false, |x| g.next(false, x), &mut n);
        let targets: Vec<T> = above.iter().filter(|t| self.ix.removals_on.contains_key(t)).copied().collect();
        if targets.is_empty() {
            self.counts.reach += n;
            return;
        }
        let (below, eb) = bfs([b], true, |x| g.next(true, x), &mut n);
        let (fa, bb) = (adjacency(&ea, true), adjacency(&eb, false));
        let mut shared: Option<Vec<Edge<T>>> = None;
        let mut adds = vec![];
        for (sid, starts) in self.units_among(&below) {
            let Some(s) = self.sids.get(&sid) else { continue };
            let ts: Vec<T> = targets.iter().filter(|t| !s.unit.contains(t)).copied().collect();
            if ts.is_empty() {
                continue;
            }
            // the ways above (a, b): from the targets outside the unit to a
            let above_ways = if ts.len() == targets.len() {
                shared.get_or_insert_with(|| bfs(targets.iter().copied(), true, |x| within(&fa, x), &mut n).1).clone()
            } else {
                bfs(ts.iter().copied(), true, |x| within(&fa, x), &mut n).1
            };
            let (_, mut ways) = bfs(starts, false, |x| within(&bb, x), &mut n);
            ways.extend(above_ways);
            ways.push(e);
            let mut out = Reach::default();
            let mut counts = Counts::default();
            self.emit(&s.unit, &ts, &ways, &mut out, &mut counts);
            self.counts.reach_seeds += counts.reach_seeds;
            adds.push((sid, out));
        }
        self.counts.reach += n;
        for (sid, out) in adds {
            self.reach_merge(&sid, out, todo);
        }
    }

    /// Adds copies (with `why`) and ways to S's reach.
    fn reach_add(&mut self, sid: &T, cs: Vec<CopyId<C, T>>, ways: Vec<Edge<T>>, why: Reason<C, T>, todo: &mut Todo<C, T>) {
        let Some(s) = self.sids.get(sid) else { return };
        let mut out = Reach::default();
        for c in cs {
            if !s.unit.contains(&c.1) {
                self.counts.reach_seeds += 1;
                out.seeds.insert(c, why);
            }
        }
        out.ways.extend(ways);
        self.reach_merge(sid, out, todo);
    }

    /// Merges `add` into S's reach; what is new joins the closure.
    fn reach_merge(&mut self, sid: &T, add: Reach<C, T>, todo: &mut Todo<C, T>) {
        let Some(s) = self.sids.get_mut(sid) else { return };
        for e in add.ways {
            if s.reach.ways.insert(e) {
                self.way_sids.entry(e).or_default().insert(*sid);
            }
        }
        for (c, r) in add.seeds {
            if let std::collections::btree_map::Entry::Vacant(v) = s.reach.seeds.entry(c) {
                v.insert(r);
                self.reach_sids.entry(c).or_default().insert(*sid);
                todo.push(sid, Item::Copy(c, r));
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
        let parts: Vec<PartId<C, T>> = self.ix.resting.get(e).map(|r| r.range((Bound::Excluded(new), hi)).flat_map(|(_, s)| s.iter().copied()).collect()).unwrap_or_default();
        for (c, i) in parts {
            self.recheck(&c, i, todo);
        }
    }

    /// The first chained grant on `e` moved later or went, from `old` to `new`: the parts resting
    /// on `e` ordered after `old` and not after `new` are no longer joined.
    fn unjoin(&mut self, e: &Edge<T>, old: Option<K>, new: Option<K>, todo: &mut Todo<C, T>) {
        let Some(old) = old else { return };
        let hi = new.map_or(Bound::Unbounded, Bound::Included);
        let parts: Vec<PartId<C, T>> = self.ix.resting.get(e).map(|r| r.range((Bound::Excluded(old), hi)).flat_map(|(_, s)| s.iter().copied()).collect()).unwrap_or_default();
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

    // ---- settling ----

    fn settle(&mut self, mut todo: Todo<C, T>) {
        // seeds computed again from nothing where a change could shrink them
        for sid in std::mem::take(&mut todo.travel) {
            let Some(s) = self.sids.get(&sid) else { continue };
            let mut counts = Counts::default();
            let new = self.travel_of(s.actor, &mut counts);
            self.counts.opened += counts.opened;
            self.counts.seeds += counts.seeds;
            let old = s.travel.clone();
            for t in old.open.difference(&new.open) {
                remove_from(&mut self.open_sids, t, &sid);
            }
            for t in new.open.difference(&old.open) {
                self.open_sids.entry(*t).or_default().insert(sid);
            }
            self.reseed(&sid, &old.seeds, &new.seeds, &mut todo, true);
            if let Some(s) = self.sids.get_mut(&sid) {
                s.travel = new;
            }
        }
        for sid in std::mem::take(&mut todo.reach) {
            let Some(s) = self.sids.get(&sid) else { continue };
            let mut counts = Counts::default();
            let new = self.reach_of(&s.unit, &mut counts);
            self.counts.reach += counts.reach;
            self.counts.reach_seeds += counts.reach_seeds;
            let old = s.reach.clone();
            for c in old.seeds.keys().filter(|c| !new.seeds.contains_key(c)) {
                remove_from(&mut self.reach_sids, c, &sid);
            }
            for c in new.seeds.keys().filter(|c| !old.seeds.contains_key(c)) {
                self.reach_sids.entry(*c).or_default().insert(sid);
            }
            for e in old.ways.difference(&new.ways) {
                remove_from(&mut self.way_sids, e, &sid);
            }
            for e in new.ways.difference(&old.ways) {
                self.way_sids.entry(*e).or_default().insert(sid);
            }
            self.reseed(&sid, &old.seeds, &new.seeds, &mut todo, false);
            if let Some(s) = self.sids.get_mut(&sid) {
                s.reach = new;
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

    /// One kind of S's seeds (`travel`, else reach) moves from `old` to `new`: a seed lost from
    /// both closes S again, a new one joins its closure.
    fn reseed(&self, sid: &T, old: &Required<C, T>, new: &Required<C, T>, todo: &mut Todo<C, T>, travel: bool) {
        let Some(s) = self.sids.get(sid) else { return };
        let other = if travel { &s.reach.seeds } else { &s.travel.seeds };
        if old.keys().any(|c| !new.contains_key(c) && !other.contains_key(c)) {
            todo.dirty.insert(*sid);
        }
        for (c, r) in new {
            if !old.contains_key(c) {
                todo.push(sid, Item::Copy(*c, *r));
            }
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
        work.extend(s.seeds().map(|(c, r)| Item::Copy(*c, *r)));
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
