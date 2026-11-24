//! The evidence a sync ID requires (notes/evidence-derivation.md; spec/permissions.md §4 Evidence
//! of a commit, Evidence of a sync ID, Role changes travel). The engine keeps one over its held
//! set (`kept`), which `sync/certified.rs` reads.
//!
//! A function of the copies (commit, thing) a node holds and of each sync ID's unit: the least set
//! the closure rules give over them. Changes come in by call (`add`, `forget`, `open_path`, `join`,
//! `leave`, `add_sid`, `remove_sid`, `add_record`, `remove_record`); each extends the closure from what it adds, or closes again from the sync ID's seeds
//! where it can shrink it. `from_scratch` is the same closure from nothing. Generic over the thing
//! (`T`), commit (`C`) and step (`S`: step IDs and their keys) types so it runs over held-model's
//! worlds as over the engine's.
//!
//! The closure (E1, notes/a2-spec/README.md Open 2): a member brings every held edge write on each
//! edge of its stated paths and on each edge it writes, whatever their validity or order, and the
//! `sync.0` writes recording the steps that place the delete keys it lists. **Keys-open travel**
//! (`Config::keys_open`) is a graph over things, kept as an index so a change reaches only the sync
//! IDs it can move: edges of held writes giving read, and record edges (`add_record`, standing
//! while the record is held), from a sync ID's actor to the holders whose role changes travel under it.

use osis_base::memo::Stamps;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::hash::Hash;

pub mod held;
pub(crate) mod kept;

/// An edge: (holder, target). Its holder is a thing (`H` = `T`) or, where the derivation reads key
/// grants, a key (`Holds`).
pub type Edge<T, H = T> = (H, T);

/// A grant's holder as the derivation takes it (spec/permissions.md §1): a thing, or a key, which
/// holds no read and is no sync ID's actor, so keys-open travel and travelling holders are things.
pub trait Holds<T>: Ord + Copy + Debug + Hash + From<T> {
    /// The thing it is, where it is one.
    fn thing(&self) -> Option<T>;
}

impl<T: Ord + Copy + Debug + Hash> Holds<T> for T {
    fn thing(&self) -> Option<T> {
        Some(*self)
    }
}
/// A copy: a commit's parts on one thing, (commit ID, thing).
pub type CopyId<C, T> = (C, T);
/// Held copies with their parts.
pub type HeldCopies<C, T, S, H = T> = BTreeMap<CopyId<C, T>, Vec<Part<T, S, H>>>;
/// What a body brings: its parts' path edges and the delete keys it lists.
type BodyAtoms<T, S, H> = (Vec<Edge<T, H>>, Vec<Del<T, S>>);

/// A sync ID's evidence: each copy with the reason it is in it.
pub type Required<C, T, S, H = T> = BTreeMap<CopyId<C, T>, Reason<T, S, H>>;

/// An edge write's facts (its edge is (holder, the copy's thing)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Write<H> {
    pub holder: H,
    /// (keys-open travel) It gives read or above (any `until`) and is no self-removal: a step by
    /// which keys open.
    pub gives_read: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind<H> {
    /// A part with no edge write: content, a purge request, a compaction snapshot, a `sync.0` write.
    Content,
    Write(Write<H>),
}

/// The level of a checked delete key (spec/crypto.md §7 Levels): a step's delete key (1) or its
/// write key (3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Admin,
    Writer,
}

/// A delete key a part lists at level 1 or 3 for its thing's delete base (spec/crypto.md §7 Header
/// list).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Del<T, S> {
    pub base: T,
    pub level: Level,
    pub key: S,
}

/// A step a `sync.0` part records on its thing (spec/sync-ids.md §2): its ID, its parent's, and
/// the keys it bears at levels 1 and 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step<S> {
    pub id: S,
    pub prev: Option<S>,
    pub delete: S,
    pub write: S,
}

impl<S: Copy> Step<S> {
    fn key(&self, l: Level) -> S {
        match l {
            Level::Admin => self.delete,
            Level::Writer => self.write,
        }
    }
}

/// One part of a held copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part<T, S, H = T> {
    pub kind: Kind<H>,
    /// The edges of the path its commit states for the thing, its key hop first; `None` while
    /// that path is not known here (a split entry that has not opened): it brings none.
    pub hops: Option<Vec<Edge<T, H>>>,
    /// The delete keys it lists at levels 1 and 3.
    pub dels: Vec<Del<T, S>>,
    /// The steps it records on its thing (a `sync.0` part).
    pub steps: Vec<Step<S>>,
}

impl<T, S, H> Part<T, S, H> {
    /// A part with no delete keys and no steps.
    pub fn new(kind: Kind<H>, hops: Option<Vec<Edge<T, H>>>) -> Self {
        Part { kind, hops, dels: vec![], steps: vec![] }
    }
}

/// Why a copy is in a sync ID's evidence (the first reason found).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reason<T, S, H = T> {
    /// An edge write on an edge the set uses.
    Edge(Edge<T, H>),
    /// A write naming this holder, whose role changes travel under the sync ID: its actor, or
    /// (`keys_open`) a thing the actor's keys open (Role changes travel).
    Travels(T),
    /// It records this step of the base's sync ID, on the path placing a listed delete key.
    Step(T, S),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    /// Role changes travel's keys-open half: a write naming a holder the actor holds read or above
    /// on, through held grants at any time, is a seed (held-model `Rule::keys_open`). Off: only
    /// writes naming the actor.
    pub keys_open: bool,
}

/// Work done, by kind (count tests: notes/evidence-derivation.md, Incremental).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Atom counts moved (a body's edges and delete keys in a sync ID).
    pub atoms: usize,
    /// Edges a closure took in.
    pub edges: usize,
    /// Copies a closure looked at.
    pub visits: usize,
    /// (keys-open) Things and edges a keys-open computation walked.
    pub opened: usize,
    /// Closures computed again from seeds.
    pub closes: usize,
    /// Bodies read (taken in or out of a sync ID).
    pub bodies: usize,
    /// Writes naming a travelling holder a seed computation from nothing read.
    pub seeds: usize,
    /// Steps a closure walked placing a delete key.
    pub steps: usize,
}

impl std::ops::Sub for Counts {
    type Output = Counts;
    fn sub(self, b: Counts) -> Counts {
        let d = |x: usize, y: usize| x.saturating_sub(y);
        Counts {
            atoms: d(self.atoms, b.atoms),
            edges: d(self.edges, b.edges),
            visits: d(self.visits, b.visits),
            opened: d(self.opened, b.opened),
            closes: d(self.closes, b.closes),
            bodies: d(self.bodies, b.bodies),
            seeds: d(self.seeds, b.seeds),
            steps: d(self.steps, b.steps),
        }
    }
}

/// A part of a held copy: (copy, part index).
type PartId<C, T> = (CopyId<C, T>, usize);

/// A graph over things: per edge the parts setting it, the record edges (standing with no part),
/// and the adjacency holder to target.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Graph<C, T> {
    parts: BTreeMap<Edge<T>, BTreeSet<PartId<C, T>>>,
    records: BTreeSet<Edge<T>>,
    out: BTreeMap<T, BTreeSet<T>>,
}

impl<C: Ord + Copy, T: Ord + Copy> Graph<C, T> {
    fn new() -> Self {
        Graph { parts: BTreeMap::new(), records: BTreeSet::new(), out: BTreeMap::new() }
    }
    fn has(&self, e: &Edge<T>) -> bool {
        self.records.contains(e) || self.parts.contains_key(e)
    }
    /// True when the edge is new.
    fn insert(&mut self, e: Edge<T>, p: PartId<C, T>) -> bool {
        let new = !self.has(&e);
        self.parts.entry(e).or_default().insert(p);
        if new {
            self.out.entry(e.0).or_default().insert(e.1);
        }
        new
    }
    /// A record edge; true when the edge is new.
    fn insert_record(&mut self, e: Edge<T>) -> bool {
        let new = !self.has(&e);
        self.records.insert(e);
        if new {
            self.out.entry(e.0).or_default().insert(e.1);
        }
        new
    }
    /// A record edge held no more; true when the edge is gone.
    fn remove_record(&mut self, e: &Edge<T>) -> bool {
        if !self.records.remove(e) || self.parts.contains_key(e) {
            return false;
        }
        remove_from(&mut self.out, &e.0, &e.1);
        true
    }
    /// True when the edge is gone.
    fn remove(&mut self, e: &Edge<T>, p: &PartId<C, T>) -> bool {
        let Some(s) = self.parts.get_mut(e) else { return false };
        if !s.remove(p) || !s.is_empty() {
            return false;
        }
        self.parts.remove(e);
        if self.records.contains(e) {
            return false;
        }
        remove_from(&mut self.out, &e.0, &e.1);
        true
    }
    fn next(&self, x: T) -> impl Iterator<Item = T> + '_ {
        self.out.get(&x).into_iter().flatten().copied()
    }
}

/// A step held on a base: the step and the copies recording it.
#[derive(Clone, Debug)]
struct HeldStep<C, S> {
    step: Step<S>,
    by: BTreeSet<C>,
}

/// The held copies and what the closure looks them up by.
#[derive(Clone, Debug)]
struct Ix<C, T, S, H> {
    copies: HeldCopies<C, T, S, H>,
    on_thing: BTreeMap<T, BTreeSet<C>>,
    /// Copies with an edge write on the edge.
    on_edge: BTreeMap<Edge<T, H>, BTreeSet<CopyId<C, T>>>,
    /// Copies with an edge write naming the holder.
    by_holder: BTreeMap<H, BTreeSet<CopyId<C, T>>>,
    /// Record edges (each a mint admin's edge on the thing it minted).
    records: BTreeSet<Edge<T>>,
    /// (keys-open travel) Parts giving read, by edge, and the record edges.
    reads: Graph<C, T>,
    /// Steps recorded per (base, step ID).
    steps: BTreeMap<(T, S), HeldStep<C, S>>,
    /// Step IDs per (base, level, key) they bear.
    bearing: BTreeMap<Del<T, S>, BTreeSet<S>>,
    /// The stamps of what a closure looks up (`Row`), and of each sync ID's closure: a derived
    /// value that read the derivation moves with the rows it read (`osis_base::memo`).
    stamps: Stamps,
}

/// What a reader of the derivation depends on, as its stamps name it: one closure lookup (a
/// copy's parts, the copies on an edge, the steps bearing a key, a held step) or one sync ID's
/// closure (`required`, `edges`).
#[derive(Hash)]
enum Row<'a, C, T, S, H> {
    Copy(&'a CopyId<C, T>),
    Edge(&'a Edge<T, H>),
    Bearing(&'a Del<T, S>),
    Step(&'a (T, S)),
    Sid(&'a T),
}

impl<C: Hash, T: Hash, S: Hash, H: Hash> Ix<C, T, S, H> {
    fn read(&self, r: Row<'_, C, T, S, H>) {
        self.stamps.read(&r);
    }
    fn wrote(&self, r: Row<'_, C, T, S, H>) {
        self.stamps.wrote(&r, true);
    }
}

/// A sync ID's closure over its seeds.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Closure<C, T, S, H> {
    members: Required<C, T, S, H>,
    edges: BTreeSet<Edge<T, H>>,
    dels: BTreeSet<Del<T, S>>,
}

impl<C, T, S, H> Default for Closure<C, T, S, H> {
    fn default() -> Self {
        Closure { members: BTreeMap::new(), edges: BTreeSet::new(), dels: BTreeSet::new() }
    }
}

/// The holders whose role changes travel under a sync ID, and the writes naming them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Travel<C, T, S, H> {
    /// The actor and (`keys_open`) what it holds read or above on through held grants.
    open: BTreeSet<T>,
    /// Writes naming a holder in `open`.
    seeds: Required<C, T, S, H>,
}

/// What the bodies of a sync ID bring, each with the number of bodies bringing it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Atoms<T, S, H> {
    edges: BTreeMap<Edge<T, H>, usize>,
    dels: BTreeMap<Del<T, S>, usize>,
}

impl<T, S, H> Default for Atoms<T, S, H> {
    fn default() -> Self {
        Atoms { edges: BTreeMap::new(), dels: BTreeMap::new() }
    }
}

#[derive(Clone, Debug)]
struct Sid<C, T, S, H> {
    actor: T,
    unit: BTreeSet<T>,
    atoms: Atoms<T, S, H>,
    travel: Travel<C, T, S, H>,
    closure: Closure<C, T, S, H>,
}

enum Item<C, T, S, H> {
    Edge(Edge<T, H>),
    Del(Del<T, S>),
    Copy(CopyId<C, T>, Reason<T, S, H>),
}

/// What an update leaves to do: closures to extend, sync IDs to close again, travel to compute
/// again from nothing.
struct Todo<C, T, S, H> {
    work: BTreeMap<T, Vec<Item<C, T, S, H>>>,
    dirty: BTreeSet<T>,
    travel: BTreeSet<T>,
}

impl<C, T, S, H> Default for Todo<C, T, S, H> {
    fn default() -> Self {
        Todo { work: BTreeMap::new(), dirty: BTreeSet::new(), travel: BTreeSet::new() }
    }
}

impl<C, T: Ord + Clone, S, H> Todo<C, T, S, H> {
    fn push(&mut self, sid: &T, item: Item<C, T, S, H>) {
        self.work.entry(sid.clone()).or_default().push(item);
    }
}

/// The evidence of every sync ID registered, over one node's held copies.
#[derive(Clone, Debug)]
pub struct Evidence<C, T, S, H = T> {
    cfg: Config,
    ix: Ix<C, T, S, H>,
    sids: BTreeMap<T, Sid<C, T, S, H>>,
    edge_sids: BTreeMap<Edge<T, H>, BTreeSet<T>>,
    member_sids: BTreeMap<CopyId<C, T>, BTreeSet<T>>,
    thing_sids: BTreeMap<T, BTreeSet<T>>,
    /// Thing → sync IDs whose `open` holds it.
    open_sids: BTreeMap<T, BTreeSet<T>>,
    /// Base → sync IDs whose closure places a delete key of it.
    base_sids: BTreeMap<T, BTreeSet<T>>,
    counts: Counts,
}

/// Breadth-first from `from` (included) by `next`: the things reached. Each thing and edge walked
/// counts one in `n`.
fn bfs<T: Ord + Copy, I: IntoIterator<Item = T>>(from: impl IntoIterator<Item = T>, next: impl Fn(T) -> I, n: &mut usize) -> BTreeSet<T> {
    let mut seen = BTreeSet::new();
    let mut todo = vec![];
    for x in from {
        if seen.insert(x) {
            todo.push(x);
        }
    }
    while let Some(x) = todo.pop() {
        *n += 1;
        for y in next(x) {
            *n += 1;
            if seen.insert(y) {
                todo.push(y);
            }
        }
    }
    seen
}

/// The edges a part's edge write sets (at most one).
fn own_edge<T: Copy, S, H: Copy>(p: &Part<T, S, H>, on: T) -> Option<Edge<T, H>> {
    match p.kind {
        Kind::Write(w) => Some((w.holder, on)),
        Kind::Content => None,
    }
}

impl<C, T, S, H> Evidence<C, T, S, H>
where
    C: Ord + Copy + Debug + Hash,
    T: Ord + Copy + Debug + Hash,
    S: Ord + Copy + Debug + Hash,
    H: Holds<T>,
{
    pub fn new(cfg: Config) -> Self {
        let ix = Ix {
            copies: BTreeMap::new(),
            on_thing: BTreeMap::new(),
            on_edge: BTreeMap::new(),
            by_holder: BTreeMap::new(),
            records: BTreeSet::new(),
            reads: Graph::new(),
            steps: BTreeMap::new(),
            bearing: BTreeMap::new(),
            stamps: Stamps::named("evidence"),
        };
        Evidence { cfg, ix, sids: BTreeMap::new(), edge_sids: BTreeMap::new(), member_sids: BTreeMap::new(), thing_sids: BTreeMap::new(), open_sids: BTreeMap::new(), base_sids: BTreeMap::new(), counts: Counts::default() }
    }

    pub fn counts(&self) -> Counts {
        self.counts
    }

    /// The whole derivation is read (a read no row names).
    fn read_all(&self) {
        self.ix.stamps.read_all();
    }

    /// The copies S's evidence holds (things outside its unit), each with a reason.
    pub fn required(&self, sid: &T) -> Option<&Required<C, T, S, H>> {
        self.ix.read(Row::Sid(sid));
        self.sids.get(sid).map(|s| &s.closure.members)
    }

    /// The edges S's evidence uses.
    pub fn edges(&self, sid: &T) -> Option<&BTreeSet<Edge<T, H>>> {
        self.ix.read(Row::Sid(sid));
        self.sids.get(sid).map(|s| &s.closure.edges)
    }

    /// The edges S's bodies bring and how many bring each.
    pub fn atoms(&self, sid: &T) -> Option<&BTreeMap<Edge<T, H>, usize>> {
        self.read_all();
        self.sids.get(sid).map(|s| &s.atoms.edges)
    }

    pub fn holds(&self, c: &CopyId<C, T>) -> bool {
        self.ix.read(Row::Copy(c));
        self.ix.copies.contains_key(c)
    }

    /// S's evidence computed from nothing over the held copies (the same closure).
    pub fn from_scratch(&self, sid: &T) -> Option<Required<C, T, S, H>> {
        self.from_scratch_counted(sid).map(|r| r.0)
    }

    /// `from_scratch` with the work it did.
    pub fn from_scratch_counted(&self, sid: &T) -> Option<(Required<C, T, S, H>, Counts)> {
        self.read_all();
        let s = self.sids.get(sid)?;
        let mut counts = Counts::default();
        let atoms = self.atoms_of(&s.unit, &mut counts);
        let mut work: Vec<Item<C, T, S, H>> = atoms.edges.keys().map(|e| Item::Edge(*e)).collect();
        work.extend(atoms.dels.keys().map(|d| Item::Del(*d)));
        let travel = self.travel_of(s.actor, &mut counts);
        work.extend(travel.seeds.iter().map(|(c, r)| Item::Copy(*c, *r)));
        let mut cl = Closure::default();
        close(&self.ix, &s.unit, &mut cl, work, &mut counts);
        Some((cl.members, counts))
    }

    /// The evidence of copies `seeds` alone (spec/permissions.md §4 Evidence of a commit): the
    /// closure from what each brings (its parts' known path edges, the edges its edge writes set,
    /// the delete keys it lists), the seeds left out. What a fire, a sealed copy or an edge piece
    /// carries beside its copy.
    pub fn closure_of(&self, seeds: &BTreeSet<CopyId<C, T>>) -> Required<C, T, S, H> {
        let mut work = Vec::new();
        for c in seeds {
            self.ix.read(Row::Copy(c));
            for p in self.ix.copies.get(c).into_iter().flatten() {
                work.extend(p.hops.iter().flatten().chain(&own_edge(p, c.1)).map(|e| Item::Edge(*e)));
                work.extend(p.dels.iter().map(|d| Item::Del(*d)));
            }
        }
        let mut cl = Closure::default();
        close(&self.ix, &BTreeSet::new(), &mut cl, work, &mut Counts::default());
        cl.members.retain(|c, _| !seeds.contains(c));
        cl.members
    }

    /// What the bodies on `unit`'s things bring, from nothing.
    fn atoms_of(&self, unit: &BTreeSet<T>, counts: &mut Counts) -> Atoms<T, S, H> {
        let mut atoms = Atoms::default();
        for t in unit {
            for c in self.ix.on_thing.get(t).into_iter().flatten() {
                counts.bodies += 1;
                let (edges, dels) = self.body_atoms(&(*c, *t));
                for e in edges {
                    *atoms.edges.entry(e).or_insert(0) += 1;
                }
                for d in dels {
                    *atoms.dels.entry(d).or_insert(0) += 1;
                }
            }
        }
        atoms
    }

    /// Checks the incremental state against itself built from nothing (tests, at teardown or every
    /// step): per sync ID its evidence, atoms and travelling holders equal from scratch, the
    /// keys-open graph holds exactly the held parts giving read and the records, and the reverse
    /// indexes (edge, member, thing, open thing, base → sync IDs) hold exactly what the sync IDs do.
    pub fn check(&self) -> Result<(), String> {
        self.read_all();
        let mut reads = Graph::new();
        for e in &self.ix.records {
            reads.insert_record(*e);
        }
        for (c, parts) in &self.ix.copies {
            for (i, p) in parts.iter().enumerate() {
                if let Kind::Write(w) = p.kind
                    && w.gives_read
                    && let Some(h) = w.holder.thing()
                {
                    reads.insert((h, c.1), (*c, i));
                }
            }
        }
        if reads != self.ix.reads {
            return Err("the keys-open graph does not hold exactly the parts giving read and the records".into());
        }
        let mut edge_sids: BTreeMap<Edge<T, H>, BTreeSet<T>> = BTreeMap::new();
        let mut member_sids: BTreeMap<CopyId<C, T>, BTreeSet<T>> = BTreeMap::new();
        let mut thing_sids: BTreeMap<T, BTreeSet<T>> = BTreeMap::new();
        let mut open_sids: BTreeMap<T, BTreeSet<T>> = BTreeMap::new();
        let mut base_sids: BTreeMap<T, BTreeSet<T>> = BTreeMap::new();
        for (sid, s) in &self.sids {
            // the same copies (each with the first reason found, which may differ)
            let scratch = self.from_scratch(sid).unwrap_or_default();
            if scratch.keys().ne(s.closure.members.keys()) {
                return Err(format!("sid {sid:?}: incremental {:?} from scratch {scratch:?}", s.closure.members));
            }
            let atoms = self.atoms_of(&s.unit, &mut Counts::default());
            if atoms != s.atoms {
                return Err(format!("sid {sid:?}: atoms {:?}, counted {atoms:?}", s.atoms));
            }
            let travel = self.travel_of(s.actor, &mut Counts::default());
            if travel.open != s.travel.open || travel.seeds.keys().ne(s.travel.seeds.keys()) {
                return Err(format!("sid {sid:?}: travel {:?}, computed {travel:?}", s.travel));
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
            for d in &s.closure.dels {
                base_sids.entry(d.base).or_default().insert(*sid);
            }
        }
        // `leave` may leave a thing's set empty
        let things: BTreeMap<T, BTreeSet<T>> = self.thing_sids.iter().filter(|(_, s)| !s.is_empty()).map(|(k, v)| (*k, v.clone())).collect();
        if edge_sids != self.edge_sids || member_sids != self.member_sids || thing_sids != things || open_sids != self.open_sids || base_sids != self.base_sids {
            return Err("a reverse index (edge, member, thing, open thing, base → sync IDs) is stale".into());
        }
        Ok(())
    }

    /// Registers sync ID `sid` with actor `actor` and an empty unit.
    pub fn add_sid(&mut self, sid: T, actor: T) {
        if self.sids.contains_key(&sid) {
            return;
        }
        self.ix.stamps.moved();
        self.ix.wrote(Row::Sid(&sid));
        let travel = Travel { open: BTreeSet::new(), seeds: BTreeMap::new() };
        self.sids.insert(sid, Sid { actor, unit: BTreeSet::new(), atoms: Atoms::default(), travel, closure: Closure::default() });
        let mut todo = Todo::default();
        todo.travel.insert(sid);
        self.settle(todo);
    }

    /// Sync ID `sid` registered no more: its unit, travel and closure go, in proportion to them.
    pub fn remove_sid(&mut self, sid: &T) {
        let Some(s) = self.sids.remove(sid) else { return };
        self.ix.stamps.moved();
        self.ix.wrote(Row::Sid(sid));
        for e in &s.closure.edges {
            remove_from(&mut self.edge_sids, e, sid);
        }
        for m in s.closure.members.keys() {
            remove_from(&mut self.member_sids, m, sid);
        }
        for b in s.closure.dels.iter().map(|d| d.base).collect::<BTreeSet<_>>() {
            remove_from(&mut self.base_sids, &b, sid);
        }
        for t in &s.unit {
            remove_from(&mut self.thing_sids, t, sid);
        }
        for t in &s.travel.open {
            remove_from(&mut self.open_sids, t, sid);
        }
    }

    /// The sync IDs registered.
    pub fn sids(&self) -> impl Iterator<Item = T> + '_ {
        self.read_all();
        self.sids.keys().copied()
    }

    /// The held copies with their parts.
    pub fn copies(&self) -> &HeldCopies<C, T, S, H> {
        self.read_all();
        &self.ix.copies
    }

    /// The record edges held.
    pub fn records(&self) -> &BTreeSet<Edge<T>> {
        self.read_all();
        &self.ix.records
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
    /// t still need becomes copies.
    fn retag(&mut self, sid: &T, t: T, joins: bool) {
        let Some(s) = self.sids.get_mut(sid) else { return };
        let moved = if joins { s.unit.insert(t) } else { s.unit.remove(&t) };
        if !moved {
            return;
        }
        self.ix.stamps.moved();
        let had = s.closure.members.keys().any(|c| c.1 == t);
        if joins {
            self.thing_sids.entry(t).or_default().insert(*sid);
        } else if let Some(x) = self.thing_sids.get_mut(&t) {
            x.remove(sid);
        }
        let mut todo = Todo::default();
        for c in self.ix.on_thing.get(&t).cloned().unwrap_or_default() {
            self.body_move(sid, &(c, t), joins, &mut todo);
        }
        if had || !joins {
            todo.dirty.insert(*sid);
        }
        self.settle(todo);
    }

    /// Record edge `e` (holder: the mint admin; target: the thing it minted), standing while the
    /// record is held: an edge of the keys-open graph (an admin edge, giving read).
    pub fn add_record(&mut self, e: Edge<T>) {
        if !self.ix.records.insert(e) {
            return;
        }
        self.ix.stamps.moved();
        let mut todo = Todo::default();
        if self.ix.reads.insert_record(e) {
            self.read_edge(e, &mut todo);
        }
        self.settle(todo);
    }

    /// Record edge `e` held no more (its thing's record forgotten): a shrink of the keys-open
    /// graph, so the sync IDs whose open things held both its ends compute theirs again.
    pub fn remove_record(&mut self, e: &Edge<T>) {
        if !self.ix.records.remove(e) {
            return;
        }
        self.ix.stamps.moved();
        let mut todo = Todo::default();
        if self.ix.reads.remove_record(e)
            && let (Some(a), Some(b)) = (self.open_sids.get(&e.0), self.open_sids.get(&e.1))
        {
            todo.travel.extend(a.intersection(b).copied());
        }
        self.settle(todo);
    }

    /// A copy held from now on (a copy already held is taken again with these facts).
    pub fn add(&mut self, c: CopyId<C, T>, parts: Vec<Part<T, S, H>>) {
        if self.ix.copies.contains_key(&c) {
            self.forget(&c);
        }
        let mut todo = Todo::default();
        self.ix.stamps.moved();
        self.ix.wrote(Row::Copy(&c));
        self.ix.on_thing.entry(c.1).or_default().insert(c.0);
        let mut steps = false;
        for (i, p) in parts.iter().enumerate() {
            for s in &p.steps {
                steps = true;
                self.ix.wrote(Row::Step(&(c.1, s.id)));
                let h = self.ix.steps.entry((c.1, s.id)).or_insert_with(|| HeldStep { step: *s, by: BTreeSet::new() });
                h.by.insert(c.0);
                for level in [Level::Admin, Level::Writer] {
                    let d = Del { base: c.1, level, key: s.key(level) };
                    self.ix.wrote(Row::Bearing(&d));
                    self.ix.bearing.entry(d).or_default().insert(s.id);
                }
            }
            let Kind::Write(w) = p.kind else { continue };
            let e = (w.holder, c.1);
            self.ix.wrote(Row::Edge(&e));
            self.ix.on_edge.entry(e).or_default().insert(c);
            self.ix.by_holder.entry(w.holder).or_default().insert(c);
            for sid in self.edge_sids.get(&e).cloned().unwrap_or_default() {
                todo.push(&sid, Item::Copy(c, Reason::Edge(e)));
            }
            // a seed of each sync ID its holder's role changes travel under (a thing's: a key
            // is no sync ID's actor and holds no read)
            let Some(holder) = w.holder.thing() else { continue };
            for sid in self.open_sids.get(&holder).cloned().unwrap_or_default() {
                if let Some(s) = self.sids.get_mut(&sid)
                    && !s.travel.seeds.contains_key(&c)
                {
                    s.travel.seeds.insert(c, Reason::Travels(holder));
                    todo.push(&sid, Item::Copy(c, Reason::Travels(holder)));
                }
            }
            if w.gives_read && self.ix.reads.insert((holder, c.1), (c, i)) {
                self.read_edge((holder, c.1), &mut todo);
            }
        }
        self.ix.copies.insert(c, parts);
        // a step new to a base may extend or join a path placing a key (rare: close again)
        if steps {
            todo.dirty.extend(self.base_sids.get(&c.1).into_iter().flatten().copied());
        }
        for sid in self.thing_sids.get(&c.1).cloned().unwrap_or_default() {
            self.body_move(&sid, &c, true, &mut todo);
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

    fn forget_one(&mut self, c: &CopyId<C, T>, todo: &mut Todo<C, T, S, H>) {
        if !self.ix.copies.contains_key(c) {
            return;
        }
        for sid in self.thing_sids.get(&c.1).cloned().unwrap_or_default() {
            self.body_move(&sid, c, false, todo);
        }
        for sid in self.member_sids.get(c).cloned().unwrap_or_default() {
            todo.dirty.insert(sid);
        }
        let parts = self.ix.copies.remove(c).unwrap_or_default();
        self.ix.stamps.moved();
        self.ix.wrote(Row::Copy(c));
        remove_from(&mut self.ix.on_thing, &c.1, &c.0);
        for (i, p) in parts.iter().enumerate() {
            for s in &p.steps {
                self.ix.wrote(Row::Step(&(c.1, s.id)));
                if let Some(h) = self.ix.steps.get_mut(&(c.1, s.id)) {
                    h.by.remove(&c.0);
                    if h.by.is_empty() {
                        self.ix.steps.remove(&(c.1, s.id));
                        for level in [Level::Admin, Level::Writer] {
                            let d = Del { base: c.1, level, key: s.key(level) };
                            self.ix.wrote(Row::Bearing(&d));
                            remove_from(&mut self.ix.bearing, &d, &s.id);
                        }
                    }
                }
                todo.dirty.extend(self.base_sids.get(&c.1).into_iter().flatten().copied());
            }
            let Kind::Write(w) = p.kind else { continue };
            let e = (w.holder, c.1);
            self.ix.wrote(Row::Edge(&e));
            remove_from(&mut self.ix.on_edge, &e, c);
            remove_from(&mut self.ix.by_holder, &w.holder, c);
            let Some(holder) = w.holder.thing() else { continue };
            // a travel seed it was leaves with it
            for sid in self.open_sids.get(&holder).cloned().unwrap_or_default() {
                if self.sids.get_mut(&sid).is_some_and(|s| s.travel.seeds.remove(c).is_some()) {
                    todo.dirty.insert(sid);
                }
            }
            // a shrink of the graph: the sync IDs it can move compute theirs again
            let e = (holder, c.1);
            if w.gives_read && self.ix.reads.remove(&e, &(*c, i)) {
                let (a, b) = (self.open_sids.get(&e.0), self.open_sids.get(&e.1));
                if let (Some(a), Some(b)) = (a, b) {
                    todo.travel.extend(a.intersection(b).copied());
                }
            }
        }
    }

    /// Part `i` of copy `c` now knows its path (its split entry opened here).
    pub fn open_path(&mut self, c: &CopyId<C, T>, i: usize, hops: Vec<Edge<T, H>>) {
        let Some(p) = self.ix.copies.get_mut(c).and_then(|ps| ps.get_mut(i)) else { return };
        if p.hops.is_some() {
            return;
        }
        p.hops = Some(hops.clone());
        self.ix.stamps.moved();
        self.ix.wrote(Row::Copy(c));
        let mut todo = Todo::default();
        for sid in self.thing_sids.get(&c.1).cloned().unwrap_or_default() {
            self.counts.bodies += 1;
            self.atoms_move(&sid, hops.iter().copied(), [].into_iter(), true, &mut todo);
        }
        for sid in self.member_sids.get(c).cloned().unwrap_or_default() {
            for e in &hops {
                todo.push(&sid, Item::Edge(*e));
            }
        }
        self.settle(todo);
    }

    // ---- keys-open travel ----

    /// The holders whose role changes travel under a sync ID with actor `actor`, and the writes
    /// naming them, from nothing.
    fn travel_of(&self, actor: T, counts: &mut Counts) -> Travel<C, T, S, H> {
        let open = if self.cfg.keys_open { bfs([actor], |x| self.ix.reads.next(x), &mut counts.opened) } else { BTreeSet::from([actor]) };
        let mut seeds = BTreeMap::new();
        for h in &open {
            for c in self.ix.by_holder.get(&H::from(*h)).into_iter().flatten() {
                counts.seeds += 1;
                seeds.entry(*c).or_insert(Reason::Travels(*h));
            }
        }
        Travel { open, seeds }
    }

    /// A new edge giving read: each sync ID whose open things hold its holder opens what its
    /// target leads to, and takes the writes naming each thing it opens.
    fn read_edge(&mut self, e: Edge<T>, todo: &mut Todo<C, T, S, H>) {
        if !self.cfg.keys_open {
            return;
        }
        for sid in self.open_sids.get(&e.0).cloned().unwrap_or_default() {
            let Some(s) = self.sids.get(&sid) else { continue };
            if s.travel.open.contains(&e.1) {
                continue;
            }
            let open = &s.travel.open;
            let new = bfs([e.1], |x| self.ix.reads.next(x).filter(|y| !open.contains(y)), &mut self.counts.opened);
            for t in new {
                self.open_sids.entry(t).or_default().insert(sid);
                let writes = self.ix.by_holder.get(&H::from(t)).cloned().unwrap_or_default();
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

    // ---- bodies ----

    /// What body `c` brings: each part's path edges where known, and the delete keys it lists.
    fn body_atoms(&self, c: &CopyId<C, T>) -> BodyAtoms<T, S, H> {
        let parts = self.ix.copies.get(c).map(Vec::as_slice).unwrap_or_default();
        let edges = parts.iter().flat_map(|p| p.hops.iter().flatten().copied()).collect();
        let dels = parts.iter().flat_map(|p| p.dels.iter().copied()).collect();
        (edges, dels)
    }

    /// Body `c` enters S (`add`) or leaves it.
    fn body_move(&mut self, sid: &T, c: &CopyId<C, T>, add: bool, todo: &mut Todo<C, T, S, H>) {
        self.counts.bodies += 1;
        let (edges, dels) = self.body_atoms(c);
        self.atoms_move(sid, edges.into_iter(), dels.into_iter(), add, todo);
    }

    fn atoms_move(&mut self, sid: &T, edges: impl Iterator<Item = Edge<T, H>>, dels: impl Iterator<Item = Del<T, S>>, add: bool, todo: &mut Todo<C, T, S, H>) {
        let Some(s) = self.sids.get_mut(sid) else { return };
        for e in edges {
            self.counts.atoms += 1;
            if count(&mut s.atoms.edges, e, add) {
                if add {
                    todo.push(sid, Item::Edge(e));
                } else {
                    todo.dirty.insert(*sid);
                }
            }
        }
        for d in dels {
            self.counts.atoms += 1;
            if count(&mut s.atoms.dels, d, add) {
                if add {
                    todo.push(sid, Item::Del(d));
                } else {
                    todo.dirty.insert(*sid);
                }
            }
        }
    }

    // ---- settling ----

    fn settle(&mut self, mut todo: Todo<C, T, S, H>) {
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
            // a seed lost closes S again, a new one joins its closure
            if old.seeds.keys().any(|c| !new.seeds.contains_key(c)) {
                todo.dirty.insert(sid);
            }
            for (c, r) in &new.seeds {
                if !old.seeds.contains_key(c) {
                    todo.push(&sid, Item::Copy(*c, *r));
                }
            }
            if let Some(s) = self.sids.get_mut(&sid) {
                s.travel = new;
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
    fn extend(&mut self, sid: &T, work: Vec<Item<C, T, S, H>>) {
        let Some(s) = self.sids.get_mut(sid) else { return };
        let added = close(&self.ix, &s.unit, &mut s.closure, work, &mut self.counts);
        if !added.edges.is_empty() || !added.members.is_empty() {
            self.ix.wrote(Row::Sid(sid));
        }
        for e in added.edges {
            self.edge_sids.entry(e).or_default().insert(*sid);
        }
        for m in added.members {
            self.member_sids.entry(m).or_default().insert(*sid);
        }
        for b in added.bases {
            self.base_sids.entry(b).or_default().insert(*sid);
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
        for b in old.dels.iter().map(|d| d.base).collect::<BTreeSet<_>>() {
            remove_from(&mut self.base_sids, &b, sid);
        }
        let Some(s) = self.sids.get(sid) else { return };
        let mut work: Vec<Item<C, T, S, H>> = s.atoms.edges.keys().map(|e| Item::Edge(*e)).collect();
        work.extend(s.atoms.dels.keys().map(|d| Item::Del(*d)));
        work.extend(s.travel.seeds.iter().map(|(c, r)| Item::Copy(*c, *r)));
        self.extend(sid, work);
        // `extend` stamped what it added: a closure that only shrank is stamped here
        if self.sids.get(sid).is_some_and(|s| s.closure != old) {
            self.ix.wrote(Row::Sid(sid));
        }
    }
}

/// Moves the count of `k` by one (`add`); true where it passed between 0 and 1.
fn count<K: Ord>(m: &mut BTreeMap<K, usize>, k: K, add: bool) -> bool {
    if add {
        let n = m.entry(k).or_insert(0);
        *n += 1;
        return *n == 1;
    }
    let Some(n) = m.get_mut(&k) else { return false };
    *n -= 1;
    if *n > 0 {
        return false;
    }
    m.remove(&k);
    true
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

/// What a closure step added: edges, members, and bases whose keys it placed.
struct Added<C, T, H> {
    edges: Vec<Edge<T, H>>,
    members: Vec<CopyId<C, T>>,
    bases: Vec<T>,
}

/// The closure step (spec/permissions.md §4 Evidence of a commit), from `work` over the held
/// copies: an edge brings every held copy with an edge write on it; a delete key brings the copies
/// recording each step from the base's genesis to a step bearing it; a copy (outside the unit)
/// brings its parts' known path edges, the edges its edge writes set and the delete keys it lists.
fn close<C, T, S, H>(ix: &Ix<C, T, S, H>, unit: &BTreeSet<T>, cl: &mut Closure<C, T, S, H>, mut work: Vec<Item<C, T, S, H>>, counts: &mut Counts) -> Added<C, T, H>
where
    C: Ord + Copy + Hash,
    T: Ord + Copy + Hash,
    S: Ord + Copy + Hash,
    H: Ord + Copy + Hash,
{
    let mut added = Added { edges: vec![], members: vec![], bases: vec![] };
    while let Some(item) = work.pop() {
        match item {
            Item::Edge(e) => {
                if !cl.edges.insert(e) {
                    continue;
                }
                counts.edges += 1;
                added.edges.push(e);
                ix.read(Row::Edge(&e));
                work.extend(ix.on_edge.get(&e).into_iter().flatten().map(|c| Item::Copy(*c, Reason::Edge(e))));
            }
            Item::Del(d) => {
                if !cl.dels.insert(d) {
                    continue;
                }
                added.bases.push(d.base);
                // each step bearing the key, up to the genesis (a step's ID commits to its parent)
                let mut walked = BTreeSet::new();
                ix.read(Row::Bearing(&d));
                let mut todo: Vec<S> = ix.bearing.get(&d).into_iter().flatten().copied().collect();
                while let Some(id) = todo.pop() {
                    ix.read(Row::Step(&(d.base, id)));
                    let Some(h) = ix.steps.get(&(d.base, id)) else { continue };
                    if !walked.insert(id) {
                        continue;
                    }
                    counts.steps += 1;
                    work.extend(h.by.iter().map(|c| Item::Copy((*c, d.base), Reason::Step(d.base, id))));
                    todo.extend(h.step.prev);
                }
            }
            Item::Copy(c, why) => {
                counts.visits += 1;
                if unit.contains(&c.1) || cl.members.contains_key(&c) {
                    continue;
                }
                ix.read(Row::Copy(&c));
                let Some(parts) = ix.copies.get(&c) else { continue };
                cl.members.insert(c, why);
                added.members.push(c);
                for p in parts {
                    work.extend(p.hops.iter().flatten().chain(&own_edge(p, c.1)).map(|e| Item::Edge(*e)));
                    work.extend(p.dels.iter().map(|d| Item::Del(*d)));
                }
            }
        }
    }
    added
}
