//! The evidence a sync ID requires (notes/evidence-derivation.md; spec/permissions.md
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
//! One seed relation is a graph over things, kept as an index so a change reaches only the sync IDs
//! it can move (notes/evidence-derivation.md, Keys-open travel): **keys-open travel**
//! (`Config::keys_open`) over chained grants giving read and record edges, from a sync ID's actor to
//! the holders whose role changes travel under it. Record edges are an input of their own
//! (`add_record`), standing for good.
//!
//! A3 (notes/a3-spec/permissions.md): a lowering's list **leaves** each sync ID requires
//! (`Config::leaves`, `leaves.rs`).

use osis_base::Role;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::ops::Bound;

mod leaves;

pub use leaves::LeafWhy;

/// An edge: (holder, target).
pub type Edge<T> = (T, T);
/// A copy: a commit's parts on one thing, (commit ID, thing).
pub type CopyId<C, T> = (C, T);

/// A sync ID's evidence: each copy with the reason it is in it.
pub type Required<C, T> = BTreeMap<CopyId<C, T>, Reason<C, T>>;

/// A part of a held copy: (copy, part index).
type PartId<C, T> = (CopyId<C, T>, usize);

/// What a part needs of one hop of its stated path, at least (spec/permissions.md §5.1 step 3, a
/// part's least need): a role (write for content, admin for an edge write, write for a finalize,
/// a may-grant grant's level on its path's hops but the last), or may-grant (a may-grant grant's
/// level on its path's last hop). A grant joins the hop for the part only giving it (notes/a2-spec
/// README.md OPEN 16: a hop granted too little joins nothing, so the part waits).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Need {
    Role(Role),
    MayGrant(Role),
}

impl Need {
    const ALL: [Need; 8] = [Need::Role(Role::Sync), Need::Role(Role::Read), Need::Role(Role::Write), Need::Role(Role::Admin), Need::MayGrant(Role::Sync), Need::MayGrant(Role::Read), Need::MayGrant(Role::Write), Need::MayGrant(Role::Admin)];
}

/// What a grant gives a hop, `until` disregarded: its role, and the level it may grant up to (its
/// role for an admin grant or one carrying the may-grant flag; None: it may grant nothing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gives {
    pub role: Role,
    pub may_grant: Option<Role>,
}

impl Gives {
    /// A grant of `role` without the may-grant flag (an admin grant may grant up to admin).
    pub fn role(role: Role) -> Gives {
        Gives { role, may_grant: (role == Role::Admin).then_some(Role::Admin) }
    }
    pub fn meets(&self, n: Need) -> bool {
        match n {
            Need::Role(l) => self.role >= l,
            Need::MayGrant(l) => self.may_grant.is_some_and(|i| i >= l),
        }
    }
}

/// One edge of a stated path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hop<T> {
    pub edge: Edge<T>,
    /// A record edge (the mint admin's): no grant joins it, none needed.
    pub record: bool,
    /// What the part needs of it.
    pub need: Need,
}

/// An edge write's facts (its edge is (holder, the copy's thing)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Write<C, T> {
    pub holder: T,
    /// It sets a role above none (no self-removal, no finalize), giving this: it can join a
    /// path's hop for a part needing no more.
    pub grant: Option<Gives>,
    /// (leaves) It gives below write at its own `ts`, and is no finalize: a self-removal and a
    /// grant of read have this shape, a demotion from admin to write has not. Such a write cuts
    /// content only where it takes write away: ordered after a held chained write on its edge
    /// giving write or above, or on a record edge (the derivation decides, from what is held).
    pub removal: bool,
    /// (leaves) It gives write or above (any `until`): what a removal on its edge takes away.
    pub gives_write: bool,
    /// (keys-open travel) It gives read or above (any `until`) and is no self-removal: a step by
    /// which keys open.
    pub gives_read: bool,
    /// The creation of the entry it resets, as its reset names it (spec/permissions.md §2).
    pub creation: Option<CopyId<C, T>>,
    /// (leaves) The things its list root holds a leaf pair for (notes/a3-spec/permissions.md §5.1
    /// Frontier): the leaf (commit ID, thing) exists for each.
    pub leaves: Vec<T>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind<C, T> {
    /// A part with no edge-class part: content, a purge request, a compaction snapshot.
    Content,
    Write(Write<C, T>),
    /// (leaves) An addendum against a lowering of `edge` listing `lists`: with `Config::leaves` a
    /// body only while it lists a held copy with a content part resting on `edge` (draft §4: an
    /// addendum is evidence of those, and leaves with the last). Otherwise as content.
    Addendum { edge: Edge<T>, lists: Vec<CopyId<C, T>> },
}

impl<C, T> Kind<C, T> {
    /// No edge-class part: what a lowering's leaf is read for (content, an addendum).
    fn content_class(&self) -> bool {
        matches!(self, Kind::Content | Kind::Addendum { .. })
    }
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
    /// A chained write naming this holder, whose role changes travel under the sync ID: its
    /// actor, or (`keys_open`) a thing the actor's keys open (Role changes travel).
    Travels(T),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    /// Role changes travel's keys-open half: a chained write naming a holder the actor holds read
    /// or above on, through chained grants at any time, is a seed (held-model `Rule::keys_open`).
    /// Off: only writes naming the actor.
    pub keys_open: bool,
    /// (A3) A lowering's list leaves are evidence (`leaves`; draft §4 the leaf bullet) and an
    /// addendum is a body only while it lists a held commit resting on its removal's edge.
    pub leaves: bool,
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
    /// (keys-open) Things and edges a keys-open computation walked.
    pub opened: usize,
    /// Closures computed again from seeds.
    pub closes: usize,
    /// Bodies read (taken in or out of a sync ID).
    pub bodies: usize,
    /// Writes naming a travelling holder a seed computation from nothing read.
    pub seeds: usize,
    /// (leaves) Lowering parts looked at for a leaf, and (a lowering, a thing) pairs whose leaf was
    /// decided.
    pub leaf_checks: usize,
    /// (leaves) Held parts `judged_by` looked at.
    pub judged: usize,
}

impl std::ops::Sub for Counts {
    type Output = Counts;
    fn sub(self, b: Counts) -> Counts {
        let d = |x: usize, y: usize| x.saturating_sub(y);
        Counts {
            atoms: d(self.atoms, b.atoms),
            edges: d(self.edges, b.edges),
            visits: d(self.visits, b.visits),
            rechecks: d(self.rechecks, b.rechecks),
            opened: d(self.opened, b.opened),
            closes: d(self.closes, b.closes),
            bodies: d(self.bodies, b.bodies),
            seeds: d(self.seeds, b.seeds),
            leaf_checks: d(self.leaf_checks, b.leaf_checks),
            judged: d(self.judged, b.judged),
        }
    }
}

#[derive(Clone, Debug)]
struct Held<C, T, K> {
    parts: Vec<Part<C, T, K>>,
    joined: Vec<bool>,
    /// A body where its thing is in a unit (`Config::leaves`: an addendum listing nothing it can
    /// keep is none).
    live: bool,
}

/// Parts by key: (copy, part index).
type ByKey<C, T, K> = BTreeMap<K, BTreeSet<PartId<C, T>>>;

/// A graph over things: per edge the chained parts setting it, the record edges (standing with no
/// part), and the adjacency holder to target.
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
    fn link(&mut self, e: Edge<T>) {
        self.out.entry(e.0).or_default().insert(e.1);
    }
    /// True when the edge is new.
    fn insert(&mut self, e: Edge<T>, p: PartId<C, T>) -> bool {
        let new = !self.has(&e);
        self.parts.entry(e).or_default().insert(p);
        if new {
            self.link(e);
        }
        new
    }
    /// A record edge; true when the edge is new.
    fn insert_record(&mut self, e: Edge<T>) -> bool {
        let new = !self.has(&e);
        self.records.insert(e);
        if new {
            self.link(e);
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

/// `Evidence::graphs`: the keys-open graph and the write keys built from nothing.
struct Graphs<C, T, K> {
    reads: Graph<C, T>,
    write_keys: BTreeMap<Edge<T>, ByKey<C, T, K>>,
}

/// The held copies and what the closure looks them up by.
#[derive(Clone, Debug)]
struct Ix<C, T, K> {
    copies: BTreeMap<CopyId<C, T>, Held<C, T, K>>,
    on_thing: BTreeMap<T, BTreeSet<C>>,
    /// Copies with a chained write on the edge.
    taken_on: BTreeMap<Edge<T>, BTreeSet<CopyId<C, T>>>,
    /// Chained grants on the edge meeting the need, by key: the first decides which parts needing
    /// it the edge joins.
    grants: BTreeMap<(Edge<T>, Need), ByKey<C, T, K>>,
    /// Parts whose known path uses the edge (no record edge) with that need, by `pos`.
    resting: BTreeMap<(Edge<T>, Need), ByKey<C, T, K>>,
    /// Copies with a chained write naming the holder.
    by_holder: BTreeMap<T, BTreeSet<CopyId<C, T>>>,
    /// Copies with a write whose reset names the copy as its entry's creation.
    resetters: BTreeMap<CopyId<C, T>, BTreeSet<CopyId<C, T>>>,
    /// Record edges (each a mint admin's edge on the thing it minted).
    records: BTreeSet<Edge<T>>,
    /// (leaves) Chained parts giving write, per edge by key: the first decides which removals on
    /// the edge take write away (cut content resting on it).
    write_keys: BTreeMap<Edge<T>, ByKey<C, T, K>>,
    /// (keys-open travel) Chained parts giving read, by edge.
    reads: Graph<C, T>,
    /// (leaves) What leaves and addenda are looked up by.
    lx: leaves::LeafIx<C, T>,
}

/// A sync ID's closure over its seeds.
#[derive(Clone, Debug)]
struct Closure<C, T> {
    members: Required<C, T>,
    edges: BTreeSet<Edge<T>>,
}

impl<C, T> Default for Closure<C, T> {
    fn default() -> Self {
        Closure { members: BTreeMap::new(), edges: BTreeSet::new() }
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
    closure: Closure<C, T>,
    /// (leaves) Per (edge, unit thing), the bodies on that thing with a content-class part
    /// resting on the edge.
    rest: BTreeMap<(Edge<T>, T), usize>,
    /// (leaves) Per lowering copy in the set (a member or a body), the things whose leaf of it the
    /// sync ID requires, each with why.
    leaves: BTreeMap<CopyId<C, T>, BTreeMap<T, LeafWhy>>,
}

enum Item<C, T> {
    Edge(Edge<T>),
    Copy(CopyId<C, T>, Reason<C, T>),
}

/// What an update leaves to do: closures to extend, sync IDs to close again, travel seeds to
/// compute again from nothing; leaves to decide again (per sync ID, or per (sync ID, lowering
/// copy)).
struct Todo<C, T> {
    work: BTreeMap<T, Vec<Item<C, T>>>,
    dirty: BTreeSet<T>,
    travel: BTreeSet<T>,
    leaves_all: BTreeSet<T>,
    leaves: BTreeSet<(T, CopyId<C, T>)>,
}

impl<C, T> Default for Todo<C, T> {
    fn default() -> Self {
        Todo { work: BTreeMap::new(), dirty: BTreeSet::new(), travel: BTreeSet::new(), leaves_all: BTreeSet::new(), leaves: BTreeSet::new() }
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
    counts: Counts,
}

fn first<K: Ord + std::marker::Copy, V>(m: Option<&BTreeMap<K, V>>) -> Option<K> {
    m.and_then(|m| m.keys().next().copied())
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
            resetters: BTreeMap::new(),
            records: BTreeSet::new(),
            write_keys: BTreeMap::new(),
            reads: Graph::new(),
            lx: leaves::LeafIx::default(),
        };
        Evidence { cfg, ix, sids: BTreeMap::new(), edge_sids: BTreeMap::new(), member_sids: BTreeMap::new(), thing_sids: BTreeMap::new(), open_sids: BTreeMap::new(), counts: Counts::default() }
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
                if !self.live(&copy) {
                    continue;
                }
                for e in self.body_edges(&copy) {
                    *atoms.entry(e).or_insert(0) += 1;
                }
                counts.bodies += 1;
            }
        }
        work.extend(atoms.keys().map(|e| Item::Edge(*e)));
        let travel = self.travel_of(s.actor, &mut counts);
        work.extend(travel.seeds.iter().map(|(c, r)| Item::Copy(*c, *r)));
        let mut cl = Closure::default();
        close(&self.ix, &s.unit, &mut cl, work, &mut counts);
        Some((cl.members, counts))
    }

    /// Checks the incremental state against itself built from nothing (tests, at teardown or every
    /// step): per sync ID its evidence, atoms and travelling holders equal from scratch, the
    /// keys-open graph and the write keys hold exactly the held chained parts, and the reverse
    /// indexes (edge, member, thing, open thing → sync IDs) hold exactly what the sync IDs do.
    pub fn check(&self) -> Result<(), String> {
        let mut edge_sids: BTreeMap<Edge<T>, BTreeSet<T>> = BTreeMap::new();
        let mut member_sids: BTreeMap<CopyId<C, T>, BTreeSet<T>> = BTreeMap::new();
        let mut thing_sids: BTreeMap<T, BTreeSet<T>> = BTreeMap::new();
        let mut open_sids: BTreeMap<T, BTreeSet<T>> = BTreeMap::new();
        let g = self.graphs();
        if g.reads != self.ix.reads || g.write_keys != self.ix.write_keys {
            return Err("the keys-open graph or the write keys do not hold exactly the chained parts and records".into());
        }
        for (c, h) in &self.ix.copies {
            for (i, (p, j)) in h.parts.iter().zip(&h.joined).enumerate() {
                if *j != self.joined(p) {
                    return Err(format!("copy {c:?} part {i}: joined {j}, computed {}", !j));
                }
            }
            if h.live != self.live_of(c) {
                return Err(format!("copy {c:?}: live {}, computed {}", h.live, !h.live));
            }
        }
        self.check_leaves()?;
        for (sid, s) in &self.sids {
            // the same copies (each with the first reason found, which may differ)
            let scratch = self.from_scratch(sid).unwrap_or_default();
            if scratch.keys().ne(s.closure.members.keys()) {
                return Err(format!("sid {sid:?}: incremental {:?} from scratch {scratch:?}", s.closure.members));
            }
            let mut atoms: BTreeMap<Edge<T>, usize> = BTreeMap::new();
            for t in &s.unit {
                for c in self.ix.on_thing.get(t).into_iter().flatten() {
                    if !self.live(&(*c, *t)) {
                        continue;
                    }
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
        }
        // `leave` may leave a thing's set empty
        let things: BTreeMap<T, BTreeSet<T>> = self.thing_sids.iter().filter(|(_, s)| !s.is_empty()).map(|(k, v)| (*k, v.clone())).collect();
        if edge_sids != self.edge_sids || member_sids != self.member_sids || thing_sids != things || open_sids != self.open_sids {
            return Err("a reverse index (edge, member, thing, open thing → sync IDs) is stale".into());
        }
        Ok(())
    }

    /// The keys-open graph and the write keys built from nothing over the held copies and records.
    fn graphs(&self) -> Graphs<C, T, K> {
        let mut g = Graphs { reads: Graph::new(), write_keys: BTreeMap::new() };
        for e in &self.ix.records {
            g.reads.insert_record(*e);
        }
        for (c, h) in &self.ix.copies {
            for (i, p) in h.parts.iter().enumerate() {
                if let Kind::Write(w) = &p.kind
                    && p.chained
                {
                    let e = (w.holder, c.1);
                    if w.gives_write {
                        g.write_keys.entry(e).or_default().entry(p.pos).or_default().insert((*c, i));
                    }
                    if w.gives_read {
                        g.reads.insert(e, (*c, i));
                    }
                }
            }
        }
        g
    }

    /// Registers sync ID `sid` with actor `actor` and an empty unit.
    pub fn add_sid(&mut self, sid: T, actor: T) {
        if self.sids.contains_key(&sid) {
            return;
        }
        let travel = Travel { open: BTreeSet::new(), seeds: BTreeMap::new() };
        self.sids.insert(sid, Sid { actor, unit: BTreeSet::new(), atoms: BTreeMap::new(), travel, closure: Closure::default(), rest: BTreeMap::new(), leaves: BTreeMap::new() });
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
    /// t still need becomes copies.
    fn retag(&mut self, sid: &T, t: T, joins: bool) {
        let Some(s) = self.sids.get_mut(sid) else { return };
        let moved = if joins { s.unit.insert(t) } else { s.unit.remove(&t) };
        if !moved {
            return;
        }
        let had = s.closure.members.keys().any(|c| c.1 == t);
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
        self.settle(todo);
    }

    /// Record edge `e` (holder: the mint admin; target: the thing it minted), standing for good: an
    /// edge of the keys-open graph (an admin edge, giving read) and what every removal on it takes
    /// write away from. Records are identity: none is ever taken back.
    pub fn add_record(&mut self, e: Edge<T>) {
        if !self.ix.records.insert(e) {
            return;
        }
        let mut todo = Todo::default();
        if self.ix.reads.insert_record(e) {
            self.read_edge(e, &mut todo);
        }
        self.recut(&e, &mut todo);
        self.settle(todo);
    }

    /// A copy held from now on (a copy already held is taken again with these facts).
    pub fn add(&mut self, c: CopyId<C, T>, parts: Vec<Part<C, T, K>>) {
        if self.ix.copies.contains_key(&c) {
            self.forget(&c);
        }
        let mut todo = Todo::default();
        let n = parts.len();
        self.ix.copies.insert(c, Held { parts, joined: vec![false; n], live: true });
        self.ix.on_thing.entry(c.1).or_default().insert(c.0);
        let live = self.live_of(&c);
        if let Some(h) = self.ix.copies.get_mut(&c) {
            h.live = live;
        }
        self.leaf_index(&c, true);
        let held = self.ix.copies.get(&c).map(|h| h.parts.clone()).unwrap_or_default();
        for (i, p) in held.iter().enumerate() {
            if let Kind::Write(w) = &p.kind
                && let Some(cr) = w.creation
            {
                self.ix.resetters.entry(cr).or_default().insert(c);
            }
            if let Some(hops) = &p.hops {
                for h in hops.iter().filter(|h| !h.record) {
                    self.ix.resting.entry((h.edge, h.need)).or_default().entry(p.pos).or_default().insert((c, i));
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
        // an addendum listing it may keep something now
        self.relive_listers(&c, &mut todo);
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
                    remove_by_key(&mut self.ix.resting, &(hp.edge, hp.need), &p.pos, &(*c, i));
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
        self.leaf_index(c, false);
        self.ix.copies.remove(c);
        if let Some(s) = self.ix.on_thing.get_mut(&c.1) {
            s.remove(&c.0);
            if s.is_empty() {
                self.ix.on_thing.remove(&c.1);
            }
        }
        self.relive_listers(c, todo);
        // a travel seed it was leaves with it
        let holders: BTreeSet<T> = h.parts.iter().filter_map(|p| if let Kind::Write(w) = &p.kind { Some(w.holder) } else { None }).collect();
        for hd in holders {
            for sid in self.open_sids.get(&hd).cloned().unwrap_or_default() {
                if self.sids.get_mut(&sid).is_some_and(|s| s.travel.seeds.remove(c).is_some()) {
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
            self.ix.resting.entry((h.edge, h.need)).or_default().entry(pos).or_default().insert((*c, i));
        }
        let mut todo = Todo::default();
        // (leaves) what it rests on is known now: out with the old edges, in with the new
        let sids = if self.live(c) { self.thing_sids.get(&c.1).cloned().unwrap_or_default() } else { BTreeSet::new() };
        for sid in &sids {
            self.rest_move(sid, c, false, &mut todo);
        }
        self.leaf_index(c, false);
        if let Some(p) = self.ix.copies.get_mut(c).and_then(|h| h.parts.get_mut(i)) {
            p.hops = Some(hops);
        }
        self.leaf_index(c, true);
        for sid in &sids {
            self.rest_move(sid, c, true, &mut todo);
        }
        self.recheck(c, i, &mut todo);
        self.relive_listers(c, &mut todo);
        self.settle(todo);
    }

    // ---- what a change moves ----

    /// Indexes a chained part of a held copy and queues what it brings where.
    fn chained_on(&mut self, c: &CopyId<C, T>, i: usize, todo: &mut Todo<C, T>) {
        let Some(p) = self.part(c, i) else { return };
        match &p.kind {
            Kind::Content | Kind::Addendum { .. } => {}
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
                    let before = first(self.ix.write_keys.get(&e));
                    self.ix.write_keys.entry(e).or_default().entry(p.pos).or_default().insert((*c, i));
                    if before.is_none_or(|b| p.pos < b) {
                        self.recut(&e, todo);
                    }
                }
                if let Some(g) = w.grant {
                    for n in Need::ALL.into_iter().filter(|&n| g.meets(n)) {
                        let before = first(self.ix.grants.get(&(e, n)));
                        self.ix.grants.entry((e, n)).or_default().entry(p.pos).or_default().insert((*c, i));
                        if before.is_none_or(|b| p.pos < b) {
                            self.rejoin(&(e, n), Some(p.pos), before, todo);
                        }
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
            Kind::Content | Kind::Addendum { .. } => {}
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
                                    if s.travel.seeds.remove(c).is_some() {
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
                if w.gives_write {
                    let before = first(self.ix.write_keys.get(&e));
                    remove_by_key(&mut self.ix.write_keys, &e, &p.pos, &(*c, i));
                    if first(self.ix.write_keys.get(&e)) != before {
                        self.recut(&e, todo);
                    }
                }
                if let Some(g) = w.grant {
                    for n in Need::ALL.into_iter().filter(|&n| g.meets(n)) {
                        let before = first(self.ix.grants.get(&(e, n)));
                        remove_by_key(&mut self.ix.grants, &(e, n), &p.pos, &(*c, i));
                        let after = first(self.ix.grants.get(&(e, n)));
                        if after != before {
                            self.unjoin(&(e, n), before, after, todo);
                        }
                    }
                }
            }
        }
    }

    // ---- keys-open travel ----

    /// The holders whose role changes travel under a sync ID with actor `actor`, and the chained
    /// writes naming them, from nothing.
    fn travel_of(&self, actor: T, counts: &mut Counts) -> Travel<C, T> {
        let open = if self.cfg.keys_open { bfs([actor], |x| self.ix.reads.next(x), &mut counts.opened) } else { BTreeSet::from([actor]) };
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
            let new = bfs([e.1], |x| self.ix.reads.next(x).filter(|y| !open.contains(y)), &mut self.counts.opened);
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

    /// A removal-shaped part on `e` at `pos` takes write away (cuts content resting on `e`): `e`
    /// is a record edge, or a held chained write on `e` giving write or above is ordered before it.
    fn takes_write(&self, e: &Edge<T>, pos: K) -> bool {
        self.ix.records.contains(e) || first(self.ix.write_keys.get(e)).is_some_and(|f| f < pos)
    }

    fn part(&self, c: &CopyId<C, T>, i: usize) -> Option<Part<C, T, K>> {
        self.ix.copies.get(c).and_then(|h| h.parts.get(i)).cloned()
    }

    /// The first chained grant on `e` meeting a need moved earlier, from `old` to `new`: the parts
    /// resting on `e` with that need ordered after `new` and not after `old` may be joined now.
    fn rejoin(&mut self, e: &(Edge<T>, Need), new: Option<K>, old: Option<K>, todo: &mut Todo<C, T>) {
        let Some(new) = new else { return };
        let hi = old.map_or(Bound::Unbounded, Bound::Included);
        let parts: Vec<PartId<C, T>> = self.ix.resting.get(e).map(|r| r.range((Bound::Excluded(new), hi)).flat_map(|(_, s)| s.iter().copied()).collect()).unwrap_or_default();
        for (c, i) in parts {
            self.recheck(&c, i, todo);
        }
    }

    /// The first chained grant on `e` meeting a need moved later or went, from `old` to `new`: the
    /// parts resting on `e` with that need ordered after `old` and not after `new` are no longer
    /// joined.
    fn unjoin(&mut self, e: &(Edge<T>, Need), old: Option<K>, new: Option<K>, todo: &mut Todo<C, T>) {
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
        let bodies = if self.live(c) { self.thing_sids.get(&c.1).cloned().unwrap_or_default() } else { BTreeSet::new() };
        if !now {
            for sid in bodies {
                self.atoms_out(&sid, edges.clone(), todo);
            }
            for sid in self.member_sids.get(c).cloned().unwrap_or_default() {
                todo.dirty.insert(sid);
            }
            return;
        }
        for sid in bodies {
            self.atoms_in(&sid, edges.clone(), todo);
        }
        for sid in self.member_sids.get(c).cloned().unwrap_or_default() {
            for e in edges.clone() {
                todo.push(&sid, Item::Edge(e));
            }
        }
    }

    /// A part's path is joined: each edge that is no record edge holds a held chained grant
    /// giving what the part needs there, ordered before the part.
    fn joined(&self, p: &Part<C, T, K>) -> bool {
        p.hops.as_ref().is_some_and(|hops| hops.iter().filter(|h| !h.record).all(|h| first(self.ix.grants.get(&(h.edge, h.need))).is_some_and(|f| f < p.pos)))
    }

    /// The edges body `c` brings: each joined part's path edges.
    fn body_edges(&self, c: &CopyId<C, T>) -> Vec<Edge<T>> {
        let Some(h) = self.ix.copies.get(c) else { return vec![] };
        let mut out = vec![];
        for (p, j) in h.parts.iter().zip(&h.joined) {
            if *j {
                out.extend(p.hops.iter().flatten().map(|h| h.edge));
            }
        }
        out
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

    /// A held copy is a body where its thing is in a unit (`Config::leaves`: an addendum only
    /// while it lists something it can keep).
    fn live(&self, c: &CopyId<C, T>) -> bool {
        self.ix.copies.get(c).is_some_and(|h| h.live)
    }

    fn body_add(&mut self, sid: &T, c: &CopyId<C, T>, todo: &mut Todo<C, T>) {
        self.counts.bodies += 1;
        if !self.live(c) {
            return;
        }
        let edges = self.body_edges(c);
        self.atoms_in(sid, edges.into_iter(), todo);
        self.rest_move(sid, c, true, todo);
    }

    fn body_remove(&mut self, sid: &T, c: &CopyId<C, T>, todo: &mut Todo<C, T>) {
        self.counts.bodies += 1;
        if !self.live(c) {
            return;
        }
        let edges = self.body_edges(c);
        self.atoms_out(sid, edges.into_iter(), todo);
        self.rest_move(sid, c, false, todo);
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
            self.reseed(&sid, &old.seeds, &new.seeds, &mut todo);
            if let Some(s) = self.sids.get_mut(&sid) {
                s.travel = new;
            }
        }
        for sid in std::mem::take(&mut todo.dirty) {
            todo.work.remove(&sid);
            self.reclose(&sid);
            todo.leaves_all.insert(sid);
        }
        for (sid, work) in std::mem::take(&mut todo.work) {
            for m in self.extend(&sid, work) {
                todo.leaves.insert((sid, m));
            }
        }
        self.settle_leaves(std::mem::take(&mut todo.leaves_all), std::mem::take(&mut todo.leaves));
    }

    /// S's travel seeds move from `old` to `new`: a seed lost closes S again, a new one joins its
    /// closure.
    fn reseed(&self, sid: &T, old: &Required<C, T>, new: &Required<C, T>, todo: &mut Todo<C, T>) {
        if old.keys().any(|c| !new.contains_key(c)) {
            todo.dirty.insert(*sid);
        }
        for (c, r) in new {
            if !old.contains_key(c) {
                todo.push(sid, Item::Copy(*c, *r));
            }
        }
    }

    /// Extends S's closure by `work` and indexes what it added; the members it added.
    fn extend(&mut self, sid: &T, work: Vec<Item<C, T>>) -> Vec<CopyId<C, T>> {
        let Some(s) = self.sids.get_mut(sid) else { return vec![] };
        let (edges, members) = close(&self.ix, &s.unit, &mut s.closure, work, &mut self.counts);
        for e in edges {
            self.edge_sids.entry(e).or_default().insert(*sid);
        }
        for m in &members {
            self.member_sids.entry(*m).or_default().insert(*sid);
        }
        members
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
        work.extend(s.travel.seeds.iter().map(|(c, r)| Item::Copy(*c, *r)));
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
/// parts' path edges and the creations their resets name.
/// Returns the edges and members it added.
fn close<C, T, K>(ix: &Ix<C, T, K>, unit: &BTreeSet<T>, cl: &mut Closure<C, T>, mut work: Vec<Item<C, T>>, counts: &mut Counts) -> (Vec<Edge<T>>, Vec<CopyId<C, T>>)
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
                for (p, j) in h.parts.iter().zip(&h.joined) {
                    if *j {
                        work.extend(p.hops.iter().flatten().map(|h| Item::Edge(h.edge)));
                    }
                    if let Kind::Write(w) = &p.kind
                        && let Some(cr) = w.creation
                    {
                        work.push(Item::Copy(cr, Reason::Creation(c)));
                    }
                }
            }
        }
    }
    (edges, members)
}
