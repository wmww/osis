//! The walk itself (spec/permissions.md §5.1; notes/write-path-design.md §1, W1 to W10): one walk
//! per component of the edges. The pass state is each edge's applied writes by key, each with the
//! edge's state just after it, so the state before any key is a point query and a restart is a
//! truncation: the checkpoint at every key. The walk's events (each lowering judged, with its
//! drops) are kept in the order given; an update replays its component from the earliest key it
//! touches, keeping the events given before any pass reached that key (`Walk::run`).
//!
//! The key hop (spec/permissions.md §1) keeps no edge until accounts are ordinary things
//! (notes/redesign-plan.md A4): it gives admin where the signer's record holds its key and
//! nothing elsewhere (`path::shape`); it becomes an edge like any, with the edge writes on it,
//! there.

use super::path::shape;
use super::{Changed, Commit, List, Part, PartKind, Status};
use crate::types::{Edge, WriteId};
use osis_base::{CommitId, Role, Tid, Ts};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{self, Excluded, Included, Unbounded};
use std::sync::Arc;

/// An edge (holder, target), interned.
type E = u32;
/// A part, by its place in `Walk::items`.
type Slot = u32;
/// A role; `None` is no role.
type Lvl = Option<Role>;
/// An edge's history: the applied writes, in key order.
pub type History = Vec<(Key, Option<Edge>)>;

const ADMIN: Lvl = Some(Role::Admin);
/// The two levels a cut is counted at (spec/permissions.md §5.2: write, admin).
const LEVELS: [Role; 2] = [Role::Write, Role::Admin];

/// One applied write on an edge in the settled walk, with what it found there (content reads the
/// value and the edge as restored before it).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Applied {
    pub key: Key,
    pub value: Option<Edge>,
    /// The edge's value just before it (its last change, else the record value, else none).
    pub before: Option<Edge>,
    /// An explicit write (§2): not a self-removal, a finalize or a may-grant grant.
    pub explicit: bool,
    /// The edge as restored just before it: what it gave and what it let grant (§5.1).
    pub restored: Option<Role>,
    pub restored_grant: Option<Role>,
}

impl Applied {
    /// A cut below `r` (§5.2): an explicit write whose value gives below `r` at its `ts` and that
    /// takes the edge, as restored, from `r` or above.
    pub fn cuts(&self, r: Role) -> bool {
        self.explicit && self.restored >= Some(r) && alive(self.value.as_ref(), self.key.ts) < Some(r)
    }
}

/// An applied write in the pass: what it found, its part, and the edge as restored just after it.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Entry {
    a: Applied,
    slot: Slot,
    restored: Lvl,
    rgrant: Lvl,
}

/// A part's position in the walk (§5.1 step 1): (`ts`, thing signed as, commit ID), then its
/// place in the commit's order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Key {
    pub ts: Ts,
    pub signer: Tid,
    pub commit: CommitId,
    pub part: u32,
}

impl Key {
    /// The start of `ts` (§5.2 Position): before every part at that `ts`.
    pub fn start(ts: Ts) -> Key {
        Key { ts, signer: Tid::from_bytes([0; 15]), commit: CommitId([0; 32]), part: 0 }
    }
}

/// Before every part.
const FIRST: Key = Key { ts: Ts::ZERO, signer: Tid::from_bytes([0; 15]), commit: CommitId([0; 32]), part: 0 };

/// Work done, for the count tests (notes/perm-paths.md, Cost).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Counts {
    /// Parts taken by a pass (each pass from where it started).
    pub steps: u64,
    /// Passes (a restart continues from its earliest drop, one pass each).
    pub passes: u64,
    /// Restarts: a commit whose lowerings applied with drops.
    pub restarts: u64,
    /// Setters read by void checks (`keeps`).
    pub setters: u64,
    /// Parts resting on a lowered edge looked at by audits and seeds.
    pub audited: u64,
    /// Components walked from scratch for their trust: a trust switch, a void trusted round.
    pub scratch: u64,
    /// Content (§5.2): edge reads, namers, addenda and snapshots looked at by delta queries.
    pub content: u64,
    /// Addenda judged and entries read by the addenda fixpoint.
    pub addenda: u64,
    /// Parts and events moved by component merges.
    pub merged: u64,
    /// Parts judged by the chained pass.
    pub chained: u64,
}

impl Counts {
    fn zip(&self, o: &Counts, f: impl Fn(u64, u64) -> u64) -> Counts {
        Counts {
            steps: f(self.steps, o.steps),
            passes: f(self.passes, o.passes),
            restarts: f(self.restarts, o.restarts),
            setters: f(self.setters, o.setters),
            audited: f(self.audited, o.audited),
            scratch: f(self.scratch, o.scratch),
            content: f(self.content, o.content),
            addenda: f(self.addenda, o.addenda),
            merged: f(self.merged, o.merged),
            chained: f(self.chained, o.chained),
        }
    }

    /// The work done since `earlier`.
    pub fn since(&self, earlier: &Counts) -> Counts {
        self.zip(earlier, |a, b| a - b)
    }

    pub(super) fn add(&mut self, o: &Counts) {
        *self = self.zip(o, |a, b| a + b);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verdict {
    Applied,
    Void,
}

/// How a part applied in the pass (§5.1 step 2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum How {
    Admin,
    Flag,
    Finalize,
}

/// How the settled walk applies an edge write (§2, §5.1 step 2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Way {
    /// By admin along its path: an explicit write.
    Explicit,
    /// A self-removal.
    Leave,
    /// As a may-grant grant.
    MayGrant,
    /// As a finalize.
    Finalize,
}

/// What a part needs of one edge it rests on (§5.1 step 3): a role there, or that the edge lets
/// its holder grant the role (the last edge of a may-grant grant's path).
#[derive(Clone, Copy)]
enum Need {
    Role(Lvl),
    Flag(Lvl),
}

impl Need {
    fn met(self, role: Lvl, grants: Lvl) -> bool {
        match self {
            Need::Role(r) => role >= r,
            Need::Flag(r) => grants >= r,
        }
    }
}

/// The role a value gives at `ts`.
fn alive(v: Option<&Edge>, ts: Ts) -> Lvl {
    v.filter(|v| v.alive_at(Some(ts))).map(|v| v.role)
}

/// A value's may-grant flag.
fn flag(v: Option<&Edge>) -> bool {
    v.is_some_and(|v| v.may_grant)
}

/// What a value giving `role` lets its holder grant (§5.1): its role at admin or with the flag.
fn grantable(role: Lvl, flag: bool) -> Lvl {
    if role == ADMIN || flag { role } else { None }
}

/// A role's place in `Role::ALL`.
fn ri(r: Role) -> usize {
    Role::ALL.iter().position(|&x| x == r).unwrap_or(0)
}

/// An edge-class part, with what the walk holds of it.
#[derive(Clone)]
struct Item {
    key: Key,
    id: WriteId,
    ts: Ts,
    signer: Tid,
    on: Tid,
    /// The edge it sets.
    e: E,
    value: Option<Edge>,
    frontier: Option<Arc<List>>,
    /// Its path's edges; none where not `well`.
    hops: Vec<E>,
    /// Its members name no thing twice, its marks are valid and its commit sets no edge twice.
    well: bool,
    /// A self-removal: its path ends at the holder of the edge it sets.
    leave: bool,
    finalize: bool,
    live: bool,
    verdict: Option<Verdict>,
    /// In D by a lowering's drops: that lowering.
    dropped: Option<Slot>,
    /// In D as a trusted write's seed.
    seeded: bool,
    /// How the pass applied it, where it did.
    how: Option<How>,
    /// Made by right in the walk as it stands before its key (§5.2 Re-grant).
    by_right: bool,
    /// Chained (§4 Chained writes).
    chained: bool,
}

impl Item {
    /// The item of a slot not in use.
    fn nil() -> Item {
        let none = Tid::from_bytes([0; 15]);
        Item { key: FIRST, id: WriteId(CommitId([0; 32]), 0), ts: Ts::ZERO, signer: none, on: none, e: E::MAX, value: None, frontier: None, hops: vec![], well: false, leave: false, finalize: false, live: false, verdict: None, dropped: None, seeded: false, how: None, by_right: false, chained: false }
    }
    fn after(&self) -> Lvl {
        alive(self.value.as_ref(), self.ts)
    }
    fn after_grant(&self) -> Lvl {
        grantable(self.after(), flag(self.value.as_ref()))
    }
    /// An edge write giving below admin at its `ts`, no finalize (a self-removal included).
    fn lowering_shape(&self) -> bool {
        !self.finalize && self.after() < ADMIN
    }
    /// A lowering (§5.1).
    fn lowering(&self) -> bool {
        self.lowering_shape() && !self.leave
    }
    /// The role of an edge write that may apply as a may-grant grant (§2): one adding a grant.
    fn flag_grant(&self) -> Lvl {
        (!self.leave && !self.finalize).then(|| self.after()).flatten().and(self.value.map(|v| v.role))
    }
    /// The edges it rests on (§5.1): its path's, and a self-removal's own.
    fn rests(&self) -> impl Iterator<Item = E> + '_ {
        self.hops.iter().copied().chain(self.leave.then_some(self.e))
    }
    fn rests_on(&self, e: E) -> bool {
        self.rests().any(|h| h == e)
    }
    /// What the chained pass has it set (§4): its role and what it lets grant, `until`
    /// disregarded.
    fn chain_sets(&self) -> [Option<usize>; 2] {
        let role = self.value.map(|v| v.role);
        [role.map(ri), grantable(role, flag(self.value.as_ref())).map(|r| GRANT + ri(r))]
    }
}

/// `EdgeInfo::chain`'s second half: the levels chained writes let grant.
const GRANT: usize = 4;

#[derive(Clone)]
struct EdgeInfo {
    name: (Tid, Tid),
    record: bool,
    /// Union-find over the edges: a root names its component.
    parent: E,
    /// The pass: its applied writes by key.
    hist: BTreeMap<Key, Entry>,
    /// The keys of its cuts below each of `LEVELS`.
    cuts: [BTreeSet<Key>; 2],
    /// The held parts setting it, and those resting on it.
    setters: BTreeSet<(Key, Slot)>,
    resting: BTreeSet<(Key, Slot)>,
    /// The keys of the chained writes setting it at each role (`Role::ALL`'s order), then of those
    /// letting grant each role.
    chain: [BTreeSet<Key>; 8],
}

impl EdgeInfo {
    fn nil() -> EdgeInfo {
        let none = Tid::from_bytes([0; 15]);
        EdgeInfo { name: (none, none), record: false, parent: E::MAX, hist: BTreeMap::new(), cuts: Default::default(), setters: BTreeSet::new(), resting: BTreeSet::new(), chain: Default::default() }
    }
}

/// A lowering judged: its verdict is in its item; applied, its drops.
#[derive(Clone)]
struct Event {
    key: Key,
    slot: Slot,
    drops: Vec<Slot>,
}

/// One component: its parts in key order, the events given in order, its trusted writes walked
/// as trusted and those void, and the earliest key an update touched.
#[derive(Clone, Default)]
struct Comp {
    order: BTreeMap<Key, Slot>,
    events: Vec<Event>,
    active: BTreeSet<Slot>,
    void: BTreeSet<Slot>,
    dirty: Option<Key>,
}

/// What an update changed, as first found: `Walk::changed` compares with what stands.
#[derive(Clone, Default)]
struct Journal {
    status: BTreeMap<WriteId, Option<Status>>,
    hist: BTreeMap<(E, Key), Option<Entry>>,
    finals: BTreeMap<E, Lvl>,
    firsts: BTreeMap<E, [Option<Key>; 2]>,
    chained: BTreeSet<WriteId>,
}

#[derive(Clone)]
pub(super) struct Walk {
    mint: BTreeMap<Tid, Tid>,
    single: bool,
    edges: Tab<EdgeInfo>,
    edge_ids: BTreeMap<(Tid, Tid), E>,
    items: Tab<Item>,
    free: Vec<Slot>,
    freed: Vec<Slot>,
    ids: BTreeMap<WriteId, Slot>,
    commits: BTreeMap<CommitId, Vec<Slot>>,
    comps: BTreeMap<E, Comp>,
    void: BTreeSet<WriteId>,
    journal: Journal,
    pub counts: Counts,
}

impl Walk {
    /// `single`: every edge in one component (a test mode: the walk by components must read
    /// exactly as it).
    pub(super) fn new(records: &BTreeMap<Tid, Tid>, single: bool) -> Walk {
        let mut w = Walk {
            mint: records.clone(),
            single,
            edges: Tab::new(EdgeInfo::nil()),
            edge_ids: BTreeMap::new(),
            items: Tab::new(Item::nil()),
            free: vec![],
            freed: vec![],
            ids: BTreeMap::new(),
            commits: BTreeMap::new(),
            comps: BTreeMap::new(),
            void: BTreeSet::new(),
            journal: Journal::default(),
            counts: Counts::default(),
        };
        for (t, a) in records {
            w.intern((*a, *t));
        }
        w
    }

    fn intern(&mut self, name: (Tid, Tid)) -> E {
        if let Some(&e) = self.edge_ids.get(&name) {
            return e;
        }
        let e = self.edges.len();
        self.edges.push(EdgeInfo { name, record: self.mint.get(&name.1) == Some(&name.0), parent: e, ..EdgeInfo::nil() });
        self.edge_ids.insert(name, e);
        if self.single && e > 0 {
            self.union(0, e);
        }
        e
    }

    /// A record that came: `t`'s mint admin, its record edge in force from the start. A held part
    /// whose shape read `t`'s record chain without it is the caller's to give again.
    pub(super) fn add_record(&mut self, t: Tid, admin: Tid) {
        self.mint.insert(t, admin);
        match self.edge_ids.get(&(admin, t)).copied() {
            Some(e) if !self.ed(e).record => {
                let fin = self.final_pair(e).0;
                self.journal.finals.entry(e).or_insert(fin);
                self.note_first(e);
                self.edges[e].record = true;
                self.touch(e, FIRST);
            }
            Some(_) => {}
            None => {
                self.intern((admin, t));
            }
        }
    }

    /// A record that went: its record edge with it, from the start.
    pub(super) fn remove_record(&mut self, t: &Tid) {
        let Some(admin) = self.mint.remove(t) else { return };
        if let Some(e) = self.edge_ids.get(&(admin, *t)).copied().filter(|&e| self.ed(e).record) {
            let fin = self.final_pair(e).0;
            self.journal.finals.entry(e).or_insert(fin);
            self.note_first(e);
            self.edges[e].record = false;
            self.touch(e, FIRST);
        }
    }

    /// The held commits with an edge-class part resting on (holder, target) (§5.1 Rests on).
    pub(super) fn resting(&self, holder: &Tid, target: &Tid) -> BTreeSet<CommitId> {
        let Some(ed) = self.edge(holder, target) else { return BTreeSet::new() };
        ed.resting.iter().map(|&(_, s)| self.it(s).id.0).collect()
    }

    /// The held commits with an edge-class part setting or resting on (holder, target).
    pub(super) fn through(&self, holder: &Tid, target: &Tid) -> BTreeSet<CommitId> {
        let Some(ed) = self.edge(holder, target) else { return BTreeSet::new() };
        ed.setters.iter().chain(&ed.resting).map(|&(_, s)| self.it(s).id.0).collect()
    }

    fn edge(&self, holder: &Tid, target: &Tid) -> Option<&EdgeInfo> {
        self.edge_ids.get(&(*holder, *target)).map(|&e| self.ed(e))
    }

    fn ed(&self, e: E) -> &EdgeInfo {
        &self.edges[e]
    }

    fn it(&self, s: Slot) -> &Item {
        &self.items[s]
    }

    fn find(&self, mut e: E) -> E {
        while self.ed(e).parent != e {
            e = self.ed(e).parent;
        }
        e
    }

    /// Joins the components of `a` and `b`, the smaller into the larger. Its events go after the
    /// larger's: the two walked nothing of each other, so any order keeping each one's is a walk
    /// of both.
    fn union(&mut self, a: E, b: E) -> E {
        let (a, b) = (self.find(a), self.find(b));
        if a == b {
            return a;
        }
        let len = |c: Option<&Comp>| c.map_or(0, |c| c.order.len());
        let (big, small) = if len(self.comps.get(&a)) >= len(self.comps.get(&b)) { (a, b) } else { (b, a) };
        self.edges[small].parent = big;
        if let Some(s) = self.comps.remove(&small) {
            self.counts.merged += (s.order.len() + s.events.len()) as u64;
            let c = self.comps.entry(big).or_default();
            c.order.extend(s.order);
            c.events.extend(s.events);
            c.active.extend(s.active);
            c.void.extend(s.void);
            c.dirty = [c.dirty, s.dirty].into_iter().flatten().min();
        }
        big
    }

    fn touch(&mut self, e: E, k: Key) {
        let c = self.find(e);
        let d = &mut self.comps.entry(c).or_default().dirty;
        *d = Some(d.map_or(k, |x| x.min(k)));
    }

    /// A commit's edge-class parts as items, in the commit's order (§5.1 step 1): the parts on no
    /// hop of a path the commit states, then those on one; in each by thing, then holder.
    fn compile(&mut self, c: &Commit) -> Vec<Item> {
        let mut own: BTreeSet<(Tid, Tid)> = BTreeSet::new();
        let mut sets: BTreeSet<(Tid, Tid)> = BTreeSet::new();
        let mut twice = false;
        for p in c.parts.iter().filter(|p| !matches!(p.kind, PartKind::None)) {
            own.extend(shape(&self.mint, c.signer, &p.path, p.direct, p.on, None, true).hops);
            if let PartKind::Edge(w) = &p.kind {
                twice |= !sets.insert((w.holder, p.on));
            }
        }
        let mut parts: Vec<(bool, Tid, Tid, u32)> = vec![];
        for (n, p) in c.parts.iter().enumerate() {
            if let PartKind::Edge(w) = &p.kind {
                parts.push((own.contains(&(w.holder, p.on)), p.on, w.holder, n as u32));
            }
        }
        parts.sort();
        let mut out = vec![];
        for (place, (_, on, holder, n)) in parts.into_iter().enumerate() {
            let Some(Part { path, direct, kind: PartKind::Edge(w), .. }) = c.parts.get(n as usize) else { continue };
            let sh = shape(&self.mint, c.signer, path, *direct, on, Some(holder), true);
            let well = sh.well && !twice;
            let hops = if well { sh.hops.iter().map(|&h| self.intern(h)).collect() } else { vec![] };
            out.push(Item {
                key: Key { ts: c.ts, signer: c.signer, commit: c.id, part: place as u32 },
                id: WriteId(c.id, n),
                ts: c.ts,
                signer: c.signer,
                on,
                e: self.intern((holder, on)),
                value: w.value,
                frontier: w.frontier.clone(),
                hops,
                well,
                leave: sh.leave,
                // a removal of another holder's grant carrying no frontier, no self-removal (§2)
                finalize: w.value.is_none() && w.frontier.is_none() && !sh.leave && holder != c.signer,
                live: true,
                verdict: None,
                dropped: None,
                seeded: false,
                how: None,
                by_right: false,
                chained: false,
            });
        }
        out
    }

    /// Takes in commits not held: their parts join their components, each dirty from its key.
    pub(super) fn take(&mut self, commits: &[Commit]) {
        let mut chain = BTreeSet::new();
        for c in commits {
            let mut slots = vec![];
            let mut by_thing: BTreeMap<Tid, E> = BTreeMap::new();
            for it in self.compile(c) {
                let s = match self.free.pop() {
                    Some(s) => {
                        self.items[s] = it;
                        s
                    }
                    None => {
                        self.items.push(it);
                        self.items.len() - 1
                    }
                };
                let it = self.it(s).clone();
                self.journal.status.entry(it.id).or_insert(None);
                self.ids.insert(it.id, s);
                // a commit's parts on a thing fall together: one component
                let mut root = *by_thing.entry(it.on).or_insert(it.e);
                for h in it.rests().chain([it.e]) {
                    root = self.union(root, h);
                }
                self.edges[it.e].setters.insert((it.key, s));
                for h in it.rests() {
                    self.edges[h].resting.insert((it.key, s));
                }
                let root = self.find(root);
                self.comps.entry(root).or_default().order.insert(it.key, s);
                self.touch(it.e, it.key);
                chain.insert((it.key, s));
                slots.push(s);
            }
            self.seed_new(&slots);
            self.commits.insert(c.id, slots);
        }
        self.chain_fix(chain);
    }

    /// Forgets held commits: their parts leave their components, each dirty from its key.
    pub(super) fn forget(&mut self, commits: &[CommitId]) {
        let mut chain = BTreeSet::new();
        for c in commits {
            for s in self.commits.remove(c).unwrap_or_default() {
                let it = self.it(s).clone();
                self.note(s);
                self.ids.remove(&it.id);
                self.void.remove(&it.id);
                self.unapply(s);
                self.note_first(it.e);
                if it.chained {
                    self.journal.chained.insert(it.id);
                    if self.chain_put(s, false) {
                        chain.extend(self.ed(it.e).resting.range((Excluded((it.key, s)), Unbounded)).copied());
                    }
                }
                self.edges[it.e].setters.remove(&(it.key, s));
                for h in it.rests() {
                    self.edges[h].resting.remove(&(it.key, s));
                }
                let root = self.find(it.e);
                let c = self.comps.entry(root).or_default();
                // its place among the trusted writes stays until `settle` finds it gone
                c.order.remove(&it.key);
                self.touch(it.e, it.key);
                let dead = &mut self.items[s];
                dead.live = false;
                dead.hops.clear();
                dead.frontier = None;
                self.freed.push(s);
            }
        }
        self.chain_fix(chain);
    }

    pub(super) fn holds(&self, c: &CommitId) -> bool {
        self.commits.contains_key(c)
    }

    /// Starts an update: `changed` reports from here.
    pub(super) fn begin(&mut self) {
        self.journal = Journal::default();
        self.free.append(&mut self.freed);
    }

    // ---- the journal ----

    fn note(&mut self, s: Slot) {
        let id = self.it(s).id;
        if !self.journal.status.contains_key(&id) {
            let st = self.status_of(s);
            self.journal.status.insert(id, st);
        }
    }

    fn note_edge(&mut self, e: E, k: Key) {
        let fin = self.final_pair(e).0;
        self.journal.finals.entry(e).or_insert(fin);
        let old = self.ed(e).hist.get(&k).copied();
        self.journal.hist.entry((e, k)).or_insert(old);
    }

    /// Before a part setting `e` is made by right otherwise, or goes.
    fn note_first(&mut self, e: E) {
        if !self.journal.firsts.contains_key(&e) {
            let was = self.firsts(e);
            self.journal.firsts.insert(e, was);
        }
    }

    /// Takes part `s` out of the pass.
    fn unapply(&mut self, s: Slot) {
        let (e, k) = (self.it(s).e, self.it(s).key);
        if self.it(s).how.is_some() {
            self.note_edge(e, k);
            let ed = &mut self.edges[e];
            ed.hist.remove(&k);
            for c in &mut ed.cuts {
                c.remove(&k);
            }
            self.items[s].how = None;
        }
    }

    /// Puts part `s` in the pass, applied as `how`.
    fn apply(&mut self, s: Slot, how: How, en: Entry) {
        let (e, k) = (self.it(s).e, self.it(s).key);
        self.note_edge(e, k);
        let ed = &mut self.edges[e];
        for (c, r) in ed.cuts.iter_mut().zip(LEVELS) {
            if en.a.cuts(r) {
                c.insert(k);
            }
        }
        ed.hist.insert(k, en);
        self.items[s].how = Some(how);
    }

    /// The pass back to before `m` in component `c`: every part at or after it unapplied.
    fn truncate(&mut self, c: E, m: Key) {
        let later: Vec<Slot> = self.comps.get(&c).into_iter().flat_map(|c| c.order.range(m..).map(|x| *x.1)).collect();
        for s in later {
            self.note(s);
            self.unapply(s);
        }
    }

    /// What the update since `begin` changed.
    pub(super) fn changed(&mut self) -> Changed {
        let j = std::mem::take(&mut self.journal);
        let mut ch = Changed::default();
        for (id, was) in j.status {
            let now = self.ids.get(&id).and_then(|&s| self.status_of(s));
            if now.is_some() && was != now {
                ch.parts.insert(id);
                if matches!(was, Some(Status::Applied | Status::MayGrant)) {
                    ch.was_applied.insert(id);
                }
            }
        }
        for ((e, k), was) in j.hist {
            let now = self.ed(e).hist.get(&k).copied();
            let name = self.ed(e).name;
            if was.map(|x| x.a.value) != now.map(|x| x.a.value) {
                let at = ch.edges.entry(name).or_insert(k);
                *at = (*at).min(k);
            }
            if LEVELS.iter().any(|&r| was.is_some_and(|x| x.a.cuts(r)) != now.is_some_and(|x| x.a.cuts(r))) {
                let at = ch.cuts.entry(name).or_insert(k);
                *at = (*at).max(k);
            }
        }
        for (e, was) in j.finals {
            if was != self.final_pair(e).0 {
                ch.regrant.insert(self.ed(e).name);
            }
        }
        for (e, was) in j.firsts {
            if was != self.firsts(e) {
                ch.regrant.insert(self.ed(e).name);
            }
        }
        ch.chained = j.chained;
        ch
    }

    // ---- trust ----

    /// Whether `j` is a seed of trusted write `r` by itself (§5.1 Seeds): of another commit,
    /// ordered before it, resting on its hop, not named, its least need there not met.
    fn seeds_alone(&self, r: Slot, j: Slot) -> bool {
        let (rt, jt) = (self.it(r), self.it(j));
        jt.key < rt.key && jt.id.0 != rt.id.0 && jt.rests_on(rt.e) && !self.listed(r, j) && !self.need(j, rt.e, true).met(rt.after(), rt.after_grant())
    }

    /// The seeds of `r`: those by themselves, and with each the other parts of its commit on its
    /// thing ordered before `r`.
    fn seeds_of(&mut self, r: Slot) -> BTreeSet<Slot> {
        let rt = self.it(r).clone();
        let before: Vec<Slot> = self.ed(rt.e).resting.range(..(rt.key, 0)).map(|x| x.1).collect();
        self.counts.audited += before.len() as u64;
        let alone: Vec<Slot> = before.into_iter().filter(|&j| self.seeds_alone(r, j)).collect();
        let mut out: BTreeSet<Slot> = alone.iter().copied().collect();
        for j in alone {
            let jt = self.it(j);
            out.extend(self.commits.get(&jt.id.0).into_iter().flatten().copied().filter(|&x| self.it(x).on == jt.on && self.it(x).key < rt.key));
        }
        out
    }

    /// Seeds component `c` anew under its active trusted writes; it is walked from scratch.
    fn reseed(&mut self, c: E) {
        let Some(comp) = self.comps.get(&c) else { return };
        let (all, active): (Vec<Slot>, Vec<Slot>) = (comp.order.values().copied().collect(), comp.active.iter().copied().collect());
        let mut seeds = BTreeSet::new();
        for r in active {
            seeds.extend(self.seeds_of(r));
        }
        for s in all {
            let on = seeds.contains(&s);
            if self.it(s).seeded != on {
                self.note(s);
                self.items[s].seeded = on;
            }
        }
        self.touch(c, FIRST);
    }

    /// Seeds the new parts `slots` of one commit under the trusted writes active in their
    /// components.
    fn seed_new(&mut self, slots: &[Slot]) {
        for &j in slots {
            let active: Vec<Slot> = self.comps.get(&self.find(self.it(j).e)).into_iter().flat_map(|c| c.active.iter().copied()).filter(|&r| self.it(r).live).collect();
            self.counts.audited += active.len() as u64;
            for r in active {
                if !self.seeds_alone(r, j) {
                    continue;
                }
                let (on, rk) = (self.it(j).on, self.it(r).key);
                for &x in slots {
                    let xt = &mut self.items[x];
                    xt.seeded |= xt.on == on && xt.key < rk;
                }
            }
        }
    }

    /// Settles every component an update touched, and those holding a write of `switched` (added
    /// to or taken from `trust`), each as from scratch under the trust set (§5.1 Trust set): its
    /// held trusted writes walked as trusted, then the walk, the trusted writes it does not apply
    /// void, all at once, and the walk again without their seeds, until none is.
    pub(super) fn settle(&mut self, trust: &BTreeSet<WriteId>, switched: &BTreeSet<WriteId>) {
        for id in switched {
            if let Some(&s) = self.ids.get(id) {
                self.touch(self.it(s).e, FIRST);
            }
        }
        let dirty: Vec<E> = self.comps.iter().filter(|(_, c)| c.dirty.is_some()).map(|(&e, _)| e).collect();
        let held: Vec<Slot> = trust.iter().filter_map(|id| self.ids.get(id).copied()).collect();
        for c in dirty {
            // read as from scratch: every held trusted write of it counts again
            let all: BTreeSet<Slot> = held.iter().copied().filter(|&s| self.find(self.it(s).e) == c).collect();
            let mut round = 0;
            while let Some(comp) = self.comps.get_mut(&c) {
                let active: BTreeSet<Slot> = if round == 0 { all.clone() } else { comp.active.difference(&comp.void).copied().collect() };
                if round == 0 {
                    for s in std::mem::take(&mut comp.void) {
                        let id = self.items[s].id;
                        self.void.remove(&id);
                    }
                }
                let Some(comp) = self.comps.get_mut(&c) else { break };
                if comp.active != active {
                    comp.active = active;
                    self.counts.scratch += 1;
                    self.reseed(c);
                }
                self.run(c);
                let gone: Vec<Slot> = self.comps.get(&c).into_iter().flat_map(|c| c.active.iter().copied()).filter(|&s| self.it(s).how.is_none()).collect();
                if gone.is_empty() {
                    break;
                }
                for s in gone {
                    self.void.insert(self.it(s).id);
                    if let Some(comp) = self.comps.get_mut(&c) {
                        comp.void.insert(s);
                    }
                }
                round += 1;
            }
        }
    }

    pub(super) fn void_trusted(&self) -> &BTreeSet<WriteId> {
        &self.void
    }

    // ---- the pass ----

    /// Edge `e` just before `k`: its value (`None`: never set), and the edge as restored, in
    /// what it gives and lets grant.
    fn state(&self, e: E, k: Key) -> (Option<Option<Edge>>, Lvl, Lvl) {
        let ed = self.ed(e);
        match ed.hist.range(..k).next_back() {
            Some((_, en)) => (Some(en.a.value), en.restored, en.rgrant),
            None if ed.record => (Some(Some(Edge::new(Role::Admin))), ADMIN, ADMIN),
            None => (None, None, None),
        }
    }

    fn value(&self, e: E, k: Key) -> Option<Edge> {
        self.state(e, k).0.flatten()
    }

    /// What `e` gives just before `k`, read at `ts`.
    fn at(&self, e: E, k: Key, ts: Ts) -> Lvl {
        alive(self.value(e, k).as_ref(), ts)
    }

    /// What `e` lets its holder grant just before `k`, read at `ts`.
    fn lets(&self, e: E, k: Key, ts: Ts) -> Lvl {
        let v = self.value(e, k);
        grantable(alive(v.as_ref(), ts), flag(v.as_ref()))
    }

    /// `r`'s list names `j`: its leaf of `j`'s thing lists `j`'s commit.
    fn listed(&self, r: Slot, j: Slot) -> bool {
        let jt = self.it(j);
        self.it(r).frontier.as_ref().is_some_and(|f| f.names(&jt.id.0, &jt.on))
    }

    /// What `j` needs of `e` (§5.1 step 3): admin; a may-grant grant (`as_flag`: applied as one,
    /// or not applied and one that may) its role, on its path's last edge as what the edge lets
    /// grant; a finalize write.
    fn need(&self, j: Slot, e: E, as_flag: bool) -> Need {
        let jt = self.it(j);
        match jt.flag_grant().filter(|_| as_flag) {
            Some(r) if jt.hops.last() == Some(&e) => Need::Flag(Some(r)),
            Some(r) => Need::Role(Some(r)),
            None if jt.finalize => Need::Role(Some(Role::Write)),
            None => Need::Role(ADMIN),
        }
    }

    /// Whether `it`'s path gives admin just before its key.
    fn admin(&self, it: &Item) -> bool {
        it.hops.iter().all(|&h| self.at(h, it.key, it.ts) == ADMIN)
    }

    /// Whether `it`'s path gives may-grant at its role just before its key (§2).
    fn may_grant(&self, it: &Item) -> bool {
        let (Some(r), Some((&last, before))) = (it.flag_grant(), it.hops.split_last()) else { return false };
        self.lets(last, it.key, it.ts) >= Some(r) && before.iter().all(|&h| self.at(h, it.key, it.ts) >= Some(r))
    }

    /// Walks component `c` again from its dirty key (`Comp::dirty`). The events given before any
    /// pass reached that key stand: the passes that gave them read nothing at or after it. Every
    /// later event is undone (its verdict, its drops), and the pass goes on from the earliest key
    /// those and the update touch: before it the pass is as the walk from scratch has it there.
    fn run(&mut self, c: E) {
        let Some(comp) = self.comps.get_mut(&c) else { return };
        let Some(from) = comp.dirty.take() else { return };
        let keep = comp.events.iter().position(|ev| ev.key >= from).unwrap_or(comp.events.len());
        let undone = comp.events.split_off(keep);
        let mut at = from;
        for ev in undone {
            for s in ev.drops.into_iter().chain([ev.slot]) {
                if !self.it(s).live {
                    continue;
                }
                self.note(s);
                let it = &mut self.items[s];
                if s == ev.slot {
                    it.verdict = None;
                } else {
                    it.dropped = None;
                }
                at = at.min(it.key);
            }
        }
        self.truncate(c, at);
        loop {
            self.counts.passes += 1;
            // the commit taking effect, and the drops its parts made in this pass
            let mut cur: Option<CommitId> = None;
            let mut cdrops: Vec<Slot> = vec![];
            let mut next = Included(at);
            while let Some((&k, &s)) = self.comps.get(&c).and_then(|c| c.order.range((next, Unbounded)).next()) {
                if cur != Some(k.commit) {
                    if !cdrops.is_empty() {
                        break;
                    }
                    cur = Some(k.commit);
                }
                next = Excluded(k);
                self.step(c, s, &mut cdrops);
            }
            // the pass ends once a commit whose lowerings dropped has taken effect; the next
            // goes on from the earliest drop
            let Some(first) = cdrops.iter().map(|&s| self.it(s).key).min() else { return };
            self.counts.restarts += 1;
            self.truncate(c, first);
            at = first;
        }
    }

    /// Takes part `s` in the pass (§5.1 steps 2 and 3).
    fn step(&mut self, c: E, s: Slot, cdrops: &mut Vec<Slot>) {
        self.counts.steps += 1;
        crate::count::walked(1);
        let it = self.it(s).clone();
        let by_right = it.well && !it.leave && !it.finalize && (self.admin(&it) || self.may_grant(&it));
        if by_right != it.by_right {
            self.note_first(it.e);
            self.items[s].by_right = by_right;
        }
        if it.dropped.is_some() || it.seeded {
            return;
        }
        let (old, stored, stored_grant) = self.state(it.e, it.key);
        let old = old.flatten();
        let (cur, cur_grant) = (alive(old.as_ref(), it.ts), grantable(alive(old.as_ref(), it.ts), flag(old.as_ref())));
        let (restored, rgrant) = (stored.max(cur), stored_grant.max(cur_grant));
        let (after, after_grant) = (it.after(), it.after_grant());
        let verdict = it.verdict.filter(|_| it.lowering());
        let how = match verdict {
            Some(Verdict::Void) => return,
            // applied for good where it lowers; where it would raise the edge as restored it
            // applies only as any write does
            Some(Verdict::Applied) => {
                if (after > restored || after_grant > rgrant) && !self.admin(&it) {
                    return;
                }
                How::Admin
            }
            None if !it.well => return,
            None if it.finalize => {
                // it ends a grant past its `until`, by a writer holding at least the grant's role
                let Some(g) = old.filter(|g| g.until.is_some() && !g.alive_at(Some(it.ts))) else { return };
                if it.hops.iter().any(|&h| self.at(h, it.key, it.ts) < Some(g.role.max(Role::Write))) {
                    return;
                }
                How::Finalize
            }
            None if self.admin(&it) => How::Admin,
            None => {
                if cur.is_some() || !self.may_grant(&it) {
                    return;
                }
                How::Flag
            }
        };
        // a self-removal only lowers (§2)
        if it.leave && it.value.is_some_and(|n| !old.is_some_and(|o| leaves(&n, &o))) {
            return;
        }
        let explicit = how == How::Admin && !it.leave;
        let mut drops = vec![];
        if verdict.is_none() && explicit && (restored > after || rgrant > after_grant) {
            let q = self.audit(s, restored, rgrant);
            let gone: BTreeSet<Slot> = q.iter().chain(cdrops.iter()).copied().collect();
            let kept = self.keeps(s, &gone);
            self.note(s);
            self.items[s].verdict = Some(if kept { Verdict::Applied } else { Verdict::Void });
            if kept {
                drops = q;
            }
            if let Some(comp) = self.comps.get_mut(&c) {
                comp.events.push(Event { key: it.key, slot: s, drops: drops.clone() });
            }
            if !kept {
                return;
            }
        }
        // the edge as restored reads each value with its `until` disregarded
        let raw = it.value.map(|v| v.role);
        let raw_grant = grantable(raw, flag(it.value.as_ref()));
        let (new, new_grant) = match how {
            How::Admin if explicit => (raw, raw_grant),
            How::Flag => (stored.max(raw), stored_grant.max(raw_grant)),
            _ => (stored, stored_grant),
        };
        let a = Applied { key: it.key, value: it.value, before: old, explicit, restored, restored_grant: rgrant };
        self.apply(s, how, Entry { a, slot: s, restored: new, rgrant: new_grant });
        for j in drops {
            self.note(j);
            self.items[j].dropped = Some(s);
            cdrops.push(j);
        }
    }

    /// The drops of lowering `l`, taking its edge down from `restored` and `rgrant` (§5.1 step
    /// 3): the held parts of other commits ordered before it, resting on its edge, not in D, not
    /// void, not named, whose need there the edge as restored met and its value does not; and
    /// with each the other parts of its commit on its thing.
    fn audit(&mut self, l: Slot, restored: Lvl, rgrant: Lvl) -> Vec<Slot> {
        let lt = self.it(l).clone();
        let before: Vec<Slot> = self.ed(lt.e).resting.range(..(lt.key, 0)).map(|x| x.1).collect();
        self.counts.audited += before.len() as u64;
        let droppable = |w: &Walk, j: Slot| {
            let jt = w.it(j);
            jt.dropped.is_none() && !jt.seeded && jt.verdict != Some(Verdict::Void) && jt.id.0 != lt.id.0
        };
        let alone: Vec<Slot> = before
            .into_iter()
            .filter(|&j| {
                let n = self.need(j, lt.e, self.it(j).how.is_none_or(|h| h == How::Flag));
                droppable(self, j) && !self.listed(l, j) && n.met(restored, rgrant) && !n.met(lt.after(), lt.after_grant())
            })
            .collect();
        let mut q: BTreeSet<Slot> = alone.iter().copied().collect();
        for j in alone {
            let jt = self.it(j);
            q.extend(self.commits.get(&jt.id.0).into_iter().flatten().copied().filter(|&x| self.it(x).on == jt.on && droppable(self, x)));
        }
        q.into_iter().collect()
    }

    /// Whether lowering `l` keeps its authority once `gone` is dropped (§5.1 step 4): every edge
    /// of its path keeps admin, read back along the parts the pass applied on it, latest first,
    /// passing over `gone`, self-removals still giving admin and grants that do not keep in turn.
    /// Each part's own check is made once; no later part is read and nothing is walked again.
    fn keeps(&mut self, l: Slot, gone: &BTreeSet<Slot>) -> bool {
        let mut memo: BTreeMap<Slot, bool> = BTreeMap::new();
        // per applied part passed over for good (gone, or a grant that does not keep): the
        // earliest part passed over in one run with it, so a later scan reads the run once
        let mut skip: BTreeMap<(E, Key), Key> = BTreeMap::new();
        // the part checked, the hop of it being read, and where on that hop's history
        let mut stack: Vec<(Slot, usize, Bound<Key>)> = vec![(l, 0, Excluded(self.it(l).key))];
        while let Some(&(w, hop, from)) = stack.last() {
            let (key, ts) = (self.it(w).key, self.it(w).ts);
            let Some(&e) = self.it(w).hops.get(hop) else {
                memo.insert(w, true);
                stack.pop();
                continue;
            };
            let mut upper = from;
            let mut passed: Vec<Key> = vec![];
            // whether the hop keeps admin, or the part whose own check comes first
            let decided = loop {
                let Some((k, en)) = self.ed(e).hist.range((Unbounded, upper)).next_back().map(|(k, en)| (*k, *en)) else { break Ok(self.ed(e).record) };
                self.counts.setters += 1;
                let admin = alive(en.a.value.as_ref(), ts) == ADMIN;
                let jt = self.it(en.slot);
                upper = Excluded(skip.get(&(e, k)).copied().unwrap_or(k));
                if gone.contains(&en.slot) || memo.get(&en.slot) == Some(&false) {
                    passed.push(k);
                    continue;
                }
                if jt.leave && admin {
                    passed.clear();
                    continue;
                }
                if jt.leave {
                    break Ok(false);
                }
                match memo.get(&en.slot) {
                    Some(true) => break Ok(admin),
                    _ if jt.lowering_shape() => break Ok(admin),
                    _ => break Err((en.slot, k)),
                }
            };
            if let Some(&to) = passed.last() {
                skip.extend(passed.into_iter().map(|k| ((e, k), to)));
            }
            let Some(top) = stack.last_mut() else { break };
            match decided {
                Ok(true) => *top = (w, hop + 1, Excluded(key)),
                Ok(false) => {
                    memo.insert(w, false);
                    stack.pop();
                }
                Err((j, k)) => {
                    top.2 = Included(k);
                    stack.push((j, 0, Excluded(self.it(j).key)));
                }
            }
        }
        memo.get(&l).copied().unwrap_or(false)
    }

    // ---- the chained pass (§4 Chained writes) ----

    /// The highest of levels `base..base + 4` a chained write before `k` set on `e`.
    fn chain_max(&self, e: E, base: usize, k: Key) -> Lvl {
        let ed = self.ed(e);
        if ed.record {
            return ADMIN;
        }
        Role::ALL.into_iter().rev().find(|&r| ed.chain.get(base + ri(r)).and_then(BTreeSet::first).is_some_and(|x| *x < k))
    }

    fn chain_judge(&self, s: Slot) -> bool {
        let it = self.it(s);
        if !it.well {
            return false;
        }
        let least = it.hops.iter().map(|&h| self.chain_max(h, 0, it.key)).min().unwrap_or(ADMIN);
        if it.finalize || it.leave {
            return least >= if it.finalize { Some(Role::Write) } else { ADMIN };
        }
        let flagged = || {
            let (Some(r), Some((&last, before))) = (it.flag_grant(), it.hops.split_last()) else { return false };
            self.chain_max(last, GRANT, it.key) >= Some(r) && before.iter().all(|&h| self.chain_max(h, 0, it.key) >= Some(r))
        };
        least == ADMIN || flagged()
    }

    /// Puts what chained part `s` sets in its edge's levels, or takes it out; whether it sets
    /// anything.
    fn chain_put(&mut self, s: Slot, on: bool) -> bool {
        let it = self.it(s).clone();
        let sets = if it.leave || it.finalize { [None; 2] } else { it.chain_sets() };
        for i in sets.into_iter().flatten() {
            if let Some(set) = self.edges[it.e].chain.get_mut(i) {
                if on { set.insert(it.key) } else { set.remove(&it.key) };
            }
        }
        sets != [None; 2]
    }

    /// Judges `todo` in key order, and after each part whose chained-ness moved the parts resting
    /// on the edge it sets.
    fn chain_fix(&mut self, mut todo: BTreeSet<(Key, Slot)>) {
        while let Some((k, s)) = todo.pop_first() {
            if !self.it(s).live || self.it(s).key != k {
                continue;
            }
            self.counts.chained += 1;
            let ch = self.chain_judge(s);
            if ch == self.it(s).chained {
                continue;
            }
            self.items[s].chained = ch;
            let (id, e) = (self.it(s).id, self.it(s).e);
            if !self.journal.chained.remove(&id) {
                self.journal.chained.insert(id);
            }
            if self.chain_put(s, ch) {
                todo.extend(self.ed(e).resting.range((Excluded((k, s)), Unbounded)).copied());
            }
        }
    }

    // ---- readings ----

    fn status_of(&self, s: Slot) -> Option<Status> {
        let it = self.it(s);
        Some(match it.how {
            _ if !it.live => return None,
            Some(How::Flag) => Status::MayGrant,
            Some(_) => Status::Applied,
            None if it.dropped.is_some() || it.seeded => Status::Dropped,
            None if it.verdict == Some(Verdict::Void) => Status::Void,
            None => Status::Unapplied,
        })
    }

    pub(super) fn status(&self, id: &WriteId) -> Option<Status> {
        self.ids.get(id).and_then(|&s| self.status_of(s))
    }

    pub(super) fn statuses(&self) -> BTreeMap<WriteId, Status> {
        self.ids.iter().filter_map(|(&id, &s)| Some((id, self.status_of(s)?))).collect()
    }

    pub(super) fn key_of(&self, id: &WriteId) -> Option<Key> {
        self.ids.get(id).map(|&s| self.it(s).key)
    }

    pub(super) fn is_chained(&self, id: &WriteId) -> Option<bool> {
        self.ids.get(id).map(|&s| self.it(s).chained)
    }

    fn entries(&self, holder: &Tid, target: &Tid) -> impl DoubleEndedIterator<Item = &Entry> + '_ {
        self.edge(holder, target).into_iter().flat_map(|e| e.hist.values())
    }

    pub(super) fn history(&self, holder: &Tid, target: &Tid) -> History {
        self.entries(holder, target).map(|en| (en.a.key, en.a.value)).collect()
    }

    pub(super) fn writes(&self, holder: &Tid, target: &Tid) -> Vec<Applied> {
        self.entries(holder, target).map(|en| en.a).collect()
    }

    /// Every edge with an applied write, and every record edge, with its history.
    pub(super) fn histories(&self) -> BTreeMap<(Tid, Tid), History> {
        self.edges.iter().filter(|e| e.record || !e.hist.is_empty()).map(|e| (e.name, e.hist.values().map(|en| (en.a.key, en.a.value)).collect())).collect()
    }

    pub(super) fn value_before(&self, holder: &Tid, target: &Tid, key: &Key) -> Option<Edge> {
        self.edge_ids.get(&(*holder, *target)).and_then(|&e| self.value(e, *key))
    }

    pub(super) fn role_before(&self, holder: &Tid, target: &Tid, key: &Key) -> Lvl {
        alive(self.value_before(holder, target, key).as_ref(), key.ts)
    }

    fn cuts(&self, holder: &Tid, target: &Tid, r: Role) -> Option<&BTreeSet<Key>> {
        self.edge(holder, target).and_then(|e| e.cuts.get(LEVELS.iter().position(|&l| l == r)?))
    }

    /// The key of the last cut of the edge below `r` (write or admin).
    pub(super) fn last_cut(&self, holder: &Tid, target: &Tid, r: Role) -> Option<Key> {
        self.cuts(holder, target, r)?.last().copied()
    }

    /// The cuts of the edge below `r` at or after `from`.
    pub(super) fn cuts_from(&self, holder: &Tid, target: &Tid, r: Role, from: &Key) -> Vec<WriteId> {
        let Some(e) = self.edge(holder, target) else { return vec![] };
        self.cuts(holder, target, r).into_iter().flat_map(|c| c.range(*from..)).filter_map(|k| e.hist.get(k)).map(|en| self.it(en.slot).id).collect()
    }

    /// The last applied write on the edge before `key`.
    pub(super) fn last_before(&self, holder: &Tid, target: &Tid, key: &Key) -> Option<(WriteId, Applied)> {
        self.edge(holder, target)?.hist.range(..*key).next_back().map(|(_, en)| (self.it(en.slot).id, en.a))
    }

    /// Whether held part `id` would apply at its key were its edge's value `old` there, the rest
    /// as the settled walk has it (§5.1 step 2; a lowering's judging is not run: a dropped or void
    /// part applies nowhere).
    pub(super) fn would_apply(&self, id: &WriteId, old: Option<Edge>) -> bool {
        let Some(it) = self.ids.get(id).map(|&s| self.it(s)) else { return false };
        if !it.live || !it.well || it.dropped.is_some() || it.seeded || it.verdict == Some(Verdict::Void) {
            return false;
        }
        let by = if it.finalize {
            old.filter(|g| g.until.is_some() && !g.alive_at(Some(it.ts))).is_some_and(|g| it.hops.iter().all(|&h| self.at(h, it.key, it.ts) >= Some(g.role.max(Role::Write))))
        } else {
            self.admin(it) || alive(old.as_ref(), it.ts).is_none() && self.may_grant(it)
        };
        by && !(it.leave && it.value.is_some_and(|n| !old.is_some_and(|o| leaves(&n, &o))))
    }

    /// The lowering whose drops hold part `id` (`None`: not dropped, or a trusted write's seed).
    pub(super) fn dropped_by(&self, id: &WriteId) -> Option<WriteId> {
        let it = self.it(*self.ids.get(id)?);
        it.dropped.filter(|_| it.live).map(|d| self.it(d).id)
    }

    /// How the settled walk applies part `id` (`None`: held, not applied; not held).
    pub(super) fn way(&self, id: &WriteId) -> Option<Way> {
        let it = self.it(*self.ids.get(id)?);
        Some(match it.how? {
            How::Admin if it.leave => Way::Leave,
            How::Admin => Way::Explicit,
            How::Flag => Way::MayGrant,
            How::Finalize => Way::Finalize,
        })
    }

    /// The edge as restored after every applied write (§5.1): what it gives and lets grant.
    pub(super) fn restored(&self, holder: &Tid, target: &Tid) -> (Lvl, Lvl) {
        let Some(ed) = self.edge(holder, target) else { return (None, None) };
        match ed.hist.values().next_back() {
            Some(en) => (en.restored, en.rgrant),
            None if ed.record => (ADMIN, ADMIN),
            None => (None, None),
        }
    }

    /// The last applied write on the edge.
    pub(super) fn last(&self, holder: &Tid, target: &Tid) -> Option<(WriteId, Applied)> {
        self.edge(holder, target)?.hist.values().next_back().map(|en| (self.it(en.slot).id, en.a))
    }

    /// Applied part `id`: its edge and what it found.
    pub(super) fn applied_write(&self, id: &WriteId) -> Option<((Tid, Tid), Applied)> {
        let it = self.it(*self.ids.get(id)?);
        let ed = self.ed(it.e);
        ed.hist.get(&it.key).map(|en| (ed.name, en.a))
    }

    /// The held edge-class parts of `commit`.
    pub(super) fn parts_of(&self, commit: &CommitId) -> Vec<WriteId> {
        self.commits.get(commit).into_iter().flatten().map(|&s| self.it(s).id).collect()
    }

    /// What `e` gives and lets grant in the end, every `until` counted removed.
    fn final_pair(&self, e: E) -> (Lvl, Lvl) {
        let ed = self.ed(e);
        let last = ed.hist.values().next_back().map_or(ed.record.then(|| Edge::new(Role::Admin)), |en| en.a.value);
        let v = last.filter(|v| v.until.is_none());
        (v.map(|v| v.role), grantable(v.map(|v| v.role), flag(v.as_ref())))
    }

    /// The final role of each edge the settled walk set (and each record edge), and what it lets
    /// grant.
    pub(super) fn finals(&self) -> BTreeMap<(Tid, Tid), (Lvl, Lvl)> {
        (0..self.edges.len()).filter(|&e| self.ed(e).record || !self.ed(e).hist.is_empty()).map(|e| (self.ed(e).name, self.final_pair(e))).collect()
    }

    pub(super) fn final_of(&self, holder: &Tid, target: &Tid) -> Lvl {
        self.edge_ids.get(&(*holder, *target)).and_then(|&e| self.final_pair(e).0)
    }

    /// Edge `e`'s first points for write and admin (§5.2 Re-grant): the key of the first held part
    /// setting it at the role or above (`until` disregarded) made by right; a record edge's is
    /// the start.
    fn firsts(&self, e: E) -> [Option<Key>; 2] {
        let ed = self.ed(e);
        LEVELS.map(|r| if ed.record { Some(FIRST) } else { ed.setters.iter().map(|&(_, s)| self.it(s)).find(|it| it.by_right && it.value.is_some_and(|v| v.role >= r)).map(|it| it.key) })
    }

    /// The edge's first point for `r` (write or admin).
    pub(super) fn first_by_right(&self, holder: &Tid, target: &Tid, r: Role) -> Option<Key> {
        let e = *self.edge_ids.get(&(*holder, *target))?;
        self.firsts(e).into_iter().zip(LEVELS).find(|x| x.1 == r)?.0
    }

    /// Per edge with one, its first points for write and for admin.
    pub(super) fn first_points(&self) -> BTreeMap<(Tid, Tid), [Option<Key>; 2]> {
        (0..self.edges.len()).map(|e| (self.ed(e).name, self.firsts(e))).filter(|(_, p)| p.iter().any(Option::is_some)).collect()
    }

    /// Per edge a chained write set (§4 Chained writes), the key of its first chained write giving
    /// write and giving admin, `until` disregarded.
    pub(super) fn chained(&self) -> BTreeMap<(Tid, Tid), [Option<Key>; 2]> {
        let first = |e: &EdgeInfo, r: Role| e.chain.iter().take(GRANT).skip(ri(r)).filter_map(BTreeSet::first).min().copied();
        self.edges.iter().map(|e| (e.name, LEVELS.map(|r| first(e, r)))).filter(|(_, f)| f.iter().any(Option::is_some)).collect()
    }

    /// The dispute candidates (§5.1 Trust set): the held lowerings of another holder's edge,
    /// not in `trust`, not dropped by a trusted write, that have a seed; each with whether its
    /// drops include another lowering of another holder's edge (a reach-back candidate).
    pub(super) fn candidates(&mut self, trust: &BTreeSet<WriteId>) -> Vec<(WriteId, bool)> {
        let slots: Vec<Slot> = self.ids.values().copied().collect();
        let contested = |w: &Self, s: Slot| w.it(s).lowering() && w.ed(w.it(s).e).name.0 != w.it(s).signer;
        let back: BTreeSet<Slot> = slots.iter().filter(|&&s| contested(self, s)).filter_map(|&s| self.it(s).dropped).collect();
        let mut out = vec![];
        for s in slots {
            let it = self.it(s);
            let by_trusted = it.seeded || it.dropped.is_some_and(|d| trust.contains(&self.it(d).id));
            let id = it.id;
            if contested(self, s) && !trust.contains(&id) && !by_trusted && !self.seeds_of(s).is_empty() {
                out.push((id, back.contains(&s)));
            }
        }
        out
    }

    /// Entries kept in memory: parts, edges, applied writes, events.
    pub(super) fn footprint(&self) -> u64 {
        let comps: usize = self.comps.values().map(|c| c.events.len()).sum();
        let edges: usize = self.edges.iter().map(|e| e.hist.len()).sum();
        (self.ids.len() + self.edges.len() as usize + edges + comps) as u64
    }
}

/// `n` lowers `o` in every component (§2 Self-removal): no role, may-grant flag or `until` above
/// it, no `floor` below it.
fn leaves(n: &Edge, o: &Edge) -> bool {
    let until = match (n.until, o.until) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(a), Some(b)) => a <= b,
    };
    n.role <= o.role && (!flag(Some(n)) || flag(Some(o))) && until && n.floor.unwrap_or(0) >= o.floor.unwrap_or(0)
}

/// A table indexed by `u32`, reading its nil element past its end: no index panics.
#[derive(Clone)]
struct Tab<V> {
    rows: Vec<V>,
    nil: V,
}

impl<V> Tab<V> {
    fn new(nil: V) -> Tab<V> {
        Tab { rows: vec![], nil }
    }
    fn len(&self) -> u32 {
        self.rows.len() as u32
    }
    fn push(&mut self, x: V) {
        self.rows.push(x);
    }
    fn iter(&self) -> std::slice::Iter<'_, V> {
        self.rows.iter()
    }
}

impl<V> std::ops::Index<u32> for Tab<V> {
    type Output = V;
    fn index(&self, i: u32) -> &V {
        self.rows.get(i as usize).unwrap_or(&self.nil)
    }
}

impl<V> std::ops::IndexMut<u32> for Tab<V> {
    fn index_mut(&mut self, i: u32) -> &mut V {
        self.rows.get_mut(i as usize).unwrap_or(&mut self.nil)
    }
}
