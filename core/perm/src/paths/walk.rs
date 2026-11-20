//! The walk itself (notes/perm-paths.md, One definition): the pass state with an undo
//! entry per applied part, and the event log of verdicts by reach, both per component of the
//! edges, so a restart, an update and a forget all roll a component's state back to a key and
//! continue there. Parts that can never apply (inert) are walked by no component.

use super::path::shape;
use super::{Changed, Commit, PartKind, Status};
use crate::types::{lowers, Edge, Frontier, WriteId};
use osis_base::{CommitId, Role, Tid, Ts};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Unbounded};
use std::sync::Arc;

/// A thing, interned.
type T = u32;
/// An edge (holder, target), interned.
type E = u32;
/// A part, by its place in `Walk::items`.
type Slot = u32;
/// An edge's history: the applied writes, in key order.
pub type History = Vec<(Key, Option<Edge>)>;

/// One applied write on an edge in the settled walk, with what it found there (draft §5.1:
/// content and the second walk read the value and the edge as restored before it).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Applied {
    pub key: Key,
    pub value: Option<Edge>,
    /// The edge's value just before it (its last change, else the record value, else none).
    pub before: Option<Edge>,
    /// An explicit write (draft §2): not a self-removal, a finalize or an invite grant.
    pub explicit: bool,
    /// The edge as restored just before it, in role and in invite (draft §5.1).
    pub restored: Option<Role>,
    pub restored_invite: Option<Role>,
}

impl Applied {
    /// A cut below `r` (draft §5.2): an explicit write whose value gives below `r` at its `ts` and
    /// that takes the edge, as restored, from `r` or above.
    pub fn cuts(&self, r: Role) -> bool {
        self.explicit && self.restored >= Some(r) && alive(self.value.as_ref(), self.key.ts) < Some(r)
    }
}

/// An applied write in the pass: its entry and its slot.
#[derive(Clone, Copy)]
struct Entry {
    a: Applied,
    slot: Slot,
}

/// The two levels a cut is counted at (draft §5.2: write, admin).
const LEVELS: [Role; 2] = [Role::Write, Role::Admin];
/// A part's place within its commit: (thing written, on the commit's own path, a vouch, holder):
/// the part setting an edge of the commit's own path after every other part on its thing, vouches
/// included, so no part's path is changed by an earlier part of its commit (draft §5.1 step 1).
type PartOrder = (Tid, bool, u8, Tid);
/// A role; `None` is no role.
type Lvl = Option<Role>;

const ADMIN: Lvl = Some(Role::Admin);

/// A part's position in the walk (draft §5.1 step 1): (`ts`, signer, commit ID), then its
/// place in the commit's order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Key {
    pub ts: Ts,
    pub signer: Tid,
    pub commit: CommitId,
    pub part: u32,
}

impl Key {
    pub(super) fn commit_start(self) -> Key {
        Key { part: 0, ..self }
    }
    /// The start of `ts` (draft §5.2 Position): before every part at that `ts`.
    pub fn start(ts: Ts) -> Key {
        Key { ts, signer: Tid::from_bytes([0; 15]), commit: CommitId([0; 32]), part: 0 }
    }
}

/// Work done, for the count tests (notes/perm-paths.md, Cost shapes).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Counts {
    /// Parts taken by a pass (each pass from where it started).
    pub steps: u64,
    /// Passes (a restart continues from its earliest drop, one pass each).
    pub passes: u64,
    /// Restarts: a lowering applied with drops.
    pub restarts: u64,
    /// Setters read by void checks (`keeps`).
    pub setters: u64,
    /// Parts resting on a lowered edge looked at by audits and seeds.
    pub audited: u64,
    /// Trust switches and void trusted rounds (each an update of the components it reaches).
    pub scratch: u64,
    /// Content (draft §5.2): edge reads, namers, addenda and snapshots looked at by delta
    /// queries.
    pub content: u64,
    /// Addenda judged and entries read by the addenda fixpoint.
    pub addenda: u64,
    /// Entries (parts, events, undo and chain entries, vouches) moved by component merges.
    pub merged: u64,
    /// Chained writes replayed by the chained pass.
    pub chained: u64,
}

impl Counts {
    /// The work done since `earlier`.
    pub fn since(&self, earlier: &Counts) -> Counts {
        Counts {
            steps: self.steps - earlier.steps,
            passes: self.passes - earlier.passes,
            restarts: self.restarts - earlier.restarts,
            setters: self.setters - earlier.setters,
            audited: self.audited - earlier.audited,
            scratch: self.scratch - earlier.scratch,
            content: self.content - earlier.content,
            addenda: self.addenda - earlier.addenda,
            merged: self.merged - earlier.merged,
            chained: self.chained - earlier.chained,
        }
    }

    pub(super) fn add(&mut self, o: &Counts) {
        self.steps += o.steps;
        self.passes += o.passes;
        self.restarts += o.restarts;
        self.setters += o.setters;
        self.audited += o.audited;
        self.scratch += o.scratch;
        self.content += o.content;
        self.addenda += o.addenda;
        self.merged += o.merged;
        self.chained += o.chained;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verdict {
    Applied,
    Void,
}

#[derive(Clone)]
struct EdgeItem {
    e: E,
    holder: T,
    value: Option<Edge>,
    frontier: Option<Arc<Frontier>>,
    remains: Option<E>,
    adminless: bool,
    finalize: bool,
    /// The path's last edge: its final hop where that joins Ak (the signer for an empty path)
    /// to the thing in one edge (draft §1 Path).
    last: Option<E>,
    /// The value it sets in the chained pass (draft §4): well, no self-removal, no finalize.
    sets: Option<Edge>,
}

#[derive(Clone)]
struct Item {
    key: Key,
    id: WriteId,
    ts: Ts,
    signer: T,
    on: T,
    /// The edges the walk reads as its path (none for a commit setting an edge twice).
    hops: Vec<E>,
    /// The stated path's edges, whatever the commit (the chained pass reads them).
    path: Vec<E>,
    /// Its members name no thing twice (and an edge-class part is not on its signer).
    shape_well: bool,
    /// As `shape_well`, and its commit sets no edge twice.
    well: bool,
    /// A self-removal: its path ends at the holder of the edge it sets.
    leave: bool,
    /// `None`: a vouch.
    edge: Option<EdgeItem>,
    /// A vouch's removal and list.
    vouch: Option<(CommitId, Frontier)>,
}

fn alive(v: Option<&Edge>, ts: Ts) -> Lvl {
    v.filter(|v| v.alive_at(Some(ts))).map(|v| v.role)
}

/// The invite a value gives: every invite at admin, else its field at most its role.
fn give_invite(role: Lvl, field: Lvl) -> Lvl {
    if role == ADMIN { ADMIN } else { field.min(role) }
}

/// A standing admin edge: admin, no `until`.
fn standing(v: Option<&Edge>) -> bool {
    v.is_some_and(|v| v.role == Role::Admin && v.until.is_none())
}

impl Item {
    fn nil() -> Item {
        let key = Key { ts: Ts::ZERO, signer: Tid::from_bytes([0; 15]), commit: CommitId([0; 32]), part: 0 };
        Item { key, id: WriteId(CommitId([0; 32]), 0), ts: Ts::ZERO, signer: T::MAX, on: T::MAX, hops: vec![], path: vec![], shape_well: false, well: false, leave: false, edge: None, vouch: None }
    }
    fn after(&self) -> Lvl {
        self.edge.as_ref().and_then(|ei| alive(ei.value.as_ref(), self.ts))
    }
    fn after_inv(&self) -> Lvl {
        give_invite(self.after(), self.edge.as_ref().and_then(|ei| ei.value.and_then(|v| v.invite)))
    }
    /// An edge write giving below admin at its `ts`, no finalize (a self-removal included).
    fn lowering_shape(&self) -> bool {
        self.edge.as_ref().is_some_and(|ei| !ei.finalize) && self.after() < ADMIN
    }
    /// A lowering (draft §5.1): an explicit write giving its edge below admin at its `ts`.
    fn lowering(&self) -> bool {
        self.lowering_shape() && !self.leave
    }
    /// The level of an edge write that may apply as an invite grant (draft §2): its role, below
    /// admin, alive at its `ts`, its invite at most its role.
    fn invite_level(&self) -> Lvl {
        let ei = self.edge.as_ref()?;
        let v = ei.value?;
        (!self.leave && !ei.finalize && v.invite <= Some(v.role) && v.role < Role::Admin && v.alive_at(Some(self.ts))).then_some(Some(v.role))?
    }
    fn finalize(&self) -> bool {
        self.edge.as_ref().is_some_and(|ei| ei.finalize)
    }
    /// The edges it rests on: its path's, and a self-removal's own.
    fn rests(&self) -> Vec<E> {
        let mut r = self.hops.clone();
        if let Some(ei) = self.edge.as_ref().filter(|_| self.leave) {
            r.push(ei.e);
        }
        r
    }
    /// The edges a non-inert part touches (notes/perm-paths.md, Components): its own, its stated
    /// path's and its remaining admin's.
    fn touches(&self) -> Vec<E> {
        let mut t: Vec<E> = self.edge.iter().map(|ei| ei.e).collect();
        t.extend(&self.path);
        t.extend(self.edge.as_ref().and_then(|ei| ei.remains));
        t
    }
}

/// What a part needs of one edge of its path.
#[derive(Clone, Copy)]
enum Need {
    Role(Lvl),
    Invite(Lvl),
}

impl Need {
    fn met(self, role: Lvl, invite: Lvl) -> bool {
        match self {
            Need::Role(r) => role >= r,
            Need::Invite(r) => invite >= r,
        }
    }
}

/// An applied part's change, undone by a rollback.
#[derive(Clone)]
struct Undo {
    slot: Slot,
    /// The edge it set and that edge's value and edge as restored before (none for a vouch).
    edge: Option<(E, Option<Option<Edge>>, Lvl, Lvl)>,
}

/// A chained set undone by a rollback of the chained pass: the edge, its levels and first keys
/// before.
type ChainUndo = (E, (Lvl, Lvl), [Option<Key>; 2]);

/// What a vouch is, for the counting rule (draft §5.1 Vouches): its key, thing, signer, removal
/// and list.
pub(super) struct VouchItem<'a> {
    pub id: WriteId,
    pub applied: bool,
    pub key: Key,
    pub on: Tid,
    pub signer: Tid,
    pub removal: CommitId,
    pub list: &'a Frontier,
}

/// A verdict given: the lowering's key and slot, its drops, and the inert parts its audit would
/// drop (counted, never walked).
#[derive(Clone)]
struct Event {
    key: Key,
    slot: Slot,
    drops: Vec<Slot>,
    inert: Vec<Slot>,
}

/// The lowering being judged, as the audit reads it.
struct Judging {
    slot: Slot,
    commit: CommitId,
    e: E,
    restored: Lvl,
    rinv: Lvl,
    after: Lvl,
    after_inv: Lvl,
}

/// How `setter_keeps` accepts the setter it stops at.
#[derive(Clone, Copy)]
enum Accept {
    /// It gives admin at this `ts` (an edge of a path keeping admin).
    AdminAt(Ts),
    /// It is a standing admin (the remaining admin staying standing).
    Standing,
}

/// One component (notes/perm-paths.md, Components): its parts in key order, its event log by
/// (reach, sequence), its undo stack by key, its chained writes and their undo by commit.
#[derive(Clone)]
struct Comp {
    /// Its edges: the union keeps the larger root.
    edges: u32,
    order: BTreeMap<Key, Slot>,
    log: BTreeMap<(Key, u64), Event>,
    /// The greatest key the walk had reached when giving its last kept event.
    reach: Option<Key>,
    undo: BTreeMap<Key, Undo>,
    chain: BTreeMap<Key, Slot>,
    chain_undo: BTreeMap<Key, Vec<ChainUndo>>,
    vouches: BTreeSet<Slot>,
    /// The first walk: its state is not this component's walk (it held no vouch when its input
    /// changed), so it is walked from its start once it holds one.
    stale: bool,
}

impl Comp {
    fn one() -> Comp {
        Comp { edges: 1, order: BTreeMap::new(), log: BTreeMap::new(), reach: None, undo: BTreeMap::new(), chain: BTreeMap::new(), chain_undo: BTreeMap::new(), vouches: BTreeSet::new(), stale: false }
    }
}

/// Moves the smaller map's entries into the larger, which `big` then holds; the entries moved.
fn absorb<K: Ord, V>(big: &mut BTreeMap<K, V>, mut small: BTreeMap<K, V>) -> u64 {
    if big.len() < small.len() {
        std::mem::swap(big, &mut small);
    }
    let n = small.len() as u64;
    big.extend(small);
    n
}

#[derive(Clone)]
pub(super) struct Walk {
    things: BTreeMap<Tid, T>,
    names: Tab<Tid>,
    edges: BTreeMap<(T, T), E>,
    ends: Tab<(T, T)>,
    /// Thing to mint admin (the records).
    mint: BTreeMap<Tid, Tid>,
    record: Tab<bool>,
    items: Tab<Item>,
    /// A forgotten part's slot (left nil once its component rolled it back: `graves`).
    dead: Tab<bool>,
    graves: Vec<Slot>,
    ids: BTreeMap<WriteId, Slot>,
    by_commit: BTreeMap<CommitId, Vec<Slot>>,
    /// Per edge, the walked parts resting on it: through it, or a self-removal of it.
    resting: Tab<BTreeSet<Slot>>,
    /// Per edge, the inert parts resting on it.
    inert_rest: Tab<BTreeSet<Slot>>,
    held: BTreeSet<CommitId>,
    /// The timeline: it walks every component and keeps the chained pass (content reads it). The
    /// first walk walks only the components holding a vouch (notes/perm-paths.md, Two walks).
    timeline: bool,
    /// Partitioning off (`Paths::single`, a test mode): every part walked, in one component.
    single: bool,
    /// The single component's first edge (`single` only).
    anchor: Option<E>,
    // ---- components ----
    /// The union-find over edges; a root names its component.
    parent: Tab<E>,
    comps: BTreeMap<E, Comp>,
    /// A record edge, or the own edge of a held non-inert write with a value.
    live: Tab<bool>,
    /// A part with a hop not live, or members naming a thing twice: it never applies.
    inert: Tab<bool>,
    /// Inert parts by an edge of their path not live.
    waiting: BTreeMap<E, Vec<Slot>>,
    /// Vouches by the removal they name, and by each commit they list.
    by_removal: BTreeMap<CommitId, BTreeSet<Slot>>,
    listing: BTreeMap<CommitId, BTreeSet<Slot>>,
    /// Per component, the earliest key to update from (walk and chained pass).
    dirty: BTreeMap<E, Key>,
    chain_dirty: BTreeMap<E, Key>,
    /// The components updated since `begin`.
    ran: BTreeSet<E>,
    // ---- trust ----
    /// The active trusted writes.
    trust: BTreeSet<Slot>,
    trusted_on: BTreeMap<E, BTreeSet<Slot>>,
    seeds: BTreeMap<Slot, BTreeSet<Slot>>,
    /// Per part, the active trusted writes seeding it.
    seeded: Tab<u32>,
    /// (removal, commit, thing) triples the counting vouch entries add to removals' lists, each
    /// naming the commit's parts on that thing alone: empty in the first walk, the counting entries
    /// in the second (draft §5.1 Vouches).
    vouched: BTreeSet<(CommitId, CommitId, Tid)>,
    // ---- carried from pass to pass ----
    verdict: Tab<Option<Verdict>>,
    /// The lowering whose audit dropped a walked part.
    dropped: Tab<Option<Slot>>,
    /// The lowerings whose audits would drop an inert part.
    inert_by: BTreeMap<Slot, BTreeSet<Slot>>,
    seq: u64,
    // ---- the pass ----
    /// The component being walked.
    cur: E,
    val: Tab<Option<Option<Edge>>>,
    restored: Tab<Lvl>,
    rinv: Tab<Lvl>,
    hist: Tab<Vec<Entry>>,
    /// Per edge, per level (`LEVELS`), the keys of its cuts in the pass, ascending.
    cuts: Tab<[Vec<Key>; 2]>,
    applied: Tab<bool>,
    invited: Tab<bool>,
    // ---- the chained pass (draft §4) ----
    /// Per edge the highest role and invite chained writes set (record edges: admin, implicit).
    level: Tab<(Lvl, Lvl)>,
    /// Per edge the first chained key giving write, and giving admin.
    first: Tab<[Option<Key>; 2]>,
    /// While an update runs: each part's status and each edge's history before it first changed.
    journal: Option<Journal>,
    pub(super) counts: Counts,
}

/// An edge's journal entry: the earliest key changed, its entries from there as they were, and
/// its final value before the update.
type Noted = (Key, Vec<Applied>, Option<Option<Edge>>);

#[derive(Clone, Default)]
struct Journal {
    parts: BTreeMap<Slot, Option<Status>>,
    /// Per edge: the earliest key changed, and the entries from it on as they were, with the
    /// final value before the update.
    edges: BTreeMap<E, Noted>,
    /// Per edge, its first chained keys before the update.
    chain: BTreeMap<E, [Option<Key>; 2]>,
}

impl Walk {
    pub(super) fn new(records: &BTreeMap<Tid, Tid>, timeline: bool, single: bool) -> Walk {
        let mut w = Walk {
            things: BTreeMap::new(),
            names: Tab::new(Tid::from_bytes([0; 15])),
            edges: BTreeMap::new(),
            ends: Tab::new((T::MAX, T::MAX)),
            mint: records.clone(),
            record: Tab::new(false),
            items: Tab::new(Item::nil()),
            dead: Tab::new(true),
            graves: vec![],
            ids: BTreeMap::new(),
            by_commit: BTreeMap::new(),
            resting: Tab::new(BTreeSet::new()),
            inert_rest: Tab::new(BTreeSet::new()),
            held: BTreeSet::new(),
            timeline,
            single,
            anchor: None,
            parent: Tab::new(E::MAX),
            comps: BTreeMap::new(),
            live: Tab::new(false),
            inert: Tab::new(true),
            waiting: BTreeMap::new(),
            by_removal: BTreeMap::new(),
            listing: BTreeMap::new(),
            dirty: BTreeMap::new(),
            chain_dirty: BTreeMap::new(),
            ran: BTreeSet::new(),
            trust: BTreeSet::new(),
            trusted_on: BTreeMap::new(),
            seeds: BTreeMap::new(),
            seeded: Tab::new(0),
            vouched: BTreeSet::new(),
            verdict: Tab::new(None),
            dropped: Tab::new(None),
            inert_by: BTreeMap::new(),
            seq: 0,
            cur: E::MAX,
            val: Tab::new(None),
            restored: Tab::new(None),
            rinv: Tab::new(None),
            hist: Tab::new(vec![]),
            cuts: Tab::new([vec![], vec![]]),
            applied: Tab::new(false),
            invited: Tab::new(false),
            level: Tab::new((None, None)),
            first: Tab::new([None, None]),
            journal: None,
            counts: Counts::default(),
        };
        for (thing, admin) in records {
            let (t, a) = (w.thing(thing), w.thing(admin));
            let e = w.edge(a, t);
            w.record[e] = true;
            w.live[e] = true;
            w.val[e] = Some(Some(Edge::new(Role::Admin)));
            w.restored[e] = ADMIN;
            w.rinv[e] = ADMIN;
        }
        w
    }

    fn thing(&mut self, t: &Tid) -> T {
        if let Some(&i) = self.things.get(t) {
            return i;
        }
        let i = self.names.len();
        self.things.insert(*t, i);
        self.names.push(*t);
        i
    }

    fn edge(&mut self, holder: T, target: T) -> E {
        if let Some(&e) = self.edges.get(&(holder, target)) {
            return e;
        }
        let e = self.ends.len();
        self.edges.insert((holder, target), e);
        self.ends.push((holder, target));
        self.record.push(false);
        self.resting.push(BTreeSet::new());
        self.inert_rest.push(BTreeSet::new());
        self.parent.push(e);
        self.live.push(false);
        self.val.push(None);
        self.restored.push(None);
        self.rinv.push(None);
        self.hist.push(vec![]);
        self.cuts.push([vec![], vec![]]);
        self.level.push((None, None));
        self.first.push([None, None]);
        e
    }

    fn find_edge(&self, holder: &Tid, target: &Tid) -> Option<E> {
        self.edges.get(&(*self.things.get(holder)?, *self.things.get(target)?)).copied()
    }

    fn intern(&mut self, e: (Tid, Tid)) -> E {
        let (h, t) = (self.thing(&e.0), self.thing(&e.1));
        self.edge(h, t)
    }

    // ---- components ----

    /// The root of edge `e`'s component.
    fn find(&self, mut e: E) -> E {
        while self.parent[e] != e && self.parent[e] != E::MAX {
            e = self.parent[e];
        }
        e
    }

    fn comp_mut(&mut self, root: E) -> &mut Comp {
        self.comps.entry(root).or_insert_with(Comp::one)
    }

    /// The component a walked part is in: its own edge's, else its path's first.
    fn home(&self, s: Slot) -> Option<E> {
        self.items[s].touches().first().map(|&e| self.find(e))
    }

    /// Joins the components of `a` and `b`: the smaller's maps move into the larger's; the root.
    fn union(&mut self, a: E, b: E) -> E {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra == rb {
            return ra;
        }
        let ca = self.comps.remove(&ra).unwrap_or_else(Comp::one);
        let cb = self.comps.remove(&rb).unwrap_or_else(Comp::one);
        let (root, other, mut big, small) = if ca.edges >= cb.edges { (ra, rb, ca, cb) } else { (rb, ra, cb, ca) };
        self.parent[other] = root;
        big.edges += small.edges;
        let mut n = absorb(&mut big.order, small.order);
        n += absorb(&mut big.log, small.log);
        n += absorb(&mut big.undo, small.undo);
        n += absorb(&mut big.chain, small.chain);
        let mut cu = small.chain_undo;
        if big.chain_undo.len() < cu.len() {
            std::mem::swap(&mut big.chain_undo, &mut cu);
        }
        for (k, mut v) in cu {
            n += v.len() as u64;
            big.chain_undo.entry(k).or_default().append(&mut v);
        }
        let mut vs = small.vouches;
        if big.vouches.len() < vs.len() {
            std::mem::swap(&mut big.vouches, &mut vs);
        }
        n += vs.len() as u64;
        big.vouches.extend(vs);
        big.reach = big.reach.max(small.reach);
        big.stale |= small.stale;
        self.counts.merged += n;
        self.comps.insert(root, big);
        for d in [&mut self.dirty, &mut self.chain_dirty] {
            if let Some(k) = d.remove(&other) {
                let m = d.get(&root).map_or(k, |&j: &Key| j.min(k));
                d.insert(root, m);
            }
        }
        root
    }

    /// The component `s` is updated in from its key.
    fn mark(&mut self, s: Slot) {
        if self.inert[s] || self.dead[s] {
            return;
        }
        let Some(c) = self.home(s) else { return };
        let k = self.items[s].key;
        let m = self.dirty.get(&c).map_or(k, |&j| j.min(k));
        self.dirty.insert(c, m);
    }

    // ---- input ----

    /// Compiles a commit's edge-class parts into items in key order (its deltas are content's);
    /// the slots made.
    fn compile(&mut self, c: &Commit) -> Vec<Slot> {
        let signer = self.thing(&c.signer);
        // (sort key, input index, item)
        let mut made: Vec<(PartOrder, u32, Item)> = vec![];
        for (ix, p) in (0u32..).zip(c.parts.iter()) {
            let holder = match &p.kind {
                PartKind::Edge(ew) => Some(ew.holder),
                PartKind::Vouch { .. } => None,
                PartKind::Delta(_) => continue,
            };
            let sh = shape(&self.mint, c.signer, &p.path, p.on, holder, true);
            let on = self.thing(&p.on);
            let hops: Vec<E> = sh.hops.iter().map(|&e| self.intern(e)).collect();
            // the part on an edge of the commit's own path comes last on its thing: a self-removal
            // of the path's last thing, or the final edge joining Ak to the thing
            let own = holder.is_some_and(|h| sh.leave || sh.final_hop == Some((h, p.on)));
            let (edge, vouch) = match &p.kind {
                PartKind::Edge(ew) => {
                    let h = self.thing(&ew.holder);
                    let e = self.edge(h, on);
                    let remains = ew.remains.map(|n| self.intern((n, p.on)));
                    let last = sh.last.map(|l| self.intern(l));
                    let finalize = ew.value.is_none() && ew.frontier.is_none() && !sh.leave && h != signer;
                    let ei = EdgeItem { e, holder: h, value: ew.value, frontier: ew.frontier.clone(), remains, adminless: ew.adminless, finalize, last, sets: ew.value.filter(|_| sh.well && !sh.leave && !finalize) };
                    (Some(ei), None)
                }
                PartKind::Vouch { removal, list } => (None, Some((*removal, list.clone()))),
                PartKind::Delta(_) => continue,
            };
            let sort = (p.on, own, u8::from(edge.is_none()), holder.unwrap_or(Tid::from_bytes([0; 15])));
            let key = Key { ts: c.ts, signer: c.signer, commit: c.id, part: 0 };
            let item = Item { key, id: WriteId(c.id, ix), ts: c.ts, signer, on, path: hops.clone(), hops, shape_well: sh.well, well: sh.well, leave: sh.leave, edge, vouch };
            made.push((sort, ix, item));
        }
        made.sort_by_key(|m| (m.0, m.1));
        // two parts on one holder's edge cannot be encoded: the commit is bad input
        let sets: Vec<E> = made.iter().filter_map(|m| m.2.edge.as_ref().map(|ei| ei.e)).collect();
        let twice = sets.iter().collect::<BTreeSet<_>>().len() < sets.len();
        let mut slots = vec![];
        for (n, (_, _, mut it)) in (0u32..).zip(made) {
            it.key.part = n;
            if twice {
                it.well = false;
                it.hops.clear();
            }
            let s = self.items.len();
            self.ids.insert(it.id, s);
            self.by_commit.entry(c.id).or_default().push(s);
            if let Some((removal, list)) = &it.vouch {
                self.by_removal.entry(*removal).or_default().insert(s);
                for x in list.commits() {
                    self.listing.entry(*x).or_default().insert(s);
                }
            }
            self.items.push(it);
            self.dead.push(false);
            self.inert.push(true);
            self.verdict.push(None);
            self.dropped.push(None);
            self.seeded.push(0);
            self.applied.push(false);
            self.invited.push(false);
            slots.push(s);
        }
        slots
    }

    /// Takes in the commits not held yet (journalling the new parts): each part is inert or joins
    /// its component, which is then updated from its key.
    pub(super) fn take(&mut self, commits: &[Commit]) {
        for c in commits {
            if !self.held.insert(c.id) {
                continue;
            }
            let slots = self.compile(c);
            // a commit with no edge-class part is content's alone
            if slots.is_empty() {
                self.held.remove(&c.id);
            }
            for s in slots {
                self.note_new(s);
                self.place(s);
            }
        }
    }

    /// Places a new part: inert where a hop is not live (it waits on it), else walked; its seeds.
    fn place(&mut self, s: Slot) {
        let it = &self.items[s];
        let dead: Vec<E> = it.path.iter().copied().filter(|&e| !self.live[e]).collect();
        let rests = it.rests();
        if !self.single && (!it.shape_well || !dead.is_empty()) {
            for e in dead {
                self.waiting.entry(e).or_default().push(s);
            }
            for e in rests {
                self.inert_rest[e].insert(s);
            }
        } else {
            self.activate(s);
        }
        // the active trusted writes on an edge it rests on seed it where it is theirs
        let rs: Vec<Slot> = self.items[s].rests().into_iter().filter_map(|e| self.trusted_on.get(&e)).flatten().copied().collect();
        for r in rs {
            if self.seeds_it(r, s) && self.seeds.entry(r).or_default().insert(s) {
                self.seed(s, 1);
            }
        }
    }

    /// Walks part `s` from now on: it joins its touched edges' components (and, a vouch, its
    /// removal's; an edge write, the vouches naming its commit), and its own edge turns live,
    /// waking the inert parts that waited on it, in turn.
    fn activate(&mut self, s: Slot) {
        let mut todo = vec![s];
        while let Some(s) = todo.pop() {
            self.inert[s] = false;
            let it = self.items[s].clone();
            let touch = it.touches();
            let Some(&a) = touch.first() else { continue };
            let mut root = self.find(a);
            for &e in &touch {
                root = self.union(root, e);
            }
            if self.single {
                match self.anchor {
                    Some(x) => root = self.union(root, x),
                    None => self.anchor = Some(root),
                }
            }
            // a counting entry makes a removal's list read the vouch's verdict
            let partners: Vec<Slot> = match &it.vouch {
                Some((removal, _)) => self.by_commit.get(removal).into_iter().flatten().copied().collect(),
                None => self.by_removal.get(&it.key.commit).into_iter().flatten().copied().collect(),
            };
            for p in partners {
                if !self.inert[p]
                    && let Some(&b) = self.items[p].touches().first()
                {
                    root = self.union(root, b);
                }
            }
            for e in it.rests() {
                self.inert_rest[e].remove(&s);
                self.resting[e].insert(s);
            }
            let comp = self.comp_mut(root);
            comp.order.insert(it.key, s);
            if it.vouch.is_some() {
                comp.vouches.insert(s);
            }
            let chained = it.edge.as_ref().is_some_and(|ei| ei.sets.is_some());
            if self.timeline && chained {
                self.comp_mut(root).chain.insert(it.key, s);
                let m = self.chain_dirty.get(&root).map_or(it.key, |&j| j.min(it.key));
                self.chain_dirty.insert(root, m);
            }
            self.mark(s);
            // its own edge turns live: wake what waited on it
            if let Some(ei) = it.edge.as_ref().filter(|ei| ei.value.is_some() && !self.live[ei.e]) {
                self.live[ei.e] = true;
                for j in self.waiting.remove(&ei.e).unwrap_or_default() {
                    let jt = &self.items[j];
                    if self.inert[j] && !self.dead[j] && jt.shape_well && jt.path.iter().all(|&h| self.live[h]) {
                        // it was walked by no component: its inert droppers go with the events
                        // its component forgets from its key
                        self.note_part(j);
                        self.inert[j] = false;
                        todo.push(j);
                    }
                }
            }
        }
    }

    /// Forgets the commits held (notes/perm-paths.md, Forget): each walked part leaves at its key,
    /// its component updated from there; an inert one leaves its indexes.
    pub(super) fn forget(&mut self, commits: &[CommitId]) {
        for c in commits {
            if !self.held.remove(c) {
                continue;
            }
            for s in self.by_commit.remove(c).unwrap_or_default() {
                self.note_part(s);
                if self.trust.contains(&s) {
                    self.untrust(s);
                }
                let it = self.items[s].clone();
                if !self.inert[s] {
                    self.mark(s);
                    if let Some(root) = self.home(s) {
                        let comp = self.comp_mut(root);
                        comp.order.remove(&it.key);
                        comp.vouches.remove(&s);
                        if comp.chain.remove(&it.key).is_some() {
                            let m = self.chain_dirty.get(&root).map_or(it.key, |&j| j.min(it.key));
                            self.chain_dirty.insert(root, m);
                        }
                    }
                }
                for e in it.rests() {
                    self.resting[e].remove(&s);
                    self.inert_rest[e].remove(&s);
                    if let Some(rs) = self.trusted_on.get(&e).cloned() {
                        for r in rs {
                            if self.seeds.get_mut(&r).is_some_and(|x| x.remove(&s)) {
                                self.seeded[s] = self.seeded[s].saturating_sub(1);
                            }
                        }
                    }
                }
                for e in &it.path {
                    if let Some(w) = self.waiting.get_mut(e) {
                        w.retain(|&j| j != s);
                    }
                }
                if let Some((removal, list)) = &it.vouch {
                    if let Some(v) = self.by_removal.get_mut(removal) {
                        v.remove(&s);
                    }
                    for x in list.commits() {
                        if let Some(v) = self.listing.get_mut(x) {
                            v.remove(&s);
                        }
                    }
                }
                self.ids.remove(&it.id);
                self.inert_by.remove(&s);
                self.dead[s] = true;
                self.graves.push(s);
            }
        }
    }

    /// Drops the forgotten parts' remains once their components rolled them back.
    fn bury(&mut self) {
        for s in std::mem::take(&mut self.graves) {
            self.items[s] = Item::nil();
            self.verdict[s] = None;
            self.dropped[s] = None;
            self.seeded[s] = 0;
            self.applied[s] = false;
            self.invited[s] = false;
        }
    }

    /// Runs every component an input change reached from its earliest key (the walk and the
    /// chained pass); the components run join `ran`.
    pub(super) fn run_dirty(&mut self) {
        for (c, mut p) in std::mem::take(&mut self.dirty) {
            if !self.timeline {
                let comp = self.comp_mut(c);
                if comp.vouches.is_empty() {
                    comp.stale = true;
                    continue;
                }
                if std::mem::take(&mut comp.stale) {
                    p = Key::start(Ts::ZERO);
                }
            }
            let x = self.cut(c, p);
            self.run(c, x.commit_start());
            self.ran.insert(c);
        }
        for (c, p) in std::mem::take(&mut self.chain_dirty) {
            self.chain_from(c, p);
        }
        self.bury();
    }

    /// Whether an input change waits to be walked.
    pub(super) fn is_dirty(&self) -> bool {
        !self.dirty.is_empty() || !self.chain_dirty.is_empty()
    }

    /// The components waiting to be walked, and those walked since `begin`.
    pub(super) fn touched(&self) -> BTreeSet<E> {
        self.dirty.keys().chain(self.ran.iter()).map(|&c| self.find(c)).collect()
    }

    /// Whether a commit with edge-class parts is held.
    pub(super) fn holds(&self, c: &CommitId) -> bool {
        self.held.contains(c)
    }

    /// The component a held part is in (its own edge's for an inert edge write).
    pub(super) fn comp_of(&self, id: &WriteId) -> Option<E> {
        let s = *self.ids.get(id)?;
        self.items[s].edge.as_ref().map(|ei| self.find(ei.e)).or_else(|| self.home(s).filter(|_| !self.inert[s]))
    }

    /// Forgets component `c`'s events reaching `p` or past it (notes/perm-paths.md, The event log
    /// by reach); the key to roll back to: the earliest of `p` and those events' keys and drops.
    fn cut(&mut self, c: E, p: Key) -> Key {
        let comp = self.comp_mut(c);
        let later = comp.log.split_off(&(p, 0));
        comp.reach = comp.log.last_key_value().map(|(k, _)| k.0);
        let mut x = p;
        for (_, ev) in later {
            x = x.min(ev.key);
            self.set_verdict(ev.slot, None);
            for d in ev.drops {
                x = x.min(self.items[d].key);
                self.set_dropped(d, None);
            }
            for j in ev.inert {
                self.note_part(j);
                if let Some(by) = self.inert_by.get_mut(&j) {
                    by.remove(&ev.slot);
                    if by.is_empty() {
                        self.inert_by.remove(&j);
                    }
                }
            }
        }
        x
    }

    /// Starts journalling an update.
    pub(super) fn begin(&mut self) {
        self.journal = Some(Journal::default());
        self.ran.clear();
    }

    /// Sets the counting entries' pairs (the second walk): each held removal whose list they
    /// change is walked again from its key, and its seeds are read again where it is trusted.
    pub(super) fn set_vouched(&mut self, vouched: BTreeSet<(CommitId, CommitId, Tid)>) {
        let changed: BTreeSet<CommitId> = self.vouched.symmetric_difference(&vouched).map(|p| p.0).collect();
        self.vouched = vouched;
        for r in changed {
            for s in self.by_commit.get(&r).cloned().unwrap_or_default() {
                self.mark(s);
                if self.trust.contains(&s) {
                    self.reseed(s);
                }
            }
        }
    }

    // ---- trust (draft §5.1 Trust set) ----

    /// Sets the active trusted writes: each one activated or put aside changes its seeds.
    pub(super) fn set_active(&mut self, active: &BTreeSet<WriteId>) {
        let want: BTreeSet<Slot> = active.iter().filter_map(|id| self.ids.get(id).copied()).filter(|&s| self.items[s].edge.is_some()).collect();
        for r in self.trust.difference(&want).copied().collect::<Vec<_>>() {
            self.untrust(r);
        }
        for r in want.difference(&self.trust).copied().collect::<Vec<_>>() {
            self.trust.insert(r);
            if let Some(ei) = &self.items[r].edge {
                self.trusted_on.entry(ei.e).or_default().insert(r);
            }
            self.reseed(r);
            // its own status may change with no seed moving: its component is walked again
            self.mark(r);
        }
    }

    fn untrust(&mut self, r: Slot) {
        self.trust.remove(&r);
        if let Some(ei) = &self.items[r].edge
            && let Some(t) = self.trusted_on.get_mut(&ei.e)
        {
            t.remove(&r);
        }
        for j in self.seeds.remove(&r).unwrap_or_default() {
            self.seed(j, -1);
        }
        self.mark(r);
    }

    /// Reads trusted write `r`'s seeds again: the held parts of other commits ordered before it,
    /// resting on its edge, that its list does not name, whose least need there its value does
    /// not meet.
    fn reseed(&mut self, r: Slot) {
        let Some(e) = self.items[r].edge.as_ref().map(|ei| ei.e) else { return };
        let cands: Vec<Slot> = self.resting[e].iter().chain(self.inert_rest[e].iter()).copied().collect();
        let mut now = BTreeSet::new();
        for j in cands {
            self.counts.audited += 1;
            if self.seeds_it(r, j) {
                now.insert(j);
            }
        }
        let was = self.seeds.insert(r, now.clone()).unwrap_or_default();
        for &j in was.difference(&now) {
            self.seed(j, -1);
        }
        for &j in now.difference(&was) {
            self.seed(j, 1);
        }
    }

    fn seeds_it(&self, r: Slot, j: Slot) -> bool {
        let it = &self.items[r];
        let Some(ei) = &it.edge else { return false };
        let jt = &self.items[j];
        jt.key < it.key && jt.key.commit != it.key.commit && !self.listed(r, j) && !self.need(j, ei.e, true).met(it.after(), it.after_inv())
    }

    /// Counts a seed of `j` up or down; a walked part's component is walked again from its key.
    fn seed(&mut self, j: Slot, by: i32) {
        self.note_part(j);
        let was = self.seeded[j];
        self.seeded[j] = if by > 0 { was + 1 } else { was.saturating_sub(1) };
        if (was == 0) != (self.seeded[j] == 0) {
            self.mark(j);
        }
    }

    /// The active trusted writes the walk does not apply.
    pub(super) fn unapplied_trusted(&self) -> Vec<WriteId> {
        self.trust.iter().filter(|&&s| !self.applied[s]).map(|&s| self.items[s].id).collect()
    }

    // ---- what changed: a journal of first values, kept while an update runs ----

    fn note_new(&mut self, s: Slot) {
        if let Some(j) = &mut self.journal {
            j.parts.insert(s, None);
        }
    }

    fn note_part(&mut self, s: Slot) {
        if self.journal.as_ref().is_some_and(|j| !j.parts.contains_key(&s)) {
            let st = self.status_of(s);
            if let Some(j) = &mut self.journal {
                j.parts.insert(s, st);
            }
        }
    }

    /// Before `hist[e]` changes at `k`: keeps its entries from `k` on as they were (entries
    /// before the earliest change noted are untouched, so the copy only grows downward).
    fn note_edge(&mut self, e: E, k: Key) {
        let Some(j) = &mut self.journal else { return };
        let h = &self.hist[e];
        let from = h.partition_point(|y| y.a.key < k);
        match j.edges.get_mut(&e) {
            None => {
                j.edges.insert(e, (k, h.iter().skip(from).map(|y| y.a).collect(), self.val[e]));
            }
            Some((kmin, old, _)) if k < *kmin => {
                let upto = h.partition_point(|y| y.a.key < *kmin);
                let mut head: Vec<Applied> = h.iter().skip(from).take(upto.saturating_sub(from)).map(|y| y.a).collect();
                head.append(old);
                *old = head;
                *kmin = k;
            }
            Some(_) => {}
        }
    }

    fn set_verdict(&mut self, s: Slot, v: Option<Verdict>) {
        self.note_part(s);
        self.verdict[s] = v;
    }

    fn set_dropped(&mut self, s: Slot, d: Option<Slot>) {
        self.note_part(s);
        self.dropped[s] = d;
    }

    /// What the update changed, from the journal: parts, history (from the first key that
    /// differs), cuts (the latest key of a cut added or removed), final roles and first chained
    /// points (`regrant`).
    pub(super) fn changed(&mut self) -> Changed {
        let Some(j) = self.journal.take() else { return Changed::default() };
        let mut out = Changed::default();
        for (s, was) in j.parts {
            if !self.dead[s] && was != self.status_of(s) {
                out.parts.insert(self.items[s].id);
            }
        }
        for (e, (kmin, old, was)) in j.edges {
            let h = &self.hist[e];
            let now: Vec<Applied> = h.iter().skip(h.partition_point(|y| y.a.key < kmin)).map(|y| y.a).collect();
            let name = self.name(e);
            let at = old.iter().zip(&now).position(|(p, q)| (p.key, p.value) != (q.key, q.value)).unwrap_or(old.len().min(now.len()));
            if let Some(k) = old.get(at).map(|p| p.key).into_iter().chain(now.get(at).map(|q| q.key)).min() {
                out.edges.insert(name, k);
            }
            let cut_keys = |v: &[Applied]| -> BTreeSet<(Key, [bool; 2])> { v.iter().map(|a| (a.key, LEVELS.map(|r| a.cuts(r)))).filter(|c| c.1 != [false, false]).collect() };
            if let Some(k) = cut_keys(&old).symmetric_difference(&cut_keys(&now)).map(|c| c.0).max() {
                out.cuts.insert(name, k);
            }
            if final_role(was) != final_role(self.val[e]) {
                out.regrant.insert(name);
            }
        }
        for (e, was) in j.chain {
            if self.first[e] != was {
                out.regrant.insert(self.name(e));
            }
        }
        out
    }

    fn name(&self, e: E) -> (Tid, Tid) {
        let (h, t) = self.ends[e];
        (self.names[h], self.names[t])
    }

    // ---- the walk ----

    /// Runs component `c`'s passes from `from` until one adds nothing to D; a pass ending at a
    /// lowering whose drops joined D continues from its earliest drop's commit, the state rolled
    /// back there.
    fn run(&mut self, c: E, mut from: Key) {
        self.cur = c;
        loop {
            self.rollback(c, from);
            self.counts.passes += 1;
            match self.pass(c, from) {
                Some(r) => {
                    from = r.commit_start();
                    self.counts.restarts += 1;
                }
                None => return,
            }
        }
    }

    fn rollback(&mut self, c: E, x: Key) {
        let tail = self.comp_mut(c).undo.split_off(&x);
        for (k, u) in tail.into_iter().rev() {
            self.note_part(u.slot);
            if let Some((e, ..)) = u.edge {
                self.note_edge(e, k);
            }
            self.applied[u.slot] = false;
            self.invited[u.slot] = false;
            if let Some((e, v, r, ri)) = u.edge {
                self.val[e] = v;
                self.restored[e] = r;
                self.rinv[e] = ri;
                if let Some(y) = self.hist[e].pop() {
                    for (n, lvl) in LEVELS.into_iter().enumerate() {
                        if y.a.cuts(lvl)
                            && let Some(c) = self.cuts[e].get_mut(n)
                        {
                            c.pop();
                        }
                    }
                }
            }
        }
    }

    /// One pass of component `c` from `from`; the earliest drop's key where a commit's lowerings
    /// dropped something.
    fn pass(&mut self, c: E, from: Key) -> Option<Key> {
        let mut cur: Option<CommitId> = None;
        let mut cdrops: Vec<Slot> = vec![];
        let next_of = |w: &Walk, k: Option<Key>| -> Option<(Key, Slot)> {
            let comp = w.comps.get(&c)?;
            match k {
                None => comp.order.range(from..).next(),
                Some(k) => comp.order.range((Excluded(k), Unbounded)).next(),
            }
            .map(|(k, s)| (*k, *s))
        };
        let mut next = next_of(self, None);
        while let Some((k, s)) = next {
            if cur != Some(k.commit) {
                if !cdrops.is_empty() {
                    return cdrops.iter().map(|&d| self.items[d].key).min();
                }
                cur = Some(k.commit);
            }
            if self.dropped[s].is_none() && self.seeded[s] == 0 {
                self.counts.steps += 1;
                self.step(s, &mut cdrops);
            }
            next = next_of(self, Some(k));
        }
        cdrops.iter().map(|&d| self.items[d].key).min()
    }

    fn at(&self, e: E, ts: Ts) -> Lvl {
        self.val[e].and_then(|v| alive(v.as_ref(), ts))
    }

    fn invite_at(&self, e: E, ts: Ts) -> Lvl {
        give_invite(self.at(e, ts), self.val[e].flatten().and_then(|v| v.invite))
    }

    /// `r`'s list names `j` (draft §5.1): its frontier, or (the second walk) a counting entry on
    /// `j`'s thing.
    fn listed(&self, r: Slot, j: Slot) -> bool {
        let c = self.items[j].key.commit;
        self.items[r].edge.as_ref().and_then(|ei| ei.frontier.as_ref()).is_some_and(|f| f.covers(&c)) || self.vouched.contains(&(self.items[r].key.commit, c, self.names[self.items[j].on]))
    }

    /// What part `j` needs of edge `e` it rests on (draft §5.1 step 3): an invite grant (applied
    /// as one, or, `as_invite`, one that may) its level as an invite where `e` is its path's last
    /// edge and as a role elsewhere; a finalize write; any other admin.
    fn need(&self, j: Slot, e: E, as_invite: bool) -> Need {
        let it = &self.items[j];
        match it.invite_level() {
            Some(r) if as_invite && it.hops.last() == Some(&e) => Need::Invite(Some(r)),
            Some(r) if as_invite => Need::Role(Some(r)),
            _ if it.finalize() => Need::Role(Some(Role::Write)),
            _ => Need::Role(ADMIN),
        }
    }

    fn rests_on(&self, j: Slot, e: E) -> bool {
        let it = &self.items[j];
        it.hops.contains(&e) || (it.leave && it.edge.as_ref().is_some_and(|ei| ei.e == e))
    }

    /// Whether lowering `l` puts `j` in question and drops it: of another commit, resting on
    /// its edge, not named by its list, its need there met as restored and not by the new value.
    fn gone(&self, l: &Judging, j: Slot) -> bool {
        let it = &self.items[j];
        if it.key.commit == l.commit || !self.rests_on(j, l.e) || self.listed(l.slot, j) {
            return false;
        }
        let n = self.need(j, l.e, self.invited[j] || !self.applied[j]);
        n.met(l.restored, l.rinv) && !n.met(l.after, l.after_inv)
    }

    /// The last-admin rule (draft §1): `None` where it stops the write; else the remaining admin
    /// edge it relies on, if any.
    fn remains(&self, s: Slot) -> Option<Option<E>> {
        let it = &self.items[s];
        let Some(ei) = &it.edge else { return Some(None) };
        if ei.adminless {
            return Some(None);
        }
        let old = self.val[ei.e].flatten();
        if !standing(old.as_ref()) || standing(ei.value.as_ref()) {
            return Some(None);
        }
        let ok = |x: E| x != ei.e && standing(self.val[x].flatten().as_ref());
        if let Some(l) = ei.last.filter(|&l| ok(l)) {
            return Some(Some(l));
        }
        ei.remains.filter(|&x| ok(x)).map(Some)
    }

    fn log_event(&mut self, ev: Event) {
        let c = self.cur;
        self.seq += 1;
        let seq = self.seq;
        let comp = self.comp_mut(c);
        let reach = comp.reach.map_or(ev.key, |r| r.max(ev.key));
        comp.reach = Some(reach);
        comp.log.insert((reach, seq), ev);
    }

    /// Takes part `s` in the pass (draft §5.1 steps 2 and 3).
    fn step(&mut self, s: Slot, cdrops: &mut Vec<Slot>) {
        let it = &self.items[s];
        let ts = it.ts;
        let judged = if it.lowering() { self.verdict[s] } else { None };
        let mut as_invite = false;
        let mut as_finalize = false;
        match judged {
            Some(Verdict::Applied) => {
                // applied for good where it takes its edge as restored down or keeps it; where it
                // would raise it, only by admin along its path
                if let Some(ei) = &it.edge {
                    let e = ei.e;
                    let raises = it.after() > self.restored[e].max(self.at(ei.e, ts)) || it.after_inv() > self.rinv[e].max(self.invite_at(ei.e, ts));
                    if raises && !it.hops.iter().all(|&h| self.at(h, ts) == ADMIN) {
                        return;
                    }
                }
            }
            Some(Verdict::Void) => return,
            None => {
                if !it.well {
                    return;
                }
                let path_role = it.hops.iter().map(|&h| self.at(h, ts)).min().unwrap_or(ADMIN);
                match &it.edge {
                    Some(ei) if ei.finalize => {
                        // it ends a grant past its `until`, along a path giving write and the
                        // grant's role
                        let old = self.val[ei.e].flatten();
                        let ended = old.is_some_and(|v| !v.alive_at(Some(ts)));
                        if !(ended && path_role >= old.map(|v| v.role).max(Some(Role::Write))) {
                            return;
                        }
                        as_finalize = true;
                    }
                    _ if path_role == ADMIN => {}
                    Some(ei) => {
                        // an invite grant: a holder with no current grant, its level within the
                        // path's invite (the roles before the last edge, the last edge's invite)
                        let Some(lvl) = it.invite_level() else { return };
                        let Some((last, before)) = it.hops.split_last() else { return };
                        if self.at(ei.e, ts).is_some() || !before.iter().all(|&h| self.at(h, ts) >= Some(lvl)) || self.invite_at(*last, ts) < Some(lvl) {
                            return;
                        }
                        as_invite = true;
                    }
                    None => return,
                }
            }
        }
        let key = it.key;
        let c = self.cur;
        let Some(ei) = it.edge.clone() else {
            self.note_part(s);
            self.applied[s] = true;
            self.comp_mut(c).undo.insert(key, Undo { slot: s, edge: None });
            return;
        };
        let leave = it.leave;
        let explicit = !leave && !as_invite && !as_finalize;
        let relied = if judged.is_none() && !as_invite && !as_finalize {
            match self.remains(s) {
                None => return,
                Some(r) => r,
            }
        } else {
            None
        };
        let e = ei.e;
        let old = self.val[e].flatten();
        // a self-removal only lowers (draft §2)
        if leave && !lowers(ei.value.as_ref(), old.as_ref()) {
            return;
        }
        let restored = self.restored[e].max(self.at(ei.e, ts));
        let rinv = self.rinv[e].max(self.invite_at(ei.e, ts));
        let (after, after_inv) = (it.after(), it.after_inv());
        let falls = restored > after || rinv > after_inv;
        let mut q = vec![];
        let mut qi = vec![];
        if judged.is_none() && explicit && falls {
            let l = Judging { slot: s, commit: key.commit, e: ei.e, restored, rinv, after, after_inv };
            let mut chk = Check::default();
            let kept = self.keeps(&l, cdrops, s, &mut chk) && relied.is_none_or(|r| self.setter_keeps(&l, cdrops, r, key, Accept::Standing, &mut chk));
            if !kept {
                self.set_verdict(s, Some(Verdict::Void));
                self.log_event(Event { key, slot: s, drops: vec![], inert: vec![] });
                return;
            }
            for &j in &self.resting[e] {
                self.counts.audited += 1;
                if self.items[j].key < key && self.dropped[j].is_none() && self.seeded[j] == 0 && self.verdict[j] != Some(Verdict::Void) && self.gone(&l, j) {
                    q.push(j);
                }
            }
            for &j in &self.inert_rest[e] {
                self.counts.audited += 1;
                if self.items[j].key < key && self.gone(&l, j) {
                    qi.push(j);
                }
            }
            self.set_verdict(s, Some(Verdict::Applied));
            self.log_event(Event { key, slot: s, drops: q.clone(), inert: qi.clone() });
        }
        self.note_part(s);
        self.note_edge(ei.e, key);
        let u = Undo { slot: s, edge: Some((ei.e, self.val[e], self.restored[e], self.rinv[e])) };
        self.comp_mut(c).undo.insert(key, u);
        let a = Applied { key, value: ei.value, before: self.val[e].flatten(), explicit, restored, restored_invite: rinv };
        for (n, lvl) in LEVELS.into_iter().enumerate() {
            if a.cuts(lvl)
                && let Some(c) = self.cuts[e].get_mut(n)
            {
                c.push(key);
            }
        }
        self.val[e] = Some(ei.value);
        if explicit {
            self.restored[e] = ei.value.map(|v| v.role);
            self.rinv[e] = after_inv;
        } else if as_invite {
            self.restored[e] = self.restored[e].max(ei.value.map(|v| v.role));
            self.rinv[e] = self.rinv[e].max(after_inv);
            self.invited[s] = true;
        }
        self.hist[e].push(Entry { a, slot: s });
        self.applied[s] = true;
        for j in q {
            self.set_dropped(j, Some(s));
            cdrops.push(j);
        }
        for j in qi {
            self.note_part(j);
            self.inert_by.entry(j).or_default().insert(s);
        }
    }

    // ---- the chained pass (draft §4 Chained writes) ----

    /// Rolls component `c`'s chained pass back to `p` and replays its chained writes from there,
    /// commit by commit: a write is chained where every edge of its path is a record edge or set
    /// at admin by a chained write of an earlier commit (an invite grant: its role on each edge
    /// but the last, an invite of it on the last); a chained write sets its edge at the role and
    /// invite it sets, `until` disregarded.
    fn chain_from(&mut self, c: E, p: Key) {
        let p = p.commit_start();
        let tail = self.comp_mut(c).chain_undo.split_off(&p);
        for (_, us) in tail.into_iter().rev() {
            for (e, lv, fi) in us.into_iter().rev() {
                self.chain_note(e);
                self.level[e] = lv;
                self.first[e] = fi;
            }
        }
        let todo: Vec<(Key, Slot)> = self.comps.get(&c).map(|x| x.chain.range(p..).map(|(k, s)| (*k, *s)).collect()).unwrap_or_default();
        let mut i = 0;
        while i < todo.len() {
            let commit = todo.get(i).map(|t| t.0.commit);
            let mut sets: Vec<(Key, E, Edge)> = vec![];
            while let Some(&(k, s)) = todo.get(i).filter(|t| Some(t.0.commit) == commit) {
                i += 1;
                self.counts.chained += 1;
                let it = &self.items[s];
                let Some((e, v)) = it.edge.as_ref().and_then(|ei| Some((ei.e, ei.sets?))) else { continue };
                let role = |h: E| if self.record[h] { ADMIN } else { self.level[h].0 };
                let inv = |h: E| if self.record[h] { ADMIN } else { self.level[h].1 };
                let admin = it.path.iter().all(|&h| role(h) == ADMIN);
                let lvl = (v.invite <= Some(v.role) && v.role < Role::Admin && v.alive_at(Some(it.ts))).then_some(Some(v.role));
                let invited = lvl.is_some_and(|l| it.path.split_last().is_some_and(|(last, before)| inv(*last) >= l && before.iter().all(|&h| role(h) >= l)));
                if admin || invited {
                    sets.push((k, e, v));
                }
            }
            for (k, e, v) in sets {
                self.chain_note(e);
                let undo = (e, self.level[e], self.first[e]);
                self.comp_mut(c).chain_undo.entry(k.commit_start()).or_default().push(undo);
                let (r0, i0) = self.level[e];
                self.level[e] = (r0.max(Some(v.role)), i0.max(give_invite(Some(v.role), v.invite)));
                if v.role < Role::Write {
                    continue;
                }
                for (n, r) in LEVELS.into_iter().enumerate() {
                    if v.role >= r
                        && let Some(slot) = self.first[e].get_mut(n)
                        && slot.is_none()
                    {
                        *slot = Some(k);
                    }
                }
            }
        }
    }

    fn chain_note(&mut self, e: E) {
        let was = self.first[e];
        if let Some(j) = &mut self.journal {
            j.chain.entry(e).or_insert(was);
        }
    }

    // ---- keeps (draft §5.1 step 4) ----

    /// Whether part `w`, applied in this pass, keeps admin on every edge of its path once
    /// lowering `l`'s drops and its commit's earlier drops are passed over.
    fn keeps(&mut self, l: &Judging, cdrops: &[Slot], w: Slot, chk: &mut Check) -> bool {
        self.chase(l, cdrops, Frame::Keeps { w, hop: 0 }, chk)
    }

    /// Edge `e` read back along the writes this pass applied on it before `key`, latest first,
    /// passing over the drops and the grants that do not keep in turn: the first left decides by
    /// `accept`; with none left, a record edge keeps.
    fn setter_keeps(&mut self, l: &Judging, cdrops: &[Slot], e: E, key: Key, accept: Accept, chk: &mut Check) -> bool {
        let upper = self.hist[e].partition_point(|y| y.a.key < key);
        self.chase(l, cdrops, Frame::Setter { e, upper, start: upper, accept }, chk)
    }

    /// `keeps` and `setter_keeps` as one loop over an explicit stack: a grant chain is as long as
    /// its writers make it. Within one check the setter deciding a scan of an edge below a
    /// position is the same whoever chased it there (the check's drops and memo are fixed), so it
    /// is cached per (edge, position), every position a scan passed included: each edge position
    /// is read once per check (notes/perm-paths.md, The void check).
    fn chase(&mut self, l: &Judging, cdrops: &[Slot], top: Frame, chk: &mut Check) -> bool {
        let mut stack = vec![top];
        // the answer of the frame popped last, for its parent
        let mut ret: Option<bool> = None;
        'frames: while let Some(f) = stack.pop() {
            match f {
                Frame::Keeps { w, mut hop } => {
                    match ret.take() {
                        Some(false) => {
                            chk.memo.insert(w, false);
                            ret = Some(false);
                            continue;
                        }
                        Some(true) => hop += 1,
                        None => {
                            if let Some(&m) = chk.memo.get(&w) {
                                ret = Some(m);
                                continue;
                            }
                        }
                    }
                    let it = &self.items[w];
                    let Some(&e) = it.hops.get(hop) else {
                        chk.memo.insert(w, true);
                        ret = Some(true);
                        continue;
                    };
                    let (key, ts) = (it.key, it.ts);
                    let upper = self.hist[e].partition_point(|y| y.a.key < key);
                    stack.push(Frame::Keeps { w, hop });
                    stack.push(Frame::Setter { e, upper, start: upper, accept: Accept::AdminAt(ts) });
                }
                Frame::Setter { e, mut upper, start, accept } => {
                    // (the lowest position answered, the deciding entry: none left reads the record)
                    let mut decided: Option<(usize, Option<usize>)> = None;
                    if ret.take() == Some(true) {
                        decided = Some((upper + 1, Some(upper)));
                    }
                    while decided.is_none() {
                        if let Some(&d) = chk.found.get(&(e, upper)) {
                            decided = Some((upper, d));
                            break;
                        }
                        if upper == 0 {
                            decided = Some((0, None));
                            break;
                        }
                        upper -= 1;
                        let Some(&Entry { slot: j, .. }) = self.hist[e].get(upper) else {
                            decided = Some((upper, None));
                            break;
                        };
                        self.counts.setters += 1;
                        if cdrops.contains(&j) || self.gone(l, j) {
                            continue;
                        }
                        let jt = &self.items[j];
                        let decides = jt.lowering_shape() || jt.leave || match chk.memo.get(&j) {
                            Some(&m) => m,
                            None => {
                                stack.push(Frame::Setter { e, upper, start, accept });
                                stack.push(Frame::Keeps { w: j, hop: 0 });
                                continue 'frames;
                            }
                        };
                        if decides {
                            decided = Some((upper + 1, Some(upper)));
                        }
                    }
                    let (lo, d) = decided.unwrap_or((start, None));
                    for p in lo..=start {
                        chk.found.insert((e, p), d);
                    }
                    ret = Some(match d.and_then(|i| self.hist[e].get(i)) {
                        Some(y) => Self::accepts(accept, y.a.value.as_ref()),
                        None => self.record[e],
                    });
                }
            }
        }
        ret.unwrap_or(false)
    }

    fn accepts(accept: Accept, v: Option<&Edge>) -> bool {
        match accept {
            Accept::AdminAt(ts) => alive(v, ts) == ADMIN,
            Accept::Standing => standing(v),
        }
    }

    // ---- reading ----

    fn status_of(&self, s: Slot) -> Option<Status> {
        if self.dead[s] {
            return None;
        }
        Some(if self.applied[s] {
            if self.invited[s] { Status::Invited } else { Status::Applied }
        } else if self.dropped[s].is_some() || self.seeded[s] > 0 || self.inert_by.contains_key(&s) {
            Status::Dropped
        } else if self.verdict[s] == Some(Verdict::Void) {
            Status::Void
        } else {
            Status::Unapplied
        })
    }

    pub(super) fn status(&self, id: &WriteId) -> Option<Status> {
        self.status_of(*self.ids.get(id)?)
    }

    pub(super) fn statuses(&self) -> BTreeMap<WriteId, Status> {
        self.ids.iter().filter_map(|(id, &s)| Some((*id, self.status_of(s)?))).collect()
    }

    pub(super) fn is_edge_write(&self, id: &WriteId) -> bool {
        self.ids.get(id).is_some_and(|&s| self.items[s].edge.is_some())
    }

    pub(super) fn key_of(&self, id: &WriteId) -> Option<Key> {
        self.ids.get(id).map(|&s| self.items[s].key)
    }

    pub(super) fn history(&self, holder: &Tid, target: &Tid) -> History {
        self.find_edge(holder, target).map_or(vec![], |e| self.hist[e].iter().map(|y| (y.a.key, y.a.value)).collect())
    }

    pub(super) fn writes(&self, holder: &Tid, target: &Tid) -> Vec<Applied> {
        self.find_edge(holder, target).map_or(vec![], |e| self.hist[e].iter().map(|y| y.a).collect())
    }

    pub(super) fn histories(&self) -> BTreeMap<(Tid, Tid), History> {
        let mut out = BTreeMap::new();
        for e in 0..self.ends.len() {
            if self.record[e] || !self.hist[e].is_empty() {
                out.insert(self.name(e), self.hist[e].iter().map(|y| (y.a.key, y.a.value)).collect());
            }
        }
        out
    }

    pub(super) fn value_before(&self, holder: &Tid, target: &Tid, key: &Key) -> Option<Edge> {
        let e = self.find_edge(holder, target)?;
        let h = &self.hist[e];
        match h.partition_point(|y| y.a.key < *key) {
            0 => self.record[e].then(|| Edge::new(Role::Admin)),
            n => h.get(n - 1).and_then(|y| y.a.value),
        }
    }

    pub(super) fn role_before(&self, holder: &Tid, target: &Tid, key: &Key) -> Lvl {
        alive(self.value_before(holder, target, key).as_ref(), key.ts)
    }

    /// The latest cut of (holder, target) below `r` in the settled walk.
    pub(super) fn last_cut(&self, holder: &Tid, target: &Tid, r: Role) -> Option<Key> {
        let e = self.find_edge(holder, target)?;
        let n = usize::from(r == Role::Admin);
        self.cuts[e].get(n).and_then(|c| c.last().copied())
    }

    /// An applied edge write's edge and entry.
    pub(super) fn applied_write(&self, id: &WriteId) -> Option<((Tid, Tid), Applied)> {
        let s = *self.ids.get(id)?;
        let it = &self.items[s];
        let ei = it.edge.as_ref().filter(|_| self.applied[s])?;
        let h = &self.hist[ei.e];
        let y = h.get(h.partition_point(|y| y.a.key < it.key))?;
        (y.a.key == it.key).then_some((self.name(ei.e), y.a))
    }

    /// The edge-class parts of `commit` held here, by `WriteId`.
    pub(super) fn parts_of(&self, commit: &CommitId) -> Vec<WriteId> {
        self.by_commit.get(commit).into_iter().flatten().map(|&s| self.items[s].id).collect()
    }

    /// The held vouches of components `comps`, and those listing a commit of `listing`, applied
    /// or not.
    pub(super) fn vouches(&self, comps: &BTreeSet<E>, listing: &BTreeSet<CommitId>) -> Vec<VouchItem<'_>> {
        let mut slots: BTreeSet<Slot> = comps.iter().filter_map(|c| self.comps.get(&self.find(*c))).flat_map(|c| c.vouches.iter().copied()).collect();
        slots.extend(listing.iter().filter_map(|c| self.listing.get(c)).flatten());
        let mut out = vec![];
        for s in slots {
            let it = &self.items[s];
            if let (false, Some((removal, list))) = (self.dead[s], &it.vouch) {
                out.push(VouchItem { id: it.id, applied: self.applied[s], key: it.key, on: self.names[it.on], signer: self.names[it.signer], removal: *removal, list });
            }
        }
        out
    }

    /// The edge writes of `commit` the walk applies as lowerings (explicit writes giving their
    /// edge below admin at their `ts`: draft §5.1 Vouches, the first counting condition): each
    /// one's edge and key.
    pub(super) fn lowers(&self, commit: &CommitId) -> Vec<((Tid, Tid), Key)> {
        let mut out = vec![];
        for &s in self.by_commit.get(commit).into_iter().flatten() {
            let it = &self.items[s];
            if !it.lowering() {
                continue;
            }
            if let Some((e, a)) = self.applied_write(&it.id).filter(|(_, a)| a.explicit) {
                out.push((e, a.key));
            }
        }
        out
    }

    pub(super) fn finals(&self) -> BTreeMap<(Tid, Tid), (Lvl, Lvl)> {
        let mut out = BTreeMap::new();
        for e in 0..self.ends.len() {
            if let Some(v) = self.val[e] {
                let role = final_role(Some(v));
                out.insert(self.name(e), (role, give_invite(role, v.and_then(|v| v.invite))));
            }
        }
        out
    }

    /// The final role of (holder, target), every `until` counted removed.
    pub(super) fn final_of(&self, holder: &Tid, target: &Tid) -> Lvl {
        self.find_edge(holder, target).and_then(|e| final_role(self.val[e]))
    }


    /// Per edge, the key of its first chained write giving write and admin (draft §4).
    pub(super) fn chained(&self) -> BTreeMap<(Tid, Tid), [Option<Key>; 2]> {
        (0..self.ends.len()).filter(|&e| self.first[e] != [None, None]).map(|e| (self.name(e), self.first[e])).collect()
    }

    /// The first chained key of (holder, target) giving `r`.
    pub(super) fn first_chained(&self, holder: &Tid, target: &Tid, r: Role) -> Option<Key> {
        let e = self.find_edge(holder, target)?;
        self.first[e].get(usize::from(r == Role::Admin)).copied().flatten()
    }

    /// The dispute candidates (draft §5.1 Trust set): held explicit-shaped lowerings of a grant
    /// whose holder is not their signer, not trusted and not dropped by a trusted write. (Those
    /// a walk trusting them applies as invite grants are none: `Paths::disputes`.)
    pub(super) fn candidates(&self) -> Vec<WriteId> {
        let mut out = vec![];
        for (s, it) in (0..).zip(self.items.iter()) {
            let Some(ei) = &it.edge else { continue };
            if self.dead[s] {
                continue;
            }
            let by_trusted = self.seeded[s] > 0 || self.dropped[s].is_some_and(|d| self.trust.contains(&d)) || self.inert_by.get(&s).is_some_and(|by| by.iter().any(|d| self.trust.contains(d)));
            if ei.holder == it.signer || !it.lowering() || self.trust.contains(&s) || by_trusted {
                continue;
            }
            out.push(it.id);
        }
        out
    }

    /// The components walked in the first walk (holding a vouch, not stale), each with its parts.
    pub(super) fn vouch_comps(&self) -> Vec<(E, Vec<WriteId>)> {
        self.comps.iter().filter(|(_, c)| !c.vouches.is_empty() && !c.stale).map(|(&r, c)| (r, c.order.values().map(|&s| self.items[s].id).collect())).collect()
    }

    /// Entries the walk keeps in memory: parts, edges, events, undo and chain entries, for the
    /// memory count (notes/perm-paths.md, The delta-facts seam).
    pub(super) fn footprint(&self) -> u64 {
        let comps: usize = self.comps.values().map(|c| c.order.len() + c.log.len() + c.undo.len() + c.chain.len() + c.chain_undo.len()).sum();
        let hist: usize = (0..self.ends.len()).map(|e| self.hist[e].len()).sum();
        (self.items.len() as usize + self.ends.len() as usize + self.held.len() + comps + hist) as u64
    }
}

/// The final role a value gives, every `until` counted removed.
fn final_role(v: Option<Option<Edge>>) -> Lvl {
    v.flatten().filter(|v| v.until.is_none()).map(|v| v.role)
}

#[derive(Clone, Copy)]
enum Frame {
    /// `keeps(w)`, at its `hop`th edge.
    Keeps { w: Slot, hop: usize },
    /// `setter_keeps` on `e`, below hist index `upper`, begun at `start`; where it waits on a
    /// grant's own `keeps`, that grant is at index `upper`.
    Setter { e: E, upper: usize, start: usize, accept: Accept },
}

/// One void check's memory: `keeps` per part, and per (edge, position) the entry deciding a
/// scan below it (none: no setter left).
#[derive(Default)]
struct Check {
    memo: BTreeMap<Slot, bool>,
    found: BTreeMap<(E, usize), Option<usize>>,
}

/// A table indexed by an interned number the walk made itself; an index past it reads its nil
/// value (and writes go to it), so no lookup panics.
#[derive(Clone)]
struct Tab<V> {
    v: Vec<V>,
    nil: V,
}

impl<V> Tab<V> {
    fn new(nil: V) -> Tab<V> {
        Tab { v: vec![], nil }
    }
    fn len(&self) -> u32 {
        self.v.len() as u32
    }
    fn push(&mut self, x: V) {
        self.v.push(x);
    }
    fn iter(&self) -> std::slice::Iter<'_, V> {
        self.v.iter()
    }
}

impl<V> std::ops::Index<u32> for Tab<V> {
    type Output = V;
    fn index(&self, i: u32) -> &V {
        self.v.get(i as usize).unwrap_or(&self.nil)
    }
}

impl<V> std::ops::IndexMut<u32> for Tab<V> {
    fn index_mut(&mut self, i: u32) -> &mut V {
        match self.v.get_mut(i as usize) {
            Some(x) => x,
            None => &mut self.nil,
        }
    }
}
