//! The walk itself (notes/perm-paths.md, One definition): the pass state with an undo entry per
//! applied part, and the event log of verdicts in the order given, so a restart and an update
//! both roll the state back to a key and continue.

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
    /// Walks from scratch (trust changes, trusted walks, their redos, dispute candidates).
    pub scratch: u64,
    /// Content (draft §5.2): edge reads, namers, addenda and snapshots looked at by delta
    /// queries.
    pub content: u64,
    /// Addenda judged and entries read by the addenda fixpoint.
    pub addenda: u64,
}

impl Counts {
    pub(super) fn add(&mut self, o: &Counts) {
        self.steps += o.steps;
        self.passes += o.passes;
        self.restarts += o.restarts;
        self.setters += o.setters;
        self.audited += o.audited;
        self.scratch += o.scratch;
        self.content += o.content;
        self.addenda += o.addenda;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verdict {
    Applied,
    Void,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Dropper {
    /// A trusted write's seed.
    Seed(Slot),
    /// A lowering's audit.
    Audit(Slot),
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
}

#[derive(Clone)]
struct Item {
    key: Key,
    id: WriteId,
    ts: Ts,
    signer: T,
    on: T,
    hops: Vec<E>,
    /// Its members name no thing twice, and its commit sets no edge twice.
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
        Item { key, id: WriteId(CommitId([0; 32]), 0), ts: Ts::ZERO, signer: T::MAX, on: T::MAX, hops: vec![], well: false, leave: false, edge: None, vouch: None }
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
    key: Key,
    slot: Slot,
    /// The edge it set and that edge's value and edge as restored before (none for a vouch).
    edge: Option<(E, Option<Option<Edge>>, Lvl, Lvl)>,
}

/// What a vouch is, for the counting rule (draft §5.1 Vouches): its key, thing, signer, removal
/// and list.
pub(super) struct VouchItem<'a> {
    pub key: Key,
    pub on: Tid,
    pub signer: Tid,
    pub removal: CommitId,
    pub list: &'a Frontier,
}

/// A verdict given: the lowering's key and slot, and its drops.
#[derive(Clone)]
struct Event {
    key: Key,
    slot: Slot,
    drops: Vec<Slot>,
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
    ids: BTreeMap<WriteId, Slot>,
    order: BTreeMap<Key, Slot>,
    by_commit: BTreeMap<CommitId, Vec<Slot>>,
    /// The vouches held.
    vouch_slots: Vec<Slot>,
    /// Per edge, the parts resting on it: through it, or a self-removal of it.
    resting: Tab<Vec<Slot>>,
    held: BTreeSet<CommitId>,
    trust: BTreeSet<Slot>,
    /// (removal, commit) pairs the counting vouch entries add to removals' lists: empty in the
    /// first walk, the counting entries in the second (draft §5.1 Vouches).
    vouched: BTreeSet<(CommitId, CommitId)>,
    // carried from pass to pass
    verdict: Tab<Option<Verdict>>,
    dropped: Tab<Option<Dropper>>,
    log: Vec<Event>,
    // the pass
    val: Tab<Option<Option<Edge>>>,
    restored: Tab<Lvl>,
    rinv: Tab<Lvl>,
    hist: Tab<Vec<Entry>>,
    /// Per edge, per level (`LEVELS`), the keys of its cuts in the pass, ascending.
    cuts: Tab<[Vec<Key>; 2]>,
    applied: Tab<bool>,
    invited: Tab<bool>,
    undo: Vec<Undo>,
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
}

impl Walk {
    pub(super) fn new(records: &BTreeMap<Tid, Tid>) -> Walk {
        let mut w = Walk {
            things: BTreeMap::new(),
            names: Tab::new(Tid::from_bytes([0; 15])),
            edges: BTreeMap::new(),
            ends: Tab::new((T::MAX, T::MAX)),
            mint: records.clone(),
            record: Tab::new(false),
            items: Tab::new(Item::nil()),
            ids: BTreeMap::new(),
            order: BTreeMap::new(),
            by_commit: BTreeMap::new(),
            vouch_slots: vec![],
            resting: Tab::new(vec![]),
            held: BTreeSet::new(),
            trust: BTreeSet::new(),
            vouched: BTreeSet::new(),
            verdict: Tab::new(None),
            dropped: Tab::new(None),
            log: vec![],
            val: Tab::new(None),
            restored: Tab::new(None),
            rinv: Tab::new(None),
            hist: Tab::new(vec![]),
            cuts: Tab::new([vec![], vec![]]),
            applied: Tab::new(false),
            invited: Tab::new(false),
            undo: vec![],
            journal: None,
            counts: Counts::default(),
        };
        for (thing, admin) in records {
            let (t, a) = (w.thing(thing), w.thing(admin));
            let e = w.edge(a, t);
            w.record[e] = true;
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
        self.resting.push(vec![]);
        self.val.push(None);
        self.restored.push(None);
        self.rinv.push(None);
        self.hist.push(vec![]);
        self.cuts.push([vec![], vec![]]);
        e
    }

    fn find_edge(&self, holder: &Tid, target: &Tid) -> Option<E> {
        self.edges.get(&(*self.things.get(holder)?, *self.things.get(target)?)).copied()
    }

    fn intern(&mut self, e: (Tid, Tid)) -> E {
        let (h, t) = (self.thing(&e.0), self.thing(&e.1));
        self.edge(h, t)
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
                    let ei = EdgeItem {
                        e,
                        holder: h,
                        value: ew.value,
                        frontier: ew.frontier.clone(),
                        remains,
                        adminless: ew.adminless,
                        finalize: ew.value.is_none() && ew.frontier.is_none() && !sh.leave && h != signer,
                        last,
                    };
                    (Some(ei), None)
                }
                PartKind::Vouch { removal, list } => (None, Some((*removal, list.clone()))),
                PartKind::Delta(_) => continue,
            };
            let sort = (p.on, own, u8::from(edge.is_none()), holder.unwrap_or(Tid::from_bytes([0; 15])));
            let key = Key { ts: c.ts, signer: c.signer, commit: c.id, part: 0 };
            made.push((sort, ix, Item { key, id: WriteId(c.id, ix), ts: c.ts, signer, on, hops, well: sh.well, leave: sh.leave, edge, vouch }));
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
            for &h in &it.hops {
                self.resting[h].push(s);
            }
            if let Some(ei) = it.edge.as_ref().filter(|_| it.leave) {
                self.resting[ei.e].push(s);
            }
            self.ids.insert(it.id, s);
            self.order.insert(it.key, s);
            self.by_commit.entry(c.id).or_default().push(s);
            if it.vouch.is_some() {
                self.vouch_slots.push(s);
            }
            self.items.push(it);
            self.verdict.push(None);
            self.dropped.push(None);
            self.applied.push(false);
            self.invited.push(false);
            slots.push(s);
        }
        slots
    }

    /// Takes in the commits not held yet (journalling the new parts); the earliest key added.
    pub(super) fn take(&mut self, commits: &[Commit]) -> Option<Key> {
        let mut first: Option<Key> = None;
        for c in commits {
            if !self.held.insert(c.id) {
                continue;
            }
            for s in self.compile(c) {
                let k = self.items[s].key;
                first = Some(first.map_or(k, |f| f.min(k)));
                self.note_new(s);
            }
        }
        first
    }

    /// The incremental update (notes/perm-paths.md, One definition): forgets every event given
    /// at or after `p` and rolls back to the earliest of `p` and the keys those events judged or
    /// dropped, then walks on. Only under an empty trust set.
    pub(super) fn update_from(&mut self, p: Key) {
        let cut = self.log.iter().position(|ev| ev.key >= p).unwrap_or(self.log.len());
        let mut x = p;
        for ev in self.log.split_off(cut) {
            x = x.min(ev.key);
            self.set_verdict(ev.slot, None);
            for d in ev.drops {
                x = x.min(self.items[d].key);
                self.set_dropped(d, None);
            }
        }
        self.run(x.commit_start());
    }

    /// Starts journalling an update.
    pub(super) fn begin(&mut self) {
        self.journal = Some(Journal::default());
    }

    /// Sets the counting entries' pairs (the second walk); the earliest key of a held removal
    /// whose list they change.
    pub(super) fn set_vouched(&mut self, vouched: BTreeSet<(CommitId, CommitId)>) -> Option<Key> {
        let changed: BTreeSet<CommitId> = self.vouched.symmetric_difference(&vouched).map(|p| p.0).collect();
        self.vouched = vouched;
        changed.iter().filter_map(|r| self.by_commit.get(r)).flatten().map(|&s| self.items[s].key).min()
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

    fn set_dropped(&mut self, s: Slot, d: Option<Dropper>) {
        self.note_part(s);
        self.dropped[s] = d;
    }

    /// What the update changed, from the journal: parts, history (from the first key that
    /// differs), cuts (the latest key of a cut added or removed) and final roles (`regrant`).
    pub(super) fn changed(&mut self) -> Changed {
        let Some(j) = self.journal.take() else { return Changed::default() };
        let mut out = Changed::default();
        for (s, was) in j.parts {
            if was != self.status_of(s) {
                out.parts.insert(self.items[s].id);
            }
        }
        for (e, (kmin, old, was)) in j.edges {
            let h = &self.hist[e];
            let now: Vec<Applied> = h.iter().skip(h.partition_point(|y| y.a.key < kmin)).map(|y| y.a).collect();
            let (h, t) = self.ends[e];
            let name = (self.names[h], self.names[t]);
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
        out
    }

    // ---- the walk ----

    /// From scratch under the trusted writes `active` (draft §5.1 Trust set): D at their seeds,
    /// no verdict. Which trusted writes are void is `Paths`'s (it reads the second walk).
    pub(super) fn scratch(&mut self, active: &BTreeSet<WriteId>) {
        self.counts.scratch += 1;
        self.trust = active.iter().filter_map(|id| self.ids.get(id).copied()).filter(|&s| self.items[s].edge.is_some()).collect();
        self.rollback(Key::start(Ts::ZERO));
        self.log.clear();
        for s in 0..self.items.len() {
            if self.verdict[s].is_some() {
                self.set_verdict(s, None);
            }
            if self.dropped[s].is_some() {
                self.set_dropped(s, None);
            }
        }
        let active: Vec<Slot> = self.trust.iter().copied().collect();
        for r in active {
            self.seed(r);
        }
        if let Some((&k, _)) = self.order.iter().next() {
            self.run(k);
        }
    }

    /// Trusted write `r`'s seeds join D: the held parts of other commits ordered before it,
    /// resting on its edge, that its list does not name, whose least need there its value does
    /// not meet.
    fn seed(&mut self, r: Slot) {
        let it = &self.items[r];
        let Some(ei) = &it.edge else { return };
        let (h, after, ai, key) = (ei.e, it.after(), it.after_inv(), it.key);
        let mut d = vec![];
        for &j in &self.resting[h] {
            self.counts.audited += 1;
            let jt = &self.items[j];
            if jt.key < key && jt.key.commit != key.commit && !self.listed(r, j) && !self.need(j, h, true).met(after, ai) {
                d.push(j);
            }
        }
        for j in d {
            if self.dropped[j].is_none() {
                self.set_dropped(j, Some(Dropper::Seed(r)));
            }
        }
    }

    /// Runs passes from `from` until one adds nothing to D; a pass ending at a lowering whose
    /// drops joined D continues from its earliest drop's commit, the state rolled back there.
    fn run(&mut self, mut from: Key) {
        loop {
            self.rollback(from);
            self.counts.passes += 1;
            match self.pass(from) {
                Some(r) => {
                    from = r.commit_start();
                    self.counts.restarts += 1;
                }
                None => return,
            }
        }
    }

    fn rollback(&mut self, x: Key) {
        while self.undo.last().is_some_and(|u| u.key >= x) {
            let Some(u) = self.undo.pop() else { break };
            self.note_part(u.slot);
            if let Some((e, ..)) = u.edge {
                self.note_edge(e, u.key);
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

    /// One pass from `from`; the earliest drop's key where a commit's lowerings dropped something.
    fn pass(&mut self, from: Key) -> Option<Key> {
        let mut cur: Option<CommitId> = None;
        let mut cdrops: Vec<Slot> = vec![];
        let mut next = self.order.range(from..).next().map(|(k, s)| (*k, *s));
        while let Some((k, s)) = next {
            if cur != Some(k.commit) {
                if !cdrops.is_empty() {
                    return cdrops.iter().map(|&d| self.items[d].key).min();
                }
                cur = Some(k.commit);
            }
            if self.dropped[s].is_none() {
                self.counts.steps += 1;
                self.step(s, &mut cdrops);
            }
            next = self.order.range((Excluded(k), Unbounded)).next().map(|(k, s)| (*k, *s));
        }
        cdrops.iter().map(|&d| self.items[d].key).min()
    }

    fn at(&self, e: E, ts: Ts) -> Lvl {
        self.val[e].and_then(|v| alive(v.as_ref(), ts))
    }

    fn invite_at(&self, e: E, ts: Ts) -> Lvl {
        give_invite(self.at(e, ts), self.val[e].flatten().and_then(|v| v.invite))
    }

    /// `r`'s list names `j` (draft §5.1): its frontier, or (the second walk) a counting entry.
    fn listed(&self, r: Slot, j: Slot) -> bool {
        let c = self.items[j].key.commit;
        self.items[r].edge.as_ref().and_then(|ei| ei.frontier.as_ref()).is_some_and(|f| f.covers(&c)) || self.vouched.contains(&(self.items[r].key.commit, c))
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
        let Some(ei) = it.edge.clone() else {
            self.note_part(s);
            self.applied[s] = true;
            self.undo.push(Undo { key, slot: s, edge: None });
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
        if judged.is_none() && explicit && falls {
            let l = Judging { slot: s, commit: key.commit, e: ei.e, restored, rinv, after, after_inv };
            let mut memo = BTreeMap::new();
            let kept = self.keeps(&l, cdrops, s, &mut memo) && relied.is_none_or(|r| self.setter_keeps(&l, cdrops, r, key, Accept::Standing, &mut memo));
            if !kept {
                self.set_verdict(s, Some(Verdict::Void));
                self.log.push(Event { key, slot: s, drops: vec![] });
                return;
            }
            for &j in &self.resting[e] {
                self.counts.audited += 1;
                if self.items[j].key < key && self.dropped[j].is_none() && self.verdict[j] != Some(Verdict::Void) && self.gone(&l, j) {
                    q.push(j);
                }
            }
            self.set_verdict(s, Some(Verdict::Applied));
            self.log.push(Event { key, slot: s, drops: q.clone() });
        }
        self.note_part(s);
        self.note_edge(ei.e, key);
        self.undo.push(Undo { key, slot: s, edge: Some((ei.e, self.val[e], self.restored[e], self.rinv[e])) });
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
            self.set_dropped(j, Some(Dropper::Audit(s)));
            cdrops.push(j);
        }
    }

    // ---- keeps (draft §5.1 step 4) ----

    /// Whether part `w`, applied in this pass, keeps admin on every edge of its path once
    /// lowering `l`'s drops and its commit's earlier drops are passed over.
    fn keeps(&mut self, l: &Judging, cdrops: &[Slot], w: Slot, memo: &mut BTreeMap<Slot, bool>) -> bool {
        self.chase(l, cdrops, Frame::Keeps { w, hop: 0 }, memo)
    }

    /// Edge `e` read back along the writes this pass applied on it before `key`, latest first,
    /// passing over the drops and the grants that do not keep in turn: the first left decides by
    /// `accept`; with none left, a record edge keeps.
    fn setter_keeps(&mut self, l: &Judging, cdrops: &[Slot], e: E, key: Key, accept: Accept, memo: &mut BTreeMap<Slot, bool>) -> bool {
        let upper = self.hist[e].partition_point(|y| y.a.key < key);
        self.chase(l, cdrops, Frame::Setter { e, upper, accept, waiting: None }, memo)
    }

    /// `keeps` and `setter_keeps` as one loop over an explicit stack: a grant chain is as long as
    /// its writers make it.
    fn chase(&mut self, l: &Judging, cdrops: &[Slot], top: Frame, memo: &mut BTreeMap<Slot, bool>) -> bool {
        let mut stack = vec![top];
        // the answer of the frame popped last, for its parent
        let mut ret: Option<bool> = None;
        'frames: while let Some(f) = stack.pop() {
            match f {
                Frame::Keeps { w, mut hop } => {
                    match ret.take() {
                        Some(false) => {
                            memo.insert(w, false);
                            ret = Some(false);
                            continue;
                        }
                        Some(true) => hop += 1,
                        None => {
                            if let Some(&m) = memo.get(&w) {
                                ret = Some(m);
                                continue;
                            }
                        }
                    }
                    let it = &self.items[w];
                    let Some(&e) = it.hops.get(hop) else {
                        memo.insert(w, true);
                        ret = Some(true);
                        continue;
                    };
                    let (key, ts) = (it.key, it.ts);
                    let upper = self.hist[e].partition_point(|y| y.a.key < key);
                    stack.push(Frame::Keeps { w, hop });
                    stack.push(Frame::Setter { e, upper, accept: Accept::AdminAt(ts), waiting: None });
                }
                Frame::Setter { e, mut upper, accept, waiting } => {
                    if ret.take() == Some(true) {
                        ret = Some(Self::accepts(accept, waiting.flatten().as_ref()));
                        continue;
                    }
                    while upper > 0 {
                        upper -= 1;
                        let Some(&Entry { slot: j, a }) = self.hist[e].get(upper) else { break };
                        let v = a.value;
                        self.counts.setters += 1;
                        if cdrops.contains(&j) || self.gone(l, j) {
                            continue;
                        }
                        let jt = &self.items[j];
                        let decides = jt.lowering_shape() || jt.leave || match memo.get(&j) {
                            Some(&m) => m,
                            None => {
                                stack.push(Frame::Setter { e, upper, accept, waiting: Some(v) });
                                stack.push(Frame::Keeps { w: j, hop: 0 });
                                continue 'frames;
                            }
                        };
                        if decides {
                            ret = Some(Self::accepts(accept, v.as_ref()));
                            continue 'frames;
                        }
                    }
                    ret = Some(self.record[e]);
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
        Some(if self.applied[s] {
            if self.invited[s] { Status::Invited } else { Status::Applied }
        } else if self.dropped[s].is_some() {
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
        for (e, &(h, t)) in (0..).zip(self.ends.iter()) {
            if self.record[e] || !self.hist[e].is_empty() {
                out.insert((self.names[h], self.names[t]), self.hist[e].iter().map(|y| (y.a.key, y.a.value)).collect());
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
        let (a, t) = self.ends[ei.e];
        (y.a.key == it.key).then_some(((self.names[a], self.names[t]), y.a))
    }

    /// The edge-class parts of `commit` held here, by `WriteId`.
    pub(super) fn parts_of(&self, commit: &CommitId) -> Vec<WriteId> {
        self.by_commit.get(commit).into_iter().flatten().map(|&s| self.items[s].id).collect()
    }

    /// The applied vouches.
    pub(super) fn vouches(&self) -> Vec<VouchItem<'_>> {
        let mut out = vec![];
        for &s in &self.vouch_slots {
            let it = &self.items[s];
            if let (true, Some((removal, list))) = (self.applied[s], &it.vouch) {
                out.push(VouchItem { key: it.key, on: self.names[it.on], signer: self.names[it.signer], removal: *removal, list });
            }
        }
        out
    }

    /// The edge writes of `commit` applying as explicit writes that lower a grant whose holder is
    /// not the commit's signer, taking from the edge's value just before them (draft §5.1
    /// Vouches, the first counting condition): each one's edge and key.
    pub(super) fn takes(&self, commit: &CommitId) -> Vec<((Tid, Tid), Key)> {
        let mut out = vec![];
        for &s in self.by_commit.get(commit).into_iter().flatten() {
            let it = &self.items[s];
            if it.edge.as_ref().is_none_or(|ei| ei.holder == it.signer) {
                continue;
            }
            if let Some((e, a)) = self.applied_write(&it.id).filter(|(_, a)| a.explicit && takes_from(a.value.as_ref(), a.before.as_ref())) {
                out.push((e, a.key));
            }
        }
        out
    }

    pub(super) fn finals(&self) -> BTreeMap<(Tid, Tid), (Lvl, Lvl)> {
        let mut out = BTreeMap::new();
        for (e, &(h, t)) in (0..).zip(self.ends.iter()) {
            if let Some(v) = self.val[e] {
                let role = final_role(Some(v));
                out.insert((self.names[h], self.names[t]), (role, give_invite(role, v.and_then(|v| v.invite))));
            }
        }
        out
    }

    /// The final role of (holder, target), every `until` counted removed.
    pub(super) fn final_of(&self, holder: &Tid, target: &Tid) -> Lvl {
        self.find_edge(holder, target).and_then(|e| final_role(self.val[e]))
    }

    pub(super) fn applied_ids(&self) -> BTreeSet<WriteId> {
        (0..self.items.len()).filter(|&s| self.applied[s]).map(|s| self.items[s].id).collect()
    }

    /// The dispute candidates (draft §5.1 Trust set): held explicit-shaped lowerings of a grant
    /// whose holder is not their signer, not trusted and not dropped by a trusted write. (Those
    /// a walk trusting them applies as invite grants are none: `Paths::disputes`.)
    pub(super) fn candidates(&self) -> Vec<WriteId> {
        let mut out = vec![];
        for (s, it) in (0..).zip(self.items.iter()) {
            let Some(ei) = &it.edge else { continue };
            let by_trusted = match self.dropped[s] {
                Some(Dropper::Seed(d) | Dropper::Audit(d)) => self.trust.contains(&d),
                None => false,
            };
            if ei.holder == it.signer || !it.lowering() || self.trust.contains(&s) || by_trusted {
                continue;
            }
            out.push(it.id);
        }
        out
    }
}

/// The final role a value gives, every `until` counted removed.
fn final_role(v: Option<Option<Edge>>) -> Lvl {
    v.flatten().filter(|v| v.until.is_none()).map(|v| v.role)
}

/// `new` takes from `old` (draft §5.1 Vouches): removing it, or setting a role, invite or `until`
/// below it or a `floor` above it.
fn takes_from(new: Option<&Edge>, old: Option<&Edge>) -> bool {
    match (new, old) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(n), Some(o)) => {
            let until_below = match (n.until, o.until) {
                (Some(a), Some(b)) => a < b,
                (Some(_), None) => true,
                (None, _) => false,
            };
            n.role < o.role || n.invite < o.invite || until_below || n.floor.unwrap_or(0) > o.floor.unwrap_or(0)
        }
    }
}

#[derive(Clone, Copy)]
enum Frame {
    /// `keeps(w)`, at its `hop`th edge.
    Keeps { w: Slot, hop: usize },
    /// `setter_keeps` on `e`, below hist index `upper`; `waiting`: the value of the grant whose
    /// own `keeps` is being chased.
    Setter { e: E, upper: usize, accept: Accept, waiting: Option<Option<Edge>> },
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
