//! The walk itself (notes/perm-paths.md, One definition): the pass state with an undo entry per
//! applied part, and the event log of verdicts in the order given, so a restart and an update
//! both roll the state back to a key and continue.

use super::{Changed, Commit, PartKind, Status};
use crate::types::{lowers, Edge, Frontier, WriteId};
use osis_base::format::MAX_CHAIN_DEPTH;
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
/// A part's place within its commit: (thing written, a vouch, on the commit's own path, holder).
type PartOrder = (Tid, u8, bool, Tid);
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
    fn commit_start(self) -> Key {
        Key { part: 0, ..self }
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
    hops: Vec<E>,
    /// Its members name no thing twice, and its commit sets no edge twice.
    well: bool,
    /// A self-removal: its path ends at the holder of the edge it sets.
    leave: bool,
    /// `None`: a vouch.
    edge: Option<EdgeItem>,
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
        Item { key, id: WriteId(CommitId([0; 32]), 0), ts: Ts::ZERO, signer: T::MAX, hops: vec![], well: false, leave: false, edge: None }
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
    mint: BTreeMap<T, T>,
    record: Tab<bool>,
    items: Tab<Item>,
    ids: BTreeMap<WriteId, Slot>,
    order: BTreeMap<Key, Slot>,
    /// Per edge, the parts resting on it: through it, or a self-removal of it.
    resting: Tab<Vec<Slot>>,
    held: BTreeSet<CommitId>,
    trust: BTreeSet<WriteId>,
    // carried from pass to pass
    verdict: Tab<Option<Verdict>>,
    dropped: Tab<Option<Dropper>>,
    log: Vec<Event>,
    void_trusted: BTreeSet<Slot>,
    // the pass
    val: Tab<Option<Option<Edge>>>,
    restored: Tab<Lvl>,
    rinv: Tab<Lvl>,
    hist: Tab<Vec<(Key, Slot, Option<Edge>)>>,
    applied: Tab<bool>,
    invited: Tab<bool>,
    undo: Vec<Undo>,
    /// While an update runs: each part's status and each edge's history before it first changed.
    journal: Option<Journal>,
    pub(super) counts: Counts,
}

#[derive(Clone, Default)]
struct Journal {
    parts: BTreeMap<Slot, Option<Status>>,
    /// Per edge: the earliest key changed, and the entries from it on as they were.
    edges: BTreeMap<E, (Key, History)>,
}

impl Walk {
    pub(super) fn new(records: &BTreeMap<Tid, Tid>, trust: BTreeSet<WriteId>) -> Walk {
        let mut w = Walk {
            things: BTreeMap::new(),
            names: Tab::new(Tid::from_bytes([0; 15])),
            edges: BTreeMap::new(),
            ends: Tab::new((T::MAX, T::MAX)),
            mint: BTreeMap::new(),
            record: Tab::new(false),
            items: Tab::new(Item::nil()),
            ids: BTreeMap::new(),
            order: BTreeMap::new(),
            resting: Tab::new(vec![]),
            held: BTreeSet::new(),
            trust,
            verdict: Tab::new(None),
            dropped: Tab::new(None),
            log: vec![],
            void_trusted: BTreeSet::new(),
            val: Tab::new(None),
            restored: Tab::new(None),
            rinv: Tab::new(None),
            hist: Tab::new(vec![]),
            applied: Tab::new(false),
            invited: Tab::new(false),
            undo: vec![],
            journal: None,
            counts: Counts::default(),
        };
        for (thing, admin) in records {
            let (t, a) = (w.thing(thing), w.thing(admin));
            w.mint.insert(t, a);
        }
        let recs: Vec<(T, T)> = w.mint.iter().map(|(&t, &a)| (a, t)).collect();
        for (a, t) in recs {
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
        e
    }

    fn find_edge(&self, holder: &Tid, target: &Tid) -> Option<E> {
        self.edges.get(&(*self.things.get(holder)?, *self.things.get(target)?)).copied()
    }

    /// The edges joining consecutive members `p`, `q` (draft §1 Hops): the record edges from `p`
    /// down to `q` where `p` is on `q`'s record chain, else their direct edge.
    fn joins(&mut self, p: T, q: T) -> Vec<E> {
        let mut down = vec![];
        let mut t = q;
        while let Some(&m) = self.mint.get(&t) {
            down.push((m, t));
            if m == p {
                down.reverse();
                return down.into_iter().map(|(a, b)| self.edge(a, b)).collect();
            }
            if down.len() >= MAX_CHAIN_DEPTH {
                break;
            }
            t = m;
        }
        vec![self.edge(p, q)]
    }

    // ---- input ----

    /// Compiles a commit's parts into items in key order; the slots made.
    fn compile(&mut self, c: &Commit) -> Vec<Slot> {
        let signer = self.thing(&c.signer);
        // (sort key, input index, item)
        let mut made: Vec<(PartOrder, u32, Item)> = vec![];
        for (ix, p) in c.parts.iter().enumerate() {
            let on = self.thing(&p.on);
            let path: Vec<T> = p.path.iter().map(|t| self.thing(t)).collect();
            let mut members = vec![signer];
            members.extend(&path);
            let ak = *members.last().unwrap_or(&signer);
            let holder = match &p.kind {
                PartKind::Edge(ew) => Some(self.thing(&ew.holder)),
                PartKind::Vouch { .. } => None,
            };
            let leave = holder.is_some_and(|h| h == ak);
            if !leave {
                members.push(on);
            }
            let well = members.iter().collect::<BTreeSet<_>>().len() == members.len();
            let mut hops = vec![];
            if well {
                for pair in members.windows(2) {
                    if let [a, b] = pair {
                        hops.extend(self.joins(*a, *b));
                    }
                }
            }
            // the part on an edge of the commit's own path comes last on its thing: a self-removal
            // of the path's last thing, or the final edge joining Ak to the thing
            let final_hop = self.joins(ak, on).last().map(|&e| self.ends[e]);
            let own = holder.is_some_and(|h| h == ak || final_hop == Some((h, on)));
            let edge = match &p.kind {
                PartKind::Edge(ew) => {
                    let h = holder.unwrap_or(signer);
                    let e = self.edge(h, on);
                    let remains = ew.remains.map(|n| {
                        let n = self.thing(&n);
                        self.edge(n, on)
                    });
                    let last = hops.last().copied().filter(|&l| self.ends[l] == (ak, on)).filter(|_| !leave);
                    Some(EdgeItem {
                        e,
                        holder: h,
                        value: ew.value,
                        frontier: ew.frontier.clone(),
                        remains,
                        adminless: ew.adminless,
                        finalize: ew.value.is_none() && ew.frontier.is_none() && !leave && h != signer,
                        last,
                    })
                }
                PartKind::Vouch { .. } => None,
            };
            let sort = (p.on, u8::from(edge.is_none()), own, holder.map_or(Tid::from_bytes([0; 15]), |h| self.names[h]));
            let key = Key { ts: c.ts, signer: c.signer, commit: c.id, part: 0 };
            made.push((sort, ix as u32, Item { key, id: WriteId(c.id, ix as u32), ts: c.ts, signer, hops, well, leave, edge }));
        }
        made.sort_by_key(|m| (m.0, m.1));
        // two parts on one holder's edge cannot be encoded: the commit is bad input
        let sets: Vec<E> = made.iter().filter_map(|m| m.2.edge.as_ref().map(|ei| ei.e)).collect();
        let twice = sets.iter().collect::<BTreeSet<_>>().len() < sets.len();
        let mut slots = vec![];
        for (n, (_, _, mut it)) in made.into_iter().enumerate() {
            it.key.part = n as u32;
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
            self.items.push(it);
            self.verdict.push(None);
            self.dropped.push(None);
            self.applied.push(false);
            self.invited.push(false);
            slots.push(s);
        }
        slots
    }

    pub(super) fn add(&mut self, commits: &[Commit]) -> Changed {
        let mut first: Option<Key> = None;
        let mut new = vec![];
        for c in commits {
            if !self.held.insert(c.id) {
                continue;
            }
            for s in self.compile(c) {
                let k = self.items[s].key;
                first = Some(first.map_or(k, |f| f.min(k)));
                new.push(s);
            }
        }
        let Some(p) = first else { return Changed::default() };
        self.journal = Some(Journal::default());
        for &s in &new {
            self.note_new(s);
        }
        if !self.trust.is_empty() {
            self.settle();
        } else {
            // forget every event given at or after p, and roll back to the earliest of p and the
            // keys those events judged or dropped
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
        self.changed()
    }

    pub(super) fn set_trust(&mut self, trust: BTreeSet<WriteId>) -> Changed {
        self.trust = trust;
        self.journal = Some(Journal::default());
        self.settle();
        self.changed()
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
        let from = h.partition_point(|y| y.0 < k);
        match j.edges.get_mut(&e) {
            None => {
                j.edges.insert(e, (k, h.iter().skip(from).map(|y| (y.0, y.2)).collect()));
            }
            Some((kmin, old)) if k < *kmin => {
                let upto = h.partition_point(|y| y.0 < *kmin);
                let mut head: History = h.iter().skip(from).take(upto.saturating_sub(from)).map(|y| (y.0, y.2)).collect();
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

    /// What the update changed, from the journal.
    fn changed(&mut self) -> Changed {
        let Some(j) = self.journal.take() else { return Changed::default() };
        let mut out = Changed::default();
        for (s, was) in j.parts {
            if was != self.status_of(s) {
                out.parts.insert(self.items[s].id);
            }
        }
        for (e, (kmin, old)) in j.edges {
            let h = &self.hist[e];
            let now: History = h.iter().skip(h.partition_point(|y| y.0 < kmin)).map(|y| (y.0, y.2)).collect();
            let at = old.iter().zip(&now).position(|(p, q)| p != q).unwrap_or(old.len().min(now.len()));
            let k = old.get(at).map(|p| p.0).into_iter().chain(now.get(at).map(|q| q.0)).min();
            if let Some(k) = k {
                let (h, t) = self.ends[e];
                out.edges.insert((self.names[h], self.names[t]), k);
            }
        }
        out
    }

    // ---- the walk ----

    /// From scratch: D at the seeds of the trusted writes still active, no verdict; a trusted
    /// write the settled walk does not apply is void, every such write losing its seeds at once,
    /// and the walk is redone until none is (draft §5.1 Trust set).
    fn settle(&mut self) {
        let mut active: BTreeSet<Slot> = self.trust.iter().filter_map(|id| self.ids.get(id).copied()).filter(|&s| self.items[s].edge.is_some()).collect();
        self.void_trusted.clear();
        loop {
            self.counts.scratch += 1;
            self.rollback(Key { ts: Ts::ZERO, signer: Tid::from_bytes([0; 15]), commit: CommitId([0; 32]), part: 0 });
            self.log.clear();
            for s in 0..self.items.len() {
                if self.verdict[s].is_some() {
                    self.set_verdict(s, None);
                }
                if self.dropped[s].is_some() {
                    self.set_dropped(s, None);
                }
            }
            for &r in &active {
                self.seed(r);
            }
            if let Some((&k, _)) = self.order.iter().next() {
                self.run(k);
            }
            let gone: Vec<Slot> = active.iter().copied().filter(|&r| !self.applied[r]).collect();
            if gone.is_empty() {
                return;
            }
            for r in gone {
                active.remove(&r);
                self.void_trusted.insert(r);
            }
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
                self.hist[e].pop();
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

    fn listed(&self, r: Slot, j: Slot) -> bool {
        let c = self.items[j].key.commit;
        self.items[r].edge.as_ref().and_then(|ei| ei.frontier.as_ref()).is_some_and(|f| f.covers(&c))
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
        self.val[e] = Some(ei.value);
        if explicit {
            self.restored[e] = ei.value.map(|v| v.role);
            self.rinv[e] = after_inv;
        } else if as_invite {
            self.restored[e] = self.restored[e].max(ei.value.map(|v| v.role));
            self.rinv[e] = self.rinv[e].max(after_inv);
            self.invited[s] = true;
        }
        self.hist[e].push((key, s, ei.value));
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
        let upper = self.hist[e].partition_point(|y| y.0 < key);
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
                    let upper = self.hist[e].partition_point(|y| y.0 < key);
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
                        let Some(&(_, j, v)) = self.hist[e].get(upper) else { break };
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

    pub(super) fn key_of(&self, id: &WriteId) -> Option<Key> {
        self.ids.get(id).map(|&s| self.items[s].key)
    }

    pub(super) fn history(&self, holder: &Tid, target: &Tid) -> History {
        self.find_edge(holder, target).map_or(vec![], |e| self.hist[e].iter().map(|y| (y.0, y.2)).collect())
    }

    pub(super) fn histories(&self) -> BTreeMap<(Tid, Tid), History> {
        let mut out = BTreeMap::new();
        for (e, &(h, t)) in (0..).zip(self.ends.iter()) {
            if self.record[e] || !self.hist[e].is_empty() {
                out.insert((self.names[h], self.names[t]), self.hist[e].iter().map(|y| (y.0, y.2)).collect());
            }
        }
        out
    }

    pub(super) fn value_before(&self, holder: &Tid, target: &Tid, key: &Key) -> Option<Edge> {
        let e = self.find_edge(holder, target)?;
        let h = &self.hist[e];
        match h.partition_point(|y| y.0 < *key) {
            0 => self.record[e].then(|| Edge::new(Role::Admin)),
            n => h.get(n - 1).and_then(|y| y.2),
        }
    }

    pub(super) fn role_before(&self, holder: &Tid, target: &Tid, key: &Key) -> Lvl {
        alive(self.value_before(holder, target, key).as_ref(), key.ts)
    }

    pub(super) fn finals(&self) -> BTreeMap<(Tid, Tid), (Lvl, Lvl)> {
        let mut out = BTreeMap::new();
        for (e, &(h, t)) in (0..).zip(self.ends.iter()) {
            if let Some(v) = self.val[e] {
                let role = v.filter(|v| v.until.is_none()).map(|v| v.role);
                out.insert((self.names[h], self.names[t]), (role, give_invite(role, v.and_then(|v| v.invite))));
            }
        }
        out
    }

    pub(super) fn void_trusted(&self) -> BTreeSet<WriteId> {
        self.void_trusted.iter().map(|&s| self.items[s].id).collect()
    }

    fn applied_set(&self) -> BTreeSet<Slot> {
        (0..self.items.len()).filter(|&s| self.applied[s]).collect()
    }

    /// The dispute set (draft §5.1 Trust set): held explicit lowerings of a grant whose holder
    /// is not their signer, not trusted and not dropped by a trusted write, whose trust changes
    /// what applies or the final roles; one the walk trusting it applies as an invite grant is
    /// none.
    pub(super) fn disputes(&self) -> BTreeSet<WriteId> {
        let applied = self.applied_set();
        let roles: BTreeMap<(Tid, Tid), Lvl> = self.finals().into_iter().map(|(k, v)| (k, v.0)).collect();
        let mut out = BTreeSet::new();
        for (s, it) in (0..).zip(self.items.iter()) {
            let Some(ei) = &it.edge else { continue };
            let by_trusted = match self.dropped[s] {
                Some(Dropper::Seed(d) | Dropper::Audit(d)) => self.trust.contains(&self.items[d].id),
                None => false,
            };
            if ei.holder == it.signer || !it.lowering() || self.trust.contains(&it.id) || by_trusted {
                continue;
            }
            let mut t = self.clone();
            t.trust.insert(it.id);
            t.settle();
            if t.invited[s] {
                continue;
            }
            let troles: BTreeMap<(Tid, Tid), Lvl> = t.finals().into_iter().map(|(k, v)| (k, v.0)).collect();
            if t.applied_set() != applied || troles != roles {
                out.insert(it.id);
            }
        }
        out
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
