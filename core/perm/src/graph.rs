//! Authority over one edge state (spec/permissions.md §1, §2, §5.1 step 3): effective role as
//! the widest path over role edges, may-grant, the path search. Record edges
//! (spec/permissions.md §1) are virtual: a mint admin's edge on its thing is read from the
//! creation record (`Records`) unless an edge write set it (`Edges` holds the value written, or
//! that it was removed), so dependent things cost the edge state nothing.

use crate::types::{earliest, mark, Edge};
use osis_base::format::{PathMarks, MAX_CHAIN_DEPTH};
use osis_base::{CreationRecord, RecordLink, Role, Tid, Ts, WallMs};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What a thing may write of another's grants (spec/permissions.md §2), ordered: admin above
/// every may-grant role.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Class {
    None,
    /// It may add holders up to this role (§2 Path's may-grant).
    MayGrant(Role),
    /// Admin: every edge write.
    Edge,
}

/// A node's standing on a thing: its class and effective role.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Standing {
    pub class: Class,
    pub role: Option<Role>,
}

/// The value of a record edge in force (spec/permissions.md §1): admin, no `until`.
pub const RECORD_EDGE: Edge = Edge { role: Role::Admin, until: None, may_grant: false, retain: false, floor: None };

/// Record links of every thing with a verified `created.0`: each thing's mint admin (or that
/// it is a key actor), and the things each actor is mint admin of.
#[derive(Clone, Debug, Default)]
pub struct Records {
    link: BTreeMap<Tid, RecordLink>,
    mint_admin_of: BTreeMap<Tid, Vec<Tid>>,
}

impl Records {
    pub fn insert(&mut self, t: Tid, rec: &CreationRecord) {
        let link = rec.record_link();
        if let RecordLink::Admin(a) = link {
            self.mint_admin_of.entry(a).or_default().push(t);
        }
        self.link.insert(t, link);
    }
    /// Forgets `t`'s record.
    pub fn remove(&mut self, t: &Tid) {
        if let Some(RecordLink::Admin(a)) = self.link.remove(t)
            && let Some(v) = self.mint_admin_of.get_mut(&a)
        {
            v.retain(|x| x != t);
            if v.is_empty() {
                self.mint_admin_of.remove(&a);
            }
        }
    }
    /// Every record link, by thing.
    pub fn links(&self) -> impl Iterator<Item = (&Tid, &RecordLink)> {
        self.link.iter()
    }
    pub fn link(&self, t: &Tid) -> Option<RecordLink> {
        self.link.get(t).copied()
    }
    pub fn is_key(&self, t: &Tid) -> bool {
        self.link(t) == Some(RecordLink::Key)
    }
    /// The things `a` is mint admin of (its record edges' targets).
    pub fn mint_admin_of(&self, a: &Tid) -> &[Tid] {
        self.mint_admin_of.get(a).map_or(&[], |v| v.as_slice())
    }
    /// The mint admin of `t` (its record edge's holder) when its record is held and names one.
    pub fn mint_admin(&self, t: &Tid) -> Option<Tid> {
        self.mint_admin_ref(t).copied()
    }
    fn mint_admin_ref(&self, t: &Tid) -> Option<&Tid> {
        match self.link.get(t) {
            Some(RecordLink::Admin(a)) => Some(a),
            _ => None,
        }
    }
    /// Whether (`holder`, `target`) is `target`'s record edge.
    pub fn is_record_edge(&self, holder: &Tid, target: &Tid) -> bool {
        self.mint_admin(target) == Some(*holder)
    }
}

/// An edge state: every current `roles.0` edge set by a write (a record edge in force is read
/// from the records, `Records`; one written over is here, one removed in `cut`). The per-target
/// and per-holder maps are shared between clones until written (a kept state costs O(targets +
/// holders), not O(edges)).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Edges {
    by_target: BTreeMap<Tid, Arc<BTreeMap<Tid, Edge>>>,
    by_holder: BTreeMap<Tid, Arc<BTreeSet<Tid>>>,
    /// Record edges (holder, target) a write removed, with no value written since.
    cut: BTreeSet<(Tid, Tid)>,
}

impl Edges {
    /// The value an edge write set (holder, target) to, if one is in force (a record edge in
    /// force by the record alone is not here: `get`).
    pub fn explicit(&self, holder: &Tid, target: &Tid) -> Option<&Edge> {
        self.by_target.get(target).and_then(|m| m.get(holder))
    }
    /// Whether a write removed the record edge (holder, target).
    pub fn is_cut(&self, holder: &Tid, target: &Tid) -> bool {
        self.cut.contains(&(*holder, *target))
    }
    /// The edge (holder, target) in force: the value written, else the record edge unless cut.
    pub fn get(&self, records: &Records, holder: &Tid, target: &Tid) -> Option<&Edge> {
        self.explicit(holder, target).or_else(|| (records.is_record_edge(holder, target) && !self.is_cut(holder, target)).then_some(&RECORD_EDGE))
    }
    /// Sets (holder, target) to `edge`; a record edge set to its record value is in force by
    /// the record again.
    pub fn set(&mut self, records: &Records, holder: Tid, target: Tid, edge: Option<Edge>) {
        if records.is_record_edge(&holder, &target) {
            mark(&mut self.cut, (holder, target), edge.is_none());
            self.set_explicit(holder, target, edge.filter(|e| *e != RECORD_EDGE));
        } else {
            self.set_explicit(holder, target, edge);
        }
    }
    fn set_explicit(&mut self, holder: Tid, target: Tid, edge: Option<Edge>) {
        match edge {
            Some(e) => {
                if self.explicit(&holder, &target) == Some(&e) {
                    return;
                }
                Arc::make_mut(self.by_target.entry(target).or_default()).insert(holder, e);
                Arc::make_mut(self.by_holder.entry(holder).or_default()).insert(target);
            }
            None => {
                if self.explicit(&holder, &target).is_none() {
                    return;
                }
                if let Some(m) = self.by_target.get_mut(&target) {
                    let m = Arc::make_mut(m);
                    m.remove(&holder);
                    if m.is_empty() {
                        self.by_target.remove(&target);
                    }
                }
                if let Some(s) = self.by_holder.get_mut(&holder) {
                    let s = Arc::make_mut(s);
                    s.remove(&target);
                    if s.is_empty() {
                        self.by_holder.remove(&holder);
                    }
                }
            }
        }
    }
    /// Written edges on `target`, by holder.
    fn holders(&self, target: &Tid) -> impl Iterator<Item = (&Tid, &Edge)> {
        self.by_target.get(target).into_iter().flat_map(|m| m.iter())
    }
    /// Targets of `holder`'s written edges.
    fn targets(&self, holder: &Tid) -> impl Iterator<Item = &Tid> {
        self.by_holder.get(holder).into_iter().flat_map(|s| s.iter())
    }
    /// Every written edge.
    pub fn iter(&self) -> impl Iterator<Item = (&Tid, &Tid, &Edge)> {
        self.by_target.iter().flat_map(|(t, m)| m.iter().map(move |(h, e)| (h, t, e)))
    }
}

/// Edges set over a base edge state: an edge here replaces the base's (`None`: removed).
/// Sorted by (holder, target), with a 256-bit filter of
/// the holders and targets present so most lookups skip them.
#[derive(Clone, Debug, Default)]
pub(crate) struct Overlay {
    set: Vec<(Tid, Tid, Option<Edge>)>,
    holders: [u64; 4],
    targets: [u64; 4],
}

/// `t`'s bit in an `Overlay` filter.
fn bit(t: &Tid) -> (usize, u64) {
    let b = t.as_bytes().last().copied().unwrap_or(0);
    (usize::from(b >> 6), 1 << (b & 63))
}

fn has(mask: &[u64; 4], t: &Tid) -> bool {
    let (i, m) = bit(t);
    mask.get(i).is_some_and(|w| w & m != 0)
}

fn set_bit(mask: &mut [u64; 4], t: &Tid) {
    let (i, m) = bit(t);
    if let Some(w) = mask.get_mut(i) {
        *w |= m;
    }
}

impl Overlay {
    pub fn set(&mut self, holder: Tid, target: Tid, edge: Option<Edge>) {
        match self.set.binary_search_by(|x| (x.0, x.1).cmp(&(holder, target))) {
            Ok(i) => {
                if let Some(x) = self.set.get_mut(i) {
                    x.2 = edge;
                }
            }
            Err(i) => self.set.insert(i, (holder, target, edge)),
        }
        set_bit(&mut self.holders, &holder);
        set_bit(&mut self.targets, &target);
    }
    fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
    /// The edges of `holder` set here, by target.
    fn of_holder(&self, holder: &Tid) -> &[(Tid, Tid, Option<Edge>)] {
        if !has(&self.holders, holder) {
            return &[];
        }
        let lo = self.set.partition_point(|x| x.0 < *holder);
        let hi = self.set.partition_point(|x| x.0 <= *holder);
        self.set.get(lo..hi).unwrap_or_default()
    }
    /// The edges on `target` set here, by holder.
    fn of_target<'s>(&'s self, target: &'s Tid) -> impl Iterator<Item = (&'s Tid, &'s Option<Edge>)> + 's {
        let any = has(&self.targets, target);
        self.set.iter().filter(move |x| any && x.1 == *target).map(|x| (&x.0, &x.2))
    }
    fn get(&self, holder: &Tid, target: &Tid) -> Option<&Option<Edge>> {
        let m = self.of_holder(holder);
        m.binary_search_by(|x| x.1.cmp(target)).ok().and_then(|i| m.get(i)).map(|x| &x.2)
    }
}

/// An edge state as a base state (a kept one) with an overlay of the changes since: a past
/// state without copying the base. Record edges in force are read from `records`.
#[derive(Clone, Debug)]
pub struct EdgesAt<'a> {
    records: &'a Records,
    base: &'a Edges,
    over: Overlay,
}

impl<'a> EdgesAt<'a> {
    pub fn new(records: &'a Records, base: &'a Edges) -> EdgesAt<'a> {
        EdgesAt { records, base, over: Overlay::default() }
    }
    pub fn set(&mut self, holder: Tid, target: Tid, edge: Option<Edge>) {
        self.over.set(holder, target, edge);
    }
    pub fn get(&self, holder: &Tid, target: &Tid) -> Option<&Edge> {
        match self.over.get(holder, target) {
            Some(e) => e.as_ref(),
            None => self.base.get(self.records, holder, target),
        }
    }
    /// Whether the overlay or a write in the base sets (holder, target), so its record edge is
    /// not in force by the record.
    fn written(&self, holder: &Tid, target: &Tid) -> bool {
        self.over.get(holder, target).is_some() || self.base.explicit(holder, target).is_some() || self.base.is_cut(holder, target)
    }
    /// Edges on `target`, by holder.
    pub fn holders<'s>(&'s self, target: &'s Tid) -> impl Iterator<Item = (&'s Tid, &'s Edge)> + 's {
        let over = &self.over;
        let base = self.base.holders(target).filter(move |(m, _)| over.get(m, target).is_none());
        let record = self.records.mint_admin_ref(target).filter(|a| !self.written(a, target)).map(|a| (a, &RECORD_EDGE));
        base.chain(over.of_target(target).filter_map(|(m, e)| e.as_ref().map(|e| (m, e)))).chain(record)
    }
    /// Targets of `holder`'s edges.
    pub fn targets<'s>(&'s self, holder: &'s Tid) -> impl Iterator<Item = &'s Tid> + 's {
        let over = self.over.of_holder(holder);
        let base = self.base.targets(holder).filter(move |t| over.binary_search_by(|x| x.1.cmp(t)).is_err());
        let record = self.records.mint_admin_of(holder).iter().filter(move |t| !self.written(holder, t));
        base.chain(over.iter().filter_map(|x| x.2.as_ref().map(|_| &x.1))).chain(record)
    }
    /// Every edge, record edges in force included (O(things)).
    pub fn iter(&self) -> impl Iterator<Item = (&Tid, &Tid, &Edge)> {
        let over = &self.over;
        let base = self.base.iter().filter(move |(m, t, _)| over.get(m, t).is_none());
        let mut set: Vec<(&Tid, &Tid, &Edge)> = over.set.iter().filter_map(|x| x.2.as_ref().map(|e| (&x.0, &x.1, e))).collect();
        set.sort_by_key(|x| (*x.1, *x.0));
        let record = self.records.links().filter_map(move |(t, o)| match o {
            RecordLink::Admin(a) if !self.written(a, t) => Some((a, t, &RECORD_EDGE)),
            _ => None,
        });
        base.chain(set).chain(record)
    }
}

/// One edge set to a value over an edge state: (holder, target, value).
type Patch = (Tid, Tid, Option<Edge>);

/// Authority queries over the records and an edge state (optionally a base with an overlay),
/// with edges alive at `ts` (`None`: the end of time), and optionally one edge patched.
#[derive(Clone)]
pub struct View<'a> {
    records: &'a Records,
    edges: &'a Edges,
    over: Option<&'a Overlay>,
    pub ts: Option<Ts>,
    patch: Option<Patch>,
}

impl<'a> View<'a> {
    pub fn new(records: &'a Records, edges: &'a Edges, ts: Option<Ts>) -> View<'a> {
        View { records, edges, over: None, ts, patch: None }
    }
    /// A view of a past edge state.
    pub fn at(edges: &'a EdgesAt<'a>, ts: Option<Ts>) -> View<'a> {
        let over = Some(&edges.over).filter(|o| !o.is_empty());
        View { records: edges.records, edges: edges.base, over, ts, patch: None }
    }
    /// Whether `t` is a key actor by its record.
    pub fn is_key(&self, t: &Tid) -> bool {
        self.records.is_key(t)
    }
    /// The same view with edge (holder, target) set to `edge`.
    pub fn patched(self, holder: Tid, target: Tid, edge: Option<Edge>) -> View<'a> {
        View { patch: Some((holder, target, edge)), ..self }
    }

    /// Whether the patch, the overlay or a write sets (holder, target): its record edge is then
    /// not in force by the record.
    fn written(&self, holder: &Tid, target: &Tid) -> bool {
        self.patch.is_some_and(|p| p.0 == *holder && p.1 == *target)
            || self.over.is_some_and(|o| o.get(holder, target).is_some())
            || self.edges.explicit(holder, target).is_some()
            || self.edges.is_cut(holder, target)
    }

    /// The edge (holder, target) in force.
    pub fn get(&self, holder: &Tid, target: &Tid) -> Option<&Edge> {
        if let Some(p) = self.patch.as_ref().filter(|p| p.0 == *holder && p.1 == *target) {
            return p.2.as_ref();
        }
        if let Some(e) = self.over.and_then(|o| o.get(holder, target)) {
            return e.as_ref();
        }
        self.edges.get(self.records, holder, target)
    }

    /// `f` on each edge of `holder`: (target, value).
    fn each_target(&self, holder: &Tid, mut f: impl FnMut(&Tid, &Edge)) {
        let patch = self.patch.as_ref().filter(|p| p.0 == *holder);
        let over = self.over.map_or(&[][..], |o| o.of_holder(holder));
        for t in self.edges.targets(holder) {
            if patch.is_some_and(|p| p.1 == *t) || (!over.is_empty() && over.binary_search_by(|x| x.1.cmp(t)).is_ok()) {
                continue;
            }
            if let Some(e) = self.edges.explicit(holder, t) {
                f(t, e);
            }
        }
        for (_, t, e) in over {
            if let Some(e) = e.as_ref().filter(|_| patch.is_none_or(|p| p.1 != *t)) {
                f(t, e);
            }
        }
        if let Some((_, t, Some(e))) = patch {
            f(t, e);
        }
        for t in self.records.mint_admin_of(holder) {
            if !self.written(holder, t) {
                f(t, &RECORD_EDGE);
            }
        }
    }

    /// `f` on each edge on `target`: (holder, value).
    fn each_holder(&self, target: &Tid, mut f: impl FnMut(&Tid, &Edge)) {
        let patch = self.patch.as_ref().filter(|p| p.1 == *target);
        let over = self.over.filter(|o| has(&o.targets, target));
        for (m, e) in self.edges.holders(target) {
            if patch.is_none_or(|p| p.0 != *m) && over.is_none_or(|o| o.get(m, target).is_none()) {
                f(m, e);
            }
        }
        for (m, e) in over.into_iter().flat_map(|o| o.of_target(target)) {
            if let Some(e) = e.as_ref().filter(|_| patch.is_none_or(|p| p.0 != *m)) {
                f(m, e);
            }
        }
        if let Some((m, _, Some(e))) = patch {
            f(m, e);
        }
        if let Some(a) = self.records.mint_admin_ref(target)
            && !self.written(a, target)
        {
            f(a, &RECORD_EDGE);
        }
    }

    /// Effective role of `x` on every thing it reaches (spec/permissions.md §1): the maximum
    /// over paths of the minimum role along the path; `x` is admin of itself.
    pub fn roles_from(&self, x: &Tid) -> BTreeMap<Tid, Role> {
        self.roles_expiring(x).0
    }

    /// `roles_from` over the edges not in `skip`, each named (target, holder).
    pub fn roles_from_without(&self, x: &Tid, skip: &BTreeSet<(Tid, Tid)>) -> BTreeMap<Tid, Role> {
        self.roles_walk(x, skip).0
    }

    /// `roles_from` and the earliest `until` of an edge it followed: the answer holds at any
    /// later ts before that, while no edge of a node it reaches changes.
    pub(crate) fn roles_expiring(&self, x: &Tid) -> (BTreeMap<Tid, Role>, Option<WallMs>) {
        self.roles_walk(x, &BTreeSet::new())
    }

    /// `roles_expiring`, not walking over an edge in `skip` (target, holder).
    fn roles_walk(&self, x: &Tid, skip: &BTreeSet<(Tid, Tid)>) -> (BTreeMap<Tid, Role>, Option<WallMs>) {
        let mut expires: Option<WallMs> = None;
        let mut best: BTreeMap<Tid, Role> = BTreeMap::from([(*x, Role::Admin)]);
        for level in Role::ALL.into_iter().rev() {
            let mut stack: Vec<Tid> = best.iter().filter(|&(_, &r)| r == level).map(|(t, _)| *t).collect();
            while let Some(e) = stack.pop() {
                self.each_target(&e, |t, edge| {
                    if edge.alive_at(self.ts) && !skip.contains(&(*t, e)) {
                        expires = earliest(expires, edge.until);
                        let (y, v) = (*t, level.min(edge.role));
                        if best.get(&y).is_none_or(|&b| v > b) {
                            best.insert(y, v);
                            if v == level {
                                stack.push(y);
                            }
                        }
                    }
                });
            }
        }
        crate::count::reached(best.len());
        // counted: tests read how much a role walk reaches
        osis_base::costs::count("perm: roles walked", best.len() as u64);
        (best, expires)
    }

    /// What `x`'s roles gain over `best`, its roles over edges this view dominates (every
    /// edge here at least as wide, alive at `ts`), where only edges out of `seeds` may be
    /// wider: the raised entries. `best` with them equals `roles_from` on this view.
    pub fn roles_raised(&self, best: &BTreeMap<Tid, Role>, seeds: &[Tid]) -> BTreeMap<Tid, Role> {
        self.roles_raised_expiring(best, seeds).0
    }

    /// `roles_raised` and the earliest `until` of an edge it followed.
    pub(crate) fn roles_raised_expiring(&self, best: &BTreeMap<Tid, Role>, seeds: &[Tid]) -> (BTreeMap<Tid, Role>, Option<WallMs>) {
        let mut expires: Option<WallMs> = None;
        let mut raised: BTreeMap<Tid, Role> = BTreeMap::new();
        let mut stack: Vec<Tid> = seeds.iter().filter(|s| best.contains_key(s)).copied().collect();
        while let Some(e) = stack.pop() {
            let Some(level) = raised.get(&e).or_else(|| best.get(&e)).copied() else { continue };
            self.each_target(&e, |t, edge| {
                if edge.alive_at(self.ts) {
                    expires = earliest(expires, edge.until);
                    let (y, v) = (*t, level.min(edge.role));
                    if raised.get(&y).or_else(|| best.get(&y)).is_none_or(|&b| v > b) {
                        raised.insert(y, v);
                        stack.push(y);
                    }
                }
            });
        }
        (raised, expires)
    }

    /// Every entity's effective role on `y` (`roles_from(x)[y]` for each `x`): the widest
    /// paths searched backward from `y`.
    pub fn roles_to(&self, y: &Tid) -> BTreeMap<Tid, Role> {
        self.roles_to_any(&[*y])
    }

    /// Every entity's highest effective role on any of `ys`.
    pub(crate) fn roles_to_any(&self, ys: &[Tid]) -> BTreeMap<Tid, Role> {
        self.roles_back(ys, &BTreeSet::new()).0
    }

    /// `roles_to` over the edges not in `skip`, each named (target, holder), and the earliest
    /// `until` of an edge it followed: the answer holds at any later ts before that, while no
    /// edge into a node it reaches changes.
    pub(crate) fn roles_to_expiring(&self, y: &Tid, skip: &BTreeSet<(Tid, Tid)>) -> (BTreeMap<Tid, Role>, Option<WallMs>) {
        self.roles_back(&[*y], skip)
    }

    /// `roles_to_any` over the edges not in `skip`, with the earliest `until` it followed.
    fn roles_back(&self, ys: &[Tid], skip: &BTreeSet<(Tid, Tid)>) -> (BTreeMap<Tid, Role>, Option<WallMs>) {
        let mut expires: Option<WallMs> = None;
        let mut best: BTreeMap<Tid, Role> = ys.iter().map(|y| (*y, Role::Admin)).collect();
        let mut stack = ys.to_vec();
        while let Some(t) = stack.pop() {
            let Some(&level) = best.get(&t) else { continue };
            let mut up: Vec<(Tid, Role)> = Vec::new();
            self.each_holder(&t, |m, e| {
                if e.alive_at(self.ts) && !skip.contains(&(t, *m)) {
                    expires = earliest(expires, e.until);
                    up.push((*m, level.min(e.role)));
                }
            });
            for (z, v) in up {
                if best.get(&z).is_none_or(|&b| v > b) {
                    best.insert(z, v);
                    stack.push(z);
                }
            }
        }
        osis_base::costs::count("perm: roles walked", best.len() as u64);
        (best, expires)
    }

    /// The ways into `y` giving at least `need` (`Ways`): breadth first, backward from `y`, over
    /// edges alive at the view's `ts` each giving `need` or more (for `Need::MayGrant`, the edges
    /// into `y` giving admin or carrying the flag: spec/permissions.md §2 Path's may-grant), holders
    /// taken in the order the edge state lists them; with the earliest `until` it followed. A
    /// mint ancestor two or more record edges up reaches a thing by its direct edge only as a hop
    /// marked direct (spec/permissions.md §1 Path, Direct mark): ways are the fewest
    /// edges (a descent counts each record edge), then the fewest marked hops, so a far mint
    /// ancestor's direct edge is stated wherever it gives the need: a write rests on the one
    /// edge rather than the record chain. The breadth-first search, ties to fewer marks. O(things reaching `y` × their edges into it × log).
    pub(crate) fn ways_to(&self, y: &Tid, need: Need) -> (Ways, Option<WallMs>) {
        let mut expires: Option<WallMs> = None;
        let mut next: BTreeMap<Tid, Tid> = BTreeMap::new();
        let mut settled: BTreeSet<Tid> = BTreeSet::new();
        // (edges, marked hops, order met) → (thing, the thing it reaches next)
        let mut queue: BTreeMap<(u32, u32, u64), (Tid, Option<Tid>)> = BTreeMap::from([((0, 0, 0), (*y, None))]);
        let mut met = 0u64;
        let role = need.role();
        while let Some(((len, marks, _), (t, via))) = queue.pop_first() {
            if !settled.insert(t) {
                continue;
            }
            if let Some(v) = via {
                next.insert(t, v);
            }
            let parent = self.records.mint_admin(&t);
            let up: BTreeSet<Tid> = std::iter::successors(parent.and_then(|p| self.records.mint_admin(&p)), |a| self.records.mint_admin(a)).take(osis_base::format::MAX_CHAIN_DEPTH).collect();
            let mut found: Vec<(Tid, bool)> = Vec::new();
            let last = matches!(need, Need::MayGrant(_)) && t == *y;
            self.each_holder(&t, |m, e| {
                let gives = e.role >= role && (!last || e.role == Role::Admin || e.may_grant);
                if e.alive_at(self.ts) && gives {
                    expires = earliest(expires, e.until);
                    found.push((*m, up.contains(m)));
                }
            });
            for (m, marked) in found {
                if !settled.contains(&m) {
                    met += 1;
                    queue.insert((len + 1, marks + u32::from(marked), met), (m, Some(t)));
                }
            }
        }
        osis_base::costs::count("perm: ways walked", next.len() as u64 + 1);
        (Ways { to: *y, next }, expires)
    }

    /// The highest role at which a path from `x` into `n` gives may-grant, given `x`'s roles
    /// (spec/permissions.md §2 Path's may-grant): over the edges into `n` giving admin or
    /// carrying the flag, what `x` holds on the holder and the edge gives.
    pub fn may_grant(&self, best: &BTreeMap<Tid, Role>, n: &Tid) -> Option<Role> {
        let mut top = None;
        self.each_holder(n, |m, e| {
            if let (Some(&r), true) = (best.get(m), e.alive_at(self.ts) && (e.role == Role::Admin || e.may_grant)) {
                top = top.max(Some(r.min(e.role)));
            }
        });
        top
    }

    /// Standing of `x` on `n` given `x`'s roles.
    pub fn standing(&self, best: &BTreeMap<Tid, Role>, n: &Tid) -> Standing {
        let role = best.get(n).copied();
        Standing { class: if role == Some(Role::Admin) { Class::Edge } else { self.may_grant(best, n).map_or(Class::None, Class::MayGrant) }, role }
    }

    /// Things reachable from `start` (included) by edges of any role and `until`.
    pub fn reach_forward(&self, start: &Tid) -> BTreeSet<Tid> {
        let mut seen = BTreeSet::from([*start]);
        let mut stack = vec![*start];
        while let Some(e) = stack.pop() {
            self.each_target(&e, |y, _| {
                if seen.insert(*y) {
                    stack.push(*y);
                }
            });
        }
        seen
    }

    /// Entities that reach `start` (included) by edges of any role and `until`.
    pub fn reach_backward(&self, start: &Tid) -> BTreeSet<Tid> {
        let mut seen = BTreeSet::from([*start]);
        let mut stack = vec![*start];
        while let Some(e) = stack.pop() {
            let mut up: Vec<Tid> = Vec::new();
            self.each_holder(&e, |m, _| up.push(*m));
            for y in up {
                if seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        seen
    }
}

/// What a path must give on the thing it ends at (spec/permissions.md §1 Path, §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Need {
    /// At least this role on every edge.
    Role(Role),
    /// May-grant at this role (§2 Path's may-grant): at least the role on every edge, the last
    /// giving admin or carrying the flag: what a may-grant grant of the role needs.
    MayGrant(Role),
}

impl Need {
    pub fn role(self) -> Role {
        match self {
            Need::Role(r) | Need::MayGrant(r) => r,
        }
    }
}

/// Every thing's shortest way into one thing `to` by edges giving some role (`View::ways_to`):
/// per thing, the next one on its way. A function of the edge state alone: the shortest way by
/// edges, and among ways as short the one the backward search met first (holders in the order the
/// edge state lists them).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ways {
    to: Tid,
    next: BTreeMap<Tid, Tid>,
}

impl Ways {
    /// The path from `from` into the thing (spec/permissions.md §1 Path): the things listed
    /// between them, each hop a direct edge or a descent (a run of record edges, whose things in
    /// between are not listed), the hops marked direct (a mint ancestor two or more record edges
    /// up reaching by its direct edge), and whether its last hop is a record edge (so the thing's
    /// own dependents are reached from the same listed things); the empty path for `from` itself.
    /// `None` where `from` has no way in. O(its length × the record chains' depth).
    pub fn path(&self, records: &Records, from: &Tid) -> Option<(Vec<Tid>, PathMarks, bool)> {
        if *from == self.to {
            return Some((Vec::new(), 0, true));
        }
        let mut hops = vec![*from];
        let mut at = *from;
        while at != self.to {
            at = *self.next.get(&at)?;
            hops.push(at);
        }
        let listed: Vec<Tid> = hops.windows(3).filter_map(|w| match w {
            [p, q, r] if !(records.is_record_edge(p, q) && records.is_record_edge(q, r)) => Some(*q),
            _ => None,
        }).collect();
        // a step that is no record edge from a mint ancestor of its target is a marked hop: its
        // first thing is a member (listed, or `from`), the hop's index its place among them
        let mut marks: PathMarks = 0;
        let mut members = 1u32;
        for w in hops.windows(2) {
            if let [p, q] = w {
                if !records.is_record_edge(p, q) && std::iter::successors(records.mint_admin(q), |a| records.mint_admin(a)).take(MAX_CHAIN_DEPTH).any(|a| a == *p) {
                    marks |= 1 << (members - 1);
                }
                if listed.contains(q) {
                    members += 1;
                }
            }
        }
        let last = hops.iter().rev().nth(1).is_some_and(|p| records.is_record_edge(p, &self.to));
        Some((listed, marks, last))
    }
}
