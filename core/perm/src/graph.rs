//! Authority over one edge state (spec/permissions.md §1, §2, §5.1 step 3): effective role as
//! the widest path over role edges, effective invite, authority class. Record edges
//! (spec/permissions.md §1) are virtual: a first admin's edge on its thing is read from the
//! creation record (`Owners`) unless an edge write set it (`Edges` holds the value written, or
//! that it was removed), so plain things cost the edge state nothing.

use crate::held::HeldSet;
use crate::types::{earliest, mark, put, Edge};
use osis_base::{CreationRecord, Owner, Role, Tid, Ts, WallMs};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Authority class of a node on a thing (spec/permissions.md §5.1 step 3), ordered: edge admin
/// above every invite level.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Class {
    None,
    Invite(Role),
    Edge,
}

/// A node's standing on a thing: its class and effective role.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Standing {
    pub class: Class,
    pub role: Option<Role>,
}

impl Standing {
    pub const NONE: Standing = Standing { class: Class::None, role: None };
    pub fn max(self, o: Standing) -> Standing {
        Standing { class: self.class.max(o.class), role: self.role.max(o.role) }
    }
}

/// The value of a record edge in force (spec/permissions.md §1): admin, no `until`, no invite.
pub const RECORD_EDGE: Edge = Edge { role: Role::Admin, until: None, invite: None, tied: None };

/// Record links of every thing with a verified `created.0`: each thing's first admin (or that
/// it is a key actor), and the things each actor is first admin of.
#[derive(Clone, Debug, Default)]
pub struct Owners {
    link: BTreeMap<Tid, Owner>,
    owned: BTreeMap<Tid, Vec<Tid>>,
}

impl Owners {
    /// From the held `created.0` records; one that does not hash to its tid is ignored.
    pub(crate) fn from_held(held: &dyn HeldSet, things: &BTreeSet<Tid>) -> Owners {
        let mut o = Owners::default();
        for t in things {
            if let Some(rec) = held.created(t)
                && rec.tid() == *t
            {
                o.insert(*t, &rec);
            }
        }
        o
    }
    pub fn insert(&mut self, t: Tid, rec: &CreationRecord) {
        let link = rec.owner_link();
        if let Owner::Admin(a) = link {
            self.owned.entry(a).or_default().push(t);
        }
        self.link.insert(t, link);
    }
    /// Every record link, by thing.
    pub fn links(&self) -> impl Iterator<Item = (&Tid, &Owner)> {
        self.link.iter()
    }
    pub fn owner(&self, t: &Tid) -> Option<Owner> {
        self.link.get(t).copied()
    }
    pub fn is_key(&self, t: &Tid) -> bool {
        self.owner(t) == Some(Owner::Key)
    }
    /// The things `a` is first admin of (its record edges' targets).
    pub fn owned(&self, a: &Tid) -> &[Tid] {
        self.owned.get(a).map_or(&[], |v| v.as_slice())
    }
    /// The first admin of `t` (its record edge's holder) when its record is held and names one.
    pub fn first_admin(&self, t: &Tid) -> Option<Tid> {
        self.first_admin_ref(t).copied()
    }
    fn first_admin_ref(&self, t: &Tid) -> Option<&Tid> {
        match self.link.get(t) {
            Some(Owner::Admin(a)) => Some(a),
            _ => None,
        }
    }
    /// Whether (`holder`, `target`) is `target`'s record edge.
    pub fn is_record_edge(&self, holder: &Tid, target: &Tid) -> bool {
        self.first_admin(target) == Some(*holder)
    }
}

/// An edge state: every current `roles.0` edge set by a write (a record edge in force is read
/// from the records, `Owners`; one written over is here, one removed in `cut`). The per-target
/// and per-holder maps are shared between clones until written (a kept state costs O(targets +
/// holders), not O(edges)).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Edges {
    by_target: BTreeMap<Tid, Arc<BTreeMap<Tid, Edge>>>,
    by_holder: BTreeMap<Tid, Arc<BTreeSet<Tid>>>,
    /// Record edges (holder, target) a write removed, with no value written since.
    cut: BTreeSet<(Tid, Tid)>,
}

/// An empty edge state: the state before every write (every record edge in force).
pub(crate) static INITIAL: Edges = Edges { by_target: BTreeMap::new(), by_holder: BTreeMap::new(), cut: BTreeSet::new() };

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
    pub fn get(&self, records: &Owners, holder: &Tid, target: &Tid) -> Option<&Edge> {
        self.explicit(holder, target).or_else(|| (records.is_record_edge(holder, target) && !self.is_cut(holder, target)).then_some(&RECORD_EDGE))
    }
    /// Sets (holder, target) to `edge`; a record edge set to its record value is in force by
    /// the record again.
    pub fn set(&mut self, records: &Owners, holder: Tid, target: Tid, edge: Option<Edge>) {
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
    /// Sets `changes` in each of `states`, consecutive kept states in order: a map two
    /// neighbours shared before stays shared (one copy per run of states sharing it).
    pub(crate) fn set_all<'a>(records: &Owners, states: impl Iterator<Item = &'a mut Arc<Edges>>, changes: &[(Tid, Tid, Option<Edge>)]) {
        /// The target's and the holder's maps before and after a change, in the previous state.
        type Was = ((Option<Arc<BTreeMap<Tid, Edge>>>, Option<Arc<BTreeMap<Tid, Edge>>>), (Option<Arc<BTreeSet<Tid>>>, Option<Arc<BTreeSet<Tid>>>));
        fn same<T>(a: &Option<Arc<T>>, b: &Option<Arc<T>>) -> bool {
            match (a, b) {
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                (None, None) => true,
                _ => false,
            }
        }
        let mut last: Vec<Was> = Vec::new();
        for s in states {
            let s = Arc::make_mut(s);
            for (j, (m, t, e)) in changes.iter().enumerate() {
                let record = records.is_record_edge(m, t);
                if record {
                    mark(&mut s.cut, (*m, *t), e.is_none());
                }
                let e = &e.filter(|e| !(record && *e == RECORD_EDGE));
                let old_t = s.by_target.get(t).cloned();
                let old_m = s.by_holder.get(m).cloned();
                let prev = last.get(j);
                let new_t = match prev {
                    Some((p, _)) if same(&p.0, &old_t) => p.1.clone(),
                    _ => {
                        let mut v = old_t.as_deref().cloned().unwrap_or_default();
                        put(&mut v, *m, *e);
                        (!v.is_empty()).then(|| Arc::new(v))
                    }
                };
                let new_m = match prev {
                    Some((_, p)) if same(&p.0, &old_m) => p.1.clone(),
                    _ => {
                        let mut v = old_m.as_deref().cloned().unwrap_or_default();
                        mark(&mut v, *t, e.is_some());
                        (!v.is_empty()).then(|| Arc::new(v))
                    }
                };
                put(&mut s.by_target, *t, new_t.clone());
                put(&mut s.by_holder, *m, new_m.clone());
                let x = ((old_t, new_t), (old_m, new_m));
                match last.get_mut(j) {
                    Some(l) => *l = x,
                    None => last.push(x),
                }
            }
        }
    }
    /// Adds `from`'s per-target maps and cut record edges (another component's: their targets
    /// are not here).
    pub(crate) fn take_targets(&mut self, from: &Edges) {
        self.by_target.extend(from.by_target.iter().map(|(t, m)| (*t, m.clone())));
        self.cut.extend(from.cut.iter().copied());
    }
    /// The (holder, target) edges that differ from `old`. O(targets), plus the holders of the
    /// targets whose maps differ: an unwritten map is shared with its clone.
    pub(crate) fn diff(&self, old: &Edges, out: &mut BTreeSet<(Tid, Tid)>) {
        out.extend(self.cut.symmetric_difference(&old.cut).copied());
        let empty = Arc::new(BTreeMap::new());
        let targets = self.by_target.keys().chain(old.by_target.keys().filter(|t| !self.by_target.contains_key(*t)));
        for t in targets {
            let (a, b) = (self.by_target.get(t).unwrap_or(&empty), old.by_target.get(t).unwrap_or(&empty));
            if Arc::ptr_eq(a, b) {
                continue;
            }
            out.extend(a.iter().filter(|(h, e)| b.get(*h) != Some(*e)).map(|(h, _)| (*h, *t)));
            out.extend(b.keys().filter(|h| !a.contains_key(*h)).map(|h| (*h, *t)));
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
    /// The record edges a write removed.
    pub(crate) fn cuts(&self) -> impl Iterator<Item = &(Tid, Tid)> {
        self.cut.iter()
    }
    /// A state from its written edges and cut record edges (a saved walk's).
    pub(crate) fn restore(written: impl IntoIterator<Item = (Tid, Tid, Edge)>, cut: BTreeSet<(Tid, Tid)>) -> Edges {
        let mut e = Edges { cut, ..Edges::default() };
        for (m, t, v) in written {
            e.set_explicit(m, t, Some(v));
        }
        e
    }
}

/// Edges set over a base edge state: an edge here replaces the base's (`None`: removed). A
/// few (at most a checkpoint interval), sorted by (holder, target), with a 256-bit filter of
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
    records: &'a Owners,
    base: &'a Edges,
    over: Overlay,
}

impl<'a> EdgesAt<'a> {
    pub fn new(records: &'a Owners, base: &'a Edges) -> EdgesAt<'a> {
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
        let record = self.records.first_admin_ref(target).filter(|a| !self.written(a, target)).map(|a| (a, &RECORD_EDGE));
        base.chain(over.of_target(target).filter_map(|(m, e)| e.as_ref().map(|e| (m, e)))).chain(record)
    }
    /// Targets of `holder`'s edges.
    pub fn targets<'s>(&'s self, holder: &'s Tid) -> impl Iterator<Item = &'s Tid> + 's {
        let over = self.over.of_holder(holder);
        let base = self.base.targets(holder).filter(move |t| over.binary_search_by(|x| x.1.cmp(t)).is_err());
        let record = self.records.owned(holder).iter().filter(move |t| !self.written(holder, t));
        base.chain(over.iter().filter_map(|x| x.2.as_ref().map(|_| &x.1))).chain(record)
    }
    /// Every edge, record edges in force included (O(things)).
    pub fn iter(&self) -> impl Iterator<Item = (&Tid, &Tid, &Edge)> {
        let over = &self.over;
        let base = self.base.iter().filter(move |(m, t, _)| over.get(m, t).is_none());
        let mut set: Vec<(&Tid, &Tid, &Edge)> = over.set.iter().filter_map(|x| x.2.as_ref().map(|e| (&x.0, &x.1, e))).collect();
        set.sort_by_key(|x| (*x.1, *x.0));
        let record = self.records.links().filter_map(move |(t, o)| match o {
            Owner::Admin(a) if !self.written(a, t) => Some((a, t, &RECORD_EDGE)),
            _ => None,
        });
        base.chain(set).chain(record)
    }
}

/// Roles by dense index, the indexes reached, and the earliest `until` followed
/// (`Dense::roles`).
pub(crate) type DenseRoles = (Vec<Option<Role>>, Vec<usize>, Option<WallMs>);

/// An edge state by dense index, for searches without map lookups per edge (the same answers
/// as `View`'s): a fixed set of entities and the edges out of and into each, record edges in
/// force included, kept in step with `set`.
pub(crate) struct Dense {
    pub ids: BTreeMap<Tid, usize>,
    pub tids: Vec<Tid>,
    out: Vec<Vec<(usize, Edge)>>,
    inc: Vec<Vec<usize>>,
    /// Every edge set has both ends indexed (else callers search through `View`).
    pub whole: bool,
}

impl Dense {
    pub fn new(records: &Owners, all: BTreeSet<Tid>, edges: &Edges) -> Dense {
        let tids: Vec<Tid> = all.into_iter().collect();
        let ids: BTreeMap<Tid, usize> = tids.iter().enumerate().map(|(i, t)| (*t, i)).collect();
        let n = tids.len();
        let mut g = Dense { out: vec![Vec::new(); n], inc: vec![Vec::new(); n], ids, tids, whole: true };
        // each pair once (a record edge only where no write set the pair): pushed, then sorted
        // once per holder (`set` keeps the order; a holder of a million things costs no scan)
        let record = records.links().filter_map(|(t, o)| match o {
            Owner::Admin(a) if edges.explicit(a, t).is_none() && !edges.is_cut(a, t) => Some((a, t, RECORD_EDGE)),
            _ => None,
        });
        for (m, t, e) in record.chain(edges.iter().map(|(m, t, e)| (m, t, *e))) {
            let (Some(&mi), Some(&ti)) = (g.ids.get(m), g.ids.get(t)) else { continue };
            if let Some(out) = g.out.get_mut(mi) {
                out.push((ti, e));
            }
            if let Some(inc) = g.inc.get_mut(ti) {
                inc.push(mi);
            }
        }
        for out in &mut g.out {
            out.sort_unstable_by_key(|x| x.0);
        }
        g
    }

    pub fn set(&mut self, holder: &Tid, target: &Tid, edge: Option<Edge>) {
        let (Some(&m), Some(&t)) = (self.ids.get(holder), self.ids.get(target)) else {
            self.whole &= edge.is_none();
            return;
        };
        let Some(out) = self.out.get_mut(m) else { return };
        match (out.binary_search_by_key(&t, |x| x.0), edge) {
            (Ok(i), Some(e)) => {
                if let Some(x) = out.get_mut(i) {
                    x.1 = e;
                }
            }
            (Ok(i), None) => {
                out.remove(i);
                if let Some(inc) = self.inc.get_mut(t)
                    && let Some(j) = inc.iter().position(|x| *x == m)
                {
                    inc.swap_remove(j);
                }
            }
            (Err(i), Some(e)) => {
                out.insert(i, (t, e));
                if let Some(inc) = self.inc.get_mut(t) {
                    inc.push(m);
                }
            }
            (Err(_), None) => {}
        }
    }

    /// `View::roles_expiring` of `x` at `ts`: the roles by index, the indexes reached, and
    /// the earliest `until` followed. `None` when not `whole` or `x` has no index.
    pub fn roles(&self, x: &Tid, ts: Ts) -> Option<DenseRoles> {
        let &xi = self.ids.get(x).filter(|_| self.whole)?;
        let mut best: Vec<Option<Role>> = vec![None; self.tids.len()];
        *best.get_mut(xi)? = Some(Role::Admin);
        let mut reached = vec![xi];
        let mut expires: Option<WallMs> = None;
        for level in [Role::Admin, Role::Write, Role::Read] {
            let mut stack: Vec<usize> = reached.iter().copied().filter(|i| best.get(*i).copied().flatten() == Some(level)).collect();
            while let Some(e) = stack.pop() {
                for (t, edge) in self.out.get(e).into_iter().flatten() {
                    if edge.alive_at(Some(ts)) {
                        expires = earliest(expires, edge.until);
                        let (y, v) = (*t, level.min(edge.role));
                        if let Some(b) = best.get_mut(y)
                            && b.is_none_or(|b| v > b)
                        {
                            if b.is_none() {
                                reached.push(y);
                            }
                            *b = Some(v);
                            if v == level {
                                stack.push(y);
                            }
                        }
                    }
                }
            }
        }
        Some((best, reached, expires))
    }

    /// `View::roles_raised_expiring` from `seed` over roles `best` by index, raised in place:
    /// the indexes raised and the earliest `until` followed.
    pub fn raise(&self, best: &mut [Option<Role>], seed: &Tid, ts: Ts) -> Option<(Vec<usize>, Option<WallMs>)> {
        let &si = self.ids.get(seed).filter(|_| self.whole)?;
        let mut expires: Option<WallMs> = None;
        let mut raised = Vec::new();
        let mut stack: Vec<usize> = best.get(si).copied().flatten().map(|_| si).into_iter().collect();
        while let Some(e) = stack.pop() {
            let Some(level) = best.get(e).copied().flatten() else { continue };
            for (t, edge) in self.out.get(e).into_iter().flatten() {
                if edge.alive_at(Some(ts)) {
                    expires = earliest(expires, edge.until);
                    let (y, v) = (*t, level.min(edge.role));
                    if let Some(b) = best.get_mut(y)
                        && b.is_none_or(|b| v > b)
                    {
                        *b = Some(v);
                        raised.push(y);
                        stack.push(y);
                    }
                }
            }
        }
        Some((raised, expires))
    }
}

/// What a standing on a thing reads besides the node's roles: its holders holding an invite
/// (edges alive).
pub(crate) struct Reads {
    pub invites: Vec<(Tid, Edge)>,
}

impl Reads {
    /// Standing of `x` on the thing `n` these are of, given `x`'s roles.
    pub fn standing(&self, best: &BTreeMap<Tid, Role>, n: &Tid) -> Standing {
        let role = best.get(n).copied();
        let class = class_of(role, || self.invites.iter().filter_map(|(m, e)| Some(e.invite?.min(*best.get(m)?).min(e.role))).max());
        Standing { class, role }
    }
}

/// Authority class from its parts (§5.1 step 3): the role on the thing, the effective invite
/// there.
fn class_of(role: Option<Role>, invite: impl FnOnce() -> Option<Role>) -> Class {
    if role == Some(Role::Admin) { Class::Edge } else { invite().map_or(Class::None, Class::Invite) }
}

/// One edge set to a value over an edge state: (holder, target, value).
type Patch = (Tid, Tid, Option<Edge>);

/// Authority queries over the records and an edge state (optionally a base with an overlay),
/// with edges alive at `ts` (`None`: the end of time), and optionally one edge patched.
#[derive(Clone)]
pub struct View<'a> {
    records: &'a Owners,
    edges: &'a Edges,
    over: Option<&'a Overlay>,
    pub ts: Option<Ts>,
    patch: Option<Patch>,
}

impl<'a> View<'a> {
    pub fn new(records: &'a Owners, edges: &'a Edges, ts: Option<Ts>) -> View<'a> {
        View { records, edges, over: None, ts, patch: None }
    }
    /// A view of a past edge state.
    pub fn at(edges: &'a EdgesAt<'a>, ts: Option<Ts>) -> View<'a> {
        let over = Some(&edges.over).filter(|o| !o.is_empty());
        View { records: edges.records, edges: edges.base, over, ts, patch: None }
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
        for t in self.records.owned(holder) {
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
        if let Some(a) = self.records.first_admin_ref(target)
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

    /// `roles_from` over paths that never pass through a thing of `avoid` (its own role on it
    /// aside).
    pub fn roles_from_avoiding(&self, x: &Tid, avoid: &BTreeSet<Tid>) -> BTreeMap<Tid, Role> {
        self.roles_walk(x, Some(avoid)).0
    }

    /// `roles_from` and the earliest `until` of an edge it followed: the answer holds at any
    /// later ts before that, while no edge of a node it reaches changes.
    pub(crate) fn roles_expiring(&self, x: &Tid) -> (BTreeMap<Tid, Role>, Option<WallMs>) {
        self.roles_walk(x, None)
    }

    /// `roles_expiring`, not walking on from `avoid`.
    fn roles_walk(&self, x: &Tid, avoid: Option<&BTreeSet<Tid>>) -> (BTreeMap<Tid, Role>, Option<WallMs>) {
        let through = |t: &Tid| avoid.is_none_or(|a| !a.contains(t));
        let mut expires: Option<WallMs> = None;
        let mut best: BTreeMap<Tid, Role> = BTreeMap::from([(*x, Role::Admin)]);
        for level in [Role::Admin, Role::Write, Role::Read] {
            let mut stack: Vec<Tid> = best.iter().filter(|&(t, &r)| r == level && through(t)).map(|(t, _)| *t).collect();
            while let Some(e) = stack.pop() {
                self.each_target(&e, |t, edge| {
                    if edge.alive_at(self.ts) {
                        expires = earliest(expires, edge.until);
                        let (y, v) = (*t, level.min(edge.role));
                        if best.get(&y).is_none_or(|&b| v > b) {
                            best.insert(y, v);
                            if v == level && through(&y) {
                                stack.push(y);
                            }
                        }
                    }
                });
            }
        }
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
        let mut best: BTreeMap<Tid, Role> = ys.iter().map(|y| (*y, Role::Admin)).collect();
        let mut stack = ys.to_vec();
        while let Some(t) = stack.pop() {
            let Some(&level) = best.get(&t) else { continue };
            let mut up: Vec<(Tid, Role)> = Vec::new();
            self.each_holder(&t, |m, e| {
                if e.alive_at(self.ts) {
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
        best
    }

    /// Effective invite on `n` given `x`'s roles (spec/permissions.md §2).
    pub fn invite(&self, best: &BTreeMap<Tid, Role>, n: &Tid) -> Option<Role> {
        let mut inv = None;
        self.each_holder(n, |m, e| {
            if let (Some(i), Some(&r), true) = (e.invite, best.get(m), e.alive_at(self.ts)) {
                inv = inv.max(Some(i.min(r).min(e.role)));
            }
        });
        inv
    }

    /// Standing of `x` on `n` given `x`'s roles.
    pub fn standing(&self, best: &BTreeMap<Tid, Role>, n: &Tid) -> Standing {
        self.reads(n).standing(best, n)
    }

    /// What a standing on `n` reads besides the node's roles.
    pub(crate) fn reads(&self, n: &Tid) -> Reads {
        let mut invites = Vec::new();
        self.each_holder(n, |m, e| {
            if e.invite.is_some() && e.alive_at(self.ts) {
                invites.push((*m, *e));
            }
        });
        Reads { invites }
    }

    /// Standing on `n` from its parts: the node's role on `n` and its roles on `n`'s holders
    /// (for the invite).
    pub(crate) fn standing_from(&self, role: Option<Role>, best: &BTreeMap<Tid, Role>, n: &Tid) -> Standing {
        Standing { class: class_of(role, || self.invite(best, n)), role }
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
