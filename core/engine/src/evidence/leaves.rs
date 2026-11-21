//! A3's list leaves as evidence (notes/a3-spec/permissions.md §4 the leaf bullet, §5.1 Reading a
//! list; notes/evidence-derivation.md, Leaves): which (lowering, thing) leaves each sync ID requires,
//! which leaves judge a held part (a reader lacking one waits), and addenda as bodies only while they
//! list something they can keep.
//!
//! A lowering L in S's set (a member, or a body) requires its leaf for thing t where
//! - **reads**: L **cuts** (a removal-shaped write taking write away on its edge: a record edge, or
//!   a held chained write giving write or above ordered before it) and a body of
//!   S on t has a content-class part resting on L's edge (`Sid::rest`, counted per (edge, thing));
//! - **home**: t is not L's own thing and L is a body of S (a far leaf stays with its lowering
//!   wherever it is a body, so a node holding L holds the leaf a write L judges elsewhere needs).

use super::*;

/// Why a sync ID requires a leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LeafWhy {
    /// A far leaf (a thing other than the lowering's own) of a lowering that is a body here.
    Home,
    /// A body here on the leaf's thing rests on the lowering's edge, which it cuts.
    Reads,
}

/// Per (edge, thing), a set.
type ByEdgeThing<T, V> = BTreeMap<(Edge<T>, T), BTreeSet<V>>;

/// The leaf indexes, over the held copies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LeafIx<C, T> {
    /// Held addenda by the copies they list.
    listers: BTreeMap<CopyId<C, T>, BTreeSet<CopyId<C, T>>>,
    /// Held copies with a content-class part whose known path uses the edge, by (edge, the copy's
    /// thing): what a leaf of a lowering of that edge for that thing judges.
    rests_on: ByEdgeThing<T, CopyId<C, T>>,
    /// Held write parts whose list root holds a leaf for the thing, by (their edge, that thing).
    leaf_on: ByEdgeThing<T, PartId<C, T>>,
    /// Held copies with such a part, by their edge, and by their thing.
    leafy_on: BTreeMap<Edge<T>, BTreeSet<CopyId<C, T>>>,
    leafy: BTreeMap<T, BTreeSet<C>>,
}

impl<C, T> Default for LeafIx<C, T> {
    fn default() -> Self {
        LeafIx { listers: BTreeMap::new(), rests_on: BTreeMap::new(), leaf_on: BTreeMap::new(), leafy_on: BTreeMap::new(), leafy: BTreeMap::new() }
    }
}

fn put<A: Ord, B: Ord>(m: &mut BTreeMap<A, BTreeSet<B>>, k: A, v: B, add: bool) {
    if add {
        m.entry(k).or_default().insert(v);
    } else {
        remove_from(m, &k, &v);
    }
}

impl<C: Ord + Copy, T: Ord + Copy> LeafIx<C, T> {
    /// Indexes held copy `c` (`add`), or takes it out.
    fn index<K>(&mut self, c: &CopyId<C, T>, parts: &[Part<C, T, K>], add: bool) {
        for l in parts.iter().filter_map(|p| if let Kind::Addendum { lists, .. } = &p.kind { Some(lists) } else { None }).flatten() {
            put(&mut self.listers, *l, *c, add);
        }
        for e in content_edges(parts) {
            put(&mut self.rests_on, (e, c.1), *c, add);
        }
        for (i, p) in parts.iter().enumerate() {
            if let Kind::Write(w) = &p.kind
                && !w.leaves.is_empty()
            {
                let e = (w.holder, c.1);
                for t in &w.leaves {
                    put(&mut self.leaf_on, (e, *t), (*c, i), add);
                }
                put(&mut self.leafy_on, e, *c, add);
                put(&mut self.leafy, c.1, c.0, add);
            }
        }
    }
}

/// The edges a copy's content-class parts rest on (their known paths').
fn content_edges<C, T: Ord + Copy, K>(parts: &[Part<C, T, K>]) -> BTreeSet<Edge<T>> {
    parts.iter().filter(|p| p.kind.content_class()).flat_map(|p| p.hops.iter().flatten().map(|h| h.edge)).collect()
}

impl<C, T, K> Evidence<C, T, K>
where
    C: Ord + Copy + Debug,
    T: Ord + Copy + Debug,
    K: Ord + Copy + Debug,
{
    /// The leaves S requires, each (lowering commit ID, thing) with why (the first reason, `Home`
    /// before `Reads`).
    pub fn leaves(&self, sid: &T) -> Option<BTreeMap<(C, T), LeafWhy>> {
        self.sids.get(sid).map(|s| flatten(&s.leaves))
    }

    /// `leaves` computed from nothing over the held copies.
    pub fn leaves_from_scratch(&self, sid: &T) -> Option<BTreeMap<(C, T), LeafWhy>> {
        self.leaves_scratch(sid).map(|(l, _)| flatten(&l))
    }

    /// The leaves that judge held copy `c` (a content-class part on t resting on the edge of a held
    /// lowering whose root holds a leaf for t, which cuts it): a node holding `c` without one of
    /// them waits for it (notes/a3-spec/commits.md §4 Unjudgeable). Looks up only the lowerings of
    /// the edges `c` rests on with a leaf for its thing.
    pub fn reading(&mut self, c: &CopyId<C, T>) -> BTreeSet<(C, T)> {
        let mut out = BTreeSet::new();
        let Some(h) = self.ix.copies.get(c) else { return out };
        let edges = content_edges(&h.parts);
        let mut n = 0;
        for e in &edges {
            for (r, i) in self.ix.lx.leaf_on.get(&(*e, c.1)).into_iter().flatten() {
                n += 1;
                if self.leaf_for(r, *i, c.1, &edges) && self.cuts(r, *i) {
                    out.insert((r.0, c.1));
                }
            }
        }
        self.counts.leaf_checks += n;
        out
    }

    /// A leaf judging held copy `c` that `has` says the node lacks: `c` waits for it.
    pub fn waits(&mut self, c: &CopyId<C, T>, has: impl Fn(&(C, T)) -> bool) -> Option<(C, T)> {
        self.reading(c).into_iter().find(|l| !has(l))
    }

    /// The held copies on `t` that lowering copy `r`'s leaf for `t` judges (what a node receiving
    /// that leaf can judge now): those resting on its edge, where it cuts them. Looks at those
    /// alone (`Counts::judged`).
    pub fn judged_by(&mut self, r: &CopyId<C, T>, t: T) -> BTreeSet<CopyId<C, T>> {
        let mut out = BTreeSet::new();
        let Some(h) = self.ix.copies.get(r) else { return out };
        let mut n = 0;
        for (i, p) in h.parts.iter().enumerate() {
            if let Kind::Write(w) = &p.kind
                && w.leaves.contains(&t)
                && self.cuts(r, i)
            {
                let e = (w.holder, r.1);
                for c in self.ix.lx.rests_on.get(&(e, t)).into_iter().flatten() {
                    n += 1;
                    if c.1 == t && self.ix.copies.get(c).is_some_and(|h| content_edges(&h.parts).contains(&e)) {
                        out.insert(*c);
                    }
                }
            }
        }
        self.counts.judged += n;
        out
    }

    /// Part `i` of held copy `r` has a leaf for `t` on one of `edges`.
    fn leaf_for(&self, r: &CopyId<C, T>, i: usize, t: T, edges: &BTreeSet<Edge<T>>) -> bool {
        matches!(self.ix.copies.get(r).and_then(|h| h.parts.get(i)), Some(Part { kind: Kind::Write(w), .. }) if w.leaves.contains(&t) && edges.contains(&(w.holder, r.1)))
    }

    /// Part `i` of held copy `c` cuts content resting on its edge: a removal-shaped write taking
    /// write away there (a record edge, or a held chained write giving write or above ordered
    /// before it).
    fn cuts(&self, c: &CopyId<C, T>, i: usize) -> bool {
        match self.ix.copies.get(c).and_then(|h| h.parts.get(i)) {
            Some(Part { kind: Kind::Write(w), pos, .. }) => w.removal && self.takes_write(&(w.holder, c.1), *pos),
            _ => false,
        }
    }

    /// Copy `c` is live (a body where its thing is in a unit): with `Config::leaves`, an addendum
    /// only while it lists a held copy with a content part resting on its removal's edge.
    pub(super) fn live_of(&self, c: &CopyId<C, T>) -> bool {
        let Some(h) = self.ix.copies.get(c) else { return false };
        if !self.cfg.leaves {
            return true;
        }
        let mut addenda = h.parts.iter().filter_map(|p| if let Kind::Addendum { edge, lists } = &p.kind { Some((edge, lists)) } else { None }).peekable();
        if addenda.peek().is_none() {
            return true;
        }
        addenda.any(|(e, lists)| lists.iter().any(|l| self.ix.copies.get(l).is_some_and(|lh| lh.parts.iter().any(|p| p.kind == Kind::Content && p.hops.iter().flatten().any(|hp| hp.edge == *e)))))
    }

    /// Indexes copy `c` for leaves (`add`) or takes it out.
    pub(super) fn leaf_index(&mut self, c: &CopyId<C, T>, add: bool) {
        if !self.cfg.leaves {
            return;
        }
        if let Some(h) = self.ix.copies.get(c) {
            self.ix.lx.index(c, &h.parts, add);
        }
    }

    /// The addenda listing `c` decide again whether they keep something (`c` arrived, left or
    /// learnt its path): one that flips leaves or joins the bodies of each unit holding its thing.
    pub(super) fn relive_listers(&mut self, c: &CopyId<C, T>, todo: &mut Todo<C, T>) {
        for a in self.ix.lx.listers.get(c).cloned().unwrap_or_default() {
            let now = self.live_of(&a);
            if self.live(&a) == now {
                continue;
            }
            let sids = self.thing_sids.get(&a.1).cloned().unwrap_or_default();
            if !now {
                for sid in &sids {
                    self.body_remove(sid, &a, todo);
                }
            }
            if let Some(h) = self.ix.copies.get_mut(&a) {
                h.live = now;
            }
            if now {
                for sid in &sids {
                    self.body_add(sid, &a, todo);
                }
            }
        }
    }

    /// Body `c` of S enters (`add`) or leaves its counts of what rests on each (edge, thing); a
    /// count reaching or leaving 0 sends the lowerings of that edge with a leaf for that thing to
    /// decide again (O(those)); a body that is a lowering with leaves decides again too.
    pub(super) fn rest_move(&mut self, sid: &T, c: &CopyId<C, T>, add: bool, todo: &mut Todo<C, T>) {
        if !self.cfg.leaves {
            return;
        }
        let edges = self.ix.copies.get(c).map(|h| content_edges(&h.parts)).unwrap_or_default();
        let Some(s) = self.sids.get_mut(sid) else { return };
        let mut flipped = vec![];
        for e in edges {
            let k = (e, c.1);
            if add {
                let n = s.rest.entry(k).or_insert(0);
                *n += 1;
                if *n == 1 {
                    flipped.push(k);
                }
            } else if let Some(n) = s.rest.get_mut(&k) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    s.rest.remove(&k);
                    flipped.push(k);
                }
            }
        }
        for k in flipped {
            for (r, _) in self.ix.lx.leaf_on.get(&k).into_iter().flatten() {
                self.counts.leaf_checks += 1;
                todo.leaves.insert((*sid, *r));
            }
        }
        if self.ix.lx.leafy.get(&c.1).is_some_and(|s| s.contains(&c.0)) {
            todo.leaves.insert((*sid, *c));
        }
    }

    /// What lowerings of `e` cut moved: each with a leaf decides again in each sync ID it is in.
    pub(super) fn recut(&mut self, e: &Edge<T>, todo: &mut Todo<C, T>) {
        if !self.cfg.leaves {
            return;
        }
        for c in self.ix.lx.leafy_on.get(e).cloned().unwrap_or_default() {
            let mut sids = self.member_sids.get(&c).cloned().unwrap_or_default();
            if self.live(&c) {
                sids.extend(self.thing_sids.get(&c.1).into_iter().flatten().copied());
            }
            for sid in sids {
                todo.leaves.insert((sid, c));
            }
        }
    }

    /// Decides the leaves again: the members of each sync ID of `all` (its closure was rebuilt), and
    /// each (sync ID, lowering) of `some`. A rebuilt closure moves which lowerings are members, never
    /// a body's leaves (moved by what moves them: rest counts, cuts, liveness, the unit, each sending
    /// its (sync ID, lowering) in `some`), so it costs O(members), not O(bodies' leaves).
    pub(super) fn settle_leaves(&mut self, all: BTreeSet<T>, some: BTreeSet<(T, CopyId<C, T>)>) {
        if !self.cfg.leaves {
            return;
        }
        for sid in &all {
            let Some(s) = self.sids.get(sid) else { continue };
            let mut n = 0;
            let mut out: BTreeMap<CopyId<C, T>, BTreeMap<T, LeafWhy>> = s.leaves.iter().filter(|(c, _)| s.unit.contains(&c.1)).map(|(c, m)| (*c, m.clone())).collect();
            for c in s.closure.members.keys().filter(|c| self.ix.lx.leafy.get(&c.1).is_some_and(|l| l.contains(&c.0))) {
                let m = self.leaves_rule(c, true, &s.unit, &s.rest, &mut n);
                if !m.is_empty() {
                    out.insert(*c, m);
                }
            }
            self.counts.leaf_checks += n;
            if let Some(s) = self.sids.get_mut(sid) {
                s.leaves = out;
            }
        }
        for (sid, c) in some {
            let Some(s) = self.sids.get(&sid) else { continue };
            let in_set = s.closure.members.contains_key(&c) || (s.unit.contains(&c.1) && self.live(&c));
            let mut n = 0;
            let m = self.leaves_rule(&c, in_set, &s.unit, &s.rest, &mut n);
            self.counts.leaf_checks += n;
            if let Some(s) = self.sids.get_mut(&sid) {
                if m.is_empty() {
                    s.leaves.remove(&c);
                } else {
                    s.leaves.insert(c, m);
                }
            }
        }
    }

    /// The leaves of lowering copy `c` a set with unit `unit` and rest counts `rest` requires, `c`
    /// being in the set (`in_set`: a member, or a body).
    fn leaves_rule(&self, c: &CopyId<C, T>, in_set: bool, unit: &BTreeSet<T>, rest: &BTreeMap<(Edge<T>, T), usize>, n: &mut usize) -> BTreeMap<T, LeafWhy> {
        let mut out = BTreeMap::new();
        let Some(h) = self.ix.copies.get(c).filter(|_| in_set) else { return out };
        for (i, p) in h.parts.iter().enumerate() {
            let Kind::Write(w) = &p.kind else { continue };
            if w.leaves.is_empty() {
                continue;
            }
            let e = (w.holder, c.1);
            let cuts = self.cuts(c, i);
            for t in &w.leaves {
                *n += 1;
                if *t != c.1 && unit.contains(&c.1) {
                    out.insert(*t, LeafWhy::Home);
                } else if cuts && unit.contains(t) && rest.get(&(e, *t)).is_some_and(|k| *k > 0) {
                    out.entry(*t).or_insert(LeafWhy::Reads);
                }
            }
        }
        out
    }

    /// S's leaves and rest counts from nothing.
    #[allow(clippy::type_complexity)]
    fn leaves_scratch(&self, sid: &T) -> Option<(BTreeMap<CopyId<C, T>, BTreeMap<T, LeafWhy>>, BTreeMap<(Edge<T>, T), usize>)> {
        let s = self.sids.get(sid)?;
        let members = self.from_scratch(sid)?;
        let mut rest: BTreeMap<(Edge<T>, T), usize> = BTreeMap::new();
        let mut set: BTreeSet<CopyId<C, T>> = members.keys().copied().collect();
        for t in &s.unit {
            for c in self.ix.on_thing.get(t).into_iter().flatten() {
                let c = (*c, *t);
                if !self.live(&c) {
                    continue;
                }
                set.insert(c);
                for e in self.ix.copies.get(&c).map(|h| content_edges(&h.parts)).unwrap_or_default() {
                    *rest.entry((e, *t)).or_insert(0) += 1;
                }
            }
        }
        let mut out = BTreeMap::new();
        for c in set {
            let m = self.leaves_rule(&c, true, &s.unit, &rest, &mut 0);
            if !m.is_empty() {
                out.insert(c, m);
            }
        }
        Some((out, rest))
    }

    /// `check`'s part: the leaf indexes, each sync ID's rest counts and leaves, against nothing.
    pub(super) fn check_leaves(&self) -> Result<(), String> {
        if !self.cfg.leaves {
            let empty = self.sids.values().all(|s| s.rest.is_empty() && s.leaves.is_empty());
            return if empty && self.ix.lx == LeafIx::default() { Ok(()) } else { Err("leaves kept with Config::leaves off".into()) };
        }
        let mut lx = LeafIx::default();
        for (c, h) in &self.ix.copies {
            lx.index(c, &h.parts, true);
        }
        if lx != self.ix.lx {
            return Err("a leaf index (listers, rests on, leaf on, leafy) is stale".into());
        }
        for (sid, s) in &self.sids {
            let Some((leaves, rest)) = self.leaves_scratch(sid) else { continue };
            if rest != s.rest {
                return Err(format!("sid {sid:?}: rest {:?}, counted {rest:?}", s.rest));
            }
            if leaves != s.leaves {
                return Err(format!("sid {sid:?}: leaves {:?}, from scratch {leaves:?}", s.leaves));
            }
        }
        Ok(())
    }
}

/// Per lowering copy its leaves, as (lowering commit ID, thing).
fn flatten<C: Ord + Copy, T: Ord + Copy>(m: &BTreeMap<CopyId<C, T>, BTreeMap<T, LeafWhy>>) -> BTreeMap<(C, T), LeafWhy> {
    let mut out = BTreeMap::new();
    for (c, ts) in m {
        for (t, why) in ts {
            let w = out.entry((c.0, *t)).or_insert(*why);
            *w = (*w).min(*why);
        }
    }
    out
}
