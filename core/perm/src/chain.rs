//! An account's signing chain (spec/crypto.md §9, spec/permissions.md §5.4): which held
//! rotations a node follows, the open head, and the warning. A pure function of the held
//! rotations, the order the node came to hold them, the rotation its user chose and (at a node
//! of the account) what its devices list says of them; nothing here reads `ts`, counters or
//! signatures (the caller checks those, and passes a merge only with every one verified, and
//! states who minted what in `Devices`).
//!
//! Principle: the first revocation seen holds. A node places the rotations in the order it came
//! to hold them (each with its chain, a merge's tips and every rotation it takes; ties
//! ancestors first; the chosen line first, at a node of the account with what it stands with).
//! Outside the account it follows each with its line unless it is beside one already followed
//! (a removed device's fork looks like any other); a node of the account reads who minted each
//! rotation and whom each removes, takes the revocations first-seen as a consistent set and
//! follows what they leave standing, so two of its devices' rotations made at once stand side
//! by side until a merge joins them. Followed rotations
//! count; nothing else does, so a removed device's fork from an epoch it still holds never
//! counts where its removal came first. A rejected line beside the followed one is the
//! warning. `joins` (descent from every anchor) is the key level's anchoring rule (osis-keys
//! `seal_keyset`).

use crate::pset::PSet;
use std::collections::{BTreeMap, BTreeSet};

/// Everything reachable from `k` over `parents`, `k` itself excluded unless a cycle returns to
/// it: a walk of what it reaches.
pub fn ancestors<N: Ord + Copy, I: IntoIterator<Item = N>>(k: N, parents: impl Fn(N) -> I) -> BTreeSet<N> {
    let mut seen = BTreeSet::new();
    let mut work = vec![k];
    while let Some(x) = work.pop() {
        for p in parents(x) {
            if seen.insert(p) {
                work.push(p);
            }
        }
    }
    seen
}

/// Whether `k` is or descends from (over `parents`) each of `anchors`.
pub fn joins<'a, N: Ord + Copy + 'a, I: IntoIterator<Item = N>>(k: N, anchors: impl IntoIterator<Item = &'a N>, parents: impl Fn(N) -> I) -> bool {
    let up = ancestors(k, parents);
    anchors.into_iter().all(|a| *a == k || up.contains(a))
}

/// Each rotation's place in `received`, its first.
fn ranks<E: Ord + Copy>(received: &[E]) -> BTreeMap<E, usize> {
    received.iter().enumerate().map(|(i, r)| (*r, i)).rev().collect()
}

/// A held epoch of the account's signing chain: a plain rotation, or a merge (one record for
/// all its certificates, spec/crypto.md §9). Its ID names the epoch it mints; the first epoch
/// (the chain's root) is minted by none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotation<E> {
    pub id: E,
    /// The epoch it is signed at: a plain rotation's the one it rotates; a merge's one of its
    /// tips.
    pub at: E,
    /// The epochs it supersedes: a plain rotation's `at` and the rotations it answers; a
    /// merge's its tips.
    pub supersedes: BTreeSet<E>,
    /// A merge's tips other than `at` (every merge signature verified by the caller); empty for
    /// a plain rotation. A merge is held only when its tips are held plain rotations none on
    /// another's line.
    pub names: BTreeSet<E>,
    /// A plain rotation's revocations its maker took that are not on its line: it stands with
    /// them (read only at a node of the account). It is held only once these are, at every node.
    pub takes: BTreeSet<E>,
}

impl<E> Rotation<E> {
    /// Whether it is a merge: it names tips.
    pub fn is_merge(&self) -> bool {
        !self.names.is_empty()
    }
}

/// What a node of the account reads of its chain as D's roster (spec/permissions.md §5.4,
/// Following, at a node of P): who minted each held rotation (its inner signature, as the caller
/// opened it) and the membership changes each carries (its sealed devices field, opened with the
/// seed of the epoch it is signed at). No removal or addition exists apart from its rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Devices<E, M> {
    /// Per held plain rotation, the key actor that minted it (one whose inner signature opens to
    /// no key actor is left out: it stands by none).
    pub minter: BTreeMap<E, M>,
    /// Per held merge, the key actors that made a certificate of it (inner signatures as
    /// `minter`'s): it stands by one that is a node of its line, not hit.
    pub certifiers: BTreeMap<E, BTreeSet<M>>,
    /// Per held rotation, the devices it removes from D.
    pub removes: BTreeMap<E, BTreeSet<M>>,
    /// Per held rotation, the devices it adds to D (a pairing).
    pub adds: BTreeMap<E, BTreeSet<M>>,
    /// The devices the account's creation record names.
    pub first: BTreeSet<M>,
}

impl<E, M> Default for Devices<E, M> {
    fn default() -> Self {
        Devices { minter: BTreeMap::new(), certifiers: BTreeMap::new(), removes: BTreeMap::new(), adds: BTreeMap::new(), first: BTreeSet::new() }
    }
}

/// Per device, the held rotations minting, adding and removing it, and its number in a node set.
struct ByDevice<M, E> {
    minted_by: BTreeMap<M, Vec<E>>,
    adds_of: BTreeMap<M, Vec<E>>,
    removes_of: BTreeMap<M, Vec<E>>,
    num: BTreeMap<M, u32>,
    devs: Vec<M>,
}

impl<M: Ord + Copy, E: Copy> ByDevice<M, E> {
    fn new(d: &Devices<E, M>) -> ByDevice<M, E> {
        let mut ix = ByDevice { minted_by: BTreeMap::new(), adds_of: BTreeMap::new(), removes_of: BTreeMap::new(), num: BTreeMap::new(), devs: Vec::new() };
        for (q, m) in &d.minter {
            ix.minted_by.entry(*m).or_default().push(*q);
        }
        for (q, ys) in &d.adds {
            for y in ys {
                ix.adds_of.entry(*y).or_default().push(*q);
            }
        }
        for (q, ys) in &d.removes {
            for y in ys {
                ix.removes_of.entry(*y).or_default().push(*q);
            }
        }
        let all: BTreeSet<M> = d.first.iter().chain(d.minter.values()).chain(d.certifiers.values().flatten()).chain(d.adds.values().flatten()).chain(d.removes.values().flatten()).copied().collect();
        for y in all {
            ix.num.insert(y, ix.devs.len() as u32);
            ix.devs.push(y);
        }
        ix
    }

    fn n(&self, y: &M) -> u32 {
        self.num.get(y).copied().unwrap_or(u32::MAX)
    }

    fn set<'a>(&self, ys: impl IntoIterator<Item = &'a M>) -> PSet
    where
        M: 'a,
    {
        ys.into_iter().fold(PSet::new(), |s, y| s.insert(self.n(y)))
    }
}

/// Each held rotation (by place in `Chain::topo`) judged under the removals carried on its line
/// and those given (`Chain::standing`).
struct Standing {
    /// Whether it stands (`Chain::stands_walk` under those removals).
    stands: Vec<bool>,
    /// The nodes of its line, after its own changes.
    nodes: Vec<PSet>,
}

/// The chain as one node judges it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain<E> {
    root: E,
    rots: BTreeMap<E, Rotation<E>>,
    /// The held rotations, each after every one it needs (its parents among them).
    topo: Vec<E>,
    /// Each held rotation's place in `topo`.
    idx: BTreeMap<E, u32>,
    /// Per held epoch (by place), its line: every held plain rotation it descends from, itself
    /// included but for a merge, by place (a merge is on a line through its tips, `on`). Shared
    /// along the chain (`PSet`): O(log n) per rotation, not a set each.
    lines: Vec<PSet>,
    /// (m, r): held rotation m rejects held rotation r.
    rejects: BTreeSet<(E, E)>,
    /// The followed rotations: these count.
    counting: BTreeSet<E>,
    /// The held rotations placed in conflict with a followed one.
    disregarded: BTreeSet<E>,
    /// The user's choice, if held.
    chosen: Option<E>,
    /// The counting epochs no counting rotation descends from.
    heads: BTreeSet<E>,
    /// Of the heads, the one whose line holds the earliest-placed rotation of those on exactly
    /// one of two lines.
    preferred: E,
    /// The disregarded tips in a rejection with a counting rotation.
    contested: BTreeSet<E>,
    /// At a node of the account: the revocations it takes, in the order taken.
    taken: Vec<E>,
}

/// What a rejection can be among: the pairs (m, r) with r a held epoch m supersedes off its own
/// line (one on it is never rejected: m itself is signed at `m.at` and shares a line with it),
/// and per epoch the held rotations signed at it.
struct Rejecting<E> {
    pairs: Vec<(E, E)>,
    signed_by: BTreeMap<E, Vec<E>>,
}


impl<E: Ord + Copy> Chain<E> {
    /// Judges `rotations` (the held ones, one record each) as a node that holds them in the
    /// order `received` (earliest first; one missing ranks after every one in it) and whose
    /// user chose `chosen`; `devices` at a node of the account (`None` elsewhere). A rotation
    /// counts as held only with its chain back to the root, a merge's tips and every
    /// rotation it takes, each so held (spec/permissions.md §5.4); the rest are pending and take
    /// part in nothing (`holds`).
    pub fn new<M: Ord + Copy>(root: E, rotations: impl IntoIterator<Item = Rotation<E>>, chosen: Option<E>, received: &[E], devices: Option<&Devices<E, M>>) -> Chain<E> {
        let rank = ranks(received);
        let rank_of = |r: &E| rank.get(r).copied().unwrap_or(usize::MAX);
        let mut pending: BTreeMap<E, Rotation<E>> = rotations.into_iter().filter(|r| r.id != root).map(|r| (r.id, r)).collect();
        // and every revocation it takes, at every node: one taking what no node of the account
        // holds would otherwise be followed outside unanswered
        let needs = |r: &Rotation<E>| -> BTreeSet<E> { std::iter::once(r.at).chain(r.names.iter().copied()).chain(r.takes.iter().copied()).filter(|n| *n != root).collect() };
        // placed as each comes to be held, the lowest ID first among those held at once: each
        // waits on a count of what it needs not yet held
        let mut missing: BTreeMap<E, usize> = BTreeMap::new();
        let mut waiters: BTreeMap<E, Vec<E>> = BTreeMap::new();
        let mut ready: BTreeSet<E> = BTreeSet::new();
        for r in pending.values() {
            let ns = needs(r);
            if ns.is_empty() {
                ready.insert(r.id);
            }
            missing.insert(r.id, ns.len());
            for n in ns {
                waiters.entry(n).or_default().push(r.id);
            }
        }
        let mut rots: BTreeMap<E, Rotation<E>> = BTreeMap::new();
        // when each came to be held with its chain: its own receipt or a parent's, the later
        let mut when: BTreeMap<E, usize> = BTreeMap::new();
        // and its depth: one more than the deepest of what it needs, so of two held at once the
        // one it needs is placed first (a receipt millisecond orders its rotations by ID)
        let mut depth: BTreeMap<E, usize> = BTreeMap::new();
        let mut topo: Vec<E> = Vec::new();
        // each line its parents' joined and, but for a merge, itself: a parent is placed first
        let mut idx: BTreeMap<E, u32> = BTreeMap::new();
        let mut lines: Vec<PSet> = Vec::new();
        while let Some(id) = ready.pop_first() {
            let Some(r) = pending.remove(&id) else { continue };
            osis_base::costs::count("chain: placed", 1);
            let parents: Vec<usize> = std::iter::once(&r.at).chain(&r.names).filter_map(|p| idx.get(p).map(|i| *i as usize)).collect();
            if r.is_merge() {
                // a merge's tips: held plain rotations, none on another's line, and all it
                // supersedes (else it is no epoch and stays pending)
                let plain = std::iter::once(&r.at).chain(&r.names).all(|t| rots.get(t).is_some_and(|x: &Rotation<E>| !x.is_merge()));
                let apart = parents.iter().all(|a| parents.iter().all(|b| a == b || !lines.get(*b).is_some_and(|l| l.contains(*a as u32))));
                let exact = r.supersedes.len() == parents.len() && std::iter::once(&r.at).chain(&r.names).all(|t| r.supersedes.contains(t));
                if !plain || !apart || !exact || parents.len() != 1 + r.names.len() {
                    continue;
                }
            }
            let line = parents.iter().filter_map(|p| lines.get(*p)).fold(PSet::new(), |l, p| l.union(p));
            let place = topo.len() as u32;
            lines.push(if r.is_merge() { line } else { line.insert(place) });
            idx.insert(id, place);
            let ns = needs(&r);
            let w = ns.iter().filter_map(|p| when.get(p)).fold(rank_of(&id), |a, b| a.max(*b));
            when.insert(id, w);
            depth.insert(id, 1 + ns.iter().filter_map(|p| depth.get(p)).max().copied().unwrap_or(0));
            rots.insert(id, r);
            topo.push(id);
            for x in waiters.remove(&id).unwrap_or_default() {
                if let Some(m) = missing.get_mut(&x) {
                    *m -= 1;
                    if *m == 0 {
                        ready.insert(x);
                    }
                }
            }
        }
        let mut c = Chain { root, rots, topo, idx, lines, rejects: BTreeSet::new(), counting: BTreeSet::new(), disregarded: BTreeSet::new(), chosen: None, heads: BTreeSet::new(), preferred: root, contested: BTreeSet::new(), taken: Vec::new() };
        c.chosen = chosen.filter(|s| c.rots.contains_key(s));
        // the chosen rotation's line first and, at a node of the account, what it stands with
        // (what a rotation on it takes, and that one's line; outside, takes decide nothing more)
        let chosen_needs: BTreeSet<E> = c.chosen.map(|s| {
            let mut up = ancestors(s, |x| c.parents(x).into_iter().chain(c.rots.get(&x).filter(|_| devices.is_some()).into_iter().flat_map(|r| r.takes.iter().copied())).collect::<Vec<E>>());
            up.insert(s);
            up
        }).unwrap_or_default();
        let mut order: Vec<E> = c.rots.keys().copied().collect();
        order.sort_by_key(|r| (!chosen_needs.contains(r), when.get(r).copied().unwrap_or(usize::MAX), depth.get(r).copied().unwrap_or(0), *r));
        let rej = c.rejecting();
        match devices {
            Some(d) => c.follow_as_node(&order, d),
            None => c.follow_outside(&order, &rej),
        }
        c.disregarded.retain(|r| !c.counting.contains(r));
        c.rejects = c.rejections(&rej, |_| true);
        c.heads = c.heads_of();
        let pos: BTreeMap<E, usize> = order.iter().enumerate().map(|(i, r)| (*r, i)).collect();
        c.preferred = c.first_line(&c.heads, &pos).unwrap_or(root);
        let mut contested: BTreeSet<E> = BTreeSet::new();
        for (m, r) in &c.rejects {
            for (a, b) in [(m, r), (r, m)] {
                if c.counting.contains(a) && !c.counting.contains(b) {
                    contested.insert(*b);
                }
            }
        }
        c.contested = contested.iter().copied().filter(|x| !contested.iter().any(|y| y != x && c.on(*x, *y))).collect();
        c
    }

    /// Held rotation `e`'s place in `topo`.
    fn place(&self, e: &E) -> Option<usize> {
        self.idx.get(e).map(|i| *i as usize)
    }

    /// Outside the account: in order, each rotation is followed with its line unless a
    /// followed one is beside it (neither on the other's line), or a rotation on its line
    /// rejects or is rejected by a followed one (a merge cannot carry in a rejection of the
    /// followed line). Each check reads only what was placed before, so a later arrival never
    /// reopens a decision. What is followed is one line, the last followed rotation's: a
    /// rotation no followed one is beside has every followed one on its line.
    fn follow_outside(&mut self, order: &[E], rej: &Rejecting<E>) {
        let pos: BTreeMap<E, usize> = order.iter().enumerate().map(|(i, r)| (*r, i)).collect();
        let mut head: Option<E> = None;
        for (i, &r) in order.iter().enumerate() {
            osis_base::costs::count("chain: followed", 1);
            if head.is_some_and(|h| self.on(r, h)) {
                continue;
            }
            let rejects = self.rejections(rej, |e| pos.get(e).is_some_and(|p| *p <= i));
            let counting = |e: E| head.is_some_and(|h| self.on(e, h));
            let rejected = rejects.iter().any(|(a, b)| (self.on(*a, r) && counting(*b)) || (self.on(*b, r) && counting(*a)));
            if rejected || head.is_some_and(|h| !self.on(h, r)) {
                self.disregarded.insert(r);
                continue;
            }
            head = Some(r);
        }
        // the followed line: its plain rotations and every held merge on it
        self.counting = head.map(|h| self.line_iter(h).chain(self.rots.values().filter(|m| m.is_merge() && self.on(m.id, h)).map(|m| m.id)).collect()).unwrap_or_default();
    }

    /// At a node of the account, which reads who minted each rotation and whom each removes
    /// and adds: the revocations (rotations carrying a removal) it takes are a consistent set,
    /// built in order: one is taken when its line and every taken one's stand with it and every
    /// revocation it stands with (on its line, or taken by a rotation on it) is taken. It follows
    /// every rotation whose line stands under the taken revocations and whose revocations it
    /// stands with are all taken: a device that took another revocation first stands with it in
    /// every rotation it makes (`Rotation::takes`), so those are that side, never merged into
    /// this one, whoever signed them. So its devices' rotations made at once all count, a
    /// removed device's plain fork never outweighs the removal, and of two revocations hitting
    /// each other the one held first holds.
    ///
    /// Cost: a revocation beside a line changes what stands on it only by hitting a rotation on
    /// it (`hits`), so each check reads the standing gathered along the lines and walks a line
    /// only where a revocation it is judged under hits one beside; the final pass gathers the
    /// standing under the taken revocations along the lines again.
    fn follow_as_node<M: Ord + Copy>(&mut self, order: &[E], d: &Devices<E, M>) {
        let revocation = |q: &E| d.removes.get(q).is_some_and(|x| !x.is_empty());
        let ix = ByDevice::new(d);
        let hits = self.hits(d, &ix);
        // per revocation, the revocations whose check it changes (it hits their line)
        let mut affects: BTreeMap<E, Vec<E>> = BTreeMap::new();
        for (i, q) in self.topo.iter().enumerate() {
            if revocation(q) {
                for e in hits.get(i).into_iter().flatten() {
                    affects.entry(*e).or_default().push(*q);
                }
            }
        }
        let s = self.standing(d, &ix, &hits, None);
        let stands = |c: &Chain<E>, r: E, w: &dyn Fn(&E) -> bool| match c.place(&r) {
            Some(i) if hits.get(i).is_some_and(|h| h.iter().any(w)) => c.stands_walk(r, w, d, &ix),
            Some(i) => s.stands.get(i).copied().unwrap_or(false),
            None => false,
        };
        let mut taken: Vec<E> = Vec::new();
        let mut taken_set: BTreeSet<E> = BTreeSet::new();
        // a rotation stands with a revocation not taken: on its line, or taken by one on it
        let mut bad: Vec<bool> = vec![false; self.topo.len()];
        for &r in order {
            let Some(i) = self.place(&r) else { continue };
            let parents_bad = self.parents(r).iter().filter_map(|p| self.place(p)).any(|p| bad.get(p).copied().unwrap_or(true));
            let takes_held = self.rots.get(&r).is_some_and(|x| x.takes.iter().all(|t| taken_set.contains(t)));
            if revocation(&r) && !parents_bad && takes_held {
                let w = |e: &E| *e == r || taken_set.contains(e);
                let others = affects.get(&r).into_iter().flatten().filter(|q| taken_set.contains(*q));
                if stands(self, r, &w) && others.clone().all(|q| self.stands_walk(*q, &w, d, &ix)) {
                    taken.push(r);
                    taken_set.insert(r);
                }
            }
            if let Some(b) = bad.get_mut(i) {
                *b = parents_bad || !takes_held || (revocation(&r) && !taken_set.contains(&r));
            }
        }
        let fin = self.standing(d, &ix, &hits, Some(&taken_set));
        for &r in order {
            let parents_count = self.parents(r).iter().all(|p| self.counting.contains(p));
            match self.place(&r) {
                Some(i) if parents_count && bad.get(i) == Some(&false) && fin.stands.get(i) == Some(&true) => {
                    self.counting.insert(r);
                }
                _ => {
                    self.disregarded.insert(r);
                }
            }
        }
        self.taken = taken;
    }

    /// Per held rotation (by place), the revocations off its line that hit a rotation on it:
    /// remove the minter of one not before them (`hit`, without its re-add clause: a superset).
    /// Gathered along the lines, so each costs what the hits are, not the line.
    fn hits<M: Ord + Copy>(&self, d: &Devices<E, M>, ix: &ByDevice<M, E>) -> Vec<BTreeSet<E>> {
        let mut hit_by: BTreeMap<E, Vec<E>> = BTreeMap::new();
        for (e, ys) in &d.removes {
            if !self.rots.contains_key(e) {
                continue;
            }
            for y in ys {
                for q in ix.minted_by.get(y).into_iter().flatten() {
                    if q != e && self.rots.contains_key(q) && !self.before(*q, *e) {
                        osis_base::costs::count("chain: hits", 1);
                        hit_by.entry(*q).or_default().push(*e);
                    }
                }
            }
        }
        let mut out: Vec<BTreeSet<E>> = Vec::with_capacity(self.topo.len());
        for &r in &self.topo {
            let mut h: BTreeSet<E> = self.parents(r).iter().filter_map(|p| self.place(p)).flat_map(|p| out.get(p).into_iter().flatten().copied()).collect();
            h.extend(hit_by.get(&r).into_iter().flatten().copied());
            h.retain(|e| !self.on(*e, r));
            out.push(h);
        }
        out
    }

    /// Whether every rotation on `r`'s line is minted by a node of the line before it, and none
    /// is hit by the removals of `rs` or those carried on the line. A rotation whose minter is
    /// no node stands by none. Walks the line: `standing` answers without, but where a removal
    /// beside hits a rotation on it.
    fn stands_walk<M: Ord + Copy>(&self, r: E, rs: &dyn Fn(&E) -> bool, d: &Devices<E, M>, ix: &ByDevice<M, E>) -> bool {
        if self.place(&r).is_none() {
            return false;
        }
        let all = |e: &E| rs(e) || (d.removes.get(e).is_some_and(|x| !x.is_empty()) && self.on(*e, r));
        if self.is_merge(&r) {
            let nodes = self.nodes_on(self.line_iter(r), &|x: &E| self.on(*x, r), &all, d, ix);
            if !self.certified(r, &|y| nodes.contains(y), &all, d, ix) {
                return false;
            }
        }
        self.line_iter(r).all(|q| {
            osis_base::costs::count("chain: line walked", 1);
            d.minter.get(&q).is_some_and(|m| self.nodes_on(self.line_iter(q).filter(|x| *x != q), &|x: &E| *x != q && self.on(*x, q), &all, d, ix).contains(m)) && !self.hit(q, &all, d, ix)
        })
    }

    /// Each held rotation's standing under the removals carried on its own line and `extra`,
    /// gathered along the lines in one pass (`stands_walk` under them): a rotation with one
    /// parent stands iff its parent does, its minter is a node of its parent's line and it is
    /// not hit; its line's nodes are its parent's, with what it adds (not hit) and removes. A
    /// merge reads its parents' the same way but for the devices the branches it joins add or
    /// remove, each read from the rotations adding and removing it; where a removal it is judged
    /// under hits a rotation on one parent's line from beside it (`hits`) it walks its line.
    fn standing<M: Ord + Copy>(&self, d: &Devices<E, M>, ix: &ByDevice<M, E>, hits: &[BTreeSet<E>], extra: Option<&BTreeSet<E>>) -> Standing {
        let revocation = |q: &E| d.removes.get(q).is_some_and(|x| !x.is_empty());
        let mut st = Standing { stands: Vec::with_capacity(self.topo.len()), nodes: Vec::with_capacity(self.topo.len()) };
        for &r in &self.topo {
            osis_base::costs::count("chain: standing", 1);
            let ps: Vec<usize> = self.parents(r).iter().filter_map(|p| self.place(p)).collect();
            let all = |e: &E| (revocation(e) && self.on(*e, r)) || extra.is_some_and(|x| x.contains(e));
            let joined = match ps.as_slice() {
                [] => Some((true, ix.set(&d.first))),
                [p] => Some((st.stands.get(*p).copied().unwrap_or(false), st.nodes.get(*p).cloned().unwrap_or_default())),
                _ => self.joined(&ps, &st, &all, d, ix, hits),
            };
            let Some((ok, mut nodes)) = joined else {
                let rs = |e: &E| extra.is_some_and(|x| x.contains(e));
                st.stands.push(self.stands_walk(r, &rs, d, ix));
                let line = self.nodes_on(self.line_iter(r), &|x: &E| self.on(*x, r), &all, d, ix);
                st.nodes.push(ix.set(&line));
                continue;
            };
            if self.is_merge(&r) {
                // a merge stands by a certificate: no device changes of its own
                let by = self.certified(r, &|y| nodes.contains(ix.n(y)), &all, d, ix);
                st.stands.push(ok && by);
                st.nodes.push(nodes);
                continue;
            }
            let hit = self.hit(r, &all, d, ix);
            let minter = d.minter.get(&r);
            st.stands.push(ok && minter.is_some_and(|m| nodes.contains(ix.n(m))) && !hit);
            if !hit {
                for y in d.adds.get(&r).into_iter().flatten().filter(|y| minter != Some(*y)) {
                    nodes = nodes.insert(ix.n(y));
                }
            }
            for y in d.removes.get(&r).into_iter().flatten() {
                nodes = nodes.remove(ix.n(y));
            }
            st.nodes.push(nodes);
        }
        st
    }

    /// For a merge with parents `ps` (by place) judged under `all`: whether every parent stands
    /// and the nodes of the line they join, from their standings; `None` where a removal of
    /// `all` hits a rotation on one parent's line from beside it (the caller walks).
    fn joined<M: Ord + Copy>(&self, ps: &[usize], st: &Standing, all: &dyn Fn(&E) -> bool, d: &Devices<E, M>, ix: &ByDevice<M, E>, hits: &[BTreeSet<E>]) -> Option<(bool, PSet)> {
        if ps.iter().any(|p| hits.get(*p).is_some_and(|h| h.iter().any(all))) {
            return None;
        }
        let pe: Vec<E> = ps.iter().filter_map(|p| self.topo.get(*p)).copied().collect();
        let in_join = |x: &E| pe.iter().any(|p| self.on(*x, *p));
        // the rotations on some parent's line but not every one's: what the branches hold
        let mut branches: BTreeSet<E> = BTreeSet::new();
        for p in &pe {
            let mut work = vec![*p];
            while let Some(x) = work.pop() {
                if pe.iter().all(|o| self.on(x, *o)) || !branches.insert(x) {
                    continue;
                }
                work.extend(self.parents(x));
            }
        }
        osis_base::costs::count("chain: branches", branches.len() as u64);
        let touched: BTreeSet<M> = branches.iter().flat_map(|q| d.adds.get(q).into_iter().flatten().chain(d.removes.get(q).into_iter().flatten())).copied().collect();
        let mut nodes = ps.first().and_then(|p| st.nodes.get(*p)).cloned().unwrap_or_default();
        for y in &touched {
            nodes = nodes.remove(ix.n(y));
        }
        for y in touched {
            let adds = ix.adds_of.get(&y).map(Vec::as_slice).unwrap_or_default();
            let removes = ix.removes_of.get(&y).map(Vec::as_slice).unwrap_or_default();
            osis_base::costs::count("chain: device events", (adds.len() + removes.len()) as u64);
            let valid = |a: &E| in_join(a) && d.minter.get(a) != Some(&y) && !self.hit(*a, all, d, ix);
            let candidate = d.first.contains(&y) || adds.iter().any(valid);
            if candidate && removes.iter().filter(|r| in_join(r)).all(|r| adds.iter().any(|a| valid(a) && self.before(*r, *a))) {
                nodes = nodes.insert(ix.n(&y));
            }
        }
        Some((ps.iter().all(|p| st.stands.get(*p) == Some(&true)), nodes))
    }

    /// Whether merge `m` has a certificate by a node of its line (`node`) that no removal of
    /// `rs` hits: one removing its maker off `m`'s line and not after `m`.
    fn certified<M: Ord + Copy>(&self, m: E, node: &dyn Fn(&M) -> bool, rs: &dyn Fn(&E) -> bool, d: &Devices<E, M>, ix: &ByDevice<M, E>) -> bool {
        d.certifiers.get(&m).into_iter().flatten().any(|y| node(y) && !ix.removes_of.get(y).into_iter().flatten().any(|r| rs(r) && !self.on(*r, m) && !self.on(m, *r)))
    }

    /// Whether a removal of `rs` hits rotation `q`: it removes `q`'s minter and `q` is not on its
    /// line before it (made before the removal), and `q` descends from no re-add of that node
    /// after the removal by a rotation not hit (`readded`).
    fn hit<M: Ord + Copy>(&self, q: E, rs: &dyn Fn(&E) -> bool, d: &Devices<E, M>, ix: &ByDevice<M, E>) -> bool {
        let Some(y) = d.minter.get(&q) else { return false };
        if self.place(&q).is_none() {
            return false;
        }
        ix.removes_of.get(y).into_iter().flatten().any(|r| *r != q && rs(r) && !self.before(q, *r) && !self.readded(*y, *r, &|a: &E| self.on(*a, q), rs, d, ix))
    }

    /// Whether a rotation on the line `on_l` tells (one descending from `r`) adds `y` back after
    /// the removal carried by `r`, minted by another node and not hit.
    fn readded<M: Ord + Copy>(&self, y: M, r: E, on_l: &dyn Fn(&E) -> bool, rs: &dyn Fn(&E) -> bool, d: &Devices<E, M>, ix: &ByDevice<M, E>) -> bool {
        ix.adds_of.get(&y).into_iter().flatten().any(|a| {
            osis_base::costs::count("chain: device events", 1);
            on_l(a) && self.before(r, *a) && d.minter.get(a) != Some(&y) && !self.hit(*a, rs, d, ix)
        })
    }

    /// Whether held rotation `x` is on `r`'s line before it (`r` descends from `x`).
    fn before(&self, x: E, r: E) -> bool {
        x != r && self.on(x, r)
    }

    /// The nodes on the line `line` lists (`on_l` tells): the creation devices and those added
    /// on it by a rotation not hit, less every one a rotation on it removes without a re-add
    /// after.
    fn nodes_on<M: Ord + Copy>(&self, line: impl Iterator<Item = E>, on_l: &dyn Fn(&E) -> bool, rs: &dyn Fn(&E) -> bool, d: &Devices<E, M>, ix: &ByDevice<M, E>) -> BTreeSet<M> {
        let mut candidates: BTreeSet<M> = d.first.clone();
        for a in line {
            osis_base::costs::count("chain: line walked", 1);
            if !self.hit(a, rs, d, ix) {
                candidates.extend(d.adds.get(&a).into_iter().flatten().filter(|y| d.minter.get(&a) != Some(*y)));
            }
        }
        candidates.into_iter().filter(|y| ix.removes_of.get(y).into_iter().flatten().filter(|r| on_l(r)).all(|r| self.readded(*y, *r, on_l, rs, d, ix))).collect()
    }

    /// At a node of the account, D's roster at epoch `e` (a held rotation, or the root): the
    /// nodes of its line under the taken revocations, a removal taken off the line holding
    /// unless the line adds its node back after it.
    pub fn roster<M: Ord + Copy>(&self, e: &E, d: &Devices<E, M>) -> BTreeSet<M> {
        self.roster_of_line(&[*e], d)
    }

    /// `roster` of the line joining the held epochs `heads` (a merge's, before it is made).
    pub fn roster_joining<M: Ord + Copy>(&self, heads: &[E], d: &Devices<E, M>) -> BTreeSet<M> {
        self.roster_of_line(heads, d)
    }

    fn roster_of_line<M: Ord + Copy>(&self, heads: &[E], d: &Devices<E, M>) -> BTreeSet<M> {
        let ix = ByDevice::new(d);
        let line = heads.iter().filter_map(|h| self.place(h).and_then(|h| self.lines.get(h))).fold(PSet::new(), |l, h| l.union(h));
        let on_l = |x: &E| self.place(x).is_some_and(|i| line.contains(i as u32));
        let taken: BTreeSet<E> = self.taken.iter().copied().collect();
        let rs = |e: &E| taken.contains(e);
        let mut nodes = self.nodes_on(line.iter().filter_map(|i| self.topo.get(i as usize).copied()), &on_l, &rs, d, &ix);
        for r in self.taken.iter().filter(|r| !on_l(r)) {
            for y in d.removes.get(r).into_iter().flatten() {
                if !self.readded(*y, *r, &on_l, &rs, d, &ix) {
                    nodes.remove(y);
                }
            }
        }
        nodes
    }

    /// Of `candidates`, the one whose line holds the earliest-placed rotation (by `pos`; ties by
    /// ID) of those on exactly one of two lines. A total order: the lines' rotations by place
    /// read as one binary number each.
    fn first_line(&self, candidates: &BTreeSet<E>, pos: &BTreeMap<E, usize>) -> Option<E> {
        let line = |c: &E| -> BTreeSet<E> { self.line_iter(*c).collect() };
        let key = |r: &E| (pos.get(r).copied().unwrap_or(usize::MAX), *r);
        let lines: BTreeMap<E, BTreeSet<E>> = candidates.iter().map(|c| (*c, line(c))).collect();
        let empty = BTreeSet::new();
        let order = |a: &E, b: &E| {
            let (la, lb) = (lines.get(a).unwrap_or(&empty), lines.get(b).unwrap_or(&empty));
            let first = la.symmetric_difference(lb).min_by_key(|r| key(r));
            match first {
                Some(r) if la.contains(r) => std::cmp::Ordering::Less,
                Some(_) => std::cmp::Ordering::Greater,
                None => a.cmp(b),
            }
        };
        candidates.iter().min_by(|a, b| order(a, b)).copied()
    }

    /// The counting epochs no counting rotation descends from: the root alone when no rotation
    /// counts.
    fn heads_of(&self) -> BTreeSet<E> {
        if self.counting.is_empty() {
            return [self.root].into();
        }
        self.tips(|x| self.counting.contains(x))
    }

    /// The epochs `m` is signed at: its own, and a merge's every tip.
    fn signed_at(&self, m: &Rotation<E>) -> BTreeSet<E> {
        std::iter::once(m.at).chain(m.names.iter().copied()).collect()
    }

    /// Held epochs `x` descends from directly: the one a plain rotation is signed at; a merge's
    /// tips.
    fn parents(&self, x: E) -> Vec<E> {
        let Some(r) = self.rots.get(&x) else { return vec![] };
        std::iter::once(r.at).chain(r.names.iter().copied()).filter(|p| self.rots.contains_key(p)).collect()
    }

    /// Whether held epoch `x` is a merge.
    fn is_merge(&self, x: &E) -> bool {
        self.rots.get(x).is_some_and(Rotation::is_merge)
    }

    /// Whether `x` is on held epoch `r`'s line (the root is on every line; a merge where its
    /// tips are: its epoch descends from exactly those).
    fn on(&self, x: E, r: E) -> bool {
        if x == self.root || x == r && self.idx.contains_key(&x) {
            return true;
        }
        let Some(l) = self.place(&r).and_then(|ri| self.lines.get(ri)) else { return false };
        match self.rots.get(&x) {
            Some(m) if m.is_merge() => std::iter::once(&m.at).chain(&m.names).all(|t| self.idx.get(t).is_some_and(|ti| l.contains(*ti))),
            _ => self.idx.get(&x).is_some_and(|xi| l.contains(*xi)),
        }
    }

    /// Held rotation `r`'s line, in the order held (each after what it needs).
    fn line_iter(&self, r: E) -> impl Iterator<Item = E> + '_ {
        self.place(&r).and_then(|i| self.lines.get(i)).into_iter().flat_map(move |l| l.iter().filter_map(move |x| self.topo.get(x as usize).copied()))
    }

    /// Every rejection among the pairs `rej` can be: held rotation m rejects held rotation r
    /// (both among `among`) where m supersedes r's epoch and no rotation among them signed at
    /// `m.at`, m included, shares a line with r (a line is contested only from below: one signed
    /// at e rejects nothing on a line through e; nor its own line, which holds the rotation
    /// minting `m.at`).
    fn rejections(&self, rej: &Rejecting<E>, among: impl Fn(&E) -> bool) -> BTreeSet<(E, E)> {
        let mut out = BTreeSet::new();
        for (m, r) in rej.pairs.iter().filter(|(m, r)| among(m) && among(r)) {
            let Some(at) = self.rots.get(m).map(|x| x.at) else { continue };
            let through = rej.signed_by.get(&at).into_iter().flatten().filter(|s| among(s)).any(|s| self.on(*s, *r) || self.on(*r, *s));
            if !through {
                out.insert((*m, *r));
            }
        }
        out
    }

    /// The pairs a rejection can be among and the rotations signed at each epoch (`Rejecting`).
    fn rejecting(&self) -> Rejecting<E> {
        let mut signed_by: BTreeMap<E, Vec<E>> = BTreeMap::new();
        let mut pairs = Vec::new();
        for m in self.rots.values() {
            for e in self.signed_at(m) {
                signed_by.entry(e).or_default().push(m.id);
            }
            for r in m.supersedes.iter().filter(|r| **r != m.id && self.rots.contains_key(*r) && !self.on(**r, m.id)) {
                pairs.push((m.id, *r));
            }
        }
        Rejecting { pairs, signed_by }
    }

    /// Whether epoch `e` is held: the root, or minted by a rotation held with its chain. A
    /// commit at an epoch not held is pending (spec/permissions.md §5.5).
    pub fn holds(&self, e: &E) -> bool {
        *e == self.root || self.rots.contains_key(e)
    }

    /// Whether held rotation `r` counts.
    pub fn counts(&self, r: &E) -> bool {
        self.counting.contains(r)
    }

    /// Whether epoch `e` counts: the root, or minted by a counting rotation.
    pub fn epoch_counts(&self, e: &E) -> bool {
        *e == self.root || self.counts(e)
    }

    /// The counting rotations closing epoch `e`: every one it does not descend from. A
    /// head has some in a fork (the other heads): a lister reads them for the cutoff once it
    /// closes (spec/permissions.md §5.5).
    pub fn closers(&self, e: &E) -> Vec<E> {
        self.counting.iter().copied().filter(|r| !(self.rots.contains_key(e) && self.on(*r, *e))).collect()
    }

    /// Whether epoch `e` is open: it is a head.
    pub fn open(&self, e: &E) -> bool {
        self.heads.contains(e)
    }

    /// Held rotation `r`'s line: itself and every held rotation it descends from.
    pub fn line(&self, r: &E) -> Option<BTreeSet<E>> {
        self.place(r).map(|_| self.line_iter(*r).collect())
    }

    /// Whether held rotation `x` is on held rotation `r`'s line (`r` descends from `x`, or is
    /// it): `line(r)` holds `x`.
    pub fn on_line(&self, x: &E, r: &E) -> bool {
        *x != self.root && self.on(*x, *r)
    }

    /// Of the held rotations `among` tells, those no other of them descends from.
    pub fn tips(&self, among: impl Fn(&E) -> bool) -> BTreeSet<E> {
        // whether one of them descends from each, gathered back along the lines
        let mut below = vec![false; self.topo.len()];
        for (i, &x) in self.topo.iter().enumerate().rev() {
            let mark = below.get(i) == Some(&true) || among(&x);
            for p in self.parents(x).iter().filter_map(|p| self.place(p)) {
                if let Some(b) = below.get_mut(p) {
                    *b |= mark;
                }
            }
        }
        let out: Vec<E> = self.topo.iter().enumerate().filter(|(i, x)| among(x) && below.get(*i) == Some(&false)).map(|(_, x)| *x).collect();
        // a merge is below an epoch whose line holds its tips without one descending from it
        // over parents (a merge of more tips): only such tips are compared
        out.iter().copied().filter(|x| !self.is_merge(x) || !out.iter().any(|y| y != x && self.on(*x, *y))).collect()
    }

    /// The tips of the held lines beside the followed one that a counting rotation rejects or
    /// that reject one: the versions of the account's history the node is told of. Empty when
    /// none.
    pub fn contested(&self) -> &BTreeSet<E> {
        &self.contested
    }

    /// Whether held rotation `r` does not count and a counting rotation rejects it or it rejects
    /// one: the Warning's word (spec/permissions.md §5.4); `contested` holds the tips of such.
    pub fn contests(&self, r: &E) -> bool {
        !self.counting.contains(r) && self.rejects.iter().any(|(a, b)| (a == r && self.counting.contains(b)) || (b == r && self.counting.contains(a)))
    }

    /// Whether the node is told the account has forked (`contested` is not empty).
    pub fn warning(&self) -> bool {
        !self.contested.is_empty()
    }

    /// The user's choice, if held.
    pub fn chosen(&self) -> Option<E> {
        self.chosen
    }

    /// Whether a counting rotation rejects held rotation `r`.
    pub fn rejected(&self, r: &E) -> bool {
        self.rejects.iter().any(|(m, x)| x == r && self.counting.contains(m))
    }

    /// Whether held rotation `r` was placed in conflict with the followed rotations.
    pub fn disregarded(&self, r: &E) -> bool {
        self.disregarded.contains(r)
    }

    /// The heads: the counting epochs no counting rotation descends from, every one open. More
    /// than one (only at a node of the account: its devices' rotations made at once) is owed a
    /// merge.
    pub fn heads(&self) -> &BTreeSet<E> {
        &self.heads
    }

    /// The preferred head, where a node of the account signs: of the heads, the one whose line
    /// holds the earliest-placed rotation not on every one's line.
    pub fn preferred(&self) -> E {
        self.preferred
    }

    /// At a node of the account, the revocations it takes, in the order taken; a rotation it
    /// makes takes those not on its line (`Rotation::takes`).
    pub fn taken(&self) -> &[E] {
        &self.taken
    }
}
