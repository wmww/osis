//! An account's signing chain (spec/crypto.md §9, spec/permissions.md §5.4): which held
//! rotations a node follows, the open head, and the warning. A pure function of the held
//! rotations, the order the node came to hold them, the rotation its user chose and (at a node
//! of the account) what its devices list says of them; nothing here reads `ts`, counters or
//! signatures (the caller checks those and states the result in `Rotation::signed` and
//! `Devices`).
//!
//! Principle: the first revocation seen holds. A node places the rotations in the order it came
//! to hold them (each with its chain, every fork it names and every rotation it takes; ties
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

use std::collections::{BTreeMap, BTreeSet};

/// Everything reachable from `k` over `parents`, `k` itself excluded unless a cycle returns to
/// it. Brute force: chains are short and a fork is rare.
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

/// A held rotation of the account's signing chain. Its ID names the epoch it mints; the first
/// epoch (the chain's root) is minted by none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotation<E> {
    pub id: E,
    /// The epoch it is signed at (the one it rotates).
    pub at: E,
    /// The epochs it supersedes: `at`, and for a merge the fork epochs it ends.
    pub supersedes: BTreeSet<E>,
    /// The fork rotations it names (a merge accepts them).
    pub names: BTreeSet<E>,
    /// The named forks whose epoch also signed it, as the caller verified (each signature
    /// checked against the key the named rotation mints). A name without its signature
    /// accepts nothing.
    pub signed: BTreeSet<E>,
    /// The revocations its maker took that are not on its line: it stands with them (read only
    /// at a node of the account). It is held only once these are, at every node.
    pub takes: BTreeSet<E>,
}

/// What a node of the account reads of its chain as D's roster (spec/permissions.md §5.4,
/// Following, at a node of P): who minted each held rotation (its inner signature, as the caller
/// opened it) and the membership changes each carries (its sealed devices field, opened with the
/// seed of the epoch it is signed at). No removal or addition exists apart from its rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Devices<E, M> {
    /// Per held rotation, the key actor that minted it (one whose inner signature opens to no
    /// key actor is left out: it stands by none).
    pub minter: BTreeMap<E, M>,
    /// Per held rotation, the devices it removes from D.
    pub removes: BTreeMap<E, BTreeSet<M>>,
    /// Per held rotation, the devices it adds to D (a pairing).
    pub adds: BTreeMap<E, BTreeSet<M>>,
    /// The devices the account's creation record names.
    pub first: BTreeSet<M>,
}

impl<E, M> Default for Devices<E, M> {
    fn default() -> Self {
        Devices { minter: BTreeMap::new(), removes: BTreeMap::new(), adds: BTreeMap::new(), first: BTreeSet::new() }
    }
}

/// The chain as one node judges it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain<E> {
    root: E,
    rots: BTreeMap<E, Rotation<E>>,
    /// Per held rotation, its line: itself and every held rotation it descends from.
    lines: BTreeMap<E, BTreeSet<E>>,
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

impl<E: Ord + Copy> Chain<E> {
    /// Judges `rotations` (the held ones, one record each) as a node that holds them in the
    /// order `received` (earliest first; one missing ranks after every one in it) and whose
    /// user chose `chosen`; `devices` at a node of the account (`None` elsewhere). A rotation
    /// counts as held only with its chain back to the root, every fork it names and every
    /// rotation it takes, each so held (spec/permissions.md §5.4); the rest are pending and take
    /// part in nothing (`holds`).
    pub fn new<M: Ord + Copy>(root: E, rotations: impl IntoIterator<Item = Rotation<E>>, chosen: Option<E>, received: &[E], devices: Option<&Devices<E, M>>) -> Chain<E> {
        let rank = ranks(received);
        let rank_of = |r: &E| rank.get(r).copied().unwrap_or(usize::MAX);
        let mut pending: BTreeMap<E, Rotation<E>> = rotations.into_iter().filter(|r| r.id != root).map(|r| (r.id, r)).collect();
        let mut rots: BTreeMap<E, Rotation<E>> = BTreeMap::new();
        // when each came to be held with its chain: its own receipt or a parent's, the later
        let mut when: BTreeMap<E, usize> = BTreeMap::new();
        // and its depth: one more than the deepest of what it needs, so of two held at once the
        // one it needs is placed first (a receipt millisecond orders its rotations by ID)
        let mut depth: BTreeMap<E, usize> = BTreeMap::new();
        let held = |rots: &BTreeMap<E, Rotation<E>>, e: &E| *e == root || rots.contains_key(e);
        // and every revocation it takes, at every node: one taking what no node of the account
        // holds would otherwise be followed outside unanswered
        let needs = |r: &Rotation<E>| -> Vec<E> { std::iter::once(r.at).chain(r.names.iter().copied()).chain(r.takes.iter().copied()).collect() };
        while let Some(id) = pending.values().find(|r| needs(r).iter().all(|n| held(&rots, n))).map(|r| r.id) {
            if let Some(r) = pending.remove(&id) {
                let w = needs(&r).iter().filter_map(|p| when.get(p)).fold(rank_of(&id), |a, b| a.max(*b));
                when.insert(id, w);
                depth.insert(id, 1 + needs(&r).iter().filter_map(|p| depth.get(p)).max().copied().unwrap_or(0));
                rots.insert(id, r);
            }
        }
        let mut c = Chain { root, rots, lines: BTreeMap::new(), rejects: BTreeSet::new(), counting: BTreeSet::new(), disregarded: BTreeSet::new(), chosen: None, heads: BTreeSet::new(), preferred: root, contested: BTreeSet::new(), taken: Vec::new() };
        c.lines = c.rots.keys().map(|&r| (r, c.line_of(r))).collect();
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
        match devices {
            Some(d) => c.follow_as_node(&order, d),
            None => c.follow_outside(&order),
        }
        c.disregarded.retain(|r| !c.counting.contains(r));
        c.rejects = c.rejections(&c.rots.keys().copied().collect());
        c.heads = c.heads_of();
        let pos: BTreeMap<E, usize> = order.iter().enumerate().map(|(i, r)| (*r, i)).collect();
        c.preferred = c.first_line(&c.heads, &pos).unwrap_or(root);
        let contested: BTreeSet<E> = c.rots.keys().copied().filter(|x| c.contests(x)).collect();
        c.contested = contested.iter().copied().filter(|x| !contested.iter().any(|y| y != x && c.on_line(*x, *y))).collect();
        c
    }

    /// Outside the account: in order, each rotation is followed with its line unless a
    /// followed one is beside it (neither on the other's line), or a rotation on its line
    /// rejects or is rejected by a followed one (a merge cannot carry in a rejection of the
    /// followed line). Each check reads only what was placed before, so a later arrival never
    /// reopens a decision.
    fn follow_outside(&mut self, order: &[E]) {
        let mut placed: BTreeSet<E> = BTreeSet::new();
        for &r in order {
            placed.insert(r);
            if self.counting.contains(&r) {
                continue;
            }
            let rejects = self.rejections(&placed);
            let line = self.lines.get(&r).cloned().unwrap_or_default();
            let rejected = line.iter().any(|q| self.counting.iter().any(|k| rejects.contains(&(*q, *k)) || rejects.contains(&(*k, *q))));
            if rejected || self.counting.iter().any(|k| !self.on_line(*k, r) && !self.on_line(r, *k)) {
                self.disregarded.insert(r);
                continue;
            }
            self.counting.extend(line);
        }
    }

    /// At a node of the account, which reads who minted each rotation and whom each removes
    /// and adds: the revocations (rotations carrying a removal) it takes are a consistent set,
    /// built in order: one is taken when its line and every taken one's stand with it and every
    /// revocation it stands with (`with_of`) is taken. It follows every rotation whose line stands
    /// under the taken revocations and whose revocations it stands with are all taken: a device
    /// that took another revocation first stands with it in every rotation it makes
    /// (`Rotation::takes`), so those are that side, never merged into this one, whoever signed
    /// them. So its devices' rotations made at once all count, a removed device's plain fork never
    /// outweighs the removal, and of two revocations hitting each other the one held first holds.
    fn follow_as_node<M: Ord + Copy>(&mut self, order: &[E], d: &Devices<E, M>) {
        let revocation = |q: &E| d.removes.get(q).is_some_and(|x| !x.is_empty());
        // the revocations r stands with: those on its line and those a rotation on it takes
        let with_of = |r: &E| -> BTreeSet<E> {
            self.lines.get(r).into_iter().flatten().flat_map(|q| std::iter::once(*q).filter(revocation).chain(self.rots.get(q).into_iter().flat_map(|x| x.takes.iter().copied()))).collect()
        };
        let mut taken: Vec<E> = Vec::new();
        for r in order.iter().filter(|r| revocation(r)) {
            let mut with = taken.clone();
            with.push(*r);
            if self.stands(*r, &with, d) && taken.iter().all(|q| self.stands(*q, &with, d)) && with_of(r).iter().all(|q| q == r || taken.contains(q)) {
                taken.push(*r);
            }
        }
        for &r in order {
            if self.stands(r, &taken, d) && with_of(&r).iter().all(|q| taken.contains(q)) {
                self.counting.insert(r);
            } else {
                self.disregarded.insert(r);
            }
        }
        self.taken = taken;
    }

    /// Whether every rotation on `r`'s line is minted by a node of the line before it, and none
    /// is hit by the removals of `rs` or those carried on the line. A rotation whose minter is
    /// no node stands by none.
    fn stands<M: Ord + Copy>(&self, r: E, rs: &[E], d: &Devices<E, M>) -> bool {
        let Some(line) = self.lines.get(&r) else { return false };
        let mut all: Vec<E> = rs.to_vec();
        all.extend(line.iter().copied().filter(|q| d.removes.get(q).is_some_and(|x| !x.is_empty()) && !rs.contains(q)));
        line.iter().all(|q| d.minter.get(q).is_some_and(|m| self.nodes_before(*q, &all, d).contains(m)) && !self.hit(*q, &all, d))
    }

    /// Whether a removal of `rs` hits rotation `q`: it removes `q`'s minter and `q` is not on its
    /// line before it (made before the removal), and `q` descends from no re-add of that node
    /// after the removal by a rotation not hit (`readded`).
    fn hit<M: Ord + Copy>(&self, q: E, rs: &[E], d: &Devices<E, M>) -> bool {
        let Some(y) = d.minter.get(&q) else { return false };
        let Some(lq) = self.lines.get(&q) else { return false };
        rs.iter().any(|r| *r != q && d.removes.get(r).is_some_and(|x| x.contains(y)) && !self.before(q, *r) && !self.readded(*y, *r, lq, rs, d))
    }

    /// Whether a rotation on line `l` adds `y` back after the removal carried by `r` (it
    /// descends from `r`), minted by another node and not hit.
    fn readded<M: Ord + Copy>(&self, y: M, r: E, l: &BTreeSet<E>, rs: &[E], d: &Devices<E, M>) -> bool {
        l.iter().any(|a| d.adds.get(a).is_some_and(|x| x.contains(&y)) && self.before(r, *a) && d.minter.get(a) != Some(&y) && !self.hit(*a, rs, d))
    }

    /// Whether held rotation `x` is on `r`'s line before it (`r` descends from `x`).
    fn before(&self, x: E, r: E) -> bool {
        x != r && self.on_line(x, r)
    }

    /// The nodes of the epoch `q` is signed at (its line before it): `nodes_on` that line.
    fn nodes_before<M: Ord + Copy>(&self, q: E, rs: &[E], d: &Devices<E, M>) -> BTreeSet<M> {
        let base: BTreeSet<E> = self.lines.get(&q).into_iter().flatten().copied().filter(|x| *x != q).collect();
        self.nodes_on(&base, rs, d)
    }

    /// The nodes on line `l`: the creation devices and those added on it by a rotation not hit,
    /// less every one a rotation on it removes without a re-add after.
    fn nodes_on<M: Ord + Copy>(&self, l: &BTreeSet<E>, rs: &[E], d: &Devices<E, M>) -> BTreeSet<M> {
        let added = l.iter().filter(|a| !self.hit(**a, rs, d)).flat_map(|a| d.adds.get(a).into_iter().flatten().filter(move |y| d.minter.get(a) != Some(*y)));
        let candidates: BTreeSet<M> = d.first.iter().copied().chain(added.copied()).collect();
        candidates.into_iter().filter(|y| l.iter().filter(|r| d.removes.get(r).is_some_and(|x| x.contains(y))).all(|r| self.readded(*y, *r, l, rs, d))).collect()
    }

    /// At a node of the account, D's roster at epoch `e` (a held rotation, or the root): the
    /// nodes of its line under the taken revocations, a removal taken off the line holding
    /// unless the line adds its node back after it.
    pub fn roster<M: Ord + Copy>(&self, e: &E, d: &Devices<E, M>) -> BTreeSet<M> {
        self.roster_of_line(&self.lines.get(e).cloned().unwrap_or_default(), d)
    }

    /// `roster` of the line joining the held epochs `heads` (a merge's, before it is made).
    pub fn roster_joining<M: Ord + Copy>(&self, heads: &[E], d: &Devices<E, M>) -> BTreeSet<M> {
        self.roster_of_line(&heads.iter().flat_map(|h| self.lines.get(h).into_iter().flatten().copied()).collect(), d)
    }

    fn roster_of_line<M: Ord + Copy>(&self, line: &BTreeSet<E>, d: &Devices<E, M>) -> BTreeSet<M> {
        let mut nodes = self.nodes_on(line, &self.taken, d);
        for r in self.taken.iter().filter(|r| !line.contains(*r)) {
            for y in d.removes.get(r).into_iter().flatten() {
                if !self.readded(*y, *r, line, &self.taken, d) {
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
        let empty = BTreeSet::new();
        let line = |c: &E| self.lines.get(c).unwrap_or(&empty);
        let key = |r: &E| (pos.get(r).copied().unwrap_or(usize::MAX), *r);
        let order = |a: &E, b: &E| {
            let (la, lb) = (line(a), line(b));
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
        self.counting.iter().copied().filter(|h| !self.counting.iter().any(|x| x != h && self.on_line(*h, *x))).collect()
    }

    /// The named forks rotation `m` accepts: held, and signed at their epoch.
    fn accepts(&self, m: &Rotation<E>) -> Vec<E> {
        m.names.iter().copied().filter(|n| m.signed.contains(n) && self.rots.contains_key(n)).collect()
    }

    /// The epochs `m` is signed at: its own, and each fork it accepts.
    fn signed_at(&self, m: &Rotation<E>) -> BTreeSet<E> {
        std::iter::once(m.at).chain(self.accepts(m)).collect()
    }

    /// Held rotations `x` descends from directly: the one minting the epoch it is signed at, and
    /// the forks it accepts.
    fn parents(&self, x: E) -> Vec<E> {
        let Some(r) = self.rots.get(&x) else { return vec![] };
        self.rots.contains_key(&r.at).then_some(r.at).into_iter().chain(self.accepts(r)).collect()
    }

    /// Whether `x` is on held rotation `r`'s line (the root is on every line).
    fn on_line(&self, x: E, r: E) -> bool {
        x == self.root || self.lines.get(&r).is_some_and(|l| l.contains(&x))
    }

    fn line_of(&self, r: E) -> BTreeSet<E> {
        let mut line = ancestors(r, |x| self.parents(x));
        line.insert(r);
        line
    }

    /// Every (m, r) among `among` with m rejecting r: m supersedes r's epoch and no rotation of
    /// `among` signed at `m.at`, m included, shares a line with r (a line is contested only
    /// from below: one signed at e rejects nothing on a line through e; nor its own line, which
    /// holds the rotation minting `m.at` and every fork m accepts).
    fn rejections(&self, among: &BTreeSet<E>) -> BTreeSet<(E, E)> {
        let mut signed_by: BTreeMap<E, Vec<E>> = BTreeMap::new();
        for s in among.iter().filter_map(|s| self.rots.get(s)) {
            for e in self.signed_at(s) {
                signed_by.entry(e).or_default().push(s.id);
            }
        }
        let mut out = BTreeSet::new();
        for m in among.iter().filter_map(|m| self.rots.get(m)) {
            for &r in m.supersedes.iter().filter(|r| **r != m.id && among.contains(r)) {
                let through = signed_by.get(&m.at).into_iter().flatten().any(|s| self.on_line(*s, r) || self.on_line(r, *s));
                if !through {
                    out.insert((m.id, r));
                }
            }
        }
        out
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
        let line = self.lines.get(e);
        self.counting.iter().copied().filter(|r| !line.is_some_and(|l| l.contains(r))).collect()
    }

    /// Whether epoch `e` is open: it is a head.
    pub fn open(&self, e: &E) -> bool {
        self.heads.contains(e)
    }

    /// Held rotation `r`'s line: itself and every held rotation it descends from.
    pub fn line(&self, r: &E) -> Option<&BTreeSet<E>> {
        self.lines.get(r)
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
        !self.counting.contains(r) && self.counting.iter().any(|m| self.rejects.contains(&(*m, *r)) || self.rejects.contains(&(*r, *m)))
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
        self.counting.iter().any(|m| self.rejects.contains(&(*m, *r)))
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
