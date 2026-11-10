//! An account's signing chain (spec/crypto.md §9, spec/permissions.md §5.4): which held
//! rotations count, which head a node follows, and account-level disputes. A pure function of
//! the held rotations, the side and the receipt order; nothing here reads `ts`, counters or
//! signatures (the caller checks those and states the result in `Rotation::signed`).
//!
//! Principle: a node reads one line. A fork (several heads, or a dispute) is resolved as every
//! dispute is: each node follows its side, by default the line it received first; a merge ends
//! a fork; a side set overrides. The open epoch is the head followed, and every other epoch is
//! closed. `joins` (descent from every anchor) is the key level's anchoring rule (osis-keys
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
}

/// The chain as one node judges it: the held rotations under its side, read along the head it
/// follows.
#[derive(Clone, Debug)]
pub struct Chain<E> {
    root: E,
    rots: BTreeMap<E, Rotation<E>>,
    /// Per held rotation, its line: itself and every held rotation it descends from.
    lines: BTreeMap<E, BTreeSet<E>>,
    /// (m, r): held rotation m rejects held rotation r.
    rejects: BTreeSet<(E, E)>,
    counting: BTreeSet<E>,
    parties: BTreeSet<E>,
    /// The side taken: the one given, else the default.
    side: Option<E>,
    /// The counting epochs no counting rotation descends from.
    heads: BTreeSet<E>,
    /// The head followed: the one open epoch.
    followed: E,
}

impl<E: Ord + Copy> Chain<E> {
    /// Judges `rotations` (the held ones, one record each) under `side`: the rotation the node
    /// sides with, if set (by the node's user, or a node of the account's own: its roster's
    /// line); else the default, from `received` (the held rotations in receipt order, earliest
    /// first; one missing from it ranks after every one in it). A rotation counts as held only
    /// with its chain back to the root (over the epochs it is signed at, spec/permissions.md
    /// §5.4); the rest are pending and take part in nothing (`holds`).
    pub fn new(root: E, rotations: impl IntoIterator<Item = Rotation<E>>, side: Option<E>, received: &[E]) -> Chain<E> {
        let mut pending: BTreeMap<E, Rotation<E>> = rotations.into_iter().filter(|r| r.id != root).map(|r| (r.id, r)).collect();
        let mut rots: BTreeMap<E, Rotation<E>> = BTreeMap::new();
        while let Some(&id) = pending.values().find(|r| r.at == root || rots.contains_key(&r.at)).map(|r| &r.id) {
            if let Some(r) = pending.remove(&id) {
                rots.insert(id, r);
            }
        }
        let mut c = Chain { root, rots, lines: BTreeMap::new(), rejects: BTreeSet::new(), counting: BTreeSet::new(), parties: BTreeSet::new(), side: None, heads: BTreeSet::new(), followed: root };
        c.lines = c.rots.keys().map(|&r| (r, c.line_of(r))).collect();
        c.rejects = c.rejections();
        c.parties = c.contesting();
        let rank = ranks(received);
        c.side = side.filter(|s| c.rots.contains_key(s)).or_else(|| c.first_line(&c.parties, &rank));
        c.counting = c.count(c.side);
        c.heads = c.heads_of();
        let on_side: BTreeSet<E> = c.heads.iter().copied().filter(|h| c.side.is_some_and(|s| c.on_line(*h, s))).collect();
        c.followed = c.first_line(if on_side.is_empty() { &c.heads } else { &on_side }, &rank).unwrap_or(root);
        c
    }

    /// Among `candidates`, the one preferred to every other: h is preferred to g when the
    /// earliest-received rotation on exactly one of their lines is on h's (receipt ties by ID).
    /// A total order: the lines' rotations by receipt read as one binary number each.
    fn first_line(&self, candidates: &BTreeSet<E>, rank: &BTreeMap<E, usize>) -> Option<E> {
        let empty = BTreeSet::new();
        let line = |c: &E| self.lines.get(c).unwrap_or(&empty);
        let key = |r: &E| (rank.get(r).copied().unwrap_or(usize::MAX), *r);
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

    /// Of held `candidates`, the one whose line `received` (earliest first) brought first, as
    /// the default side picks (`first_line`).
    pub fn prefer(&self, candidates: &BTreeSet<E>, received: &[E]) -> Option<E> {
        self.first_line(candidates, &ranks(received))
    }

    /// The counting epochs no counting rotation descends from: the root alone when no rotation
    /// counts.
    fn heads_of(&self) -> BTreeSet<E> {
        if self.counting.is_empty() {
            return [self.root].into();
        }
        self.counting.iter().copied().filter(|h| !self.counting.iter().any(|x| x != h && self.on_line(*x, *h))).collect()
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

    /// Whether `x` is on held rotation `r`'s line.
    fn on_line(&self, r: E, x: E) -> bool {
        self.lines.get(&r).is_some_and(|l| l.contains(&x))
    }

    fn line_of(&self, r: E) -> BTreeSet<E> {
        let mut line = ancestors(r, |x| self.parents(x));
        line.insert(r);
        line
    }

    /// Every (m, r) with m rejecting r: m supersedes r's epoch and no held rotation signed at
    /// `m.at`, m included, shares a line with r (a line is contested only from below: one signed
    /// at e rejects nothing on a line through e; nor its own line, which holds the rotation
    /// minting `m.at` and every fork m accepts).
    fn rejections(&self) -> BTreeSet<(E, E)> {
        let mut signed_by: BTreeMap<E, Vec<E>> = BTreeMap::new();
        for s in self.rots.values() {
            for e in self.signed_at(s) {
                signed_by.entry(e).or_default().push(s.id);
            }
        }
        let mut out = BTreeSet::new();
        for m in self.rots.values() {
            for &r in &m.supersedes {
                if !self.rots.contains_key(&r) {
                    continue;
                }
                let through = signed_by.get(&m.at).into_iter().flatten().any(|s| self.on_line(*s, r) || self.on_line(r, *s));
                if !through {
                    out.insert((m.id, r));
                }
            }
        }
        out
    }

    /// Which rotations count, well-founded: seeded by the side (whatever rejects a rotation on
    /// its line is void), then a rotation is decided once its parent and every rotation
    /// rejecting it are: void if the parent is void or a counting one rejects it, else
    /// counting. A contest no side settles stays undecided and counts for nothing.
    fn count(&self, side: Option<E>) -> BTreeSet<E> {
        let mut status: BTreeMap<E, Option<bool>> = self.rots.keys().map(|&r| (r, None)).collect();
        if let Some(line) = side.and_then(|s| self.lines.get(&s)) {
            for &(m, r) in &self.rejects {
                if line.contains(&r) {
                    status.insert(m, Some(false));
                }
            }
        }
        loop {
            let mut changed = false;
            for (&r, rot) in &self.rots {
                if status.get(&r).is_some_and(Option::is_some) {
                    continue;
                }
                let parent = if rot.at == self.root { Some(true) } else { status.get(&rot.at).copied().unwrap_or(Some(false)) };
                let rejectors: Vec<Option<bool>> = self.rejects.iter().filter(|(_, x)| *x == r).map(|(m, _)| status.get(m).copied().flatten()).collect();
                let decided = if parent == Some(false) || rejectors.contains(&Some(true)) {
                    Some(false)
                } else if parent == Some(true) && rejectors.iter().all(|s| *s == Some(false)) {
                    Some(true)
                } else {
                    None
                };
                if decided.is_some() {
                    status.insert(r, decided);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        status.into_iter().filter(|(_, s)| *s == Some(true)).map(|(r, _)| r).collect()
    }

    /// Rotations in a mutual contest: a rejects a rotation on b's line other than itself, and b
    /// one on a's.
    fn contesting(&self) -> BTreeSet<E> {
        let contests = |a: E, b: E| self.lines.get(&b).into_iter().flatten().any(|&c| c != a && self.rejects.contains(&(a, c)));
        let ids: Vec<E> = self.rots.keys().copied().collect();
        ids.iter().copied().filter(|&a| ids.iter().any(|&b| a != b && contests(a, b) && contests(b, a))).collect()
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

    /// The counting rotations closing epoch `e`: every one it does not descend from. The
    /// followed head has some in a fork (the other heads): they matter once it closes too (the
    /// cutoff, spec/permissions.md §5.5).
    pub fn closers(&self, e: &E) -> Vec<E> {
        let line = self.lines.get(e);
        self.counting.iter().copied().filter(|r| !line.is_some_and(|l| l.contains(r))).collect()
    }

    /// Whether epoch `e` is open: it is the head followed.
    pub fn open(&self, e: &E) -> bool {
        *e == self.followed
    }

    /// Held rotation `r`'s line: itself and every held rotation it descends from.
    pub fn line(&self, r: &E) -> Option<&BTreeSet<E>> {
        self.lines.get(r)
    }

    /// The rotations in an account-level dispute (mutually rejecting lines); empty when none.
    pub fn parties(&self) -> &BTreeSet<E> {
        &self.parties
    }

    pub fn dispute(&self) -> bool {
        !self.parties.is_empty()
    }

    /// The side taken: the one given, else in a dispute the party whose line holds the
    /// rotations not on every party's line received first.
    pub fn side(&self) -> Option<E> {
        self.side
    }

    /// The heads: the counting epochs no counting rotation descends from. More than one is a
    /// fork, which a merge ends.
    pub fn heads(&self) -> &BTreeSet<E> {
        &self.heads
    }

    /// The head followed, the one open epoch: among the heads whose line holds the side (all
    /// of them when none does), the one whose line holds the rotations not on every one's line
    /// received first.
    pub fn followed(&self) -> E {
        self.followed
    }

    /// Whether the reading is in doubt: a dispute, or a fork where a head not followed has on
    /// its line a merge (a rotation superseding more than the epoch it rotates) the followed
    /// head's line lacks. A lone rotation beside the followed line is what any one node's
    /// concurrent rotation, or a removed node's fork, looks like, and the next merge ends it.
    pub fn in_doubt(&self) -> bool {
        let followed = self.lines.get(&self.followed);
        let merge = |r: &E| self.rots.get(r).is_some_and(|x| x.supersedes.iter().any(|e| *e != x.at));
        self.dispute() || self.heads.iter().filter(|h| **h != self.followed).any(|h| self.lines.get(h).into_iter().flatten().any(|r| merge(r) && !followed.is_some_and(|l| l.contains(r))))
    }
}
