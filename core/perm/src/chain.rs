//! An account's signing chain (spec/crypto.md §9, spec/permissions.md §5.4): which held
//! rotations count, which epochs are open, and account-level disputes. A pure function of the
//! held rotations and the side; nothing here reads `ts`, counters or signatures (the caller
//! checks those and states the result in `Rotation::signed`).
//!
//! Principle: an epoch is open only where it descends from every counting rotation held. It is
//! the key level's anchoring rule (osis-keys `seal_keyset`: a keyset is sealed to only where it
//! descends from every anchor), so both use `joins`.

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

/// The chain as one node judges it: the held rotations under its side.
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
}

impl<E: Ord + Copy> Chain<E> {
    /// Judges `rotations` (the held ones, one record each) under `side`: the rotation the node
    /// sides with in a dispute, if any.
    pub fn new(root: E, rotations: impl IntoIterator<Item = Rotation<E>>, side: Option<E>) -> Chain<E> {
        let rots: BTreeMap<E, Rotation<E>> = rotations.into_iter().filter(|r| r.id != root).map(|r| (r.id, r)).collect();
        let mut c = Chain { root, rots, lines: BTreeMap::new(), rejects: BTreeSet::new(), counting: BTreeSet::new(), parties: BTreeSet::new() };
        c.lines = c.rots.keys().map(|&r| (r, c.line_of(r))).collect();
        c.rejects = c.rejections();
        c.counting = c.count(side);
        c.parties = c.contesting();
        c
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

    /// Whether held rotation `r` counts.
    pub fn counts(&self, r: &E) -> bool {
        self.counting.contains(r)
    }

    /// Whether epoch `e` counts: the root, or minted by a counting rotation.
    pub fn epoch_counts(&self, e: &E) -> bool {
        *e == self.root || self.counts(e)
    }

    /// The counting rotations closing epoch `e`: every one it does not descend from.
    pub fn closers(&self, e: &E) -> Vec<E> {
        let line = self.lines.get(e);
        self.counting.iter().copied().filter(|r| !line.is_some_and(|l| l.contains(r))).collect()
    }

    /// Whether epoch `e` is closed: some counting rotation closes it.
    pub fn closed(&self, e: &E) -> bool {
        !self.closers(e).is_empty()
    }

    /// Whether epoch `e` is open: it counts and descends from every counting rotation.
    pub fn open(&self, e: &E) -> bool {
        self.epoch_counts(e) && joins(*e, &self.counting, |x| self.parents(x))
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

    /// The default side in a dispute for a node that received the rotations in the order
    /// `received` (earliest first): the party whose line holds the first-received rotation
    /// not on every party's line. `None` without a dispute.
    pub fn default_side(&self, received: &[E]) -> Option<E> {
        let rank = |r: &E| received.iter().position(|x| x == r).unwrap_or(usize::MAX);
        let common = |r: &E| self.parties.iter().all(|p| self.on_line(*p, *r));
        // A party with nothing of its own on its line sorts last.
        let first = |p: &E| self.lines.get(p).into_iter().flatten().filter(|r| !common(r)).map(|r| (rank(r), *r)).min();
        self.parties.iter().copied().min_by_key(|p| first(p).map_or((true, None), |k| (false, Some(k))))
    }
}
