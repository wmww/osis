//! The epoch rule (spec/permissions.md §5.5): which commits of an account count at a node, as a
//! function of the held rotations, the side, and the held lists, listings and addenda naming
//! the account's commits. Nothing here reads `ts`, counters or the inner signature.
//!
//! Principle: closing an epoch ends the standing of what was signed at it, as a demotion ends a
//! holder's. A commit at a closed epoch counts iff some party's word names it: the rotator's
//! (a thing list of a counting rotation), the account's own later word (a counting listing), or
//! another writer's (an addendum against a counting rotation closing the epoch). When each
//! party names a commit is the one cutoff, a writer's rule (`fit_list` for the bound).

use crate::chain::{Chain, Rotation};
use osis_base::cbor::head_len;
use osis_base::format::LIST_TREE_DEPTH;
use osis_base::hash::Hasher;
use std::collections::{BTreeMap, BTreeSet};

/// A held commit of the account: its ID, the epoch it is signed at, and the things it has a
/// delta on or acts for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountCommit<E, T> {
    pub id: E,
    pub epoch: E,
    pub things: BTreeSet<T>,
}

/// A held thing list (the caller verified it against its rotation's list root,
/// `ListPath::verify`): rotation `rotation` names `commits` on `thing`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThingList<E, T> {
    pub rotation: E,
    pub thing: T,
    pub commits: BTreeSet<E>,
}

/// A held listing's word on one thing: the `listing.0` entries on `thing` of the account's
/// commit `listing` (itself one of the account's commits) name `commits`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing<E, T> {
    pub listing: E,
    pub thing: T,
    pub commits: BTreeSet<E>,
}

/// A counting addendum on `thing` against rotation `against`, listing `commits`: the caller
/// passes only addenda whose author held write on the thing just before their key and that are
/// valid (spec/permissions.md §5.2, the least fixpoint).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationAddendum<E, T> {
    pub thing: T,
    pub against: E,
    pub commits: BTreeSet<E>,
}

/// One account's commits as a node judges them.
#[derive(Clone, Debug)]
pub struct Epochs<E, T> {
    chain: Chain<E>,
    commits: BTreeMap<E, AccountCommit<E, T>>,
    /// Commits a counting thing list or counting listing names.
    named: BTreeSet<E>,
    /// (commit, thing): a counting addendum on the thing against a closer of the commit's epoch
    /// lists it.
    vouched: BTreeSet<(E, T)>,
}

impl<E: Ord + Copy, T: Ord + Copy> Epochs<E, T> {
    /// Judges the account with first epoch `root`: its held `rotations` under `side` (only
    /// those held with their chain take part, `Chain::new`), its held `commits`, and the held
    /// thing lists, listings and counting addenda naming them.
    pub fn new(
        root: E,
        rotations: impl IntoIterator<Item = Rotation<E>>,
        side: Option<E>,
        commits: impl IntoIterator<Item = AccountCommit<E, T>>,
        lists: &[ThingList<E, T>],
        listings: &[Listing<E, T>],
        addenda: &[RotationAddendum<E, T>],
    ) -> Epochs<E, T> {
        let chain = Chain::new(root, rotations, side);
        let commits: BTreeMap<E, AccountCommit<E, T>> = commits.into_iter().map(|c| (c.id, c)).collect();
        let mut e = Epochs { chain, commits, named: BTreeSet::new(), vouched: BTreeSet::new() };
        // What a word on thing t says of c: only of a commit on t.
        let says = |e: &Epochs<E, T>, t: &T, cs: &BTreeSet<E>| -> Vec<E> { cs.iter().filter(|c| e.commits.get(c).is_some_and(|c| c.things.contains(t))).copied().collect() };
        e.named = lists.iter().filter(|l| e.chain.counts(&l.rotation)).flat_map(|l| says(&e, &l.thing, &l.commits)).collect();
        // Least fixpoint: a listing at a closed epoch speaks only once it is itself named.
        loop {
            let more: Vec<E> = listings.iter().filter(|l| e.counts(&l.listing)).flat_map(|l| says(&e, &l.thing, &l.commits)).filter(|c| !e.named.contains(c)).collect();
            if more.is_empty() {
                break;
            }
            e.named.extend(more);
        }
        // An addendum speaks against a counting rotation closing the commit's epoch.
        let closes = |e: &Epochs<E, T>, r: &E, c: &E| e.commits.get(c).is_some_and(|c| e.chain.epoch_counts(&c.epoch) && e.chain.closers(&c.epoch).contains(r));
        e.vouched = addenda.iter().flat_map(|a| says(&e, &a.thing, &a.commits).into_iter().filter(|c| closes(&e, &a.against, c)).map(|c| (c, a.thing))).collect();
        e
    }

    /// The chain as judged (only rotations held with their chain).
    pub fn chain(&self) -> &Chain<E> {
        &self.chain
    }

    /// Whether held commit `c` is pending: its epoch is not held (its minting rotation, or that
    /// rotation's chain, has not arrived).
    pub fn pending(&self, c: &E) -> bool {
        self.commits.get(c).is_some_and(|c| !self.chain.holds(&c.epoch))
    }

    /// Whether held commit `c` counts whole: its epoch counts and is open, or counts and a
    /// counting thing list or listing names it.
    pub fn counts(&self, c: &E) -> bool {
        self.commits.get(c).is_some_and(|x| self.chain.epoch_counts(&x.epoch) && (self.chain.open(&x.epoch) || self.named.contains(c)))
    }

    /// Whether a counting addendum on `thing` against a counting rotation closing `c`'s epoch
    /// lists `c` (it saves `c`'s plain-content deltas on `thing`, spec/permissions.md §5.2).
    pub fn vouched(&self, c: &E, thing: &T) -> bool {
        self.vouched.contains(&(*c, *thing))
    }

    /// Whether a delta of `c` on `thing` passes the epoch rule; `plain`: a plain-content delta
    /// (a content commit with no purge request, its aspect neither role-class nor admin-only).
    pub fn delta_counts(&self, c: &E, thing: &T, plain: bool) -> bool {
        self.counts(c) || (plain && self.vouched(c, thing))
    }
}

/// Canonical bytes of a thing list's commit IDs (`[commit_id*]`, spec/wire.md §4) with `n` IDs.
pub fn list_bytes(n: usize) -> usize {
    head_len(n as u64) + n * (head_len(32) + 32)
}

/// A rotator's thing list within the bound (spec/permissions.md §5.5, Bound): every one of
/// `special` (role-class and purge-request commits) and as many of `plain` (plain content, in
/// receipt order, earliest first) as fit `max` bytes (`MAX_LIST_BYTES`). Returns the list and
/// the plain content left out, which the rotator's later listings name; `None` when `special`
/// alone passes `max`: the rotation is refused.
pub fn fit_list<E: Ord + Copy>(special: &BTreeSet<E>, plain: &[E], max: usize) -> Option<(BTreeSet<E>, Vec<E>)> {
    if list_bytes(special.len()) > max {
        return None;
    }
    let room = (0..=plain.len()).take_while(|&k| list_bytes(special.len() + k) <= max).last().unwrap_or(0);
    let mut list = special.clone();
    list.extend(plain.iter().take(room));
    Some((list, plain.iter().skip(room).copied().collect()))
}

/// A thing list's leaf in its rotation's list tree, from the canonical bytes of its `ThingList`
/// (spec/wire.md §4, List tree).
pub fn list_leaf(thing_list: &[u8]) -> [u8; 32] {
    Hasher::new().update(b"osis v1 list leaf").update(thing_list).finalize()
}

fn list_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    Hasher::new().update(b"osis v1 list node").update(left).update(right).finalize()
}

/// A leaf's place in a list tree: its index and the `LIST_TREE_DEPTH` sibling hashes from the
/// leaf up (a `ThingCert`'s, spec/wire.md §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListPath {
    pub index: u64,
    pub siblings: Vec<[u8; 32]>,
}

impl ListPath {
    /// The root folding `leaf` along this path gives; `None` for a path of another length or an
    /// index past the tree (bad input).
    pub fn root(&self, leaf: [u8; 32]) -> Option<[u8; 32]> {
        if self.siblings.len() != LIST_TREE_DEPTH as usize || self.index >> LIST_TREE_DEPTH != 0 {
            return None;
        }
        Some(self.siblings.iter().enumerate().fold(leaf, |acc, (k, s)| if self.index >> k & 1 == 1 { list_node(s, &acc) } else { list_node(&acc, s) }))
    }

    /// Whether `leaf` sits on this path under `root`; a cert that does not verify is bad input.
    pub fn verify(&self, leaf: [u8; 32], root: &[u8; 32]) -> bool {
        self.root(leaf).is_some_and(|r| r == *root)
    }
}

/// A rotation's list tree over `leaves` (each at its index): the root and each leaf's path, in
/// order. Every subtree holding no leaf hashes to a value of `fresh` (random, so the paths show
/// nothing of how many things are listed). `None` when two leaves share an index or one is past
/// the tree: the rotation is refused.
pub fn list_tree(leaves: &[(u64, [u8; 32])], mut fresh: impl FnMut() -> [u8; 32]) -> Option<([u8; 32], Vec<ListPath>)> {
    let indices: BTreeSet<u64> = leaves.iter().map(|l| l.0).collect();
    if indices.len() != leaves.len() || indices.iter().any(|i| i >> LIST_TREE_DEPTH != 0) {
        return None;
    }
    let mut paths: Vec<ListPath> = leaves.iter().map(|l| ListPath { index: l.0, siblings: Vec::new() }).collect();
    let all: Vec<usize> = (0..leaves.len()).collect();
    let root = subtree(LIST_TREE_DEPTH, &all, leaves, &mut paths, &mut fresh);
    Some((root, paths))
}

/// The hash of the subtree of height `h` holding leaves `at` (indices into `leaves`), pushing
/// each one's sibling at every level below `h`.
fn subtree(h: u32, at: &[usize], leaves: &[(u64, [u8; 32])], paths: &mut [ListPath], fresh: &mut impl FnMut() -> [u8; 32]) -> [u8; 32] {
    let Some(&first) = at.first() else { return fresh() };
    if h == 0 {
        return leaves.get(first).map_or_else(&mut *fresh, |l| l.1);
    }
    let (right, left): (Vec<usize>, Vec<usize>) = at.iter().partition(|&&i| leaves.get(i).is_some_and(|l| l.0 >> (h - 1) & 1 == 1));
    let l = subtree(h - 1, &left, leaves, paths, fresh);
    let r = subtree(h - 1, &right, leaves, paths, fresh);
    for (side, sib) in [(&left, r), (&right, l)] {
        for &i in side {
            if let Some(p) = paths.get_mut(i) {
                p.siblings.push(sib);
            }
        }
    }
    list_node(&l, &r)
}
