//! The epoch rule (spec/permissions.md §5.5): which commits of an account count at a node, as a
//! function of the held rotations, the side, and the held lists, listings and addenda naming
//! the account's commits. Nothing here reads `ts`, counters or the inner signature.
//!
//! Principle: closing an epoch ends the standing of what was signed at it, as a demotion ends a
//! holder's. A commit at a closed epoch counts iff some party's word names it: the rotator's
//! (a thing list of a counting rotation), the account's own later word (a counting listing), or
//! another writer's (an addendum against a counting rotation closing the epoch). When each
//! party names a commit is the one cutoff, a writer's rule (`fit_list` for the bound).
//!
//! Addenda are not judged here: an addendum counts by §5.2's least fixpoint, which may run
//! through other accounts' epochs (a witness's addendum at its own closed epoch), so it is
//! `Timeline::vouching`'s, fed each addendum's `EpochStanding`. Lists and listings save whole
//! commits (role commits among them), so the timeline reads `counts`, which no addendum moves.

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
/// commit `listing` name `commits`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing<E, T> {
    pub listing: AccountCommit<E, T>,
    pub thing: T,
    pub commits: BTreeSet<E>,
}

/// What the epoch rule says of one held commit of the account, before §5.2 judges it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EpochStanding<E> {
    /// It counts whole: its epoch is open, a counting list or listing names it, or
    /// (a rotation) the chain counts it.
    Counts,
    /// It does not count. A counting addendum on a thing against one of `closers` (the counting
    /// rotations closing its epoch; none when the epoch does not count, or for a rotation)
    /// listing it saves its plain deltas there (spec/permissions.md §5.5, the addenda fixpoint
    /// of §5.2).
    Closed(BTreeSet<E>),
}

/// One account's epochs as a node judges them: the chain and the held words naming the
/// account's commits at closed epochs. Holds nothing per commit: a commit is judged when asked
/// (`standing`), so building it costs the rotations, lists and listings held, never the
/// account's history.
#[derive(Clone, Debug)]
pub struct Epochs<E, T> {
    chain: Chain<E>,
    /// The held epoch that is open (the head followed), as a set.
    open: BTreeSet<E>,
    /// Per held epoch that counts and is closed, its closers.
    closers: BTreeMap<E, BTreeSet<E>>,
    /// (commit, thing): a counting thing list or counting listing names the commit on the thing.
    named: BTreeSet<(E, T)>,
}

impl<E: Ord + Copy, T: Ord + Copy> Epochs<E, T> {
    /// Judges the account with first epoch `root`: its held `rotations` under `side` and
    /// `received` (only those held with their chain take part, `Chain::new`) and the held thing
    /// lists and listings naming its commits.
    pub fn new(root: E, rotations: impl IntoIterator<Item = Rotation<E>>, side: Option<E>, received: &[E], lists: &[ThingList<E, T>], listings: &[Listing<E, T>]) -> Epochs<E, T> {
        let rotations: Vec<Rotation<E>> = rotations.into_iter().collect();
        let held: BTreeSet<E> = rotations.iter().map(|r| r.id).chain([root]).collect();
        let chain = Chain::new(root, rotations, side, received);
        let held: Vec<E> = held.into_iter().filter(|e| chain.holds(e) && chain.epoch_counts(e)).collect();
        let open = held.iter().filter(|e| chain.open(e)).copied().collect();
        let mut e = Epochs { chain, open, closers: BTreeMap::new(), named: BTreeSet::new() };
        e.closers = held.iter().filter(|x| !e.open.contains(x)).map(|x| (*x, e.chain.closers(x).into_iter().collect())).collect();
        e.named = lists.iter().filter(|l| e.chain.counts(&l.rotation)).flat_map(|l| l.commits.iter().map(|c| (*c, l.thing))).collect();
        // Least fixpoint: a listing at a closed epoch speaks only once it is itself named.
        loop {
            let more: Vec<(E, T)> = listings.iter().filter(|l| e.counts(&l.listing)).flat_map(|l| l.commits.iter().map(|c| (*c, l.thing))).filter(|x| !e.named.contains(x)).collect();
            if more.is_empty() {
                break;
            }
            e.named.extend(more);
        }
        e
    }

    /// The chain as judged (only rotations held with their chain).
    pub fn chain(&self) -> &Chain<E> {
        &self.chain
    }

    /// Whether `c` is pending: its epoch is not held (its minting rotation, or that rotation's
    /// chain, has not arrived).
    pub fn pending(&self, c: &AccountCommit<E, T>) -> bool {
        !self.chain.holds(&c.epoch)
    }

    /// Whether `c` counts whole: a held rotation counts by the chain alone; any other commit
    /// iff its epoch is open, or counts and a counting thing list or listing on one
    /// of its things names it.
    pub fn counts(&self, c: &AccountCommit<E, T>) -> bool {
        if self.chain.holds(&c.id) {
            return self.chain.counts(&c.id);
        }
        self.open.contains(&c.epoch) || self.closers.contains_key(&c.epoch) && c.things.iter().any(|t| self.named.contains(&(c.id, *t)))
    }

    /// What the epoch rule says of `c` (`EpochStanding`).
    pub fn standing(&self, c: &AccountCommit<E, T>) -> EpochStanding<E> {
        if self.counts(c) {
            return EpochStanding::Counts;
        }
        EpochStanding::Closed(if self.chain.holds(&c.id) { BTreeSet::new() } else { self.closers.get(&c.epoch).cloned().unwrap_or_default() })
    }

    /// What a commit signed at `e` that no word names stands as (its `standing`, a rotation
    /// aside).
    pub fn unnamed(&self, e: &E) -> EpochStanding<E> {
        if self.open.contains(e) { EpochStanding::Counts } else { EpochStanding::Closed(self.closers.get(e).cloned().unwrap_or_default()) }
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
