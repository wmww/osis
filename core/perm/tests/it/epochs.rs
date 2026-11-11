//! The epoch rule (spec/permissions.md §5.5): a commit at a closed epoch counts iff a counting
//! rotation's thing list names it, a counting listing names it, or a counting addendum vouches
//! for it (here: every addendum given counts; their own fixpoint is `Timeline::vouching`'s). Hand worlds of core/test/roles-model `epochs` on synthetic commits (a rotation's ID is
//! the epoch it mints, the root 0; commits 100 and up; X is the removed node), then a
//! differential against the model's random worlds.
#![allow(clippy::needless_range_loop)]

use crate::common::seeded;
use osis_perm::epochs::{fit_list, list_bytes, list_leaf, list_tree};
use osis_perm::{AccountCommit, EpochStanding, Epochs, ListPath, Listing, Rotation, ThingList};
use std::collections::BTreeMap;
use roles_model::epochs::{self as model, Kind, Verdict, World};
use roles_model::Rng;
use std::collections::BTreeSet;

fn set(v: &[u32]) -> BTreeSet<u32> {
    v.iter().copied().collect()
}

fn rot(id: u32, at: u32, sup: &[u32], names: &[u32]) -> Rotation<u32> {
    Rotation { id, at, supersedes: set(sup), names: set(names), signed: set(names) }
}

/// Commit `id` at `epoch` on thing 0.
fn c(id: u32, epoch: u32) -> AccountCommit<u32, u32> {
    AccountCommit { id, epoch, things: set(&[0]) }
}

fn list(rotation: u32, commits: &[u32]) -> ThingList<u32, u32> {
    ThingList { rotation, thing: 0, commits: set(commits) }
}

/// Listing `listing` (a commit at `epoch` on thing 0) naming `commits` on thing 0.
fn listing_at(listing: u32, epoch: u32, commits: &[u32]) -> Listing<u32, u32> {
    Listing { listing: c(listing, epoch), thing: 0, commits: set(commits) }
}

/// A counting addendum on `thing` against rotation `against`, listing `commits`.
#[derive(Clone, Debug)]
struct RotationAddendum<T> {
    thing: T,
    against: u32,
    commits: BTreeSet<u32>,
}

fn addendum(against: u32, commits: &[u32]) -> RotationAddendum<u32> {
    RotationAddendum { thing: 0, against, commits: set(commits) }
}

/// Perm's judgment of an account with its held commits and counting addenda, asked by commit ID.
struct Judged<T> {
    e: Epochs<u32, T>,
    commits: BTreeMap<u32, AccountCommit<u32, T>>,
    addenda: Vec<RotationAddendum<T>>,
}

impl<T: Ord + Copy> Judged<T> {
    fn new(e: Epochs<u32, T>, commits: impl IntoIterator<Item = AccountCommit<u32, T>>, addenda: Vec<RotationAddendum<T>>) -> Judged<T> {
        Judged { e, commits: commits.into_iter().map(|c| (c.id, c)).collect(), addenda }
    }
    fn chain(&self) -> &osis_perm::Chain<u32> {
        self.e.chain()
    }
    fn counts(&self, id: &u32) -> bool {
        self.commits.get(id).is_some_and(|c| self.e.counts(c))
    }
    fn pending(&self, id: &u32) -> bool {
        self.commits.get(id).is_some_and(|c| self.e.pending(c))
    }
    /// A counting addendum on `thing` against a closer of `id`'s epoch lists it.
    fn vouched(&self, id: &u32, thing: &T) -> bool {
        let Some(c) = self.commits.get(id).filter(|c| c.things.contains(thing)) else { return false };
        let EpochStanding::Closed(closers) = self.e.standing(c) else { return false };
        self.addenda.iter().any(|a| a.thing == *thing && a.commits.contains(id) && closers.contains(&a.against))
    }
    /// Whether a delta of `id` on `thing` passes the epoch rule; `plain`: a plain-content delta.
    fn delta_counts(&self, id: &u32, thing: &T, plain: bool) -> bool {
        self.counts(id) || plain && self.vouched(id, thing)
    }
}

type Parts<'a> = (&'a [ThingList<u32, u32>], &'a [Listing<u32, u32>], &'a [RotationAddendum<u32>]);

/// Rotations received in ID order.
fn judge(rots: &[Rotation<u32>], commits: &[AccountCommit<u32, u32>], parts: Parts) -> Judged<u32> {
    let mut received: Vec<u32> = rots.iter().map(|r| r.id).collect();
    received.sort();
    judge_as(rots, &received, commits, parts)
}

fn judge_as(rots: &[Rotation<u32>], received: &[u32], commits: &[AccountCommit<u32, u32>], (l, g, a): Parts) -> Judged<u32> {
    Judged::new(Epochs::new(0, rots.to_vec(), None, received, l, g), commits.to_vec(), a.to_vec())
}

/// The rotator received X's write (100) and lists it; X's later write at the old epoch (101)
/// counts nowhere once the rotation is held, whatever its stamp.
#[test]
fn rotator_received_write_counts_later_write_does_not() {
    let commits = [c(100, 0), c(101, 0)];
    let e = judge(&[rot(1, 0, &[0], &[])], &commits, (&[list(1, &[100])], &[], &[]));
    assert!(e.counts(&100) && !e.counts(&101));
    let before = judge(&[], &commits, (&[], &[], &[]));
    assert!(before.counts(&100) && before.counts(&101), "without the rotation the epoch is open");
}

/// A witness received X's write (100) in time and the rotator did not: its addendum against
/// the rotation saves the plain delta on its thing, nothing else.
#[test]
fn write_only_a_witness_received_counts() {
    let mut on_two = c(100, 0);
    on_two.things.insert(1);
    let e = judge(&[rot(1, 0, &[0], &[])], &[on_two, c(101, 0)], (&[list(1, &[])], &[], &[addendum(1, &[100])]));
    assert!(e.delta_counts(&100, &0, true) && !e.counts(&100));
    assert!(!e.delta_counts(&100, &0, false), "an addendum saves plain content only");
    assert!(!e.delta_counts(&100, &1, true), "an addendum speaks for its own thing");
    assert!(!e.delta_counts(&101, &0, true));
    // Against a rotation that does not close the epoch (101 at epoch 1, which descends from it)
    // or one that is not held, it says nothing.
    let e = judge(&[rot(1, 0, &[0], &[]), rot(2, 1, &[1], &[])], &[c(101, 1)], (&[], &[], &[addendum(1, &[101]), addendum(7, &[101])]));
    assert!(!e.vouched(&101, &0) && !e.counts(&101));
}

/// Node 2 rotates (1) before X's removal (2) reaches it, boxing X epoch 1. X's later write at
/// its old epoch (100) and at the sibling's (101) both fall where the removal's line is
/// followed: the removal closes the sibling's epoch, and node 0's merge (4, signed at 1) closes
/// both again; X's fork (3) counts only in the window before the merge, as the sibling's line
/// does at a reader that follows it.
#[test]
fn later_write_does_not_count_at_its_old_epoch_or_a_siblings() {
    let commits = [c(100, 0), c(101, 1), c(102, 3)];
    let rots = [rot(1, 0, &[0], &[]), rot(2, 0, &[0], &[]), rot(3, 1, &[1, 2], &[]), rot(4, 2, &[1, 2, 3], &[1])];
    let e = judge_as(&rots[..2], &[2, 1], &commits, (&[list(1, &[]), list(2, &[])], &[], &[]));
    assert!(!e.counts(&100) && !e.counts(&101), "the removal closes the sibling's epoch");
    let e = judge_as(&rots[..2], &[1, 2], &commits, (&[list(1, &[]), list(2, &[])], &[], &[]));
    assert!(!e.counts(&100) && e.counts(&101), "the fork window at a reader the sibling's rotation reached first");
    let window = judge(&rots[..3], &commits, (&[list(3, &[101])], &[], &[]));
    assert!(window.counts(&101) && window.counts(&102), "the fork window: X's fork rejects the removal");
    let merged = judge(&rots, &commits, (&[list(3, &[101]), list(4, &[])], &[], &[]));
    assert!(merged.chain().counts(&4) && !merged.chain().counts(&3));
    assert!(!merged.counts(&100) && !merged.counts(&101) && !merged.counts(&102));
}

/// Node 2's write at the closed epoch (100), which the rotator never received, counts once
/// node 2's listing at the open epoch (200) names it.
#[test]
fn siblings_listing_revives_its_offline_write() {
    let rots = [rot(1, 0, &[0], &[])];
    let commits = [c(100, 0), c(200, 1)];
    assert!(!judge(&rots, &commits, (&[list(1, &[])], &[], &[])).counts(&100));
    let e = judge(&rots, &commits, (&[list(1, &[])], &[listing_at(200, 1, &[100])], &[]));
    assert!(e.counts(&200) && e.counts(&100));
}

/// Y's listing at epoch 1 (200) names Y's write (100); Y's removal closes epoch 1. The listing
/// speaks only once the second rotation's list names it, and its word falls with it.
#[test]
fn listing_at_a_closed_epoch_counts_once_listed() {
    let rots = [rot(1, 0, &[0], &[]), rot(2, 1, &[1], &[])];
    let commits = [c(100, 0), c(200, 1)];
    let listed = judge(&rots, &commits, (&[list(1, &[]), list(2, &[200])], &[listing_at(200, 1, &[100])], &[]));
    assert!(listed.counts(&200) && listed.counts(&100));
    let unlisted = judge(&rots, &commits, (&[list(1, &[])], &[listing_at(200, 1, &[100])], &[]));
    assert!(!unlisted.counts(&200) && !unlisted.counts(&100));
    // Listings chained through closed epochs count by the least fixpoint, never by themselves.
    let chained = judge(&rots, &[c(100, 0), c(200, 1), c(201, 1)], (&[], &[listing_at(200, 1, &[201]), listing_at(201, 1, &[200, 100])], &[]));
    assert!(!chained.counts(&200) && !chained.counts(&201) && !chained.counts(&100));
}

/// A word on one thing speaks only of commits on it: thing 1's list naming a commit on thing 2
/// saves nothing; the commit's own thing's list saves it whole, its other things' deltas too.
#[test]
fn thing_list_names_only_commits_on_its_thing() {
    let rots = [rot(1, 0, &[0], &[])];
    let on = |id: u32, things: &[u32]| AccountCommit { id, epoch: 0, things: set(things) };
    let wrong = ThingList { rotation: 1, thing: 1, commits: set(&[100]) };
    let right = ThingList { rotation: 1, thing: 1, commits: set(&[101]) };
    let e = judge(&rots, &[on(100, &[2]), on(101, &[1, 2])], (&[wrong, right], &[], &[]));
    assert!(!e.counts(&100) && e.counts(&101) && e.delta_counts(&101, &2, false));
}

/// The removal commit (100, on the devices actor, thing 9) counts wherever its rotation does:
/// the rotation's list for the devices actor names it.
#[test]
fn removal_commit_counts_through_its_rotation() {
    let removal = AccountCommit { id: 100, epoch: 0, things: set(&[9]) };
    let e = judge(&[rot(1, 0, &[0], &[])], std::slice::from_ref(&removal), (&[ThingList { rotation: 1, thing: 9, commits: set(&[100]) }], &[], &[]));
    assert!(e.counts(&100));
    assert!(judge(&[], &[removal], (&[], &[], &[])).counts(&100), "alone it closes nothing");
}

/// Covered commits are listed (spec/permissions.md §5.5): the rotator's list names a commit a
/// snapshot it holds covers, so the write counts on its own once that snapshot falls.
#[test]
fn covered_commits_are_listed() {
    let covered = set(&[101]);
    let (l, over) = fit_list(&covered, &[100], list_bytes(2)).unwrap();
    assert_eq!((l.clone(), over), (set(&[100, 101]), vec![]));
    let e = judge(&[rot(1, 0, &[0], &[])], &[c(100, 0), c(101, 0)], (&[ThingList { rotation: 1, thing: 0, commits: l }], &[], &[]));
    assert!(e.counts(&101));
}

/// A commit at an epoch whose minting rotation, or that rotation's chain, is not held is pending;
/// a rotation whose chain is not held takes part in nothing (it closes nothing, lists nothing).
#[test]
fn commit_at_an_unheld_epoch_is_pending_and_an_unrooted_rotation_closes_nothing() {
    let commits = [c(100, 2), c(101, 0)];
    // 2 is signed at epoch 1, whose rotation is not held.
    let e = judge(&[rot(2, 1, &[1, 0], &[])], &commits, (&[list(2, &[101])], &[], &[]));
    assert!(e.pending(&100) && !e.counts(&100) && !e.chain().holds(&2));
    assert!(e.counts(&101) && e.chain().open(&0), "the unrooted rotation closes nothing");
    let e = judge(&[rot(1, 0, &[0], &[]), rot(2, 1, &[1], &[])], &commits, (&[], &[], &[]));
    assert!(!e.pending(&100) && e.counts(&100) && !e.counts(&101));
}

/// A thing list's path folds to its rotation's list root; a wrong path, index or leaf is bad
/// input.
#[test]
fn list_path_checks_and_a_wrong_path_is_bad_input() {
    let mut n = 0u8;
    let fresh = || {
        n = n.wrapping_add(1);
        [n; 32]
    };
    let leaves = [(5u64, list_leaf(b"a")), (6, list_leaf(b"b")), (u64::from(u32::MAX), list_leaf(b"c"))];
    let (root, paths) = list_tree(&leaves, fresh).unwrap();
    for (p, l) in paths.iter().zip(&leaves) {
        assert_eq!(p.siblings.len(), 32);
        assert!(p.verify(l.1, &root));
    }
    let p = &paths[0];
    assert!(!p.verify(list_leaf(b"b"), &root), "another list");
    assert!(!ListPath { index: 4, ..p.clone() }.verify(leaves[0].1, &root), "another index");
    let mut wrong = p.clone();
    wrong.siblings[31][0] ^= 1;
    assert!(!wrong.verify(leaves[0].1, &root), "a wrong sibling");
    assert!(!ListPath { index: p.index, siblings: p.siblings[..31].to_vec() }.verify(leaves[0].1, &root), "a short path");
    assert!(ListPath { index: 1 << 32, siblings: p.siblings.clone() }.root(leaves[0].1).is_none(), "past the tree");
    assert!(list_tree(&[(1, [0; 32]), (1, [1; 32])], || [0; 32]).is_none(), "two leaves at one index");
    assert!(list_tree(&[(1 << 32, [0; 32])], || [0; 32]).is_none(), "an index past the tree");
}

/// Bound (spec/permissions.md §5.5): plain content received last goes past it into later
/// listings; role-class and purge commits alone past it refuse the rotation.
#[test]
fn role_part_over_the_bound_is_refused() {
    let special = set(&[1, 2]);
    let (l, over) = fit_list(&special, &[10, 11, 12], list_bytes(3)).unwrap();
    assert_eq!((l, over), (set(&[1, 2, 10]), vec![11, 12]));
    assert_eq!(fit_list(&special, &[10], list_bytes(2)), Some((special.clone(), vec![10])));
    assert_eq!(fit_list(&special, &[], list_bytes(1)), None, "the special commits alone pass it");
    assert_eq!(list_bytes(1), osis_base::encode(&osis_base::Value::List(vec![osis_base::Value::bytes(&[0; 32])])).len());
    assert_eq!(list_bytes(30), osis_base::encode(&osis_base::Value::List(vec![osis_base::Value::bytes(&[0; 32]); 30])).len());
}

// Differential against roles-model `epochs`.

/// The devices actor's thing, where removal commits sit.
const D: usize = usize::MAX;

/// Perm's ID of model item `i`: a rotation's is the epoch it mints, others' 1000 past the item ID.
fn pid(w: &World, i: usize) -> u32 {
    match &w.items[i].kind {
        Kind::Rotation { new, .. } => *new,
        _ => 1000 + w.items[i].id,
    }
}

fn pid_of(w: &World, id: u32) -> u32 {
    let i = id as usize - 1;
    if i < w.items.len() { pid(w, i) } else { 1000 + id }
}

/// Perm's verdict on the model's held set under `side` (a model item index), observer `o`'s
/// receipt order.
fn perm_epochs(w: &World, o: usize, held: &[bool], side: Option<usize>) -> Judged<usize> {
    let mut rots = Vec::new();
    let mut commits = Vec::new();
    let mut lists = Vec::new();
    let mut listings = Vec::new();
    let mut addenda = Vec::new();
    let ids = |v: &[u32]| -> BTreeSet<u32> { v.iter().map(|&id| pid_of(w, id)).collect() };
    for (i, it) in w.items.iter().enumerate() {
        if !held[i] {
            continue;
        }
        match &it.kind {
            Kind::Rotation { at, new, supersedes, names, removes } => {
                // A name accepts a fork only when the merge is signed at its epoch (the model's
                // merges always are).
                let names: BTreeSet<u32> = names.iter().map(|&id| pid_of(w, id)).collect();
                rots.push(Rotation { id: *new, at: *at, supersedes: supersedes.iter().copied().collect(), signed: names.clone(), names });
                if let Some(rm) = removes {
                    lists.push(ThingList { rotation: *new, thing: D, commits: ids(&[*rm]) });
                }
            }
            // A list past the bound does not decode (bad input), so never reaches judgment.
            Kind::List { rot, thing, lists: l } if w.bound.is_none_or(|b| l.len() <= b) => lists.push(ThingList { rotation: pid_of(w, *rot), thing: *thing, commits: ids(l) }),
            Kind::Addendum { against, thing, lists: l } if w.writer[it.author] == Some(*thing) => addenda.push(RotationAddendum { thing: *thing, against: pid_of(w, *against), commits: ids(l) }),
            _ => {}
        }
        if let (Some(e), false) = (it.epoch, matches!(it.kind, Kind::Rotation { .. })) {
            let thing = it.kind.thing().unwrap_or(D);
            let c = AccountCommit { id: pid(w, i), epoch: e, things: [thing].into() };
            if let Kind::Listing { thing, lists: l, .. } = &it.kind {
                listings.push(Listing { listing: c.clone(), thing: *thing, commits: ids(l) });
            }
            commits.push(c);
        }
    }
    let mut received: Vec<usize> = (0..w.items.len()).filter(|&i| held[i] && matches!(w.items[i].kind, Kind::Rotation { .. })).collect();
    received.sort_by_key(|&i| (w.items[i].recv[o], w.items[i].id));
    let received: Vec<u32> = received.into_iter().map(|i| pid(w, i)).collect();
    Judged::new(Epochs::new(0, rots, side.map(|s| pid(w, s)), &received, &lists, &listings), commits, addenda)
}

/// The first difference between the model's verdict `v` (`judge_at`) and perm at observer `o`
/// holding `held`.
fn epochs_diff(w: &World, o: usize, held: &[bool], v: &Verdict) -> Option<String> {
    let side = v.side;
    // P's nodes are given their roster's side (the devices actor's line); without one, or for
    // anyone else, perm takes its default from the receipt order.
    let e = perm_epochs(w, o, held, w.roster_side(o, held));
    // Which rotations take part (held with their chain): the disputes, the side, the head
    // followed.
    let parties: BTreeSet<u32> = v.parties.iter().map(|&i| pid(w, i)).collect();
    if *e.chain().parties() != parties {
        return Some(format!("observer n{o}: parties model {parties:?}, perm {:?}", e.chain().parties()));
    }
    if e.chain().side() != side.map(|s| pid(w, s)) {
        return Some(format!("observer n{o}: side model {side:?}, perm {:?}", e.chain().side()));
    }
    if e.chain().followed() != v.followed.map_or(0, |f| pid(w, f)) {
        return Some(format!("observer n{o}: followed model {:?}, perm {:?}", v.followed, e.chain().followed()));
    }
    if e.chain().in_doubt() != w.in_doubt(held, v) {
        return Some(format!("observer n{o}: in doubt model {}, perm {}", w.in_doubt(held, v), e.chain().in_doubt()));
    }
    let rooted = w.rooted(held);
    let minted = |ep: u32| ep == 0 || (0..w.items.len()).any(|r| rooted[r] && matches!(w.items[r].kind, Kind::Rotation { new, .. } if new == ep));
    for (i, it) in w.items.iter().enumerate() {
        if !held[i] {
            continue;
        }
        let (m, p) = match &it.kind {
            Kind::Rotation { new, .. } if rooted[i] != e.chain().holds(new) => (rooted[i], e.chain().holds(new)),
            Kind::Rotation { new, .. } => (v.counting[i], e.chain().counts(new)),
            _ if it.epoch.is_some_and(|ep| minted(ep) == e.pending(&pid(w, i))) => (!minted(it.epoch.unwrap_or(0)), e.pending(&pid(w, i))),
            _ if it.epoch.is_some() => (v.as_p[i], e.delta_counts(&pid(w, i), &it.kind.thing().unwrap_or(D), matches!(it.kind, Kind::Content { plain: true, .. }))),
            _ => continue,
        };
        if m != p {
            return Some(format!("observer n{o}, item #{} {:?} at {:?}: model {m}, perm {p}", it.id, it.kind, it.epoch));
        }
    }
    None
}

fn epochs_run(samples: u64, seed: u64) {
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    let (mut checked, mut closed_named, mut unrooted) = (0u64, 0u64, 0u64);
    for s in 0..samples {
        let w = model::random_world(&mut rng);
        // Every observer at every receipt time.
        let mut times: Vec<u32> = w.items.iter().flat_map(|i| i.recv.iter().copied()).filter(|&t| t < roles_model::shrink::LATE).collect();
        times.sort_unstable();
        times.dedup();
        for o in 0..w.nodes {
            let mut last: Option<Vec<bool>> = None;
            for &t in &times {
                let held = w.held_at(o, t);
                // what is checked is a function of the world, the observer and its held set: a
                // time that brought this observer nothing checks nothing new
                if last.as_ref() == Some(&held) {
                    continue;
                }
                checked += 1;
                unrooted += u64::from(w.rooted(&held) != held);
                let v = w.judge_at(o, &held);
                if let Some(d) = epochs_diff(&w, o, &held, &v) {
                    panic!("seed {seed:#x} sample {s}: {d}\n{w:?}");
                }
                closed_named += w.items.iter().enumerate().filter(|(i, it)| v.as_p[*i] && it.epoch.is_some_and(|e| v.closed.contains(&e)) && !matches!(it.kind, Kind::Rotation { .. })).count() as u64;
                last = Some(held);
            }
        }
    }
    eprintln!("epochs model: {samples} worlds, {checked} observer-prefixes ({unrooted} holding a rotation without its chain), {closed_named} closed-epoch commits counting");
    assert!(closed_named > 0, "the run reaches commits named at a closed epoch");
    assert!(unrooted > 0, "the run reaches rotations held without their chain");
}

/// spec/permissions.md §5.4, Side: a node of P whose roster authorizes no held rotation (here
/// only removed nodes X and Y rotated) takes a dispute's preferred party, as anyone else does.
/// X and Y fork from the root (1, 2) and each merges the other out (3, 4); node 3 received Y's
/// line first.
#[test]
fn node_of_p_without_a_roster_line_takes_the_preferred_party() {
    let mut w = World::shape(4, vec![vec![0]], vec![vec![0]; 4], vec![None; 4], None, None, false);
    w.left = vec![roles_model::shrink::LATE, 0, 0, roles_model::shrink::LATE];
    for (id, author, at, new, t, seen) in [(1, 1, 0, 1, 1, 3), (2, 2, 0, 2, 1, 1), (3, 1, 1, 3, 2, 4), (4, 2, 2, 4, 2, 2)] {
        let mut recv = vec![roles_model::shrink::LATE; 4];
        recv[1] = t;
        recv[2] = t;
        recv[3] = seen;
        let kind = Kind::Rotation { at, new, supersedes: if at == 0 { vec![0] } else { vec![1, 2] }, names: vec![], removes: None };
        w.items.push(model::Item { id, kind, author, epoch: Some(at), t, ts: t, recv, hostile: true });
    }
    let all = vec![true; 4];
    assert_eq!(w.parties(&all), vec![2, 3]);
    assert_eq!((w.roster_side(3, &all), w.default_side(3, &all)), (None, Some(3)));
    assert_eq!(perm_epochs(&w, 3, &all, None).chain().side(), Some(4));
    assert_eq!(epochs_diff(&w, 3, &all, &w.judge_at(3, &all)), None);
}

/// spec/permissions.md §5.4-§5.5: the epoch rule agrees with core/test/roles-model `epochs` at
/// every observer and receipt prefix.
#[test]
fn epochs_model_agrees() {
    epochs_run(300, 0x5eed_0e00);
}

/// spec/permissions.md §5.5: as above, more samples (a property).
#[test]
#[ignore]
fn epochs_model_agrees_large() {
    crate::common::sharded(300_000, 0x5eed_0e01, epochs_run);
}
