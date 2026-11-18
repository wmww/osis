//! The epoch rule (spec/permissions.md §5.5): a commit at a closed epoch counts iff a counting
//! rotation's thing list names it, a counting listing names it, or a counting addendum vouches
//! for it (here: every addendum given counts; their own fixpoint is `Timeline::vouching`'s). Hand
//! worlds on synthetic commits (a rotation's ID is the epoch it mints, the root 0; commits 100 and
//! up; X is the removed node), then a differential against core/test/roles-model `epochs`, chain
//! (roles-model `custody`) and layer 2 alike, at every observer and receipt prefix of every world.
#![allow(clippy::needless_range_loop)]

use crate::common::seeded;
use osis_perm::epochs::{fit_list, list_bytes, list_leaf, list_tree};
use osis_perm::{AccountCommit, Devices, EpochStanding, Epochs, ListPath, Listing, Rotation, ThingList};
use std::collections::BTreeMap;
use roles_model::custody::{self as cu, Line, NEVER, OWN, Z};
use roles_model::epochs::{self as model, Kind, World};
use roles_model::Rng;
use std::collections::BTreeSet;

fn set(v: &[u32]) -> BTreeSet<u32> {
    v.iter().copied().collect()
}

fn rot(id: u32, at: u32, sup: &[u32], names: &[u32]) -> Rotation<u32> {
    Rotation { id, at, supersedes: set(sup), names: set(names), takes: BTreeSet::new() }
}

/// Commit `id` at `epoch` on thing 0.
fn c(id: u32, epoch: u32) -> AccountCommit<u32, u32> {
    AccountCommit { id, epoch, things: set(&[0]), role: true }
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
        if self.e.standing(c) != EpochStanding::Closed {
            return false;
        }
        self.addenda.iter().any(|a| a.thing == *thing && a.commits.contains(id) && self.e.closes(&a.against, id, &c.epoch))
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

/// Every rotation carries a removal (each revokes the epochs it closes) unless `carriers` says
/// which do.
fn judge_as(rots: &[Rotation<u32>], received: &[u32], commits: &[AccountCommit<u32, u32>], parts: Parts) -> Judged<u32> {
    judge_carrying(rots, &rots.iter().map(|r| r.id).collect(), received, commits, parts)
}

fn judge_carrying(rots: &[Rotation<u32>], carriers: &BTreeSet<u32>, received: &[u32], commits: &[AccountCommit<u32, u32>], (l, g, a): Parts) -> Judged<u32> {
    Judged::new(Epochs::new::<u32>(0, rots.to_vec(), None, received, None, carriers, l, g), commits.to_vec(), a.to_vec())
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
/// its old epoch (100) falls with the removal; at the sibling's (101) it counts where the
/// sibling's rotation was held first, until P's merge of 1 and 2 (4) and a rotation answering X's
/// fork (5, at 4); X's fork (3) counts only where it came before them.
#[test]
fn later_write_does_not_count_at_its_old_epoch_or_a_siblings() {
    let commits = [c(100, 0), c(101, 1), c(102, 3)];
    let rots = [rot(1, 0, &[0], &[]), rot(2, 0, &[0], &[]), rot(3, 1, &[1, 2], &[]), rot(4, 2, &[1, 2], &[1]), rot(5, 4, &[4, 3], &[])];
    for (received, sibling) in [([2, 1], false), ([1, 2], true)] {
        let e = judge_as(&rots[..2], &received, &commits, (&[list(1, &[]), list(2, &[])], &[], &[]));
        assert!(!e.counts(&100) && e.counts(&101) == sibling, "the sibling's epoch is open where it was held first");
    }
    let window = judge(&rots[..3], &commits, (&[list(3, &[101])], &[], &[]));
    assert!(window.counts(&101) && window.counts(&102), "the fork window: X's fork rejects the removal");
    let parts = [list(3, &[101]), list(5, &[])];
    let merged = judge_as(&rots, &[1, 2, 4, 5, 3], &commits, (&parts, &[], &[]));
    assert!(merged.chain().counts(&4) && merged.chain().counts(&5) && !merged.chain().counts(&3));
    assert!(!merged.counts(&100) && !merged.counts(&101) && !merged.counts(&102));
    // held after X's fork, the merge is beside the line followed: told, staying
    let late = judge(&rots, &commits, (&parts, &[], &[]));
    assert!(late.chain().counts(&3) && !late.chain().counts(&4) && !late.chain().counts(&5) && late.chain().warning());
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
    let on = |id: u32, things: &[u32]| AccountCommit { id, epoch: 0, things: set(things), role: false };
    let wrong = ThingList { rotation: 1, thing: 1, commits: set(&[100]) };
    let right = ThingList { rotation: 1, thing: 1, commits: set(&[101]) };
    let e = judge(&rots, &[on(100, &[2]), on(101, &[1, 2])], (&[wrong, right], &[], &[]));
    assert!(!e.counts(&100) && e.counts(&101) && e.delta_counts(&101, &2, false));
}

/// The removal commit (100, on the account root, thing 9) counts wherever its rotation does:
/// the rotation's list for the account root names it.
#[test]
fn removal_commit_counts_through_its_rotation() {
    let removal = AccountCommit { id: 100, epoch: 0, things: set(&[9]), role: true };
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

// Differential against roles-model `epochs` (its chain is roles-model `custody`'s).

/// Perm's IDs: a plain rotation's is its custody item ID; a merge epoch's `MERGE` past its place
/// among the world's merge epochs (the model's ties, `model::MERGE_TIE`); a layer-2 item's `COMMIT` past its ID.
const MERGE: u32 = 100_000;
const COMMIT: u32 = 1_000_000;

/// Perm's ID of epoch `e`.
fn eid(w: &World, e: &Line) -> u32 {
    if e.is_empty() {
        0
    } else if w.c.single(e) {
        w.c.tips(e)[0]
    } else {
        MERGE + (w.c.merge_tie[e] - model::MERGE_TIE) as u32
    }
}

/// Perm's ID of what custody item `q` (a rotation or certificate) mints.
fn minted(w: &World, q: u32) -> u32 {
    eid(w, &w.c.mints(q))
}

/// Perm's judgment at observer `v` at `t`.
fn perm_epochs(w: &World, v: usize, t: u32) -> Judged<usize> {
    let c = &w.c;
    let j = w.view(v, t);
    let now = t.min(w.end);
    let held: Vec<&cu::Item> = c.items.iter().filter(|i| i.recv[v] <= now).collect();
    let mut rots = Vec::new();
    let mut received: Vec<(u32, u32)> = Vec::new();
    let mut carriers = BTreeSet::new();
    let mut d = Devices { first: (0..OWN).collect(), ..Devices::default() };
    let mut certs: BTreeMap<Line, (u32, BTreeSet<usize>)> = BTreeMap::new();
    for i in &held {
        let opens = j.signers.get(&i.id).copied().flatten();
        match &i.kind {
            cu::Kind::Plain { at, removes, adds, takes, answers } => {
                let at = eid(w, at);
                let supersedes = std::iter::once(at).chain(answers.iter().map(|q| minted(w, *q))).collect();
                rots.push(Rotation { id: i.id, at, supersedes, names: BTreeSet::new(), takes: takes.iter().copied().collect() });
                received.push((i.recv[v], i.id));
                if !removes.is_empty() {
                    carriers.insert(i.id);
                }
                if let Some(m) = opens {
                    d.minter.insert(i.id, m);
                    if !removes.is_empty() {
                        d.removes.insert(i.id, removes.iter().copied().collect());
                    }
                    if !adds.is_empty() {
                        d.adds.insert(i.id, adds.iter().copied().collect());
                    }
                }
            }
            cu::Kind::Cert { .. } => {
                let e = c.mints(i.id);
                let x = certs.entry(e).or_insert((NEVER, BTreeSet::new()));
                x.0 = x.0.min(i.recv[v]);
                x.1.extend(opens);
            }
            _ => {}
        }
    }
    for (e, (at, by)) in certs {
        let id = eid(w, &e);
        let tips: BTreeSet<u32> = c.tips(&e).into_iter().collect();
        let first = *tips.first().unwrap();
        rots.push(Rotation { id, at: first, supersedes: tips.clone(), names: tips.iter().copied().filter(|x| *x != first).collect(), takes: BTreeSet::new() });
        received.push((at, id));
        d.certifiers.insert(id, by);
    }
    received.sort();
    let received: Vec<u32> = received.into_iter().map(|r| r.1).collect();
    let cid = |id: u32| COMMIT + id;
    let l2 = w.held(v, t);
    let (mut commits, mut lists, mut listings, mut addenda) = (vec![], vec![], vec![], vec![]);
    for i in w.items.iter().filter(|i| l2[i.id as usize - 1]) {
        let ids_of = |v: &[u32]| -> BTreeSet<u32> { v.iter().map(|x| cid(*x)).collect() };
        let commit = AccountCommit { id: cid(i.id), epoch: eid(w, &i.epoch), things: [i.kind.thing()].into(), role: !i.kind.plain() };
        match &i.kind {
            Kind::Content { .. } | Kind::Cover { p: true, .. } => commits.push(commit),
            Kind::Listing { thing, names } => {
                listings.push(Listing { listing: commit.clone(), thing: *thing, commits: ids_of(names) });
                commits.push(commit);
            }
            // a list past the bound does not decode (bad input), so never reaches judgment
            Kind::List { rot, thing, names } if w.bound.is_none_or(|b| names.len() <= b) => lists.push(ThingList { rotation: *rot, thing: *thing, commits: ids_of(names) }),
            Kind::Addendum { against, thing, names } if w.writer[i.author] == Some(*thing) => addenda.push(RotationAddendum { thing: *thing, against: *against, commits: ids_of(names) }),
            _ => {}
        }
    }
    let chosen = j.chosen.map(|x| minted(w, x));
    let e = Epochs::new(0, rots, chosen, &received, (v < OWN).then_some(&d), &carriers, &lists, &listings);
    Judged::new(e, commits, addenda)
}

/// The first difference between the model and perm at observer `v` at `t`.
fn epochs_diff(w: &World, v: usize, t: u32) -> Option<String> {
    let c = &w.c;
    let j = w.view(v, t);
    let e = perm_epochs(w, v, t);
    let ch = e.chain();
    let at = |what: &str, m: String, p: String| Some(format!("observer {} at {t}: {what}: model {m}, perm {p}", cu::NAMES[v]));
    for i in c.items.iter().filter(|i| i.recv[v] <= t.min(w.end)) {
        let (m, p) = match &i.kind {
            cu::Kind::Plain { .. } => (j.chain.contains(&i.id).then(|| j.followed.contains(&i.id)), ch.holds(&i.id).then(|| ch.counts(&i.id))),
            cu::Kind::Cert { .. } => {
                let mint = c.mints(i.id);
                let id = eid(w, &mint);
                (j.merges.contains(&mint).then(|| j.counting.contains(&mint)), ch.holds(&id).then(|| ch.counts(&id)))
            }
            _ => continue,
        };
        if m != p {
            return at(&format!("#{} {:?} (held with chain: counts)", i.id, i.kind), format!("{m:?}"), format!("{p:?}"));
        }
    }
    let heads: BTreeSet<u32> = j.heads.iter().map(|h| eid(w, h)).collect();
    if heads != *ch.heads() {
        return at("heads", format!("{heads:?}"), format!("{:?}", ch.heads()));
    }
    if eid(w, &j.preferred) != ch.preferred() {
        return at("preferred", format!("{:?}", j.preferred), format!("{}", ch.preferred()));
    }
    if j.warning != ch.warning() {
        return at("warning", format!("{}", j.warning), format!("{}", ch.warning()));
    }
    if v < OWN && j.taken != ch.taken() {
        return at("taken", format!("{:?}", j.taken), format!("{:?}", ch.taken()));
    }
    let held = w.held(v, t);
    let vd = model::judge(w, j, &held);
    for i in w.items.iter().filter(|i| held[i.id as usize - 1] && i.kind.is_commit()) {
        let (k, id) = (i.id as usize - 1, COMMIT + i.id);
        if vd.pending[k] != e.pending(&id) {
            return at(&format!("l{} {:?} at {:?} pending", i.id, i.kind, i.epoch), format!("{}", vd.pending[k]), format!("{}", e.pending(&id)));
        }
        let p = e.delta_counts(&id, &i.kind.thing(), i.kind.plain());
        if vd.saved[k] != p {
            return at(&format!("l{} {:?} by {} at {:?} counts", i.id, i.kind, cu::NAMES[i.author], i.epoch), format!("{}", vd.saved[k]), format!("{p}"));
        }
    }
    None
}

fn epochs_run(samples: u64, seed: u64) {
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    let (mut checked, mut closed_named, mut unrooted) = (0u64, 0u64, 0u64);
    for s in 0..samples {
        let w = model::random_world(&mut rng, model::Control::None);
        // every observer at every tick its held set or its user's choice moves
        for v in (0..cu::N).filter(|v| *v != Z) {
            for t in 0..=model::fin(&w) {
                let moved = t == 0 || w.c.items.iter().any(|i| i.recv[v] == t) || w.items.iter().any(|i| i.recv[v] == t) || w.c.switches.iter().any(|x| x.0 == v && x.1 == t);
                if !moved {
                    continue;
                }
                checked += 1;
                let j = w.view(v, t);
                unrooted += u64::from(w.c.items.iter().any(|i| i.recv[v] <= t && w.c.seedy(i.id) && !j.chain.contains(&i.id)));
                if let Some(d) = epochs_diff(&w, v, t) {
                    model::print_world(&w);
                    panic!("seed {seed:#x} sample {s}: {d}");
                }
                let vd = model::judge(&w, j, &w.held(v, t));
                let ep_revoked = |e: &Line| j.followed.iter().any(|q| !e.contains(q) && !w.c.removes(*q).is_empty());
                closed_named += w.items.iter().filter(|i| vd.counts[i.id as usize - 1] && !j.heads.contains(&i.epoch) && ep_revoked(&i.epoch)).count() as u64;
            }
        }
    }
    eprintln!("epochs model: {samples} worlds, every one checked: {checked} observer-prefixes ({unrooted} holding a rotation without its chain), {closed_named} revoked-epoch commits counting");
    assert!(closed_named > 0, "the run reaches commits named at a revoked epoch");
    assert!(unrooted > 0, "the run reaches rotations held without their chain");
}

/// spec/permissions.md §5.4-§5.5: the chain and the epoch rule agree with core/test/roles-model
/// `epochs` at every observer and receipt prefix of every world.
#[test]
fn epochs_model_agrees() {
    epochs_run(20, 0);
}

/// spec/permissions.md §5.4-§5.5: as above, more samples (a property).
#[test]
#[ignore]
fn epochs_model_agrees_large() {
    crate::common::sharded(2_000, 0x5eed_0e01, epochs_run);
}

