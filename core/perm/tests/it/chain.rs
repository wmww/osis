//! An account's signing chain (spec/crypto.md §9, spec/permissions.md §5.4): what a node
//! follows is a function of the held rotations, the order it came to hold them, its user's
//! choice and (at a node of the account) what its devices list says. Hand worlds of
//! core/test/roles-model `forks`; a rotation's ID is the epoch it mints, the root 0.

use osis_perm::{Chain, Devices, Rotation};
use roles_model::forks;
use std::collections::BTreeSet;

fn set(v: &[u32]) -> BTreeSet<u32> {
    v.iter().copied().collect()
}

/// Rotation `id` signed at `at`, superseding `sup`, naming `names` each with its signature.
fn rot(id: u32, at: u32, sup: &[u32], names: &[u32]) -> Rotation<u32> {
    Rotation { id, at, supersedes: set(sup), names: set(names), signed: set(names), takes: BTreeSet::new() }
}

/// Outside the account, held in the order `received`, `chosen` its user's choice.
fn outside(rots: &[Rotation<u32>], chosen: Option<u32>, received: &[u32]) -> Chain<u32> {
    Chain::new::<char>(0, rots.to_vec(), chosen, received, None)
}

/// The commit creating D in `devices`, held before anything (`rec`).
const CREATED: u32 = 99;

/// `received` after the commit creating D.
fn rec(received: &[u32]) -> Vec<u32> {
    [&[CREATED], received].concat()
}

/// D at a node of the account: A, B, T, X and Y paired by its creating commit (`CREATED`);
/// `minted` (rotation, node), `removes` (rotation, node it removes; its frontier the creating
/// commit), `grants` (node, epoch) by A, each a commit 100 and up.
fn devices(minted: &[(u32, char)], removes: &[(u32, char)], grants: &[(char, u32)]) -> Devices<u32, char> {
    let mut d = Devices { minter: minted.iter().copied().collect(), first: "ABTXY".chars().map(|m| (CREATED, m)).collect(), ..Devices::default() };
    for (r, n) in removes {
        d.removes.entry(*r).or_insert_with(BTreeSet::new).insert(*n);
        d.covers.insert(*r, [CREATED].into());
    }
    for (i, (n, e)) in grants.iter().enumerate() {
        let g = 100 + i as u32;
        d.commits.insert(g, (Some('A'), *e));
        d.grants.insert((g, *n));
    }
    d
}

/// At a node of the account (`devices`).
fn own(rots: &[Rotation<u32>], received: &[u32], minted: &[(u32, char)], removes: &[(u32, char)], grants: &[(char, u32)]) -> Chain<u32> {
    Chain::new(0, rots.to_vec(), None, &rec(received), Some(&devices(minted, removes, grants)))
}

/// A's removal of X (1) and B's of Y (2), made at once at the root.
fn fork() -> Vec<Rotation<u32>> {
    vec![rot(1, 0, &[0], &[]), rot(2, 0, &[0], &[])]
}

#[test]
fn outside_the_account_the_first_fork_held_is_followed() {
    let c = outside(&fork(), None, &[1, 2]);
    assert!(c.counts(&1) && !c.counts(&2) && c.disregarded(&2) && !c.warning());
    assert!(c.open(&1) && !c.open(&2) && c.heads() == &set(&[1]));
    assert_eq!(c.closers(&2), vec![1]);
    let c = outside(&fork(), None, &[2, 1]);
    assert!(c.counts(&2) && !c.counts(&1));
    let c = outside(&fork(), Some(2), &[1, 2]);
    assert!(c.counts(&2) && !c.counts(&1), "the chosen line is placed first");
}

#[test]
fn a_node_of_the_account_follows_its_devices_rotations_made_at_once() {
    for received in [[1, 2], [2, 1]] {
        let c = own(&fork(), &received, &[(1, 'A'), (2, 'B')], &[(1, 'X'), (2, 'Y')], &[]);
        assert!(c.counts(&1) && c.counts(&2) && c.heads() == &set(&[1, 2]) && !c.warning());
        assert_eq!(c.preferred(), received[0], "it signs at the one it held first");
    }
}

/// A merge (3, at 1) naming B's rotation 2 brings it back wherever 1 or 2 was followed.
#[test]
fn a_merge_joins_a_fork_back() {
    let mut rots = fork();
    rots.push(rot(3, 1, &[1, 2], &[2]));
    for received in [[1, 2, 3], [2, 1, 3], [2, 3, 1]] {
        let c = outside(&rots, None, &received);
        assert!(c.counts(&1) && c.counts(&2) && c.counts(&3) && c.heads() == &set(&[3]) && !c.warning(), "{received:?}");
    }
    // a merge waits for every fork it names
    let c = outside(&[rots[0].clone(), rots[2].clone()], None, &[1, 3]);
    assert!(!c.holds(&3) && c.heads() == &set(&[1]));
    // a name without its signature accepts nothing: the merge is a plain sibling of 2
    rots[2].signed.clear();
    let c = outside(&rots, None, &[2, 1, 3]);
    assert!(c.counts(&2) && !c.counts(&3) && !c.line(&3).is_some_and(|l| l.contains(&2)));
}

/// A removes X (1); X forks from the root (2), A rejects it (3), X forks again (4), A rejects
/// that (5).
fn refork() -> Vec<Rotation<u32>> {
    vec![rot(1, 0, &[0], &[]), rot(2, 0, &[0], &[]), rot(3, 1, &[1, 2], &[]), rot(4, 0, &[0], &[]), rot(5, 3, &[3, 4], &[])]
}

#[test]
fn a_removed_devices_forks_never_count_where_its_removal_came_first() {
    let r = refork();
    let c = outside(&r[..4], None, &[1, 2, 3, 4]);
    assert!(c.counts(&3) && !c.counts(&2) && !c.counts(&4) && c.heads() == &set(&[3]));
    assert!(c.warning() && c.contested() == &set(&[2]), "told once A rejects a fork");
    let c = outside(&r, None, &[1, 2, 3, 4, 5]);
    assert!(c.counts(&5) && !c.counts(&4) && c.contested() == &set(&[2, 4]));
    let c = own(&r, &[1, 2, 3, 4, 5], &[(1, 'A'), (2, 'X'), (3, 'A'), (4, 'X'), (5, 'A')], &[(1, 'X')], &[]);
    assert!(c.counts(&5) && !c.counts(&2) && !c.counts(&4) && c.heads() == &set(&[5]) && c.warning());
}

#[test]
fn a_reader_that_held_the_thiefs_revocation_first_stays_with_it_and_is_told() {
    let r = refork();
    let c = outside(&r, None, &[4, 1, 2, 3, 5]);
    assert!(c.counts(&4) && !c.counts(&1) && !c.counts(&5) && c.heads() == &set(&[4]));
    assert!(c.warning() && c.contested() == &set(&[5]), "A's rejection of the fork it follows");
    let c = outside(&r, Some(5), &[4, 1, 2, 3, 5]);
    assert!(c.counts(&5) && !c.counts(&4) && c.warning(), "a switch holds");
    // at a node of the account a plain fork never outweighs its maker's removal; a fork
    // revoking A held first does
    let minted = [(1, 'A'), (2, 'X'), (3, 'A'), (4, 'X'), (5, 'A')];
    let c = own(&r, &[4, 1, 2, 3, 5], &minted, &[(1, 'X')], &[]);
    assert!(c.counts(&5) && !c.counts(&4) && c.warning());
    let c = own(&r, &[4, 1, 2, 3, 5], &minted, &[(1, 'X'), (4, 'A')], &[]);
    assert!(c.counts(&4) && !c.counts(&1) && !c.counts(&5) && c.warning());
}

/// X's merge (6, at 2, naming A's 3) carries in 3's rejection of 2: where 2 is followed, it
/// is disregarded, whatever it names.
#[test]
fn a_merge_carrying_a_rejection_of_the_followed_line_is_disregarded() {
    let mut r = refork()[..3].to_vec();
    r.push(rot(6, 2, &[2, 3], &[3]));
    let c = outside(&r, None, &[2, 1, 3, 6]);
    assert!(c.counts(&2) && !c.counts(&6) && !c.counts(&3));
}

#[test]
fn rotation_from_above_rejects_nothing() {
    // 5, signed at the root, supersedes 1, whose line runs through the root: a sibling
    let rots = vec![rot(1, 0, &[0], &[]), rot(5, 0, &[0, 1], &[])];
    let c = own(&rots, &[1, 5], &[(1, 'A'), (5, 'B')], &[], &[]);
    assert!(c.counts(&1) && c.counts(&5) && !c.warning());
}

#[test]
fn ill_formed_supersedes_entry_is_ignored() {
    // its own ancestors (1 and the root) and an epoch never minted
    let c = outside(&[rot(1, 0, &[0], &[]), rot(7, 1, &[1], &[]), rot(6, 7, &[7, 1, 0, 99], &[])], None, &[1, 7, 6]);
    assert!(c.counts(&1) && c.counts(&7) && c.counts(&6) && c.open(&6) && !c.warning());
}

/// X's rotation made before its removal at epoch 1 (2, on 1's line) stands; one beside it (3)
/// does not, until a grant at a followed epoch after the removal puts X back (at 4: X's 5 at 4).
#[test]
fn a_removal_revokes_only_what_its_node_made_beside_it() {
    let rots = vec![rot(1, 0, &[0], &[]), rot(2, 1, &[1], &[]), rot(4, 2, &[2], &[]), rot(3, 1, &[1], &[]), rot(5, 4, &[4], &[])];
    let minted = [(1, 'A'), (2, 'X'), (4, 'A'), (3, 'X'), (5, 'X')];
    let c = own(&rots, &[1, 2, 4, 3, 5], &minted, &[(4, 'X')], &[]);
    assert!(c.counts(&2) && c.counts(&4) && !c.counts(&3) && !c.counts(&5));
    let c = own(&rots, &[1, 2, 4, 3, 5], &minted, &[(4, 'X')], &[('X', 4)]);
    assert!(c.counts(&5) && !c.counts(&3), "re-added at 4: its rotation from 4 stands");
    let c = own(&rots, &[1, 2, 4, 3, 5], &minted, &[(4, 'X')], &[('X', 3)]);
    assert!(!c.counts(&5), "a grant at an epoch not followed puts no one back");
}

/// At a node of the account: B removes Z (1) and A removes B (2), at once. Held in that order,
/// B's revocation is taken first; A's would hit B's rotation, so it is not taken and its
/// rotation is disregarded, whatever else stands; held the other way, A's holds. A rotation
/// whose inner signature opens to no node (3) never stands, revoking no one.
#[test]
fn a_node_takes_the_revocation_it_held_first_and_never_follows_an_unminted_rotation() {
    let rots = vec![rot(1, 0, &[0], &[]), rot(2, 0, &[0], &[]), rot(3, 0, &[0], &[])];
    let minted = [(1, 'B'), (2, 'A')];
    let c = own(&rots[..2], &[1, 2], &minted, &[(1, 'Z'), (2, 'B')], &[]);
    assert!(c.counts(&1) && !c.counts(&2) && c.disregarded(&2));
    let c = own(&rots[..2], &[2, 1], &minted, &[(1, 'Z'), (2, 'B')], &[]);
    assert!(c.counts(&2) && !c.counts(&1));
    let c = own(&rots, &[3, 1, 2], &minted, &[], &[]);
    assert!(!c.counts(&3) && c.counts(&1) && c.counts(&2) && c.heads() == &set(&[1, 2]));
}

/// A removed node seals inner signatures as Z, a key actor it makes up, with its old epochs'
/// inner key (spec/permissions.md §5.4, Following, at a node of P).
/// A removes X at the root (1); Z forks at the root (2), revoking A or no one. X's grant of D
/// to Z (101) stands only when the removal's frontier covers it (X paired Z in plain sight, its
/// remover held it); else Z is no node and its fork stands by nothing. Z's fork counts as held
/// only once Z is known (the grant held), so a revocation held before then is placed after the
/// removal. X's commits on D the frontier does not cover, Z's, and one signed by no key actor
/// do not count (`cut`).
#[test]
fn a_key_actor_a_removed_node_makes_up_is_no_node() {
    let rots = vec![rot(1, 0, &[0], &[]), rot(2, 0, &[0], &[])];
    let world = |revokes: bool, covered: bool| {
        let mut d = devices(&[(1, 'A'), (2, 'Z')], &[(1, 'X')], &[]);
        if revokes {
            d.removes.insert(2, ['A'].into());
            d.covers.insert(2, [CREATED].into());
        }
        d.commits.insert(101, (Some('X'), 0));
        d.grants.insert((101, 'Z'));
        d.commits.insert(102, (Some('X'), 0));
        d.grants.insert((102, 'X'));
        d.commits.insert(103, (Some('Z'), 0));
        d.commits.insert(104, (None, 0));
        if covered {
            d.covers.insert(1, [CREATED, 101].into());
        }
        d
    };
    for received in [[2, 1, 101], [101, 1, 2]] {
        let c = Chain::new(0, rots.clone(), None, &rec(&received), Some(&world(true, false)));
        assert!(c.counts(&1) && !c.counts(&2), "{received:?}");
        assert!(c.cut(&101) && c.cut(&102) && c.cut(&103) && c.cut(&104), "{:?}", c.cuts());
    }
    for covered in [false, true] {
        let c = Chain::new(0, rots.clone(), None, &rec(&[1, 101, 2]), Some(&world(false, covered)));
        assert!(c.counts(&1) && c.counts(&2) == covered && c.cut(&101) != covered, "covered {covered}");
    }
}

/// X rotated before its removal (2) and A merges it in the rotation carrying the removal (3, at
/// A's 1, naming 2): 2 is on the removal's line, made before it, so the removal stands.
#[test]
fn a_removal_merging_its_targets_earlier_rotation_stands() {
    let rots = vec![rot(1, 0, &[0], &[]), rot(2, 0, &[0], &[]), rot(3, 1, &[1, 2], &[2])];
    let c = own(&rots, &[1, 2, 3], &[(1, 'A'), (2, 'X'), (3, 'A')], &[(3, 'X')], &[]);
    assert!(c.counts(&3) && c.counts(&2) && c.heads() == &set(&[3]));
}

/// X's self-grant (101) at B's rotation made unaware of X's removal (2, boxed to X) puts X
/// nowhere: a re-add is a grant by another node, and the removal's frontier does not cover it
/// (spec/permissions.md §5.4, Following, at a node of P). X's fork from 2 (3) stands nowhere.
#[test]
fn a_removed_nodes_grant_to_itself_is_no_readd() {
    let rots = vec![rot(1, 0, &[0], &[]), rot(2, 0, &[0], &[]), rot(3, 2, &[2], &[])];
    let mut d = devices(&[(1, 'A'), (2, 'B'), (3, 'X')], &[(1, 'X')], &[]);
    d.commits.insert(101, (Some('X'), 2));
    d.grants.insert((101, 'X'));
    let c = Chain::new(0, rots, None, &rec(&[1, 2, 101, 3]), Some(&d));
    assert!(c.counts(&1) && c.counts(&2) && !c.counts(&3) && c.cut(&101));
}

/// A rotates (1) and removes X (3, at 1); B rotated unaware (2) and took X's revocation of A (4)
/// first, so its next rotation (5, at 2, superseding only 2) takes 4. At A, holding 3 first, 5
/// stands with a revocation A does not take: that side, never counting beside 3, though nothing
/// on its line is X's (spec/permissions.md §5.4, Following, at a node of P). Read without what it
/// takes, 5 would be an honest fork at A, a head boxed to X. At B once its user chooses 3 the
/// same holds, so B's merge names its 2 alone. 5 is held only once 4 is, at every node.
#[test]
fn a_rotation_taking_a_revocation_not_taken_here_is_the_other_side() {
    let mut r5 = rot(5, 2, &[2], &[]);
    r5.takes = set(&[4]);
    let rots = vec![rot(1, 0, &[0], &[]), rot(2, 0, &[0], &[]), rot(3, 1, &[1], &[]), rot(4, 0, &[0], &[]), r5.clone()];
    let minted = [(1, 'A'), (2, 'B'), (3, 'A'), (4, 'X'), (5, 'B')];
    let d = devices(&minted, &[(3, 'X'), (4, 'A')], &[]);
    let a = Chain::new(0, rots.clone(), None, &rec(&[1, 3, 4, 2, 5]), Some(&d));
    assert!(a.counts(&3) && a.counts(&2) && !a.counts(&4) && !a.counts(&5) && a.heads() == &set(&[2, 3]), "A: heads {:?}", a.heads());
    let mut blind = rots.clone();
    blind[4].takes.clear();
    let a = Chain::new(0, blind, None, &rec(&[1, 3, 4, 2, 5]), Some(&d));
    assert!(a.counts(&5) && a.heads() == &set(&[3, 5]), "without what 5 takes: heads {:?}", a.heads());
    let early: Vec<Rotation<u32>> = rots.iter().filter(|r| r.id != 4).cloned().collect();
    let a = Chain::new(0, early, None, &rec(&[1, 3, 2, 5]), Some(&d));
    assert!(!a.holds(&5) && a.holds(&2), "5 waits for 4 at a node of P");
    let outside = Chain::new(0, rots.iter().filter(|r| r.id != 4).cloned(), None, &rec(&[1, 3, 2, 5]), None::<&Devices<u32, char>>);
    assert!(!outside.holds(&5), "5 waits for 4 outside P too");
    let b = Chain::new(0, rots.clone(), None, &rec(&[1, 2, 4, 5, 3]), Some(&d));
    assert!(b.counts(&4) && b.counts(&5) && !b.counts(&3), "B before its switch");
    let b = Chain::new(0, rots, Some(3), &rec(&[1, 2, 4, 5, 3]), Some(&d));
    assert!(b.counts(&3) && b.counts(&2) && !b.counts(&5) && b.heads() == &set(&[2, 3]), "B after: heads {:?}", b.heads());
}

/// `Chain` as node `v` of core/test/roles-model `forks` world `w` judges it at `now`, with the
/// model's choice `chosen`: the held rotations, the receipt order of rotations and D grants
/// (one tick's by ID), and at a node of P what D says (signers by inner signature, removals with
/// their frontiers, grants, the nodes paired before the world).
fn forks_chain(w: &forks::World, v: usize, now: u32, chosen: Option<u32>) -> Chain<u32> {
    let held: Vec<&forks::Item> = w.items.iter().filter(|i| i.recv[v] <= now).collect();
    let rots: Vec<Rotation<u32>> = held.iter().filter_map(|i| match &i.kind {
        forks::Kind::Rot { at, names, sup, takes, .. } => Some(Rotation { id: i.id, at: *at, supersedes: sup.iter().copied().collect(), names: names.iter().copied().collect(), signed: names.iter().copied().collect(), takes: takes.iter().copied().collect() }),
        _ => None,
    }).collect();
    let mut order: Vec<(u32, u32)> = held.iter().filter(|i| matches!(i.kind, forks::Kind::Rot { .. } | forks::Kind::Grant { .. } | forks::Kind::Creation { .. })).map(|i| (i.recv[v], i.id)).collect();
    order.sort();
    // the real commit creating D (pairing P's nodes before the world), held first
    let created = 1_000_000;
    let received: Vec<u32> = std::iter::once(created).chain(order.into_iter().map(|x| x.1)).collect();
    let devices = (v < forks::OWN).then(|| {
        let mut d = Devices { first: (0..forks::OWN).map(|m| (created, m)).collect(), ..Devices::default() };
        for i in &held {
            match &i.kind {
                forks::Kind::Rot { removes, covers, .. } => {
                    if let Some(m) = forks::signer_at(w, v, now, i.id) {
                        d.minter.insert(i.id, m);
                    }
                    if let Some(y) = removes {
                        d.removes.insert(i.id, [*y].into());
                        d.covers.insert(i.id, covers.iter().copied().chain([created]).collect());
                    }
                }
                forks::Kind::Grant { to } => {
                    d.commits.insert(i.id, (forks::signer_at(w, v, now, i.id), i.epoch));
                    d.grants.insert((i.id, *to));
                }
                forks::Kind::Creation { to } => {
                    d.commits.insert(i.id, (forks::signer_at(w, v, now, i.id), i.epoch));
                    d.first.insert((i.id, *to));
                }
                _ => {}
            }
        }
        d
    });
    Chain::new(0, rots, chosen, &received, devices.as_ref())
}

/// `samples` random `forks` worlds from `seed`, settled: at every node and time, what perm
/// counts, its heads and the warning agree with the model; at P's nodes a key actor X made up
/// is on the model's roster iff a grant of D to it counts (is not `cut`).
fn forks_run(samples: u64, seed: u64) -> u64 {
    let mut rng = roles_model::Rng(seed | 1);
    let mut checked = 0;
    for s in 0..samples {
        let mut w = forks::random_world(&mut rng);
        let end = forks::settle(&mut w, 12);
        for v in (0..forks::N).filter(|v| *v != forks::Z) {
            for now in 0..=end {
                let j = forks::judge(&w, v, now);
                let c = forks_chain(&w, v, now, j.chosen);
                let counting: BTreeSet<u32> = j.chain.iter().copied().filter(|r| c.counts(r)).collect();
                let heads: BTreeSet<u32> = c.heads().clone();
                assert!(counting == j.counting && heads == j.heads && c.warning() == j.warning, "seed {seed:#x} world {s} node {v} at {now}: perm counts {counting:?} heads {heads:?} warning {}, model {:?} {:?} {}", c.warning(), j.counting, j.heads, j.warning);
                if v < forks::OWN {
                    // Z (never removed) is on the model's roster iff a grant to it by another
                    // signer, or a commit creating D made again pairing it, counts here
                    let granted = w.items.iter().any(|i| i.recv[v] <= now && !c.cut(&i.id) && match i.kind {
                        forks::Kind::Grant { to } => to == forks::Z && forks::signer_at(&w, v, now, i.id) != Some(forks::Z),
                        forks::Kind::Creation { to } => to == forks::Z,
                        _ => false,
                    });
                    assert_eq!(granted, j.roster.contains(&forks::Z), "seed {seed:#x} world {s} node {v} at {now}: Z on the roster");
                }
                checked += 1;
            }
        }
    }
    checked
}

/// spec/permissions.md §5.4: the chain agrees with core/test/roles-model `forks` (a removed
/// node making up key actors and editing D among its moves) at every node and time.
#[test]
fn forks_model_agrees() {
    assert!(forks_run(150, 0xf0c5) > 0);
}

/// spec/permissions.md §5.4: as above, more samples (a property).
#[test]
#[ignore]
fn forks_model_agrees_large() {
    crate::common::sharded(20_000, 0xf0c5_0e01, forks_run);
}

/// A removes X (5) and then Y (3, at 5) within one millisecond: placed by when each came to be
/// held, then ancestors first, never by ID alone, so A takes both (spec/permissions.md §5.4,
/// Placing). Taken by ID, 3 would come first, standing with 5 not yet taken, and A would
/// disregard its own removal of Y.
#[test]
fn a_rotation_is_placed_after_its_line_whatever_its_id() {
    let rots = vec![rot(5, 0, &[0], &[]), rot(3, 5, &[5], &[])];
    let a = own(&rots, &[3, 5], &[(5, 'A'), (3, 'A')], &[(5, 'X'), (3, 'Y')], &[]);
    assert!(a.counts(&5) && a.counts(&3) && a.taken() == [5, 3], "heads {:?} taken {:?}", a.heads(), a.taken());
}

/// B's rotation (4, at 2) takes X's revocation of A (3); A removed X (1). A's user chooses 4:
/// what 4 stands with is placed with its line, ahead of A's own removal, so the choice holds
/// (spec/permissions.md §5.4, Placing).
#[test]
fn a_chosen_line_is_placed_with_what_it_takes() {
    let mut r4 = rot(4, 2, &[2], &[]);
    r4.takes = set(&[3]);
    let rots = vec![rot(1, 0, &[0], &[]), rot(2, 0, &[0], &[]), rot(3, 0, &[0], &[]), r4];
    let d = devices(&[(1, 'A'), (2, 'B'), (3, 'X'), (4, 'B')], &[(1, 'X'), (3, 'A')], &[]);
    let a = Chain::new(0, rots.clone(), None, &rec(&[1, 2, 3, 4]), Some(&d));
    assert!(a.counts(&1) && !a.counts(&4), "before the choice");
    let a = Chain::new(0, rots, Some(4), &rec(&[1, 2, 3, 4]), Some(&d));
    assert!(a.counts(&4) && a.counts(&3) && !a.counts(&1), "the choice holds: heads {:?} taken {:?}", a.heads(), a.taken());
}
