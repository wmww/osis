//! An account's signing chain (spec/crypto.md §9, spec/permissions.md §5.4): counting and the
//! head followed are a function of the held rotations, the side and the receipt order. Each test is a hand world of
//! core/test/roles-model `epochs` (`forks_merges_and_supersedes_entries`, `thief_fork_and_dispute`,
//! `removed_node_holding_a_sibling_epoch`); a rotation's ID is the epoch it mints, the root 0.

use osis_perm::{Chain, Rotation};
use std::collections::BTreeSet;

fn set(v: &[u32]) -> BTreeSet<u32> {
    v.iter().copied().collect()
}

/// Rotation `id` signed at `at`, superseding `sup`, naming `names` each with its signature.
fn rot(id: u32, at: u32, sup: &[u32], names: &[u32]) -> Rotation<u32> {
    Rotation { id, at, supersedes: set(sup), names: set(names), signed: set(names) }
}

/// Received in ID order.
fn chain(rots: &[Rotation<u32>], side: Option<u32>) -> Chain<u32> {
    let mut received: Vec<u32> = rots.iter().map(|r| r.id).collect();
    received.sort();
    received_as(rots, side, &received)
}

fn received_as(rots: &[Rotation<u32>], side: Option<u32>, received: &[u32]) -> Chain<u32> {
    Chain::new(0, rots.to_vec(), side, received)
}

/// Node 0's rotation 1 and node 2's rotation 2, concurrent at the root.
fn fork() -> Vec<Rotation<u32>> {
    vec![rot(1, 0, &[0], &[]), rot(2, 0, &[0], &[])]
}

#[test]
fn fork_rotations_both_count_and_the_first_received_is_followed() {
    let c = chain(&fork(), None);
    assert!(c.counts(&1) && c.counts(&2) && !c.dispute());
    assert_eq!(c.heads(), &set(&[1, 2]));
    assert!(c.open(&1) && !c.open(&2) && !c.open(&0) && !c.in_doubt(), "the line received first is read, silently");
    assert_eq!(c.closers(&1), vec![2], "the other head still closes it for the cutoff");
    let c = received_as(&fork(), None, &[2, 1]);
    assert!(c.open(&2) && !c.open(&1));
    let c = received_as(&fork(), Some(2), &[1, 2]);
    assert!(c.open(&2), "the side overrides the receipt order");
}

/// The removal 1, a fork 2 by the removed node merged out by 3; the removed node forks again
/// from the root (4), a plain sibling nothing rejects.
fn refork() -> Vec<Rotation<u32>> {
    vec![rot(1, 0, &[0], &[]), rot(2, 0, &[0], &[]), rot(3, 1, &[1, 2], &[]), rot(4, 0, &[0], &[])]
}

#[test]
fn a_refork_beside_a_merged_line_hides_nothing_where_the_line_came_first() {
    let r = refork();
    let c = received_as(&r, None, &[1, 2, 3, 4]);
    assert!(c.counts(&3) && c.counts(&4) && !c.counts(&2) && !c.dispute());
    assert_eq!(c.heads(), &set(&[3, 4]));
    assert!(c.open(&3) && !c.in_doubt(), "the line followed stays open: the lone fork is closed");
    // A reader the fork reached first follows it, in doubt: the other line carries a merge.
    let c = received_as(&r, None, &[4, 1, 2, 3]);
    assert!(c.open(&4) && c.in_doubt());
    let c = received_as(&r, Some(3), &[4, 1, 2, 3]);
    assert!(c.open(&3), "switching to the merged line");
    // The next merge rejects the fork unnamed and ends the fork at every reader.
    let mut m = r.clone();
    m.push(rot(5, 3, &[3, 4], &[]));
    for received in [[1, 2, 3, 4, 5], [4, 1, 2, 3, 5]] {
        let c = received_as(&m, None, &received);
        assert!(c.open(&5) && !c.counts(&4) && c.heads().len() == 1 && !c.in_doubt());
    }
    let c = received_as(&m, Some(4), &[4, 1, 2, 3, 5]);
    assert!(c.open(&4) && !c.counts(&5), "a side set holds against the merge");
}

#[test]
fn merge_rejects_an_unnamed_superseded_line() {
    let mut rots = fork();
    rots.push(rot(3, 1, &[1, 2], &[]));
    let c = chain(&rots, None);
    assert!(c.counts(&3) && !c.counts(&2) && c.counts(&1));
    assert!(c.open(&3) && !c.dispute() && c.heads() == &set(&[3]));
    // Everything below the rejected line is void and rejects nothing: 5, under 2, supersedes
    // sibling 6, which the merge accepts.
    let mut rots = fork();
    rots.extend([rot(6, 0, &[0], &[]), rot(7, 1, &[1, 2], &[6]), rot(5, 2, &[2, 6], &[])]);
    let c = chain(&rots, None);
    assert!(c.counts(&7) && !c.counts(&2) && !c.counts(&5) && c.counts(&6));
    // Naming the fork accepts it: it counts, closed.
    let mut rots = fork();
    rots.push(rot(4, 1, &[1, 2], &[2]));
    let c = chain(&rots, None);
    assert!(c.counts(&4) && c.counts(&2) && !c.open(&2) && c.open(&4));
}

#[test]
fn rotation_from_above_rejects_nothing() {
    // 5, signed at the root, supersedes 1, whose line runs through the root.
    let mut rots = fork();
    rots.push(rot(5, 0, &[0, 1], &[]));
    let c = chain(&rots, None);
    assert!(c.counts(&1) && c.counts(&2) && c.counts(&5) && !c.dispute());
}

#[test]
fn ill_formed_supersedes_entry_is_ignored() {
    // Its own ancestors (1 and the root) and an epoch never minted.
    let c = chain(&[rot(1, 0, &[0], &[]), rot(7, 1, &[1], &[]), rot(6, 7, &[7, 1, 0, 99], &[])], None);
    assert!(c.counts(&1) && c.counts(&7) && c.counts(&6) && c.open(&6));
}

/// Node 0 removes X (rotation 1); X, not boxed it, forks from the root (10); node 0 merges
/// out the fork (30), X counter-merges (40). The outsider received 30 before 40.
fn thief() -> Vec<Rotation<u32>> {
    vec![rot(1, 0, &[0], &[]), rot(10, 0, &[0], &[]), rot(30, 1, &[1, 10], &[]), rot(40, 10, &[1, 10], &[10])]
}

#[test]
fn removed_nodes_fork_is_void_once_the_owners_merge_is_held() {
    let t = thief();
    let c = chain(&t[..2], None);
    assert!(c.counts(&1) && c.counts(&10) && c.open(&1) && !c.open(&10), "before the merge the fork counts; the removal, received first, is followed");
    let c = chain(&t[..3], None);
    assert!(c.counts(&30) && c.counts(&1) && !c.counts(&10) && !c.dispute());
}

#[test]
fn mutual_rejection_reports_a_dispute_and_defaults_to_the_first_received_line() {
    let t = thief();
    let c = received_as(&t, None, &[1, 10, 30, 40]);
    assert_eq!(c.parties(), &set(&[30, 40]));
    assert!(c.in_doubt());
    assert_eq!((c.side(), c.followed()), (Some(30), 30));
    assert_eq!(received_as(&t, None, &[10, 1, 40, 30]).side(), Some(40));
    let owner = chain(&t, Some(30));
    assert!(owner.dispute() && owner.counts(&1) && owner.counts(&30) && !owner.counts(&10) && !owner.counts(&40));
    let x = chain(&t, Some(40));
    assert!(x.dispute() && x.counts(&10) && x.counts(&40) && !x.counts(&1) && !x.counts(&30));
    // Rotations on every party's line decide nothing: the same contest under a common 5.
    let under = |r: &Rotation<u32>| Rotation { at: if r.at == 0 { 5 } else { r.at }, supersedes: r.supersedes.iter().map(|&e| if e == 0 { 5 } else { e }).collect(), ..r.clone() };
    let mut t5: Vec<Rotation<u32>> = t.iter().map(under).collect();
    t5.push(rot(5, 0, &[0], &[]));
    let c = received_as(&t5, None, &[5, 10, 1, 40, 30]);
    assert_eq!(c.parties(), &set(&[30, 40]));
    assert_eq!(c.side(), Some(40));
}

/// Node 2 rotates (1) before X's removal (2) reaches it, boxing X epoch 1; X forks from epoch
/// 1 (3), superseding the removal unnamed; node 0 merges at 2 naming node 2's fork (4).
fn sibling(signed: bool) -> Vec<Rotation<u32>> {
    let mut m = rot(4, 2, &[1, 2, 3], &[1]);
    if !signed {
        m.signed.clear();
    }
    vec![rot(1, 0, &[0], &[]), rot(2, 0, &[0], &[]), rot(3, 1, &[1, 2], &[]), m]
}

#[test]
fn removal_closes_a_concurrent_siblings_epoch() {
    let c = received_as(&sibling(true)[..2], None, &[2, 1]);
    assert!(c.counts(&1) && c.counts(&2) && c.open(&2) && !c.open(&1));
    assert_eq!(c.closers(&1), vec![2]);
}

#[test]
fn merge_signed_at_a_forks_epoch_protects_its_line() {
    let s = sibling(true);
    let window = chain(&s[..3], None);
    assert!(window.counts(&3) && !window.counts(&2), "until the merge, X's fork rejects the removal (the fork window)");
    for side in [None, Some(2), Some(4)] {
        let c = chain(&s, side);
        assert!(c.counts(&2) && c.counts(&4) && c.counts(&1) && !c.counts(&3) && !c.dispute() && c.open(&4));
    }
}

#[test]
fn name_without_its_signature_accepts_nothing() {
    let c = received_as(&sibling(false), None, &[]);
    assert!(!c.line(&4).is_some_and(|l| l.contains(&1)));
    assert_eq!(c.parties(), &set(&[3, 4]), "the merge no longer protects the removal's line: X's fork contests it");
    let c = chain(&sibling(false), Some(4));
    assert!(c.counts(&4) && !c.counts(&1), "the merge rejects the fork it named unsigned");
}
