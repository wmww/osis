//! Grants without history (spec/crypto.md §4, Floors): a cut, a floor per keyset, the carry and
//! boxing rules. What every test checks is what a user observes: which secrets of the actor a
//! party's nodes hold or can open from the actor's `secrets.0` (a new node of it included).

#![allow(clippy::unwrap_used)]
use super::tests::{Key, edge, granted, independent_thing, openable, rotate_leaving_out, synced};
use crate::flows::edges::History;
use crate::local_peer::LocalPeer;
use osis_base::{Role, Tid};
use osis_crypto::Epoch;
use std::collections::BTreeSet;

const READ: [Role; 1] = [Role::Read];

/// Every read epoch of `g` any peer holds a secret of.
fn read_epochs(lp: &LocalPeer, g: Tid) -> BTreeSet<Epoch> {
    lp.peers.iter().flat_map(|p| p.engine.epochs(&g).map(|e| e.read.held().map(|x| x.0).collect::<Vec<_>>()).unwrap_or_default()).collect()
}

/// The read epochs of `g` party `x` reaches: those its own node holds and those it opens from the
/// `secrets.0` state peer `i` holds (what a new node of it opens).
fn reaches(lp: &mut LocalPeer, i: usize, g: Tid, x: Tid) -> BTreeSet<Epoch> {
    let own: BTreeSet<Epoch> = lp.peers.iter().filter(|p| p.engine.me() == x).flat_map(|p| p.engine.epochs(&g).map(|e| e.read.held().map(|y| y.0).collect::<Vec<_>>()).unwrap_or_default()).collect();
    let opened: BTreeSet<Epoch> = openable(lp, i, &[g], x, BTreeSet::new()).into_iter().filter(|k: &Key| k.1 == Role::Read).map(|k| k.2).collect();
    own.into_iter().chain(opened).collect()
}

/// The read epochs of `g` a new node of `x` opens from the `secrets.0` state peer `i` holds.
fn fresh(lp: &mut LocalPeer, i: usize, g: Tid, x: Tid) -> BTreeSet<Epoch> {
    openable(lp, i, &[g], x, BTreeSet::new()).into_iter().filter(|k: &Key| k.1 == Role::Read).map(|k| k.2).collect()
}

/// Rounds of every peer's re-seals, history adds and due rotations, synced, until none writes.
fn settle_all(lp: &mut LocalPeer, g: Tid) {
    for _ in 0..8 {
        let mut n = 0;
        for p in 0..lp.peers.len() {
            n += lp.peers[p].engine.ensure_rotated(&g).map(|x| x.0.commits.len()).unwrap_or(0);
            n += lp.peers[p].engine.reseal_after_pass(&g).map(|x| x.commits.len()).unwrap_or(0);
            lp.sync_all().unwrap();
        }
        if n == 0 {
            return;
        }
    }
    panic!("no fixpoint in 8 rounds");
}

/// Peers: 0 = admin A (`g`'s mint admin), 1 = reader P (with history), 2 = N (granted without
/// history by A once `g` has `before` read epochs past its first). Returns the peers, `g`, the
/// tids and the cut's epoch.
fn cut_world(before: usize) -> (LocalPeer, Tid, Vec<Tid>, Epoch) {
    let mut lp = synced(3);
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    for _ in 0..before {
        rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    }
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant_with(&g, &tids[2], &edge(Role::Read), History::None).unwrap();
    let cut = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    lp.sync_all().unwrap();
    (lp, g, tids, cut)
}

// spec/crypto.md §4 (Floors): N, granted without history, holds and opens the cut and nothing
// before it, after every co-holder's adds and re-seals; P, a holder with history, still opens
// every epoch; both read what A writes after.
#[test]
fn cut_grant_opens_nothing_before_it_spec_crypto_4() {
    let (mut lp, g, tids, cut) = cut_world(2);
    settle_all(&mut lp, g);
    let n = reaches(&mut lp, 0, g, tids[2]);
    assert!(n.contains(&cut), "N lacks the cut");
    assert!(n.iter().all(|e| e.n() >= cut.n()), "N reaches an epoch before its cut: {n:?} (cut {cut:?})");
    let e = lp.peers[2].engine.epochs(&g).unwrap();
    assert_eq!(e.read.current(), vec![cut], "the cut is N's current epoch");
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    lp.sync_all().unwrap();
    settle_all(&mut lp, g);
    let after = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    assert!(lp.peers[2].engine.epochs(&g).unwrap().read.secret(&after).is_some(), "N does not read A's later epoch");
    let n = reaches(&mut lp, 0, g, tids[2]);
    assert!(n.iter().all(|e| e.n() >= cut.n()), "a later rotation hands N an epoch before its cut: {n:?}");
    let all = read_epochs(&lp, g);
    assert_eq!(fresh(&mut lp, 0, g, tids[1]), all, "a new node of P, with history, lacks an epoch");
}

/// Peers: 0 = admin A, 1 = admin B, 2 = reader P (with history), 3 = N, all granted by A and
/// synced, `g` rotated once by A (so it has an epoch below the cut that no first box opens).
fn two_admins() -> (LocalPeer, Tid, Vec<Tid>) {
    let mut lp = synced(4);
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    lp.sync_all().unwrap();
    (lp, g, tids)
}

/// Asserts `x` reaches no read epoch of `g` below `cut` nor any in `beside`, from any peer's
/// state or its own node.
fn reaches_nothing_before(lp: &mut LocalPeer, g: Tid, x: Tid, cut: &Epoch, beside: &BTreeSet<Epoch>, what: &str) {
    for i in 0..lp.peers.len() {
        let r = reaches(lp, i, g, x);
        let bad: Vec<&Epoch> = r.iter().filter(|e| e.n() < cut.n() || beside.contains(e)).collect();
        assert!(bad.is_empty(), "{what}: peer {i}'s state hands {x} {bad:?} (cut {cut:?})");
    }
}

// spec/crypto.md §4 (floors: model X_cut): A cuts for N while B, not holding the grant, rotates
// beside it; P adds history, A merges. N gets neither an epoch before its cut nor B's fork (its
// history opens the past), and reads the merge.
#[test]
fn fork_beside_the_cut_never_reaches_the_newcomer_spec_crypto_4() {
    let mut lp = synced(5);
    let tids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant_with(&g, &tids[3], &edge(Role::Read), History::None).unwrap();
    let cut = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    // Q, granted with history by A, never boxed at B's fork (B holds neither grant): its fork
    // reaches Q only by a tip add once A's rotation drops it
    lp.peers[0].engine.grant(&g, &tids[4], &edge(Role::Read)).unwrap();
    rotate_leaving_out(&mut lp, 1, g, &BTreeSet::from(READ), &[]);
    let fork = lp.peers[1].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    assert_ne!(fork, cut);
    lp.sync_all().unwrap();
    // forks stand: A rotates over them (the model's merge) before anyone re-seals Q at the fork
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    lp.sync_all().unwrap();
    settle_all(&mut lp, g);
    reaches_nothing_before(&mut lp, g, tids[3], &cut, &BTreeSet::from([fork]), "a fork beside the cut");
    let newest = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    assert!(newest.n() > cut.n(), "no merge");
    assert!(lp.peers[3].engine.epochs(&g).unwrap().read.secret(&newest).is_some(), "N does not read the merge");
    let all = read_epochs(&lp, g);
    for p in [1, 2, 4] {
        assert_eq!(fresh(&mut lp, 0, g, tids[p]), all, "a new node of peer {p}, with history, lacks an epoch");
    }
}

// spec/crypto.md §5 (Who wraps under what: a rotation goes under an epoch it supersedes): N,
// granted without history, holds A's rotation before its cut but no epoch it supersedes. Logging
// it again, N wraps it as A did (what a holder of the superseded epoch opens) or not at all,
// never under N's own epoch, which a holder still catching up through that rotation lacks.
#[test]
fn a_rotation_before_the_cut_wraps_under_what_it_supersedes_or_not_at_all_spec_crypto_5() {
    let (mut lp, g, _, cut) = cut_world(2);
    settle_all(&mut lp, g);
    let at_a = lp.peers[0].engine.epochs(&g).unwrap();
    let before: Vec<Epoch> = at_a.read.held().map(|x| x.0).filter(|e| e.n() > 0 && e.n() < cut.n()).collect();
    assert!(!before.is_empty(), "no rotation before the cut");
    for e in before {
        let (_, r) = *lp.peers[0].engine.core.ix.epoch_intro.get(&(g, Role::Read, e)).unwrap();
        assert!(lp.peers[2].engine.core.ix.commits.contains_key(&r), "N lacks the rotation to {e:?}");
        let parts: Vec<usize> = (0..lp.peers[0].engine.header(&r).unwrap().aspects.len()).collect();
        let by_a = lp.peers[0].engine.wrap_secret(&g, Some((&r, &parts))).unwrap().expect("A wraps its rotation");
        if let Some(by_n) = lp.peers[2].engine.wrap_secret(&g, Some((&r, &parts))).unwrap() {
            assert_eq!(by_n.expose(), by_a.expose(), "N wraps the rotation to {e:?} under an epoch it does not supersede");
        }
    }
}

// spec/crypto.md §4 (the boxing rule; current: model X_cut_nofloor): B holds A's cut but not the
// rotation before it, so the epoch before that is current at B beside the cut. B's re-seals box
// N at no epoch below N's floor, and N counts none current; B rotates over it instead (a low
// floor), boxing N.
#[test]
fn holder_lacking_the_rotation_before_the_cut_reseals_nothing_below_it_spec_crypto_4() {
    let mut lp = synced(4);
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let before = super::tests::commit_ids(&mut lp, 0);
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    let r1: BTreeSet<osis_base::CommitId> = super::tests::commit_ids(&mut lp, 0).difference(&before).copied().collect();
    lp.peers[0].engine.grant_with(&g, &tids[3], &edge(Role::Read), History::None).unwrap();
    let cut = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    for pk in lp.packages_for(0, 1).unwrap() {
        if !r1.contains(&pk.id) {
            lp.deliver(1, &pk).unwrap();
        }
    }
    for pk in lp.packages_for(0, 3).unwrap() {
        if !r1.contains(&pk.id) {
            lp.deliver(3, &pk).unwrap();
        }
    }
    // N holds the cut and the epoch the missing rotation superseded, established (its secret not
    // held, no names needed): below N's floor, it is no current epoch of N's
    assert_eq!(lp.peers[3].engine.epochs(&g).unwrap().read.current(), vec![cut], "N counts an epoch below its floor current");
    let at_b = lp.peers[1].engine.epochs(&g).unwrap().read.current();
    assert!(at_b.len() > 1 && at_b.contains(&cut), "the epoch before the rotation is not current at B beside the cut: {at_b:?}");
    lp.peers[1].engine.reseal_after_pass(&g).unwrap();
    for i in [1, 3] {
        lp.sync(1, i).unwrap();
        lp.sync(0, i).unwrap();
    }
    reaches_nothing_before(&mut lp, g, tids[3], &cut, &BTreeSet::new(), "B's re-seal");
    // B's rotation over that low-floor epoch (due at its pass end) boxes N
    let at_n = lp.peers[3].engine.epochs(&g).unwrap();
    let cur = at_n.read.current();
    assert!(!cur.is_empty() && cur.iter().all(|e| e.n() >= cut.n() && at_n.read.secret(e).is_some()), "N's current epochs: {cur:?} (cut {cut:?})");
}

// spec/crypto.md §4 (Floors: a grant with history boxes each dropped epoch; a party's floor):
// after A's cut for N, A cuts for admin B too, then grants Q with history: Q opens every epoch.
// B, granted without history, grants R with history: R's floor is B's (a party hands no history
// it was not given), so R opens nothing before B's cut. N still none before its own.
#[test]
fn grants_with_history_after_a_cut_open_everything_spec_crypto_4() {
    let mut lp = synced(6);
    let tids: Vec<Tid> = (0..6).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant_with(&g, &tids[3], &edge(Role::Read), History::None).unwrap();
    let cut = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    lp.peers[0].engine.grant_with(&g, &tids[1], &edge(Role::Admin), History::None).unwrap();
    let b_cut = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&g, &tids[4], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    // the grant itself boxes Q at each dropped epoch: no tip add yet
    let all = read_epochs(&lp, g);
    assert_eq!(fresh(&mut lp, 0, g, tids[4]), all, "Q's grant with history leaves out an epoch");
    lp.peers[1].engine.grant(&g, &tids[5], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    settle_all(&mut lp, g);
    let all = read_epochs(&lp, g);
    for p in [2, 4] {
        assert_eq!(fresh(&mut lp, 0, g, tids[p]), all, "a new node of peer {p}, granted with history, lacks an epoch");
    }
    reaches_nothing_before(&mut lp, g, tids[3], &cut, &BTreeSet::new(), "grants with history beside N");
    reaches_nothing_before(&mut lp, g, tids[5], &b_cut, &BTreeSet::new(), "a grant with history by B");
    reaches_nothing_before(&mut lp, g, tids[1], &b_cut, &BTreeSet::new(), "B's own grants");
    assert!(lp.peers[5].engine.epochs(&g).unwrap().read.holds_current(), "R reads nothing current");
}

/// Peer `i` rotates `g`'s read as a hostile writer may: its keyset listing `lists` with floor
/// `floor` (any the validity rule lets through; a node reads it as at most its n), boxing every
/// holder as the rules give from that keyset, its history box carrying nothing (so it supersedes
/// only what it lists). Returns the new epoch.
fn hostile_rotation(lp: &mut LocalPeer, i: usize, g: Tid, lists: &BTreeSet<Epoch>, floor: u64) -> Epoch {
    lp.peers[i]
        .engine
        .run(|tx| {
            let me = tx.core.writer()?;
            let mut held = (*tx.core.epochs(&g).unwrap()).clone();
            let secrets = crate::flows::secrets_in(tx, &g)?;
            let mut boxing = super::recipients(tx, &me, &g, &[])?;
            // the boxing rule from the written floor
            boxing.holders.retain(|h| h.floor <= floor);
            // a view whose own floor lets nothing in: its history box carries nothing
            held.read.set_floors(Default::default(), u64::MAX);
            let names = super::departures::names(tx.core, &g, None);
            let mut rot = osis_keys::rotate_leaving_out(&g, &BTreeSet::from(READ), &held, &secrets, &boxing.holders, &Default::default(), &Default::default(), &names, false, &mut *tx.rng)?;
            let ks = rot.keys.keysets.get_mut(&Role::Read).unwrap();
            ks.supersedes = lists.iter().map(osis_keys::aspects::to_schema).collect();
            let x = &rot.rotated[0];
            let entry = osis_crypto::seal_history(&x.secret, &g, Role::Read, &x.epoch, &osis_crypto::HistoryEntry { earlier: Vec::new(), names: names.to_value(), floor, roles: Vec::new() })?;
            rot.secrets.history.insert(osis_keys::aspects::history_key(Role::Read, &x.epoch), entry);
            let mut m = crate::Mutation::new();
            crate::flows::put_secrets(&mut m, g, &rot.secrets, false)?;
            crate::flows::put_keysets(&mut m, g, &rot.keys)?;
            m.unchecked();
            tx.core.skip_writer_rules = true;
            let c = crate::engine::Engine::commit_tx(tx, m);
            tx.core.skip_writer_rules = false;
            c?;
            super::record(tx, g, &rot)?;
            Ok(rot.rotated[0].epoch)
        })
        .unwrap()
}

// spec/crypto.md §4 (the carry rule: judges the maker, model X_host_nomaker): H, granted write
// without history, rotates listing only the epoch the cut superseded, with floor 0. Co-holders
// holding that epoch add no history at H's epoch: H's floor is its cut's n. H reaches nothing
// before its cut.
#[test]
fn hostile_low_floor_epoch_takes_no_earlier_secret_spec_crypto_4() {
    let (mut lp, g, tids) = two_admins();
    let before = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    lp.peers[0].engine.grant_with(&g, &tids[3], &edge(Role::Write), History::None).unwrap();
    let cut = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    lp.sync_all().unwrap();
    let h = hostile_rotation(&mut lp, 3, g, &BTreeSet::from([before]), 0);
    lp.sync_all().unwrap();
    assert!(lp.peers[2].engine.epochs(&g).unwrap().read.is_current(&h), "H's epoch is not current at P");
    settle_all(&mut lp, g);
    reaches_nothing_before(&mut lp, g, tids[3], &cut, &BTreeSet::new(), "adds at a low-floor epoch by H");
}

// spec/crypto.md §4 (A party's floor: one above n is read as n, model X_cap_nocap): W, a writer with
// history, rotates writing a floor far above its n; A rotates over it, then cuts for N, then
// rotates again. A's last rotation carries no epoch before the cut to N.
#[test]
fn floor_above_n_carries_nothing_past_a_later_cut_spec_crypto_4() {
    let mut lp = synced(4);
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    let cur: BTreeSet<Epoch> = lp.peers[1].engine.epochs(&g).unwrap().read.current().into_iter().collect();
    hostile_rotation(&mut lp, 1, g, &cur, 1000);
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant_with(&g, &tids[3], &edge(Role::Read), History::None).unwrap();
    let cut = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    lp.sync_all().unwrap();
    settle_all(&mut lp, g);
    reaches_nothing_before(&mut lp, g, tids[3], &cut, &BTreeSet::new(), "a floor above n");
}

// spec/crypto.md §4 (Floors: an epoch's floor is what its entries write, a rotation's, the
// greatest of its maker's and its holders'): W, a writer with history, rotates after N's cut
// listing the cut with floor 0, so co-holders carry what came before into W's epoch. N is never
// boxed there (a writer may leave anyone out), reaches nothing before its cut, and reads A's
// next epoch, which carries neither W's epoch nor anything before the cut.
#[test]
fn low_floor_over_the_cut_hands_the_newcomer_nothing_before_it_spec_crypto_4() {
    let mut lp = synced(4);
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant_with(&g, &tids[3], &edge(Role::Read), History::None).unwrap();
    let cut = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    lp.sync_all().unwrap();
    let w = hostile_rotation(&mut lp, 1, g, &BTreeSet::from([cut]), 0);
    lp.sync_all().unwrap();
    settle_all(&mut lp, g);
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    let next = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    lp.sync_all().unwrap();
    settle_all(&mut lp, g);
    assert!(lp.peers[3].engine.epochs(&g).unwrap().read.secret(&next).is_some(), "N does not read A's next epoch");
    reaches_nothing_before(&mut lp, g, tids[3], &cut, &BTreeSet::from([w]), "W's low floor");
}

/// A fallible `hostile_rotation` (H may hold nothing yet).
fn try_hostile(lp: &mut LocalPeer, i: usize, g: Tid, lists: &BTreeSet<Epoch>, floor: u64) -> Option<Epoch> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hostile_rotation(lp, i, g, lists, floor))).ok()
}

// spec/crypto.md §4 (Floors), the invariant (`floors`): no secret below a holder's floor reaches
// it. Randomized: admins A and B rotate, re-seal, add history and merge under partial syncs;
// reader P adds; A cuts for N, then for H, a writer granted without history that rotates
// listing any epochs it knows of with any floor up to its n. Neither N nor H ever reaches,
// from its own node or any state a peer holds, an epoch some peer held when its cut was made
// (its cut's causal past, and more: every epoch then known). Fails with the carry rule or the
// boxing rule off.
#[test]
#[ignore = "property"]
fn nothing_before_a_cut_reaches_its_holder_plain_spec_crypto_4() {
    osis_base::testenv::run_seeds("rotation::tests_cut::nothing_before_a_cut_reaches_its_holder_plain_spec_crypto_4", &NOTHING_BEFORE_SEEDS, false, cut_replay("nothing_before_a_cut_reaches_its_holder_large_spec_crypto_4"), nothing_before_a_cut);
}

/// The `_plain` property's seeds, a covering set: with the boxing or the carry rule off, every one of
/// seeds 1-40 fails; with the carry rule's maker clause off 5 (2 among them), with a box allowed
/// one floor low 23 (2).
const NOTHING_BEFORE_SEEDS: [u64; 3] = [1, 2, 3];

/// Small size (a tenth of large) or large under `OSIS_FULL=1`; seeds: OSIS_CUT_START,
/// OSIS_CUT_SEEDS.
#[test]
#[ignore = "property"]
fn nothing_before_a_cut_reaches_its_holder_large_spec_crypto_4() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_CUT_START", "OSIS_CUT_SEEDS", osis_base::testenv::large(1..201));
    s.run("rotation::tests_cut::nothing_before_a_cut_reaches_its_holder_large_spec_crypto_4", cut_replay("nothing_before_a_cut_reaches_its_holder_large_spec_crypto_4"), nothing_before_a_cut);
}

/// The replay line of `test`'s seed `s` (a `_large` twin of this module).
fn cut_replay(test: &'static str) -> impl Fn(u64) -> String + Sync {
    move |s| format!("OSIS_CUT_START={s} OSIS_CUT_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_cut::{test}")
}

/// One seed of `nothing_before_a_cut_reaches_its_holder_plain_spec_crypto_4`.
fn nothing_before_a_cut(seed: u64) {
    let read = BTreeSet::from(READ);
    let mut rng = super::tests::Rng(seed.wrapping_mul(0x9e37_79b9).wrapping_add(7));
    let (mut lp, g, tids) = granted(5, &[(1, Role::Admin), (2, Role::Read)]);
    let mut before: Vec<(usize, BTreeSet<Epoch>)> = Vec::new();
    let cut_at = [rng.next(4) as usize, 4 + rng.next(4) as usize];
    for step in 0..14 {
        for (k, (who, role)) in [(3usize, Role::Read), (4, Role::Write)].into_iter().enumerate() {
            if step == cut_at[k] {
                let known = read_epochs(&lp, g);
                if lp.peers[0].engine.grant_with(&g, &tids[who], &edge(role), History::None).is_ok() {
                    before.push((who, known));
                }
            }
        }
        match rng.next(7) {
            0 => rotate_leaving_out(&mut lp, 0, g, &read, &[]),
            1 => rotate_leaving_out(&mut lp, 1, g, &read, &[]),
            2 => {
                let (a, b) = (rng.next(5) as usize, rng.next(5) as usize);
                if a != b {
                    lp.sync(a, b).unwrap();
                }
            }
            3 => {
                let p = rng.next(5) as usize;
                let _ = lp.peers[p].engine.reseal_after_pass(&g);
            }
            4 => {
                let p = rng.next(2) as usize;
                let _ = lp.peers[p].engine.ensure_rotated(&g);
            }
            5 => {
                let known: Vec<Epoch> = lp.peers[4].engine.epochs(&g).map(|e| e.read.epochs().map(|x| *x.0).collect()).unwrap_or_default();
                let lists: BTreeSet<Epoch> = known.iter().filter(|_| rng.next(2) == 0).copied().collect();
                let top = lists.iter().map(Epoch::n).max().unwrap_or(0) + 1;
                let floor = rng.next(top + 1);
                if !lists.is_empty() && before.iter().any(|(w, _)| *w == 4) {
                    try_hostile(&mut lp, 4, g, &lists, floor);
                }
            }
            _ => lp.sync_all().unwrap(),
        }
    }
    lp.sync_all().unwrap();
    for p in [0, 1, 2] {
        let _ = lp.peers[p].engine.reseal_after_pass(&g);
    }
    lp.sync_all().unwrap();
    for (who, known) in &before {
        for i in 0..5 {
            let bad: Vec<Epoch> = reaches(&mut lp, i, g, tids[*who]).intersection(known).copied().collect();
            assert!(bad.is_empty(), "seed {seed}: peer {i}'s state hands peer {who} {bad:?}, held before its cut");
        }
    }
}

/// Whether package `pk` has an aspect on `g` other than its creation record: one `g`'s sync IDs
/// carry sealed.
fn on_g(pk: &crate::local_peer::Package, g: Tid) -> bool {
    aspect_on_g(&osis_commit::CommitBlob::decode(&pk.bytes).unwrap().header, g)
}

/// `on_g` of a commit's header.
fn aspect_on_g(h: &osis_commit::Header, g: Tid) -> bool {
    h.aspects.iter().any(|a| a.tid == g && a.ak.as_str() != "created.0")
}

/// What `g`'s sync IDs hold: each commit on `g` sealed once, by the first peer to log it, under
/// its wrap epoch then (`LocalPeer::sealed`, as node-sync logs a body soon after it is made
/// or received).
#[derive(Default)]
struct Logged {
    logged: BTreeSet<osis_base::CommitId>,
    held: Vec<crate::local_peer::SealedPackage>,
}

impl Logged {
    /// Peers `among` log what they hold that is not logged yet, after the rotations due
    /// before they encrypt (noted).
    fn log(&mut self, lp: &mut LocalPeer, g: Tid, among: &[usize]) {
        for &p in among {
            let _ = lp.peers[p].engine.ensure_rotated(&g);
            let e = &lp.peers[p].engine;
            let ids: Vec<osis_base::CommitId> = e.commit_ids().into_iter().filter(|id| !self.logged.contains(id) && e.header(id).is_some_and(|h| aspect_on_g(&h, g))).collect();
            if ids.is_empty() {
                continue;
            }
            for pk in lp.sealed(p, &ids).unwrap() {
                if self.logged.insert(pk.id) {
                    self.held.push(pk);
                }
            }
        }
    }
}

/// Peers 0 = admin A, 1 = admin B (granted without history when `b_cut`, after M's removal),
/// 2 = M (a reader). A rotates `g` once, removes M (its rotation R), rotates again (an epoch made
/// knowing the removal). Returns the peers, `g`, the tids, what M read before its removal (every
/// read epoch held then) and the epochs made since (R's and the one after).
fn removed_member(b_cut: bool) -> (LocalPeer, Tid, Vec<Tid>, BTreeSet<Epoch>, BTreeSet<Epoch>) {
    let mut lp = synced(3);
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, 0);
    if !b_cut {
        lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
    }
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    lp.sync_all().unwrap();
    let read = read_epochs(&lp, g);
    lp.peers[0].engine.demote(&g, &crate::flows::Demotion { holder: tids[2], new: None, retain: None }).unwrap();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    let gone: BTreeSet<Epoch> = read_epochs(&lp, g).difference(&read).copied().collect();
    if b_cut {
        lp.peers[0].engine.grant_with(&g, &tids[1], &edge(Role::Admin), History::None).unwrap();
    }
    lp.sync_all().unwrap();
    (lp, g, tids, read, gone)
}

/// Asserts the re-added `m` reaches, from every peer's state, all of `read` (a new node of it
/// opens what its earlier nodes read: model `ReaddFresh`) and, from its node or any state, none of
/// `gone` (made knowing its removal: `NoAbsence`).
fn readd_holds(lp: &mut LocalPeer, g: Tid, m: Tid, read: &BTreeSet<Epoch>, gone: &BTreeSet<Epoch>) {
    for i in 0..lp.peers.len() {
        let f = fresh(lp, i, g, m);
        assert!(f.is_superset(read), "peer {i}: a new node of M lacks {:?}", read.difference(&f).collect::<Vec<_>>());
        let bad: Vec<Epoch> = reaches(lp, i, g, m).intersection(gone).copied().collect();
        assert!(bad.is_empty(), "peer {i}: M reaches {bad:?}, made knowing its removal");
    }
}

// spec/crypto.md §4 (floors: re-added without history: models X_readd, X_readd_fresh, X_gone):
// M, removed, is re-added by A without history while B rotates beside the re-add. A new node of
// M opens what M read before its removal, never an epoch made knowing it (R's, A's next, B's),
// and M's current epochs are the re-add's and after.
#[test]
fn readd_without_history_opens_what_it_read_before_spec_crypto_4() {
    let (mut lp, g, tids, read, mut gone) = removed_member(false);
    lp.peers[0].engine.grant_with(&g, &tids[2], &edge(Role::Read), History::None).unwrap();
    let cut = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    // the re-add's own boxes, before any tip add
    let f = fresh(&mut lp, 0, g, tids[2]);
    assert!(f.is_superset(&read), "the re-add leaves out {:?}", read.difference(&f).collect::<Vec<_>>());
    rotate_leaving_out(&mut lp, 1, g, &BTreeSet::from(READ), &[]);
    gone.insert(lp.peers[1].engine.epochs(&g).unwrap().read.newest_held().unwrap().0);
    lp.sync_all().unwrap();
    settle_all(&mut lp, g);
    readd_holds(&mut lp, g, tids[2], &read, &gone);
    assert!(lp.peers[2].engine.epochs(&g).unwrap().read.current().iter().all(|e| e.n() >= cut.n()), "M counts an epoch before its re-add current");
}

// spec/crypto.md §4 (Floors: a history-less re-adder): B, granted without history after M's
// removal, re-adds M without history; B holds none of what M read before, so A, holding it,
// boxes it to M (the tip add).
#[test]
fn readd_by_a_history_less_admin_opens_what_it_read_before_spec_crypto_4() {
    let (mut lp, g, tids, read, gone) = removed_member(true);
    lp.peers[1].engine.grant_with(&g, &tids[2], &edge(Role::Read), History::None).unwrap();
    lp.sync_all().unwrap();
    settle_all(&mut lp, g);
    readd_holds(&mut lp, g, tids[2], &read, &gone);
}

// spec/crypto.md §4 (Floors: compaction snapshots): after A's cut for N, A compacts `g`'s
// `secrets.0` and `keys.0` and drops every body the snapshots cover. Q, granted with history
// later, holds the earlier epochs by the snapshots alone: it still comes to open every epoch,
// and N still none before its cut.
#[test]
fn compacted_cut_keeps_its_floors_spec_crypto_4() {
    let mut lp = synced(4);
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    lp.peers[0].engine.grant_with(&g, &tids[2], &edge(Role::Read), History::None).unwrap();
    let cut = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    lp.sync_all().unwrap();
    let all_before = super::tests::commit_ids(&mut lp, 0);
    for k in ["secrets.0", "keys.0"].map(|k| osis_base::Ak::new(k).unwrap()) {
        lp.peers[0].engine.snapshot(&g, &k).unwrap().unwrap();
        for c in &all_before {
            if lp.peers[0].engine.body_not_dropped(c, &g, &k) {
                let _ = lp.peers[0].engine.drop_body(c, &g, &k);
            }
        }
    }
    lp.peers[0].engine.grant(&g, &tids[3], &edge(Role::Read)).unwrap();
    // Q syncs with A alone: it holds what A's snapshots carry, never the dropped bodies
    for _ in 0..3 {
        lp.sync(0, 3).unwrap();
        lp.sync(3, 0).unwrap();
        let _ = lp.peers[0].engine.reseal_after_pass(&g);
        let _ = lp.peers[3].engine.reseal_after_pass(&g);
    }
    lp.sync(0, 3).unwrap();
    let held: BTreeSet<osis_base::CommitId> = super::tests::commit_ids(&mut lp, 3);
    assert!(all_before.iter().any(|c| !held.contains(c) || !lp.peers[3].engine.body_not_dropped(c, &g, &osis_base::Ak::new("keys.0").unwrap())), "Q holds every body the snapshots cover");
    let all = read_epochs(&lp, g);
    assert_eq!(fresh(&mut lp, 0, g, tids[3]), all, "Q, granted with history after the compaction, lacks an epoch");
    reaches_nothing_before(&mut lp, g, tids[2], &cut, &BTreeSet::new(), "the compacted cut");
}

/// The read epochs of `g` that `x` opens from peer `i`'s states of `actors` (through holder
/// actors among them) or holds on its own node.
fn reaches_via(lp: &mut LocalPeer, i: usize, actors: &[Tid], g: Tid, x: Tid) -> BTreeSet<Epoch> {
    let own: BTreeSet<Epoch> = lp.peers.iter().filter(|p| p.engine.me() == x).flat_map(|p| p.engine.epochs(&g).map(|e| e.read.held().map(|y| y.0).collect::<Vec<_>>()).unwrap_or_default()).collect();
    let opened = openable(lp, i, actors, x, BTreeSet::new()).into_iter().filter(|k: &Key| k.0 == g && k.1 == Role::Read).map(|k| k.2);
    own.into_iter().chain(opened).collect()
}

// spec/crypto.md §4 (Floors: a party's floor through holder actors): team T (admin X, member M)
// is granted read on `g` without history. M, reading `g` only through T, reaches nothing before
// T's cut, by T's boxes or its own node, after co-holders' adds and re-seals. Granted read on
// `g` directly with history too, M's floor is the least over its paths: its own nodes count every
// epoch current and it comes to open them all.
#[test]
fn cut_through_a_holder_actor_spec_crypto_4() {
    let mut lp = synced(4);
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Read)).unwrap();
    let t = independent_thing(&mut lp, 2);
    lp.peers[2].engine.grant(&t, &tids[3], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant_with(&g, &t, &edge(Role::Read), History::None).unwrap();
    let cut = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    lp.sync_all().unwrap();
    settle_all(&mut lp, g);
    for i in 0..4 {
        let r = reaches_via(&mut lp, i, &[g, t], g, tids[3]);
        assert!(r.contains(&cut), "peer {i}: M does not reach T's cut");
        let bad: Vec<&Epoch> = r.iter().filter(|e| e.n() < cut.n()).collect();
        assert!(bad.is_empty(), "peer {i}: M reaches {bad:?} through T");
    }
    let m_floor = lp.peers[3].engine.run(|tx| Ok(super::floors::party_floor(tx.core, &g, &tids[3]))).unwrap();
    assert_eq!(m_floor, cut.n(), "M's floor through T");
    lp.peers[0].engine.grant(&g, &tids[3], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    settle_all(&mut lp, g);
    let m_floor = lp.peers[3].engine.run(|tx| Ok(super::floors::party_floor(tx.core, &g, &tids[3]))).unwrap();
    assert_eq!(m_floor, 0, "M's floor over both paths");
    let all = read_epochs(&lp, g);
    assert_eq!(fresh(&mut lp, 0, g, tids[3]), all, "a new node of M, granted directly with history, lacks an epoch");
}

// spec/crypto.md §4 (Floors: an epoch's floor is what its history entries write, read under its
// secret): B rotates twice beside the cut; H, a writer granted without history, writes a
// rotation commit of B's newest fork epoch, its keyset listing the cut and a history entry at it
// with a floor at its n, under a secret H made up (it holds none of the fork's). No co-holder
// then reads the fork's floor as raised, so none carries it (its history opens the past) into
// an epoch N reads.
#[test]
fn forged_floor_on_a_fork_beside_the_cut_carries_nothing_spec_crypto_4() {
    let mut lp = synced(5);
    let tids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant_with(&g, &tids[3], &edge(Role::Read), History::None).unwrap();
    let cut = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    lp.peers[0].engine.grant_with(&g, &tids[4], &edge(Role::Write), History::None).unwrap();
    rotate_leaving_out(&mut lp, 1, g, &BTreeSet::from(READ), &[]);
    let fork1 = lp.peers[1].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    rotate_leaving_out(&mut lp, 1, g, &BTreeSet::from(READ), &[]);
    let fork = lp.peers[1].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    lp.sync_all().unwrap();
    lp.peers[4]
        .engine
        .run(|tx| {
            let names = super::departures::names(tx.core, &g, None);
            let made_up = osis_crypto::Secret32::random(&mut *tx.rng);
            let ks = osis_keys::aspects::keyset(&fork, &made_up, &BTreeSet::from([cut]), &names);
            let w = osis_keys::aspects::KeysWrite { keysets: std::collections::BTreeMap::from([(Role::Read, ks)]) };
            let mut m = crate::Mutation::new();
            crate::flows::put_keysets(&mut m, g, &w)?;
            let made_up_epoch = Epoch::derive(&g, Role::Read, fork.n(), &made_up).unwrap();
            let entry = osis_crypto::seal_history(&made_up, &g, Role::Read, &made_up_epoch, &osis_crypto::HistoryEntry { earlier: Vec::new(), names: names.to_value(), floor: fork.n(), roles: Vec::new() })?;
            let mut sw = osis_keys::SecretsWrite::default();
            sw.history.insert(osis_keys::aspects::history_key(Role::Read, &fork), entry);
            crate::flows::put_secrets(&mut m, g, &sw, false)?;
            m.unchecked();
            tx.core.skip_writer_rules = true;
            let c = crate::engine::Engine::commit_tx(tx, m);
            tx.core.skip_writer_rules = false;
            c.map(|_| ())
        })
        .unwrap();
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    lp.sync_all().unwrap();
    settle_all(&mut lp, g);
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    lp.sync_all().unwrap();
    settle_all(&mut lp, g);
    reaches_nothing_before(&mut lp, g, tids[3], &cut, &BTreeSet::from([fork1, fork]), "a forged floor on the fork");
}

/// Peer `i` writes key `k` on `g`'s `x:m.0` (content, never a role part).
fn put(lp: &mut LocalPeer, i: usize, g: Tid, k: &str) {
    let mut m = crate::Mutation::new();
    m.op(g, &osis_base::Ak::new("x:m.0").unwrap(), osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(osis_base::Value::Str(k.into()))], op: osis_crdt::Op::Put(osis_base::Value::Int(1)) }).unwrap();
    lp.peers[i].commit(m).unwrap();
}

/// The keys peer `i` reads on `g`'s `x:m.0`.
fn content(lp: &mut LocalPeer, i: usize, g: Tid) -> BTreeSet<String> {
    match lp.peers[i].engine.get(&g, &osis_base::Ak::new("x:m.0").unwrap()).unwrap() {
        Some(osis_base::Value::Map(m)) => m.into_keys().filter_map(|k| if let osis_base::Value::Str(s) = k { Some(s) } else { None }).collect(),
        _ => BTreeSet::new(),
    }
}

// spec/crypto.md §4 (floors; low floor: model X_rmrace): A removes reader M, then cuts for N. B
// holds the cut (boxed) but not the removal, so it meets neither the cut's names nor knows M left:
// the epoch before the removal is current at B with a floor below N's. B rotates over it only once
// it holds the removal: its rotation would box M at an epoch made knowing M's removal.
#[test]
fn low_floor_waits_for_the_names_spec_crypto_4() {
    let mut lp = synced(4);
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let read = read_epochs(&lp, g);
    let before = super::tests::commit_ids(&mut lp, 0);
    lp.peers[0].engine.demote(&g, &crate::flows::Demotion { holder: tids[2], new: None, retain: None }).unwrap();
    let removal: BTreeSet<osis_base::CommitId> = super::tests::commit_ids(&mut lp, 0).difference(&before).copied().collect();
    lp.peers[0].engine.grant_with(&g, &tids[3], &edge(Role::Read), History::None).unwrap();
    for pk in lp.packages_for(0, 1).unwrap() {
        if !removal.contains(&pk.id) {
            let _ = lp.peers[1].receive(&pk.bytes, pk.blobs.clone());
        }
    }
    lp.peers[1].engine.reseal_after_pass(&g).unwrap();
    let m = reaches(&mut lp, 1, g, tids[2]);
    assert!(m.is_subset(&read), "B's state hands M {:?}, made knowing its removal", m.difference(&read).collect::<Vec<_>>());
}

/// The content commits peer `i` holds on `g` (not role commits, not snapshots): every one an
/// edit somebody made.
fn edits_on(lp: &LocalPeer, i: usize, g: Tid) -> BTreeSet<osis_base::CommitId> {
    let e = &lp.peers[i].engine;
    e.core.ix.commits.iter().filter(|(_, m)| !m.header.kind.is_compaction() && m.header.aspects.iter().any(|a| a.tid == g && osis_schema::core_types::is_content(a.ak.as_str()))).map(|(c, _)| *c).collect()
}

// spec/crypto.md §4 (Floors: a dependent thing's epoch reads its base epoch's floor), §5 (Passing
// on): T, a dependent thing minted with admin `g`, has content from before A's cut for N. A seals T's content
// under the cut's derived epoch at the cut's floor, so T's commit from before it is neither
// wrapped nor sealed again there, and A owes T's state a snapshot as `g`'s own.
#[test]
fn dependent_thing_below_a_cut_keeps_its_floor_spec_crypto_4() {
    let mut lp = synced(2);
    let n = lp.peers[1].engine.me();
    let g = independent_thing(&mut lp, 0);
    let t = {
        let mut m = crate::Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, g);
        lp.peers[0].commit(m).unwrap();
        lp.hold(t);
        t
    };
    put(&mut lp, 0, t, "before");
    let old = edits_on(&lp, 0, t);
    lp.peers[0].engine.grant_with(&g, &n, &edge(Role::Read), History::None).unwrap();
    let cut = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    let (_, f) = lp.peers[0].engine.core.seal_epoch(&t).unwrap();
    assert_eq!(f, cut.n(), "T's content is sealed below the cut's floor");
    for c in &old {
        let parts: Vec<usize> = (0..lp.peers[0].engine.header(c).unwrap().aspects.len()).collect();
        assert!(lp.peers[0].engine.wrap_secret(&g, Some((c, &parts))).unwrap().is_none(), "T's commit from before the cut is wrapped under it");
    }
    assert!(lp.sealed(0, &old.iter().copied().collect::<Vec<_>>()).unwrap().is_empty(), "T's commit from before the cut is sealed again under it");
    let snaps = lp.peers[0].engine.core.ix.snapshots.get(&(t, osis_base::Ak::new("x:m.0").unwrap())).map_or(0, |s| s.len());
    assert_eq!(snaps, 1, "A writes no snapshot of T's state at the cut");
}

// spec/crypto.md §4 (State at a cut): the cut's snapshots carry state, not history: a thing with
// 8 aspects, each written 3 or 30 times over (its state the same), costs the same commits and
// bytes at the cut; one snapshot per aspect holding state, none for a signal.
#[test]
fn cut_state_cost_does_not_grow_with_history_spec_crypto_4() {
    let cost = |rounds: usize| {
        let mut lp = synced(2);
        let n = lp.peers[1].engine.me();
        let g = independent_thing(&mut lp, 0);
        for r in 0..rounds {
            let mut m = crate::Mutation::new();
            for a in 0..8 {
                m.op(g, &osis_base::Ak::new(format!("x:a{a}.0")).unwrap(), osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Set(osis_base::Value::Str(format!("value {}", if r + 1 == rounds { "last" } else { "earlier" }))) }).unwrap();
            }
            lp.peers[0].commit(m).unwrap();
        }
        let before: BTreeSet<osis_base::CommitId> = lp.peers[0].engine.core.ix.commits.keys().copied().collect();
        lp.peers[0].engine.grant_with(&g, &n, &edge(Role::Read), History::None).unwrap();
        let new: Vec<_> = lp.commit_ids(0).into_iter().filter(|c| !before.contains(c)).map(|c| lp.peers[0].engine.package(&c).unwrap().unwrap()).collect();
        let snaps: Vec<_> = new.iter().filter(|pk| osis_commit::CommitBlob::decode(&pk.bytes).unwrap().header.kind.is_compaction()).collect();
        let bytes: usize = snaps.iter().map(|pk| pk.bytes.len()).sum();
        eprintln!("rounds {rounds}: {} commits at the cut, {} snapshots, {bytes} snapshot bytes", new.len(), snaps.len());
        (new.len(), snaps.len(), bytes)
    };
    let (small, big) = (cost(3), cost(30));
    assert_eq!(small.1, 8, "one snapshot per aspect holding state");
    assert_eq!((small.0, small.1), (big.0, big.1), "the cut's commits grow with history");
    assert!(big.2 <= small.2 + 8 * 4, "the cut's snapshot bytes grow with history: {} against {}", big.2, small.2);
}

/// The compaction snapshots peer `i` wrote itself.
fn own_snapshots(lp: &LocalPeer, i: usize) -> usize {
    let e = &lp.peers[i].engine;
    let me = e.me();
    e.core.ix.commits.values().filter(|m| m.header.kind.is_compaction() && m.view.signer == me).count()
}

// spec/crypto.md §4 (State at a cut): a writer granted with history after a cut (or a new node
// of any writer) fetches the role commits first, then the bodies from before the cut, the cut's
// snapshots after them (a first sync goes by order, spec/crypto.md §5 Order). Those bodies are covered by the
// cut's snapshots, so it owes no snapshot of its own: it writes none, however its fetch is cut
// into steps (the test writes owed snapshots after each, as a pass end would).
#[test]
fn late_bodies_a_cut_covers_owe_no_snapshot_spec_crypto_4() {
    let mut lp = synced(3);
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, 0);
    let mut logged = Logged::default();
    for r in 0..3 {
        let mut m = crate::Mutation::new();
        for a in 0..4 {
            m.op(g, &osis_base::Ak::new(format!("x:a{a}.0")).unwrap(), osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Set(osis_base::Value::Str(format!("value {r}"))) }).unwrap();
        }
        lp.peers[0].commit(m).unwrap();
        logged.log(&mut lp, g, &[0]);
    }
    let cut = lp.peers[0].engine.grant_with(&g, &tids[1], &edge(Role::Read), History::None).unwrap();
    let _ = cut;
    logged.log(&mut lp, g, &[0]);
    let done = lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Write)).unwrap();
    logged.log(&mut lp, g, &[0]);
    let snaps_a = own_snapshots(&lp, 0);
    assert_eq!(snaps_a, 4, "A writes the state at its cut");
    // W: its grant and A's commits off `g` whole, then `g`'s sync IDs in `ts` order, one step each
    for c in &done.commits {
        let pk = lp.peers[0].engine.package(c).unwrap().unwrap();
        let _ = lp.peers[2].receive(&pk.bytes, pk.blobs.clone());
    }
    for pk in lp.packages_for(0, 2).unwrap() {
        if !on_g(&pk, g) {
            let _ = lp.peers[2].receive(&pk.bytes, pk.blobs.clone());
        }
    }
    let mut held = logged.held.clone();
    // spec/crypto.md §5 Order: role commits first (order 0), then by `ts`
    held.sort_by_key(|pk| lp.peers[0].engine.header(&pk.id).map(|h| (!matches!(h.kind, osis_commit::Kind::Role), h.ts)));
    for pk in &held {
        lp.deliver_sealed(2, std::slice::from_ref(pk)).unwrap();
        lp.peers[2].engine.purge_resnapshots().unwrap();
    }
    lp.deliver_sealed(2, &held).unwrap();
    lp.peers[2].engine.purge_resnapshots().unwrap();
    lp.peers[2].engine.reseal_after_pass(&g).unwrap();
    for a in 0..4 {
        let ak = osis_base::Ak::new(format!("x:a{a}.0")).unwrap();
        assert_eq!(lp.peers[2].engine.get(&g, &ak).unwrap(), Some(osis_base::Value::Str("value 2".into())), "W reads another state");
    }
    assert_eq!(own_snapshots(&lp, 2), 0, "W snapshots state the cut's snapshots carry");
}

// spec/crypto.md §4 (State at a cut), spec/sync-ids.md §1 (Chunk reuse): a large value written
// before a cut reaches its holder through the cut's snapshot, which links the value's chunk
// tree as written: the snapshot is a few hundred bytes and no chunk is encrypted again.
#[test]
fn cut_snapshot_of_a_large_value_reuses_its_chunks_spec_crypto_4() {
    let mut lp = synced(2);
    let n = lp.peers[1].engine.me();
    let g = independent_thing(&mut lp, 0);
    let ak = osis_base::Ak::new("x:b.0").unwrap();
    let mut x = vec![0u8; 1 << 20];
    osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(3), &mut x);
    let mut m = crate::Mutation::new();
    m.set(g, &ak, &osis_base::Value::Bytes(x.clone())).unwrap();
    lp.peers[0].commit(m).unwrap();
    let tree: BTreeSet<_> = lp.peers[0].engine.live_trees(&g).unwrap().blobs.into_iter().collect();
    assert!(tree.len() > 4, "the value is chunked");
    let before: BTreeSet<osis_base::CommitId> = lp.peers[0].engine.core.ix.commits.keys().copied().collect();
    lp.peers[0].engine.grant_with(&g, &n, &edge(Role::Read), History::None).unwrap();
    let snaps: Vec<_> = lp.commit_ids(0).into_iter().filter(|c| !before.contains(c)).map(|c| lp.peers[0].engine.package(&c).unwrap().unwrap()).filter(|pk| osis_commit::CommitBlob::decode(&pk.bytes).unwrap().header.kind.is_compaction()).collect();
    assert_eq!(snaps.len(), 1, "one snapshot of the value");
    let s = &snaps[0];
    eprintln!("snapshot of a 1 MiB value: {} bytes, {} linked blobs", s.bytes.len(), s.blobs.len());
    assert!(s.bytes.len() < 2048, "the snapshot carries the value: {} bytes", s.bytes.len());
    assert!(s.blobs.iter().all(|(b, _)| tree.contains(b)), "the snapshot encrypts a chunk again");
    assert_eq!(lp.peers[0].engine.live_trees(&g).unwrap().blobs.into_iter().collect::<BTreeSet<_>>(), tree, "the value's tree changed");
}

static BIG: osis_schema::StaticSchema = osis_schema::StaticSchema::new("cutbig.osis", "revision 1; purgeable_by(author, admin) aspect k:b.0: blob;\n");

// spec/sync-ids.md §1 (Repair carries current state), spec/crypto.md §5 (Passing on: floors):
// after a cut, a repair is written as state is: it rewrites the aspect's live value where that
// value's tree reaches a lost chunk, so the floor clause does not hold it back; a chunk only a
// replaced version reaches (history, kept) is never passed on, under the cut's epoch or any.
#[test]
fn a_repair_after_a_cut_passes_on_live_state_alone_spec_sync_ids_1() {
    let mut lp = synced(2);
    let n = lp.peers[1].engine.me();
    let g = independent_thing(&mut lp, 0);
    let key: osis_schema::Aspect<osis_base::Value> = osis_schema::Aspect::new("k:b.0", &BIG);
    let ak = osis_base::Ak::new("k:b.0").unwrap();
    let mut m = crate::Mutation::new();
    m.set(g, &osis_schema::core_types::RETENTION, &osis_schema::core_types::RetentionSetting::of(ak.clone(), osis_schema::History::Keep { until: Some(4_000_000_000_000), after: None })).unwrap();
    lp.peers[0].commit(m).unwrap();
    let mut v = vec![0u8; 256 << 10];
    osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(9), &mut v);
    let write = |lp: &mut LocalPeer, v: &[u8]| {
        let mut m = crate::Mutation::new();
        m.set(g, &key, &osis_base::Value::Bytes(v.to_vec())).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.peers[0].engine.live_trees(&g).unwrap().blobs
    };
    let first = write(&mut lp, &v);
    let n_len = v.len();
    v[n_len - 4..].copy_from_slice(b"edit");
    let second = write(&mut lp, &v);
    let replaced: BTreeSet<osis_base::BlobId> = first.difference(&second).copied().collect();
    let shared: BTreeSet<osis_base::BlobId> = first.intersection(&second).copied().collect();
    assert!(!replaced.is_empty() && !shared.is_empty(), "the edit reuses chunks and replaces some");
    lp.peers[0].engine.grant_with(&g, &n, &edge(Role::Read), History::None).unwrap();
    let lost: BTreeSet<osis_base::BlobId> = replaced.iter().chain(&shared).copied().collect();
    let e = &mut lp.peers[0].engine;
    assert!(replaced.iter().all(|b| e.read(|tx| tx.blobs.held(b)).unwrap()), "the replaced version is kept");
    let c = e.relink(&lost, &[g].into(), &mut |_, _| true).unwrap().expect("a repair after the cut");
    let now = e.live_trees(&g).unwrap().blobs;
    assert!(now.is_disjoint(&lost), "the repair links no lost chunk");
    let parts: crate::sync::PartSet = (0..e.header(&c).unwrap().aspects.len()).collect();
    let mut linked = BTreeSet::new();
    let mut todo = e.piece_roots(&c, &parts).unwrap();
    while let Some(p) = todo.pop() {
        if linked.insert(p.blob()) {
            todo.extend(e.piece_below(&p).unwrap().map(|k| k.to_vec()).unwrap_or_default());
        }
    }
    assert!(linked.is_disjoint(&replaced), "a chunk only the replaced version reaches is passed on");
    assert!(!linked.is_empty() && linked.is_subset(&now), "the repair carries the live value");
}

/// Peer `i` writes key `k` on `g`'s `x:m.0`, expiring at `t` (wall ms), a commit of its own.
fn put_expiring(lp: &mut LocalPeer, i: usize, g: Tid, k: &str, t: u64) {
    let ak = osis_base::Ak::new("x:m.0").unwrap();
    let mut m = crate::Mutation::new();
    m.op(g, &ak, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(osis_base::Value::Str(k.into()))], op: osis_crdt::Op::Put(osis_base::Value::Int(1)) }).unwrap();
    m.expires(g, &ak, osis_base::WallMs(t)).unwrap();
    lp.peers[i].commit(m).unwrap();
}

/// `content` after peer `i`'s due timers ran.
fn content_now(lp: &mut LocalPeer, i: usize, g: Tid) -> BTreeSet<String> {
    lp.peers[i].tick().unwrap();
    content(lp, i, g)
}

fn keys(v: &[&str]) -> BTreeSet<String> {
    v.iter().map(|s| s.to_string()).collect()
}

// spec/commits.md §5 Covered, spec/crdt.md §8: who can write an expiring snapshot's expiry. H, a
// writer, writes one carrying A's lasting value "x" valued and ending in 10 s (any writer may:
// a valid snapshot vouches for what it carries). B, a reader holding A's delta, never counts the
// delta covered by it, so past that expiry B still reads "x": a forged expiry drops no value
// early at an honest node holding the value's own delta. Fails with expiring snapshots covering.
#[test]
fn forged_expiring_snapshot_ends_no_lasting_value_spec_commits_5() {
    let mut lp = synced(3);
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
    put(&mut lp, 0, g, "x");
    lp.sync_all().unwrap();
    let ak = osis_base::Ak::new("x:m.0").unwrap();
    let t = lp.peers[1].engine.now().0 + 10_000;
    let forged = lp.peers[1]
        .engine
        .run(|tx| {
            let st = tx.state(&g, &ak)?.cloned().unwrap();
            let (ts, node) = (tx.core.hlc.next(), tx.core.writer_for(&g)?);
            crate::retention::snapshot::build_snapshot(tx, g, ak.clone(), st, ts, node, Default::default(), Default::default(), Some(t), false)
        })
        .unwrap();
    let pk = lp.peers[1].engine.package(&forged).unwrap().unwrap();
    lp.peers[2].receive(&pk.bytes, pk.blobs.clone()).unwrap();
    let held: Vec<osis_base::CommitId> = edits_on(&lp, 2, g).into_iter().collect();
    // node-sync drops each body a held snapshot covers
    for c in &held {
        if lp.peers[2].engine.covered(&forged, c, &g, &ak).unwrap() == Some(true) {
            lp.peers[2].engine.drop_body(c, &g, &ak).unwrap();
        }
    }
    lp.advance(20_000);
    assert_eq!(content_now(&mut lp, 2, g), keys(&["x"]), "a forged expiry ends a lasting value at B");
}

// spec/commits.md §5 Covered, spec/crdt.md §8: what a cut's expiring snapshots cost over many
// cuts. A writes "e" (expiring in 100 s) and cuts for N, then for M: each cut writes an expiring
// snapshot ending with "e", and the second covers the first (both end then), so one per expiry
// and aspect stays however many cuts are made; neither covers "e"'s own delta (it may outlive an
// expiring snapshot claiming a sooner end). Fails with expiring snapshots covering nothing (the
// cuts' snapshots pile up until "e" ends).
#[test]
fn each_cut_replaces_the_last_cuts_expiring_snapshots_spec_commits_5() {
    let mut lp = synced(3);
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, 0);
    let ak = osis_base::Ak::new("x:m.0").unwrap();
    let t = lp.peers[0].engine.now().0 + 100_000;
    put_expiring(&mut lp, 0, g, "e", t);
    let delta = *edits_on(&lp, 0, g).iter().next().unwrap();
    let ending = |lp: &LocalPeer| -> Vec<osis_base::CommitId> {
        let e = &lp.peers[0].engine;
        e.core.ix.by_aspect.get(&(g, ak.clone())).into_iter().flatten().map(|x| x.1).filter(|c| e.header(c).is_some_and(|h| h.kind.is_compaction() && h.expires == Some(t))).collect()
    };
    for to in &tids[1..] {
        lp.advance(10);
        lp.peers[0].engine.grant_with(&g, to, &edge(Role::Read), History::None).unwrap();
    }
    let x = ending(&lp);
    assert_eq!(x.len(), 2, "each cut writes an expiring snapshot ending with the value");
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.covered(&x[1], &x[0], &g, &ak).unwrap(), Some(true), "a cut's expiring snapshot does not replace the last cut's");
    assert_eq!(e.covered(&x[0], &x[1], &g, &ak).unwrap(), Some(false));
    for s in &x {
        assert_eq!(e.covered(s, &delta, &g, &ak).unwrap(), Some(false), "an expiring snapshot covers a delta");
    }
}

// spec/crdt.md §4.7, §8, spec/commits.md §5 Covered, §6: randomized differential over expiring
// snapshots. A writes lasting and expiring map keys and register values, compacts, and writes
// the expiring snapshots a cut writes (`write_expiring`); H, a writer, forges snapshots of its
// whole state: expiring at a random time, or lasting with every value it holds (a writer's
// snapshot vouches for what it carries). R1 (a reader) and R2 (a writer) get every snapshot and the same random half
// of the deltas (a holder granted without history holds no delta from before its cut), in
// phases, each in its own random order; R2 restarts at random, drops every body a held
// snapshot covers and compacts. Between phases time passes. Holding the same commits but what R2 dropped as
// covered, R1 and R2 read alike at every point, R1 reads no value of a delta whose header it
// holds past that delta's expiry, and, where H forged no lasting snapshot of the map, none at all
// once every expiry has passed. Fails with an expiring snapshot covering a body of
// another expiry or a lasting one, with a value R holds only from expiring snapshots kept
// valued in R2's own snapshot, and with an expiring snapshot's values kept past its expiry.
#[test]
#[ignore = "property"]
fn expiring_snapshots_read_alike_whatever_arrives_and_is_covered_plain_spec_crdt_8() {
    let (m_ak, r_ak) = (osis_base::Ak::new("x:m.0").unwrap(), osis_base::Ak::new("x:r.0").unwrap());
    let (mut compared, mut dropped, mut ended) = (0, 0, 0);
    for seed in 1..=10u64 {
        let mut rng = super::tests::Rng(seed * 0x9e37_79b9 + 11);
        let mut lp = synced(4);
        let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
        let g = independent_thing(&mut lp, 0);
        lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Write)).unwrap();
        lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
        lp.peers[0].engine.grant(&g, &tids[3], &edge(Role::Write)).unwrap();
        lp.sync_all().unwrap();
        let start: BTreeSet<osis_base::CommitId> = lp.peers[0].engine.core.ix.commits.keys().copied().collect();
        // key name -> (its commit, its expiry)
        let mut expiring_keys: Vec<(String, osis_base::CommitId, u64)> = Vec::new();
        // whether H forged a lasting snapshot (its copies of expiring values then last where
        // their delta's header is not held)
        let mut lasting_forged = false;
        for step in 0..14 {
            lp.advance(1 + rng.next(3_000));
            let now = lp.peers[0].engine.now().0;
            let t = now + 1_000 * (1 + rng.next(4)) * 5;
            match rng.next(9) {
                0 | 1 => put(&mut lp, 0, g, &format!("k{step}")),
                2 | 3 => {
                    let k = format!("e{step}");
                    let mut m = crate::Mutation::new();
                    m.op(g, &m_ak, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(osis_base::Value::Str(k.clone()))], op: osis_crdt::Op::Put(osis_base::Value::Int(1)) }).unwrap();
                    m.expires(g, &m_ak, osis_base::WallMs(t)).unwrap();
                    let c = lp.peers[0].commit(m).unwrap().unwrap();
                    expiring_keys.push((k, c, t));
                }
                4 => {
                    let mut m = crate::Mutation::new();
                    m.op(g, &r_ak, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Set(osis_base::Value::Int(step)) }).unwrap();
                    if rng.next(2) == 0 {
                        m.expires(g, &r_ak, osis_base::WallMs(t)).unwrap();
                    }
                    lp.peers[0].commit(m).unwrap();
                }
                5 => {
                    let ak = if rng.next(2) == 0 { &m_ak } else { &r_ak };
                    let _ = lp.peers[0].engine.snapshot(&g, ak).unwrap();
                    lp.peers[0]
                        .engine
                        .run(|tx| {
                            let owed: BTreeSet<osis_base::CommitId> = tx.core.ix.by_aspect.get(&(g, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
                            crate::retention::snapshot::write_expiring(tx, &g, ak, &owed)
                        })
                        .unwrap();
                }
                6 | 7 => {
                    lp.sync(0, 1).unwrap();
                    let ak = if rng.next(2) == 0 { &m_ak } else { &r_ak };
                    let ends = (rng.next(3) > 0).then_some(t + 1_000 * rng.next(3) * 5 - 5_000 * rng.next(2));
                    lasting_forged |= ends.is_none() && ak == &m_ak;
                    lp.peers[1]
                        .engine
                        .run(|tx| {
                            let Some(st) = tx.state(&g, ak)?.cloned() else { return Ok(None) };
                            let (ts, node) = (tx.core.hlc.next(), tx.core.writer_for(&g)?);
                            let ends = ends.filter(|e| *e > ts.wall_ms().0);
                            crate::retention::snapshot::build_snapshot(tx, g, ak.clone(), st, ts, node, Default::default(), Default::default(), ends, false).map(Some)
                        })
                        .unwrap();
                }
                _ => lp.sync(1, 0).unwrap(),
            }
        }
        lp.sync(1, 0).unwrap();
        // every commit on g past the setup: each snapshot, half the deltas
        let mut sent: Vec<osis_base::CommitId> = Vec::new();
        for (c, m) in lp.peers[0].engine.core.ix.commits.iter() {
            if start.contains(c) || !m.header.aspects.iter().any(|a| a.tid == g && (a.ak == m_ak || a.ak == r_ak)) {
                continue;
            }
            if m.header.kind.is_compaction() || rng.next(2) == 0 {
                sent.push(*c);
            }
        }
        let shuffled = |rng: &mut super::tests::Rng, v: &[osis_base::CommitId]| {
            let mut v = v.to_vec();
            for i in (1..v.len()).rev() {
                v.swap(i, rng.next(i as u64 + 1) as usize);
            }
            v
        };
        let sent = shuffled(&mut rng, &sent);
        let pks: Vec<_> = sent.iter().map(|c| (*c, lp.peers[0].engine.package(c).unwrap().unwrap())).collect();
        let phases = 1 + rng.next(3) as usize;
        let per = pks.len().div_ceil(phases).max(1);
        let read = |lp: &mut LocalPeer, i: usize| (lp.peers[i].engine.get(&g, &m_ak).unwrap(), lp.peers[i].engine.get(&g, &r_ak).unwrap());
        let mut check = |lp: &mut LocalPeer, what: &str| {
            for i in [2, 3] {
                lp.peers[i].tick().unwrap();
            }
            assert_eq!(read(lp, 2), read(lp, 3), "seed {seed}: R1 and R2 read apart {what}");
            let now = lp.peers[2].engine.now().0;
            let keys = content(lp, 2, g);
            for (k, c, t) in &expiring_keys {
                let held = lp.peers[2].engine.header(c).is_some();
                assert!(!(held && now >= *t && keys.contains(k)), "seed {seed}: {k} read past its expiry {what}");
            }
            compared += 1;
        };
        for (ph, batch) in pks.chunks(per).enumerate() {
            for (c, pk) in batch {
                let _ = lp.peers[2].receive(&pk.bytes, pk.blobs.clone());
                let _ = c;
            }
            let ids: Vec<osis_base::CommitId> = batch.iter().map(|x| x.0).collect();
            for c in shuffled(&mut rng, &ids) {
                let pk = &batch.iter().find(|x| x.0 == c).unwrap().1;
                let _ = lp.peers[3].receive(&pk.bytes, pk.blobs.clone());
            }
            if rng.next(2) == 0 {
                lp.peers[3].restart(seed).unwrap();
            }
            // R2 drops every body a held snapshot covers (node-sync's compaction)
            for ak in [&m_ak, &r_ak] {
                let on: Vec<osis_base::CommitId> = lp.peers[3].engine.core.ix.by_aspect.get(&(g, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
                let snaps: Vec<osis_base::CommitId> = on.iter().copied().filter(|s| lp.peers[3].engine.header(s).is_some_and(|h| h.kind.is_compaction())).collect();
                for s in &snaps {
                    for c in &on {
                        if c != s && lp.peers[3].engine.covered(s, c, &g, ak).unwrap() == Some(true) {
                            let _ = lp.peers[3].engine.drop_body(c, &g, ak);
                            if lp.peers[3].engine.header(c).is_some_and(|h| h.kind.is_compaction() && h.expires.is_some()) {
                                dropped += 1;
                            }
                        }
                    }
                }
                // and compacts: its snapshot carries no value it holds from expiring snapshots alone
                if rng.next(2) == 0 {
                    let _ = lp.peers[3].engine.snapshot(&g, ak).unwrap();
                }
            }
            check(&mut lp, &format!("after phase {ph}"));
            lp.advance(rng.next(12_000));
            check(&mut lp, &format!("after phase {ph}, time passed"));
        }
        lp.advance(60_000);
        check(&mut lp, "past every expiry");
        // with no forged lasting copy, every expiring value has ended, held from its delta or
        // from expiring snapshots alone
        if !lasting_forged {
            let keys = content(&mut lp, 2, g);
            assert!(keys.iter().all(|k| !k.starts_with('e')), "seed {seed}: an expiring value outlives every expiry: {keys:?}");
            ended += 1;
        }
    }
    assert!(compared >= 30 && dropped >= 3 && ended >= 3, "only {compared} comparisons, {dropped} expiring snapshots dropped as covered, {ended} seeds with every value ended");
}
