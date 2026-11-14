//! Grants without history (spec/crypto.md §4, Floors): a cut, a floor per keyset, the carry and
//! boxing rules. What every test checks is what a user observes: which secrets of the actor a
//! party's nodes hold or can open from the actor's `secrets.0` (a new node of it included).

#![allow(clippy::unwrap_used)]
use super::tests::{Key, Pass, edge, granted, group, openable, rotate_leaving_out, synced};
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
            n += lp.peers[p].engine.reseal_due(&g, &Pass).map(|x| x.commits.len()).unwrap_or(0);
            lp.sync_all().unwrap();
        }
        if n == 0 {
            return;
        }
    }
    panic!("no fixpoint in 8 rounds");
}

/// Peers: 0 = admin A (`g`'s first admin), 1 = reader P (with history), 2 = N (granted without
/// history by A once `g` has `before` read epochs past its first). Returns the peers, `g`, the
/// tids and the cut's epoch.
fn cut_world(before: usize) -> (LocalPeer, Tid, Vec<Tid>, Epoch) {
    let mut lp = synced(3);
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
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
    let g = group(&mut lp, 0);
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

// spec/crypto.md §4 (Floors; model X_cut): A cuts for N while B, not holding the grant, rotates
// beside it; P adds history, A merges. N gets neither an epoch before its cut nor B's fork (its
// history opens the past), and reads the merge.
#[test]
fn fork_beside_the_cut_never_reaches_the_newcomer_spec_crypto_4() {
    let mut lp = synced(5);
    let tids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
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

// spec/crypto.md §4 (the boxing rule, Current; model X_cut_nofloor): B holds A's cut but not the
// rotation before it, so the epoch before that is current at B beside the cut. B's re-seals box
// N at no epoch below N's floor, and N counts none current; B rotates over it instead (a low
// floor), boxing N.
#[test]
fn holder_lacking_the_rotation_before_the_cut_reseals_nothing_below_it_spec_crypto_4() {
    let mut lp = synced(4);
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let before = super::tests::commit_ids(&mut lp, 0);
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from(READ), &[]);
    let r1: BTreeSet<osis_base::CommitId> = super::tests::commit_ids(&mut lp, 0).difference(&before).copied().collect();
    lp.peers[0].engine.grant_with(&g, &tids[3], &edge(Role::Read), History::None).unwrap();
    let cut = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
    for pk in lp.packages(0).unwrap() {
        if !r1.contains(&pk.id) {
            lp.deliver(1, &pk).unwrap();
        }
    }
    for pk in lp.packages(0).unwrap() {
        if !r1.contains(&pk.id) {
            lp.deliver(3, &pk).unwrap();
        }
    }
    // N holds the cut and the epoch the missing rotation superseded, established (its secret not
    // held, no names needed): below N's floor, it is no current epoch of N's
    assert_eq!(lp.peers[3].engine.epochs(&g).unwrap().read.current(), vec![cut], "N counts an epoch below its floor current");
    let at_b = lp.peers[1].engine.epochs(&g).unwrap().read.current();
    assert!(at_b.len() > 1 && at_b.contains(&cut), "the epoch before the rotation is not current at B beside the cut: {at_b:?}");
    lp.peers[1].engine.reseal_due(&g, &Pass).unwrap();
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
    let g = group(&mut lp, 0);
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

// spec/crypto.md §4 (the carry rule judges the maker; model X_host_nomaker): H, granted write
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

// spec/crypto.md §4 (a floor above n is read as n; model X_cap_nocap): W, a writer with
// history, rotates writing a floor far above its n; A rotates over it, then cuts for N, then
// rotates again. A's last rotation carries no epoch before the cut to N.
#[test]
fn floor_above_n_carries_nothing_past_a_later_cut_spec_crypto_4() {
    let mut lp = synced(4);
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
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

// spec/crypto.md §4 (Floors: an epoch's floor is what its entries write; a rotation's, the
// greatest of its maker's and its holders'): W, a writer with history, rotates after N's cut
// listing the cut with floor 0, so co-holders carry what came before into W's epoch. N is never
// boxed there (a writer may leave anyone out), reaches nothing before its cut, and reads A's
// next epoch, which carries neither W's epoch nor anything before the cut.
#[test]
fn low_floor_over_the_cut_hands_the_newcomer_nothing_before_it_spec_crypto_4() {
    let mut lp = synced(4);
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
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
fn nothing_before_a_cut_reaches_its_holder_spec_crypto_4() {
    osis_base::testenv::run_seeds("rotation::tests_cut::nothing_before_a_cut_reaches_its_holder_spec_crypto_4", &NOTHING_BEFORE_SEEDS, false, cut_replay("nothing_before_a_cut_reaches_its_holder_large_spec_crypto_4"), nothing_before_a_cut);
}

/// The default test's seeds, a covering set: with the boxing or the carry rule off, every one of
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

/// One seed of `nothing_before_a_cut_reaches_its_holder_spec_crypto_4`.
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
                let _ = lp.peers[p].engine.reseal_due(&g, &Pass);
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
        let _ = lp.peers[p].engine.reseal_due(&g, &Pass);
    }
    lp.sync_all().unwrap();
    for (who, known) in &before {
        for i in 0..5 {
            let bad: Vec<Epoch> = reaches(&mut lp, i, g, tids[*who]).intersection(known).copied().collect();
            assert!(bad.is_empty(), "seed {seed}: peer {i}'s state hands peer {who} {bad:?}, held before its cut");
        }
    }
}

/// Whether package `pk` has an aspect on `g` other than its creation record: one `g`'s labels
/// carry sealed.
fn on_g(pk: &crate::local_peer::Package, g: Tid) -> bool {
    aspect_on_g(&osis_commit::CommitBlob::decode(&pk.bytes).unwrap().header, g)
}

/// `on_g` of a commit's header.
fn aspect_on_g(h: &osis_commit::Header, g: Tid) -> bool {
    h.aspects.iter().any(|a| a.tid == g && a.ak.as_str() != "created.0")
}

/// What `g`'s labels hold: each commit on `g` sealed once, by the first peer to place it, under
/// its wrap epoch then (`LocalPeer::sealed`, as node-sync places a body soon after it is made
/// or received).
#[derive(Default)]
struct Label {
    placed: BTreeSet<osis_base::CommitId>,
    held: Vec<crate::local_peer::SealedPackage>,
    /// The commits flows owed to a party's inbox (or node), by recipient.
    inbox: BTreeSet<(Tid, osis_base::CommitId)>,
}

impl Label {
    /// Notes the inbox and direct deliveries `done` owes.
    fn note(&mut self, done: &crate::flows::Done) {
        for d in &done.deliveries {
            match d {
                crate::flows::Delivery::Inbox { to, resend, .. } => {
                    self.inbox.insert((*to, resend.commit));
                }
                crate::flows::Delivery::Direct { to, commits } => self.inbox.extend(commits.iter().map(|c| (*to, *c))),
                _ => {}
            }
        }
    }

    /// Peers `among` place what they hold that is not placed yet, after the rotations due
    /// before they encrypt (noted).
    fn place(&mut self, lp: &mut LocalPeer, g: Tid, among: &[usize]) {
        for &p in among {
            if let Ok((d, _)) = lp.peers[p].engine.ensure_rotated(&g) {
                self.note(&d);
            }
            let e = &lp.peers[p].engine;
            let ids: Vec<osis_base::CommitId> = e.commit_ids().into_iter().filter(|id| !self.placed.contains(id) && e.header(id).is_some_and(|h| aspect_on_g(&h, g))).collect();
            if ids.is_empty() {
                continue;
            }
            for pk in lp.sealed(p, &ids).unwrap() {
                if self.placed.insert(pk.id) {
                    self.held.push(pk);
                }
            }
        }
    }
}

/// Delivers to peer `to` what a history-less holder of `g` gets: its grant's commits (`done`, by
/// peer `from`) and those owed to its inbox (`label.inbox`), whole; `from`'s commits with no
/// aspect on `g` but its creation record, raw; and what `g`'s labels hold (`label`), sealed as
/// placed: `to` opens what its secrets and roles secrets open (spec/crypto.md §4, Roles secrets),
/// so of what was placed before its cut only the `roles.0` sections.
fn deliver_as_newcomer(lp: &mut LocalPeer, from: usize, to: usize, g: Tid, done: &crate::flows::Done, label: &Label) {
    let me = lp.peers[to].engine.me();
    let inbox = label.inbox.iter().filter(|(t, _)| *t == me).map(|x| x.1);
    for c in done.commits.iter().copied().chain(inbox) {
        if let Some(pk) = lp.peers[from].engine.package(&c).unwrap() {
            let _ = lp.peers[to].receive(&pk.bytes, pk.blobs.clone());
        }
    }
    for pk in lp.packages(from).unwrap() {
        if !on_g(&pk, g) {
            let _ = lp.peers[to].receive(&pk.bytes, pk.blobs.clone());
        }
    }
    let left = lp.deliver_sealed(to, &label.held).unwrap();
    if std::env::var("OSIS_CUT_DUMP").is_ok() {
        for c in left {
            let h = lp.peers[from].engine.header(&c).unwrap();
            eprintln!("unopened {c:?}: {:?}", h.aspects.iter().map(|a| (a.tid, a.ak.as_str().to_string())).collect::<Vec<_>>());
        }
    }
}

// spec/crypto.md §4 (Roles secrets; model X_names): A removes P, then cuts for N. N opens
// nothing under `g`'s labels from before the cut but the role parts, under the roles secrets the
// cut's history entry carries: it meets the cut's names (P's removal) by them, establishes the cut
// and reads it, and counts no epoch before it current. With P a writer, the cut's keyset carries
// P's demotion (Carried demotions): N holds that keyset only once it opened the demotion by those
// same roles secrets, so its box at the cut must open before the keyset is held.
#[test]
fn cut_after_a_removal_establishes_at_the_newcomer_spec_crypto_4() {
    for role in [Role::Read, Role::Write] {
        let mut lp = synced(3);
        let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
        let g = group(&mut lp, 0);
        let mut label = Label::default();
        lp.peers[0].engine.grant(&g, &tids[1], &edge(role)).unwrap();
        label.place(&mut lp, g, &[0]);
        lp.sync_all().unwrap();
        lp.peers[0].engine.demote(&g, &crate::flows::Demotion { holder: tids[1], new: None, retain: None }).unwrap();
        label.place(&mut lp, g, &[0]);
        let done = lp.peers[0].engine.grant_with(&g, &tids[2], &edge(Role::Read), History::None).unwrap();
        let cut = lp.peers[0].engine.epochs(&g).unwrap().read.newest_held().unwrap().0;
        label.place(&mut lp, g, &[0]);
        deliver_as_newcomer(&mut lp, 0, 2, g, &done, &label);
        let e = lp.peers[2].engine.epochs(&g).unwrap();
        assert!(e.read.is_established(&cut), "{role:?}: N does not establish the cut");
        assert_eq!(e.read.current(), vec![cut], "{role:?}: N's current epochs");
        assert!(e.read.secret(&cut).is_some(), "{role:?}: N lacks the cut's secret");
    }
}

/// Peers 0 = admin A, 1 = admin B (granted without history when `b_cut`, after M's removal),
/// 2 = M (a reader). A rotates `g` once, removes M (its rotation R), rotates again (an epoch made
/// knowing the removal). Returns the peers, `g`, the tids, what M read before its removal (every
/// read epoch held then) and the epochs made since (R's and the one after).
fn removed_member(b_cut: bool) -> (LocalPeer, Tid, Vec<Tid>, BTreeSet<Epoch>, BTreeSet<Epoch>) {
    let mut lp = synced(3);
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
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

// spec/crypto.md §4 (Floors: re-added without history; models X_readd, X_readd_fresh, X_gone):
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

// spec/crypto.md §4 (Floors), spec/commits.md §5 (The setting, One way): A sets `g`'s history
// setting twice (purge on replace for one AK, then keep for it and another), then cuts for N. N
// opens neither setting, yet holds the setting in force as it reads: the voided keep as no
// history, the other keep as kept.
#[test]
fn cut_newcomer_holds_the_setting_in_force_spec_commits_5() {
    use osis_schema::History as Kept;
    use osis_schema::core_types::{RETENTION, RetentionEntry, RetentionSetting};
    let mut lp = synced(2);
    let tids: Vec<Tid> = (0..2).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    let (x, y) = (osis_base::Ak::new("note.0").unwrap(), osis_base::Ak::new("body.0").unwrap());
    let keep = RetentionEntry { history: Some(Kept::Keep { until: None, after: Some(1000) }), expires: None, r#final: false };
    let purge = RetentionEntry { history: Some(Kept::PurgeOnReplace), expires: None, r#final: false };
    let mut label = Label::default();
    for s in [RetentionSetting { rules: [(x.clone(), purge)].into(), ..Default::default() }, RetentionSetting { rules: [(x.clone(), keep), (y.clone(), keep)].into(), ..Default::default() }] {
        let mut m = crate::Mutation::new();
        m.set(g, &RETENTION, &s).unwrap();
        lp.peers[0].commit(m).unwrap();
        label.place(&mut lp, g, &[0]);
        lp.advance(10);
    }
    let done = lp.peers[0].engine.grant_with(&g, &tids[1], &edge(Role::Read), History::None).unwrap();
    label.place(&mut lp, g, &[0]);
    deliver_as_newcomer(&mut lp, 0, 1, g, &done, &label);
    let s = lp.peers[1].engine.run(|tx| Ok(crate::apply::validity::setting_now(tx.core, &g))).unwrap().expect("N holds no setting");
    assert_eq!(s.rules.get(&x).and_then(|e| e.history), None, "the keep after purge on replace reads as kept at N");
    assert_eq!(s.rules.get(&y).and_then(|e| e.history), keep.history, "N lacks the setting's keep");
}

// spec/crypto.md §4 (Floors: compaction snapshots): after A's cut for N, A compacts `g`'s
// `secrets.0` and `keys.0` and drops every body the snapshots cover. Q, granted with history
// later, holds the earlier epochs by the snapshots alone: it still comes to open every epoch,
// and N still none before its cut.
#[test]
fn compacted_cut_keeps_its_floors_spec_crypto_4() {
    let mut lp = synced(4);
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
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
        let _ = lp.peers[0].engine.reseal_due(&g, &Pass);
        let _ = lp.peers[3].engine.reseal_due(&g, &Pass);
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
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Read)).unwrap();
    let t = group(&mut lp, 2);
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
    let g = group(&mut lp, 0);
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

/// Peer `i` rotates `g`'s read as a due rotation does (`rotate_boxing`: inbox deliveries to the
/// holders it boxes that cannot open its wrap).
fn rotate(lp: &mut LocalPeer, i: usize, g: Tid) -> crate::flows::Done {
    lp.peers[i]
        .engine
        .run(|tx| {
            let me = tx.core.writer()?;
            let holders = super::recipients(tx, &me, &g, &[])?;
            super::rotate_boxing(tx, me, g, &BTreeSet::from(READ), &holders)
        })
        .unwrap()
}

// spec/crypto.md §4 (Floors: a low floor; Roles secrets; model X_cut): B, not holding A's cut for
// N, rotates beside it (a fork whose floor is 0, below N's). At A's pass end that fork is a
// current epoch N's floor bars it from, so A's rotation is due: it merges both, boxes N, and
// owes N its commit by inbox (it is wrapped under B's fork, which N cannot open); its history
// entry carries the fork's roles secret, so N reads B's raise made on the fork.
#[test]
fn fork_beside_the_cut_is_merged_for_the_newcomer_spec_crypto_4() {
    let (mut lp, g, tids) = two_admins();
    let mut label = Label::default();
    label.place(&mut lp, g, &[0]);
    let done = lp.peers[0].engine.grant_with(&g, &tids[3], &edge(Role::Read), History::None).unwrap();
    label.note(&done);
    label.place(&mut lp, g, &[0]);
    label.note(&rotate(&mut lp, 1, g));
    label.note(&lp.peers[1].engine.grant(&g, &tids[2], &edge(Role::Write)).unwrap());
    label.place(&mut lp, g, &[1]);
    sync_among(&mut lp, &[0, 1, 2]);
    let merge = lp.peers[0].engine.reseal_due(&g, &Pass).unwrap();
    assert!(!merge.commits.is_empty(), "A's rotation over B's fork is not due");
    let n = lp.peers[3].engine.me();
    assert!(merge.deliveries.iter().any(|d| matches!(d, crate::flows::Delivery::Inbox { to, .. } | crate::flows::Delivery::Direct { to, .. } if *to == n)), "the merge is not owed to N");
    label.note(&merge);
    settle_among(&mut lp, g, &[0, 1, 2], &mut label);
    label.place(&mut lp, g, &[0, 1, 2]);
    deliver_as_newcomer(&mut lp, 0, 3, g, &done, &label);
    let roster = |lp: &LocalPeer, i: usize| lp.peers[i].engine.roster(&g).into_iter().map(|(h, e)| (h, e.role)).collect::<Vec<_>>();
    assert_eq!(roster(&lp, 3), roster(&lp, 0), "N's roster differs from A's");
    let cur = lp.peers[0].engine.epochs(&g).unwrap().read.current();
    let at_n = lp.peers[3].engine.epochs(&g).unwrap();
    assert!(cur.iter().all(|e| at_n.read.secret(e).is_some()), "N lacks a current epoch of A's: {cur:?}");
}

/// Syncs peers `among` with each other, raw, in every direction.
fn sync_among(lp: &mut LocalPeer, among: &[usize]) {
    for _ in 0..2 {
        for a in among {
            for b in among.iter().filter(|b| *b != a) {
                lp.sync(*a, *b).unwrap();
            }
        }
    }
}

/// `settle_all` among `among` alone, noting what is owed to inboxes.
fn settle_among(lp: &mut LocalPeer, g: Tid, among: &[usize], label: &mut Label) {
    for _ in 0..8 {
        let mut n = 0;
        for p in among {
            if let Ok((d, _)) = lp.peers[*p].engine.ensure_rotated(&g) {
                n += d.commits.len();
                label.note(&d);
            }
            if let Ok(d) = lp.peers[*p].engine.reseal_due(&g, &Pass) {
                n += d.commits.len();
                label.note(&d);
            }
            sync_among(lp, among);
        }
        if n == 0 {
            return;
        }
    }
    panic!("no fixpoint in 8 rounds");
}

// spec/crypto.md §4 (Roles secrets; model X_race, Roster): B, not holding A's cut for N, raises
// P to write, with no rotation: a role commit under an epoch below N's floor that no later
// rotation drops. N, taking `g`'s labels as sealed, opens its `roles.0` section under the roles
// secret the cut carries, so it reads P as a writer as A does.
#[test]
fn grant_beside_a_cut_reaches_the_newcomer_spec_crypto_4() {
    let (mut lp, g, tids) = two_admins();
    let mut label = Label::default();
    label.place(&mut lp, g, &[0]);
    let done = lp.peers[0].engine.grant_with(&g, &tids[3], &edge(Role::Read), History::None).unwrap();
    label.place(&mut lp, g, &[0]);
    lp.peers[1].engine.grant(&g, &tids[2], &edge(Role::Write)).unwrap();
    // B places its raise before it holds the cut: under the epoch the cut supersedes
    label.place(&mut lp, g, &[1]);
    settle_among(&mut lp, g, &[0, 1, 2], &mut label);
    label.place(&mut lp, g, &[0, 1, 2]);
    deliver_as_newcomer(&mut lp, 0, 3, g, &done, &label);
    let roster = |lp: &LocalPeer, i: usize| lp.peers[i].engine.roster(&g).into_iter().map(|(h, e)| (h, e.role)).collect::<Vec<_>>();
    assert_eq!(roster(&lp, 0).iter().find(|x| x.0 == tids[2]).map(|x| x.1), Some(Role::Write), "A reads B's raise");
    assert_eq!(roster(&lp, 3), roster(&lp, 0), "N's roster differs from A's");
}

// spec/crypto.md §4 (Roles secrets): a cut writes the same commits and owes the same deliveries
// whatever the role history: after 3 or 30 rounds of granting P and removing it again (each
// removal a rotation), no role commit is placed again.
#[test]
fn cut_cost_does_not_grow_with_role_history_spec_crypto_4() {
    let cost = |rounds: usize| {
        let mut lp = synced(3);
        let (p, n) = (lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let g = group(&mut lp, 0);
        for _ in 0..rounds {
            lp.peers[0].engine.grant(&g, &p, &edge(Role::Read)).unwrap();
            lp.peers[0].engine.demote(&g, &crate::flows::Demotion { holder: p, new: None, retain: None }).unwrap();
        }
        let done = lp.peers[0].engine.grant_with(&g, &n, &edge(Role::Read), History::None).unwrap();
        assert!(!done.deliveries.iter().any(|d| matches!(d, crate::flows::Delivery::Removal { .. })), "a cut places a role commit again");
        (done.commits.len(), done.deliveries.len())
    };
    assert_eq!(cost(3), cost(30), "a cut's commits and deliveries grow with the role history");
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

// spec/crypto.md §4 (Roles secrets, State at a cut), §5 (Passing on): randomized differential.
// Admins A and B grant, raise and remove members, rotate and write content, syncing at random
// (forks included); at a random step A cuts for N while B keeps going. N takes every peer's
// commits on `g` only as `g`'s labels carry them, sealed: it reads the same roster as A, holds no
// read secret below its cut, holds no content commit from before it (written by anyone, beside
// the cut included, whatever a peer encrypts again) nor unwraps one's label entry (its header),
// yet reads the same current state as A, expiring values included, before and after they end.
// Fails without roles secrets in history entries (N misses every role commit before its cut),
// with content wrapped under the roles secret (N unwraps what came before) or also sealed there,
// or without the floor clause of Passing on (N holds what came before), and without the state
// at a cut (N misses state from before it) or its expiring snapshots (N misses a value that has
// not ended).
#[test]
fn newcomer_reads_the_roster_from_sealed_labels_spec_crypto_4() {
    let cut = osis_base::testenv::run_seeds("rotation::tests_cut::newcomer_reads_the_roster_from_sealed_labels_spec_crypto_4", &NEWCOMER_SEEDS, false, cut_replay("newcomer_reads_the_roster_from_sealed_labels_large_spec_crypto_4"), newcomer_reads_the_roster);
    assert!(cut.iter().filter(|c| **c).count() >= NEWCOMER_SEEDS.len() / 2, "only {cut:?} seeds cut");
}

/// The default test's seeds, a covering set: each cuts; with the boxing or the carry rule off
/// every one of seeds 1-40 fails, without the state at a cut 34, with content wrapped under the
/// roles secret 34 (sealed there too, the same 34), without roles secrets in history entries 17 (these three
/// among each), without the floor clause of Passing on 23 (1 and 5).
const NEWCOMER_SEEDS: [u64; 3] = [1, 3, 5];

/// Small size (a tenth of large) or large under `OSIS_FULL=1`; seeds: OSIS_CUT_START,
/// OSIS_CUT_SEEDS.
#[test]
#[ignore = "property"]
fn newcomer_reads_the_roster_from_sealed_labels_large_spec_crypto_4() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_CUT_START", "OSIS_CUT_SEEDS", osis_base::testenv::large(1..201));
    s.run("rotation::tests_cut::newcomer_reads_the_roster_from_sealed_labels_large_spec_crypto_4", cut_replay("newcomer_reads_the_roster_from_sealed_labels_large_spec_crypto_4"), newcomer_reads_the_roster);
}

/// One seed of `newcomer_reads_the_roster_from_sealed_labels_spec_crypto_4`: whether A cut.
fn newcomer_reads_the_roster(seed: u64) -> bool {
    let mut rng = super::tests::Rng(seed.wrapping_mul(0x2545_f491).wrapping_add(3));
    let among = [0usize, 1, 2, 3, 4];
    let (mut lp, (g, tids)) = LocalPeer::cached("rotation::tests_cut::newcomer_reads_the_roster", || {
        let mut lp = synced(6);
        let tids: Vec<Tid> = (0..6).map(|i| lp.peers[i].engine.me()).collect();
        let g = group(&mut lp, 0);
        lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
        sync_among(&mut lp, &among);
        (lp, (g, tids))
    });
    let cut_at = rng.next(10) as usize;
    let mut done = None;
    let mut before = BTreeSet::new();
    let mut label = Label::default();
    label.place(&mut lp, g, &among);
    for step in 0..14 {
        if step == cut_at {
            for p in among {
                before.extend(edits_on(&lp, p, g));
            }
            done = lp.peers[0].engine.grant_with(&g, &tids[5], &edge(Role::Read), History::None).ok();
            done.iter().for_each(|d| label.note(d));
            put(&mut lp, 0, g, "after");
            label.place(&mut lp, g, &[0]);
        }
        let admin = rng.next(2) as usize;
        if done.is_none() {
            // some values expire: the newcomer reads each until it ends (expiring snapshots)
            match rng.next(3) {
                0 => {
                    let t = lp.peers[admin].engine.now().0 + 1_000 * (1 + rng.next(60));
                    put_expiring(&mut lp, admin, g, &format!("before{step}"), t);
                }
                _ => put(&mut lp, admin, g, &format!("before{step}")),
            }
        }
        let x = tids[2 + rng.next(3) as usize];
        match rng.next(6) {
            0 => {
                let role = [Role::Read, Role::Write][rng.next(2) as usize];
                if let Ok(d) = lp.peers[admin].engine.grant(&g, &x, &edge(role)) {
                    label.note(&d);
                }
            }
            1 => {
                if let Ok(d) = lp.peers[admin].engine.demote(&g, &crate::flows::Demotion { holder: x, new: None, retain: None }) {
                    label.note(&d);
                }
            }
            2 => label.note(&rotate(&mut lp, admin, g)),
            3 => {
                let (a, b) = (among[rng.next(5) as usize], among[rng.next(5) as usize]);
                if a != b {
                    lp.sync(a, b).unwrap();
                }
            }
            _ => sync_among(&mut lp, &among),
        }
        // each peer places what it made or received soon after (a random one first)
        let first = rng.next(5) as usize;
        label.place(&mut lp, g, &[among[first]]);
        label.place(&mut lp, g, &among);
    }
    let Some(done) = done else { return false };
    let cut = lp.peers[0].engine.epochs(&g).unwrap().read.held().map(|x| x.0).filter(|e| done.commits.iter().any(|c| lp.peers[0].engine.core.ix.epoch_intro.get(&(g, Role::Read, *e)).is_some_and(|(_, x)| x == c))).max_by_key(Epoch::n).unwrap();
    settle_among(&mut lp, g, &among, &mut label);
    label.place(&mut lp, g, &among);
    // a peer encrypts again some commits it holds (node-sync seals a body again: a placement
    // past a delete, a body with no held encryption)
    let p = among[rng.next(5) as usize];
    let again: Vec<osis_base::CommitId> = lp.packages(p).unwrap().into_iter().filter(|pk| on_g(pk, g) && rng.next(2) == 0).map(|pk| pk.id).collect();
    label.held.extend(lp.sealed(p, &again).unwrap());
    deliver_as_newcomer(&mut lp, 0, 5, g, &done, &label);
    let roster = |lp: &LocalPeer, i: usize| lp.peers[i].engine.roster(&g).into_iter().map(|(h, e)| (h, e.role)).collect::<Vec<_>>();
    if std::env::var("OSIS_CUT_DUMP").is_ok() && roster(&lp, 5) != roster(&lp, 0) {
        let ne = lp.peers[5].engine.epochs(&g).unwrap();
        for p in among {
            let e = lp.peers[p].engine.epochs(&g).unwrap();
            let cur = e.read.current();
            for (x, i) in e.read.epochs() {
                eprintln!("peer {p} {:?} n{} held {} cur {} est {} | N roles {} est {}", &x.nonce()[..2], x.n(), i.secret.is_some(), cur.contains(x), i.established.is_some(), ne.read.roles_secret(x).is_some(), ne.read.is_established(x));
            }
        }
    }
    assert_eq!(roster(&lp, 5), roster(&lp, 0), "seed {seed}: N's roster differs from A's");
    let below: Vec<Epoch> = lp.peers[5].engine.epochs(&g).unwrap().read.held().map(|x| x.0).filter(|e| e.n() < cut.n()).collect();
    assert!(below.is_empty(), "seed {seed}: N holds {below:?} below its cut {cut:?}");
    holds_none(&lp, 5, &before, &format!("seed {seed}"));
    // nor reads the header of one: the wrap gates it (spec/crypto.md §5 Passing on)
    let open: Vec<_> = label.held.iter().filter(|pk| before.contains(&pk.id) && unwraps(&lp, 5, pk)).map(|pk| pk.id).collect();
    assert!(open.is_empty(), "seed {seed}: N unwraps label entries from before its cut: {open:?}");
    let read = content(&mut lp, 5, g);
    assert!(read.contains("after"), "seed {seed}: N does not read A's write after its cut");
    assert_eq!(read, content(&mut lp, 0, g), "seed {seed}: N reads another state than A");
    for step in [30_000, 60_000] {
        lp.advance(step);
        assert_eq!(content_now(&mut lp, 5, g), content_now(&mut lp, 0, g), "seed {seed}: N reads another state than A {step} ms on");
    }
    true
}

// spec/crypto.md §4 (Roles secrets; model X_two, Alike): A cuts for N while B cuts for N2, each
// not holding the other's cut. Every holder is re-sealed at both cut epochs; each newcomer opens
// the other cut's role parts (its keyset and history box) under the roles secret its own carries,
// so it counts the same current epochs as A.
#[test]
fn concurrent_cuts_read_alike_spec_crypto_4() {
    let mut lp = synced(5);
    let tids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    let mut label = Label::default();
    label.note(&lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap());
    label.note(&lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap());
    sync_among(&mut lp, &[0, 1, 2]);
    label.place(&mut lp, g, &[0, 1]);
    let done_n = lp.peers[0].engine.grant_with(&g, &tids[3], &edge(Role::Read), History::None).unwrap();
    let done_n2 = lp.peers[1].engine.grant_with(&g, &tids[4], &edge(Role::Read), History::None).unwrap();
    label.note(&done_n);
    label.note(&done_n2);
    label.place(&mut lp, g, &[0]);
    label.place(&mut lp, g, &[1]);
    settle_among(&mut lp, g, &[0, 1, 2], &mut label);
    label.place(&mut lp, g, &[0, 1, 2]);
    deliver_as_newcomer(&mut lp, 0, 3, g, &done_n, &label);
    deliver_as_newcomer(&mut lp, 1, 4, g, &done_n2, &label);
    let cur = |lp: &LocalPeer, i: usize| lp.peers[i].engine.epochs(&g).unwrap().read.current();
    assert!(cur(&lp, 0).len() > 1, "the cuts do not fork");
    if std::env::var("OSIS_CUT_DUMP").is_ok() {
        for i in [0, 3, 4] {
            let e = lp.peers[i].engine.epochs(&g).unwrap();
            for (x, inf) in e.read.epochs() {
                eprintln!("peer {i} n{} {:?} secret {} est {} cur {} floor {} roles {}", x.n(), &x.nonce()[..2], inf.secret.is_some(), inf.established.is_some(), e.read.is_current(x), e.read.floor(x), e.read.roles_secret(x).is_some());
            }
            eprintln!("peer {i} roster {:?}", lp.peers[i].engine.roster(&g).len());
        }
    }
    for i in [3, 4] {
        assert_eq!(cur(&lp, i), cur(&lp, 0), "newcomer {i}'s current epochs differ from A's");
    }
}

// spec/crypto.md §4 (Floors, Low floor; model X_rmrace): A removes reader M, then cuts for N. B
// holds the cut (boxed) but not the removal, so it meets neither the cut's names nor knows M left:
// the epoch before the removal is current at B with a floor below N's. B rotates over it only once
// it holds the removal: its rotation would box M at an epoch made knowing M's removal.
#[test]
fn low_floor_waits_for_the_names_spec_crypto_4() {
    let mut lp = synced(4);
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let read = read_epochs(&lp, g);
    let before = super::tests::commit_ids(&mut lp, 0);
    lp.peers[0].engine.demote(&g, &crate::flows::Demotion { holder: tids[2], new: None, retain: None }).unwrap();
    let removal: BTreeSet<osis_base::CommitId> = super::tests::commit_ids(&mut lp, 0).difference(&before).copied().collect();
    lp.peers[0].engine.grant_with(&g, &tids[3], &edge(Role::Read), History::None).unwrap();
    for pk in lp.packages(0).unwrap() {
        if !removal.contains(&pk.id) {
            let _ = lp.peers[1].receive(&pk.bytes, pk.blobs.clone());
        }
    }
    lp.peers[1].engine.reseal_due(&g, &Pass).unwrap();
    let m = reaches(&mut lp, 1, g, tids[2]);
    assert!(m.is_subset(&read), "B's state hands M {:?}, made knowing its removal", m.difference(&read).collect::<Vec<_>>());
}

/// The content commits peer `i` holds on `g` (not role commits, not snapshots): every one an
/// edit somebody made.
fn edits_on(lp: &LocalPeer, i: usize, g: Tid) -> BTreeSet<osis_base::CommitId> {
    let e = &lp.peers[i].engine;
    e.core.ix.commits.iter().filter(|(_, m)| !m.header.kind.is_compaction() && m.header.aspects.iter().any(|a| a.tid == g && osis_schema::core_types::is_content(a.ak.as_str()))).map(|(c, _)| *c).collect()
}

/// Whether peer `n` unwraps a blob key of sealed package `pk` with the secrets it holds.
fn unwraps(lp: &LocalPeer, n: usize, pk: &crate::local_peer::SealedPackage) -> bool {
    pk.entries.iter().any(|e| e.wraps.iter().any(|(a, w)| osis_label::unwrap_any(lp.peers[n].engine.read_secrets(a).iter(), &e.id, w).is_some()))
}

/// Asserts N (peer `n`) holds no commit of `before` (the content commits from before its cut):
/// neither as a commit nor as a header.
fn holds_none(lp: &LocalPeer, n: usize, before: &BTreeSet<osis_base::CommitId>, what: &str) {
    let held: Vec<_> = before.iter().filter(|c| lp.peers[n].engine.header(c).is_some()).collect();
    assert!(held.is_empty(), "{what}: N holds commits from before its cut: {held:?}");
}

// spec/crypto.md §5 (Passing on, floors), §4 (State at a cut): A writes "draft", removes it and
// writes "final", then cuts for N; B, another admin not holding the cut yet, writes "beside" and
// goes offline for good. A encrypts its pre-cut commits again (node-sync seals a body again: a placement past a delete, a
// body with no held encryption), and B's commit reaches A late. N never holds a commit from
// before its cut, its own or as a header, nor B's (written beside the grant); it reads the
// current state ("final", "beside", and "after", written after) and no earlier one ("draft").
// Each shape fails without the floor clause (a fresh encryption or wrap hands N the commit) or
// without the state at a cut (N misses "final" or "beside").
#[test]
fn content_encrypted_again_after_a_cut_stays_hidden_spec_crypto_5() {
    for again in [false, true] {
        let mut lp = synced(3);
        let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
        let g = group(&mut lp, 0);
        lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
        lp.sync_all().unwrap();
        let mut label = Label::default();
        put(&mut lp, 0, g, "draft");
        remove(&mut lp, 0, g, "draft");
        put(&mut lp, 0, g, "final");
        label.place(&mut lp, g, &[0, 1]);
        let done = lp.peers[0].engine.grant_with(&g, &tids[2], &edge(Role::Read), History::None).unwrap();
        label.note(&done);
        put(&mut lp, 1, g, "beside");
        label.place(&mut lp, g, &[1]);
        let mut before = edits_on(&lp, 0, g);
        before.extend(edits_on(&lp, 1, g));
        label.place(&mut lp, g, &[0]);
        put(&mut lp, 0, g, "after");
        label.place(&mut lp, g, &[0]);
        if again {
            let ids: Vec<osis_base::CommitId> = edits_on(&lp, 0, g).intersection(&before).copied().collect();
            label.held.extend(lp.sealed(0, &ids).unwrap());
        }
        // B goes offline for good; its commit reaches A late, sealed as B placed it: A owes the
        // state it carries
        lp.deliver_sealed(0, &label.held).unwrap();
        settle_among(&mut lp, g, &[0], &mut label);
        label.place(&mut lp, g, &[0]);
        deliver_as_newcomer(&mut lp, 0, 2, g, &done, &label);
        holds_none(&lp, 2, &before, &format!("again {again}"));
        assert_eq!(content(&mut lp, 2, g), content(&mut lp, 0, g), "again {again}: N reads another state than A");
        assert_eq!(content(&mut lp, 2, g), BTreeSet::from(["final".to_string(), "beside".into(), "after".into()]), "again {again}");
    }
}

/// Peer `i` removes key `k` from `g`'s `x:m.0`.
fn remove(lp: &mut LocalPeer, i: usize, g: Tid, k: &str) {
    let mut m = crate::Mutation::new();
    m.op(g, &osis_base::Ak::new("x:m.0").unwrap(), osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Remove(osis_base::Value::Str(k.into())) }).unwrap();
    lp.peers[i].commit(m).unwrap();
}

static DOC: osis_schema::StaticSchema = osis_schema::StaticSchema::new("cutdoc.osis", "revision 1; purgeable_by(author, admin) aspect k:t.0: text;\n");

// spec/crypto.md §4 (State at a cut), Tess: a shared document granted from now shows its finished
// text, never the edits before. A writes a text in four edits, history kept (P, granted with
// history, lists every version), compacts it, then grants N read without history. N reads the final text, holds
// none of the edits (so lists no earlier version), and reads A's next edit; P still lists every one.
#[test]
fn from_now_document_shows_its_text_not_its_edits_spec_crypto_4() {
    let mut lp = synced(3);
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    let key: osis_schema::Aspect<osis_base::Value> = osis_schema::Aspect::new("k:t.0", &DOC);
    let ak = osis_base::Ak::new("k:t.0").unwrap();
    let mut m = crate::Mutation::new();
    m.set(g, &osis_schema::core_types::RETENTION, &osis_schema::core_types::RetentionSetting::of(ak.clone(), osis_schema::History::Keep { until: Some(4_000_000_000_000), after: None })).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Read)).unwrap();
    let edit = |lp: &mut LocalPeer, op: osis_crdt::Op| {
        let mut m = crate::Mutation::new();
        m.op(g, &key, osis_crdt::PathOp { path: vec![], op }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let text = |lp: &mut LocalPeer, i: usize| match lp.peers[i].engine.get(&g, &ak).unwrap() {
        Some(osis_base::Value::Str(s)) => s,
        v => format!("{v:?}"),
    };
    edit(&mut lp, osis_crdt::Op::Insert { at: 0, items: vec![osis_base::Value::Str("embarassing draft".into())] });
    edit(&mut lp, osis_crdt::Op::Delete { at: 0, len: 12 });
    edit(&mut lp, osis_crdt::Op::Insert { at: 0, items: vec![osis_base::Value::Str("the final ".into())] });
    edit(&mut lp, osis_crdt::Op::Insert { at: 15, items: vec![osis_base::Value::Str(".".into())] });
    assert_eq!(text(&mut lp, 0), "the final draft.");
    // compacted before the grant: that snapshot is history as much as the edits
    assert!(lp.peers[0].engine.snapshot(&g, &ak).unwrap().is_some(), "A compacts");
    let mut label = Label::default();
    label.place(&mut lp, g, &[0]);
    let before = edits_on(&lp, 0, g);
    let done = lp.peers[0].engine.grant_with(&g, &tids[2], &edge(Role::Read), History::None).unwrap();
    label.note(&done);
    label.place(&mut lp, g, &[0]);
    deliver_as_newcomer(&mut lp, 0, 2, g, &done, &label);
    assert_eq!(text(&mut lp, 2), "the final draft.", "N reads another text");
    holds_none(&lp, 2, &before, "the document");
    let versions = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.held_parts(&g, &ak, crate::engine::listing::CommitFrom::Oldest, 100, usize::MAX).unwrap().0.len();
    edit(&mut lp, osis_crdt::Op::Insert { at: 16, items: vec![osis_base::Value::Str("!".into())] });
    label.place(&mut lp, g, &[0]);
    deliver_as_newcomer(&mut lp, 0, 2, g, &done, &label);
    assert_eq!(text(&mut lp, 2), "the final draft.!", "N misses A's edit after its grant");
    lp.sync(0, 1).unwrap();
    assert!(versions(&mut lp, 1) >= 5, "P, with history, lists every edit");
    holds_none(&lp, 2, &before, "after the next edit");
}

// spec/crypto.md §4 (State at a cut), notes/chat.md (a message is a signal fire with no current
// value): a chat granted from now. N reads the chat's name, no message from before its grant
// (a signal has no state a snapshot carries), and every message after it.
#[test]
fn from_now_chat_shows_no_earlier_message_spec_crypto_4() {
    let mut lp = synced(2);
    let n = lp.peers[1].engine.me();
    let g = group(&mut lp, 0);
    let (msg_ak, name_ak) = (osis_base::Ak::new("x:msg~0").unwrap(), osis_base::Ak::new("x:name.0").unwrap());
    let mut m = crate::Mutation::new();
    m.set(g, &osis_schema::core_types::RETENTION, &osis_schema::core_types::RetentionSetting::of(msg_ak.clone(), osis_schema::History::Keep { until: Some(4_000_000_000_000), after: None })).unwrap();
    m.op(g, &name_ak, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Set(osis_base::Value::Str("team".into())) }).unwrap();
    lp.peers[0].commit(m).unwrap();
    let say = |lp: &mut LocalPeer, t: &str| {
        let mut m = crate::Mutation::new();
        m.op(g, &msg_ak, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Set(osis_base::Value::Str(t.into())) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let early = [say(&mut lp, "secret plans"), say(&mut lp, "more plans")];
    let mut label = Label::default();
    label.place(&mut lp, g, &[0]);
    let done = lp.peers[0].engine.grant_with(&g, &n, &edge(Role::Write), History::None).unwrap();
    label.note(&done);
    let welcome = say(&mut lp, "welcome");
    label.place(&mut lp, g, &[0]);
    deliver_as_newcomer(&mut lp, 0, 1, g, &done, &label);
    let fires = |lp: &mut LocalPeer, i: usize| -> Vec<osis_base::CommitId> {
        let (parts, _) = lp.peers[i].engine.held_parts(&g, &msg_ak, crate::engine::listing::CommitFrom::Oldest, 100, usize::MAX).unwrap();
        parts.iter().map(|p| p.id).collect()
    };
    assert_eq!(fires(&mut lp, 0).len(), 3, "A lists every message");
    assert_eq!(fires(&mut lp, 1), vec![welcome], "N lists another set of messages than the one after its grant");
    holds_none(&lp, 1, &BTreeSet::from(early), "the chat");
    assert_eq!(lp.peers[1].engine.get(&g, &name_ak).unwrap(), Some(osis_base::Value::Str("team".into())), "N misses the chat's name");
}

// spec/crypto.md §4 (Floors: a plain thing's epoch reads its base epoch's floor), §5 (Passing
// on): T, a plain thing under `g`, has content from before A's cut for N. A seals T's content
// under the cut's derived epoch at the cut's floor, so T's commit from before it is neither
// wrapped nor sealed again there, and A owes T's state a snapshot as `g`'s own.
#[test]
fn plain_thing_below_a_cut_keeps_its_floor_spec_crypto_4() {
    let mut lp = synced(2);
    let n = lp.peers[1].engine.me();
    let g = group(&mut lp, 0);
    let t = {
        let mut m = crate::Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, g);
        lp.peers[0].commit(m).unwrap();
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
        let g = group(&mut lp, 0);
        for r in 0..rounds {
            let mut m = crate::Mutation::new();
            for a in 0..8 {
                m.op(g, &osis_base::Ak::new(format!("x:a{a}.0")).unwrap(), osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Set(osis_base::Value::Str(format!("value {}", if r + 1 == rounds { "last" } else { "earlier" }))) }).unwrap();
            }
            lp.peers[0].commit(m).unwrap();
        }
        let before: BTreeSet<osis_base::CommitId> = lp.peers[0].engine.core.ix.commits.keys().copied().collect();
        lp.peers[0].engine.grant_with(&g, &n, &edge(Role::Read), History::None).unwrap();
        let new: Vec<_> = lp.packages(0).unwrap().into_iter().filter(|pk| !before.contains(&pk.id)).collect();
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
    e.core.ix.commits.values().filter(|m| m.header.kind.is_compaction() && m.view.author == me).count()
}

// spec/crypto.md §4 (State at a cut): a writer granted with history after a cut (or a new node
// of any writer) fetches the role commits first, then the bodies from before the cut, the cut's
// snapshots after them (a first sync goes by order, spec/crypto.md §5 Order). Those bodies are covered by the
// cut's snapshots, so it owes no snapshot of its own: it writes none, however its fetch is cut
// into steps (node-sync writes owed snapshots after each, `SyncEngine::engine_events`).
#[test]
fn late_bodies_a_cut_covers_owe_no_snapshot_spec_crypto_4() {
    let mut lp = synced(3);
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    let mut label = Label::default();
    for r in 0..3 {
        let mut m = crate::Mutation::new();
        for a in 0..4 {
            m.op(g, &osis_base::Ak::new(format!("x:a{a}.0")).unwrap(), osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Set(osis_base::Value::Str(format!("value {r}"))) }).unwrap();
        }
        lp.peers[0].commit(m).unwrap();
        label.place(&mut lp, g, &[0]);
    }
    let cut = lp.peers[0].engine.grant_with(&g, &tids[1], &edge(Role::Read), History::None).unwrap();
    label.note(&cut);
    label.place(&mut lp, g, &[0]);
    let done = lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Write)).unwrap();
    label.note(&done);
    label.place(&mut lp, g, &[0]);
    let snaps_a = own_snapshots(&lp, 0);
    assert_eq!(snaps_a, 4, "A writes the state at its cut");
    // W: its grant and A's commits off `g` whole, then `g`'s labels in `ts` order, one step each
    for c in &done.commits {
        let pk = lp.peers[0].engine.package(c).unwrap().unwrap();
        let _ = lp.peers[2].receive(&pk.bytes, pk.blobs.clone());
    }
    for pk in lp.packages(0).unwrap() {
        if !on_g(&pk, g) {
            let _ = lp.peers[2].receive(&pk.bytes, pk.blobs.clone());
        }
    }
    let mut held = label.held.clone();
    // spec/crypto.md §5 Order: role commits first (order 0), then by `ts`
    held.sort_by_key(|pk| lp.peers[0].engine.header(&pk.id).map(|h| (!matches!(h.kind, osis_commit::Kind::Role), h.ts)));
    for pk in &held {
        lp.deliver_sealed(2, std::slice::from_ref(pk)).unwrap();
        lp.peers[2].engine.purge_resnapshots().unwrap();
    }
    lp.deliver_sealed(2, &held).unwrap();
    lp.peers[2].engine.purge_resnapshots().unwrap();
    lp.peers[2].engine.reseal_due(&g, &Pass).unwrap();
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
    let g = group(&mut lp, 0);
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
    let snaps: Vec<_> = lp.packages(0).unwrap().into_iter().filter(|pk| !before.contains(&pk.id) && osis_commit::CommitBlob::decode(&pk.bytes).unwrap().header.kind.is_compaction()).collect();
    assert_eq!(snaps.len(), 1, "one snapshot of the value");
    let s = &snaps[0];
    eprintln!("snapshot of a 1 MiB value: {} bytes, {} linked blobs", s.bytes.len(), s.blobs.len());
    assert!(s.bytes.len() < 2048, "the snapshot carries the value: {} bytes", s.bytes.len());
    assert!(s.blobs.iter().all(|(b, _)| tree.contains(b)), "the snapshot encrypts a chunk again");
    assert_eq!(lp.peers[0].engine.live_trees(&g).unwrap().blobs.into_iter().collect::<BTreeSet<_>>(), tree, "the value's tree changed");
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

/// Delivers to peer `to` every role commit peer `from` holds, raw.
fn roles_to(lp: &mut LocalPeer, from: usize, to: usize) {
    for pk in lp.packages(from).unwrap() {
        if osis_commit::CommitBlob::decode(&pk.bytes).unwrap().header.kind == osis_commit::Kind::Role {
            let _ = lp.peers[to].receive(&pk.bytes, pk.blobs.clone());
        }
    }
}

fn keys(v: &[&str]) -> BTreeSet<String> {
    v.iter().map(|s| s.to_string()).collect()
}

// spec/crypto.md §4 (State at a cut), spec/crdt.md §8 (expiring snapshots), Tess: a holder
// granted without history reads the current state, expiring values included, each until it
// ends. A writes "plain", "soon" (expiring in 10 s) and "later" (in 100 s), then cuts for N (a
// writer). N reads all three, then each goes at its expiry at N as at A. N, which holds those
// values from the cut's expiring snapshots alone, compacts: P, a holder with history that gets
// only N's snapshot, never reads an expiring value from it. Fails without the expiring
// snapshots (N reads neither "soon" nor "later") and with N's snapshot carrying the values it
// holds from them (P reads them for good).
#[test]
fn from_now_reads_expiring_values_until_they_end_spec_crypto_4() {
    let mut lp = synced(3);
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let now = lp.peers[0].engine.now().0;
    put(&mut lp, 0, g, "plain");
    put_expiring(&mut lp, 0, g, "soon", now + 10_000);
    put_expiring(&mut lp, 0, g, "later", now + 100_000);
    let mut label = Label::default();
    label.place(&mut lp, g, &[0]);
    let done = lp.peers[0].engine.grant_with(&g, &tids[2], &edge(Role::Write), History::None).unwrap();
    label.note(&done);
    label.place(&mut lp, g, &[0]);
    deliver_as_newcomer(&mut lp, 0, 2, g, &done, &label);
    assert_eq!(content(&mut lp, 2, g), keys(&["plain", "soon", "later"]), "N misses an expiring value");
    let ak = osis_base::Ak::new("x:m.0").unwrap();
    let snap = lp.peers[2].engine.snapshot(&g, &ak).unwrap().expect("N compacts");
    roles_to(&mut lp, 0, 1);
    let pk = lp.peers[2].engine.package(&snap).unwrap().unwrap();
    lp.peers[1].receive(&pk.bytes, pk.blobs.clone()).unwrap();
    lp.advance(20_000);
    assert_eq!(content_now(&mut lp, 0, g), keys(&["plain", "later"]));
    assert_eq!(content_now(&mut lp, 2, g), keys(&["plain", "later"]), "N reads another state than A once one value ended");
    lp.advance(100_000);
    assert_eq!(content_now(&mut lp, 0, g), keys(&["plain"]));
    assert_eq!(content_now(&mut lp, 2, g), keys(&["plain"]), "N reads a value past its expiry");
    assert_eq!(content_now(&mut lp, 1, g), keys(&["plain"]), "N's snapshot hands P a value past its expiry");
    // a stale copy of the expiring snapshots arriving later brings nothing back
    lp.deliver_sealed(2, &label.held).unwrap();
    assert_eq!(content_now(&mut lp, 2, g), keys(&["plain"]), "a late copy of an expiring snapshot brings its value back");
}

/// Peer `i` fires `t` on `g`'s `x:msg~0`, replacing `o` if given.
fn say(lp: &mut LocalPeer, i: usize, g: Tid, t: &str, o: Option<osis_base::CommitId>) -> osis_base::CommitId {
    let ak = osis_base::Ak::new("x:msg~0").unwrap();
    let mut m = crate::Mutation::new();
    m.op(g, &ak, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Set(osis_base::Value::Str(t.into())) }).unwrap();
    if let Some(o) = o {
        m.replaces(g, &ak, o).unwrap();
    }
    lp.peers[i].commit(m).unwrap().unwrap()
}

/// The fires peer `i` lists on `g`'s `x:msg~0` (an honored version under its original), each
/// with the text it reads as.
fn fires(lp: &mut LocalPeer, i: usize, g: Tid) -> Vec<(osis_base::CommitId, String)> {
    let ak = osis_base::Ak::new("x:msg~0").unwrap();
    let e = &mut lp.peers[i].engine;
    let (parts, _) = e.held_parts(&g, &ak, crate::engine::listing::CommitFrom::Oldest, 100, usize::MAX).unwrap();
    let mut out = Vec::new();
    for p in parts {
        if e.listed_at(&p.id, &[(g, ak.clone())]).unwrap() {
            let row = e.commit_row(&p.id, &|_, _| true, usize::MAX).unwrap().unwrap();
            out.push((p.id, format!("{:?}", row.parts.first().map(|x| &x.body))));
        }
    }
    out
}

// spec/commits.md §5 Signals, spec/crypto.md §4 (State at a cut), Tess: a holder granted without
// history sees no past message, nor a later edit of one. A says "typo" before cutting for N and
// fixes it after (an edit, `replaces`), then says "welcome": N lists "welcome" alone, A both. P,
// a reader with history holding the fix but not the message it edits (gone from history, never
// fetched), still lists the fix as a message of its own. A's edit of "welcome" claims too low a
// floor (any writer may claim any): N, holding "welcome", reads the edit. Fails without the
// original's floor on the edit (N lists the fix as a new message), and with the claim trusted
// where the original is held (N reads "welcome" unedited).
#[test]
fn from_now_lists_no_edit_of_an_earlier_message_spec_commits_5() {
    let mut lp = synced(3);
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    let msg_ak = osis_base::Ak::new("x:msg~0").unwrap();
    let mut m = crate::Mutation::new();
    m.set(g, &osis_schema::core_types::RETENTION, &osis_schema::core_types::RetentionSetting::of(msg_ak, osis_schema::History::Keep { until: Some(4_000_000_000_000), after: None })).unwrap();
    let setting = lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Read)).unwrap();
    let typo = say(&mut lp, 0, g, "typo", None);
    let mut label = Label::default();
    label.place(&mut lp, g, &[0]);
    let done = lp.peers[0].engine.grant_with(&g, &tids[2], &edge(Role::Write), History::None).unwrap();
    label.note(&done);
    let fix = say(&mut lp, 0, g, "fixed", Some(typo));
    let welcome = say(&mut lp, 0, g, "welcome", None);
    // the welcome's edit claims a floor below N's: N, holding the welcome, judges it
    lp.peers[0].engine.core.lie_floor = Some(0);
    say(&mut lp, 0, g, "welcome!", Some(welcome));
    lp.peers[0].engine.core.lie_floor = None;
    label.place(&mut lp, g, &[0]);
    deliver_as_newcomer(&mut lp, 0, 2, g, &done, &label);
    assert_eq!(fires(&mut lp, 0, g).iter().map(|x| x.0).collect::<Vec<_>>(), vec![typo, welcome], "A lists the message (as its fix) and the welcome");
    assert!(fires(&mut lp, 0, g)[0].1.contains("fixed"), "A reads the fix");
    assert_eq!(fires(&mut lp, 2, g).iter().map(|x| x.0).collect::<Vec<_>>(), vec![welcome], "N lists an edit of a message from before its grant");
    assert!(fires(&mut lp, 2, g)[0].1.contains("welcome!"), "an edit's claimed floor hides it from N, which holds its message");
    // P: every role commit, the setting and the fix alone
    roles_to(&mut lp, 0, 1);
    for c in [setting, fix] {
        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
        lp.peers[1].receive(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    assert_eq!(fires(&mut lp, 1, g).iter().map(|x| x.0).collect::<Vec<_>>(), vec![fix], "P, with history, lists no fix whose message it lacks");
}

// spec/crdt.md §4.6 (an undo never extends a value's lifetime), §4.7, §8: N, granted without
// history (a writer), holds A's value 1 of register `x:r.0` from the cut's expiring snapshot
// alone, no delta of it. A sets it to 2 after the cut; N undoes that, writing 1 back: the undo
// expires with the value it copies, which N knows only from the snapshot. Fails with the
// snapshot's expiry not read (the value written back lasts for good).
#[test]
fn from_now_undo_writes_back_an_expiring_value_with_its_expiry_spec_crdt_4() {
    let mut lp = synced(2);
    let n = lp.peers[1].engine.me();
    let g = group(&mut lp, 0);
    let ak = osis_base::Ak::new("x:r.0").unwrap();
    let mut m = crate::Mutation::new();
    m.set(g, &osis_schema::core_types::RETENTION, &osis_schema::core_types::RetentionSetting::of(ak.clone(), osis_schema::History::Keep { until: Some(4_000_000_000_000), after: None })).unwrap();
    lp.peers[0].commit(m).unwrap();
    let set = |lp: &mut LocalPeer, i: usize, v: i64, t: Option<u64>| {
        lp.advance(10);
        let mut m = crate::Mutation::new();
        m.op(g, &ak, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Set(osis_base::Value::Int(v)) }).unwrap();
        if let Some(t) = t {
            m.expires(g, &ak, osis_base::WallMs(t)).unwrap();
        }
        lp.peers[i].commit(m).unwrap().unwrap()
    };
    let now = lp.peers[0].engine.now().0;
    set(&mut lp, 0, 1, Some(now + 100_000));
    let mut label = Label::default();
    label.place(&mut lp, g, &[0]);
    let done = lp.peers[0].engine.grant_with(&g, &n, &edge(Role::Write), History::None).unwrap();
    label.note(&done);
    let two = set(&mut lp, 0, 2, None);
    label.place(&mut lp, g, &[0]);
    deliver_as_newcomer(&mut lp, 0, 1, g, &done, &label);
    let r = |lp: &mut LocalPeer| lp.peers[1].engine.get(&g, &ak).unwrap();
    assert_eq!(r(&mut lp), Some(osis_base::Value::Int(2)));
    lp.advance(10);
    let mut m = crate::Mutation::new();
    m.undo(two);
    lp.peers[1].commit(m).unwrap();
    assert_eq!(r(&mut lp), Some(osis_base::Value::Int(1)), "N's undo writes back the value before");
    lp.advance(200_000);
    lp.peers[1].tick().unwrap();
    assert_eq!(r(&mut lp), None, "N's undo keeps a value past its expiry");
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
    let g = group(&mut lp, 0);
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
            crate::retention::snapshot::build_snapshot(tx, g, ak.clone(), st, ts, node, Default::default(), Default::default(), Some(t))
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

// spec/crdt.md §4.7, §8, spec/crypto.md §4 (State at a cut): who can write an expiring
// snapshot's expiry, at a holder granted without history. H, a writer, writes one carrying A's
// lasting "x" and A's "e" (expiring in 10 s) valued, ending in 50 s, and A holds it when it cuts
// for N. N reads "x" for good and "e" until 10 s, as A does. After the cut H sends N another,
// ending in 40 s, carrying A's lasting register value 1; A sets the register to 2 and N undoes
// that, writing back the 1 it holds from the cut's lasting snapshot: it lasts. An honest node
// judges a value it holds from its own delta or a lasting body by them, never by an expiring
// snapshot's claim. Fails with expiring snapshots' copies counted without that (A's cut carries
// "e" until 50 s and drops "x" from its lasting snapshot, so N loses it at 50 s; N's undo
// writes 1 back ending at 40 s).
#[test]
fn forged_expiring_snapshot_neither_ends_nor_extends_a_value_at_a_newcomer_spec_crdt_8() {
    let mut lp = synced(3);
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    let (ak, reg) = (osis_base::Ak::new("x:m.0").unwrap(), osis_base::Ak::new("x:r.0").unwrap());
    let set = |lp: &mut LocalPeer, v: i64| {
        let mut m = crate::Mutation::new();
        m.op(g, &reg, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Set(osis_base::Value::Int(v)) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let mut m = crate::Mutation::new();
    m.set(g, &osis_schema::core_types::RETENTION, &osis_schema::core_types::RetentionSetting::of(reg.clone(), osis_schema::History::Keep { until: Some(4_000_000_000_000), after: None })).unwrap();
    lp.peers[0].commit(m).unwrap();
    let now = lp.peers[0].engine.now().0;
    put(&mut lp, 0, g, "x");
    put_expiring(&mut lp, 0, g, "e", now + 10_000);
    set(&mut lp, 1);
    for pk in lp.packages(0).unwrap() {
        let _ = lp.peers[1].receive(&pk.bytes, pk.blobs.clone());
    }
    // H's expiring snapshot of its whole state of `on`, ending at `t`
    let forge = |lp: &mut LocalPeer, on: &osis_base::Ak, t: u64| {
        let forged = lp.peers[1]
            .engine
            .run(|tx| {
                let st = tx.state(&g, on)?.cloned().unwrap();
                let (ts, node) = (tx.core.hlc.next(), tx.core.writer_for(&g)?);
                crate::retention::snapshot::build_snapshot(tx, g, on.clone(), st, ts, node, Default::default(), Default::default(), Some(t))
            })
            .unwrap();
        lp.peers[1].engine.package(&forged).unwrap().unwrap()
    };
    let pk = forge(&mut lp, &ak, now + 50_000);
    lp.peers[0].receive(&pk.bytes, pk.blobs.clone()).unwrap();
    let mut label = Label::default();
    label.place(&mut lp, g, &[0]);
    let done = lp.peers[0].engine.grant_with(&g, &tids[2], &edge(Role::Write), History::None).unwrap();
    label.note(&done);
    label.place(&mut lp, g, &[0]);
    deliver_as_newcomer(&mut lp, 0, 2, g, &done, &label);
    assert_eq!(content(&mut lp, 2, g), keys(&["x", "e"]));
    let r = |lp: &mut LocalPeer| lp.peers[2].engine.get(&g, &reg).unwrap();
    assert_eq!(r(&mut lp), Some(osis_base::Value::Int(1)));
    lp.advance(20_000);
    assert_eq!(content_now(&mut lp, 0, g), keys(&["x"]));
    assert_eq!(content_now(&mut lp, 2, g), keys(&["x"]), "a forged expiry extends a value at N");
    let pk = forge(&mut lp, &reg, now + 40_000);
    lp.peers[2].receive(&pk.bytes, pk.blobs.clone()).unwrap();
    lp.advance(10);
    let two = set(&mut lp, 2);
    let pk = lp.peers[0].engine.package(&two).unwrap().unwrap();
    lp.peers[2].receive(&pk.bytes, pk.blobs.clone()).unwrap();
    lp.advance(10);
    let mut m = crate::Mutation::new();
    m.undo(two);
    lp.peers[2].commit(m).unwrap();
    assert_eq!(r(&mut lp), Some(osis_base::Value::Int(1)), "N's undo writes back the value before");
    lp.advance(40_000);
    assert_eq!(content_now(&mut lp, 2, g), keys(&["x"]), "a forged expiry ends a lasting value at N");
    assert_eq!(r(&mut lp), Some(osis_base::Value::Int(1)), "a forged expiry ends the value N's undo writes back");
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
    let g = group(&mut lp, 0);
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
