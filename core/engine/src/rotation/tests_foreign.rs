//! Foreign keysets (spec/crypto.md §4 Holder actors, Foreign; notes/disputes.md, Rotations under
//! a fork): a permanent fork on a holder actor M of A, A's admins holding A directly. Shapes from
//! core/test/tla/rotation/ForkRot.tla.

#![allow(clippy::unwrap_used)]
use super::tests::{edge, independent_thing, newest_read, rotate_as, rotate_leaving_out, synced};
use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use osis_base::{Role, Tid};
use osis_crypto::Epoch;

const P: usize = 0;
const Q: usize = 1;

/// P (peer 0) and Q (1), admins of M and of A, M a reader of A (C, peer 2, the mint admin of
/// both), synced. Then the fight on M: Q removes P (its clock ahead), P removes Q stamped earlier,
/// each before seeing the other's, each removal rotating M (kQ, kP); P and Q exchange everything,
/// each siding with itself for good: the other's keyset of M is held invalid there. C hears no
/// more. Returns the peers, M, A, kP, kQ.
fn fork_on_m() -> (LocalPeer, Tid, Tid, Epoch, Epoch) {
    let (lp, (m, a, kp, kq)) = LocalPeer::cached("rotation::tests_foreign::fork_on_m", || {
        let mut lp = synced(3);
        let (p, q) = (lp.peers[P].engine.tid(), lp.peers[Q].engine.tid());
        let m = independent_thing(&mut lp, 2);
        let a = independent_thing(&mut lp, 2);
        for t in [m, a] {
            for h in [p, q] {
                lp.peers[2].engine.grant(&t, &h, &edge(Role::Admin)).unwrap();
            }
        }
        lp.sync_all().unwrap();
        lp.peers[2].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        lp.advance(1000);
        lp.peers[Q].clock.advance(5000);
        lp.peers[Q].engine.demote(&m, &Demotion { holder: p, new: None, retain: None }).unwrap();
        lp.peers[P].engine.demote(&m, &Demotion { holder: q, new: None, retain: None }).unwrap();
        let (kp, kq) = (newest_read(&lp, P, m).unwrap(), newest_read(&lp, Q, m).unwrap());
        exchange(&mut lp);
        (lp, (m, a, kp, kq))
    });
    (lp, m, a, kp, kq)
}

/// P and Q send each other everything.
fn exchange(lp: &mut LocalPeer) {
    lp.sync(P, Q).unwrap();
    lp.sync(Q, P).unwrap();
}

/// Rounds of P and Q each rotating what is due on A (at once, then at a pass's end) and
/// re-sealing, then exchanging, until a round makes nothing or `max` rounds: the rotations of A
/// each round.
fn rounds(lp: &mut LocalPeer, a: Tid, max: usize) -> Vec<usize> {
    let mut out = Vec::new();
    while out.len() < max {
        let mut n = 0;
        for i in [P, Q] {
            n += lp.peers[i].engine.ensure_rotated(&a).unwrap().0.commits.len();
            n += lp.peers[i].engine.pass_end_rotations(&a).unwrap().commits.len();
            n += lp.peers[i].engine.reseal_after_pass(&a).unwrap().commits.len();
        }
        exchange(lp);
        out.push(n);
        if n == 0 {
            break;
        }
    }
    out
}

/// Whether keyset `k` of `m` is held valid at peer `i`.
fn held_valid(lp: &LocalPeer, i: usize, m: Tid, k: Epoch) -> bool {
    lp.peers[i].engine.core.ix.keysets.contains_key(&(m, Role::Read, k))
}

// spec/crypto.md §4 (Foreign), model `FR_m` (and `FR_m_now`, its negative control): under a
// permanent fork on holder actor M, each side holding the other's keysets of M invalid, the
// rotations of A stop: each side's epoch of A boxing M at its own keyset is foreign at the other,
// supersedes nothing there and makes nothing due there. As built (every valid rotation
// superseding, a box naming a keyset held invalid due), the sides rotate A in turn for good.
#[test]
fn fork_on_a_holder_actor_stops_rotating_spec_crypto_4() {
    let (mut lp, m, a, kp, kq) = fork_on_m();
    assert!(held_valid(&lp, P, m, kp) && !held_valid(&lp, P, m, kq), "P holds kQ invalid");
    assert!(held_valid(&lp, Q, m, kq) && !held_valid(&lp, Q, m, kp), "Q holds kP invalid");
    let r = rounds(&mut lp, a, 10);
    assert!(r.last() == Some(&0) && r.iter().sum::<usize>() <= 6, "rotations of A stop: {r:?}");
    // settled, each side writes under an epoch of its own sealing M at its own keyset
    for (i, k) in [(P, kp), (Q, kq)] {
        let e = newest_read(&lp, i, a).unwrap();
        assert!(!is_foreign(&lp, i, a, e) && boxed_at(&mut lp, i, a, e, m) == Some(k), "peer {i}");
        // the box records and invalid keysets foreign rests on: an open and a rebuild agree
        lp.peers[i].engine.check_index();
    }
}

/// Whether `a`'s read epoch `e` is foreign at peer `i`.
fn is_foreign(lp: &LocalPeer, i: usize, a: Tid, e: Epoch) -> bool {
    lp.peers[i].engine.epochs(&a).unwrap().read.is_foreign(&e)
}

/// The keyset of `m` the box of `a`'s read epoch `e` to `m` names at peer `i`.
fn boxed_at(lp: &mut LocalPeer, i: usize, a: Tid, e: Epoch, m: Tid) -> Option<Epoch> {
    let s = lp.peers[i].engine.get_typed(&a, &osis_schema::core_types::SECRETS).unwrap()?;
    s.boxes.iter().find(|(k, _)| k.holder == osis_base::Weak(m) && k.role == Role::Read && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|x| x == e)).and_then(|(_, b)| osis_keys::box_keysets(b).into_iter().next())
}

/// The rotations of A peer `i` makes now: what is due at once and at a pass's end.
fn due_now(lp: &mut LocalPeer, i: usize, a: Tid) -> usize {
    lp.peers[i].engine.ensure_rotated(&a).unwrap().0.commits.len() + lp.peers[i].engine.pass_end_rotations(&a).unwrap().commits.len()
}

/// `fork_on_m`, then P and Q each rotate A once for the fork (eP boxing M at kP, eQ at kQ),
/// neither having seen the other's, and exchange. Returns the peers, M, A, eP, eQ.
fn concurrent_epochs() -> (LocalPeer, Tid, Tid, Epoch, Epoch) {
    let (mut lp, m, a, kp, kq) = fork_on_m();
    for i in [P, Q] {
        assert_eq!(lp.peers[i].engine.ensure_rotated(&a).unwrap().0.commits.len(), 1, "peer {i} rotates A for M's knowing keyset");
    }
    let (ep, eq) = (newest_read(&lp, P, a).unwrap(), newest_read(&lp, Q, a).unwrap());
    assert_eq!((boxed_at(&mut lp, P, a, ep, m), boxed_at(&mut lp, Q, a, eq, m)), (Some(kp), Some(kq)));
    exchange(&mut lp);
    (lp, m, a, ep, eq)
}

// spec/crypto.md §4 (Foreign: makes no rotation due), model `FR_m_supsonly`: P's epoch eP, held at
// Q, boxes M at kP, held invalid at Q: a stale box, which would make Q's knowing re-key due; eP
// is foreign at Q, so nothing is due there, and alike at P for eQ.
#[test]
fn foreign_epoch_makes_nothing_due_spec_crypto_4() {
    let (mut lp, _, a, ep, eq) = concurrent_epochs();
    for (i, theirs) in [(Q, ep), (P, eq)] {
        let cur = lp.peers[i].engine.epochs(&a).unwrap().read.current();
        assert!(cur.contains(&theirs) && is_foreign(&lp, i, a, theirs), "peer {i}: the other's epoch current and foreign");
        assert_eq!(due_now(&mut lp, i, a), 0, "peer {i}: nothing due");
    }
}

// spec/crypto.md §4 (Foreign: supersedes nothing), model `FR_m_dueonly`: P, holding eQ (foreign
// at P), rotates A again (eP2): its keyset lists eQ nowhere, its history box carries it. At Q,
// eP2 is foreign and supersedes nothing: eQ stays current there, Q's newest, and nothing is due;
// superseding, it would leave Q only foreign epochs to write under, a rotation due at once.
#[test]
fn foreign_rotation_supersedes_nothing_spec_crypto_4() {
    let (mut lp, _, a, _, eq) = concurrent_epochs();
    lp.advance(1000);
    rotate_leaving_out(&mut lp, P, a, &[Role::Read].into(), &[]);
    let ep2 = newest_read(&lp, P, a).unwrap();
    let lists = |lp: &LocalPeer, i: usize, e: Epoch| lp.peers[i].engine.core.ix.keysets.get(&(a, Role::Read, e)).map(|k| k.lists.clone()).unwrap_or_default();
    assert!(!lists(&lp, P, ep2).contains(&eq), "eP2's keyset lists no foreign epoch");
    assert!(!lp.peers[P].engine.epochs(&a).unwrap().read.current().contains(&eq), "its history box carries eQ: superseded at P");
    exchange(&mut lp);
    assert!(is_foreign(&lp, Q, a, ep2));
    assert_eq!(newest_read(&lp, Q, a), Some(eq), "eQ stays Q's newest");
    assert_eq!(due_now(&mut lp, Q, a), 0);
}

// spec/crypto.md §4 (Foreign: blocked, current), model `FR_m_exclude` (`Kept`): eP at Q is blocked
// (nobody there encrypts under it) yet current: a grant there boxes the grantee at it, and Q's
// next rotation's history box carries it (its keyset does not list it: ForkDepth `FD_fork_list`),
// so its content stays readable to Q's later holders.
#[test]
fn foreign_epoch_blocks_and_stays_current_spec_crypto_4() {
    let (mut lp, _, a, ep, _) = concurrent_epochs();
    let blocked = lp.peers[Q].engine.run(|tx| {
        let deps = super::departures(tx, &a)?;
        super::blocked_epoch(tx, &tx.core.tid(), &a, Role::Read, &ep, &deps, super::Walk::Encrypt)
    });
    assert!(blocked.unwrap(), "eP is blocked at Q");
    let x = independent_thing(&mut lp, Q);
    lp.peers[Q].engine.grant(&a, &x, &edge(Role::Read)).unwrap();
    assert!(boxed_at(&mut lp, Q, a, ep, x).is_some(), "the grant boxes X at eP");
    lp.advance(1000);
    rotate_leaving_out(&mut lp, Q, a, &[Role::Read].into(), &[]);
    let eq2 = newest_read(&lp, Q, a).unwrap();
    let k = lp.peers[Q].engine.core.ix.keysets.get(&(a, Role::Read, eq2)).unwrap().lists.clone();
    assert!(!k.contains(&ep), "Q's next keyset lists no foreign epoch: {k:?}");
    let ep_q = lp.peers[Q].engine.epochs(&a).unwrap();
    let read = &ep_q.read;
    assert!(read.get(&eq2).is_some_and(|i| i.supersedes.contains(&ep)), "its history box carries eP");
    assert!(!read.current().contains(&ep), "superseded at Q");
}

// spec/crypto.md §4 (Foreign; Stale), model `FR_m` (`Quiet`: each shared epoch the other side
// re-seals M into costs a side one rotation): P rotates A leaving M out (eS: its own box records
// name nothing, so it is foreign nowhere). Q re-seals M into eS at kQ; at P that re-seal's box is
// stale (a re-seal's box makes its epoch stale, not foreign: eS was not built on it), so P
// rotates once, then nothing is due anywhere.
#[test]
fn reseal_into_a_shared_epoch_costs_one_rotation_spec_crypto_4() {
    let (mut lp, m, a, _, kq) = fork_on_m();
    rotate_as(&mut lp, P, a, &[Role::Read].into(), &[(m, None)]).unwrap();
    let es = newest_read(&lp, P, a).unwrap();
    assert_eq!(boxed_at(&mut lp, P, a, es, m), None, "eS leaves M out");
    exchange(&mut lp);
    assert!(!is_foreign(&lp, Q, a, es) && !is_foreign(&lp, P, a, es), "foreign nowhere");
    lp.peers[Q].engine.reseal_after_pass(&a).unwrap();
    assert_eq!(boxed_at(&mut lp, Q, a, es, m), Some(kq), "Q re-seals M into eS");
    exchange(&mut lp);
    assert!(!is_foreign(&lp, P, a, es), "the re-seal makes eS stale at P, not foreign");
    assert_eq!(due_now(&mut lp, P, a), 1, "one rotation at P");
    exchange(&mut lp);
    // P's rotation removed the boxes at eS, current still at Q (eP is foreign there): Q
    // re-seals its holders into it, once
    for i in [P, Q] {
        assert_eq!(due_now(&mut lp, i, a), 0, "peer {i}: no rotation due");
    }
    lp.peers[Q].engine.reseal_after_pass(&a).unwrap();
    exchange(&mut lp);
    let r = rounds(&mut lp, a, 10);
    assert_eq!(r, vec![0], "then none");
}

/// `fork_on_m` with G above A: P and Q admins of G, A a reader of G (C's), and the fight on M.
fn fork_below_g() -> (LocalPeer, Tid, Tid, Tid) {
    let (lp, (m, a, g)) = LocalPeer::cached("rotation::tests_foreign::fork_below_g", || {
        let mut lp = synced(3);
        let (p, q) = (lp.peers[P].engine.tid(), lp.peers[Q].engine.tid());
        let m = independent_thing(&mut lp, 2);
        let a = independent_thing(&mut lp, 2);
        let g = independent_thing(&mut lp, 2);
        for t in [m, a, g] {
            for h in [p, q] {
                lp.peers[2].engine.grant(&t, &h, &edge(Role::Admin)).unwrap();
            }
        }
        lp.sync_all().unwrap();
        lp.peers[2].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
        lp.peers[2].engine.grant(&g, &a, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        lp.advance(1000);
        lp.peers[Q].clock.advance(5000);
        lp.peers[Q].engine.demote(&m, &Demotion { holder: p, new: None, retain: None }).unwrap();
        lp.peers[P].engine.demote(&m, &Demotion { holder: q, new: None, retain: None }).unwrap();
        exchange(&mut lp);
        (lp, (m, a, g))
    });
    (lp, m, a, g)
}

// spec/crypto.md §4 (Foreign: an epoch boxing a foreign keyset is foreign): the fork on M two
// levels below G (M a reader of A, A a reader of G, P and Q admins of all three). P's epoch of G
// boxes A at P's epoch of A, foreign at Q: P's epoch of G is foreign at Q in turn, so the
// rotations of G stop as A's do (judged one level only, the sides rotate G in turn for good).
#[test]
fn fork_two_below_stops_rotating_spec_crypto_4() {
    let (mut lp, _m, a, g) = fork_below_g();
    let mut out = Vec::new();
    for _ in 0..10 {
        let mut n = 0;
        for x in [a, g] {
            for i in [P, Q] {
                n += lp.peers[i].engine.ensure_rotated(&x).unwrap().0.commits.len();
                n += lp.peers[i].engine.pass_end_rotations(&x).unwrap().commits.len();
                n += lp.peers[i].engine.reseal_after_pass(&x).unwrap().commits.len();
            }
        }
        exchange(&mut lp);
        out.push(n);
        if n == 0 {
            break;
        }
    }
    assert_eq!(out.last(), Some(&0), "{out:?}");
    // settled, each side writes G under an epoch of its own boxing A at its own epoch of A
    for i in [P, Q] {
        let eg = newest_read(&lp, i, g).unwrap();
        let ea = newest_read(&lp, i, a).unwrap();
        assert!(!is_foreign(&lp, i, g, eg), "peer {i}");
        assert_eq!(boxed_at(&mut lp, i, g, eg, a), Some(ea), "peer {i}: G boxes A at its newest");
    }
}

/// Rounds over `things` (in order) as `fork_two_below_stops_rotating_spec_crypto_4`'s: each of P
/// and Q rotating what is due and re-sealing, then exchanging, until a round makes nothing or
/// `max` rounds. The commits of each round.
fn rounds_over(lp: &mut LocalPeer, things: &[Tid], max: usize) -> Vec<usize> {
    let mut out = Vec::new();
    while out.len() < max {
        let mut n = 0;
        for x in things {
            for i in [P, Q] {
                n += lp.peers[i].engine.ensure_rotated(x).unwrap().0.commits.len();
                n += lp.peers[i].engine.pass_end_rotations(x).unwrap().commits.len();
                n += lp.peers[i].engine.reseal_after_pass(x).unwrap().commits.len();
            }
        }
        exchange(lp);
        out.push(n);
        if n == 0 {
            break;
        }
    }
    out
}

// spec/crypto.md §4 (Foreign: an epoch boxing a foreign keyset is foreign, and above its thing
// a foreign keyset is sealed to nowhere; Seal), model `ForkDepth` (`FD_fork`; `FD_fork_builder`,
// `FD_fork_list` its negative controls): the fork on M two levels below G, but P rotates A and G
// first and Q only once it holds them. Were P's keyset of A an anchor or Seal candidate to G at
// Q, or did Q's rotation of A list P's epoch (current at Q, foreign there), each side would find
// its own keyset of A stale to G or seal A at the other's, leave A out of G and re-key A, making
// the other side's stale in turn, for good. Rotations stop, and each side writes G under an epoch
// of its own boxing A.
#[test]
fn fork_two_below_one_side_first_stops_rotating_spec_crypto_4() {
    let (mut lp, _m, a, g) = fork_below_g();
    for x in [a, g] {
        lp.peers[P].engine.ensure_rotated(&x).unwrap();
    }
    assert!(newest_read(&lp, P, g) != newest_read(&lp, Q, g), "P rotated G");
    exchange(&mut lp);
    let r = rounds_over(&mut lp, &[a, g], 12);
    assert_eq!(r.last(), Some(&0), "rotations stop: {r:?}");
    for i in [P, Q] {
        let eg = newest_read(&lp, i, g).unwrap();
        let ea = newest_read(&lp, i, a).unwrap();
        assert!(!is_foreign(&lp, i, g, eg), "peer {i}");
        assert_eq!(boxed_at(&mut lp, i, g, eg, a), Some(ea), "peer {i}: G boxes A at its newest");
    }
}

const W: usize = 3;
const R: usize = 4;

/// The fork on M (P against Q, as `fork_below_g`) below A below G, with W (peer 3) a writer of G
/// alone and R (peer 4) a writer of A and a reader of G: each may rotate one of the two. Q
/// rotates A for the fork (eQ, boxing M at Q's keyset), then everyone syncs: W and R, holding
/// both removals with no order, take the walk's side, P's (Q's removal of P is stamped after P's
/// of Q), where eQ is foreign.
fn fork_with_one_role_rotators() -> (LocalPeer, Tid, Tid, Tid, Epoch) {
    let (lp, (m, a, g, eq)) = LocalPeer::cached("rotation::tests_foreign::fork_with_one_role_rotators", || {
        let mut lp = synced(5);
        let ids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.me()).collect();
        let (m, a, g) = (independent_thing(&mut lp, 2), independent_thing(&mut lp, 2), independent_thing(&mut lp, 2));
        for t in [m, a, g] {
            for i in [P, Q] {
                lp.peers[2].engine.grant(&t, &ids[i], &edge(Role::Admin)).unwrap();
            }
        }
        lp.peers[2].engine.grant(&g, &ids[W], &edge(Role::Write)).unwrap();
        lp.peers[2].engine.grant(&a, &ids[R], &edge(Role::Write)).unwrap();
        lp.peers[2].engine.grant(&g, &ids[R], &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        lp.peers[2].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
        lp.peers[2].engine.grant(&g, &a, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        lp.advance(1000);
        lp.peers[Q].clock.advance(5000);
        lp.peers[Q].engine.demote(&m, &Demotion { holder: ids[P], new: None, retain: None }).unwrap();
        lp.peers[P].engine.demote(&m, &Demotion { holder: ids[Q], new: None, retain: None }).unwrap();
        exchange(&mut lp);
        lp.peers[Q].engine.ensure_rotated(&a).unwrap();
        let eq = newest_read(&lp, Q, a).unwrap();
        lp.sync_all().unwrap();
        (lp, (m, a, g, eq))
    });
    (lp, m, a, g, eq)
}

// spec/crypto.md §4 (Foreign; Left out, Re-key: at most one rotation of M per rotator of M):
// on P's side Q's epoch eQ of A is foreign, current and blocked, and lists A's first epoch, which
// it keeps stale. W rotates G: Seal gives that stale keyset, so W leaves A out of G, recording
// eQ with causes that stand for good. R re-keys A at G's pass end; its rotation carries
// eQ in its history box, superseding it at R (its maker, holding the secret), so eQ is no current
// keyset of A there and the record no longer leaves A out: five more pass ends of G, W
// re-sealing and nobody rotating G, rotate A no more.
#[test]
fn a_foreign_keyset_left_out_is_rekeyed_once_spec_crypto_4() {
    let (mut lp, _m, a, g, eq) = fork_with_one_role_rotators();
    assert!(lp.peers[R].engine.epochs(&a).unwrap().read.is_foreign(&eq), "eQ foreign at R");
    lp.advance(1000);
    rotate_as(&mut lp, W, g, &[Role::Read].into(), &[]).unwrap();
    lp.sync_all().unwrap();
    let eg = newest_read(&lp, W, g).unwrap();
    let rec = lp.peers[R].engine.core.ix.keysets.get(&(g, Role::Read, eg)).and_then(|k| k.left_out.get(&a).cloned()).unwrap_or_default();
    assert!(rec.contains_key(&eq), "W's rotation of G leaves A out at eQ: {rec:?}");
    let mut rekeys = Vec::new();
    for _ in 0..6 {
        lp.advance(1000);
        let before = newest_read(&lp, R, a);
        lp.peers[R].engine.pass_end_rotations(&g).unwrap();
        rekeys.push(newest_read(&lp, R, a) != before);
        lp.sync_all().unwrap();
        lp.peers[W].engine.reseal_after_pass(&g).unwrap();
        lp.sync_all().unwrap();
    }
    assert_eq!(rekeys.iter().filter(|x| **x).count(), 1, "A re-keyed once: {rekeys:?}");
}
