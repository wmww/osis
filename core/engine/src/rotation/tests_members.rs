//! Holder actors (spec/crypto.md §4, Holder actors; spec/permissions.md §3): sealing at an
//! anchored keyset or jointly (rule 1), stale boxes (rule 2), rotations due (rule 3), no key cycles (rule 4) and
//! tainted keysets (4b). The leak oracle is `openable`: what a departed party opens from its old
//! secrets and every box held, whatever its own node does. Shapes from the depth-0 model
//! (core/test/tla/rotation/Depth0.tla).

#![allow(clippy::unwrap_used)]
use super::tests::{all_boxed, blocked_at, commit_ids, deliver_without_secrets, edge, independent_thing, held_by, leaked, newest_read, openable, rotate_as, rotate_leaving_out, send_skipping, settle, synced};
use crate::Mutation;
use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use osis_base::{CommitId, Role, Tid, Time};
use osis_crypto::Epoch;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

type Opened = BTreeSet<(Tid, Role, Epoch)>;

/// Whether `a`'s `secrets.0` at peer `i` boxes `h` at all.
fn boxes(lp: &mut LocalPeer, i: usize, a: Tid, h: Tid) -> bool {
    lp.peers[i].engine.get_typed(&a, &ct::SECRETS).unwrap().is_some_and(|s| s.boxes.keys().any(|k| k.holder == osis_base::Weak(h)))
}

/// The keyset of `m` the box of `a`'s newest read epoch to `m` names, at peer `i`.
fn sealed_at(lp: &mut LocalPeer, i: usize, a: Tid, m: Tid) -> Option<Epoch> {
    let e = newest_read(lp, i, a)?;
    let s = lp.peers[i].engine.get_typed(&a, &ct::SECRETS).unwrap()?;
    s.boxes.iter().find(|(k, _)| k.holder == osis_base::Weak(m) && k.role == Role::Read && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|x| x == e)).and_then(|(_, b)| osis_keys::box_keysets(b).into_iter().next())
}

/// Peer `i` rotates `rot` of `g` leaving out the holders `skip` (`rotate_as`).
fn rotate_skipping(lp: &mut LocalPeer, i: usize, g: Tid, rot: &BTreeSet<Role>, skip: &[Tid]) {
    rotate_as(lp, i, g, rot, &skip.iter().map(|t| (*t, None)).collect::<Vec<_>>()).unwrap();
}

/// The newest epochs of `gs` (actors with the peer writing under each) that `d` opens from its
/// old secrets `start` beyond what boxes to `d` itself give it (through every actor of `gs`),
/// once each writer rotated what is due before encrypting (`ensure_rotated`), synced, until none
/// is: the leak oracle of writers holding every knowing keyset (before that, a writer that has
/// not received a holder actor's knowing rotation is within the stated limit).
fn leaks_after_cascade(lp: &mut LocalPeer, gs: &[(Tid, usize)], d: Tid, start: &Opened) -> Vec<(Tid, Role)> {
    for _ in 0..8 {
        let mut n = 0;
        for &(t, i) in gs {
            n += lp.peers[i].engine.ensure_rotated(&t).unwrap().0.commits.len();
        }
        lp.sync_all().unwrap();
        if n == 0 {
            break;
        }
    }
    let actors: Vec<Tid> = gs.iter().map(|g| g.0).collect();
    let mut out = Vec::new();
    for &(t, i) in gs {
        let legit = openable(lp, i, &actors, d, BTreeSet::new());
        let all = openable(lp, i, &actors, d, start.clone());
        let blocked = blocked_at(lp, i, t);
        let Some(e) = lp.peers[i].engine.epochs(&t) else { continue };
        for r in osis_keys::ROLES {
            if let Some((n, _)) = e.role(r).newest_held()
                && !blocked.contains(&r)
                && all.contains(&(t, r, n))
                && !legit.contains(&(t, r, n))
            {
                out.push((t, r));
            }
        }
    }
    out
}

fn removal(lp: &mut LocalPeer, i: usize, t: Tid, d: Tid) -> Vec<osis_base::CommitId> {
    lp.peers[i].engine.demote(&t, &Demotion { holder: d, new: None, retain: None }).unwrap().commits
}

// spec/crypto.md §4 (holder actors: stale), spec/permissions.md §3 (required rotation; required through a's keyset): a node removed 12 actors below G0 (G11 in G10 ... in G0). No departure is G0's,
// but each level's box to the one below is stale once that one rotates, so the cascade rotates
// every level, bottom-up, and the removed node holds none of it.
#[test]
fn removal_twelve_deep_rotates_every_level_spec_crypto_4() {
    let mut lp = synced(2);
    let d = lp.peers[1].engine.tid();
    let gs: Vec<Tid> = (0..12).map(|_| independent_thing(&mut lp, 0)).collect();
    for w in gs.windows(2) {
        lp.grant_through(0, w[0], w[1], &edge(Role::Write));
    }
    lp.grant_through(0, gs[11], d, &edge(Role::Write));
    lp.sync(0, 1).unwrap();
    assert!(newest_read(&lp, 1, gs[0]).is_some(), "d reads G0 through 11 actors");
    let before: Vec<_> = gs.iter().map(|g| newest_read(&lp, 0, *g)).collect();
    removal(&mut lp, 0, gs[11], d);
    assert!(lp.peers[0].engine.departures(&gs[0]).unwrap().is_empty(), "nothing departed from G0");
    assert!(blocked_at(&mut lp, 0, gs[10]).contains(&Role::Read), "G10's box to G11 is stale");
    assert!(blocked_at(&mut lp, 0, gs[0]).contains(&Role::Read), "G0 boxes G1 at a keyset peer 0 may not encrypt under, down to G10's");
    let (done, still) = lp.peers[0].engine.ensure_rotated(&gs[0]).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(done.commits.len(), 11, "G10 up to G0");
    for (i, g) in gs.iter().enumerate() {
        assert_ne!(newest_read(&lp, 0, *g), before[i], "G{i} rotated");
    }
    assert!(lp.peers[0].engine.ensure_rotated(&gs[0]).unwrap().0.commits.is_empty(), "settled");
    lp.sync(0, 1).unwrap();
    let top = newest_read(&lp, 0, gs[0]).unwrap();
    assert!(lp.peers[1].engine.epochs(&gs[0]).unwrap().read.secret(&top).is_none(), "d does not hold G0's new secret");
}

// spec/crypto.md §4, spec/permissions.md §3: a diamond (A over X and Y, both over Z): a removal
// from Z rotates X, Y and A once each, by staleness. A lattice 4 wide and 10 deep (4^9 chains
// from the top to the bottom actor) rotates each actor above the bottom once.
#[test]
fn diamond_and_lattice_rotate_once_spec_crypto_4() {
    let mut lp = synced(2);
    let d = lp.peers[1].engine.tid();
    let [a, x, y, z] = [0; 4].map(|_| independent_thing(&mut lp, 0));
    for (t, m) in [(a, x), (a, y), (x, z), (y, z)] {
        lp.peers[0].engine.grant(&t, &m, &edge(Role::Write)).unwrap();
    }
    lp.peers[0].engine.grant(&z, &d, &edge(Role::Read)).unwrap();
    removal(&mut lp, 0, z, d);
    let (done, still) = lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(done.commits.len(), 3, "X, Y, then A");
    assert!(lp.peers[0].engine.ensure_rotated(&a).unwrap().0.commits.is_empty());
    let top = independent_thing(&mut lp, 0);
    let mut layer = vec![top];
    for _ in 0..9 {
        let next: Vec<Tid> = (0..4).map(|_| independent_thing(&mut lp, 0)).collect();
        for t in &layer {
            for m in &next {
                lp.peers[0].engine.grant(t, m, &edge(Role::Write)).unwrap();
            }
        }
        layer = next;
    }
    lp.peers[0].engine.grant(&layer[0], &d, &edge(Role::Read)).unwrap();
    removal(&mut lp, 0, layer[0], d);
    let (done, still) = lp.peers[0].engine.ensure_rotated(&top).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(done.commits.len(), 8 * 4 + 1, "every actor above the bottom one once");
}

/// A cycle of `len` actors of peer 0's, `cyc[i + 1]` granted on `cyc[i]` in order, so the
/// last grant (`cyc[0]` on `cyc[len - 1]`) closes the cycle and is keyless; D and N readers of
/// `cyc[len - 1]`, which reads the whole cycle.
fn cycle(lp: &mut LocalPeer, len: usize) -> Vec<Tid> {
    let (d, n) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let cyc: Vec<Tid> = (0..len).map(|_| independent_thing(lp, 0)).collect();
    for i in 0..len {
        lp.peers[0].clock.advance(1);
        lp.grant_through(0, cyc[i], cyc[(i + 1) % len], &edge(Role::Read));
    }
    for x in [d, n] {
        lp.grant_through(0, cyc[len - 1], x, &edge(Role::Read));
    }
    cyc
}

// spec/crypto.md §4 (key access: no key cycles), spec/permissions.md §3 (role cycles): X0 <-
// X1 (<- X2) <- X0, the grant closing the cycle last: keyless, so its holder is boxed nothing
// and no key cycle forms. D, a reader of the last actor, reads the whole cycle; its removal
// leaves no epoch a writer encrypts under (after the rotations due) that D opens; the cycle
// settles with every holder with key access boxed, and N, still a reader, reads it all.
#[test]
fn removal_in_cycle_spec_crypto_4() {
    for len in [2, 3] {
        let mut lp = synced(3);
        let d = lp.peers[1].engine.tid();
        let cyc = cycle(&mut lp, len);
        assert!(!boxes(&mut lp, 0, cyc[len - 1], cyc[0]), "len {len}: the closing grant is keyless");
        assert!(!lp.peers[0].engine.run(|tx| Ok(super::members::keyed(tx.core, &cyc[len - 1], &cyc[0]))).unwrap());
        lp.sync(0, 1).unwrap();
        let start = held_by(&lp, 1, &cyc);
        assert!(cyc.iter().all(|t| start.contains(&(*t, Role::Read, newest_read(&lp, 0, *t).unwrap()))), "len {len}: D reads the whole cycle");
        removal(&mut lp, 0, cyc[len - 1], d);
        let gs: Vec<(Tid, usize)> = cyc.iter().map(|t| (*t, 0)).collect();
        assert_eq!(leaks_after_cascade(&mut lp, &gs, d, &start), vec![], "len {len}: after the removal");
        assert_eq!(settle(&mut lp, &[0], &cyc), 0, "len {len}: nothing left after the cascade");
        assert!(cyc.iter().all(|t| blocked_at(&mut lp, 0, *t).is_empty()), "len {len}");
        assert!(all_boxed(&mut lp, 0, &cyc), "len {len}");
        assert_eq!(leaked(&mut lp, 0, &cyc, d, start), Vec::<Tid>::new(), "len {len}");
        lp.sync(0, 2).unwrap();
        for t in &cyc {
            assert_eq!(newest_read(&lp, 2, *t), newest_read(&lp, 0, *t), "len {len}: N reads the cycle");
        }
    }
}

// spec/crypto.md §4 (key access), spec/permissions.md §3: a cycle (B over P; Q holds P first,
// then P holds Q: keyless). A removal from Q rotates P (its box to Q stale), then B; P is never
// re-sealed on Q, and nothing churns.
#[test]
fn keyless_holder_never_resealed_spec_crypto_4() {
    let mut lp = synced(2);
    let d = lp.peers[1].engine.tid();
    let [b, p, q] = [0; 3].map(|_| independent_thing(&mut lp, 0));
    for (t, m) in [(b, p), (p, q), (q, p)] {
        lp.peers[0].clock.advance(1);
        lp.peers[0].engine.grant(&t, &m, &edge(Role::Write)).unwrap();
    }
    lp.peers[0].engine.grant(&q, &d, &edge(Role::Read)).unwrap();
    removal(&mut lp, 0, q, d);
    let (done, still) = lp.peers[0].engine.ensure_rotated(&b).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(done.commits.len(), 2, "P, then B");
    assert!(lp.peers[0].engine.reseal_after_pass(&q).unwrap().commits.is_empty(), "P has no key access to Q");
    assert!(!boxes(&mut lp, 0, q, p));
    assert!(lp.peers[0].engine.ensure_rotated(&b).unwrap().0.commits.is_empty(), "no churn around the cycle");
    assert_eq!(settle(&mut lp, &[0], &[b, p, q]), 0);
}

// spec/crypto.md §4 (Key access), model `D0_fa_flip`, spec/permissions.md §1: T's mint admin is
// X, so T's grant on X closes a cycle through the record grant and is keyless (X boxes T nothing).
// Another admin of T removes X's record grant: T's grant is the only link left, it gains key
// access, and X's admin re-seals T; nothing leaks to X's side meanwhile and nobody is locked out.
#[test]
fn grant_on_mint_admin_keyless_until_record_edge_goes_spec_crypto_4() {
    let mut lp = synced(2);
    let d = lp.peers[1].engine.tid();
    let x = independent_thing(&mut lp, 0);
    let t = {
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, x);
        lp.peers[0].commit(m).unwrap();
        lp.hold(t);
        t
    };
    lp.peers[0].clock.advance(1);
    lp.peers[0].engine.grant(&x, &t, &edge(Role::Read)).unwrap();
    assert!(!boxes(&mut lp, 0, x, t), "T's grant on X is keyless: X's key yields T's by the record grant");
    lp.peers[0].clock.advance(1);
    lp.peers[0].engine.grant(&t, &d, &edge(Role::Admin)).unwrap();
    lp.sync(0, 1).unwrap();
    assert!(lp.peers[1].engine.reseal_after_pass(&x).unwrap().commits.is_empty(), "nothing to re-seal while the record grant stands");
    lp.peers[1].clock.advance(1);
    removal(&mut lp, 1, t, x);
    // T's removal rotation was judged with its grant keyless: no KEM key in its read keyset; KEM
    // key due at T's pass end writes one (spec/crypto.md §3)
    lp.peers[1].engine.reseal_after_pass(&t).unwrap();
    lp.sync(1, 0).unwrap();
    assert!(!lp.peers[0].engine.roster(&t).contains_key(&x), "X's record grant is gone");
    let done = lp.peers[0].engine.reseal_after_pass(&x).unwrap();
    assert!(!done.commits.is_empty(), "X re-seals T: its grant has key access now");
    assert!(boxes(&mut lp, 0, x, t));
    lp.sync(0, 1).unwrap();
    // one round: X's admin adds T's derived epoch (established at it alone) to T's history
    assert!(settle(&mut lp, &[0, 1], &[x, t]) <= 1, "settled");
    assert!(all_boxed(&mut lp, 0, &[x, t]));
}

// spec/crypto.md §4, spec/permissions.md §3 (role cycles; required rotation), model `D0_nc_below`: X and Y readers of each
// other (X granted on Y first, Y's grant on X keyless), Z a reader of X, D a reader of Z: D reads
// Z, X and Y. D's removal from Z makes X's box to Z stale, then Y's to X: the cascade rotates
// each once (Y in the same step as X, `rotate_above`), nothing is re-sealed, and D opens no epoch
// a writer encrypts under.
#[test]
fn departure_below_cycle_spec_crypto_4() {
    let mut lp = synced(2);
    let d = lp.peers[1].engine.tid();
    let [x, y, z] = [0; 3].map(|_| independent_thing(&mut lp, 0));
    for (t, m) in [(y, x), (x, y), (x, z)] {
        lp.peers[0].clock.advance(1);
        lp.grant_through(0, t, m, &edge(Role::Read));
    }
    lp.grant_through(0, z, d, &edge(Role::Read));
    lp.sync(0, 1).unwrap();
    let all = [x, y, z];
    let start = held_by(&lp, 1, &all);
    assert!(start.iter().any(|k| k.0 == y), "D reads Y through Z and X");
    removal(&mut lp, 0, z, d);
    let (done, still) = lp.peers[0].engine.ensure_rotated(&x).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(done.commits.len(), 2, "X, then Y above it (its box to X stale)");
    let gs: Vec<(Tid, usize)> = all.iter().map(|t| (*t, 0)).collect();
    assert_eq!(leaks_after_cascade(&mut lp, &gs, d, &start), vec![]);
    assert_eq!(settle(&mut lp, &[0], &all), 0, "settled");
    assert!(all_boxed(&mut lp, 0, &all));
    assert_eq!(leaked(&mut lp, 0, &all, d, start), Vec::<Tid>::new());
}

// spec/permissions.md §3 (role cycles): each admin acts alone: X (peer 0's) and Y (peer 2's)
// readers of each other, no common admin, Y granted on X first (X on Y keyless); D a reader of
// Y reads both. Peer 2 removes D: Y rotates. Peer 0, once it holds that, finds X's box to Y stale
// and rotates X. D opens neither, at either peer; the cycle settles.
#[test]
fn cycle_with_disjoint_admins_converges_spec_permissions_3() {
    let mut lp = synced(3);
    let d = lp.peers[1].engine.tid();
    let x = independent_thing(&mut lp, 0);
    let y = independent_thing(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.grant_through(0, x, y, &edge(Role::Read));
    lp.sync_all().unwrap();
    lp.peers[2].clock.advance(1_000);
    lp.grant_through(2, y, x, &edge(Role::Read));
    lp.grant_through(2, y, d, &edge(Role::Read));
    lp.sync_all().unwrap();
    for i in [0, 2] {
        assert!(!boxes(&mut lp, i, y, x), "peer {i}: X's grant on Y keyless");
    }
    let start = held_by(&lp, 1, &[x, y]);
    assert!(start.contains(&(x, Role::Read, newest_read(&lp, 1, x).unwrap())), "D reads X through Y");
    removal(&mut lp, 2, y, d);
    lp.sync(2, 0).unwrap();
    assert!(blocked_at(&mut lp, 0, x).contains(&Role::Read), "X's box to Y stale");
    let (done, still) = lp.peers[0].engine.ensure_rotated(&x).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(done.commits.len(), 1, "X");
    lp.sync_all().unwrap();
    for i in [0, 2] {
        assert!(all_boxed(&mut lp, i, &[x, y]));
        assert_eq!(leaked(&mut lp, i, &[x, y], d, start.clone()), Vec::<Tid>::new());
    }
    assert_eq!(settle(&mut lp, &[0, 2], &[x, y]), 0, "settled");
}

// spec/crypto.md §4, spec/permissions.md §3 (role cycles), model `D0_nc2`: X (peer 0's) and Y (peer 2's)
// readers of each other, Y first; D leaves X and E leaves Y concurrently, each by its actor's
// admin, neither knowing the other. Once each holds both, the cycle settles: no lockout (every
// holder with key access boxed, N of X and M of Y read what they hold roles on) and neither D
// nor E opens a newest epoch.
#[test]
fn cycle_concurrent_departures_spec_crypto_4() {
    let mut lp = synced(5);
    let [d, e, n] = [1, 3, 4].map(|i| lp.peers[i].engine.tid());
    let m = n;
    let x = independent_thing(&mut lp, 0);
    let y = independent_thing(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&x, &y, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&x, &d, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&x, &n, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[2].clock.advance(1_000);
    lp.peers[2].engine.grant(&y, &x, &edge(Role::Read)).unwrap();
    lp.peers[2].engine.grant(&y, &e, &edge(Role::Read)).unwrap();
    lp.peers[2].engine.grant(&y, &m, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    let (sd, se) = (held_by(&lp, 1, &[x, y]), held_by(&lp, 3, &[x, y]));
    removal(&mut lp, 0, x, d);
    removal(&mut lp, 2, y, e);
    lp.sync_all().unwrap();
    settle(&mut lp, &[0, 2], &[x, y]);
    for i in [0, 2] {
        assert!(all_boxed(&mut lp, i, &[x, y]), "peer {i}: no lockout");
        assert_eq!(leaked(&mut lp, i, &[x, y], d, sd.clone()), Vec::<Tid>::new(), "peer {i}: D");
        assert_eq!(leaked(&mut lp, i, &[x, y], e, se.clone()), Vec::<Tid>::new(), "peer {i}: E");
    }
    lp.sync_all().unwrap();
    for (t, i) in [(x, 0), (y, 2)] {
        assert_eq!(newest_read(&lp, 4, t), newest_read(&lp, i, t), "the remaining node reads {t:?}");
    }
}

/// Holder actor M (admins m1 = peer 0, m2 = peer 2, reader D = peer 1) reads A (admins a1 = peer
/// 3, a2 = peer 4), all synced: built once, a copy each call. Returns the peers, M and A.
fn two_admin_holder() -> (LocalPeer, Tid, Tid) {
    let (lp, (m, a)) = LocalPeer::cached("rotation::tests_members::two_admin_holder", || {
        let mut lp = synced(5);
        let (d, m2, a2) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid(), lp.peers[4].engine.tid());
        let m = independent_thing(&mut lp, 0);
        let a = independent_thing(&mut lp, 3);
        lp.grant_through(0, m, m2, &edge(Role::Admin));
        lp.grant_through(0, m, d, &edge(Role::Read));
        lp.grant_through(3, a, a2, &edge(Role::Admin));
        lp.sync_all().unwrap();
        lp.grant_through(3, a, m, &edge(Role::Read));
        lp.sync_all().unwrap();
        (lp, (m, a))
    });
    (lp, m, a)
}

/// Readers R (0) and E (3) of M (peer 2's), M a reader of A (peer 1's), A a reader of G (peer 0's),
/// W (4) G's admin, all synced: built once, a copy each call. Returns the peers, M, A, G.
fn co_writer_world() -> (LocalPeer, Tid, Tid, Tid) {
    let (lp, (m, a, g)) = LocalPeer::cached("rotation::tests_members::co_writer_world", || {
        let mut lp = synced(5);
        let [r, _, _, e, w] = std::array::from_fn(|i| lp.peers[i].engine.tid());
        let m = independent_thing(&mut lp, 2);
        for h in [r, e] {
            lp.peers[2].engine.grant(&m, &h, &edge(Role::Read)).unwrap();
        }
        lp.sync_all().unwrap();
        let a = independent_thing(&mut lp, 1);
        lp.peers[1].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        let g = independent_thing(&mut lp, 0);
        lp.peers[0].engine.grant(&g, &a, &edge(Role::Read)).unwrap();
        lp.peers[0].engine.grant(&g, &w, &edge(Role::Admin)).unwrap();
        lp.sync_all().unwrap();
        (lp, (m, a, g))
    });
    (lp, m, a, g)
}

/// Holder actor M (peer 1's admin m1, peer 3's admin Z) with reader D (2) reads A (peer 0's).
/// m1 removes D (C_M: M's knowing keyset kk). Returns the peers, A, M, C_M, M's keyset k0
/// before, kk and D's secrets of M and A before.
type MemberWorld = (LocalPeer, Tid, Tid, BTreeSet<osis_base::CommitId>, Epoch, Epoch, Opened);
fn member_world(d_role: Role) -> MemberWorld {
    let (lp, (a, m, c_m, k0, kk, start)) = LocalPeer::cached(&format!("rotation::tests_members::member_world/{d_role:?}"), || {
        let mut lp = synced(5);
        let tids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.tid()).collect();
        let m = independent_thing(&mut lp, 1);
        lp.peers[1].engine.grant(&m, &tids[2], &edge(d_role)).unwrap();
        lp.peers[1].engine.grant(&m, &tids[3], &edge(Role::Admin)).unwrap();
        let a = independent_thing(&mut lp, 0);
        lp.peers[0].engine.grant(&a, &tids[4], &edge(Role::Admin)).unwrap();
        lp.sync_all().unwrap();
        lp.grant_through(0, a, m, &edge(Role::Read));
        lp.sync_all().unwrap();
        let start = held_by(&lp, 2, &[m, a]);
        let k0 = newest_read(&lp, 1, m).unwrap();
        let before = commit_ids(&mut lp, 1);
        removal(&mut lp, 1, m, tids[2]);
        let c_m: BTreeSet<_> = commit_ids(&mut lp, 1).difference(&before).copied().collect();
        let kk = newest_read(&lp, 1, m).unwrap();
        (lp, (a, m, c_m, k0, kk, start))
    });
    (lp, a, m, c_m, k0, kk, start)
}

// spec/crypto.md §4 (Seal; Anchors; Forks stand): anchored until a merge; model `D0_member_anchor`: A seals
// M at m1's knowing keyset kk. Z, not knowing D left, forks M twice from before (F2, newest by
// n, not descending from kk); A holds F2 valid and newer, yet its next rotation seals M at kk,
// never at F2, so D opens no epoch of A made since its removal, not even by a history box. m1
// merges (F2 current and missing D's departure): A's box at kk is stale, A moves to the merge.
#[test]
fn ignorant_fork_anchored_until_merge_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let (mut lp, a, m, c_m, _, kk, start) = member_world(Role::Read);
    let d = lp.peers[2].engine.tid();
    send_skipping(&mut lp, 1, 0, &BTreeSet::new());
    assert!(blocked_at(&mut lp, 0, a).contains(&Role::Read), "A's box to M at the old keyset is stale");
    lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert_eq!(sealed_at(&mut lp, 0, a, m), Some(kk), "A sealed M at kk");
    // Z forks M, twice, never having seen C_M
    lp.peers[3].clock.advance(60_000);
    rotate_leaving_out(&mut lp, 3, m, &read, &[]);
    rotate_leaving_out(&mut lp, 3, m, &read, &[]);
    let f2 = newest_read(&lp, 3, m).unwrap();
    assert!(f2.n() > kk.n());
    send_skipping(&mut lp, 3, 0, &c_m);
    assert!(lp.peers[0].engine.core.ix.keysets.contains_key(&(m, Role::Read, f2)), "F2 held valid at A");
    assert!(blocked_at(&mut lp, 0, a).is_empty(), "kk is not stale: nothing lists it");
    rotate_leaving_out(&mut lp, 0, a, &read, &[]);
    assert_eq!(sealed_at(&mut lp, 0, a, m), Some(kk), "anchored on kk, not the newer ignorant fork");
    let opened = openable(&mut lp, 0, &[m, a], d, start.clone());
    let since: Vec<_> = lp.peers[0].engine.epochs(&a).unwrap().read.held().map(|x| x.0).filter(|e| !start.contains(&(a, Role::Read, *e))).collect();
    assert_eq!(since.len(), 2, "two rotations of A since D's removal");
    assert!(since.iter().all(|e| !opened.contains(&(a, Role::Read, *e))), "D opens no epoch of A since its removal");
    // m1 merges, A moves
    send_skipping(&mut lp, 3, 1, &BTreeSet::new());
    let (done, _) = lp.peers[1].engine.ensure_rotated(&m).unwrap();
    assert_eq!(done.commits.len(), 1, "m1 merges F2");
    let merged = newest_read(&lp, 1, m).unwrap();
    send_skipping(&mut lp, 1, 0, &BTreeSet::new());
    assert!(blocked_at(&mut lp, 0, a).contains(&Role::Read), "kk listed by the merge: stale");
    lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert_eq!(sealed_at(&mut lp, 0, a, m), Some(merged));
    assert_eq!(leaked(&mut lp, 0, &[m, a], d, start), Vec::<Tid>::new());
}

// spec/crypto.md §4 (Forks stand; Stale): merge; model `D0_member_anchor`: m1 removes D (kk1) and rotates M
// again (kk2, n 3). Z, not knowing, forks M from before (F, n 2): it loses the (n, nonce) order
// to kk2 at m1, so only merge supersedes it. A gets F first and seals M there (D opens it: the
// stated limit, a keyset written without knowing the removal). m1, holding F, rotates while F
// is current and misses D's departure; A's box at F is then stale and A moves: D opens nothing
// new. Without merge F stays current, A anchored on it never moves.
#[test]
fn merge_moves_off_losing_ignorant_fork_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let (mut lp, a, m, c_m, _, _, start) = member_world(Role::Read);
    let d = lp.peers[2].engine.tid();
    let before = commit_ids(&mut lp, 1);
    rotate_leaving_out(&mut lp, 1, m, &read, &[]);
    let later: BTreeSet<_> = commit_ids(&mut lp, 1).difference(&before).copied().collect();
    let kk2 = newest_read(&lp, 1, m).unwrap();
    lp.peers[3].clock.advance(60_000);
    rotate_leaving_out(&mut lp, 3, m, &read, &[]);
    let f = newest_read(&lp, 3, m).unwrap();
    assert!(f.n() < kk2.n(), "F loses the order");
    send_skipping(&mut lp, 3, 0, &c_m.union(&later).copied().collect());
    lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert_eq!(sealed_at(&mut lp, 0, a, m), Some(f), "A sealed M at the ignorant fork");
    send_skipping(&mut lp, 3, 1, &BTreeSet::new());
    let (done, _) = lp.peers[1].engine.ensure_rotated(&m).unwrap();
    assert_eq!(done.commits.len(), 1, "m1 merges F, current beside its newer kk2");
    let merged = newest_read(&lp, 1, m).unwrap();
    send_skipping(&mut lp, 1, 0, &BTreeSet::new());
    lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert_eq!(sealed_at(&mut lp, 0, a, m), Some(merged), "A moved off F");
    assert_eq!(leaked(&mut lp, 0, &[m, a], d, start), Vec::<Tid>::new());
}

/// The keysets of `m` the box of `a`'s newest read epoch to `m` names, at peer `i` (several: a
/// joint box).
fn sealed_keysets(lp: &mut LocalPeer, i: usize, a: Tid, m: Tid) -> BTreeSet<Epoch> {
    let Some(e) = newest_read(lp, i, a) else { return BTreeSet::new() };
    let s = lp.peers[i].engine.get_typed(&a, &ct::SECRETS).unwrap().unwrap_or_default();
    s.boxes.iter().filter(|(k, _)| k.holder == osis_base::Weak(m) && k.role == Role::Read && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|x| x == e)).flat_map(|(_, b)| osis_keys::box_keysets(b)).collect()
}

/// `two_admin_holder` with M forked by its admins m1 (0) and m2 (2) (keysets k1, k2) and A forked
/// over them: a1 (3) rotated A onto k1, a2 (4) onto k2, and a1 holds both A's forks, so A's
/// anchors for M fork. Returns the peers, M, A, k1, k2.
fn forked_anchors() -> (LocalPeer, Tid, Tid, Epoch, Epoch) {
    let read = BTreeSet::from([Role::Read]);
    let none = BTreeSet::new();
    let (mut lp, m, a) = two_admin_holder();
    rotate_leaving_out(&mut lp, 0, m, &read, &[]);
    let k1 = newest_read(&lp, 0, m).unwrap();
    lp.peers[2].clock.advance(1_000);
    rotate_leaving_out(&mut lp, 2, m, &read, &[]);
    let k2 = newest_read(&lp, 2, m).unwrap();
    send_skipping(&mut lp, 0, 3, &none);
    send_skipping(&mut lp, 2, 4, &none);
    lp.peers[3].engine.ensure_rotated(&a).unwrap();
    lp.peers[4].engine.ensure_rotated(&a).unwrap();
    send_skipping(&mut lp, 4, 3, &none);
    assert_eq!(lp.peers[3].engine.epochs(&a).unwrap().read.current().len(), 2, "A forked over M's two keysets");
    (lp, m, a, k1, k2)
}

// spec/crypto.md §4 (Seal; jointly): where the anchors fork; model `Joint.tla` `J_safety`: A's two
// current epochs anchor M at k1 and k2. m1 removes reader D from M (k3, listing k1 only), ordered
// before k2 (m2's clock is ahead), so a1, holding neither secret, judges k2 by order as covering
// it. a1, holding the removal's keyset, rotates A at once (its box at k1 is stale), sealing M
// jointly at k3 and k2: D, boxed at k2 but not k3, opens none of it; m2, holding both, does.
// Nothing waits for a keyset of M past both anchors (a merge only M's admins could make). Sealing
// M at k2 alone would hand D a1's new epoch; at k3 alone, it would move A off k2, which a party m2
// removed may hold. spec/crypto.md §4 (Seal; Encrypting under): a joint box held back by departures only where every keyset it names misses one, judged by order; model `JointRule.tla`: with the removal
// ordered after k2 (`late`), k2 misses a departure a1 knows; k3 covers it, so a1 seals M jointly at
// k2 and k3 all the same, and m2 reads A with no rotation of M (M's admins may all be gone).
#[test]
fn forked_anchors_seal_jointly_spec_crypto_4() {
    let none = BTreeSet::new();
    for late in [false, true] {
        let (mut lp, m, a, _, k2) = forked_anchors();
        let d = lp.peers[1].engine.tid();
        let mut start = held_by(&lp, 1, &[m, a]);
        for i in [3, 4] {
            start = openable(&mut lp, i, &[m, a], d, start);
        }
        if late {
            lp.peers[0].clock.advance(60_000);
        }
        removal(&mut lp, 0, m, d);
        let k3 = newest_read(&lp, 0, m).unwrap();
        send_skipping(&mut lp, 0, 3, &none);
        let (done, still) = lp.peers[3].engine.ensure_rotated(&a).unwrap();
        assert!(!done.commits.is_empty() && still.is_empty(), "late {late}: a1 rotates A at once");
        assert_eq!(sealed_keysets(&mut lp, 3, a, m), BTreeSet::from([k2, k3]), "late {late}: M sealed jointly at both forks");
        let w = newest_read(&lp, 3, a).unwrap();
        assert!(!openable(&mut lp, 3, &[m, a], d, start.clone()).contains(&(a, Role::Read, w)), "late {late}: D opens none of what a1 writes");
        lp.sync_all().unwrap();
        assert!(lp.peers[2].engine.epochs(&a).unwrap().read.secret(&w).is_some(), "late {late}: m2, holding both forks, reads A's new epoch, M not re-keyed");
        if !late {
            settle(&mut lp, &[0, 2, 3, 4], &[m, a]);
        }
        assert_eq!(leaked(&mut lp, 3, &[m, a], d, start), Vec::<Tid>::new(), "late {late}");
    }
}

// spec/permissions.md §3 (the rotation of a's roles it requires are one role commit), spec/crypto.md §4 (Seal; jointly), model `Joint.tla` `J_gone`, `J_stay`: A's anchors for M fork, and M's admins m1 and m2, the only
// nodes that may rotate M, are gone for good. a1 removes a2 from A: the removal carries A's
// rotation, M sealed jointly at both forks; nothing is left due, so a1 writes under A. a2 opens
// nothing of the new epoch; reader D of M, boxed at both forks, reads it.
#[test]
fn forked_holder_with_its_admins_gone_rotates_spec_permissions_3() {
    let (mut lp, m, a, k1, k2) = forked_anchors();
    let (d, a2) = (lp.peers[1].engine.tid(), lp.peers[4].engine.tid());
    let start = held_by(&lp, 4, &[m, a]);
    let before = lp.peers[3].engine.epochs(&a).unwrap().read.current();
    removal(&mut lp, 3, a, a2);
    assert!(!lp.peers[3].engine.core.key_holders(&a).iter().any(|h| h.0 == a2), "a2 holds no role on A");
    assert_ne!(lp.peers[3].engine.epochs(&a).unwrap().read.current(), before, "the removal rotated A");
    let (done, still) = lp.peers[3].engine.ensure_rotated(&a).unwrap();
    assert!(done.commits.is_empty() && still.is_empty(), "nothing due: a1 writes under A");
    assert!(blocked_at(&mut lp, 3, a).is_empty());
    assert_eq!(sealed_keysets(&mut lp, 3, a, m), BTreeSet::from([k1, k2]), "M sealed jointly at both forks");
    let w = newest_read(&lp, 3, a).unwrap();
    assert!(!openable(&mut lp, 3, &[m, a], a2, start).contains(&(a, Role::Read, w)), "a2 opens nothing of A's new epoch");
    lp.sync(3, 1).unwrap();
    assert!(lp.peers[1].engine.epochs(&a).unwrap().read.secret(&w).is_some(), "D reads A's new epoch");
    assert!(lp.peers[1].engine.core.key_holders(&m).iter().any(|h| h.0 == d));
}

// spec/crypto.md §4 (Encrypting under; a joint box only when every epoch it names is): the box clause: as
// `forked_anchors_seal_jointly_spec_crypto_4` with the removal late, a1's epoch w boxes M jointly at k2
// and k3. m2 (lacking k3) makes N with a1 a reader; a1 grants N on A (w boxes N), then m2 grants M
// on N, sealed at k2 alone. D opens k2, so N's epoch, so w: a1 may not encrypt under w though the
// joint box to M at k2 is not blocked.
#[test]
fn keyset_in_joint_box_reached_alone_blocks_spec_crypto_4() {
    let none = BTreeSet::new();
    let (mut lp, m, a, _, _) = forked_anchors();
    let (d, a1) = (lp.peers[1].engine.tid(), lp.peers[3].engine.tid());
    lp.peers[0].clock.advance(60_000);
    removal(&mut lp, 0, m, d);
    send_skipping(&mut lp, 0, 3, &none);
    lp.peers[3].engine.ensure_rotated(&a).unwrap();
    assert_eq!(sealed_keysets(&mut lp, 3, a, m).len(), 2, "M sealed jointly");
    let n = independent_thing(&mut lp, 2);
    lp.peers[2].engine.grant(&n, &a1, &edge(Role::Read)).unwrap();
    send_skipping(&mut lp, 2, 3, &none);
    // a1 takes m2's grant on N by its fire
    lp.pass_fires(3).unwrap();
    lp.peers[3].engine.grant(&a, &n, &edge(Role::Read)).unwrap();
    assert!(blocked_at(&mut lp, 3, a).is_empty(), "N's epoch boxes nothing yet");
    lp.peers[2].engine.grant(&n, &m, &edge(Role::Read)).unwrap();
    send_skipping(&mut lp, 2, 3, &none);
    assert!(blocked_at(&mut lp, 3, a).contains(&Role::Read), "w reaches k2 alone through N");
}

// spec/crypto.md §4 (Seal): a joint box held back where every keyset it names misses a departure; model `JointRule.tla` `NoPooledLeak`: A's anchors for M fork at k1 and k2 (as
// `forked_anchors`), and a1 reads M too, so it judges M's keysets by their history. m1 removes D1
// (k3, listing k1) and m2 removes D2 (k4, listing k2) concurrently: each fork misses the other's
// removal. D1 opens k4 and D2 k3, so pooled they would open a joint box at k3 and k4: a1 leaves
// M out of A until a rotator of M re-keys it knowing both.
#[test]
fn each_fork_missing_a_different_removal_leaves_holder_out_spec_crypto_4() {
    let roles = BTreeSet::from([Role::Sync, Role::Read]);
    let none = BTreeSet::new();
    let mut lp = synced(6);
    let [_, d1, m2, a1, a2, d2] = std::array::from_fn(|i| lp.peers[i].engine.tid());
    let m = independent_thing(&mut lp, 0);
    let a = independent_thing(&mut lp, 3);
    lp.peers[0].engine.grant(&m, &m2, &edge(Role::Admin)).unwrap();
    for h in [d1, d2, a1] {
        lp.peers[0].engine.grant(&m, &h, &edge(Role::Read)).unwrap();
    }
    lp.peers[3].engine.grant(&a, &a2, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[3].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, m, &roles, &[]);
    lp.peers[2].clock.advance(1_000);
    rotate_leaving_out(&mut lp, 2, m, &roles, &[]);
    send_skipping(&mut lp, 0, 3, &none);
    send_skipping(&mut lp, 2, 4, &none);
    lp.peers[3].engine.ensure_rotated(&a).unwrap();
    lp.peers[4].engine.ensure_rotated(&a).unwrap();
    send_skipping(&mut lp, 4, 3, &none);
    assert_eq!(lp.peers[3].engine.epochs(&a).unwrap().read.current().len(), 2, "A forked over M's two keysets");
    let mut starts = [held_by(&lp, 1, &[m, a]), held_by(&lp, 5, &[m, a])];
    for (s, d) in starts.iter_mut().zip([d1, d2]) {
        for i in [3, 4] {
            *s = openable(&mut lp, i, &[m, a], d, s.clone());
        }
    }
    removal(&mut lp, 0, m, d1);
    removal(&mut lp, 2, m, d2);
    send_skipping(&mut lp, 0, 3, &none);
    send_skipping(&mut lp, 2, 3, &none);
    let (done, _) = lp.peers[3].engine.ensure_rotated(&a).unwrap();
    assert!(!done.commits.is_empty(), "a1 rotates A");
    assert!(sealed_keysets(&mut lp, 3, a, m).is_empty(), "M left out: each fork misses a removal");
    let w = newest_read(&lp, 3, a).unwrap();
    for (s, d) in starts.into_iter().zip([d1, d2]) {
        assert!(!openable(&mut lp, 3, &[m, a], d, s).contains(&(a, Role::Read, w)), "neither removed party opens A's new epoch");
    }
}

// spec/crypto.md §4 (Held keyset; Descends; Stale): a forged keyset is held invalid; model `D0_member_forge`: D, an admin of M, forges M's keyset X_d (listing kk) after its removal. R
// (peer 0) lacks the removal: X_d is valid there, descends from kk, and R seals A at it (D
// opens R's epoch: the stated limit). W (peer 4) holds the removal and X_d: X_d is invalid
// there, so R's box at it is stale and W rotates before encrypting, never sealing at X_d. Once
// the removal reaches R, X_d leaves R's held keysets and R rotates too.
#[test]
fn forged_keyset_invalid_where_removal_arrived_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let (mut lp, a, m, c_m, k0, kk, start) = member_world(Role::Admin);
    let d = lp.peers[2].engine.tid();
    // R gets everything but the removal (which carries kk)
    send_skipping(&mut lp, 1, 0, &c_m);
    let s_d = osis_crypto::Secret32::from_bytes([79; 32]);
    let x_d = Epoch::derive(&m, Role::Read, kk.n() + 1, &s_d).unwrap();
    let forged = osis_keys::keyset(&x_d, &s_d.clone().into(), &BTreeSet::from([k0, kk]), &Default::default(), true);
    let mut mu = Mutation::new();
    mu.op(m, &ct::KEYS, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Replace(osis_schema::Codec::to_value(&Some(forged))) }).unwrap();
    mu.unchecked();
    lp.peers[2].clock.advance(60_000);
    lp.peers[2].engine.core.skip_writer_rules = true;
    lp.peers[2].commit(mu).unwrap().unwrap();
    let held = |lp: &LocalPeer, i: usize| lp.peers[i].engine.core.ix.keysets.contains_key(&(m, Role::Read, x_d));
    send_skipping(&mut lp, 2, 0, &c_m);
    // R lacks kk's commit (it is the removal) and holds X_d valid
    assert!(held(&lp, 0), "X_d valid at R");
    rotate_leaving_out(&mut lp, 0, a, &read, &[]);
    assert_eq!(sealed_at(&mut lp, 0, a, m), Some(x_d), "R seals M at the forgery");
    let e = newest_read(&lp, 0, a).unwrap();
    let mut d_m = osis_keys::ActorEpochs::default();
    d_m.read.set_secret(x_d, s_d);
    d_m.read.set_established(x_d, osis_keys::Provenance::Derived);
    assert!(super::tests::opens_through(&mut lp, 0, a, m, &d_m).read.reading_secret(&e).is_some(), "the stated limit: D opens R's epoch");
    // W holds everything
    for i in [0, 1, 2] {
        send_skipping(&mut lp, i, 4, &BTreeSet::new());
    }
    assert!(!held(&lp, 4), "X_d invalid at W");
    assert!(blocked_at(&mut lp, 4, a).contains(&Role::Read), "R's box at X_d is stale at W");
    lp.peers[4].engine.ensure_rotated(&a).unwrap();
    let w = newest_read(&lp, 4, a).unwrap();
    assert_ne!(sealed_at(&mut lp, 4, a, m), Some(x_d));
    assert!(super::tests::opens_through(&mut lp, 4, a, m, &d_m).read.reading_secret(&w).is_none(), "D opens no epoch W writes under");
    // the removal reaches R: X_d is held no more, alike after a rebuild
    send_skipping(&mut lp, 1, 0, &BTreeSet::new());
    assert!(!held(&lp, 0), "X_d invalid at R once the removal arrived");
    lp.peers[0].engine.rebuild_index().unwrap();
    assert!(!held(&lp, 0), "rebuilt");
    lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert_ne!(sealed_at(&mut lp, 0, a, m), Some(x_d));
    assert_eq!(leaked(&mut lp, 0, &[m, a], d, start), Vec::<Tid>::new());
}

// spec/crypto.md §4 (Carried), model `Carry`: a node learning an epoch learns the keysets its boxes name with it: peer 0 seals A's holder M at m1's knowing keyset kk and places kk's
// commit under A's sync ID with its rotation. W (peer 4, A's other admin) gets peer 0's commits
// but not kk's (a peer withholding the carried commit): kk is no anchor there (not held), so W's
// next rotation of A seals M at k0, which D opens (the stated limit: W holds no knowing keyset
// of M). Peer 0 finds that box stale and moves A back to kk; once kk's commit reaches W, W
// seals at kk. D opens nothing a writer holding kk encrypts under.
#[test]
fn lacking_carried_keyset_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let (mut lp, a, m, c_m, k0, kk, start) = member_world(Role::Read);
    let d = lp.peers[2].engine.tid();
    send_skipping(&mut lp, 1, 0, &BTreeSet::new());
    let (done, _) = lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert_eq!(sealed_at(&mut lp, 0, a, m), Some(kk));
    let rot = *done.commits.last().unwrap();
    let with = lp.peers[0].engine.logged_with(&rot).unwrap();
    assert!(with.iter().any(|c| c_m.contains(c)), "kk's commit logged with the rotation: {with:?}");
    send_skipping(&mut lp, 0, 4, &c_m);
    assert!(!lp.peers[4].engine.core.ix.keysets.contains_key(&(m, Role::Read, kk)), "W lacks kk");
    assert!(blocked_at(&mut lp, 4, a).is_empty(), "an unheld keyset is not stale");
    lp.peers[4].clock.advance(60_000);
    rotate_leaving_out(&mut lp, 4, a, &read, &[]);
    assert_eq!(sealed_at(&mut lp, 4, a, m), Some(k0), "W, lacking the anchor, seals at the keyset D opens");
    assert_eq!(leaked(&mut lp, 4, &[m, a], d, start.clone()), vec![a], "the stated limit: D reads W's epoch");
    send_skipping(&mut lp, 4, 0, &BTreeSet::new());
    assert!(blocked_at(&mut lp, 0, a).contains(&Role::Read), "W's box at k0 is stale where kk is held");
    lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert_eq!(sealed_at(&mut lp, 0, a, m), Some(kk));
    assert_eq!(leaked(&mut lp, 0, &[m, a], d, start.clone()), Vec::<Tid>::new());
    send_skipping(&mut lp, 0, 4, &BTreeSet::new());
    send_skipping(&mut lp, 1, 4, &BTreeSet::new());
    assert!(blocked_at(&mut lp, 4, a).is_empty());
    rotate_leaving_out(&mut lp, 4, a, &read, &[]);
    assert_eq!(sealed_at(&mut lp, 4, a, m), Some(kk), "with kk held, W seals at it");
    assert_eq!(leaked(&mut lp, 4, &[m, a], d, start), Vec::<Tid>::new());
}

// spec/permissions.md §3 (holder actors), spec/requirements.md (Permissions: the inside-member
// limit), spec/crypto.md §4 (Encrypting under: sealing M at a keyset is encrypting under it): a
// departure inside M is M's to rotate for. D leaves M by itself (nothing rotates M). A grant of M
// on T by a node that may not rotate M (T's admin reading M, or a may-grant holder on T): one that
// has not learned the departure seals M at its keyset D holds, so D reads T until M's knowing
// keyset reaches T's writers, then not (rule 2); one that knows it may not encrypt under that
// keyset, so its grant waits for M's rotation. M's admin, granting, rotates M first (sealing to it
// is encrypting under its epoch): D never reads T.
#[test]
fn grant_to_unrotated_holder_stated_limit_spec_permissions_3() {
    // granter: 0 T's admin reading M, 2 M's admin and T's mint admin, 0 by a may-grant on T whose mint admin is 3; whether
    // the granter has learned D's departure
    for (g, first, knows) in [(0, 0, false), (0, 0, true), (2, 2, true), (0, 3, false), (0, 3, true)] {
        let (mut lp, (m, t)) = LocalPeer::cached(&format!("rotation::tests_members::grant_to_unrotated/{first}/{}", first != g), || {
            let mut lp = synced(4);
            let d = lp.peers[1].engine.tid();
            let p0 = lp.peers[0].engine.tid();
            let m = independent_thing(&mut lp, 2);
            lp.peers[2].engine.grant(&m, &d, &edge(Role::Read)).unwrap();
            lp.peers[2].engine.grant(&m, &p0, &edge(Role::Read)).unwrap();
            let t = independent_thing(&mut lp, first);
            if first != g {
                lp.peers[first].engine.grant(&t, &p0, &ct::Grant { may_grant: true, ..edge(Role::Write) }).unwrap();
            }
            lp.sync_all().unwrap();
            (lp, (m, t))
        });
        let d = lp.peers[1].engine.tid();
        let start = held_by(&lp, 1, &[m]);
        lp.peers[1].engine.demote(&m, &Demotion { holder: d, new: None, retain: None }).unwrap();
        if knows {
            lp.sync_all().unwrap();
        } else {
            send_skipping(&mut lp, 1, 2, &BTreeSet::new());
        }
        if knows && g != 2 {
            assert!(lp.peers[g].engine.grant(&t, &m, &edge(Role::Write)).is_err(), "granter {g} knows: no grant sealing M at a keyset not covering D's departure");
            let _ = lp.peers[2].engine.ensure_rotated(&m).unwrap();
            lp.sync_all().unwrap();
        }
        lp.peers[g].engine.grant(&t, &m, &edge(Role::Write)).unwrap();
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[first].engine.roster(&t).get(&m).map(|e| e.role), Some(Role::Write), "a valid grant");
        let reads = leaked(&mut lp, first, &[m, t], d, start.clone()).contains(&t);
        assert_eq!(reads, !knows, "granter {g}: D reads T until M's knowing keyset reaches T's writers");
        let _ = lp.peers[2].engine.ensure_rotated(&m).unwrap();
        lp.sync_all().unwrap();
        settle(&mut lp, &[2, first], &[m, t]);
        assert!(all_boxed(&mut lp, first, &[m, t]), "M boxed");
        assert_eq!(leaked(&mut lp, first, &[m, t], d, start), Vec::<Tid>::new(), "granter {g}: once M rotated, not");
    }
}

// spec/crypto.md §4 (Key access; Tainted; knowing re-key): judged over the grants held; model `D0_nc_hide_taint_lean`: Y holds X (granted first, by peer 0), X holds Y (later, by
// peer 2, Y's admin, which lacks the earlier grant): peer 2 takes its grant as keyed and boxes Y
// to X, a key cycle. Peer 0 holds both: Y's keyset boxes X, which has no key access to Y, so it
// is tainted: peer 0 never seals X to it and its box at it is stale. D, removed from X by peer 0,
// opens none of X's new epochs, though it opens Y's tainted one through X's old keyset. Once the
// grant reaches peer 2, it re-keys Y without X, and X is re-sealed to Y: no lockout.
#[test]
fn hidden_grant_tainted_keyset_spec_crypto_4() {
    let mut lp = synced(3);
    let d = lp.peers[1].engine.tid();
    let x = independent_thing(&mut lp, 0);
    let y = independent_thing(&mut lp, 2);
    lp.peers[0].engine.grant(&x, &d, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let before = commit_ids(&mut lp, 0);
    lp.peers[0].engine.grant(&x, &y, &edge(Role::Read)).unwrap();
    let earlier: BTreeSet<_> = commit_ids(&mut lp, 0).difference(&before).copied().collect();
    lp.peers[2].clock.advance(1_000);
    lp.peers[2].engine.grant(&y, &x, &edge(Role::Read)).unwrap();
    assert!(boxes(&mut lp, 2, y, x), "peer 2, lacking the earlier grant, boxes Y to X");
    send_skipping(&mut lp, 2, 0, &BTreeSet::new());
    lp.sync(0, 1).unwrap();
    let start = held_by(&lp, 1, &[x, y]);
    // at peer 0, X's grant on Y is keyless and Y's keyset boxing X tainted
    assert!(!lp.peers[0].engine.run(|tx| Ok(super::members::keyed(tx.core, &y, &x))).unwrap());
    assert!(blocked_at(&mut lp, 0, x).contains(&Role::Read), "X's box to Y at the tainted keyset is stale");
    removal(&mut lp, 0, x, d);
    lp.peers[0].engine.ensure_rotated(&x).unwrap();
    assert!(blocked_at(&mut lp, 0, x).is_empty());
    let opened = openable(&mut lp, 0, &[x, y], d, start.clone());
    assert!(opened.iter().any(|k| k.0 == y), "D opens Y's tainted keyset through X's old one");
    assert!(!opened.contains(&(x, Role::Read, newest_read(&lp, 0, x).unwrap())), "but not X's new epoch: Y left out");
    assert_eq!(sealed_at(&mut lp, 0, x, y), None, "Y has no untainted keyset: left out");
    // the earlier grant reaches peer 2: it re-keys Y without X
    assert!(earlier.iter().all(|c| !lp.peers[2].engine.core.ix.commits.contains_key(c)), "peer 2 lacks the earlier grant");
    send_skipping(&mut lp, 0, 2, &BTreeSet::new());
    let (done, _) = lp.peers[2].engine.ensure_rotated(&y).unwrap();
    assert!(!done.commits.is_empty(), "the knowing re-key");
    assert!(!boxes(&mut lp, 2, y, x), "Y boxes X no more");
    lp.sync_all().unwrap();
    settle(&mut lp, &[0, 2], &[x, y]);
    assert!(all_boxed(&mut lp, 0, &[x, y]) && all_boxed(&mut lp, 2, &[x, y]), "no lockout: Y re-sealed on X");
    assert!(sealed_at(&mut lp, 0, x, y).is_some());
    assert_eq!(leaked(&mut lp, 0, &[x, y], d, start), Vec::<Tid>::new());
}

// spec/crypto.md §4 (Key access; knowing re-key): judged over the grants held: Y
// holds X (granted first, by peer 0), X holds Y (later, by peer 2, which lacks the earlier
// grant): peer 2 boxes Y to X, a key cycle, with nothing departed and no keyset stale. Once the
// earlier grant reaches peer 2, its grant is keyless there and peer 2 re-keys Y without X.
#[test]
fn knowing_rekey_after_hidden_grant_spec_crypto_4() {
    let mut lp = synced(3);
    let x = independent_thing(&mut lp, 0);
    let y = independent_thing(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&x, &y, &edge(Role::Read)).unwrap();
    lp.peers[2].clock.advance(1_000);
    lp.peers[2].engine.grant(&y, &x, &edge(Role::Read)).unwrap();
    assert!(boxes(&mut lp, 2, y, x), "peer 2, lacking the earlier grant, boxes Y to X");
    assert!(lp.peers[2].engine.ensure_rotated(&y).unwrap().0.commits.is_empty(), "nothing due yet");
    send_skipping(&mut lp, 0, 2, &BTreeSet::new());
    let (done, still) = lp.peers[2].engine.ensure_rotated(&y).unwrap();
    assert_eq!(done.commits.len(), 1, "the knowing re-key");
    assert!(still.is_empty() && !boxes(&mut lp, 2, y, x), "Y boxes X no more");
    assert!(lp.peers[2].engine.ensure_rotated(&y).unwrap().0.commits.is_empty(), "settled");
}

// spec/crypto.md §4 (Boxes: an invalid commit's boxes judge nothing): peer 0 demotes Y's admin
// peer 2 to reader while peer 2, not knowing, grants X read on Y, boxing Y's read epoch to X. At
// peer 0 the grant is invalid (peer 2 is no admin there): X holds no role on Y, yet the box opens
// Y's epoch for X's member D. That epoch is one peer 2 holds as a reader and could hand on
// anyway: peer 0 counts no departure from the box, nor from the raise of a reader author, and
// rotates nothing for it (the stated limit).
#[test]
fn invalid_grant_box_judges_nothing_spec_crypto_4() {
    let mut lp = synced(3);
    let (d, p2) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let y = independent_thing(&mut lp, 0);
    let x = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&y, &p2, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&x, &d, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let start = held_by(&lp, 1, &[x, y]);
    lp.peers[0].engine.demote(&y, &Demotion { holder: p2, new: Some(edge(Role::Read)), retain: None }).unwrap();
    lp.peers[2].clock.advance(1_000);
    lp.peers[2].engine.grant(&y, &x, &edge(Role::Read)).unwrap();
    let e0 = newest_read(&lp, 2, y).unwrap();
    assert!(openable(&mut lp, 2, &[x, y], d, start.clone()).contains(&(y, Role::Read, e0)), "the box to X opens Y's epoch for D");
    lp.sync_all().unwrap();
    assert!(!lp.peers[0].engine.core.key_holders(&y).iter().any(|h| h.0 == x), "the grant is invalid at peer 0");
    assert!(lp.peers[0].engine.core.key_holders(&y).iter().any(|h| h.0 == p2), "its author still reads Y");
    assert_eq!(newest_read(&lp, 2, y), Some(e0), "and holds the epoch it boxed");
    assert!(blocked_at(&mut lp, 0, y).is_empty());
    assert!(lp.peers[0].engine.ensure_rotated(&y).unwrap().0.commits.is_empty());
}

// spec/requirements.md Permissions (a role M holds on A reaches M's holders; a secret once shared
// cannot be un-shared): the mint admin demotes writer D on G to reader, rotating write to e1 that D
// lacks, then raises D on M, a writer of G, to write: D writes G through M again and opens e1 by
// G's box to M. Removing M from G rotates write to e2, which D opens no way.
#[test]
fn access_regained_through_a_holder_actor_reads_what_the_departure_rotated_spec_crypto_4() {
    let mut lp = synced(2);
    let d = lp.peers[1].engine.tid();
    let g = independent_thing(&mut lp, 0);
    let m = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &m, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&g, &d, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&m, &d, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let write = |lp: &LocalPeer| lp.peers[0].engine.epochs(&g).and_then(|e| e.role(Role::Write).newest_held().map(|x| x.0)).unwrap();
    lp.peers[0].engine.demote(&g, &Demotion { holder: d, new: Some(edge(Role::Read)), retain: None }).unwrap();
    let e1 = write(&lp);
    lp.sync_all().unwrap();
    assert!(!held_by(&lp, 1, &[g]).contains(&(g, Role::Write, e1)), "the demotion's epoch is closed to D");
    lp.peers[0].engine.grant(&m, &d, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    let mut kept = held_by(&lp, 1, &[g, m]);
    assert!(kept.contains(&(g, Role::Write, e1)), "D, a writer of G through M, opens e1");
    lp.peers[0].engine.demote(&g, &Demotion { holder: m, new: None, retain: None }).unwrap();
    let e2 = write(&lp);
    assert_ne!(e1, e2, "M's removal rotates write");
    lp.sync_all().unwrap();
    kept.extend(held_by(&lp, 1, &[g, m]));
    assert!(!openable(&mut lp, 0, &[g, m], d, kept).contains(&(g, Role::Write, e2)), "D opens no epoch made since M's removal");
    assert!(blocked_at(&mut lp, 0, g).is_empty());
    assert!(lp.peers[0].engine.ensure_rotated(&g).unwrap().0.commits.is_empty(), "nothing due");
}

// spec/crypto.md §4 (Boxes: an invalid grant's box opens what its author held; Departures: the
// author's own lowering rotates past it): admin A demotes writer D to reader, rotating write to
// e1 that D lacks; the mint admin removes A, rotating write to e2; A, not knowing, re-grants D write,
// boxing e1. Settled, the grant is invalid and D a reader. D opens e1 (A held it and handed it
// on: a secret once shared cannot be un-shared) but not e2, which every writer encrypts under.
#[test]
fn invalid_regrant_hands_on_only_what_its_author_held_spec_crypto_4() {
    let mut lp = synced(3);
    let (a, d) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &a, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &d, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    let write = |lp: &LocalPeer, i: usize| lp.peers[i].engine.epochs(&g).and_then(|e| e.role(Role::Write).newest_held().map(|x| x.0));
    lp.peers[1].clock.advance(1_000);
    lp.peers[1].engine.demote(&g, &Demotion { holder: d, new: Some(edge(Role::Read)), retain: None }).unwrap();
    let e1 = write(&lp, 1).unwrap();
    lp.sync(1, 0).unwrap();
    lp.peers[0].clock.advance(2_000);
    lp.peers[0].engine.demote(&g, &Demotion { holder: a, new: None, retain: None }).unwrap();
    let e2 = write(&lp, 0).unwrap();
    assert_ne!(e1, e2, "A's removal rotates write");
    lp.peers[1].clock.advance(3_000);
    lp.peers[1].engine.grant(&g, &d, &edge(Role::Write)).unwrap();
    // D, holding the grant before A's removal, opens e1 and keeps it
    lp.sync(1, 2).unwrap();
    let mut kept = held_by(&lp, 2, &[g]);
    assert!(kept.contains(&(g, Role::Write, e1)), "A's box hands D e1 (the limit)");
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[0].engine.core.key_holders(&g).into_iter().find(|h| h.0 == d).map(|h| h.1), Some(Role::Read), "the re-grant is invalid: D reads");
    kept.extend(held_by(&lp, 2, &[g]));
    let opens = openable(&mut lp, 0, &[g], d, kept);
    assert!(!opens.contains(&(g, Role::Write, e2)), "D opens no epoch made since A's removal");
    assert!(blocked_at(&mut lp, 0, g).is_empty());
    assert!(lp.peers[0].engine.ensure_rotated(&g).unwrap().0.commits.is_empty(), "nothing due");
    assert_eq!(write(&lp, 0), Some(e2), "the mint admin writes under e2");
}

// The same limit through a holder actor (spec/crypto.md §4, Boxes): holder actor M is admin of
// G; A is admin of M. The mint admin demotes admin D of G to reader, rotating G's admin to e1, which
// boxes M at its keyset k; then removes A from M, rotating M and G past k. A, not knowing,
// grants D admin of M, boxing k. Settled, the grant is invalid and D a reader of G. D opens e1
// (through k, which A held and handed on, as A opens it) but nothing made since A's removal.
#[test]
fn invalid_grant_on_a_holder_actor_hands_on_what_its_keyset_opens_spec_crypto_4() {
    let mut lp = synced(3);
    let (a, d) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let g = independent_thing(&mut lp, 0);
    let m = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &m, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&m, &a, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &d, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let admin = |lp: &LocalPeer| lp.peers[0].engine.epochs(&g).and_then(|e| e.role(Role::Admin).newest_held().map(|x| x.0));
    lp.peers[0].clock.advance(1_000);
    lp.peers[0].engine.demote(&g, &Demotion { holder: d, new: Some(edge(Role::Read)), retain: None }).unwrap();
    let e1 = admin(&lp).unwrap();
    lp.sync(0, 1).unwrap();
    lp.peers[0].clock.advance(2_000);
    lp.peers[0].engine.demote(&m, &Demotion { holder: a, new: None, retain: None }).unwrap();
    lp.peers[0].engine.ensure_rotated(&g).unwrap();
    let e2 = admin(&lp).unwrap();
    assert_ne!(e1, e2, "A's removal from M rotates G's admin");
    lp.peers[1].clock.advance(3_000);
    lp.peers[1].engine.grant(&m, &d, &edge(Role::Admin)).unwrap();
    lp.sync(1, 2).unwrap();
    let mut kept = held_by(&lp, 2, &[g, m]);
    assert!(kept.contains(&(g, Role::Admin, e1)), "A's box at k hands D e1 (the limit)");
    lp.sync_all().unwrap();
    settle(&mut lp, &[0], &[g, m]);
    assert_eq!(lp.peers[0].engine.core.key_holders(&m).into_iter().find(|h| h.0 == d), None, "the grant is invalid");
    kept.extend(held_by(&lp, 2, &[g, m]));
    let opens = openable(&mut lp, 0, &[g, m], d, kept);
    assert!(!opens.contains(&(g, Role::Admin, e2)), "D opens no epoch made since A's removal");
    assert!(!opens.contains(&(g, Role::Admin, admin(&lp).unwrap())), "nor G's current admin epoch");
    assert!(blocked_at(&mut lp, 0, g).is_empty());
}

// spec/crypto.md §4 (Boxes: an invalid commit's boxes judge nothing;
// issue held-boxes-reader-rekey (closed)): reader R of G writes `secrets.0` deltas (invalid: a delta
// needs write) boxing G's current read epoch to party P, which holds no role on G. G's admin
// counts no departure from them and rotates nothing: a reader cannot make G rotate per commit,
// and a rotation would buy nothing against it (R holds the new epoch too).
#[test]
fn reader_junk_boxes_force_no_rotation_spec_crypto_4() {
    let mut lp = synced(3);
    let (r, p) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &r, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let e0 = newest_read(&lp, 0, g).unwrap();
    for _ in 0..3 {
        lp.peers[1].clock.advance(1_000);
        let s = lp.peers[1].engine.get_typed(&g, &ct::SECRETS).unwrap().unwrap();
        let own = s.boxes.iter().find(|(k, _)| k.holder == osis_base::Weak(r) && k.role == Role::Read).map(|(_, b)| b.clone()).unwrap();
        let key = ct::BoxKey { holder: osis_base::Weak(p), role: Role::Read, epoch: osis_keys::aspects::to_schema(&e0) };
        let w = osis_keys::SecretsWrite { boxes: [(key, own)].into(), ..Default::default() };
        lp.peers[1]
            .engine
            .run(|tx| {
                // as R's engine would refuse to: every node judges it invalid
                tx.core.skip_writer_rules = true;
                let mut m = Mutation::new();
                m.unchecked();
                crate::flows::put_secrets(&mut m, g, &w, true)?;
                crate::engine::Engine::commit_tx(tx, m)?;
                tx.core.skip_writer_rules = false;
                Ok(())
            })
            .unwrap();
    }
    send_skipping(&mut lp, 1, 0, &BTreeSet::new());
    let ak = crate::flows::ak("secrets.0").unwrap();
    assert_eq!(lp.peers[0].engine.core.ix.invalid.get(&(g, ak)).map_or(0, |c| c.len()), 3, "peer 0 holds the junk deltas, invalid");
    assert!(lp.peers[0].engine.departures(&g).unwrap().is_empty(), "no departure from junk boxes");
    assert!(blocked_at(&mut lp, 0, g).is_empty());
    assert!(lp.peers[0].engine.ensure_rotated(&g).unwrap().0.commits.is_empty(), "no rotation");
    assert_eq!(newest_read(&lp, 0, g), Some(e0));
}

// spec/crypto.md §4 (Forks stand; Stale): merge; model `D0_nc_2adm`: X (peer 0's) holds Y keyless, Y (admins y1 = peer 2, y2 = peer 3)
// holds X, D a reader of Y. y1 removes D (knowing keyset kk); y2, not knowing, rotates Y (an
// ignorant fork F). Peer 0 holding both seals X at kk or F as rule 1 gives; once y1 merges F,
// peer 0's box is stale and it moves: D opens no newest epoch, nothing locks out.
#[test]
fn second_admin_ignorant_fork_in_cycle_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let mut lp = synced(4);
    let [d, y2] = [1, 3].map(|i| lp.peers[i].engine.tid());
    let x = independent_thing(&mut lp, 0);
    let y = independent_thing(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&x, &y, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[2].clock.advance(1_000);
    lp.peers[2].engine.grant(&y, &x, &edge(Role::Read)).unwrap();
    lp.peers[2].engine.grant(&y, &y2, &edge(Role::Admin)).unwrap();
    lp.peers[2].engine.grant(&y, &d, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let start = held_by(&lp, 1, &[x, y]);
    let before = commit_ids(&mut lp, 2);
    removal(&mut lp, 2, y, d);
    let c_y: BTreeSet<_> = commit_ids(&mut lp, 2).difference(&before).copied().collect();
    lp.peers[3].clock.advance(60_000);
    rotate_leaving_out(&mut lp, 3, y, &read, &[]);
    for i in [2, 3] {
        send_skipping(&mut lp, i, 0, &BTreeSet::new());
    }
    lp.peers[0].engine.ensure_rotated(&x).unwrap();
    // y1 merges F
    send_skipping(&mut lp, 3, 2, &BTreeSet::new());
    lp.peers[2].engine.ensure_rotated(&y).unwrap();
    lp.sync_all().unwrap();
    settle(&mut lp, &[0, 2, 3], &[x, y]);
    for i in [0, 2, 3] {
        assert!(all_boxed(&mut lp, i, &[x, y]), "peer {i}: no lockout");
        assert_eq!(leaked(&mut lp, i, &[x, y], d, start.clone()), Vec::<Tid>::new(), "peer {i}");
    }
    assert!(!c_y.is_empty());
}

// spec/crypto.md §4 (rotating needs only the right to rotate; History box), spec/permissions.md §3: P writes A
// only through holder actor M (mint admin: peer 2). A's mint admin rotates A's read leaving M
// out (Seal found no keyset; here by hand), so P holds A's write but no current read. E, a
// writer of A, leaves by itself: the read epoch P lacks, ordered before that, cannot cover it,
// so P rotates read and write, superseding it unread, wrapped under the read secret it holds;
// A's mint admin, holding it, adds it to P's epoch's history.
#[test]
fn rotator_lacking_read_rotates_read_too_spec_permissions_3() {
    let mut lp = synced(5);
    let [p, e] = [1, 4].map(|i| lp.peers[i].engine.tid());
    let a = independent_thing(&mut lp, 0);
    let m = independent_thing(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.grant_through(2, m, p, &edge(Role::Write));
    lp.sync_all().unwrap();
    lp.grant_through(0, a, m, &edge(Role::Write));
    lp.grant_through(0, a, e, &edge(Role::Write));
    lp.sync_all().unwrap();
    assert!(newest_read(&lp, 1, a).is_some(), "P reads A through M");
    rotate_skipping(&mut lp, 0, a, &BTreeSet::from([Role::Read]), &[m]);
    lp.sync_all().unwrap();
    assert!(newest_read(&lp, 1, a).is_none(), "M left out of A's read");
    let lacked = lp.peers[1].engine.epochs(&a).unwrap().read.current()[0];
    assert!(lp.peers[1].engine.epochs(&a).unwrap().write.newest_held().is_some(), "P still holds A's write");
    removal(&mut lp, 4, a, e);
    lp.sync_all().unwrap();
    let write = |lp: &LocalPeer| lp.peers[1].engine.epochs(&a).unwrap().write.newest_held().map(|x| x.0);
    let before = write(&lp);
    let (_, still) = lp.peers[1].engine.ensure_rotated(&a).unwrap();
    assert_ne!(write(&lp), before, "A's write rotated");
    assert!(still.is_empty(), "{still:?}");
    let ep = lp.peers[1].engine.epochs(&a).unwrap();
    assert!(ep.read.newest_held().is_some() && !ep.read.is_current(&lacked), "A's read rotated over the epoch P lacks");
    assert!(osis_keys::wrap_epoch(&ep.read).is_some(), "P is not stranded");
    settle(&mut lp, &[1, 2, 0], &[m, a]);
    assert!(lp.peers[1].engine.epochs(&a).unwrap().read.secret(&lacked).is_some(), "P holds the superseded secret by history");
    let (_, still) = lp.peers[1].engine.ensure_rotated(&a).unwrap();
    assert!(still.is_empty(), "{still:?}");
}

/// The write-lacking shape of `rotator_lacking_read_rotates_read_too_spec_permissions_3`: P is A's
/// admin only through holder actor M (mint admin: peer 2), and A's mint admin rotates A's write leaving
/// M out, so P holds A's read and admin but no current write; F (5) is an admin of A. Returns
/// the peers and A, M.
fn lacking_write() -> (LocalPeer, Tid, Tid) {
    let (lp, (a, m)) = LocalPeer::cached("rotation::tests_members::lacking_write", || {
        let mut lp = synced(6);
        let [p, f] = [1, 5].map(|i| lp.peers[i].engine.tid());
        let a = independent_thing(&mut lp, 0);
        let m = independent_thing(&mut lp, 2);
        lp.sync_all().unwrap();
        lp.peers[2].engine.grant(&m, &p, &edge(Role::Admin)).unwrap();
        lp.sync_all().unwrap();
        lp.peers[0].engine.grant(&a, &m, &edge(Role::Admin)).unwrap();
        lp.refer(2, m, a);
        lp.peers[0].engine.grant(&a, &f, &edge(Role::Admin)).unwrap();
        lp.sync_all().unwrap();
        rotate_skipping(&mut lp, 0, a, &BTreeSet::from([Role::Write]), &[m]);
        lp.sync_all().unwrap();
        let ep = lp.peers[1].engine.epochs(&a).unwrap();
        assert!(ep.write.newest_held().is_none(), "M left out of A's write");
        assert!(ep.read.newest_held().is_some() && ep.admin.newest_held().is_some(), "P holds A's read and admin");
        (lp, (a, m))
    });
    (lp, a, m)
}

// spec/crypto.md §4 (rotating needs only the right to rotate; History box), spec/permissions.md §3: F, an admin
// of A, leaves by itself. P rotates all three roles of A, the write epoch it lacks superseded
// unread; A's mint admin, holding it, adds it to P's write epoch's history.
#[test]
fn rotator_lacking_write_rotates_history_added_spec_permissions_3() {
    let (mut lp, a, m) = lacking_write();
    let f = lp.peers[5].engine.tid();
    removal(&mut lp, 5, a, f);
    lp.sync_all().unwrap();
    let lacked = lp.peers[1].engine.epochs(&a).unwrap().write.current()[0];
    let admin = |lp: &LocalPeer| lp.peers[1].engine.epochs(&a).unwrap().admin.newest_held().map(|x| x.0);
    let before = admin(&lp);
    let (_, still) = lp.peers[1].engine.ensure_rotated(&a).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_ne!(admin(&lp), before, "A's admin rotated");
    let e = lp.peers[1].engine.epochs(&a).unwrap();
    assert!(e.write.newest_held().is_some() && !e.write.is_current(&lacked), "A's write rotated over the epoch P lacks");
    assert!(e.write.secret(&lacked).is_none());
    assert!(osis_keys::wrap_epoch(&e.read).is_some(), "P's read is current: not stranded");
    settle(&mut lp, &[2, 0], &[m, a]);
    let e = lp.peers[1].engine.epochs(&a).unwrap();
    assert!(e.write.secret(&lacked).is_some(), "P holds the superseded write secret by history");
    let (_, still) = lp.peers[1].engine.ensure_rotated(&a).unwrap();
    assert!(still.is_empty(), "{still:?}");
}

// A removal P makes itself in that shape rotates A's write, whose current secret P lacks
// (spec/crypto.md §4: rotating needs no secret): F is out and the removal's epoch alone is
// current.
#[test]
fn removal_lacking_rotated_secret_rotates_spec_permissions_3() {
    let (mut lp, a, _) = lacking_write();
    let f = lp.peers[5].engine.tid();
    let lacked = lp.peers[1].engine.epochs(&a).unwrap().write.current()[0];
    lp.peers[1].engine.demote(&a, &Demotion { holder: f, new: None, retain: None }).unwrap();
    assert!(!lp.peers[1].engine.core.current_holders(&a).iter().any(|(m, _, _)| *m == f), "F removed");
    let e = lp.peers[1].engine.epochs(&a).unwrap();
    assert_eq!(e.write.current().len(), 1, "the removal's epoch alone is current");
    assert!(e.write.newest_held().is_some() && !e.write.is_current(&lacked), "the epoch P lacked is superseded");
}

// spec/permissions.md §3, spec/crypto.md §4 (Seal; rotating needs only the right to rotate): P
// is A's admin only through holder actor M (mint admin: peer 2), which rotates M leaving P out,
// so P holds M's new keyset but not its secret. P's removal of F carries A's rotation all the
// same, sealing M to that keyset's KEM key: valid at every node, the departure covered.
#[test]
fn removal_through_a_holder_it_cannot_open_rotates_spec_crypto_4() {
    let mut lp = synced(6);
    let [p, f] = [1, 5].map(|i| lp.peers[i].engine.tid());
    let a = independent_thing(&mut lp, 0);
    let m = independent_thing(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.grant_through(2, m, p, &edge(Role::Admin));
    lp.sync_all().unwrap();
    lp.grant_through(0, a, m, &edge(Role::Admin));
    lp.grant_through(0, a, f, &edge(Role::Admin));
    lp.sync_all().unwrap();
    rotate_skipping(&mut lp, 2, m, &BTreeSet::from(Role::ALL), &[p]);
    lp.sync_all().unwrap();
    assert!(lp.peers[1].engine.epochs(&m).unwrap().admin.newest_held().is_none(), "P lacks M's new keyset secret");
    let epochs = lp.peers[1].engine.epochs(&a);
    lp.peers[1].engine.demote(&a, &Demotion { holder: f, new: None, retain: None }).unwrap();
    assert!(!lp.peers[1].engine.core.current_holders(&a).iter().any(|(x, _, _)| *x == f), "F removed");
    assert_ne!(lp.peers[1].engine.epochs(&a), epochs, "with its rotation");
    assert!(blocked_at(&mut lp, 1, a).is_empty(), "the departure covered at P");
    lp.sync_all().unwrap();
    assert!(blocked_at(&mut lp, 0, a).is_empty(), "A's mint admin holds P's rotation, covering");
}

/// Delivers peer `from`'s commits `ids` to peer `to` without any `keys.0` or `secrets.0` delta on
/// `x` (a role change arriving without its rotation).
fn deliver_edges_only(lp: &mut LocalPeer, from: usize, to: usize, x: Tid, ids: &[osis_base::CommitId]) {
    for pk in lp.packages_for(from, to).unwrap().into_iter().filter(|p| ids.contains(&p.id)) {
        let b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        let cut = osis_commit::rewrite(&b, |ai| b.header.aspects.get(ai).is_some_and(|a| a.tid == x && matches!(a.ak.as_str(), "secrets.0" | "keys.0")));
        let _ = lp.peers[to].receive(&cut.encode(), pk.blobs.clone());
    }
}

// spec/crypto.md §4 (Encrypting under: a node's own departure holds back none of its
// encrypting): C, X's only admin, reads T and is removed from it (T rotated in the removal). C hears
// of the removal before T's new keyset, still holding T's old secret. Its own departure is no
// reason to keep X from T: it rotates nothing for it, and a rotation of X it makes (removing E)
// boxes T at the newest keyset of T it holds, which only C itself left, so T's members read X's
// new epoch. Once T's new keyset reaches C that box is stale and C rotates X again, sealing T
// there: B reads it, E opens nothing of it. (C counting its own departure left T out of X until T's
// members' stranded reports carried T's next keyset to it.)
#[test]
fn own_removal_from_holder_actor_keeps_sealing_it_spec_crypto_4() {
    let mut lp = synced(4);
    let [_, b, c, e] = std::array::from_fn(|i| lp.peers[i].engine.tid());
    let t = independent_thing(&mut lp, 0);
    for h in [b, c] {
        lp.grant_through(0, t, h, &edge(Role::Read));
    }
    lp.sync_all().unwrap();
    let x = independent_thing(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.grant_through(2, x, t, &edge(Role::Read));
    lp.grant_through(2, x, e, &edge(Role::Read));
    lp.sync_all().unwrap();
    assert_eq!(newest_read(&lp, 1, x), newest_read(&lp, 2, x), "B reads X through T");
    let t1 = newest_read(&lp, 2, t).unwrap();
    let rm = removal(&mut lp, 0, t, c);
    deliver_edges_only(&mut lp, 0, 2, t, &rm);
    assert!(!lp.peers[2].engine.core.current_holders(&t).iter().any(|(h, _, _)| *h == c), "C knows its removal");
    assert!(lp.peers[2].engine.epochs(&t).unwrap().read.secret(&t1).is_some(), "C still holds T's old secret");
    let x1 = newest_read(&lp, 2, x);
    assert!(lp.peers[2].engine.ensure_rotated(&x).unwrap().0.commits.is_empty(), "C's own removal rotates nothing of X");
    assert_eq!(newest_read(&lp, 2, x), x1);
    lp.peers[2].engine.demote(&x, &Demotion { holder: e, new: None, retain: None }).unwrap();
    assert_eq!(sealed_at(&mut lp, 2, x, t), Some(t1), "T sealed at the keyset C holds");
    lp.sync(2, 1).unwrap();
    assert_eq!(newest_read(&lp, 1, x), newest_read(&lp, 2, x), "B reads X's new epoch");
    // T's new keyset reaches B, and C (as a certificate under X's sync IDs): the box is stale
    lp.sync(0, 1).unwrap();
    deliver_without_secrets(&mut lp, 0, 2, t);
    let t2 = newest_read(&lp, 0, t).unwrap();
    assert!(!lp.peers[2].engine.ensure_rotated(&x).unwrap().0.commits.is_empty(), "C rotates X onto T's new keyset");
    assert_eq!(sealed_at(&mut lp, 2, x, t), Some(t2));
    lp.sync(2, 1).unwrap();
    assert_eq!(newest_read(&lp, 1, x), newest_read(&lp, 2, x), "B reads it");
    let e_held = held_by(&lp, 3, &[x]);
    assert!(!leaked(&mut lp, 2, &[t, x], e, e_held).contains(&x), "E opens nothing new");
}

// spec/crypto.md §4 (Encrypting under): an epoch whose secret the node lacks is judged by order; model `D0_order`: X administers A, which M holds; X holds none of M's secrets. E leaves M by
// self-removal, so M does not rotate. X knows the departure; M's keyset was made before it, so it
// cannot cover it: X's next rotation of A leaves M out (E opens nothing of it). Once M's rotation
// for the departure reaches X, X seals M there again, and E opens nothing of A's new epochs.
#[test]
fn departure_from_an_unread_holder_is_judged_by_order_spec_crypto_4() {
    let mut lp = synced(3);
    let e = lp.peers[2].engine.tid();
    let m = independent_thing(&mut lp, 1);
    lp.grant_through(1, m, e, &edge(Role::Read));
    let a = independent_thing(&mut lp, 0);
    lp.sync_all().unwrap();
    lp.grant_through(0, a, m, &edge(Role::Read));
    lp.sync_all().unwrap();
    let k1 = newest_read(&lp, 1, m).unwrap();
    assert!(lp.peers[0].engine.epochs(&m).is_none_or(|x| x.read.secret(&k1).is_none()), "X holds none of M's secrets");
    let start = held_by(&lp, 2, &[m, a]);
    lp.peers[2].engine.demote(&m, &Demotion { holder: e, new: None, retain: None }).unwrap();
    lp.sync_all().unwrap();
    assert!(!lp.peers[0].engine.departures(&m).unwrap().is_empty(), "X knows E left M");
    rotate_skipping(&mut lp, 0, a, &BTreeSet::from([Role::Read]), &[]);
    assert_eq!(sealed_at(&mut lp, 0, a, m), None, "M left out: its keyset was made before E left");
    assert_eq!(leaked(&mut lp, 0, &[m, a], e, start.clone()), Vec::<Tid>::new());
    settle(&mut lp, &[1, 0], &[m, a]);
    let k2 = newest_read(&lp, 1, m).unwrap();
    assert_ne!(k1, k2, "M rotated for E's departure");
    assert_eq!(sealed_at(&mut lp, 0, a, m), Some(k2), "A sealed to M's new keyset");
    assert_eq!(newest_read(&lp, 1, a), newest_read(&lp, 0, a), "M's members read A");
    assert_eq!(leaked(&mut lp, 0, &[m, a], e, start), Vec::<Tid>::new());
}

// spec/crypto.md §4 (Encrypting under): the box clause follows every box the node holds; model `D0_readers_out`: G {R, A}, A {a1, M}, M {m1, R, E}. m1 removes E from M; R, G's admin, holds
// M's new keyset but may not rotate A, whose box to M names M's old one. G's epoch boxes A at a
// keyset E opens, so R rotates G leaving A out and E opens nothing R writes under G; once a1
// moves A onto M's new keyset, R seals A again.
#[test]
fn box_walk_passes_actors_the_node_may_not_rotate_spec_crypto_4() {
    let mut lp = synced(4);
    let [r, _, _, e] = std::array::from_fn(|i| lp.peers[i].engine.tid());
    let g = independent_thing(&mut lp, 0);
    let a = independent_thing(&mut lp, 1);
    let m = independent_thing(&mut lp, 2);
    for h in [r, e] {
        lp.peers[2].engine.grant(&m, &h, &edge(Role::Read)).unwrap();
    }
    lp.sync_all().unwrap();
    lp.peers[1].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&g, &a, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    assert!(newest_read(&lp, 0, a).is_some(), "R reads A through M");
    let start = held_by(&lp, 3, &[m, a, g]);
    removal(&mut lp, 2, m, e);
    lp.sync(2, 0).unwrap();
    assert!(blocked_at(&mut lp, 0, g).contains(&Role::Read), "G's epoch boxes A at a keyset boxing M at one E opens");
    let (done, still) = lp.peers[0].engine.ensure_rotated(&g).unwrap();
    assert!(!done.commits.is_empty() && still.is_empty(), "R rotates G");
    assert_eq!(sealed_at(&mut lp, 0, g, a), None, "leaving A out");
    let w = newest_read(&lp, 0, g).unwrap();
    assert!(!openable(&mut lp, 0, &[m, a, g], e, start.clone()).contains(&(g, Role::Read, w)), "E opens nothing R writes under G");
    lp.sync_all().unwrap();
    settle(&mut lp, &[2, 1, 0], &[m, a, g]);
    assert!(all_boxed(&mut lp, 0, &[m, a, g]), "A boxed at G again");
    assert_eq!(leaked(&mut lp, 0, &[m, a, g], e, start), Vec::<Tid>::new());
}

// spec/crypto.md §4 (History box: any holder of the epoch's role adds): W, demoted to read, still
// holds the current write epoch and an earlier write secret its history lists not. It adds no
// write history (that needs write): its re-seal pass writes nothing there, and fails nothing.
#[test]
fn lowered_holder_adds_no_history_above_its_role_spec_crypto_4() {
    let mut lp = synced(2);
    let [x, w] = std::array::from_fn(|i| lp.peers[i].engine.tid());
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &w, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    // W's write epoch leaves X out; X supersedes it lacking its secret, so its history lists it not
    rotate_skipping(&mut lp, 1, g, &BTreeSet::from([Role::Write]), &[x]);
    lp.sync_all().unwrap();
    rotate_skipping(&mut lp, 0, g, &BTreeSet::from([Role::Write]), &[]);
    lp.sync_all().unwrap();
    let rm = lp.peers[0].engine.demote(&g, &Demotion { holder: w, new: Some(edge(Role::Read)), retain: None }).unwrap().commits;
    deliver_edges_only(&mut lp, 0, 1, g, &rm);
    assert_eq!(lp.peers[1].engine.core.role_now(&w, &g), Some(Role::Read), "W knows its demotion");
    let e = lp.peers[1].engine.epochs(&g).unwrap();
    assert!(e.write.current().iter().all(|c| e.write.secret(c).is_some()), "W holds the current write epoch");
    let done = lp.peers[1].engine.reseal_after_pass(&g).unwrap();
    assert!(done.commits.is_empty(), "no write history from a reader");
}

// spec/crypto.md §4 (Departure: a rotator that no longer holds r): an honest rotator whose role
// on M runs through holder T (keyed) is lowered on T, then re-granted. The admin rotates M once
// for it; re-granted, P has departed nothing, and no further pass rotates M (bounded: the
// rotator's departure ends with its epoch, superseded).
#[test]
fn lowered_rotator_rotates_once_spec_crypto_4() {
    let mut lp = synced(2);
    let p = lp.peers[1].engine.tid();
    let t = independent_thing(&mut lp, 0);
    let m = independent_thing(&mut lp, 0);
    for (x, h) in [(m, t), (t, p)] {
        lp.peers[0].clock.advance(1);
        lp.grant_through(0, x, h, &edge(Role::Write));
    }
    lp.sync_all().unwrap();
    assert!(boxes(&mut lp, 0, m, t), "M's grant to T is keyed");
    lp.peers[1].clock.advance(1_000);
    rotate_skipping(&mut lp, 1, m, &BTreeSet::from([Role::Read, Role::Write]), &[]);
    lp.sync_all().unwrap();
    let rotations = |lp: &mut LocalPeer| (0..3).map(|_| {
        let n = lp.peers[0].engine.ensure_rotated(&t).unwrap().0.commits.len() + lp.peers[0].engine.ensure_rotated(&m).unwrap().0.commits.len();
        lp.sync_all().unwrap();
        n
    }).collect::<Vec<_>>();
    lp.peers[0].engine.demote(&t, &Demotion { holder: p, new: Some(edge(Role::Read)), retain: None }).unwrap();
    lp.sync_all().unwrap();
    let k = newest_read(&lp, 0, m);
    let first = rotations(&mut lp);
    assert!(first[0] > 0 && first[1..].iter().all(|n| *n == 0), "one round of rotations, then none: {first:?}");
    assert_eq!(newest_read(&lp, 0, m), k, "M's read epoch P made stands: P still reads M");
    lp.grant_through(0, t, p, &edge(Role::Write));
    lp.sync_all().unwrap();
    assert_eq!(rotations(&mut lp), vec![0, 0, 0], "re-granted: nothing more rotates");
}

// spec/crypto.md §4 (holder actors: stale; rotation due): one cause, one rotation. D's removal
// from G goes alone (no rotation, as by a remover that may not rotate); G's rotation, due at G's admin, makes T's
// box to G stale at each of T's three admins. The admin rotates T in the same step
// (`rotate_above`), so T's other admins, judging after, find nothing due: T moves one epoch,
// unforked, where each admin rotating T for the stale box forked it three ways.
#[test]
fn holder_rotation_rotates_above_at_once_spec_crypto_4() {
    let mut lp = synced(4);
    let [_, b, c, d] = std::array::from_fn(|i| lp.peers[i].engine.tid());
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &d, &edge(Role::Read)).unwrap();
    let t = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&t, &g, &edge(Role::Read)).unwrap();
    for h in [b, c] {
        lp.peers[0].engine.grant(&t, &h, &edge(Role::Admin)).unwrap();
    }
    lp.sync_all().unwrap();
    let k = newest_read(&lp, 0, t).unwrap();
    removal_alone(&mut lp, 0, g, d);
    assert_eq!(lp.peers[0].engine.ensure_rotated(&g).unwrap().0.commits.len(), 2, "G's rotation, then T's");
    lp.sync_all().unwrap();
    let after: Vec<usize> = [1, 2, 0].into_iter().map(|p| lp.peers[p].engine.ensure_rotated(&t).unwrap().0.commits.len()).collect();
    assert_eq!(after, vec![0, 0, 0], "T's other admins, then its rotator, find nothing due");
    let cur = lp.peers[1].engine.epochs(&t).unwrap().read.current();
    assert_eq!((cur.len(), cur[0].n()), (1, k.n() + 1), "one rotation of T");
}

/// Three rounds of R (0) rotating `g` as due and W (4) re-sealing it, synced: R rotates once, W
/// re-seals nothing.
fn r_rotates_once_w_reseals_nothing(lp: &mut LocalPeer, g: Tid) {
    let mut counts = Vec::new();
    for _ in 0..3 {
        let rot = lp.peers[0].engine.ensure_rotated(&g).unwrap().0.commits.len();
        lp.sync_all().unwrap();
        let reseal = lp.peers[4].engine.reseal_after_pass(&g).unwrap().commits.len();
        lp.sync_all().unwrap();
        counts.push((rot, reseal));
    }
    assert_eq!(counts, vec![(1, 0), (0, 0), (0, 0)], "R rotates G once; W re-seals nothing");
}

// spec/crypto.md §4 (Encrypting under; holder actors: stale, Seal): G {R, W, A}, A {a1, M},
// M {m1, R, E}. m1 removes E from M, rotating M; a1 never rotates A, whose epoch boxes M at the
// keyset E opens. R knows the removal, so rotates G leaving A out. W, G's other admin, holds
// none of M's secrets but holds M's new keyset: A's box to M is stale there, so W leaves A out
// too rather than re-sealing it (each re-seal made G's epoch blocked at R, which rotated again,
// for good while A's rotation never came).
#[test]
fn co_writer_seals_no_keyset_with_a_stale_box_spec_crypto_4() {
    let (mut lp, m, a, g) = co_writer_world();
    let e = lp.peers[3].engine.tid();
    let start = held_by(&lp, 3, &[m, a, g]);
    removal(&mut lp, 2, m, e);
    lp.sync_all().unwrap();
    assert!(lp.peers[4].engine.epochs(&m).is_none_or(|x| x.read.held().next().is_none()), "W holds none of M's secrets");
    r_rotates_once_w_reseals_nothing(&mut lp, g);
    assert_eq!(sealed_at(&mut lp, 4, g, a), None, "A left out");
    assert_eq!(leaked(&mut lp, 0, &[m, a, g], e, start), vec![a], "E opens only A, which a1 never rotates");
}

// spec/crypto.md §4 (Encrypting under: a stale box at any epoch the walk follows; Seal; Stale; a
// departure from a holder actor M' of M): the world above, nobody but W acting after the removal,
// so no keyset of G records A left out. W holds none of A's or M's secrets but M's knowing keyset,
// so A's epoch's box to M, one level below G, is stale there: W may not write under G's epoch
// boxing A at it (E opens it through A). W's due rotation (before writing), and one W makes
// unasked (the seal rule alone), leave A out of G's new epoch: E opens none of it.
#[test]
fn writer_leaves_out_at_a_stale_box_below_spec_crypto_4() {
    for due in [true, false] {
        let (mut lp, m, a, g) = co_writer_world();
        let e = lp.peers[3].engine.tid();
        let start = held_by(&lp, 3, &[m, a, g]);
        removal(&mut lp, 2, m, e);
        lp.sync_all().unwrap();
        assert!(lp.peers[4].engine.epochs(&a).is_none_or(|x| x.read.held().next().is_none()), "W holds none of A's secrets");
        assert!(blocked_at(&mut lp, 4, g).contains(&Role::Read), "G's epoch blocked at W");
        if due {
            let rot = lp.peers[4].engine.ensure_rotated(&g).unwrap().0.commits.len();
            assert_eq!(rot, 1, "W rotates G");
            assert!(blocked_at(&mut lp, 4, g).is_empty());
        } else {
            rotate_skipping(&mut lp, 4, g, &BTreeSet::from([Role::Read]), &[]);
        }
        assert_eq!(sealed_at(&mut lp, 4, g, a), None, "due {due}: A left out");
        assert!(!leaked(&mut lp, 4, &[m, a, g], e, start).contains(&g), "due {due}: E opens none of G's new epoch");
    }
}

/// Peer `i` removes `d` from `t` alone (no rotation, as by a remover that may not rotate).
fn removal_alone(lp: &mut LocalPeer, i: usize, t: Tid, d: Tid) {
    lp.peers[i]
        .engine
        .run(|tx| {
            let mut m = Mutation::new();
            m.ts = Some(tx.core.hlc.next());
            crate::flows::edges::removal(tx, &mut m, t, d)?;
            m.frontier(osis_perm::Frontier::default());
            crate::engine::Engine::commit_tx(tx, m).map(|_| ())
        })
        .unwrap();
}

// spec/crypto.md §4 (Seal; Left out), model `D0_readers_g2_mark`: G {R, W, A}, A {a1, M},
// M {m1, R, E}. m1 removes E from M alone: M keeps the keyset E opens, so W, G's other admin
// reading neither A nor M, can tell nothing of it. R knows the removal, so rotates G leaving A out
// at A's keyset, and G's keyset records it; W then does not re-seal A there (each re-seal made
// G's epoch blocked at R, which rotated again, for as long as M did not rotate). Once M and A
// rotate, both re-seal A at A's knowing keyset, which descends from the one recorded.
#[test]
fn co_writer_reseals_no_holder_left_out_spec_crypto_4() {
    let (mut lp, m, a, g) = co_writer_world();
    let e = lp.peers[3].engine.tid();
    let start = held_by(&lp, 3, &[m, a, g]);
    let k_a = sealed_at(&mut lp, 0, g, a).unwrap();
    removal_alone(&mut lp, 2, m, e);
    lp.sync_all().unwrap();
    r_rotates_once_w_reseals_nothing(&mut lp, g);
    assert_eq!(sealed_at(&mut lp, 4, g, a), None, "A left out");
    let ks = lp.peers[4].engine.core.ix.keysets.get(&(g, Role::Read, newest_read(&lp, 4, g).unwrap())).unwrap().left_out.clone();
    assert_eq!(ks.get(&a).map(|x| x.keys().copied().collect()), Some(BTreeSet::from([k_a])), "G's keyset records A's keyset it left A out at");
    assert!(ks[&a][&k_a].iter().all(|c| lp.peers[4].engine.core.cause_held(c)) && !ks[&a][&k_a].is_empty(), "with its causes, held at W");
    assert!(!leaked(&mut lp, 0, &[m, a, g], e, start.clone()).contains(&g), "E opens nothing R writes under G");
    // M rotates knowing the removal, then A (its box to M is stale): A is re-sealed to G
    settle(&mut lp, &[2, 1, 0, 4], &[m, a, g]);
    assert_ne!(sealed_at(&mut lp, 4, g, a), None, "A re-sealed to G");
    assert!(all_boxed(&mut lp, 0, &[m, a, g]));
    assert_eq!(leaked(&mut lp, 0, &[m, a, g], e, start), Vec::<Tid>::new());
    // the record is obsolete once A is boxed past it: G's next rotation boxes A and records nothing
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from([Role::Read]), &[]);
    lp.sync_all().unwrap();
    let ks = &lp.peers[4].engine.core.ix.keysets.get(&(g, Role::Read, newest_read(&lp, 4, g).unwrap())).unwrap().left_out;
    assert!(ks.is_empty(), "{ks:?}");
    assert_ne!(sealed_at(&mut lp, 4, g, a), None);
}

// spec/crypto.md §4 (Seal; Left out), model `D0_above_g2_mark`: G {a1, W, A}, A {a1, E}. a1
// removes E from A alone and rotates G leaving A out at A's keyset E opens; W, reading not A and
// lacking the removal (so not judging A's keyset by order), does not re-seal A there. Once a1
// rotates A, W re-seals A at that keyset.
#[test]
fn removal_alone_left_out_stays_out_at_co_writer_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let mut lp = synced(3);
    let [_, w, e] = std::array::from_fn(|i| lp.peers[i].engine.tid());
    let a = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&a, &e, &edge(Role::Read)).unwrap();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &a, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&g, &w, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let start = held_by(&lp, 2, &[a, g]);
    let before = commit_ids(&mut lp, 0);
    removal_alone(&mut lp, 0, a, e);
    let removal: BTreeSet<osis_base::CommitId> = commit_ids(&mut lp, 0).difference(&before).copied().collect();
    rotate_leaving_out(&mut lp, 0, g, &read, &[]);
    assert_eq!(sealed_at(&mut lp, 0, g, a), None, "a1 leaves A out");
    send_skipping(&mut lp, 0, 1, &removal);
    assert!(lp.peers[1].engine.departures(&a).unwrap().is_empty(), "W lacks the removal");
    assert!(lp.peers[1].engine.epochs(&a).is_none_or(|x| x.read.held().next().is_none()), "W holds none of A's secrets");
    assert_eq!(lp.peers[1].engine.reseal_after_pass(&g).unwrap().commits.len(), 0, "W re-seals nothing");
    lp.sync_all().unwrap();
    assert_eq!(sealed_at(&mut lp, 1, g, a), None);
    assert!(!leaked(&mut lp, 0, &[a, g], e, start.clone()).contains(&g), "E opens nothing a1 writes under G");
    lp.peers[0].engine.ensure_rotated(&a).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.reseal_after_pass(&g).unwrap().commits.len(), 1, "W re-seals A at its knowing keyset");
    lp.sync_all().unwrap();
    assert_eq!(sealed_at(&mut lp, 1, g, a), newest_read(&lp, 0, a));
    assert_eq!(leaked(&mut lp, 0, &[a, g], e, start), Vec::<Tid>::new());
}

// spec/permissions.md §3 (re-seal), spec/crypto.md §4 (Encrypting under): a re-seal pass reads
// its candidates after the rotations and finalizes due first. X admins G, which M reads; X writes
// M only through H, whose newest keyset X lacks the secret of (H rotated leaving X out, M boxing
// H there). M, lacking a box at G's newest epoch, is a candidate; X's finalize of Y's ended edge
// on M comes first and carries M's rotation (sealing H to its keyset's KEM key), so the pass
// re-seals M at that new keyset, never at the one Y reads.
#[test]
fn reseal_candidates_follow_the_finalize_before_them_spec_permissions_3() {
    let mut lp = synced(3);
    let [_, x, y] = std::array::from_fn(|i| lp.peers[i].engine.tid());
    let (g, m, h) = (independent_thing(&mut lp, 0), independent_thing(&mut lp, 0), independent_thing(&mut lp, 0));
    lp.peers[0].engine.grant(&h, &x, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&m, &h, &edge(Role::Write)).unwrap();
    let until = Time(lp.peers[0].engine.core.now().0 + 100);
    lp.peers[0].engine.grant(&m, &y, &ct::Grant { until: Some(until), ..edge(Role::Read) }).unwrap();
    lp.peers[0].engine.grant(&g, &m, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&g, &x, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    rotate_skipping(&mut lp, 0, h, &BTreeSet::from([Role::Read, Role::Write]), &[x]);
    assert!(!lp.peers[0].engine.ensure_rotated(&m).unwrap().0.commits.is_empty(), "M rotates onto H's new keyset");
    rotate_skipping(&mut lp, 0, g, &BTreeSet::from([Role::Read]), &[m]);
    lp.sync_all().unwrap();
    lp.peers[1].clock.advance(1_000);
    let cands = lp.peers[1].engine.run(|tx| super::reseal_candidates(tx, &g)).unwrap();
    assert!(cands.iter().any(|c| c.0 == m), "M is a candidate before the finalize: {cands:?}");
    let before = newest_read(&lp, 1, m);
    lp.peers[1].engine.reseal_after_pass(&g).unwrap();
    assert!(lp.peers[1].engine.core.current_holders(&m).iter().all(|(h, _, _)| *h != y), "X finalized Y");
    assert!(blocked_at(&mut lp, 1, m).is_empty(), "its rotation covers Y's departure");
    let now = newest_read(&lp, 1, m);
    assert_ne!(now, before, "M rotated with the finalize");
    assert_eq!(sealed_at(&mut lp, 1, g, m), now, "M re-sealed at X's new keyset");
}

// spec/permissions.md §2 (finalize), §3 (re-seal): a holder lacking a box is a re-seal candidate
// until the clock reaches its grant's `until` (the edge counts as removed from then), then a
// departure due and no candidate: the clock alone moves the candidates (`reseal_candidates` is a
// memo, its time read up to the component's horizon), at that very millisecond.
#[test]
fn reseal_candidates_follow_the_clock_spec_permissions_2() {
    let mut lp = synced(1);
    let (g, m) = (independent_thing(&mut lp, 0), independent_thing(&mut lp, 0));
    let until = Time(lp.peers[0].engine.core.now().0 + 1_000);
    lp.peers[0].engine.grant(&g, &m, &ct::Grant { until: Some(until), ..edge(Role::Read) }).unwrap();
    rotate_skipping(&mut lp, 0, g, &BTreeSet::from([Role::Read]), &[m]);
    let cands = |lp: &mut LocalPeer| lp.peers[0].engine.run(|tx| super::reseal_candidates(tx, &g)).unwrap();
    assert!(cands(&mut lp).iter().any(|c| c.0 == m), "M lacks its box at G's newest epoch");
    lp.peers[0].clock.set(Time(until.0 - 1));
    assert!(cands(&mut lp).iter().any(|c| c.0 == m), "a millisecond before its `until`");
    lp.peers[0].clock.set(until);
    let after = cands(&mut lp);
    assert!(after.iter().all(|c| c.0 != m), "M's grant ended: a departure due, no re-seal: {after:?}");
}

// spec/crypto.md §4 (Key access: a keyless grant is a role all the same), spec/permissions.md §3
// (Who rotates): P writes A directly and is admin of A only through M, whose grant on A is
// keyless (A held M first), so P's rotations of A box M nothing. P's rotation of read (which also
// refreshes A's deposit seed, an admin field judged by role) is valid.
#[test]
fn rotation_through_a_keyless_grant_is_valid_spec_crypto_4() {
    let mut lp = synced(2);
    let p = lp.peers[1].engine.tid();
    let a = independent_thing(&mut lp, 0);
    let m = independent_thing(&mut lp, 1);
    lp.sync_all().unwrap();
    lp.peers[1].engine.grant(&m, &a, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&a, &p, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.core.role_now(&p, &a), Some(Role::Admin));
    let before = commit_ids(&mut lp, 1);
    lp.peers[1].engine.run(|tx| super::rotate_now(tx, p, a, &BTreeSet::from([Role::Read]))).unwrap();
    let c = *commit_ids(&mut lp, 1).difference(&before).next().unwrap();
    let meta = lp.peers[1].engine.core.ix.commits.get(&c).cloned().unwrap();
    assert!(meta.view.aspects.iter().enumerate().filter(|(_, x)| x.tid == a).all(|(ai, _)| meta.valid_at(ai)));
}

// spec/permissions.md §3 (Who rotates), spec/crypto.md §4 (orphaned): a role through a keyless
// grant is no right to rotate. Cycle as above; X reads M directly and writes it only through G's
// keyless grant on H. Peer 0 rotates M's read boxing X alone; at writer W (peer 2), lacking the
// new secret, the epoch boxes no holder that may rotate read (X's rotation would be invalid):
// orphaned, so W rotates it.
#[test]
fn keyless_route_is_no_rotator_spec_crypto_4() {
    let mut lp = synced(3);
    let (o, x, w) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let (g, m, h) = (independent_thing(&mut lp, 0), independent_thing(&mut lp, 0), independent_thing(&mut lp, 0));
    lp.peers[0].engine.grant(&g, &m, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&m, &h, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&h, &g, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &x, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&m, &x, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&m, &w, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    let due = |lp: &mut LocalPeer| lp.peers[2].engine.run(|tx| super::rotation_due(tx, &w, &m, super::Due::Encrypt, &BTreeSet::new())).unwrap();
    assert!(due(&mut lp).is_empty());
    rotate_skipping(&mut lp, 0, m, &BTreeSet::from([Role::Read]), &[o, h, w]);
    lp.sync_all().unwrap();
    let e = newest_read(&lp, 0, m).unwrap();
    assert!(lp.peers[2].engine.epochs(&m).unwrap().read.secret(&e).is_none(), "W lacks the new read secret");
    assert!(due(&mut lp).contains(&Role::Read), "orphaned at W: X is no rotator of M");
}

/// A destroyed holder actor's world (spec/crypto.md §4, Holder actors, Destroyed): peer 0 makes T,
/// expiring at `T0 + 50 s` (mint admin peer 0, independent) and X (independent),
/// grants T read on X; peer 2 makes G and peer 0 grants G read on T; peer 1 reads T, and peer
/// 3 reads G; D is dependent, T its mint admin. Synced: T, X, G.
fn destroyed_world() -> (LocalPeer, Tid, Tid, Tid, Tid) {
    let mut lp = LocalPeer::new(4, 0, T0).unwrap();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_expiring_thing(&mut m, me, Some(Time(T0.0 + 50_000)));
    m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &osis_base::Value::Int(0)).unwrap();
    m.expires_all(Time(T0.0 + 50_000));
    lp.peers[0].commit(m).unwrap();
    lp.hold(t);
    lp.peers[0].engine.make_independent(&t).unwrap();
    let mut m = Mutation::new();
    let d = lp.peers[0].engine.new_thing(&mut m, t);
    lp.peers[0].commit(m).unwrap();
    let x = independent_thing(&mut lp, 0);
    let g = independent_thing(&mut lp, 2);
    // the granters keep the nodes they grant (a strong from the node root): nothing else
    // needs another account's node
    let (n1, n3) = (lp.peers[1].engine.tid(), lp.peers[3].engine.tid());
    lp.peers[0].know(&[n1]).unwrap();
    lp.peers[2].know(&[n3]).unwrap();
    lp.sync_all().unwrap();
    lp.grant_through(0, x, t, &edge(Role::Read));
    lp.grant_through(0, t, g, &edge(Role::Read));
    lp.grant_through(0, t, n1, &edge(Role::Read));
    lp.grant_through(2, g, n3, &edge(Role::Read));
    lp.sync_all().unwrap();
    (lp, t, x, g, d)
}

const T0: Time = Time(1_700_000_000_000);

// spec/crypto.md §4 (Holder actors, Destroyed): a destroyed thing holds no keys and nobody stands
// in its place. Once T expires, X's admin rotates X (its box to T is a departure) boxing neither
// T nor G, T's holder: peers 1 and 3, reading X only through T, open nothing of X's new epoch
// from every secret they held and hold X for keys no more, while their roles through T stand
// for judging writes (spec/commits.md §5 Destruction). Their nodes drop X keeping no copy, as at
// a removal not saying retain (spec/permissions.md §3 Lost access). Nobody holds D, T's
// dependent, for keys
#[test]
fn destroying_a_holder_actor_ends_access_through_it_spec_crypto_4() {
    let (mut lp, t, x, g, d) = destroyed_world();
    let (n0, n1, n3) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[3].engine.tid());
    let k = osis_base::Ak::new("x:a.0").unwrap();
    let mut m = Mutation::new();
    m.set(x, &k, &osis_base::Value::Int(7)).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[3].engine.get(&x, &k).unwrap(), Some(osis_base::Value::Int(7)), "peer 3 reads X's content");
    assert_eq!(lp.peers[0].engine.core.keyed_role_now(&n0, &d), Some(Role::Admin), "peer 0 holds D through T");
    let start: Opened = held_by(&lp, 1, &[t, x]).into_iter().chain(held_by(&lp, 3, &[t, x, g])).collect();
    assert!(held_by(&lp, 3, &[x]).iter().any(|k| k.0 == x), "peer 3 reads X through G and T");
    let before = newest_read(&lp, 0, x);
    lp.advance(100_000);
    for i in 0..lp.peers.len() {
        lp.peers[i].tick().unwrap();
    }
    lp.sync_all().unwrap();
    assert!(lp.peers[0].engine.core.destroyed(&t), "T destroyed");
    let core = &lp.peers[0].engine.core;
    assert!(!core.key_holders(&x).iter().any(|h| h.0 == t || h.0 == g), "nobody in T's place: {:?}", core.key_holders(&x));
    for n in [n1, n3] {
        assert_eq!(super::members::role_for_keys(core, &n, &x), None, "no role for keys through T");
        assert!(core.timelines().role(&n, &x, osis_perm::At::KEYS).is_some(), "the role through T stands for writes");
    }
    assert_eq!(core.keyed_role_now(&n0, &d), None, "nobody holds D through T");
    assert!(super::may_rotate(core, &n0, &d).is_empty(), "nobody rotates D through T");
    settle(&mut lp, &[0], &[x]);
    let w = newest_read(&lp, 0, x).unwrap();
    assert_ne!(Some(w), before, "X rotated past its box to T");
    assert!(!boxes(&mut lp, 0, x, t) && !boxes(&mut lp, 0, x, g), "X boxes neither T nor G");
    for n in [n1, n3] {
        assert!(!openable(&mut lp, 0, &[t, x, g], n, start.clone()).contains(&(x, Role::Read, w)), "{n:?} opens nothing of X's new epoch");
    }
    assert!(all_boxed(&mut lp, 0, &[x]), "every holder of X boxed");
    for i in [1, 3] {
        lp.peers[i].engine.drop_lost_secrets().unwrap();
        assert!(!lp.peers[i].engine.core.ix.kept.contains_key(&x), "peer {i} keeps no copy of X through T");
        assert_eq!(lp.peers[i].engine.get(&x, &k).unwrap(), None, "peer {i} reads none of X's content");
    }
    assert_eq!(lp.peers[0].engine.get(&x, &k).unwrap(), Some(osis_base::Value::Int(7)), "X's admin reads it on");
}

// spec/requirements.md (Purging or expiring a thing's creation: it comes back only if the purge
// turns out invalid), spec/crypto.md §4 (Destroyed): peer 1, an admin of T, destroys it while
// peer 0 removes peer 1 from T, neither holding the other's commit. Peer 2, an admin of X holding
// the destruction alone, rotates X without T. Once the removal reaches it the destruction falls:
// T holds X again for keys and is re-sealed, so peer 3 (through G and T) reads X's newest epoch,
// and peer 1, removed from T, opens nothing of it
#[test]
fn a_destruction_that_falls_gives_access_through_it_back_spec_crypto_4() {
    let (mut lp, t, x, g, _) = destroyed_world();
    let (n1, n2) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    lp.peers[0].know(&[n2]).unwrap();
    lp.sync_all().unwrap();
    lp.grant_through(0, t, n1, &edge(Role::Admin));
    lp.grant_through(0, x, n2, &edge(Role::Admin));
    lp.sync_all().unwrap();
    let start = held_by(&lp, 1, &[t, x]);
    lp.advance(1_000);
    {
        let e = &mut lp.peers[1].engine;
        let mut m = Mutation::new();
        let now = e.now();
        m.set(t, &ct::PURGE, &now).unwrap();
        m.purge(osis_commit::PurgeItem::Aspect { tid: t, ak: ct::CREATED.name() });
        e.commit(m).unwrap().unwrap();
    }
    lp.advance(1_000);
    lp.peers[0].engine.demote(&t, &Demotion { holder: n1, new: None, retain: None }).unwrap();
    let before = newest_read(&lp, 2, x);
    send_skipping(&mut lp, 1, 2, &BTreeSet::new());
    assert!(lp.peers[2].engine.core.destroyed(&t), "T destroyed at peer 2");
    lp.peers[2].engine.ensure_rotated(&x).unwrap();
    let w0 = newest_read(&lp, 2, x).unwrap();
    assert_ne!(Some(w0), before, "peer 2 rotated X past its box to T");
    assert!(!boxes_at(&mut lp, 2, x, t, w0), "X's new epoch boxes no T");
    lp.sync_all().unwrap();
    for i in 0..lp.peers.len() {
        assert!(!lp.peers[i].engine.core.destroyed(&t), "peer {i}: the destruction fell");
    }
    settle(&mut lp, &[0, 2], &[x]);
    let w = newest_read(&lp, 0, x).unwrap();
    assert!(lp.peers[0].engine.core.key_holders(&x).iter().any(|h| h.0 == t), "T holds X again");
    assert!(boxes_at(&mut lp, 0, x, t, w), "T boxed at X's newest epoch");
    assert_eq!(newest_read(&lp, 3, x), Some(w), "peer 3 reads X through G and T again");
    assert!(!openable(&mut lp, 0, &[t, x, g], n1, start).contains(&(x, Role::Read, w)), "peer 1, removed from T, opens nothing of it");
}

/// Whether `a`'s `secrets.0` at peer `i` boxes `h` at read epoch `e`.
fn boxes_at(lp: &mut LocalPeer, i: usize, a: Tid, h: Tid, e: Epoch) -> bool {
    lp.peers[i].engine.get_typed(&a, &ct::SECRETS).unwrap().is_some_and(|s| s.boxes.keys().any(|k| k.holder == osis_base::Weak(h) && k.role == Role::Read && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|x| x == e)))
}

// spec/crypto.md §4 (Box records: a rotation's alone), spec/permissions.md §4 (current `keys.0`
// commits: every commit with a write live in the `keys.0` state): grants on A write nothing in
// A's `keys.0`, so after a deposit seed refresh and holder actor grants A's current `keys.0`
// commits are the refresh and A's rotation, the same at 2 and at 20 holder actors granted.
#[test]
fn grants_leave_the_current_keys_as_they_were_spec_permissions_4() {
    let current = |n: usize| {
        let mut lp = synced(1);
        let a = independent_thing(&mut lp, 0);
        let seed = *lp.peers[0].engine.refresh_deposit_seed(&a).unwrap().commits.last().unwrap();
        let before = lp.peers[0].engine.current_keys(&a).unwrap();
        assert!(before.contains(&seed), "the deposit seed refresh among A's current keys.0 commits");
        for _ in 0..n {
            let t = independent_thing(&mut lp, 0);
            let done = lp.peers[0].engine.grant(&a, &t, &edge(Role::Read)).unwrap();
            for c in &done.commits {
                let h = lp.peers[0].engine.header(c).unwrap();
                assert!(h.aspect_index(&a, "keys.0").is_none(), "a grant writes no keys.0 on A");
            }
        }
        assert_eq!(lp.peers[0].engine.current_keys(&a).unwrap(), before, "A's current keys.0 commits unmoved by {n} grants");
        before.len()
    };
    assert_eq!(current(2), current(20));
}

/// What osis-sync's driver runs at peer `i` with nothing written: the role commits owed on each
/// held actor (`Life`, when `role_duty_due`), the lost-access drop (when `role_duties_due`), then
/// a complete pass of each sync ID it wants one of, its end deciding (`pass_end`, as status calls
/// it).
pub(super) fn driver_duties(lp: &mut LocalPeer, i: usize) {
    let e = &mut lp.peers[i].engine;
    for a in e.held_actors() {
        if e.role_duty_due(&a).unwrap() {
            e.ensure_rotated(&a).unwrap();
        }
    }
    if e.role_duties_due().unwrap() {
        e.role_duties().unwrap();
    }
    let wanted: Vec<_> = e.passes_wanted().unwrap().keys().copied().collect();
    for s in wanted {
        let now = e.begin_pass();
        e.note_complete_pass(&s, now).unwrap();
        for o in e.sync_owners(&s).unwrap() {
            e.pass_end(&o).unwrap();
        }
    }
}

// spec/crypto.md §4 (Encrypting under: a stale box blocks, a node that may rotate the actor
// rotates before encrypting), spec/permissions.md §3 (Required rotation): as
// `writer_rotates_past_a_stale_box_below_before_writing_spec_crypto_4`, but with only what
// osis-sync's driver runs (the role duties and pass ends), not `ensure_rotated` by hand. M's
// rotation is a role commit on M alone, so nothing lists G (nor A) for the duties, and no pass
// of G's sync IDs is wanted (no role commit on G arrived): the derived duty (`role_duty_due`, per
// held actor) is what rotates A and G, else every write under them waits for good.
#[test]
fn the_driver_rotates_past_a_stale_box_below_spec_crypto_4() {
    let (mut lp, m, a, g) = co_writer_world();
    let e = lp.peers[3].engine.tid();
    // every sync ID read had its complete pass: nothing is owed before the removal
    for i in 0..5 {
        driver_duties(&mut lp, i);
    }
    assert!(blocked_at(&mut lp, 1, a).is_empty() && blocked_at(&mut lp, 4, g).is_empty(), "nothing blocked before");
    removal(&mut lp, 2, m, e);
    lp.sync_all().unwrap();
    for _ in 0..3 {
        for i in 0..5 {
            driver_duties(&mut lp, i);
        }
        lp.sync_all().unwrap();
    }
    assert!(blocked_at(&mut lp, 1, a).is_empty(), "A's admin rotated A past its stale box to M");
    for i in [0, 4] {
        assert!(blocked_at(&mut lp, i, g).is_empty(), "peer {i}, an admin of G, rotated G");
    }
}

// spec/crypto.md §4 (Stale; Encrypting under), notes/holder-actors.md (Stale): the
// remover is A's only admin. Its removal of R from M rotates M, whose box from A at M's old
// keyset is then stale; the removal's own rotation is not followed upward, and nothing arrives
// from elsewhere, so the derived duty on A rotates it, else A's epoch would stay blocked at its
// only rotator for good.
#[test]
fn the_removers_duties_rotate_above_its_own_removal_spec_crypto_4() {
    let mut lp = synced(2);
    let r = lp.peers[1].engine.tid();
    let m = independent_thing(&mut lp, 0);
    let a = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&m, &r, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    driver_duties(&mut lp, 0);
    assert!(blocked_at(&mut lp, 0, a).is_empty(), "nothing blocked before");
    removal(&mut lp, 0, m, r);
    driver_duties(&mut lp, 0);
    assert!(blocked_at(&mut lp, 0, a).is_empty(), "A rotated past its stale box to M");
}

// spec/crypto.md §4 (Left out; Stale), spec/permissions.md §3: G {g0, W admin, M}, M {m0, N},
// N {n0, P admin}. P rotates N while n0 demotes P concurrently, so P's rotation turns invalid once
// both are held. W holds P's rotation but not the demotion: M's box to N names the keyset P's
// rotation supersedes, stale at W, so W's rotation of G leaves M out and records M's keyset with
// P's rotation as its cause. Once everything is held P's rotation is invalid, but a rotation
// stands while held (a keyset held invalid blocks a box naming it as one held valid blocks a box
// naming what it lists), so M's rotator re-keys M once and every holder of G with key access ends
// boxed at G's current epochs (model `LO_rot`; `LO_inv_old` fails `Live`).
#[test]
fn left_out_on_an_invalidated_rotation_ends_with_one_rekey_spec_crypto_4() {
    let mut lp = synced(5);
    let [_, p, _, _, w] = std::array::from_fn(|i| lp.peers[i].engine.tid());
    let n = independent_thing(&mut lp, 3);
    lp.peers[3].engine.grant(&n, &p, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let m = independent_thing(&mut lp, 2);
    lp.peers[2].engine.grant(&m, &n, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &m, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&g, &w, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let before = commit_ids(&mut lp, 1);
    rotate_skipping(&mut lp, 1, n, &BTreeSet::from([Role::Read]), &[]);
    let p_rot = *commit_ids(&mut lp, 1).difference(&before).next().unwrap();
    lp.peers[3].engine.demote(&n, &Demotion { holder: p, new: Some(edge(Role::Read)), retain: None }).unwrap();
    lp.sync(1, 4).unwrap();
    rotate_skipping(&mut lp, 4, g, &BTreeSet::from([Role::Read]), &[]);
    assert_eq!(sealed_at(&mut lp, 4, g, m), None, "W leaves M out");
    let rec = recorded(&lp, 4, g, m);
    assert!(rec.len() == 1 && rec.values().all(|c| c.contains(&p_rot)), "the record names P's rotation: {rec:?}");
    let km = newest_read(&lp, 2, m);
    lp.sync_all().unwrap();
    settle(&mut lp, &[0, 1, 2, 3, 4], &[n, m, g]);
    assert!(all_boxed(&mut lp, 0, &[g]), "M ends boxed at G's current epochs");
    assert_eq!(newest_read(&lp, 2, m).unwrap().n(), km.unwrap().n() + 1, "M re-keyed once");
}

// spec/crypto.md §4 (Left out: a commit writing a keyset stands as a rotation, whatever its edge
// writes), model `LO_rot`: as above, but P's rotation of N is its removal of Z, in one commit
// writing both the edge and N's keyset. Once everything is held the removal is invalid, so Z
// never left; it stands all the same as the rotation it also is, and M re-keys once. Fails with
// the cause judged by its grant writes first (an invalid departure voiding the record).
#[test]
fn left_out_on_an_invalidated_removal_rotation_stands_as_a_rotation_spec_crypto_4() {
    let mut lp = synced(5);
    let [z, p, _, _, w] = std::array::from_fn(|i| lp.peers[i].engine.tid());
    let n = independent_thing(&mut lp, 3);
    lp.peers[3].engine.grant(&n, &p, &edge(Role::Admin)).unwrap();
    lp.peers[3].engine.grant(&n, &z, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let m = independent_thing(&mut lp, 2);
    lp.peers[2].engine.grant(&m, &n, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &m, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&g, &w, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let before = commit_ids(&mut lp, 1);
    removal(&mut lp, 1, n, z);
    let new: Vec<CommitId> = commit_ids(&mut lp, 1).difference(&before).copied().collect();
    let [p_rm] = new.as_slice() else { panic!("one commit: {new:?}") };
    assert!(lp.peers[1].engine.core.ix.held.edge_commit(p_rm).is_some() && super::members::writes_keyset(&lp.peers[1].engine.core, p_rm), "a grant write and a keyset");
    lp.peers[3].engine.demote(&n, &Demotion { holder: p, new: Some(edge(Role::Read)), retain: None }).unwrap();
    lp.sync(1, 4).unwrap();
    rotate_skipping(&mut lp, 4, g, &BTreeSet::from([Role::Read]), &[]);
    assert_eq!(sealed_at(&mut lp, 4, g, m), None, "W leaves M out");
    let rec = recorded(&lp, 4, g, m);
    assert!(rec.len() == 1 && rec.values().all(|c| c.contains(p_rm)), "the record names P's removal: {rec:?}");
    let km = newest_read(&lp, 2, m);
    lp.sync_all().unwrap();
    assert!(!lp.peers[0].engine.departures(&n).unwrap().iter().any(|x| x.holder == z), "the removal is invalid: Z never left");
    settle(&mut lp, &[0, 1, 2, 3, 4], &[n, m, g]);
    assert!(all_boxed(&mut lp, 0, &[g]), "M ends boxed at G's current epochs");
    assert_eq!(newest_read(&lp, 2, m).unwrap().n(), km.unwrap().n() + 1, "M re-keyed once");
}

/// The keysets of `m` (each with its causes) peer `i` finds `a`'s current read keysets record.
fn recorded(lp: &LocalPeer, i: usize, a: Tid, m: Tid) -> std::collections::BTreeMap<Epoch, BTreeSet<CommitId>> {
    let ix = &lp.peers[i].engine.core.ix.keysets;
    let mut out: std::collections::BTreeMap<Epoch, BTreeSet<CommitId>> = Default::default();
    for e in lp.peers[i].engine.epochs(&a).map(|e| e.read.current()).unwrap_or_default() {
        for (q, c) in ix.get(&(a, Role::Read, e)).and_then(|k| k.left_out.get(&m)).into_iter().flatten() {
            out.entry(*q).or_default().extend(c.iter().copied());
        }
    }
    out
}

/// Peers 0 (g0), 1 (m0), 2 (D), 3 (W), 4 (Q). M {m0, Q admin, D reader}; G {g0, W admin, M
/// reader}, all synced; neither g0 nor W is in M. Returns the peers, M, G and M's read keyset k0.
fn left_out_world() -> (LocalPeer, Tid, Tid, Epoch) {
    let (lp, (m, g, k0)) = LocalPeer::cached("rotation::tests_members::left_out_world", || {
        let mut lp = synced(5);
        let [_, _, d, w, q] = std::array::from_fn(|i| lp.peers[i].engine.tid());
        let m = independent_thing(&mut lp, 1);
        lp.peers[1].engine.grant(&m, &q, &edge(Role::Admin)).unwrap();
        lp.peers[1].engine.grant(&m, &d, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        let g = independent_thing(&mut lp, 0);
        lp.peers[0].engine.grant(&g, &w, &edge(Role::Admin)).unwrap();
        lp.peers[0].engine.grant(&g, &m, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        let k0 = newest_read(&lp, 1, m).unwrap();
        assert_eq!(sealed_at(&mut lp, 0, g, m), Some(k0));
        (lp, (m, g, k0))
    });
    (lp, m, g, k0)
}

/// Peer `i` removes D from M alone (`removal_alone`), and g0 alone gets it, then rotates G: it
/// judges k0 by order (it reads no secret of M), so it leaves M out and records k0 with the
/// removal's grant write as its cause. Returns the removal's commits.
fn g0_leaves_m_out(lp: &mut LocalPeer, i: usize, m: Tid, g: Tid, k0: Epoch) -> BTreeSet<CommitId> {
    let d = lp.peers[2].engine.tid();
    let before = commit_ids(lp, i);
    removal_alone(lp, i, m, d);
    let rm: BTreeSet<CommitId> = commit_ids(lp, i).difference(&before).copied().collect();
    send_skipping(lp, i, 0, &BTreeSet::new());
    assert!(lp.peers[0].engine.epochs(&m).is_none_or(|x| x.read.held().next().is_none()), "g0 reads no secret of M");
    rotate_skipping(lp, 0, g, &BTreeSet::from([Role::Read]), &[]);
    assert_eq!(sealed_at(lp, 0, g, m), None, "g0 leaves M out");
    let rec = recorded(lp, 0, g, m);
    assert_eq!(rec.keys().copied().collect::<Vec<_>>(), vec![k0], "g0 records k0");
    assert!(rec[&k0].iter().all(|c| rm.contains(c)) && !rec[&k0].is_empty(), "its cause is the removal: {rec:?}");
    rm
}

// spec/crypto.md §4 (Left out: a cause stands while its departure stands), model `LO_inv`: Q
// removes D from M alone while m0 demotes Q concurrently (writes nothing else). g0 gets the
// removal only, leaves M out of G and records k0 with it. Once the demotion is held everywhere
// the removal is invalid, D never left, and the record counts nothing: M ends boxed at G at
// every admin, M never rotated.
#[test]
fn left_out_ends_with_a_departure_by_a_concurrently_demoted_admin_spec_crypto_4() {
    let (mut lp, m, g, k0) = left_out_world();
    let q = lp.peers[4].engine.tid();
    lp.peers[1]
        .engine
        .run(|tx| {
            let mut mu = Mutation::new();
            mu.ts = Some(tx.core.hlc.next());
            crate::flows::edges::removal(tx, &mut mu, m, q)?;
            crate::flows::put_edge(&mut mu, m, q, &edge(Role::Read))?;
            mu.frontier(osis_perm::Frontier::default());
            crate::engine::Engine::commit_tx(tx, mu).map(|_| ())
        })
        .unwrap();
    g0_leaves_m_out(&mut lp, 4, m, g, k0);
    lp.sync_all().unwrap();
    let d = lp.peers[2].engine.tid();
    assert!(!lp.peers[0].engine.departures(&m).unwrap().iter().any(|x| x.holder == d), "the removal is invalid: D never left");
    settle(&mut lp, &[0, 1, 3], &[m, g]);
    for i in [0, 3] {
        assert!(all_boxed(&mut lp, i, &[g]), "peer {i}: M boxed at G");
    }
    assert_eq!(newest_read(&lp, 1, m), Some(k0), "M's read never rotated");
}

// spec/crypto.md §4 (Left out: a regrant ends the departure, and so the record): m0 removes D
// from M alone; g0 leaves M out of G recording k0 with the removal. m0 grants D read again: the
// departure is gone, so the record counts nothing and M is re-sealed at k0, nothing rotated.
#[test]
fn left_out_ends_with_a_regrant_spec_crypto_4() {
    let (mut lp, m, g, k0) = left_out_world();
    let d = lp.peers[2].engine.tid();
    g0_leaves_m_out(&mut lp, 1, m, g, k0);
    // the regrant alone, as M's rotation would have been due before any other write of m0
    lp.peers[1]
        .engine
        .run(|tx| {
            let mut mu = Mutation::new();
            mu.ts = Some(tx.core.hlc.next());
            crate::flows::put_edge(&mut mu, m, d, &edge(Role::Read))?;
            crate::engine::Engine::commit_tx(tx, mu).map(|_| ())
        })
        .unwrap();
    lp.sync_all().unwrap();
    assert!(!lp.peers[0].engine.departures(&m).unwrap().iter().any(|x| x.holder == d), "D's departure ended");
    lp.peers[3].engine.reseal_after_pass(&g).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(sealed_at(&mut lp, 0, g, m), Some(k0), "W re-seals M at k0");
    settle(&mut lp, &[0, 1, 3], &[m, g]);
    assert!(all_boxed(&mut lp, 0, &[g]));
    assert_eq!(newest_read(&lp, 1, m), Some(k0), "M never rotated");
}

/// The current read epochs of `a` at peer `i` whose boxes to `m` name `k`.
fn boxing_at(lp: &mut LocalPeer, i: usize, a: Tid, m: Tid, k: Epoch) -> Vec<Epoch> {
    let current = lp.peers[i].engine.epochs(&a).unwrap().read.current();
    let s = lp.peers[i].engine.get_typed(&a, &ct::SECRETS).unwrap().unwrap();
    s.boxes
        .iter()
        .filter(|(x, b)| x.holder == osis_base::Weak(m) && x.role == Role::Read && osis_keys::box_keysets(b).contains(&k))
        .filter_map(|(x, _)| osis_keys::aspects::from_schema(&x.epoch).ok())
        .filter(|e| current.contains(e))
        .collect()
}

// spec/crypto.md §4 (Carried: a keyset of A recording causes counts as not arrived until each
// is held; Left out: a keyset M is left out at is blocked by a box), model `LO_voidunheld`: m0 removes D
// from M alone; g0 alone gets the removal and leaves M out of G recording k0, the cause logged
// with its rotation. W, G's other admin, reading no secret of M and lacking the removal, rotates
// G beside it, sealing M at k0 (the stated limit). W then gets g0's rotation without the removal:
// the record is not judged void for want of its cause, so W's own epoch, boxing M at k0, is
// blocked by a box and W rotates G leaving M out, sealing nothing at k0 since; once the removal
// arrives it stands, and W still does not. M's rotator re-keys (the recorded keyset is current),
// and W then re-seals M at the fresh keyset.
#[test]
fn left_out_waits_for_a_withheld_cause_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let (mut lp, m, g, k0) = left_out_world();
    let d = lp.peers[2].engine.tid();
    let start = held_by(&lp, 2, &[m, g]);
    let before = commit_ids(&mut lp, 0);
    let rm = g0_leaves_m_out(&mut lp, 1, m, g, k0);
    let rot = *commit_ids(&mut lp, 0).difference(&before).find(|c| !rm.contains(c)).unwrap();
    let with = lp.peers[0].engine.logged_with(&rot).unwrap();
    assert!(rm.iter().all(|c| with.contains(c)), "the cause is logged with the rotation: {with:?}");
    rotate_skipping(&mut lp, 3, g, &read, &[]);
    assert_eq!(sealed_at(&mut lp, 3, g, m), Some(k0), "W, knowing nothing of the removal, seals M at k0");
    send_skipping(&mut lp, 0, 3, &rm);
    assert!(lp.peers[3].engine.departures(&m).unwrap().is_empty(), "W lacks the removal");
    assert_eq!(lp.peers[3].engine.epochs(&g).unwrap().read.current().len(), 2, "G forks at W");
    assert!(!lp.peers[3].engine.ensure_rotated(&g).unwrap().0.commits.is_empty(), "W's epoch boxing M at k0 is blocked: W rotates");
    lp.peers[3].engine.reseal_after_pass(&g).unwrap();
    assert_eq!(boxing_at(&mut lp, 3, g, m, k0), Vec::<Epoch>::new(), "W seals M at k0 nowhere");
    send_skipping(&mut lp, 1, 3, &BTreeSet::new());
    lp.peers[3].engine.reseal_after_pass(&g).unwrap();
    assert_eq!(boxing_at(&mut lp, 3, g, m, k0), Vec::<Epoch>::new(), "the cause stands: W seals M at k0 nowhere");
    assert!(!leaked(&mut lp, 3, &[m, g], d, start.clone()).contains(&g), "D opens nothing of G's new epoch");
    lp.sync_all().unwrap();
    settle(&mut lp, &[1, 0, 3], &[m, g]);
    assert_ne!(newest_read(&lp, 3, m), Some(k0), "M re-keyed");
    assert!(all_boxed(&mut lp, 3, &[g]));
    assert_eq!(leaked(&mut lp, 0, &[m, g], d, start), Vec::<Tid>::new());
}

// spec/crypto.md §4 (Left out: Re-key), model `LO_ign` (`LO_ign_old` fails `Live`): M {m0, Z
// admins, D, g0 readers}, G {g0, M}. m0 removes D from M alone; Z, not knowing it, rotates M
// (ki, ordered after the removal) leaving m0 out, D boxed. m0, M's only rotator acting (Z never
// acts again), holds no secret of ki, so judges it by order: it covers. g0 reads ki by its names:
// it misses D's removal, so g0 leaves M out of G recording ki. At the end of its next pass of G,
// m0 re-keys M (ki is current and recorded with a standing cause), once; g0 re-seals M at the
// fresh keyset, which D opens nothing of.
#[test]
fn rotator_judging_by_order_rekeys_a_recorded_keyset_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let mut lp = synced(4);
    let [g0, m0, z, d] = std::array::from_fn(|i| lp.peers[i].engine.tid());
    let m = independent_thing(&mut lp, 1);
    lp.peers[1].engine.grant(&m, &z, &edge(Role::Admin)).unwrap();
    for h in [d, g0] {
        lp.peers[1].engine.grant(&m, &h, &edge(Role::Read)).unwrap();
    }
    lp.sync_all().unwrap();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &m, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let start = held_by(&lp, 3, &[m, g]);
    removal_alone(&mut lp, 1, m, d);
    lp.peers[2].clock.advance(60_000);
    rotate_skipping(&mut lp, 2, m, &read, &[m0]);
    let ki = newest_read(&lp, 2, m).unwrap();
    lp.sync_all().unwrap();
    assert!(lp.peers[1].engine.epochs(&m).unwrap().read.secret(&ki).is_none(), "m0 holds no secret of ki");
    assert!(lp.peers[1].engine.ensure_rotated(&m).unwrap().0.commits.is_empty(), "m0, judging ki by order, owes M nothing");
    lp.peers[0].engine.ensure_rotated(&g).unwrap();
    assert_eq!(sealed_at(&mut lp, 0, g, m), None, "g0 leaves M out");
    assert!(recorded(&lp, 0, g, m).contains_key(&ki), "recording ki");
    lp.sync_all().unwrap();
    let n = ki.n();
    lp.peers[1].engine.reseal_after_pass(&g).unwrap();
    assert_eq!(newest_read(&lp, 1, m).unwrap().n(), n + 1, "m0 re-keys M once");
    lp.peers[1].engine.reseal_after_pass(&g).unwrap();
    assert_eq!(newest_read(&lp, 1, m).unwrap().n(), n + 1, "and not again");
    lp.sync_all().unwrap();
    lp.peers[0].engine.reseal_after_pass(&g).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(sealed_at(&mut lp, 0, g, m), newest_read(&lp, 1, m), "g0 re-seals M at the fresh keyset");
    assert!(all_boxed(&mut lp, 0, &[g]));
    assert_eq!(leaked(&mut lp, 0, &[m, g], d, start), Vec::<Tid>::new(), "D opens nothing");
}

/// Peer `i` rotates `a`'s read leaving holder actor `m` out, recording it left out at `q` with
/// `causes`: what a hostile writer of `a` may write.
fn rotate_recording(lp: &mut LocalPeer, i: usize, a: Tid, m: Tid, q: Epoch, causes: &[CommitId]) {
    lp.peers[i]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&a).unwrap();
            let mut boxing = super::recipients(tx, &tx.core.tid(), &a, &[(m, None)])?;
            boxing.left_out.entry(Role::Read).or_default().entry(m).or_default().insert(q, causes.iter().copied().collect());
            let mut mu = Mutation::new();
            let r = super::rotation_into(tx, &mut mu, a, &BTreeSet::from([Role::Read]), &held, &boxing, crate::rotation::Departs::No)?;
            crate::engine::Engine::commit_tx(tx, mu)?;
            super::record(tx, a, &r)
        })
        .unwrap();
}

// spec/crypto.md §4 (Left out: a false record), hostile writer H of A: M {a0, D removed with M's
// rotation}, A {a0, H writer, M}. Each of H's rotations of A recording M's current keyset with a
// standing cause (D's removal, which that keyset covers) or a commit nobody holds forces one
// rotation of M at a0's next pass end, none after it, and A re-seals M at the fresh keyset;
// recording a keyset not held valid, or with a cause that stands nowhere (the grant of M on A),
// forces none. No rotation boxes D, who opens nothing.
#[test]
fn hostile_record_forces_one_rotation_per_record_spec_crypto_4() {
    let mut lp = synced(3);
    let [_, h, d] = std::array::from_fn(|i| lp.peers[i].engine.tid());
    let m = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&m, &d, &edge(Role::Read)).unwrap();
    let a = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&a, &h, &edge(Role::Write)).unwrap();
    let before = commit_ids(&mut lp, 0);
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
    let grant: Vec<CommitId> = commit_ids(&mut lp, 0).difference(&before).copied().collect();
    lp.sync_all().unwrap();
    let start = held_by(&lp, 2, &[m, a]);
    let before = commit_ids(&mut lp, 0);
    removal(&mut lp, 0, m, d);
    let rm: Vec<CommitId> = commit_ids(&mut lp, 0).difference(&before).copied().collect();
    lp.sync_all().unwrap();
    settle(&mut lp, &[0], &[m, a]);
    for (round, causes) in [rm.clone(), vec![CommitId([3; 32])]].into_iter().enumerate() {
        let k = newest_read(&lp, 0, m).unwrap();
        rotate_recording(&mut lp, 1, a, m, k, &causes);
        lp.sync_all().unwrap();
        assert_eq!(sealed_at(&mut lp, 0, a, m), None, "round {round}: M left out");
        lp.peers[0].engine.reseal_after_pass(&a).unwrap();
        lp.peers[0].engine.reseal_after_pass(&a).unwrap();
        assert_eq!(newest_read(&lp, 0, m).unwrap().n(), k.n() + 1, "round {round}: one rotation of M");
        lp.sync_all().unwrap();
        assert_eq!(sealed_at(&mut lp, 0, a, m), newest_read(&lp, 0, m), "round {round}: A re-seals M");
    }
    let current = newest_read(&lp, 0, m).unwrap();
    for (q, causes) in [(Epoch::new(99, [9; 32]).unwrap(), rm.clone()), (current, grant)] {
        rotate_recording(&mut lp, 1, a, m, q, &causes);
        lp.sync_all().unwrap();
        lp.peers[0].engine.reseal_after_pass(&a).unwrap();
        assert_eq!(newest_read(&lp, 0, m), Some(current), "recording {q:?} with {causes:?} forces no rotation of M");
        lp.sync_all().unwrap();
        assert_eq!(sealed_at(&mut lp, 0, a, m), Some(current), "A re-seals M at it");
    }
    assert!(all_boxed(&mut lp, 0, &[m, a]));
    assert_eq!(leaked(&mut lp, 0, &[m, a], d, start), Vec::<Tid>::new(), "D opens nothing");
}

// spec/wire.md §7 (Left out: each recorded keyset's causes nonempty): a rotation asked to record
// holder actor M left out at its current keyset with no cause (none of the rotator's judgement
// read one) records nothing of M: its keyset of A arrives at a reader, recording no keyset of M,
// and M is still left out of that rotation.
#[test]
fn a_keyset_with_no_cause_is_never_recorded_spec_crypto_4() {
    let mut lp = synced(2);
    let h = lp.peers[1].engine.tid();
    let m = independent_thing(&mut lp, 0);
    let a = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&a, &h, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let k = newest_read(&lp, 0, m).unwrap();
    rotate_recording(&mut lp, 1, a, m, k, &[]);
    let e = newest_read(&lp, 1, a).unwrap();
    assert!(recorded(&lp, 1, a, m).is_empty(), "the writer records no keyset of M");
    assert_eq!(sealed_at(&mut lp, 1, a, m), None, "M left out all the same");
    lp.sync_all().unwrap();
    assert_eq!(newest_read(&lp, 0, a), Some(e), "A's keyset arrives");
    assert!(recorded(&lp, 0, a, m).is_empty(), "recording nothing of M");
    assert!(lp.peers[1].engine.core.ix.keysets.get(&(a, Role::Read, e)).unwrap().left_out.is_empty());
}

// spec/wire.md §7 (Left out: causes nonempty), spec/commits.md §4 (Judged alone: bad by itself):
// a hostile writer H of A rotates A recording M's current keyset with an empty cause set, which
// would count for nothing. Its `keys.0` delta is bad input at a reader, which refuses the commit
// (its only other delta, `secrets.0`, needs it): the keyset is held nowhere but H. Control: the
// same rotation recording one cause (a commit nobody holds) arrives.
#[test]
fn a_record_with_no_cause_is_bad_input_spec_crypto_4() {
    let mut lp = synced(2);
    let h = lp.peers[1].engine.tid();
    let m = independent_thing(&mut lp, 0);
    let a = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&a, &h, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let k = newest_read(&lp, 0, m).unwrap();
    for (causes, held) in [(BTreeSet::from([CommitId([3; 32])]), true), (BTreeSet::new(), false)] {
        let before = commit_ids(&mut lp, 1);
        lp.peers[1]
            .engine
            .run(|tx| {
                let held = tx.core.epochs(&a).unwrap();
                let boxing = super::recipients(tx, &h, &a, &[(m, None)])?;
                let secrets = crate::flows::secrets_in(tx, &a)?;
                let names = super::departures::names(tx.core, &a, None);
                let mut rot = osis_keys::rotate_leaving_out(&a, &BTreeSet::from([Role::Read]), &held, &secrets, &boxing.holders, &boxing.left_out, &osis_keys::Carried::default(), &BTreeSet::new(), &names, false, None, &mut *tx.rng).unwrap();
                // written raw, past the writer's rules: the writer records no causeless keyset
                let ks = rot.keys.keysets.get_mut(&Role::Read).unwrap();
                ks.left_out.insert(m.into(), [(osis_keys::aspects::to_schema(&k), causes.clone())].into());
                let mut mu = Mutation::new();
                crate::flows::put_secrets(&mut mu, a, &rot.secrets, false)?;
                crate::flows::put_keysets(&mut mu, a, &rot.keys)?;
                mu.unchecked();
                tx.core.skip_writer_rules = true;
                let c = crate::engine::Engine::commit_tx(tx, mu);
                tx.core.skip_writer_rules = false;
                c?;
                super::record(tx, a, &rot)
            })
            .unwrap();
        let e = newest_read(&lp, 1, a).unwrap();
        let id = *commit_ids(&mut lp, 1).difference(&before).next().unwrap();
        let pk = lp.peers[1].engine.package(&id).unwrap().unwrap();
        lp.peers[0].receive(&pk.bytes, pk.blobs).unwrap();
        assert_eq!(lp.peers[0].engine.core.ix.keysets.contains_key(&(a, Role::Read, e)), held, "causes {causes:?}: the keyset held at a reader");
    }
}

// spec/crypto.md §4 (Left out: a record with a cause not held counts; Held keyset), hostile
// writer H of A removed: M {m0}, A {a0, H writer, M reader}, G {g0, A reader}. H rotates A
// recording M's current keyset with a commit nobody holds, then a0 removes H from A; M's only
// rotator m0 is away for good. Each rotation of A copies the record while M is left out, so a
// keyset of A waiting for its causes would arrive nowhere, a0 included, and A would rotate again
// at every pass. A's keysets arrive wherever their bodies do: A and G settle, G boxes A at A's
// current keyset, and M stays out of A only at the recorded keyset until M re-keys (the stated
// cost of a false record).
#[test]
fn a_removed_writers_unheld_cause_keeps_no_keyset_from_arriving_spec_crypto_4() {
    let mut lp = synced(4);
    let [_, h, _, _] = std::array::from_fn(|i| lp.peers[i].engine.tid());
    let m = independent_thing(&mut lp, 3);
    let a = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&a, &h, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let g = independent_thing(&mut lp, 2);
    lp.peers[2].engine.grant(&g, &a, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let k = newest_read(&lp, 3, m).unwrap();
    rotate_recording(&mut lp, 1, a, m, k, &[CommitId([3; 32])]);
    for (x, y) in [(1, 0), (1, 2)] {
        lp.sync(x, y).unwrap();
    }
    removal(&mut lp, 0, a, h);
    let mut last = 0;
    for _ in 0..6 {
        last = 0;
        for p in [0, 2] {
            for x in [a, g] {
                last += lp.peers[p].engine.ensure_rotated(&x).unwrap().0.commits.len();
                last += lp.peers[p].engine.reseal_after_pass(&x).unwrap().commits.len();
            }
            for (x, y) in [(0, 2), (2, 0), (0, 1), (2, 1)] {
                lp.sync(x, y).unwrap();
            }
        }
    }
    assert_eq!(last, 0, "A and G settle with m0 away");
    let e = newest_read(&lp, 0, a).unwrap();
    for i in [0, 2] {
        assert!(lp.peers[i].engine.core.keyset(&a, Role::Read, &e).is_some(), "peer {i}: A's current keyset arrived");
    }
    assert_eq!(recorded(&lp, 0, a, m).into_keys().collect::<Vec<_>>(), vec![k], "M left out of A at k alone");
    assert_eq!(sealed_at(&mut lp, 2, g, a), Some(e), "G seals A at its current keyset");
    assert!(all_boxed(&mut lp, 2, &[g]), "every holder of G boxed");
}

/// Peer `i` rotates `a`'s read boxing `z` too, a party holding no role on `a`: what a hostile
/// writer of `a` may write. The rotation's commit.
fn rotate_boxing(lp: &mut LocalPeer, i: usize, a: Tid, z: Tid) -> CommitId {
    let before = commit_ids(lp, i);
    lp.peers[i]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&a).unwrap();
            let mut boxing = super::recipients(tx, &tx.core.tid(), &a, &[])?;
            boxing.holders.push(crate::flows::recipient(tx, z, Role::Read)?);
            let mut mu = Mutation::new();
            let r = super::rotation_into(tx, &mut mu, a, &BTreeSet::from([Role::Read]), &held, &boxing, crate::rotation::Departs::No)?;
            crate::engine::Engine::commit_tx(tx, mu)?;
            super::record(tx, a, &r)
        })
        .unwrap();
    *commit_ids(lp, i).difference(&before).next().unwrap()
}

// spec/crypto.md §4 (Left out: a box departure's cause is the rotation of the epoch it holds;
// Departure), model `LO_nofact` (no record: churn): M {m0, Q admin, W reader}, G {g0, W admin,
// M reader}; g0 reads no secret of M. Q rotates M boxing Z, who holds no role on M: a box
// departure no edge shows. W, reading M's boxes, leaves M out of G recording k1 with Q's
// rotation; g0, judging k1 by order, finds the record standing and seals M at k1 nowhere (else W
// would rotate G again for each such re-seal). m0's knowing re-key ends it; Z opens nothing.
#[test]
fn a_box_departure_is_recorded_with_its_epochs_rotation_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let mut lp = synced(5);
    let [_, _, q, w, z] = std::array::from_fn(|i| lp.peers[i].engine.tid());
    let m = independent_thing(&mut lp, 1);
    lp.peers[1].engine.grant(&m, &q, &edge(Role::Admin)).unwrap();
    lp.peers[1].engine.grant(&m, &w, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &w, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &m, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let start = held_by(&lp, 4, &[m, g]);
    let q_rot = rotate_boxing(&mut lp, 2, m, z);
    lp.sync_all().unwrap();
    let k1 = newest_read(&lp, 3, m).unwrap();
    rotate_skipping(&mut lp, 3, g, &read, &[]);
    assert_eq!(sealed_at(&mut lp, 3, g, m), None, "W leaves M out");
    let rec = recorded(&lp, 3, g, m);
    assert!(rec.get(&k1).is_some_and(|c| c.contains(&q_rot)), "W records k1 with Q's rotation: {rec:?}");
    lp.sync_all().unwrap();
    lp.peers[0].engine.reseal_after_pass(&g).unwrap();
    assert_eq!(boxing_at(&mut lp, 0, g, m, k1), Vec::<Epoch>::new(), "g0 seals M at k1 nowhere");
    lp.sync_all().unwrap();
    assert!(lp.peers[3].engine.ensure_rotated(&g).unwrap().0.commits.is_empty(), "W owes G nothing more");
    settle(&mut lp, &[0, 1, 3], &[m, g]);
    assert_ne!(newest_read(&lp, 1, m), Some(k1), "m0 re-keyed M");
    assert!(all_boxed(&mut lp, 0, &[g]));
    assert_eq!(leaked(&mut lp, 0, &[m, g], z, start), Vec::<Tid>::new(), "Z opens nothing");
}

// spec/crypto.md §4 (Left out: a box or rotator departure's cause; Departure): M {m0, P admin}.
// P rotates M (kP). A departure of P no edge into M shows (a rotator departure: its role ran
// through a holder actor it has left) has kP's rotation as its cause, the epoch P holds the
// secret of; where P's own edge shows it leaving, that edge's newest needed write instead (a
// regrant ends it, and the record with it).
#[test]
fn a_rotator_departures_cause_is_its_rotation_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let mut lp = synced(2);
    let p = lp.peers[1].engine.tid();
    let m = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&m, &p, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let before = commit_ids(&mut lp, 1);
    rotate_skipping(&mut lp, 1, m, &read, &[]);
    let p_rot = *commit_ids(&mut lp, 1).difference(&before).next().unwrap();
    lp.sync_all().unwrap();
    let departure = osis_keys::Departure::holder(p, Role::Read).upto(Role::Read);
    let got = lp.peers[0].engine.run(|tx| super::departures::departure_causes(tx, &m, Role::Read, &departure, &[])).unwrap();
    assert_eq!(got, BTreeSet::from([p_rot]), "the rotator departure's cause is P's rotation");
    let before = commit_ids(&mut lp, 0);
    removal_alone(&mut lp, 0, m, p);
    let rm: BTreeSet<CommitId> = commit_ids(&mut lp, 0).difference(&before).copied().collect();
    let deps = lp.peers[0].engine.departures(&m).unwrap();
    assert!(deps.iter().any(|d| d.holder == p && d.edge.is_some()), "P's edge shows it leaving");
    let got = lp.peers[0].engine.run(|tx| super::departures::departure_causes(tx, &m, Role::Read, &departure, &deps)).unwrap();
    assert!(!got.is_empty() && got.is_subset(&rm), "with an edge showing it, the edge's write: {got:?}");
}

// spec/crypto.md §4 (Left out: a box naming a keyset held invalid has that keyset's rotations
// as causes; Stale): G {g0, W admin, M}, M {m0, N}, N {n0, P admin}. P rotates N (kn) while n0
// demotes P concurrently; m0, holding P's rotation and not the demotion, rotates M boxing N at
// kn. Once the demotion is held kn is held invalid, so M's box to N is stale: W leaves M out of G
// recording M's keyset with P's rotation, and G ends boxing M once m0 re-keys.
#[test]
fn a_box_naming_an_invalid_keyset_is_recorded_with_its_rotation_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let mut lp = synced(5);
    let [_, p, _, _, w] = std::array::from_fn(|i| lp.peers[i].engine.tid());
    let n = independent_thing(&mut lp, 3);
    lp.peers[3].engine.grant(&n, &p, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let m = independent_thing(&mut lp, 2);
    lp.peers[2].engine.grant(&m, &n, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let g = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &m, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&g, &w, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let before = commit_ids(&mut lp, 1);
    rotate_skipping(&mut lp, 1, n, &read, &[]);
    let p_rot = *commit_ids(&mut lp, 1).difference(&before).next().unwrap();
    let kn = newest_read(&lp, 1, n).unwrap();
    lp.peers[3].engine.demote(&n, &Demotion { holder: p, new: Some(edge(Role::Read)), retain: None }).unwrap();
    lp.sync(1, 2).unwrap();
    rotate_skipping(&mut lp, 2, m, &read, &[]);
    assert_eq!(sealed_at(&mut lp, 2, m, n), Some(kn), "m0 boxes N at P's keyset");
    let km = newest_read(&lp, 2, m).unwrap();
    lp.sync_all().unwrap();
    rotate_skipping(&mut lp, 4, g, &read, &[]);
    assert_eq!(sealed_at(&mut lp, 4, g, m), None, "W leaves M out");
    let rec = recorded(&lp, 4, g, m);
    assert!(rec.get(&km).is_some_and(|c| c.contains(&p_rot)), "W records M's keyset with P's rotation: {rec:?}");
    lp.sync_all().unwrap();
    settle(&mut lp, &[0, 2, 3, 4], &[n, m, g]);
    assert!(all_boxed(&mut lp, 0, &[g]));
}

// spec/crypto.md §4 (Left out: a rotator departure's cause is its epoch's rotation; Departure),
// model `LO_nofact` (no record: churn): M {m0, N write, W reader}, N {n0, P write}, G {g0, W
// admin, M reader}. P rotates M through N (kP); n0 removes P from N. W, reading M but not N, finds
// P's departure from M by kP's rotator alone (no edge into M shows it), leaves M out of G and
// records kP with P's rotation among its causes (beside N's rotation, which makes kP's box to N
// stale). g0, reading no secret of M, seals M at kP nowhere; m0's re-key ends it and P opens
// nothing written after. (A removal alone, with an empty frontier, would cut P's rotation.)
#[test]
fn a_rotator_departure_alone_is_recorded_with_its_rotation_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let mut lp = synced(5);
    let [_, p, _, w, _] = std::array::from_fn(|i| lp.peers[i].engine.tid());
    let n = independent_thing(&mut lp, 2);
    lp.grant_through(2, n, p, &edge(Role::Write));
    lp.sync_all().unwrap();
    let m = independent_thing(&mut lp, 0);
    lp.grant_through(0, m, n, &edge(Role::Write));
    lp.grant_through(0, m, w, &edge(Role::Read));
    lp.sync_all().unwrap();
    let g = independent_thing(&mut lp, 4);
    lp.grant_through(4, g, w, &edge(Role::Admin));
    lp.grant_through(4, g, m, &edge(Role::Read));
    lp.sync_all().unwrap();
    assert!(boxes(&mut lp, 0, m, n), "M's grant to N is keyed");
    lp.peers[1].clock.advance(1_000);
    let before = commit_ids(&mut lp, 1);
    rotate_skipping(&mut lp, 1, m, &read, &[]);
    let p_rot = *commit_ids(&mut lp, 1).difference(&before).next().unwrap();
    let kp = newest_read(&lp, 1, m).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(newest_read(&lp, 3, m), Some(kp), "W holds P's keyset of M");
    let start = held_by(&lp, 1, &[m, g]);
    removal(&mut lp, 2, n, p);
    lp.sync_all().unwrap();
    let deps = lp.peers[3].engine.departures(&m).unwrap();
    assert!(deps.iter().any(|d| d.holder == p && d.edge.is_none()), "W sees P's rotator departure: {deps:?}");
    rotate_skipping(&mut lp, 3, g, &read, &[]);
    assert_eq!(sealed_at(&mut lp, 3, g, m), None, "W leaves M out");
    let rec = recorded(&lp, 3, g, m);
    assert!(rec.get(&kp).is_some_and(|c| c.contains(&p_rot)), "W records kP with P's rotation: {rec:?}");
    lp.sync_all().unwrap();
    lp.peers[4].engine.reseal_after_pass(&g).unwrap();
    assert_eq!(boxing_at(&mut lp, 4, g, m, kp), Vec::<Epoch>::new(), "g0 seals M at kP nowhere");
    lp.sync_all().unwrap();
    assert!(lp.peers[3].engine.ensure_rotated(&g).unwrap().0.commits.is_empty(), "W owes G nothing more");
    settle(&mut lp, &[0, 2, 3, 4], &[n, m, g]);
    assert_ne!(newest_read(&lp, 0, m), Some(kp), "M re-keyed off kP");
    assert!(all_boxed(&mut lp, 0, &[g]));
    assert_eq!(leaked(&mut lp, 0, &[m, g], p, start), Vec::<Tid>::new(), "P opens nothing new");
}

// spec/crypto.md §4 (Left out: a rotation cause stands while held, a false record costs a re-key), model
// `LO_hostile` (`HostileEnds`): A {a0, H writer, M}, M {a0}. H records M's current keyset with
// A's own rotation as its cause, which stands everywhere for good. a0 then removes H: its
// removal's rotation of A still leaves M out, copying the record, and one re-key of M ends it;
// no later pass rotates M again.
#[test]
fn a_hostile_record_on_a_rotation_ends_with_its_writers_removal_spec_crypto_4() {
    let mut lp = synced(2);
    let h = lp.peers[1].engine.tid();
    let m = independent_thing(&mut lp, 0);
    let a = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&a, &h, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let ea = newest_read(&lp, 0, a).unwrap();
    let cause = lp.peers[0].engine.core.ix.epoch_intro.get(&(a, Role::Read, ea)).unwrap().1;
    let k = newest_read(&lp, 0, m).unwrap();
    rotate_recording(&mut lp, 1, a, m, k, &[cause]);
    lp.sync_all().unwrap();
    assert_eq!(sealed_at(&mut lp, 0, a, m), None, "M left out");
    removal(&mut lp, 0, a, h);
    assert_eq!(sealed_at(&mut lp, 0, a, m), None, "the removal's rotation leaves M out too");
    assert!(recorded(&lp, 0, a, m).get(&k).is_some_and(|c| c.contains(&cause)), "and copies the record");
    lp.sync_all().unwrap();
    settle(&mut lp, &[0], &[m, a]);
    assert_eq!(newest_read(&lp, 0, m).unwrap().n(), k.n() + 1, "one re-key of M");
    assert_eq!(sealed_at(&mut lp, 0, a, m), newest_read(&lp, 0, m), "A re-seals M at it");
    assert_eq!(settle(&mut lp, &[0], &[m, a]), 0, "nothing more");
    assert_eq!(recorded(&lp, 0, a, m).keys().copied().collect::<Vec<_>>(), vec![k], "until A's next rotation, only the superseded keyset stays recorded");
    assert!(all_boxed(&mut lp, 0, &[m, a]));
}
