//! Holder actors (spec/crypto.md §4, Holder actors; spec/permissions.md §3): sealing at an
//! anchored keyset (rule 1), stale boxes (rule 2), merge (rule 3), no key cycles (rule 4) and
//! tainted keysets (4b). The leak oracle is `openable`: what a departed party opens from its old
//! secrets and every box held, whatever its own node does. Shapes from the depth-0 model
//! (core/test/tla/rotation/Depth0.tla).

#![allow(clippy::unwrap_used)]
use super::tests::{Pass, all_boxed, blocked_at, commit_ids, deliver_without_secrets, edge, group, held_by, leaked, newest_read, openable, rotate_leaving_out, rotate_unchecked, send_skipping, settle, synced};
use crate::Mutation;
use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use osis_base::{Role, Tid, WallMs};
use osis_crypto::Epoch;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

type Opened = BTreeSet<(Tid, Role, Epoch)>;

/// Whether `a`'s `secrets.0` at peer `i` boxes `h` at all.
fn boxes(lp: &mut LocalPeer, i: usize, a: Tid, h: Tid) -> bool {
    lp.peers[i].engine.get_typed(&a, &ct::SECRETS).unwrap().is_some_and(|s| s.boxes.keys().any(|k| k.holder == h))
}

/// The keyset of `m` the box of `a`'s newest read epoch to `m` names, at peer `i`.
fn sealed_at(lp: &mut LocalPeer, i: usize, a: Tid, m: Tid) -> Option<Epoch> {
    let e = newest_read(lp, i, a)?;
    let s = lp.peers[i].engine.get_typed(&a, &ct::SECRETS).unwrap()?;
    s.boxes.iter().find(|(k, _)| k.holder == m && k.role == Role::Read && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|x| x == e)).and_then(|(_, b)| osis_keys::box_epoch(b))
}

/// Peer `i` rotates `rot` of `g` leaving out the holders `skip` (a rotation that, by rule 1 or
/// by design, boxes them nothing).
fn rotate_skipping(lp: &mut LocalPeer, i: usize, g: Tid, rot: &BTreeSet<Role>, skip: &[Tid]) {
    let skip: Vec<(Tid, Option<Role>)> = skip.iter().map(|t| (*t, None)).collect();
    lp.peers[i]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&g).unwrap();
            let holders = super::recipients(tx, &tx.core.writer().unwrap(), &g, &skip)?.ok_or(super::SEAL_WAITS)?;
            let mut m = Mutation::new();
            let r = super::rotation_into(tx, &mut m, g, rot, &held, &holders, false)?;
            crate::engine::Engine::commit_tx(tx, m)?;
            super::record(tx, g, &r)
        })
        .unwrap();
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

// spec/crypto.md §4 (holder actors: stale), spec/permissions.md §3 (required rotation through
// A's keyset): a node removed 12 actors below G0 (G11 in G10 ... in G0). No departure is G0's,
// but each level's box to the one below is stale once that one rotates, so the cascade rotates
// every level, bottom-up, and the removed node holds none of it.
#[test]
fn removal_twelve_deep_rotates_every_level_spec_crypto_4() {
    let mut lp = synced(2);
    let d = lp.peers[1].engine.me();
    let gs: Vec<Tid> = (0..12).map(|_| group(&mut lp, 0)).collect();
    for w in gs.windows(2) {
        lp.peers[0].engine.grant(&w[0], &w[1], &edge(Role::Write)).unwrap();
    }
    lp.peers[0].engine.grant(&gs[11], &d, &edge(Role::Write)).unwrap();
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
    let d = lp.peers[1].engine.me();
    let [a, x, y, z] = [0; 4].map(|_| group(&mut lp, 0));
    for (t, m) in [(a, x), (a, y), (x, z), (y, z)] {
        lp.peers[0].engine.grant(&t, &m, &edge(Role::Write)).unwrap();
    }
    lp.peers[0].engine.grant(&z, &d, &edge(Role::Read)).unwrap();
    removal(&mut lp, 0, z, d);
    let (done, still) = lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(done.commits.len(), 3, "X, Y, then A");
    assert!(lp.peers[0].engine.ensure_rotated(&a).unwrap().0.commits.is_empty());
    let top = group(&mut lp, 0);
    let mut layer = vec![top];
    for _ in 0..9 {
        let next: Vec<Tid> = (0..4).map(|_| group(&mut lp, 0)).collect();
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
    let (d, n) = (lp.peers[1].engine.me(), lp.peers[2].engine.me());
    let cyc: Vec<Tid> = (0..len).map(|_| group(lp, 0)).collect();
    for i in 0..len {
        lp.peers[0].clock.advance(1);
        lp.peers[0].engine.grant(&cyc[i], &cyc[(i + 1) % len], &edge(Role::Read)).unwrap();
    }
    for x in [d, n] {
        lp.peers[0].engine.grant(&cyc[len - 1], &x, &edge(Role::Read)).unwrap();
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
        let d = lp.peers[1].engine.me();
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
    let d = lp.peers[1].engine.me();
    let [b, p, q] = [0; 3].map(|_| group(&mut lp, 0));
    for (t, m) in [(b, p), (p, q), (q, p)] {
        lp.peers[0].clock.advance(1);
        lp.peers[0].engine.grant(&t, &m, &edge(Role::Write)).unwrap();
    }
    lp.peers[0].engine.grant(&q, &d, &edge(Role::Read)).unwrap();
    removal(&mut lp, 0, q, d);
    let (done, still) = lp.peers[0].engine.ensure_rotated(&b).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(done.commits.len(), 2, "P, then B");
    assert!(lp.peers[0].engine.reseal_due(&q, &Pass).unwrap().commits.is_empty(), "P has no key access to Q");
    assert!(!boxes(&mut lp, 0, q, p));
    assert!(lp.peers[0].engine.ensure_rotated(&b).unwrap().0.commits.is_empty(), "no churn around the cycle");
    assert_eq!(settle(&mut lp, &[0], &[b, p, q]), 0);
}

// spec/crypto.md §4 (key access; model `D0_fa_flip`), spec/permissions.md §1: T's first admin is
// X, so T's grant on X closes a cycle through the record edge and is keyless (X boxes T nothing).
// Another admin of T removes X's record edge: T's grant is the only link left, it gains key
// access, and X's admin re-seals T; nothing leaks to X's side meanwhile and nobody is locked out.
#[test]
fn grant_on_first_admin_keyless_until_record_edge_goes_spec_crypto_4() {
    let mut lp = synced(2);
    let d = lp.peers[1].engine.me();
    let x = group(&mut lp, 0);
    let t = {
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, x);
        lp.peers[0].commit(m).unwrap();
        t
    };
    lp.peers[0].clock.advance(1);
    lp.peers[0].engine.grant(&x, &t, &edge(Role::Read)).unwrap();
    assert!(!boxes(&mut lp, 0, x, t), "T's grant on X is keyless: X's key yields T's by the record edge");
    lp.peers[0].clock.advance(1);
    lp.peers[0].engine.grant(&t, &d, &edge(Role::Admin)).unwrap();
    lp.sync(0, 1).unwrap();
    assert!(lp.peers[1].engine.reseal_due(&x, &Pass).unwrap().commits.is_empty(), "nothing to re-seal while the record edge stands");
    lp.peers[1].clock.advance(1);
    removal(&mut lp, 1, t, x);
    lp.sync(1, 0).unwrap();
    assert!(!lp.peers[0].engine.roster(&t).contains_key(&x), "X's record edge is gone");
    let done = lp.peers[0].engine.reseal_due(&x, &Pass).unwrap();
    assert!(!done.commits.is_empty(), "X re-seals T: its grant has key access now");
    assert!(boxes(&mut lp, 0, x, t));
    lp.sync(0, 1).unwrap();
    // one round: X's admin adds T's derived epoch (established at it alone) to T's history
    assert!(settle(&mut lp, &[0, 1], &[x, t]) <= 1, "settled");
    assert!(all_boxed(&mut lp, 0, &[x, t]));
}

// spec/crypto.md §4, spec/permissions.md §3 (model `D0_nc_below`): X and Y readers of each
// other (X granted on Y first, Y's grant on X keyless), Z a reader of X, D a reader of Z: D reads
// Z, X and Y. D's removal from Z makes X's box to Z stale, then Y's to X: the cascade rotates
// each once (Y in the same step as X, `rotate_above`), nothing is re-sealed, and D opens no epoch
// a writer encrypts under.
#[test]
fn departure_below_cycle_spec_crypto_4() {
    let mut lp = synced(2);
    let d = lp.peers[1].engine.me();
    let [x, y, z] = [0; 3].map(|_| group(&mut lp, 0));
    for (t, m) in [(y, x), (x, y), (x, z)] {
        lp.peers[0].clock.advance(1);
        lp.peers[0].engine.grant(&t, &m, &edge(Role::Read)).unwrap();
    }
    lp.peers[0].engine.grant(&z, &d, &edge(Role::Read)).unwrap();
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

// spec/permissions.md §3 (Role cycles; each admin acts alone): X (peer 0's) and Y (peer 2's)
// readers of each other, no common admin, Y granted on X first (X on Y keyless); D a reader of
// Y reads both. Peer 2 removes D: Y rotates. Peer 0, once it holds that, finds X's box to Y stale
// and rotates X. D opens neither, at either peer; the cycle settles.
#[test]
fn cycle_with_disjoint_admins_converges_spec_permissions_3() {
    let mut lp = synced(3);
    let d = lp.peers[1].engine.me();
    let x = group(&mut lp, 0);
    let y = group(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&x, &y, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[2].clock.advance(1_000);
    lp.peers[2].engine.grant(&y, &x, &edge(Role::Read)).unwrap();
    lp.peers[2].engine.grant(&y, &d, &edge(Role::Read)).unwrap();
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

// spec/crypto.md §4, spec/permissions.md §3 (model `D0_nc2`): X (peer 0's) and Y (peer 2's)
// readers of each other, Y first; D leaves X and E leaves Y concurrently, each by its actor's
// admin, neither knowing the other. Once each holds both, the cycle settles: no lockout (every
// holder with key access boxed, N of X and M of Y read what they hold roles on) and neither D
// nor E opens a newest epoch.
#[test]
fn cycle_concurrent_departures_spec_crypto_4() {
    let mut lp = synced(5);
    let [d, e, n] = [1, 3, 4].map(|i| lp.peers[i].engine.me());
    let m = n;
    let x = group(&mut lp, 0);
    let y = group(&mut lp, 2);
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
        let (d, m2, a2) = (lp.peers[1].engine.me(), lp.peers[2].engine.me(), lp.peers[4].engine.me());
        let m = group(&mut lp, 0);
        let a = group(&mut lp, 3);
        lp.peers[0].engine.grant(&m, &m2, &edge(Role::Admin)).unwrap();
        lp.peers[0].engine.grant(&m, &d, &edge(Role::Read)).unwrap();
        lp.peers[3].engine.grant(&a, &a2, &edge(Role::Admin)).unwrap();
        lp.sync_all().unwrap();
        lp.peers[3].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
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
        let [r, _, _, e, w] = std::array::from_fn(|i| lp.peers[i].engine.me());
        let m = group(&mut lp, 2);
        for h in [r, e] {
            lp.peers[2].engine.grant(&m, &h, &edge(Role::Read)).unwrap();
        }
        lp.sync_all().unwrap();
        let a = group(&mut lp, 1);
        lp.peers[1].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        let g = group(&mut lp, 0);
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
        let tids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.me()).collect();
        let m = group(&mut lp, 1);
        lp.peers[1].engine.grant(&m, &tids[2], &edge(d_role)).unwrap();
        lp.peers[1].engine.grant(&m, &tids[3], &edge(Role::Admin)).unwrap();
        let a = group(&mut lp, 0);
        lp.peers[0].engine.grant(&a, &tids[4], &edge(Role::Admin)).unwrap();
        lp.sync_all().unwrap();
        lp.peers[0].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        let start = held_by(&lp, 2, &[m, a]);
        let k0 = lp.peers[1].engine.epochs(&m).unwrap().read.newest_held().unwrap().0;
        let before = commit_ids(&mut lp, 1);
        removal(&mut lp, 1, m, tids[2]);
        let c_m: BTreeSet<_> = commit_ids(&mut lp, 1).difference(&before).copied().collect();
        let kk = lp.peers[1].engine.epochs(&m).unwrap().read.newest_held().unwrap().0;
        (lp, (a, m, c_m, k0, kk, start))
    });
    (lp, a, m, c_m, k0, kk, start)
}

// spec/crypto.md §4 (Seal: anchored, rule 1; merge, rule 3; model `D0_member_anchor`): A seals
// M at m1's knowing keyset kk. Z, not knowing D left, forks M twice from before (F2, newest by
// n, not descending from kk); A holds F2 valid and newer, yet its next rotation seals M at kk,
// never at F2, so D opens no epoch of A made since its removal, not even by a history box. m1
// merges (F2 current and missing D's departure): A's box at kk is stale, A moves to the merge.
#[test]
fn ignorant_fork_anchored_until_merge_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let (mut lp, a, m, c_m, _, kk, start) = member_world(Role::Read);
    let d = lp.peers[2].engine.me();
    send_skipping(&mut lp, 1, 0, &BTreeSet::new());
    assert!(blocked_at(&mut lp, 0, a).contains(&Role::Read), "A's box to M at the old keyset is stale");
    lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert_eq!(sealed_at(&mut lp, 0, a, m), Some(kk), "A sealed M at kk");
    // Z forks M, twice, never having seen C_M
    lp.peers[3].clock.advance(60_000);
    rotate_leaving_out(&mut lp, 3, m, &read, &[]);
    rotate_leaving_out(&mut lp, 3, m, &read, &[]);
    let f2 = lp.peers[3].engine.epochs(&m).unwrap().read.newest_held().unwrap().0;
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
    let merged = lp.peers[1].engine.epochs(&m).unwrap().read.newest_held().unwrap().0;
    send_skipping(&mut lp, 1, 0, &BTreeSet::new());
    assert!(blocked_at(&mut lp, 0, a).contains(&Role::Read), "kk listed by the merge: stale");
    lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert_eq!(sealed_at(&mut lp, 0, a, m), Some(merged));
    assert_eq!(leaked(&mut lp, 0, &[m, a], d, start), Vec::<Tid>::new());
}

// spec/crypto.md §4 (merge, rule 3; model `D0_member_anchor`): m1 removes D (kk1) and rotates M
// again (kk2, n 3). Z, not knowing, forks M from before (F, n 2): it loses the (n, nonce) order
// to kk2 at m1, so only merge supersedes it. A gets F first and seals M there (D opens it: the
// stated limit, a keyset written without knowing the removal). m1, holding F, rotates while F
// is current and misses D's departure; A's box at F is then stale and A moves: D opens nothing
// new. Without merge F stays current, A anchored on it never moves.
#[test]
fn merge_moves_off_losing_ignorant_fork_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let (mut lp, a, m, c_m, _, _, start) = member_world(Role::Read);
    let d = lp.peers[2].engine.me();
    let before = commit_ids(&mut lp, 1);
    rotate_leaving_out(&mut lp, 1, m, &read, &[]);
    let later: BTreeSet<_> = commit_ids(&mut lp, 1).difference(&before).copied().collect();
    let kk2 = lp.peers[1].engine.epochs(&m).unwrap().read.newest_held().unwrap().0;
    lp.peers[3].clock.advance(60_000);
    rotate_leaving_out(&mut lp, 3, m, &read, &[]);
    let f = lp.peers[3].engine.epochs(&m).unwrap().read.newest_held().unwrap().0;
    assert!(f.n() < kk2.n(), "F loses the order");
    send_skipping(&mut lp, 3, 0, &c_m.union(&later).copied().collect());
    lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert_eq!(sealed_at(&mut lp, 0, a, m), Some(f), "A sealed M at the ignorant fork");
    send_skipping(&mut lp, 3, 1, &BTreeSet::new());
    let (done, _) = lp.peers[1].engine.ensure_rotated(&m).unwrap();
    assert_eq!(done.commits.len(), 1, "m1 merges F, current beside its newer kk2");
    let merged = lp.peers[1].engine.epochs(&m).unwrap().read.newest_held().unwrap().0;
    send_skipping(&mut lp, 1, 0, &BTreeSet::new());
    lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert_eq!(sealed_at(&mut lp, 0, a, m), Some(merged), "A moved off F");
    assert_eq!(leaked(&mut lp, 0, &[m, a], d, start), Vec::<Tid>::new());
}

// spec/crypto.md §4 (Seal: wait while the anchors fork; merge, rule 3; model `D0_fork_wait`): M (admins m1 = peer 0, m2 = peer 2, reader D) holds
// read on A (admins a1 = peer 3, a2 = peer 4). m1 and m2 each rotate M (keysets k1, k2), a1 and a2
// each rotate A onto the one they hold, so A's two current epochs anchor M at k1 and k2. m1
// removes D (its keyset lists k1 only) and, once it holds k2, merges. a1's merge of A waits
// until a keyset of M descends from both anchors, then seals M at m1's merge. Leaving M out
// instead dropped the anchors: a2, holding neither the removal nor the merge, re-sealed M at a1's
// epoch at k1 or k2, both open to D, after a1 had written under it holding the merge.
#[test]
fn forked_anchors_wait_for_merge_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let none = BTreeSet::new();
    let (mut lp, m, a) = two_admin_holder();
    let d = lp.peers[1].engine.me();
    let start = held_by(&lp, 1, &[m, a]);
    rotate_leaving_out(&mut lp, 0, m, &read, &[]);
    lp.peers[2].clock.advance(1_000);
    rotate_leaving_out(&mut lp, 2, m, &read, &[]);
    send_skipping(&mut lp, 0, 3, &none);
    send_skipping(&mut lp, 2, 4, &none);
    lp.peers[3].engine.ensure_rotated(&a).unwrap();
    lp.peers[4].engine.ensure_rotated(&a).unwrap();
    send_skipping(&mut lp, 4, 3, &none);
    assert_eq!(lp.peers[3].engine.epochs(&a).unwrap().read.current().len(), 2, "A forked over M's two keysets");
    // D was boxed at k1 and k2, and A's two epochs through them (the stated limit)
    let mut start = start;
    for i in [3, 4] {
        start = openable(&mut lp, i, &[m, a], d, start);
    }
    let before = commit_ids(&mut lp, 0);
    removal(&mut lp, 0, m, d);
    send_skipping(&mut lp, 0, 3, &none);
    let (done, _) = lp.peers[3].engine.ensure_rotated(&a).unwrap();
    assert!(done.commits.is_empty(), "a1's merge of A waits: no keyset of M descends from both anchors");
    assert_eq!(lp.peers[3].engine.epochs(&a).unwrap().read.current().len(), 2);
    // m1 merges k2; a1 merges A, sealing M at it, and writes under that epoch
    send_skipping(&mut lp, 2, 0, &none);
    let (done, _) = lp.peers[0].engine.ensure_rotated(&m).unwrap();
    assert_eq!(done.commits.len(), 1, "m1 merges the fork");
    let merged = lp.peers[0].engine.epochs(&m).unwrap().read.newest_held().unwrap().0;
    let knowing: BTreeSet<_> = commit_ids(&mut lp, 0).difference(&before).copied().collect();
    send_skipping(&mut lp, 0, 3, &none);
    let (_, still) = lp.peers[3].engine.ensure_rotated(&a).unwrap();
    assert!(still.is_empty());
    assert_eq!(sealed_at(&mut lp, 3, a, m), Some(merged));
    let w = newest_read(&lp, 3, a).unwrap();
    // a2, holding neither the removal nor the merge, finds M boxed: nothing to re-seal
    send_skipping(&mut lp, 3, 4, &knowing);
    lp.peers[4].engine.reseal_due(&a, &Pass).unwrap();
    send_skipping(&mut lp, 4, 3, &none);
    assert!(!openable(&mut lp, 3, &[m, a], d, start.clone()).contains(&(a, Role::Read, w)), "D opens none of what a1 wrote");
    lp.sync_all().unwrap();
    settle(&mut lp, &[0, 2, 3, 4], &[m, a]);
    assert_eq!(leaked(&mut lp, 3, &[m, a], d, start), Vec::<Tid>::new());
}

// spec/permissions.md §3 (a removal goes alone while Seal waits), spec/crypto.md §4 (Seal; model
// `D0_fork_rm`): as `forked_anchors_wait_for_merge_spec_crypto_4`, A's two current epochs anchor
// M at its two keysets k1 and k2. a1 removes a2 from A: no rotation of A can seal M yet, so the
// removal goes alone. a2 holds no role at once; A's rotation stays due and a1 encrypts nothing
// under A until M's merge lets it rotate, which covers a2's departure: a2 opens nothing new.
// (Before: the removal itself waited for M's merger, so a writer of M withholding its merge kept
// a2's role on A.)
#[test]
fn removal_goes_alone_while_seal_waits_spec_permissions_3() {
    let read = BTreeSet::from([Role::Read]);
    let none = BTreeSet::new();
    let (mut lp, m, a) = two_admin_holder();
    let a2 = lp.peers[4].engine.me();
    rotate_leaving_out(&mut lp, 0, m, &read, &[]);
    lp.peers[2].clock.advance(1_000);
    rotate_leaving_out(&mut lp, 2, m, &read, &[]);
    send_skipping(&mut lp, 0, 3, &none);
    send_skipping(&mut lp, 2, 4, &none);
    lp.peers[3].engine.ensure_rotated(&a).unwrap();
    lp.peers[4].engine.ensure_rotated(&a).unwrap();
    send_skipping(&mut lp, 4, 3, &none);
    send_skipping(&mut lp, 2, 3, &none);
    assert_eq!(lp.peers[3].engine.epochs(&a).unwrap().read.current().len(), 2, "A forked over M's two keysets");
    let start = held_by(&lp, 4, &[m, a]);
    let before = lp.peers[3].engine.epochs(&a).unwrap().read.current();
    // a1 removes a2: written at once, without a rotation
    assert_eq!(removal(&mut lp, 3, a, a2).len(), 1, "the removal is written");
    assert!(!lp.peers[3].engine.core.key_holders(&a).iter().any(|h| h.0 == a2), "a2 holds no role on A");
    assert_eq!(lp.peers[3].engine.epochs(&a).unwrap().read.current(), before, "no rotation of A");
    let (done, still) = lp.peers[3].engine.ensure_rotated(&a).unwrap();
    assert!(done.commits.is_empty() && still.contains(&Role::Read), "A's rotation due waits; a1 encrypts nothing under A");
    // M merges; a1 rotates A, covering a2's departure
    lp.sync_all().unwrap();
    let mut merged = 0;
    for i in [0, 2] {
        merged += lp.peers[i].engine.ensure_rotated(&m).unwrap().0.commits.len();
        lp.sync_all().unwrap();
    }
    assert_eq!(merged, 1, "M's merger merges");
    let (done, still) = lp.peers[3].engine.ensure_rotated(&a).unwrap();
    assert!(!done.commits.is_empty() && still.is_empty(), "A rotates once M merged");
    let w = newest_read(&lp, 3, a).unwrap();
    assert!(!openable(&mut lp, 3, &[m, a], a2, start).contains(&(a, Role::Read, w)), "a2 opens nothing of A's new epoch");
}

// spec/crypto.md §4 (Encrypting under: an epoch boxing a holder actor at a keyset the node may
// not encrypt under; Seal: such a holder is left out), spec/permissions.md §3 (a removal goes
// alone; model `D0_above`): as `removal_goes_alone_while_seal_waits_spec_permissions_3`, with A
// holding read on G (a1's). a1 removes a2 from A alone: A's epochs cover no departure of a2 yet,
// so G's epoch, boxing A at one, is blocked at a1 as well, and G's rotation leaves A out; a2 opens
// nothing a1 writes under G. Once M merges and A rotates, A is re-sealed to G: no lockout. (Before:
// a1 rotated G sealing A at its uncovered keyset, which a2 opens.)
#[test]
fn removal_alone_leaves_holder_out_above_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let none = BTreeSet::new();
    let mut lp = synced(5);
    let (d, m2, a2) = (lp.peers[1].engine.me(), lp.peers[2].engine.me(), lp.peers[4].engine.me());
    let m = group(&mut lp, 0);
    let a = group(&mut lp, 3);
    let g = group(&mut lp, 3);
    lp.peers[0].engine.grant(&m, &m2, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&m, &d, &edge(Role::Read)).unwrap();
    lp.peers[3].engine.grant(&a, &a2, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[3].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
    lp.peers[3].engine.grant(&g, &a, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, m, &read, &[]);
    lp.peers[2].clock.advance(1_000);
    rotate_leaving_out(&mut lp, 2, m, &read, &[]);
    send_skipping(&mut lp, 0, 3, &none);
    send_skipping(&mut lp, 2, 4, &none);
    lp.peers[3].engine.ensure_rotated(&a).unwrap();
    lp.peers[4].engine.ensure_rotated(&a).unwrap();
    send_skipping(&mut lp, 4, 3, &none);
    send_skipping(&mut lp, 2, 3, &none);
    assert_eq!(lp.peers[3].engine.epochs(&a).unwrap().read.current().len(), 2, "A forked over M's two keysets");
    // G's box to A's keyset before the fork is stale: G moves to a fork's
    lp.peers[3].engine.ensure_rotated(&g).unwrap();
    send_skipping(&mut lp, 3, 4, &none);
    assert!(blocked_at(&mut lp, 3, g).is_empty(), "G is written under before the removal");
    let start = held_by(&lp, 4, &[m, a, g]);
    assert_eq!(removal(&mut lp, 3, a, a2).len(), 1, "the removal is written alone");
    let (done, still) = lp.peers[3].engine.ensure_rotated(&a).unwrap();
    assert!(done.commits.is_empty() && still.contains(&Role::Read), "A's rotation waits");
    lp.sync_all().unwrap();
    assert!(blocked_at(&mut lp, 3, g).contains(&Role::Read), "G's epoch boxes A at a keyset a1 may not encrypt under");
    let (done, still) = lp.peers[3].engine.ensure_rotated(&g).unwrap();
    assert!(!done.commits.is_empty() && still.is_empty(), "a1 rotates G");
    assert_eq!(sealed_at(&mut lp, 3, g, a), None, "leaving A out");
    let w = newest_read(&lp, 3, g).unwrap();
    assert!(!openable(&mut lp, 3, &[m, a, g], a2, start.clone()).contains(&(g, Role::Read, w)), "a2 opens nothing a1 writes under G");
    assert!(lp.peers[3].engine.run(|tx| super::reseal_candidates(tx, &g)).unwrap().is_empty(), "nor re-seals A to G yet");
    // M merges; A rotates, covering a2's departure, and is re-sealed to G
    lp.sync_all().unwrap();
    settle(&mut lp, &[0, 2, 3], &[m, a, g]);
    assert!(all_boxed(&mut lp, 3, &[m, a, g]), "A boxed at G again");
    assert!(blocked_at(&mut lp, 3, g).is_empty(), "G is written under again");
    assert_eq!(leaked(&mut lp, 3, &[m, a, g], a2, start), Vec::<Tid>::new());
}

// spec/crypto.md §4 (Held keyset: valid; Descends; Stale: held invalid; model
// `D0_member_forge`): D, an admin of M, forges M's keyset X_d (listing kk) after its removal. R
// (peer 0) lacks the removal: X_d is valid there, descends from kk, and R seals A at it (D
// opens R's epoch: the stated limit). W (peer 4) holds the removal and X_d: X_d is invalid
// there, so R's box at it is stale and W rotates before encrypting, never sealing at X_d. Once
// the removal reaches R, X_d leaves R's held keysets and R rotates too.
#[test]
fn forged_keyset_invalid_where_removal_arrived_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let (mut lp, a, m, c_m, k0, kk, start) = member_world(Role::Admin);
    let d = lp.peers[2].engine.me();
    // R gets everything but the removal (which carries kk)
    send_skipping(&mut lp, 1, 0, &c_m);
    let s_d = osis_crypto::Secret32::from_bytes([79; 32]);
    let x_d = Epoch::derive(&m, Role::Read, kk.n() + 1, &s_d).unwrap();
    let forged = osis_keys::keyset(&x_d, &s_d, &BTreeSet::from([k0, kk]), &Default::default());
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

// spec/crypto.md §4 (Carried; model `Carry`: a node learning an epoch learns the keysets its
// boxes name with it): peer 0 seals A's holder M at m1's knowing keyset kk and places kk's
// commit under A's label with its rotation. W (peer 4, A's other admin) gets peer 0's commits
// but not kk's (a host withholding the carried commit): kk is no anchor there (not held), so W's
// next rotation of A seals M at k0, which D opens (the stated limit: W holds no knowing keyset
// of M). Peer 0 finds that box stale and moves A back to kk; once kk's commit reaches W, W
// seals at kk. D opens nothing a writer holding kk encrypts under.
#[test]
fn lacking_carried_keyset_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let (mut lp, a, m, c_m, k0, kk, start) = member_world(Role::Read);
    let d = lp.peers[2].engine.me();
    send_skipping(&mut lp, 1, 0, &BTreeSet::new());
    let (done, _) = lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert_eq!(sealed_at(&mut lp, 0, a, m), Some(kk));
    let carried = done.deliveries.iter().any(|x| matches!(x, crate::flows::Delivery::First { commits, under } if under == &vec![a] && commits.iter().any(|c| c_m.contains(c))));
    assert!(carried, "kk's commit placed under A's label with the rotation: {:?}", done.deliveries);
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
// on T by a node that may not rotate M (T's admin reading M, or an invite holder on T): one that
// has not learned the departure seals M at its keyset D holds, so D reads T until M's knowing
// keyset reaches T's writers, then not (rule 2); one that knows it may not encrypt under that
// keyset, so its grant waits for M's rotation. M's admin, granting, rotates M first (sealing to it
// is encrypting under its epoch): D never reads T.
#[test]
fn grant_to_unrotated_holder_stated_limit_spec_permissions_3() {
    // granter: 0 T's admin reading M, 2 M's admin and T's first admin, 0 by invite on T whose first admin is 3; whether
    // the granter has learned D's departure
    for (g, first, knows) in [(0, 0, false), (0, 0, true), (2, 2, true), (0, 3, false), (0, 3, true)] {
        let (mut lp, (m, t)) = LocalPeer::cached(&format!("rotation::tests_members::grant_to_unrotated/{first}/{}", first != g), || {
            let mut lp = synced(4);
            let d = lp.peers[1].engine.me();
            let p0 = lp.peers[0].engine.me();
            let m = group(&mut lp, 2);
            lp.peers[2].engine.grant(&m, &d, &edge(Role::Read)).unwrap();
            lp.peers[2].engine.grant(&m, &p0, &edge(Role::Read)).unwrap();
            let t = group(&mut lp, first);
            if first != g {
                lp.peers[first].engine.grant(&t, &p0, &ct::Edge { invite: Some(Role::Write), ..edge(Role::Write) }).unwrap();
            }
            lp.sync_all().unwrap();
            (lp, (m, t))
        });
        let d = lp.peers[1].engine.me();
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

// spec/crypto.md §4 (key access judged over the grants held; Tainted, 4b; the knowing re-key;
// model `D0_nc_hide_taint_lean`): Y holds X (granted first, by peer 0), X holds Y (later, by
// peer 2, Y's admin, which lacks the earlier grant): peer 2 takes its grant as keyed and boxes Y
// to X, a key cycle. Peer 0 holds both: Y's keyset boxes X, which has no key access to Y, so it
// is tainted: peer 0 never seals X to it and its box at it is stale. D, removed from X by peer 0,
// opens none of X's new epochs, though it opens Y's tainted one through X's old keyset. Once the
// grant reaches peer 2, it re-keys Y without X, and X is re-sealed to Y: no lockout.
#[test]
fn hidden_grant_tainted_keyset_spec_crypto_4() {
    let mut lp = synced(3);
    let d = lp.peers[1].engine.me();
    let x = group(&mut lp, 0);
    let y = group(&mut lp, 2);
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

// spec/crypto.md §4 (key access judged over the grants held; the knowing re-key, rule 4): Y
// holds X (granted first, by peer 0), X holds Y (later, by peer 2, which lacks the earlier
// grant): peer 2 boxes Y to X, a key cycle, with nothing departed and no keyset stale. Once the
// earlier grant reaches peer 2, its grant is keyless there and peer 2 re-keys Y without X.
#[test]
fn knowing_rekey_after_hidden_grant_spec_crypto_4() {
    let mut lp = synced(3);
    let x = group(&mut lp, 0);
    let y = group(&mut lp, 2);
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
// anyway: peer 0 counts no departure from the box and rotates nothing for it (the stated limit).
#[test]
fn invalid_grant_box_judges_nothing_spec_crypto_4() {
    let mut lp = synced(3);
    let (d, p2) = (lp.peers[1].engine.me(), lp.peers[2].engine.me());
    let y = group(&mut lp, 0);
    let x = group(&mut lp, 0);
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

// spec/crypto.md §4 (Boxes: an invalid grant's box opens what its author held; Departures: the
// author's own lowering rotates past it): admin A demotes writer D to reader, rotating write to
// e1 that D lacks; the owner removes A, rotating write to e2; A, not knowing, re-grants D write,
// boxing e1. Settled, the grant is invalid and D a reader. D opens e1 (A held it and handed it
// on: a secret once shared cannot be un-shared) but not e2, which every writer encrypts under.
#[test]
fn invalid_regrant_hands_on_only_what_its_author_held_spec_crypto_4() {
    let mut lp = synced(3);
    let (a, d) = (lp.peers[1].engine.me(), lp.peers[2].engine.me());
    let g = group(&mut lp, 0);
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
    assert_eq!(write(&lp, 0), Some(e2), "the owner writes under e2");
}

// spec/crypto.md §4 (Boxes: an invalid commit's boxes judge nothing;
// issue held-boxes-reader-rekey (closed)): reader R of G writes `secrets.0` deltas (invalid: a delta
// needs write) boxing G's current read epoch to party P, which holds no role on G. G's admin
// counts no departure from them and rotates nothing: a reader cannot make G rotate per commit,
// and a rotation would buy nothing against it (R holds the new epoch too).
#[test]
fn reader_junk_boxes_force_no_rotation_spec_crypto_4() {
    let mut lp = synced(3);
    let (r, p) = (lp.peers[1].engine.me(), lp.peers[2].engine.me());
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &r, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let e0 = newest_read(&lp, 0, g).unwrap();
    for _ in 0..3 {
        lp.peers[1].clock.advance(1_000);
        let s = lp.peers[1].engine.get_typed(&g, &ct::SECRETS).unwrap().unwrap();
        let own = s.boxes.iter().find(|(k, _)| k.holder == r && k.role == Role::Read).map(|(_, b)| b.clone()).unwrap();
        let key = ct::BoxKey { holder: p, role: Role::Read, epoch: osis_keys::aspects::to_schema(&e0) };
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

// spec/crypto.md §4 (merge, rule 3; model `D0_nc_2adm`, the shape that broke the candidate
// rules before rule 4): X (peer 0's) holds Y keyless, Y (admins y1 = peer 2, y2 = peer 3)
// holds X, D a reader of Y. y1 removes D (knowing keyset kk); y2, not knowing, rotates Y (an
// ignorant fork F). Peer 0 holding both seals X at kk or F as rule 1 gives; once y1 merges F,
// peer 0's box is stale and it moves: D opens no newest epoch, nothing locks out.
#[test]
fn second_admin_ignorant_fork_in_cycle_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let mut lp = synced(4);
    let [d, y2] = [1, 3].map(|i| lp.peers[i].engine.me());
    let x = group(&mut lp, 0);
    let y = group(&mut lp, 2);
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

// spec/crypto.md §4 (rotating needs no secret; History box), spec/permissions.md §3: P writes A
// only through holder actor M (first admin: peer 2). A's first admin rotates A's read leaving M
// out (Seal found no keyset; here by hand), so P holds A's write but no current read. E, a
// writer of A, leaves by itself: the read epoch P lacks covers nothing, so P rotates read and
// write, superseding it unread, wrapped under the read secret it holds; A's first admin, holding
// it, adds it to P's epoch's history.
#[test]
fn rotator_lacking_read_rotates_read_too_spec_permissions_3() {
    let mut lp = synced(5);
    let [p, e] = [1, 4].map(|i| lp.peers[i].engine.me());
    let a = group(&mut lp, 0);
    let m = group(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.peers[2].engine.grant(&m, &p, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&a, &e, &edge(Role::Write)).unwrap();
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
/// admin only through holder actor M (first admin: peer 2), and A's first admin rotates A's write leaving
/// M out, so P holds A's read and admin but no current write; F (5) is an admin of A. Returns
/// the peers and A, M.
fn lacking_write() -> (LocalPeer, Tid, Tid) {
    let (lp, (a, m)) = LocalPeer::cached("rotation::tests_members::lacking_write", || {
        let mut lp = synced(6);
        let [p, f] = [1, 5].map(|i| lp.peers[i].engine.me());
        let a = group(&mut lp, 0);
        let m = group(&mut lp, 2);
        lp.sync_all().unwrap();
        lp.peers[2].engine.grant(&m, &p, &edge(Role::Admin)).unwrap();
        lp.sync_all().unwrap();
        lp.peers[0].engine.grant(&a, &m, &edge(Role::Admin)).unwrap();
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

// spec/crypto.md §4 (rotating needs no secret; History box), spec/permissions.md §3: F, an admin
// of A, leaves by itself. P rotates all three roles of A, the write epoch it lacks superseded
// unread; A's first admin, holding it, adds it to P's write epoch's history.
#[test]
fn rotator_lacking_write_rotates_history_added_spec_permissions_3() {
    let (mut lp, a, m) = lacking_write();
    let f = lp.peers[5].engine.me();
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
    let f = lp.peers[5].engine.me();
    let lacked = lp.peers[1].engine.epochs(&a).unwrap().write.current()[0];
    lp.peers[1].engine.demote(&a, &Demotion { holder: f, new: None, retain: None }).unwrap();
    assert!(!lp.peers[1].engine.core.current_holders(&a).iter().any(|(m, _, _)| *m == f), "F removed");
    let e = lp.peers[1].engine.epochs(&a).unwrap();
    assert_eq!(e.write.current().len(), 1, "the removal's epoch alone is current");
    assert!(e.write.newest_held().is_some() && !e.write.is_current(&lacked), "the epoch P lacked is superseded");
}

// spec/crypto.md §4 (Possession, Writers), spec/permissions.md §3: P is A's admin only through
// holder actor M (first admin: peer 2), which rotates M leaving P out, so P holds M's new keyset
// but not its secret and cannot show M. P's removal of F goes alone (its rotation would fail
// Authority everywhere), the departure uncovered; once M's admin re-seals P on M, P's due
// rotation of A follows and covers it.
#[test]
fn removal_without_possession_goes_alone_spec_crypto_4() {
    let mut lp = synced(6);
    let [p, f] = [1, 5].map(|i| lp.peers[i].engine.me());
    let a = group(&mut lp, 0);
    let m = group(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.peers[2].engine.grant(&m, &p, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&a, &f, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    rotate_skipping(&mut lp, 2, m, &BTreeSet::from([Role::Read, Role::Write, Role::Admin]), &[p]);
    lp.sync_all().unwrap();
    assert!(lp.peers[1].engine.epochs(&m).unwrap().admin.newest_held().is_none(), "P lacks M's new keyset secret");
    let epochs = lp.peers[1].engine.epochs(&a);
    lp.peers[1].engine.demote(&a, &Demotion { holder: f, new: None, retain: None }).unwrap();
    assert!(!lp.peers[1].engine.core.current_holders(&a).iter().any(|(x, _, _)| *x == f), "F removed");
    assert_eq!(lp.peers[1].engine.epochs(&a), epochs, "alone: P cannot show M");
    assert!(!blocked_at(&mut lp, 1, a).is_empty(), "the departure is uncovered");
    assert!(lp.peers[1].engine.ensure_rotated(&a).unwrap().0.commits.is_empty(), "P rotates A without showing M");
    lp.sync_all().unwrap();
    assert!(!lp.peers[2].engine.reseal_due(&m, &Pass).unwrap().commits.is_empty(), "M's admin re-seals P");
    lp.sync_all().unwrap();
    let (done, still) = lp.peers[1].engine.ensure_rotated(&a).unwrap();
    assert!(!done.commits.is_empty(), "P rotates A once it shows M");
    assert!(still.is_empty(), "{still:?}");
    lp.sync_all().unwrap();
    assert!(blocked_at(&mut lp, 0, a).is_empty(), "A's first admin holds P's rotation, covering");
}

// spec/crypto.md §4 (Possession, Writers): the writer's Authority check reads the boxes its
// rotation writes, as every receiver judges them. P is A's admin only through holder actor M; M's
// admin rotates M's write role leaving P out, so P holds M's read and admin secrets but not its
// new write one. A's write boxes to M are stale, so P's write rotation of A is due; it would box
// M's write role sealed (P cannot sign for that keyset), and a box of a role it does not rotate
// shows nothing. So P waits (write blocked) instead of committing a rotation every node, P
// included, judges invalid; once re-sealed on M it rotates.
#[test]
fn authority_counts_only_rotated_roles_spec_crypto_4() {
    let mut lp = synced(3);
    let p = lp.peers[1].engine.me();
    let a = group(&mut lp, 0);
    let m = group(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.peers[2].engine.grant(&m, &p, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    rotate_skipping(&mut lp, 2, m, &BTreeSet::from([Role::Write]), &[p]);
    lp.sync_all().unwrap();
    let em = lp.peers[1].engine.epochs(&m).unwrap();
    assert!(em.write.newest_held().is_none() && em.read.newest_held().is_some(), "P holds M's read secret, not its new write one");
    assert!(blocked_at(&mut lp, 1, a).contains(&Role::Write), "A's write boxes to M are stale");
    let (done, still) = lp.peers[1].engine.ensure_rotated(&a).unwrap();
    assert!(done.commits.is_empty(), "P waits: its rotation could not show M");
    assert!(still.contains(&Role::Write), "{still:?}");
    lp.sync_all().unwrap();
    assert!(!lp.peers[2].engine.reseal_due(&m, &Pass).unwrap().commits.is_empty(), "M's admin re-seals P");
    lp.sync_all().unwrap();
    let (done, still) = lp.peers[1].engine.ensure_rotated(&a).unwrap();
    assert!(!done.commits.is_empty(), "P rotates A once it shows M");
    assert!(still.is_empty(), "{still:?}");
}

/// Delivers peer `from`'s commits `ids` to peer `to` without any `keys.0` or `secrets.0` delta on
/// `x` (a notice of a role change without its rotation).
fn deliver_edges_only(lp: &mut LocalPeer, from: usize, to: usize, x: Tid, ids: &[osis_base::CommitId]) {
    for pk in lp.packages(from).unwrap().into_iter().filter(|p| ids.contains(&p.id)) {
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
    let [_, b, c, e] = std::array::from_fn(|i| lp.peers[i].engine.me());
    let t = group(&mut lp, 0);
    for h in [b, c] {
        lp.peers[0].engine.grant(&t, &h, &edge(Role::Read)).unwrap();
    }
    lp.sync_all().unwrap();
    let x = group(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.peers[2].engine.grant(&x, &t, &edge(Role::Read)).unwrap();
    lp.peers[2].engine.grant(&x, &e, &edge(Role::Read)).unwrap();
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
    // T's new keyset reaches B, and C (as a certificate under X's labels): the box is stale
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

// spec/crypto.md §4 (Encrypting under: an epoch whose secret the node lacks is judged by order;
// model `D0_order`): X administers A, which M holds; X holds none of M's secrets. E leaves M by
// self-removal, so M does not rotate. X knows the departure; M's keyset was made before it, so it
// cannot cover it: X's next rotation of A leaves M out (E opens nothing of it). Once M's rotation
// for the departure reaches X, X seals M there again, and E opens nothing of A's new epochs.
#[test]
fn departure_from_an_unread_holder_is_judged_by_order_spec_crypto_4() {
    let mut lp = synced(3);
    let e = lp.peers[2].engine.me();
    let m = group(&mut lp, 1);
    lp.peers[1].engine.grant(&m, &e, &edge(Role::Read)).unwrap();
    let a = group(&mut lp, 0);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
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

// spec/crypto.md §4 (Encrypting under: the box clause follows every box the node holds; model
// `D0_readers_out`): G {R, A}, A {a1, M}, M {m1, R, E}. m1 removes E from M; R, G's admin, holds
// M's new keyset but may not rotate A, whose box to M names M's old one. G's epoch boxes A at a
// keyset E opens, so R rotates G leaving A out and E opens nothing R writes under G; once a1
// moves A onto M's new keyset, R seals A again.
#[test]
fn box_walk_passes_actors_the_node_may_not_rotate_spec_crypto_4() {
    let mut lp = synced(4);
    let [r, _, _, e] = std::array::from_fn(|i| lp.peers[i].engine.me());
    let g = group(&mut lp, 0);
    let a = group(&mut lp, 1);
    let m = group(&mut lp, 2);
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

// spec/crypto.md §4 (Encrypting under: the maker of an epoch opens it): A and M in a cycle (M
// holds write on A first, so A's grant on M is keyless: M boxes A nothing). P writes A, so M
// through it. Demoted to read on A, P, unaware, rotates M (its maker holds M's epoch with no box
// naming it); re-granted write, P's removal from A lists that rotation in its frontier, so it
// stands (spec/permissions.md §5.2). P holds no role on M any more: M's epoch it made is uncovered, so the
// admin rotates M before sealing it into A, and P opens nothing written under A after.
#[test]
fn maker_lowered_through_a_holder_actor_opens_nothing_new_spec_crypto_4() {
    let mut lp = synced(2);
    let p = lp.peers[1].engine.me();
    let a = group(&mut lp, 0);
    let m = group(&mut lp, 0);
    for (t, h) in [(a, m), (m, a), (a, p)] {
        lp.peers[0].clock.advance(1);
        lp.peers[0].engine.grant(&t, &h, &edge(Role::Write)).unwrap();
    }
    lp.sync_all().unwrap();
    assert!(!boxes(&mut lp, 0, m, a), "A's grant on M is keyless");
    lp.peers[0].engine.demote(&a, &Demotion { holder: p, new: Some(edge(Role::Read)), retain: None }).unwrap();
    lp.peers[1].clock.advance(1_000);
    let made = rotate_unchecked(&mut lp, 1, m, &BTreeSet::from([Role::Read, Role::Write])).1;
    let k2 = made.iter().find(|x| x.1 == Role::Read).map(|x| x.2);
    let start: Opened = held_by(&lp, 1, &[m, a]).into_iter().chain(made).collect();
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&a, &p, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    removal(&mut lp, 0, a, p);
    lp.sync_all().unwrap();
    assert_eq!(newest_read(&lp, 0, m), k2, "P's epoch of M stands");
    assert!(lp.peers[0].engine.core.role_now(&p, &m).is_none(), "P holds no role on M");
    let (_, still) = lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(leaked(&mut lp, 0, &[m, a], p, start), Vec::<Tid>::new());
    assert_ne!(newest_read(&lp, 0, m), k2, "M rotated off P's epoch");
    lp.sync_all().unwrap();
    for x in [m, a] {
        assert!(lp.peers[0].engine.ensure_rotated(&x).unwrap().0.commits.is_empty(), "one rotation, no churn");
    }
}

// spec/crypto.md §4 (History box: any holder of the epoch's role adds): W, demoted to read, still
// holds the current write epoch and an earlier write secret its history lists not. It adds no
// write history (that needs write): its re-seal pass writes nothing there, and fails nothing.
#[test]
fn lowered_holder_adds_no_history_above_its_role_spec_crypto_4() {
    let mut lp = synced(2);
    let [x, w] = std::array::from_fn(|i| lp.peers[i].engine.me());
    let g = group(&mut lp, 0);
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
    let done = lp.peers[1].engine.reseal_due(&g, &Pass).unwrap();
    assert!(done.commits.is_empty(), "no write history from a reader");
}

// spec/crypto.md §4 (Departure: a maker that no longer holds r): an honest maker whose role
// on M runs through team T (keyed) is lowered on T, then re-granted. The admin rotates M once
// for it; re-granted, P has departed nothing, and no further pass rotates M (bounded: the
// maker's departure ends with its epoch, superseded).
#[test]
fn lowered_maker_rotates_once_spec_crypto_4() {
    let mut lp = synced(2);
    let p = lp.peers[1].engine.me();
    let t = group(&mut lp, 0);
    let m = group(&mut lp, 0);
    for (x, h) in [(m, t), (t, p)] {
        lp.peers[0].clock.advance(1);
        lp.peers[0].engine.grant(&x, &h, &edge(Role::Write)).unwrap();
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
    lp.peers[0].engine.grant(&t, &p, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(rotations(&mut lp), vec![0, 0, 0], "re-granted: nothing more rotates");
}

// spec/crypto.md §4 (holder actors: stale; rotation due): one cause, one rotation. D's removal
// from G goes alone (no rotation, as while Seal waits); G's rotation, due at G's admin, makes T's
// box to G stale at each of T's three admins. The admin rotates T in the same step
// (`rotate_above`), so T's other admins, judging after, find nothing due: T moves one epoch,
// unforked, where each admin rotating T for the stale box forked it three ways.
#[test]
fn holder_rotation_rotates_above_at_once_spec_crypto_4() {
    let mut lp = synced(4);
    let [_, b, c, d] = std::array::from_fn(|i| lp.peers[i].engine.me());
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &d, &edge(Role::Read)).unwrap();
    let t = group(&mut lp, 0);
    lp.peers[0].engine.grant(&t, &g, &edge(Role::Read)).unwrap();
    for h in [b, c] {
        lp.peers[0].engine.grant(&t, &h, &edge(Role::Admin)).unwrap();
    }
    lp.sync_all().unwrap();
    let k = newest_read(&lp, 0, t).unwrap();
    lp.peers[0]
        .engine
        .run(|tx| {
            let mut m = Mutation::new();
            m.ts = Some(tx.core.hlc.next());
            crate::flows::edges::removal(tx, &mut m, g, d)?;
            m.frontier(osis_schema::Codec::to_value(&ct::Frontier::default()));
            crate::engine::Engine::commit_tx(tx, m).map(|_| ())
        })
        .unwrap();
    assert_eq!(lp.peers[0].engine.ensure_rotated(&g).unwrap().0.commits.len(), 2, "G's rotation, then T's");
    lp.sync_all().unwrap();
    let after: Vec<usize> = [1, 2, 0].into_iter().map(|p| lp.peers[p].engine.ensure_rotated(&t).unwrap().0.commits.len()).collect();
    assert_eq!(after, vec![0, 0, 0], "T's other admins, then its rotator, find nothing due");
    let cur = lp.peers[1].engine.epochs(&t).unwrap().read.current();
    assert_eq!((cur.len(), cur[0].n()), (1, k.n() + 1), "one rotation of T");
}

// spec/crypto.md §4 (merge: the merger): three admins rotate T at once; holding the same three
// forks, one of them merges (the maker of the newest fork but one), not every maker of a fork
// but the newest, whose merges would fork again.
#[test]
fn three_forks_take_one_merge_spec_crypto_4() {
    let mut lp = synced(3);
    let [_, b, c] = std::array::from_fn(|i| lp.peers[i].engine.me());
    let t = group(&mut lp, 0);
    for h in [b, c] {
        lp.peers[0].engine.grant(&t, &h, &edge(Role::Admin)).unwrap();
    }
    lp.sync_all().unwrap();
    for p in 0..3 {
        lp.peers[p].clock.advance(1);
        rotate_skipping(&mut lp, p, t, &BTreeSet::from([Role::Read]), &[]);
    }
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[0].engine.epochs(&t).unwrap().read.current().len(), 3, "three forks");
    let merges: usize = (0..3).map(|p| lp.peers[p].engine.ensure_rotated(&t).unwrap().0.commits.len()).sum();
    assert_eq!(merges, 1, "one merger");
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.epochs(&t).unwrap().read.current().len(), 1, "merged");
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
    let e = lp.peers[3].engine.me();
    let start = held_by(&lp, 3, &[m, a, g]);
    removal(&mut lp, 2, m, e);
    lp.sync_all().unwrap();
    assert!(lp.peers[4].engine.epochs(&m).is_none_or(|x| x.read.held().next().is_none()), "W holds none of M's secrets");
    let mut counts = Vec::new();
    for _ in 0..3 {
        let rot = lp.peers[0].engine.ensure_rotated(&g).unwrap().0.commits.len();
        lp.sync_all().unwrap();
        let reseal = lp.peers[4].engine.reseal_due(&g, &Pass).unwrap().commits.len();
        lp.sync_all().unwrap();
        counts.push((rot, reseal));
    }
    assert_eq!(counts, vec![(1, 0), (0, 0), (0, 0)], "R rotates G once; W re-seals nothing");
    assert_eq!(sealed_at(&mut lp, 4, g, a), None, "A left out");
    assert_eq!(leaked(&mut lp, 0, &[m, a, g], e, start), vec![a], "E opens only A, which a1 never rotates");
}

/// Peer `i` removes `d` from `t` alone (no rotation, as while Seal waits or Authority fails).
fn removal_alone(lp: &mut LocalPeer, i: usize, t: Tid, d: Tid) {
    lp.peers[i]
        .engine
        .run(|tx| {
            let mut m = Mutation::new();
            m.ts = Some(tx.core.hlc.next());
            crate::flows::edges::removal(tx, &mut m, t, d)?;
            m.frontier(osis_schema::Codec::to_value(&ct::Frontier::default()));
            crate::engine::Engine::commit_tx(tx, m).map(|_| ())
        })
        .unwrap();
}

// spec/crypto.md §4 (Seal, Left out; model `D0_readers_g2_mark`): G {R, W, A}, A {a1, M},
// M {m1, R, E}. m1 removes E from M alone: M keeps the keyset E opens, so W, G's other admin
// reading neither A nor M, can tell nothing of it. R knows the removal, so rotates G leaving A out
// at A's keyset, and G's keyset records it; W then does not re-seal A there (each re-seal made
// G's epoch blocked at R, which rotated again, for as long as M did not rotate). Once M and A
// rotate, both re-seal A at A's knowing keyset, which descends from the one recorded.
#[test]
fn co_writer_reseals_no_holder_left_out_spec_crypto_4() {
    let (mut lp, m, a, g) = co_writer_world();
    let e = lp.peers[3].engine.me();
    let start = held_by(&lp, 3, &[m, a, g]);
    let k_a = sealed_at(&mut lp, 0, g, a).unwrap();
    removal_alone(&mut lp, 2, m, e);
    lp.sync_all().unwrap();
    let mut counts = Vec::new();
    for _ in 0..3 {
        let rot = lp.peers[0].engine.ensure_rotated(&g).unwrap().0.commits.len();
        lp.sync_all().unwrap();
        let reseal = lp.peers[4].engine.reseal_due(&g, &Pass).unwrap().commits.len();
        lp.sync_all().unwrap();
        counts.push((rot, reseal));
    }
    assert_eq!(counts, vec![(1, 0), (0, 0), (0, 0)], "R rotates G once; W re-seals nothing");
    assert_eq!(sealed_at(&mut lp, 4, g, a), None, "A left out");
    let ks = lp.peers[4].engine.core.ix.keysets.get(&(g, Role::Read, newest_read(&lp, 4, g).unwrap())).unwrap().left_out.clone();
    assert_eq!(ks, [(a, BTreeSet::from([k_a]))].into(), "G's keyset records A's keyset it left A out at");
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

// spec/crypto.md §4 (Seal, Left out; model `D0_above_g2_mark`): G {a1, W, A}, A {a1, E}. a1
// removes E from A alone and rotates G leaving A out at A's keyset E opens; W, reading not A and
// lacking the removal (so not judging A's keyset by order), does not re-seal A there. Once a1
// rotates A, W re-seals A at that keyset.
#[test]
fn removal_alone_left_out_stays_out_at_co_writer_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let mut lp = synced(3);
    let [_, w, e] = std::array::from_fn(|i| lp.peers[i].engine.me());
    let a = group(&mut lp, 0);
    lp.peers[0].engine.grant(&a, &e, &edge(Role::Read)).unwrap();
    let g = group(&mut lp, 0);
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
    assert_eq!(lp.peers[1].engine.reseal_due(&g, &Pass).unwrap().commits.len(), 0, "W re-seals nothing");
    lp.sync_all().unwrap();
    assert_eq!(sealed_at(&mut lp, 1, g, a), None);
    assert!(!leaked(&mut lp, 0, &[a, g], e, start.clone()).contains(&g), "E opens nothing a1 writes under G");
    lp.peers[0].engine.ensure_rotated(&a).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.reseal_due(&g, &Pass).unwrap().commits.len(), 1, "W re-seals A at its knowing keyset");
    lp.sync_all().unwrap();
    assert_eq!(sealed_at(&mut lp, 1, g, a), newest_read(&lp, 0, a));
    assert_eq!(leaked(&mut lp, 0, &[a, g], e, start), Vec::<Tid>::new());
}

// spec/permissions.md §3 (re-seal), spec/crypto.md §4 (Possession, Encrypting under): a re-seal
// pass reads its candidates after the rotations and finalizes due first. X admins G, which M
// reads; X writes M only through H, whose newest keyset X lacks the secret of (H rotated leaving
// X out, M boxing H there), so X's finalize of Y's ended edge on M goes without its rotation and
// leaves M's keyset uncovered at X: M, lacking a box at G's newest epoch, is a candidate before
// it and out after. The pass re-seals nothing (it does not fail); once M's admin rotates M, X
// re-seals M at that keyset.
#[test]
fn reseal_candidates_follow_the_finalize_before_them_spec_permissions_3() {
    let mut lp = synced(3);
    let [_, x, y] = std::array::from_fn(|i| lp.peers[i].engine.me());
    let (g, m, h) = (group(&mut lp, 0), group(&mut lp, 0), group(&mut lp, 0));
    lp.peers[0].engine.grant(&h, &x, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&m, &h, &edge(Role::Write)).unwrap();
    let until = WallMs(lp.peers[0].engine.core.now().0 + 100);
    lp.peers[0].engine.grant(&m, &y, &ct::Edge { until: Some(until), ..edge(Role::Read) }).unwrap();
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
    lp.peers[1].engine.reseal_due(&g, &Pass).unwrap();
    assert!(lp.peers[1].engine.departures(&m).unwrap().iter().any(|d| d.holder == y), "X finalized Y alone");
    assert_eq!(sealed_at(&mut lp, 1, g, m), None, "M is left out at X");
    lp.sync_all().unwrap();
    lp.advance(1_000);
    assert!(!lp.peers[0].engine.ensure_rotated(&m).unwrap().0.commits.is_empty(), "M's admin covers Y's departure");
    lp.sync_all().unwrap();
    lp.peers[1].engine.reseal_due(&g, &Pass).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(sealed_at(&mut lp, 1, g, m), newest_read(&lp, 0, m));
}

// spec/crypto.md §4 (Possession, Authority; Key access; Merger): a role reached only through a
// keyless grant makes no valid rotation, whatever roles it rotates. Cycle G -> H -> M -> G (M
// admin on G, H admin on M, then G admin on H: keyless). X writes G and reads H, so writes M only
// through G's keyless grant on H: it holds H's read secret, never its write one. Its rotations
// of M, read and write or write alone, show H at no role its write needs: invalid at every node,
// so they fork nothing (a proof at read once made the first valid and the second not, so a fork
// whose maker was X stayed forked when X merged write alone). Nor is X a merger
// (`may_rotate_keyed`).
#[test]
fn keyless_route_makes_no_valid_rotation_spec_crypto_4() {
    let mut lp = synced(2);
    let x = lp.peers[1].engine.me();
    let (g, m, h) = (group(&mut lp, 0), group(&mut lp, 0), group(&mut lp, 0));
    lp.peers[0].engine.grant(&g, &m, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&m, &h, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&h, &g, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &x, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&h, &x, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    assert!(lp.peers[0].engine.run(|tx| Ok(super::members::key_access(tx.core).contains(&(h, g)))).unwrap(), "G's grant on H is keyless");
    let (maybe, keyed) = lp.peers[0].engine.run(|tx| Ok((super::may_rotate(tx.core, &x, &m), super::members::may_rotate_keyed(tx.core, &x, &m)))).unwrap();
    assert!(maybe.contains(&Role::Write) && !keyed.contains(&Role::Write), "X writes M only through the keyless grant: {maybe:?} {keyed:?}");
    let made = [BTreeSet::from([Role::Read, Role::Write]), BTreeSet::from([Role::Write])].map(|rot| rotate_unchecked(&mut lp, 1, m, &rot).0);
    lp.sync_all().unwrap();
    for i in 0..2 {
        for c in &made {
            let meta = lp.peers[i].engine.core.ix.commits.get(c).cloned().expect("held");
            assert!(meta.view.aspects.iter().enumerate().filter(|(_, a)| a.tid == m).all(|(ai, _)| !meta.valid_at(ai)), "peer {i}: X's rotation of M valid");
        }
        assert_eq!(lp.peers[i].engine.epochs(&m).unwrap().write.current().len(), 1, "peer {i}: M's write forked");
    }
    assert!(blocked_at(&mut lp, 0, g).is_empty(), "G's admin may encrypt under G");
}

/// An ended holder actor's world (spec/crypto.md §4, Holder actors, Ended): peer 0 makes T,
/// expiring at `T0 + 50 s` (first admin peer 0, secrets of its own) and X (secrets of its own),
/// grants T read on X; peer 2 makes G and peer 0 grants G read on T; peer 1 reads T, and peer
/// 3 reads G. Synced: T, X, G. Built once, copied (`LocalPeer::cached`).
fn ended_world() -> (LocalPeer, Tid, Tid, Tid) {
    let (lp, (t, x, g)) = LocalPeer::cached("rotation::ended_world", || {
        let (lp, t, x, g) = build_ended_world();
        (lp, (t, x, g))
    });
    (lp, t, x, g)
}

fn build_ended_world() -> (LocalPeer, Tid, Tid, Tid) {
    let mut lp = LocalPeer::new(4, 0, T0).unwrap();
    let me = lp.peers[0].engine.me();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &osis_base::Value::Int(0)).unwrap();
    m.expires_all(WallMs(T0.0 + 50_000));
    lp.peers[0].commit(m).unwrap();
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    let x = group(&mut lp, 0);
    let g = group(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&x, &t, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&t, &g, &edge(Role::Read)).unwrap();
    let n1 = lp.peers[1].engine.tid();
    lp.peers[0].engine.grant(&t, &n1, &edge(Role::Read)).unwrap();
    let n3 = lp.peers[3].engine.tid();
    lp.peers[2].engine.grant(&g, &n3, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    (lp, t, x, g)
}

const T0: WallMs = WallMs(1_700_000_000_000);

/// T ends: time passes it and every peer ticks, synced.
fn end_t(lp: &mut LocalPeer, t: Tid) {
    lp.advance(100_000);
    for i in 0..lp.peers.len() {
        lp.peers[i].tick().unwrap();
    }
    lp.sync_all().unwrap();
    for i in 0..lp.peers.len() {
        assert!(lp.peers[i].engine.core.ended(&t) || lp.peers[i].engine.core.created(&t).is_none(), "peer {i}: T ended");
    }
}

// spec/crypto.md §4 (Holder actors, Ended): an ended actor holds no keys, so X's admin, once T
// ended, rotates X (its box to T is a departure) boxing T's frozen holders in T's place: G and
// itself, never peer 1, removed from T before the ending. Peer 1 opens none of X's new epoch from
// every secret it held; peer 3, reading X only through G and T, reads it
#[test]
fn ended_holder_actor_boxes_its_frozen_holders_never_one_removed_before_spec_crypto_4() {
    let (mut lp, t, x, g) = ended_world();
    let n1 = lp.peers[1].engine.tid();
    let start = held_by(&lp, 1, &[t, x]);
    assert!(start.iter().any(|k| k.0 == x), "peer 1 reads X through T");
    lp.peers[0].engine.demote(&t, &Demotion { holder: n1, new: None, retain: None }).unwrap();
    lp.sync_all().unwrap();
    end_t(&mut lp, t);
    let holders = lp.peers[0].engine.core.key_holders(&x);
    assert!(holders.iter().any(|h| h.0 == g) && !holders.iter().any(|h| h.0 == t || h.0 == n1), "T's frozen holders in its place: {holders:?}");
    let before = newest_read(&lp, 0, x);
    settle(&mut lp, &[0], &[x]);
    let w = newest_read(&lp, 0, x).unwrap();
    assert_ne!(Some(w), before, "X rotated past its box to T");
    assert!(boxes(&mut lp, 0, x, g), "G boxed on X");
    assert!(!openable(&mut lp, 0, &[t, x, g], n1, start).contains(&(x, Role::Read, w)), "peer 1 opens nothing of X's new epoch");
    assert!(all_boxed(&mut lp, 0, &[x]), "every holder of X boxed");
    assert_eq!(newest_read(&lp, 3, x), Some(w), "peer 3 reads X through G");
}

// spec/crypto.md §4 (Holder actors, Ended; Stale): X's rotation after T's ending boxes T's frozen
// holder G at its current keyset as any holder actor: G's admin removes peer 3 from G, so X's box
// to G goes stale and X rotates onto G's new keyset, which peer 3 opens nothing of
#[test]
fn rotation_after_an_ending_seals_a_frozen_holder_at_its_current_keyset_spec_crypto_4() {
    let (mut lp, t, x, g) = ended_world();
    end_t(&mut lp, t);
    settle(&mut lp, &[0], &[x]);
    assert!(boxes(&mut lp, 0, x, g), "G boxed on X");
    let n3 = lp.peers[3].engine.tid();
    let start = held_by(&lp, 3, &[g, x]);
    assert!(start.iter().any(|k| k.0 == x), "peer 3 reads X through G");
    lp.peers[2].engine.demote(&g, &Demotion { holder: n3, new: None, retain: None }).unwrap();
    lp.sync_all().unwrap();
    let gk = newest_read(&lp, 2, g).unwrap();
    settle(&mut lp, &[0, 2], &[g, x]);
    assert_eq!(sealed_at(&mut lp, 0, x, g), Some(gk), "X sealed at G's keyset past the removal");
    let w = newest_read(&lp, 0, x).unwrap();
    assert!(!openable(&mut lp, 0, &[t, x, g], n3, start).contains(&(x, Role::Read, w)), "peer 3 opens nothing of X's new epoch");
}
