//! Published KEM keys (spec/crypto.md §3): only where something seals to a keyset; the granter's
//! check (spec/permissions.md §2 Granting to a thing); KEM key due (KemKeys.tla `KK_written`).

#![allow(clippy::unwrap_used)]
use super::tests::{edge, rotate_as, settle, synced};
use crate::error::Error;
use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use crate::Mutation;
use osis_base::{Role, Tid};
use osis_keys::ROLES;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

/// A thing of peer `i`'s made independent, holding no role anywhere, no signal enabled: nobody
/// seals to it. Held at `at`.
fn plain(lp: &mut LocalPeer, i: usize, at: &[usize]) -> Tid {
    let me = lp.peers[i].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[i].engine.new_thing(&mut m, me);
    lp.peers[i].commit(m).unwrap();
    lp.peers[i].engine.make_independent(&t).unwrap();
    for j in at {
        lp.hold_at(*j, t);
    }
    t
}

fn keys(lp: &mut LocalPeer, i: usize, t: Tid) -> ct::Keys {
    lp.peers[i].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap()
}

/// The roles whose keyset in `t`'s `keys.0` at peer `i` carries a KEM key.
fn kem_roles(lp: &mut LocalPeer, i: usize, t: Tid) -> BTreeSet<Role> {
    let k = keys(lp, i, t);
    ROLES.into_iter().filter(|r| osis_keys::aspects::keyset_of(&k, *r).is_some_and(|ks| ks.kem_key.is_some())).collect()
}

/// The epoch of `t`'s read keyset at peer `i`.
fn read_epoch(lp: &mut LocalPeer, i: usize, t: Tid) -> ct::Epoch {
    keys(lp, i, t).read.unwrap().epoch
}

// An independent thing nobody seals to (made independent, holding nothing, no signal) publishes
// no KEM key in any keyset and no read key in its step keys; a node thing (minted with a key)
// publishes every one.
#[test]
fn a_thing_nobody_seals_to_publishes_no_kem_key_spec_crypto_3() {
    let mut lp = synced(1);
    let h = plain(&mut lp, 0, &[0]);
    assert_eq!(kem_roles(&mut lp, 0, h), BTreeSet::new());
    assert!(keys(&mut lp, 0, h).step.unwrap().read.unwrap().kem_key.is_none(), "no read KEM key in its step keys");
    let me = lp.peers[0].engine.tid();
    assert_eq!(kem_roles(&mut lp, 0, me), ROLES.into_iter().collect());
}

// A grant of read to such a thing rotates its sync and read roles first, in the grant's
// transaction, with KEM keys (the granter may write it); its write and admin keysets stay bare.
#[test]
fn a_grant_rotates_the_holders_roles_first_spec_permissions_2() {
    let mut lp = synced(1);
    let (h, g) = (plain(&mut lp, 0, &[0]), plain(&mut lp, 0, &[0]));
    let before = read_epoch(&mut lp, 0, h);
    lp.peers[0].engine.grant(&g, &h, &edge(Role::Read)).unwrap();
    assert_ne!(read_epoch(&mut lp, 0, h), before, "rotated");
    assert_eq!(kem_roles(&mut lp, 0, h), BTreeSet::from([Role::Sync, Role::Read]));
}

// A writer of H, not an admin, holding H's keys: a read grant rotates H's sync and read (a
// writer may), an admin grant is refused (H's admin keyset carries no KEM key and a writer may
// not rotate admin).
#[test]
fn a_granter_that_may_not_rotate_the_holder_is_refused_spec_permissions_2() {
    let mut lp = synced(2);
    let p1 = lp.peers[1].engine.tid();
    let h = plain(&mut lp, 0, &[0, 1]);
    lp.peers[0].engine.grant(&h, &p1, &edge(Role::Write)).unwrap();
    let g = plain(&mut lp, 1, &[0, 1]);
    lp.sync_all().unwrap();
    let e = lp.peers[1].engine.grant(&g, &h, &edge(Role::Admin)).unwrap_err();
    assert!(matches!(e, Error::Misuse(s) if s.contains("KEM")), "{e:?}");
    lp.peers[1].engine.grant(&g, &h, &edge(Role::Read)).unwrap();
    assert_eq!(kem_roles(&mut lp, 1, h), BTreeSet::from([Role::Sync, Role::Read]));
}

// A granter that may not write H and holds no card of it (here: none of H's keys) is refused.
#[test]
fn a_granter_without_card_or_write_is_refused_spec_permissions_2() {
    let mut lp = synced(2);
    let h = plain(&mut lp, 0, &[0]);
    let g = plain(&mut lp, 1, &[1]);
    lp.sync_all().unwrap();
    let e = lp.peers[1].engine.grant(&g, &h, &edge(Role::Read)).unwrap_err();
    assert!(matches!(e, Error::Permission { tid, needs: Role::Write } if tid == h), "{e:?}");
}

// KemKeys.tla `KK_written`: peer 1 grants M read on A, sealing at M's keyset k1 (with KEM keys: M
// read X). M leaves X, and peer 0, M's admin, rotates M (k2, no KEM key: it holds nothing peer 0
// knows of) before the grant reaches it. Peer 1 finds k1 stale and k2 no candidate: M is left
// out, with no record. KEM key due: peer 0, holding the grant, rotates M with KEM keys at a pass's
// end, and peer 1 re-seals M at that keyset.
#[test]
fn kem_key_due_ends_a_lockout_spec_crypto_3() {
    let mut lp = synced(2);
    let p1 = lp.peers[1].engine.tid();
    let m = plain(&mut lp, 0, &[0, 1]);
    let x = plain(&mut lp, 0, &[0]);
    lp.peers[0].engine.grant(&x, &m, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&m, &p1, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let a = plain(&mut lp, 1, &[0, 1]);
    lp.peers[1].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.demote(&x, &Demotion { holder: m, new: None, retain: None }).unwrap();
    rotate_as(&mut lp, 0, m, &BTreeSet::from([Role::Sync, Role::Read]), &[]).unwrap();
    assert_eq!(kem_roles(&mut lp, 0, m), BTreeSet::new(), "k2 carries no KEM key");
    lp.sync_all().unwrap();
    settle(&mut lp, &[0, 1], &[m, a, x]);
    let k = read_epoch(&mut lp, 1, m);
    assert!(kem_roles(&mut lp, 1, m).contains(&Role::Read), "M's newest read keyset carries a KEM key");
    let ae = read_epoch(&mut lp, 1, a);
    let sealed = keys(&mut lp, 1, a).sealed;
    let named = sealed.get(&ct::BoxKey { holder: m.into(), role: Role::Read, epoch: ae }).cloned().unwrap_or_default();
    assert!(named.contains(&k), "A boxes M at its newest keyset: {named:?}, {k:?}");
}

// spec/crypto.md §4 (Seal: a candidate carries a KEM key or its secret is held), KemKeys.tla
// `KK_fallback`: peer 2, no member of M, grants M read on A, sealing at M's keyset k1 (with KEM
// keys: M reads X). M leaves X and peer 0 rotates M to k2, with no KEM key. Before KEM key due,
// peer 2 holds k2 and no secret of it: its rotation of A leaves M out, never sealing at k1, which
// the party M's maker removed may hold. Fails with Seal falling back to k1 below the KEM-less
// newest keyset (`KK_fallback`).
#[test]
fn a_kem_less_keyset_leaves_its_holder_out_spec_crypto_4() {
    let mut lp = synced(3);
    let m = plain(&mut lp, 0, &[0, 2]);
    let x = plain(&mut lp, 0, &[0]);
    lp.peers[0].engine.grant(&x, &m, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let a = plain(&mut lp, 2, &[2]);
    lp.peers[2].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
    let k1 = osis_keys::aspects::from_schema(&read_epoch(&mut lp, 2, m)).unwrap();
    // the keysets of M that A's boxes to M at A's current read epochs name, at peer 2
    let boxed_at = |lp: &mut LocalPeer| {
        let current = lp.peers[2].engine.epochs(&a).unwrap().read.current();
        let s = lp.peers[2].engine.get_typed(&a, &ct::SECRETS).unwrap().unwrap();
        let at = |x: &ct::BoxKey| osis_keys::aspects::from_schema(&x.epoch).is_ok_and(|e| current.contains(&e));
        s.boxes.iter().filter(|(x, _)| x.holder == m.into() && x.role == Role::Read && at(x)).flat_map(|(_, b)| osis_keys::box_keysets(b)).collect::<BTreeSet<_>>()
    };
    assert_eq!(boxed_at(&mut lp), BTreeSet::from([k1]), "M boxed at k1");
    lp.peers[0].engine.demote(&x, &Demotion { holder: m, new: None, retain: None }).unwrap();
    rotate_as(&mut lp, 0, m, &BTreeSet::from([Role::Sync, Role::Read]), &[]).unwrap();
    assert_eq!(kem_roles(&mut lp, 0, m), BTreeSet::new(), "k2 carries no KEM key");
    lp.sync_all().unwrap();
    assert_ne!(osis_keys::aspects::from_schema(&read_epoch(&mut lp, 2, m)).unwrap(), k1, "peer 2 holds k2");
    rotate_as(&mut lp, 2, a, &BTreeSet::from([Role::Sync, Role::Read]), &[]).unwrap();
    assert_eq!(boxed_at(&mut lp), BTreeSet::new(), "M left out, not sealed at k1");
}

// A reader of H, neither writer nor holding a card, holds H's current `keys.0` (the newest it
// holds, carrying KEM keys: H reads X): its grant to H stands, sealed at H's newest read keyset
// there, and rotates nothing of H (it may not).
#[test]
fn a_reader_holding_the_holders_current_keys_grants_spec_permissions_2() {
    let mut lp = synced(2);
    let p1 = lp.peers[1].engine.tid();
    let h = plain(&mut lp, 0, &[0, 1]);
    let x = plain(&mut lp, 0, &[0]);
    lp.peers[0].engine.grant(&x, &h, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&h, &p1, &edge(Role::Read)).unwrap();
    let g = plain(&mut lp, 1, &[0, 1]);
    lp.sync_all().unwrap();
    let epoch = read_epoch(&mut lp, 1, h);
    assert_eq!(read_epoch(&mut lp, 0, h), epoch, "peer 1 holds H's current read keyset");
    assert!(lp.peers[1].engine.core.role_now(&p1, &h) < Some(Role::Write));
    lp.peers[1].engine.grant(&g, &h, &edge(Role::Read)).unwrap();
    assert_eq!(read_epoch(&mut lp, 1, h), epoch, "nothing of H rotated");
}
