#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Established epochs (spec/crypto.md §4; spec/permissions.md §3 re-seal): the TLC traces of
//! core/test/tla/rotation/AMBIGUITIES.md (R9, `MC_reorder`), snapshot establishment, the `/secrets`
//! compaction gate.

use crate::common;
use common::*;
use osis_base::{Role, Tid, WallMs};
use osis_keys::aspects::{box_key, history_key, to_schema};
use osis_keys::{
    ActorEpochs, Departure, Error, KeysWrite, Member, MemoryHeldActors, Opener, Provenance, Recipient, Rotation, box_member, ingest,
    may_compact_secrets, may_encrypt_under, reseal_member, reseal_needed, roles_up_to, rotate, snapshot_keyed,
};
use osis_crypto::Epoch;
use osis_schema::core_types::{Keys, Secrets};
use std::collections::BTreeSet;

fn cid(b: u8) -> osis_base::CommitId {
    osis_base::CommitId([b; 32])
}

fn read() -> BTreeSet<Role> {
    [Role::Read].into_iter().collect()
}

/// Actor A owned by P; members a2 (admin, a co-admin's actor) and m1 (read). Node a1 (P's
/// device) made A's secrets; node a2 applied that commit.
struct World {
    a: Tid,
    p: Tid,
    a2: Tid,
    m1: Tid,
    pe: ActorEpochs,
    a2e: ActorEpochs,
    m1e: ActorEpochs,
    /// a1's view and A's `/secrets` after the first rotation.
    a1v: ActorEpochs,
    s0: Secrets,
    k0: Keys,
    /// a2's view after applying it.
    a2v: ActorEpochs,
    e0: Epoch,
    seed: u64,
}

impl World {
    fn new() -> World {
        let (a, p, a2, m1) = (tid(1), tid(2), tid(3), tid(4));
        let (pe, a2e, m1e) = (person(0x20), person(0x30), person(0x40));
        let derived = ActorEpochs::derived(&pe, &a);
        let members = [actor_rcpt(p, Role::Admin, &pe), actor_rcpt(a2, Role::Admin, &a2e), actor_rcpt(m1, Role::Read, &m1e)];
        let r0 = rotate(&a, &roles_up_to(Role::Admin), &derived, &Secrets::default(), &members, &|_, _| true, &mut rng(1)).unwrap();
        let (mut s0, mut k0, mut a1v) = (Secrets::default(), Keys::default(), derived);
        r0.secrets.apply(&mut s0);
        r0.keys.apply(&mut k0);
        r0.record(&mut a1v);
        let mut a2v = ActorEpochs::default();
        ingest(&a, &s0, &Opener::Actor { member: a2, epochs: &a2e }, &mut a2v, None).unwrap();
        assert!(r0.secrets.applied(&mut a2v, cid(1), (&r0.keys, &Keys::default())).unwrap());
        let e0 = r0.rotated[0].epoch;
        assert_eq!(a2v.read.current(), vec![e0]);
        assert_eq!(a2v.read.provenance(&e0), Some(Provenance::Chain));
        World { a, p, a2, m1, pe, a2e, m1e, a1v, s0, k0, a2v, e0, seed: 10 }
    }

    fn rcpt(&self, who: Tid) -> Recipient {
        match who {
            w if w == self.p => actor_rcpt(self.p, Role::Admin, &self.pe),
            w if w == self.a2 => actor_rcpt(self.a2, Role::Admin, &self.a2e),
            _ => actor_rcpt(self.m1, Role::Read, &self.m1e),
        }
    }

    /// A read rotation from `view` over `s` boxing `members`.
    fn rotate(&mut self, view: &ActorEpochs, s: &Secrets, members: &[Tid]) -> Rotation {
        self.seed += 1;
        let rc: Vec<Recipient> = members.iter().map(|m| self.rcpt(*m)).collect();
        rotate(&self.a, &read(), view, s, &rc, &|_, _| true, &mut rng(self.seed)).unwrap()
    }

    /// a1 removes m1: the removal commit's rotation (no box for m1), held by a1 only.
    fn remove_m1(&mut self) -> (Rotation, ActorEpochs, Secrets) {
        let (v0, s0) = (self.a1v.clone(), self.s0.clone());
        let r1 = self.rotate(&v0, &s0, &[self.p, self.a2]);
        let (mut v, mut s) = (v0, s0);
        r1.secrets.apply(&mut s);
        r1.record(&mut v);
        (r1, v, s)
    }
}

// spec/crypto.md §4 (established; history boxes of established secrets only), spec/sync.md §5
// (register before upload), spec/permissions.md §3–§4 (stranded heartbeat, re-seal); TLC R9: a1
// re-seals a2 at e1 before e1's commit reaches a2. a2 holds e1's secret but not the removal: it
// boxes e1 nowhere (re-seal, grant, history box), so m1 opens nothing of e1 through a2's fork.
#[test]
fn r9_reseal_before_rotation_commit() {
    let mut w = World::new();
    let (r1, a1v1, s1) = w.remove_m1();
    let e1 = r1.rotated[0].epoch;
    // a2 is stranded at the head (e1 registered, its commit not uploaded); a1 re-seals it.
    let reseal = reseal_member(&w.a, &a1v1, &s1, &w.rcpt(w.a2), &read(), &mut rng(2)).unwrap().unwrap();
    assert!(reseal.history.contains_key(&history_key(Role::Read, &e1)));
    let mut s2 = w.s0.clone();
    reseal.apply(&mut s2);
    let mut a2v = w.a2v.clone();
    assert!(!reseal.applied(&mut a2v, cid(3), (&KeysWrite::default(), &w.k0)).unwrap());
    ingest(&w.a, &s2, &Opener::Actor { member: w.a2, epochs: &w.a2e }, &mut a2v, None).unwrap();
    assert!(a2v.read.secret(&e1).is_some());
    assert!(!a2v.read.is_established(&e1));
    assert_eq!(a2v.read.current(), vec![w.e0]);
    assert!(!may_compact_secrets(&s2, &a2v).unwrap());

    // In the window a2 re-seals and grants at e0 only.
    let g = actor_rcpt(tid(5), Role::Read, &person(0x50));
    for out in [reseal_member(&w.a, &a2v, &s2, &g, &read(), &mut rng(3)), box_member(&w.a, &a2v, &s2, &g, &read(), &mut rng(4))] {
        let out = out.unwrap().unwrap();
        assert!(out.boxes.keys().all(|k| k.epoch == to_schema(&w.e0)));
        assert!(!out.history.contains_key(&history_key(Role::Read, &e1)));
    }

    // a2 rotates (a fork with e1), boxing m1: it does not know the removal.
    let r2 = w.rotate(&a2v, &s2, &[w.p, w.a2, w.m1]);
    let e2 = r2.rotated[0].epoch;
    assert_eq!(r2.rotated[0].supersedes, [w.e0].into_iter().collect());
    assert_eq!(e2.n(), e1.n(), "a fork: n from established epochs only");
    let mut s3 = s2.clone();
    r2.secrets.apply(&mut s3);
    r2.record(&mut a2v);
    let mut m1v = ActorEpochs::default();
    ingest(&w.a, &s3, &Opener::Actor { member: w.m1, epochs: &w.m1e }, &mut m1v, None).unwrap();
    assert!(m1v.read.secret(&e2).is_some());
    assert!(m1v.read.secret(&e1).is_none(), "e2's history box carries e1");

    // e1's commit reaches a2: established, and e2 (boxing m1) no longer covers the departure.
    assert!(r1.secrets.applied(&mut a2v, cid(4), (&r1.keys, &w.k0)).unwrap());
    r1.secrets.apply(&mut s3);
    assert_eq!(a2v.read.provenance(&e1), Some(Provenance::Chain));
    let deps = [Departure::member(w.m1, Role::Read)];
    let none = MemoryHeldActors::default();
    assert!(!may_encrypt_under(&s3, &a2v, Role::Read, &e2, &deps, &none));
    assert!(may_encrypt_under(&s3, &a2v, Role::Read, &e1, &deps, &none));
}

// spec/crypto.md §4, spec/permissions.md §3; TLC `MC_reorder`: a1 removes m1 (e1) and rotates
// again (e2), registering before uploading; a1 re-seals stranded a2 at e2, so a2 holds e1's
// secret by e2's history box. a2 gets e2's commit from a peer, not e1's: neither is established,
// a complete pass reports no re-seal of m1 and none can box e2. Once e1 arrives, both are.
#[test]
fn reorder_holding_e2_without_e1() {
    let mut w = World::new();
    let (r1, a1v1, s1) = w.remove_m1();
    let e1 = r1.rotated[0].epoch;
    let r2 = w.rotate(&a1v1, &s1, &[w.p, w.a2]);
    let e2 = r2.rotated[0].epoch;
    let (mut a1v2, mut s1b) = (a1v1.clone(), s1.clone());
    r2.secrets.apply(&mut s1b);
    r2.record(&mut a1v2);
    let reseal = reseal_member(&w.a, &a1v2, &s1b, &w.rcpt(w.a2), &read(), &mut rng(2)).unwrap().unwrap();

    // a2: the re-seal, then e2's commit from peer a1.
    let mut s2 = w.s0.clone();
    reseal.apply(&mut s2);
    r2.secrets.apply(&mut s2);
    let mut a2v = w.a2v.clone();
    reseal.applied(&mut a2v, cid(3), (&KeysWrite::default(), &w.k0)).unwrap();
    r2.secrets.applied(&mut a2v, cid(5), (&r2.keys, &w.k0)).unwrap();
    ingest(&w.a, &s2, &Opener::Actor { member: w.a2, epochs: &w.a2e }, &mut a2v, None).unwrap();
    // e1's secret from the history box e2's applied rotation commit wrote
    assert!(a2v.read.secret(&e1).is_some() && a2v.read.secret(&e2).is_some());
    assert!(!a2v.read.is_established(&e1) && !a2v.read.is_established(&e2));
    assert_eq!(a2v.read.current(), vec![w.e0]);
    assert!(!may_compact_secrets(&s2, &a2v).unwrap());

    // A complete pass with m1 still a member as a2 sees it: no re-seal, and none boxes e2.
    let members = [
        Member { member: w.p, role: Role::Admin, until: None },
        Member { member: w.a2, role: Role::Admin, until: None },
        Member { member: w.m1, role: Role::Read, until: None },
    ];
    assert!(reseal_needed(&s2, &a2v, &members, WallMs(0), &|_, _, _| true).is_empty());
    let out = reseal_member(&w.a, &a2v, &s2, &w.rcpt(w.m1), &read(), &mut rng(3)).unwrap().unwrap();
    assert!(!out.boxes.contains_key(&box_key(w.m1, Role::Read, &e2)));
    assert!(!out.history.contains_key(&history_key(Role::Read, &e2)));

    // e1 arrives (with the removal): both established, e2 current.
    assert!(r1.secrets.applied(&mut a2v, cid(4), (&r1.keys, &w.k0)).unwrap());
    assert_eq!(a2v.read.secret(&e1), a1v1.read.secret(&e1));
    assert_eq!(a2v.read.provenance(&e1), Some(Provenance::Chain));
    assert_eq!(a2v.read.provenance(&e2), Some(Provenance::Chain));
    assert_eq!(a2v.read.current(), vec![e2]);
    let mut s3 = w.s0.clone();
    for x in [&reseal, &r1.secrets, &r2.secrets] {
        x.apply(&mut s3);
    }
    assert!(may_compact_secrets(&s3, &a2v).unwrap());
}

// spec/crypto.md §4 (snapshot establishment), spec/permissions.md §3: a node holding only a
// compaction snapshot after m1's removal does not re-seal a raced grantee at the
// snapshot-established epoch (it may rotate instead); a grant there is allowed. Once the rotation
// commit is applied the epoch is chain-established and the re-seal is due.
#[test]
fn snapshot_established_no_reseal() {
    let mut w = World::new();
    let (r1, _, s1) = w.remove_m1();
    let e1 = r1.rotated[0].epoch;
    let (g, ge) = (tid(5), person(0x50));
    let mut v = ActorEpochs::default();
    ingest(&w.a, &s1, &Opener::Actor { member: w.a2, epochs: &w.a2e }, &mut v, None).unwrap();
    assert!(v.read.current().is_empty());
    assert!(snapshot_keyed(&s1, &mut v).unwrap());
    assert_eq!(v.read.current(), vec![e1]);
    assert!(v.read.newest_is_snapshot());
    assert!(may_compact_secrets(&s1, &v).unwrap());
    let members = [Member { member: g, role: Role::Read, until: None }];
    assert!(reseal_needed(&s1, &v, &members, WallMs(0), &|_, _, _| true).is_empty());
    let rc = actor_rcpt(g, Role::Read, &ge);
    assert!(matches!(reseal_member(&w.a, &v, &s1, &rc, &read(), &mut rng(2)), Err(Error::NoSecret(Role::Read))));
    assert!(box_member(&w.a, &v, &s1, &rc, &read(), &mut rng(3)).unwrap().is_some());
    // The rotation commit applied: e0 (keyed by its history box in the snapshot) is established,
    // so e1 is chain-established.
    assert!(r1.secrets.applied(&mut v, cid(4), (&r1.keys, &w.k0)).unwrap());
    assert_eq!(v.read.provenance(&e1), Some(Provenance::Chain));
    assert!(!v.read.newest_is_snapshot());
    assert_eq!(reseal_needed(&s1, &v, &members, WallMs(0), &|_, _, _| true), vec![(g, read())]);
    assert!(reseal_member(&w.a, &v, &s1, &rc, &read(), &mut rng(4)).unwrap().is_some());
}

const TOP: u64 = i64::MAX as u64;

/// A box for a2 at an epoch of n `n` (the planter's choosing) under a made-up secret.
fn planted(w: &World, n: u64) -> (Epoch, Secrets) {
    let secret = osis_crypto::Secret32::from_bytes([0xee; 32]);
    let e = Epoch::derive(&w.a, Role::Read, n, &secret).unwrap();
    let mut v = ActorEpochs::default();
    v.read.set_secret(e, secret);
    v.read.set_established(e, Provenance::Own);
    let out = box_member(&w.a, &v, &Secrets::default(), &w.rcpt(w.a2), &read(), &mut rng(77)).unwrap().unwrap();
    let mut s = Secrets::default();
    out.apply(&mut s);
    (e, s)
}

// spec/crypto.md §4 (a rotation's n is 1 + the greatest n it supersedes; a pending commit's
// secrets are kept for reading only): epochs seen only in an unchecked commit (an unopenable box,
// a reading-only candidate) or named by an applied box without establishing are never a base for
// n, even at the top of the int range; an unchecked source leaves nothing behind once dropped.
#[test]
fn planted_epochs_never_base_a_rotation() {
    let mut w = World::new();
    let mut v = w.a2v.clone();
    let from = osis_keys::Unchecked { author: osis_keys::UNKNOWN_AUTHOR, commit: osis_base::CommitId([9; 32]) };
    // an unopenable box at the top (keyed to someone else): no entry at all
    let (top, mut s) = planted(&w, TOP);
    let k = s.boxes.keys().next().unwrap().clone();
    let b = s.boxes.remove(&k).unwrap();
    s.boxes.insert(box_key(w.m1, Role::Read, &top), b);
    ingest(&w.a, &s, &Opener::Actor { member: w.a2, epochs: &w.a2e }, &mut v, Some(from)).unwrap();
    assert!(v.read.get(&top).is_none(), "an unchecked box records no epoch");
    // an openable one: reading-only, never a base
    let (_, s) = planted(&w, TOP);
    ingest(&w.a, &s, &Opener::Actor { member: w.a2, epochs: &w.a2e }, &mut v, Some(from)).unwrap();
    assert!(v.read.is_reading_only(&top));
    // an applied box naming an epoch establishes nothing
    let other = Epoch::new(TOP, [2; 32]).unwrap();
    v.read.observe(other);
    let r = w.rotate(&v, &w.s0.clone(), &[w.p, w.a2]);
    assert_eq!(r.rotated[0].epoch.n(), w.e0.n() + 1);
    assert_eq!(r.rotated[0].supersedes, [w.e0].into_iter().collect());
    // the pending commit dropped: its epoch goes with its secret
    assert!(v.drop_reading_from(&from.commit));
    assert!(v.read.get(&top).is_none());
    assert!(v.read.get(&other).is_some(), "an entry the pending commit did not give stays");
}

// spec/crypto.md §4 (headroom): an applied rotation commit or a snapshot naming an epoch above
// `MAX_FREE_N` establishes it only next to an established epoch at n-1 or above, so a writer
// jumping to the top of the int range blocks no later rotation; a jump within the headroom
// establishes and later rotations count up from it.
#[test]
fn jumped_epochs_keep_rotation_possible() {
    let mut w = World::new();
    let mut v = w.a2v.clone();
    let top = Epoch::new(TOP, [1; 32]).unwrap();
    v.read.set_applied(top, cid(7), [w.e0]);
    v.read.set_snapshot(Epoch::new(TOP - 1, [1; 32]).unwrap());
    v.establish();
    assert!(!v.read.is_established(&top));
    assert_eq!(v.read.current(), vec![w.e0]);
    let r = w.rotate(&v, &w.s0.clone(), &[w.p, w.a2]);
    assert_eq!(r.rotated[0].epoch.n(), w.e0.n() + 1);
    // within the headroom: established, and the chain goes on above it
    let free = Epoch::new(osis_keys::MAX_FREE_N, [1; 32]).unwrap();
    v.read.set_applied(free, cid(8), [w.e0]);
    v.establish();
    assert_eq!(v.read.current(), vec![free]);
    let next = Epoch::new(osis_keys::MAX_FREE_N + 1, [1; 32]).unwrap();
    let skip = Epoch::new(osis_keys::MAX_FREE_N + 3, [1; 32]).unwrap();
    v.read.set_applied(next, cid(9), [free]);
    v.read.set_applied(skip, cid(10), [free]);
    v.establish();
    assert!(v.read.is_established(&next) && !v.read.is_established(&skip));
}

// spec/crypto.md §3, §4 (headroom): a writer of the owner jumped its epochs past `MAX_FREE_N`;
// a thing switching to secrets of its own still starts its chain at `MAX_FREE_N` at most (derived
// epochs are capped below it), so a member holding no secret of the owner establishes the switch from the
// rotation commit alone and the headroom rule needs nothing it cannot check.
#[test]
fn switch_under_jumped_owner_establishes_at_members() {
    let (a, p, m) = (tid(1), tid(2), tid(3));
    let high = osis_keys::MAX_FREE_N + 5;
    let mut pe = ActorEpochs::default();
    for (i, r) in osis_keys::ROLES.into_iter().enumerate() {
        pe.role_mut(r).set_secret(ep(high, 0x20), osis_crypto::Secret32::from_bytes([0x20 + i as u8; 32]));
        pe.role_mut(r).set_established(ep(high, 0x20), Provenance::Own);
    }
    let me = person(0x30);
    let owner = Recipient { member: p, role: Role::Admin, keys: osis_keys::MemberKeys::from_keys(&keys_of(&pe)).unwrap().with_own(&pe) };
    let members = [owner, actor_rcpt(m, Role::Write, &me)];
    let rot = rotate(&a, &roles_up_to(Role::Admin), &ActorEpochs::derived(&pe, &a), &Secrets::default(), &members, &|_, _| true, &mut rng(1)).unwrap();
    let mut s = Secrets::default();
    rot.secrets.apply(&mut s);
    for (who, opener) in [(m, Opener::Actor { member: m, epochs: &me }), (p, Opener::Actor { member: p, epochs: &pe })] {
        let mut v = ActorEpochs::default();
        ingest(&a, &s, &opener, &mut v, None).unwrap();
        rot.secrets.applied(&mut v, cid(1), (&rot.keys, &Keys::default())).unwrap();
        for x in &rot.rotated {
            assert_eq!(x.epoch.n(), osis_keys::MAX_FREE_N);
            if who == p || x.role != Role::Admin {
                assert!(v.role(x.role).is_established(&x.epoch), "{who:?} {:?}", x.role);
                assert_eq!(v.role(x.role).newest(), Some(x.epoch));
            }
        }
    }
}

// spec/crypto.md §4 (a secret learned only from a pending commit is kept for reading): a pending
// commit's history box at an epoch the node holds checked (forgeable by any ex-holder of it)
// lists epochs that stay reading-only (bounded), supersede nothing, and leave with the commit.
#[test]
fn pending_history_box_plants_nothing() {
    let w = World::new();
    let mut v = w.a2v.clone();
    let s0 = v.read.secret(&w.e0).unwrap().clone();
    // (a history box lists only epochs below its own)
    let planted = osis_crypto::Secret32::from_bytes([0xee; 32]);
    let top = Epoch::derive(&w.a, Role::Read, w.e0.n() - 1, &planted).unwrap();
    let ct = osis_crypto::seal_history(&s0, &w.a, Role::Read, &w.e0, &[(top, planted)]).unwrap();
    let mut s = Secrets::default();
    s.history.insert(history_key(Role::Read, &w.e0), ct);
    let from = osis_keys::Unchecked { author: osis_keys::UNKNOWN_AUTHOR, commit: osis_base::CommitId([9; 32]) };
    ingest(&w.a, &s, &Opener::Actor { member: w.a2, epochs: &w.a2e }, &mut v, Some(from)).unwrap();
    assert!(v.read.is_reading_only(&top));
    assert!(!v.read.get(&w.e0).unwrap().supersedes.contains(&top));
    assert!(v.drop_reading_from(&from.commit));
    assert!(v.read.get(&top).is_none());
}

// spec/crypto.md §4 (established by an applied valid rotation commit): a holder re-claiming e0
// in a later valid commit (e0's keyset and a history box of its own) that is then found invalid
// leaves e0 established by its genuine rotation commit.
#[test]
fn reclaim_then_invalidated_keeps_chain() {
    let w = World::new();
    let mut v = w.a2v.clone();
    let s0 = v.read.secret(&w.e0).unwrap().clone();
    let mut again = osis_keys::SecretsWrite::default();
    again.history.insert(history_key(Role::Read, &w.e0), osis_crypto::seal_history(&s0, &w.a, Role::Read, &w.e0, &[]).unwrap());
    let ks = KeysWrite { keysets: [(Role::Read, osis_keys::keyset(&w.e0, &s0))].into_iter().collect() };
    assert!(again.applied(&mut v, cid(2), (&ks, &w.k0)).unwrap());
    assert_eq!(v.read.get(&w.e0).unwrap().applied.len(), 2);
    v.unset_applied(&cid(2));
    v.establish();
    assert_eq!(v.read.provenance(&w.e0), Some(Provenance::Chain));
    assert_eq!(v.read.current(), vec![w.e0]);
    // the genuine one invalidated too: e0 is no longer established by chain
    v.unset_applied(&cid(1));
    v.establish();
    assert!(!v.read.is_established(&w.e0));
}
