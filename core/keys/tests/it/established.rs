#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Established epochs (spec/crypto.md §4; spec/permissions.md §3 re-seal): the TLC traces of
//! core/test/tla/rotation/AMBIGUITIES.md (R9, `MC_reorder`), snapshot establishment, the `secrets.0`
//! compaction gate.

use crate::common::Applied;
use crate::common;
use common::*;
use osis_base::{Role, Tid};
use osis_keys::aspects::{box_key, history_key, to_schema};
use osis_keys::{
    ActorEpochs, Departure, KeysWrite, Holder, Names, Opener, Provenance, Recipient, Rotation, box_holder, ingest,
    may_compact_secrets, may_encrypt_under, reseal_needed, roles_up_to, rotate, snapshot_keyed,
};
use osis_crypto::Epoch;
use osis_schema::core_types::Secrets;
use std::collections::BTreeSet;

fn cid(b: u8) -> osis_base::CommitId {
    osis_base::CommitId([b; 32])
}

fn read() -> BTreeSet<Role> {
    [Role::Read].into_iter().collect()
}

/// The name of a1's removal of m1 (`World::remove_m1`, commit `cid(4)`).
fn r1_name(w: &World) -> osis_keys::Name {
    osis_keys::Name { thing: w.a, key: osis_keys::Key { ts: 4, node: tid(9), commit: cid(4) } }
}

/// Holds the commits listed; every rotator holds its role.
struct Holding(BTreeSet<osis_base::CommitId>);

impl osis_keys::Held for Holding {
    fn met(&self, n: &osis_keys::Name) -> bool {
        self.0.contains(&n.key.commit)
    }
    fn holds(&self, _: &osis_base::Tid, _: Role) -> bool {
        true
    }
    fn departed(&self, own: &osis_keys::Own) -> bool {
        u8::try_from(own.ts).is_ok_and(|b| self.0.contains(&cid(b)))
    }
    fn publishes(&self, _: Role, _: &Epoch, _: &osis_keys::NamesDigest) -> bool {
        true
    }
}

/// Actor A (first admin P); holders a2 (admin, a co-admin's actor) and m1 (read). Node a1 (one of
/// P's nodes) made A's secrets; node a2 applied that commit.
struct World {
    a: Tid,
    p: Tid,
    a2: Tid,
    m1: Tid,
    pe: ActorEpochs,
    a2e: ActorEpochs,
    m1e: ActorEpochs,
    /// a1's view and A's `secrets.0` after the first rotation.
    a1v: ActorEpochs,
    s0: Secrets,
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
        let holders = [actor_rcpt(p, Role::Admin, &pe), actor_rcpt(a2, Role::Admin, &a2e), actor_rcpt(m1, Role::Read, &m1e)];
        let r0 = rotate(&a, &roles_up_to(Role::Admin), &derived, &Secrets::default(), &holders, &osis_keys::Names::default(), &mut rng(1)).unwrap();
        let (mut s0, mut a1v) = (Secrets::default(), derived);
        r0.secrets.apply(&mut s0);
        a1v = applied(&r0, &a1v, 1);
        let mut a2v = ActorEpochs::default();
        ingest(&a, &s0, &Opener::Actor { holder: a2, epochs: &a2e }, &mut a2v, None).unwrap();
        assert!(r0.secrets.applied(&mut a2v, cid(1), &r0.keys).unwrap());
        let e0 = r0.rotated[0].epoch;
        assert_eq!(a2v.read.current(), vec![e0]);
        assert_eq!(a2v.read.provenance(&e0), Some(Provenance::Rotated));
        World { a, p, a2, m1, pe, a2e, m1e, a1v, s0, a2v, e0, seed: 10 }
    }

    fn rcpt(&self, who: Tid) -> Recipient {
        match who {
            w if w == self.p => actor_rcpt(self.p, Role::Admin, &self.pe),
            w if w == self.a2 => actor_rcpt(self.a2, Role::Admin, &self.a2e),
            _ => actor_rcpt(self.m1, Role::Read, &self.m1e),
        }
    }

    /// A read rotation from `view` over `s` boxing `holders`, naming `names`.
    fn rotate_naming(&mut self, view: &ActorEpochs, s: &Secrets, holders: &[Tid], names: &Names) -> Rotation {
        self.seed += 1;
        let rc: Vec<Recipient> = holders.iter().map(|m| self.rcpt(*m)).collect();
        rotate(&self.a, &read(), view, s, &rc, names, &mut rng(self.seed)).unwrap()
    }

    /// A read rotation naming nothing.
    fn rotate(&mut self, view: &ActorEpochs, s: &Secrets, holders: &[Tid]) -> Rotation {
        self.rotate_naming(view, s, holders, &Names::default())
    }

    /// a1 removes m1 (commit `cid(4)`): the removal commit's rotation (no box for m1, its names'
    /// departs mark set), held by a1 only.
    fn remove_m1(&mut self) -> (Rotation, ActorEpochs, Secrets) {
        let (v0, s0) = (self.a1v.clone(), self.s0.clone());
        let r1 = self.rotate_naming(&v0, &s0, &[self.p, self.a2], &Names { departs: Some(osis_keys::Own { ts: 4, node: tid(9) }), ..Names::default() });
        let (mut v, mut s) = (v0, s0);
        r1.secrets.apply(&mut s);
        v = applied(&r1, &v, 4);
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
    let reseal = box_holder(&w.a, &a1v1, &hist(&w.a, &a1v1, &s1), &w.rcpt(w.a2), &read(), &mut rng(2)).unwrap().unwrap();
    assert!(reseal.history.contains_key(&history_key(Role::Read, &e1)));
    let mut s2 = w.s0.clone();
    reseal.apply(&mut s2);
    let mut a2v = w.a2v.clone();
    assert!(!reseal.applied(&mut a2v, cid(3), &KeysWrite::default()).unwrap());
    ingest(&w.a, &s2, &Opener::Actor { holder: w.a2, epochs: &w.a2e }, &mut a2v, None).unwrap();
    assert!(a2v.read.secret(&e1).is_some());
    assert!(!a2v.read.is_established(&e1));
    assert_eq!(a2v.read.current(), vec![w.e0]);
    assert!(!may_compact_secrets(&s2, &a2v).unwrap());

    // In the window a2 re-seals and grants at e0 only.
    let g = actor_rcpt(tid(5), Role::Read, &person(0x50));
    for out in [box_holder(&w.a, &a2v, &hist(&w.a, &a2v, &s2), &g, &read(), &mut rng(3)), box_holder(&w.a, &a2v, &hist(&w.a, &a2v, &s2), &g, &read(), &mut rng(4))] {
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
    a2v = r2.preview(&a2v).unwrap();
    let mut m1v = ActorEpochs::default();
    ingest(&w.a, &s3, &Opener::Actor { holder: w.m1, epochs: &w.m1e }, &mut m1v, None).unwrap();
    assert!(m1v.read.secret(&e2).is_some());
    assert!(m1v.read.secret(&e1).is_none(), "e2's history box carries e1");

    // e1's commit reaches a2: established, and e2 (its rotator did not know it) does not cover the
    // departure; e1 does (its own rotation commit).
    assert!(r1.secrets.applied(&mut a2v, cid(4), &r1.keys).unwrap());
    r1.secrets.apply(&mut s3);
    ingest(&w.a, &s3, &Opener::Actor { holder: w.a2, epochs: &w.a2e }, &mut a2v, None).unwrap();
    assert_eq!(a2v.read.provenance(&e1), Some(Provenance::Rotated));
    let deps = [Departure::holder(w.m1, Role::Read).at(Some(r1_name(&w)))];
    let all = osis_keys::AllHeld;
    assert!(!may_encrypt_under(&w.a, &a2v, Role::Read, &e2, &deps, &all));
    assert!(may_encrypt_under(&w.a, &a2v, Role::Read, &e1, &deps, &all));
}

// spec/crypto.md §4 (names), spec/permissions.md §3; TLC `MC_reorder`: a1 removes m1 (e1, commit
// R1) and rotates again (e2, naming R1), registering before uploading; a1 re-seals stranded a2 at
// e2, so a2 holds e1's secret by e2's history box. a2 gets e2's commit from a peer, not R1:
// neither is established (e2's names unmet), a complete pass reports no re-seal of m1 and none
// can box e2. Once R1 arrives, both are.
#[test]
fn reorder_holding_e2_without_e1() {
    let mut w = World::new();
    let (r1, a1v1, s1) = w.remove_m1();
    let e1 = r1.rotated[0].epoch;
    let names = Names { list: [r1_name(&w)].into(), departs: None };
    let r2 = w.rotate_naming(&a1v1, &s1, &[w.p, w.a2], &names);
    let e2 = r2.rotated[0].epoch;
    let (mut a1v2, mut s1b) = (a1v1.clone(), s1.clone());
    r2.secrets.apply(&mut s1b);
    a1v2 = r2.preview(&a1v2).unwrap();
    let reseal = box_holder(&w.a, &a1v2, &hist(&w.a, &a1v2, &s1b), &w.rcpt(w.a2), &read(), &mut rng(2)).unwrap().unwrap();

    // a2: the re-seal, then e2's commit from peer a1.
    let mut s2 = w.s0.clone();
    reseal.apply(&mut s2);
    r2.secrets.apply(&mut s2);
    let mut a2v = w.a2v.clone();
    let without_r1 = Holding([cid(1), cid(3), cid(5)].into());
    reseal.rotated(&mut a2v, cid(3), &KeysWrite::default()).unwrap();
    r2.secrets.rotated(&mut a2v, cid(5), &r2.keys).unwrap();
    ingest(&w.a, &s2, &Opener::Actor { holder: w.a2, epochs: &w.a2e }, &mut a2v, None).unwrap();
    a2v.establish(&without_r1);
    // e1's secret from the history box e2's applied rotation commit wrote
    assert!(a2v.read.secret(&e1).is_some() && a2v.read.secret(&e2).is_some());
    assert!(!a2v.read.is_established(&e1) && !a2v.read.is_established(&e2));
    assert_eq!(a2v.read.current(), vec![w.e0]);
    assert!(!may_compact_secrets(&s2, &a2v).unwrap());

    // A complete pass with m1 still a holder as a2 sees it: no re-seal, and none boxes e2.
    let holders = [
        Holder { holder: w.p, role: Role::Admin },
        Holder { holder: w.a2, role: Role::Admin },
        Holder { holder: w.m1, role: Role::Read },
    ];
    assert!(reseal_needed(&s2, &a2v, &holders).is_empty());
    let out = box_holder(&w.a, &a2v, &hist(&w.a, &a2v, &s2), &w.rcpt(w.m1), &read(), &mut rng(3)).unwrap().unwrap();
    assert!(!out.boxes.contains_key(&box_key(w.m1, Role::Read, &e2)));
    assert!(!out.history.contains_key(&history_key(Role::Read, &e2)));

    // R1 arrives (the removal, with e1's history box): both established, e2 current.
    let mut s3 = w.s0.clone();
    for x in [&reseal, &r1.secrets, &r2.secrets] {
        x.apply(&mut s3);
    }
    ingest(&w.a, &s3, &Opener::Actor { holder: w.a2, epochs: &w.a2e }, &mut a2v, None).unwrap();
    assert!(r1.secrets.applied(&mut a2v, cid(4), &r1.keys).unwrap());
    assert_eq!(a2v.read.secret(&e1), a1v1.read.secret(&e1));
    assert_eq!(a2v.read.provenance(&e1), Some(Provenance::Rotated));
    assert_eq!(a2v.read.provenance(&e2), Some(Provenance::Rotated));
    assert_eq!(a2v.read.current(), vec![e2]);
    assert!(may_compact_secrets(&s3, &a2v).unwrap());
}

// spec/crypto.md §4 (snapshot establishment; names: the departing commit), spec/permissions.md
// §3: a node holding only a compaction snapshot keying e1, made by m1's removal R1, does not use
// e1 while it does not hold R1. Once it does, e1 is established and a raced grantee is re-sealed
// at it like at any other.
#[test]
fn snapshot_established_needs_departure() {
    let mut w = World::new();
    let (r1, _, s1) = w.remove_m1();
    let e1 = r1.rotated[0].epoch;
    let (g, ge) = (tid(5), person(0x50));
    let mut v = ActorEpochs::default();
    ingest(&w.a, &s1, &Opener::Actor { holder: w.a2, epochs: &w.a2e }, &mut v, None).unwrap();
    assert!(v.read.current().is_empty());
    assert!(snapshot_keyed(&s1, osis_base::CommitId([1; 32]), &mut v).unwrap());
    let holders = [Holder { holder: g, role: Role::Read }];
    let rc = actor_rcpt(g, Role::Read, &ge);
    v.establish(&Holding(BTreeSet::new()));
    assert!(!v.read.is_established(&e1), "the removal not held");
    assert!(!may_compact_secrets(&s1, &v).unwrap());
    // e0 (keyed by its history box, its names met) is current: boxed there only
    assert_eq!(v.read.current(), vec![w.e0]);
    let out = box_holder(&w.a, &v, &hist(&w.a, &v, &s1), &rc, &read(), &mut rng(2)).unwrap().unwrap();
    assert!(out.boxes.keys().all(|k| k.epoch == to_schema(&w.e0)));
    // the removal held (its edge write: its secrets.0 body may be compacted away)
    v.establish(&Holding([cid(4)].into()));
    assert_eq!(v.read.provenance(&e1), Some(Provenance::Rotated));
    assert_eq!(v.read.current(), vec![e1]);
    assert!(may_compact_secrets(&s1, &v).unwrap());
    assert_eq!(reseal_needed(&s1, &v, &holders), vec![(g, read())]);
    assert!(box_holder(&w.a, &v, &hist(&w.a, &v, &s1), &rc, &read(), &mut rng(3)).unwrap().is_some());
}

const TOP: u64 = i64::MAX as u64;

/// A box for a2 at an epoch of n `n` (the planter's choosing) under a made-up secret.
fn planted(w: &World, n: u64) -> (Epoch, Secrets) {
    let secret = osis_crypto::Secret32::from_bytes([0xee; 32]);
    let e = Epoch::derive(&w.a, Role::Read, n, &secret).unwrap();
    let mut v = ActorEpochs::default();
    v.read.set_secret(e, secret);
    v.read.set_established(e, Provenance::Fixed);
    let out = box_holder(&w.a, &v, &hist(&w.a, &v, &Secrets::default()), &w.rcpt(w.a2), &read(), &mut rng(77)).unwrap().unwrap();
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
    ingest(&w.a, &s, &Opener::Actor { holder: w.a2, epochs: &w.a2e }, &mut v, Some(from)).unwrap();
    assert!(v.read.get(&top).is_none(), "an unchecked box records no epoch");
    // an openable one: reading-only, never a base
    let (_, s) = planted(&w, TOP);
    ingest(&w.a, &s, &Opener::Actor { holder: w.a2, epochs: &w.a2e }, &mut v, Some(from)).unwrap();
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
    v.read.set_rotation(top, cid(7), [w.e0].into());
    v.read.set_snapshot(Epoch::new(TOP - 1, [1; 32]).unwrap(), osis_base::CommitId([1; 32]));
    v.establish(&osis_keys::AllHeld);
    assert!(!v.read.is_established(&top));
    assert_eq!(v.read.current(), vec![w.e0]);
    let r = w.rotate(&v, &w.s0.clone(), &[w.p, w.a2]);
    assert_eq!(r.rotated[0].epoch.n(), w.e0.n() + 1);
    // within the headroom: established, and the chain goes on above it
    let free = Epoch::new(osis_keys::MAX_FREE_N, [1; 32]).unwrap();
    v.read.set_rotation(free, cid(8), [w.e0].into());
    v.establish(&osis_keys::AllHeld);
    assert_eq!(v.read.current(), vec![free]);
    let next = Epoch::new(osis_keys::MAX_FREE_N + 1, [1; 32]).unwrap();
    let skip = Epoch::new(osis_keys::MAX_FREE_N + 3, [1; 32]).unwrap();
    v.read.set_rotation(next, cid(9), [free].into());
    v.read.set_rotation(skip, cid(10), [free].into());
    v.establish(&osis_keys::AllHeld);
    assert!(v.read.is_established(&next) && !v.read.is_established(&skip));
}

// spec/crypto.md §3, §4 (headroom): a writer of the base actor jumped its epochs past `MAX_FREE_N`;
// a thing switching to secrets of its own still starts its chain at `MAX_FREE_N` at most (derived
// epochs are capped below it), so a holder holding no secret of the base actor establishes the switch from the
// rotation commit alone and the headroom rule needs nothing it cannot check.
#[test]
fn switch_under_jumped_base_establishes_at_holders() {
    let (a, p, m) = (tid(1), tid(2), tid(3));
    let high = osis_keys::MAX_FREE_N + 5;
    let mut pe = ActorEpochs::default();
    for (i, r) in osis_keys::ROLES.into_iter().enumerate() {
        pe.role_mut(r).set_secret(ep(high, 0x20), osis_crypto::Secret32::from_bytes([0x20 + i as u8; 32]));
        pe.role_mut(r).set_established(ep(high, 0x20), Provenance::Fixed);
    }
    let me = person(0x30);
    let admin = Recipient { holder: p, role: Role::Admin, keys: osis_keys::HolderKeys::from_keys(&keys_of(&pe)).unwrap().with_own(&pe) };
    let holders = [admin, actor_rcpt(m, Role::Write, &me)];
    let rot = rotate(&a, &roles_up_to(Role::Admin), &ActorEpochs::derived(&pe, &a), &Secrets::default(), &holders, &osis_keys::Names::default(), &mut rng(1)).unwrap();
    let mut s = Secrets::default();
    rot.secrets.apply(&mut s);
    for (who, opener) in [(m, Opener::Actor { holder: m, epochs: &me }), (p, Opener::Actor { holder: p, epochs: &pe })] {
        let mut v = ActorEpochs::default();
        ingest(&a, &s, &opener, &mut v, None).unwrap();
        rot.secrets.applied(&mut v, cid(1), &rot.keys).unwrap();
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
    let ct = osis_crypto::seal_history(&s0, &w.a, Role::Read, &w.e0, &[(top, planted)], &osis_keys::Names::default().to_value()).unwrap();
    let mut s = Secrets::default();
    s.history.insert(history_key(Role::Read, &w.e0), ct);
    let from = osis_keys::Unchecked { author: osis_keys::UNKNOWN_AUTHOR, commit: osis_base::CommitId([9; 32]) };
    ingest(&w.a, &s, &Opener::Actor { holder: w.a2, epochs: &w.a2e }, &mut v, Some(from)).unwrap();
    assert!(v.read.is_reading_only(&top));
    assert!(!v.read.get(&w.e0).unwrap().supersedes.contains(&top));
    assert!(v.drop_reading_from(&from.commit));
    assert!(v.read.get(&top).is_none());
}

// spec/crypto.md §4 (established by an applied valid rotation commit): a holder writing e0's
// keyset again in a later valid commit (with a history box of its own) that is then found invalid
// leaves e0 established by its genuine rotation commit.
#[test]
fn rewrite_then_invalidated_keeps_rotation() {
    let w = World::new();
    let mut v = w.a2v.clone();
    let s0 = v.read.secret(&w.e0).unwrap().clone();
    let mut again = osis_keys::SecretsWrite::default();
    again.history.insert(history_key(Role::Read, &w.e0), osis_crypto::seal_history(&s0, &w.a, Role::Read, &w.e0, &[], &osis_keys::Names::default().to_value()).unwrap());
    let ks = KeysWrite { keysets: [(Role::Read, osis_keys::keyset(&w.e0, &s0, &Default::default(), &Default::default()))].into_iter().collect() };
    assert!(again.applied(&mut v, cid(2), &ks).unwrap());
    assert_eq!(v.read.get(&w.e0).unwrap().rotations.len(), 2);
    v.invalidate(&cid(2));
    v.establish(&osis_keys::AllHeld);
    assert_eq!(v.read.provenance(&w.e0), Some(Provenance::Rotated));
    assert_eq!(v.read.current(), vec![w.e0]);
    // the genuine one invalidated too: e0 is no longer established
    v.invalidate(&cid(1));
    v.establish(&osis_keys::AllHeld);
    assert!(!v.read.is_established(&w.e0));
}
