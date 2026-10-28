#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Grants, re-seals, history re-writes, box checks and sizes (spec/crypto.md §4, spec/wire.md §7).

use crate::common;
use common::*;
use osis_core::Role;
use osis_crypto::{BoxItem, BoxSlot, Secret32, seal_box};
use osis_keys::aspects::{box_key, history_key, to_schema};
use osis_keys::{ActorEpochs, Error, MemberKeys, Opener, Recipient, ROLES, box_member, ingest, open_boxes, roles_up_to, rotate};
use osis_schema::core_types::{Sealed, SealedBox, SecretBox, Secrets};
use std::collections::BTreeSet;

/// An unchecked source: a pending commit by node `n`.
fn from(n: u8) -> osis_keys::Unchecked {
    osis_keys::Unchecked { author: osis_core::Tid::from_bytes([n; 15]), commit: osis_core::CommitId([n; 32]) }
}

struct Forked {
    a: osis_core::Tid,
    view: ActorEpochs,
    s: Secrets,
    forks: [osis_crypto::Epoch; 2],
}

/// Actor A (owner P, symmetric) after its own-secrets switch and a read fork.
fn forked() -> Forked {
    let (a, p) = (tid(1), tid(2));
    let pe = person(0x20);
    let owner = Recipient { member: p, role: Role::Admin, keys: MemberKeys::from_keys(&keys_of(&pe)).unwrap().with_own(&pe) };
    let mut view = ActorEpochs::derived(&pe, &a);
    let mut s = Secrets::default();
    let r1 = rotate(&a, &roles_up_to(Role::Admin), &view, &s, std::slice::from_ref(&owner), &|_, _| true, &mut rng(1)).unwrap();
    r1.secrets.apply(&mut s);
    r1.record(&mut view);
    let read: BTreeSet<Role> = [Role::Read].into_iter().collect();
    let x = rotate(&a, &read, &view, &s, std::slice::from_ref(&owner), &|_, _| true, &mut rng(2)).unwrap();
    let y = rotate(&a, &read, &view, &s, std::slice::from_ref(&owner), &|_, _| true, &mut rng(3)).unwrap();
    x.secrets.apply(&mut s);
    y.secrets.apply(&mut s);
    x.record(&mut view);
    y.record(&mut view);
    Forked { a, view, s, forks: [x.rotated[0].epoch, y.rotated[0].epoch] }
}

// spec/crypto.md §4: a grant writes the grantee's boxes for every granted role at each current
// epoch (forks included) and re-writes those epochs' history boxes unchanged; the grantee then
// reads every earlier epoch.
#[test]
fn grant_boxes_every_current_epoch() {
    let f = forked();
    let (g, ge) = (tid(5), person(0x50));
    let w = box_member(&f.a, &f.view, &f.s, &actor_rcpt(g, Role::Write, &ge), &roles_up_to(Role::Write), &mut rng(9)).unwrap().unwrap();
    let keys: BTreeSet<_> = w.boxes.keys().cloned().collect();
    let ew = f.view.write.newest().unwrap();
    let want: BTreeSet<_> = [box_key(g, Role::Read, &f.forks[0]), box_key(g, Role::Read, &f.forks[1]), box_key(g, Role::Write, &ew)].into_iter().collect();
    assert_eq!(keys, want);
    for (r, e) in [(Role::Read, f.forks[0]), (Role::Read, f.forks[1]), (Role::Write, ew)] {
        assert_eq!(w.history[&history_key(r, &e)], f.s.history[&history_key(r, &e)]);
    }
    assert!(w.removed.is_empty() && w.rotations(None).unwrap().iter().all(|(_, _, sup)| sup.is_empty()));
    let mut s = f.s.clone();
    w.apply(&mut s);
    let mut gv = ActorEpochs::default();
    assert!(ingest(&f.a, &s, &Opener::Actor { member: g, epochs: &ge }, &mut gv, None).unwrap().is_empty());
    for (e, _) in f.view.read.held() {
        assert!(gv.read.secret(&e).is_some(), "{e:?}");
    }
    assert!(gv.admin.held().next().is_none());
}

// spec/crypto.md §4: a key-actor grantee gets one box keyed at its highest role carrying each
// role's newest epoch.
#[test]
fn grant_to_key_actor() {
    let f = forked();
    let (k, seed) = (tid(6), Secret32::from_bytes([0x60; 32]));
    let w = box_member(&f.a, &f.view, &f.s, &key_rcpt(k, Role::Write, &seed), &roles_up_to(Role::Admin), &mut rng(9)).unwrap().unwrap();
    let ew = f.view.write.newest().unwrap();
    assert_eq!(w.boxes.keys().cloned().collect::<Vec<_>>(), vec![box_key(k, Role::Write, &ew)]);
    let mut s = f.s.clone();
    w.apply(&mut s);
    let mut kv = ActorEpochs::default();
    ingest(&f.a, &s, &Opener::KeyActor { member: k, seed: &seed }, &mut kv, None).unwrap();
    // Establishment from the state as a snapshot (the grantee's commits elided).
    osis_keys::snapshot_keyed(&s, &mut kv).unwrap();
    assert_eq!(kv.read.newest_held().map(|x| x.0), f.view.read.newest());
    assert_eq!(kv.write.newest_held().map(|x| x.0), Some(ew));
    // Its seed holder writes symmetric boxes instead, one per (role, epoch).
    let sym = Recipient { member: k, role: Role::Read, keys: MemberKeys::KeyActor { kem: osis_crypto::KeyActorKeys::from_seed(&seed).kem.public().clone(), seed: Some(seed.clone()) } };
    let w = box_member(&f.a, &f.view, &f.s, &sym, &roles_up_to(Role::Read), &mut rng(9)).unwrap().unwrap();
    assert_eq!(w.boxes.len(), 2);
    assert!(w.boxes.values().all(|b| matches!(b, SecretBox::Symmetric(x) if x.wrap.len() == 49)));
    let mut s = f.s.clone();
    w.apply(&mut s);
    let mut kv = ActorEpochs::default();
    ingest(&f.a, &s, &Opener::KeyActor { member: k, seed: &seed }, &mut kv, None).unwrap();
    assert!(f.forks.iter().all(|e| kv.read.secret(e).is_some()));
}

// spec/permissions.md §3: a re-seal goes to the member's newest keyset the node holds.
#[test]
fn reseal_to_newest_keyset() {
    let f = forked();
    let m = tid(3);
    let mut me = person(0x30);
    for (i, r) in ROLES.into_iter().enumerate() {
        me.role_mut(r).rotation(ep(2, 0x31), [ep(1, 0x30)]);
        me.role_mut(r).set_established(ep(2, 0x31), osis_keys::Provenance::Own);
        me.role_mut(r).set_secret(ep(2, 0x31), Secret32::from_bytes([0x70 + i as u8; 32]));
    }
    let read: BTreeSet<Role> = [Role::Read].into_iter().collect();
    let w = box_member(&f.a, &f.view, &f.s, &actor_rcpt(m, Role::Read, &me), &read, &mut rng(9)).unwrap().unwrap();
    for b in w.boxes.values() {
        let SecretBox::Sealed(b) = b else { panic!() };
        assert_eq!(b.keyset, Some(to_schema(&ep(2, 0x31))));
    }
    // Opening with only the old keyset's secret fails to find a key; the new one opens.
    let mut s = f.s.clone();
    w.apply(&mut s);
    let old = person(0x30);
    let (got, _) = open_boxes(&f.a, &s, &Opener::Actor { member: m, epochs: &old });
    assert!(got.is_empty());
    let (got, failed) = open_boxes(&f.a, &s, &Opener::Actor { member: m, epochs: &me });
    assert_eq!((got.len(), failed.len()), (2, 0));
    // No keyset known: nothing is boxed.
    let none = Recipient { member: m, role: Role::Read, keys: MemberKeys::Actor { keysets: Default::default(), own: Default::default() } };
    assert!(box_member(&f.a, &f.view, &f.s, &none, &read, &mut rng(9)).unwrap().is_none());
    // A granter holding no current secret of a role cannot grant it.
    let mut stale = f.view.clone();
    stale.read = Default::default();
    assert_eq!(box_member(&f.a, &stale, &f.s, &actor_rcpt(m, Role::Read, &me), &read, &mut rng(9)).unwrap_err(), Error::NoSecret(Role::Read));
}

// spec/wire.md §7: a box opens only at its own key; contents must match the key (role, epoch).
#[test]
fn box_checks() {
    let f = forked();
    let (m, me) = (tid(3), person(0x30));
    let read: BTreeSet<Role> = [Role::Read].into_iter().collect();
    let w = box_member(&f.a, &f.view, &f.s, &actor_rcpt(m, Role::Read, &me), &read, &mut rng(9)).unwrap().unwrap();
    // Moved to another key: decryption fails.
    let (k, b) = w.boxes.iter().next().unwrap();
    let mut moved = Secrets::default();
    let mut k2 = k.clone();
    k2.epoch = to_schema(&ep(9, 9));
    moved.boxes.insert(k2, b.clone());
    let (got, failed) = open_boxes(&f.a, &moved, &Opener::Actor { member: m, epochs: &me });
    assert!(got.is_empty() && matches!(failed[0].1, Error::Crypto(_)));
    // Payload naming another epoch than its key: rejected after opening.
    let slot = BoxSlot::Secrets { actor: f.a, member: m, role: Role::Read, epoch: f.forks[0] };
    let kem = osis_crypto::role_kem(me.read.secret(&ep(1, 0x30)).unwrap());
    let items = [BoxItem { role: Role::Read, epoch: ep(7, 7), secret: Secret32::from_bytes([1; 32]) }];
    let raw = seal_box(kem.public(), &slot, Some(ep(1, 0x30)), &items, &mut rng(1)).unwrap();
    let mut bad = Secrets::default();
    bad.boxes.insert(box_key(m, Role::Read, &f.forks[0]), SecretBox::Sealed(SealedBox { keyset: Some(to_schema(&ep(1, 0x30))), suite: 1, sealed: Sealed::X25519MlKem768(raw) }));
    let (got, failed) = open_boxes(&f.a, &bad, &Opener::Actor { member: m, epochs: &me });
    assert!(got.is_empty());
    assert_eq!(failed[0].1, Error::Mismatch("box items"));
}

// notes/crypto.md, Costs (spec/crypto.md §1, spec/wire.md §7): a sealed box is about 1.2 KB, a
// symmetric one 49 bytes plus its epoch.
#[test]
fn sizes() {
    let f = forked();
    let (m, me) = (tid(3), person(0x30));
    let w = box_member(&f.a, &f.view, &f.s, &actor_rcpt(m, Role::Read, &me), &roles_up_to(Role::Read), &mut rng(9)).unwrap().unwrap();
    for b in w.boxes.values() {
        let enc = osis_core::cbor::encode(&osis_schema::Codec::to_value(b));
        assert!((1200..1300).contains(&enc.len()), "{}", enc.len());
    }
    for (k, b) in f.s.boxes.iter().filter(|(k, _)| k.member == tid(2)) {
        let enc = osis_core::cbor::encode(&osis_schema::Codec::to_value(b));
        assert!(enc.len() < 100, "{k:?} {}", enc.len());
    }
}

// spec/crypto.md §4: "a secret learned only from a pending or invalid commit is kept for reading
// and never encrypted under until an applied valid box carries it". Boxes sealed to the grantee
// by someone holding other secrets (the unchecked set) yield reading-only secrets; no encrypting
// getter returns them, even once the epochs are established; the applied valid box replaces
// them, and a later unchecked box never replaces a checked secret.
#[test]
fn unchecked_boxes_are_reading_only() {
    let f = forked();
    let (g, ge) = (tid(5), person(0x50));
    let rcpt = actor_rcpt(g, Role::Read, &ge);
    let read = roles_up_to(Role::Read);
    let mut fake_view = f.view.clone();
    for e in f.forks {
        fake_view.read.set_secret(e, Secret32::from_bytes([0xee; 32]));
    }
    let fake = box_member(&f.a, &fake_view, &f.s, &rcpt, &read, &mut rng(8)).unwrap().unwrap();
    let mut s_fake = f.s.clone();
    fake.apply(&mut s_fake);
    let mut gv = ActorEpochs::default();
    ingest(&f.a, &s_fake, &Opener::Actor { member: g, epochs: &ge }, &mut gv, Some(from(1))).unwrap();
    for e in f.forks {
        assert_eq!(gv.read.reading_secrets(&e), vec![&Secret32::from_bytes([0xee; 32])]);
        assert!(gv.read.secret(&e).is_none() && gv.read.is_reading_only(&e));
        gv.read.set_established(e, osis_keys::Provenance::Chain);
    }
    assert!(gv.read.newest_held().is_none() && gv.read.newest_secret().is_none() && gv.read.held_established().next().is_none());
    assert_eq!(osis_keys::wrap_epoch(&gv.read), osis_keys::WrapEpoch::None);
    assert_eq!(gv.read.held_newest_first().len(), 2, "still tried for reading");
    // the applied valid grant replaces them
    let real = box_member(&f.a, &f.view, &f.s, &rcpt, &read, &mut rng(9)).unwrap().unwrap();
    let mut s = f.s.clone();
    real.apply(&mut s);
    ingest(&f.a, &s, &Opener::Actor { member: g, epochs: &ge }, &mut gv, None).unwrap();
    for e in f.forks {
        assert_eq!(gv.read.secret(&e), f.view.read.secret(&e));
    }
    assert_eq!(gv.read.newest_held().map(|x| x.0), f.view.read.newest());
    // an unchecked box arriving later changes nothing
    ingest(&f.a, &s_fake, &Opener::Actor { member: g, epochs: &ge }, &mut gv, Some(from(1))).unwrap();
    for e in f.forks {
        assert_eq!(gv.read.secret(&e), f.view.read.secret(&e));
    }
}

// spec/crypto.md §4: what a reading-only secret opens through history boxes is reading-only too,
// until the checked state carries it.
#[test]
fn reading_only_through_history() {
    let f = forked();
    let (g, ge) = (tid(5), person(0x50));
    let w = box_member(&f.a, &f.view, &f.s, &actor_rcpt(g, Role::Read, &ge), &roles_up_to(Role::Read), &mut rng(9)).unwrap().unwrap();
    let mut s = f.s.clone();
    w.apply(&mut s);
    let mut gv = ActorEpochs::default();
    ingest(&f.a, &s, &Opener::Actor { member: g, epochs: &ge }, &mut gv, Some(from(2))).unwrap();
    let older: Vec<_> = gv.read.held_newest_first().into_iter().map(|x| x.0).filter(|e| !f.forks.contains(e)).collect();
    assert!(!older.is_empty());
    assert!(older.iter().all(|e| gv.read.is_reading_only(e)));
    ingest(&f.a, &s, &Opener::Actor { member: g, epochs: &ge }, &mut gv, None).unwrap();
    assert!(older.iter().all(|e| !gv.read.is_reading_only(e) && gv.read.secret(e).is_some()));
}

// spec/crypto.md §4: secrets of a pending grant are kept for reading. A wrong secret planted for
// an epoch before the genuine pending box arrives does not hide it: every candidate is kept, the
// history box opens with the genuine one and the head's registered label key finds it.
#[test]
fn planted_reading_secret_does_not_hide_genuine_spec_crypto_4() {
    let f = forked();
    let (g, ge) = (tid(5), person(0x50));
    let rcpt = actor_rcpt(g, Role::Read, &ge);
    let read = roles_up_to(Role::Read);
    let mut fake_view = f.view.clone();
    for e in f.forks {
        fake_view.read.set_secret(e, Secret32::from_bytes([0xee; 32]));
    }
    let fake = box_member(&f.a, &fake_view, &f.s, &rcpt, &read, &mut rng(8)).unwrap().unwrap();
    let mut s_fake = f.s.clone();
    fake.apply(&mut s_fake);
    let real = box_member(&f.a, &f.view, &f.s, &rcpt, &read, &mut rng(9)).unwrap().unwrap();
    let mut s = f.s.clone();
    real.apply(&mut s);
    let mut gv = ActorEpochs::default();
    ingest(&f.a, &s_fake, &Opener::Actor { member: g, epochs: &ge }, &mut gv, Some(from(1))).unwrap();
    ingest(&f.a, &s, &Opener::Actor { member: g, epochs: &ge }, &mut gv, Some(from(2))).unwrap();
    for e in f.forks {
        let genuine = f.view.read.secret(&e).unwrap();
        assert_eq!(gv.read.reading_secrets(&e).len(), 2);
        assert!(gv.read.reading_secrets(&e).contains(&genuine) && gv.read.is_reading_only(&e));
        let key = osis_crypto::label_role_key(osis_keys::label_role(Role::Read), genuine, 3).verifying_key();
        assert_eq!(osis_keys::registered_secret(&gv.read, Role::Read, 3, &key), Some((e, genuine)));
    }
    let older: Vec<_> = f.view.read.held().map(|x| x.0).filter(|e| !f.forks.contains(e)).collect();
    assert!(!older.is_empty());
    assert!(older.iter().all(|e| gv.read.reading_secrets(e) == vec![f.view.read.secret(e).unwrap()]), "history opened with the genuine one");
}

// spec/crypto.md §4: reading-only candidates are bounded: one per author node and epoch, at most
// `MAX_READING_PER_AUTHOR` per author and `MAX_READING` per role; a source commit that applies or
// is dropped takes its candidates with it.
#[test]
fn reading_candidates_bounded_spec_crypto_4() {
    let ep = |n: u64| osis_crypto::Epoch::new(n, [n as u8; 16]).unwrap();
    let mut a = ActorEpochs::default();
    // one author: one candidate per epoch, then its cap
    a.read.set_reading_secret(ep(1), Secret32::from_bytes([1; 32]), from(1));
    a.read.set_reading_secret(ep(1), Secret32::from_bytes([2; 32]), from(1));
    assert_eq!(a.read.reading_secrets(&ep(1)).len(), 1);
    for n in 2..200 {
        a.read.set_reading_secret(ep(n), Secret32::from_bytes([3; 32]), from(1));
    }
    let count = |a: &ActorEpochs| a.read.held_newest_first().len();
    assert_eq!(count(&a), osis_keys::MAX_READING_PER_AUTHOR);
    // another author still gets its candidate at a planted epoch
    a.read.set_reading_secret(ep(1), Secret32::from_bytes([9; 32]), from(2));
    assert_eq!(a.read.reading_secrets(&ep(1)).len(), 2);
    // a total cap over authors
    for n in 10..40u8 {
        for e in 0..64 {
            a.read.set_reading_secret(ep(1000 + e), Secret32::from_bytes([n; 32]), from(n));
        }
    }
    assert_eq!(count(&a), osis_keys::MAX_READING);
    // the source commit goes: its candidates too
    assert!(a.drop_reading_from(&from(2).commit));
    assert_eq!(a.read.reading_secrets(&ep(1)).len(), 1);
}

// spec/crypto.md §3, §4: a published keyset names the KEM key derived from its epoch's genuine
// secret, so a planted candidate for a published epoch goes (however many authors plant it).
#[test]
fn planted_candidate_against_published_keyset_spec_crypto_4() {
    let f = forked();
    let e = f.forks[0];
    let genuine = f.view.read.secret(&e).unwrap().clone();
    let mut a = ActorEpochs::default();
    for n in 1..40 {
        a.read.set_reading_secret(e, Secret32::from_bytes([n; 32]), from(n));
    }
    a.read.set_reading_secret(e, genuine.clone(), from(200));
    let keys = osis_schema::core_types::Keys { read: Some(osis_keys::keyset(&e, &genuine)), ..Default::default() };
    assert!(osis_keys::prune_reading(&mut a, &keys));
    assert_eq!(a.read.reading_secrets(&e), vec![&genuine]);
}

// spec/crypto.md §4: authors whose chain the node does not know share one budget (throwaway
// identities gain nothing), several candidates per epoch.
#[test]
fn unknown_authors_share_one_budget_spec_crypto_4() {
    let ep = osis_crypto::Epoch::new(1, [1; 16]).unwrap();
    let unknown = |n: u8| osis_keys::Unchecked { author: osis_keys::UNKNOWN_AUTHOR, commit: osis_core::CommitId([n; 32]) };
    let mut a = ActorEpochs::default();
    for n in 0..200u8 {
        a.read.set_reading_secret(ep, Secret32::from_bytes([n; 32]), unknown(n));
    }
    assert_eq!(a.read.reading_secrets(&ep).len(), osis_keys::MAX_READING_PER_AUTHOR);
    // a known author still has its own
    a.read.set_reading_secret(ep, Secret32::from_bytes([0xaa; 32]), from(7));
    assert_eq!(a.read.reading_secrets(&ep).len(), osis_keys::MAX_READING_PER_AUTHOR + 1);
}

// spec/crypto.md §4, spec/permissions.md §2: a history key may hold several live entries (an
// invite holder's put next to the genuine one); a newer garbage entry wins the merged read, so
// readers try each entry and still open the older epochs.
#[test]
fn history_alternatives_tried_spec_crypto_4() {
    let f = forked();
    let (g, ge) = (tid(5), person(0x50));
    let w = box_member(&f.a, &f.view, &f.s, &actor_rcpt(g, Role::Read, &ge), &roles_up_to(Role::Read), &mut rng(9)).unwrap().unwrap();
    let mut s = f.s.clone();
    w.apply(&mut s);
    let older: Vec<_> = f.view.read.held().map(|x| x.0).filter(|e| !f.forks.contains(e)).collect();
    assert!(!older.is_empty());
    let mut bad = s.clone();
    let mut alts = osis_keys::HistoryAlts::new();
    for (k, ct) in bad.history.iter_mut() {
        alts.insert(k.clone(), vec![vec![0x5a; ct.len()], ct.clone()]);
        *ct = vec![0x5a; ct.len()];
    }
    let mut plain = ActorEpochs::default();
    osis_keys::ingest(&f.a, &bad, &Opener::Actor { member: g, epochs: &ge }, &mut plain, None).unwrap();
    assert!(older.iter().all(|e| plain.read.secret(e).is_none()), "the merged read alone hides them");
    let mut gv = ActorEpochs::default();
    osis_keys::ingest_with(&f.a, &bad, &alts, &Opener::Actor { member: g, epochs: &ge }, &mut gv, None).unwrap();
    assert!(older.iter().all(|e| gv.read.secret(e).is_some()), "each entry tried");
}
