#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Key-actor members across rotations, carried secrets, wrap epochs, supersedes for non-holders
//! (spec/crypto.md §4, §5; spec/permissions.md §3).

mod common;
use common::*;
use osis_core::{Role, Tid, WallMs};
use osis_crypto::{Epoch, Secret32};
use osis_keys::aspects::box_key;
use osis_keys::{ActorEpochs, Member, MemberKeys, Opener, Recipient, SecretsWrite, box_member, ingest, reseal_needed, roles_up_to, rotate};
use osis_schema::core_types::{Keys, Secrets};
use std::collections::BTreeSet;

fn set(r: &[Role]) -> BTreeSet<Role> {
    r.iter().copied().collect()
}

fn owner(p: Tid, pe: &ActorEpochs) -> Recipient {
    Recipient { member: p, role: Role::Admin, keys: MemberKeys::from_keys(&keys_of(pe)).unwrap().with_own(pe) }
}

/// Actor A owned by P after its own-secrets switch, boxing `extra` too.
fn switched(extra: &[Recipient]) -> (Tid, Tid, ActorEpochs, ActorEpochs, Secrets) {
    let (a, p, pe) = (tid(1), tid(2), person(0x20));
    let mut view = ActorEpochs::derived(&pe, &a);
    let mut members = vec![owner(p, &pe)];
    members.extend_from_slice(extra);
    let r = rotate(&a, &roles_up_to(Role::Admin), &view, &Secrets::default(), &members, &|_, _| true, &mut rng(1)).unwrap();
    let mut s = Secrets::default();
    r.secrets.apply(&mut s);
    r.record(&mut view);
    (a, p, pe, view, s)
}

// spec/permissions.md §3: a key actor's grant raced by a read-only rotation keeps its write-keyed
// box, which does not carry the new read epoch; the re-seal trigger counts that box only where
// its writing commit knew the epoch.
#[test]
fn key_actor_grant_raced_by_read_rotation() {
    let (a, p, pe, view, base) = switched(&[]);
    let (k, seed) = (tid(6), Secret32::from_bytes([0x60; 32]));
    let grant = box_member(&a, &view, &base, &key_rcpt(k, Role::Write, &seed), &roles_up_to(Role::Write), &mut rng(2)).unwrap().unwrap();
    let rot = rotate(&a, &set(&[Role::Read]), &view, &base, &[owner(p, &pe)], &|_, _| true, &mut rng(3)).unwrap();
    let mut s = base.clone();
    grant.apply(&mut s);
    rot.secrets.apply(&mut s);
    let mut v = view.clone();
    rot.record(&mut v);
    let er2 = rot.rotated[0].epoch;
    let members = [Member { member: k, role: Role::Write, until: None }];
    // The grant knew the epochs it boxed; it did not know er2.
    let grant_keys: BTreeSet<_> = grant.boxes.keys().cloned().collect();
    let knows = |key: &osis_schema::core_types::BoxKey, r: Role, e: &Epoch| !(grant_keys.contains(key) && r == Role::Read && *e == er2);
    assert_eq!(reseal_needed(&s, &v, &members, WallMs(0), &knows), vec![(k, set(&[Role::Read]))]);
    // The lenient reading misses it.
    assert!(reseal_needed(&s, &v, &members, WallMs(0), &|_, _, _| true).is_empty());
    let w = box_member(&a, &v, &s, &key_rcpt(k, Role::Write, &seed), &set(&[Role::Read]), &mut rng(4)).unwrap().unwrap();
    w.apply(&mut s);
    assert!(reseal_needed(&s, &v, &members, WallMs(0), &knows).is_empty());
    let mut kv = ActorEpochs::default();
    ingest(&a, &s, &Opener::KeyActor { member: k, seed: &seed }, &mut kv).unwrap();
    assert!(kv.read.secret(&er2).is_some());
}

// spec/crypto.md §4: a rotation that removes a key actor's only box and writes it no role (its
// demotion admin -> write rotating admin) writes it a box with every role it still holds.
#[test]
fn key_actor_demoted_keeps_lower_roles() {
    let (k, seed) = (tid(6), Secret32::from_bytes([0x60; 32]));
    let (a, p, pe, view, s0) = switched(&[key_rcpt(k, Role::Admin, &seed)]);
    let ea = view.admin.newest().unwrap();
    assert!(s0.boxes.contains_key(&box_key(k, Role::Admin, &ea)));
    let rot = rotate(&a, &set(&[Role::Admin]), &view, &s0, &[owner(p, &pe), key_rcpt(k, Role::Write, &seed)], &|_, _| true, &mut rng(2)).unwrap();
    let mut s = s0.clone();
    rot.secrets.apply(&mut s);
    let mut v = view.clone();
    rot.record(&mut v);
    let ew = v.write.newest().unwrap();
    assert_eq!(s.boxes.keys().filter(|b| b.member == k).cloned().collect::<Vec<_>>(), vec![box_key(k, Role::Write, &ew)]);
    let mut kv = ActorEpochs::default();
    ingest(&a, &s, &Opener::KeyActor { member: k, seed: &seed }, &mut kv).unwrap();
    assert!(kv.read.secret(&v.read.newest().unwrap()).is_some());
    assert!(kv.write.secret(&ew).is_some());
    assert!(kv.admin.secret(&rot.rotated[0].epoch).is_none());
}

// spec/crypto.md §4: carrying a lower role's secret to a key actor is encrypting under its epoch:
// an uncovered one is rotated too.
// spec/crypto.md §4 (encrypt under covering epoch)
#[test]
fn carried_role_rotates_when_uncovered() {
    let (k, seed) = (tid(6), Secret32::from_bytes([0x60; 32]));
    let (a, p, pe, view, s0) = switched(&[key_rcpt(k, Role::Admin, &seed)]);
    let members = [owner(p, &pe), key_rcpt(k, Role::Admin, &seed)];
    let rot = rotate(&a, &set(&[Role::Admin]), &view, &s0, &members, &|r, _| r != Role::Write, &mut rng(2)).unwrap();
    let roles: BTreeSet<Role> = rot.rotated.iter().map(|r| r.role).collect();
    assert_eq!(roles, set(&[Role::Write, Role::Admin]));
    let rot = rotate(&a, &set(&[Role::Admin]), &view, &s0, &members, &|_, _| true, &mut rng(2)).unwrap();
    assert_eq!(rot.rotated.len(), 1);
}

// spec/crypto.md §5: a rotation commit wraps under the newest read epoch it supersedes whose
// secret the rotator holds.
#[test]
fn wrap_under_held_superseded() {
    let (a, p, pe, mut view, s) = switched(&[]);
    let e1 = view.read.newest().unwrap();
    // A fork the rotator knows but holds no secret of, newer than its own.
    let fork = Epoch::new(e1.n(), [0; 16]).unwrap();
    view.read.rotation(fork, view.read.get(&e1).unwrap().supersedes.clone());
    view.read.set_established(fork, osis_keys::Provenance::Own);
    assert_eq!(view.read.newest(), Some(fork));
    let rot = rotate(&a, &set(&[Role::Read]), &view, &s, &[owner(p, &pe)], &|_, _| true, &mut rng(2)).unwrap();
    assert_eq!(rot.rotated[0].supersedes, [e1, fork].into_iter().collect());
    assert_eq!(rot.wrap_epoch(), Some(e1));
}

// spec/crypto.md §4: a non-holder learns what a rotation supersedes from the keyset it replaces
// when no box of the role is removed (all members key actors, boxes keyed at their top role).
#[test]
fn supersedes_from_keyset_bump() {
    let (k, seed) = (tid(6), Secret32::from_bytes([0x60; 32]));
    let (o, oseed) = (tid(7), Secret32::from_bytes([0x70; 32]));
    let mut view = ActorEpochs::derived(&ActorEpochs::key_actor(&oseed), &tid(1));
    let a = tid(1);
    let members = [key_rcpt(o, Role::Admin, &oseed), key_rcpt(k, Role::Write, &seed)];
    let r1 = rotate(&a, &roles_up_to(Role::Admin), &view, &Secrets::default(), &members, &|_, _| true, &mut rng(1)).unwrap();
    let mut s = Secrets::default();
    r1.secrets.apply(&mut s);
    r1.record(&mut view);
    let mut keys = Keys::default();
    r1.keys.apply(&mut keys);
    let r2 = rotate(&a, &set(&[Role::Read]), &view, &s, &members, &|_, _| true, &mut rng(2)).unwrap();
    assert!(r2.secrets.removed.is_empty());
    let er1 = r1.rotated[0].epoch;
    let er2 = r2.rotated[0].epoch;
    // A non-holder applying both rotation commits.
    let observe = |with_keys: bool| {
        let mut v = ActorEpochs::default();
        assert!(r1.secrets.applied(&mut v, (&r1.keys, &Keys::default())).unwrap());
        if with_keys {
            assert!(r2.secrets.applied(&mut v, (&r2.keys, &keys)).unwrap());
        } else {
            r2.secrets.observe(&mut v, None).unwrap();
            v.read.set_applied(er2, []);
            v.establish();
        }
        v.read.current()
    };
    assert_eq!(observe(true), vec![er2]);
    let mut both = vec![er1, er2];
    both.sort();
    assert_eq!(observe(false), both);
}

// spec/crypto.md §4: an epoch first seen in a commit is not established until its rotation commit
// is applied (`Chain`); a grant re-writing a history box establishes nothing; joining writes, a
// later removal wins over an earlier put.
#[test]
fn observe_and_extend() {
    let (a, p, pe, view, s) = switched(&[]);
    let rot = rotate(&a, &set(&[Role::Read]), &view, &s, &[owner(p, &pe)], &|_, _| true, &mut rng(2)).unwrap();
    let mut v = view.clone();
    rot.secrets.observe(&mut v, None).unwrap();
    let e2 = rot.rotated[0].epoch;
    assert!(!v.read.is_current(&e2));
    // The rotated view re-sealing someone at e2: applying that re-seal establishes nothing.
    let mut rv = view.clone();
    rot.record(&mut rv);
    let mut s2 = s.clone();
    rot.secrets.apply(&mut s2);
    let (k, seed) = (tid(6), Secret32::from_bytes([0x60; 32]));
    let reseal = osis_keys::reseal_member(&a, &rv, &s2, &key_rcpt(k, Role::Read, &seed), &set(&[Role::Read]), &mut rng(3)).unwrap().unwrap();
    assert!(!reseal.history.is_empty());
    assert!(!reseal.applied(&mut v, (&osis_keys::KeysWrite::default(), &Keys::default())).unwrap());
    assert!(!v.read.is_current(&e2));
    assert!(rot.secrets.applied(&mut v, (&rot.keys, &Keys::default())).unwrap());
    assert_eq!(v.read.current(), vec![e2]);
    assert_eq!(v.read.provenance(&e2), Some(osis_keys::Provenance::Chain));
    let key = box_key(p, Role::Read, &e2);
    let mut w = rot.secrets.clone();
    w.extend(SecretsWrite { removed: [key.clone()].into_iter().collect(), ..SecretsWrite::default() });
    assert!(!w.boxes.contains_key(&key) && w.removed.contains(&key));
}
