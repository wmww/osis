#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Key-actor holders across rotations, wrap epochs, supersession read from the commits alone
//! (spec/crypto.md §4, §5; spec/permissions.md §3).

use crate::common;
use common::*;
use osis_base::{Role, Tid, WallMs};
use osis_crypto::{Epoch, Secret32};
use osis_keys::aspects::box_key;
use osis_keys::{ActorEpochs, Holder, HolderKeys, Opener, Recipient, SecretsWrite, box_holder, ingest, reseal_needed, roles_up_to, rotate};
use osis_schema::core_types::Secrets;
use std::collections::BTreeSet;

fn set(r: &[Role]) -> BTreeSet<Role> {
    r.iter().copied().collect()
}

fn owner(p: Tid, pe: &ActorEpochs) -> Recipient {
    Recipient { holder: p, role: Role::Admin, keys: HolderKeys::from_keys(&keys_of(pe)).unwrap().with_own(pe) }
}

/// Actor A owned by P after its own-secrets switch, boxing `extra` too.
fn switched(extra: &[Recipient]) -> (Tid, Tid, ActorEpochs, ActorEpochs, Secrets) {
    let (a, p, pe) = (tid(1), tid(2), person(0x20));
    let mut view = ActorEpochs::derived(&pe, &a);
    let mut holders = vec![owner(p, &pe)];
    holders.extend_from_slice(extra);
    let r = rotate(&a, &roles_up_to(Role::Admin), &view, &Secrets::default(), &holders, &mut rng(1)).unwrap();
    let mut s = Secrets::default();
    r.secrets.apply(&mut s);
    view = r.preview(&view).unwrap();
    (a, p, pe, view, s)
}

// spec/permissions.md §3: a key actor's grant raced by a read-only rotation (made unaware of
// it) keeps its box at the superseded read epoch only: the re-seal trigger asks for the new one.
#[test]
fn key_actor_grant_raced_by_read_rotation() {
    let (a, p, pe, view, base) = switched(&[]);
    let (k, seed) = (tid(6), Secret32::from_bytes([0x60; 32]));
    let grant = box_holder(&a, &view, &base, &key_rcpt(k, Role::Write, &seed), &roles_up_to(Role::Write), &mut rng(2)).unwrap().unwrap();
    let rot = rotate(&a, &set(&[Role::Read]), &view, &base, &[owner(p, &pe)], &mut rng(3)).unwrap();
    let mut s = base.clone();
    grant.apply(&mut s);
    rot.secrets.apply(&mut s);
    let mut v = view.clone();
    v = rot.preview(&v).unwrap();
    let er2 = rot.rotated[0].epoch;
    let holders = [Holder { holder: k, role: Role::Write, until: None }];
    assert_eq!(reseal_needed(&s, &v, &holders, WallMs(0)), vec![(k, set(&[Role::Read]))]);
    let w = box_holder(&a, &v, &s, &key_rcpt(k, Role::Write, &seed), &set(&[Role::Read]), &mut rng(4)).unwrap().unwrap();
    w.apply(&mut s);
    assert!(reseal_needed(&s, &v, &holders, WallMs(0)).is_empty());
    let mut kv = ActorEpochs::default();
    ingest(&a, &s, &Opener::KeyActor { holder: k, seed: &seed }, &mut kv, None).unwrap();
    assert!(kv.read.secret(&er2).is_some());
}

// spec/crypto.md §4: a rotation of admin demoting a key actor to write removes its admin box
// only; its read and write boxes stay.
#[test]
fn key_actor_demoted_keeps_lower_roles() {
    let (k, seed) = (tid(6), Secret32::from_bytes([0x60; 32]));
    let (a, p, pe, view, s0) = switched(&[key_rcpt(k, Role::Admin, &seed)]);
    let ea = view.admin.newest().unwrap();
    assert!(s0.boxes.contains_key(&box_key(k, Role::Admin, &ea)));
    let rot = rotate(&a, &set(&[Role::Admin]), &view, &s0, &[owner(p, &pe), key_rcpt(k, Role::Write, &seed)], &mut rng(2)).unwrap();
    let mut s = s0.clone();
    rot.secrets.apply(&mut s);
    let mut v = view.clone();
    v = rot.preview(&v).unwrap();
    let (er, ew) = (v.read.newest().unwrap(), v.write.newest().unwrap());
    assert_eq!(s.boxes.keys().filter(|b| b.holder == k).cloned().collect::<Vec<_>>(), vec![box_key(k, Role::Read, &er), box_key(k, Role::Write, &ew)]);
    let mut kv = ActorEpochs::default();
    ingest(&a, &s, &Opener::KeyActor { holder: k, seed: &seed }, &mut kv, None).unwrap();
    assert!(kv.read.secret(&er).is_some());
    assert!(kv.write.secret(&ew).is_some());
    assert!(kv.admin.secret(&rot.rotated[0].epoch).is_none());
}

// spec/crypto.md §5: a rotation commit wraps under the newest read epoch it supersedes whose
// secret the rotator holds.
#[test]
fn wrap_under_held_superseded() {
    let (a, p, pe, mut view, s) = switched(&[]);
    let e1 = view.read.newest().unwrap();
    // A fork the rotator knows (its box to P held) but holds no secret of, newer than its own.
    let fork = Epoch::new(e1.n(), [0; 32]).unwrap();
    view.read.rotation(fork, view.read.get(&e1).unwrap().supersedes.clone());
    view.read.set_established(fork, osis_keys::Provenance::Fixed);
    assert_eq!(view.read.newest(), Some(fork));
    let mut s = s;
    let p_box = s.boxes[&box_key(p, Role::Read, &e1)].clone();
    s.boxes.insert(box_key(p, Role::Read, &fork), p_box);
    let rot = rotate(&a, &set(&[Role::Read]), &view, &s, &[owner(p, &pe)], &mut rng(2)).unwrap();
    // it supersedes the epochs whose boxes it removes and those its history box lists
    let held: BTreeSet<Epoch> = view.read.held_established().map(|x| x.0).collect();
    assert_eq!(rot.rotated[0].supersedes, held.iter().copied().chain([fork]).collect());
    assert!(held.contains(&e1) && !held.contains(&fork));
    assert_eq!(rot.wrap_epoch(), Some(e1));
}

// spec/crypto.md §4: what a rotation supersedes is read from its commit alone, so every node
// holding the same commits agrees on the current epochs, in whatever order they arrived. X and
// Y fork read; Z rotates read unaware of Y. A non-holder applying them in any order counts Y and
// Z current, as do the rotators.
#[test]
fn supersession_independent_of_arrival_order() {
    let (a, p, pe, view, s) = switched(&[]);
    let holders = [owner(p, &pe)];
    let x = rotate(&a, &set(&[Role::Read]), &view, &s, &holders, &mut rng(2)).unwrap();
    let y = rotate(&a, &set(&[Role::Read]), &view, &s, &holders, &mut rng(3)).unwrap();
    let (mut sx, mut vx) = (s.clone(), view.clone());
    x.secrets.apply(&mut sx);
    vx = x.preview(&vx).unwrap();
    let z = rotate(&a, &set(&[Role::Read]), &vx, &sx, &holders, &mut rng(4)).unwrap();
    // `switched`'s rotation again (same inputs and randomness)
    let r0 = rotate(&a, &roles_up_to(Role::Admin), &ActorEpochs::derived(&pe, &a), &Secrets::default(), &holders, &mut rng(1)).unwrap();
    assert_eq!(view.read.newest(), Some(r0.rotated[0].epoch));
    let commits = [(&x, 2u8), (&y, 3), (&z, 4)];
    let mut want = vec![y.rotated[0].epoch, z.rotated[0].epoch];
    want.sort();
    for order in [[0, 1, 2], [1, 0, 2], [1, 2, 0], [2, 1, 0], [0, 2, 1], [2, 0, 1]] {
        let mut v = ActorEpochs::default();
        r0.secrets.claimed(&mut v, osis_base::CommitId([1; 32]), &r0.keys, true).unwrap();
        for i in order {
            let (rot, c) = commits[i];
            rot.secrets.claimed(&mut v, osis_base::CommitId([c; 32]), &rot.keys, true).unwrap();
        }
        assert_eq!(v.read.current(), want, "{order:?}");
    }
    // the rotators' own views agree
    let mut vz = vx.clone();
    vz = z.preview(&vz).unwrap();
    y.secrets.claimed(&mut vz, osis_base::CommitId([3; 32]), &y.keys, true).unwrap();
    assert_eq!(vz.read.current(), want);
}

// spec/crypto.md §4: an epoch first seen in a commit is not established until its rotation commit
// is applied (`Chain`); a grant re-writing a history box establishes nothing; joining writes, a
// later removal wins over an earlier put.
#[test]
fn observe_and_extend() {
    let (a, p, pe, view, s) = switched(&[]);
    let rot = rotate(&a, &set(&[Role::Read]), &view, &s, &[owner(p, &pe)], &mut rng(2)).unwrap();
    let mut v = view.clone();
    rot.secrets.observe(&mut v).unwrap();
    let e2 = rot.rotated[0].epoch;
    assert!(!v.read.is_current(&e2));
    // The rotated view re-sealing someone at e2: applying that re-seal establishes nothing.
    let mut rv = view.clone();
    rv = rot.preview(&rv).unwrap();
    let mut s2 = s.clone();
    rot.secrets.apply(&mut s2);
    let (k, seed) = (tid(6), Secret32::from_bytes([0x60; 32]));
    let reseal = osis_keys::reseal_holder(&a, &rv, &s2, &key_rcpt(k, Role::Read, &seed), &set(&[Role::Read]), &mut rng(3)).unwrap().unwrap();
    assert!(!reseal.history.is_empty());
    assert!(!reseal.claimed(&mut v, osis_base::CommitId([3; 32]), &osis_keys::KeysWrite::default(), true).unwrap());
    assert!(!v.read.is_current(&e2));
    assert!(rot.secrets.claimed(&mut v, osis_base::CommitId([2; 32]), &rot.keys, true).unwrap());
    assert_eq!(v.read.current(), vec![e2]);
    assert_eq!(v.read.provenance(&e2), Some(osis_keys::Provenance::Chain));
    let key = box_key(p, Role::Read, &e2);
    let mut w = rot.secrets.clone();
    w.extend(SecretsWrite { removed: [(key.clone(), Default::default())].into_iter().collect(), ..SecretsWrite::default() });
    assert!(!w.boxes.contains_key(&key) && w.removed.contains_key(&key));
}
