#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The covers rule and re-seal trigger scenarios (spec/crypto.md §3, §4; spec/permissions.md §3).

mod common;
use common::*;
use osis_core::{Role, Tid, WallMs};
use osis_crypto::Secret32;
use osis_keys::{
    ActorEpochs, Departure, Member, MemoryHeldActors, MemberKeys, Opener, ROLES, Recipient, box_member, ingest, may_encrypt_under, reseal_needed, roles_up_to, rotate, rotate_first,
};
use osis_schema::core_types::Secrets;
use std::collections::BTreeSet;

fn owner_rcpt(p: Tid, pe: &ActorEpochs) -> Recipient {
    Recipient { member: p, role: Role::Admin, keys: MemberKeys::from_keys(&keys_of(pe)).unwrap().with_own(pe) }
}

fn read() -> BTreeSet<Role> {
    [Role::Read].into_iter().collect()
}

/// Actor `a` owned by P after its own-secrets switch boxing `extra` members too.
fn switched(a: Tid, p: Tid, pe: &ActorEpochs, extra: &[Recipient]) -> (ActorEpochs, Secrets) {
    let mut view = ActorEpochs::derived(pe, &a);
    let mut members = vec![owner_rcpt(p, pe)];
    members.extend_from_slice(extra);
    let r = rotate(&a, &roles_up_to(Role::Admin), &view, &Secrets::default(), &members, &|_, _| true, &mut rng(1)).unwrap();
    let mut s = Secrets::default();
    r.secrets.apply(&mut s);
    r.record(&mut view);
    (view, s)
}

// spec/crypto.md §4 (departure inside a member) and §3 (derived secrets): a device removed from
// person P makes P rotate; a thing T with secrets of its own still boxes P under P's old secret,
// so T's epochs do not cover it and a node that may rotate T rotates first; a plain thing owned
// by P derives from P's new epoch and needs nothing.
#[test]
fn lost_device_owner_rotation() {
    let (t, p) = (tid(1), tid(2));
    let pe = person(0x20);
    let (tview, ts) = switched(t, p, &pe, &[]);
    // P rotates every role after the device removal.
    let mut pe2 = pe.clone();
    for (i, r) in ROLES.into_iter().enumerate() {
        pe2.role_mut(r).rotation(ep(2, 0x21), [ep(1, 0x20)]);
        pe2.role_mut(r).set_established(ep(2, 0x21), osis_keys::Provenance::Own);
        pe2.role_mut(r).set_secret(ep(2, 0x21), Secret32::from_bytes([0x90 + i as u8; 32]));
    }
    // P's own /secrets after the rotation hold no box for the device.
    let mut newest = MemoryHeldActors::default();
    newest.map.insert(p, (Secrets::default(), pe2.clone()));
    let deps = [Departure::inside(p, &Departure::member(tid(9), Role::Read))];
    let all = roles_up_to(Role::Admin);
    for r in ROLES {
        let (e, _) = tview.role(r).newest_held().unwrap();
        assert!(!may_encrypt_under(&ts, &tview, r, &e, &deps, &newest));
    }
    assert_eq!(rotate_first(&ts, &tview, &all, &all, &deps, &newest), all);
    // A writer of T may rotate read and write only.
    let rw: BTreeSet<Role> = [Role::Read, Role::Write].into_iter().collect();
    assert_eq!(rotate_first(&ts, &tview, &all, &rw, &deps, &newest), rw);
    // T rotates, boxing P under its new secrets: covered.
    let r = rotate(&t, &all, &tview, &ts, &[owner_rcpt(p, &pe2)], &|_, _| true, &mut rng(2)).unwrap();
    let (mut tv2, mut ts2) = (tview.clone(), ts.clone());
    r.secrets.apply(&mut ts2);
    r.record(&mut tv2);
    assert!(rotate_first(&ts2, &tv2, &all, &all, &deps, &newest).is_empty());
    // A plain thing U owned by P: its derived epoch is P's newest.
    let u = ActorEpochs::derived(&pe2, &tid(3));
    assert_eq!(u.read.newest(), Some(ep(2, 0x21)));
}

// spec/permissions.md §3: a grant raced by a rotation leaves the grantee without a box at the
// current epoch; the re-seal trigger finds it (not within `MAX_DRIFT` of its `until`), and the
// re-seal clears it.
#[test]
fn grant_raced_by_rotation() {
    let (a, p, g) = (tid(1), tid(2), tid(5));
    let (pe, ge) = (person(0x20), person(0x50));
    let (view, base) = switched(a, p, &pe, &[]);
    let grant = box_member(&a, &view, &base, &actor_rcpt(g, Role::Read, &ge), &read(), &mut rng(3)).unwrap().unwrap();
    let rot = rotate(&a, &read(), &view, &base, &[owner_rcpt(p, &pe)], &|_, _| true, &mut rng(4)).unwrap();
    let mut s = base.clone();
    rot.secrets.apply(&mut s);
    grant.apply(&mut s);
    let mut v = view.clone();
    rot.record(&mut v);
    let now = WallMs(1_000_000_000);
    let members = [Member { member: p, role: Role::Admin, until: None }, Member { member: g, role: Role::Read, until: None }];
    assert_eq!(reseal_needed(&s, &v, &members, now, &|_, _, _| true), vec![(g, read())]);
    let near = [Member { member: g, role: Role::Read, until: Some(WallMs(now.0 + 3_600_000)) }];
    assert!(reseal_needed(&s, &v, &near, now, &|_, _, _| true).is_empty());
    let far = [Member { member: g, role: Role::Read, until: Some(WallMs(now.0 + 3_600_001)) }];
    assert_eq!(reseal_needed(&s, &v, &far, now, &|_, _, _| true).len(), 1);
    let reseal = osis_keys::reseal_member(&a, &v, &s, &actor_rcpt(g, Role::Read, &ge), &read(), &mut rng(5)).unwrap().unwrap();
    reseal.apply(&mut s);
    assert!(reseal_needed(&s, &v, &members, now, &|_, _, _| true).is_empty());
    let mut gv = ActorEpochs::default();
    ingest(&a, &s, &Opener::Actor { member: g, epochs: &ge }, &mut gv, true).unwrap();
    assert!(gv.read.secret(&v.read.newest().unwrap()).is_some());
}

// spec/crypto.md §4, spec/permissions.md §3: a node holding an eager rotation that boxes M, but
// not yet the removal of M (which travels with its own rotation, forking), may encrypt under it;
// once the removal arrives the eager epoch does not cover it and the node rotates first, past
// both forks, excluding M.
#[test]
fn rotation_held_before_the_removal() {
    let (a, p, m) = (tid(1), tid(2), tid(3));
    let (pe, me) = (person(0x20), person(0x30));
    let (view, base) = switched(a, p, &pe, &[actor_rcpt(m, Role::Read, &me)]);
    let with_m = [owner_rcpt(p, &pe), actor_rcpt(m, Role::Read, &me)];
    let eager = rotate(&a, &read(), &view, &base, &with_m, &|_, _| true, &mut rng(6)).unwrap();
    let removal = rotate(&a, &read(), &view, &base, &with_m[..1], &|_, _| true, &mut rng(7)).unwrap();
    let none = MemoryHeldActors::default();
    // Before the removal: only the eager rotation held, no departure known.
    let (mut s, mut v) = (base.clone(), view.clone());
    eager.secrets.apply(&mut s);
    eager.record(&mut v);
    let e2 = eager.rotated[0].epoch;
    assert!(may_encrypt_under(&s, &v, Role::Read, &e2, &[], &none));
    // The removal commit arrives with its rotation.
    removal.secrets.apply(&mut s);
    removal.record(&mut v);
    let e2r = removal.rotated[0].epoch;
    let deps = [Departure::member(m, Role::Read)];
    assert!(!may_encrypt_under(&s, &v, Role::Read, &e2, &deps, &none));
    assert!(may_encrypt_under(&s, &v, Role::Read, &e2r, &deps, &none));
    let first = rotate_first(&s, &v, &read(), &read(), &deps, &none);
    assert_eq!(first.contains(&Role::Read), v.read.newest() == Some(e2));
    // Rotating past both forks excludes M.
    let heal = rotate(&a, &read(), &v, &s, &with_m[..1], &|_, _| true, &mut rng(8)).unwrap();
    assert_eq!(heal.rotated[0].supersedes, [e2, e2r].into_iter().collect());
    heal.secrets.apply(&mut s);
    heal.record(&mut v);
    let e3 = heal.rotated[0].epoch;
    assert!(may_encrypt_under(&s, &v, Role::Read, &e3, &deps, &none));
    let mut mv = ActorEpochs::default();
    ingest(&a, &s, &Opener::Actor { member: m, epochs: &me }, &mut mv, true).unwrap();
    assert!(mv.read.secret(&e3).is_none());
    // A key-actor member's box keyed at a higher role counts as a box for the lower roles.
    let (k, seed) = (tid(6), Secret32::from_bytes([0x60; 32]));
    let w = box_member(&a, &v, &s, &key_rcpt(k, Role::Write, &seed), &roles_up_to(Role::Write), &mut rng(9)).unwrap().unwrap();
    w.apply(&mut s);
    let kdep = [Departure::member(k, Role::Read)];
    assert!(!may_encrypt_under(&s, &v, Role::Read, &e3, &kdep, &none));
    assert!(reseal_needed(&s, &v, &[Member { member: k, role: Role::Write, until: None }], WallMs(0), &|_, _, _| true).is_empty());
}
