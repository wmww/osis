#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The covers rule (by names) and re-seal trigger scenarios (spec/crypto.md §3, §4;
//! spec/permissions.md §3).

use crate::common;
use common::*;
use osis_base::{Role, Tid, WallMs};
use osis_crypto::Secret32;
use osis_keys::{
    ActorEpochs, AllHeld, Departure, Holder, HolderKeys, Key, Name, Names, Opener, ROLES, Recipient, box_holder, ingest, may_encrypt_under, reseal_needed, roles_up_to, rotate,
    rotate_first,
};
use osis_schema::core_types::Secrets;
use std::collections::BTreeSet;

fn owner_rcpt(p: Tid, pe: &ActorEpochs) -> Recipient {
    Recipient { holder: p, role: Role::Admin, keys: HolderKeys::from_keys(&keys_of(pe)).unwrap().with_own(pe) }
}

fn read() -> BTreeSet<Role> {
    [Role::Read].into_iter().collect()
}

/// A departure's name: commit `b`'s key, on `thing`.
fn name(thing: Tid, b: u8) -> Name {
    Name { thing, key: Key { ts: u64::from(b), node: tid(9), commit: osis_base::CommitId([b; 32]) } }
}

fn naming(n: Name) -> Names {
    Names { list: [n].into(), ..Names::default() }
}

/// Actor `a` owned by P after its own-secrets switch boxing `extra` holders too.
fn switched(a: Tid, p: Tid, pe: &ActorEpochs, extra: &[Recipient]) -> (ActorEpochs, Secrets) {
    let mut view = ActorEpochs::derived(pe, &a);
    let mut holders = vec![owner_rcpt(p, pe)];
    holders.extend_from_slice(extra);
    let r = rotate(&a, &roles_up_to(Role::Admin), &view, &Secrets::default(), &holders, &osis_keys::Names::default(), &mut rng(1)).unwrap();
    let mut s = Secrets::default();
    r.secrets.apply(&mut s);
    view = r.preview(&view).unwrap();
    (view, s)
}

// spec/crypto.md §4 (departure inside a holder, covers by names) and §3 (derived secrets): a
// device removed from person P; a thing T with secrets of its own whose epochs do not name it
// does not cover it, so a node that may rotate T rotates first; T's rotation naming it covers it;
// a plain thing owned by P derives from P's new epoch and needs nothing.
#[test]
fn lost_device_owner_rotation() {
    let (t, p) = (tid(1), tid(2));
    let pe = person(0x20);
    let (tview, _) = switched(t, p, &pe, &[]);
    let removal = name(p, 7);
    let deps = [Departure::inside(p, &Departure::holder(tid(9), Role::Read).at(Some(removal)))];
    let all = roles_up_to(Role::Admin);
    for r in ROLES {
        let (e, _) = tview.role(r).newest_held().unwrap();
        assert!(!may_encrypt_under(&t, &tview, r, &e, &deps, &AllHeld));
    }
    assert_eq!(rotate_first(&t, &tview, &all, &all, &deps, &AllHeld), all);
    // A writer of T may rotate read and write only.
    let rw: BTreeSet<Role> = [Role::Read, Role::Write].into_iter().collect();
    assert_eq!(rotate_first(&t, &tview, &all, &rw, &deps, &AllHeld), rw);
    // T rotates naming the removal: covered. Naming something else covers nothing.
    let mut pe2 = pe.clone();
    for (i, r) in ROLES.into_iter().enumerate() {
        pe2.role_mut(r).rotation(ep(2, 0x21), [ep(1, 0x20)]);
        pe2.role_mut(r).set_established(ep(2, 0x21), osis_keys::Provenance::Fixed);
        pe2.role_mut(r).set_secret(ep(2, 0x21), Secret32::from_bytes([0x90 + i as u8; 32]));
    }
    let ts = osis_schema::core_types::Secrets::default();
    for (names, covered) in [(naming(name(p, 8)), false), (naming(removal), true)] {
        let r = rotate(&t, &all, &tview, &ts, &[owner_rcpt(p, &pe2)], &names, &mut rng(2)).unwrap();
        let tv2 = r.preview(&tview).unwrap();
        assert_eq!(rotate_first(&t, &tv2, &all, &all, &deps, &AllHeld).is_empty(), covered);
    }
    // A plain thing U owned by P: its derived epoch is at P's newest's n.
    let u = ActorEpochs::derived(&pe2, &tid(3));
    let s = osis_crypto::thing_role_secret(pe2.read.secret(&ep(2, 0x21)).unwrap(), Role::Read, &tid(3));
    assert_eq!(u.read.newest(), Some(osis_crypto::Epoch::derive(&tid(3), Role::Read, 2, &s).unwrap()));
}

// spec/permissions.md §3: a grant raced by a rotation leaves the grantee without a box at the
// current epoch; the re-seal trigger finds it (not within `MAX_DRIFT` of its `until`), and the
// re-seal clears it.
#[test]
fn grant_raced_by_rotation() {
    let (a, p, g) = (tid(1), tid(2), tid(5));
    let (pe, ge) = (person(0x20), person(0x50));
    let (view, base) = switched(a, p, &pe, &[]);
    let grant = box_holder(&a, &view, &base, &actor_rcpt(g, Role::Read, &ge), &read(), &mut rng(3)).unwrap().unwrap();
    let rot = rotate(&a, &read(), &view, &base, &[owner_rcpt(p, &pe)], &osis_keys::Names::default(), &mut rng(4)).unwrap();
    let mut s = base.clone();
    rot.secrets.apply(&mut s);
    grant.apply(&mut s);
    let mut v = view.clone();
    v = rot.preview(&v).unwrap();
    let now = WallMs(1_000_000_000);
    let holders = [Holder { holder: p, role: Role::Admin, until: None }, Holder { holder: g, role: Role::Read, until: None }];
    assert_eq!(reseal_needed(&s, &v, &holders, now), vec![(g, read())]);
    let near = [Holder { holder: g, role: Role::Read, until: Some(WallMs(now.0 + 3_600_000)) }];
    assert!(reseal_needed(&s, &v, &near, now).is_empty());
    let far = [Holder { holder: g, role: Role::Read, until: Some(WallMs(now.0 + 3_600_001)) }];
    assert_eq!(reseal_needed(&s, &v, &far, now).len(), 1);
    let reseal = osis_keys::box_holder(&a, &v, &s, &actor_rcpt(g, Role::Read, &ge), &read(), &mut rng(5)).unwrap().unwrap();
    reseal.apply(&mut s);
    assert!(reseal_needed(&s, &v, &holders, now).is_empty());
    let mut gv = ActorEpochs::default();
    ingest(&a, &s, &Opener::Actor { holder: g, epochs: &ge }, &mut gv, None).unwrap();
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
    let removed = name(a, 7);
    let eager = rotate(&a, &read(), &view, &base, &with_m, &Names::default(), &mut rng(6)).unwrap();
    let removal = rotate(&a, &read(), &view, &base, &with_m[..1], &naming(removed), &mut rng(7)).unwrap();
    // Before the removal: only the eager rotation held, no departure known.
    let (mut s, mut v) = (base.clone(), view.clone());
    eager.secrets.apply(&mut s);
    v = eager.preview(&v).unwrap();
    let e2 = eager.rotated[0].epoch;
    assert!(may_encrypt_under(&a, &v, Role::Read, &e2, &[], &AllHeld));
    // The removal commit arrives with its rotation.
    removal.secrets.apply(&mut s);
    v = removal.preview(&v).unwrap();
    let e2r = removal.rotated[0].epoch;
    let deps = [Departure::holder(m, Role::Read).at(Some(removed))];
    assert!(!may_encrypt_under(&a, &v, Role::Read, &e2, &deps, &AllHeld));
    assert!(may_encrypt_under(&a, &v, Role::Read, &e2r, &deps, &AllHeld));
    let first = rotate_first(&a, &v, &read(), &read(), &deps, &AllHeld);
    assert_eq!(first.contains(&Role::Read), v.read.newest() == Some(e2));
    // Rotating past both forks excludes M.
    let heal = rotate(&a, &read(), &v, &s, &with_m[..1], &naming(removed), &mut rng(8)).unwrap();
    let history: BTreeSet<_> = v.read.held_established().map(|x| x.0).collect();
    assert!(history.contains(&e2) && history.contains(&e2r));
    assert_eq!(heal.rotated[0].supersedes, history);
    heal.secrets.apply(&mut s);
    v = heal.preview(&v).unwrap();
    let e3 = heal.rotated[0].epoch;
    assert!(may_encrypt_under(&a, &v, Role::Read, &e3, &deps, &AllHeld));
    let mut mv = ActorEpochs::default();
    ingest(&a, &s, &Opener::Actor { holder: m, epochs: &me }, &mut mv, None).unwrap();
    assert!(mv.read.secret(&e3).is_none());
    // A key-actor holder boxed write is boxed read too.
    let (k, seed) = (tid(6), Secret32::from_bytes([0x60; 32]));
    let w = box_holder(&a, &v, &s, &key_rcpt(k, Role::Write, &seed), &roles_up_to(Role::Write), &mut rng(9)).unwrap().unwrap();
    w.apply(&mut s);
    let kdep = [Departure::holder(k, Role::Read).at(Some(name(a, 10)))];
    assert!(!may_encrypt_under(&a, &v, Role::Read, &e3, &kdep, &AllHeld));
    assert!(reseal_needed(&s, &v, &[Holder { holder: k, role: Role::Write, until: None }], WallMs(0)).is_empty());
}

// spec/crypto.md §4 (boxes decide nothing; study C2): an epoch whose rotation left M unboxed
// (its rotator had not read M's grant) does not cover M's later removal: a re-sealer that knows
// the grant but not the removal boxes M there. Only an epoch naming the removal covers it; one
// whose names are not met here covers nothing; a departure no rotation can name (`at` none)
// is covered by none.
#[test]
fn missing_box_covers_nothing() {
    let (a, p, m) = (tid(1), tid(2), tid(3));
    let pe = person(0x20);
    let (view, base) = switched(a, p, &pe, &[]);
    let rot = rotate(&a, &read(), &view, &base, &[owner_rcpt(p, &pe)], &Names::default(), &mut rng(7)).unwrap();
    let v = rot.preview(&view).unwrap();
    let e1 = rot.rotated[0].epoch;
    let removed = name(a, 7);
    let dep = [Departure::holder(m, Role::Read).at(Some(removed))];
    assert!(!may_encrypt_under(&a, &v, Role::Read, &e1, &dep, &AllHeld));
    assert_eq!(rotate_first(&a, &v, &read(), &read(), &dep, &AllHeld), read());
    let named = rotate(&a, &read(), &v, &base, &[owner_rcpt(p, &pe)], &naming(removed), &mut rng(8)).unwrap();
    let v2 = named.preview(&v).unwrap();
    let e2 = named.rotated[0].epoch;
    assert!(may_encrypt_under(&a, &v2, Role::Read, &e2, &dep, &AllHeld));
    struct Unmet;
    impl osis_keys::Held for Unmet {
        fn met(&self, _: &Name) -> bool {
            false
        }
        fn keyset(&self, _: &osis_keys::KeysetName) -> bool {
            true
        }
        fn departed(&self, _: &osis_keys::Own) -> bool {
            true
        }
    }
    assert!(!osis_keys::covers(&a, &v2, Role::Read, &e2, &dep[0], &Unmet));
    assert!(!may_encrypt_under(&a, &v2, Role::Read, &e2, &[Departure::holder(m, Role::Read)], &AllHeld));
}
