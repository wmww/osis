#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The covers rule (by names) and re-seal trigger scenarios (spec/crypto.md §3, §4;
//! spec/permissions.md §3).

use crate::common;
use common::*;
use osis_base::{Role, Tid};
use osis_crypto::Secret32;
use osis_keys::{
    ActorEpochs, AllHeld, Departure, Holder, HolderKeys, Key, Maker, Name, Names, Opener, Recipient, box_holder, fork_merger, ingest, may_encrypt_under, merge_due, reseal_needed,
    roles_up_to, rotate,
};
use osis_schema::core_types::Secrets;
use std::collections::BTreeSet;

fn admin_rcpt(p: Tid, pe: &ActorEpochs) -> Recipient {
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
    Names { list: [n].into(), departs: None }
}

/// Actor `a` (first admin P) after its own-secrets switch boxing `extra` holders too.
fn switched(a: Tid, p: Tid, pe: &ActorEpochs, extra: &[Recipient]) -> (ActorEpochs, Secrets) {
    let mut view = ActorEpochs::derived(pe, &a);
    let mut holders = vec![admin_rcpt(p, pe)];
    holders.extend_from_slice(extra);
    let r = rotate(&a, &roles_up_to(Role::Admin), &view, &Secrets::default(), &holders, &osis_keys::Names::default(), &mut rng(1)).unwrap();
    let mut s = Secrets::default();
    r.secrets.apply(&mut s);
    view = r.preview(&view).unwrap();
    (view, s)
}

// spec/permissions.md §3: a grant raced by a rotation leaves the grantee without a box at the
// current epoch; the re-seal trigger finds it, and the re-seal clears it.
#[test]
fn grant_raced_by_rotation() {
    let (a, p, g) = (tid(1), tid(2), tid(5));
    let (pe, ge) = (person(0x20), person(0x50));
    let (view, base) = switched(a, p, &pe, &[]);
    let grant = box_holder(&a, &view, &hist(&a, &view, &base), &actor_rcpt(g, Role::Read, &ge), &read(), &mut rng(3)).unwrap().unwrap();
    let rot = rotate(&a, &read(), &view, &base, &[admin_rcpt(p, &pe)], &osis_keys::Names::default(), &mut rng(4)).unwrap();
    let mut s = base.clone();
    rot.secrets.apply(&mut s);
    grant.apply(&mut s);
    let mut v = view.clone();
    v = rot.preview(&v).unwrap();
    let holders = [Holder { holder: p, role: Role::Admin }, Holder { holder: g, role: Role::Read }];
    assert_eq!(reseal_needed(&s, &v, &holders), vec![(g, read())]);
    let reseal = osis_keys::box_holder(&a, &v, &hist(&a, &v, &s), &actor_rcpt(g, Role::Read, &ge), &read(), &mut rng(5)).unwrap().unwrap();
    reseal.apply(&mut s);
    assert!(reseal_needed(&s, &v, &holders).is_empty());
    let mut gv = ActorEpochs::default();
    ingest(&a, &s, &Opener::Actor { holder: g, epochs: &ge }, &mut gv, None).unwrap();
    assert!(gv.read.secret(&v.read.newest().unwrap()).is_some());
}

// spec/crypto.md §4 (merge), spec/permissions.md §3: a node holding an eager rotation that boxes
// M, but not yet the removal of M (which travels with its own rotation, forking), may encrypt
// under it; once the removal arrives the eager epoch does not cover it, and the node rotates
// while it stays current, newest or not, past both forks, excluding M.
#[test]
fn rotation_held_before_the_removal() {
    let (a, p, m) = (tid(1), tid(2), tid(3));
    let (pe, me) = (person(0x20), person(0x30));
    let (view, base) = switched(a, p, &pe, &[actor_rcpt(m, Role::Read, &me)]);
    let with_m = [admin_rcpt(p, &pe), actor_rcpt(m, Role::Read, &me)];
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
    assert!(merge_due(&a, &v, Role::Read, &deps, &AllHeld), "the eager fork is current, whichever is newest");
    // Rotating past both forks excludes M.
    let heal = rotate(&a, &read(), &v, &s, &with_m[..1], &naming(removed), &mut rng(8)).unwrap();
    let history: BTreeSet<_> = v.read.held_established().map(|x| x.0).collect();
    assert!(history.contains(&e2) && history.contains(&e2r));
    assert_eq!(heal.rotated[0].supersedes, history);
    heal.secrets.apply(&mut s);
    v = heal.preview(&v).unwrap();
    let e3 = heal.rotated[0].epoch;
    assert!(may_encrypt_under(&a, &v, Role::Read, &e3, &deps, &AllHeld));
    assert!(!merge_due(&a, &v, Role::Read, &deps, &AllHeld));
    let mut mv = ActorEpochs::default();
    ingest(&a, &s, &Opener::Actor { holder: m, epochs: &me }, &mut mv, None).unwrap();
    assert!(mv.read.secret(&e3).is_none());
    // A key-actor holder boxed write is boxed read too.
    let (k, seed) = (tid(6), Secret32::from_bytes([0x60; 32]));
    let w = box_holder(&a, &v, &hist(&a, &v, &s), &key_rcpt(k, Role::Write, &seed), &roles_up_to(Role::Write), &mut rng(9)).unwrap().unwrap();
    w.apply(&mut s);
    let kdep = [Departure::holder(k, Role::Read).at(Some(name(a, 10)))];
    assert!(!may_encrypt_under(&a, &v, Role::Read, &e3, &kdep, &AllHeld));
    assert!(reseal_needed(&s, &v, &[Holder { holder: k, role: Role::Write }]).is_empty());
}

// spec/crypto.md §4 (merge, merger): two rotations of read from one epoch fork it. Its merger is
// the maker of the epoch other than the newest; the newest's maker merges only when that maker
// may not rotate (or is unknown); a third node likewise. One epoch: no merge.
#[test]
fn fork_merger_is_one_maker() {
    let (a, p) = (tid(1), tid(2));
    let pe = person(0x20);
    let (view, base) = switched(a, p, &pe, &[]);
    assert!(!fork_merger(&view, Role::Read, |_| None), "one current epoch");
    let holders = [admin_rcpt(p, &pe)];
    let (r1, r2) = (rotate(&a, &read(), &view, &base, &holders, &Names::default(), &mut rng(6)).unwrap(), rotate(&a, &read(), &view, &base, &holders, &Names::default(), &mut rng(7)).unwrap());
    let mut v = r1.preview(&view).unwrap();
    v = r2.preview(&v).unwrap();
    assert_eq!(v.read.current().len(), 2);
    let newest = v.read.newest().unwrap();
    let other = *v.read.current().iter().find(|e| **e != newest).unwrap();
    let by = |mine: osis_crypto::Epoch, other_may: bool| move |e: &osis_crypto::Epoch| Some(Maker { me: *e == mine, may_rotate: *e == mine || other_may });
    assert!(fork_merger(&v, Role::Read, by(other, true)), "the maker of the epoch other than the newest");
    assert!(!fork_merger(&v, Role::Read, by(newest, true)), "the newest's maker abstains");
    assert!(fork_merger(&v, Role::Read, by(newest, false)), "... unless the other maker may not rotate");
    assert!(!fork_merger(&v, Role::Read, |_| Some(Maker { me: false, may_rotate: true })), "a third node abstains");
    assert!(fork_merger(&v, Role::Read, |_| None), "makers unknown: anyone");
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
    let rot = rotate(&a, &read(), &view, &base, &[admin_rcpt(p, &pe)], &Names::default(), &mut rng(7)).unwrap();
    let v = rot.preview(&view).unwrap();
    let e1 = rot.rotated[0].epoch;
    let removed = name(a, 7);
    let dep = [Departure::holder(m, Role::Read).at(Some(removed))];
    assert!(!may_encrypt_under(&a, &v, Role::Read, &e1, &dep, &AllHeld));
    assert!(merge_due(&a, &v, Role::Read, &dep, &AllHeld));
    let named = rotate(&a, &read(), &v, &base, &[admin_rcpt(p, &pe)], &naming(removed), &mut rng(8)).unwrap();
    let v2 = named.preview(&v).unwrap();
    let e2 = named.rotated[0].epoch;
    assert!(may_encrypt_under(&a, &v2, Role::Read, &e2, &dep, &AllHeld));
    struct Unmet;
    impl osis_keys::Held for Unmet {
        fn met(&self, _: &Name) -> bool {
            false
        }
        fn holds(&self, _: &osis_base::Tid, _: Role) -> bool {
            true
        }
        fn departed(&self, _: &osis_keys::Own) -> bool {
            true
        }
        fn publishes(&self, _: Role, _: &osis_crypto::Epoch, _: &osis_keys::NamesDigest) -> bool {
            true
        }
    }
    assert!(!osis_keys::covers(&a, &v2, Role::Read, &e2, &dep[0], &Unmet));
    assert!(!may_encrypt_under(&a, &v2, Role::Read, &e2, &[Departure::holder(m, Role::Read)], &AllHeld));
}
