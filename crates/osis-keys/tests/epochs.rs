#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Epochs, rotations, forks and the `/secrets` delta rules (spec/crypto.md §3, §4).

mod common;
use common::*;
use osis_core::Role;
use osis_crypto::{Secret32, thing_role_secret};
use osis_keys::aspects::{box_key, history_key};
use osis_keys::{ActorEpochs, MemberKeys, Opener, Recipient, ROLES, ingest, rotate};
use osis_schema::core_types::{Keys, SecretBox, Secrets};
use std::collections::BTreeSet;

fn all() -> BTreeSet<Role> {
    ROLES.into_iter().collect()
}

fn read() -> BTreeSet<Role> {
    [Role::Read].into_iter().collect()
}

struct World {
    a: osis_core::Tid,
    p: osis_core::Tid,
    m: osis_core::Tid,
    l: osis_core::Tid,
    pe: ActorEpochs,
    me: ActorEpochs,
    lseed: Secret32,
}

impl World {
    fn new() -> World {
        World { a: tid(1), p: tid(2), m: tid(3), l: tid(4), pe: person(0x20), me: person(0x30), lseed: Secret32::from_bytes([0x40; 32]) }
    }
    /// Owner P (its secrets held: symmetric boxes), read member M, write key-actor member L.
    fn members(&self) -> Vec<Recipient> {
        vec![
            Recipient { member: self.p, role: Role::Admin, keys: MemberKeys::from_keys(&keys_of(&self.pe)).unwrap().with_own(&self.pe) },
            actor_rcpt(self.m, Role::Read, &self.me),
            key_rcpt(self.l, Role::Write, &self.lseed),
        ]
    }
}

// spec/crypto.md §3: giving a plain thing secrets of its own is a rotation of all three roles from
// the derived epochs; the history boxes carry the derived secrets. §4 box forms: the owner gets
// symmetric boxes, an actor member sealed boxes naming its keyset, a key-actor member one box
// keyed at the highest role written carrying every written role.
#[test]
fn own_secrets_switch() {
    let w = World::new();
    let derived = ActorEpochs::derived(&w.pe, &w.a);
    let rot = rotate(&w.a, &all(), &derived, &Secrets::default(), &w.members(), &|_, _| true, &mut rng(1)).unwrap();
    assert!(rot.unboxed.is_empty());
    let mut s = Secrets::default();
    rot.secrets.apply(&mut s);
    let e = |r: Role| rot.rotated.iter().find(|x| x.role == r).unwrap().epoch;
    assert!(ROLES.iter().all(|r| e(*r).n() == 2));
    assert_eq!(rot.wrap_epoch(), Some(ep(1, 0x20)));
    // Owner: three symmetric boxes of 49 bytes (spec/wire.md §7).
    for r in ROLES {
        match &s.boxes[&box_key(w.p, r, &e(r))] {
            SecretBox::Symmetric(b) => assert_eq!(b.wrap.len(), 49),
            other => panic!("{other:?}"),
        }
    }
    // M: one sealed read box, about 1.2 KB, naming its keyset; nothing for write or admin.
    match &s.boxes[&box_key(w.m, Role::Read, &e(Role::Read))] {
        SecretBox::Sealed(b) => {
            assert_eq!(b.keyset, Some(osis_keys::aspects::to_schema(&ep(1, 0x30))));
            let osis_schema::core_types::Sealed::X25519MlKem768(bytes) = &b.sealed;
            assert!((1150..1300).contains(&bytes.len()), "{}", bytes.len());
        }
        other => panic!("{other:?}"),
    }
    assert!(!s.boxes.keys().any(|k| k.member == w.m && k.role != Role::Read));
    // L: one box keyed (L, write, e_w).
    let lkeys: Vec<_> = s.boxes.keys().filter(|k| k.member == w.l).collect();
    assert_eq!(lkeys, vec![&box_key(w.l, Role::Write, &e(Role::Write))]);
    assert_eq!(s.history.len(), 3);

    // Each opens what it holds; history yields the derived secrets.
    let mut me = w.me.clone();
    let mut ma = ActorEpochs::default();
    // M opens with its own role secrets: Opener::Actor over M's epochs.
    let errs = ingest(&w.a, &s, &Opener::Actor { member: w.m, epochs: &me }, &mut ma, None).unwrap();
    assert!(errs.is_empty(), "{errs:?}");
    // Opening establishes nothing; applying the rotation commit does (spec/crypto.md §4).
    assert!(ma.read.current().is_empty());
    let applied = |v: &mut ActorEpochs| assert!(rot.secrets.applied(v, (&rot.keys, &Keys::default())).unwrap());
    applied(&mut ma);
    let derived_read = thing_role_secret(w.pe.read.secret(&ep(1, 0x20)).unwrap(), Role::Read, &w.a);
    assert_eq!(ma.read.secret(&ep(1, 0x20)), Some(&derived_read));
    assert_eq!(ma.read.newest_held().unwrap().0, e(Role::Read));
    assert!(ma.write.held().next().is_none());
    me.read = Default::default();
    let mut none = ActorEpochs::default();
    ingest(&w.a, &s, &Opener::Actor { member: w.m, epochs: &me }, &mut none, None).unwrap();
    assert!(none.read.held().next().is_none());

    let mut la = ActorEpochs::default();
    ingest(&w.a, &s, &Opener::KeyActor { member: w.l, seed: &w.lseed }, &mut la, None).unwrap();
    applied(&mut la);
    assert_eq!(la.read.newest_held().unwrap().0, e(Role::Read));
    assert_eq!(la.write.newest_held().unwrap().0, e(Role::Write));
    assert!(la.admin.held().next().is_none());

    let mut pa = ActorEpochs::default();
    ingest(&w.a, &s, &Opener::Actor { member: w.p, epochs: &w.pe }, &mut pa, None).unwrap();
    applied(&mut pa);
    for r in ROLES {
        assert_eq!(pa.role(r).newest_held().unwrap().0, e(r));
    }
}

// spec/crypto.md §4: concurrent rotations of one role fork the epoch; each removes only boxes
// keyed with that role at the epochs it superseded, so both rotations' boxes survive the merge in
// either order and members hold both secrets; the next rotation supersedes both and its history
// box carries both.
#[test]
fn fork_merge() {
    let w = World::new();
    let derived = ActorEpochs::derived(&w.pe, &w.a);
    let r1 = rotate(&w.a, &all(), &derived, &Secrets::default(), &w.members(), &|_, _| true, &mut rng(1)).unwrap();
    let mut base = Secrets::default();
    r1.secrets.apply(&mut base);
    let mut view = derived.clone();
    r1.record(&mut view);

    let x = rotate(&w.a, &read(), &view, &base, &w.members(), &|_, _| true, &mut rng(2)).unwrap();
    let y = rotate(&w.a, &read(), &view, &base, &w.members(), &|_, _| true, &mut rng(3)).unwrap();
    let (ex, ey) = (x.rotated[0].epoch, y.rotated[0].epoch);
    assert_eq!((ex.n(), ey.n()), (3, 3));
    assert_ne!(ex, ey);
    // Only read boxes at the superseded epoch are removed.
    assert!(x.secrets.removed.iter().all(|k| k.role == Role::Read));
    assert_eq!(x.secrets.removed.len(), 2); // P and M; L's box is keyed at write

    let (mut s1, mut s2) = (base.clone(), base.clone());
    x.secrets.apply(&mut s1);
    y.secrets.apply(&mut s1);
    y.secrets.apply(&mut s2);
    x.secrets.apply(&mut s2);
    assert_eq!(s1, s2);
    for e in [ex, ey] {
        for m in [w.p, w.m] {
            assert!(s1.boxes.contains_key(&box_key(m, Role::Read, &e)));
        }
        // L (write key actor) gets a read-only box keyed at read.
        assert!(s1.boxes.contains_key(&box_key(w.l, Role::Read, &e)));
    }
    // L's earlier write-keyed box survives: write was not rotated.
    let ew = r1.rotated.iter().find(|r| r.role == Role::Write).unwrap().epoch;
    assert!(s1.boxes.contains_key(&box_key(w.l, Role::Write, &ew)));

    // A member's view after both deltas: both current, newest by lowest nonce; both secrets held.
    let mut ma = ActorEpochs::default();
    let mut k1 = Keys::default();
    r1.secrets.applied(&mut ma, (&r1.keys, &k1)).unwrap();
    r1.keys.apply(&mut k1);
    for rot in [&x, &y] {
        rot.secrets.applied(&mut ma, (&rot.keys, &k1)).unwrap();
    }
    ingest(&w.a, &s1, &Opener::Actor { member: w.m, epochs: &w.me }, &mut ma, None).unwrap();
    let mut cur = vec![ex, ey];
    cur.sort();
    assert_eq!(ma.read.current(), cur);
    let newest = if ex.nonce() < ey.nonce() { ex } else { ey };
    assert_eq!(ma.read.newest(), Some(newest));
    assert!(ma.read.secret(&ex).is_some() && ma.read.secret(&ey).is_some());

    // The next rotation by a node holding both supersedes both; its history carries both.
    let mut zview = view.clone();
    x.record(&mut zview);
    y.record(&mut zview);
    let z = rotate(&w.a, &read(), &zview, &s1, &w.members(), &|_, _| true, &mut rng(4)).unwrap();
    assert_eq!(z.rotated[0].supersedes, [ex, ey].into_iter().collect());
    assert_eq!(z.rotated[0].epoch.n(), 4);
    let mut s3 = s1.clone();
    z.secrets.apply(&mut s3);
    assert!(!s3.boxes.keys().any(|k| k.role == Role::Read && (k.epoch == osis_keys::aspects::to_schema(&ex) || k.epoch == osis_keys::aspects::to_schema(&ey))));
    // A member that only gets the newest box reaches every earlier read secret by history.
    let mut fresh = ActorEpochs::default();
    ingest(&w.a, &s3, &Opener::Actor { member: w.m, epochs: &w.me }, &mut fresh, None).unwrap();
    // Holding s3 as a compaction snapshot establishes what it keys; history supersedes the rest.
    assert!(osis_keys::snapshot_keyed(&s3, &mut fresh).unwrap());
    for e in [ex, ey, r1.rotated[0].epoch, ep(1, 0x20)] {
        assert!(fresh.read.secret(&e).is_some(), "{e:?}");
    }
    assert_eq!(fresh.read.current(), vec![z.rotated[0].epoch]);
    assert!(s3.history.contains_key(&history_key(Role::Read, &ex)));
}
