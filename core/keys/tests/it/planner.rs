//! Wrap epochs, sync ID epochs and delete keys (spec/crypto.md §5, §7, spec/sync-ids.md §2,
//! spec/sync-ids.md §6).

use crate::common::*;
use osis_base::Role;
use osis_crypto::{Epoch, RoleKey, Secret32, role_key};
use osis_keys::{
    ActorEpochs, newer_than_head,
    registered_epoch, registration_epochs, roles_up_to, delete_candidates, wrap_epoch,
};
use std::collections::BTreeSet;

// spec/crypto.md §5: wrap under the newest current read epoch held; stranded: none;
// a rotation commit under the newest read epoch it supersedes.
#[test]
fn wrap_epochs() {
    let rg = &mut rng(0);
    let mut a = actor_epochs(0x20);
    assert_eq!(wrap_epoch(&a.read), Some(ep(1, 0x20)));
    a.read.set_history(ep(2, 5), BTreeSet::new(), [ep(1, 0x20)], None);
    a.read.set_established(ep(2, 5), osis_keys::Provenance::Fixed);
    assert_eq!(wrap_epoch(&a.read), None);
    assert_eq!(wrap_epoch(&ActorEpochs::default().read), None);
    let pe = actor_epochs(0x20);
    let mut view = ActorEpochs::derived(&pe, &tid(1));
    let r = osis_keys::rotate(&tid(1), &roles_up_to(Role::Admin), &view, &Default::default(), &[], &osis_keys::Names::default(), &mut *rg).unwrap();
    assert_eq!(r.wrap_epoch(), ActorEpochs::derived(&pe, &tid(1)).read.newest());
    view = r.preview(&view).unwrap();
    assert_eq!(wrap_epoch(&view.read), Some(r.role(Role::Read).unwrap().epoch));
    let w = osis_keys::rotate(&tid(1), &roles(&[Role::Write]), &view, &Default::default(), &[], &osis_keys::Names::default(), &mut *rg).unwrap();
    assert_eq!(w.wrap_epoch(), None);
}

// spec/sync-ids.md §2, spec/sync-ids.md §6: role keys come from the sync, write and admin roles' newest epochs (the
// read epoch gives the claim set only); a node finds the held epoch a head registered by its key;
// an admin holding a newer sync, write or admin epoch than the head re-registers, a newer read
// epoch alone makes no step.
#[test]
fn sync_id_epochs() {
    let mut a = actor_epochs(0x20);
    let [s, r, w, ad] = registration_epochs(&a).unwrap();
    assert_eq!((s.0, r.0, w.0, ad.0), (ep(1, 0x20), ep(1, 0x20), ep(1, 0x20), ep(1, 0x20)));
    let key = role_key(RoleKey::Sync, s.1).verifying_key();
    assert_ne!(role_key(RoleKey::Sync, r.1).verifying_key(), key, "the sync key derives from the sync secret");
    let head = [Some(ep(1, 0x20)), Some(ep(1, 0x20)), Some(ep(1, 0x20))];
    a.read.set_history(ep(2, 1), BTreeSet::new(), [ep(1, 0x20)], None);
    a.read.set_established(ep(2, 1), osis_keys::Provenance::Fixed);
    a.read.set_secret(ep(2, 1), Secret32::from_bytes([9; 32]));
    assert!(!newer_than_head(&a, head), "the read epoch registers no key");
    a.sync.set_history(ep(2, 1), BTreeSet::new(), [ep(1, 0x20)], None);
    a.sync.set_established(ep(2, 1), osis_keys::Provenance::Fixed);
    a.sync.set_secret(ep(2, 1), Secret32::from_bytes([8; 32]));
    assert_eq!(registered_epoch(&a, RoleKey::Sync, &key), Some(ep(1, 0x20)));
    assert_eq!(registered_epoch(&a, RoleKey::Sync, &role_key(RoleKey::Sync, &Secret32::from_bytes([8; 32])).verifying_key()), Some(ep(2, 1)));
    assert!(newer_than_head(&a, head));
    assert!(!newer_than_head(&a, [Some(ep(2, 1)), Some(ep(1, 0x20)), Some(ep(1, 0x20))]));
    assert!(!newer_than_head(&a, [None, Some(ep(1, 0x20)), Some(ep(1, 0x20))]));
    a.admin.observe(ep(2, 2));
    a.admin.set_history(ep(2, 2), BTreeSet::new(), [ep(1, 0x20)], None);
    a.admin.set_established(ep(2, 2), osis_keys::Provenance::Fixed);
    assert!(registration_epochs(&a).is_none());
}

/// Account P (nodes `k1`, `k2`) whose epochs a writer jumped past the cap, every role at
/// `MAX_FREE_N + 5`, secrets varying with `b`.
fn jumped_person(b: u8) -> ActorEpochs {
    let mut pe = ActorEpochs::default();
    for (i, r) in osis_keys::ROLES.into_iter().enumerate() {
        let e = Epoch::derive(&tid(2), r, osis_keys::MAX_FREE_N + 5, &Secret32::from_bytes([b ^ (i as u8) << 6; 32])).unwrap();
        pe.role_mut(r).set_secret(e, Secret32::from_bytes([b ^ (i as u8) << 6; 32]));
        pe.role_mut(r).set_established(e, osis_keys::Provenance::Fixed);
    }
    pe
}

// spec/crypto.md §3, §4, spec/sync-ids.md §6: past the cap derived epochs all sit at n 2^62 − 1 but
// order as the mint admin's, so after P's rotation removing a node the dependent thing U's head (its
// epochs before) is stepped every time, not by nonce luck.
#[test]
fn jumped_mint_admin_rotation_steps_a_dependent_thing() {
    let (p, u) = (tid(2), tid(11));
    for b in 0..32u8 {
        let mut pe = jumped_person(b);
        let before = ActorEpochs::derived(&pe, &u);
        let [s, _, w, ad] = registration_epochs(&before).unwrap().map(|(e, _)| Some(e));
        let head = [s, w, ad];
        assert!(!newer_than_head(&before, head));
        // k2 removed: the rotation boxes k1 only
        let r = osis_keys::rotate(&p, &roles_up_to(Role::Admin), &pe, &Default::default(), &[actor_rcpt(tid(3), Role::Admin, &actor_epochs(0x51))], &osis_keys::Names::default(), &mut rng(b.into())).unwrap();
        pe = r.preview(&pe).unwrap();
        let after = ActorEpochs::derived(&pe, &u);
        assert!(newer_than_head(&after, head), "seed {b}");
        assert_eq!(after.read.newest().unwrap().n(), osis_keys::MAX_FREE_N - 1);
    }
}

// spec/crypto.md §3, §4: concurrent mint admin forks past the cap; U's newest derived epoch is the one
// derived from P's newest (greater n), whatever the derived nonces.
#[test]
fn jumped_base_forks_derive_base_newest() {
    let (p, u) = (tid(2), tid(11));
    for b in 0..32u8 {
        let base = jumped_person(b);
        // fork A: two rotations (n + 2); fork B: one (n + 1); both current
        let mut a = base.clone();
        for i in 0..2u64 {
            let r = osis_keys::rotate(&p, &roles_up_to(Role::Admin), &a, &Default::default(), &[], &osis_keys::Names::default(), &mut rng(u64::from(b) << 8 | i)).unwrap();
            a = r.preview(&a).unwrap();
        }
        let mut pe = a.clone();
        let rb = osis_keys::rotate(&p, &roles_up_to(Role::Admin), &base, &Default::default(), &[], &osis_keys::Names::default(), &mut rng(u64::from(b) << 8 | 9)).unwrap();
        pe = rb.preview(&pe).unwrap();
        let want = a.read.newest().unwrap();
        assert_eq!(pe.read.current().len(), 2);
        assert_eq!(pe.read.newest(), Some(want));
        let d = ActorEpochs::derived(&pe, &u);
        let ds = osis_crypto::thing_role_secret(a.read.secret(&want).unwrap(), Role::Read, &u);
        let de = Epoch::derive(&u, Role::Read, osis_keys::MAX_FREE_N - 1, &ds).unwrap();
        assert_eq!(d.read.newest(), Some(de), "seed {b}");
        assert_eq!(wrap_epoch(&d.read), Some(de), "seed {b}");
        // nested: V minted with dependent U carries P's order through U's derived epochs
        let v = tid(12);
        let vs = osis_crypto::thing_role_secret(&ds, Role::Read, &v);
        let ve = Epoch::derive(&v, Role::Read, osis_keys::MAX_FREE_N - 1, &vs).unwrap();
        assert_eq!(ActorEpochs::derived(&d, &v).read.newest(), Some(ve), "seed {b}");
    }
}

// spec/crypto.md §7: a level's delete key from its newest held secret (the step key of its role);
// level 2 from the author's actor; holders try every epoch.
#[test]
fn delete_keys() {
    let dk = |l: u8, s: &Secret32| osis_crypto::DeleteSecret::at_level(l, s).verifying_key();
    fn delete_key(l: u8, t: &ActorEpochs, a: Option<&ActorEpochs>) -> Option<osis_crypto::VerifyingKey> {
        delete_candidates(l, t, a).first().map(|(_, s)| osis_crypto::DeleteSecret::at_level(l, s).verifying_key())
    }
    let (mut thing, author) = (actor_epochs(0x20), actor_epochs(0x30));
    assert_eq!(delete_key(1, &thing, Some(&author)), Some(dk(1, thing.admin.secret(&ep(1, 0x20)).unwrap())));
    // a level's key is its role's step key (spec/sync-ids.md §2)
    assert_eq!(delete_key(1, &thing, None), Some(osis_crypto::role_key(osis_crypto::RoleKey::Delete, thing.admin.secret(&ep(1, 0x20)).unwrap()).verifying_key()));
    assert_eq!(delete_key(3, &thing, None), Some(osis_crypto::role_key(osis_crypto::RoleKey::Write, thing.write.secret(&ep(1, 0x20)).unwrap()).verifying_key()));
    assert_eq!(delete_key(2, &thing, Some(&author)), Some(dk(2, author.write.secret(&ep(1, 0x30)).unwrap())));
    assert_eq!(delete_key(3, &thing, Some(&author)), Some(dk(3, thing.write.secret(&ep(1, 0x20)).unwrap())));
    assert_eq!(delete_key(2, &thing, None), None);
    thing.write.set_history(ep(2, 0), BTreeSet::new(), [ep(1, 0x20)], None);
    thing.write.set_established(ep(2, 0), osis_keys::Provenance::Fixed);
    thing.write.set_secret(ep(2, 0), Secret32::from_bytes([5; 32]));
    assert_eq!(delete_key(3, &thing, None), Some(dk(3, &Secret32::from_bytes([5; 32]))));
    let c: Vec<_> = delete_candidates(3, &thing, None).into_iter().map(|x| x.0).collect();
    assert_eq!(c, vec![ep(2, 0), ep(1, 0x20)]);
    assert!(delete_candidates(2, &thing, None).is_empty());
    // no admin secret held, no level-1 secret (a writer lists the step's public key)
    let mut writer = actor_epochs(0x40);
    writer.admin = Default::default();
    assert_eq!(delete_key(1, &writer, None), None);
}
