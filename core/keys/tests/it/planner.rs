#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! What a removal reaches, wrap epochs, label epochs and delete keys (spec/permissions.md §3,
//! spec/crypto.md §5, §7, spec/sync-ids.md §2, spec/sync-ids.md §6).

use crate::common;
use common::*;
use osis_base::{CommitId, CreationRecord, Role, Tid, Ts};
use osis_crypto::{Epoch, LabelRole, Secret32, label_role_key};
use osis_keys::{
    ActorEpochs, Graph, PermGraph, newer_than_head, reached,
    registered_epoch, registration_epochs, roles_up_to, delete_candidates, delete_key, wrap_epoch,
};
use osis_perm::{At, Edge, EdgeOp, RoleCommit, MemoryHeldSet, Timeline};
use std::collections::{BTreeMap, BTreeSet};

fn set(r: &[Role]) -> BTreeSet<Role> {
    r.iter().copied().collect()
}

/// A role graph held in memory.
#[derive(Default)]
struct MemoryGraph {
    edges: BTreeMap<Tid, Vec<(Tid, Role)>>,
}

impl Graph for MemoryGraph {
    fn edges(&self, holder: &Tid) -> Vec<(Tid, Role)> {
        self.edges.get(holder).cloned().unwrap_or_default()
    }
}

// spec/permissions.md §3: `reached` (the labels a removal is placed under) is the fixpoint of
// the things one hop from the start or from a thing reached, never through the avoided holder,
// on random graphs with cycles and first admins, and stays linear on a lattice with 6^11 paths.
#[test]
fn reached_is_the_hop_fixpoint() {
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    for _ in 0..300 {
        let mut g = MemoryGraph::default();
        for v in 1..=8u8 {
            for t in 1..=8u8 {
                if t != v && next(4) == 0 {
                    let role = [Role::Read, Role::Write, Role::Admin][next(3) as usize];
                    g.edges.entry(tid(v)).or_default().push((tid(t), role));
                }
            }
        }
        let (start, avoid) = (tid(1 + next(8) as u8), tid(1 + next(8) as u8));
        if start == avoid {
            continue;
        }
        let hop = |v: &Tid| g.edges.get(v).into_iter().flatten().map(|x| x.0);
        let mut want: BTreeSet<Tid> = BTreeSet::new();
        loop {
            let more: BTreeSet<Tid> = std::iter::once(start).chain(want.iter().copied()).flat_map(|v| hop(&v).collect::<Vec<_>>()).filter(|t| *t != start && *t != avoid).collect();
            if more.is_subset(&want) {
                break;
            }
            want.extend(more);
        }
        assert_eq!(reached(&g, start, avoid), want);
    }
    let mut g = MemoryGraph::default();
    let mut layer = vec![tid(200)];
    for l in 0..12u8 {
        let next: Vec<Tid> = (0..6u8).map(|i| tid(l * 6 + i + 1)).collect();
        for v in &layer {
            g.edges.insert(*v, next.iter().map(|t| (*t, Role::Write)).collect());
        }
        layer = next;
    }
    assert_eq!(reached(&g, tid(200), tid(250)).len(), 72);
}

// spec/permissions.md §3: the graph over perm's timeline (live edges, record edges included).
#[test]
fn perm_graph() {
    let mut held = MemoryHeldSet::new();
    let d = held.create(CreationRecord::KeyActor { alg: 1, public_key: vec![7; 32], nonce: [1; 32], account: false });
    let p = held.create(CreationRecord::Thing { admin: d, nonce: [2; 32], link: None });
    let t = held.create(CreationRecord::Thing { admin: p, nonce: [3; 32], link: None });
    let a2 = held.create(CreationRecord::Thing { admin: d, nonce: [4; 32], link: None });
    held.add_commit(RoleCommit {
        id: CommitId([9; 32]),
        ts: Ts::make(osis_base::WallMs(1000), 0).unwrap(),
        author: d,
        actor: d,
        frontier: None,
        ops: vec![EdgeOp { target: a2, holder: p, edge: Some(Edge::new(Role::Write)) }],
    });
    let tl = Timeline::evaluate(&held);
    let g = PermGraph { timeline: &tl, at: At::now(Ts::make(osis_base::WallMs(2000), 0).unwrap()) };
    let mut edges = g.edges(&p);
    edges.sort();
    let mut want = vec![(a2, Role::Write), (t, Role::Admin)];
    want.sort();
    assert_eq!(edges, want);
    assert_eq!(reached(&g, p, tid(99)), BTreeSet::from([t, a2]));
}

// spec/crypto.md §5: wrap under the newest current read epoch held; stranded: none;
// a rotation commit under the newest read epoch it supersedes.
#[test]
fn wrap_epochs() {
    let rg = &mut rng(0);
    let mut a = person(0x20);
    assert_eq!(wrap_epoch(&a.read), Some(ep(1, 0x20)));
    a.read.set_history(ep(2, 5), BTreeSet::new(), [ep(1, 0x20)]);
    a.read.set_established(ep(2, 5), osis_keys::Provenance::Fixed);
    assert_eq!(wrap_epoch(&a.read), None);
    assert_eq!(wrap_epoch(&ActorEpochs::default().read), None);
    let pe = person(0x20);
    let mut view = ActorEpochs::derived(&pe, &tid(1));
    let r = osis_keys::rotate(&tid(1), &roles_up_to(Role::Admin), &view, &Default::default(), &[], &osis_keys::Names::default(), &mut *rg).unwrap();
    assert_eq!(r.wrap_epoch(), ActorEpochs::derived(&pe, &tid(1)).read.newest());
    view = r.preview(&view).unwrap();
    assert_eq!(wrap_epoch(&view.read), Some(r.role(Role::Read).unwrap().epoch));
    let w = osis_keys::rotate(&tid(1), &set(&[Role::Write]), &view, &Default::default(), &[], &osis_keys::Names::default(), &mut *rg).unwrap();
    assert_eq!(w.wrap_epoch(), None);
}

// spec/sync-ids.md §2, spec/sync-ids.md §6: label keys come from the sync, write and admin roles' newest epochs (the
// read epoch gives the claim set only); a node finds the held epoch a head registered by its key;
// an admin holding a newer sync, write or admin epoch than the head re-registers, a newer read
// epoch alone makes no step.
#[test]
fn label_epochs() {
    let mut a = person(0x20);
    let [s, r, w, ad] = registration_epochs(&a).unwrap();
    assert_eq!((s.0, r.0, w.0, ad.0), (ep(1, 0x20), ep(1, 0x20), ep(1, 0x20), ep(1, 0x20)));
    let key = label_role_key(LabelRole::Sync, s.1).verifying_key();
    assert_ne!(label_role_key(LabelRole::Sync, r.1).verifying_key(), key, "the sync key derives from the sync secret");
    let head = [Some(ep(1, 0x20)), Some(ep(1, 0x20)), Some(ep(1, 0x20))];
    a.read.set_history(ep(2, 1), BTreeSet::new(), [ep(1, 0x20)]);
    a.read.set_established(ep(2, 1), osis_keys::Provenance::Fixed);
    a.read.set_secret(ep(2, 1), Secret32::from_bytes([9; 32]));
    assert!(!newer_than_head(&a, head), "the read epoch registers no key");
    a.sync.set_history(ep(2, 1), BTreeSet::new(), [ep(1, 0x20)]);
    a.sync.set_established(ep(2, 1), osis_keys::Provenance::Fixed);
    a.sync.set_secret(ep(2, 1), Secret32::from_bytes([8; 32]));
    assert_eq!(registered_epoch(&a, LabelRole::Sync, &key), Some(ep(1, 0x20)));
    assert_eq!(registered_epoch(&a, LabelRole::Sync, &label_role_key(LabelRole::Sync, &Secret32::from_bytes([8; 32])).verifying_key()), Some(ep(2, 1)));
    assert!(newer_than_head(&a, head));
    assert!(!newer_than_head(&a, [Some(ep(2, 1)), Some(ep(1, 0x20)), Some(ep(1, 0x20))]));
    assert!(!newer_than_head(&a, [None, Some(ep(1, 0x20)), Some(ep(1, 0x20))]));
    a.admin.observe(ep(2, 2));
    a.admin.set_history(ep(2, 2), BTreeSet::new(), [ep(1, 0x20)]);
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
// order as the base actor's, so after P's rotation removing a node the plain group U's head (its
// epochs before) is stepped every time, not by nonce luck.
#[test]
fn jumped_base_rotation_steps_plain_group() {
    let (p, u) = (tid(2), tid(11));
    let s1 = Secret32::from_bytes([0x51; 32]);
    for b in 0..32u8 {
        let mut pe = jumped_person(b);
        let before = ActorEpochs::derived(&pe, &u);
        let [s, _, w, ad] = registration_epochs(&before).unwrap().map(|(e, _)| Some(e));
        let head = [s, w, ad];
        assert!(!newer_than_head(&before, head));
        // k2 removed: the rotation boxes k1 only
        let r = osis_keys::rotate(&p, &roles_up_to(Role::Admin), &pe, &Default::default(), &[key_rcpt(tid(3), Role::Admin, &s1)], &osis_keys::Names::default(), &mut rng(b.into())).unwrap();
        pe = r.preview(&pe).unwrap();
        let after = ActorEpochs::derived(&pe, &u);
        assert!(newer_than_head(&after, head), "seed {b}");
        assert_eq!(after.read.newest().unwrap().n(), osis_keys::MAX_FREE_N - 1);
    }
}

// spec/crypto.md §3, §4: concurrent base actor forks past the cap; U's newest derived epoch is the one
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
        // nested: V under plain U carries P's order through U's derived epochs
        let v = tid(12);
        let vs = osis_crypto::thing_role_secret(&ds, Role::Read, &v);
        let ve = Epoch::derive(&v, Role::Read, osis_keys::MAX_FREE_N - 1, &vs).unwrap();
        assert_eq!(ActorEpochs::derived(&d, &v).read.newest(), Some(ve), "seed {b}");
    }
}

// spec/crypto.md §7: delete keys per level from the newest held secret; level 2 from the
// author's actor; holders try every epoch; the published keyset names the same key.
#[test]
fn delete_keys() {
    let dk = |s: &Secret32| osis_crypto::DeleteSecret::derive(s).verifying_key();
    let (mut thing, author) = (person(0x20), person(0x30));
    assert_eq!(delete_key(1, &thing, Some(&author)), Some(dk(thing.admin.secret(&ep(1, 0x20)).unwrap())));
    assert_eq!(delete_key(2, &thing, Some(&author)), Some(dk(author.write.secret(&ep(1, 0x30)).unwrap())));
    assert_eq!(delete_key(3, &thing, Some(&author)), Some(dk(thing.write.secret(&ep(1, 0x20)).unwrap())));
    assert_eq!(delete_key(2, &thing, None), None);
    let ks = osis_keys::keyset(&ep(1, 0x20), thing.admin.secret(&ep(1, 0x20)).unwrap(), &Default::default(), &Default::default());
    assert_eq!(ks.delete_key, osis_schema::core_types::SigningKey::Ed25519(delete_key(1, &thing, None).unwrap().to_bytes().to_vec()));
    thing.write.set_history(ep(2, 0), BTreeSet::new(), [ep(1, 0x20)]);
    thing.write.set_established(ep(2, 0), osis_keys::Provenance::Fixed);
    thing.write.set_secret(ep(2, 0), Secret32::from_bytes([5; 32]));
    assert_eq!(delete_key(3, &thing, None), Some(dk(&Secret32::from_bytes([5; 32]))));
    let c: Vec<_> = delete_candidates(3, &thing, None).into_iter().map(|x| x.0).collect();
    assert_eq!(c, vec![ep(2, 0), ep(1, 0x20)]);
    assert!(delete_candidates(2, &thing, None).is_empty());
    // no admin secret held, no level-1 key (a writer takes the published one)
    let mut writer = person(0x40);
    writer.admin = Default::default();
    assert_eq!(delete_key(1, &writer, None), None);
}
