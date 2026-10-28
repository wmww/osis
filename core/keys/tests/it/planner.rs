#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Rotation planner, wrap epochs, label epochs and delete keys (spec/permissions.md §3,
//! spec/crypto.md §5, §7, spec/sync.md §2, §5).

use crate::common;
use common::*;
use osis_core::{CommitId, CreationRecord, Role, Tid, Ts};
use osis_crypto::{Secret32, label_role_key};
use osis_keys::{
    ActorEpochs, Departure, Graph, MemoryGraph, PermGraph, WrapEpoch, label_role, lost_access, newer_than_head, plan_departure, plan_inside,
    registered_epoch, registration_epochs, roles_up_to, delete_candidates, delete_key, wrap_epoch,
};
use osis_perm::{At, Dots, Edge, EdgeOp, MembershipCommit, MemoryHeldSet, Timeline};
use std::collections::BTreeSet;

fn set(r: &[Role]) -> BTreeSet<Role> {
    r.iter().copied().collect()
}

/// P (person) owns T1 (own secrets) and plain U, which owns T3 (own); P writes team A2, which
/// reads doc T4 and owns T5.
fn graph() -> MemoryGraph {
    let mut g = MemoryGraph::default();
    let [p, t1, u, t3, a2, t4, t5] = [2, 10, 11, 12, 20, 21, 22].map(tid);
    g.owned.insert(p, vec![t1, u]);
    g.owned.insert(u, vec![t3]);
    g.owned.insert(a2, vec![t5]);
    g.edges.insert(p, vec![(a2, Role::Write)]);
    g.edges.insert(a2, vec![(t4, Role::Read)]);
    g.own_secrets = [p, t1, t3, a2, t4, t5].into_iter().collect();
    g
}

// spec/permissions.md §3: a device removed from P requires rotating P's roles it held and, on
// every thing with secrets of its own that P's roles open, transitively, the roles P holds there
// (through plain things too); the plan names the departures each must cover.
#[test]
fn device_removal_cascade() {
    let g = graph();
    let (p, d) = (tid(2), tid(1));
    let plan = plan_departure(&g, p, d, Role::Read, Role::Admin);
    let all = roles_up_to(Role::Admin);
    assert_eq!(plan.immediate(), Some((p, &all)));
    let req: Vec<(Tid, BTreeSet<Role>)> = plan.required().into_iter().map(|(t, e)| (*t, e.roles.clone())).collect();
    let rw = set(&[Role::Read, Role::Write]);
    assert_eq!(
        req,
        vec![(p, all.clone()), (tid(10), all.clone()), (tid(20), rw.clone()), (tid(12), all.clone()), (tid(21), set(&[Role::Read])), (tid(22), rw.clone())]
    );
    assert!(!plan.entries[&tid(11)].own_secrets);
    let dd = Departure::member(d, Role::Read);
    assert_eq!(plan.entries[&p].departures, [dd.clone()].into_iter().collect());
    assert_eq!(plan.entries[&tid(12)].departures, [Departure::inside(tid(11), &Departure::inside(p, &dd))].into_iter().collect());
    assert_eq!(plan.entries[&tid(21)].departures, [Departure::inside(tid(20), &Departure::inside(p, &dd))].into_iter().collect());
    // Top-down: P, then what P reaches directly, then the next hop.
    let order: Vec<Tid> = plan.required().into_iter().map(|(t, _)| *t).collect();
    assert_eq!(order, vec![p, tid(10), tid(20), tid(12), tid(21), tid(22)]);
    // A writer of A2 rotates its read and write there; nothing elsewhere.
    let mine = plan.mine(&|t| if *t == tid(20) { rw.clone() } else { BTreeSet::new() });
    assert_eq!(mine, vec![(tid(20), rw.clone())]);
}

// spec/permissions.md §3 (per-role KEM keys, spec/crypto.md §3): a demotion exposes only the
// roles lost; through P's write secret only write-role boxes of things below open.
#[test]
fn demotion_scope() {
    let g = graph();
    let plan = plan_departure(&g, tid(2), tid(1), Role::Admin, Role::Admin);
    assert_eq!(plan.entries[&tid(2)].roles, set(&[Role::Admin]));
    assert_eq!(plan.entries[&tid(10)].roles, set(&[Role::Admin]));
    assert!(!plan.entries.contains_key(&tid(20)));
    let plan = plan_departure(&g, tid(2), tid(1), Role::Write, Role::Admin);
    assert_eq!(plan.entries[&tid(20)].roles, set(&[Role::Write]));
    assert!(!plan.entries.contains_key(&tid(21)));
    assert_eq!(plan.entries[&tid(22)].roles, set(&[Role::Write]));
    // A read member's removal: read only, everywhere.
    let plan = plan_departure(&g, tid(2), tid(1), Role::Read, Role::Read);
    assert!(plan.required().into_iter().all(|(_, e)| e.roles == set(&[Role::Read])));
    // Nothing lost: nothing to do.
    assert!(plan_departure(&g, tid(2), tid(1), Role::Admin, Role::Write).entries.is_empty());
}

// spec/permissions.md §3: cycles of membership terminate; a node that lost read access drops the
// actor and what it reads by no other path.
// spec/permissions.md §3 (drop lost secrets)
#[test]
fn cycles_and_lost_access() {
    let mut g = MemoryGraph::default();
    let (a, b, c) = (tid(1), tid(2), tid(3));
    g.edges.insert(a, vec![(b, Role::Admin)]);
    g.edges.insert(b, vec![(a, Role::Read), (c, Role::Read)]);
    g.own_secrets = [a, b, c].into_iter().collect();
    let plan = plan_inside(&g, a, roles_up_to(Role::Admin), Departure::member(tid(9), Role::Read));
    assert_eq!(plan.entries[&a].roles, roles_up_to(Role::Admin));
    assert_eq!(plan.entries[&b].roles, roles_up_to(Role::Admin));
    assert_eq!(plan.entries[&c].roles, set(&[Role::Read]));
    let lost = lost_access(&g, b, &|t| *t == c);
    assert_eq!(lost, vec![b, a]);
}

// spec/permissions.md §3: the planner runs over perm's timeline (owned things and live edges).
#[test]
fn perm_graph() {
    let mut held = MemoryHeldSet::new();
    let d = held.create(CreationRecord::KeyActor { alg: 1, public_key: vec![7; 32], nonce: [1; 32] });
    let p = held.create(CreationRecord::Thing { owner: d, nonce: [2; 32] });
    let t = held.create(CreationRecord::Thing { owner: p, nonce: [3; 32] });
    let a2 = held.create(CreationRecord::Thing { owner: d, nonce: [4; 32] });
    held.add_commit(MembershipCommit {
        id: CommitId([9; 32]),
        ts: Ts::make(osis_core::WallMs(1000), 0).unwrap(),
        author: d,
        actor: d,
        frontier: None,
        ops: vec![EdgeOp { target: a2, member: p, edge: Some(Edge::new(Role::Write)), dots: Dots::Node { lo: 0, hi: 1 } }],
    });
    let tl = Timeline::evaluate(&held);
    let own = |x: &Tid| *x != t;
    let g = PermGraph { timeline: &tl, at: At::now(Ts::make(osis_core::WallMs(2000), 0).unwrap()), own_secrets: &own };
    assert_eq!(g.owned(&p), vec![t]);
    assert_eq!(g.edges(&p), vec![(a2, Role::Write)]);
    let plan = plan_departure(&g, p, tid(99), Role::Read, Role::Admin);
    assert_eq!(plan.entries[&a2].roles, set(&[Role::Read, Role::Write]));
    assert!(!plan.entries[&t].own_secrets);
}

// spec/crypto.md §5: wrap under the newest current read epoch held; stranded: the newest held;
// a rotation commit under the newest read epoch it supersedes.
#[test]
fn wrap_epochs() {
    let mut a = person(0x20);
    assert_eq!(wrap_epoch(&a.read), WrapEpoch::Current(ep(1, 0x20)));
    a.read.rotation(ep(2, 5), [ep(1, 0x20)]);
    a.read.set_established(ep(2, 5), osis_keys::Provenance::Own);
    assert_eq!(wrap_epoch(&a.read), WrapEpoch::Stranded(ep(1, 0x20)));
    assert_eq!(wrap_epoch(&ActorEpochs::default().read), WrapEpoch::None);
    let pe = person(0x20);
    let mut view = ActorEpochs::derived(&pe, &tid(1));
    let r = osis_keys::rotate(&tid(1), &roles_up_to(Role::Admin), &view, &Default::default(), &[], &|_, _| true, &mut rng(1)).unwrap();
    assert_eq!(r.wrap_epoch(), Some(ep(1, 0x20)));
    r.record(&mut view);
    assert_eq!(wrap_epoch(&view.read), WrapEpoch::Current(r.rotated[0].epoch));
    let w = osis_keys::rotate(&tid(1), &set(&[Role::Write]), &view, &Default::default(), &[], &|_, _| true, &mut rng(2)).unwrap();
    assert_eq!(w.wrap_epoch(), None);
}

// spec/sync.md §2, §5: label keys come from each role's newest epoch; a node finds the held epoch
// a head registered by its key; an admin holding a newer epoch than the head re-registers.
#[test]
fn label_epochs() {
    let mut a = person(0x20);
    let [r, w, ad] = registration_epochs(&a).unwrap();
    assert_eq!((r.0, w.0, ad.0), (ep(1, 0x20), ep(1, 0x20), ep(1, 0x20)));
    let key = label_role_key(label_role(Role::Read), r.1, 3).verifying_key();
    a.read.rotation(ep(2, 1), [ep(1, 0x20)]);
    a.read.set_established(ep(2, 1), osis_keys::Provenance::Own);
    a.read.set_secret(ep(2, 1), Secret32::from_bytes([9; 32]));
    assert_eq!(registered_epoch(&a.read, Role::Read, 3, &key), Some(ep(1, 0x20)));
    assert_eq!(registered_epoch(&a.read, Role::Read, 4, &key), None);
    let head = [Some(ep(1, 0x20)), Some(ep(1, 0x20)), Some(ep(1, 0x20))];
    assert!(newer_than_head(&a, head));
    assert!(!newer_than_head(&a, [Some(ep(2, 1)), Some(ep(1, 0x20)), Some(ep(1, 0x20))]));
    assert!(!newer_than_head(&a, [None, Some(ep(1, 0x20)), Some(ep(1, 0x20))]));
    a.admin.observe(ep(2, 2));
    a.admin.rotation(ep(2, 2), [ep(1, 0x20)]);
    a.admin.set_established(ep(2, 2), osis_keys::Provenance::Own);
    assert!(registration_epochs(&a).is_none());
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
    let ks = osis_keys::keyset(&ep(1, 0x20), thing.admin.secret(&ep(1, 0x20)).unwrap());
    assert_eq!(ks.delete_key, osis_schema::core_types::SigningKey::Ed25519(delete_key(1, &thing, None).unwrap().to_bytes().to_vec()));
    thing.write.rotation(ep(2, 0), [ep(1, 0x20)]);
    thing.write.set_established(ep(2, 0), osis_keys::Provenance::Own);
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
