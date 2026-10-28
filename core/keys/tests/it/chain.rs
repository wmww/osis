#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A departure two hops below a doc (spec/crypto.md §4 covers rule, recursive; spec/permissions.md
//! §3 top-down rotation): device D removed from person P, P member of team T, T member of doc U.

use crate::common;
use common::*;
use osis_base::{Role, Tid};
use osis_crypto::Secret32;
use osis_keys::{
    ActorEpochs, Departure, MemberKeys, MemoryGraph, MemoryHeldActors, Opener, Recipient, ingest, may_encrypt_under, plan_departure, roles_up_to,
    rotate,
};
use osis_schema::core_types::Secrets;

struct Actor {
    tid: Tid,
    view: ActorEpochs,
    s: Secrets,
}

fn rseed() -> Secret32 {
    Secret32::from_bytes([0x11; 32])
}

/// Recovery key R owns everything; the node holds its seed.
fn owner() -> Recipient {
    let seed = rseed();
    Recipient { member: tid(0x11), role: Role::Admin, keys: MemberKeys::KeyActor { kem: osis_crypto::KeyActorKeys::from_seed(&seed).kem.public().clone(), seed: Some(seed) } }
}

/// An actor member whose secrets the node holds (symmetric boxes naming its newest epoch).
fn holder(a: &Actor, role: Role) -> Recipient {
    Recipient { member: a.tid, role, keys: MemberKeys::from_keys(&keys_of(&a.view)).unwrap().with_own(&a.view) }
}

fn rotated(a: &Actor, members: &[Recipient], seed: u64) -> Actor {
    let r = rotate(&a.tid, &roles_up_to(Role::Admin), &a.view, &a.s, members, &|_, _| true, &mut rng(seed)).unwrap();
    let (mut view, mut s) = (a.view.clone(), a.s.clone());
    r.secrets.apply(&mut s);
    r.record(&mut view);
    Actor { tid: a.tid, view, s }
}

fn fresh(t: Tid, members: &[Recipient], seed: u64) -> Actor {
    let derived = ActorEpochs::derived(&ActorEpochs::key_actor(&rseed()), &t);
    rotated(&Actor { tid: t, view: derived, s: Secrets::default() }, members, seed)
}

fn held(actors: &[&Actor]) -> MemoryHeldActors {
    let mut h = MemoryHeldActors::default();
    for a in actors {
        h.map.insert(a.tid, (a.s.clone(), a.view.clone()));
    }
    h
}

// spec/crypto.md §4: a departure inside a member is covered only if the member's box names its
// newest keyset epoch and that epoch covers the departure, recursively; spec/permissions.md §3:
// the chain rotates top-down (P, T, U), and the removed device, holding P's old secrets, opens
// nothing at U's new epoch.
#[test]
fn two_hop_departure() {
    let (dt, d2t) = (tid(0xd1), tid(0xd2));
    let (dseed, d2seed) = (Secret32::from_bytes([0xd1; 32]), Secret32::from_bytes([0xd2; 32]));
    let dev = |t: Tid, s: &Secret32| key_rcpt(t, Role::Admin, s);
    let p = fresh(tid(2), &[owner(), dev(dt, &dseed), dev(d2t, &d2seed)], 1);
    let t = fresh(tid(3), &[owner(), holder(&p, Role::Write)], 2);
    let u = fresh(tid(4), &[owner(), holder(&t, Role::Write)], 3);

    // The planner: P first (in the removal commit), then T, then U.
    let mut g = MemoryGraph::default();
    g.edges.insert(p.tid, vec![(t.tid, Role::Write)]);
    g.edges.insert(t.tid, vec![(u.tid, Role::Write)]);
    g.own_secrets = [p.tid, t.tid, u.tid].into_iter().collect();
    let plan = plan_departure(&g, p.tid, dt, Role::Read, Role::Admin);
    let order: Vec<Tid> = plan.required().into_iter().map(|(x, _)| *x).collect();
    assert_eq!(order, vec![p.tid, t.tid, u.tid]);
    let deps: Vec<Departure> = plan.entries[&u.tid].departures.iter().cloned().collect();
    assert_eq!(deps, vec![Departure::inside(t.tid, &Departure::inside(p.tid, &Departure::member(dt, Role::Read)))]);

    // D removed from P: P rotates in the removal commit.
    let p2 = rotated(&p, &[owner(), dev(d2t, &d2seed)], 4);
    let read_ok = |a: &Actor, h: &MemoryHeldActors, deps: &[Departure]| {
        let (e, _) = a.view.read.newest_held().unwrap();
        may_encrypt_under(&a.s, &a.view, Role::Read, &e, deps, h)
    };
    // T unrotated: U's epoch does not cover (T's box names T's newest, which does not).
    assert!(!read_ok(&u, &held(&[&p2, &t]), &deps));
    // Nor without what the node holds of the chain.
    assert!(!read_ok(&u, &held(&[]), &deps));
    let tdeps: Vec<Departure> = plan.entries[&t.tid].departures.iter().cloned().collect();
    assert!(!read_ok(&t, &held(&[&p2]), &tdeps));
    let t2 = rotated(&t, &[owner(), holder(&p2, Role::Write)], 5);
    assert!(read_ok(&t2, &held(&[&p2]), &tdeps));
    // T rotated: U still names T's old keyset.
    assert!(!read_ok(&u, &held(&[&p2, &t2]), &deps));
    let u2 = rotated(&u, &[owner(), holder(&t2, Role::Write)], 6);
    assert!(read_ok(&u2, &held(&[&p2, &t2]), &deps));

    // D holds P's old secrets; following the chain it opens nothing new.
    let mut dp = ActorEpochs::default();
    ingest(&p.tid, &p.s, &Opener::KeyActor { member: dt, seed: &dseed }, &mut dp, None).unwrap();
    ingest(&p.tid, &p2.s, &Opener::KeyActor { member: dt, seed: &dseed }, &mut dp, None).unwrap();
    assert!(dp.read.secret(&p2.view.read.newest().unwrap()).is_none());
    let mut dtv = ActorEpochs::default();
    ingest(&t.tid, &t2.s, &Opener::Actor { member: p.tid, epochs: &dp }, &mut dtv, None).unwrap();
    assert!(dtv.read.secret(&t2.view.read.newest().unwrap()).is_none());
    let mut du = ActorEpochs::default();
    ingest(&u.tid, &u2.s, &Opener::Actor { member: t.tid, epochs: &dtv }, &mut du, None).unwrap();
    assert!(du.read.secret(&u2.view.read.newest().unwrap()).is_none());
    // The remaining device follows the same chain to U's new epoch.
    let mut d2p = ActorEpochs::default();
    ingest(&p.tid, &p2.s, &Opener::KeyActor { member: d2t, seed: &d2seed }, &mut d2p, None).unwrap();
    let mut d2tv = ActorEpochs::default();
    ingest(&t.tid, &t2.s, &Opener::Actor { member: p.tid, epochs: &d2p }, &mut d2tv, None).unwrap();
    let mut d2u = ActorEpochs::default();
    ingest(&u.tid, &u2.s, &Opener::Actor { member: t.tid, epochs: &d2tv }, &mut d2u, None).unwrap();
    assert!(d2u.read.secret(&u2.view.read.newest().unwrap()).is_some());
}
