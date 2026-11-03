#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A departure two hops below a doc (spec/crypto.md §4 covers rule by names; spec/permissions.md
//! §3 top-down rotation and the box judgement of a holder actor's keyset, recursive): device D
//! removed from person P, P holder of team T, T holder of doc U.

use crate::common;
use common::*;
use osis_base::{Role, Tid};
use osis_crypto::Secret32;
use osis_keys::{
    ActorEpochs, AllHeld, Departure, HolderKeys, Key, MemoryGraph, MemoryHeldActors, Name, Names, Opener, Recipient, ingest, keeps_out, may_encrypt_under, plan_departure,
    roles_up_to, rotate,
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
    Recipient { holder: tid(0x11), role: Role::Admin, keys: HolderKeys::KeyActor { kem: osis_crypto::KeyActorKeys::from_seed(&seed).kem.public().clone(), seed: Some(seed) } }
}

/// An actor holder whose secrets the node holds (symmetric boxes naming its newest epoch).
fn holder(a: &Actor, role: Role) -> Recipient {
    Recipient { holder: a.tid, role, keys: HolderKeys::from_keys(&keys_of(&a.view)).unwrap().with_own(&a.view) }
}

fn rotated(a: &Actor, holders: &[Recipient], seed: u64) -> Actor {
    rotated_naming(a, holders, seed, &Names::default())
}

fn rotated_naming(a: &Actor, holders: &[Recipient], seed: u64, names: &Names) -> Actor {
    let r = rotate(&a.tid, &roles_up_to(Role::Admin), &a.view, &a.s, holders, names, &mut rng(seed)).unwrap();
    let (mut view, mut s) = (a.view.clone(), a.s.clone());
    r.secrets.apply(&mut s);
    view = r.preview(&view).unwrap();
    Actor { tid: a.tid, view, s }
}

fn fresh(t: Tid, holders: &[Recipient], seed: u64) -> Actor {
    let derived = ActorEpochs::derived(&ActorEpochs::key_actor(&rseed()), &t);
    rotated(&Actor { tid: t, view: derived, s: Secrets::default() }, holders, seed)
}

fn held(actors: &[&Actor]) -> MemoryHeldActors {
    let mut h = MemoryHeldActors::default();
    for a in actors {
        h.map.insert(a.tid, (std::sync::Arc::new(a.s.clone()), a.view.clone()));
    }
    h
}

// spec/permissions.md §3 (Left out): a holder actor's box keeps a departure inside it out only if
// it names the holder's newest keyset epoch and that epoch's boxes keep it out, recursively;
// spec/crypto.md §4: an epoch covers the departure only once its names name it; the chain rotates
// top-down (P, T, U), and the removed device, holding P's old secrets, opens nothing at U's new
// epoch.
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
    let removal = Name { thing: p.tid, key: Key { ts: 4, node: tid(0xd2), commit: osis_base::CommitId([4; 32]) } };
    let named = |d: &Departure| d.clone().at(Some(removal));
    let deps: Vec<Departure> = plan.entries[&u.tid].departures.iter().map(named).collect();
    assert_eq!(deps, vec![Departure::inside(t.tid, &Departure::inside(p.tid, &Departure::holder(dt, Role::Read).at(Some(removal))))]);
    let names = Names { list: [removal].into(), ..Names::default() };

    // D removed from P: P rotates in the removal commit.
    let p2 = rotated_naming(&p, &[owner(), dev(d2t, &d2seed)], 4, &names);
    let boxes_ok = |a: &Actor, h: &MemoryHeldActors, deps: &[Departure]| {
        let (e, _) = a.view.read.newest_held().unwrap();
        deps.iter().all(|d| keeps_out(&a.s, Role::Read, &e, d, h))
    };
    let read_ok = |a: &Actor, deps: &[Departure]| {
        let (e, _) = a.view.read.newest_held().unwrap();
        may_encrypt_under(&a.tid, &a.view, Role::Read, &e, deps, &AllHeld)
    };
    // T unrotated: U's boxes do not keep it out (T's box names T's newest, which does not).
    assert!(!boxes_ok(&u, &held(&[&p2, &t]), &deps));
    // Nor without what the node holds of the chain.
    assert!(!boxes_ok(&u, &held(&[]), &deps));
    let tdeps: Vec<Departure> = plan.entries[&t.tid].departures.iter().map(named).collect();
    assert!(!boxes_ok(&t, &held(&[&p2]), &tdeps) && !read_ok(&t, &tdeps));
    // T rotated without naming the removal: its boxes keep D out, but it covers nothing.
    let t1 = rotated(&t, &[owner(), holder(&p2, Role::Write)], 7);
    assert!(boxes_ok(&t1, &held(&[&p2]), &tdeps) && !read_ok(&t1, &tdeps));
    let t2 = rotated_naming(&t, &[owner(), holder(&p2, Role::Write)], 5, &names);
    assert!(boxes_ok(&t2, &held(&[&p2]), &tdeps) && read_ok(&t2, &tdeps));
    // T rotated: U still names T's old keyset.
    assert!(!boxes_ok(&u, &held(&[&p2, &t2]), &deps) && !read_ok(&u, &deps));
    let u2 = rotated_naming(&u, &[owner(), holder(&t2, Role::Write)], 6, &names);
    assert!(boxes_ok(&u2, &held(&[&p2, &t2]), &deps) && read_ok(&u2, &deps));

    // D holds P's old secrets; following the chain it opens nothing new.
    let mut dp = ActorEpochs::default();
    ingest(&p.tid, &p.s, &Opener::KeyActor { holder: dt, seed: &dseed }, &mut dp, None).unwrap();
    ingest(&p.tid, &p2.s, &Opener::KeyActor { holder: dt, seed: &dseed }, &mut dp, None).unwrap();
    assert!(dp.read.secret(&p2.view.read.newest().unwrap()).is_none());
    let mut dtv = ActorEpochs::default();
    ingest(&t.tid, &t2.s, &Opener::Actor { holder: p.tid, epochs: &dp }, &mut dtv, None).unwrap();
    assert!(dtv.read.secret(&t2.view.read.newest().unwrap()).is_none());
    let mut du = ActorEpochs::default();
    ingest(&u.tid, &u2.s, &Opener::Actor { holder: t.tid, epochs: &dtv }, &mut du, None).unwrap();
    assert!(du.read.secret(&u2.view.read.newest().unwrap()).is_none());
    // The remaining device follows the same chain to U's new epoch.
    let mut d2p = ActorEpochs::default();
    ingest(&p.tid, &p2.s, &Opener::KeyActor { holder: d2t, seed: &d2seed }, &mut d2p, None).unwrap();
    let mut d2tv = ActorEpochs::default();
    ingest(&t.tid, &t2.s, &Opener::Actor { holder: p.tid, epochs: &d2p }, &mut d2tv, None).unwrap();
    let mut d2u = ActorEpochs::default();
    ingest(&u.tid, &u2.s, &Opener::Actor { holder: t.tid, epochs: &d2tv }, &mut d2u, None).unwrap();
    assert!(d2u.read.secret(&u2.view.read.newest().unwrap()).is_some());
}
