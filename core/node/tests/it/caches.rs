#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The rebuildable caches (notes/local-store.md; notes/engine-store.md, Open): the persisted
//! index, its `node/edges` rows and the saved role walks. That an open from them gives what a
//! rebuild from the commit records gives is the debug check after sampled transactions
//! (`Engine::check_index`); these are the rules it cannot reach: damage, crashes, restores.

use crate::common;
use crate::flows::{edge_of, people, spread, thing_of};
use common::*;
use osis_base::{Clock, ManualClock, Role, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::SeededRng;
use osis_node::flows::Demotion;
use osis_node::local_peer::LocalPeer;
use osis_node::{Config, Engine, Mutation};
use osis_schema::Codec;
use osis_schema::core_types as ct;
use osis_store::{Fault, Faults, MemoryBackend, MemoryRoot};
use std::sync::Arc;

/// `holder`'s edge on `thing` by the engine (`None` removes it); refusals are fine.
fn try_edge(e: &mut Engine, thing: Tid, holder: Tid, role: Option<Role>) {
    // remove + put (spec/permissions.md §2)
    let mut m = Mutation::new();
    m.op(thing, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(holder)) }).unwrap();
    if let Some(r) = role {
        m.op(thing, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(holder))], op: Op::Set(edge(r).to_value()) }).unwrap();
    }
    // an explicit removal (with no frontier, a finalize) or a write that audits carries one
    // (spec/permissions.md §2, §5.1)
    if e.needs_frontier(&thing, &holder, role.map(edge).as_ref()) {
        m.frontier(ct::Frontier::default().to_value());
    }
    let _ = e.commit(m);
}

/// Reopens and checks the timelines against what the node had and against one from-scratch
/// evaluation; returns how many components the open restored from saved walks.
fn reopen_same(e: &mut Engine, at: &str) -> usize {
    let perm = e.perm_digest(false);
    e.reload().unwrap();
    assert_eq!(e.perm_digest(false), perm, "{at}: reopened");
    assert_eq!(e.perm_digest(true), perm, "{at}: from scratch");
    e.walks_restored()
}

// spec: none (rebuildable caches): a truncated, garbled or missing `node/edges` row, an index
// tagged with other rules (its states joined so) or a row that does not decode, and a saved walk
// truncated, with a flipped bit or saved under other rules, each make the open evaluate anew from
// the commit records: what the node had (an invalid part included, its state joined again), the
// rows and walks saved again for the next open
#[test]
fn damaged_caches_are_rebuilt() {
    let (mut lp, ps) = people(3);
    let (pa, pb, pc) = (ps[0], ps[1], ps[2]);
    lp.peers[0].engine.set_walk_cache_min(1);
    let d = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&d, &pc, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    let write = |lp: &mut LocalPeer, i: usize, v: &str| {
        let mut m = Mutation::new();
        m.set(d, &REG, &s(v)).unwrap();
        lp.peers[i].commit(m).unwrap().unwrap()
    };
    write(&mut lp, 1, "bob before");
    spread(&mut lp);
    lp.advance(10);
    lp.peers[0].engine.demote(&d, &Demotion { holder: pb, new: None, retain: None }).unwrap();
    lp.advance(10);
    write(&mut lp, 1, "bob after");
    spread(&mut lp);
    let e = &mut lp.peers[0].engine;
    let reg = ak("t:reg.0");
    assert_eq!(e.get(&d, &reg).unwrap(), Some(s("bob before")), "bob's late write invalid here");
    let before = (e.index_digest(), e.perm_digest(false), e.edges_rows().unwrap());
    assert!(before.0.commits.values().any(|c| c.valid.contains(&false)), "an invalid part is indexed");
    reopen_same(e, "saved");
    assert!(reopen_same(e, "restored") > 0);
    for how in 0..5u8 {
        match how {
            0..3 => assert_eq!(e.damage_edges(how).unwrap(), before.2.len()),
            // another build's rules: everything valid, states joined so; then a row that does
            // not decode
            _ => e.damage_index(how == 4).unwrap(),
        }
        if how == 3 {
            // its body went: no rules join it again
            assert_eq!(e.get(&d, &reg).unwrap(), Some(s("bob before")), "the old rules' state");
        }
        e.reload().unwrap();
        assert_eq!((e.index_digest(), e.perm_digest(false), e.edges_rows().unwrap()), before, "index damage {how}");
        assert!(e.index_current().unwrap(), "index damage {how}: tagged again");
        assert_eq!(e.get(&d, &reg).unwrap(), Some(s("bob before")), "index damage {how}: joined again");
    }
    for how in 0..3u8 {
        assert!(e.damage_walks(how).unwrap() > 0);
        assert_eq!(reopen_same(e, &format!("walk damage {how}")), 0, "walk damage {how}: not used");
        assert!(reopen_same(e, &format!("after walk damage {how}")) > 0, "walk damage {how}: saved again");
    }
}

// spec: none (notes/engine-store.md, Open): a reopen of the caches never takes the engine's generation
// back, so a cache keyed on it (the sync engine's labels) is never taken for current afterwards
#[test]
fn reload_never_takes_generation_back() {
    let mut lp = net(1, 0);
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let me = e.me();
    let t = e.new_thing(&mut m, me);
    e.commit(m).unwrap();
    for i in 0..10u8 {
        try_edge(e, t, Tid::from_bytes([60 + i; 15]), Some(Role::Read));
    }
    for rebuild in [false, true] {
        let before = e.core.generation;
        if rebuild {
            e.rebuild_index().unwrap();
        } else {
            e.reload().unwrap();
        }
        assert!(e.core.generation > before, "rebuild {rebuild}: {} after {before}", e.core.generation);
    }
}

// spec/permissions.md §5.1 step 5; spec: none (rebuildable caches): new things in a saved
// component between opens (leaves by their `created.0`, one of them with a smaller tid than the
// saved root, then edges on them) still resume its walk
#[test]
fn new_things_between_opens_still_restore() {
    let mut lp = net(1, 0);
    let e = &mut lp.peers[0].engine;
    let me = e.me();
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, me);
    e.commit(m).unwrap();
    for i in 0..80u8 {
        try_edge(e, t, Tid::from_bytes([60 + i % 5; 15]), Some(if i % 2 == 0 { Role::Read } else { Role::Write }));
    }
    reopen_same(e, "saved");
    assert_eq!(reopen_same(e, "restored"), 1);
    let mut smaller = false;
    for k in 0..12 {
        let mut m = Mutation::new();
        let d = e.new_thing(&mut m, me);
        e.commit(m).unwrap();
        smaller |= d < t;
        if k % 3 == 0 {
            try_edge(e, d, Tid::from_bytes([60; 15]), Some(Role::Read));
        }
        assert_eq!(reopen_same(e, &format!("new thing {k}")), 1, "new thing {k}: evaluated from scratch");
    }
    assert!(smaller, "no new thing below the saved root");
}

// spec/commits.md §4 (all or none); spec: none (rebuildable caches): a crash at any durable write
// of a content commit and then of edge writes that save their component's walk, then open: the
// open resumes the walk saved before, and computes what a rebuild of what landed computes
#[test]
fn crash_at_every_write_keeps_caches_exact() {
    let mut crashed_any = false;
    for n in 0.. {
        let faults = Faults::new();
        let (backend, root, clock) = (MemoryBackend::with_faults(faults.clone()), MemoryRoot::with_faults(faults.clone()), Arc::new(ManualClock::new(T0)));
        let blob_disk = (MemoryBackend::with_faults(faults.clone()), MemoryRoot::with_faults(faults.clone()));
        let open = |create: bool, seed: u64| -> osis_node::Result<Engine> {
            let c: Arc<dyn Clock> = clock.clone();
            let mut e = if create {
                Engine::create(Box::new(backend.clone()), Box::new(root.clone()), osis_node::local_peer::blob_area(&blob_disk, seed)?, Config::default(), c, Box::new(SeededRng::from_u64(seed)))?
            } else {
                Engine::open(Box::new(backend.clone()), Box::new(root.clone()), osis_node::local_peer::blob_area(&blob_disk, seed)?, Config::default(), c, Box::new(SeededRng::from_u64(seed)))?
            };
            e.set_walk_cache_min(1);
            Ok(e)
        };
        let mut e = open(true, 0).unwrap();
        e.create_account(&[]).unwrap();
        let me = e.me();
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, me);
        m.set(t, &REG, &s("one")).unwrap();
        e.commit(m).unwrap();
        for i in 0..6u8 {
            try_edge(&mut e, t, Tid::from_bytes([70 + i; 15]), Some(Role::Read));
        }
        faults.at(n, Fault::Crash);
        clock.advance(1);
        let mut m = Mutation::new();
        m.set(t, &REG, &s("two")).unwrap();
        m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s("x")) }).unwrap();
        let _ = e.commit(m);
        for i in 0..6u8 {
            clock.advance(1);
            try_edge(&mut e, t, Tid::from_bytes([70 + i; 15]), Some(Role::Write));
        }
        let crashed = faults.crashed();
        drop(e);
        faults.revive();
        let mut e = open(false, 1).unwrap();
        assert_eq!(e.perm_digest(false), e.perm_digest(true), "crash at write {n}");
        // the first grants saved the walk before the faults: every open resumes it
        assert!(e.walks_restored() > 0, "crash at write {n}: the saved walk was not used");
        e.check_index();
        if !crashed {
            break;
        }
        crashed_any = true;
    }
    assert!(crashed_any);
}
