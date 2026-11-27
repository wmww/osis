#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The rebuildable caches (notes/local-store.md; notes/engine-store.md, Open): the persisted
//! index, its `node/perm` rows and the saved role walks. That an open from them gives what a
//! rebuild from the commit records gives is the debug check after sampled transactions
//! (`Engine::check_index`); these are the rules it cannot reach: damage, crashes, restores.

use crate::common;
use crate::flows::{edge_of, people, spread, thing_of};
use common::*;
use osis_base::{Clock, ManualClock, Role, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::SeededRng;
use osis_engine::flows::Demotion;
use osis_engine::local_peer::LocalPeer;
use osis_engine::{Config, Engine, Mutation};
use osis_schema::Codec;
use osis_schema::core_types as ct;
use osis_store::{Fault, Faults, MemoryBackend, MemoryRoot};
use std::sync::Arc;

/// `holder`'s edge on `thing` by the engine (`None` removes it); refusals are fine.
fn try_edge(e: &mut Engine, thing: Tid, holder: Tid, role: Option<Role>) {
    // remove + put (spec/permissions.md §2)
    let mut m = Mutation::new();
    m.op(thing, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Weak(holder)) }).unwrap();
    if let Some(r) = role {
        m.op(thing, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Weak(holder))], op: Op::Set(edge(r).to_value()) }).unwrap();
    }
    // an explicit removal (with no frontier, a finalize) or a write that audits carries one
    // (spec/permissions.md §2, §5.1)
    if e.needs_frontier(&thing, &holder, role.map(edge).as_ref()) {
        m.frontier(osis_perm::Frontier::default());
    }
    let _ = e.commit(m);
}

/// Reopens and checks the timeline against what the node had and against one from-scratch
/// evaluation (the timeline is derived at each open).
fn reopen_same(e: &mut Engine, at: &str) {
    let perm = e.perm_digest(false);
    e.reload().unwrap();
    assert_eq!(e.perm_digest(false), perm, "{at}: reopened");
    assert_eq!(e.perm_digest(true), perm, "{at}: from scratch");
}

// spec: none (rebuildable caches): a truncated, garbled or missing `node/perm` row, an index
// tagged with other rules (its states joined so) or a row that does not decode, each make the
// open evaluate anew from the commit records: what the node had (an invalid part included, its
// state joined again), the rows saved again for the next open
#[test]
fn damaged_caches_are_rebuilt() {
    let (mut lp, ps) = people(3);
    let (pa, pb, pc) = (ps[0], ps[1], ps[2]);
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
    let before = (e.index_digest(), e.perm_digest(false), e.perm_rows().unwrap());
    assert!(before.0.commits.values().any(|c| c.valid.contains(&false)), "an invalid part is indexed");
    reopen_same(e, "reopened");
    for how in 0..5u8 {
        match how {
            0..3 => assert_eq!(e.damage_perm_rows(how).unwrap(), before.2.len()),
            // another build's rules: everything valid, states joined so; then a row that does
            // not decode
            _ => e.damage_index(how == 4).unwrap(),
        }
        if how == 3 {
            // its body went: no rules join it again
            assert_eq!(e.get(&d, &reg).unwrap(), Some(s("bob before")), "the old rules' state");
        }
        e.reload().unwrap();
        assert_eq!((e.index_digest(), e.perm_digest(false), e.perm_rows().unwrap()), before, "index damage {how}");
        assert!(e.index_current().unwrap(), "index damage {how}: tagged again");
        assert_eq!(e.get(&d, &reg).unwrap(), Some(s("bob before")), "index damage {how}: joined again");
    }
}

// spec: none (notes/engine.md, Stamps): a reload or rebuild of the indexes builds them anew, so
// no answer kept of the old ones (`Engine::memo`) is taken for current afterwards
#[test]
fn a_reload_moves_every_read_of_the_indexes() {
    let mut lp = net(1, 0);
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let me = e.tid();
    let t = e.new_thing(&mut m, me);
    e.commit(m).unwrap();
    for i in 0..10u8 {
        try_edge(e, t, Tid::from_bytes([60 + i; 15]), Some(Role::Read));
    }
    let memo = osis_engine::engine::Kept::new("test: commit ids");
    let runs = std::cell::Cell::new(0);
    let read = |e: &mut osis_engine::Engine| {
        e.memo(&memo, &(), |e| {
            runs.set(runs.get() + u32::from(!osis_base::memo::comparing()));
            Ok(e.commit_ids())
        })
        .unwrap()
    };
    for rebuild in [false, true] {
        let ids = read(e);
        assert_eq!(read(e), ids);
        let before = runs.get();
        if rebuild {
            e.rebuild_index().unwrap();
        } else {
            e.reload().unwrap();
        }
        assert_eq!(read(e), ids);
        assert_eq!(runs.get(), before + 1, "rebuild {rebuild}: the kept ids read again once");
    }
}

// spec/permissions.md §5.1 step 5 (the walk is a function of the held commits): new things
// between opens (leaves by their `created.0`, then edges on them) read alike reopened and from
// scratch
#[test]
fn new_things_between_opens_read_alike() {
    let mut lp = net(1, 0);
    let e = &mut lp.peers[0].engine;
    let me = e.tid();
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, me);
    e.commit(m).unwrap();
    for i in 0..80u8 {
        try_edge(e, t, Tid::from_bytes([60 + i % 5; 15]), Some(if i % 2 == 0 { Role::Read } else { Role::Write }));
    }
    reopen_same(e, "reopened");
    let mut smaller = false;
    for k in 0..12 {
        let mut m = Mutation::new();
        let d = e.new_thing(&mut m, me);
        e.commit(m).unwrap();
        smaller |= d < t;
        if k % 3 == 0 {
            try_edge(e, d, Tid::from_bytes([60; 15]), Some(Role::Read));
        }
        reopen_same(e, &format!("new thing {k}"));
    }
    assert!(smaller, "no new thing below the saved root");
}

// spec/commits.md §4 (applies in one storage transaction): all or none; spec: none (rebuildable caches): a crash at any durable write
// of a content commit and then of edge writes, then open: the open computes what a rebuild of
// what landed computes
#[test]
fn crash_at_every_write_keeps_caches_exact() {
    let mut crashed_any = false;
    for n in 0.. {
        let faults = Faults::new();
        let (backend, root, clock) = (MemoryBackend::with_faults(faults.clone()), MemoryRoot::with_faults(faults.clone()), Arc::new(ManualClock::new(T0)));
        let blob_disk = (MemoryBackend::with_faults(faults.clone()), MemoryRoot::with_faults(faults.clone()));
        let open = |create: bool, seed: u64| -> osis_engine::Result<Engine> {
            let c: Arc<dyn Clock> = clock.clone();
            let e = if create {
                Engine::create(Box::new(backend.clone()), Box::new(root.clone()), osis_engine::local_peer::blob_area(&blob_disk, seed)?, Config::default(), c, Box::new(SeededRng::from_u64(seed)))?
            } else {
                Engine::open(Box::new(backend.clone()), Box::new(root.clone()), osis_engine::local_peer::blob_area(&blob_disk, seed)?, Config::default(), c, Box::new(SeededRng::from_u64(seed)))?
            };
            Ok(e)
        };
        let mut e = open(true, 0).unwrap();
        let me = e.tid();
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
        e.check_index();
        if !crashed {
            break;
        }
        crashed_any = true;
    }
    assert!(crashed_any);
}
