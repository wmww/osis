#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The saved membership walks (notes/local-store.md, rebuildable caches; notes/node.md, Open):
//! an open resumes each component's walk from the store and gives what a from-scratch
//! evaluation gives (spec/permissions.md §5.1 step 5: validity is a function of the held set);
//! a damaged, truncated or foreign walk is evaluated anew, never an error; a crash at any write
//! leaves no walk ahead of its commits. Likewise the index's rows of what perm reads of each
//! membership commit (`node/edges`): an open from them equals a rebuild from the commit records.

use crate::common;
use common::*;
use osis_core::{Clock, ManualClock, Role, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::SeededRng;
use osis_node::local_peer::LocalPeer;
use osis_node::{Config, Engine, Mutation};
use osis_schema::Codec;
use osis_schema::core_types as ct;
use osis_store::{Fault, Faults, MemoryBackend, MemoryRoot};
use std::sync::Arc;

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

/// `member`'s edge on `thing` by the engine (`None` removes it); refusals are fine.
fn try_edge(e: &mut Engine, thing: Tid, member: Tid, role: Option<Role>) {
    let mut m = Mutation::new();
    let op = match role {
        Some(r) => PathOp { path: vec![PathSeg::Key(Value::Tid(member))], op: Op::Set(edge(r).to_value()) },
        None => PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(member)) },
    };
    m.op(thing, &ct::MEMBERS, op).unwrap();
    let _ = e.commit(m);
}

/// The index digest without the held set's arrival order.
fn validity(d: &str) -> String {
    d.lines().filter(|l| !l.starts_with("held ")).collect::<Vec<_>>().join("\n")
}

/// Reopens the engine's indexes from its store and checks the timelines against what it had
/// and against one from-scratch evaluation; returns how many components were restored.
fn reopen_same(e: &mut Engine, at: &str) -> usize {
    let (perm, index) = (e.perm_digest(false), e.index_digest());
    assert_eq!(perm, e.perm_digest(true), "{at}: before the reopen");
    e.reload_index().unwrap();
    assert_eq!(e.perm_digest(false), perm, "{at}: reopened");
    assert_eq!(e.perm_digest(true), perm, "{at}: from scratch");
    // held commits are listed in arrival order, which an open does not keep
    assert_eq!(validity(&e.index_digest()), validity(&index), "{at}: index");
    e.walks_restored()
}

/// Reopens from the persisted index (perm's inputs from the `node/edges` rows), then rebuilds
/// from the commit records: the same timelines, validity and rows.
fn reopen_equals_rebuild(e: &mut Engine, at: &str) {
    assert!(e.index_current().unwrap(), "{at}: index not current");
    let rows = e.edges_rows().unwrap();
    e.reload_index().unwrap();
    let (perm, index) = (e.perm_digest(false), validity(&e.index_digest()));
    assert_eq!(perm, e.perm_digest(true), "{at}: reopened against from scratch");
    e.rebuild_index().unwrap();
    assert_eq!(e.perm_digest(false), perm, "{at}: rebuilt");
    assert_eq!(validity(&e.index_digest()), index, "{at}: rebuilt index");
    assert_eq!(e.edges_rows().unwrap(), rows, "{at}: rebuilt rows");
}

/// Two nodes: peer 0 owns the docs and a team, makes peer 1 admin of some, both write edges,
/// peer 0 demotes peer 1 now and then (dropping its unreceived writes) and snapshots rosters;
/// commits travel late and out of order.
/// Returns how many membership snapshots it made.
fn history(seed: u64, steps: usize, mut each: impl FnMut(&mut LocalPeer, usize, &mut Rng)) -> usize {
    let mut rng = Rng(seed | 1);
    let mut snapshots = 0;
    let mut lp = LocalPeer::new(2, seed, T0).unwrap();
    for p in &mut lp.peers {
        p.engine.set_walk_cache_min(1 + rng.below(4) as usize);
    }
    let docs: Vec<Tid> = (0..4).map(|_| new_thing(&mut lp, 0)).collect();
    let team = new_thing(&mut lp, 0);
    let p1 = lp.peers[1].engine.tid();
    let members: Vec<Tid> = (0..6u8).map(|i| Tid::from_bytes([50 + i; 15])).chain([team]).collect();
    for step in 0..steps {
        let doc = docs[rng.below(4) as usize];
        let roles = [None, Some(Role::Read), Some(Role::Write), Some(Role::Admin)];
        match rng.below(10) {
            0 | 1 => try_edge(&mut lp.peers[0].engine, doc, p1, roles[rng.below(4) as usize]),
            2..=6 => {
                let i = rng.below(2) as usize;
                let m = members[rng.below(members.len() as u64) as usize];
                try_edge(&mut lp.peers[i].engine, doc, m, roles[rng.below(3) as usize]);
            }
            7 => {
                let _ = lp.peers[0].engine.roster_snapshot(&doc, None);
                // a membership snapshot (of the node's `/keys`) reaches perm's inputs too
                let node = lp.peers[0].engine.tid();
                if let Ok(Some(_)) = lp.peers[0].engine.snapshot(&node, &osis_core::Ak::new("/keys").unwrap()) {
                    snapshots += 1;
                }
            }
            _ => {
                let (a, b) = if rng.below(2) == 0 { (0, 1) } else { (1, 0) };
                lp.sync(a, b).unwrap();
            }
        }
        lp.peers[rng.below(2) as usize].clock.advance(1 + rng.below(3));
        each(&mut lp, step, &mut rng);
    }
    snapshots
}

// spec/permissions.md §5.1 step 5, §6: reopening from the saved walks (exact, or older and
// continued over the commits since) gives the timelines a from-scratch evaluation gives, rosters
// and ledgers included, over random two-node histories with late arrivals, demotions and roster
// snapshots
#[test]
fn reopen_from_saved_walks_equals_from_scratch() {
    let mut restored = 0;
    for seed in 1..=4u64 {
        let _ = history(seed * 7919, 120, |lp, step, rng| {
            if rng.below(6) == 0 {
                let i = rng.below(2) as usize;
                restored += reopen_same(&mut lp.peers[i].engine, &format!("seed {seed} step {step} peer {i}"));
            }
        });
    }
    assert!(restored > 0, "no walk was restored");
}

// spec/permissions.md §5.1 step 5, §6; spec: none (local store index, notes/node.md Open): an
// open adapting perm's inputs from the index's per-commit rows gives what a rebuild from the
// commit records gives (timelines, validity, the rows themselves) over random two-node histories
// with late arrivals, demotions, roster snapshots and membership snapshots
#[test]
fn reopen_from_edge_rows_equals_rebuild() {
    let mut snapshots = 0;
    for seed in 1..=4u64 {
        snapshots += history(seed * 104_729, 100, |lp, step, rng| {
            if rng.below(8) == 0 {
                let i = rng.below(2) as usize;
                reopen_equals_rebuild(&mut lp.peers[i].engine, &format!("seed {seed} step {step} peer {i}"));
            }
        });
    }
    assert!(snapshots > 0, "no membership snapshot");
}

// spec: none (local store index, notes/node.md Open): a truncated, garbled or missing
// `node/edges` row, or an index tagged with other rules, makes the open rebuild from the commit
// records: the same timelines and validity, and the rows written again as they were
#[test]
fn damaged_edge_rows_are_rebuilt() {
    let mut lp = LocalPeer::new(2, 0xed6e, T0).unwrap();
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let me = e.tid();
    let t = e.new_thing(&mut m, me);
    e.commit(m).unwrap();
    for i in 0..20u8 {
        try_edge(e, t, Tid::from_bytes([60 + i % 5; 15]), Some(if i % 2 == 0 { Role::Read } else { Role::Write }));
        if i == 9 {
            e.roster_snapshot(&t, None).unwrap();
        }
    }
    let (perm, index) = (e.perm_digest(false), validity(&e.index_digest()));
    let rows = e.edges_rows().unwrap();
    assert!(rows.len() > 20);
    for how in 0..4u8 {
        if how < 3 {
            assert_eq!(e.damage_edges(how).unwrap(), rows.len());
        } else {
            e.damage_index(false).unwrap();
        }
        e.reload_index().unwrap();
        assert_eq!(e.perm_digest(false), perm, "damage {how}");
        assert_eq!(validity(&e.index_digest()), index, "damage {how}: index");
        assert_eq!(e.edges_rows().unwrap(), rows, "damage {how}: rows");
        assert!(e.index_current().unwrap());
    }
}

// spec: none (local store cache, notes/local-store.md): a saved walk truncated, with a flipped
// bit, or saved under other rules is not used: the open evaluates anew (the same timelines) and
// saves it again, so the next open restores it
#[test]
fn damaged_saved_walks_are_rebuilt() {
    let mut lp = LocalPeer::new(2, 0x5eed, T0).unwrap();
    let e = &mut lp.peers[0].engine;
    e.set_walk_cache_min(1);
    let mut m = Mutation::new();
    let me = e.tid();
    let t = e.new_thing(&mut m, me);
    e.commit(m).unwrap();
    for i in 0..20u8 {
        try_edge(e, t, Tid::from_bytes([60 + i % 5; 15]), Some(if i % 2 == 0 { Role::Read } else { Role::Write }));
    }
    reopen_same(e, "saved");
    assert!(reopen_same(e, "restored") > 0);
    for how in 0..3u8 {
        assert!(e.damage_walks(how).unwrap() > 0);
        assert_eq!(reopen_same(e, &format!("damage {how}")), 0, "damage {how}: not used");
        assert!(reopen_same(e, &format!("after damage {how}")) > 0, "damage {how}: saved again");
    }
}

struct Dev {
    faults: Faults,
    backend: MemoryBackend,
    root: MemoryRoot,
    clock: Arc<ManualClock>,
}

impl Dev {
    fn create(&self) -> Engine {
        let c: Arc<dyn Clock> = self.clock.clone();
        let mut e = Engine::create(Box::new(self.backend.clone()), Box::new(self.root.clone()), Config::default(), c, Box::new(SeededRng::from_u64(9))).unwrap();
        e.set_walk_cache_min(1);
        e
    }
    fn open(&self) -> osis_node::Result<Engine> {
        let c: Arc<dyn Clock> = self.clock.clone();
        let mut e = Engine::open(Box::new(self.backend.clone()), Box::new(self.root.clone()), Config::default(), c, Box::new(SeededRng::from_u64(10)))?;
        e.set_walk_cache_min(1);
        Ok(e)
    }
}

// spec/commits.md §4 (all or none); spec: none (local store cache, notes/local-store.md): a crash
// at any durable write of edge writes (and a roster snapshot) that save their component's walk,
// then open: the open resumes a saved walk, its timelines equal a from-scratch evaluation of what
// landed, and the index's `node/edges` rows equal a rebuild's
#[test]
fn crash_at_every_write_keeps_saved_walks_exact() {
    let mut crashed_any = false;
    for n in 0.. {
        let faults = Faults::new();
        let dev = Dev { backend: MemoryBackend::with_faults(faults.clone()), root: MemoryRoot::with_faults(faults.clone()), faults, clock: Arc::new(ManualClock::new(T0)) };
        let mut e = dev.create();
        let mut m = Mutation::new();
        let me = e.tid();
        let t = e.new_thing(&mut m, me);
        e.commit(m).unwrap();
        for i in 0..6u8 {
            try_edge(&mut e, t, Tid::from_bytes([70 + i; 15]), Some(Role::Read));
        }
        dev.faults.at(n, Fault::Crash);
        for i in 0..6u8 {
            dev.clock.advance(1);
            try_edge(&mut e, t, Tid::from_bytes([70 + i; 15]), Some(Role::Write));
            if i == 2 {
                let _ = e.roster_snapshot(&t, None);
            }
        }
        let crashed = dev.faults.crashed();
        drop(e);
        dev.faults.revive();
        let mut e = dev.open().unwrap();
        assert_eq!(e.perm_digest(false), e.perm_digest(true), "crash at write {n}");
        // the first grants saved the walk before the faults: every open resumes it
        assert!(e.walks_restored() > 0, "crash at write {n}: the saved walk was not used");
        // the `node/edges` rows the open read are those of what landed
        reopen_equals_rebuild(&mut e, &format!("crash at write {n}"));
        if !crashed {
            break;
        }
        crashed_any = true;
    }
    assert!(crashed_any);
}

// spec/permissions.md §5.1 step 5; spec: none (local store cache, notes/local-store.md): new
// things in a saved component between opens (leaves by their `/created`, one of them with a
// smaller tid than the saved root, then edges on them) still resume its walk
#[test]
fn new_things_between_opens_still_restore() {
    let mut lp = LocalPeer::new(1, 0x7e57, T0).unwrap();
    let e = &mut lp.peers[0].engine;
    let me = e.tid();
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
