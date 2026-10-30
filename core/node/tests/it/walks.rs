#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The saved membership walks (notes/local-store.md, rebuildable caches; notes/node.md, Open):
//! an open resumes each component's walk from the store and gives what a from-scratch
//! evaluation gives (spec/permissions.md §5.1 step 5: validity is a function of the held set);
//! a damaged, truncated or foreign walk is evaluated anew, never an error; a crash at any write
//! leaves no walk ahead of its commits. Likewise the index's rows of what perm reads of each
//! membership commit (`node/edges`): an open from them equals a rebuild from the commit records.

use crate::common;
use common::*;
use osis_base::Classified;
use osis_base::{Clock, ManualClock, Role, Tid, Value};
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
    // remove + put (spec/permissions.md §2)
    let mut m = Mutation::new();
    m.op(thing, &ct::MEMBERS, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(member)) }).unwrap();
    if let Some(r) = role {
        m.op(thing, &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(member))], op: Op::Set(edge(r).to_value()) }).unwrap();
    }
    let _ = e.commit(m);
}

/// The index digest without the held set's arrival order.
fn validity(d: osis_node::engine::IndexDigest) -> osis_node::engine::IndexDigest {
    d.without_held()
}

/// Reopens the engine's indexes from its store and checks the timelines against what it had
/// and against one from-scratch evaluation; returns how many components were restored.
fn reopen_same(e: &mut Engine, at: &str) -> usize {
    let (perm, index) = (e.perm_digest(false), e.index_digest());
    assert_eq!(perm, e.perm_digest(true), "{at}: before the reopen");
    e.reload().unwrap();
    assert_eq!(e.perm_digest(false), perm, "{at}: reopened");
    assert_eq!(e.perm_digest(true), perm, "{at}: from scratch");
    // held commits are listed in arrival order, which an open does not keep
    assert_eq!(validity(e.index_digest()), validity(index), "{at}: index");
    e.walks_restored()
}

/// Reopens from the persisted index (perm's inputs from the `node/edges` rows), then rebuilds
/// from the commit records: the same timelines, validity and rows.
fn reopen_equals_rebuild(e: &mut Engine, at: &str) {
    assert!(e.index_current().unwrap(), "{at}: index not current");
    let rows = e.edges_rows().unwrap();
    e.reload().unwrap();
    let (perm, index) = (e.perm_digest(false), validity(e.index_digest()));
    assert_eq!(perm, e.perm_digest(true), "{at}: reopened against from scratch");
    e.rebuild_index().unwrap();
    assert_eq!(e.perm_digest(false), perm, "{at}: rebuilt");
    assert_eq!(validity(e.index_digest()), index, "{at}: rebuilt index");
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
                if let Ok(Some(_)) = lp.peers[0].engine.snapshot(&node, &osis_base::Ak::new("/keys").unwrap()) {
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
    let (perm, index) = (e.perm_digest(false), validity(e.index_digest()));
    let rows = e.edges_rows().unwrap();
    assert!(rows.len() > 20);
    for how in 0..4u8 {
        if how < 3 {
            assert_eq!(e.damage_edges(how).unwrap(), rows.len());
        } else {
            e.damage_index(false).unwrap();
        }
        e.reload().unwrap();
        assert_eq!(e.perm_digest(false), perm, "damage {how}");
        assert_eq!(validity(e.index_digest()), index, "damage {how}: index");
        assert_eq!(e.edges_rows().unwrap(), rows, "damage {how}: rows");
        assert!(e.index_current().unwrap());
    }
}

// spec: none (notes/node.md, Open): a reopen of the caches never takes the engine's generation
// back, so a cache keyed on it (the sync engine's labels) is never taken for current afterwards
#[test]
fn reload_never_takes_generation_back() {
    let mut lp = LocalPeer::new(1, 0x6e7e, T0).unwrap();
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let me = e.tid();
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

/// What a node computes, opened from the persisted index and then rebuilt from the commit
/// records: validity, perm's timelines and the states of `things` all equal what it had; the
/// open decodes no header (`LazyHeader`; perm's adaptation reads the views and `node/edges`
/// rows, a membership commit's frontier among the view).
fn open_equals_rebuild(e: &mut Engine, things: &[Tid], at: &str) {
    open_equals_rebuild_decoding(e, things, 0, at);
}

/// `open_equals_rebuild` where the open decodes `decoded` headers.
fn open_equals_rebuild_decoding(e: &mut Engine, things: &[Tid], decoded: usize, at: &str) {
    assert!(e.index_current().unwrap(), "{at}: index not current");
    let had = (validity(e.index_digest()), e.perm_digest(false), states(e, things));
    e.reload().unwrap();
    assert_eq!(e.headers_decoded(), decoded, "{at}: headers the open decoded");
    assert_eq!(had.0.first_diff(&validity(e.index_digest())), None, "{at}: index opened");
    assert_eq!((validity(e.index_digest()), e.perm_digest(false), states(e, things)), had, "{at}: opened from the index");
    e.rebuild_index().unwrap();
    assert_eq!(had.0.first_diff(&validity(e.index_digest())), None, "{at}: index rebuilt");
    assert_eq!((validity(e.index_digest()), e.perm_digest(false), states(e, things)), had, "{at}: rebuilt");
}

fn add_tag(lp: &mut LocalPeer, i: usize, t: Tid, v: &str) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s(v)) }).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

// spec/requirements.md, Decentralization (a node's judgment of every write is a function of the
// data it holds); spec/permissions.md §5.2: after a validity flip (a revoke its writer missed), an
// un-merge (an invalid write arriving), an import (a moved thing), a forget (lost access) and a
// crash at every write of a transaction, an open from the persisted index computes what a
// rebuild from the commit records computes
#[test]
fn open_equals_rebuild_after_each_kind_of_change() {
    let mut lp = LocalPeer::new(3, 0x0be2, T0).unwrap();
    let (a, b, c) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, a);
    lp.peers[0].commit(m).unwrap().unwrap();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, t, c, Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    for i in 0..5 {
        add_tag(&mut lp, 0, t, &format!("e{i}"));
    }
    let bs = add_tag(&mut lp, 1, t, "b");
    let pk1 = lp.packages(1).unwrap();
    lp.deliver(0, pk1.iter().find(|p| p.id == bs).unwrap()).unwrap();
    open_equals_rebuild(&mut lp.peers[0].engine, &[t], "before");
    // C revokes B without having seen B's add: delivered to A, the add turns invalid
    let scope = osis_perm::DemotionScope { membership: [(b, [t].into())].into(), content: [(b, [t].into())].into() };
    let now = lp.peers[2].engine.now();
    let f = lp.peers[2].engine.frontier(&scope, now).unwrap();
    let mut m = Mutation::new();
    m.op(t, &ct::MEMBERS, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(b)) }).unwrap();
    m.frontier(f.to_value());
    let rv = lp.peers[2].commit(m).unwrap().unwrap();
    let late = add_tag(&mut lp, 1, t, "late");
    let (pk2, pk1) = (lp.packages(2).unwrap(), lp.packages(1).unwrap());
    lp.deliver(0, pk2.iter().find(|p| p.id == rv).unwrap()).unwrap();
    let tags = |lp: &mut LocalPeer| match lp.peers[0].engine.get(&t, &ak("/t/tags")).unwrap() {
        Some(Value::Set(s)) => s.len(),
        _ => 0,
    };
    assert_eq!(tags(&mut lp), 5, "the revoke flips B's add invalid");
    open_equals_rebuild(&mut lp.peers[0].engine, &[t], "validity flip");
    lp.deliver(0, pk1.iter().find(|p| p.id == late).unwrap()).unwrap();
    assert_eq!(tags(&mut lp), 5, "B's late add arrives invalid");
    open_equals_rebuild(&mut lp.peers[0].engine, &[t], "un-merge");
    // A moves the thing: a copy written as imports, which C receives
    let (copy, imports) = lp.peers[0].engine.move_thing(&t, a).unwrap();
    assert!(!imports.is_empty());
    open_equals_rebuild(&mut lp.peers[0].engine, &[t, copy], "import (writer)");
    sync(&mut lp, 0, 2);
    assert!(lp.peers[2].engine.header(&imports[0]).is_some(), "C holds the import");
    open_equals_rebuild(&mut lp.peers[2].engine, &[t, copy], "import (receiver)");
}

// spec/requirements.md, Decentralization; spec/permissions.md §3 (drop lost secrets): after a
// member removed from a thing with secrets of its own forgets what it lost, an open from the
// persisted index computes what a rebuild from the commit records computes
#[test]
fn open_equals_rebuild_after_a_forget() {
    let mut lp = LocalPeer::new(2, 0xf0e7, T0).unwrap();
    let servers = vec![osis_label::Address { url: "quic://s1:1".into(), key: [7; 32] }];
    let pa = lp.peers[0].engine.create_person(&servers).unwrap().0.person;
    let pb = lp.peers[1].engine.create_person(&servers).unwrap().0.person;
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    let d = lp.peers[0].engine.new_thing(&mut m, pa);
    m.set(d, &REG, &s("new")).unwrap();
    lp.peers[0].engine.commit(m).unwrap().unwrap();
    lp.peers[0].engine.grant(&d, &pb, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.set(d, &REG, &s("by b")).unwrap();
    lp.peers[1].engine.commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    open_equals_rebuild(&mut lp.peers[1].engine, &[d], "member");
    lp.peers[0].engine.demote(&d, &osis_node::flows::Demotion { member: pb, new: None, presync: osis_node::flows::PreSync::Synced }).unwrap();
    lp.sync_all().unwrap();
    let (_, gone) = lp.peers[1].engine.forget_lost(true).unwrap();
    assert!(gone.things.contains(&d), "B forgets the thing");
    open_equals_rebuild(&mut lp.peers[1].engine, &[d], "forget");
    open_equals_rebuild(&mut lp.peers[0].engine, &[d], "owner");
}

// spec/requirements.md, Decentralization; spec/commits.md §5 (a dropped body leaves no local
// index entry derived from it): after `/secrets` and `/keys` compactions drop a grant's and a
// demotion's rotation bodies, an open from the persisted index computes what a rebuild from the
// commit records computes, whole index included (box and epoch notes, rotation roles, epochs'
// snapshot marks), also after a later rotation
#[test]
fn open_equals_rebuild_after_a_secrets_compaction() {
    let mut lp = LocalPeer::new(4, 0x5ec7, T0).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.tid()).collect();
    let (a, w, r, r2) = (tids[0], tids[1], tids[2], tids[3]);
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, a);
    m.set(t, &REG, &s("x")).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let mut ids = Vec::new();
    for (who, role) in [(w, Role::Write), (r, Role::Read)] {
        ids.extend(lp.peers[0].engine.grant(&t, &who, &edge(role)).unwrap().commits);
    }
    lp.sync_all().unwrap();
    let demote = osis_node::flows::Demotion { member: r, new: None, presync: osis_node::flows::PreSync::Synced };
    ids.extend(lp.peers[0].engine.demote(&t, &demote).unwrap().commits);
    lp.sync_all().unwrap();
    // the admin compacts both aspects and drops every body a snapshot covers
    let compact = |e: &mut Engine, ids: &mut Vec<osis_base::CommitId>| {
        let mut dropped = 0;
        for k in ["/secrets", "/keys"] {
            let k = osis_base::Ak::new(k).unwrap();
            let Some(snap) = e.snapshot(&t, &k).unwrap() else { continue };
            for c in ids.iter() {
                if e.body_not_dropped(c, &t, &k) && e.covered(&snap, c, &t, &k).unwrap() == Some(true) {
                    e.drop_body(c, &t, &k).unwrap();
                    dropped += 1;
                }
            }
            ids.push(snap);
        }
        dropped
    };
    assert!(compact(&mut lp.peers[0].engine, &mut ids) >= 2, "a grant's and a rotation's bodies dropped");
    open_equals_rebuild(&mut lp.peers[0].engine, &[t], "compacted");
    // a later grant and rotation over the compacted aspects, compacted again
    ids.extend(lp.peers[0].engine.grant(&t, &r2, &edge(Role::Read)).unwrap().commits);
    let demote = osis_node::flows::Demotion { member: w, new: None, presync: osis_node::flows::PreSync::Synced };
    ids.extend(lp.peers[0].engine.demote(&t, &demote).unwrap().commits);
    lp.sync_all().unwrap();
    open_equals_rebuild(&mut lp.peers[0].engine, &[t], "rotated after");
    compact(&mut lp.peers[0].engine, &mut ids);
    open_equals_rebuild(&mut lp.peers[0].engine, &[t], "compacted again");
}

// as above, randomized: four nodes grant, demote (rotations), compact `/secrets` and `/keys`
// dropping what the snapshot covers, and pass commits on late and out of order; at random points
// and at the end an open equals a rebuild, whole index included. Seeds: OSIS_WALKS_SECRETS_START,
// OSIS_WALKS_SECRETS_SEEDS (default 0..4), a thread per core (OSIS_WALKS_THREADS).
#[test]
fn open_equals_rebuild_random_secrets_compactions() {
    let range = osis_base::testenv::Seeds::from_env("OSIS_WALKS_SECRETS_START", "OSIS_WALKS_SECRETS_SEEDS", 0..4);
    let seeds: Vec<u64> = range.range.clone().collect();
    let name = "walks::open_equals_rebuild_random_secrets_compactions";
    let replay = |s: u64| format!("OSIS_WALKS_SECRETS_START={s} OSIS_WALKS_SECRETS_SEEDS=1 cargo test --workspace --test it {name} -- --exact");
    let dropped: usize = run_seeds_noted(name, &seeds, range.overridden, "OSIS_WALKS_THREADS", replay, secrets_history).into_iter().sum();
    if !range.overridden {
        assert!(dropped > 0, "no membership body dropped");
    }
}

/// One random history of `open_equals_rebuild_random_secrets_compactions`; how many membership
/// bodies it dropped.
fn secrets_history(seed: u64) -> usize {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut lp = LocalPeer::new(4, 0x5ec0 + seed, T0).unwrap();
    lp.sync_all().unwrap();
    let ids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.tid()).collect();
    let t = new_thing(&mut lp, 0);
    let _ = lp.peers[0].engine.grant(&t, &ids[1], &edge(Role::Admin));
    for m in &ids[2..] {
        let _ = lp.peers[0].engine.grant(&t, m, &edge(Role::Read));
    }
    lp.sync_all().unwrap();
    let mut dropped = 0;
    for step in 0..30 {
        let i = rng.below(4) as usize;
        let m = ids[1 + rng.below(3) as usize];
        match rng.below(8) {
            0 | 1 => {
                let role = [Role::Read, Role::Write, Role::Admin][rng.below(3) as usize];
                let _ = lp.peers[i].engine.grant(&t, &m, &edge(role));
            }
            2 => {
                let d = osis_node::flows::Demotion { member: m, new: None, presync: osis_node::flows::PreSync::Synced };
                let _ = lp.peers[i].engine.demote(&t, &d);
            }
            3 | 4 => {
                let k = ak(["/secrets", "/keys"][rng.below(2) as usize]);
                let e = &mut lp.peers[i].engine;
                if let Ok(Some(snap)) = e.snapshot(&t, &k) {
                    let on: Vec<_> = e.commit_ids().into_iter().filter(|c| *c != snap && e.header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t && x.ak == k))).collect();
                    for c in on {
                        if e.body_not_dropped(&c, &t, &k) && e.covered(&snap, &c, &t, &k).is_ok_and(|x| x == Some(true)) {
                            e.drop_body(&c, &t, &k).unwrap();
                            dropped += 1;
                        }
                    }
                }
            }
            5 | 6 => {
                let j = (i + 1 + rng.below(3) as usize) % 4;
                let pk = lp.packages(i).unwrap();
                let n = pk.len() as u64;
                for _ in 0..1 + rng.below(n + 1) {
                    let _ = lp.deliver(j, &pk[rng.below(n) as usize]);
                }
            }
            _ => open_equals_rebuild(&mut lp.peers[i].engine, &[t], &format!("seed {seed} step {step} peer {i}")),
        }
        lp.peers[i].clock.advance(1 + rng.below(3));
    }
    lp.sync_all().unwrap();
    for i in 0..4 {
        open_equals_rebuild(&mut lp.peers[i].engine, &[t], &format!("seed {seed} end, peer {i}"));
    }
    dropped
}

// spec/requirements.md, Decentralization; spec/commits.md §4 (all or none): a crash at any
// durable write of a content commit and then an edge write, then open: what the open from the
// persisted index computes equals a rebuild of what landed
#[test]
fn open_equals_rebuild_after_a_crash() {
    let mut crashed_any = false;
    for n in 0.. {
        let faults = Faults::new();
        let dev = Dev { backend: MemoryBackend::with_faults(faults.clone()), root: MemoryRoot::with_faults(faults.clone()), faults, clock: Arc::new(ManualClock::new(T0)) };
        let mut e = dev.create();
        let me = e.tid();
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, me);
        m.set(t, &REG, &s("one")).unwrap();
        e.commit(m).unwrap();
        try_edge(&mut e, t, Tid::from_bytes([80; 15]), Some(Role::Read));
        dev.faults.at(n, Fault::Crash);
        dev.clock.advance(1);
        let mut m = Mutation::new();
        m.set(t, &REG, &s("two")).unwrap();
        m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s("x")) }).unwrap();
        let _ = e.commit(m);
        try_edge(&mut e, t, Tid::from_bytes([81; 15]), Some(Role::Write));
        let crashed = dev.faults.crashed();
        drop(e);
        dev.faults.revive();
        let mut e = dev.open().unwrap();
        open_equals_rebuild(&mut e, &[t], &format!("crash at write {n}"));
        if !crashed {
            break;
        }
        crashed_any = true;
    }
    assert!(crashed_any);
}

/// A frontier covering `x`'s writes on `t`'s tags up to `n`, padded past `CHUNK_THRESHOLD` when
/// `big` (it then goes by link).
fn tags_frontier(t: Tid, x: Tid, n: u64, big: bool) -> ct::Frontier {
    let tags = |n: u64| std::collections::BTreeMap::from([("/t/tags".to_string(), std::collections::BTreeMap::from([(x, n)]))]);
    let mut writes = std::collections::BTreeMap::from([(t, tags(n))]);
    for i in 0..if big { 4000u32 } else { 0 } {
        let b = i.to_be_bytes();
        writes.insert(Tid::from_bytes([b[0], b[1], b[2], b[3], 9, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]), tags(5));
    }
    ct::Frontier { writes, commits: Default::default() }
}

// spec/requirements.md, Decentralization; spec/permissions.md §5.1 (a demotion's frontier keeps
// what the demoter had received), §6 (a roster snapshot's ledger, its large frontiers by link):
// demotions with an inline and a linked frontier, then a roster snapshot whose ledger links one;
// an open from the persisted index (perm's adaptation from the views, the frontier among them,
// and the `node/edges` rows) computes what a rebuild computes and decodes only the snapshot's
// header (its chunk list holds the linked tenure frontier)
#[test]
fn open_equals_rebuild_after_demotions_and_a_roster_snapshot() {
    let mut lp = LocalPeer::new(2, 0xde70, T0).unwrap();
    lp.sync_all().unwrap();
    let (a, x) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, a);
    lp.peers[0].commit(m).unwrap().unwrap();
    let demote = |lp: &mut LocalPeer, f: ct::Frontier| {
        let mut m = Mutation::new();
        m.op(t, &ct::MEMBERS, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(x)) }).unwrap();
        m.frontier(f.to_value());
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    for (n, big) in [(1, false), (2, true)] {
        set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Write)), None);
        lp.sync_all().unwrap();
        let got = add_tag(&mut lp, 1, t, &format!("x{n}"));
        // a write the demoter has not received: dropped by the frontier
        add_tag(&mut lp, 1, t, &format!("late{n}"));
        let pk = lp.packages(1).unwrap();
        lp.deliver(0, pk.iter().find(|p| p.id == got).unwrap()).unwrap();
        demote(&mut lp, tags_frontier(t, x, n * 2 - 1, big));
        open_equals_rebuild(&mut lp.peers[0].engine, &[t], &format!("demotion {n}"));
        lp.sync_all().unwrap();
        let Some(Value::Set(tags)) = lp.peers[0].engine.get(&t, &ak("/t/tags")).unwrap() else { panic!("demotion {n}: no tags") };
        assert!(tags.contains(&s(&format!("x{n}"))) && !tags.contains(&s(&format!("late{n}"))), "demotion {n}: the unreceived write dropped");
    }
    let s = *lp.peers[0].engine.roster_snapshot(&t, None).unwrap().commits.last().unwrap();
    assert!(lp.peers[0].engine.header(&s).is_some_and(|h| !h.chunks.is_empty()), "the ledger links a frontier");
    open_equals_rebuild_decoding(&mut lp.peers[0].engine, &[t], 1, "roster snapshot");
    sync(&mut lp, 0, 1);
    open_equals_rebuild_decoding(&mut lp.peers[1].engine, &[t], 1, "roster snapshot (receiver)");
}

/// `open_equals_rebuild` without the count of decoded headers (a roster snapshot linking a
/// tenure frontier decodes its own).
fn open_equals_rebuild_any(e: &mut Engine, things: &[Tid], at: &str) {
    assert!(e.index_current().unwrap(), "{at}: index not current");
    let take = |e: &mut Engine| (validity(e.index_digest()), e.perm_digest(false), states(e, things));
    let had = take(e);
    e.reload().unwrap();
    same(&take(e), &had, &format!("{at}: opened from the index"));
    e.rebuild_index().unwrap();
    same(&take(e), &had, &format!("{at}: rebuilt"));
}

type Digest = (osis_node::engine::IndexDigest, String, Vec<(Tid, osis_base::Ak, Option<Value>)>);

/// Equal digests, else the lines that differ.
fn same(got: &Digest, want: &Digest, at: &str) {
    if got == want {
        return;
    }
    let diff = |a: &str, b: &str| -> Vec<String> {
        let (x, y): (std::collections::BTreeSet<&str>, std::collections::BTreeSet<&str>) = (a.lines().collect(), b.lines().collect());
        x.symmetric_difference(&y).map(|l| format!("{} {}", if x.contains(l) { "got " } else { "want" }, l.chars().take(600).collect::<String>())).collect()
    };
    panic!("{at}: index {:?}\nperm {:#?}\nstates equal {}", want.0.first_diff(&got.0), diff(&got.1, &want.1), got.2 == want.2);
}

/// A large blob: one of a few bases with a small tail (a rewrite reuses most chunks).
fn big_blob(rng: &mut Rng) -> Value {
    let base = rng.below(3) as u32;
    let mut v: Vec<u8> = (0..600_000u32).map(|i| ((i.wrapping_mul(7 + base)) % 251) as u8).collect();
    for _ in 0..rng.below(3) {
        v.push(rng.below(256) as u8);
    }
    Value::Bytes(v)
}

/// What a random history reached on one node: commits with dropped parts, commits with an
/// invalid part, roster snapshots, chunks indexed.
fn reached(e: &Engine) -> [usize; 4] {
    let d = e.index_digest();
    let [dropped, invalid, _] = e.drop_counts();
    [dropped, invalid, d.commits.values().filter(|c| c.kind == osis_commit::Kind::RosterSnapshot).count(), d.by_chunk.len()]
}

// spec/requirements.md, Decentralization; spec/permissions.md §5.2; spec/commits.md §5: random
// three-node histories of large values, tags, keep-at-most-0 aspects (drops, large ones with
// their chunks), compaction snapshots, revokes that flip validity and un-merge late writes,
// roster snapshots, a move (imports) and late, out-of-order deliveries: at random points a node
// opened from its persisted index, and then rebuilt from its commit records, equals the running
// node (views, `by_thing`, `by_chunk`, validity, perm, states). Seeds: OSIS_WALKS_START,
// OSIS_WALKS_SEEDS, a thread per core (OSIS_WALKS_THREADS); every failing seed is reported.
#[test]
fn open_equals_rebuild_random_histories() {
    let range = osis_base::testenv::Seeds::from_env("OSIS_WALKS_START", "OSIS_WALKS_SEEDS", 0..4);
    let seeds: Vec<u64> = range.range.clone().collect();
    let name = "walks::open_equals_rebuild_random_histories";
    let replay = |s: u64| format!("OSIS_WALKS_START={s} OSIS_WALKS_SEEDS=1 cargo test --workspace --test it {name} -- --exact");
    let mut most = [0usize; 4];
    for (r, _) in run_seeds_noted(name, &seeds, range.overridden, "OSIS_WALKS_THREADS", replay, |seed| random_history(seed, 1, false, false)) {
        for k in 0..4 {
            most[k] = most[k].max(r[k]);
        }
    }
    // the default seeds reach drops, invalid parts, roster snapshots and chunks (other ranges,
    // a one-seed repro say, pass or fail on their own)
    if !range.overridden {
        assert!(most.iter().all(|n| *n > 0), "reached (dropped, invalid, roster snapshots, chunks): {most:?}");
    }
}

// as above: seeds where a snapshot of the moved thing carried imported writes whose origin
// commit arrived after it (the carried index depended on that order)
#[test]
fn open_equals_rebuild_random_histories_carried_imports() {
    for seed in [261, 377] {
        let _ = random_history(seed, 1, false, false);
    }
}

// as above, spec/crdt.md §4.8: seeds where a keep-at-most-0 body died and dropped, its killer
// turned invalid, and a late body older than it arrived (they failed under the old exact dating
// of dropped bodies)
#[test]
fn open_equals_rebuild_random_histories_unkilled_residue() {
    for seed in [40558, 40797] {
        let _ = random_history(seed, 1, false, false);
    }
}

// as above, spec/commits.md §5: seeds where a write of a keep-at-most-0 map died while its part
// had not arrived (a late part): the death went to that unheld part and dropped it, so the part
// was both dropped and missing in place, dropped only after a rebuild (737046 on main too)
#[test]
fn open_equals_rebuild_random_histories_unheld_part_dies() {
    for seed in [737046, 737257] {
        let _ = random_history(seed, 1, false, false);
    }
}

// spec/requirements.md, Decentralization and Out of scope ("malicious readers can only waste
// storage"); spec/permissions.md §5.2: as above, with nodes taking hostile snapshots that copy a
// held tag's dot and `ts` with another value, sent on like any commit: open equals rebuild, and
// once every node holds everything no forged value shows and the tags agree. Seeds:
// OSIS_WALKS_FORGED_START, OSIS_WALKS_FORGED_SEEDS (default 0..16), a thread per core.
#[test]
fn open_equals_rebuild_random_histories_forged() {
    let range = osis_base::testenv::Seeds::from_env("OSIS_WALKS_FORGED_START", "OSIS_WALKS_FORGED_SEEDS", 0..16);
    let seeds: Vec<u64> = range.range.clone().collect();
    let name = "walks::open_equals_rebuild_random_histories_forged";
    let replay = |s: u64| format!("OSIS_WALKS_FORGED_START={s} OSIS_WALKS_FORGED_SEEDS=1 cargo test --workspace --test it {name} -- --exact");
    run_seeds_noted(name, &seeds, range.overridden, "OSIS_WALKS_THREADS", replay, |seed| random_history(seed, 1, false, true));
}

// as above with moves weighted up (copies of copies, their aspects snapshotted); seeds 6013,
// 6106 and 6305 failed on issues/carried-import-order.md (about one seed in ten did; one in 200
// without the weighting). With hostile second imports into a copy (spec/permissions.md §7):
// seeds DOUBLES (6012 and 6036 failed while the last import to arrive named the author; 51999
// while an invalid snapshot still counted as a carrier of deaths), and every
// seed of OSIS_WALKS_MOVES_START, OSIS_WALKS_MOVES_SEEDS (OSIS_WALKS_MOVES_DOUBLES=0: without
// them, as the first three), a thread per core (OSIS_WALKS_THREADS).
#[test]
fn open_equals_rebuild_random_histories_moves() {
    const PLAIN: [u64; 3] = [6013, 6106, 6305];
    const DOUBLES: [u64; 3] = [6012, 6036, 51999];
    use osis_base::testenv::{Seeds, u64_var};
    let range = Seeds::from_env("OSIS_WALKS_MOVES_START", "OSIS_WALKS_MOVES_SEEDS", 0..1);
    let start = u64_var("OSIS_WALKS_MOVES_START");
    let doubles_on = u64_var("OSIS_WALKS_MOVES_DOUBLES") != Some(0);
    let seeds: Vec<(u64, bool)> = match start {
        Some(_) => range.range.clone().map(|s| (s, doubles_on)).collect(),
        None => PLAIN.map(|s| (s, false)).into_iter().chain(DOUBLES.map(|s| (s, true))).collect(),
    };
    let doubles: std::collections::BTreeMap<u64, bool> = seeds.iter().copied().collect();
    let name = "walks::open_equals_rebuild_random_histories_moves";
    let replay = |s: u64| format!("OSIS_WALKS_MOVES_START={s} OSIS_WALKS_MOVES_DOUBLES={} cargo test --workspace --test it {name} -- --exact", u8::from(doubles[&s]));
    let keys: Vec<u64> = doubles.keys().copied().collect();
    let mut doubled = 0;
    for (seed, (_, n)) in keys.iter().zip(run_seeds_noted(name, &keys, start.is_some(), "OSIS_WALKS_THREADS", replay, |seed| random_history(seed, 3, doubles[&seed], false))) {
        if n > 0 {
            eprintln!("seed {seed}: {n} double imports");
        }
        doubled += n;
    }
    assert!(doubled > 0 || start.is_some(), "no double import");
}

/// One random history of `open_equals_rebuild_random_histories` with up to `max_moves` moves (more
/// than one: moves from step 10, moved things snapshotted more), and with `doubles` sometimes a
/// second import of a moved thing into its copy; returns what it reached on any node (most of
/// each `reached` count) and how many double imports it made.
fn random_history(seed: u64, max_moves: usize, doubles: bool, forge: bool) -> ([usize; 4], usize) {
    let mut most = [0usize; 4];
    let mut forged = 0usize;
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut lp = LocalPeer::new(3, 0x7a1c + seed, T0).unwrap();
    lp.sync_all().unwrap();
    let ids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.tid()).collect();
    let mut things: Vec<Tid> = (0..2).map(|_| new_thing(&mut lp, 0)).collect();
    for t in things.clone() {
        set_edge(&mut lp.peers[0].engine, t, ids[1], Some(edge(Role::Write)), None);
        set_edge(&mut lp.peers[0].engine, t, ids[2], Some(edge(Role::Admin)), None);
    }
    lp.sync_all().unwrap();
    let mut moves = 0;
    let (mut moved, mut double_imports) = (Vec::new(), 0);
    for step in 0..60 {
        let i = rng.below(3) as usize;
        let t = things[rng.below(things.len() as u64) as usize];
        let mut m = Mutation::new();
        match rng.below(16) {
            0 => {
                m.set(t, &BLOB, &big_blob(&mut rng)).unwrap();
            }
            1 | 2 => {
                m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s(&format!("t{step}"))) }).unwrap();
            }
            3 => {
                m.op(t, &KEPTSET, PathOp { path: Vec::new(), op: Op::Add(s(&format!("k{step}"))) }).unwrap();
            }
            4 => {
                m.set(t, &GONE, &s(&format!("g{step}"))).unwrap();
            }
            5 => {
                let fill: std::collections::BTreeMap<Value, Value> = (0..40 + rng.below(40)).map(|k| (s(&format!("k{k:03}")), s(&format!("{step}{}", "g".repeat(400))))).collect();
                m.set(t, &GONEMAP, &Value::Map(fill)).unwrap();
            }
            6 if forge && rng.below(3) == 0 => {
                // a hostile snapshot copying another value under a held tag's dot
                let o = things[rng.below(2) as usize];
                if forge_tag(&mut lp, i, o, step, &mut rng) {
                    forged += 1;
                }
            }
            6 => {
                let a = ak(["/t/keptset", "/t/gonemap", "/t/tags"][rng.below(3) as usize]);
                let e = &mut lp.peers[i].engine;
                // not with forged snapshots: a forged copy under the dot of a body dropped before
                // others got it shows where the original never arrived (issues/forged-cover.md)
                if let Ok(Some(snap)) = e.snapshot(&t, &a)
                    && !forge
                    && rng.below(2) == 0
                {
                    // the compactor drops what it covers (node-sync's compaction): such a body
                    // is missing again if the cover turns invalid (`retention::uncover`)
                    let on: Vec<_> = e.commit_ids().into_iter().filter(|c| *c != snap && e.header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t && x.ak == a))).collect();
                    for c in on {
                        if e.body_not_dropped(&c, &t, &a) && e.covered(&snap, &c, &t, &a).is_ok_and(|x| x == Some(true)) {
                            e.drop_body(&c, &t, &a).unwrap();
                        }
                    }
                }
            }
            7 => {
                // the admin revokes or restores the writer, a revoke with what it received
                let role = [None, Some(Role::Read), Some(Role::Write)][rng.below(3) as usize];
                m.op(t, &ct::MEMBERS, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(ids[1])) }).unwrap();
                if let Some(e) = role {
                    m.op(t, &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(ids[1]))], op: Op::Set(edge(e).to_value()) }).unwrap();
                }
                let scope = osis_perm::DemotionScope { membership: [(ids[1], [t].into())].into(), content: [(ids[1], [t].into())].into() };
                let now = lp.peers[2].engine.now();
                if role != Some(Role::Write)
                    && let Ok(f) = lp.peers[2].engine.frontier(&scope, now)
                {
                    m.frontier(f.to_value());
                }
                let _ = lp.peers[2].commit(m);
                m = Mutation::new();
            }
            8 => {
                let _ = lp.peers[i].engine.roster_snapshot(&t, None);
            }
            x @ (9 | 14) if moves < max_moves && if max_moves > 1 { step > 10 } else { x == 9 && step > 20 } => {
                if let Ok((copy, _)) = lp.peers[0].engine.move_thing(&t, ids[0]) {
                    things.push(copy);
                    moved.push((t, copy));
                    moves += 1;
                }
            }
            15 if max_moves > 1 && moves > 0 => {
                let c = *things.last().unwrap();
                if doubles && rng.below(3) == 0 {
                    // the creator's hostile second import: each origin listed twice on a copy
                    let (o, c) = moved[rng.below(moved.len() as u64) as usize];
                    if lp.peers[0].engine.reimport(&o, &c).is_ok_and(|v| !v.is_empty()) {
                        double_imports += 1;
                    }
                }
                let a = ["/t/keptset", "/t/gonemap", "/t/tags"][rng.below(3) as usize];
                let _ = lp.peers[i].engine.snapshot(&c, &ak(a));
            }
            10 => lp.advance(1 + rng.below(1_200_000)),
            11..=13 => {
                // some of i's commits, shuffled, to another node
                let j = (i + 1 + rng.below(2) as usize) % 3;
                let mut pk = lp.packages(i).unwrap();
                let n = pk.len();
                for k in 0..n {
                    let r = k + rng.below((n - k) as u64) as usize;
                    pk.swap(k, r);
                }
                for p in pk.iter().take(1 + rng.below(n as u64 + 1) as usize) {
                    let _ = lp.deliver(j, p);
                }
            }
            _ => {
                let e = &mut lp.peers[i].engine;
                let r = reached(e);
                for k in 0..4 {
                    most[k] = most[k].max(r[k]);
                }
                open_equals_rebuild_any(e, &things, &format!("seed {seed} step {step} peer {i}"));
            }
        }
        if !m.is_empty() {
            let _ = lp.peers[i].commit(m);
        }
        lp.peers[i].clock.advance(1 + rng.below(3));
    }
    lp.sync_all().unwrap();
    for i in 0..3 {
        let r = reached(&lp.peers[i].engine);
        for k in 0..4 {
            most[k] = most[k].max(r[k]);
        }
        open_equals_rebuild_any(&mut lp.peers[i].engine, &things, &format!("seed {seed} end, peer {i}"));
    }
    if forge {
        // every node holds every commit now: forged copies show on no original, and the tags
        // agree (a copy may hold one its mover imported while it lacked the forged write's own
        // commit: the forging snapshot vouched for it, spec/permissions.md §5.2)
        let tagged = |lp: &mut LocalPeer, i: usize| things.iter().map(|t| lp.peers[i].engine.get(t, &ak("/t/tags")).unwrap()).collect::<Vec<_>>();
        let first = tagged(&mut lp, 0);
        assert!(!format!("{:?}", &first[..2]).contains("forged"), "seed {seed}: a forged copy shows: {first:?}");
        for i in 1..3 {
            assert_eq!(tagged(&mut lp, i), first, "seed {seed}: peer {i} differs ({forged} forged)");
        }
    }
    (most, double_imports)
}

/// Peer `i` forges a snapshot of `t`'s `/t/tags`: its state with the value of a held tag (a
/// node-form commit's element) replaced, under that element's dot and `ts`, and takes it.
fn forge_tag(lp: &mut LocalPeer, i: usize, t: Tid, step: usize, rng: &mut Rng) -> bool {
    use osis_crdt::{Batch, Source, Writer};
    let tags = ak("/t/tags");
    let e = &lp.peers[i].engine;
    let held: Vec<(osis_base::Ts, Tid, u64)> = e
        .commit_ids()
        .iter()
        .filter_map(|id| e.header(id))
        .filter(|h| h.kind == osis_commit::Kind::Content && h.form == osis_commit::Form::Node)
        .filter_map(|h| h.aspects.iter().find(|a| a.tid == t && a.ak == tags).map(|a| (h.ts, h.author, a.lo)))
        .collect();
    if held.is_empty() {
        return false;
    }
    let (ts, author, lo) = held[rng.below(held.len() as u64) as usize];
    let dot = osis_crdt::Dot::new(Source::node(author), lo);
    let Some(mut f) = lp.peers[i].engine.state(&t, &tags).unwrap() else { return false };
    f.strip_copies(&|d| *d == dot);
    let mut b = Batch::new(&f, Writer::new(ts, Source::node(author), lo));
    if b.apply(&PathOp { path: Vec::new(), op: Op::Add(s(&format!("forged{step}"))) }, &osis_crdt::AnyView).is_err() {
        return false;
    }
    let Some((extra, _)) = b.finish() else { return false };
    f.join(extra);
    let now = osis_base::Ts::make(lp.peers[i].engine.now(), 0).unwrap();
    let bytes = forge_snapshot(lp, i, t, &tags, now, f);
    lp.peers[i].engine.ingest(&bytes, Vec::new()).is_ok()
}

// spec/requirements.md, Decentralization; spec/permissions.md §5.2, §7: a snapshot of a moved
// thing carries imported writes (source `Commit(o)`, o the origin on the old thing); they are
// the held import's, not carried, whether o arrives before or after the snapshot
#[test]
fn carried_imports_alike_in_both_orders() {
    let mut lp = LocalPeer::new(4, 0xca22, T0).unwrap();
    lp.sync_all().unwrap();
    let (a, x) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    let t = new_thing(&mut lp, 0);
    set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    let o = add_tag(&mut lp, 1, t, "a");
    let pk = lp.packages(1).unwrap();
    lp.deliver(0, pk.iter().find(|p| p.id == o).unwrap()).unwrap();
    let (copy, _) = lp.peers[0].engine.move_thing(&t, a).unwrap();
    lp.peers[0].engine.snapshot(&copy, &ak("/t/tags")).unwrap();
    let pk = lp.packages(0).unwrap();
    let (late, rest): (Vec<_>, Vec<_>) = pk.iter().partition(|p| p.id == o);
    // peer 2: o last; peer 3: o first
    for p in rest.iter().chain(&late) {
        lp.deliver(2, p).unwrap();
    }
    for p in late.iter().chain(&rest) {
        lp.deliver(3, p).unwrap();
    }
    for i in [2, 3] {
        assert!(lp.peers[i].engine.index_digest().carried.is_empty(), "peer {i}: the import's writes are not carried");
        open_equals_rebuild_any(&mut lp.peers[i].engine, &[t, copy], &format!("peer {i}"));
    }
}

// spec/permissions.md §5.2, §7: a snapshot of a moved thing carries an import's writes (source
// `Commit(o)`); its author, revoked on the copy's owner before the move, could write neither:
// a node holding o (on the old thing) but not the import shows them nowhere (o owns nothing on
// the copy, and the invalid snapshot gives nothing).
#[test]
fn carried_imports_without_the_import_spec_perm_5_2() {
    let mut lp = LocalPeer::new(4, 0xca23, T0).unwrap();
    lp.sync_all().unwrap();
    let a = lp.peers[0].engine.tid();
    // P owned by peer 2, peer 0 admin on it; t is peer 0's with one tag (o)
    let p = new_thing(&mut lp, 2);
    set_edge(&mut lp.peers[2].engine, p, a, Some(edge(Role::Admin)), None);
    let t = new_thing(&mut lp, 0);
    lp.sync_all().unwrap();
    let o = add_tag(&mut lp, 0, t, "a");
    lp.sync_all().unwrap();
    // peer 2 revokes peer 0 on P; peer 0, unaware, moves t into P after it
    set_edge(&mut lp.peers[2].engine, p, a, None, None);
    lp.peers[0].clock.advance(1_000);
    let (copy, imports) = lp.peers[0].engine.move_thing(&t, p).unwrap();
    assert!(!imports.is_empty());
    // peer 0 snapshots the copy's tags: the snapshot carries the import's writes
    assert!(lp.peers[0].engine.snapshot(&copy, &ak("/t/tags")).unwrap().is_some());
    let shown = lp.peers[0].engine.get(&copy, &ak("/t/tags")).unwrap();
    assert!(format!("{shown:?}").contains("\"a\""), "peer 0 shows its import: {shown:?}");
    sync(&mut lp, 0, 2);
    // peer 2, holding everything: the import is invalid, so nothing
    let tags = ak("/t/tags");
    let none = lp.peers[2].engine.get(&copy, &tags).unwrap();
    assert!(!format!("{none:?}").contains("\"a\""), "the invalid import's writes are not shown: {none:?}");
    let full = states(&mut lp.peers[2].engine, &[t, copy, p]);
    // peer 3 gets everything but the imports (it holds o)
    let pk = lp.packages(2).unwrap();
    for x in pk.iter().filter(|x| !imports.contains(&x.id)) {
        lp.deliver(3, x).unwrap();
    }
    assert!(lp.peers[3].engine.header(&o).is_some() && imports.iter().all(|i| lp.peers[3].engine.header(i).is_none()));
    assert_eq!(lp.peers[3].engine.get(&copy, &tags).unwrap(), none, "an invalid snapshot gives nothing");
    open_equals_rebuild_any(&mut lp.peers[3].engine, &[t, copy, p], "without the imports");
    for x in pk.iter().filter(|x| imports.contains(&x.id)) {
        lp.deliver(3, x).unwrap();
    }
    assert_eq!(states(&mut lp.peers[3].engine, &[t, copy, p]), full, "then alike with them");
}

// spec/requirements.md, Decentralization; spec/permissions.md §7: the copy's hostile creator
// imports t into it a second time, so two held imports list each origin; each owns the origin's
// writes on its aspects. Two nodes taking the imports in either order, and a snapshot of the
// copy, agree (imports, carried writes, states) and equal their rebuilds, also where the
// snapshot comes before either import.
#[test]
fn double_import_alike_in_both_orders_spec_perm_7() {
    let mut lp = LocalPeer::new(6, 0xd0b1, T0).unwrap();
    lp.sync_all().unwrap();
    let (a, x) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    let t = new_thing(&mut lp, 0);
    set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    add_tag(&mut lp, 1, t, "a");
    add_tag(&mut lp, 0, t, "b");
    lp.sync_all().unwrap();
    let (copy, first) = lp.peers[0].engine.move_thing(&t, a).unwrap();
    lp.peers[0].clock.advance(1_000);
    // peer 0 imports t again: each origin listed twice on the copy
    let second = lp.peers[0].engine.reimport(&t, &copy).unwrap();
    assert!(!first.is_empty() && !second.is_empty());
    let pk0 = lp.packages(0).unwrap();
    let dup = pk0.iter().filter(|p| second.contains(&p.id)).cloned().collect::<Vec<_>>();
    let (imp, rest): (Vec<_>, Vec<_>) = pk0.iter().filter(|&p| !second.contains(&p.id)).cloned().partition(|p| first.contains(&p.id));
    for p in &rest {
        for i in 2..6 {
            lp.deliver(i, p).unwrap();
        }
    }
    // peer 2: the first move, then the second; peer 3 the other way round
    for (i, ps) in [(2, [&imp, &dup]), (3, [&dup, &imp])] {
        for p in ps.into_iter().flatten() {
            assert!(matches!(lp.deliver(i, p).unwrap(), osis_node::Ingested::Applied(_)), "peer {i} applies each import");
        }
    }
    // peer 0 holds both and snapshots the copy's tags
    let snap = lp.peers[0].engine.snapshot(&copy, &ak("/t/tags")).unwrap().unwrap();
    let pk0 = lp.packages(0).unwrap();
    let sp: Vec<_> = pk0.iter().filter(|p| p.id == snap).cloned().collect();
    // peer 4: the second move, the snapshot, the first; peer 5: the snapshot, then both
    for (i, ps) in [(2, vec![&sp]), (3, vec![&sp]), (4, vec![&dup, &sp, &imp]), (5, vec![&sp, &dup, &imp])] {
        for p in ps.into_iter().flatten() {
            assert!(matches!(lp.deliver(i, p).unwrap(), osis_node::Ingested::Applied(_)), "peer {i} applies {:?}", p.id);
        }
    }
    let moved = |e: &Engine| {
        let d = e.index_digest();
        (d.tables["imports"].clone(), d.carried)
    };
    for i in 3..6 {
        assert_eq!(moved(&lp.peers[2].engine), moved(&lp.peers[i].engine), "peer {i}: imports, carried");
        assert_eq!(states(&mut lp.peers[2].engine, &[t, copy]), states(&mut lp.peers[i].engine, &[t, copy]), "peer {i}");
    }
    for i in 2..6 {
        open_equals_rebuild_any(&mut lp.peers[i].engine, &[t, copy], &format!("peer {i}"));
    }
}

// spec/requirements.md, Out of scope ("malicious readers can only waste storage");
// spec/permissions.md §7: an import into a copy by a node other than its creator (here a writer
// demoted to reader, unaware) is bad input and changes nothing, whatever origins it lists. It
// stripped the copy's imported writes (issues/invalid-import-strips-origin.md).
#[test]
fn invalid_reimport_changes_nothing_spec_perm_7() {
    let mut lp = LocalPeer::new(3, 0xd0b2, T0).unwrap();
    lp.sync_all().unwrap();
    let (a, x) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    let t = new_thing(&mut lp, 0);
    set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    add_tag(&mut lp, 1, t, "a");
    add_tag(&mut lp, 0, t, "b");
    lp.sync_all().unwrap();
    let (copy, _) = lp.peers[0].engine.move_thing(&t, a).unwrap();
    set_edge(&mut lp.peers[0].engine, copy, x, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    // peer 1 is demoted to reader before it imports t into the copy again, unaware
    set_edge(&mut lp.peers[0].engine, copy, x, Some(edge(Role::Read)), None);
    lp.sync(0, 2).unwrap();
    let before = states(&mut lp.peers[2].engine, &[t, copy]);
    let second = lp.peers[1].engine.reimport(&t, &copy).unwrap();
    assert!(!second.is_empty());
    let pk = lp.packages(1).unwrap();
    for p in pk.iter().filter(|p| second.contains(&p.id)) {
        assert_eq!(lp.deliver(2, p).unwrap_err().class(), osis_base::ErrorClass::BadInput, "not the copy's creator");
    }
    assert_eq!(states(&mut lp.peers[2].engine, &[t, copy]), before, "an invalid import changes nothing");
}

// spec/permissions.md §7, §5.2: an import naming as origin a commit on its own thing (here a
// commit-form write by the copy's owner) is void wherever both are held, in either order: it
// joins nothing and its invalidity never un-merges that commit's own writes
// (issues/import-origin-same-thing.md).
#[test]
fn import_of_own_thing_commit_void_spec_perm_7() {
    let mut lp = LocalPeer::new(3, 0xd0b4, T0).unwrap();
    lp.sync_all().unwrap();
    let x = lp.peers[1].engine.tid();
    let t = new_thing(&mut lp, 0);
    let o = new_thing(&mut lp, 0);
    set_edge(&mut lp.peers[0].engine, o, x, Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    // peer 1, an admin of `o`, creates the copy under it, then is removed
    let (copy, _) = lp.peers[1].engine.move_thing(&t, o).unwrap();
    lp.sync(1, 0).unwrap();
    set_edge(&mut lp.peers[0].engine, o, x, None, None);
    let body = ak("/t/body");
    let mut m = Mutation::new();
    m.commit_form();
    m.set(copy, &body, &s("by owner")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync(0, 1).unwrap();
    let imports = lp.peers[1].engine.reimport(&copy, &copy).unwrap();
    assert!(!imports.is_empty());
    let pk1: Vec<_> = lp.packages(1).unwrap().into_iter().filter(|p| imports.contains(&p.id)).collect();
    // peer 0: the commit first; peer 2: the imports first
    for p in &pk1 {
        lp.deliver(0, p).unwrap();
    }
    for p in lp.packages(0).unwrap().iter().filter(|p| p.id != c && !imports.contains(&p.id)) {
        lp.deliver(2, p).unwrap();
    }
    for p in &pk1 {
        let r = lp.deliver(2, p).unwrap();
        assert!(matches!(r, osis_node::Ingested::Applied(_)), "{r:?}");
    }
    let pc = lp.peers[0].engine.package(&c).unwrap().unwrap();
    lp.deliver(2, &pc).unwrap();
    let of_c = *imports.iter().find(|i| lp.peers[1].engine.header(i).unwrap().origins.iter().any(|o| o.commit == c)).unwrap();
    for i in 0..3 {
        assert_eq!(lp.peers[i].engine.get(&copy, &body).unwrap(), Some(s("by owner")), "peer {i}");
        assert!(lp.peers[i].engine.core.ix.void.contains(&of_c), "peer {i}");
    }
    let s0 = states(&mut lp.peers[0].engine, &[copy]);
    assert_eq!(states(&mut lp.peers[2].engine, &[copy]), s0);
    assert_eq!(states(&mut lp.peers[1].engine, &[copy]), s0);
}

// spec/permissions.md §7, §5.2: a node holding a snapshot of a copy but not the move's imports
// shows the imported writes it carries (the snapshot vouches for them). An import by another
// node (a reader of the copy) is refused and changes nothing (it once re-attributed those writes
// to itself, judged invalid there, and they vanished).
#[test]
fn foreign_import_does_not_claim_carried_writes_spec_perm_7() {
    let mut lp = LocalPeer::new(3, 0xd0b3, T0).unwrap();
    lp.sync_all().unwrap();
    let (a, x) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    let t = new_thing(&mut lp, 0);
    set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    add_tag(&mut lp, 0, t, "a");
    lp.sync_all().unwrap();
    let (copy, imports) = lp.peers[0].engine.move_thing(&t, a).unwrap();
    set_edge(&mut lp.peers[0].engine, copy, x, Some(edge(Role::Read)), None);
    lp.peers[0].engine.snapshot(&copy, &ak("/t/tags")).unwrap().unwrap();
    // peer 2: everything but the imports; peer 1 (a reader of the copy): everything
    let pk0 = lp.packages(0).unwrap();
    for p in &pk0 {
        lp.deliver(1, p).unwrap();
        if !imports.contains(&p.id) {
            lp.deliver(2, p).unwrap();
        }
    }
    let tags = ak("/t/tags");
    let shown = lp.peers[2].engine.get(&copy, &tags).unwrap();
    assert!(format!("{shown:?}").contains("\"a\""), "the snapshot's carried writes: {shown:?}");
    let moved = |e: &Engine| {
        let d = e.index_digest();
        (d.tables["imports"].clone(), d.carried)
    };
    let carried = moved(&lp.peers[2].engine).1;
    let before = states(&mut lp.peers[2].engine, &[t, copy]);
    let foreign = lp.peers[1].engine.reimport(&t, &copy).unwrap();
    assert!(!foreign.is_empty());
    let pk1 = lp.packages(1).unwrap();
    for p in pk1.iter().filter(|p| foreign.contains(&p.id)) {
        assert_eq!(lp.deliver(2, p).unwrap_err().class(), osis_base::ErrorClass::BadInput, "not the copy's creator");
    }
    assert_eq!(moved(&lp.peers[2].engine).1, carried);
    assert_eq!(states(&mut lp.peers[2].engine, &[t, copy]), before);
    open_equals_rebuild_any(&mut lp.peers[2].engine, &[t, copy], "after the foreign import");
}

// spec/requirements.md, Decentralization; spec/permissions.md §7, spec/commits.md §4: a foreign
// import whose parts a node does not hold (the copy not synced) waits for the copy's creation
// record like one with parts and is then refused, as one with parts is.
#[test]
fn foreign_import_without_parts_waits_for_the_record_spec_perm_7() {
    let mut lp = LocalPeer::new(3, 0xd0b5, T0).unwrap();
    lp.sync_all().unwrap();
    let (a, x) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    let t = new_thing(&mut lp, 0);
    set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    add_tag(&mut lp, 0, t, "a");
    lp.sync_all().unwrap();
    let (copy, imports) = lp.peers[0].engine.move_thing(&t, a).unwrap();
    set_edge(&mut lp.peers[0].engine, copy, x, Some(edge(Role::Read)), None);
    lp.peers[0].engine.snapshot(&copy, &ak("/t/tags")).unwrap().unwrap();
    let pk0 = lp.packages(0).unwrap();
    for p in &pk0 {
        lp.deliver(1, p).unwrap();
    }
    // the reader imports t into the copy, so as to be the least import
    let foreign = lp.peers[1].engine.reimport(&t, &copy).unwrap();
    assert!(!foreign.is_empty());
    // peer 2: the foreign imports without parts first, then everything but the move's imports
    let pk1 = lp.packages(1).unwrap();
    for p in pk1.iter().filter(|p| foreign.contains(&p.id)) {
        let mut b = osis_commit::CommitBlob::decode(&p.bytes).unwrap();
        b.parts.clear();
        let r = lp.peers[2].engine.ingest(&b.encode(), Vec::new()).unwrap();
        assert!(matches!(r, osis_node::Ingested::Pending(_, osis_node::Reason::UnknownCreated(c)) if c == copy), "waits for the copy's record: {r:?}");
    }
    for p in pk0.iter().filter(|p| !imports.contains(&p.id)) {
        lp.deliver(2, p).unwrap();
    }
    assert!(lp.peers[2].engine.pending().is_empty(), "refused once the record is held");
    let shown = lp.peers[2].engine.get(&copy, &ak("/t/tags")).unwrap();
    assert!(format!("{shown:?}").contains("\"a\""), "the snapshot's carried writes: {shown:?}");
    open_equals_rebuild_any(&mut lp.peers[2].engine, &[t, copy], "after the foreign import");
}

// spec/permissions.md §5.2, §7: an origin's writes a valid snapshot of a copy carries count
// whatever the imports held: the snapshot vouches for them. The copy's creator moved t (`x` on
// the list, `r` on the register), snapshotted the list, saw `x` deleted on t, then re-imported
// twice (the list no longer shown: those imports lack it), the second time after its admin edge
// on the copy's owner was removed. Nodes taking the re-imports in either order show `x` and
// agree with each other and with their rebuilds.
#[test]
fn invalid_import_after_snapshot_alike_spec_perm_7() {
    let mut lp = LocalPeer::new(5, 0xd0b4, T0).unwrap();
    lp.sync_all().unwrap();
    let a = lp.peers[0].engine.tid();
    // P owned by peer 2, peer 0 admin on it; t is peer 0's
    let p = new_thing(&mut lp, 2);
    set_edge(&mut lp.peers[2].engine, p, a, Some(edge(Role::Admin)), None);
    let t = new_thing(&mut lp, 0);
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.set(t, &LIST, &Value::List(vec![s("x")])).unwrap();
    m.set(t, &REG, &s("r")).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let (copy, _) = lp.peers[0].engine.move_thing(&t, p).unwrap();
    let list = ak("/t/list");
    lp.peers[0].engine.snapshot(&copy, &list).unwrap().unwrap();
    let mut m = Mutation::new();
    m.op(t, &LIST, PathOp { path: Vec::new(), op: Op::Delete { at: 0, len: 1 } }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[0].clock.advance(1_000);
    let lesser = lp.peers[0].engine.reimport(&t, &copy).unwrap();
    // peer 2 removes peer 0 from P with what it received; peer 0, unaware, imports once more
    lp.sync(0, 2).unwrap();
    let scope = osis_perm::DemotionScope { membership: [(a, [p].into())].into(), content: [(a, [p, copy].into())].into() };
    let now = lp.peers[2].engine.now();
    let f = lp.peers[2].engine.frontier(&scope, now).unwrap();
    set_edge(&mut lp.peers[2].engine, p, a, None, Some(f.to_value()));
    lp.peers[0].clock.advance(1_000);
    let greater = lp.peers[0].engine.reimport(&t, &copy).unwrap();
    assert!(!lesser.is_empty() && !greater.is_empty());
    let pk0 = lp.packages(0).unwrap();
    let (l, g): (Vec<_>, Vec<_>) = pk0.iter().filter(|x| lesser.contains(&x.id) || greater.contains(&x.id)).cloned().partition(|x| lesser.contains(&x.id));
    // peers 3 and 4 hold everything but the imports first: the first move's never reach them,
    // so the list's writes the snapshot carries are judged by the claim
    let import = |e: &Engine, id| e.header(id).is_some_and(|h| h.kind == osis_commit::Kind::Import);
    let pk2 = lp.packages(2).unwrap();
    let rest: Vec<_> = pk0.iter().chain(&pk2).filter(|x| !import(&lp.peers[0].engine, &x.id)).cloned().collect();
    for i in [3, 4] {
        for x in &rest {
            lp.deliver(i, x).unwrap();
        }
    }
    let moved = |e: &Engine| {
        let d = e.index_digest();
        (d.tables["imports"].clone(), d.carried)
    };
    let shows = |e: &mut Engine| format!("{:?}", e.get(&copy, &list).unwrap()).contains("\"x\"");
    // peer 3: the greater (invalid) import, then the lesser; peer 4 the other way round
    for x in &g {
        lp.deliver(3, x).unwrap();
    }
    let carried = moved(&lp.peers[3].engine).1;
    assert!(carried.values().flatten().any(|g| matches!(g.src.kind(), osis_crdt::SourceKind::Commit(_))), "the list's writes are carried: {carried:?}");
    assert!(shows(&mut lp.peers[3].engine), "the snapshot vouches for them");
    open_equals_rebuild_any(&mut lp.peers[3].engine, &[t, copy, p], "greater import only");
    for x in &l {
        lp.deliver(3, x).unwrap();
    }
    assert!(shows(&mut lp.peers[3].engine), "both imports");
    for x in l.iter().chain(&g) {
        lp.deliver(4, x).unwrap();
    }
    assert!(shows(&mut lp.peers[4].engine), "peer 4");
    assert_eq!(moved(&lp.peers[3].engine), moved(&lp.peers[4].engine), "imports, carried");
    assert_eq!(states(&mut lp.peers[3].engine, &[t, copy, p]), states(&mut lp.peers[4].engine, &[t, copy, p]));
    for i in [3, 4] {
        open_equals_rebuild_any(&mut lp.peers[i].engine, &[t, copy, p], &format!("peer {i}"));
    }
}
