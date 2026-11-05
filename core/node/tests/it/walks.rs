#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The saved role walks (notes/local-store.md, rebuildable caches; notes/node.md, Open):
//! an open resumes each component's walk from the store and gives what a from-scratch
//! evaluation gives (spec/permissions.md §5.1 step 5: validity is a function of the held set);
//! a damaged, truncated or foreign walk is evaluated anew, never an error; a crash at any write
//! leaves no walk ahead of its commits. Likewise the index's rows of what perm reads of each
//! role commit (`node/edges`): an open from them equals a rebuild from the commit records.

use crate::common;
use common::*;
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

/// `holder`'s edge on `thing` by the engine (`None` removes it); refusals are fine.
fn try_edge(e: &mut Engine, thing: Tid, holder: Tid, role: Option<Role>) {
    // remove + put (spec/permissions.md §2)
    let mut m = Mutation::new();
    m.op(thing, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(holder)) }).unwrap();
    match role {
        Some(r) => m.op(thing, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(holder))], op: Op::Set(edge(r).to_value()) }).map(|_| ()).unwrap(),
        // an explicit removal: with no frontier it would be a finalize (spec/permissions.md §2)
        None => {
            m.frontier(ct::Frontier::default().to_value());
        }
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
/// Returns how many role snapshots it made.
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
    let holders: Vec<Tid> = (0..6u8).map(|i| Tid::from_bytes([50 + i; 15])).chain([team]).collect();
    for step in 0..steps {
        let doc = docs[rng.below(4) as usize];
        let roles = [None, Some(Role::Read), Some(Role::Write), Some(Role::Admin)];
        match rng.below(10) {
            0 | 1 => try_edge(&mut lp.peers[0].engine, doc, p1, roles[rng.below(4) as usize]),
            2..=6 => {
                let i = rng.below(2) as usize;
                let m = holders[rng.below(holders.len() as u64) as usize];
                try_edge(&mut lp.peers[i].engine, doc, m, roles[rng.below(3) as usize]);
            }
            7 => {
                let _ = lp.peers[0].engine.roster_snapshot(&doc, None);
                // a role snapshot (of the node's `keys.0`) reaches perm's inputs too
                let node = lp.peers[0].engine.tid();
                if let Ok(Some(_)) = lp.peers[0].engine.snapshot(&node, &osis_base::Ak::new("keys.0").unwrap()) {
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
// with late arrivals, demotions, roster snapshots and role snapshots
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
    assert!(snapshots > 0, "no role snapshot");
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
// things in a saved component between opens (leaves by their `created.0`, one of them with a
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
/// rows, a role commit's frontier among the view).
pub(crate) fn open_equals_rebuild(e: &mut Engine, things: &[Tid], at: &str) {
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
// un-merge (an invalid write arriving), a forget (lost access) and a crash at every write of a
// transaction, an open from the persisted index computes what a rebuild from the commit records
// computes
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
    let scope = osis_perm::DemotionScope { roles: [(b, [t].into())].into(), content: [(b, [t].into())].into() };
    let now = lp.peers[2].engine.now();
    let f = lp.peers[2].engine.frontier(&scope, now).unwrap();
    let mut m = Mutation::new();
    m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(b)) }).unwrap();
    m.frontier(f.to_value());
    let rv = lp.peers[2].commit(m).unwrap().unwrap();
    let late = add_tag(&mut lp, 1, t, "late");
    let (pk2, pk1) = (lp.packages(2).unwrap(), lp.packages(1).unwrap());
    lp.deliver(0, pk2.iter().find(|p| p.id == rv).unwrap()).unwrap();
    let tags = |lp: &mut LocalPeer| match lp.peers[0].engine.get(&t, &ak("t:tags.0")).unwrap() {
        Some(Value::Set(s)) => s.len(),
        _ => 0,
    };
    assert_eq!(tags(&mut lp), 5, "the revoke flips B's add invalid");
    open_equals_rebuild(&mut lp.peers[0].engine, &[t], "validity flip");
    lp.deliver(0, pk1.iter().find(|p| p.id == late).unwrap()).unwrap();
    assert_eq!(tags(&mut lp), 5, "B's late add arrives invalid");
    open_equals_rebuild(&mut lp.peers[0].engine, &[t], "un-merge");
}

// spec/requirements.md, Decentralization; spec/permissions.md §3 (drop lost secrets): after a
// holder removed from a thing with secrets of its own forgets what it lost, an open from the
// persisted index computes what a rebuild from the commit records computes
#[test]
fn open_equals_rebuild_after_a_forget() {
    let mut lp = LocalPeer::new(2, 0xf0e7, T0).unwrap();
    let hosts = vec![osis_label::Address { url: "quic://s1:1".into(), key: [7; 32] }];
    let pa = lp.peers[0].engine.create_person(&hosts).unwrap().0.person;
    let pb = lp.peers[1].engine.create_person(&hosts).unwrap().0.person;
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
    open_equals_rebuild(&mut lp.peers[1].engine, &[d], "holder");
    lp.peers[0].engine.demote(&d, &osis_node::flows::Demotion { holder: pb, new: None, presync: osis_node::flows::PreSync::Synced, keep: None }).unwrap();
    lp.sync_all().unwrap();
    let gone = lp.peers[1].engine.forget_lost(osis_node::rotation::LostScope::Due).unwrap().forgotten;
    assert!(gone.things.contains(&d), "B forgets the thing");
    open_equals_rebuild(&mut lp.peers[1].engine, &[d], "forget");
    open_equals_rebuild(&mut lp.peers[0].engine, &[d], "owner");
}

// spec/requirements.md, Decentralization; spec/commits.md §5 (a dropped body leaves no local
// index entry derived from it): after `secrets.0` and `keys.0` compactions drop a grant's and a
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
    let demote = osis_node::flows::Demotion { holder: r, new: None, presync: osis_node::flows::PreSync::Synced, keep: None };
    ids.extend(lp.peers[0].engine.demote(&t, &demote).unwrap().commits);
    lp.sync_all().unwrap();
    // the admin compacts both aspects and drops every body a snapshot covers
    let compact = |e: &mut Engine, ids: &mut Vec<osis_base::CommitId>| {
        let mut dropped = 0;
        for k in ["secrets.0", "keys.0"] {
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
    let demote = osis_node::flows::Demotion { holder: w, new: None, presync: osis_node::flows::PreSync::Synced, keep: None };
    ids.extend(lp.peers[0].engine.demote(&t, &demote).unwrap().commits);
    lp.sync_all().unwrap();
    open_equals_rebuild(&mut lp.peers[0].engine, &[t], "rotated after");
    compact(&mut lp.peers[0].engine, &mut ids);
    open_equals_rebuild(&mut lp.peers[0].engine, &[t], "compacted again");
}

// as above, randomized: four nodes grant, demote (rotations), compact `secrets.0` and `keys.0`
// dropping what the snapshot covers, and pass commits on late and out of order; at random points
// and at the end an open equals a rebuild, whole index included. Seeds 0..4 and FOUND; more in
// `_large`. FOUND: 10607 kept a thing in `own_keys` after its `keys.0` went back to missing, which
// a rebuild lost; 225191 left a part `uncover` made missing judged by its dropped body's role
// (`uncovered_part_judged_anew`).
#[test]
fn open_equals_rebuild_random_secrets_compactions() {
    const FOUND: [u64; 2] = [10607, 225191];
    let seeds: Vec<u64> = (0..4).chain(FOUND).collect();
    let dropped: usize = osis_base::testenv::run_seeds("walks::open_equals_rebuild_random_secrets_compactions", &seeds, false, secrets_replay, secrets_history).into_iter().sum();
    assert!(dropped > 0, "no role body dropped");
}

/// Seeds: OSIS_WALKS_SECRETS_START, OSIS_WALKS_SECRETS_SEEDS (default 0..200).
#[test]
#[ignore = "tier 2"]
fn open_equals_rebuild_random_secrets_compactions_large() {
    osis_base::testenv::Seeds::from_env("OSIS_WALKS_SECRETS_START", "OSIS_WALKS_SECRETS_SEEDS", osis_base::testenv::large(0..200)).run("walks::open_equals_rebuild_random_secrets_compactions_large", secrets_replay, secrets_history);
}

fn secrets_replay(s: u64) -> String {
    format!("OSIS_WALKS_SECRETS_START={s} OSIS_WALKS_SECRETS_SEEDS=1 cargo test --workspace --test it walks::open_equals_rebuild_random_secrets_compactions_large -- --ignored --exact")
}

// spec/permissions.md §5.2 (a part dropped as covered whose coverer turns invalid is missing
// again, judged as at a node that never held it): B removes admin D, rotating the admin keyset;
// C compacts `keys.0` and drops the rotation's part; A demotes B to write (the rotation's `keys.0`
// part turns invalid: it needs admin) and removes C (the snapshot turns invalid): the part,
// missing again, needs only write and turns valid, as a rebuild judges it. Shrunk from walks seed 225191, where
// the flip went unjudged.
#[test]
fn uncovered_part_judged_anew() {
    let mut lp = LocalPeer::new(4, 0x0c0e, T0).unwrap();
    lp.sync_all().unwrap();
    let ids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.tid()).collect();
    let (b, c, d) = (ids[1], ids[2], ids[3]);
    let t = new_thing(&mut lp, 0);
    for m in [b, c, d] {
        lp.peers[0].engine.grant(&t, &m, &edge(Role::Admin)).unwrap();
    }
    lp.sync_all().unwrap();
    let deliver = |lp: &mut LocalPeer, from: usize, to: usize, cs: &[osis_base::CommitId]| {
        let pk = lp.packages(from).unwrap();
        for p in pk.iter().filter(|p| cs.contains(&p.id)) {
            lp.deliver(to, p).unwrap();
        }
    };
    let tick = |lp: &mut LocalPeer| (0..4).for_each(|i| lp.peers[i].clock.advance(1));
    // B's removal of D reaches C alone
    tick(&mut lp);
    let rm = osis_node::flows::Demotion { holder: d, new: None, presync: osis_node::flows::PreSync::Synced, keep: None };
    let g = lp.peers[1].engine.demote(&t, &rm).unwrap().commits;
    deliver(&mut lp, 1, 2, &g);
    // C compacts `keys.0`, dropping the rotation's part
    tick(&mut lp);
    let keys = ak("keys.0");
    let e = &mut lp.peers[2].engine;
    let snap = e.snapshot(&t, &keys).unwrap().unwrap();
    let on: Vec<_> = g.iter().filter(|x| e.header(x).is_some_and(|h| h.aspects.iter().any(|a| a.tid == t && a.ak == keys))).copied().collect();
    assert!(!on.is_empty(), "the removal writes `keys.0`");
    for x in &on {
        assert_eq!(e.covered(&snap, x, &t, &keys).unwrap(), Some(true));
        e.drop_body(x, &t, &keys).unwrap();
    }
    // A, having seen neither, demotes B to write and removes C
    tick(&mut lp);
    let to_write = osis_node::flows::Demotion { holder: b, new: Some(edge(Role::Write)), presync: osis_node::flows::PreSync::Synced, keep: None };
    let db = lp.peers[0].engine.demote(&t, &to_write).unwrap().commits;
    let gone = osis_node::flows::Demotion { holder: c, new: None, presync: osis_node::flows::PreSync::Synced, keep: None };
    let dc = lp.peers[0].engine.demote(&t, &gone).unwrap().commits;
    deliver(&mut lp, 0, 2, &db);
    let valid = |e: &Engine, x: &osis_base::CommitId| e.body_valid(x, &t, &keys).unwrap();
    assert!(on.iter().all(|x| !valid(&lp.peers[2].engine, x)), "B's admin write invalid after the demotion");
    open_equals_rebuild(&mut lp.peers[2].engine, &[t], "B demoted");
    deliver(&mut lp, 0, 2, &dc);
    assert!(on.iter().all(|x| valid(&lp.peers[2].engine, x)), "missing again, the part needs write only");
    open_equals_rebuild(&mut lp.peers[2].engine, &[t], "C removed");
}

/// One random history of `open_equals_rebuild_random_secrets_compactions`; how many role-class
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
                let d = osis_node::flows::Demotion { holder: m, new: None, presync: osis_node::flows::PreSync::Synced, keep: None };
                let _ = lp.peers[i].engine.demote(&t, &d);
            }
            3 | 4 => {
                let k = ak(["secrets.0", "keys.0"][rng.below(2) as usize]);
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

/// A frontier listing `commits`, padded past `CHUNK_THRESHOLD` when `big` (it then goes by
/// link).
fn listing(commits: &[osis_base::CommitId], big: bool) -> ct::Frontier {
    let mut f = ct::Frontier { commits: commits.iter().copied().collect() };
    for i in 0..if big { 4000u32 } else { 0 } {
        let b = i.to_be_bytes();
        f.commits.insert(osis_base::CommitId([b[0], b[1], b[2], b[3], 9, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]));
    }
    f
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
        m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(x)) }).unwrap();
        m.frontier(f.to_value());
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let mut received = Vec::new();
    for (n, big) in [(1, false), (2, true)] {
        set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Write)), None);
        lp.sync_all().unwrap();
        let got = add_tag(&mut lp, 1, t, &format!("x{n}"));
        received.push(got);
        // a write the demoter has not received: dropped by the frontier
        add_tag(&mut lp, 1, t, &format!("late{n}"));
        let pk = lp.packages(1).unwrap();
        lp.deliver(0, pk.iter().find(|p| p.id == got).unwrap()).unwrap();
        demote(&mut lp, listing(&received, big));
        open_equals_rebuild(&mut lp.peers[0].engine, &[t], &format!("demotion {n}"));
        lp.sync_all().unwrap();
        let Some(Value::Set(tags)) = lp.peers[0].engine.get(&t, &ak("t:tags.0")).unwrap() else { panic!("demotion {n}: no tags") };
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
// roster snapshots and late, out-of-order deliveries: at random points a node
// opened from its persisted index, and then rebuilt from its commit records, equals the running
// node (views, `by_thing`, `by_chunk`, validity, perm, states). Seeds 0..4, which reach drops,
// invalid parts, roster snapshots and chunks; more in `_large`.
#[test]
fn open_equals_rebuild_random_histories() {
    let seeds: Vec<u64> = (0..4).collect();
    let mut most = [0usize; 4];
    for r in osis_base::testenv::run_seeds("walks::open_equals_rebuild_random_histories", &seeds, false, walks_replay, |seed| random_history(seed, false)) {
        for k in 0..4 {
            most[k] = most[k].max(r[k]);
        }
    }
    assert!(most.iter().all(|n| *n > 0), "reached (dropped, invalid, roster snapshots, chunks): {most:?}");
}

/// Seeds: OSIS_WALKS_START, OSIS_WALKS_SEEDS (default 0..200).
#[test]
#[ignore = "tier 2"]
fn open_equals_rebuild_random_histories_large() {
    osis_base::testenv::Seeds::from_env("OSIS_WALKS_START", "OSIS_WALKS_SEEDS", osis_base::testenv::large(0..200)).run("walks::open_equals_rebuild_random_histories_large", walks_replay, |seed| random_history(seed, false));
}

fn walks_replay(s: u64) -> String {
    format!("OSIS_WALKS_START={s} OSIS_WALKS_SEEDS=1 cargo test --workspace --test it walks::open_equals_rebuild_random_histories_large -- --ignored --exact")
}

// as above, spec/crdt.md §4.8: seeds where a keep-at-most-0 body died and dropped, its killer
// turned invalid, and a late body older than it arrived (they failed under the old exact dating
// of dropped bodies)
#[test]
fn open_equals_rebuild_random_histories_unkilled_residue() {
    for seed in [40558, 40797] {
        let _ = random_history(seed, false);
    }
}

// as above, spec/commits.md §5: seeds where a write of a keep-at-most-0 map died while its part
// had not arrived (a late part): the death went to that unheld part and dropped it, so the part
// was both dropped and missing in place, dropped only after a rebuild (737046 on main too)
#[test]
fn open_equals_rebuild_random_histories_unheld_part_dies() {
    for seed in [737046, 737257] {
        let _ = random_history(seed, false);
    }
}

// spec/requirements.md, Decentralization and Threat model ("malicious readers can only waste
// storage"); spec/permissions.md §5.2: as above, with nodes taking hostile snapshots that copy a
// held tag's dot and `ts` with another value, sent on like any commit, and compactors dropping
// what they cover: open equals rebuild, and once every node holds everything the tags agree
// (a valid snapshot's copy governs where the original is held too). Seeds 0..4; more in
// `_large`.
#[test]
fn open_equals_rebuild_random_histories_forged() {
    // 9374128: a part turning missing again left held snapshots' copies of its writes uncarried
    // (`retention::note_carried_again`)
    let seeds: Vec<u64> = (0..4).chain([9374128]).collect();
    osis_base::testenv::run_seeds("walks::open_equals_rebuild_random_histories_forged", &seeds, false, forged_replay, |seed| random_history(seed, true));
}

/// Seeds: OSIS_WALKS_FORGED_START, OSIS_WALKS_FORGED_SEEDS (default 0..200).
#[test]
#[ignore = "tier 2"]
fn open_equals_rebuild_random_histories_forged_large() {
    osis_base::testenv::Seeds::from_env("OSIS_WALKS_FORGED_START", "OSIS_WALKS_FORGED_SEEDS", osis_base::testenv::large(0..200)).run("walks::open_equals_rebuild_random_histories_forged_large", forged_replay, |seed| random_history(seed, true));
}

fn forged_replay(s: u64) -> String {
    format!("OSIS_WALKS_FORGED_START={s} OSIS_WALKS_FORGED_SEEDS=1 cargo test --workspace --test it walks::open_equals_rebuild_random_histories_forged_large -- --ignored --exact")
}

/// One random history of `open_equals_rebuild_random_histories`; returns what it reached on any
/// node (most of each `reached` count).
fn random_history(seed: u64, forge: bool) -> [usize; 4] {
    let mut most = [0usize; 4];
    let mut forged = 0usize;
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut lp = LocalPeer::new(3, 0x7a1c + seed, T0).unwrap();
    lp.sync_all().unwrap();
    let ids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.tid()).collect();
    let things: Vec<Tid> = (0..2).map(|_| new_thing(&mut lp, 0)).collect();
    for t in things.clone() {
        set_edge(&mut lp.peers[0].engine, t, ids[1], Some(edge(Role::Write)), None);
        set_edge(&mut lp.peers[0].engine, t, ids[2], Some(edge(Role::Admin)), None);
    }
    lp.sync_all().unwrap();
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
                let fill: osis_base::ValueMap = (0..40 + rng.below(40)).map(|k| (s(&format!("k{k:03}")), s(&format!("{step}{}", "g".repeat(400))))).collect();
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
                let a = ak(["t:keptset.0", "t:gonemap.0", "t:tags.0"][rng.below(3) as usize]);
                let e = &mut lp.peers[i].engine;
                if let Ok(Some(snap)) = e.snapshot(&t, &a)
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
                m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(ids[1])) }).unwrap();
                if let Some(e) = role {
                    m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(ids[1]))], op: Op::Set(edge(e).to_value()) }).unwrap();
                }
                let scope = osis_perm::DemotionScope { roles: [(ids[1], [t].into())].into(), content: [(ids[1], [t].into())].into() };
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
        // every node holds every commit it has not dropped: the tags agree, a valid forger's
        // copies showing wherever they are held, the original or not (spec/permissions.md §5.2)
        let tagged = |lp: &mut LocalPeer, i: usize| things.iter().map(|t| lp.peers[i].engine.get(t, &ak("t:tags.0")).unwrap()).collect::<Vec<_>>();
        let first = tagged(&mut lp, 0);
        for i in 1..3 {
            assert_eq!(tagged(&mut lp, i), first, "seed {seed}: peer {i} differs ({forged} forged)");
        }
    }
    most
}

/// Peer `i` forges a snapshot of `t`'s `t:tags.0`: its state with the value of a held tag (a
/// session-form commit's element) replaced, under that element's dot and `ts`, and takes it.
fn forge_tag(lp: &mut LocalPeer, i: usize, t: Tid, step: usize, rng: &mut Rng) -> bool {
    use osis_crdt::{Batch, Source, Writer};
    let tags = ak("t:tags.0");
    let e = &lp.peers[i].engine;
    let held: Vec<(osis_base::Ts, Source, u64)> = e
        .commit_ids()
        .iter()
        .filter_map(|id| e.header(id).map(|h| (*id, h)))
        .filter(|(_, h)| h.kind == osis_commit::Kind::Content && h.form.counted())
        .filter_map(|(id, h)| h.aspects.iter().find(|a| a.tid == t && a.ak == tags).map(|a| (h.ts, h.form.own_source(h.author, id), a.lo)))
        .collect();
    if held.is_empty() {
        return false;
    }
    let (ts, src, lo) = held[rng.below(held.len() as u64) as usize].clone();
    let dot = osis_crdt::Dot::new(src.clone(), lo);
    let Some(mut f) = lp.peers[i].engine.state(&t, &tags).unwrap() else { return false };
    f.strip_copies(&|d| *d == dot);
    let mut b = Batch::new(&f, Writer::new(ts, src, lo));
    if b.apply(&PathOp { path: Vec::new(), op: Op::Add(s(&format!("forged{step}"))) }, &osis_crdt::AnyView).is_err() {
        return false;
    }
    let Some((extra, _)) = b.finish() else { return false };
    f.join(extra);
    let now = osis_base::Ts::make(lp.peers[i].engine.now(), 0).unwrap();
    let bytes = forge_snapshot(lp, i, t, &tags, now, f);
    lp.peers[i].engine.ingest(&bytes, Vec::new()).is_ok()
}
