#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The saved membership walks (notes/local-store.md, rebuildable caches; notes/node.md, Open):
//! an open resumes each component's walk from the store and gives what a from-scratch
//! evaluation gives (spec/permissions.md §5.1 step 5: validity is a function of the held set);
//! a damaged, truncated or foreign walk is evaluated anew, never an error; a crash at any write
//! leaves no walk ahead of its commits. Likewise the index's rows of what perm reads of each
//! membership commit (`node/edges`): an open from them equals a rebuild from the commit records.

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
    let had = (validity(&e.index_digest()), e.perm_digest(false), states(e, things));
    e.reload_index().unwrap();
    assert_eq!(e.headers_decoded(), decoded, "{at}: headers the open decoded");
    assert_eq!((validity(&e.index_digest()), e.perm_digest(false), states(e, things)), had, "{at}: opened from the index");
    e.rebuild_index().unwrap();
    assert_eq!((validity(&e.index_digest()), e.perm_digest(false), states(e, things)), had, "{at}: rebuilt");
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
    let take = |e: &mut Engine| (validity(&e.index_digest()), e.perm_digest(false), states(e, things));
    let had = take(e);
    e.reload_index().unwrap();
    same(&take(e), &had, &format!("{at}: opened from the index"));
    e.rebuild_index().unwrap();
    same(&take(e), &had, &format!("{at}: rebuilt"));
}

type Digest = (String, String, Vec<(Tid, osis_base::Ak, Option<Value>)>);

/// Equal digests, else the lines that differ.
fn same(got: &Digest, want: &Digest, at: &str) {
    if got == want {
        return;
    }
    let diff = |a: &str, b: &str| -> Vec<String> {
        let (x, y): (std::collections::BTreeSet<&str>, std::collections::BTreeSet<&str>) = (a.lines().collect(), b.lines().collect());
        x.symmetric_difference(&y).map(|l| format!("{} {}", if x.contains(l) { "got " } else { "want" }, l.chars().take(600).collect::<String>())).collect()
    };
    panic!("{at}: index {:#?}\nperm {:#?}\nstates equal {}", diff(&got.0, &want.0), diff(&got.1, &want.1), got.2 == want.2);
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
    let commits = || d.lines().filter(|l| l.starts_with("commit "));
    [
        commits().filter(|l| !l.contains(" {} ")).count(),
        commits().filter(|l| l.split(" View").next().is_some_and(|h| h.contains("false"))).count(),
        commits().filter(|l| l.contains("kind: RosterSnapshot")).count(),
        d.lines().filter(|l| l.starts_with("by_chunk")).map(|l| l.matches("BlobId(").count()).sum(),
    ]
}

// spec/requirements.md, Decentralization; spec/permissions.md §5.2; spec/commits.md §5: random
// three-node histories of large values, tags, keep-at-most-0 aspects (drops, large ones with
// their chunks), compaction snapshots, revokes that flip validity and un-merge late writes,
// roster snapshots, a move (imports) and late, out-of-order deliveries: at random points a node
// opened from its persisted index, and then rebuilt from its commit records, equals the running
// node (views, `by_thing`, `by_chunk`, validity, perm, states). Seeds: OSIS_WALKS_START,
// OSIS_WALKS_SEEDS.
#[test]
fn open_equals_rebuild_random_histories() {
    let env = |k: &str, d: u64| std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d);
    let (start, seeds) = (env("OSIS_WALKS_START", 0), env("OSIS_WALKS_SEEDS", 4));
    let mut most = [0usize; 4];
    for seed in start..start + seeds {
        random_history(seed, &mut most, 1);
    }
    // the histories reach drops, invalid parts, roster snapshots and chunks
    assert!(most.iter().all(|n| *n > 0), "reached (dropped, invalid, roster snapshots, chunks): {most:?}");
}

// as above: seeds where a snapshot of the moved thing carried imported writes whose origin
// commit arrived after it (the carried index depended on that order)
#[test]
fn open_equals_rebuild_random_histories_carried_imports() {
    for seed in [261, 377] {
        random_history(seed, &mut [0; 4], 1);
    }
}

// as above with moves weighted up (copies of copies, their aspects snapshotted); seeds 6013,
// 6106 and 6305 failed on issues/carried-import-order.md (about one seed in ten did; one in 200
// without the weighting). OSIS_WALKS_MOVES_START, OSIS_WALKS_MOVES_SEEDS run others.
#[test]
fn open_equals_rebuild_random_histories_moves() {
    let env = |k: &str| std::env::var(k).ok().and_then(|s| s.parse::<u64>().ok());
    let seeds: Vec<u64> = match (env("OSIS_WALKS_MOVES_START"), env("OSIS_WALKS_MOVES_SEEDS")) {
        (Some(a), n) => (a..a + n.unwrap_or(1)).collect(),
        _ => vec![6013, 6106, 6305],
    };
    for seed in seeds {
        random_history(seed, &mut [0; 4], 3);
    }
}

/// One random history of `open_equals_rebuild_random_histories` with up to `max_moves` moves (more
/// than one: moves from step 10, moved things snapshotted more); raises `most` to what it reached.
fn random_history(seed: u64, most: &mut [usize; 4], max_moves: usize) {
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
            6 => {
                let a = ["/t/keptset", "/t/gonemap", "/t/tags"][rng.below(3) as usize];
                let _ = lp.peers[i].engine.snapshot(&t, &ak(a));
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
                    moves += 1;
                }
            }
            15 if max_moves > 1 && moves > 0 => {
                let c = *things.last().unwrap();
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
    let carried = |e: &Engine| e.index_digest().lines().find(|l| l.starts_with("carried ")).unwrap_or_default().to_string();
    for i in [2, 3] {
        assert_eq!(carried(&lp.peers[i].engine), "carried {}", "peer {i}: the import's writes are not carried");
        open_equals_rebuild_any(&mut lp.peers[i].engine, &[t, copy], &format!("peer {i}"));
    }
}

// spec/permissions.md §5.2, §7: a snapshot of a moved thing carries an import's writes (source
// `Commit(o)`); a node holding o (on the old thing) but not the import judges them as the
// import's author, so an import invalid on the copy (its author revoked before it) shows them
// nowhere. The old rule took o held as their own commit held, and showed them.
#[test]
fn carried_imports_judged_without_the_import_spec_perm_5_2() {
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
    assert_eq!(lp.peers[3].engine.get(&copy, &tags).unwrap(), none, "carried writes of an import not held are judged as its author's");
    open_equals_rebuild_any(&mut lp.peers[3].engine, &[t, copy, p], "without the imports");
    for x in pk.iter().filter(|x| imports.contains(&x.id)) {
        lp.deliver(3, x).unwrap();
    }
    assert_eq!(states(&mut lp.peers[3].engine, &[t, copy, p]), full, "then alike with them");
}
