#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Session sources (spec/crdt.md §2.1) and traced snapshot tables (spec/crdt.md §8,
//! spec/commits.md §4, §5): a snapshot lists only the sessions with a write left in it, and its
//! readers take an absent session as one it holds nothing of.

use crate::common;
use common::*;
use osis_commit::CommitBlob;
use osis_base::{Ak, Classified, CommitId, Role, Tid, Value};
use osis_node::local_peer::{LocalPeer, Package};
use osis_node::{Engine, Mutation};
use std::collections::BTreeSet;

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

fn set(lp: &mut LocalPeer, i: usize, t: Tid, k: &osis_schema::Aspect<Value>, v: &str) -> CommitId {
    let mut m = Mutation::new();
    m.set(t, k, &s(v)).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

/// The frontiers of held snapshot `snap` of `(t, a)`.
fn frontiers_of(e: &Engine, snap: &CommitId, t: &Tid, a: &Ak) -> osis_crdt::Frontiers {
    e.core.ix.snapshots.get(&(*t, a.clone())).into_iter().flatten().find(|x| x.1 == *snap).map(|x| x.2.clone()).expect("a held snapshot")
}

/// The own source of held commit `c` at peer `i`.
fn source_of(lp: &LocalPeer, i: usize, c: &CommitId) -> osis_crdt::Source {
    let h = lp.peers[i].engine.header(c).unwrap();
    h.form.own_source(h.author, *c)
}

/// `bytes` of a commit with only its parts on `ak`.
fn only(bytes: &[u8], h: &osis_commit::Header, ak: &str) -> Vec<u8> {
    let mut b = CommitBlob::decode(bytes).unwrap();
    b.parts.retain(|p| h.aspects[p.ai].ak.as_str() == ak);
    b.encode()
}

/// Drops at `e` every body of `(t, a)` that snapshot `s` covers (node-sync's compaction).
fn drop_covered_by(e: &mut Engine, s: &CommitId, t: &Tid, a: &Ak) {
    let held: Vec<CommitId> = e.core.ix.by_aspect.get(&(*t, a.clone())).into_iter().flatten().map(|x| x.1).collect();
    for c in held {
        if c != *s && e.body_not_dropped(&c, t, a) && e.covered(s, &c, t, a).unwrap() == Some(true) {
            e.drop_body(&c, t, a).unwrap();
        }
    }
}

// spec/crdt.md §2.1, §8, spec/commits.md §5: a register written once per launch (each launch a
// session): the snapshot lists the one session with a write left, covers every earlier launch's
// body (their sessions left no trace in it) and covers an earlier snapshot that listed a session
// since pruned; the older snapshot covers nothing newer.
#[test]
fn snapshot_lists_only_traced_sessions_spec_crdt_8() {
    let mut lp = net(1, 0x5e55);
    let t = new_thing(&mut lp, 0);
    let reg = ak("t:reg.0");
    let mut commits = Vec::new();
    let mut first_snap = None;
    for i in 0..8u64 {
        lp.peers[0].restart(0x5e60 + i).unwrap();
        lp.advance(1_000);
        commits.push(set(&mut lp, 0, t, &REG, &format!("launch {i}")));
        if i == 3 {
            lp.advance(1_000);
            first_snap = lp.peers[0].engine.snapshot(&t, &reg).unwrap();
        }
    }
    let sessions: BTreeSet<_> = commits.iter().map(|c| source_of(&lp, 0, c)).collect();
    assert_eq!(sessions.len(), commits.len(), "a session per launch");
    lp.advance(1_000);
    let e = &mut lp.peers[0].engine;
    let snap = e.snapshot(&t, &reg).unwrap().unwrap();
    let fr = frontiers_of(e, &snap, &t, &reg);
    let last = source_of(&lp, 0, commits.last().unwrap());
    assert_eq!(fr.sources().map(|x| x.0).collect::<Vec<_>>(), vec![last.clone()], "one session listed: the last launch's");
    assert_eq!(fr.of(&last), 1);
    let e = &mut lp.peers[0].engine;
    for c in &commits[..commits.len() - 1] {
        assert_eq!(e.covered(&snap, c, &t, &reg).unwrap(), Some(true), "an earlier launch's body is covered");
    }
    assert_eq!(e.covered(&snap, commits.last().unwrap(), &t, &reg).unwrap(), Some(true));
    let first_snap = first_snap.unwrap();
    assert_eq!(frontiers_of(e, &first_snap, &t, &reg).sources().count(), 1);
    assert_eq!(e.covered(&snap, &first_snap, &t, &reg).unwrap(), Some(true), "the newer snapshot covers the older, whose session it holds nothing of");
    assert_eq!(e.covered(&first_snap, &snap, &t, &reg).unwrap(), Some(false), "not the other way round");
    assert_eq!(e.get(&t, &reg).unwrap(), Some(s("launch 7")));
}

// spec/commits.md §5: a held body is judged by the join, whatever the frontier. W gets only the later
// of A's two writes per aspect, so its snapshots list A's session short of them. When the earlier writes
// come, the dead register write is covered (holders must not keep uploading it for a right holder
// to delete, `snapshot_rights`), and the live tag is not.
#[test]
fn frontier_gap_covers_what_joins_unchanged_spec_commits_5() {
    let mut lp = net(2, 0x5e90);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let w = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    let tag = |lp: &mut LocalPeer, v: &str| {
        let mut m = Mutation::new();
        m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s(v)) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let old = set(&mut lp, 0, t, &REG, "old");
    let old_tag = tag(&mut lp, "x");
    lp.advance(1_000);
    let new = set(&mut lp, 0, t, &REG, "new");
    let new_tag = tag(&mut lp, "y");
    let pks = packages(&mut lp, 0);
    let pk = |c: &CommitId| pks.iter().find(|p| p.id == *c).unwrap();
    lp.deliver(1, pk(&new)).unwrap();
    lp.deliver(1, pk(&new_tag)).unwrap();
    lp.advance(1_000);
    let (reg, tags) = (ak("t:reg.0"), ak("t:tags.0"));
    let snap = lp.peers[1].engine.snapshot(&t, &reg).unwrap().unwrap();
    let snap_tags = lp.peers[1].engine.snapshot(&t, &tags).unwrap().unwrap();
    let src = source_of(&lp, 0, &new);
    // the register's first write is the thing's creation
    for (z, a, stops) in [(&snap, &reg, 1), (&snap_tags, &tags, 0)] {
        let fr = frontiers_of(&lp.peers[1].engine, z, &t, a);
        assert!(fr.lists(&src) && fr.of(&src) == stops, "the session listed short of the earlier write");
    }
    lp.deliver(1, pk(&old)).unwrap();
    lp.deliver(1, pk(&old_tag)).unwrap();
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.covered(&snap, &old, &t, &reg).unwrap(), Some(true), "dead in the snapshot");
    assert_eq!(e.covered(&snap, &new, &t, &reg).unwrap(), Some(true));
    assert_eq!(e.covered(&snap_tags, &old_tag, &t, &tags).unwrap(), Some(false), "live, not in the snapshot");
    assert_eq!(e.covered(&snap_tags, &new_tag, &t, &tags).unwrap(), Some(true));
}

// spec/commits.md §5: a later snapshot covers an earlier one by the join, whatever the frontiers. B
// knows A's session only through A's snapshot, so its own lists it at 0, below A's. Each writer's
// latest snapshot would otherwise stay beside the others' for good.
#[test]
fn snapshot_covers_one_reaching_further_spec_commits_5() {
    let mut lp = net(2, 0x5e91);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let w = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    let tags = ak("t:tags.0");
    let add = |lp: &mut LocalPeer, i: usize, v: &str| {
        let mut m = Mutation::new();
        m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s(v)) }).unwrap();
        lp.peers[i].commit(m).unwrap().unwrap()
    };
    let c = add(&mut lp, 0, "a");
    lp.advance(1_000);
    let z1 = lp.peers[0].engine.snapshot(&t, &tags).unwrap().unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == z1).unwrap();
    lp.deliver(1, &pk).unwrap();
    lp.advance(1_000);
    add(&mut lp, 1, "b");
    lp.advance(1_000);
    let zb = lp.peers[1].engine.snapshot(&t, &tags).unwrap().unwrap();
    let src = source_of(&lp, 0, &c);
    let e = &mut lp.peers[1].engine;
    assert_eq!(frontiers_of(e, &z1, &t, &tags).of(&src), 1);
    let fr = frontiers_of(e, &zb, &t, &tags);
    assert!(fr.lists(&src) && fr.of(&src) == 0);
    assert_eq!(e.covered(&zb, &z1, &t, &tags).unwrap(), Some(true));
    assert_eq!(e.covered(&z1, &zb, &t, &tags).unwrap(), Some(false));
    assert_eq!(e.get(&t, &tags).unwrap(), Some(Value::Set([s("a"), s("b")].into())));
}

// spec/commits.md §4 (a node never waits for a part), spec/crdt.md §8: A's commit c writes the
// register and a tag; B, syncing the thing, gets c without its tags part and W's snapshot of the
// tags, written without c: c applies at B (the register shows), and its tags part joins when it
// comes, the snapshot holding nothing of its session.
#[test]
fn untraced_session_part_joins_late_spec_commits_4() {
    let mut lp = net(3, 0x5e70);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let w = lp.peers[2].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    let mut m = Mutation::new();
    m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s("w")) }).unwrap();
    lp.peers[2].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("a")).unwrap();
    m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s("a")) }).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == c).unwrap();
    let h = lp.peers[0].engine.header(&c).unwrap();
    lp.advance(1_000);
    let snap = lp.peers[2].engine.snapshot(&t, &ak("t:tags.0")).unwrap().unwrap();
    assert!(!frontiers_of(&lp.peers[2].engine, &snap, &t, &ak("t:tags.0")).lists(&source_of(&lp, 0, &c)), "W never received c");
    sync(&mut lp, 2, 1);
    lp.peers[1].engine.ingest(&only(&pk.bytes, &h, "t:reg.0"), Vec::new()).unwrap();
    lp.peers[1].engine.reexamine().unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.pending().is_empty(), "{:?}", e.pending());
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("a")));
    assert_eq!(e.get(&t, &ak("t:tags.0")).unwrap(), Some(Value::Set([s("w")].into())));
    lp.deliver(1, &pk).unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:tags.0")).unwrap(), Some(Value::Set([s("a"), s("w")].into())), "the part joined late");
}

/// The store's bytes at peer `i`.
fn store_bytes(lp: &LocalPeer, i: usize) -> usize {
    lp.peers[i].backend.dump().iter().map(|(k, v)| k.len() + v.len()).sum()
}

/// The size of the snapshot delta of `(t, a)` a compaction now writes, its frontier entries, and the
/// bodies left of the aspect after it drops what it covers: one overwrite, one compaction.
fn overwrite_and_compact(lp: &mut LocalPeer, t: Tid, i: u64) -> Vec<(usize, usize, usize)> {
    let mut m = Mutation::new();
    m.set(t, &REG, &s(&format!("v{i:06}"))).unwrap();
    m.set(t, &BIG, &Value::Map([(s("k"), s(&format!("v{i:06}")))].into())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    [ak("t:reg.0"), ak("t:big.0")]
        .iter()
        .map(|a| {
            let e = &mut lp.peers[0].engine;
            let snap = e.snapshot(&t, a).unwrap().unwrap();
            drop_covered_by(e, &snap, &t, a);
            let pk = e.package(&snap).unwrap().unwrap();
            let blob = CommitBlob::decode(&pk.bytes).unwrap();
            (blob.parts[0].delta.len(), frontiers_of(e, &snap, &t, a).sources().count(), e.held_bodies(&t, a))
        })
        .collect()
}

// spec: none (notes/growth.md, Tess's session rule). A session that writes nothing leaves
// nothing in the store.
#[test]
fn session_writing_nothing_leaves_nothing() {
    let mut lp = net(1, 0x5e78);
    let t = new_thing(&mut lp, 0);
    overwrite_and_compact(&mut lp, t, 0);
    let before = store_bytes(&lp, 0);
    for i in 0..20 {
        lp.advance(1_000);
        lp.peers[0].restart(0x5e80 + i).unwrap();
    }
    assert_eq!(store_bytes(&lp, 0), before);
}

// spec: none (notes/growth.md, Tess's session rule). A register and a map written whole,
// overwritten and compacted once per launch, cost what the same writes cost in one launch: the
// snapshots hold steady (one session listed; the map also its entry's first), and the store holds
// no more per launch.
#[test]
fn steady_aspect_holds_steady_across_sessions() {
    let run = |launches: bool| {
        let mut lp = net(1, 0x5e90);
        let t = new_thing(&mut lp, 0);
        let mut last = Vec::new();
        for i in 0..24u64 {
            if launches {
                lp.peers[0].restart(0x5ea0 + i).unwrap();
            }
            lp.advance(1_000);
            let round = overwrite_and_compact(&mut lp, t, i);
            if i >= 2 && launches {
                assert_eq!(round.iter().map(|x| (x.1, x.2)).collect::<Vec<_>>(), vec![(1, 1), (2, 1)], "round {i}");
                if !last.is_empty() {
                    assert_eq!(round, last, "round {i}: the snapshots hold steady");
                }
                last = round;
            }
        }
        store_bytes(&lp, 0)
    };
    let (many, one) = (run(true), run(false));
    assert!(many <= one + one / 50, "{many} B over 24 launches, {one} B in one");
}

// spec/crdt.md §8: a snapshot's frontier entries are exactly its fragment's session sources:
// one naming a source the fragment lacks, or one missing for a source it holds, is bad input at
// ingest.
#[test]
fn untraced_frontier_entry_is_bad_input_spec_crdt_8() {
    let mut lp = net(2, 0x5e80);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let reg = ak("t:reg.0");
    set(&mut lp, 0, t, &REG, "real");
    sync(&mut lp, 0, 1);
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[0].engine.now(), 0).unwrap();
    let author = lp.peers[0].engine.tid();
    let f = lp.peers[0].engine.state(&t, &reg).unwrap().unwrap().clone();
    let cx = osis_commit::writer_ctx(osis_commit::Form::Commit, osis_commit::Kind::ContentSnapshot, now, author, 0, 0);
    let sound = osis_crdt::encode_snapshot(&osis_crdt::Snapshot { absorbed: Default::default(), nonce: [7; 16], fragment: f, frontiers: Default::default() }, &cx, None).unwrap();
    let tamper = |edit: &dyn Fn(&mut Vec<Value>)| {
        let Value::List(mut top) = osis_base::decode(&sound, &osis_base::Limits::DEFAULT).unwrap() else { panic!() };
        edit(&mut top);
        osis_base::encode(&Value::List(top))
    };
    // a session not in the fragment, listed with a frontier
    let other = osis_crdt::Session { node: lp.peers[1].engine.tid(), nonce: [9; 16] };
    let extra = tamper(&|top| {
        let Value::List(srcs) = &mut top[1] else { panic!() };
        srcs.push(Value::Bytes(other.to_bytes().to_vec()));
        let n = srcs.len() as i64;
        let Value::List(fr) = &mut top[4] else { panic!() };
        fr.push(Value::List(vec![Value::Int(n), Value::Int(5)]));
    });
    // the one session of the fragment without its entry
    let missing = tamper(&|top| top[4] = Value::List(Vec::new()));
    let ok = forge_snapshot_bytes(&mut lp, 0, t, &reg, now, sound.clone());
    assert!(matches!(lp.peers[1].engine.ingest(&ok, Vec::new()).unwrap(), osis_node::Ingested::Applied(_)));
    for (what, bytes) in [("an untraced source listed", extra), ("a traced source unlisted", missing)] {
        let forged = forge_snapshot_bytes(&mut lp, 0, t, &reg, now, bytes);
        let e = lp.peers[1].engine.ingest(&forged, Vec::new()).unwrap_err();
        assert_eq!(e.class(), osis_base::ErrorClass::BadInput, "{what}: {e}");
    }
    assert_eq!(lp.peers[1].engine.get(&t, &reg).unwrap(), Some(s("real")));
}

/// Random writes by two writers across restarts (a session each), compacted at random points
/// so sessions get pruned from the snapshots; a fresh node given only what a writer still holds
/// (header-only commits for dropped bodies, the snapshots) reads as the writers do, and so does
/// every node after every original body is replayed into it.
fn pruned_sessions_check(seed: u64) -> Result<(), String> {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut lp = net(3, 0x5e90 + seed);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let w = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    let aspects = [ak("t:reg.0"), ak("t:tags.0"), ak("t:gonemap.0")];
    let mut packs: Vec<Package> = Vec::new();
    let mut snaps: Vec<Package> = Vec::new();
    let mut restarts = 0;
    for step in 0..40u64 {
        let by = rng.below(2) as usize;
        if rng.below(4) == 0 {
            lp.peers[by].restart(seed * 1000 + step).map_err(|e| e.to_string())?;
            restarts += 1;
        }
        lp.advance(1 + rng.below(500));
        let a = rng.below(3) as usize;
        let mut m = Mutation::new();
        let v = s(&format!("v{step}"));
        let key = s(&format!("k{}", rng.below(3)));
        match (a, rng.below(3)) {
            (0, _) => m.set(t, &REG, &v).unwrap(),
            (1, 0) => m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(key) }).unwrap(),
            (1, _) => m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(key) }).unwrap(),
            (_, 0) => m.op(t, &GONEMAP, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(key) }).unwrap(),
            _ => m.op(t, &GONEMAP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(key)], op: osis_crdt::Op::Set(v) }).unwrap(),
        };
        if let Ok(Some(id)) = lp.peers[by].commit(m) {
            packs.push(packages(&mut lp, by).into_iter().find(|p| p.id == id).unwrap());
        }
        if rng.below(3) == 0 {
            sync(&mut lp, by, 1 - by);
        }
        if rng.below(4) == 0 {
            let a = &aspects[rng.below(3) as usize];
            lp.advance(1);
            if let Some(sid) = lp.peers[by].engine.snapshot(&t, a).map_err(|e| format!("snapshot: {e}"))? {
                snaps.push(packages(&mut lp, by).into_iter().find(|p| p.id == sid).unwrap());
                drop_covered_by(&mut lp.peers[by].engine, &sid, &t, a);
            }
        }
    }
    if restarts == 0 {
        lp.peers[1].restart(seed * 1000 + 99).map_err(|e| e.to_string())?;
    }
    sync(&mut lp, 0, 1);
    sync(&mut lp, 1, 0);
    lp.advance(1_000);
    for a in &aspects {
        if let Some(sid) = lp.peers[0].engine.snapshot(&t, a).map_err(|e| format!("snapshot: {e}"))? {
            snaps.push(packages(&mut lp, 0).into_iter().find(|p| p.id == sid).unwrap());
            sync(&mut lp, 0, 1);
            for p in 0..2 {
                drop_covered_by(&mut lp.peers[p].engine, &sid, &t, a);
            }
        }
    }
    let reads = |lp: &mut LocalPeer, p: usize| aspects.iter().map(|a| lp.peers[p].engine.get(&t, a).unwrap()).collect::<Vec<_>>();
    let want = reads(&mut lp, 0);
    if reads(&mut lp, 1) != want {
        return Err(format!("the writers differ: {want:?} vs {:?}", reads(&mut lp, 1)));
    }
    // a fresh node from what peer 0 still holds
    for pk in packages(&mut lp, 0) {
        let _ = lp.deliver(2, &pk);
    }
    lp.peers[2].engine.reexamine().map_err(|e| e.to_string())?;
    if !lp.peers[2].engine.pending().is_empty() {
        let mut dump = String::new();
        for (c, _) in lp.peers[2].engine.pending() {
            let h = lp.peers[0].engine.header(&c).unwrap();
            dump += &format!("\npending {c:?} by {:?} form {:?} ts {:?} aspects {:?}", h.author, h.form, h.ts, h.aspects.iter().map(|a| (a.ak.as_str().to_string(), a.lo, a.hi)).collect::<Vec<_>>());
            for a in &h.aspects {
                dump += &format!("\n at peer 0:\n{}\n at fresh:\n{}", lp.peers[0].engine.aspect_dump(&t, &a.ak), lp.peers[2].engine.aspect_dump(&t, &a.ak));
                for (ts, s, fr, _) in lp.peers[2].engine.core.ix.snapshots.get(&(t, a.ak.clone())).into_iter().flatten() {
                    dump += &format!("\n  fresh snapshot {s:?} ts {ts:?} frontiers {fr:?}");
                }
            }
        }
        return Err(format!("the fresh node pends: {:?}{dump}", lp.peers[2].engine.pending()));
    }
    if reads(&mut lp, 2) != want {
        return Err(format!("the fresh node differs: {want:?} vs {:?}", reads(&mut lp, 2)));
    }
    // every original body again, everywhere
    for p in 0..3 {
        for pk in packs.iter().chain(&snaps) {
            let _ = lp.deliver(p, pk);
        }
        lp.peers[p].engine.reexamine().map_err(|e| e.to_string())?;
        if !lp.peers[p].engine.pending().is_empty() {
            return Err(format!("peer {p} pends after the replay: {:?}", lp.peers[p].engine.pending()));
        }
        if reads(&mut lp, p) != want {
            return Err(format!("peer {p} differs after the replay: {want:?} vs {:?}", reads(&mut lp, p)));
        }
    }
    Ok(())
}

/// spec/commits.md §5 (a held body is judged by the join whatever the frontiers): two writers see part of
/// each other's commits, so their snapshots list sessions short of bodies. Given everything, a
/// node dropping what the join covers reads and rebuilds as one dropping nothing, and a fresh node
/// from the bodies it still holds has nothing pending; no snapshot covers a delta stamped after it.
fn gap_cover_check(seed: u64) -> Result<(), String> {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut lp = net(5, 0x5ea0 + seed);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let w = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    let aspects = [ak("t:reg.0"), ak("t:tags.0"), ak("t:gonemap.0"), ak("t:list.0"), ak("t:text.0"), ak("t:count.0"), ak("t:shape.0"), ak("t:rec.0")];
    let mut packs: Vec<Package> = Vec::new();
    let mut snaps: Vec<(CommitId, Ak)> = Vec::new();
    let root = |op| osis_crdt::PathOp { path: Vec::new(), op };
    for step in 0..40u64 {
        let by = rng.below(2) as usize;
        lp.advance(1 + rng.below(500));
        let v = s(&format!("v{step}"));
        let key = s(&format!("k{}", rng.below(3)));
        let at = rng.below(3) as usize;
        let mut m = Mutation::new();
        let one = |m: &mut Mutation, a: u64, rng: &mut Rng| { match (a, rng.below(3)) {
            (0, _) => m.set(t, &REG, &v).unwrap(),
            (1, 0) => m.op(t, &TAGS, root(osis_crdt::Op::Remove(key.clone()))).unwrap(),
            (1, _) => m.op(t, &TAGS, root(osis_crdt::Op::Add(key.clone()))).unwrap(),
            (2, 0) => m.op(t, &GONEMAP, root(osis_crdt::Op::Remove(key.clone()))).unwrap(),
            (2, _) => m.op(t, &GONEMAP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(key.clone())], op: osis_crdt::Op::Set(v.clone()) }).unwrap(),
            (3, 0) => m.op(t, &LIST, root(osis_crdt::Op::Delete { at, len: 1 })).unwrap(),
            (3, _) => m.op(t, &LIST, root(osis_crdt::Op::Insert { at: 0, items: vec![v.clone()] })).unwrap(),
            (4, 0) => m.op(t, &TEXT, root(osis_crdt::Op::Delete { at, len: 1 })).unwrap(),
            (4, _) => m.op(t, &TEXT, root(osis_crdt::Op::Insert { at: 0, items: vec![s("ab")] })).unwrap(),
            (5, _) => m.op(t, &COUNT, root(osis_crdt::Op::Inc(Value::Int(1)))).unwrap(),
            (6, n) => m.set(t, &SHAPE, &Value::Enum(1, Some(Box::new(Value::Int(n as i64))))).unwrap(),
            (_, n) => m.set(t, &REC, &item("r", n as i64)).unwrap(),
        }; };
        one(&mut m, rng.below(8), &mut rng);
        if rng.below(4) == 0 {
            one(&mut m, rng.below(8), &mut rng);
        }
        if let Ok(Some(id)) = lp.peers[by].commit(m) {
            let pk = packages(&mut lp, by).into_iter().find(|p| p.id == id).unwrap();
            if rng.below(3) == 0 {
                let _ = lp.deliver(1 - by, &pk);
            }
            packs.push(pk);
        }
        if rng.below(4) == 0 {
            let a = &aspects[rng.below(8) as usize];
            lp.advance(1);
            if let Some(sid) = lp.peers[by].engine.snapshot(&t, a).map_err(|e| format!("snapshot: {e}"))? {
                let pk = packages(&mut lp, by).into_iter().find(|p| p.id == sid).unwrap();
                if rng.below(3) == 0 {
                    let _ = lp.deliver(1 - by, &pk);
                }
                packs.push(pk);
                snaps.push((sid, a.clone()));
            }
        }
    }
    for p in [2, 3] {
        for i in (1..packs.len()).rev() {
            packs.swap(i, rng.below(i as u64 + 1) as usize);
        }
        for pk in &packs {
            let _ = lp.deliver(p, pk);
        }
        lp.peers[p].engine.reexamine().map_err(|e| e.to_string())?;
    }
    let reads = |lp: &mut LocalPeer, p: usize| aspects.iter().map(|a| lp.peers[p].engine.get(&t, a).unwrap()).collect::<Vec<_>>();
    let states = |lp: &mut LocalPeer, p: usize| aspects.iter().map(|a| lp.peers[p].engine.state(&t, a).unwrap().map(|f| format!("{f:?}"))).collect::<Vec<_>>();
    let want = reads(&mut lp, 2);
    for (sid, a) in &snaps {
        let e = &mut lp.peers[3].engine;
        let held: Vec<CommitId> = e.core.ix.by_aspect.get(&(t, a.clone())).into_iter().flatten().map(|x| x.1).collect();
        for c in held {
            if c == *sid || !e.body_not_dropped(&c, &t, a) || !e.body_not_dropped(sid, &t, a) || e.covered(sid, &c, &t, a).unwrap() != Some(true) {
                continue;
            }
            let (h, sh) = (e.header(&c).unwrap(), e.header(sid).unwrap());
            if h.ts > sh.ts {
                return Err(format!("{a:?}: {sid:?} covers {c:?} stamped after it"));
            }
            e.drop_body(&c, &t, a).unwrap();
        }
    }
    if reads(&mut lp, 3) != want {
        return Err(format!("the dropper differs: {want:?} vs {:?}", reads(&mut lp, 3)));
    }
    if states(&mut lp, 3) != states(&mut lp, 2) {
        let (x, y) = (states(&mut lp, 3), states(&mut lp, 2));
        return Err(format!("the dropper's state differs:\n{x:#?}\n{y:#?}"));
    }
    // a commit with no body left goes under no label (none here is a lasting header, §5)
    let (bodies, headers): (Vec<Package>, Vec<Package>) = packages(&mut lp, 3).into_iter().partition(|pk| lp.peers[3].engine.body(&pk.id).unwrap().is_some());
    for pk in &bodies {
        let _ = lp.deliver(4, pk);
    }
    lp.peers[4].engine.reexamine().map_err(|e| e.to_string())?;
    if !lp.peers[4].engine.pending().is_empty() {
        return Err(format!("the fresh node pends: {:?}", lp.peers[4].engine.pending()));
    }
    if reads(&mut lp, 4) != want {
        return Err(format!("the fresh node differs: {want:?} vs {:?}", reads(&mut lp, 4)));
    }
    // bare headers change no read (spec/commits.md §4: a commit with no part held applies as its header)
    for pk in &headers {
        let _ = lp.deliver(4, pk);
    }
    lp.peers[4].engine.reexamine().map_err(|e| e.to_string())?;
    // only a part under purge on replace waits: a body gone as covered has its coverer
    for (c, _) in lp.peers[4].engine.pending() {
        if !lp.peers[3].engine.header(&c).is_some_and(|h| h.aspects.iter().any(|a| a.ak == aspects[2])) {
            return Err(format!("the fresh node pends on a bare header with no part under purge on replace: {c:?}"));
        }
    }
    if reads(&mut lp, 4) != want {
        return Err(format!("the fresh node differs after the bare headers: {want:?} vs {:?}", reads(&mut lp, 4)));
    }
    // the original bodies again
    for pk in &packs {
        let _ = lp.deliver(4, pk);
    }
    lp.peers[4].engine.reexamine().map_err(|e| e.to_string())?;
    if !lp.peers[4].engine.pending().is_empty() {
        return Err(format!("the fresh node pends after the replay: {:?}", lp.peers[4].engine.pending()));
    }
    if reads(&mut lp, 4) != want {
        return Err(format!("the fresh node differs after the replay: {want:?} vs {:?}", reads(&mut lp, 4)));
    }
    // the writer falls where the admin never got its later commits: what they killed comes back
    // alike at the node that dropped it, once the bodies arrive again (a purge-on-replace body went from both)
    let by_w: BTreeSet<CommitId> = packs.iter().filter(|p| lp.peers[0].engine.header(&p.id).is_some_and(|h| h.author == w)).map(|p| p.id).collect();
    use osis_schema::Codec;
    let f = osis_schema::core_types::Frontier { commits: by_w };
    let dm = set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Read)), Some(f.to_value()));
    let at_admin = packages(&mut lp, 0);
    let pk = at_admin.iter().find(|p| p.id == dm).unwrap();
    for p in [2, 3] {
        lp.deliver(p, pk).unwrap();
        lp.peers[p].engine.reexamine().map_err(|e| e.to_string())?;
    }
    // (the thing's first commit too: the `packs` start after it, and it may have gone as covered)
    for p in [2, 3] {
        for pk in packs.iter().chain(&at_admin) {
            let _ = lp.deliver(p, pk);
        }
        lp.peers[p].engine.reexamine().map_err(|e| e.to_string())?;
    }
    let want = reads(&mut lp, 2);
    if reads(&mut lp, 3) != want {
        return Err(format!("after the fall the dropper differs:\n{want:?}\n{:?}", reads(&mut lp, 3)));
    }
    Ok(())
}

fn gap_cover_replay(seed: u64) -> String {
    format!("OSIS_GAPCOVER_START={seed} OSIS_GAPCOVER_SEEDS=1 cargo test -p osis-node --test it -- --ignored sessions::gap_cover_large")
}

// spec/commits.md §5: `gap_cover_check`.
#[test]
fn gap_cover_spec_commits_5() {
    let seeds: Vec<u64> = (0..3).collect();
    osis_base::testenv::run_seeds("sessions::gap_cover_spec_commits_5", &seeds, false, gap_cover_replay, |seed| gap_cover_check(seed).unwrap_or_else(|e| panic!("seed {seed}: {e}")));
}

/// Seeds: OSIS_GAPCOVER_START, OSIS_GAPCOVER_SEEDS (default 0..100).
#[test]
#[ignore = "tier 2"]
fn gap_cover_large_spec_commits_5() {
    osis_base::testenv::Seeds::from_env("OSIS_GAPCOVER_START", "OSIS_GAPCOVER_SEEDS", osis_base::testenv::large(0..100)).run("sessions::gap_cover_large_spec_commits_5", gap_cover_replay, |seed| gap_cover_check(seed).unwrap_or_else(|e| panic!("seed {seed}: {e}")));
}

fn pruned_replay(seed: u64) -> String {
    format!("OSIS_SESSIONS_START={seed} OSIS_SESSIONS_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact sessions::pruned_sessions_converge_large_spec_crdt_8")
}

// spec/crdt.md §8, spec/commits.md §4, §5 (traced tables): `pruned_sessions_check`.
#[test]
fn pruned_sessions_converge_spec_crdt_8() {
    let seeds: Vec<u64> = (0..4).collect();
    osis_base::testenv::run_seeds("sessions::pruned_sessions_converge_spec_crdt_8", &seeds, false, pruned_replay, |seed| pruned_sessions_check(seed).unwrap_or_else(|e| panic!("seed {seed}: {e}")));
}

/// Seeds: OSIS_SESSIONS_START, OSIS_SESSIONS_SEEDS (default 0..200).
#[test]
#[ignore = "tier 2"]
fn pruned_sessions_converge_large_spec_crdt_8() {
    osis_base::testenv::Seeds::from_env("OSIS_SESSIONS_START", "OSIS_SESSIONS_SEEDS", osis_base::testenv::large(0..200)).run("sessions::pruned_sessions_converge_large_spec_crdt_8", pruned_replay, |seed| pruned_sessions_check(seed).unwrap_or_else(|e| panic!("seed {seed}: {e}")));
}

// spec/commits.md §4, §5: Z1 (earlier) and Z2 (after c, no trace of c's session) hold the same. Z2
// counts c's missing part as held, so Z1 stamped before c must not cover it away: both holders of
// Z2 apply c alike.
#[test]
fn snapshot_not_covered_by_an_earlier_equal_spec_commits_4() {
    let mut lp = net(5, 0x5e81);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    for p in [2, 3] {
        let w = lp.peers[p].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    }
    lp.sync_all().unwrap();
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    lp.peers[4].engine.set_syncing(t, true).unwrap();
    let tags = ak("t:tags.0");
    let mut m = Mutation::new();
    m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s("w")) }).unwrap();
    lp.peers[2].commit(m).unwrap().unwrap();
    sync(&mut lp, 2, 3);
    lp.advance(1_000);
    let z1 = lp.peers[2].engine.snapshot(&t, &tags).unwrap().unwrap();
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("a")).unwrap();
    m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s("a")) }).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == c).unwrap();
    let h = lp.peers[0].engine.header(&c).unwrap();
    lp.advance(1_000);
    // a Z2 with the higher ID
    let mut z2 = lp.peers[3].engine.snapshot(&t, &tags).unwrap().unwrap();
    while z2 < z1 {
        lp.advance(1_000);
        z2 = lp.peers[3].engine.snapshot(&t, &tags).unwrap().unwrap();
    }
    sync(&mut lp, 2, 1);
    sync(&mut lp, 2, 4);
    // only the Z2 with the higher ID: the earlier tries stay at peer 3
    let z2p = packages(&mut lp, 3).into_iter().find(|p| p.id == z2).unwrap();
    lp.deliver(1, &z2p).unwrap();
    lp.deliver(4, &z2p).unwrap();
    let e = &mut lp.peers[4].engine;
    assert_eq!(e.covered(&z1, &z2, &t, &tags).unwrap(), Some(false), "a snapshot covers none stamped later");
    assert_eq!(e.covered(&z2, &z1, &t, &tags).unwrap(), Some(true), "Z2 covers Z1");
    let mut read = Vec::new();
    for p in [1, 4] {
        let e = &mut lp.peers[p].engine;
        e.ingest(&only(&pk.bytes, &h, "t:reg.0"), Vec::new()).unwrap();
        e.reexamine().unwrap();
        read.push((e.pending().len(), e.get(&t, &ak("t:reg.0")).unwrap()));
    }
    eprintln!("z1 {z1:?} z2 {z2:?} c {c:?} peer 1 and 4 (pending, reg): {read:?}");
    assert_eq!(read[0], read[1], "both hold the same bodies");
}

// spec/permissions.md §4: a Flip flag about a body whose writes died settles under a later valid
// snapshot though it lists no session of the body.
#[test]
fn flip_flag_on_a_pruned_session_settles_spec_permissions_4() {
    let mut lp = net(4, 0x5e82);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (w, y) = (lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, t, y, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    let asp = ak("t:gone.0");
    // a snapshot stamped before the body settles nothing
    set(&mut lp, 3, t, &GONE, "v0");
    lp.sync_all().unwrap();
    lp.advance(1_000);
    lp.peers[3].engine.snapshot(&t, &asp).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let c1 = set(&mut lp, 0, t, &GONE, "v1");
    lp.sync_all().unwrap();
    lp.advance(1_000);
    set(&mut lp, 2, t, &GONE, "v2");
    lp.sync_all().unwrap();
    // peer 1 lets the dead body go (its keep bounds; no snapshot held, so not as covered)
    lp.peers[1].engine.drop_body(&c1, &t, &asp).unwrap();
    lp.advance(1_000);
    let f = osis_schema::core_types::Frontier { commits: Default::default() };
    let fall = set_edge(&mut lp.peers[0].engine, t, w, None, Some(osis_schema::Codec::to_value(&f)));
    // only the demotion: a full sync would give peer 1 the dropped body again
    let fp = packages(&mut lp, 0).into_iter().find(|p| p.id == fall).unwrap();
    lp.deliver(1, &fp).unwrap();
    lp.deliver(3, &fp).unwrap();
    let flagged = |lp: &mut LocalPeer| lp.peers[1].engine.suspects().unwrap().iter().any(|x| x.0 == t && x.1 == asp);
    assert!(flagged(&mut lp), "W's write fell where a body was dropped: flagged");
    lp.advance(1_000);
    let v3 = set(&mut lp, 3, t, &GONE, "v3");
    lp.advance(1_000);
    let z = lp.peers[3].engine.snapshot(&t, &asp).unwrap().unwrap();
    for pk in packages(&mut lp, 3).into_iter().filter(|p| p.id == v3 || p.id == z) {
        lp.deliver(1, &pk).unwrap();
    }
    let e = &mut lp.peers[1].engine;
    assert!(e.commit_ids().contains(&z));
    eprintln!("reads {:?} digest alike {}", e.get(&t, &asp).unwrap(), lp.peers[1].engine.state_digest(&t, &asp).unwrap() == lp.peers[3].engine.state_digest(&t, &asp).unwrap());
    assert!(!flagged(&mut lp), "a valid later snapshot settles the flag");
    // its author removed, listing none of its commits: it gives nothing, the flag shows again
    let f = osis_schema::core_types::Frontier { commits: Default::default() };
    let gone = set_edge(&mut lp.peers[0].engine, t, y, None, Some(osis_schema::Codec::to_value(&f)));
    let gp = packages(&mut lp, 0).into_iter().find(|p| p.id == gone).unwrap();
    lp.deliver(1, &gp).unwrap();
    assert!(flagged(&mut lp), "the snapshot that settled it turned invalid");
}

// spec/sync.md §7, spec/commits.md §5: snapshots of equal `ts` holding the same cover each other;
// the higher commit ID goes, as covered, and the lower counts for all it did (a commit stamped
// before both, its missing part held under either).
#[test]
fn equal_stamped_snapshots_cover_each_other_spec_sync_7() {
    let mut lp = net(5, 0x5e83);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    for p in [2, 3] {
        let w = lp.peers[p].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    }
    lp.sync_all().unwrap();
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    lp.peers[4].engine.set_syncing(t, true).unwrap();
    let tags = ak("t:tags.0");
    let mut m = Mutation::new();
    m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s("w")) }).unwrap();
    lp.peers[2].commit(m).unwrap().unwrap();
    sync(&mut lp, 2, 3);
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("a")).unwrap();
    m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s("a")) }).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == c).unwrap();
    let h = lp.peers[0].engine.header(&c).unwrap();
    lp.advance(1_000);
    let a = lp.peers[2].engine.snapshot(&t, &tags).unwrap().unwrap();
    let b = lp.peers[3].engine.snapshot(&t, &tags).unwrap().unwrap();
    assert_eq!(lp.peers[2].engine.header(&a).unwrap().ts.to_u64(), lp.peers[3].engine.header(&b).unwrap().ts.to_u64(), "one wall, no later clock seen");
    for from in [2, 3] {
        sync(&mut lp, from, 1);
        sync(&mut lp, from, 4);
    }
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let e = &mut lp.peers[4].engine;
    assert_eq!(e.covered(&lo, &hi, &t, &tags).unwrap(), Some(true));
    assert_eq!(e.covered(&hi, &lo, &t, &tags).unwrap(), Some(true));
    e.drop_body(&hi, &t, &tags).unwrap();
    assert!(e.core.ix.commits.get(&hi).unwrap().dropped.values().all(|d| d.why == osis_node::engine::DropFor::Cover && !d.stands_in));
    let mut read = Vec::new();
    for p in [1, 4] {
        let e = &mut lp.peers[p].engine;
        e.ingest(&only(&pk.bytes, &h, "t:reg.0"), Vec::new()).unwrap();
        e.reexamine().unwrap();
        read.push((e.pending().len(), e.get(&t, &ak("t:reg.0")).unwrap()));
    }
    assert_eq!(read[0], (0, Some(s("a"))));
    assert_eq!(read[0], read[1]);
}

// spec/commits.md §4, §5: a snapshot stamped after c by a writer since removed still stands in, and
// the valid older snapshot, however alike, does not cover it away: one holder given c's part late
// and one given it first read alike. A later snapshot holding less than an earlier one (a lagging
// writer's) stays the same way.
#[test]
fn invalid_or_lagging_later_snapshot_stays_and_stands_in_spec_commits_5() {
    let mut lp = net(4, 0x5e84);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (w, y) = (lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, t, y, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    let tags = ak("t:tags.0");
    let add = |lp: &mut LocalPeer, i: usize, v: &str| {
        let mut m = Mutation::new();
        m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s(v)) }).unwrap();
        lp.peers[i].commit(m).unwrap().unwrap()
    };
    add(&mut lp, 2, "w");
    sync(&mut lp, 2, 3);
    // W's earlier snapshot holds more than Y's later one: W's "x" never reached Y
    add(&mut lp, 2, "x");
    lp.advance(1_000);
    let z1 = lp.peers[2].engine.snapshot(&t, &tags).unwrap().unwrap();
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("a")).unwrap();
    m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s("a")) }).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == c).unwrap();
    let h = lp.peers[0].engine.header(&c).unwrap();
    lp.advance(1_000);
    let z2 = lp.peers[3].engine.snapshot(&t, &tags).unwrap().unwrap();
    sync(&mut lp, 2, 1);
    sync(&mut lp, 3, 1);
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.covered(&z1, &z2, &t, &tags).unwrap(), Some(false), "a lagging later snapshot is not covered");
    // Y removed, its snapshot listed by nothing: invalid, and still not covered
    let f = osis_schema::core_types::Frontier { commits: Default::default() };
    let gone = set_edge(&mut lp.peers[0].engine, t, y, None, Some(osis_schema::Codec::to_value(&f)));
    let gp = packages(&mut lp, 0).into_iter().find(|p| p.id == gone).unwrap();
    lp.deliver(1, &gp).unwrap();
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.covered(&z2, &z1, &t, &tags).unwrap(), Some(false), "an invalid snapshot covers nothing");
    assert_eq!(e.covered(&z1, &z2, &t, &tags).unwrap(), Some(false), "nor is it covered by an older one");
    e.ingest(&only(&pk.bytes, &h, "t:reg.0"), Vec::new()).unwrap();
    e.reexamine().unwrap();
    assert_eq!(e.pending().len(), 0, "Y could write: its snapshot counts the tags part held");
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("a")));
}

/// A Flip flag about `body` of `(t, asp)` at peer 1, dropped for its bounds: W's write falls.
fn flip_flag_on(lp: &mut LocalPeer, t: Tid, asp: &Ak, body: &CommitId) {
    let w = lp.peers[2].engine.tid();
    lp.peers[1].engine.drop_body(body, &t, asp).unwrap();
    lp.advance(1_000);
    let f = osis_schema::core_types::Frontier { commits: Default::default() };
    let fall = set_edge(&mut lp.peers[0].engine, t, w, None, Some(osis_schema::Codec::to_value(&f)));
    for p in packages(lp, 0).into_iter().filter(|p| p.id == fall) {
        lp.deliver(1, &p).unwrap();
    }
    assert!(lp.peers[1].engine.suspects().unwrap().iter().any(|x| x.0 == t && x.1 == *asp), "flagged");
}

/// Y's later write and snapshot of `(t, asp)` reach peer 1.
fn later_snapshot_settles(lp: &mut LocalPeer, t: Tid, asp: &Ak) {
    lp.advance(1_000);
    let v = set(lp, 3, t, &GONE, "later");
    lp.advance(1_000);
    let z = lp.peers[3].engine.snapshot(&t, asp).unwrap().unwrap();
    for p in packages(lp, 3).into_iter().filter(|p| p.id == v || p.id == z) {
        lp.deliver(1, &p).unwrap();
    }
    assert!(!lp.peers[1].engine.suspects().unwrap().iter().any(|x| x.0 == t && x.1 == *asp), "settled");
}

// spec/permissions.md §4: a flag about a dropped snapshot body settles like any other. Its dormancy
// read `Absorbed`, which never lists a snapshot, so it never did, and it filled the heartbeat.
#[test]
fn flip_flag_on_a_snapshot_body_settles_spec_permissions_4() {
    let mut lp = net(4, 0x5e85);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    for p in [2, 3] {
        let w = lp.peers[p].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    }
    lp.sync_all().unwrap();
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    let asp = ak("t:gone.0");
    set(&mut lp, 0, t, &GONE, "v1");
    lp.advance(1_000);
    let z = lp.peers[0].engine.snapshot(&t, &asp).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(1_000);
    set(&mut lp, 2, t, &GONE, "v2");
    lp.sync_all().unwrap();
    flip_flag_on(&mut lp, t, &asp, &z);
    later_snapshot_settles(&mut lp, t, &asp);
}
