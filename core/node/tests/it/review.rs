#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Regression tests from the node-core review.

use crate::common;
use common::*;
use osis_commit::{CommitBlob, PurgeItem};
use osis_base::{Role, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::local_peer::Package;
use osis_node::{Ingested, Mutation, Reason};
use osis_perm::DemotionScope;
use osis_schema::Codec;

fn set(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: osis_base::Tid, k: &osis_schema::Aspect<Value>, v: &str) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.set(t, k, &s(v)).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

fn strip_parts(pk: &Package, keep: impl Fn(&str) -> bool, h: &osis_commit::Header) -> Vec<u8> {
    let mut b = CommitBlob::decode(&pk.bytes).unwrap();
    b.parts.retain(|p| keep(h.aspects[p.ai].ak.as_str()));
    b.encode()
}

// spec/crdt.md §4.6, spec/permissions.md §5.2: another writer's nested write into a map entry an
// invalid delta created goes with it, whether it arrived before or after the revoke.
#[test]
fn nested_write_under_invalid_entry_spec_crdt_4_6() {
    let mut lp = net(3, 71);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, t, c, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    // b creates key "ash" (never seen by node 0 before the revoke); c writes into it
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("ash"))], op: Op::Set(item("b", 1)) }).unwrap();
    let bid = lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 2);
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("ash")), PathSeg::Field(1)], op: Op::Set(Value::Int(8)) }).unwrap();
    lp.peers[2].commit(m).unwrap().unwrap();
    let scope = DemotionScope { membership: [(b, [t].into())].into(), content: [(b, [t].into())].into() };
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&scope, now).unwrap();
    set_edge(&mut lp.peers[0].engine, t, b, None, Some(f.to_value()));
    // node 0: c's write first, then the revoke is held, then b's commit
    sync(&mut lp, 2, 0);
    let bpk = lp.peers[1].engine.package(&bid).unwrap().unwrap();
    lp.deliver(0, &bpk).unwrap();
    // node 2: had b's and c's writes joined, then receives the revoke
    sync(&mut lp, 0, 2);
    sync(&mut lp, 0, 1);
    sync(&mut lp, 1, 0);
    let want = lp.peers[0].engine.get(&t, &ak("/t/map")).unwrap();
    for i in 1..3 {
        assert_eq!(lp.peers[i].engine.get(&t, &ak("/t/map")).unwrap(), want, "node {i}");
        assert_eq!(lp.peers[i].engine.state(&t, &ak("/t/map")).unwrap(), lp.peers[0].engine.state(&t, &ak("/t/map")).unwrap());
    }
}

// spec/commits.md §4: a missing delta whose expiry has passed counts as held.
#[test]
fn expired_missing_delta_counts_as_held_spec_commits_4() {
    let mut lp = net(2, 72);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    let mut m = Mutation::new();
    m.set(t, &BRIEF, &s("gone soon")).unwrap();
    m.set(t, &REG, &s("stays")).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
    let partial = strip_parts(&pk, |a| a != "/t/brief", &h);
    assert!(matches!(lp.peers[1].engine.ingest(&partial, Vec::new()).unwrap(), Ingested::Pending(_, Reason::WaitDeltas)));
    lp.advance(3_600_001);
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/reg")).unwrap(), Some(s("stays")));
}

// spec/commits.md §4: a part that does not hash to its header entry is dropped alone; the
// commit waits for (or applies without) that delta and takes the good copy later.
#[test]
fn bad_part_dropped_alone_spec_commits_4() {
    let mut lp = net(2, 73);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("r")).unwrap();
    m.set(t, &KEPT, &s("k")).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
    let mut b = CommitBlob::decode(&pk.bytes).unwrap();
    let last = b.parts.len() - 1;
    let n = b.parts[last].delta.len();
    b.parts[last].delta[n - 1] ^= 1;
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    let r = lp.peers[1].engine.ingest(&b.encode(), Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::WaitDeltas)), "{r:?}");
    assert_eq!(lp.deliver(1, &pk).unwrap(), Ingested::Applied(id));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/kept")).unwrap(), Some(s("k")));
}

// spec/commits.md §5: a purge drops every body carrying the purged values, snapshots included.
#[test]
fn purge_drops_snapshots_spec_commits_5() {
    let mut lp = net(1, 74);
    let t = new_thing(&mut lp, 0);
    let secret = set(&mut lp, 0, t, &REG, "secret");
    let snap = lp.peers[0].engine.snapshot(&t, &ak("/t/reg")).unwrap().unwrap();
    assert!(lp.peers[0].engine.holds_body(&snap, &t, &ak("/t/reg")));
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("/t/reg") });
    lp.peers[0].commit(m).unwrap();
    assert!(!lp.peers[0].engine.holds_body(&secret, &t, &ak("/t/reg")));
    assert!(!lp.peers[0].engine.holds_body(&snap, &t, &ak("/t/reg")));
    // a purge never carries expires (spec/commits.md §5)
    let mut m = Mutation::new();
    m.set(t, &BRIEF, &s("x")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("/t/reg") });
    assert!(lp.peers[0].commit(m).is_err());
}

// spec/commits.md §5: a body is one projection class: its deltas share deaths and are dropped
// together; while one of them has a live write the class is kept (`AT_MOST_GRACE`); keep at
// most 0 drops at apply the kill that leaves it none, even when the killing `ts` is ahead of
// the clock.
#[test]
fn body_is_a_class_spec_commits_5() {
    let mut lp = net(2, 75);
    let t = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("a")).unwrap();
    m.set(t, &GONE2, &s("a2")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    // node 0's clock is ahead; its kills reach node 1
    lp.peers[0].clock.advance(600_000);
    set(&mut lp, 0, t, &GONE, "b");
    sync(&mut lp, 0, 1);
    let e = &mut lp.peers[1].engine;
    assert!(e.holds_body(&c, &t, &ak("/t/gone")) && e.holds_body(&c, &t, &ak("/t/gone2")), "/t/gone2 is still live");
    set(&mut lp, 0, t, &GONE2, "b2");
    sync(&mut lp, 0, 1);
    let e = &mut lp.peers[1].engine;
    assert!(!e.holds_body(&c, &t, &ak("/t/gone")));
    assert!(!e.holds_body(&c, &t, &ak("/t/gone2")));
    assert_eq!(e.get(&t, &ak("/t/gone2")).unwrap(), Some(s("b2")));
    // deaths aggregate over the class: killing one delta's write dates the other's body
    let mut m = Mutation::new();
    m.set(t, &SHORT, &s("r")).unwrap();
    m.set(t, &SHORT2, &s("y")).unwrap();
    let c2 = lp.peers[0].commit(m).unwrap().unwrap();
    set(&mut lp, 0, t, &SHORT, "r2");
    let e = &mut lp.peers[0].engine;
    assert!(e.deaths(&c2, &t, &ak("/t/short2")).unwrap().is_some());
    assert_eq!(e.deaths(&c2, &t, &ak("/t/short2")).unwrap(), e.deaths(&c2, &t, &ak("/t/short")).unwrap());
}

// spec/crdt.md §8: snapshot frontiers cover only writes the state reflects (valid ones).
#[test]
fn snapshot_frontier_valid_only_spec_crdt_8() {
    let mut lp = net(2, 76);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    let scope = DemotionScope { membership: [(b, [t].into())].into(), content: [(b, [t].into())].into() };
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&scope, now).unwrap();
    lp.advance(10);
    set(&mut lp, 1, t, &REG, "b's");
    lp.advance(10);
    set_edge(&mut lp.peers[0].engine, t, b, None, Some(f.to_value()));
    sync(&mut lp, 1, 0);
    let r = lp.peers[0].engine.receipt(&t, &ak("/t/reg")).unwrap();
    assert_eq!(r.contiguous(&b, u64::MAX), 1, "received, though invalid");
    let snap = lp.peers[0].engine.snapshot(&t, &ak("/t/reg")).unwrap().unwrap();
    let mut lp2 = net(1, 77);
    lp2.advance(100);
    for p in lp.packages(0).unwrap() {
        let h = lp.peers[0].engine.header(&p.id).unwrap();
        let skip = h.author == b && h.aspects.iter().any(|a| a.ak.as_str() == "/t/reg");
        if !skip {
            let _ = lp2.deliver(0, &p);
        }
    }
    assert!(lp2.peers[0].engine.commit_ids().contains(&snap));
    assert_eq!(lp2.peers[0].engine.receipt(&t, &ak("/t/reg")).unwrap().contiguous(&b, u64::MAX), 0);
    // snapshot retention takes the schema's default bounds (keep at least 1d)
    set(&mut lp, 0, t, &KEPT, "k");
    let ks = lp.peers[0].engine.snapshot(&t, &ak("/t/kept")).unwrap().unwrap();
    let sh = lp.peers[0].engine.header(&ks).unwrap();
    assert_eq!(sh.aspects[0].retention.at_least.rel, Some(86_400_000));
}

// spec/permissions.md §7: a move is one local transaction: refused as a whole.
#[test]
fn move_is_atomic_spec_perm_7() {
    let mut lp = net(2, 78);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    let before = lp.peers[1].engine.commit_ids().len();
    // node 1 may not create things owned by node 0
    let a = lp.peers[0].engine.tid();
    assert!(lp.peers[1].engine.move_thing(&t, a).is_err());
    assert_eq!(lp.peers[1].engine.commit_ids().len(), before);
    // a failed transaction rolls the caches back: the next commit takes the same counters
    let me = lp.peers[1].engine.tid();
    let mut m = Mutation::new();
    let x = lp.peers[1].engine.new_thing(&mut m, me);
    m.set(x, &REG, &s("ok")).unwrap();
    lp.peers[1].commit(m).unwrap();
    assert_eq!(lp.peers[1].engine.get(&x, &ak("/t/reg")).unwrap(), Some(s("ok")));
}

// spec/permissions.md §7: resolution follows `/moved` up to RESOLUTION_HOPS.
#[test]
fn resolution_hops_spec_perm_7() {
    let mut lp = net(1, 79);
    let t1 = new_thing(&mut lp, 0);
    let t2 = new_thing(&mut lp, 0);
    let t3 = new_thing(&mut lp, 0);
    for (a, b) in [(t1, t2), (t2, t3)] {
        let mut m = Mutation::new();
        m.set(a, &osis_schema::core_types::MOVED, &b).unwrap();
        lp.peers[0].commit(m).unwrap();
    }
    let me = lp.peers[0].engine.tid();
    assert_eq!(lp.peers[0].engine.resolve(&me, &t1), t3);
    let _ = WallMs(0);
}


// spec/crdt.md §3.3 rule 7, spec/permissions.md §7 (a snapshot origin's bare anchors are
// imported): a text reset while another writer inserted at an element the reset pruned, then
// compacted (its ordinary bodies dropped), moves complete: the copy reads like the original, at
// the mover and at a node receiving the import.
#[test]
fn move_reset_compacted_text_complete_spec_perm_7() {
    let mut lp = net(2, 79);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (a, b) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    let mut m = Mutation::new();
    m.set(t, &TEXT, &s("abc")).unwrap();
    let c1 = lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.replace(t, &TEXT, &s("xyz")).unwrap();
    let c2 = lp.peers[0].commit(m).unwrap().unwrap();
    // later, b inserts after `b` without having seen the reset: `b` is a bare anchor after it
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.op(t, &TEXT, PathOp { path: Vec::new(), op: Op::Insert { at: 2, items: vec![s("q")] } }).unwrap();
    let c3 = lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    let k = ak("/t/text");
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.get(&t, &k).unwrap(), Some(s("xyzq")));
    let snap = e.snapshot(&t, &k).unwrap().unwrap();
    for c in [c1, c2, c3] {
        assert_eq!(e.covered(&snap, &c, &t, &k).unwrap(), Some(true));
        e.drop_body(&c, &t, &k).unwrap();
    }
    let (copy, imports) = e.move_thing(&t, a).unwrap();
    assert!(imports.iter().any(|i| e.header(i).is_some_and(|h| h.origins.iter().any(|o| o.commit == snap))), "the snapshot is an origin");
    assert_eq!(e.get(&copy, &k).unwrap(), Some(s("xyzq")), "the copy is complete");
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.get(&copy, &k).unwrap(), Some(s("xyzq")), "receivers accept the import");
}

// spec/permissions.md §7 (an import carries the bare anchors its imported writes reference): a
// text reset and compacted, then an insert at an element the reset pruned arrives (beyond the
// snapshot, imported from its own commit): the snapshot's import keeps that anchor, so the copy
// places the insert.
#[test]
fn move_keeps_anchor_of_later_insert_spec_perm_7() {
    let mut lp = net(2, 80);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (a, b) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    let mut m = Mutation::new();
    m.set(t, &TEXT, &s("abc")).unwrap();
    let c1 = lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.replace(t, &TEXT, &s("xyz")).unwrap();
    let c2 = lp.peers[0].commit(m).unwrap().unwrap();
    let k = ak("/t/text");
    let e = &mut lp.peers[0].engine;
    let snap = e.snapshot(&t, &k).unwrap().unwrap();
    for c in [c1, c2] {
        e.drop_body(&c, &t, &k).unwrap();
    }
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.op(t, &TEXT, PathOp { path: Vec::new(), op: Op::Insert { at: 2, items: vec![s("q")] } }).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.get(&t, &k).unwrap(), Some(s("xyzq")));
    let (copy, imports) = e.move_thing(&t, a).unwrap();
    assert!(imports.iter().any(|i| e.header(i).is_some_and(|h| h.origins.iter().any(|o| o.commit == snap))));
    assert_eq!(e.get(&copy, &k).unwrap(), Some(s("xyzq")), "the copy places the insert");
}

// spec/permissions.md §7, spec/crdt.md §3.3 rule 7 (`MAX_DELTA_BARE`): a 100k-character text
// replaced three times (300k bare anchors nothing anchors at) and compacted moves: the import
// carries only the referenced bare anchors, so it stays within the bound.
#[test]
#[ignore = "tier 2"]
fn move_many_bare_anchors_spec_perm_7() {
    let mut lp = net(1, 81);
    let t = new_thing(&mut lp, 0);
    let a = lp.peers[0].engine.tid();
    let k = ak("/t/text");
    let mut ids = Vec::new();
    for ch in ["a", "b", "c", "d"] {
        let mut m = Mutation::new();
        m.replace(t, &TEXT, &s(&ch.repeat(100_000))).unwrap();
        ids.push(lp.peers[0].commit(m).unwrap().unwrap());
        lp.advance(1_000);
    }
    let e = &mut lp.peers[0].engine;
    e.snapshot(&t, &k).unwrap().unwrap();
    for c in ids {
        e.drop_body(&c, &t, &k).unwrap();
    }
    let (copy, _) = e.move_thing(&t, a).unwrap();
    assert_eq!(e.get(&copy, &k).unwrap(), Some(s(&"d".repeat(100_000))));
}

/// Text `t` on peer 0: "headtail", then `n` characters typed between, then deleted (two
/// commits: a delete is at most `MAX_DELTA_BARE` elements), all but the last `kept` of them;
/// then "SECRETmid" typed after "head" and "SECRET" deleted (shown "mid" anchors at it);
/// compacted (the snapshot carries the deleted elements content-less, its bodies dropped) when
/// `compact`.
fn deleted_text(lp: &mut osis_node::local_peer::LocalPeer, t: osis_base::Tid, n: usize, kept: usize, compact: bool) {
    let mut m = Mutation::new();
    m.set(t, &TEXT, &s("headtail")).unwrap();
    let mut ids = vec![lp.peers[0].commit(m).unwrap().unwrap()];
    let mut m = Mutation::new();
    m.op(t, &TEXT, PathOp { path: Vec::new(), op: Op::Insert { at: 4, items: vec![s(&"x".repeat(n))] } }).unwrap();
    ids.push(lp.peers[0].commit(m).unwrap().unwrap());
    let gone = n - kept;
    for len in [gone / 2, gone - gone / 2] {
        let mut m = Mutation::new();
        m.op(t, &TEXT, PathOp { path: Vec::new(), op: Op::Delete { at: 4, len } }).unwrap();
        ids.push(lp.peers[0].commit(m).unwrap().unwrap());
    }
    for op in [Op::Insert { at: 4, items: vec![s("SECRETmid")] }, Op::Delete { at: 4, len: 6 }] {
        let mut m = Mutation::new();
        m.op(t, &TEXT, PathOp { path: Vec::new(), op }).unwrap();
        ids.push(lp.peers[0].commit(m).unwrap().unwrap());
    }
    if compact {
        let k = ak("/t/text");
        let e = &mut lp.peers[0].engine;
        e.snapshot(&t, &k).unwrap().unwrap();
        for c in ids {
            e.drop_body(&c, &t, &k).unwrap();
        }
    }
}

// spec/permissions.md §7 (an import carries only the sequence elements the importer's state
// shows and those they anchor at, the latter without content), spec/crdt.md §3.3 rule 7
// (`MAX_DELTA_BARE`): a text with 300k characters deleted and a word erased inside shown text
// moves, from its commits or compacted: the copy reads like the original, the imports are
// small and hold no erased text, and a receiver accepts them.
#[test]
#[ignore = "tier 2"]
fn move_deleted_text_small_import_spec_perm_7() {
    for compact in [false, true] {
        let mut lp = net(2, 82);
        lp.sync_all().unwrap();
        let t = new_thing(&mut lp, 0);
        let a = lp.peers[0].engine.tid();
        deleted_text(&mut lp, t, 300_000, 0, compact);
        let k = ak("/t/text");
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.get(&t, &k).unwrap(), Some(s("headmidtail")));
        let (copy, imports) = e.move_thing(&t, a).unwrap();
        assert_eq!(e.get(&copy, &k).unwrap(), Some(s("headmidtail")), "compact {compact}: the copy is complete");
        let mut size = 0;
        for i in &imports {
            let pk = e.package(i).unwrap().unwrap();
            size += pk.bytes.len() + pk.blobs.iter().map(|(_, b)| b.len()).sum::<usize>();
            for b in std::iter::once(&pk.bytes).chain(pk.blobs.iter().map(|(_, b)| b)) {
                assert!(!b.windows(6).any(|w| w == b"SECRET"), "compact {compact}: erased text in an import");
            }
        }
        assert!(size < 16 * 1024, "compact {compact}: imports of {size} bytes");
        sync(&mut lp, 0, 1);
        assert_eq!(lp.peers[1].engine.get(&copy, &k).unwrap(), Some(s("headmidtail")), "compact {compact}: receivers accept the import");
    }
}

// spec/permissions.md §7, spec/crdt.md §3.3 rule 7 (`MAX_DELTA_BARE`): a compacted text whose
// shown last character is typed after 400k deleted ones (its placement anchors at all of them)
// still needs an import over the bound: the move fails cleanly, creating nothing.
#[test]
#[ignore = "tier 2"]
fn move_over_max_delta_bare_fails_spec_perm_7() {
    let mut lp = net(1, 83);
    let t = new_thing(&mut lp, 0);
    let a = lp.peers[0].engine.tid();
    deleted_text(&mut lp, t, 400_000, 1, true);
    let k = ak("/t/text");
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.get(&t, &k).unwrap(), Some(s("headmidxtail")));
    let before = e.commit_ids().len();
    let err = e.move_thing(&t, a).unwrap_err();
    assert!(err.to_string().contains("MAX_DELTA_BARE"), "{err}");
    assert_eq!(e.commit_ids().len(), before, "nothing written");
}

// spec/commits.md §5 (a body's live writes span every aspect of its class): a body on two
// aspects asked by one of them, then changed through the other, is judged afresh whichever
// aspect is asked (liveness is not cached per asked aspect alone: a stale answer gave a timed
// delete with no carrier, or a carrier for nothing).
#[test]
fn body_live_spans_its_class_spec_commits_5() {
    let mut lp = net(1, 84);
    let t = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    m.set(t, &SHORT, &s("a")).unwrap();
    m.set(t, &SHORT2, &s("a2")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(10);
    set(&mut lp, 0, t, &SHORT, "b");
    let (a1, a2) = (ak("/t/short"), ak("/t/short2"));
    let e = &mut lp.peers[0].engine;
    assert!(e.body_live(&c, &t, &a1).unwrap(), "its /t/short2 write is live");
    lp.advance(10);
    set(&mut lp, 0, t, &SHORT2, "b2");
    let e = &mut lp.peers[0].engine;
    assert!(e.holds_body(&c, &t, &a1), "dead, kept to first death plus 10 min");
    assert!(!e.body_live(&c, &t, &a2).unwrap());
    assert!(!e.body_live(&c, &t, &a1).unwrap(), "asked by the other aspect of the body");
}
