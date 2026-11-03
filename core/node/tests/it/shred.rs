#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Forensic deletion at node level: after a purge, an expiry or a keep-at-most drop, an attacker
//! holding the device (every key the current root yields) and every row ever written (freed
//! pages, old versions) recovers nothing of the dropped body (spec/commits.md §5: dropping a
//! body destroys every local copy so that later compromise of the node recovers nothing;
//! spec/requirements.md, Deletion: forward secure).

use crate::common;
use common::*;
use osis_commit::PurgeItem;
use osis_base::{Clock, ManualClock, Tid, Value};
use osis_crypto::SeededRng;
use osis_node::local_peer::{LocalPeer, Peer};
use osis_node::{Config, Engine, Mutation};
use osis_store::{MemoryBackend, MemoryRoot, StoreConfig};
use std::sync::Arc;

/// A peer over a small key tree (arity 4: few units share a leaf, so a shred elsewhere does
/// not incidentally rotate a leaked copy away) and small pages, recording every row written.
fn peer(seed: u64) -> Peer {
    let clock = Arc::new(ManualClock::new(T0));
    let (backend, root) = (MemoryBackend::new(), MemoryRoot::new());
    backend.record_history();
    let cfg = Config { store: StoreConfig { arity: 4, depth: 8, page_max: 512, ..StoreConfig::default() }, ..Config::default() };
    let c: Arc<dyn Clock> = clock.clone();
    let mut engine = Engine::create(Box::new(backend.clone()), Box::new(root.clone()), cfg, c, Box::new(SeededRng::from_u64(seed))).unwrap();
    let events = engine.subscribe();
    Peer { engine, clock, backend, root, events, restarts: 0 }
}

/// `p` restarted over its durable state, as `peer` opens it.
fn reopened(p: Peer, seed: u64) -> Peer {
    let Peer { clock, backend, root, .. } = p;
    let cfg = Config { store: StoreConfig { arity: 4, depth: 8, page_max: 512, ..StoreConfig::default() }, ..Config::default() };
    let c: Arc<dyn Clock> = clock.clone();
    let mut engine = Engine::open(Box::new(backend.clone()), Box::new(root.clone()), cfg, c, Box::new(SeededRng::from_u64(seed))).unwrap();
    let events = engine.subscribe();
    Peer { engine, clock, backend, root, events, restarts: 0 }
}

fn net2(seed: u64) -> LocalPeer {
    LocalPeer::of(vec![peer(seed), peer(seed + 1)], seed)
}

fn big(marker: &str) -> String {
    format!("{marker}{}", "x".repeat(400))
}

fn set(lp: &mut LocalPeer, i: usize, t: Tid, k: &osis_schema::Aspect<Value>, v: &str) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.set(t, k, &s(v)).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

/// Unrelated writes so the store grows past one leaf of the key tree.
fn filler(lp: &mut LocalPeer, i: usize, n: usize) {
    for k in 0..n {
        let t = new_thing(lp, i);
        set(lp, i, t, &REG, &format!("filler {k}"));
    }
}

// spec/commits.md §5: a purge drops every local copy (the commit record, state, undo buffer)
// so that later compromise recovers nothing
#[test]
fn purged_body_unrecoverable_spec_commits_5() {
    let mut lp = net2(71);
    let t = new_thing(&mut lp, 0);
    let marker = "PURGED-MARK-41c9";
    let secret = set(&mut lp, 0, t, &REG, &big(marker));
    filler(&mut lp, 0, 6);
    assert!(recoverable(&mut lp.peers[0], marker.as_bytes()), "the attack finds live content");
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("t:reg.0") });
    lp.peers[0].commit(m).unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&secret, &t, &ak("t:reg.0")));
    assert!(!recoverable(&mut lp.peers[0], marker.as_bytes()), "purged content recovered");
}

// spec/commits.md §5: a commit held pending before it applied leaves no copy once its body is
// purged
#[test]
fn purged_after_pending_unrecoverable_spec_commits_5() {
    let mut lp = net2(72);
    let t = new_thing(&mut lp, 0);
    let marker = "PENDING-MARK-8d2e";
    let secret = set(&mut lp, 0, t, &REG, &big(marker));
    // node 1 gets the marker commit before the thing's creation: held pending
    let pks = lp.packages(0).unwrap();
    let pk = pks.iter().find(|p| p.id == secret).unwrap().clone();
    assert!(matches!(lp.deliver(1, &pk).unwrap(), osis_node::Ingested::Pending(..)));
    filler(&mut lp, 1, 6);
    lp.sync(0, 1).unwrap();
    assert!(lp.peers[1].engine.body_not_dropped(&secret, &t, &ak("t:reg.0")));
    filler(&mut lp, 1, 6);
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("t:reg.0") });
    lp.peers[0].commit(m).unwrap();
    lp.sync(0, 1).unwrap();
    assert!(!lp.peers[1].engine.body_not_dropped(&secret, &t, &ak("t:reg.0")));
    assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "purged content recovered from the pending copy");
}

/// Node 0 writes `marker` on `t` and a value on `t2` in commit `c` (`whole`: its package), then purges
/// `c`'s part on `t` (`request`). Node 1 knows `t`, syncs both, and lacks `t2`'s record: `c` waits whole.
fn pending_purge(seed: u64, marker: &str) -> (LocalPeer, Tid, osis_base::CommitId, osis_node::local_peer::Package, osis_node::local_peer::Package) {
    let mut lp = net2(seed);
    let t = new_thing(&mut lp, 0);
    lp.sync(0, 1).unwrap();
    let t2 = new_thing(&mut lp, 0);
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    lp.peers[1].engine.set_syncing(t2, true).unwrap();
    let mut m = Mutation::new();
    m.set(t, &REG, &s(&big(marker))).unwrap();
    m.set(t2, &REG, &s("other")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    // taken before the purge drops it at its author
    let whole = lp.peers[0].engine.package(&c).unwrap().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    let request = lp.peers[0].engine.package(&p).unwrap().unwrap();
    (lp, t, c, whole, request)
}

// spec/commits.md §5: a part of a commit held pending that a held purge request names is held value-less:
// its values go from the pending copy, whether the request comes first or after
#[test]
fn purged_while_pending_unrecoverable_spec_commits_5() {
    for request_first in [true, false] {
        let marker = "PENDING-PURGE-3f1a";
        let (mut lp, t, c, whole, request) = pending_purge(75 + 10 * u64::from(request_first), marker);
        let order = if request_first { [&request, &whole] } else { [&whole, &request] };
        for pk in order {
            lp.deliver(1, pk).unwrap();
            lp.peers[1].engine.reexamine().unwrap();
        }
        assert!(lp.peers[1].engine.pending().iter().any(|x| x.0 == c), "request first {request_first}: it waits for t2");
        assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("public")));
        assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "request first {request_first}: purged content recovered from the pending copy");
        assert!(lp.peers[1].engine.suspects().unwrap().is_empty(), "request first {request_first}: held value-less, not dropped");
    }
}

// spec/commits.md §4 (copies), §5: a copy of a pending commit holding a purged part is spent (node-sync
// forgets its blob) once the pending copy holds its other parts alike; while a junk copy holds another
// part's slot (its thing's record away, the hash uncheckable) it may hold the only true copy: not spent.
#[test]
fn copy_with_a_purged_part_spent_unless_it_may_be_needed_spec_commits_5() {
    for junk in [false, true] {
        let (mut lp, t, c, whole, request) = pending_purge(95 + u64::from(junk), "SPENT-MARK-0c4d");
        let copy = osis_commit::CommitBlob::decode(&whole.bytes).unwrap();
        if junk {
            let mut j = copy.clone();
            j.parts.retain(|p| j.header.aspects[p.ai].tid != t);
            for p in &mut j.parts {
                p.delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![6; 40])]));
            }
            lp.peers[1].engine.ingest(&j.encode(), Vec::new()).unwrap();
        }
        lp.deliver(1, &whole).unwrap();
        assert!(!lp.peers[1].engine.spent_copy(&c, &copy).unwrap(), "junk {junk}: nothing went yet");
        lp.deliver(1, &request).unwrap();
        lp.peers[1].engine.reexamine().unwrap();
        assert!(lp.peers[1].engine.pending().iter().any(|x| x.0 == c), "junk {junk}");
        assert_eq!(lp.peers[1].engine.spent_copy(&c, &copy).unwrap(), !junk, "junk {junk}");
    }
}

// spec/commits.md §6: at T the body is dropped; spec/commits.md §5: no local copy survives
#[test]
fn expired_body_unrecoverable_spec_commits_6() {
    let mut lp = net2(73);
    let t = new_thing(&mut lp, 0);
    let marker = "EXPIRED-MARK-77aa";
    let c = set(&mut lp, 0, t, &BRIEF, &big(marker));
    filler(&mut lp, 0, 6);
    lp.advance(3_600_001);
    lp.peers[0].engine.tick().unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&c, &t, &ak("t:brief.0")));
    assert!(!recoverable(&mut lp.peers[0], marker.as_bytes()), "expired content recovered");
}

// spec/commits.md §5 (keep at most 0): the replacing node drops the body in the killing
// transaction; no local copy survives
#[test]
fn kept_at_most_zero_unrecoverable_spec_commits_5() {
    let mut lp = net2(74);
    let t = new_thing(&mut lp, 0);
    let marker = "ATMOST-MARK-5b01";
    let c = set(&mut lp, 0, t, &GONE, &big(marker));
    filler(&mut lp, 0, 6);
    lp.advance(5);
    set(&mut lp, 0, t, &GONE, "final");
    assert!(!lp.peers[0].engine.body_not_dropped(&c, &t, &ak("t:gone.0")));
    assert!(!recoverable(&mut lp.peers[0], marker.as_bytes()), "dropped content recovered");
}

// spec/commits.md §5 (keep at most 0), spec/requirements.md (Scale: O(change)): in a paged map
// state, the dropped body's pages are rewritten shredded (not the whole state); no copy of the
// superseded entry value survives
#[test]
fn kept_at_most_zero_paged_unrecoverable_spec_commits_5() {
    let mut lp = net2(75);
    let t = new_thing(&mut lp, 0);
    let fill: std::collections::BTreeMap<Value, Value> = (0..66).map(|i| (s(&format!("k{i:03}")), s(&"f".repeat(1100)))).collect();
    let mut m = Mutation::new();
    m.set(t, &GONEMAP, &Value::Map(fill)).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let marker = "PAGED-ATMOST-MARK-77e3";
    let edit = |lp: &mut LocalPeer, v: &str| {
        let mut m = Mutation::new();
        m.op(t, &GONEMAP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("k047"))], op: osis_crdt::Op::Set(s(v)) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    lp.advance(5);
    let c = edit(&mut lp, &big(marker));
    filler(&mut lp, 0, 6);
    assert!(recoverable(&mut lp.peers[0], marker.as_bytes()), "the attack finds live content");
    lp.advance(5);
    edit(&mut lp, "final");
    assert!(!lp.peers[0].engine.body_not_dropped(&c, &t, &ak("t:gonemap.0")));
    assert!(!recoverable(&mut lp.peers[0], marker.as_bytes()), "dropped content recovered");
    assert_eq!(lp.peers[0].engine.get_at(&t, &ak("t:gonemap.0"), &[osis_crdt::PathSeg::Key(s("k047"))]).unwrap(), Some(s("final")));
}

// spec/commits.md §6, spec/crdt.md §4.7 (expiry), spec/requirements.md (Scale: O(change)): an
// expiring entry of a paged map goes value-less in its page (rewritten shredded with its key
// index row), not by rewriting the whole state; no copy of its value survives
#[test]
fn expired_entry_paged_unrecoverable_spec_commits_6() {
    let mut lp = net2(76);
    let t = new_thing(&mut lp, 0);
    let fill: std::collections::BTreeMap<Value, Value> = (0..66).map(|i| (s(&format!("k{i:03}")), s(&"f".repeat(1100)))).collect();
    let mut m = Mutation::new();
    m.set(t, &BIG, &Value::Map(fill)).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let marker = "PAGED-EXPIRY-MARK-31aa";
    lp.advance(5);
    let mut m = Mutation::new();
    m.op(t, &BIG, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("k999"))], op: osis_crdt::Op::Set(s(&big(marker))) }).unwrap();
    m.expires(t, &BIG, osis_base::WallMs(lp.peers[0].engine.now().0 + 60_000)).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    filler(&mut lp, 0, 6);
    assert!(recoverable(&mut lp.peers[0], marker.as_bytes()), "the attack finds live content");
    lp.advance(60_001);
    lp.peers[0].engine.tick().unwrap();
    assert_eq!(lp.peers[0].engine.get_at(&t, &ak("t:big.0"), &[osis_crdt::PathSeg::Key(s("k999"))]).unwrap(), None);
    // the value, the key, nor the key's hash (the paged map's key index): one attack
    let h = osis_base::hash::hash(&osis_base::encode(&s("k999")));
    let found = plaintexts(&mut lp.peers[0]);
    for (needle, what) in [(marker.as_bytes(), "expired content"), (b"k999".as_slice(), "the expired key"), (h.as_slice(), "the expired key's index row")] {
        assert!(!found.iter().any(|x| contains(x, needle)), "{what} recovered");
    }
    assert_eq!(lp.peers[0].engine.get_at(&t, &ak("t:big.0"), &[osis_crdt::PathSeg::Key(s("k007"))]).unwrap(), Some(s(&"f".repeat(1100))));
}

// spec/commits.md §6, spec/crdt.md §4.7, §5.5: an expiring element of a paged set goes
// value-less in its page and leaves its value index; no copy of its value survives; adding the
// value again and removing another by value work over the pages
#[test]
fn expired_element_paged_set_unrecoverable_spec_commits_6() {
    let mut lp = net2(77);
    let t = new_thing(&mut lp, 0);
    let a = ak("t:bigset.0");
    let mut m = Mutation::new();
    m.set(t, &a, &Value::Set((0..66).map(|i| s(&format!("e{i:03}{}", "f".repeat(1100)))).collect())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let marker = big("PAGED-SET-EXPIRY-MARK-5b1e");
    let add = |lp: &mut LocalPeer, v: &str, exp: Option<u64>| {
        let mut m = Mutation::new();
        m.op(t, &a, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Add(s(v)) }).unwrap();
        if let Some(e) = exp {
            m.expires(t, &a, osis_base::WallMs(e)).unwrap();
        }
        lp.peers[0].commit(m).unwrap()
    };
    lp.advance(5);
    let exp = lp.peers[0].engine.now().0 + 60_000;
    add(&mut lp, &marker, Some(exp)).unwrap();
    filler(&mut lp, 0, 6);
    assert!(recoverable(&mut lp.peers[0], marker.as_bytes()), "the attack finds live content");
    lp.advance(60_001);
    lp.peers[0].engine.tick().unwrap();
    assert!(!recoverable(&mut lp.peers[0], marker.as_bytes()), "expired content recovered");
    let read = |lp: &mut LocalPeer| match lp.peers[0].engine.get(&t, &a).unwrap() {
        Some(Value::Set(v)) => v,
        x => panic!("{x:?}"),
    };
    assert_eq!(read(&mut lp).len(), 66);
    assert!(add(&mut lp, &marker, None).is_some(), "the value is gone, so it is added again");
    let gone = format!("e007{}", "f".repeat(1100));
    let mut m = Mutation::new();
    m.op(t, &a, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Remove(s(&gone)) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let v = read(&mut lp);
    assert!(v.len() == 66 && v.contains(&s(&marker)) && !v.contains(&s(&gone)));
}

// spec/commits.md §5: shredding a version covers every chunk only it reached (chunk keys live in
// links inside the dropped body); a purged large value's chunks stay unopenable from what the
// device still yields, though their ciphertext may linger in freed storage
#[test]
fn purged_large_value_unrecoverable_spec_commits_5() {
    let mut lp = net2(75);
    let t = new_thing(&mut lp, 0);
    let marker = b"LARGE-MARK-c4f2";
    let mut v = vec![0u8; 300 * 1024];
    let mut r = SeededRng::from_u64(9);
    osis_crypto::RngCore::fill_bytes(&mut r, &mut v);
    v[150_000..150_000 + marker.len()].copy_from_slice(marker);
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(v)).unwrap();
    let secret = lp.peers[0].commit(m).unwrap().unwrap();
    let chunks: Vec<Vec<u8>> = lp.peers[0].engine.package(&secret).unwrap().unwrap().blobs.into_iter().map(|(_, b)| b).collect();
    assert!(!chunks.is_empty(), "the value is chunked");
    // the attack opens blobs (tree nodes, chunks) with the link keys it recovers
    let opens = |p: &mut Peer| found_in(&mut p.engine, &p.backend, marker).iter().any(|f| matches!(f, osis_store::Source::Blob { .. }));
    assert!(opens(&mut lp.peers[0]), "the attack opens live chunks");
    filler(&mut lp, 0, 6);
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(b"small".to_vec())).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("t:blob.0") });
    lp.peers[0].commit(m).unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&secret, &t, &ak("t:blob.0")));
    assert!(!opens(&mut lp.peers[0]), "a purged chunk opened");
}

// spec/commits.md §5 (keep at most 0: a body with a live write keeps to the next compaction or
// its first death plus `AT_MOST_GRACE`), spec/requirements.md (Scale: cost per change): an
// erasing edit of a big record (compacted, or an ordinary commit) writes O(change) and keeps
// the body; at the bound the body is dropped and no local copy of the erased entry survives
#[test]
fn at_most_zero_live_body_dropped_at_bound_unrecoverable_spec_commits_5() {
    for compact in [true, false] {
        let mut lp = net2(77);
        let t = new_thing(&mut lp, 0);
        let marker = "LIVE-ATMOST-MARK-c90d";
        let mut fill: std::collections::BTreeMap<Value, Value> = (0..300).map(|i| (s(&format!("k{i:03}")), s(&"f".repeat(1100)))).collect();
        fill.insert(s("secret"), s(&big(marker)));
        let mut m = Mutation::new();
        m.set(t, &GONEMAP, &Value::Map(fill)).unwrap();
        let c0 = lp.peers[0].commit(m).unwrap().unwrap();
        let k = ak("t:gonemap.0");
        // compaction: a snapshot, then the covered body dropped
        let body = if compact {
            let s1 = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
            lp.peers[0].engine.drop_body(&c0, &t, &k).unwrap();
            s1
        } else {
            c0
        };
        filler(&mut lp, 0, 6);
        lp.advance(5);
        let written = |p: &mut osis_node::local_peer::Peer| p.backend.history().iter().map(|(r, v)| r.len() + v.len()).sum::<usize>();
        let before = written(&mut lp.peers[0]);
        let mut m = Mutation::new();
        m.op(t, &GONEMAP, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(s("secret")) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        let cost = written(&mut lp.peers[0]) - before;
        assert!(cost < 96 * 1024, "compact {compact}: an erasing edit wrote {cost} bytes (the record is about 330 KB)");
        let e = &mut lp.peers[0].engine;
        assert!(e.body_not_dropped(&body, &t, &k), "compact {compact}: the body keeps to the next compaction");
        let first = e.deaths(&body, &t, &k).unwrap().unwrap().0.wall_ms().0;
        assert_eq!(e.body_keep(&body, &t, &k).unwrap().at_most, Some(first + osis_base::format::AT_MOST_GRACE_MS));
        lp.advance(osis_base::format::AT_MOST_GRACE_MS + 1);
        lp.peers[0].engine.tick().unwrap();
        assert!(!lp.peers[0].engine.body_not_dropped(&body, &t, &k), "compact {compact}");
        assert!(!recoverable(&mut lp.peers[0], marker.as_bytes()), "compact {compact}: erased content recovered");
        assert_eq!(lp.peers[0].engine.get_at(&t, &k, &[osis_crdt::PathSeg::Key(s("k007"))]).unwrap(), Some(s(&"f".repeat(1100))));
    }
}

// spec/requirements.md Deletion (purge is prompt, no fingerprint), spec/crdt.md §5.6: an app
// map's key is user content; once its entry is removed and the creation purged, neither the
// removal's body nor a later snapshot's tombstone keeps it, at the writer or a receiver
#[test]
fn removed_map_key_gone_after_purge_spec_crdt_5_6() {
    let mut lp = net2(78);
    let t = new_thing(&mut lp, 0);
    let marker = "KEY-MARK-5e17";
    let k = ak("t:big.0");
    let put = |lp: &mut LocalPeer, key: &str| {
        let mut m = Mutation::new();
        m.op(t, &BIG, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(key))], op: osis_crdt::Op::Set(s("v")) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let c = put(&mut lp, marker);
    lp.sync(0, 1).unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.op(t, &BIG, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(s(marker)) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync(0, 1).unwrap();
    filler(&mut lp, 0, 6);
    lp.advance(5);
    let mut m = Mutation::new();
    m.op(t, &BIG, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("other"))], op: osis_crdt::Op::Set(s("w")) }).unwrap();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: k.clone() });
    lp.peers[0].commit(m).unwrap();
    lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.sync(0, 1).unwrap();
    for i in [0, 1] {
        assert!(!lp.peers[i].engine.body_not_dropped(&c, &t, &k), "peer {i}");
        assert_eq!(lp.peers[i].engine.get_at(&t, &k, &[osis_crdt::PathSeg::Key(s("other"))]).unwrap(), Some(s("w")));
        assert!(!recoverable(&mut lp.peers[i], marker.as_bytes()), "peer {i}: the removed key recovered");
    }
}

// spec/crdt.md §4.7: a part of an expired delta arriving after T, later than the rest of its
// commit, joins value-less and drops again; no local copy of its value survives
#[test]
fn expired_late_part_unrecoverable_spec_crdt_4_7() {
    let mut lp = net2(78);
    let t = new_thing(&mut lp, 0);
    lp.sync(0, 1).unwrap();
    let marker = "LATEEXP-MARK-3e9f";
    let mut m = Mutation::new();
    m.set(t, &BRIEF, &s(&big(marker))).unwrap();
    m.set(t, &REG, &s("plain")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.packages(0).unwrap().into_iter().find(|p| p.id == c).unwrap();
    let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let brief = b.header.aspects.iter().position(|a| a.ak.as_str() == "t:brief.0").unwrap();
    b.parts.retain(|x| x.ai != brief);
    lp.peers[1].engine.ingest(&b.encode(), pk.blobs.clone()).unwrap();
    filler(&mut lp, 1, 6);
    lp.advance(3_600_001);
    lp.peers[1].engine.tick().unwrap();
    // taken (`retention::takes_late`): joined, then dropped again
    assert!(matches!(lp.peers[1].engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap(), osis_node::Ingested::Applied(_)));
    filler(&mut lp, 1, 6);
    assert!(!lp.peers[1].engine.body_not_dropped(&c, &t, &ak("t:brief.0")));
    assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "expired content recovered from the late part");
}

// spec/commits.md §5 (no copy past T): a commit held pending (its thing's creation not held) past
// its expiry drops the expiring part from its stored copy at T, which then counts as never
// received; the aspect is flagged suspect (spec/permissions.md §4)
#[test]
fn pending_part_dropped_at_expiry_spec_commits_5() {
    let mut lp = net2(79);
    let t = new_thing(&mut lp, 0);
    let marker = "PENDEXP-MARK-5b1c";
    let c = set(&mut lp, 0, t, &BRIEF, &big(marker));
    let pk = lp.packages(0).unwrap().into_iter().find(|p| p.id == c).unwrap();
    assert!(matches!(lp.deliver(1, &pk).unwrap(), osis_node::Ingested::Pending(..)));
    filler(&mut lp, 1, 6);
    lp.advance(3_600_001);
    lp.peers[1].engine.tick().unwrap();
    filler(&mut lp, 1, 6);
    assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "expired content recovered from the pending copy");
    assert!(lp.peers[1].engine.suspects().unwrap().iter().any(|(x, a, _, _)| *x == t && a.as_str() == "t:brief.0"), "flagged suspect");
}

// spec/commits.md §4 (a commit no part of which is held waits whole for its things, synced or
// not): peer 1 gets peer 0's expiring write on a thing whose creation record it lacks, past T.
// The part goes (counts as never received, §5) and the commit, left with no part, pends on the
// record whether peer 1 syncs the thing or not (it applied header-only where the thing was not
// synced: order seeds 1007, 1046); the record come, it applies.
#[test]
fn partless_commit_pends_on_its_thing_spec_commits_4() {
    for syncing in [false, true] {
        let mut lp = net2(81);
        lp.sync_all().unwrap();
        let t = new_thing(&mut lp, 0);
        let mut m = Mutation::new();
        m.set(t, &BRIEF, &s("brief")).unwrap();
        m.expires(t, &BRIEF, osis_base::WallMs(lp.peers[0].engine.now().0 + 60_000)).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let pk = lp.packages(0).unwrap().into_iter().find(|p| p.id == c).unwrap();
        lp.peers[1].engine.set_syncing(t, syncing).unwrap();
        lp.advance(120_000);
        assert!(matches!(lp.deliver(1, &pk).unwrap(), osis_node::Ingested::Pending(_, osis_node::Reason::UnknownCreated(x)) if x == t), "syncing {syncing}");
        assert!(!lp.peers[1].engine.commit_ids().contains(&c), "syncing {syncing}: applied header-only");
        assert!(lp.peers[1].engine.suspects().unwrap().iter().any(|x| x.0 == t && x.1 == ak("t:brief.0")), "flagged");
        lp.sync(0, 1).unwrap();
        assert!(lp.peers[1].engine.commit_ids().contains(&c) && lp.peers[1].engine.pending().iter().all(|x| x.0 != c), "syncing {syncing}: applied once the record came");
    }
}

// spec/permissions.md §4 (a suspect flag names the bodies it is about): peer 1 drops peer 0's
// expiring write W at T while it pends on its thing's record, and flags the aspect. Peer 2, a
// writer that never received W, writes the aspect and snapshots it after T: joined at peer 1
// with the record, the snapshot lists nothing of W, so the flag stays (peer 1 still lacks W's
// value-less write; clearing on any later-stamped snapshot hid that: order seed 4108). A copy
// of W arriving late (joined and stripped, spec/crdt.md §4.7) is the body back: the flag goes.
#[test]
fn suspect_flag_outlives_a_snapshot_listing_nothing_of_it_spec_permissions_4() {
    let mut lp = net(3, 83);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let two = lp.peers[2].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, two, Some(edge(osis_base::Role::Write)), None);
    lp.sync(0, 2).unwrap();
    let mut m = Mutation::new();
    m.set(t, &BRIEF, &s("brief")).unwrap();
    m.expires(t, &BRIEF, osis_base::WallMs(lp.peers[0].engine.now().0 + 60_000)).unwrap();
    let w = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.packages(0).unwrap().into_iter().find(|p| p.id == w).unwrap();
    assert!(matches!(lp.deliver(1, &pk).unwrap(), osis_node::Ingested::Pending(..)));
    lp.advance(120_000);
    lp.peers[1].engine.tick().unwrap();
    let brief = ak("t:brief.0");
    let flagged = |lp: &mut LocalPeer| lp.peers[1].engine.suspects().unwrap().iter().any(|x| x.0 == t && x.1 == brief);
    assert!(flagged(&mut lp), "flagged at T");
    set(&mut lp, 2, t, &BRIEF, "two");
    lp.peers[2].clock.advance(1);
    let s2 = lp.peers[2].engine.snapshot(&t, &brief).unwrap().expect("a snapshot");
    lp.sync(2, 1).unwrap();
    assert!(lp.peers[1].engine.commit_ids().contains(&s2) && lp.peers[1].engine.commit_ids().contains(&w), "the record came: the snapshot and the part-less commit applied");
    assert!(flagged(&mut lp), "a snapshot listing nothing of W clears nothing");
    lp.sync(0, 1).unwrap();
    assert!(!flagged(&mut lp), "W's late copy is the body back");
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.state_digest(&t, &brief).unwrap(), lp.peers[0].engine.state_digest(&t, &brief).unwrap());
}

// spec/commits.md §5, spec/requirements.md (Deterministic): a commit, its thing's record and a purge
// request naming its parts on a register, a list and a map (resetting nothing), in every order: the node
// holds each aspect as its author does (the parts value-less, their non-value writes kept), whether the
// parts waited when the request came or not, flags nothing and keeps no purged value.
#[test]
fn purge_of_a_waiting_part_reads_alike_spec_commits_5() {
    use osis_crdt::{Op, PathOp, PathSeg};
    let aspects = [ak("t:reg.0"), ak("t:list.0"), ak("t:big.0")];
    let mut reads = Vec::new();
    for order in [[0usize, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let mut lp = net2(131);
        let t = new_thing(&mut lp, 0);
        let mut m = Mutation::new();
        m.set(t, &REG, &s("old")).unwrap();
        m.set(t, &LIST, &Value::List(vec![s("a")])).unwrap();
        m.op(t, &BIG, PathOp { path: vec![PathSeg::Key(s("k"))], op: Op::Set(s("old")) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        let t3 = new_thing(&mut lp, 0);
        lp.sync(0, 1).unwrap();
        lp.peers[1].engine.set_syncing(t3, true).unwrap();
        lp.peers[1].engine.set_syncing(t, true).unwrap();
        let had: std::collections::BTreeSet<_> = lp.packages(0).unwrap().iter().map(|p| p.id).collect();
        let t2 = new_thing(&mut lp, 0);
        lp.peers[1].engine.set_syncing(t2, true).unwrap();
        let rec: Vec<_> = lp.packages(0).unwrap().into_iter().filter(|p| !had.contains(&p.id)).collect();
        lp.advance(5);
        let mut m = Mutation::new();
        m.set(t, &REG, &s("SECRET-9c2e")).unwrap();
        m.op(t, &LIST, PathOp { path: Vec::new(), op: Op::Insert { at: 1, items: vec![s("SECRET-L7a1")] } }).unwrap();
        m.op(t, &BIG, PathOp { path: vec![PathSeg::Key(s("SECRET-K3b8"))], op: Op::Set(s("SECRET-V5d0")) }).unwrap();
        m.set(t2, &REG, &s("other")).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let whole = lp.peers[0].engine.package(&c).unwrap().unwrap();
        lp.advance(5);
        let mut m = Mutation::new();
        m.set(t3, &REG, &s("other3")).unwrap();
        for a in &aspects {
            m.purge(PurgeItem::Commit { commit: c, tid: t, ak: a.clone() });
        }
        let p = lp.peers[0].commit(m).unwrap().unwrap();
        let request = lp.peers[0].engine.package(&p).unwrap().unwrap();
        let groups = [rec, vec![whole], vec![request]];
        let markers = ["SECRET-9c2e", "SECRET-L7a1", "SECRET-K3b8", "SECRET-V5d0"];
        for (i, g) in order.iter().enumerate() {
            for pk in &groups[*g] {
                lp.deliver(1, pk).unwrap();
            }
            lp.peers[1].engine.reexamine().unwrap();
            // the request held while the commit waits: its values left already
            if order[..=i].contains(&2) && lp.peers[1].engine.pending().iter().any(|x| x.0 == c) {
                for marker in markers {
                    assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "order {order:?}, waiting: {marker}");
                }
            }
        }
        {
            let e = &mut lp.peers[1].engine;
            assert!(e.pending().is_empty(), "order {order:?}: {:?}", e.pending());
            assert_eq!(e.get(&t2, &ak("t:reg.0")).unwrap(), Some(s("other")), "order {order:?}");
            assert!(e.suspects().unwrap().is_empty(), "order {order:?}");
        }
        let mut read = Vec::new();
        for a in &aspects {
            let author = lp.peers[0].engine.state_digest(&t, a).unwrap();
            assert_eq!(lp.peers[1].engine.state_digest(&t, a).unwrap(), author, "order {order:?}: {a:?} as its author holds it");
            read.push(lp.peers[1].engine.get(&t, a).unwrap());
        }
        for marker in markers {
            assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "order {order:?}: {marker}");
        }
        reads.push(read);
    }
    assert_eq!(reads[0][0], None, "the value-less write wins over \"old\"");
    assert!(reads.iter().all(|r| *r == reads[0]), "{reads:?}");
}

// spec/commits.md §5, spec/requirements.md (Deterministic): commit `c` writes `t` (reg, list) and `t2`;
// node 1 syncs `t2`, not `t`, and gets `c` as two copies (one without the list part, one of it alone, as
// blobs of two retention classes would bring it): with the first alone `c` applies its `t2` part and the
// reg part waits alone for its unit. A purge request naming the reg part, in every order: the node holds
// `t` as its author does and flags nothing.
#[test]
fn purge_of_a_part_waiting_aside_reads_alike_spec_commits_5() {
    for order in [[0usize, 1, 2], [1, 0, 2], [0, 2, 1], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let mut lp = net2(141);
        let t = new_thing(&mut lp, 0);
        let t2 = new_thing(&mut lp, 0);
        let t3 = new_thing(&mut lp, 0);
        lp.sync(0, 1).unwrap();
        lp.peers[1].engine.set_syncing(t2, true).unwrap();
        lp.peers[1].engine.set_syncing(t3, true).unwrap();
        lp.advance(5);
        let mut m = Mutation::new();
        m.set(t, &REG, &s("SECRET-R4e1")).unwrap();
        m.set(t, &LIST, &Value::List(vec![s("a")])).unwrap();
        m.set(t2, &REG, &s("other")).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let whole = lp.peers[0].engine.package(&c).unwrap().unwrap();
        lp.advance(5);
        let mut m = Mutation::new();
        m.set(t3, &REG, &s("other3")).unwrap();
        m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
        let p = lp.peers[0].commit(m).unwrap().unwrap();
        let request = lp.peers[0].engine.package(&p).unwrap().unwrap();
        let mut part = osis_commit::CommitBlob::decode(&whole.bytes).unwrap();
        let list = part.header.aspects.iter().position(|a| a.tid == t && a.ak == ak("t:list.0")).unwrap();
        let mut rest = part.clone();
        part.parts.retain(|q| q.ai != list);
        rest.parts.retain(|q| q.ai == list);
        for g in order {
            match g {
                0 => drop(lp.peers[1].engine.ingest(&part.encode(), Vec::new()).unwrap()),
                1 => drop(lp.deliver(1, &request).unwrap()),
                _ => drop(lp.peers[1].engine.ingest(&rest.encode(), Vec::new()).unwrap()),
            }
            lp.peers[1].engine.reexamine().unwrap();
            assert!(lp.peers[1].engine.suspects().unwrap().is_empty(), "order {order:?} after {g}: held value-less, not dropped");
        }
        let e = &mut lp.peers[1].engine;
        assert!(e.pending().is_empty(), "order {order:?}: {:?}", e.pending());
        assert_eq!(e.get(&t2, &ak("t:reg.0")).unwrap(), Some(s("other")), "order {order:?}");
        assert!(e.suspects().unwrap().is_empty(), "order {order:?}: {:?}", e.suspects().unwrap());
        for a in [ak("t:reg.0"), ak("t:list.0")] {
            let author = lp.peers[0].engine.state_digest(&t, &a).unwrap();
            assert_eq!(lp.peers[1].engine.state_digest(&t, &a).unwrap(), author, "order {order:?}: {a:?} as its author holds it");
        }
        assert!(!recoverable(&mut lp.peers[1], b"SECRET-R4e1"), "order {order:?}");
    }
}

// spec/commits.md §4, §5: beside a part past its expiry that goes, because the commit would wait without
// it, a waiting part a held purge request names is held value-less, and joins so when the commit applies:
// the node holds its aspect as the author does, no value left, only the expired part's aspect flagged.
// Its thing synced the commit waits whole (`examine` says so itself), not synced `waits_without_expired` does.
#[test]
fn purged_part_waits_beside_a_part_past_expiry_spec_commits_5() {
    for synced in [false, true] {
        let mut lp = net2(142);
        let (t, t2, t3) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0), new_thing(&mut lp, 0));
        lp.sync(0, 1).unwrap();
        lp.peers[1].engine.set_syncing(t, synced).unwrap();
        lp.advance(5);
        let mut m = Mutation::new();
        m.set(t, &REG, &s("SECRET-R4e2")).unwrap();
        m.set(t, &LIST, &Value::List(vec![s("a")])).unwrap();
        m.set(t2, &BRIEF, &s("BRIEF-R4e2")).unwrap();
        m.expires(t2, &BRIEF, osis_base::WallMs(lp.peers[0].engine.now().0 + 60_000)).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let whole = lp.peers[0].engine.package(&c).unwrap().unwrap();
        lp.advance(5);
        let mut m = Mutation::new();
        m.set(t3, &REG, &s("other3")).unwrap();
        m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
        let p = lp.peers[0].commit(m).unwrap().unwrap();
        let request = lp.peers[0].engine.package(&p).unwrap().unwrap();
        let mut part = osis_commit::CommitBlob::decode(&whole.bytes).unwrap();
        let list = part.header.aspects.iter().position(|a| a.tid == t && a.ak == ak("t:list.0")).unwrap();
        let mut rest = part.clone();
        part.parts.retain(|q| q.ai != list);
        rest.parts.retain(|q| q.ai == list);
        lp.advance(120_000);
        lp.peers[0].engine.tick().unwrap();
        lp.deliver(1, &request).unwrap();
        let r = lp.peers[1].engine.ingest(&part.encode(), Vec::new()).unwrap();
        assert!(matches!(r, osis_node::Ingested::Pending(_, osis_node::Reason::WaitDeltas)), "{r:?}");
        let [secret, brief] = recovered(&mut lp.peers[1], [b"SECRET-R4e2", b"BRIEF-R4e2"]);
        assert!(!secret, "held value-less");
        assert!(!brief, "gone");
        let flagged = |lp: &mut LocalPeer| lp.peers[1].engine.suspects().unwrap().into_iter().map(|x| (x.0, x.1)).collect::<Vec<_>>();
        assert_eq!(flagged(&mut lp), vec![(t2, ak("t:brief.0"))]);
        lp.peers[1].engine.ingest(&rest.encode(), Vec::new()).unwrap();
        lp.peers[1].engine.reexamine().unwrap();
        let e = &mut lp.peers[1].engine;
        assert!(e.pending().is_empty() && e.commit_ids().contains(&c), "{:?}", e.pending());
        for a in [ak("t:reg.0"), ak("t:list.0")] {
            let author = lp.peers[0].engine.state_digest(&t, &a).unwrap();
            assert_eq!(lp.peers[1].engine.state_digest(&t, &a).unwrap(), author, "{a:?} as its author holds it");
        }
        assert!(!recoverable(&mut lp.peers[1], b"SECRET-R4e2"));
        assert_eq!(flagged(&mut lp), vec![(t2, ak("t:brief.0"))], "the expired part's alone");
    }
}

// spec/commits.md §5: a waiting part a held purge request names, its value large (chunks) or its delta
// paged (a map of many big entries), keeps no purged value while it waits or once applied
#[test]
fn purged_while_pending_large_or_paged_unrecoverable_spec_commits_5() {
    let marker = "PEND-LARGE-MARK-5a9b";
    for (large, request_first) in [(true, true), (true, false), (false, true), (false, false)] {
        let mut lp = net2(151 + 2 * u64::from(large) + u64::from(request_first));
        let t = new_thing(&mut lp, 0);
        lp.sync(0, 1).unwrap();
        let had: std::collections::BTreeSet<_> = lp.packages(0).unwrap().iter().map(|p| p.id).collect();
        let t2 = new_thing(&mut lp, 0);
        let rec: Vec<_> = lp.packages(0).unwrap().into_iter().filter(|p| !had.contains(&p.id)).collect();
        lp.peers[1].engine.set_syncing(t, true).unwrap();
        lp.peers[1].engine.set_syncing(t2, true).unwrap();
        let (a, mut m) = (if large { ak("t:blob.0") } else { ak("t:gonemap.0") }, Mutation::new());
        if large {
            let mut v = vec![0u8; 300 * 1024];
            osis_crypto::RngCore::fill_bytes(&mut SeededRng::from_u64(9), &mut v);
            v[150_000..150_000 + marker.len()].copy_from_slice(marker.as_bytes());
            m.set(t, &BLOB, &Value::Bytes(v)).unwrap();
        } else {
            let mut fill: std::collections::BTreeMap<Value, Value> = (0..66).map(|i| (s(&format!("k{i:03}")), s(&"f".repeat(1100)))).collect();
            fill.insert(s("k030"), s(&big(marker)));
            m.set(t, &GONEMAP, &Value::Map(fill)).unwrap();
        }
        m.set(t2, &REG, &s("other")).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let whole = lp.peers[0].engine.package(&c).unwrap().unwrap();
        lp.advance(5);
        let mut m = Mutation::new();
        m.set(t, &REG, &s("public")).unwrap();
        m.purge(PurgeItem::Commit { commit: c, tid: t, ak: a.clone() });
        let p = lp.peers[0].commit(m).unwrap().unwrap();
        let request = lp.peers[0].engine.package(&p).unwrap().unwrap();
        let order = if request_first { [&request, &whole] } else { [&whole, &request] };
        for pk in order {
            lp.deliver(1, pk).unwrap();
            lp.peers[1].engine.reexamine().unwrap();
        }
        assert!(lp.peers[1].engine.pending().iter().any(|x| x.0 == c), "large {large} request first {request_first}: it waits for t2");
        assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "large {large} request first {request_first}: recovered while waiting");
        for pk in &rec {
            lp.deliver(1, pk).unwrap();
        }
        lp.peers[1].engine.reexamine().unwrap();
        assert!(lp.peers[1].engine.pending().is_empty(), "large {large} request first {request_first}");
        assert_eq!(lp.peers[1].engine.state_digest(&t, &a).unwrap(), lp.peers[0].engine.state_digest(&t, &a).unwrap(), "large {large} request first {request_first}");
        assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "large {large} request first {request_first}: recovered once applied");
    }
}

/// The parts of `pk` on `(t, a)`, each slot's delta replaced by what a stripped slot holds, if `empty`.
fn part_on(pk: &osis_node::local_peer::Package, t: Tid, a: &osis_base::Ak, empty: bool) -> Vec<u8> {
    let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let h = b.header.clone();
    b.parts.retain(|p| h.aspects[p.ai].tid == t && h.aspects[p.ai].ak == *a);
    assert!(!b.parts.is_empty());
    if empty {
        for p in &mut b.parts {
            p.delta = osis_base::encode(&Value::List(Vec::new()));
        }
    }
    b.encode()
}

// spec/commits.md §5: a part held value-less, past its expiry when its commit applies beside it, goes
// with its kept stripped delta: nothing is left for a relay's empty slot to bring back.
#[test]
fn stripped_delta_goes_with_its_part_past_expiry_spec_commits_5() {
    let mut lp = net2(301);
    let (t, y, q) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    lp.sync(0, 1).unwrap();
    lp.advance(5);
    let exp = osis_base::WallMs(lp.peers[0].engine.now().0 + 60_000);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("SECRET-R5b")).unwrap();
    m.expires(t, &REG, exp).unwrap();
    m.set(t, &LIST, &Value::List(vec![s("a")])).unwrap();
    m.set(y, &REG, &s("y")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(q, &REG, &s("q")).unwrap();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    let request = lp.peers[0].engine.package(&p).unwrap().unwrap();
    lp.deliver(1, &request).unwrap();
    lp.peers[1].engine.ingest(&part_on(&pk, t, &ak("t:reg.0"), false), Vec::new()).unwrap();
    assert_eq!(lp.peers[1].engine.stripped_count(&c).unwrap(), 1);
    lp.peers[1].clock.advance(120_000);
    lp.peers[1].engine.ingest(&part_on(&pk, y, &ak("t:reg.0"), false), Vec::new()).unwrap();
    assert!(lp.peers[1].engine.commit_ids().contains(&c) && lp.peers[1].engine.pending().is_empty(), "{:?}", lp.peers[1].engine.pending());
    assert_eq!(lp.peers[1].engine.stripped_count(&c).unwrap(), 0);
    let _ = lp.peers[1].engine.ingest(&part_on(&pk, t, &ak("t:reg.0"), true), Vec::new());
    assert!(lp.peers[1].engine.pending().is_empty());
    assert!(!recoverable(&mut lp.peers[1], b"SECRET-R5b"));
}

// spec/commits.md §4, §5: a relay's junk beside a true part past its expiry is no part that went: only
// the true part's aspect is flagged.
#[test]
fn junk_beside_a_part_past_expiry_raises_no_flag_spec_commits_5() {
    let mut lp = net2(302);
    let (t, y) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    lp.sync(0, 1).unwrap();
    lp.advance(5);
    let exp = osis_base::WallMs(lp.peers[0].engine.now().0 + 60_000);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("a")).unwrap();
    m.expires(t, &REG, exp).unwrap();
    m.set(t, &BRIEF, &s("b")).unwrap();
    m.expires(t, &BRIEF, exp).unwrap();
    m.set(y, &REG, &s("y")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    lp.peers[1].clock.advance(120_000);
    let mut b = osis_commit::CommitBlob::decode(&part_on(&pk, t, &ak("t:reg.0"), false)).unwrap();
    b.parts.extend(osis_commit::CommitBlob::decode(&part_on(&pk, t, &ak("t:brief.0"), true)).unwrap().parts);
    b.parts.sort_by_key(|p| (p.ai, p.di));
    let r = lp.peers[1].engine.ingest(&b.encode(), Vec::new()).unwrap();
    assert!(matches!(r, osis_node::Ingested::Pending(_, osis_node::Reason::WaitDeltas)), "{r:?}");
    let flagged: Vec<_> = lp.peers[1].engine.suspects().unwrap().into_iter().map(|x| x.1).collect();
    assert_eq!(flagged, vec![ak("t:reg.0")]);
}

/// Of each 5040 orders of `past_expiry_and_purge_alike_in_every_order`, this stride's: 1 runs them all
/// (with the sync sets and clocks 75600 cases, 670 s on 16 threads at load).
const ORDER_STRIDE: usize = 389;

// spec/commits.md §4, §5: a purged part, a part past its expiry, an unchecked first copy of a slot and
// a relay's empty slots (the bytes of a stripped one, no record behind them or one), in any order, T
// passing and a restart anywhere among them: each true copy delivered again at the end, the node reads
// alike whatever it syncs, its commit applied, no flag left, nothing of either value recoverable.
#[test]
fn past_expiry_and_purge_alike_in_every_order_spec_commits_5() {
    let mut lp = net2(304);
    let (t2, t3) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    let setup = lp.packages(0).unwrap();
    let t = new_thing(&mut lp, 0);
    let rec: Vec<_> = lp.packages(0).unwrap().into_iter().filter(|p| !setup.iter().any(|k| k.id == p.id)).collect();
    assert_eq!(rec.len(), 1);
    lp.advance(5);
    let start = lp.peers[0].engine.now().0;
    let exp = osis_base::WallMs(start + 60_000);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("SECRET-R5c")).unwrap();
    m.set(t, &LIST, &Value::List(vec![s("a")])).unwrap();
    m.set(t2, &BRIEF, &s("BRIEF-R5c")).unwrap();
    m.expires(t2, &BRIEF, exp).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let whole = lp.peers[0].engine.package(&c).unwrap().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t3, &REG, &s("other3")).unwrap();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    let request = lp.peers[0].engine.package(&p).unwrap().unwrap();
    let ids: std::collections::BTreeSet<_> = lp.packages(0).unwrap().iter().map(|p| p.id).collect();
    let (reg, list, brief) = (ak("t:reg.0"), ak("t:list.0"), ak("t:brief.0"));
    let items = [
        (request.bytes.clone(), request.blobs.clone()),
        (part_on(&whole, t, &reg, false), Vec::new()),
        (part_on(&whole, t, &list, false), Vec::new()),
        (part_on(&whole, t2, &brief, false), Vec::new()),
        (part_on(&whole, t, &reg, true), Vec::new()),
        (part_on(&whole, t2, &brief, true), Vec::new()),
        (rec[0].bytes.clone(), rec[0].blobs.clone()),
    ];
    let mut orders: Vec<Vec<usize>> = vec![Vec::new()];
    for i in 0..items.len() {
        orders = orders.iter().flat_map(|q| (0..=q.len()).map(move |at| { let mut x = q.clone(); x.insert(at, i); x })).collect();
    }
    // (what it syncs, deliveries before T, whether a tick follows T)
    let shapes: Vec<(usize, usize, bool)> = (0..3).flat_map(|sync| [(0, false), (2, false), (2, true), (4, false), (4, true)].map(|(k, tick)| (sync, k, tick))).collect();
    let cases: Vec<(usize, usize)> = shapes.iter().enumerate().flat_map(|(n, _)| (0..orders.len()).step_by(ORDER_STRIDE).map(move |o| (n, o))).collect();
    let outcomes = std::sync::Mutex::new(std::collections::BTreeMap::<String, String>::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let (setup, items, orders, shapes, cases, ids) = (&setup, &items, &orders, &shapes, &cases, &ids);
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let at = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(&(n, o)) = cases.get(at) else { return };
                let ((sync, k, tick), order) = (shapes[n], &orders[o]);
                let mut p = peer(9000 + at as u64);
                for pk in setup {
                    p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
                }
                match sync {
                    1 => p.engine.set_syncing(t, true).unwrap(),
                    2 => p.engine.set_syncing(t2, true).unwrap(),
                    _ => {}
                }
                let late = exp.0 + 5_000;
                let to = |p: &mut Peer, when: u64| {
                    let now = p.engine.now().0;
                    p.clock.advance(when.saturating_sub(now));
                };
                to(&mut p, if k > 0 { start + 20 } else { late });
                for (i, x) in order.iter().enumerate() {
                    if i == k && k > 0 {
                        to(&mut p, late);
                        if tick {
                            p.engine.tick().unwrap();
                        }
                    }
                    if i == 3 && at % 2 == 1 {
                        p = reopened(p, at as u64);
                    }
                    let _ = p.engine.ingest(&items[*x].0, items[*x].1.clone());
                    p.engine.reexamine().unwrap();
                    // never shown past its expiry (a value held before T goes at the tick), nor after the request
                    if (k == 0 || tick) && p.engine.now().0 >= exp.0 {
                        assert_eq!(p.engine.get(&t2, &brief).unwrap(), None, "order {order:?}");
                    }
                    if order[..=i].contains(&0) {
                        assert_ne!(p.engine.get(&t, &reg).unwrap(), Some(s("SECRET-R5c")), "order {order:?}");
                    }
                }
                // before the copies that would heal it: every item delivered once
                let [kept_secret, kept_brief] = recovered(&mut p, [b"SECRET-R5c", b"BRIEF-R5c"]);
                assert!(!kept_secret, "order {order:?}: purged value kept");
                assert!(!(k == 0 || tick) || !kept_brief, "order {order:?}: expired value kept");
                if p.engine.pending().is_empty() {
                    assert_eq!(p.engine.stripped_count(&c).unwrap(), 0, "order {order:?}: nothing waits");
                }
                for x in [1, 2, 3] {
                    let _ = p.engine.ingest(&items[x].0, items[x].1.clone());
                    p.engine.reexamine().unwrap();
                }
                p.engine.tick().unwrap();
                p.engine.reexamine().unwrap();
                let e = &mut p.engine;
                let got = format!("applied {} pending {:?} stripped {} flags {:?} reads {:?} {:?} {:?} digests {:?} {:?} {:?} {:?}", e.commit_ids().contains(&c), e.pending(), e.stripped_count(&c).unwrap(), e.suspects().unwrap().iter().map(|f| f.1.clone()).collect::<Vec<_>>(), e.get(&t, &reg).unwrap(), e.get(&t, &list).unwrap(), e.get(&t2, &brief).unwrap(), e.state_digest(&t, &reg).unwrap(), e.state_digest(&t, &list).unwrap(), e.state_digest(&t2, &brief).unwrap(), crate::judgment::observe(e, ids));
                let [kept_secret, kept_brief] = recovered(&mut p, [b"SECRET-R5c", b"BRIEF-R5c"]);
                let gone = !kept_secret && !kept_brief;
                outcomes.lock().unwrap().entry(format!("gone {gone} {got}")).or_insert(format!("sync {sync} k {k} tick {tick} order {order:?}"));
            });
        }
    });
    let out = outcomes.into_inner().unwrap();
    assert_eq!(out.len(), 1, "{out:#?}");
    let (only, _) = out.iter().next().unwrap();
    assert!(only.starts_with("gone true applied true pending [] stripped 0 flags [] reads None Some(List([Str(\"a\")])) None"), "{only}");
}

// spec/commits.md §4, §5: a purged permanent delta reads alike whatever came first and whatever the
// node syncs: its body, its header-only blob, the purge request (or the request's own header-only
// blob with a snapshot listing its delta), a restart anywhere among them. Each ends with the commit
// applied without its body, the purge named, nothing waiting, nothing of the value recoverable.
#[test]
fn tombstone_alike_in_every_order_spec_commits_5() {
    use osis_commit::CommitBlob;
    let forever = osis_schema::Retention { by: osis_schema::PurgeBy::AuthorOrAdmin, at_least: osis_schema::Bound { abs: Some(osis_commit::FOREVER), rel: None }, at_most: osis_schema::Bound::default() };
    let marker = "TOMBSTONE-SECRET-8e1a";
    let mut lp = net2(611);
    let setup = lp.packages(0).unwrap();
    let t = new_thing(&mut lp, 0);
    let rec: Vec<_> = lp.packages(0).unwrap().into_iter().filter(|p| !setup.iter().any(|k| k.id == p.id)).collect();
    assert_eq!(rec.len(), 1);
    lp.advance(5);
    let mut m = Mutation::new();
    m.retention(t, &REG, forever).unwrap();
    m.set(t, &REG, &s(&big(marker))).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let whole = lp.peers[0].engine.package(&c).unwrap().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
    m.set(t, &REG, &s("after")).unwrap();
    let pc = lp.peers[0].commit(m).unwrap().unwrap();
    let request = lp.peers[0].engine.package(&pc).unwrap().unwrap();
    lp.advance(5);
    let z = lp.peers[0].engine.snapshot(&t, &ak("t:reg.0")).unwrap().unwrap();
    let snap = lp.peers[0].engine.package(&z).unwrap().unwrap();
    let header = |b: &[u8]| osis_commit::rewrite(&CommitBlob::decode(b).unwrap(), |_, _| true).encode();
    let item = |pk: &osis_node::local_peer::Package| (pk.bytes.clone(), pk.blobs.clone());
    let (cw, ch, pw, ph, zw, rc) = (item(&whole), (header(&whole.bytes), Vec::new()), item(&request), (header(&request.bytes), Vec::new()), item(&snap), item(&rec[0]));
    let sets = [("body, header and request", vec![cw.clone(), ch.clone(), pw.clone(), rc.clone()]), ("header and request", vec![ch.clone(), pw, rc.clone()]), ("two headers and a snapshot", vec![ch, ph, zw, rc])];
    let mut cases = 0;
    for (what, items) in sets {
        let mut orders: Vec<Vec<usize>> = vec![Vec::new()];
        for i in 0..items.len() {
            orders = orders.iter().flat_map(|q| (0..=q.len()).map(move |at| { let mut x = q.clone(); x.insert(at, i); x })).collect();
        }
        for syncing in [true, false] {
            for order in &orders {
                for restart in 0..=order.len() {
                    cases += 1;
                    let mut p = peer(7000 + cases);
                    for pk in &setup {
                        p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
                    }
                    if syncing {
                        p.engine.set_syncing(t, true).unwrap();
                    }
                    for (at, i) in order.iter().enumerate() {
                        if at == restart {
                            p = reopened(p, 8000 + cases);
                        }
                        p.engine.ingest(&items[*i].0, items[*i].1.clone()).unwrap();
                    }
                    let e = &mut p.engine;
                    let at = format!("{what}, syncing {syncing}, order {order:?}, restart {restart}");
                    assert!(e.commit_ids().contains(&c), "{at}: not applied");
                    assert!(!e.body_not_dropped(&c, &t, &ak("t:reg.0")), "{at}: its body is held");
                    assert_eq!(e.purged_on(&t, &ak("t:reg.0")).unwrap().get(&c), Some(&pc), "{at}");
                    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("after")), "{at}");
                    assert!(e.pending().is_empty(), "{at}: {:?}", e.pending());
                    assert!(e.suspects().unwrap().is_empty(), "{at}: flagged");
                    // the slow check: a sample
                    if restart == order.len() {
                        assert!(!recoverable(&mut p, marker.as_bytes()), "{at}: recoverable");
                    }
                }
            }
        }
    }
    // every case ran: both sync modes, each order, each restart point
    assert_eq!(cases, 2 * (24 * 5 + 6 * 4 + 24 * 5));
}

// spec/sync.md §6: a purge request becomes must-hold when the delta it names arrives after it: the
// purge commit is judged again then, not only at its own changes.
#[test]
fn request_is_judged_again_when_the_named_delta_arrives_spec_sync_6() {
    let forever = osis_schema::Retention { by: osis_schema::PurgeBy::AuthorOrAdmin, at_least: osis_schema::Bound { abs: Some(osis_commit::FOREVER), rel: None }, at_most: osis_schema::Bound::default() };
    let mut lp = net2(631);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    lp.advance(5);
    let mut m = Mutation::new();
    m.retention(t, &REG, forever).unwrap();
    m.set(t, &REG, &s("x")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let body = lp.peers[0].engine.package(&c).unwrap().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
    m.set(t, &REG, &s("after")).unwrap();
    let pc = lp.peers[0].commit(m).unwrap().unwrap();
    let request = lp.peers[0].engine.package(&pc).unwrap().unwrap();
    let e = &mut lp.peers[1].engine;
    e.ingest(&request.bytes, request.blobs.clone()).unwrap();
    assert!(e.commit_ids().contains(&pc));
    e.take_changed();
    e.ingest(&body.bytes, body.blobs.clone()).unwrap();
    assert!(e.commit_ids().contains(&c));
    assert!(e.take_changed().commits.contains(&pc));
}
