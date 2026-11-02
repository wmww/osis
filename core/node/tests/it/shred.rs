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
    Peer { engine, clock, backend, root, events }
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

// spec/commits.md §5: a part of a commit held pending that a held purge request names goes from
// the pending copy, whether the request comes first or after
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
        assert_eq!(lp.peers[1].engine.suspects().unwrap().len(), 1, "request first {request_first}: flagged");
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



// spec/commits.md §5, spec/permissions.md §4: a commit, its thing's record and a purge request naming a
// part of it (resetting nothing), in every order: the node reads as its author (the part value-less), or,
// where the part waited when the request came (it counts as never received), flags the aspect suspect.
#[test]
fn purge_of_a_waiting_part_reads_alike_or_flags_spec_commits_5() {
    let mut outs = Vec::new();
    for order in [[0usize, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let mut lp = net2(131);
        let t = new_thing(&mut lp, 0);
        set(&mut lp, 0, t, &REG, "old");
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
        m.set(t, &REG, &s("secret")).unwrap();
        m.set(t2, &REG, &s("other")).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let whole = lp.peers[0].engine.package(&c).unwrap().unwrap();
        lp.advance(5);
        let mut m = Mutation::new();
        m.set(t3, &REG, &s("other3")).unwrap();
        m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
        let p = lp.peers[0].commit(m).unwrap().unwrap();
        let request = lp.peers[0].engine.package(&p).unwrap().unwrap();
        let groups = [rec, vec![whole], vec![request]];
        for g in order {
            for pk in &groups[g] {
                lp.deliver(1, pk).unwrap();
            }
            lp.peers[1].engine.reexamine().unwrap();
        }
        let want = lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap();
        let e = &mut lp.peers[1].engine;
        assert!(e.pending().is_empty(), "order {order:?}");
        assert_eq!(e.get(&t2, &ak("t:reg.0")).unwrap(), Some(s("other")), "order {order:?}");
        let flagged = e.suspects().unwrap().iter().any(|x| x.0 == t && x.1 == ak("t:reg.0"));
        let read = e.get(&t, &ak("t:reg.0")).unwrap();
        assert!(read == want || flagged, "order {order:?}: {read:?}, author {want:?}");
        outs.push(flagged);
    }
    // the request before the commit applies drops its part: both outcomes occur
    assert!(outs.contains(&true) && outs.contains(&false), "{outs:?}");
}
