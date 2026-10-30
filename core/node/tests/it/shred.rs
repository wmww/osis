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
use std::collections::HashSet;
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
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("/t/reg") });
    lp.peers[0].commit(m).unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&secret, &t, &ak("/t/reg")));
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
    assert!(lp.peers[1].engine.body_not_dropped(&secret, &t, &ak("/t/reg")));
    filler(&mut lp, 1, 6);
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("/t/reg") });
    lp.peers[0].commit(m).unwrap();
    lp.sync(0, 1).unwrap();
    assert!(!lp.peers[1].engine.body_not_dropped(&secret, &t, &ak("/t/reg")));
    assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "purged content recovered from the pending copy");
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
    assert!(!lp.peers[0].engine.body_not_dropped(&c, &t, &ak("/t/brief")));
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
    assert!(!lp.peers[0].engine.body_not_dropped(&c, &t, &ak("/t/gone")));
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
    assert!(!lp.peers[0].engine.body_not_dropped(&c, &t, &ak("/t/gonemap")));
    assert!(!recoverable(&mut lp.peers[0], marker.as_bytes()), "dropped content recovered");
    assert_eq!(lp.peers[0].engine.get_at(&t, &ak("/t/gonemap"), &[osis_crdt::PathSeg::Key(s("k047"))]).unwrap(), Some(s("final")));
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
    assert_eq!(lp.peers[0].engine.get_at(&t, &ak("/t/big"), &[osis_crdt::PathSeg::Key(s("k999"))]).unwrap(), None);
    // the value, the key, nor the key's hash (the paged map's key index): one attack
    let h = osis_base::hash::hash(&osis_base::encode(&s("k999")));
    let found = plaintexts(&mut lp.peers[0]);
    for (needle, what) in [(marker.as_bytes(), "expired content"), (b"k999".as_slice(), "the expired key"), (h.as_slice(), "the expired key's index row")] {
        assert!(!found.iter().any(|x| contains(x, needle)), "{what} recovered");
    }
    assert_eq!(lp.peers[0].engine.get_at(&t, &ak("/t/big"), &[osis_crdt::PathSeg::Key(s("k007"))]).unwrap(), Some(s(&"f".repeat(1100))));
}

// spec/commits.md §6, spec/crdt.md §4.7, §5.5: an expiring element of a paged set goes
// value-less in its page and leaves its value index; no copy of its value survives; adding the
// value again and removing another by value work over the pages
#[test]
fn expired_element_paged_set_unrecoverable_spec_commits_6() {
    let mut lp = net2(77);
    let t = new_thing(&mut lp, 0);
    let a = ak("/t/bigset");
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
    // the attack opens blobs (tree nodes, chunks) with any 32-byte CBOR byte string (a link
    // key) it recovers, from rows and from blobs it opened
    let cbor_keys = |x: &[u8]| -> Vec<[u8; 32]> {
        let plain = x.windows(34).filter(|w| w[0] == 0x58 && w[1] == 32).map(|w| w[2..].try_into().unwrap());
        let link = x.windows(35).filter(|w| w[0] == 0x58 && w[1] == 33).map(|w| w[3..].try_into().unwrap());
        plain.chain(link).collect()
    };
    let opens = |p: &mut Peer| -> bool {
        let mut keys: HashSet<[u8; 32]> = plaintexts(p).iter().flat_map(|x| cbor_keys(x)).collect();
        let mut opened = vec![false; chunks.len()];
        loop {
            let mut new = Vec::new();
            for (i, c) in chunks.iter().enumerate() {
                if opened[i] {
                    continue;
                }
                if let Some(pt) = keys.iter().find_map(|k| osis_label::open(c, &osis_crypto::Secret32::from_bytes(*k)).ok().map(|x| x.1)) {
                    if contains(&pt, marker) {
                        return true;
                    }
                    opened[i] = true;
                    new.extend(cbor_keys(&pt));
                }
            }
            if new.is_empty() {
                return false;
            }
            keys.extend(new);
        }
    };
    assert!(opens(&mut lp.peers[0]), "the attack opens live chunks");
    filler(&mut lp, 0, 6);
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(b"small".to_vec())).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("/t/blob") });
    lp.peers[0].commit(m).unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&secret, &t, &ak("/t/blob")));
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
        let k = ak("/t/gonemap");
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
    let k = ak("/t/big");
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
