#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Forensic deletion at node level: after a purge, an expiry or a purge-on-replace drop, an attacker
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
    let blob_disk = (MemoryBackend::new(), MemoryRoot::new());
    blob_disk.0.record_history();
    let mut engine = Engine::create(Box::new(backend.clone()), Box::new(root.clone()), osis_node::local_peer::blob_area(&blob_disk, seed).unwrap(), cfg, c, Box::new(SeededRng::from_u64(seed))).unwrap();
    engine.create_account(&[]).unwrap();
    engine.take_wakes();
    let events = engine.subscribe();
    Peer { engine, clock, backend, root, blob_disk, events, restarts: 0, discarded: Vec::new(), discards: 0 }
}

/// `p` restarted over its durable state, as `peer` opens it.
fn reopened(p: Peer, seed: u64) -> Peer {
    let Peer { clock, backend, root, blob_disk, discarded, .. } = p;
    let cfg = Config { store: StoreConfig { arity: 4, depth: 8, page_max: 512, ..StoreConfig::default() }, ..Config::default() };
    let c: Arc<dyn Clock> = clock.clone();
    let mut engine = Engine::open(Box::new(backend.clone()), Box::new(root.clone()), osis_node::local_peer::blob_area(&blob_disk, seed).unwrap(), cfg, c, Box::new(SeededRng::from_u64(seed))).unwrap();
    let events = engine.subscribe();
    let mut p = Peer { engine, clock, backend, root, blob_disk, events, restarts: 0, discarded, discards: 0 };
    p.fetch_discarded().unwrap();
    p
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

// spec/commits.md §6: at T the body is dropped; spec/commits.md §5: no local copy survives
#[test]
fn expired_body_unrecoverable_spec_commits_6() {
    let mut lp = net2(73);
    let t = new_thing(&mut lp, 0);
    let marker = "EXPIRED-MARK-77aa";
    let c = set(&mut lp, 0, t, &BRIEF, &big(marker));
    filler(&mut lp, 0, 6);
    lp.advance(3_600_001);
    lp.peers[0].tick().unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&c, &t, &ak("t:brief.0")));
    assert!(!recoverable(&mut lp.peers[0], marker.as_bytes()), "expired content recovered");
}

// spec/commits.md §5 (purge on replace): the replacing node drops the body in the killing
// transaction; no local copy survives
#[test]
fn purged_on_replace_unrecoverable_spec_commits_5() {
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

// spec/commits.md §5 (purge on replace), spec/requirements.md (Scale: O(change)): in a paged map
// state, the dropped body's pages are rewritten shredded (not the whole state); no copy of the
// superseded entry value survives
#[test]
fn purged_on_replace_paged_unrecoverable_spec_commits_5() {
    let mut lp = net2(75);
    let t = new_thing(&mut lp, 0);
    let fill: osis_base::ValueMap = (0..66).map(|i| (s(&format!("k{i:03}")), s(&"f".repeat(1100)))).collect();
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
    let fill: osis_base::ValueMap = (0..66).map(|i| (s(&format!("k{i:03}")), s(&"f".repeat(1100)))).collect();
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
    lp.peers[0].tick().unwrap();
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
    lp.peers[0].tick().unwrap();
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
    let opens = |p: &mut Peer| found_in(p, marker).iter().any(|f| matches!(f, osis_store::Source::Blob { .. }));
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

// spec/commits.md §5 (purge on replace: the writer covers what its edit replaced in that
// transaction): an erasing edit of a big record (compacted, or an ordinary commit) drops the
// replaced body in the edit's transaction, and no local copy of the erased entry survives. The
// cost is a snapshot of the record (spec/requirements.md Scale, the cost the app chooses).
#[test]
fn erasing_edit_drops_replaced_body_unrecoverable_spec_commits_5() {
    for compact in [true, false] {
        let mut lp = net2(77);
        let t = new_thing(&mut lp, 0);
        let marker = "LIVE-ATMOST-MARK-c90d";
        let mut fill: osis_base::ValueMap = (0..300).map(|i| (s(&format!("k{i:03}")), s(&"f".repeat(1100)))).collect();
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
        let mut m = Mutation::new();
        m.op(t, &GONEMAP, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(s("secret")) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        assert!(!lp.peers[0].engine.body_not_dropped(&body, &t, &k), "compact {compact}: dropped in the erasing transaction");
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
    let at = osis_base::WallMs(lp.peers[0].engine.now().0 + 3_600_000);
    let mut m = Mutation::new();
    m.set(t, &BRIEF, &s(&big(marker))).unwrap();
    m.set(t, &REG, &s("plain")).unwrap();
    // one expiry per commit (spec/commits.md §6)
    m.expires(t, &BRIEF, at).unwrap();
    m.expires(t, &REG, at).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.packages(0).unwrap().into_iter().find(|p| p.id == c).unwrap();
    let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let brief = b.header.aspects.iter().position(|a| a.ak.as_str() == "t:brief.0").unwrap();
    b.parts.retain(|x| x.ai != brief);
    lp.peers[1].receive(&b.encode(), pk.blobs.clone()).unwrap();
    filler(&mut lp, 1, 6);
    lp.advance(3_600_001);
    lp.peers[1].tick().unwrap();
    // taken (`retention::takes_late`): joined, then dropped again
    assert!(matches!(lp.peers[1].receive(&pk.bytes, pk.blobs.clone()).unwrap(), osis_node::Ingested::Applied(_)));
    filler(&mut lp, 1, 6);
    assert!(!lp.peers[1].engine.body_not_dropped(&c, &t, &ak("t:brief.0")));
    assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "expired content recovered from the late part");
}

// spec/commits.md §4 (a commit with no part held applies as its header alone): peer 1 gets peer 0's
// expiring write on a thing whose creation record it lacks, past T: nothing of it is kept (spec/commits.md
// §4 Unjudgeable), whether peer 1 syncs the thing or not; fetched again with its record, the part
// past T counts as never received and the commit applies as its header.
#[test]
fn partless_commit_applies_as_its_header_spec_commits_4() {
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
        assert!(matches!(lp.deliver(1, &pk).unwrap(), osis_node::Ingested::Awaits(_, _)), "syncing {syncing}: cannot be judged");
        lp.sync(0, 1).unwrap();
        assert!(lp.peers[1].engine.commit_ids().contains(&c) && lp.peers[1].engine.pending().iter().all(|x| x.0 != c), "syncing {syncing}");
        assert_eq!(lp.peers[1].engine.get_typed(&t, &BRIEF).unwrap(), None, "syncing {syncing}");
    }
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
            lp.peers[1].reexamine().unwrap();
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
                0 => drop(lp.peers[1].receive(&part.encode(), Vec::new()).unwrap()),
                1 => drop(lp.deliver(1, &request).unwrap()),
                _ => drop(lp.peers[1].receive(&rest.encode(), Vec::new()).unwrap()),
            }
            lp.peers[1].reexamine().unwrap();
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

// spec/commits.md §5: a part a held request purges, past its expiry when its commit's other part
// comes, goes: nothing is left for a relay's empty slot to bring back.
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
    // one expiry per commit (spec/commits.md §6)
    m.expires(t, &LIST, exp).unwrap();
    m.expires(y, &REG, exp).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(q, &REG, &s("q")).unwrap();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    let request = lp.peers[0].engine.package(&p).unwrap().unwrap();
    lp.deliver(1, &request).unwrap();
    lp.peers[1].receive(&part_on(&pk, t, &ak("t:reg.0"), false), Vec::new()).unwrap();
    assert!(!lp.peers[1].engine.body_not_dropped(&c, &t, &ak("t:reg.0")), "purged");
    lp.peers[1].clock.advance(120_000);
    lp.peers[1].receive(&part_on(&pk, y, &ak("t:reg.0"), false), Vec::new()).unwrap();
    assert!(lp.peers[1].engine.commit_ids().contains(&c) && lp.peers[1].engine.pending().is_empty(), "{:?}", lp.peers[1].engine.pending());
    assert_eq!(lp.peers[1].engine.stripped_count(&c).unwrap(), 0);
    let _ = lp.peers[1].receive(&part_on(&pk, t, &ak("t:reg.0"), true), Vec::new());
    assert!(lp.peers[1].engine.pending().is_empty());
    assert!(!recoverable(&mut lp.peers[1], b"SECRET-R5b"));
}

// spec/commits.md §4, §5, §6, spec/crdt.md §4.7: a commit past its expiry, every part of it (one
// expiry per commit), given with a true part and a relay's junk (a stripped slot) and without its
// third part: nothing waits for it, so it applies at once, no aspect is
// flagged (no part went while pending), and the true part joins value-less: the older value is
// superseded, as at a node that held the commit before T.
#[test]
fn junk_beside_a_part_past_expiry_raises_no_flag_spec_commits_5() {
    let mut lp = net2(302);
    let (t, y) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    let mut m = Mutation::new();
    m.set(t, &REG, &s("old")).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync(0, 1).unwrap();
    lp.advance(5);
    let exp = osis_base::WallMs(lp.peers[0].engine.now().0 + 60_000);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("a")).unwrap();
    m.set(t, &BRIEF, &s("b")).unwrap();
    m.set(y, &REG, &s("y")).unwrap();
    for (x, k) in [(t, &REG), (t, &BRIEF), (y, &REG)] {
        m.expires(x, k, exp).unwrap();
    }
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    lp.peers[1].clock.advance(120_000);
    let mut b = osis_commit::CommitBlob::decode(&part_on(&pk, t, &ak("t:reg.0"), false)).unwrap();
    b.parts.extend(osis_commit::CommitBlob::decode(&part_on(&pk, t, &ak("t:brief.0"), true)).unwrap().parts);
    b.parts.sort_by_key(|p| p.ai);
    let r = lp.peers[1].receive(&b.encode(), Vec::new()).unwrap();
    assert!(!matches!(r, osis_node::Ingested::Pending(..)), "{r:?}");
    lp.peers[1].reexamine().unwrap();
    assert!(lp.peers[1].engine.pending().is_empty(), "{:?}", lp.peers[1].engine.pending());
    assert!(lp.peers[1].engine.commit_ids().contains(&c));
    assert!(lp.peers[1].engine.suspects().unwrap().is_empty());
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), None, "the true part joined value-less");
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:brief.0")).unwrap(), None);
    // the writer past T reads the same
    lp.peers[0].clock.advance(120_000);
    lp.peers[0].tick().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap(), None);
    assert_eq!(lp.peers[0].engine.state_digest(&t, &ak("t:reg.0")).unwrap(), lp.peers[1].engine.state_digest(&t, &ak("t:reg.0")).unwrap());
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
    // one expiry per commit (spec/commits.md §6)
    for (x, k) in [(t, &REG), (t, &LIST), (t2, &BRIEF)] {
        m.expires(x, k, exp).unwrap();
    }
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
                    p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
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
                            p.tick().unwrap();
                        }
                    }
                    if i == 3 && at % 2 == 1 {
                        p = reopened(p, at as u64);
                    }
                    let _ = p.receive(&items[*x].0, items[*x].1.clone());
                    p.reexamine().unwrap();
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
                    let _ = p.receive(&items[x].0, items[x].1.clone());
                    p.reexamine().unwrap();
                }
                p.tick().unwrap();
                p.reexamine().unwrap();
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
    // every part expires with the commit (spec/commits.md §6): the list's element too, and with
    // it the list (a value-less creation makes nothing present, spec/crdt.md §4.3)
    assert!(only.starts_with("gone true applied true pending [] stripped 0 flags [] reads None None None"), "{only}");
}

// spec/commits.md §4, §5: a purged permanent delta reads alike whatever came first and whatever the
// node syncs: its body, its header-only blob, the purge request (or the request's own header-only
// blob with a snapshot listing its delta), a restart anywhere among them. Each ends with the commit
// applied without its body, the purge named, nothing waiting, nothing of the value recoverable.
// The default test runs every third case (orders by restart points); the property all.
#[test]
fn tombstone_alike_spec_commits_5() {
    tombstone_alike(3);
}

// As above, every order and restart point.
#[test]
#[ignore = "property"]
fn tombstone_alike_in_every_order_exhaustive_spec_commits_5() {
    tombstone_alike(1);
}

/// Every `stride`th case (3 is coprime with the 4 and 5 restart points of an order).
fn tombstone_alike(stride: u64) {
    use osis_commit::CommitBlob;
    let forever = osis_schema::Retention { by: osis_schema::PurgeBy::AuthorOrAdmin };
    let marker = "TOMBSTONE-SECRET-8e1a";
    let mut lp = net2(611);
    let setup = lp.packages(0).unwrap();
    let t = new_thing_keeping(&mut lp, 0, &[("t:reg.0", osis_schema::History::FOREVER)]);
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
    let header = |b: &[u8]| osis_commit::rewrite(&CommitBlob::decode(b).unwrap(), |_| true).encode();
    let item = |pk: &osis_node::local_peer::Package| (pk.bytes.clone(), pk.blobs.clone());
    let (cw, ch, pw, ph, zw, rc) = (item(&whole), (header(&whole.bytes), Vec::new()), item(&request), (header(&request.bytes), Vec::new()), item(&snap), item(&rec[0]));
    let sets = [("body, header and request", vec![cw.clone(), ch.clone(), pw.clone(), rc.clone()]), ("header and request", vec![ch.clone(), pw, rc.clone()]), ("two headers and a snapshot", vec![ch, ph, zw, rc])];
    // every case, then those of this stride on a thread per core: each is its own node
    let mut cases = 0;
    let mut jobs = Vec::new();
    for (k, (_, items)) in sets.iter().enumerate() {
        let mut orders: Vec<Vec<usize>> = vec![Vec::new()];
        for i in 0..items.len() {
            orders = orders.iter().flat_map(|q| (0..=q.len()).map(move |at| { let mut x = q.clone(); x.insert(at, i); x })).collect();
        }
        for syncing in [true, false] {
            for order in &orders {
                for restart in 0..=order.len() {
                    cases += 1;
                    if cases % stride == 0 {
                        jobs.push((k, syncing, order.clone(), restart, cases));
                    }
                }
            }
        }
    }
    let one = |j: u64| {
        osis_base::testenv::caught(|| {
            let (k, syncing, order, restart, case) = &jobs[j as usize];
            let (what, items) = &sets[*k];
            let mut p = peer(7000 + case);
            for pk in &setup {
                p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
            }
            if *syncing {
                p.engine.set_syncing(t, true).unwrap();
            }
            for (at, i) in order.iter().enumerate() {
                if at == *restart {
                    p = reopened(p, 8000 + case);
                }
                p.receive(&items[*i].0, items[*i].1.clone()).unwrap();
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
            if *restart == order.len() {
                assert!(!recoverable(&mut p, marker.as_bytes()), "{at}: recoverable");
            }
            Ok(())
        })
    };
    let idx: Vec<u64> = (0..jobs.len() as u64).collect();
    let fails: Vec<String> = osis_base::testenv::par_map(&idx, osis_base::testenv::threads("OSIS_SEED_THREADS"), one).into_iter().filter_map(Result::err).collect();
    assert!(fails.is_empty(), "{} of {} cases failed, the first: {}", fails.len(), jobs.len(), fails[0]);
    // every case counted: both sync modes, each order, each restart point
    assert_eq!(cases, 2 * (24 * 5 + 6 * 4 + 24 * 5));
}

// spec/sync.md §6: a purge request becomes must-hold when the delta it names arrives after it: the
// purge commit is judged again then, not only at its own changes.
#[test]
fn request_is_judged_again_when_the_named_delta_arrives_spec_sync_6() {
    let forever = osis_schema::Retention { by: osis_schema::PurgeBy::AuthorOrAdmin };
    let mut lp = net2(631);
    let t = new_thing_keeping(&mut lp, 0, &[("t:reg.0", osis_schema::History::FOREVER)]);
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

/// Node 0's paged map on `t` over an older value node 1 holds, by commit `c` (`whole`: its package), and a
/// request naming it that resets nothing; node 1 holds `c` with its last page away, then the request.
fn purged_page_away(lp: &mut LocalPeer, marker: &str) -> (Tid, osis_base::CommitId, osis_node::local_peer::Package) {
    let a = ak("t:big.0");
    let t = new_thing(lp, 0);
    let mut m = Mutation::new();
    m.set(t, &BIG, &Value::Map(osis_base::ValueMap::from([(s("older"), s("kept"))]))).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync(0, 1).unwrap();
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    lp.advance(5);
    // the marker in every entry, so whichever page stays away the held ones carry it
    let fill: osis_base::ValueMap = (0..400).map(|i| (s(&format!("k{i:03}")), s(&format!("{marker}{}", "f".repeat(1100))))).collect();
    let mut m = Mutation::new();
    m.set(t, &BIG, &Value::Map(fill)).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let whole = lp.peers[0].engine.package(&c).unwrap().unwrap();
    assert!(whole.blobs.len() > 1, "paged: {} blobs, {} bytes", whole.blobs.len(), whole.bytes.len());
    let mut held = whole.blobs.clone();
    held.pop();
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: a });
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    let request = lp.peers[0].engine.package(&p).unwrap().unwrap();
    lp.peers[1].receive(&whole.bytes, held).unwrap();
    lp.peers[1].reexamine().unwrap();
    assert!(lp.peers[1].engine.pending().iter().any(|x| x.0 == c), "it waits for its page");
    assert!(recoverable(&mut lp.peers[1], marker.as_bytes()), "held so far");
    lp.deliver(1, &request).unwrap();
    lp.peers[1].reexamine().unwrap();
    (t, c, whole)
}

// spec/commits.md §5: a waiting part a held request names goes at once while a page of it is away (the
// part's bytes cannot be stripped), the pages it holds readable no more; its commit then applies and the
// aspect is flagged, its non-value writes missing.
#[test]
fn purged_with_a_page_away_goes_at_once_spec_commits_5() {
    let marker = "PAGE-AWAY-4c8e";
    let mut lp = net2(341);
    let (t, c, _) = purged_page_away(&mut lp, marker);
    let e = &mut lp.peers[1].engine;
    assert!(e.pending().is_empty() && e.commit_ids().contains(&c), "{:?}", e.pending());
    assert_eq!(e.suspects().unwrap().into_iter().map(|x| (x.0, x.1)).collect::<Vec<_>>(), vec![(t, ak("t:big.0"))]);
    assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "recovered with a page away");
}

// spec/commits.md §5: the older value a part gone with a page away leaves showing, flagged, goes with a
// snapshot by a writer or a copy arriving again, and neither brings back the purged value.
#[test]
fn flagged_read_of_a_part_gone_with_a_page_away_is_repaired_spec_commits_5() {
    for by_snapshot in [true, false] {
        let marker = "PAGE-REPAIR-5d1a";
        let mut lp = net2(351);
        let a = ak("t:big.0");
        let (t, _, whole) = purged_page_away(&mut lp, marker);
        assert_eq!(lp.peers[1].engine.get(&t, &a).unwrap(), Some(Value::Map(osis_base::ValueMap::from([(s("older"), s("kept"))]))), "by snapshot {by_snapshot}");
        assert_eq!(lp.peers[1].engine.suspects().unwrap().len(), 1);
        if by_snapshot {
            lp.advance(5);
            let sc = lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
            let pk = lp.peers[0].engine.package(&sc).unwrap().unwrap();
            lp.deliver(1, &pk).unwrap();
        } else {
            lp.peers[1].receive(&whole.bytes, whole.blobs.clone()).unwrap();
        }
        lp.peers[1].reexamine().unwrap();
        assert_eq!(lp.peers[1].engine.get(&t, &a).unwrap(), lp.peers[0].engine.get(&t, &a).unwrap(), "by snapshot {by_snapshot}");
        assert!(lp.peers[1].engine.suspects().unwrap().is_empty(), "by snapshot {by_snapshot}");
        assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "by snapshot {by_snapshot}");
    }
}

// spec/commits.md §5 (holding a body as its leftover destroys every copy of its values), spec/crdt.md
// §4.7: a snapshot stripped for one purged delta still carries the other values it copied; a second
// request purging one of those replaces the leftover, and the old leftover row's bytes must go with
// it (was: the row was overwritten unshredded, so the old page kept the value).
#[test]
fn snapshot_leftover_stripped_again_unrecoverable_spec_commits_5() {
    let mut lp = net2(81);
    let t = new_thing_keeping(&mut lp, 0, &[("t:text.0", DAY)]);
    lp.sync(0, 1).unwrap();
    let k = ak("t:big.0");
    let (mx, my) = ("SNAPX-MARK-1a2b", "SNAPY-MARK-3c4d");
    let put = |lp: &mut LocalPeer, key: &str, val: &str| {
        let mut m = Mutation::new();
        m.op(t, &BIG, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(key))], op: osis_crdt::Op::Set(s(val)) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let cx = put(&mut lp, "kx", &big(mx));
    lp.advance(5);
    let cy = put(&mut lp, "ky", &big(my));
    lp.advance(5);
    let snap = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.sync(0, 1).unwrap();
    filler(&mut lp, 0, 6);
    filler(&mut lp, 1, 6);
    lp.advance(5);
    let purge = |lp: &mut LocalPeer, c, key: &str| {
        let mut m = Mutation::new();
        m.op(t, &BIG, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(key))], op: osis_crdt::Op::Set(s("w")) }).unwrap();
        m.purge(PurgeItem::Commit { commit: c, tid: t, ak: k.clone() });
        lp.peers[0].commit(m).unwrap().unwrap();
    };
    purge(&mut lp, cx, "ox");
    lp.sync(0, 1).unwrap();
    for i in [0, 1] {
        let e = &mut lp.peers[i].engine;
        let sai = e.header(&snap).unwrap().aspects.iter().position(|a| a.tid == t && a.ak == k).unwrap();
        let m = e.core.ix.commits.get(&snap).unwrap();
        assert!(m.stripped.contains(&sai), "peer {i}: the snapshot carrying the purged value is held as its leftover");
        assert!(!recoverable(&mut lp.peers[i], mx.as_bytes()), "peer {i}: the first purged value recovered");
    }
    filler(&mut lp, 0, 6);
    filler(&mut lp, 1, 6);
    lp.advance(5);
    purge(&mut lp, cy, "oy");
    lp.sync(0, 1).unwrap();
    filler(&mut lp, 0, 6);
    filler(&mut lp, 1, 6);
    for i in [0, 1] {
        assert_eq!(lp.peers[i].engine.get_at(&t, &k, &[osis_crdt::PathSeg::Key(s("ky"))]).unwrap(), None, "peer {i}");
        let [x, y] = recovered(&mut lp.peers[i], [mx.as_bytes(), my.as_bytes()]);
        assert!(!x && !y, "peer {i}: purged values recovered from the replaced leftover: x {x}, y {y}");
    }
}

/// Node 1 holds snapshot `snap` of `t:big.0` carrying `cx` (marker `mx`) and `cy` (`my`), both
/// by 0; admin 2 purged `cx` (the snapshot held as its leftover), then 0 demoted 2 without having
/// seen the request: it fell at 1, the snapshot still held as its leftover.
struct Fallen {
    lp: LocalPeer,
    t: Tid,
    cy: osis_base::CommitId,
    my: &'static str,
}

fn fallen_snapshot_rig(seed: u64) -> Fallen {
    use osis_base::Role;
    use osis_node::flows::Demotion;
    let mut lp = LocalPeer::of(vec![peer(seed), peer(seed + 1), peer(seed + 2)], seed);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let x = lp.peers[2].engine.me();
    lp.peers[0].engine.grant(&t, &x, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let k = ak("t:big.0");
    let (mx, my) = ("ASIDEX-MARK-5e6f", "ASIDEY-MARK-7a8b");
    let cx = big_put(&mut lp, 0, t, "kx", &big(mx), None);
    lp.advance(5);
    let cy = big_put(&mut lp, 0, t, "ky", &big(my), None);
    lp.advance(5);
    let snap = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.sync_all().unwrap();
    filler(&mut lp, 1, 6);
    lp.advance(5);
    let p1 = big_put(&mut lp, 2, t, "ox", "w", Some(cx));
    let pk = lp.peers[2].engine.package(&p1).unwrap().unwrap();
    lp.deliver(1, &pk).unwrap();
    lp.peers[1].reexamine().unwrap();
    let sai = lp.peers[1].engine.header(&snap).unwrap().aspects.iter().position(|a| a.tid == t && a.ak == k).unwrap();
    assert!(lp.peers[1].engine.core.ix.commits.get(&snap).unwrap().stripped.contains(&sai), "the snapshot is held as its leftover");
    lp.advance(5);
    let done = lp.peers[0].engine.demote(&t, &Demotion { holder: x, new: None, retain: None }).unwrap();
    for id in &done.commits {
        let pk = lp.peers[0].engine.package(id).unwrap().unwrap();
        lp.deliver(1, &pk).unwrap();
    }
    lp.peers[1].reexamine().unwrap();
    let m = lp.peers[1].engine.core.ix.commits.get(&snap).unwrap();
    assert!(m.stripped.contains(&sai) && !m.missing.contains(&sai), "fallen: the snapshot stays held as its leftover");
    Fallen { lp, t, cy, my }
}

/// Node `i` writes `val` at key `key` of `t:big.0`, purging `purge` if given.
fn big_put(lp: &mut LocalPeer, i: usize, t: Tid, key: &str, val: &str, purge: Option<osis_base::CommitId>) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.op(t, &BIG, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(key))], op: osis_crdt::Op::Set(s(val)) }).unwrap();
    if let Some(c) = purge {
        m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:big.0") });
    }
    lp.peers[i].commit(m).unwrap().unwrap()
}

// spec/commits.md §5 (a purge destroys every local copy of the values it names), spec/crdt.md §4.7:
// a snapshot's leftover keeps the other values it copied and stays held through its purge's fall,
// so a second request purging one of those strips it there too and leaves no copy behind.
// spec/commits.md §5: the leftover indexes as an open rebuilding the index reads it.
#[test]
fn fallen_snapshot_leftover_gone_for_a_later_purge_spec_commits_5() {
    let Fallen { mut lp, t, cy, my } = fallen_snapshot_rig(371);
    let e = &mut lp.peers[1].engine;
    let opened = e.index_digest().without_held();
    e.rebuild_index().unwrap();
    assert_eq!(opened.first_diff(&e.index_digest().without_held()), None);
    filler(&mut lp, 1, 6);
    lp.advance(5);
    let p2 = big_put(&mut lp, 0, t, "oy", "w", Some(cy));
    let pk = lp.peers[0].engine.package(&p2).unwrap().unwrap();
    lp.deliver(1, &pk).unwrap();
    lp.peers[1].reexamine().unwrap();
    filler(&mut lp, 1, 6);
    assert_eq!(lp.peers[1].engine.get_at(&t, &ak("t:big.0"), &[osis_crdt::PathSeg::Key(s("ky"))]).unwrap(), None);
    assert!(!recoverable(&mut lp.peers[1], my.as_bytes()), "the second purged value recovered from the fallen snapshot's leftover");
}

/// Puts entry `key` of `t`'s `t:map.0` (`map<string, item>`), `expires` at that wall time.
fn put_entry(lp: &mut LocalPeer, t: Tid, key: &str, expires: Option<u64>) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.op(t, &MAP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(key))], op: osis_crdt::Op::Set(item("v", 1)) }).unwrap();
    if let Some(e) = expires {
        m.expires(t, &MAP, osis_base::WallMs(e)).unwrap();
    }
    lp.peers[0].commit(m).unwrap().unwrap()
}

/// Writes `n` into entry `key` of `t`'s `t:map.0`: a body repeating the key.
fn into_entry(lp: &mut LocalPeer, t: Tid, key: &str, n: i64) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.op(t, &MAP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(key)), osis_crdt::PathSeg::Field(1)], op: osis_crdt::Op::Set(Value::Int(n)) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap()
}

// spec/crdt.md §4.7, §5.6, spec/commits.md §5: a purge of an entry's creation takes the creation's
// values only: a later edit into the entry carries the key as its own value and keeps the entry,
// on both nodes; purged too, nothing of the key is left
#[test]
fn purge_leaves_later_edits_own_key_spec_crdt_4_7() {
    let mut lp = net2(79);
    let t = new_thing(&mut lp, 0);
    let marker = "ENTRY-KEY-MARK-3f0b";
    let k = ak("t:map.0");
    let made = put_entry(&mut lp, t, marker, None);
    lp.advance(5);
    let edit = into_entry(&mut lp, t, marker, 2);
    lp.sync(0, 1).unwrap();
    filler(&mut lp, 0, 6);
    assert!(recoverable(&mut lp.peers[0], marker.as_bytes()), "the attack finds live content");
    lp.advance(5);
    let purge = |lp: &mut LocalPeer, c: osis_base::CommitId, other: &str| {
        let mut m = Mutation::new();
        m.op(t, &MAP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(other))], op: osis_crdt::Op::Set(item("w", 3)) }).unwrap();
        m.purge(PurgeItem::Commit { commit: c, tid: t, ak: k.clone() });
        lp.peers[0].commit(m).unwrap();
        lp.sync(0, 1).unwrap();
    };
    purge(&mut lp, made, "other");
    let at = |f: u64| [osis_crdt::PathSeg::Key(s(marker)), osis_crdt::PathSeg::Field(f)];
    for i in [0, 1] {
        assert_eq!(lp.peers[i].engine.get_at(&t, &k, &at(1)).unwrap(), Some(Value::Int(2)), "peer {i}: the edit's value keeps the entry");
        assert_eq!(lp.peers[i].engine.get_at(&t, &k, &at(0)).unwrap(), None, "peer {i}: the creation's value went");
    }
    lp.advance(5);
    purge(&mut lp, edit, "other2");
    for i in [0, 1] {
        assert!(!recoverable(&mut lp.peers[i], marker.as_bytes()), "peer {i}: the purged key recovered");
    }
}

// spec/crdt.md §4.7, §5.6: an edit into an expiring entry keeps its own expiry (none) and, past the
// entry's T, the entry under its own copy of the key
#[test]
fn edit_into_expiring_entry_keeps_its_expiry_spec_crdt_4_7() {
    let mut lp = net2(80);
    let t = new_thing(&mut lp, 0);
    let marker = "EXPIRING-KEY-MARK-91c4";
    let t_end = lp.peers[0].engine.now().0 + 60_000;
    let made = put_entry(&mut lp, t, marker, Some(t_end));
    put_entry(&mut lp, t, "kept", None);
    lp.advance(5);
    let edit = into_entry(&mut lp, t, marker, 2);
    let other = into_entry(&mut lp, t, "kept", 3);
    assert_eq!(lp.peers[0].engine.header(&made).unwrap().expires, Some(t_end));
    assert_eq!(lp.peers[0].engine.header(&edit).unwrap().expires, None, "the edit's key is its own");
    assert_eq!(lp.peers[0].engine.header(&other).unwrap().expires, None);
    lp.sync(0, 1).unwrap();
    filler(&mut lp, 0, 6);
    lp.advance(60_001);
    for i in [0, 1] {
        lp.peers[i].tick().unwrap();
    }
    let at = |key: &str, f: u64| [osis_crdt::PathSeg::Key(s(key)), osis_crdt::PathSeg::Field(f)];
    for i in [0, 1] {
        assert_eq!(lp.peers[i].engine.get_at(&t, &ak("t:map.0"), &at(marker, 1)).unwrap(), Some(Value::Int(2)), "peer {i}: the edit outlives the entry's creation");
        assert_eq!(lp.peers[i].engine.get_at(&t, &ak("t:map.0"), &at(marker, 0)).unwrap(), None, "peer {i}: the creation's value expired");
        assert_eq!(lp.peers[i].engine.get_at(&t, &ak("t:map.0"), &at("kept", 1)).unwrap(), Some(Value::Int(3)));
    }
}

// spec/crdt.md §4.7, §5.7, spec/commits.md §5: an undo of a text delete carries the chars as its
// own values (an undelete): a purge of the insert leaves them, one of the undo too takes them
#[test]
fn undelete_chars_are_their_own_values_spec_crdt_4_7() {
    let mut lp = net2(81);
    let t = new_thing_keeping(&mut lp, 0, &[("t:text.0", DAY)]);
    let marker = "UNDELETE-MARK-6d2a";
    let k = ak("t:text.0");
    let text = |lp: &mut LocalPeer, v: &str| {
        let mut m = Mutation::new();
        m.set(t, &TEXT, &s(v)).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let made = text(&mut lp, marker);
    lp.advance(5);
    let del = text(&mut lp, "");
    lp.advance(5);
    let mut m = Mutation::new();
    m.undo(del);
    let undo = lp.peers[0].commit(m).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &k).unwrap(), Some(s(marker)));
    lp.sync(0, 1).unwrap();
    filler(&mut lp, 0, 6);
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("x")).unwrap();
    m.purge(PurgeItem::Commit { commit: made, tid: t, ak: k.clone() });
    lp.peers[0].commit(m).unwrap();
    lp.sync(0, 1).unwrap();
    for i in [0, 1] {
        assert_eq!(lp.peers[i].engine.get(&t, &k).unwrap(), Some(s(marker)), "peer {i}: the undelete's chars show");
    }
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("y")).unwrap();
    m.purge(PurgeItem::Commit { commit: undo, tid: t, ak: k.clone() });
    lp.peers[0].commit(m).unwrap();
    lp.sync(0, 1).unwrap();
    for i in [0, 1] {
        assert!(!recoverable(&mut lp.peers[i], marker.as_bytes()), "peer {i}: the purged chars recovered");
    }
}

// spec/requirements.md Deletion (undo never brings back what another party purged), spec/crdt.md
// §4.6 (undo revives nothing): a value is set, removed, and its set
// purged; undoing the removal (the node's own recent commit) writes none of it back, here or at
// the other node. Every write keeps history, so the undo is not refused for replacing unkept
// content (spec/commits.md §7).
#[test]
fn undo_revives_no_purged_value_spec_crdt_4_6() {
    let mut lp = net2(86);
    let mut m = Mutation::new();
    let me = lp.peers[0].engine.me();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    keep_in(&mut m, t, &setting(&[("t:reg.0", DAY)]));
    lp.peers[0].commit(m).unwrap();
    let marker = "PURGED-UNDO-5c1e";
    let k = ak("t:reg.0");
    let mut m = Mutation::new();
    m.set(t, &REG, &s(marker)).unwrap();
    let made = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.remove_aspect(t, &REG).unwrap();
    let removed = lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync(0, 1).unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &TEXT, &s("x")).unwrap();
    m.purge(PurgeItem::Commit { commit: made, tid: t, ak: k.clone() });
    lp.peers[0].commit(m).unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.undo(removed);
    lp.peers[0].engine.write(m).unwrap();
    lp.sync(0, 1).unwrap();
    for i in [0, 1] {
        assert_eq!(lp.peers[i].engine.get(&t, &k).unwrap(), None, "peer {i}");
        assert!(!recoverable(&mut lp.peers[i], marker.as_bytes()), "peer {i}: the purged value recovered");
    }
}

// spec/requirements.md Deletion (granularity is one edit of one aspect; who may purge it):
// 1 writes message `e`; 0 (the first admin) reacts to `e` and posts message `m2` in one delta `d`, then
// edits `m2` in `c`. 1, `e`'s author, purges `e`. Only `e`'s values go: `d` and `c` are 0's edits,
// which 1 has no right to purge, and `d`'s reaction keeps `e` under its own copy of the key.
#[test]
fn purge_spares_other_values_of_a_carrier_spec_commits_5() {
    use osis_crdt::{Op, PathOp, PathSeg};
    let mut lp = net(2, 82);
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.me();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(osis_base::Role::Write)), None);
    lp.sync(0, 1).unwrap();
    let k = ak("t:map.0");
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("e"))], op: Op::Set(item("E-MARK", 1)) }).unwrap();
    // its author purges it below
    m.retention(t, &MAP, crate::common::purgeable_by(osis_base::PurgeBy::AuthorOrAdmin)).unwrap();
    let e = lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync(1, 0).unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("e")), PathSeg::Field(1)], op: Op::Set(Value::Int(2)) }).unwrap();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("m2"))], op: Op::Set(item("M2-MARK", 7)) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("m2")), PathSeg::Field(1)], op: Op::Set(Value::Int(9)) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync(0, 1).unwrap();
    let m2 = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.get_at(&t, &k, &[PathSeg::Key(s("m2"))]).unwrap();
    assert_eq!(m2(&mut lp, 1), Some(item("M2-MARK", 9)));
    lp.advance(5);
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("other"))], op: Op::Set(item("w", 3)) }).unwrap();
    m.purge(PurgeItem::Commit { commit: e, tid: t, ak: k.clone() });
    lp.peers[1].commit(m).unwrap();
    lp.sync(1, 0).unwrap();
    for i in [0, 1] {
        assert_eq!(lp.peers[i].engine.get_at(&t, &k, &[PathSeg::Key(s("e")), PathSeg::Field(0)]).unwrap(), None, "peer {i}: e purged");
        assert_eq!(lp.peers[i].engine.get_at(&t, &k, &[PathSeg::Key(s("e")), PathSeg::Field(1)]).unwrap(), Some(Value::Int(2)), "peer {i}: the reaction kept");
        assert_eq!(m2(&mut lp, i), Some(item("M2-MARK", 9)), "peer {i}: 0's message and edit kept");
    }
}

// spec/requirements.md Data model, spec/crdt.md §4.7: 0 reacts to an expiring message `e` and posts a
// lasting message `m2` in one write: the commit takes no expiry, the reaction its own. Past `e`'s T
// only `e`'s own value is gone: the reaction keeps `e`, and `m2` and its edit stay.
#[test]
fn reaction_outlives_expiring_message_spec_crdt_4_7() {
    use osis_crdt::{Op, PathOp, PathSeg};
    let mut lp = net(1, 83);
    let t = new_thing(&mut lp, 0);
    let k = ak("t:map.0");
    let t_end = lp.peers[0].engine.now().0 + 60_000;
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("e"))], op: Op::Set(item("E-MARK", 1)) }).unwrap();
    m.expires(t, &MAP, osis_base::WallMs(t_end)).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("e")), PathSeg::Field(1)], op: Op::Set(Value::Int(2)) }).unwrap();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("m2"))], op: Op::Set(item("M2-MARK", 7)) }).unwrap();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("m2")), PathSeg::Field(1)], op: Op::Set(Value::Int(9)) }).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.header(&c).unwrap().expires, None, "the reaction's own expiry");
    lp.advance(60_001);
    lp.peers[0].tick().unwrap();
    assert_eq!(lp.peers[0].engine.get_at(&t, &k, &[PathSeg::Key(s("e"))]).unwrap(), Some(Value::Map([(Value::Int(1), Value::Int(2))].into_iter().collect())), "e's own value expired, the reaction kept");
    assert_eq!(lp.peers[0].engine.get_at(&t, &k, &[PathSeg::Key(s("m2"))]).unwrap(), Some(item("M2-MARK", 9)), "m2 and its edit kept");
}

// spec/crdt.md §4.6 (undo expiry): 0 removes an expiring entry and a lasting
// one in one write. Its undo would write both back in one commit with one expiry: refused, so the
// lasting entry never takes the other's. Past the expiring entry's T nothing of it is written
// back and the undo restores the lasting entry, which stays.
#[test]
fn undo_copying_two_expiries_waits_spec_crdt_4_6() {
    use osis_crdt::{Op, PathOp, PathSeg};
    let mut lp = net(1, 84);
    let t = new_thing_keeping(&mut lp, 0, &[("t:map.0", DAY)]);
    let k = ak("t:map.0");
    let t_end = lp.peers[0].engine.now().0 + 60_000;
    for (key, end) in [("e", Some(t_end)), ("kept", None)] {
        let mut m = Mutation::new();
        m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s(key))], op: Op::Set(item("v", 1)) }).unwrap();
        if let Some(e) = end {
            m.expires(t, &MAP, osis_base::WallMs(e)).unwrap();
        }
        lp.peers[0].commit(m).unwrap().unwrap();
    }
    lp.advance(5);
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: Vec::new(), op: Op::Remove(s("e")) }).unwrap();
    m.op(t, &MAP, PathOp { path: Vec::new(), op: Op::Remove(s("kept")) }).unwrap();
    let del = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(5);
    let held = lp.peers[0].engine.commit_ids().len();
    let r = lp.peers[0].engine.revert(&del);
    assert!(matches!(&r, Err(osis_node::Error::Clash(m)) if m.contains("one expiry")), "{r:?}");
    assert_eq!(lp.peers[0].engine.commit_ids().len(), held, "nothing applied");
    lp.advance(60_001);
    lp.peers[0].tick().unwrap();
    let u = lp.peers[0].engine.revert(&del).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.header(&u).unwrap().expires, None);
    assert_eq!(lp.peers[0].engine.get_at(&t, &k, &[PathSeg::Key(s("e"))]).unwrap(), None, "e expired");
    assert_eq!(lp.peers[0].engine.get_at(&t, &k, &[PathSeg::Key(s("kept"))]).unwrap(), Some(item("v", 1)));
}

// spec/commits.md §5 Purge (a snapshot has no values of its own: a request naming it takes nothing
// of it; every body carrying a purged value is held as its leftover whatever the order): a message,
// a snapshot carrying it, a later message and snapshot, and an aspect-wide request by their author,
// in every arrival order (the snapshots whole or as bare headers that a copy fills in later): the
// receiver keeps no purged value, lists the messages as purged and the snapshots as never purged,
// alike in every order, and so whether it holds a snapshot whole or dropped it as covered.
#[test]
fn purge_strips_carrying_snapshots_alike_in_every_order_spec_commits_5() {
    let k = ak("t:reg.0");
    let marker = "SECRET-SNAP-4e7a";
    let mut seen: Option<(Vec<osis_node::engine::listing::PartBody>, std::collections::BTreeMap<osis_base::CommitId, osis_base::CommitId>)> = None;
    for bare in [false, true] {
        for order in [[0usize, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
            let mut lp = net2(151);
            let t = new_thing(&mut lp, 0);
            lp.sync(0, 1).unwrap();
            lp.advance(5);
            let m1 = set(&mut lp, 0, t, &REG, marker);
            lp.advance(5);
            let s1 = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
            lp.advance(5);
            let m2 = set(&mut lp, 0, t, &REG, "later");
            lp.advance(5);
            let s2 = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
            lp.advance(5);
            let pk = |lp: &mut LocalPeer, c| lp.peers[0].engine.package(&c).unwrap().unwrap();
            let msgs = vec![pk(&mut lp, m1), pk(&mut lp, m2)];
            let snaps = vec![pk(&mut lp, s1), pk(&mut lp, s2)];
            let mut m = Mutation::new();
            m.set(t, &TEXT, &s("x")).unwrap();
            m.purge(PurgeItem::Aspect { tid: t, ak: k.clone() });
            let p = lp.peers[0].commit(m).unwrap().unwrap();
            let groups = [msgs, snaps.clone(), vec![pk(&mut lp, p)]];
            for g in order {
                for x in &groups[g] {
                    let mut x = x.clone();
                    if bare && g == 1 {
                        x.bytes = osis_commit::rewrite(&osis_commit::CommitBlob::decode(&x.bytes).unwrap(), |_| true).encode();
                    }
                    lp.deliver(1, &x).unwrap();
                }
                lp.peers[1].reexamine().unwrap();
            }
            if bare {
                // the snapshots' copies come after all
                for x in &snaps {
                    lp.deliver(1, x).unwrap();
                }
                lp.peers[1].reexamine().unwrap();
            }
            let e = &mut lp.peers[1].engine;
            let bodies: Vec<_> = [m1, m2, s1, s2].iter().map(|c| e.part(&t, &k, c, usize::MAX).unwrap().unwrap().body).collect();
            let purged = e.purged_on(&t, &k).unwrap();
            assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "bare {bare}, order {order:?}: the purged value kept");
            assert!(!purged.contains_key(&s1) && !purged.contains_key(&s2), "bare {bare}, order {order:?}: a snapshot listed purged {purged:?}");
            match &seen {
                None => seen = Some((bodies, purged)),
                Some(x) => assert_eq!(*x, (bodies, purged), "bare {bare}, order {order:?}"),
            }
            // compaction drops the older snapshot: still never purged
            let e = &mut lp.peers[1].engine;
            e.drop_body(&s1, &t, &k).unwrap();
            assert_eq!(e.part(&t, &k, &s1, usize::MAX).unwrap().unwrap().body, osis_node::engine::listing::PartBody::Dropped, "bare {bare}, order {order:?}");
            assert!(!e.purged_on(&t, &k).unwrap().contains_key(&s1), "bare {bare}, order {order:?}");
        }
    }
    let (bodies, purged) = seen.unwrap();
    assert!(matches!(bodies[0], osis_node::engine::listing::PartBody::Purged(_)), "{bodies:?}");
    assert!(matches!(bodies[1], osis_node::engine::listing::PartBody::Purged(_)), "{bodies:?}");
    assert!(purged.len() >= 2, "{purged:?}");
}
