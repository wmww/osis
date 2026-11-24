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
use osis_engine::local_peer::{LocalPeer, Peer};
use osis_engine::{Config, Engine, Mutation};
use osis_store::{MemoryBackend, MemoryRoot, StoreConfig};
use std::sync::Arc;

/// A peer over a small key tree (arity 4: few units share a leaf, so a shred elsewhere does
/// not incidentally rotate a leaked copy away) and small pages, recording every row written.
fn peer(seed: u64) -> Peer {
    let mut p = peer_bare(seed);
    p.engine.create_account().unwrap();
    p.engine.take_wakes();
    p
}

/// `peer` that joined no account yet.
fn peer_bare(seed: u64) -> Peer {
    let clock = Arc::new(ManualClock::new(T0));
    let (backend, root) = (MemoryBackend::new(), MemoryRoot::new());
    backend.record_history();
    let cfg = Config { store: StoreConfig { arity: 4, page_max: 512, ..StoreConfig::default() }, ..Config::default() };
    let c: Arc<dyn Clock> = clock.clone();
    let blob_disk = (MemoryBackend::new(), MemoryRoot::new());
    blob_disk.0.record_history();
    let mut engine = Engine::create(Box::new(backend.clone()), Box::new(root.clone()), osis_engine::local_peer::blob_area(&blob_disk, seed).unwrap(), cfg, c, Box::new(SeededRng::from_u64(seed))).unwrap();
    engine.take_wakes();
    let events = engine.subscribe();
    Peer { engine, clock, backend, root, blob_disk, events, restarts: 0, discarded: Vec::new(), discards: 0, redelivered: 0, pulled_anew: Default::default(), given: Default::default() }
}

/// `p` restarted over its durable state, as `peer` opens it.
fn reopened(p: Peer, seed: u64) -> Peer {
    let Peer { clock, backend, root, blob_disk, discarded, .. } = p;
    let cfg = Config { store: StoreConfig { arity: 4, page_max: 512, ..StoreConfig::default() }, ..Config::default() };
    let c: Arc<dyn Clock> = clock.clone();
    let mut engine = Engine::open(Box::new(backend.clone()), Box::new(root.clone()), osis_engine::local_peer::blob_area(&blob_disk, seed).unwrap(), cfg, c, Box::new(SeededRng::from_u64(seed))).unwrap();
    let events = engine.subscribe();
    let mut p = Peer { engine, clock, backend, root, blob_disk, events, restarts: 0, discarded, discards: 0, redelivered: 0, pulled_anew: Default::default(), given: Default::default() };
    p.fetch_discarded().unwrap();
    p
}

/// A node apart from `net2`'s; `FRESH + 1` reopens it on an rng stream of its own.
const FRESH: u64 = 2;

/// A `FRESH` node of peer `by`'s account (`pair_into`): it holds what it is given of `by`'s things.
fn node_of(lp: &mut LocalPeer, by: usize) -> Peer {
    let mut p = peer_bare(FRESH);
    pair_into(lp, by, &mut p);
    p
}

/// Node `p` holding `setup`, received in order.
fn holding(mut p: Peer, setup: &[osis_engine::local_peer::Package]) -> Peer {
    for pk in setup {
        p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    p
}

/// `net2` with peer 1 a node of 0's account, so it holds what it is given of 0's things.
fn net2_one() -> LocalPeer {
    LocalPeer::cached("shred::net2_one", || {
        let mut lp = LocalPeer::of(vec![peer(0)], 0).unwrap();
        let mut p = peer_bare(1);
        pair_into(&mut lp, 0, &mut p);
        lp.peers.push(p);
        (lp, ())
    })
    .0
}

/// Two peers (seeds 0 and 1), each holding the other's account chain (synced once), so either
/// may grant the other: built once (`LocalPeer::cached`).
fn net2() -> LocalPeer {
    LocalPeer::cached("shred::net2", || {
        let mut lp = LocalPeer::of(vec![peer(0), peer(1)], 0).unwrap();
        lp.sync_all().unwrap();
        (lp, ())
    })
    .0
}

/// `net2` with peer 1's thing T, peer 0 granted write on it, synced: built once
/// (`LocalPeer::cached`).
fn writable_by_0() -> (LocalPeer, Tid) {
    LocalPeer::cached("shred::writable_by_0", || {
        let mut lp = net2();
        let a = lp.peers[0].engine.me();
        let t = new_thing(&mut lp, 1);
        lp.peers[1].engine.grant(&t, &a, &edge(osis_base::Role::Write)).unwrap();
        lp.sync(1, 0).unwrap();
        (lp, t)
    })
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
// so that later compromise recovers nothing; spec/commits.md §6: at T the body is dropped, no
// local copy surviving; spec/commits.md §5 (purge on replace): the replacing node drops the body
// in the killing transaction, no local copy surviving
#[test]
fn purged_expired_or_replaced_body_unrecoverable_spec_commits_5() {
    for (case, k, marker) in [("purged", &REG, "PURGED-MARK-41c9"), ("expired", &BRIEF, "EXPIRED-MARK-77aa"), ("replaced", &GONE, "ATMOST-MARK-5b01")] {
        let mut lp = net2();
        let t = new_thing(&mut lp, 0);
        let c = set(&mut lp, 0, t, k, &big(marker));
        filler(&mut lp, 0, 6);
        match case {
            "purged" => {
                assert!(recoverable(&mut lp.peers[0], marker.as_bytes()), "the attack finds live content");
                lp.advance(5);
                let mut m = Mutation::new();
                m.set(t, &REG, &s("public")).unwrap();
                m.purge_commit(c, t, ak("t:reg.0"));
                lp.peers[0].commit(m).unwrap();
            }
            "expired" => {
                lp.advance(3_600_001);
                lp.peers[0].tick().unwrap();
            }
            _ => {
                lp.advance(5);
                set(&mut lp, 0, t, &GONE, "final");
            }
        }
        assert!(!lp.peers[0].engine.body_not_dropped(&c, &t, &k.name()), "{case}");
        assert!(!recoverable(&mut lp.peers[0], marker.as_bytes()), "{case} content recovered");
    }
}

// spec/commits.md §5 (purge on replace), spec/requirements.md (Scale: O(change)): in a paged map
// state, the dropped body's pages are rewritten shredded (not the whole state); no copy of the
// superseded entry value survives
#[test]
fn purged_on_replace_paged_unrecoverable_spec_commits_5() {
    let mut lp = net2();
    let t = new_thing(&mut lp, 0);
    let fill: osis_base::ValueMap = (0..66).map(|i| (s(&format!("k{i:03}")), s(&"f".repeat(1100)))).collect();
    put(&mut lp, 0, t, &GONEMAP, &Value::Map(fill));
    let marker = "PAGED-ATMOST-MARK-77e3";
    let edit = |lp: &mut LocalPeer, v: &str| {
        put_op(lp, 0, t, &GONEMAP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("k047"))], op: osis_crdt::Op::Set(s(v)) })
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
// expiring entry of a paged map goes in its page (rewritten shredded with its key
// index row), not by rewriting the whole state; no copy of its value survives
#[test]
fn expired_entry_paged_unrecoverable_spec_commits_6() {
    let mut lp = net2();
    let t = new_thing(&mut lp, 0);
    let fill: osis_base::ValueMap = (0..66).map(|i| (s(&format!("k{i:03}")), s(&"f".repeat(1100)))).collect();
    put(&mut lp, 0, t, &BIG, &Value::Map(fill));
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
// from its page and leaves its value index; no copy of its value survives; adding the
// value again and removing another by value work over the pages
#[test]
fn expired_element_paged_set_unrecoverable_spec_commits_6() {
    let mut lp = net2();
    let t = new_thing(&mut lp, 0);
    let a = ak("t:bigset.0");
    put(&mut lp, 0, t, &a, &Value::Set((0..66).map(|i| s(&format!("e{i:03}{}", "f".repeat(1100)))).collect()));
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
    put_op(&mut lp, 0, t, &a, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Remove(s(&gone)) });
    let v = read(&mut lp);
    assert!(v.len() == 66 && v.contains(&s(&marker)) && !v.contains(&s(&gone)));
}

// spec/commits.md §5: shredding a version covers every chunk only it reached (chunk keys live in
// links inside the dropped body); a purged large value's chunks stay unopenable from what the
// device still yields, though their ciphertext may linger in freed storage
#[test]
fn purged_large_value_unrecoverable_spec_commits_5() {
    let mut lp = net2();
    let t = new_thing(&mut lp, 0);
    let marker = b"LARGE-MARK-c4f2";
    let mut v = vec![0u8; 300 * 1024];
    let mut r = SeededRng::from_u64(0);
    osis_crypto::RngCore::fill_bytes(&mut r, &mut v);
    v[150_000..150_000 + marker.len()].copy_from_slice(marker);
    let secret = put(&mut lp, 0, t, &BLOB, &Value::Bytes(v));
    let chunks: Vec<Vec<u8>> = lp.peers[0].engine.package(&secret).unwrap().unwrap().blobs.into_iter().map(|(_, b)| b).collect();
    assert!(!chunks.is_empty(), "the value is chunked");
    // the attack opens blobs (tree nodes, chunks) with the link keys it recovers
    let opens = |p: &mut Peer| found_in(p, marker).iter().any(|f| matches!(f, osis_store::Source::Blob { .. }));
    assert!(opens(&mut lp.peers[0]), "the attack opens live chunks");
    filler(&mut lp, 0, 6);
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(b"small".to_vec())).unwrap();
    m.purge_commit(secret, t, ak("t:blob.0"));
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
        let mut lp = net2();
        let t = new_thing(&mut lp, 0);
        let marker = "LIVE-ATMOST-MARK-c90d";
        let mut fill: osis_base::ValueMap = (0..300).map(|i| (s(&format!("k{i:03}")), s(&"f".repeat(1100)))).collect();
        fill.insert(s("secret"), s(&big(marker)));
        let c0 = put(&mut lp, 0, t, &GONEMAP, &Value::Map(fill));
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
        put_op(&mut lp, 0, t, &GONEMAP, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(s("secret")) });
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
    let mut lp = net2_one();
    let t = new_thing(&mut lp, 0);
    let marker = "KEY-MARK-5e17";
    let k = ak("t:big.0");
    let put = |lp: &mut LocalPeer, key: &str| {
        put_op(lp, 0, t, &BIG, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(key))], op: osis_crdt::Op::Set(s("v")) })
    };
    let c = put(&mut lp, marker);
    lp.sync(0, 1).unwrap();
    lp.advance(5);
    put_op(&mut lp, 0, t, &BIG, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(s(marker)) });
    lp.sync(0, 1).unwrap();
    filler(&mut lp, 0, 6);
    lp.advance(5);
    let mut m = Mutation::new();
    m.op(t, &BIG, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("other"))], op: osis_crdt::Op::Set(s("w")) }).unwrap();
    m.purge_commit(c, t, k.clone());
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
// commit, joins without its writes and drops again; no local copy of its value survives
#[test]
fn expired_late_part_unrecoverable_spec_crdt_4_7() {
    let mut lp = net2();
    let t = new_shared(&mut lp, 0);
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
    let pk = packages_to(&mut lp, 0, 1).into_iter().find(|p| p.id == c).unwrap();
    let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let brief = b.header.aspects.iter().position(|a| a.ak.as_str() == "t:brief.0").unwrap();
    b.parts.retain(|x| x.ai != brief);
    lp.peers[1].receive(&b.encode(), pk.blobs.clone()).unwrap();
    filler(&mut lp, 1, 6);
    lp.advance(3_600_001);
    lp.peers[1].tick().unwrap();
    // taken (`retention::takes_late`): joined, then dropped again
    assert!(matches!(lp.peers[1].receive(&pk.bytes, pk.blobs.clone()).unwrap(), osis_engine::Ingested::Applied(_)));
    filler(&mut lp, 1, 6);
    assert!(!lp.peers[1].engine.body_not_dropped(&c, &t, &ak("t:brief.0")));
    assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "expired content recovered from the late part");
}

// spec/commits.md §4 (a commit with no part held, or whose every held part waits, applies as its header alone): peer 1 gets peer 0's
// expiring write on a thing whose creation record it lacks, past T: the part past T counts as
// never received before the commit is judged, so the commit applies as its header at once, and
// stays so once the record comes.
#[test]
fn partless_commit_applies_as_its_header_spec_commits_4() {
    let mut lp = net2_one();
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    m.set(t, &BRIEF, &s("brief")).unwrap();
    m.expires(t, &BRIEF, osis_base::WallMs(lp.peers[0].engine.now().0 + 60_000)).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.packages_for(0, 1).unwrap().into_iter().find(|p| p.id == c).unwrap();
    lp.advance(120_000);
    let r = lp.deliver(1, &pk).unwrap();
    assert_eq!(r, osis_engine::Ingested::Applied(c), "its header alone");
    lp.sync(0, 1).unwrap();
    assert!(lp.peers[1].engine.commit_ids().contains(&c) && lp.peers[1].engine.pending().iter().all(|x| x.0 != c), "{:?}", lp.peers[1].engine.pending());
    assert_eq!(lp.peers[1].engine.get_typed(&t, &BRIEF).unwrap(), None);
}

// spec/commits.md §5, spec/requirements.md (Deterministic): a commit, its thing's record and a purge
// request naming its parts on a register, a list and a map (resetting nothing), in every order: the node
// holds each aspect as its author does (the parts gone, what they replaced back), whether the parts
// waited when the request came or not, flags nothing and keeps no purged value.
#[test]
fn purge_of_a_waiting_part_reads_alike_spec_commits_5() {
    use osis_crdt::{Op, PathOp, PathSeg};
    let aspects = [ak("t:reg.0"), ak("t:list.0"), ak("t:big.0")];
    let mut base = net2_one(); // 1 a node of 0's account
    let lp = &mut base;
    let t = new_thing(lp, 0);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("old")).unwrap();
    m.set(t, &LIST, &Value::List(vec![s("a")])).unwrap();
    m.op(t, &BIG, PathOp { path: vec![PathSeg::Key(s("k"))], op: Op::Set(s("old")) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let t3 = new_thing(lp, 0);
    lp.sync(0, 1).unwrap();
    let had: std::collections::BTreeSet<_> = lp.commit_ids(0).into_iter().collect();
    let t2 = new_thing(lp, 0);
    let rec: Vec<_> = lp.packages_for(0, 1).unwrap().into_iter().filter(|p| !had.contains(&p.id)).collect();
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
        m.purge_commit(c, t, a.clone());
    }
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    let request = lp.peers[0].engine.package(&p).unwrap().unwrap();
    let groups = [rec, vec![whole], vec![request]];
    let markers = ["SECRET-9c2e", "SECRET-L7a1", "SECRET-K3b8", "SECRET-V5d0"];
    let mut reads = Vec::new();
    for order in [[0usize, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let mut lp = base.copy().unwrap();
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
            assert!(e.suspects().is_empty(), "order {order:?}");
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
    assert_eq!(reads[0][0], Some(s("old")), "the purged write gone: \"old\" reads again");
    assert!(reads.iter().all(|r| *r == reads[0]), "{reads:?}");
}

// spec/commits.md §5, spec/requirements.md (Deterministic): commit `c` writes `t` (reg, list) and `t2`;
// node 1 gets `c` as two copies (one without the list part, one of it alone, as blobs of two purge-by
// classes would bring it), each applying at once. A purge request naming the reg part, in every
// order: the node holds `t` as its author does and flags nothing. (A part waiting aside when its purge
// comes: outside::a_part_waiting_aside_is_purged_where_it_waits.)
#[test]
fn purge_of_a_commit_in_two_copies_reads_alike_spec_commits_5() {
    let mut base = net2();
    let lp = &mut base;
    let t = new_shared(lp, 0);
    let t2 = new_shared(lp, 0);
    let t3 = new_shared(lp, 0);
    lp.sync(0, 1).unwrap();
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
    m.purge_commit(c, t, ak("t:reg.0"));
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    let request = lp.peers[0].engine.package(&p).unwrap().unwrap();
    let mut part = osis_commit::CommitBlob::decode(&whole.bytes).unwrap();
    let list = part.header.aspects.iter().position(|a| a.tid == t && a.ak == ak("t:list.0")).unwrap();
    let mut rest = part.clone();
    part.parts.retain(|q| q.ai != list);
    rest.parts.retain(|q| q.ai == list);
    for order in [[0usize, 1, 2], [1, 0, 2], [0, 2, 1], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let mut lp = base.copy().unwrap();
        for g in order {
            match g {
                0 => drop(lp.peers[1].receive(&part.encode(), Vec::new()).unwrap()),
                1 => drop(lp.deliver(1, &request).unwrap()),
                _ => drop(lp.peers[1].receive(&rest.encode(), Vec::new()).unwrap()),
            }
            lp.peers[1].reexamine().unwrap();
            assert!(lp.peers[1].engine.suspects().is_empty(), "order {order:?} after {g}: gone, not dropped");
        }
        let e = &mut lp.peers[1].engine;
        assert!(e.pending().is_empty(), "order {order:?}: {:?}", e.pending());
        assert_eq!(e.get(&t2, &ak("t:reg.0")).unwrap(), Some(s("other")), "order {order:?}");
        assert!(e.suspects().is_empty(), "order {order:?}: {:?}", e.suspects());
        for a in [ak("t:reg.0"), ak("t:list.0")] {
            let author = lp.peers[0].engine.state_digest(&t, &a).unwrap();
            assert_eq!(lp.peers[1].engine.state_digest(&t, &a).unwrap(), author, "order {order:?}: {a:?} as its author holds it");
        }
        assert!(!recoverable(&mut lp.peers[1], b"SECRET-R4e1"), "order {order:?}");
    }
}

/// The parts of `pk` on `(t, a)`, each slot's delta replaced by what a stripped slot holds, if `empty`.
fn part_on(pk: &osis_engine::local_peer::Package, t: Tid, a: &osis_base::Ak, empty: bool) -> Vec<u8> {
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
    let mut lp = net2();
    let (t, y, q) = (new_shared(&mut lp, 0), new_shared(&mut lp, 0), new_shared(&mut lp, 0));
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
    m.purge_commit(c, t, ak("t:reg.0"));
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    let request = lp.peers[0].engine.package(&p).unwrap().unwrap();
    lp.deliver(1, &request).unwrap();
    lp.peers[1].receive(&part_on(&pk, t, &ak("t:reg.0"), false), Vec::new()).unwrap();
    assert!(!lp.peers[1].engine.body_not_dropped(&c, &t, &ak("t:reg.0")), "purged");
    lp.peers[1].clock.advance(120_000);
    lp.peers[1].receive(&part_on(&pk, y, &ak("t:reg.0"), false), Vec::new()).unwrap();
    assert!(lp.peers[1].engine.commit_ids().contains(&c) && lp.peers[1].engine.pending().is_empty(), "{:?}", lp.peers[1].engine.pending());
    assert_eq!(lp.peers[1].engine.stripped_count(&c).unwrap(), 0);
    unless_refused(lp.peers[1].receive(&part_on(&pk, t, &ak("t:reg.0"), true), Vec::new()));
    assert!(lp.peers[1].engine.pending().is_empty());
    assert!(!recoverable(&mut lp.peers[1], b"SECRET-R5b"));
}

// spec/commits.md §4, §5, §6, spec/crdt.md §4.7: a commit past its expiry, every part of it (one
// expiry per commit), given with a true part and a relay's junk (a stripped slot) and without its
// third part: nothing waits for it, so it applies at once, no aspect is
// flagged (no part went while pending), and the true part is gone: the older value reads, as at a
// node that held the commit before T.
#[test]
fn junk_beside_a_part_past_expiry_raises_no_flag_spec_commits_5() {
    let mut lp = net2();
    let (t, y) = (new_shared(&mut lp, 0), new_shared(&mut lp, 0));
    put(&mut lp, 0, t, &REG, &s("old"));
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
    assert!(!matches!(r, osis_engine::Ingested::Pending(..)), "{r:?}");
    lp.peers[1].reexamine().unwrap();
    assert!(lp.peers[1].engine.pending().is_empty(), "{:?}", lp.peers[1].engine.pending());
    assert!(lp.peers[1].engine.commit_ids().contains(&c));
    assert!(lp.peers[1].engine.suspects().is_empty());
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("old")), "the true part gone: the older value reads");
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:brief.0")).unwrap(), None);
    // the writer past T reads the same
    lp.peers[0].clock.advance(120_000);
    lp.peers[0].tick().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("old")));
    assert_eq!(lp.peers[0].engine.state_digest(&t, &ak("t:reg.0")).unwrap(), lp.peers[1].engine.state_digest(&t, &ak("t:reg.0")).unwrap());
}

// spec/commits.md §4, §5: a purged part, a part past its expiry, an unchecked first copy of a slot and
// a relay's empty slots (the bytes of a stripped one, no record behind them or one), in any order, T
// passing and a restart anywhere among them: each true copy delivered again at the end, the node reads
// alike, its commit applied, no flag left, nothing of either value recoverable.
// The default test runs the 7 rotations of the items' order (each item first and last, each pair
// both ways round) at each place of T among them, ticked or not; a restart in half of those cases,
// so each rotation and each place of T meets both (every pair of the three choices once).
#[test]
fn past_expiry_and_purge_alike_spec_commits_5() {
    past_expiry_and_purge_alike(false);
}

// As above, all 5040 orders in every shape (50400 cases).
#[test]
#[ignore = "by hand: every order"]
fn past_expiry_and_purge_alike_in_every_order_by_hand_spec_commits_5() {
    past_expiry_and_purge_alike(true);
}

fn past_expiry_and_purge_alike(every: bool) {
    let mut lp = net2();
    // the nodes judged: nodes of 0's account
    let mut node = node_of(&mut lp, 0);
    let (t2, t3) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    let setup = lp.packages_to_peer(0, &mut node).unwrap();
    let t = new_thing(&mut lp, 0);
    let rec: Vec<_> = lp.packages_to_peer(0, &mut node).unwrap().into_iter().filter(|p| !setup.iter().any(|k| k.id == p.id)).collect();
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
    m.purge_commit(c, t, ak("t:reg.0"));
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    let request = lp.peers[0].engine.package(&p).unwrap().unwrap();
    let ids: std::collections::BTreeSet<_> = lp.commit_ids(0).into_iter().collect();
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
    let n = items.len();
    let mut orders: Vec<Vec<usize>> = (0..n).map(|r| (0..n).map(|i| (r + i) % n).collect()).collect();
    if every {
        orders = vec![Vec::new()];
        for i in 0..n {
            orders = orders.iter().flat_map(|q| (0..=q.len()).map(move |at| { let mut x = q.clone(); x.insert(at, i); x })).collect();
        }
    }
    // (whether it restarts before the fourth item, deliveries before T, whether a tick follows T)
    let shapes: Vec<(bool, usize, bool)> = [false, true].into_iter().flat_map(|restart| [(0, false), (2, false), (2, true), (4, false), (4, true)].map(|(k, tick)| (restart, k, tick))).collect();
    // by hand every order in every shape; else each order and place of T once, restarting at
    // alternate ones
    let cases: Vec<(usize, usize)> = match every {
        true => (0..shapes.len()).flat_map(|n| (0..orders.len()).map(move |o| (n, o))).collect(),
        false => (0..5).flat_map(|t| (0..orders.len()).map(move |o| (t + 5 * ((t + o) % 2), o))).collect(),
    };
    let outcomes = std::sync::Mutex::new(std::collections::BTreeMap::<String, String>::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    // every case starts at one node holding the setup: built once, each case a copy of it
    let base = std::sync::Mutex::new(holding(node, &setup));
    let (base, items, orders, shapes, cases, ids) = (&base, &items, &orders, &shapes, &cases, &ids);
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let at = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(&(n, o)) = cases.get(at) else { return };
                let ((restart, k, tick), order) = (shapes[n], &orders[o]);
                let mut p = base.lock().unwrap().copy().unwrap();
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
                    if i == 3 && restart {
                        p = reopened(p, FRESH + 1);
                    }
                    unless_refused(p.receive(&items[*x].0, items[*x].1.clone()));
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
                    unless_refused(p.receive(&items[x].0, items[x].1.clone()));
                    p.reexamine().unwrap();
                }
                p.tick().unwrap();
                p.reexamine().unwrap();
                let e = &mut p.engine;
                let got = format!("applied {} pending {:?} stripped {} flags {:?} reads {:?} {:?} {:?} digests {:?} {:?} {:?} {:?}", e.commit_ids().contains(&c), e.pending(), e.stripped_count(&c).unwrap(), e.suspects().iter().map(|f| f.1.clone()).collect::<Vec<_>>(), e.get(&t, &reg).unwrap(), e.get(&t, &list).unwrap(), e.get(&t2, &brief).unwrap(), e.state_digest(&t, &reg).unwrap(), e.state_digest(&t, &list).unwrap(), e.state_digest(&t2, &brief).unwrap(), crate::judgment::observe(e, ids));
                let [kept_secret, kept_brief] = recovered(&mut p, [b"SECRET-R5c", b"BRIEF-R5c"]);
                let gone = !kept_secret && !kept_brief;
                outcomes.lock().unwrap().entry(format!("gone {gone} {got}")).or_insert(format!("restart {restart} k {k} tick {tick} order {order:?}"));
            });
        }
    });
    let out = outcomes.into_inner().unwrap();
    assert_eq!(out.len(), 1, "{out:#?}");
    let (only, _) = out.iter().next().unwrap();
    // every part expires with the commit (spec/commits.md §6) and is gone (spec/crdt.md §4.7): the
    // register reads the record's "new" it replaced, the list and brief nothing, as before `c`
    assert!(only.starts_with("gone true applied true pending [] stripped 0 flags [] reads Some(Str(\"new\")) None None"), "{only}");
}

// spec/commits.md §4, §5: a purged permanent delta reads alike whatever came first and whatever the
// node syncs: its body, its header-only blob, the purge request (or the request's own header-only
// blob with a snapshot listing its delta), a restart anywhere among them. Each ends with the commit
// applied without its body, the purge named, nothing waiting, nothing of the value recoverable.
// The `_plain` property runs every third case (orders by restart points); the exhaustive one all.
#[test]
#[ignore = "property"]
fn tombstone_alike_plain_spec_commits_5() {
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
    let forever = osis_schema::PurgeBy::AuthorOrAdmin;
    let marker = "TOMBSTONE-SECRET-8e1a";
    let mut lp = net2();
    // the nodes judged: nodes of 0's account
    let mut node = node_of(&mut lp, 0);
    let setup = lp.packages_to_peer(0, &mut node).unwrap();
    let t = new_thing_keeping(&mut lp, 0, &[("t:reg.0", osis_schema::History::FOREVER)]);
    let rec: Vec<_> = lp.packages_to_peer(0, &mut node).unwrap().into_iter().filter(|p| !setup.iter().any(|k| k.id == p.id)).collect();
    assert_eq!(rec.len(), 1);
    lp.advance(5);
    let mut m = Mutation::new();
    m.purge_by(t, &REG, forever).unwrap();
    m.set(t, &REG, &s(&big(marker))).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let whole = lp.peers[0].engine.package(&c).unwrap().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.purge_commit(c, t, ak("t:reg.0"));
    m.set(t, &REG, &s("after")).unwrap();
    let pc = lp.peers[0].commit(m).unwrap().unwrap();
    let request = lp.peers[0].engine.package(&pc).unwrap().unwrap();
    lp.advance(5);
    let z = lp.peers[0].engine.snapshot(&t, &ak("t:reg.0")).unwrap().unwrap();
    let snap = lp.peers[0].engine.package(&z).unwrap().unwrap();
    let header = |b: &[u8]| osis_commit::rewrite(&CommitBlob::decode(b).unwrap(), |_| true).encode();
    let item = |pk: &osis_engine::local_peer::Package| (pk.bytes.clone(), pk.blobs.clone());
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
        for order in &orders {
            for restart in 0..=order.len() {
                cases += 1;
                if cases % stride == 0 {
                    jobs.push((k, order.clone(), restart));
                }
            }
        }
    }
    let base = std::sync::Mutex::new(holding(node, &setup));
    let one = |j: u64| {
        osis_base::testenv::caught(|| {
            let (k, order, restart) = &jobs[j as usize];
            let (what, items) = &sets[*k];
            let mut p = base.lock().unwrap().copy().unwrap();
            for (at, i) in order.iter().enumerate() {
                if at == *restart {
                    p = reopened(p, FRESH + 1);
                }
                p.receive(&items[*i].0, items[*i].1.clone()).unwrap();
            }
            let e = &mut p.engine;
            let at = format!("{what}, order {order:?}, restart {restart}");
            assert!(e.commit_ids().contains(&c), "{at}: not applied");
            assert!(!e.body_not_dropped(&c, &t, &ak("t:reg.0")), "{at}: its body is held");
            assert_eq!(e.purged_on(&t, &ak("t:reg.0")).unwrap().get(&c), Some(&pc), "{at}");
            assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("after")), "{at}");
            assert!(e.pending().is_empty(), "{at}: {:?}", e.pending());
            assert!(e.suspects().is_empty(), "{at}: flagged");
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
    // every case counted: each order, each restart point
    assert_eq!(cases, 24 * 5 + 6 * 4 + 24 * 5);
}

/// Node 0's paged map on `t` over an older value node 1 holds, by commit `c` (`whole`: its package), and a
/// request naming it that resets nothing; node 1 holds `c` with its last page away, then the request.
fn purged_page_away(lp: &mut LocalPeer, marker: &str) -> (Tid, osis_base::CommitId, osis_engine::local_peer::Package) {
    let a = ak("t:big.0");
    // 1 reads t
    lp.sync(1, 0).unwrap();
    let t = new_shared(lp, 0);
    put(lp, 0, t, &BIG, &Value::Map(osis_base::ValueMap::from([(s("older"), s("kept"))])));
    lp.sync(0, 1).unwrap();
    lp.advance(5);
    // the marker in every entry, so whichever page stays away the held ones carry it
    let fill: osis_base::ValueMap = (0..400).map(|i| (s(&format!("k{i:03}")), s(&format!("{marker}{}", "f".repeat(1100))))).collect();
    let c = put(lp, 0, t, &BIG, &Value::Map(fill));
    let whole = lp.peers[0].engine.package(&c).unwrap().unwrap();
    assert!(whole.blobs.len() > 1, "paged: {} blobs, {} bytes", whole.blobs.len(), whole.bytes.len());
    let mut held = whole.blobs.clone();
    held.pop();
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge_commit(c, t, a);
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

// spec/commits.md §5, spec/crdt.md §4.7: a waiting part a held request names goes at once while a
// page of it is away (its bytes cannot be decoded), the pages it holds readable no more; its commit
// then applies, nothing flagged: the purged writes have no effect, so the node reads as the writer
// that held and removed them (the older value back), and a snapshot by the writer or a copy
// arriving again changes nothing and brings back no purged value.
#[test]
fn purged_with_a_page_away_goes_at_once_spec_commits_5() {
    for by_snapshot in [true, false] {
        let marker = "PAGE-AWAY-4c8e";
        let mut lp = net2();
        let a = ak("t:big.0");
        let (t, c, whole) = purged_page_away(&mut lp, marker);
        let e = &mut lp.peers[1].engine;
        assert!(e.pending().is_empty() && e.commit_ids().contains(&c), "{:?}", e.pending());
        assert!(e.suspects().is_empty(), "nothing flagged");
        assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "recovered with a page away");
        let older = Some(Value::Map(osis_base::ValueMap::from([(s("older"), s("kept"))])));
        assert_eq!(lp.peers[1].engine.get(&t, &a).unwrap(), older, "by snapshot {by_snapshot}");
        assert_eq!(lp.peers[0].engine.get(&t, &a).unwrap(), older, "by snapshot {by_snapshot}: the writer");
        if by_snapshot {
            lp.advance(5);
            let sc = lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
            let pk = lp.peers[0].engine.package(&sc).unwrap().unwrap();
            lp.deliver(1, &pk).unwrap();
        } else {
            lp.peers[1].receive(&whole.bytes, whole.blobs.clone()).unwrap();
        }
        lp.peers[1].reexamine().unwrap();
        assert_eq!(lp.peers[1].engine.get(&t, &a).unwrap(), older, "by snapshot {by_snapshot}");
        assert!(lp.peers[1].engine.suspects().is_empty(), "by snapshot {by_snapshot}");
        assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "by snapshot {by_snapshot}");
    }
}

// spec/commits.md §5 (Dropping a body), spec/crdt.md
// §4.7: a snapshot stripped for one purged delta still carries the other values it copied; a second
// request purging one of those replaces the leftover, and the old leftover row's bytes must go with
// it (was: the row was overwritten unshredded, so the old page kept the value).
#[test]
fn snapshot_leftover_stripped_again_unrecoverable_spec_commits_5() {
    let mut lp = net2_one();
    let t = new_thing_keeping(&mut lp, 0, &[("t:text.0", DAY)]);
    lp.sync(0, 1).unwrap();
    let k = ak("t:big.0");
    let (mx, my) = ("SNAPX-MARK-1a2b", "SNAPY-MARK-3c4d");
    let put = |lp: &mut LocalPeer, key: &str, val: &str| {
        put_op(lp, 0, t, &BIG, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(key))], op: osis_crdt::Op::Set(s(val)) })
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
        m.purge_commit(c, t, k.clone());
        lp.peers[0].commit(m).unwrap().unwrap();
    };
    purge(&mut lp, cx, "ox");
    lp.sync(0, 1).unwrap();
    for i in [0, 1] {
        let e = &mut lp.peers[i].engine;
        let sai = e.header(&snap).unwrap().aspects.iter().position(|a| a.tid == t && a.ak == k).unwrap();
        let m = e.core.ix.commits.get(&snap).unwrap();
        assert!(m.stripped(sai), "peer {i}: the snapshot carrying the purged value is held as its leftover");
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

fn fallen_snapshot_rig() -> Fallen {
    use osis_base::Role;
    use osis_engine::flows::Demotion;
    let mut lp = LocalPeer::of(vec![peer(0), peer(1), peer(2)], 0).unwrap();
    lp.sync_all().unwrap();
    let t = new_shared(&mut lp, 0);
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
    assert!(lp.peers[1].engine.core.ix.commits.get(&snap).unwrap().stripped(sai), "the snapshot is held as its leftover");
    lp.advance(5);
    let done = lp.peers[0].engine.demote(&t, &Demotion { holder: x, new: None, retain: None }).unwrap();
    for id in &done.commits {
        let pk = lp.peers[0].engine.package(id).unwrap().unwrap();
        lp.deliver(1, &pk).unwrap();
    }
    lp.peers[1].reexamine().unwrap();
    let m = lp.peers[1].engine.core.ix.commits.get(&snap).unwrap();
    assert!(m.stripped(sai) && !m.missing(sai), "fallen: the snapshot stays held as its leftover");
    Fallen { lp, t, cy, my }
}

/// Node `i` writes `val` at key `key` of `t:big.0`, purging `purge` if given.
fn big_put(lp: &mut LocalPeer, i: usize, t: Tid, key: &str, val: &str, purge: Option<osis_base::CommitId>) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.op(t, &BIG, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(key))], op: osis_crdt::Op::Set(s(val)) }).unwrap();
    if let Some(c) = purge {
        m.purge_commit(c, t, ak("t:big.0"));
    }
    lp.peers[i].commit(m).unwrap().unwrap()
}

// spec/commits.md §5 (Dropping a body), spec/crdt.md §4.7:
// a snapshot's leftover keeps the other values it copied and stays held through its purge's fall,
// so a second request purging one of those strips it there too and leaves no copy behind.
// spec/commits.md §5: the leftover indexes as an open rebuilding the index reads it.
#[test]
fn fallen_snapshot_leftover_gone_for_a_later_purge_spec_commits_5() {
    let Fallen { mut lp, t, cy, my } = fallen_snapshot_rig();
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
    put_op(lp, 0, t, &MAP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(key)), osis_crdt::PathSeg::Field(1)], op: osis_crdt::Op::Set(Value::Int(n)) })
}

// spec/crdt.md §4.7, §5.6, spec/commits.md §5: a purge of an entry's creation takes the entry from
// the read on both nodes: a later edit into it stays held under its own copy of the key but reads as
// at a node that never held the creation (no live record); purged too, nothing of the key is left
#[test]
fn purge_of_an_entry_hides_later_edits_into_it_spec_crdt_4_7() {
    let mut lp = net2_one();
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
        m.purge_commit(c, t, k.clone());
        lp.peers[0].commit(m).unwrap();
        lp.sync(0, 1).unwrap();
    };
    purge(&mut lp, made, "other");
    let at = |f: u64| [osis_crdt::PathSeg::Key(s(marker)), osis_crdt::PathSeg::Field(f)];
    for i in [0, 1] {
        assert_eq!(lp.peers[i].engine.get_at(&t, &k, &[osis_crdt::PathSeg::Key(s(marker))]).unwrap(), None, "peer {i}: the entry went with its creation");
        assert_eq!(lp.peers[i].engine.get_at(&t, &k, &at(1)).unwrap(), None, "peer {i}: the edit into it reads as never held");
        assert_eq!(lp.peers[i].engine.get_at(&t, &k, &[osis_crdt::PathSeg::Key(s("other"))]).unwrap(), Some(item("w", 3)), "peer {i}");
    }
    lp.advance(5);
    purge(&mut lp, edit, "other2");
    for i in [0, 1] {
        assert!(!recoverable(&mut lp.peers[i], marker.as_bytes()), "peer {i}: the purged key recovered");
    }
}

// spec/crdt.md §4.7, §5.6: an edit into an expiring entry keeps its own expiry (none); past the
// entry's T the entry is gone and the edit into it reads as at a node that never held the entry,
// while another entry and the edit into it stay
#[test]
fn edit_into_expiring_entry_keeps_its_expiry_spec_crdt_4_7() {
    let mut lp = net2_one();
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
        assert_eq!(lp.peers[i].engine.get_at(&t, &ak("t:map.0"), &[osis_crdt::PathSeg::Key(s(marker))]).unwrap(), None, "peer {i}: the entry expired");
        assert_eq!(lp.peers[i].engine.get_at(&t, &ak("t:map.0"), &at(marker, 1)).unwrap(), None, "peer {i}: the edit goes with the entry's creation");
        assert_eq!(lp.peers[i].engine.get_at(&t, &ak("t:map.0"), &at("kept", 1)).unwrap(), Some(Value::Int(3)));
    }
}

// spec/crdt.md §4.7, §5.7, spec/commits.md §5: an undo of a text delete carries the chars as its
// own values (an undelete): a purge of the insert takes the elements' creations, so the text reads
// as never inserted (an element without its creation shows no char) though the undelete's chars
// stay held; a purge of the undo too takes them
#[test]
fn undelete_chars_are_their_own_values_spec_crdt_4_7() {
    let mut lp = net2_one();
    let t = new_thing_keeping(&mut lp, 0, &[("t:text.0", DAY)]);
    let marker = "UNDELETE-MARK-6d2a";
    let k = ak("t:text.0");
    let text = |lp: &mut LocalPeer, v: &str| {
        put(lp, 0, t, &TEXT, &s(v))
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
    m.purge_commit(made, t, k.clone());
    lp.peers[0].commit(m).unwrap();
    lp.sync(0, 1).unwrap();
    for i in [0, 1] {
        assert_eq!(lp.peers[i].engine.get(&t, &k).unwrap(), Some(s("")), "peer {i}: no creation, no char");
    }
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("y")).unwrap();
    m.purge_commit(undo, t, k.clone());
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
    let mut lp = net2();
    let mut m = Mutation::new();
    let me = lp.peers[0].engine.me();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    keep_in(&mut m, t, &setting(&[("t:reg.0", DAY)]));
    lp.peers[0].commit(m).unwrap();
    lp.hold(t);
    let marker = "PURGED-UNDO-5c1e";
    let k = ak("t:reg.0");
    let made = put(&mut lp, 0, t, &REG, &s(marker));
    lp.advance(5);
    let mut m = Mutation::new();
    m.remove_aspect(t, &REG).unwrap();
    let removed = lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync(0, 1).unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &TEXT, &s("x")).unwrap();
    m.purge_commit(made, t, k.clone());
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
// 1 writes message `e`; 0 (the mint admin) reacts to `e` and posts message `m2` in one delta `d`, then
// edits `m2` in `c`. 1, `e`'s author, purges `e`. Only `e`'s writes go: `d` and `c` are 0's edits,
// which 1 has no right to purge; `d`'s reaction stays held but goes from the read with `e`'s
// creation (spec/crdt.md §4.7).
#[test]
fn purge_spares_other_values_of_a_carrier_spec_commits_5() {
    use osis_crdt::{Op, PathOp, PathSeg};
    let mut lp = net(2, 0);
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.me();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(osis_base::Role::Write)), None);
    lp.sync(0, 1).unwrap();
    let k = ak("t:map.0");
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("e"))], op: Op::Set(item("E-MARK", 1)) }).unwrap();
    // its author purges it below
    m.purge_by(t, &MAP, osis_base::PurgeBy::AuthorOrAdmin).unwrap();
    let e = lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync(1, 0).unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("e")), PathSeg::Field(1)], op: Op::Set(Value::Int(2)) }).unwrap();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("m2"))], op: Op::Set(item("M2-MARK", 7)) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(5);
    put_op(&mut lp, 0, t, &MAP, PathOp { path: vec![PathSeg::Key(s("m2")), PathSeg::Field(1)], op: Op::Set(Value::Int(9)) });
    lp.sync(0, 1).unwrap();
    let m2 = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.get_at(&t, &k, &[PathSeg::Key(s("m2"))]).unwrap();
    assert_eq!(m2(&mut lp, 1), Some(item("M2-MARK", 9)));
    lp.advance(5);
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("other"))], op: Op::Set(item("w", 3)) }).unwrap();
    m.purge_commit(e, t, k.clone());
    lp.peers[1].commit(m).unwrap();
    lp.sync(1, 0).unwrap();
    for i in [0, 1] {
        assert_eq!(lp.peers[i].engine.get_at(&t, &k, &[PathSeg::Key(s("e"))]).unwrap(), None, "peer {i}: e purged, its reaction with it");
        assert_eq!(m2(&mut lp, i), Some(item("M2-MARK", 9)), "peer {i}: 0's message and edit kept");
    }
}

// spec/requirements.md Data model, spec/crdt.md §4.7: 0 reacts to an expiring message `e` and posts a
// lasting message `m2` in one write: the commit takes no expiry, the reaction its own. Past `e`'s T
// `e` is gone and the reaction with it (it reads as at a node that never held `e`); `m2` and its
// edit, written by the same commit, stay.
#[test]
fn reaction_goes_with_its_expiring_message_spec_crdt_4_7() {
    use osis_crdt::{Op, PathOp, PathSeg};
    let mut lp = net(1, 0);
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
    assert_eq!(lp.peers[0].engine.get_at(&t, &k, &[PathSeg::Key(s("e"))]).unwrap(), None, "e expired, its reaction with it");
    assert_eq!(lp.peers[0].engine.get_at(&t, &k, &[PathSeg::Key(s("m2"))]).unwrap(), Some(item("M2-MARK", 9)), "m2 and its edit kept");
}

// spec/crdt.md §4.6 (undo expiry): 0 removes an expiring entry and a lasting
// one in one write. Its undo would write both back in one commit with one expiry: refused, so the
// lasting entry never takes the other's. Past the expiring entry's T nothing of it is written
// back and the undo restores the lasting entry, which stays.
#[test]
fn undo_copying_two_expiries_waits_spec_crdt_4_6() {
    use osis_crdt::{Op, PathOp, PathSeg};
    let mut lp = net(1, 0);
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
    assert!(matches!(&r, Err(osis_engine::Error::Clash(m)) if m.contains("one expiry")), "{r:?}");
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
    let mut seen: Option<(Vec<osis_engine::engine::listing::PartBody>, std::collections::BTreeMap<osis_base::CommitId, osis_base::CommitId>)> = None;
    for bare in [false, true] {
        for order in [[0usize, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
            let mut lp = net2_one(); // 1 a node of 0's account
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
            assert_eq!(e.part(&t, &k, &s1, usize::MAX).unwrap().unwrap().body, osis_engine::engine::listing::PartBody::Dropped, "bare {bare}, order {order:?}");
            assert!(!e.purged_on(&t, &k).unwrap().contains_key(&s1), "bare {bare}, order {order:?}");
        }
    }
    let (bodies, purged) = seen.unwrap();
    assert!(matches!(bodies[0], osis_engine::engine::listing::PartBody::Purged(_)), "{bodies:?}");
    assert!(matches!(bodies[1], osis_engine::engine::listing::PartBody::Purged(_)), "{bodies:?}");
    assert!(purged.len() >= 2, "{purged:?}");
}

/// Peer 0's packages to peer 1 carrying a part on `t` (its record, before anything else is
/// written there).
fn record_of(lp: &mut LocalPeer, t: Tid) -> Vec<osis_engine::local_peer::Package> {
    lp.packages_for(0, 1).unwrap().into_iter().filter(|p| osis_commit::CommitBlob::decode(&p.bytes).unwrap().header.aspects.iter().any(|a| a.tid == t)).collect()
}

// spec/commits.md §4 (Unjudgeable; Pending storage), §5 (Purge): a commit pending for its `ts`,
// one part on a thing whose record is away, and a purge request naming that part (pending too):
// the part waits in the pending copy while the record is away. With the record it is judged:
// purged, or read as written when no request names it.
#[test]
fn pending_part_awaiting_its_record_is_judged_with_it_spec_commits_4() {
    for purge in [false, true] {
        let mut lp = net2_one(); // 1 a node of 0's account
        let t = new_thing(&mut lp, 0);
        lp.sync(0, 1).unwrap();
        let t2 = new_thing(&mut lp, 0);
        let rec = record_of(&mut lp, t2);
        lp.peers[0].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
        let mut m = Mutation::new();
        m.set(t, &REG, &s("ahead")).unwrap();
        m.set(t2, &REG, &s("SECRET-A2f6")).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let pc = lp.peers[0].engine.package(&c).unwrap().unwrap();
        assert!(matches!(lp.deliver(1, &pc).unwrap(), osis_engine::Ingested::Pending(_, osis_engine::Reason::Drift)), "purge {purge}");
        if purge {
            let mut m = Mutation::new();
            m.purge_commit(c, t2, ak("t:reg.0"));
            m.set(t, &LIST, &Value::List(vec![s("a")])).unwrap();
            let p = lp.peers[0].commit(m).unwrap().unwrap();
            let pp = lp.peers[0].engine.package(&p).unwrap().unwrap();
            assert!(matches!(lp.deliver(1, &pp).unwrap(), osis_engine::Ingested::Pending(..)));
        }
        assert!(lp.peers[1].engine.pending().iter().any(|x| x.0 == c), "purge {purge}");
        for pk in &rec {
            lp.deliver(1, pk).unwrap();
        }
        lp.peers[1].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
        lp.peers[1].reexamine().unwrap();
        let e = &mut lp.peers[1].engine;
        assert!(e.pending().is_empty(), "purge {purge}: {:?}", e.pending());
        assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("ahead")));
        let want = lp.peers[0].engine.state_digest(&t2, &ak("t:reg.0")).unwrap();
        assert_eq!(lp.peers[1].engine.state_digest(&t2, &ak("t:reg.0")).unwrap(), want, "purge {purge}: as its author holds it");
        if purge {
            assert!(!recoverable(&mut lp.peers[1], b"SECRET-A2f6"));
        } else {
            assert_eq!(lp.peers[1].engine.get(&t2, &ak("t:reg.0")).unwrap(), Some(s("SECRET-A2f6")));
        }
    }
}

// spec/commits.md §4 (Unjudgeable), §5: an applied commit with a purged part, a part waiting for its
// pages and a part on a thing whose record is away: a copy of it holds nothing the node needs (the
// parts that wait are in its pending copy), so node-sync forgets it (`spent_copy`).
#[test]
fn copy_of_a_purged_part_beside_an_unjudgeable_one_is_spent_spec_commits_5() {
    let map: osis_base::ValueMap = (0..2000).map(|i| (Value::Str(format!("key {i:05}")), Value::Str("v".repeat(60)))).collect();
    let mut lp = net2();
    let (t, h, q) = (new_shared(&mut lp, 0), new_shared(&mut lp, 0), new_shared(&mut lp, 0));
    lp.sync(0, 1).unwrap();
    let t2 = new_shared(&mut lp, 0);
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("SECRET-C7d2")).unwrap();
    m.set(h, &BIG, &Value::Map(map)).unwrap();
    m.set(t2, &REG, &s("other")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    assert!(!pk.blobs.is_empty(), "paged");
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(q, &REG, &s("q")).unwrap();
    m.purge_commit(c, t, ak("t:reg.0"));
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    let pp = lp.peers[0].engine.package(&p).unwrap().unwrap();
    lp.deliver(1, &pp).unwrap();
    lp.peers[1].receive(&pk.bytes, Vec::new()).unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.commit_ids().contains(&c) && e.pending().iter().any(|x| x.0 == c), "applied, its paged part waiting");
    let copy = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    assert!(e.spent_copy(&c, &copy).unwrap(), "nothing of it needed");
    assert!(!recoverable(&mut lp.peers[1], b"SECRET-C7d2"));
}

// spec/commits.md §5 (A waiting part past its expiry: goes at T, counts as never received), §4 (Examined
// again: the clock reaching its expiry): commit `c` overwrites `t`'s register, pending for its `ts`, its
// expiry T past that `ts`. Past T, ticked at T or not, the node examines it again: the part went at
// T, so the register reads its older value, as at a node that applied it before T (spec/crdt.md
// §4.7), with no suspect flag; nothing waits and the node reads alike either way.
#[test]
fn part_pending_for_its_ts_goes_at_its_expiry_ticked_or_not_spec_commits_5() {
    let mut lp = net2_one(); // 1 a node of 0's account
    let t = new_thing(&mut lp, 0);
    put(&mut lp, 0, t, &REG, &s("old"));
    lp.sync(0, 1).unwrap();
    let ahead = 3 * osis_base::format::MAX_DRIFT_MS;
    lp.peers[0].clock.advance(ahead);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("SECRET-D4c7")).unwrap();
    m.expires(t, &REG, osis_base::WallMs(lp.peers[0].engine.now().0 + 60_000)).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pc = lp.peers[0].engine.package(&c).unwrap().unwrap();
    assert!(matches!(lp.deliver(1, &pc).unwrap(), osis_engine::Ingested::Pending(_, osis_engine::Reason::Drift)));
    let mut seen = Vec::new();
    for tick in [true, false] {
        let mut p = lp.peers[1].copy().unwrap();
        p.clock.advance(ahead + 120_000);
        if tick {
            p.tick().unwrap();
        }
        p.reexamine().unwrap();
        let e = &mut p.engine;
        assert!(e.commit_ids().contains(&c) && e.pending().is_empty(), "tick {tick}: {:?}", e.pending());
        assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("old")), "tick {tick}: never received");
        assert!(e.suspects().is_empty(), "tick {tick}: no flag, its writes have no effect anywhere (spec/crdt.md §4.7)");
        seen.push(format!("applied {} pending {:?} flags {:?} reg {:?} digest {:?}", e.commit_ids().contains(&c), e.pending(), e.suspects(), e.get(&t, &ak("t:reg.0")).unwrap(), e.state_digest(&t, &ak("t:reg.0")).unwrap()));
        assert!(!recoverable(&mut p, b"SECRET-D4c7"), "tick {tick}");
    }
    assert_eq!(seen[0], seen[1], "ticked at T or not");
}

// spec/commits.md §5 (Purge), spec/crdt.md §4.7 (Gone writes): a compaction snapshot carrying a write's
// value, pending for its `ts`, the write purged before it comes or while it waits: held without the
// purged write while it waits, and joined so once it applies: the record's value it replaced reads.
#[test]
fn waiting_snapshot_drops_a_purged_copy_spec_commits_5() {
    for purge_first in [false, true] {
        let (mut lp, t) = writable_by_0();
        lp.advance(5);
        let w = set(&mut lp, 0, t, &REG, "SECRET-W9b4");
        lp.sync(0, 1).unwrap();
        lp.peers[0].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
        let snap = lp.peers[0].engine.snapshot(&t, &ak("t:reg.0")).unwrap().unwrap();
        let sp = lp.peers[0].engine.package(&snap).unwrap().unwrap();
        let purge = |lp: &mut LocalPeer| {
            let mut m = Mutation::new();
            m.purge_commit(w, t, ak("t:reg.0"));
            m.set(t, &LIST, &Value::List(vec![s("a")])).unwrap();
            lp.peers[1].commit(m).unwrap().unwrap();
            lp.peers[1].reexamine().unwrap();
        };
        if purge_first {
            purge(&mut lp);
        }
        assert!(matches!(lp.deliver(1, &sp).unwrap(), osis_engine::Ingested::Pending(_, osis_engine::Reason::Drift)));
        if !purge_first {
            purge(&mut lp);
        }
        assert!(lp.peers[1].engine.pending().iter().any(|x| x.0 == snap));
        assert!(!recoverable(&mut lp.peers[1], b"SECRET-W9b4"), "purge first {purge_first}: the waiting snapshot's copy went");
        lp.peers[1].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
        lp.peers[1].reexamine().unwrap();
        let e = &mut lp.peers[1].engine;
        assert!(e.pending().is_empty() && e.commit_ids().contains(&snap), "{:?}", e.pending());
        assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("new")), "purged: the replaced value reads");
        assert!(e.suspects().is_empty());
        assert!(!recoverable(&mut lp.peers[1], b"SECRET-W9b4"));
    }
}

/// Waiting snapshot parts decoded (`waiting snapshot: decoded`) during `f`.
fn decoded(f: impl FnOnce()) -> u64 {
    osis_base::costs::take();
    f();
    osis_base::costs::take().iter().find(|x| x.0 == "waiting snapshot: decoded").map_or(0, |x| x.2)
}

/// `n` snapshots on an aspect with a purged write, none carrying it, pending for their `ts` at
/// peer 1, each looked at once since stored (a purge wakes them; the first look decodes again, as
/// its pending entry is noted after the bound): how many are decoded by a `reexamine` with nothing
/// changed, by the next purge on that aspect (of a write none carries), by an expiring write
/// there, and by its expiry.
fn waiting_snapshots_decoded(n: usize) -> [u64; 4] {
    let (mut lp, t) = writable_by_0();
    lp.advance(5);
    let purge = |lp: &mut LocalPeer, v: &str| {
        let w = set(lp, 1, t, &REG, v);
        let mut m = Mutation::new();
        m.purge_commit(w, t, ak("t:reg.0"));
        m.set(t, &LIST, &Value::List(vec![s(v)])).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap();
    };
    purge(&mut lp, "gone");
    lp.peers[0].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
    for i in 0..n {
        set(&mut lp, 0, t, &REG, &format!("v{i}"));
        let snap = lp.peers[0].engine.snapshot(&t, &ak("t:reg.0")).unwrap().unwrap();
        let sp = lp.peers[0].engine.package(&snap).unwrap().unwrap();
        assert!(matches!(lp.deliver(1, &sp).unwrap(), osis_engine::Ingested::Pending(_, osis_engine::Reason::Drift)));
    }
    purge(&mut lp, "first look");
    lp.peers[1].reexamine().unwrap();
    assert_eq!(lp.peers[1].engine.pending().len(), n);
    let idle = decoded(|| lp.peers[1].reexamine().unwrap());
    let purged = decoded(|| {
        purge(&mut lp, "gone too");
        lp.peers[1].reexamine().unwrap();
    });
    let expiring = decoded(|| {
        let mut m = Mutation::new();
        m.set(t, &REG, &s("brief")).unwrap();
        m.expires(t, &REG, osis_base::WallMs(lp.peers[1].engine.now().0 + 1_000)).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap();
        lp.peers[1].reexamine().unwrap();
    });
    let expired = decoded(|| {
        lp.peers[1].clock.advance(2_000);
        lp.peers[1].tick().unwrap();
    });
    assert_eq!(lp.peers[1].engine.pending().len(), n, "still waiting");
    [idle, purged, expiring, expired]
}

// notes/principles.md (Check scaling), spec/crdt.md §4.7 (Gone writes): a waiting snapshot's carried
// copies are judged by its bound, as a held snapshot's (`Carried`), decoded once while it waits:
// a purge or an expiry of writes none of them carries decodes none, at n and 10n.
#[test]
fn waiting_snapshots_decoded_once_while_they_wait_spec_commits_5() {
    assert_eq!(waiting_snapshots_decoded(3), [0, 0, 0, 0]);
    assert_eq!(waiting_snapshots_decoded(30), [0, 0, 0, 0]);
}


type Flagged = (Tid, osis_base::Ak);
type SuspectFx = osis_base::memo::Effects<Flagged, Option<(u64, u8)>>;

/// The flags of peer `i` that moved since the follower last looked: keys new from `feed` are
/// followed, each due one settled; a flag gone is let go.
fn suspects_moved(lp: &mut LocalPeer, i: usize, feed: &mut osis_base::memo::Feed<Flagged>, fx: &mut SuspectFx) -> Vec<(Flagged, Option<(u64, u8)>)> {
    let e = &lp.peers[i].engine;
    for k in feed.added() {
        fx.want(k);
    }
    let mut out = Vec::new();
    for k in fx.due() {
        if let Some((_, now)) = fx.settle(&k, || e.suspect(&k.0, &k.1)) {
            if now.is_none() {
                fx.unwant(&k);
            }
            out.push((k, now));
        }
    }
    out
}

// spec/permissions.md §4 (Suspect: dormant; Suspect list): a flag is followed per aspect, due when
// it is raised, when a valid snapshot of its aspect settles it, and when its body back clears it;
// writes elsewhere move nothing.
#[test]
fn a_suspect_flag_is_followed_per_aspect_spec_perm_4() {
    for by_snapshot in [true, false] {
        let mut lp = net2();
        let a = ak("t:big.0");
        let mine = new_thing(&mut lp, 1);
        let mut feed = lp.peers[1].engine.suspect_feed();
        let mut fx = SuspectFx::new("test suspects");
        let (t, c, whole) = purged_page_away(&mut lp, "FOLLOW-7e3c");
        lp.peers[1].engine.flag_suspect(&t, &a, osis_engine::retention::suspect::Why::Uncovered, &[(c, 0)]).unwrap();
        let moved = suspects_moved(&mut lp, 1, &mut feed, &mut fx);
        assert!(matches!(moved.as_slice(), [(k, Some((_, w)))] if *k == (t, a.clone()) && *w != 0), "raised: {moved:?}");
        for i in 0..4 {
            set(&mut lp, 1, mine, &REG, &format!("w{i}"));
            assert_eq!(suspects_moved(&mut lp, 1, &mut feed, &mut fx), vec![], "a write elsewhere");
        }
        // raised again about the same body: only the flag moves
        lp.advance(5);
        lp.peers[1].engine.flag_suspect(&t, &a, osis_engine::retention::suspect::Why::Uncovered, &[(c, 0)]).unwrap();
        let at = lp.peers[1].engine.suspect(&t, &a).unwrap().0;
        assert_eq!(suspects_moved(&mut lp, 1, &mut feed, &mut fx), vec![((t, a.clone()), Some((at, osis_engine::retention::suspect::Why::Uncovered as u8)))], "raised again");
        if by_snapshot {
            lp.advance(5);
            let sc = lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
            let pk = lp.peers[0].engine.package(&sc).unwrap().unwrap();
            lp.deliver(1, &pk).unwrap();
        } else {
            lp.peers[1].receive(&whole.bytes, whole.blobs.clone()).unwrap();
        }
        lp.peers[1].reexamine().unwrap();
        let moved = suspects_moved(&mut lp, 1, &mut feed, &mut fx);
        let want = if by_snapshot { "dormant" } else { "gone" };
        assert!(matches!(moved.as_slice(), [(k, x)] if *k == (t, a.clone()) && if by_snapshot { matches!(x, Some((_, 0))) } else { x.is_none() }), "{want}: {moved:?}");
        assert!(lp.peers[1].engine.suspects().is_empty(), "{want}");
    }
}

// spec/permissions.md §4: a follower of the flags does work per flag that moved, not per flag held: at n
// and 10n flagged aspects, raising one again re-judges that one alone.
#[test]
fn a_flag_moving_rejudges_that_flag_alone_spec_perm_4() {
    for n in [8usize, 80] {
        let mut lp = net2();
        let t = new_thing(&mut lp, 1);
        let body = |i: usize| (osis_base::CommitId([u8::try_from(i % 251).unwrap(); 32]), i / 251);
        let mut feed = lp.peers[1].engine.suspect_feed();
        let mut fx = SuspectFx::new("test suspects");
        for i in 0..n {
            lp.peers[1].engine.flag_suspect(&t, &ak(&format!("t:reg.{i}")), osis_engine::retention::suspect::Why::Uncovered, &[body(i)]).unwrap();
        }
        assert_eq!(suspects_moved(&mut lp, 1, &mut feed, &mut fx).len(), n);
        for i in 0..4 {
            lp.advance(5);
            lp.peers[1].engine.flag_suspect(&t, &ak(&format!("t:reg.{i}")), osis_engine::retention::suspect::Why::Uncovered, &[body(i)]).unwrap();
            let moved = suspects_moved(&mut lp, 1, &mut feed, &mut fx);
            assert_eq!(moved.iter().map(|m| m.0.1.clone()).collect::<Vec<_>>(), vec![ak(&format!("t:reg.{i}"))], "n {n}");
        }
    }
}


// spec/permissions.md §4 (Suspect list): a writer judging a reader's list digests each listed
// aspect once per state of it: at a 100- and a 1,000-element list, judging three entries again
// and again computes nothing anew; a write recomputes the aspect it moved alone, to the digest a
// node holding the same bodies computes, one that asked before the creation record came included.
#[test]
fn a_state_digest_is_computed_once_per_state_spec_perm_4() {
    let computed = || osis_base::costs::take().iter().find(|x| x.0 == "state digest: computed").map_or(0, |x| x.2);
    for n in [100usize, 1000] {
        let mut lp = net2_one();
        let t = new_thing(&mut lp, 0);
        let mut m = Mutation::new();
        let items = (0..n).map(|i| s(&format!("e{i}"))).collect();
        m.op(t, &LIST, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Insert { at: 0, items } }).unwrap();
        m.set(t, &REG, &s("r")).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        let listed = [ak("t:list.0"), ak("t:reg.0"), ak("t:hi.0")];
        osis_base::costs::take();
        let first: Vec<_> = listed.iter().map(|a| lp.peers[0].engine.state_digest(&t, a).unwrap().unwrap()).collect();
        for _ in 0..50 {
            for (a, d) in listed.iter().zip(&first) {
                assert_eq!(lp.peers[0].engine.state_digest(&t, a).unwrap().as_ref(), Some(d), "n {n}");
            }
        }
        assert_eq!(computed(), 3, "n {n}: each listed aspect digested once");
        put_op(&mut lp, 0, t, &LIST, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Insert { at: 0, items: vec![s("new")] } });
        osis_base::costs::take();
        let after: Vec<_> = listed.iter().map(|a| lp.peers[0].engine.state_digest(&t, a).unwrap().unwrap()).collect();
        assert_eq!(computed(), 1, "n {n}: the written aspect alone digested anew");
        assert_ne!(after[0], first[0], "n {n}: the list moved");
        assert_eq!(after[1..], first[1..], "n {n}");
        assert_eq!(lp.peers[1].engine.state_digest(&t, &listed[0]).unwrap(), None, "n {n}: creation record unknown");
        lp.sync_all().unwrap();
        let fresh: Vec<_> = listed.iter().map(|a| lp.peers[1].engine.state_digest(&t, a).unwrap().unwrap()).collect();
        assert_eq!(after, fresh, "n {n}: as a node holding the same bodies digests it");
    }
}
