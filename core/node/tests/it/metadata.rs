#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! What a blind node learns (spec/requirements.md, Untrusted nodes; notes/sync.md "What a blind
//! node learns"): real engines sync scripted scenarios through an osis-server hub, then the
//! hub's stored bytes are searched for every secret and identifier of the scenario, blob sizes
//! checked against Padmé, labels checked for shared bytes, claim sets for reader counts and
//! heartbeats for content beyond `/seen`.

use crate::net;
use net::*;
use osis_core::{BlobId, CommitId, LabelId, Role, Tid};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use osis_node::sync::EntryKind;
use osis_proto::LabelStore;
use osis_store::Backend;
use std::collections::BTreeSet;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Every live blob a server holds, per label, with its wrap.
fn stored(net: &Net, sv: usize) -> Vec<(LabelId, BlobId, Vec<u8>, [u8; 49])> {
    let s = &net.servers[sv];
    let mut out = Vec::new();
    for l in net.labels_at(sv) {
        for id in s.hub.store().live_ids(&l).unwrap() {
            let blob = s.backend.get_blob(&id).unwrap().unwrap();
            let wrap = s.hub.store().entry(&l, &id).unwrap().unwrap().wrap;
            out.push((l, id, blob, wrap));
        }
    }
    out
}

/// The label of group `g` as node `n` tracks it.
fn label_of(net: &mut Net, n: usize, g: Tid) -> LabelId {
    net.sync(n).labels().into_iter().find(|(t, _)| *t == g).unwrap().1.id
}

/// Padded plaintext length of a blob framed by spec/wire.md §5 (AEAD: 16-byte tag).
fn padded_len(blob: &[u8]) -> usize {
    let p = osis_label::Prefix::parse(blob).unwrap();
    blob.len() - p.len() - 16
}

const MARK_A: &str = "plaintext-marker-alpha-7f3a91";
const MARK_B: &str = "plaintext-marker-beta-c4e82d";
const MAP_KEY: &str = "map-key-marker-5b0e66";

/// Admin a, writer b, reader c in one group at one server: values, a map key, heartbeats.
fn scenario() -> (Net, usize, [usize; 3], Tid, Tid) {
    let mut net = Net::new();
    let sv = net.add_server();
    net.servers[sv].backend.record_history();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read)], &[sv]);
    let t = net.item(a, g, g, MARK_A);
    net.run();
    net.write(b, t, MARK_B);
    let mut m = Mutation::new();
    m.op(t, &BIG, PathOp { path: vec![PathSeg::Key(s(MAP_KEY))], op: Op::Set(s("v")) }).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    net.advance(osis_core::format::HEARTBEAT_MIN_INTERVAL_MS + 60_000);
    net.run();
    assert_eq!(net.read(c, t), Some(s(MARK_B)));
    (net, sv, [a, b, c], g, t)
}

// spec/sync.md §4, spec/requirements.md Untrusted nodes: no plaintext value or map key, tid, AK,
// schema ID, member identity (node tid or signing key) or role secret reaches the blind node's
// storage, live or overwritten
#[test]
fn blind_node_stores_nothing_forbidden() {
    let (mut net, sv, nodes, g, t) = scenario();
    let mut needles: Vec<(String, Vec<u8>)> = vec![
        ("value a".into(), MARK_A.as_bytes().to_vec()),
        ("value b".into(), MARK_B.as_bytes().to_vec()),
        ("map key".into(), MAP_KEY.as_bytes().to_vec()),
        ("schema id".into(), TEST.get().id.0.to_vec()),
        ("group tid".into(), g.as_bytes().to_vec()),
        ("item tid".into(), t.as_bytes().to_vec()),
    ];
    for ak in ["/t/reg", "/t/big", "/members", "/secrets", "/keys", "/label", "/seen", "/node", "/reach", "/group", "/created"] {
        needles.push((format!("ak {ak}"), ak.as_bytes().to_vec()));
    }
    for n in nodes {
        let tid = net.tid(n);
        needles.push((format!("node {n} tid"), tid.as_bytes().to_vec()));
        let pk = net.engine(n).identity().keys().signing.verifying_key().to_bytes();
        needles.push((format!("node {n} signing key"), pk.to_vec()));
    }
    let ep = net.engine(nodes[0]).epochs(&g).unwrap();
    for r in [Role::Read, Role::Write, Role::Admin] {
        let (_, sec) = ep.role(r).newest_secret().unwrap();
        needles.push((format!("{r:?} secret"), sec.expose().to_vec()));
    }
    let history = net.servers[sv].backend.history();
    let blobs = stored(&net, sv);
    assert!(history.len() > 20 && blobs.len() > 10, "the scenario stored something");
    // control: what the node may know (the label ID) is found by the same search
    let l = label_of(&mut net, nodes[0], g);
    assert!(history.iter().any(|(k, v)| contains(k, &l.0) || contains(v, &l.0)));
    for (what, needle) in &needles {
        for (k, v) in &history {
            assert!(!contains(k, needle) && !contains(v, needle), "{what} in the server's records");
        }
        for (_, _, b, w) in &blobs {
            assert!(!contains(b, needle) && !contains(w, needle), "{what} in a stored blob");
        }
    }
}

// spec/wire.md §5, spec/sync.md §1: every stored blob's padded plaintext is a Padmé length;
// values of 1 to 48 bytes fall into a few size classes (Padmé leaks O(log log n) bits: a 1-byte
// and a 100-byte value are in different classes, values within a class are not told apart)
#[test]
fn stored_sizes_are_padme() {
    let (mut net, sv, [a, _, _], g, t) = scenario();
    for (_, id, b, _) in stored(&net, sv) {
        let n = padded_len(&b);
        assert_eq!(osis_crypto::padme(n), n, "blob {id:?}: {n} bytes is not a Padmé length");
    }
    let l = label_of(&mut net, a, g);
    let mut sizes = BTreeSet::new();
    for len in 1..=48 {
        let c: CommitId = net.write(a, t, &"x".repeat(len));
        net.run();
        let blobs: Vec<BlobId> = net.sync(a).entries(&l).into_iter().filter_map(|(id, k)| matches!(k, EntryKind::Commit { commit, .. } if commit == c).then_some(id)).collect();
        assert_eq!(blobs.len(), 1);
        let b = net.servers[sv].backend.get_blob(&blobs[0]).unwrap().unwrap();
        let n = padded_len(&b);
        assert_eq!(osis_crypto::padme(n), n);
        sizes.insert(b.len());
    }
    assert!(sizes.len() <= 5, "48 value lengths in {} size classes: {sizes:?}", sizes.len());
}

// spec/sync.md §1, §3 (certificate blobs): two labels of one writer share no blob ID, salt or
// wrap; the commits under both (the node card, chain certificates) are fresh encryptions per label
#[test]
fn no_linkage_across_labels() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let addr = vec![net.address(sv)];
    let g1 = net.group_seeded(a, &[(b, Role::Write)], addr.clone(), 11);
    let g2 = net.group_seeded(a, &[(b, Role::Write)], addr, 12);
    net.item(a, g1, g1, "one");
    net.item(b, g2, g2, "two");
    net.run();
    let (l1, l2) = (label_of(&mut net, a, g1), label_of(&mut net, a, g2));
    let blobs = stored(&net, sv);
    let of = |l: LabelId| blobs.iter().filter(move |x| x.0 == l);
    let ids1: BTreeSet<BlobId> = of(l1).map(|x| x.1).collect();
    let salts1: BTreeSet<Vec<u8>> = of(l1).map(|x| x.2[1..17].to_vec()).collect();
    let wraps1: BTreeSet<[u8; 49]> = of(l1).map(|x| x.3).collect();
    assert!(ids1.len() > 3);
    for (_, id, b, w) in of(l2) {
        assert!(!ids1.contains(id), "a blob shared by both labels");
        assert!(!salts1.contains(&b[1..17]), "a salt reused across labels");
        assert!(!wraps1.contains(w), "a wrap reused across labels");
    }
    let commits = |net: &mut Net, l: LabelId| -> BTreeSet<CommitId> {
        net.sync(a).entries(&l).into_iter().filter_map(|(_, k)| if let EntryKind::Commit { commit, .. } = k { Some(commit) } else { None }).collect()
    };
    let (c1, c2) = (commits(&mut net, l1), commits(&mut net, l2));
    assert!(c1.intersection(&c2).next().is_some(), "certificate commits travel under both labels (as distinct blobs)");
}

// spec/sync.md §2 (claim set), notes/sync.md "What a blind node learns": claim sets are padded
// to a power of two in random order: labels with 3 and 4 readers show the same set size
#[test]
fn claim_sets_hide_reader_counts() {
    let mut net = Net::new();
    let sv = net.add_server();
    let n: Vec<usize> = (1..=5).map(|i| net.node(i, &[sv])).collect();
    let readers = |k: usize| n[1..=k].iter().map(|x| (*x, Role::Read)).collect::<Vec<_>>();
    let addr = vec![net.address(sv)];
    let g3 = net.group_seeded(n[0], &readers(2), addr.clone(), 13);
    let g4 = net.group_seeded(n[0], &readers(3), addr.clone(), 14);
    let g5 = net.group_seeded(n[0], &readers(4), addr, 15);
    net.run();
    let set = |net: &mut Net, g: Tid| {
        let l = label_of(net, n[0], g);
        let store = net.servers[sv].hub.store();
        let head = store.head(&l).unwrap().unwrap();
        store.claim_set(&l, &head).unwrap().unwrap().claims.clone()
    };
    let (s3, s4, s5) = (set(&mut net, g3), set(&mut net, g4), set(&mut net, g5));
    assert_eq!((s3.len(), s4.len(), s5.len()), (4, 4, 8));
    let mut sorted = s5.clone();
    sorted.sort();
    assert_ne!(s5, sorted, "claims in random order");
}

// spec/permissions.md §4 (heartbeat): a heartbeat commit writes `/seen` on its own node thing
// and nothing else, expiring within the heartbeat bounds
#[test]
fn heartbeats_carry_only_seen() {
    let (mut net, _, [a, b, c], _, _) = scenario();
    let mut authors = BTreeSet::new();
    let e = net.engine(a);
    for id in e.commit_ids() {
        let h = e.header(&id).unwrap();
        if !h.aspects.iter().any(|x| x.ak.as_str() == "/seen") {
            continue;
        }
        authors.insert(h.author);
        assert_eq!(h.kind, osis_commit::Kind::Content);
        assert!(h.chunks.is_empty() && h.purge.is_empty() && h.undoes.is_none() && h.frontier.is_none() && h.origins.is_empty());
        let ts = h.ts.wall_ms().0;
        for x in &h.aspects {
            assert_eq!((x.ak.as_str(), x.tid), ("/seen", h.author), "a heartbeat carried more than /seen");
            let exp = x.expires.unwrap();
            assert!(exp >= ts + osis_core::format::HEARTBEAT_MIN_LIFETIME_MS && exp <= ts + osis_core::format::HEARTBEAT_MAX_LIFETIME_MS);
        }
    }
    let want: BTreeSet<Tid> = [b, c].iter().map(|n| net.tid(*n)).collect();
    assert!(want.is_subset(&authors), "heartbeats of b and c seen by a");
}

