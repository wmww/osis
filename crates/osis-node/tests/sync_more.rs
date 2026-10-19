#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Certificates and heartbeats, pages and lazy chunks, reconciliation, inbox blobs through a
//! blind node (spec/sync.md §3, §6; spec/permissions.md §4).

mod net;
use net::*;
use osis_core::{Ak, Role, Value};
use osis_node::Mutation;
use osis_node::sync::{EntryKind, SyncConfig};
use osis_schema::AspectKey;
use osis_schema::core_types as ct;
use osis_server::Policy;
use std::collections::BTreeSet;

fn diags(net: &mut Net, nodes: &[usize]) {
    for n in nodes {
        let d = net.sync(*n).take_diagnostics();
        if !d.is_empty() {
            eprintln!("node {n}: {d:?}");
        }
    }
}

/// Commits under label `l` that `n` knows, with the aspects their headers touch.
fn commits_under(net: &mut Net, n: usize, l: &osis_core::LabelId) -> Vec<(osis_core::CommitId, osis_core::Tid, BTreeSet<String>)> {
    let entries = net.sync(n).entries(l);
    let mut out = Vec::new();
    for (_, k) in entries {
        if let EntryKind::Commit { commit, .. } = k
            && let Some(h) = net.engine(n).header(&commit)
        {
            out.push((commit, h.author, h.aspects.iter().map(|a| a.ak.as_str().to_string()).collect()));
        }
    }
    out
}

// spec/permissions.md §4, spec/sync.md §3, §5: every node placing under a label puts its node
// card and heartbeat there, a reader by deposit; co-members apply them.
#[test]
fn certificates_and_heartbeats_spec_permissions_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[sv]);
    let _g = net.group(a, &[(r, Role::Read)], &[sv]);
    net.run();
    diags(&mut net, &[a, r]);
    let l = net.label(a);
    let rt = net.tid(r);
    let under = commits_under(&mut net, a, &l);
    let by_r: Vec<&BTreeSet<String>> = under.iter().filter(|(_, au, _)| *au == rt).map(|(_, _, a)| a).collect();
    assert!(by_r.iter().any(|a| a.contains("/node")), "the reader's node card: {under:?}");
    assert!(by_r.iter().any(|a| a.contains("/seen")), "the reader's heartbeat");
    let seen = net.engine(a).get_typed(&rt, &ct::SEEN).unwrap().unwrap();
    assert!(!seen.stranded);
    // a heartbeat at most once per interval
    let n = net.server_ids(sv, &l).len();
    net.advance(60_000);
    assert_eq!(net.server_ids(sv, &l).len(), n);
}

// spec/sync.md §6, spec/commits.md §4: pages of a paged delta are fetched before its commit
// applies; chunks of a large value are fetched lazily, on demand.
#[test]
fn pages_and_lazy_chunks_spec_sync_6() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.add_node(2, SyncConfig { servers: vec![net.address(sv)], inline_limit: 0, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "x");
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let map: std::collections::BTreeMap<Value, Value> = (0..2000).map(|i| (Value::Str(format!("key {i:05}")), Value::Str("v".repeat(60)))).collect();
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(big.clone())).unwrap();
    net.engine(a).commit(m).unwrap();
    let mut m = Mutation::new();
    m.set(t, &BIG, &Value::Map(map.clone())).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    diags(&mut net, &[a, b]);
    let big_ak = Ak::new(BIG.ak()).unwrap();
    let got = net.engine(b).get(&t, &big_ak).unwrap();
    assert!(got == Some(Value::Map(map)), "the paged delta applied; pending {:?}", net.engine(b).pending());
    let blob_ak = Ak::new(BLOB.ak()).unwrap();
    assert!(net.engine(b).get_full(&t, &blob_ak).is_err(), "chunks not fetched yet");
    let acts = net.sync(b).fetch_missing();
    net.actions(b, acts);
    net.settle(100_000);
    assert_eq!(net.engine(b).get_full(&t, &blob_ak).unwrap(), Some(Value::Bytes(big)));
}

// spec/sync.md §6: a cursor the server no longer serves (log trimmed) falls back to range
// reconciliation, then a fresh cursor.
#[test]
fn reconciliation_fallback_spec_sync_6() {
    let mut net = Net::new();
    let sv = net.add_server_with(Policy { log_keep: 16, ..Policy::default() });
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "v0");
    net.run();
    net.set_online(b, false);
    for i in 1..40 {
        net.write(a, t, &format!("v{i}"));
        net.run();
    }
    net.set_online(b, true);
    net.advance(10_000);
    diags(&mut net, &[b]);
    assert_eq!(net.read(b, t), Some(s("v39")));
}

// spec/sync.md §2-§3, spec/crypto.md §5: an inbox blob sealed to an actor's read key and
// deposited under its inbox (its home label) is opened by a member device and applied.
#[test]
fn inbox_delivery_spec_sync_3() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let s_ = net.node(3, &[sv]);
    // P: an actor of A (admin) and B, its home label its inbox
    let p = net.group(a, &[(b, Role::Write)], &[sv]);
    let (_, home) = net.sync(a).labels().into_iter().next().unwrap();
    let mut m = Mutation::new();
    let inbox = ct::Inbox { label: home.id, servers: home.servers.clone() };
    m.op(p, &ct::KEYS, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(4)], op: osis_crdt::Op::Replace(Some(inbox).to_value()) }).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    // the sender knows P's /keys (paired with A) and B knows the sender's chain
    net.pair(a, s_);
    net.pair(s_, b);
    let me = net.tid(s_);
    let e = net.engine(s_);
    let mut m = Mutation::new();
    let x = e.new_thing(&mut m, me);
    m.set(x, &REG, &s("for P")).unwrap();
    let c = e.commit(m).unwrap().unwrap();
    let all: BTreeSet<usize> = (0..net.engine(s_).header(&c).unwrap().aspects.len()).collect();
    let acts = net.sync(s_).deliver_inbox(&p, &c, &all).unwrap();
    net.actions(s_, acts);
    net.run();
    diags(&mut net, &[s_, b]);
    assert!(net.sync(b).entries(&home.id).iter().any(|(_, k)| *k == EntryKind::Inbox));
    assert_eq!(net.read(b, x), Some(s("for P")));
}

use osis_schema::Codec;
