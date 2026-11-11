#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! spec: none (issues/net-reconnect.md, One node log): the node log follows every path that
//! changes a held entry, so a listing from its start is the node's live set of every label.

use crate::net::{hosted, hosted_nodes};
use crate::net;
use net::*;
use osis_base::{Ak, BlobId, LabelId, Role, Value};
use osis_schema::RawKey;
use osis_node::Mutation;
use osis_node::sync::SyncConfig;
use osis_store::NodeEvent;
use std::collections::{BTreeMap, BTreeSet};

/// Checks the log against the entries held, for every label it names; the live entries it lists.
fn compare(net: &mut Net, n: usize) -> usize {
    let events = net.sync(n).hub_store().lock().unwrap().node_log(|t| t.log_read(None, 1 << 20)).unwrap().events;
    let mut added: BTreeMap<LabelId, BTreeSet<BlobId>> = BTreeMap::new();
    for e in &events {
        match e.event {
            NodeEvent::Added(l, b) => {
                added.entry(l).or_default().insert(b);
            }
            NodeEvent::Deleted { label: l, .. } | NodeEvent::Head(l) => {
                added.entry(l).or_default();
            }
        }
    }
    let mut live = 0;
    for (l, listed) in added {
        let held: BTreeSet<BlobId> = net.sync(n).entries(&l).into_iter().map(|(b, _)| b).filter(|b| net.engine(n).has_blob(b)).collect();
        assert_eq!(listed, held, "node {n}: the log's live set of a label is the entries it serves (bytes held)");
        live += listed.len();
    }
    live
}

fn deletions(net: &mut Net, n: usize) -> usize {
    let events = net.sync(n).hub_store().lock().unwrap().node_log(|t| t.log_read(None, 1 << 20)).unwrap().events;
    events.iter().filter(|e| matches!(e.event, NodeEvent::Deleted { .. })).count()
}

// every entry path, on the writer and the receiver: a commit, its apply at another node, and a
// compaction's drop of what it covers
#[test]
fn log_follows_every_entry_path() {
    let (mut net, _host, [a, b], _g, [t]) = hosted::<2, 1>(&[(1, Role::Write)], ["one"], true);
    assert!(compare(&mut net, a) > 0, "a commit logs");
    assert!(compare(&mut net, b) > 0, "an applied commit logs");
    net.write(a, t, "two");
    net.write(a, t, "three");
    net.run();
    compare(&mut net, a);
    let acts = net.sync(a).compact(&t, &Ak::new(REG.ak()).unwrap()).unwrap();
    net.actions(a, acts);
    net.run();
    compare(&mut net, a);
    compare(&mut net, b);
    assert!(deletions(&mut net, a) > 0, "compaction's drops are deletion events");
    assert!(deletions(&mut net, b) > 0, "and reach the node that applies them");
    net.restart(a, 11);
    net.run();
    compare(&mut net, a);
}

// an entry that actually expires leaves the log as a deletion event, and a listing no longer shows it
#[test]
fn an_expired_entry_is_a_deletion_in_the_log() {
    let (mut net, _host, [a], _g, [t]) = hosted::<1, 1>(&[], ["v1"], true);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("v2")).unwrap();
    m.expires(t, &REG, osis_base::WallMs(net.now() + 5_000)).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    compare(&mut net, a);
    let before = deletions(&mut net, a);
    net.advance(6_000);
    net.run();
    assert_eq!(net.read(a, t), None, "it expired");
    assert!(deletions(&mut net, a) > before, "its entry's expiry is a deletion event");
    compare(&mut net, a);
}

/// The events a peer gets reading `n`'s log from the position where the log ends now.
fn after(net: &mut Net, n: usize, cursor: &[u8]) -> Vec<NodeEvent> {
    net.sync(n).hub_store().lock().unwrap().node_log(|t| t.log_read(Some(cursor), 1 << 20)).unwrap().events.into_iter().map(|e| e.event).collect()
}

fn cursor_at_end(net: &mut Net, n: usize) -> Vec<u8> {
    net.sync(n)
        .hub_store()
        .lock()
        .unwrap()
        .node_log(|t| {
            let end = t.log_end()?;
            t.log_cursor(end)
        })
        .unwrap()
        .expect("something logged")
}

// an announcement without bytes reaches a node before the commit blob does: a peer already past
// that point of the log learns the entry from the arrival of the bytes
#[test]
fn a_commit_blob_is_logged_when_its_bytes_arrive() {
    let (mut net, host, [a]) = hosted_nodes::<1>();
    let b = net.add_node(2, SyncConfig { hosts: vec![net.address(host)], inline_limit: 0, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let l = net.label(a);
    net.run();
    net.item(a, g, g, "one");
    net.tick(0);
    // the round where b knows an entry whose bytes have not come
    let mut pending = None;
    for _ in 0..1_000 {
        let absent = net.sync(b).entries(&l).into_iter().map(|(x, _)| x).find(|x| !net.engine(b).has_blob(x));
        if absent.is_some() {
            pending = absent;
            break;
        }
        net.round();
    }
    let blob = pending.expect("an entry announced without its bytes");
    let cursor = cursor_at_end(&mut net, b);
    net.run();
    assert!(net.engine(b).has_blob(&blob), "fetched");
    assert_eq!(after(&mut net, b, &cursor).iter().filter(|e| **e == NodeEvent::Added(l, blob)).count(), 1, "a peer past the announcement learns the entry from the bytes");
    compare(&mut net, b);
}

// a chunk gets no entry write as its bytes arrive; they log it all the same
#[test]
fn a_chunk_is_logged_when_its_bytes_arrive() {
    let (mut net, host, [a]) = hosted_nodes::<1>();
    let b = net.add_node(2, SyncConfig { hosts: vec![net.address(host)], inline_limit: 0, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    let t = net.item(a, g, g, "x");
    let v: Vec<u8> = (0..700_000u32).map(|i| (i % 251) as u8).collect();
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(v)).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    let ak = Ak::new(BLOB.ak()).unwrap();
    let Some(Value::Link(link)) = net.engine(b).get(&t, &ak).unwrap() else { panic!("a link") };
    let l = net.label(a);
    let absent: BTreeSet<BlobId> = net.sync(b).entries(&l).into_iter().map(|(x, _)| x).filter(|x| !net.engine(b).has_blob(x)).collect();
    assert!(!absent.is_empty(), "chunks stay lazy");
    let cursor = cursor_at_end(&mut net, b);
    for _ in 0..8 {
        let acts = net.sync(b).fetch_tree(&t, &link).unwrap();
        if acts.is_empty() {
            break;
        }
        net.actions(b, acts);
        net.settle(100_000);
    }
    let arrived: Vec<BlobId> = absent.iter().copied().filter(|x| net.engine(b).has_blob(x)).collect();
    assert!(!arrived.is_empty(), "the tree came");
    let logged = after(&mut net, b, &cursor);
    for x in &arrived {
        assert_eq!(logged.iter().filter(|e| **e == NodeEvent::Added(l, *x)).count(), 1, "each chunk arrival is one event");
    }
}

// spec: none (issues/net-reconnect.md: a cursor is stored only with what it covers applied): a
// crash at any write while a connected node takes a pushed event with its bytes leaves it,
// restarted, with no cursor past a commit it has not applied and the log matching what it holds;
// it then converges
#[test]
fn a_crash_taking_bytes_leaves_no_cursor_ahead_of_its_data() {
    let mut reached = false;
    for n in 0.. {
        let f = osis_store::Faults::new();
        let mut net = Net::new();
        let host = net.add_host();
        let a = net.node(1, &[host]);
        let b = net.forensic_node(2, &[host], &f);
        let g = net.group(a, &[(b, Role::Write)], &[host]);
        let t = net.item(a, g, g, "before");
        net.run();
        let l = net.label(a);
        let at = net.sync(b).cursor_seqs(&l);
        net.write(a, t, "after");
        f.at(n, osis_store::Fault::Crash);
        // runs until the device dies: the process is gone there (reads of a dead device trip
        // the engine's debug cache checks, so a panic past the crash is that same death)
        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            net.feed(a, osis_node::sync::Event::Local);
            while !f.crashed() && net.step() {}
        }));
        let crashed = f.crashed();
        if let Err(p) = run
            && !crashed
        {
            std::panic::resume_unwind(p);
        }
        f.revive();
        net.set_online(b, false);
        net.restart(b, 77);
        let cur = net.sync(b).cursor_seqs(&l);
        reached |= cur != at;
        if cur != at {
            assert_eq!(net.read(b, t), Some(s("after")), "crash at write {n}: a cursor stored ahead of its data");
        }
        compare(&mut net, b);
        net.set_online(b, true);
        net.feed(b, osis_node::sync::Event::Local);
        net.run();
        assert_eq!(net.read(b, t), Some(s("after")), "crash at write {n}: converges");
        compare(&mut net, b);
        if !crashed {
            assert!(reached, "the push moved the cursor");
            return;
        }
    }
}

// issues/net-one-peer.md step 4 (one store): co-readers with no host, each serving the group to the
// other from its one store: every entry a node holds bytes of is one row there, and the blobs on
// its disk are exactly the distinct blobs of those entries (a body read and served is stored once).
#[test]
fn a_group_read_and_served_is_stored_once() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    crate::peers::reach_ed(&mut net, a);
    let g = net.group_seeded(a, &[(b, Role::Write)], vec![], 11);
    let t = net.item(a, g, g, "one");
    net.run();
    net.write(b, t, "two");
    net.run();
    assert_eq!(net.read(a, t), Some(s("two")));
    for n in [a, b] {
        let mut held = BTreeSet::new();
        for (_, gl) in net.sync(n).labels() {
            let l = gl.id;
            let mine: BTreeSet<BlobId> = net.sync(n).entries(&l).into_iter().map(|(x, _)| x).filter(|x| net.engine(n).has_blob(x)).collect();
            let rows: BTreeSet<BlobId> = net.sync(n).hub_store().lock().unwrap().reader_rows(&l, None, 1 << 16).unwrap().into_iter().map(|(x, _)| x).collect();
            assert_eq!(rows, mine, "node {n}: one row per entry it holds");
            held.extend(mine);
        }
        assert!(!held.is_empty());
        assert_eq!(net.blobs_on_disk(n), held.len() as u64, "node {n}: each blob once");
    }
}
