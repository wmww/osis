#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! spec: none (issues/net-reconnect.md, One node log): the node log follows every path that
//! changes a held entry, so a listing from its start is the node's live set of every label.

use crate::net;
use net::*;
use osis_base::{Ak, BlobId, LabelId, Role};
use osis_schema::RawKey;
use osis_node::Mutation;
use osis_store::NodeEvent;
use std::collections::{BTreeMap, BTreeSet};

/// Checks the log against the entries held, for every label it names; the live entries it lists.
fn compare(net: &mut Net, n: usize) -> usize {
    let events = net.engine(n).run(|tx| Ok(tx.txn.log_read(None, 1 << 20)?)).unwrap().events;
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
        let held: BTreeSet<BlobId> = net.sync(n).entries(&l).into_iter().map(|(b, _)| b).collect();
        assert_eq!(listed, held, "node {n}: the log's live set of a label is the entries it holds");
        live += listed.len();
    }
    live
}

fn deletions(net: &mut Net, n: usize) -> usize {
    let events = net.engine(n).run(|tx| Ok(tx.txn.log_read(None, 1 << 20)?)).unwrap().events;
    events.iter().filter(|e| matches!(e.event, NodeEvent::Deleted { .. })).count()
}

// every entry path, on the writer and the receiver: a commit, its apply at another node, and a
// compaction's drop of what it covers
#[test]
fn log_follows_every_entry_path() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "one");
    net.run();
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
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
    let t = net.item(a, g, g, "v1");
    net.run();
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
