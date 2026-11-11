//! What a node keeps pending is bounded by the entries carrying it (notes/node-sync.md, Unjudged
//! input; spec/sync.md §3 Unjudged blobs; spec/requirements.md: peer input never causes
//! unbounded storage).

use crate::net::*;
use osis_base::Role;
use osis_proto::LabelStore;
use osis_schema::core_types as ct;

const HOURS_2: i64 = 2 * 3_600_000;

/// Node `r` writes its own card's `reach.0` `n` times, `HOURS_2` ahead: each a commit others hold
/// pending for drift, deposited (a reader's own write) under the labels it syncs.
fn cards_ahead(net: &mut Net, r: usize, n: u8) {
    let node = net.node_tid(r);
    net.set_skew(r, HOURS_2);
    for i in 0..n {
        let mut reach = net.engine(r).get_typed(&node, &ct::REACH).unwrap().unwrap_or(ct::Reach { dialable: [0; 32], items: Vec::new(), lan_secret: [0; 32], account: None });
        reach.items = vec![format!("tcp://10.0.0.{i}:1")];
        let mut m = osis_node::Mutation::new();
        m.set(node, &ct::REACH, &reach).unwrap();
        net.engine(r).commit(m).unwrap();
        let acts = net.sync(r).handle(osis_node::sync::Event::Local);
        net.actions(r, acts);
        net.run();
    }
    net.set_skew(r, 0);
}

fn drift_pending(net: &mut Net, n: usize) -> usize {
    net.engine(n).pending().iter().filter(|(_, r)| *r == osis_node::Reason::Drift).count()
}

// A reader's flood of commits that pend (drift) stays within `unvouched_cap` at the node: past it
// the entries and their pending rows go, and the app hears of it. The real commit among them comes
// back from a holder: another writer applies and promotes it once its time comes.
#[test]
fn reader_flood_of_pending_stays_within_the_cap_spec_sync_3() {
    let mut net = Net::new();
    let host = net.add_host();
    // the group's label is its inbox: a sixteenth of the cap, 8
    let cfg = osis_node::sync::SyncConfig { hosts: vec![net.address(host)], unvouched_cap: 128, ..Default::default() };
    let a = net.add_node(1, cfg);
    let r = net.node(2, &[host]);
    let w = net.node(3, &[host]);
    let _g = net.group(a, &[(r, Role::Read), (w, Role::Write)], &[host]);
    net.run();
    net.advance(30_000);
    net.diagnostics(a);
    cards_ahead(&mut net, r, 40);
    let held = drift_pending(&mut net, a);
    assert!((1..=9).contains(&held), "pending held past the cap: {held}");
    assert_eq!(drift_pending(&mut net, w), 40, "the writer's default cap holds them all");
    assert!(net.diagnostics(a).iter().any(|d| d.starts_with("InputCapped")), "the app hears of the cap");
    // the card's time comes: the writer applies and promotes the newest, which reaches `a` stamped
    net.advance(HOURS_2 as u64);
    for _ in 0..4 {
        net.run();
        net.advance(60_000);
    }
    let node = net.node_tid(r);
    let reach = net.engine(a).get_typed(&node, &ct::REACH).unwrap().map(|x| x.items);
    assert_eq!(reach, Some(vec!["tcp://10.0.0.39:1".to_string()]), "the newest card came back");
    assert_eq!(drift_pending(&mut net, a), 0);
}

// Honest pending is unaffected: a writer's commit held for drift (stamped, its entry held) stays
// pending through passes and a restart, with nothing reported, and applies when its time comes.
#[test]
fn held_pending_survives_passes_and_restart_spec_commits_4() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "v1");
    net.run();
    net.set_skew(b, HOURS_2);
    net.write(b, t, "ahead");
    net.set_skew(b, 0);
    net.run();
    assert_eq!(drift_pending(&mut net, a), 1);
    for _ in 0..3 {
        net.advance(60_000);
        net.run();
    }
    net.restart(a, 77);
    net.run();
    assert_eq!(drift_pending(&mut net, a), 1, "kept while its entry is held");
    assert!(!net.diagnostics(a).iter().any(|d| d.starts_with("InputCapped")));
    net.advance(HOURS_2 as u64);
    net.run();
    assert_eq!(net.read(a, t), Some(s("ahead")));
}

// A pending row goes with the last entry carrying it: the host deletes the entry (its author, a
// writer, deletes its own body), and the pending commit counts as never received.
#[test]
fn pending_row_goes_with_its_last_entry_spec_commits_4() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "v1");
    net.run();
    net.set_skew(b, HOURS_2);
    let c = net.write(b, t, "ahead");
    net.set_skew(b, 0);
    net.run();
    assert_eq!(drift_pending(&mut net, a), 1);
    let l = net.label(a);
    let ids: Vec<osis_base::BlobId> = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if *commit == c)).map(|(id, _)| id).collect();
    assert!(!ids.is_empty());
    let now = net.now();
    for id in &ids {
        net.hosts[host].hub.store_mut().delete(&l, id, now).unwrap();
    }
    let acts = net.sync(a).sync_now();
    net.actions(a, acts);
    net.settle(100_000);
    assert!(!net.sync(a).entries(&l).iter().any(|(id, _)| ids.contains(id)), "the deletion reached a");
    assert_eq!(drift_pending(&mut net, a), 0, "the row went with its entry");
}
