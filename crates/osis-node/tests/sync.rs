#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Node sync engines through blind nodes, in process (spec/sync.md §2-§9).

mod net;
use net::*;
use osis_core::Role;

// spec/sync.md §3, §5, §6: two nodes of one group converge through one blind server: closure
// bodies uploaded stamped, downloaded, unwrapped and applied, both ways.
#[test]
fn two_nodes_converge_spec_sync_6() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "hello");
    net.run();
    for n in [a, b] {
        eprintln!("node {n}: diags {:?}", net.sync(n).take_diagnostics());
        eprintln!("node {n}: pending {:?} knows item {}", net.engine(n).pending(), net.engine(n).knows(&t));
        let ls = net.sync(n).open_labels(&server_key(sv));
        eprintln!("node {n}: open {:?}", ls);
        let lab: Vec<_> = net.sync(n).labels().into_iter().map(|(g, l)| (g, l.id, l.servers.len())).collect();
        eprintln!("node {n}: labels {:?} groups {:?} steps {}", lab, net.engine(n).labeled_groups(), net.steps);
        for l in ls { eprintln!("  entries {:?}", net.sync(n).entries(&l)); }
    }
    for l in net.labels_at(sv) { eprintln!("server label {:?}: {} entries", l, net.server_ids(sv, &l).len()); }
    assert_eq!(net.read(b, t), Some(s("hello")));
    net.write(b, t, "back");
    net.run();
    assert_eq!(net.read(a, t), Some(s("back")));
}
