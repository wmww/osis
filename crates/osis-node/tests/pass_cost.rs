#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The cost of a label pass (notes/sync.md, Implementation (osis-node sync)): bodies are
//! projected per commit once and kept until that commit or the readers change.

mod net;
use net::*;
use osis_core::Role;

// spec/sync.md §6 (convergence after each change): after one more commit under a label holding
// many, the passes it triggers project that commit, not every held one again.
#[test]
fn pass_projects_changed_commits_only_spec_sync_6() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    for i in 0..30 {
        net.item(a, g, g, &format!("item {i}"));
    }
    net.run();
    net.advance(31_000);
    let before = net.engine(a).projections();
    let t = net.item(a, g, g, "one more");
    net.run();
    assert_eq!(net.read(b, t), Some(s("one more")));
    let spent = net.engine(a).projections() - before;
    assert!(spent < 10, "{spent} projections for one commit among 30");
}
