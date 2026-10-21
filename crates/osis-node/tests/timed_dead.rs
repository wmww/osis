#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Timed deletes of bodies whose writes all died (spec/sync.md §5, §7): no carrier snapshot.

mod net;
use net::*;
use osis_node::Mutation;
use osis_node::sync::EntryKind;

// spec/sync.md §7 (a body with live writes is deleted only while another entry carries them;
// one without needs none), spec/commits.md §5: a register under a relative keep-at-most
// replaced whole goes at its bound by a timed delete sent with the replacing upload, and no
// covering snapshot is written for it.
#[test]
fn replaced_register_needs_no_carrier_spec_sync_7() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    let t = net.item(a, g, g, "x");
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("v1")).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    let l = net.label(a);
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("v2")).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    net.run();
    let snapshots = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if net.engine(a).header(commit).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot))).count();
    assert_eq!(snapshots, 0, "no carrier for a body without live writes");
    let before = net.server_ids(sv, &l).len();
    net.set_online(a, false);
    net.clock.advance(3_600_000 + 1_000);
    let now = net.now();
    net.servers[sv].hub.tick(now);
    assert_eq!(net.server_ids(sv, &l).len() + 1, before, "the replaced body went at its bound, nobody online");
}
