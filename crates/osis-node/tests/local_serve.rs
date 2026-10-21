#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A label a node syncs with no server (spec/sync.md §5, member peer): the node serves it as
//! such a server would hold it after its sync, so what the label must no longer hold leaves the
//! served state too, and a removal moves its head.

mod net;
use net::*;
use osis_core::{Ak, BlobId, LabelId, Role, Tid, WallMs};
use osis_node::flows::{Demotion, PreSync};
use osis_node::sync::EntryKind;
use osis_schema::AspectKey;

/// Node `a` (dialable: `/reach` published) with group `g` labeled at no server, and `b` a
/// writer of it.
fn setup() -> (Net, usize, usize, Tid, LabelId) {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    let g = net.group(a, &[(b, Role::Write)], &[]);
    let acts = net.sync(a).publish_reach([1; 32], Vec::new()).unwrap();
    net.actions(a, acts);
    net.run();
    let l = net.label(a);
    assert!(net.sync(a).labels()[0].1.servers.is_empty());
    (net, a, b, g, l)
}

fn listed(net: &mut Net, n: usize, l: &LabelId) -> Vec<BlobId> {
    net.sync(n).entries(l).into_iter().map(|(id, _)| id).collect()
}

// spec/sync.md §5 (member peer: served complete), spec/commits.md §5 (a purge drops every body
// carrying the values, chunks included): a purged large value's chunks leave the served state
// and the node.
#[test]
fn purged_chunks_leave_local_label_spec_sync_5() {
    let (mut net, a, _, g, l) = setup();
    let t = net.item(a, g, g, "x");
    let big: String = (0..300_000u32).map(|i| char::from(b'a' + (i.wrapping_mul(2654435761) >> 27) as u8 % 26)).collect();
    let mut m = osis_node::Mutation::new();
    m.set(t, &GONE, &s(&big)).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let chunks: Vec<BlobId> = net.engine(a).header(&c).unwrap().chunks.iter().map(|ch| ch.blob).collect();
    assert!(!chunks.is_empty(), "a chunked value");
    let ids = listed(&mut net, a, &l);
    assert!(chunks.iter().all(|id| ids.contains(id)), "chunks served");
    let mut m = osis_node::Mutation::new();
    m.purge(osis_commit::PurgeItem::Commit { commit: c, tid: t, ak: Ak::new(GONE.ak()).unwrap() });
    m.remove_aspect(t, &GONE).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    let ids = listed(&mut net, a, &l);
    let left: Vec<_> = chunks.iter().filter(|id| ids.contains(id) || net.sync(a).holds_blob(id)).collect();
    assert!(left.is_empty(), "{} of {} chunks of the purged value stay", left.len(), chunks.len());
    let bodies = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == c)).count();
    assert_eq!(bodies, 0, "the purged body's entry went");
}

// spec/sync.md §5 (re-registration: an admin holding a newer established epoch issues a child of
// the head), spec/permissions.md §3 (a removal rotates): removing a writer moves the head of the
// label served with no server, so the removed member's old keys open nothing new.
#[test]
fn removal_moves_local_head_spec_sync_5() {
    let (mut net, a, b, g, l) = setup();
    let steps = |net: &mut Net| net.engine(a).group_labels(&g).unwrap().into_iter().find(|x| x.id == l).unwrap().steps.len();
    assert_eq!(steps(&mut net), 1);
    let bt = net.tid(b);
    let done = net.engine(a).demote(&g, &Demotion { member: bt, new: None, presync: PreSync::Synced }).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.advance(31_000);
    assert_eq!(steps(&mut net), 2, "a child step registered and recorded");
    let gl = net.engine(a).group_labels(&g).unwrap().into_iter().find(|x| x.id == l).unwrap();
    let tips = gl.tips();
    assert_eq!(tips.len(), 1);
    let (tip, _) = gl.steps.get(&tips[0]).unwrap().clone();
    let (genesis, _) = gl.steps.values().find(|(s, _)| s.prev.is_none()).unwrap().clone();
    assert_ne!(tip.keys.sync, genesis.keys.sync, "the new head has new keys");
    assert_ne!(tip.keys.write, genesis.keys.write);
}

// spec/sync.md §5 (expiry: at the prefix's T the entry goes outright), spec/commits.md §5: an
// expired body leaves the label served with no server.
#[test]
fn expired_body_leaves_local_label_spec_sync_5() {
    let (mut net, a, _, g, l) = setup();
    let t = net.item(a, g, g, "x");
    let now = net.engine(a).now();
    let mut m = osis_node::Mutation::new();
    m.set(t, &REG, &s("brief")).unwrap();
    m.expires(t, &REG, WallMs(now.0 + 5_000)).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let of_c = |net: &mut Net| net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == c)).map(|(id, _)| id).collect::<Vec<_>>();
    let ids = of_c(&mut net);
    assert!(!ids.is_empty(), "served before it expires");
    net.advance(10_000);
    net.advance(31_000);
    assert!(of_c(&mut net).is_empty(), "the expired body's entry went");
    assert!(ids.iter().all(|id| !net.sync(a).holds_blob(id)), "and its bytes");
}
