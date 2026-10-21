#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Others' certificates judged (spec/permissions.md §4; spec/sync.md §6): a node card
//! superseded by a newer one, and the dialing parts of a departed node's card, leave the label.

mod net;
use net::*;
use osis_core::{BlobId, CommitId, LabelId, Role, Tid};
use osis_node::flows::{Demotion, PreSync};
use osis_node::sync::EntryKind;

/// Entries present at server `sv` under `l` (as node `n` knows them) of commits touching
/// `(author, ak)`, with their commits.
fn card_entries(net: &mut Net, n: usize, sv: usize, l: &LabelId, author: Tid, ak: &str) -> Vec<(BlobId, CommitId)> {
    let ids = net.server_ids(sv, l);
    let mut out = Vec::new();
    for (id, k) in net.sync(n).entries(l) {
        let EntryKind::Commit { commit, parts } = k else { continue };
        let Some(h) = net.engine(n).header(&commit) else { continue };
        if ids.contains(&id) && parts.iter().any(|(ai, _)| h.aspects.get(*ai).is_some_and(|a| a.tid == author && a.ak.as_str() == ak)) {
            out.push((id, commit));
        }
    }
    out
}

fn settle(net: &mut Net) {
    for _ in 0..3 {
        net.advance(31_000);
    }
}

// spec/permissions.md §4 (the node card is placed again when it changes): once a reader's new
// `/reach` is under the label, the admin deletes the superseded card commit's entries.
#[test]
fn superseded_card_deleted_spec_permissions_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[sv]);
    let _g = net.group(a, &[(r, Role::Read)], &[sv]);
    let acts = net.sync(r).publish_reach([1; 32], Vec::new()).unwrap();
    net.actions(r, acts);
    settle(&mut net);
    let l = net.label(a);
    let rt = net.tid(r);
    let old = card_entries(&mut net, a, sv, &l, rt, "/reach");
    assert!(!old.is_empty(), "the first card is there");
    let acts = net.sync(r).publish_reach([2; 32], Vec::new()).unwrap();
    net.actions(r, acts);
    settle(&mut net);
    let now = card_entries(&mut net, a, sv, &l, rt, "/reach");
    assert!(!now.is_empty() && now.iter().all(|(_, c)| old.iter().all(|(_, o)| o != c)), "only the newer card is left: {old:?} {now:?}");
}

// spec/permissions.md §4, spec/sync.md §6 (required set): a removed reader's `/reach` and
// `/node` go from the label; its `/keys`, which chains of its old writes may need, stays.
#[test]
fn departed_node_card_deleted_spec_permissions_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[sv]);
    let g = net.group(a, &[(r, Role::Read)], &[sv]);
    let acts = net.sync(r).publish_reach([1; 32], Vec::new()).unwrap();
    net.actions(r, acts);
    settle(&mut net);
    let l = net.label(a);
    let rt = net.tid(r);
    assert!(!card_entries(&mut net, a, sv, &l, rt, "/reach").is_empty());
    let keys = card_entries(&mut net, a, sv, &l, rt, "/keys");
    assert!(!keys.is_empty());
    net.set_online(r, false);
    let done = net.engine(a).demote(&g, &Demotion { member: rt, new: None, presync: PreSync::Synced }).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    settle(&mut net);
    assert!(card_entries(&mut net, a, sv, &l, rt, "/reach").is_empty(), "the departed node's /reach went");
    assert!(card_entries(&mut net, a, sv, &l, rt, "/node").is_empty(), "and its /node");
    assert!(!card_entries(&mut net, a, sv, &l, rt, "/keys").is_empty(), "its /keys stays");
}

// spec/sync.md §3 (a certificate copy carries the blobs its parts link), §6: once no entry of
// the copied commit is under the label any more, the admin deletes the linked blobs the copy
// placed (here an owner's `/created` from a commit whose aspect list goes by link).
#[test]
fn linked_blobs_of_gone_copy_deleted_spec_sync_3() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let me = net.tid(a);
    let e = net.engine(a);
    let mut m = osis_node::Mutation::new();
    let p = e.new_thing(&mut m, me);
    for i in 0..800 {
        m.set(p, &osis_core::Ak::new(format!("/u/{}{i:05}", "a".repeat(100))).unwrap(), &s("v")).unwrap();
    }
    let pc = e.commit(m).unwrap().unwrap();
    assert!(net.engine(a).header(&pc).unwrap().links.aspects.is_some(), "the aspect list goes by link");
    let mut m = osis_node::Mutation::new();
    let h = net.engine(a).new_thing(&mut m, p);
    m.set(h, &osis_schema::core_types::GROUP, &osis_schema::core_types::Group::default()).unwrap();
    net.engine(a).commit(m).unwrap();
    let done = net.engine(a).give_own_secrets(&h).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let addr = net.address(sv);
    let (l, acts) = net.sync(a).create_label(&h, vec![addr]).unwrap();
    net.actions(a, acts);
    settle(&mut net);
    let copies: Vec<BlobId> = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == pc)).map(|(id, _)| id).collect();
    let linked: Vec<BlobId> = net.sync(a).entries(&l).into_iter().filter(|(_, k)| *k == EntryKind::Unknown).map(|(id, _)| id).collect();
    let ids = net.server_ids(sv, &l);
    assert!(!copies.is_empty() && copies.iter().all(|c| ids.contains(c)), "the owner's /created copy is there");
    assert!(!linked.is_empty() && linked.iter().all(|b| ids.contains(b)), "with its linked aspect list");
    // the copy deleted at the server behind the node's back; it learns at its next sync
    net.set_online(a, false);
    for id in &copies {
        let now = net.now();
        osis_proto::LabelStore::delete(net.servers[sv].hub.store_mut(), &l, id, now).unwrap();
    }
    net.set_online(a, true);
    settle(&mut net);
    let ids = net.server_ids(sv, &l);
    assert!(linked.iter().all(|b| !ids.contains(b)), "the linked blobs went with the copy");
}
