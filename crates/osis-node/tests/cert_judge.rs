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

// spec/permissions.md §4 (a member node places its card under the labels it reads): a reader
// removed while offline, its card deleted by the admin, then re-granted, places its card again
// when it is back, though its `/reach` did not change.
#[test]
fn regranted_node_card_placed_again_spec_permissions_4() {
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
    let first = card_entries(&mut net, a, sv, &l, rt, "/reach");
    assert!(!first.is_empty());
    net.set_online(r, false);
    let done = net.engine(a).demote(&g, &Demotion { member: rt, new: None, presync: PreSync::Synced }).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    settle(&mut net);
    assert!(card_entries(&mut net, a, sv, &l, rt, "/reach").is_empty(), "the departed node's /reach went");
    let at = net.tid(a);
    let e = net.engine(a);
    set_edge(e, g, rt, Role::Read);
    let rcpt = recipients_of(e, &[(at, Role::Admin), (rt, Role::Read)]);
    rotation(e, g, &rcpt, 9, false);
    net.pair(a, r);
    net.set_online(r, true);
    settle(&mut net);
    settle(&mut net);
    let back = card_entries(&mut net, a, sv, &l, rt, "/reach");
    assert!(back.iter().any(|(_, c)| first.iter().any(|(_, f)| f == c)), "the re-granted node's unchanged /reach is under the label again: {first:?} {back:?}");
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

/// Node `n`'s person with its home label at server `sv`.
fn person(net: &mut Net, n: usize, sv: usize) -> Tid {
    let addr = net.address(sv);
    let (p, done) = net.engine(n).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(n).carry_out(done).unwrap();
    net.actions(n, acts);
    net.run();
    p.person
}

/// Admin node `a`'s group at `sv`, granted to node `r`'s person (read, until `until`), `r`'s
/// card under the group's label: (group, person, label).
fn person_reader(net: &mut Net, a: usize, r: usize, sv: usize, until: Option<osis_core::WallMs>) -> (Tid, Tid, LabelId) {
    let g = net.group(a, &[], &[sv]);
    let p = person(net, r, sv);
    net.pair(r, a);
    let edge = osis_schema::core_types::Edge { role: Role::Read, until, invite: None, since: None };
    let done = net.engine(a).grant(&g, &p, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    for _ in 0..3 {
        net.advance(70_000);
    }
    // the group has a member who is no contact of the reader: its `/reach` goes there by choice
    let acts = net.sync(r).set_reach_policy(g, Some(true));
    net.actions(r, acts);
    let acts = net.sync(r).publish_reach([1; 32], Vec::new()).unwrap();
    net.actions(r, acts);
    settle(net);
    let l = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1.id;
    (g, p, l)
}

// spec/permissions.md §4, spec/sync.md §6 (required set): a node that departs through its
// person's removal (its own edge on the person stands) leaves the label's `/reach` and `/node`;
// its `/keys` stays.
#[test]
fn person_removed_node_card_deleted_spec_permissions_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[sv]);
    let (g, p, l) = person_reader(&mut net, a, r, sv, None);
    let rt = net.tid(r);
    assert!(!card_entries(&mut net, a, sv, &l, rt, "/reach").is_empty(), "the reader's card is under the group's label");
    let done = net.engine(a).demote(&g, &Demotion { member: p, new: None, presync: PreSync::Synced }).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    settle(&mut net);
    assert!(card_entries(&mut net, a, sv, &l, rt, "/reach").is_empty(), "the departed node's /reach went");
    assert!(card_entries(&mut net, a, sv, &l, rt, "/node").is_empty(), "and its /node");
    assert!(!card_entries(&mut net, a, sv, &l, rt, "/keys").is_empty(), "its /keys stays");
}

// spec/permissions.md §4, spec/sync.md §6: a node whose person's edge passes its `until` leaves
// the label's `/reach` and `/node` once the clock passes it (no write says so).
#[test]
fn until_expired_node_card_deleted_spec_permissions_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[sv]);
    let until = osis_core::WallMs(net.now() + 3_600_000);
    let (_, _, l) = person_reader(&mut net, a, r, sv, Some(until));
    let rt = net.tid(r);
    assert!(!card_entries(&mut net, a, sv, &l, rt, "/reach").is_empty(), "the reader's card is under the group's label");
    net.clock.advance(3_600_000);
    settle(&mut net);
    settle(&mut net);
    assert!(card_entries(&mut net, a, sv, &l, rt, "/reach").is_empty(), "the departed node's /reach went");
    assert!(card_entries(&mut net, a, sv, &l, rt, "/node").is_empty(), "and its /node");
    assert!(!card_entries(&mut net, a, sv, &l, rt, "/keys").is_empty(), "its /keys stays");
}

// spec/permissions.md §4, spec/sync.md §6: when a person is removed, a device of it whose chain
// this view does not hold (its edge on the person never reached the admin) keeps its card: "reads
// no more" alone proves nothing; the device whose chain is held loses its `/reach`.
#[test]
fn unheld_chain_card_kept_spec_permissions_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[sv]);
    let r2 = net.node(3, &[sv]);
    // through the server only (a co-reader would serve the admin the chain)
    for n in [a, r, r2] {
        let acts = net.sync(n).set_peers(false);
        net.actions(n, acts);
    }
    let (g, p, l) = person_reader(&mut net, a, r, sv, None);
    // a second device of the person, paired by r while the admin is away
    net.set_online(a, false);
    net.pair(r2, r);
    let r2t = net.tid(r2);
    let done = net.engine(r).pair(&p, &r2t).unwrap();
    let grant = done.commits[0];
    let acts = net.sync(r).carry_out(done).unwrap();
    net.actions(r, acts);
    for (_, pks) in net.sync(r).take_direct() {
        for pk in pks {
            let _ = net.engine(r2).ingest(&pk.bytes, pk.blobs);
        }
    }
    let done = net.engine(r2).paired(&p, &grant).unwrap();
    let acts = net.sync(r2).carry_out(done).unwrap();
    net.actions(r2, acts);
    for _ in 0..3 {
        net.advance(70_000);
    }
    let acts = net.sync(r2).set_reach_policy(g, Some(true));
    net.actions(r2, acts);
    let acts = net.sync(r2).publish_reach([2; 32], Vec::new()).unwrap();
    net.actions(r2, acts);
    settle(&mut net);
    // the copies of r2's edge on the person go from the server before the admin is back
    let copies: Vec<BlobId> = net.sync(r2).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == grant)).map(|(id, _)| id).collect();
    assert!(!copies.is_empty(), "r2 placed its chain under the group's label");
    let now = net.now();
    for id in &copies {
        use osis_proto::LabelStore;
        net.servers[sv].hub.store_mut().delete(&l, id, now).unwrap();
    }
    net.set_online(a, true);
    settle(&mut net);
    assert!(!net.engine(a).may_read(&r2t, &p), "the admin does not hold r2's edge on the person");
    assert!(!card_entries(&mut net, a, sv, &l, r2t, "/reach").is_empty(), "r2's card is under the group's label");
    // the admin's timelines know r2 otherwise: an edge on another thing of the admin's
    let at = net.tid(a);
    let e = net.engine(a);
    let mut m = osis_node::Mutation::new();
    let h = e.new_thing(&mut m, at);
    m.set(h, &REG, &s("h")).unwrap();
    e.commit(m).unwrap();
    set_edge(e, h, r2t, Role::Read);
    let done = net.engine(a).demote(&g, &Demotion { member: p, new: None, presync: PreSync::Synced }).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    settle(&mut net);
    let rt = net.tid(r);
    assert!(card_entries(&mut net, a, sv, &l, rt, "/reach").is_empty(), "the node whose chain is held lost its /reach");
    assert!(!card_entries(&mut net, a, sv, &l, r2t, "/reach").is_empty(), "the node whose chain is not held keeps its card");
}
