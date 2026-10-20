#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Deletions, compaction and re-registration through a blind node (spec/sync.md §5-§7;
//! spec/commits.md §5; spec/permissions.md §3, §4).

mod net;
use net::*;
use osis_core::{Ak, Role};
use osis_node::Mutation;
use osis_node::sync::EntryKind;
use osis_schema::AspectKey;
use osis_schema::core_types as ct;

fn diags(net: &mut Net, nodes: &[usize]) {
    for n in nodes {
        let d = net.sync(*n).take_diagnostics();
        if !d.is_empty() {
            eprintln!("node {n}: {d:?}");
        }
    }
}

// spec/sync.md §3 (retag), §5 (deletion by token), §6: a thing leaving the folder takes its own
// bodies out of the folder's label; a writer without the delete key deletes them by token.
#[test]
fn thing_leaving_deleted_by_token_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "x");
    net.run();
    let c = net.write(b, t, "by b");
    net.run();
    let l = net.label(a);
    let blobs: Vec<_> = net.sync(b).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == c)).map(|(id, _)| id).collect();
    assert!(!blobs.is_empty() && blobs.iter().all(|id| net.server_ids(sv, &l).contains(id)));
    // the admin is away: only the writer can act, by token
    net.set_online(a, false);
    let e = net.engine(b);
    let mut grp = e.get_typed(&g, &ct::GROUP).unwrap().unwrap();
    grp.items.remove(&t);
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &grp).unwrap();
    e.commit(m).unwrap();
    net.run();
    diags(&mut net, &[b]);
    assert!(!net.engine(b).closure(&g).contains(&t));
    let ids = net.server_ids(sv, &l);
    assert!(blobs.iter().all(|id| !ids.contains(id)), "the commit only on the departed thing went");
}

// spec/sync.md §7, spec/commits.md §5: compaction uploads the snapshot first, then drops and
// deletes the covered bodies; a member joining later reads the live value from the snapshot.
#[test]
fn compaction_then_deletion_spec_sync_7() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let c = net.node(3, &[sv]);
    net.blocked.insert((c, sv));
    let g = net.group(a, &[(c, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "v1");
    net.write(a, t, "v2");
    net.write(a, t, "v3");
    net.run();
    let l = net.label(a);
    let before = net.server_ids(sv, &l).len();
    let ak = Ak::new(REG.ak()).unwrap();
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    net.run();
    diags(&mut net, &[a]);
    let after = net.server_ids(sv, &l).len();
    assert!(after < before, "covered bodies deleted after the snapshot: {before} -> {after}");
    net.blocked.clear();
    net.advance(10_000);
    diags(&mut net, &[c]);
    assert_eq!(net.read(c, t), Some(s("v3")), "the live value is served from the snapshot");
}

// spec/sync.md §5 (re-registration, upload order), spec/permissions.md §3-§4 (stranded
// heartbeat): an admin rotating out a member issues a child step at the server after uploading
// the rotation commit; the remaining writer follows; the removed member's open walks to the new
// step, its claim is refused and it places a stranded heartbeat by deposit.
// spec/permissions.md §4 (stranded heartbeat), spec/crypto.md §4 (removed member)
#[test]
fn reregistration_after_rotation_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "before");
    net.run();
    assert_eq!(net.read(c, t), Some(s("before")));
    let l = net.label(a);
    assert_eq!(net.server_path(sv, &l).len(), 1);
    net.set_online(c, false);
    let (at, bt, ct_) = (net.tid(a), net.tid(b), net.tid(c));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write)]);
    remove_member(e, g, ct_, &rs, 41);
    net.write(a, t, "after");
    net.run();
    diags(&mut net, &[a, b]);
    assert_eq!(net.server_path(sv, &l).len(), 2, "a child step was registered");
    assert_eq!(net.sync(a).labels()[0].1.steps.len(), 2, "and recorded in /label");
    assert_eq!(net.read(b, t), Some(s("after")));
    net.write(b, t, "from b");
    net.run();
    assert_eq!(net.read(a, t), Some(s("from b")), "the writer stamps under the new step");
    // the removed member comes back: walked to the new step, claim refused, stranded heartbeat
    let n_before = net.server_ids(sv, &l).len();
    net.set_online(c, true);
    net.advance(10_000);
    assert_eq!(net.read(c, t), Some(s("before")), "nothing new readable");
    assert!(net.server_ids(sv, &l).len() > n_before, "a stranded heartbeat was deposited");
    net.run();
    let seen = net.engine(a).get_typed(&ct_, &ct::SEEN).unwrap();
    assert!(seen.is_some_and(|x| x.stranded), "co-members read the stranded heartbeat");
}

// spec/commits.md §5, spec/sync.md §5 (timed delete): replacing a body under a relative
// keep-at-most sends the timed delete with the replacing upload, after a covering snapshot; the
// server deletes it at the bound with nobody online.
#[test]
fn timed_delete_spec_sync_5() {
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
    diags(&mut net, &[a]);
    let before = net.server_ids(sv, &l).len();
    net.set_online(a, false);
    net.clock.advance(3_600_000 + 1_000);
    let now = net.now();
    net.servers[sv].hub.tick(now);
    let after = net.server_ids(sv, &l).len();
    assert_eq!(after + 1, before, "the replaced body went at its bound, nobody online");
}
