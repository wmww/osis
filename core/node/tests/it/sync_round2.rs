#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Regressions from the simulator's phase C (sync bug-fix round 2): unopenable entries, pending
//! commits and must-hold, wakes, keep-at-most drops, timed deletes, deposits in flight, clock
//! offsets.

use crate::net;
use net::*;
use osis_base::{Ak, Role};
use osis_crypto::SeededRng;
use osis_node::Mutation;
use osis_node::sync::{Action, EntryKind, Event};
use osis_proto::{Entry, LabelStore, Put};
use osis_schema::AspectKey;

/// Blob IDs node `n` knows under `l` holding commit `c`.
fn blobs_of(net: &mut Net, n: usize, l: &osis_base::LabelId, c: &osis_base::CommitId) -> Vec<osis_base::BlobId> {
    net.sync(n).entries(l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if commit == c)).map(|(id, _)| id).collect()
}

// spec/versioning.md §2 (malformed data is rejected), spec/sync.md §6: a well-framed, stamped
// blob of junk under the label is marked bad once; the writers keep uploading their must-hold
// bodies (one such entry used to stop every upload under the label).
// spec/versioning.md §2 (reject malformed)
#[test]
fn junk_entry_does_not_stall_uploads_spec_versioning_2() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "v1");
    net.run();
    let (_, gl) = net.sync(a).labels().into_iter().next().unwrap();
    let head = gl.steps.values().next().unwrap().0.clone();
    let keys = net.engine(a).head_keys(&g, gl.index, &head).unwrap();
    let read = net.engine(a).wrap_secret(&g, None).unwrap().unwrap();
    let mut rng = SeededRng::from_u64(5);
    let prefix = osis_label::Prefix::new(osis_label::Prefix::random_salt(&mut rng), None, Vec::new()).unwrap();
    let (key, blob) = osis_label::frame(&prefix, &[0x42; 64], &mut rng).unwrap();
    let id = osis_label::blob_id(&blob);
    let wrap = osis_crypto::wrap(&read, &id, &key).unwrap();
    let stamp = osis_label::sign_stamp(keys.write.as_ref().unwrap(), &gl.id, &id, &wrap);
    let e = Entry { blob, wrap, stamp };
    let put = Put { blob_id: id, blob: &e.blob, wrap: e.wrap, stamp: Some(e.stamp), expiry: None, ephemeral: false, presence: false };
    net.servers[sv].hub.store_mut().put(&gl.id, put).unwrap();
    // reconnect: the cursor sync brings the junk entry
    net.restart(a, 11);
    net.restart(b, 12);
    net.run();
    assert!(net.sync(b).entries(&gl.id).iter().any(|(x, k)| *x == id && *k == EntryKind::Bad));
    let c = net.write(b, t, "v2");
    net.run();
    let at = net.server_ids(sv, &gl.id);
    assert!(blobs_of(&mut net, b, &gl.id, &c).iter().any(|x| at.contains(x)), "b's write reached the server");
    assert_eq!(net.read(a, t), Some(s("v2")));
}

// spec/sync.md §6 (must-hold: established uncovered by held snapshots): a pending commit that is
// no snapshot (here held for drift) does not make a writer's own body on the same aspect
// may-hold (two writers' pending commits used to withhold exactly what the other waited for).
#[test]
fn pending_commit_does_not_withhold_uploads_spec_sync_6() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "v1");
    net.run();
    // b writes two hours ahead: a holds it pending for drift
    net.engine(b).set_clock_offset(2 * 3_600_000);
    net.write(b, t, "ahead");
    net.engine(b).set_clock_offset(0);
    net.run();
    assert!(net.engine(a).pending().iter().any(|(_, r)| *r == osis_node::Reason::Drift));
    let c = net.write(a, t, "mine");
    net.run();
    let l = net.label(a);
    let at = net.server_ids(sv, &l);
    assert!(blobs_of(&mut net, a, &l, &c).iter().any(|x| at.contains(x)), "a's body went up beside the pending commit");
}

// spec/crdt.md §2.2 (the drift bound is for received commits), spec/sync.md §6: a correction that
// moves the clock back below this node's HLC never stops it from committing.
#[test]
fn own_commit_after_clock_moves_back_spec_crdt_2() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let g = net.group(a, &[], &[]);
    let t = net.item(a, g, g, "v1");
    net.engine(a).set_clock_offset(12 * 3_600_000);
    net.write(a, t, "ahead");
    net.engine(a).set_clock_offset(0);
    net.write(a, t, "back");
    assert_eq!(net.read(a, t), Some(s("back")));
}

// spec/commits.md §5 (expiry): an offline node with nothing connected still asks to be woken
// for its next expiry, and every Tick asks again (a wake left unchanged was never re-armed).
#[test]
fn wake_for_expiry_and_after_every_tick_spec_commits_5() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let g = net.group(a, &[], &[]);
    let t = net.item(a, g, g, "v1");
    let mut m = Mutation::new();
    m.set(t, &BRIEF, &s("soon gone")).unwrap();
    net.engine(a).commit(m).unwrap();
    let wake = |acts: &[Action]| acts.iter().find_map(|x| if let Action::Wake { at } = x { Some(*at) } else { None });
    let acts = net.sync(a).handle(Event::Local);
    let at = wake(&acts).expect("a wake for the expiry");
    assert!(at > net.now() && at <= net.now() + 3_600_000 + 1, "at {at}");
    for _ in 0..2 {
        let acts = net.sync(a).handle(Event::Tick);
        assert!(wake(&acts).is_some_and(|x| x > net.now()), "a wake after each tick: {acts:?}");
    }
    net.clock.advance(3_600_001);
    net.sync(a).handle(Event::Tick);
    assert_eq!(net.engine(a).get(&t, &Ak::new(BRIEF.ak()).unwrap()).unwrap(), None);
}

// spec/commits.md §5 (keep at most: body and copies gone at the bound): a tick dropping a
// replaced body also drops its blob and key at the node.
// spec/commits.md §5 (keep at most)
#[test]
fn keep_at_most_drop_forgets_blob_spec_commits_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    let t = net.item(a, g, g, "v1");
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("one")).unwrap();
    let c1 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("two")).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    let l = net.label(a);
    let ids = blobs_of(&mut net, a, &l, &c1);
    assert!(!ids.is_empty());
    net.set_online(a, false);
    net.clock.advance(2 * 3_600_000);
    net.sync(a).handle(Event::Tick);
    for id in ids {
        assert!(!net.sync(a).holds_blob(&id), "dropped body's blob kept");
    }
}

// spec/commits.md §5, spec/sync.md §5 (timed delete): a timed delete lost with its connection
// goes again on the next one, and the server deletes the replaced body at the bound with the
// writer offline.
#[test]
fn timed_delete_resent_after_cut_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    let t = net.item(a, g, g, "v1");
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("one")).unwrap();
    let c1 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let first = blobs_of(&mut net, a, &l, &c1);
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("two")).unwrap();
    net.engine(a).commit(m).unwrap();
    // the pass's upload and timed delete are lost with the connection
    let lost = net.sync(a).handle(Event::Local);
    assert!(lost.iter().any(|x| matches!(x, Action::Send { .. })));
    net.set_online(a, false);
    net.set_online(a, true);
    // past the redial pause
    net.advance(6_000);
    net.set_online(a, false);
    net.clock.advance(2 * 3_600_000);
    let now = net.now();
    let out = net.servers[sv].hub.tick(now);
    drop(out);
    let at = net.server_ids(sv, &l);
    assert!(first.iter().all(|x| !at.contains(x)), "the server deleted the replaced body at its bound");
}

// spec/sync.md §5 (deposits): deposits not answered yet are not sent again by later passes.
#[test]
fn deposits_in_flight_not_resent_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[sv]);
    let g = net.group(a, &[(r, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "v1");
    net.run();
    net.sent_kinds.clear();
    // a heartbeat is due (no tick: nothing else moves)
    net.clock.advance(osis_base::format::HEARTBEAT_MIN_INTERVAL_MS + 1);
    // a burst of commits reaching the reader, a pass after each, nothing answered in between
    for i in 0..5 {
        let c = net.write(a, t, &format!("w{i}"));
        let pk = net.engine(a).package(&c).unwrap().unwrap();
        net.engine(r).ingest(&pk.bytes, pk.blobs).unwrap();
        let acts = net.sync(r).handle(Event::Local);
        net.actions(r, acts);
    }
    let burst = net.sent_kinds.get(&12).copied().unwrap_or(0);
    net.run();
    let total = net.sent_kinds.get(&12).copied().unwrap_or(0);
    assert!((1..=2).contains(&burst), "deposits re-sent in the burst: {burst}");
    assert!(total <= burst + 3, "{total}");
}

