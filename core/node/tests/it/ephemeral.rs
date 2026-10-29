//! Synced ephemeral data (notes/ephemeral.md step 3, spec/sync.md §4-§6): ephemeral commits held
//! in memory at nodes and servers, carried by the ordinary sync path; signals as relay-only
//! commits.

use crate::net;
use net::*;
use osis_base::{Role, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use osis_node::sync::{Event, SyncConfig};
use osis_schema::Lifetime;
use osis_schema::core_types as ct;
use osis_store::Backend;
use std::collections::BTreeMap;

const STATE: &str = "/win/state";
const NOTES: &str = "/win/notes";

fn eph(ak: &str) -> osis_schema::Untyped {
    ukey(ak, Lifetime::Ephemeral)
}

fn local(net: &mut Net, n: usize) {
    let acts = net.sync(n).handle(Event::Local);
    net.actions(n, acts);
}

/// Node `n` makes an ephemeral window owned by `g`, placed in `g` (the ephemeral side of its
/// `/group`), with `/win/state` = `v`.
fn window(net: &mut Net, n: usize, g: Tid, v: &str) -> Tid {
    let e = net.engine(n);
    let mut m = Mutation::new();
    let w = e.new_thing(&mut m, g);
    m.op(g, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(Value::Tid(w)) }).unwrap();
    m.set(w, &eph(STATE), &s(v)).unwrap();
    e.write(m).unwrap();
    assert!(net.engine(n).ephemeral_thing(&w).is_some(), "the window stays ephemeral");
    local(net, n);
    w
}

/// Node `n` sets key `k` of `/win/notes` of `w` to `v`.
fn note(net: &mut Net, n: usize, w: Tid, k: &str, v: &str) {
    let mut m = Mutation::new();
    m.op(w, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s(k))], op: Op::Set(s(v)) }).unwrap();
    net.engine(n).write(m).unwrap();
    local(net, n);
}

fn notes(net: &mut Net, n: usize, w: Tid) -> BTreeMap<String, String> {
    match net.eph_read(n, w, NOTES) {
        Some(Value::Map(m)) => m
            .into_iter()
            .filter_map(|(k, v)| match (k, v) {
                (Value::Str(k), Value::Str(v)) => Some((k, v)),
                _ => None,
            })
            .collect(),
        _ => BTreeMap::new(),
    }
}

fn map(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
    kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn rows(b: &osis_store::MemoryBackend) -> usize {
    b.scan(&[], None, usize::MAX).unwrap().len()
}

// notes/ephemeral.md step 3, spec/sync.md §4: an ephemeral window placed in a synced group
// reaches the other member's reads and watches; neither its store nor the server's gains a row
// (the server reserves log numbers in its label meta, the same row)
#[test]
fn window_reaches_member_no_store_rows_spec_sync_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let (rb, rs) = (rows(&net.nodes[b].backend), rows(&net.servers[sv].backend));
    let commits = net.engine(b).commit_ids().len();
    let rx = net.listen(b);
    let w = window(&mut net, a, g, "hello");
    net.run();
    assert_eq!(net.eph_read(b, w, STATE), Some(s("hello")));
    assert!(net.engine(b).groups_of(&w).contains(&g), "the placement came along");
    let changed: Vec<_> = rx.try_iter().filter_map(|e| if let osis_node::Event::Ephemeral { changed, origin: osis_node::Origin::Remote, .. } = e { Some(changed) } else { None }).flatten().collect();
    assert!(changed.iter().any(|(t, ak)| *t == w && ak.as_str() == STATE), "{changed:?}");
    assert_eq!(rows(&net.nodes[b].backend), rb, "nothing stored at the member");
    assert_eq!(rows(&net.servers[sv].backend), rs, "nothing stored at the server");
    assert_eq!(net.engine(b).commit_ids().len(), commits);
}

// notes/ephemeral.md Owner direction (the shared window): two holders keep editing while one is
// offline; on reconnect both converge on the merge, through a server
#[test]
fn shared_window_merges_after_offline_spec_sync_6() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "shared");
    note(&mut net, a, w, "x", "1");
    net.run();
    assert_eq!(notes(&mut net, b, w), map(&[("x", "1")]));
    net.set_online(b, false);
    note(&mut net, a, w, "a", "from a");
    note(&mut net, b, w, "b", "from b");
    net.run();
    assert_eq!(notes(&mut net, a, w), map(&[("x", "1"), ("a", "from a")]));
    assert_eq!(notes(&mut net, b, w), map(&[("x", "1"), ("b", "from b")]));
    net.set_online(b, true);
    net.advance(10_000);
    let want = map(&[("x", "1"), ("a", "from a"), ("b", "from b")]);
    assert_eq!(notes(&mut net, a, w), want);
    assert_eq!(notes(&mut net, b, w), want);
}

// the shared window over a direct peer link (a member peer serving the label, spec/sync.md §5):
// edits while apart merge on reconnect
#[test]
fn shared_window_merges_over_peer_link_spec_sync_5() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    for (n, k) in [(a, 0xa7), (b, 0xb7)] {
        let acts = net.sync(n).publish_reach([k; 32], vec!["https://relay.example".into()]).unwrap();
        net.actions(n, acts);
    }
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let w = window(&mut net, a, g, "direct");
    note(&mut net, a, w, "x", "1");
    net.run();
    assert_eq!(net.eph_read(b, w, STATE), Some(s("direct")));
    assert_eq!(notes(&mut net, b, w), map(&[("x", "1")]));
    net.set_online(b, false);
    note(&mut net, a, w, "a", "from a");
    note(&mut net, b, w, "b", "from b");
    net.run();
    net.set_online(b, true);
    net.advance(70_000);
    let want = map(&[("x", "1"), ("a", "from a"), ("b", "from b")]);
    assert_eq!(notes(&mut net, a, w), want);
    assert_eq!(notes(&mut net, b, w), want);
}

// notes/ephemeral.md Holders: a restarted node forgets the ephemeral state and gets it back from
// the server (its first sync of the label reconciles: its cursor had passed those entries)
#[test]
fn restarted_node_gets_state_back_spec_sync_6() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "kept");
    net.run();
    note(&mut net, b, w, "b", "before");
    net.run();
    net.restart(b, 22);
    assert_eq!(net.eph_read(b, w, STATE), None, "forgotten at restart");
    net.advance(10_000);
    assert_eq!(net.eph_read(b, w, STATE), Some(s("kept")));
    assert_eq!(notes(&mut net, b, w), map(&[("b", "before")]), "its own old writes come back too");
}

// notes/ephemeral.md At servers: a server restart loses its ephemeral entries; the holders bring
// them back (they list what they hold in their first Sync, the server wants what it lacks), so a
// node arriving later still gets the state
#[test]
fn server_restart_holders_upload_again_spec_sync_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read)], &[sv]);
    net.set_online(c, false);
    net.run();
    let w = window(&mut net, a, g, "survives");
    net.run();
    let l = net.label(a);
    assert!(net.servers[sv].hub.store().ephemeral_bytes(&l) > 0);
    net.restart_server(sv);
    assert_eq!(net.servers[sv].hub.store().ephemeral_bytes(&l), 0);
    net.run();
    net.advance(10_000);
    assert!(net.servers[sv].hub.store().ephemeral_bytes(&l) > 0, "uploaded again");
    net.set_online(a, false);
    net.set_online(b, false);
    net.set_online(c, true);
    net.advance(10_000);
    assert_eq!(net.eph_read(c, w, STATE), Some(s("survives")));
}

// notes/ephemeral.md Convergence (a holder bridging two servers carries ephemeral state across):
// A only on server 1 and C only on server 2 converge through B on both
#[test]
fn bridge_node_carries_between_servers_spec_sync_6() {
    let mut net = Net::new();
    let (s1, s2) = (net.add_server(), net.add_server());
    let a = net.node(1, &[s1]);
    let b = net.node(2, &[s1, s2]);
    let c = net.node(3, &[s2]);
    net.blocked.insert((a, s2));
    net.blocked.insert((c, s1));
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[s1, s2]);
    net.run();
    let w = window(&mut net, a, g, "bridged");
    note(&mut net, a, w, "a", "1");
    net.run();
    assert_eq!(net.eph_read(c, w, STATE), Some(s("bridged")));
    note(&mut net, c, w, "c", "2");
    net.run();
    let want = map(&[("a", "1"), ("c", "2")]);
    assert_eq!(notes(&mut net, a, w), want);
    assert_eq!(notes(&mut net, c, w), want);
}

// spec/data-model.md §1 (persistence): an ephemeral thing syncs with its record; the other member
// persists it with a durable write, keeping its tid; the first node sees it durable then
#[test]
fn ephemeral_thing_persists_same_tid_elsewhere_spec_data_model_1() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "draft");
    net.run();
    assert!(net.engine(b).ephemeral_thing(&w).is_some(), "the record came with it");
    let mut m = Mutation::new();
    m.set(w, &REG, &s("saved")).unwrap();
    net.engine(b).write(m).unwrap();
    assert!(net.engine(b).core.created(&w).is_some(), "persisted at b");
    net.run();
    assert!(net.engine(a).core.created(&w).is_some());
    assert!(net.engine(a).ephemeral_thing(&w).is_none(), "durable now");
    assert_eq!(net.read(a, w), Some(s("saved")));
    assert!(net.engine(a).groups_of(&w).contains(&g), "its placement became durable");
    assert_eq!(net.eph_read(a, w, STATE), Some(s("draft")), "ephemeral aspects stay ephemeral");
}

// spec/permissions.md §5.2 (ephemeral commits judged as snapshots: by commit ID, so a demotion's
// frontier, which lists none, covers none): a removed writer's ephemeral writes are un-merged
#[test]
fn removed_writer_ephemeral_unmerged_spec_permissions_5_2() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    note(&mut net, a, w, "a", "1");
    net.run();
    note(&mut net, b, w, "b", "2");
    net.run();
    assert_eq!(notes(&mut net, a, w), map(&[("a", "1"), ("b", "2")]));
    let bt = net.tid(b);
    let me = net.tid(a);
    let e = net.engine(a);
    let rs = recipients_of(e, &[(me, Role::Admin)]);
    remove_member(e, g, bt, &rs, 9);
    net.run();
    assert_eq!(notes(&mut net, a, w), map(&[("a", "1")]), "b's ephemeral write is un-merged");
}

// notes/ephemeral.md Bounds (server ephemeral bytes per label): past the cap uploads are refused;
// the writer compacts, deletes what the compaction covers and the label syncs again
#[test]
fn server_cap_compaction_frees_it_spec_sync_5() {
    let mut net = Net::new();
    // a few entries with their per-entry overhead (about 900 bytes each)
    let sv = net.add_server_with(osis_server::Policy { ephemeral_bytes: 6_000, ..osis_server::Policy::default() });
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "busy");
    net.run();
    for i in 0..30 {
        note(&mut net, a, w, &format!("k{i}"), "v");
        net.run();
    }
    let l = net.label(a);
    assert!(net.servers[sv].hub.store().ephemeral_bytes(&l) <= 6_000);
    assert!(net.engine(a).held_ephemeral().len() < 30, "compacted: {}", net.engine(a).held_ephemeral().len());
    let want: BTreeMap<String, String> = (0..30).map(|i| (format!("k{i}"), "v".to_string())).collect();
    assert_eq!(notes(&mut net, b, w), want);
    // a node arriving now gets the whole state from what the server kept
    net.restart(b, 23);
    net.advance(10_000);
    assert_eq!(notes(&mut net, b, w), want);
}

// a server cap too small for the compacted state: the writer compacts, the cover is refused, and
// it reports instead of compacting the cover into the next cover forever (a livelock found while
// charging per-entry overhead at servers)
#[test]
fn server_cap_below_state_reports_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server_with(osis_server::Policy { ephemeral_bytes: 2_500, ..osis_server::Policy::default() });
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let rx = net.listen(a);
    let w = window(&mut net, a, g, "busy");
    net.run();
    for i in 0..30 {
        note(&mut net, a, w, &format!("k{i}"), "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv");
        net.run();
    }
    let refused = rx.try_iter().any(|e| matches!(e, osis_node::Event::Diagnostic(d) if d.kind == osis_node::DiagnosticKind::EphemeralRefused));
    assert!(refused, "reported");
}

// notes/ephemeral.md Bounds (node ephemeral bytes per label held from others): a writer flooding
// a label with ephemeral commits fills at most the cap at another node; the rest is refused
// (`EphemeralRefused`)
#[test]
fn ephemeral_flood_bounded_spec_requirements_scale() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.add_node(2, SyncConfig { servers: vec![net.address(sv)], ephemeral_bytes: 4_000, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "flood");
    net.run();
    let rx = net.listen(b);
    for i in 0..40 {
        note(&mut net, a, w, &format!("k{i}"), "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv");
        net.run();
    }
    let l = net.label(a);
    assert!(net.sync(b).ephemeral_bytes(&l) <= 4_000, "{}", net.sync(b).ephemeral_bytes(&l));
    assert!(notes(&mut net, b, w).len() < 40);
    let refused = rx.try_iter().any(|e| matches!(e, osis_node::Event::Diagnostic(d) if d.kind == osis_node::DiagnosticKind::EphemeralRefused));
    assert!(refused, "reported");
}

// spec/permissions.md §1 (readers cannot write ephemeral data): a reader's ephemeral write is
// refused at the writer; one forged anyway is invalid at every receiver
#[test]
fn reader_cannot_write_ephemeral_spec_permissions_1() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[sv]);
    let g = net.group(a, &[(r, Role::Read)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "mine");
    net.run();
    assert_eq!(net.eph_read(r, w, STATE), Some(s("mine")), "the reader reads it");
    let mut m = Mutation::new();
    m.set(w, &eph(STATE), &s("theirs")).unwrap();
    assert!(net.engine(r).write(m).is_err(), "refused at the writer");
    let ak = osis_base::Ak::new(STATE).unwrap();
    let forged = net.engine(r).forge_ephemeral(w, &ak, s("forged")).unwrap().unwrap();
    net.engine(a).ingest_ephemeral(forged.blob).unwrap();
    assert_eq!(net.eph_read(a, w, STATE), Some(s("mine")), "invalid: not joined");
    local(&mut net, r);
    net.run();
    assert_eq!(net.eph_read(a, w, STATE), Some(s("mine")));
}

// notes/ephemeral.md Signals: a signal reaches each device connected now once, also over two
// servers (no duplicate); a device connecting later never gets it; no server holds an entry; a
// restarted node does not see it again
#[test]
fn signal_once_to_connected_devices_spec_sync_5() {
    let mut net = Net::new();
    let (s1, s2) = (net.add_server(), net.add_server());
    let a = net.node(1, &[s1, s2]);
    let b = net.node(2, &[s1, s2]);
    let c = net.node(3, &[s1]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read)], &[s1, s2]);
    let t = net.item(a, g, g, "x");
    net.set_online(c, false);
    net.run();
    let held = (rows(&net.servers[s1].backend), rows(&net.servers[s2].backend));
    let (ra, rb, rc) = (net.listen(a), net.listen(b), net.listen(c));
    net.eph_write(a, t, &ukey("/t/ring", Lifetime::Signal), s("ding"));
    net.run();
    assert_eq!(fired(&rb).len(), 1, "once, though both servers pushed it");
    assert_eq!(fired(&ra).len(), 1, "once at the sender (no echo)");
    assert_eq!((rows(&net.servers[s1].backend), rows(&net.servers[s2].backend)), held, "no server holds it");
    let l = net.label(a);
    assert_eq!(net.servers[s1].hub.store().ephemeral_bytes(&l), 0);
    net.set_online(c, true);
    net.advance(10_000);
    assert!(fired(&rc).is_empty(), "a device connecting later never gets it");
    net.restart(b, 24);
    let rb = net.listen(b);
    net.advance(10_000);
    assert!(fired(&rb).is_empty(), "a restarted node does not see it again");
}

// spec/crdt.md §4.7, spec/sync.md §1 (an ephemeral commit's expiry rides in its header and its
// blob prefix): a typing indicator written with an expiry reaches the other member and is gone
// everywhere at its time, servers included
#[test]
fn ephemeral_expiry_everywhere_spec_crdt_4_7() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let mut m = Mutation::new();
    m.set(w, &eph("/win/typing"), &Value::Bool(true)).unwrap();
    m.expires(w, &eph("/win/typing"), osis_base::WallMs(net.now() + 5_000)).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    assert_eq!(net.eph_read(b, w, "/win/typing"), Some(Value::Bool(true)));
    let l = net.label(a);
    let before = net.servers[sv].hub.store().ephemeral_bytes(&l);
    net.advance(6_000);
    assert_eq!(net.eph_read(a, w, "/win/typing"), None);
    assert_eq!(net.eph_read(b, w, "/win/typing"), None);
    assert!(net.servers[sv].hub.store().ephemeral_bytes(&l) < before, "the server dropped it unattended");
}

// spec/data-model.md §1 (an ephemeral thing's owner may be ephemeral): a window owned by an
// ephemeral workspace syncs with both records; rights come through the nearest durable owner
#[test]
fn ephemeral_owner_chain_travels_spec_data_model_1() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let e = net.engine(a);
    let mut m = Mutation::new();
    let ws = e.new_thing(&mut m, g);
    let w = e.new_thing(&mut m, ws);
    m.op(g, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(Value::Tid(w)) }).unwrap();
    m.set(w, &eph(STATE), &s("nested")).unwrap();
    e.write(m).unwrap();
    local(&mut net, a);
    net.run();
    assert_eq!(net.eph_read(b, w, STATE), Some(s("nested")));
    assert!(net.engine(b).ephemeral_thing(&ws).is_some(), "the owner's record came too");
    note(&mut net, b, w, "b", "writes through g");
    net.run();
    assert_eq!(notes(&mut net, a, w), map(&[("b", "writes through g")]));
}

// spec/sync.md §9 (a part on a thing whose record is not held waits): an ephemeral write on a
// durable thing that arrives before the thing's own commit joins once that commit is here
#[test]
fn ephemeral_part_waits_for_its_record_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    net.set_online(b, false);
    let t = net.item(a, g, g, "durable");
    net.run();
    let mut m = Mutation::new();
    m.set(t, &eph("/doc/cursor"), &Value::Int(7)).unwrap();
    net.engine(a).write(m).unwrap();
    let cs = net.engine(a).take_ephemeral().unwrap();
    assert_eq!(cs.len(), 1);
    assert!(net.engine(b).core.created(&t).is_none());
    net.engine(b).ingest_ephemeral(cs[0].blob.clone()).unwrap();
    assert_eq!(net.eph_read(b, t, "/doc/cursor"), None, "waits for the record");
    net.set_online(b, true);
    net.advance(10_000);
    assert_eq!(net.read(b, t), Some(s("durable")));
    assert_eq!(net.eph_read(b, t, "/doc/cursor"), Some(Value::Int(7)));
}

// spec/crdt.md §4.6 (un-merge rebuilds from what is held): a node's own compaction covers
// others' writes; a later validity flip on the aspect rebuilds it from the own writes and the
// held parts, the own cover included, so the covered writes stay and the holders agree
#[test]
fn own_compaction_survives_rebuild_spec_crdt_4_6() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    note(&mut net, b, w, "b", "1");
    note(&mut net, c, w, "c", "1");
    net.run();
    let cover = net.engine(a).compact_ephemeral(None, true).unwrap().expect("compacted");
    net.engine(b).ingest_ephemeral(cover.blob).unwrap();
    local(&mut net, a);
    net.run();
    note(&mut net, c, w, "c2", "2");
    net.run();
    let ct = net.tid(c);
    let me = net.tid(a);
    let bt = net.tid(b);
    let e = net.engine(a);
    let rs = recipients_of(e, &[(me, Role::Admin), (bt, Role::Write)]);
    remove_member(e, g, ct, &rs, 9);
    net.run();
    let at_a = notes(&mut net, a, w);
    assert_eq!(at_a, notes(&mut net, b, w), "holders agree");
    assert_eq!(at_a, map(&[("b", "1"), ("c", "1")]), "the covered writes stay (the cover's author is valid); c's later write goes");
}

/// One random run of the shared window (notes/ephemeral.md Convergence): four writers on two
/// servers (odd seeds: one with a small ephemeral cap, so writers compact), random ephemeral
/// writes, partitions (offline, one server blocked), node restarts and server restarts; after
/// healing every holder reads the same notes.
fn random_window_run(seed: u64) {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut rnd = move |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let mut net = Net::new();
    // odd seeds: a small ephemeral cap at the first server forces compactions
    let s1 = if seed % 2 == 1 { net.add_server_with(osis_server::Policy { ephemeral_bytes: 6_000, ..osis_server::Policy::default() }) } else { net.add_server() };
    let s2 = net.add_server();
    let nodes: Vec<usize> = (0..4).map(|i| net.node(1 + i, &[s1, s2])).collect();
    let members: Vec<(usize, Role)> = nodes[1..].iter().map(|n| (*n, Role::Write)).collect();
    let g = net.group(nodes[0], &members, &[s1, s2]);
    net.run();
    let w = window(&mut net, nodes[0], g, "w");
    net.run();
    let mut restarts = 100;
    let mut log = Vec::new();
    for step in 0..40 {
        let n = nodes[rnd(4) as usize];
        match rnd(10) {
            0..=4 => {
                if net.engine(n).ephemeral_thing(&w).is_some() || net.eph_read(n, w, STATE).is_some() {
                    let (k, v) = (format!("k{}", rnd(5)), format!("v{step}"));
                    log.push(format!("{n} writes {k}={v}"));
                    // not `note`: an offline node must not see events (its dials would hang)
                    let mut m = Mutation::new();
                    m.op(w, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s(&k))], op: Op::Set(s(&v)) }).unwrap();
                    net.engine(n).write(m).unwrap();
                }
            }
            5 => {
                let on = !net.nodes[n].online;
                log.push(format!("{n} online {on}"));
                net.set_online(n, on);
            }
            6 => {
                let s = if rnd(2) == 0 { s1 } else { s2 };
                let blocked = !net.blocked.remove(&(n, s));
                if blocked {
                    net.blocked.insert((n, s));
                    if net.conn_to(n, s).is_some() {
                        let on = net.nodes[n].online;
                        net.set_online(n, false);
                        net.set_online(n, on);
                    }
                }
                log.push(format!("{n} blocked from {s} {blocked}"));
            }
            7 => {
                restarts += 1;
                log.push(format!("{n} restarts"));
                let on = net.nodes[n].online;
                net.restart(n, restarts);
                net.set_online(n, on);
            }
            8 if rnd(4) == 0 => {
                let s = if rnd(2) == 0 { s1 } else { s2 };
                log.push(format!("server {s} restarts"));
                net.restart_server(s);
            }
            _ => {
                log.push("advance".into());
                net.advance(1_000 + rnd(20_000));
                continue;
            }
        }
        net.run();
    }
    net.blocked.clear();
    for n in &nodes {
        net.set_online(*n, true);
    }
    for _ in 0..4 {
        net.advance(15_000);
    }
    let holders: Vec<usize> = nodes.iter().copied().filter(|n| net.engine(*n).ephemeral_thing(&w).is_some()).collect();
    let first = notes(&mut net, holders[0], w);
    for n in &holders[1..] {
        assert_eq!(notes(&mut net, *n, w), first, "seed {seed}: node {n} differs from node {}\n{}", holders[0], log.join("\n"));
    }
}

// notes/ephemeral.md Convergence (randomized): holders of a shared window converge after random
// writes, partitions and restarts heal
#[test]
fn random_window_converges_spec_sync_6() {
    for seed in 0..4 {
        random_window_run(seed);
    }
}

// the same over more seeds (tier 2): OSIS_EPH_SEEDS (default 200) from OSIS_EPH_START
#[test]
#[ignore]
fn random_window_converges_large() {
    let start: u64 = std::env::var("OSIS_EPH_START").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let n: u64 = std::env::var("OSIS_EPH_SEEDS").ok().and_then(|v| v.parse().ok()).unwrap_or(200);
    for seed in start..start + n {
        random_window_run(seed);
    }
}

// spec/data-model.md §1 (two nodes persisting one ephemeral thing both carry its record,
// idempotent): a synced window under an ephemeral workspace is persisted by both members while
// apart; on reconnect both hold one durable thing (same tid, chain durable), one placement, and
// the ephemeral aspects still merged
#[test]
fn concurrent_persist_one_thing_spec_data_model_1() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let e = net.engine(a);
    let mut m = Mutation::new();
    let ws = e.new_thing(&mut m, g);
    let w = e.new_thing(&mut m, ws);
    m.op(g, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(Value::Tid(w)) }).unwrap();
    m.set(w, &eph(STATE), &s("draft")).unwrap();
    e.write(m).unwrap();
    local(&mut net, a);
    net.run();
    assert!(net.engine(b).ephemeral_thing(&w).is_some());
    net.set_online(b, false);
    for (n, v) in [(a, "from a"), (b, "from b")] {
        let mut m = Mutation::new();
        m.set(w, &REG, &s(v)).unwrap();
        net.engine(n).write(m).unwrap();
        assert!(net.engine(n).core.created(&ws).is_some(), "the chain persisted at {n}");
    }
    note(&mut net, a, w, "a", "1");
    let mut m = Mutation::new();
    m.op(w, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s("b"))], op: Op::Set(s("2")) }).unwrap();
    net.engine(b).write(m).unwrap();
    net.run();
    net.set_online(b, true);
    net.advance(10_000);
    net.advance(10_000);
    for n in [a, b] {
        assert!(net.engine(n).ephemeral_thing(&w).is_none() && net.engine(n).ephemeral_thing(&ws).is_none(), "durable at {n}");
        assert_eq!(net.engine(n).groups_of(&w).iter().filter(|x| **x == g).count(), 1);
        assert_eq!(notes(&mut net, n, w), map(&[("a", "1"), ("b", "2")]));
        assert_eq!(net.eph_read(n, w, STATE), Some(s("draft")));
    }
    assert_eq!(net.read(a, w), net.read(b, w));
}

