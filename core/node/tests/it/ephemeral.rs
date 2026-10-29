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
use std::collections::{BTreeMap, BTreeSet};

/// The label write key node `n` stamps with (the group's newest write epoch, label index 0).
pub(crate) fn write_key(net: &mut Net, n: usize, g: Tid) -> osis_crypto::SigningSecret {
    let w = net.engine(n).epochs(&g).unwrap().write.newest_held().unwrap().1.clone();
    osis_crypto::label_role_key(osis_crypto::LabelRole::Write, &w, 0)
}

/// Seals ephemeral commit `c` under `g`'s label as node `w` would, stamped with `stamp` when
/// given: (blob ID, the log event a server pushes).
pub(crate) fn sealed(net: &mut Net, w: usize, g: Tid, c: &osis_commit::CommitBlob, stamp: Option<&osis_crypto::SigningSecret>, seed: u64) -> (osis_base::BlobId, osis_proto::Event) {
    let p = osis_commit::project(c, |_| ()).unwrap().remove(0);
    let class = osis_label::Class::of_marker(c.header.ephemeral);
    let body = osis_node::labeling::Body { commit: c.id(), reader: g, parts: p.parts, expires: p.expires, keys: p.keys, blind: c.header.blind, plaintext: p.plaintext, membership: false };
    let s = osis_node::labeling::seal_body_as(&body, class, &mut osis_crypto::SeededRng::from_u64(seed)).unwrap();
    let secret = net.engine(w).wrap_secret(&g, None).unwrap().unwrap();
    let wrap = osis_crypto::wrap(&secret, &s.id, &s.key).unwrap();
    let l = net.label(w);
    let stamp = stamp.map(|k| osis_label::sign_stamp(k, &l, &s.id, &wrap));
    (s.id, osis_proto::Event::Added { blob_id: s.id, blob: Some(s.blob), wrap, stamp })
}

/// Server `sv` pushes `events` of label `l` to node `n` (a replay or a hostile server's push);
/// the node's actions.
pub(crate) fn push(net: &mut Net, n: usize, sv: usize, l: osis_base::LabelId, events: Vec<osis_proto::Event>) -> Vec<osis_node::sync::Action> {
    let conn = net.conn_to(n, sv).unwrap();
    let cursor = osis_proto::Cursor { log_id: [0; 16], seq: 0 };
    let bytes = osis_proto::encode_frame(&osis_proto::Message::Push { label: l, events, cursor }.encode());
    net.sync(n).handle(Event::Bytes { conn, bytes })
}

/// Messages node actions `acts` send on `conn`.
fn sent(acts: &[osis_node::sync::Action], conn: osis_node::sync::ConnId) -> Vec<osis_proto::Message> {
    let mut out = Vec::new();
    for a in acts {
        if let osis_node::sync::Action::Send { conn: c, bytes } = a
            && *c == conn
        {
            let mut d = osis_proto::FrameDecoder::new();
            d.push(bytes);
            while let Ok(Some(body)) = d.next_frame() {
                if let Ok(m) = osis_proto::Message::decode(&body) {
                    out.push(m);
                }
            }
        }
    }
    out
}

const STATE: &str = "/win/state";
const NOTES: &str = "/win/notes";
const CURSOR: &str = "/win/cursor";

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

pub(crate) fn rows(b: &osis_store::MemoryBackend) -> usize {
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

// notes/ephemeral.md Bounds (server cap): one write too large for the cap has nothing to compact
// (one held part): the label reports and that write stays out of the server, the defined outcome;
// later writes that fit still sync
#[test]
fn server_cap_one_huge_write_reports_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server_with(osis_server::Policy { ephemeral_bytes: 4_000, ..osis_server::Policy::default() });
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let rx = net.listen(a);
    let mut m = Mutation::new();
    m.op(w, &eph("/win/big"), PathOp { path: Vec::new(), op: Op::Set(s(&"x".repeat(6_000))) }).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    let refused = rx.try_iter().any(|e| matches!(e, osis_node::Event::Diagnostic(d) if d.kind == osis_node::DiagnosticKind::EphemeralRefused));
    assert!(refused, "reported");
    assert_eq!(net.eph_read(b, w, "/win/big"), None);
    note(&mut net, a, w, "k", "v");
    net.run();
    assert_eq!(notes(&mut net, b, w), map(&[("k", "v")]), "a later write that fits syncs");
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

// spec/commits.md §4, spec/sync.md §9 (only verified commits are held and spread): another blob
// of a held ephemeral commit, the same header with a junk delta or signature, is refused
#[test]
fn forged_copy_of_held_commit_refused_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "durable");
    net.run();
    let mut m = Mutation::new();
    m.set(t, &eph("/doc/cursor"), &Value::Int(7)).unwrap();
    net.engine(a).write(m).unwrap();
    let cs = net.engine(a).take_ephemeral().unwrap();
    let blob = cs[0].blob.clone();
    assert_eq!(net.engine(b).ingest_ephemeral(blob.clone()).unwrap(), osis_node::ephemeral::EphIngest::Held { new: true });
    assert_eq!(net.engine(b).ingest_ephemeral(blob.clone()).unwrap(), osis_node::ephemeral::EphIngest::Held { new: false }, "a true copy");
    let mut junk = blob.clone();
    junk.parts[0].delta.push(0);
    assert!(net.engine(b).ingest_ephemeral(junk).is_err(), "a junk delta");
    let mut unsigned = blob;
    unsigned.signature = osis_crypto::Signature([0; 64]);
    assert!(net.engine(b).ingest_ephemeral(unsigned).is_err(), "a junk signature");
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
    assert_eq!(at_a, map(&[("b", "1"), ("c", "1")]), "the covered writes stay (the cover's author is valid and vouches for them); c's own commit goes");
}

// spec/sync.md §7 (compaction): a cover also carries a one-part aspect of a held commit it would
// otherwise leave partly covered, so it absorbs that commit (sim `ephemeral` seed 83: a holder's
// refused cover never absorbed another's cover spanning a second window)
#[test]
fn cover_absorbs_commit_spanning_one_part_aspect_spec_sync_7() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w1 = window(&mut net, a, g, "w1");
    let w2 = window(&mut net, a, g, "w2");
    net.run();
    // one commit on w1's notes and w2's notes (w2's notes have no other part)
    let mut m = Mutation::new();
    m.op(w1, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s("a"))], op: Op::Set(s("1")) }).unwrap();
    m.op(w2, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s("a"))], op: Op::Set(s("2")) }).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    note(&mut net, b, w1, "b", "1");
    net.run();
    let cover = net.engine(b).compact_ephemeral(None, true).unwrap().expect("compacted");
    assert_eq!(net.engine(b).held_ephemeral().len(), 1, "every held commit absorbed (the windows' records and placements, both note commits), the cover held");
    net.engine(a).ingest_ephemeral(cover.blob).unwrap();
    assert_eq!(notes(&mut net, a, w2), map(&[("a", "2")]));
    assert_eq!(notes(&mut net, a, w1), map(&[("a", "1"), ("b", "1")]));
}

// spec/permissions.md §5.2 (a valid ephemeral commit vouches for the session writes it carries;
// owner decision "Snapshots vouch"): an honest writer's compaction carries a member's writes;
// once that member is removed they stay at every holder and at a node arriving later, alike
#[test]
fn removed_member_covered_writes_stay_spec_permissions_5_2() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let d = net.node(4, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write), (d, Role::Read)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    note(&mut net, c, w, "c", "from c");
    note(&mut net, a, w, "a", "from a");
    net.run();
    // b covers both writes and the covered commits go everywhere
    let held = net.engine(b).held_ephemeral().len();
    let acts = net.sync(b).compact_ephemeral_now().unwrap();
    net.actions(b, acts);
    net.run();
    assert!(net.engine(d).held_ephemeral().len() < held, "the covered commits went");
    assert_eq!(notes(&mut net, d, w), map(&[("a", "from a"), ("c", "from c")]));
    let ct = net.tid(c);
    let me = net.tid(a);
    let bt = net.tid(b);
    let dt = net.tid(d);
    let e = net.engine(a);
    let rs = recipients_of(e, &[(me, Role::Admin), (bt, Role::Write), (dt, Role::Read)]);
    remove_member(e, g, ct, &rs, 9);
    net.run();
    let both = map(&[("a", "from a"), ("c", "from c")]);
    for n in [a, b, d] {
        assert_eq!(notes(&mut net, n, w), both, "node {n}: the cover vouches for c's write");
    }
    net.restart(d, 41);
    net.advance(10_000);
    assert_eq!(notes(&mut net, d, w), both, "a node arriving later gets it from the cover");
}

/// One random run of the shared window (notes/ephemeral.md Convergence): four writers on two
/// servers (odd seeds: one with a small ephemeral cap, so writers compact), random ephemeral
/// writes, partitions (offline, one server blocked), node restarts and server restarts; after
/// healing every holder reads the same notes.
fn random_window_run(seed: u64) {
    random_window_run_on(seed, false, false)
}

/// `single`: one server only, always with the small cap (what it holds is all others get).
/// `inflight`: half the steps end after one hop of delivery instead of settling, so later
/// writes meet uploads still in flight (coalesced, spec/sync.md §9), and the second server is
/// at times slow (its messages held back for some steps).
fn random_window_run_on(seed: u64, single: bool, inflight: bool) {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut rnd = move |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let mut net = Net::new();
    // odd seeds: a small ephemeral cap at the first server forces compactions
    let s1 = if single || seed % 2 == 1 { net.add_server_with(osis_server::Policy { ephemeral_bytes: 6_000, ..osis_server::Policy::default() }) } else { net.add_server() };
    let s2 = net.add_server();
    let servers: Vec<usize> = if single { vec![s1] } else { vec![s1, s2] };
    let nodes: Vec<usize> = (0..4).map(|i| net.node(1 + i, &servers)).collect();
    let members: Vec<(usize, Role)> = nodes[1..].iter().map(|n| (*n, Role::Write)).collect();
    let g = net.group(nodes[0], &members, &servers);
    net.run();
    let w = window(&mut net, nodes[0], g, "w");
    net.run();
    let mut restarts = 100;
    let mut log = Vec::new();
    // each node's live cursor: its last presence write since its last restart
    let mut cursors: BTreeMap<usize, String> = BTreeMap::new();
    // presence writes come from their own stream, so a seed's other steps stay what they were
    let mut y = seed.wrapping_mul(0xd1b5_4a32_d192_ed03) | 1;
    let mut prnd = move |n: u64| {
        y ^= y << 13;
        y ^= y >> 7;
        y ^= y << 17;
        y % n
    };
    // in-flight steps from a stream of their own as well
    let mut z = seed.wrapping_mul(0x94d0_49bb_1331_11eb) | 1;
    let mut irnd = move || {
        z ^= z << 13;
        z ^= z >> 7;
        z ^= z << 17;
        z.is_multiple_of(2)
    };
    for step in 0..40 {
        let p = nodes[prnd(4) as usize];
        if prnd(4) == 0 && (net.engine(p).ephemeral_thing(&w).is_some() || net.eph_read(p, w, STATE).is_some()) {
            // p's cursor, keyed by p
            let v = format!("c{step}");
            log.push(format!("{p} cursor {v}"));
            let mut m = Mutation::new();
            m.op(w, &ukey(CURSOR, Lifetime::Presence), PathOp { path: vec![PathSeg::Key(s(&p.to_string()))], op: Op::Set(s(&v)) }).unwrap();
            net.engine(p).write(m).unwrap();
            cursors.insert(p, v);
        }
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
                let s = if rnd(2) == 0 || single { s1 } else { s2 };
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
                cursors.remove(&n);
                let on = net.nodes[n].online;
                net.restart(n, restarts);
                net.set_online(n, on);
            }
            8 if rnd(4) == 0 => {
                let s = if rnd(2) == 0 || single { s1 } else { s2 };
                log.push(format!("server {s} restarts"));
                net.restart_server(s);
            }
            _ => {
                log.push("advance".into());
                net.advance(1_000 + rnd(20_000));
                continue;
            }
        }
        // a slow server: its answers and pushes held back for a while
        if inflight && !single && irnd() && irnd() {
            if net.held_servers.remove(&s2) {
                log.push(format!("server {s2} answers"));
                net.release();
            } else {
                log.push(format!("server {s2} slow"));
                net.held_servers.insert(s2);
            }
        }
        if inflight && irnd() {
            log.push("one hop".into());
            for n in &nodes {
                net.feed(*n, Event::Local);
            }
            net.round();
        } else {
            net.run();
        }
    }
    net.blocked.clear();
    net.release();
    for n in &nodes {
        net.set_online(*n, true);
    }
    for _ in 0..4 {
        net.advance(15_000);
    }
    let holders: Vec<usize> = nodes.iter().copied().filter(|n| net.engine(*n).ephemeral_thing(&w).is_some()).collect();
    let Some(&h0) = holders.first() else {
        // lost only when no node holds it (spec/requirements.md Ephemeral data): every node and
        // both servers restarted
        let restarted = |who: &str| log.iter().any(|l| *l == format!("{who} restarts"));
        let all = nodes.iter().all(|n| restarted(&n.to_string())) && servers.iter().all(|s| restarted(&format!("server {s}")));
        assert!(all, "seed {seed}: nobody holds the window\n{}", log.join("\n"));
        return;
    };
    let first = notes(&mut net, h0, w);
    for n in &holders[1..] {
        assert_eq!(notes(&mut net, *n, w), first, "seed {seed}: node {n} differs from node {h0}\n{}", log.join("\n"));
    }
    // presence: every holder reads exactly the live cursors (their authors are all connected;
    // presence has its own room at a server, apart from the capped ephemeral state)
    let want: BTreeMap<String, String> = cursors.iter().filter(|(n, _)| holders.contains(n)).map(|(n, v)| (n.to_string(), v.clone())).collect();
    for n in &holders {
        assert_eq!(str_map(net.eph_read(*n, w, CURSOR)), want, "seed {seed}: node {n}'s cursors\n{}", log.join("\n"));
    }
    // and no server keeps a covered presence entry: at most one per live cursor
    let l = net.label(h0);
    for sv in &servers {
        let store = net.servers[*sv].hub.store();
        let ids = osis_proto::LabelStore::live_ids(store, &l).unwrap_or_default();
        let presence = ids.iter().filter(|b| osis_proto::LabelStore::blob(store, b).ok().flatten().and_then(|x| osis_label::Prefix::parse(&x).ok()).is_some_and(|p| p.class() == osis_label::Class::Presence)).count();
        assert!(presence <= cursors.len(), "seed {seed}: server {sv} holds {presence} presence entries for {} cursors\n{}", cursors.len(), log.join("\n"));
    }
}

/// A `map<string, string>` value as a map (absent: empty).
fn str_map(v: Option<Value>) -> BTreeMap<String, String> {
    match v {
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

// the same with one server at a small cap, at seeds where a holder's concurrent cover stayed
// refused while the server held another's, and its writes with it (no further forced compaction)
#[test]
fn random_window_one_capped_server_spec_sync_9() {
    for seed in [10, 63, 105, 162] {
        random_window_run_on(seed, true, false);
    }
}

/// The tier-2 random-window seeds: OSIS_EPH_SEEDS (default 200) from OSIS_EPH_START (default 0).
fn eph_seeds() -> std::ops::Range<u64> {
    let s = osis_base::testenv::Seeds::from_env("OSIS_EPH_START", "OSIS_EPH_SEEDS", 0..200);
    s.announce("random_window");
    s.range
}

// the same with one server at a small cap: holders converge through what it holds (compaction
// under a full server must neither loop nor stop with a holder's writes refused)
#[test]
#[ignore]
fn random_window_one_capped_server_large() {
    for seed in eph_seeds() {
        eprintln!("seed {seed}");
        random_window_run_on(seed, true, false);
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
    for seed in eph_seeds() {
        eprintln!("seed {seed}");
        random_window_run(seed);
    }
}

// the same with half the steps ending while messages are in flight, so writes meet unanswered
// uploads and are coalesced (spec/sync.md §9)
#[test]
fn random_window_inflight_spec_sync_9() {
    for seed in 0..4 {
        random_window_run_on(seed, false, true);
    }
}

// the same over more seeds (tier 2): OSIS_EPH_SEEDS (default 200) from OSIS_EPH_START
#[test]
#[ignore]
fn random_window_inflight_large() {
    for seed in eph_seeds() {
        eprintln!("seed {seed}");
        random_window_run_on(seed, false, true);
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


// spec/sync.md §9 (security review H3): ephemeral commits the engine did not verify and hold are
// neither kept nor spread: one more than `MAX_DRIFT` ahead is dropped; one by an author whose
// record is unknown waits apart, under a share of the cap, unserved and unspread
#[test]
fn unverified_ephemeral_not_kept_or_spread_spec_sync_9() {
    let mut net = Net::new();
    let (s1, s2) = (net.add_server(), net.add_server());
    let a = net.node(1, &[s1]);
    let cap = 40_000;
    let b = net.add_node(2, SyncConfig { servers: vec![net.address(s1), net.address(s2)], ephemeral_bytes: cap, ..SyncConfig::default() });
    let x = net.node(3, &[]);
    let g = net.group(a, &[(b, Role::Write)], &[s1, s2]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let l = net.label(a);
    let entries = net.sync(b).ephemeral_entries(&l);
    let at_s2 = net.servers[s2].hub.store().ephemeral_bytes(&l);
    let wk = write_key(&mut net, a, g);
    let ak = osis_base::Ak::new(STATE).unwrap();
    // a writer's commit stamped three hours ahead
    net.engine(a).set_clock_offset(3 * 3_600_000);
    let future = net.engine(a).forge_ephemeral(w, &ak, s("from the future")).unwrap().unwrap();
    net.engine(a).set_clock_offset(0);
    let (_, ev) = sealed(&mut net, a, g, &future.blob, Some(&wk), 1);
    let acts = push(&mut net, b, s1, l, vec![ev]);
    net.actions(b, acts);
    net.run();
    assert!(!net.engine(b).holds_ephemeral(&future.id), "not held");
    assert_eq!(net.eph_read(b, w, STATE), Some(s("w")));
    // commits under an author nobody here knows, stamped by a writer
    let rx = net.listen(b);
    let xt = net.tid(x);
    for i in 0..60 {
        let c = net.engine(x).forge_ephemeral(xt, &ak, s(&format!("junk {i} {}", "j".repeat(200)))).unwrap().unwrap();
        let (_, ev) = sealed(&mut net, a, g, &c.blob, Some(&wk), 10 + i);
        let acts = push(&mut net, b, s1, l, vec![ev]);
        net.actions(b, acts);
    }
    net.run();
    assert!(net.sync(b).ephemeral_pending_bytes(&l) <= cap / 4, "a share of the cap: {}", net.sync(b).ephemeral_pending_bytes(&l));
    assert!(net.sync(b).ephemeral_pending_bytes(&l) > 0, "kept apart while it waits");
    assert!(rx.try_iter().any(|e| matches!(e, osis_node::Event::Diagnostic(d) if d.kind == osis_node::DiagnosticKind::EphemeralRefused)), "reported");
    assert_eq!(net.sync(b).ephemeral_entries(&l), entries, "nothing unverified in the lane");
    assert_eq!(net.servers[s2].hub.store().ephemeral_bytes(&l), at_s2, "nothing spread to the other server");
}

// spec/sync.md §9 (security review L2): a replay of an entry a held valid compaction covers is
// not held again, and a writer deletes it where it was found
#[test]
fn replayed_covered_entry_dropped_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let l = net.label(a);
    let wk = write_key(&mut net, a, g);
    let ak = osis_base::Ak::new(NOTES).unwrap();
    let old = net.engine(a).forge_ephemeral(w, &ak, Value::Map(BTreeMap::from([(s("k"), s("old"))]))).unwrap().unwrap();
    let (id, ev) = sealed(&mut net, a, g, &old.blob, Some(&wk), 1);
    let acts = push(&mut net, b, sv, l, vec![ev.clone()]);
    net.actions(b, acts);
    net.run();
    assert!(net.engine(b).holds_ephemeral(&old.id));
    note(&mut net, b, w, "k2", "v");
    net.run();
    let acts = net.sync(b).compact_ephemeral_now().unwrap();
    net.actions(b, acts);
    net.run();
    assert!(!net.engine(b).holds_ephemeral(&old.id), "covered");
    let acts = push(&mut net, b, sv, l, vec![ev]);
    assert!(!net.engine(b).holds_ephemeral(&old.id), "a replay is not held again");
    let conn = net.conn_to(b, sv).unwrap();
    let deletes: Vec<osis_base::BlobId> = sent(&acts, conn).into_iter().flat_map(|m| if let osis_proto::Message::Delete { items, .. } = m { items.into_iter().map(|i| i.blob).collect() } else { vec![] }).collect();
    assert_eq!(deletes, vec![id], "deleted where it came back");
    net.actions(b, acts);
    net.run();
}

// spec/sync.md §9 (ephemeral parts on core aspects; security review L3): a writer's ephemeral
// part on a core aspect other than `/group` (here `/reach`) is invalid: never joined
#[test]
fn core_aspect_part_refused_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "durable");
    net.run();
    let ak = osis_base::Ak::new("/reach").unwrap();
    let forged = net.engine(a).forge_ephemeral(t, &ak, s("injected")).unwrap().unwrap();
    net.engine(b).ingest_ephemeral(forged.blob).unwrap();
    assert_eq!(net.eph_read(b, t, "/reach"), None, "not joined");
}

// security review M6: session attributions come from held parts only and go with them; relay-only
// commits add none
#[test]
fn session_claims_released_spec_requirements_scale() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let base = net.engine(b).ephemeral_claims();
    for i in 0..5 {
        net.restart(a, 50 + i);
        net.advance(10_000);
        let mut m = Mutation::new();
        m.set(w, &eph("/win/typing"), &Value::Int(i as i64)).unwrap();
        m.expires(w, &eph("/win/typing"), osis_base::WallMs(net.now() + 5_000)).unwrap();
        net.engine(a).write(m).unwrap();
        net.eph_write(a, w, &ukey("/win/ring", Lifetime::Signal), s("ding"));
        local(&mut net, a);
        net.run();
    }
    assert!(net.engine(b).ephemeral_claims() > base, "held parts name the new sessions");
    net.advance(60_000);
    assert!(net.engine(b).ephemeral_claims() <= base, "released with the expired parts: {} > {base}", net.engine(b).ephemeral_claims());
}

// open question of the step 3 review: a device reachable only through a member peer gets the
// signals that peer receives from a server, and its own reach the server's devices; each once
#[test]
fn signals_through_member_peer_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    for (n, k) in [(b, 0xb5), (c, 0xc5)] {
        let acts = net.sync(n).publish_reach([k; 32], vec!["https://relay.example".into()]).unwrap();
        net.actions(n, acts);
    }
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "x");
    net.run();
    // c loses the server: only b's peer link is left
    net.blocked.insert((c, sv));
    net.restart(c, 33);
    net.advance(10_000);
    let (ra, rb, rc) = (net.listen(a), net.listen(b), net.listen(c));
    net.eph_write(a, t, &ukey("/t/ring", Lifetime::Signal), s("from a"));
    net.run();
    assert_eq!(fired(&rb).len(), 1);
    assert_eq!(fired(&rc).len(), 1, "through the member peer, once");
    net.eph_write(c, t, &ukey("/t/ring", Lifetime::Signal), s("from c"));
    net.run();
    assert_eq!(fired(&rb).len(), 1);
    assert_eq!(fired(&ra).iter().filter(|x| x.2 == s("from c")).count(), 1, "the peer passes it to the server, once");
}

// spec/sync.md §4 (ephemeral entries are held in memory only): an ephemeral entry announced
// without its bytes (above the inline limit) is fetched and goes to the lane once its prefix
// shows its class; no sync record of it stays (one did, and a restart then counted it as held)
#[test]
fn announced_ephemeral_leaves_no_sync_record_spec_sync_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.add_node(2, SyncConfig { servers: vec![net.address(sv)], inline_limit: 0, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let l = net.label(a);
    let durable: Vec<osis_base::BlobId> = net.sync(b).entries(&l).into_iter().map(|(x, _)| x).collect();
    net.set_online(b, false);
    let w = window(&mut net, a, g, "big");
    note(&mut net, a, w, "k", "v");
    net.run();
    net.set_online(b, true);
    net.advance(10_000);
    assert_eq!(notes(&mut net, b, w), map(&[("k", "v")]));
    let after: Vec<osis_base::BlobId> = net.sync(b).entries(&l).into_iter().map(|(x, _)| x).filter(|x| !durable.contains(x)).collect();
    assert!(after.is_empty(), "ephemeral entries left sync records: {after:?}");
    assert!(net.sync(b).ephemeral_entries(&l) >= 2);
}

/// Bytes nodes send to the server while `b` writes 20 notes one by one, after `a` wrote `stuck`
/// bytes in one write (`a` holds an own entry the server refuses for good when it exceeds the cap).
fn bytes_under_stuck_entry(stuck: usize) -> usize {
    let mut net = Net::new();
    let sv = net.add_server_with(osis_server::Policy { ephemeral_bytes: 6_000, ..osis_server::Policy::default() });
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let mut m = Mutation::new();
    m.op(w, &eph("/win/big"), PathOp { path: Vec::new(), op: Op::Set(s(&"x".repeat(stuck))) }).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    let before = net.sent_bytes;
    for i in 0..20 {
        note(&mut net, b, w, &format!("k{i}"), "v");
        net.run();
    }
    let want: BTreeMap<String, String> = (0..20).map(|i| (format!("k{i}"), "v".to_string())).collect();
    assert_eq!(notes(&mut net, a, w), want);
    net.sent_bytes - before
}

// spec/sync.md §9 (compaction on a cap refusal): an own entry the server refuses for good (one
// write over the cap) does not make its holder compact and re-upload it at every other node's
// write (it did: 5.5x the bytes, one forced compaction per foreign write); only another holder's
// cover re-arms a compaction for an own refused cover
#[test]
fn server_cap_stuck_entry_no_churn_spec_sync_9() {
    let fits = bytes_under_stuck_entry(100);
    let stuck = bytes_under_stuck_entry(7_000);
    assert!(stuck < fits + fits / 4, "{stuck} bytes sent with a refused entry held, {fits} without");
}

/// Node `n` sets `ak` of `w` to `len` bytes, expiring `ms` from now (never compacted).
fn expiring(net: &mut Net, n: usize, w: Tid, ak: &str, len: usize, ms: u64) {
    let mut m = Mutation::new();
    m.set(w, &eph(ak), &s(&"x".repeat(len))).unwrap();
    m.expires(w, &eph(ak), osis_base::WallMs(net.now() + ms)).unwrap();
    net.engine(n).write(m).unwrap();
    local(net, n);
}

// spec/sync.md §9 (holders upload what a server lacks): an entry a full server refused, that no
// compaction can cover (it expires), goes up again once room is made without a deletion (b's
// entries expire there), at the periodic pass (it stayed out until a reconnect: sim
// `ephemeral_capped` seed 14)
#[test]
fn server_cap_refused_entry_retried_spec_sync_9() {
    let cap = 8_000;
    let mut net = Net::new();
    let sv = net.add_server_with(osis_server::Policy { ephemeral_bytes: cap, ..osis_server::Policy::default() });
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    let held = |net: &Net| net.servers[sv].hub.store().ephemeral_bytes(&l);
    // b fills it with entries that expire soon, until one is refused
    for i in 0.. {
        assert!(i < 20, "nothing refused under a {cap} B cap");
        let before = held(&net);
        expiring(&mut net, b, t, &format!("/win/b{i}"), 1_500, 20_000);
        net.run();
        if held(&net) == before {
            break;
        }
    }
    expiring(&mut net, a, t, "/win/a", 1_500, 600_000);
    net.run();
    assert!(net.eph_read(b, t, "/win/a").is_none(), "refused ({} B held, cap {cap})", held(&net));
    net.advance(61_000);
    assert!(net.eph_read(b, t, "/win/a").is_some(), "a's write reached b");
}

/// Upload messages nodes sent so far (osis-proto message kind 10).
fn uploads_sent(net: &Net) -> usize {
    net.sent_kinds.get(&10).copied().unwrap_or(0)
}

// spec/sync.md §9 (own plain writes made while an upload of the label is unanswered join the next
// commit): a burst of note edits during one upload in flight goes up as two commits, and both
// holders converge on every edit; B, also writing meanwhile, merges with it
#[test]
fn burst_coalesced_while_upload_in_flight_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "shared");
    net.run();
    let up = uploads_sent(&net);
    let mut want = BTreeMap::new();
    for i in 0..20 {
        note(&mut net, a, w, &format!("k{i}"), &format!("v{i}"));
        want.insert(format!("k{i}"), format!("v{i}"));
    }
    // overwrites inside the burst: the latest wins
    note(&mut net, a, w, "k3", "last");
    want.insert("k3".into(), "last".into());
    assert_eq!(uploads_sent(&net) - up, 1, "one upload in flight, the rest wait");
    note(&mut net, b, w, "b", "from b");
    want.insert("b".into(), "from b".into());
    net.run();
    assert_eq!(uploads_sent(&net) - up, 3, "A's first edit, A's other 20 in one commit, B's");
    assert_eq!(notes(&mut net, a, w), want);
    assert_eq!(notes(&mut net, b, w), want);
    // a restarted holder gets the same back from the server
    net.restart(b, 21);
    net.advance(10_000);
    assert_eq!(notes(&mut net, b, w), want);
}

// spec/sync.md §9: signals are never held back or merged: each signal write sent while a plain
// upload of the label is in flight is its own relay-only commit at once, and each fires once at B
#[test]
fn signals_not_held_back_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "x");
    net.run();
    let w = window(&mut net, a, g, "busy");
    let up = uploads_sent(&net);
    let rb = net.listen(b);
    for i in 0..5 {
        net.eph_write(a, t, &ukey("/t/ring", Lifetime::Signal), s(&format!("ding {i}")));
    }
    assert_eq!(uploads_sent(&net) - up, 5, "one relay-only upload per signal, none waits");
    net.run();
    let got: Vec<Value> = fired(&rb).into_iter().filter(|(x, ak, _, _)| *x == t && ak == "/t/ring").map(|(_, _, v, _)| v).collect();
    assert_eq!(got.len(), 5, "{got:?}");
    assert_eq!(net.eph_read(b, w, STATE), Some(s("busy")));
}

// spec/sync.md §9 (own plain writes wait only while every connection of the label has an own
// upload unanswered): with one server slow to answer, each edit reaches B through the other at
// once
#[test]
fn slow_server_holds_nothing_back_spec_sync_9() {
    let mut net = Net::new();
    let (fast, slow) = (net.add_server(), net.add_server());
    let a = net.node(1, &[fast, slow]);
    let b = net.node(2, &[fast]);
    let g = net.group(a, &[(b, Role::Write)], &[fast, slow]);
    net.run();
    let w = window(&mut net, a, g, "shared");
    net.run();
    net.held_servers.insert(slow);
    let mut want = BTreeMap::new();
    for i in 0..5 {
        note(&mut net, a, w, &format!("k{i}"), &format!("v{i}"));
        want.insert(format!("k{i}"), format!("v{i}"));
        net.run();
        assert_eq!(notes(&mut net, b, w), want, "edit {i} reached B through the fast server");
    }
    net.release();
    net.run();
    assert_eq!(notes(&mut net, b, w), want);
}

/// A writes notes while server `slow` holds its answers, then compacts: the covered entries'
/// uploads are unanswered there. `reconnect`: the connection to `slow` ends before it answers
/// and is made again; else `slow` answers. B only reads (it deletes nothing). Returns what each
/// server then holds under the label.
fn covered_while_slow(reconnect: bool) -> (BTreeSet<osis_base::BlobId>, BTreeSet<osis_base::BlobId>) {
    let mut net = Net::new();
    let (fast, slow) = (net.add_server(), net.add_server());
    let a = net.node(1, &[fast, slow]);
    let b = net.node(2, &[fast]);
    let g = net.group(a, &[(b, Role::Read)], &[fast, slow]);
    net.run();
    let w = window(&mut net, a, g, "shared");
    net.run();
    net.held_servers.insert(slow);
    for i in 0..4 {
        note(&mut net, a, w, &format!("k{i}"), &format!("v{i}"));
        net.run();
    }
    let acts = net.sync(a).compact_ephemeral_now().unwrap();
    net.actions(a, acts);
    net.run();
    if reconnect {
        net.drop_link(a, slow);
    }
    net.release();
    net.run();
    net.advance(60_000);
    assert!(net.conn_to(a, slow).is_some(), "reconnected");
    assert_eq!(notes(&mut net, b, w).len(), 4);
    let l = net.label(a);
    (net.server_ids(fast, &l).into_iter().collect(), net.server_ids(slow, &l).into_iter().collect())
}

// spec/sync.md §9 (a covered entry deleted where it was uploaded, once that upload is
// answered): a slow server ends holding what the fast one does
#[test]
fn covered_while_slow_deleted_once_answered_spec_sync_9() {
    let (fast, slow) = covered_while_slow(false);
    assert_eq!(slow, fast);
}

// the same when the connection ends before the answer: the pending delete is dropped with the
// connection, and the covered entries, announced again on the next one, are deleted then
#[test]
fn covered_while_slow_deleted_after_reconnect_spec_sync_9() {
    let (fast, slow) = covered_while_slow(true);
    assert_eq!(slow, fast);
}
