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

// spec/data-model.md §8, spec/crdt.md §4.6 (undoing a save restores the draft's ephemeral
// placement): a durable thing whose placement is ephemeral (here a draft saved, the save undone,
// the node restarted and its ephemeral writes back from the server: no undo log, nothing marks
// it a draft) gets that placement converted by its next durable write, as at its first; the
// other member sees it placed durably again
#[test]
fn ephemeral_placement_of_durable_thing_converts_spec_data_model_8() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "draft");
    net.run();
    let mut m = Mutation::new();
    m.set(w, &REG, &s("saved")).unwrap();
    let saved = net.engine(a).write(m).unwrap().unwrap().id;
    local(&mut net, a);
    net.run();
    assert!(net.engine(b).durable_groups_of(&w).contains(&g));
    let me = net.tid(a);
    net.engine(a).revert_change(saved, me).unwrap();
    local(&mut net, a);
    net.run();
    for n in [a, b] {
        assert!(net.engine(n).groups_of(&w).contains(&g) && !net.engine(n).durable_groups_of(&w).contains(&g), "placed ephemerally again");
        assert_eq!(net.read(n, w), None);
    }
    net.restart(a, 31);
    net.advance(10_000);
    assert!(net.engine(a).groups_of(&w).contains(&g) && !net.engine(a).durable_groups_of(&w).contains(&g), "the ephemeral placement came back");
    assert_eq!(net.eph_read(a, w, STATE), Some(s("draft")));
    let mut m = Mutation::new();
    m.set(w, &REG, &s("again")).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    assert!(net.engine(a).durable_groups_of(&w).contains(&g), "converted by the durable write");
    net.run();
    assert!(net.engine(b).durable_groups_of(&w).contains(&g) && net.read(b, w) == Some(s("again")));
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

// spec/crdt.md §4.6 (un-merge rebuilds from what is held), spec/sync.md §9 (an own cover carries
// the author's earlier sessions' writes): a restarted node gets its old commits back and covers
// them as its own; a later validity flip on the aspect rebuilds it from the own writes and the
// held parts, the own cover included, so the old writes stay and the holders agree
#[test]
fn own_cover_survives_rebuild_spec_crdt_4_6() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    note(&mut net, a, w, "a", "1");
    net.run();
    net.restart(a, 31);
    net.advance(10_000);
    assert_eq!(notes(&mut net, a, w), map(&[("a", "1")]), "a's earlier session's writes came back");
    note(&mut net, b, w, "b", "1");
    note(&mut net, c, w, "c", "1");
    net.run();
    let acts = net.sync(a).compact_ephemeral_now().unwrap();
    net.actions(a, acts);
    net.run();
    let at = net.tid(a);
    let by_a = |net: &mut Net, n: usize| {
        let e = net.engine(n);
        e.held_ephemeral().into_iter().filter(|(id, _, _)| e.ephemeral_header(id).is_some_and(|h| h.author == at && h.ephemeral == Some(osis_commit::EphClass::Plain))).count()
    };
    assert_eq!(by_a(&mut net, a), 1, "a's cover absorbed its earlier session's commits");
    assert_eq!(by_a(&mut net, b), 1, "and b dropped them");
    note(&mut net, c, w, "c2", "2");
    net.run();
    let ct = net.tid(c);
    let bt = net.tid(b);
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write)]);
    remove_member(e, g, ct, &rs, 9);
    net.run();
    let at_a = notes(&mut net, a, w);
    assert_eq!(at_a, notes(&mut net, b, w), "holders agree");
    assert_eq!(at_a, map(&[("a", "1"), ("b", "1")]), "a's covered writes stay; c's go");
}

// spec/sync.md §9 (an own cover absorbs every own held commit, across things): one commit
// spanning two windows and a later note are absorbed by the author's cover, at the author and at
// a holder; another writer's commits stay
#[test]
fn own_cover_absorbs_every_own_commit_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w1 = window(&mut net, a, g, "w1");
    let w2 = window(&mut net, a, g, "w2");
    net.run();
    let mut m = Mutation::new();
    m.op(w1, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s("a"))], op: Op::Set(s("1")) }).unwrap();
    m.op(w2, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s("a"))], op: Op::Set(s("2")) }).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    note(&mut net, a, w1, "a2", "3");
    note(&mut net, b, w1, "b", "1");
    net.run();
    let (at, bt) = (net.tid(a), net.tid(b));
    let held_by = |net: &mut Net, n: usize, author: Tid| {
        let e = net.engine(n);
        e.held_ephemeral().into_iter().filter(|(id, _, _)| e.ephemeral_header(id).is_some_and(|h| h.author == author)).count()
    };
    let b_held = held_by(&mut net, a, bt);
    assert!(b_held > 0);
    let acts = net.sync(a).compact_ephemeral_now().unwrap();
    net.actions(a, acts);
    net.run();
    for n in [a, b] {
        assert_eq!(held_by(&mut net, n, at), 1, "node {n}: a's commits (windows, placements, notes) absorbed by its cover");
    }
    assert_eq!(held_by(&mut net, a, bt), b_held, "b's commits are b's to cover");
    for n in [a, b] {
        assert_eq!(notes(&mut net, n, w2), map(&[("a", "2")]));
        assert_eq!(notes(&mut net, n, w1), map(&[("a", "1"), ("a2", "3"), ("b", "1")]));
    }
}

// spec/permissions.md §5.2 (an ephemeral part is judged as its author's delta and carries only
// its author's writes): covers never carry a member's writes, so once that member is removed its
// writes go at every holder and at a node arriving later, whoever compacted meanwhile
#[test]
fn removed_member_writes_go_after_covers_spec_permissions_5_2() {
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
    note(&mut net, b, w, "b", "from b");
    net.run();
    for n in [a, b] {
        let acts = net.sync(n).compact_ephemeral_now().unwrap();
        net.actions(n, acts);
        net.run();
    }
    let all = map(&[("a", "from a"), ("b", "from b"), ("c", "from c")]);
    assert_eq!(notes(&mut net, d, w), all);
    let ct = net.tid(c);
    let me = net.tid(a);
    let bt = net.tid(b);
    let dt = net.tid(d);
    let e = net.engine(a);
    let rs = recipients_of(e, &[(me, Role::Admin), (bt, Role::Write), (dt, Role::Read)]);
    remove_member(e, g, ct, &rs, 9);
    net.run();
    let left = map(&[("a", "from a"), ("b", "from b")]);
    for n in [a, b, d] {
        assert_eq!(notes(&mut net, n, w), left, "node {n}: c's write goes");
    }
    net.restart(d, 41);
    net.advance(10_000);
    assert_eq!(notes(&mut net, d, w), left, "a node arriving later agrees");
}

// spec/sync.md §9 (an ephemeral commit carries only its author's writes): a writer's commit
// carrying another node's writes under that node's name joins only the writer's own
#[test]
fn others_writes_in_a_commit_not_joined_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    assert!(net.engine(c).ephemeral_thing(&w).is_some());
    net.set_online(c, false);
    note(&mut net, a, w, "a", "1");
    note(&mut net, b, w, "b", "1");
    net.run();
    let ak = osis_base::Ak::new(NOTES).unwrap();
    let forged = net.engine(b).forge_carrying(osis_commit::EphClass::Plain, w, &ak).unwrap().unwrap();
    net.engine(c).ingest_ephemeral(forged.blob).unwrap();
    assert_eq!(notes(&mut net, c, w), map(&[("b", "1")]), "a's write is a's to send");
}

// spec/sync.md §9 (a carried `/created` is exactly one minting of its record): a writer that
// pads an ephemeral thing's `/created` with a losing junk write has its commit refused, so no
// honest node keeps that `/created` to carry in its own commits
#[test]
fn padded_created_refused_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let e = net.engine(a);
    let mut m = Mutation::new();
    let w = e.new_thing(&mut m, g);
    m.op(g, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(Value::Tid(w)) }).unwrap();
    e.write(m).unwrap();
    let ak = osis_base::Ak::new(STATE).unwrap();
    let honest = net.engine(a).forge_ephemeral(w, &ak, s("honest")).unwrap().unwrap();
    net.engine(a).pad_created(&w, Value::Bytes(vec![7; 4096])).unwrap();
    let padded = net.engine(a).forge_ephemeral(w, &ak, s("padded")).unwrap().unwrap();
    assert!(net.engine(b).ingest_ephemeral(padded.blob).is_err(), "refused");
    assert!(net.engine(b).ephemeral_thing(&w).is_none(), "its /created not kept");
    net.engine(b).ingest_ephemeral(honest.blob).unwrap();
    assert!(net.engine(b).ephemeral_thing(&w).is_some(), "the unpadded one is taken");
}

// spec/sync.md §9 (a carried `/created` is exactly one minting): an own cover joining the records
// its commits carried, two copies of one thing (as after a restart between first sights) now
// durable here, carries one of them, and receivers take it
#[test]
fn own_cover_of_two_created_copies_taken_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let e = net.engine(a);
    let mut m = Mutation::new();
    let w = e.new_thing(&mut m, g);
    m.op(g, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(Value::Tid(w)) }).unwrap();
    e.write(m).unwrap();
    let ak = osis_base::Ak::new(STATE).unwrap();
    net.engine(a).forge_ephemeral(w, &ak, s("1")).unwrap().unwrap();
    net.engine(a).remint_created(&w).unwrap();
    net.engine(a).forge_ephemeral(w, &ak, s("2")).unwrap().unwrap();
    let mut m = Mutation::new();
    m.set(w, &REG, &s("saved")).unwrap();
    net.engine(a).write(m).unwrap();
    assert!(net.engine(a).ephemeral_thing(&w).is_none(), "durable now");
    let covers = net.engine(a).compact_own_ephemeral(true).unwrap();
    assert_eq!(covers.len(), 1);
    net.run();
    net.engine(b).ingest_ephemeral(covers[0].blob.clone()).unwrap();
}

// spec/sync.md §9 (an ephemeral commit carries only its author's writes): a write under another
// node's source (not a session its `Authors` attributes to the author) is not joined either
#[test]
fn node_sourced_write_in_a_commit_not_joined_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    note(&mut net, a, w, "a", "1");
    net.run();
    let ak = osis_base::Ak::new(NOTES).unwrap();
    let at = net.engine(a).tid();
    let v = Value::Map(BTreeMap::from([(s("x"), s("forged"))]));
    let forged = net.engine(b).forge_ephemeral_as_node(w, &ak, v, at).unwrap().unwrap();
    net.engine(a).ingest_ephemeral(forged.blob).unwrap();
    assert_eq!(notes(&mut net, a, w), map(&[("a", "1")]), "b passed a write off as a's node's");
}

// spec/sync.md §9 (what a cover absorbs is deleted at a server once the cover is held there):
// the author crashes before its cover reaches the server; nothing was deleted, so the state
// stays at the server for holders, a restarted holder and the author itself (deleting first
// lost those writes there for good: the tombstones keep holders from bringing them back)
#[test]
fn author_crash_before_cover_lands_keeps_state_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    for i in 0..3 {
        note(&mut net, a, w, &format!("k{i}"), "v");
        net.run();
    }
    let want = notes(&mut net, a, w);
    assert_eq!(want.len(), 3);
    let conn = net.conn_to(a, sv).unwrap();
    let acts = net.sync(a).compact_ephemeral_now().unwrap();
    let msgs = sent(&acts, conn);
    assert!(msgs.iter().any(|m| matches!(m, osis_proto::Message::Upload { .. })), "the cover goes up");
    assert!(!msgs.iter().any(|m| matches!(m, osis_proto::Message::Delete { .. })), "nothing deleted before the cover is held there");
    // what it sent never arrives
    net.restart(a, 77);
    net.advance(10_000);
    assert_eq!(notes(&mut net, b, w), want);
    assert_eq!(notes(&mut net, a, w), want, "the author gets its writes back");
    net.restart(b, 78);
    net.advance(10_000);
    assert_eq!(notes(&mut net, b, w), want, "the server still holds them");
}

// harness (random_window_inflight seed 173899): bytes a slow server held back for a connection
// that closed when it restarted never reach the restarted node's new connection of that number
// (they carried another connection's challenge: every open there was refused)
#[test]
fn restarted_node_gets_no_old_server_bytes() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    // b's first connection since a restart (numbered 1): the server's greeting held back
    net.set_online(b, false);
    net.restart(b, 49);
    net.held_servers.insert(sv);
    net.set_online(b, true);
    net.run();
    // the server restarts (b redials, connection 2), then b (connection 1 again): the old
    // greeting must not reach it
    net.restart_server(sv);
    net.run();
    net.restart(b, 50);
    net.run();
    net.release();
    net.run();
    // redials
    net.advance(30_000);
    note(&mut net, a, w, "k", "2");
    net.run();
    assert_eq!(notes(&mut net, b, w), map(&[("k", "2")]));
}

/// One random run of the shared window (notes/ephemeral.md Convergence): four writers on two
/// servers (odd seeds: one with a random ephemeral cap, 0 and below one cover included), random
/// ephemeral writes, partitions (offline, one server blocked), node restarts and server
/// restarts; after healing every holder reads the same notes (through the uncapped server), and
/// each writer's own held commits cost at most twice their cover (spec/sync.md §9).
fn random_window_run(seed: u64) {
    random_window_run_on(seed, false, false)
}

/// `single`: one server only, always capped (what it holds is all others get): holders read
/// alike unless an entry a holder has stays out of it because it genuinely does not fit there.
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
    // odd seeds (and `single`): a random ephemeral cap at the first server, from nothing fitting
    // to the whole state fitting
    let cap = [0, 1_500, 4_000, 8_000, 16_000, 64_000][(seed / 2 % 6) as usize];
    let s1 = if single || seed % 2 == 1 { net.add_server_with(osis_server::Policy { ephemeral_bytes: cap, ..osis_server::Policy::default() }) } else { net.add_server() };
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
    // nodes that held the window since their last restart
    let mut kept: BTreeSet<usize> = BTreeSet::from([nodes[0]]);
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
                kept.remove(&n);
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
        kept.extend(nodes.iter().copied().filter(|n| syncs(&mut net, *n, w)));
    }
    net.blocked.clear();
    net.release();
    for n in &nodes {
        net.set_online(*n, true);
    }
    for _ in 0..4 {
        net.advance(15_000);
    }
    // one more periodic pass: entries a full server refused go again once room appeared
    net.advance(61_000);
    // and more while room appeared only after a pass (deletes of what an entry accepted at that
    // pass absorbs): the retry is the next pass's (spec/sync.md §9, "later"). Each such pass
    // lets in an entry that fits (or another takes its room), so at most one per entry.
    if single {
        let l = net.label(nodes[0]);
        let pending = |net: &mut Net| {
            let ids: BTreeSet<osis_base::BlobId> = net.server_ids(s1, &l).into_iter().collect();
            let store = net.servers[s1].hub.store();
            let entries: Vec<(osis_base::BlobId, usize)> = nodes.iter().filter_map(|n| net.nodes[*n].sync.as_ref()).flat_map(|x| x.ephemeral_plain_entries(&l)).collect();
            (entries.len(), entries.iter().any(|(b, size)| !ids.contains(b) && store.ephemeral_fits(&l, *size as u64)))
        };
        let (n, _) = pending(&mut net);
        for _ in 0..n {
            if !pending(&mut net).1 {
                break;
            }
            log.push("periodic pass".into());
            net.advance(61_000);
        }
    }
    let holders: Vec<usize> = nodes.iter().copied().filter(|n| syncs(&mut net, *n, w)).collect();
    let Some(&h0) = holders.first() else {
        // lost only when no node holds it (spec/requirements.md Ephemeral data): every node that
        // held it restarted since (a server holding it would have handed it back)
        assert!(kept.is_empty(), "seed {seed}: nobody holds the window, though nodes {kept:?} held it and never restarted since\n{}", log.join("\n"));
        return;
    };
    let l = net.label(h0);
    // spec/sync.md §5 (defined outcome past a cap): an entry some holder has that the only server
    // lacks and could not fit
    let refused = single && {
        let ids: BTreeSet<osis_base::BlobId> = net.server_ids(s1, &l).into_iter().collect();
        let store = net.servers[s1].hub.store();
        let mut out = false;
        for n in &holders {
            for (b, size) in net.nodes[*n].sync.as_ref().unwrap().ephemeral_plain_entries(&l) {
                out |= !ids.contains(&b) && !store.ephemeral_fits(&l, size as u64);
            }
        }
        out
    };
    // and the refusal is genuine: the server keeps no plain entry that no node holds (one every
    // holder dropped as absorbed, whose deletion never came, would fill it and excuse divergence)
    if refused {
        let store = net.servers[s1].hub.store();
        let plain: Vec<osis_base::BlobId> = net.server_ids(s1, &l).into_iter().filter(|b| osis_proto::LabelStore::blob(store, b).ok().flatten().and_then(|x| osis_label::Prefix::parse(&x).ok()).is_some_and(|p| p.class() == osis_label::Class::Ephemeral)).collect();
        let held: BTreeSet<osis_base::BlobId> = nodes.iter().flat_map(|n| net.nodes[*n].sync.as_ref().unwrap().ephemeral_plain_entries(&l).into_iter().map(|x| x.0)).collect();
        let stale: Vec<_> = plain.iter().filter(|b| !held.contains(b)).collect();
        if !stale.is_empty() {
            panic!("seed {seed}: the full server keeps entries {stale:?} no node holds (cap {cap})\n{}\n{}", log.join("\n"), lane_dump(&mut net, &nodes, &servers, &l, w));
        }
    }
    // past a refusal, holders of the same plain commits still read alike (a node's state is its
    // own commits and the valid ones it received)
    let held = |net: &mut Net, n: usize| -> BTreeSet<osis_base::CommitId> {
        let e = net.engine(n);
        e.held_ephemeral().into_iter().map(|x| x.0).filter(|c| !e.ephemeral_is_presence(c)).collect()
    };
    let mut reads: Vec<(usize, BTreeMap<String, String>, BTreeSet<osis_base::CommitId>)> = Vec::new();
    for n in &holders {
        reads.push((*n, notes(&mut net, *n, w), held(&mut net, *n)));
    }
    for (n, got, h) in &reads[1..] {
        let Some((m, want, _)) = reads.iter().find(|(_, _, h2)| !refused || h2 == h) else { continue };
        if got != want {
            panic!("seed {seed}: node {n} differs from node {m} (cap {cap})\n{}\n{}", log.join("\n"), lane_dump(&mut net, &nodes, &servers, &l, w));
        }
    }
    // spec/sync.md §9 (own compaction): each writer's own held commits within twice their cover
    // and one in flight
    for n in &nodes {
        for (actor, held, cover, largest) in net.engine(*n).own_ephemeral_load() {
            assert!(held <= osis_node::ephemeral::COVER_FACTOR * cover + largest, "seed {seed}: node {n} holds {held} B of own commits for {actor:?}, cover {cover} B\n{}", log.join("\n"));
        }
    }
    // presence: every holder reads exactly the live cursors (their authors are all connected;
    // presence has its own room at a server, apart from the capped ephemeral state); with an
    // entry refused, at most those (a writer the window's placement did not reach sends nothing)
    let want: BTreeMap<String, String> = cursors.iter().filter(|(n, _)| holders.contains(n)).map(|(n, v)| (n.to_string(), v.clone())).collect();
    for n in &holders {
        let got = str_map(net.eph_read(*n, w, CURSOR));
        if got != want && !(refused && got.iter().all(|(k, v)| want.get(k) == Some(v))) {
            panic!("seed {seed}: node {n}'s cursors {got:?}, expected {want:?} (cap {cap})\n{}\n{}", log.join("\n"), lane_dump(&mut net, &nodes, &servers, &l, w));
        }
    }
    // and no server keeps a covered presence entry: at most one per live cursor
    for sv in &servers {
        let store = net.servers[*sv].hub.store();
        let ids = osis_proto::LabelStore::live_ids(store, &l).unwrap_or_default();
        let presence = ids.iter().filter(|b| osis_proto::LabelStore::blob(store, b).ok().flatten().and_then(|x| osis_label::Prefix::parse(&x).ok()).is_some_and(|p| p.class() == osis_label::Class::Presence)).count();
        if presence > cursors.len() {
            let pids: Vec<_> = ids.iter().filter(|b| osis_proto::LabelStore::blob(store, b).ok().flatten().and_then(|x| osis_label::Prefix::parse(&x).ok()).is_some_and(|p| p.class() == osis_label::Class::Presence)).collect();
            let dump = lane_dump(&mut net, &nodes, &servers, &l, w);
            panic!("seed {seed}: server {sv} holds {presence} presence entries {pids:?} for cursors {cursors:?}\n{}\n{dump}", log.join("\n"));
        }
    }
}

/// Whether node `n` holds ephemeral thing `w` in a labeled closure (it syncs it: a record that
/// came without its placement, which a full server kept out, leaves the node writing it locally).
fn syncs(net: &mut Net, n: usize, w: Tid) -> bool {
    let e = net.engine(n);
    e.ephemeral_thing(&w).is_some() && e.ephemeral_synced(&w)
}

/// Failure detail: each node's reads and lane, each server's entries.
fn lane_dump(net: &mut Net, nodes: &[usize], servers: &[usize], l: &osis_base::LabelId, w: Tid) -> String {
    let mut out = String::new();
    for m in nodes {
        let (n, c) = (notes(net, *m, w), str_map(net.eph_read(*m, w, CURSOR)));
        out.push_str(&format!("node {m} {:?} reads {n:?} cursors {c:?}\n{}", net.tid(*m), net.nodes[*m].sync.as_ref().unwrap().ephemeral_dump(l)));
        for d in net.nodes[*m].sync.as_ref().unwrap().describe() {
            out.push_str(&format!("  {d}\n"));
        }
        let e = net.engine(*m);
        for (id, bytes, own) in e.held_ephemeral() {
            let h = e.ephemeral_header(&id).unwrap();
            out.push_str(&format!("  held {id:?} by {:?} {:?} own {own} {bytes} B\n", h.author, h.ephemeral));
        }
    }
    for sv in servers {
        out.push_str(&format!("server {sv} holds {:?}, {} B\n", net.server_ids(*sv, l), net.servers[*sv].hub.store().ephemeral_bytes(l)));
    }
    out
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

// the same with one capped server (caps 0 to fitting all; 173658: room appears only after the
// last periodic pass)
#[test]
fn random_window_one_capped_server_spec_sync_9() {
    for seed in [0, 2, 4, 6, 8, 10, 63, 105, 162, 173658] {
        random_window_run_on(seed, true, false);
    }
}

/// A tier-2 random-window run: OSIS_EPH_SEEDS (default 200) from OSIS_EPH_START (default 0), a
/// thread per core (OSIS_EPH_THREADS); every failing seed is reported with its replay command.
fn eph_large(name: &str, single: bool, inflight: bool) {
    let s = osis_base::testenv::Seeds::from_env("OSIS_EPH_START", "OSIS_EPH_SEEDS", 0..200);
    let seeds: Vec<u64> = s.range.clone().collect();
    let replay = |seed: u64| format!("OSIS_EPH_START={seed} OSIS_EPH_SEEDS=1 cargo test --workspace --test it {name} -- --ignored --exact");
    crate::common::run_seeds_noted(name, &seeds, s.overridden, "OSIS_EPH_THREADS", replay, |seed| random_window_run_on(seed, single, inflight));
}

// the same with one capped server: holders converge through what it holds, or an entry stays out
// of it that genuinely does not fit
#[test]
#[ignore]
fn random_window_one_capped_server_large() {
    eph_large("ephemeral::random_window_one_capped_server_large", true, false);
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
    eph_large("ephemeral::random_window_converges_large", false, false);
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
    eph_large("ephemeral::random_window_inflight_large", false, true);
}

// the harness: a node restarted while its server's Hello is still on the way gets nothing of
// the old connection on the new one of the same number (`random_window_inflight_large` seed
// 3300065: the stale Hello's challenge made every Open there refused, so the restarted node never
// reopened the label at that server)
#[test]
fn restart_mid_handshake_reopens() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    net.restart(a, 50);
    net.feed(a, Event::Local);
    assert!(net.conn_to(a, sv).is_some(), "dialed, the Hello queued");
    net.restart(a, 51);
    net.run();
    let d = net.sync(a).describe();
    assert!(!d.is_empty() && d.iter().all(|x| x.contains(": Open")), "{d:?}");
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
    let entries = net.sync(b).ephemeral_entries(&l);
    let at_s2 = net.servers[s2].hub.store().ephemeral_bytes(&l);
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

// spec/sync.md §9 (security review L2): a replay of an entry its author's held valid cover
// absorbs is not held again, and a writer deletes it where it was found
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
    let acts = net.sync(a).compact_ephemeral_now().unwrap();
    net.actions(a, acts);
    net.run();
    assert!(!net.engine(b).holds_ephemeral(&old.id), "covered by its author");
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
    let sv = net.add_server_with(osis_server::Policy { ephemeral_bytes: 12_000, ..osis_server::Policy::default() });
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

// spec/sync.md §5 (a refusal triggers nothing but the periodic retry): an own entry the server
// refuses for good (one write over the cap) is not re-uploaded at every other node's write (it
// was, by the compaction a refusal triggered: 5.5x the bytes)
#[test]
fn server_cap_stuck_entry_no_churn_spec_sync_9() {
    let fits = bytes_under_stuck_entry(100);
    let stuck = bytes_under_stuck_entry(13_000);
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


// spec/sync.md §9 (own covers), spec/crdt.md §8: ephemeral deltas are not paged, so an author's
// own state of one aspect far past the page target is still covered: holders converge and every
// copy (the author's held commits, a holder's lane, the server) stays within about twice it
#[test]
fn cover_past_page_target_bounded_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let l = net.label(a);
    let v = "v".repeat(1000);
    let mut peak = (0, 0, 0);
    for i in 0..400 {
        note(&mut net, a, w, &format!("k{i:03}"), &v);
        net.run();
        let load = net.engine(a).own_ephemeral_load();
        let [(_, held, cover, largest)] = load[..] else { panic!("one actor: {load:?}") };
        assert!(held <= osis_node::ephemeral::COVER_FACTOR * cover + largest, "write {i}: {held} B of own commits, cover {cover} B");
        let (at_b, at_sv) = (net.sync(b).ephemeral_bytes(&l) as usize, net.servers[sv].hub.store().ephemeral_bytes(&l) as usize);
        assert!(at_b <= 3 * cover && at_sv <= 4 * cover, "write {i}: holder {at_b} B, server {at_sv} B, cover {cover} B");
        peak = (cover, at_b, at_sv);
    }
    assert!(peak.0 > 6 * osis_base::format::PAGE_TARGET, "state far past the page target: {peak:?}");
    assert_eq!(notes(&mut net, a, w).len(), 400);
    assert_eq!(notes(&mut net, b, w), notes(&mut net, a, w));
    // a restarted holder gets it all back from the server
    let want = notes(&mut net, a, w);
    net.restart(b, 22);
    net.run();
    assert_eq!(notes(&mut net, b, w), want);
}

// spec/sync.md §3, §9, spec/crdt.md §8: an ephemeral commit past a blob (two aspects of one label,
// each delta unpaged and most of a blob) goes as several blobs under the label; a holder joins
// them all, a cover of it is several blobs too, deletes what it absorbs, and a restarted holder
// gets it all back from the server
#[test]
fn commit_past_a_blob_splits_spec_sync_9() {
    let mut net = Net::new();
    let cap: u64 = 64 << 20;
    let sv = net.add_server_with(osis_server::Policy { ephemeral_bytes: cap, ..osis_server::Policy::default() });
    let a = net.node(1, &[sv]);
    let b = net.add_node(2, SyncConfig { servers: vec![net.address(sv)], ephemeral_bytes: cap, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let (w1, w2) = (window(&mut net, a, g, "1"), window(&mut net, a, g, "2"));
    net.run();
    let l = net.label(a);
    let before = net.sync(b).ephemeral_entries(&l);
    let big = "v".repeat(5 << 20);
    let mut m = Mutation::new();
    for w in [w1, w2] {
        m.op(w, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s("big"))], op: Op::Set(s(&big)) }).unwrap();
    }
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    assert_eq!(net.sync(b).ephemeral_entries(&l), before + 2, "one commit, two blobs");
    for w in [w1, w2] {
        assert_eq!(notes(&mut net, b, w).get("big").map(String::len), Some(big.len()));
    }
    note(&mut net, a, w1, "small", "x");
    net.run();
    let acts = net.sync(a).compact_ephemeral_now().unwrap();
    net.actions(a, acts);
    net.run();
    let at_sv = net.servers[sv].hub.store().ephemeral_bytes(&l) as usize;
    assert!(at_sv < 2 * big.len() + (1 << 20), "absorbed entries deleted: server {at_sv} B");
    let want: Vec<_> = [w1, w2].into_iter().map(|w| notes(&mut net, a, w)).collect();
    net.restart(b, 22);
    net.run();
    let got: Vec<_> = [w1, w2].into_iter().map(|w| notes(&mut net, b, w)).collect();
    // the second blob may come first: its parts wait for the record the first one carries
    assert!(got == want, "restarted holder reads the author's state");
}

// spec/crdt.md §4.7, spec/sync.md §9 (a commit's records serve its other parts): an
// ephemeral commit whose expiring parts went is dropped with its `/created` parts, at its author
// and at holders, and the record of a thing nothing else uses goes with it; a copy received
// again after its expiry is not held. Expiring things do not pile up in memory.
#[test]
fn expired_commit_leaves_no_records_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let held = |net: &mut Net, n: usize| net.engine(n).held_ephemeral().len();
    let mut base = (held(&mut net, a), held(&mut net, b));
    for round in 0..3 {
        let mut made = Vec::new();
        let mut blobs = Vec::new();
        for i in 0..4 {
            let e = net.engine(a);
            let mut m = Mutation::new();
            let w = e.new_thing(&mut m, g);
            let until = osis_base::WallMs(net.now() + 5_000);
            m.op(g, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(Value::Tid(w)) }).unwrap();
            m.expires(g, &ct::GROUP, until).unwrap();
            m.set(w, &eph(STATE), &s(&format!("{round}.{i}"))).unwrap();
            m.expires(w, &eph(STATE), until).unwrap();
            net.engine(a).write(m).unwrap();
            blobs.extend(net.engine(a).take_ephemeral().unwrap().into_iter().map(|c| c.blob));
            made.push(w);
        }
        // taken by hand: b gets them directly
        for bl in &blobs {
            net.engine(b).ingest_ephemeral(bl.clone()).unwrap();
        }
        for (i, w) in made.iter().enumerate() {
            assert_eq!(net.eph_read(b, *w, STATE), Some(s(&format!("{round}.{i}"))));
            assert!(net.engine(b).ephemeral_thing(w).is_some());
        }
        assert!(held(&mut net, b) > base.1);
        net.advance(6_000);
        net.run();
        assert_eq!((held(&mut net, a), held(&mut net, b)), base, "round {round}: nothing held but what was before");
        for w in &made {
            assert_eq!(net.eph_read(b, *w, STATE), None);
            assert!(net.engine(b).ephemeral_thing(w).is_none(), "the holder's record went with the commit");
            assert!(net.engine(a).ephemeral_thing(w).is_some(), "the author's own thing stays");
        }
        for bl in &blobs {
            assert_eq!(net.engine(b).ingest_ephemeral(bl.clone()).unwrap(), osis_node::ephemeral::EphIngest::Dropped { absorbed: false });
            assert_eq!(net.engine(a).ingest_ephemeral(bl.clone()).unwrap(), osis_node::ephemeral::EphIngest::Dropped { absorbed: false });
        }
        assert_eq!((held(&mut net, a), held(&mut net, b)), base, "a copy after expiry is not held");
        assert!(made.iter().all(|w| net.engine(b).ephemeral_thing(w).is_none()));
        // a later write of a thing whose record went at b carries the record again (placed
        // again: its placement expired, so it was in no labeled closure)
        let mut m = Mutation::new();
        m.op(g, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(Value::Tid(made[0])) }).unwrap();
        m.set(made[0], &eph(STATE), &s("late")).unwrap();
        net.engine(a).write(m).unwrap();
        for c in net.engine(a).take_ephemeral().unwrap() {
            net.engine(b).ingest_ephemeral(c.blob).unwrap();
        }
        assert_eq!(net.eph_read(b, made[0], STATE), Some(s("late")), "round {round}");
        assert!(net.engine(b).ephemeral_thing(&made[0]).is_some());
        net.advance(6_000);
        net.run();
        assert_eq!(net.eph_read(b, made[0], STATE), Some(s("late")), "an unexpiring write stays");
        assert!(net.engine(b).ephemeral_thing(&made[0]).is_some());
        base = (held(&mut net, a), held(&mut net, b));
    }
}

/// Node `n` sets ephemeral aspects `/x/a<i>` of `g` to `v` for each `i` of `keys`, in one batch.
fn set_many(net: &mut Net, n: usize, g: Tid, keys: impl Iterator<Item = usize>, v: &str) {
    let mut m = Mutation::new();
    for i in keys {
        m.set(g, &eph(&format!("/x/a{i:04}")), &s(v)).unwrap();
    }
    net.engine(n).write(m).unwrap();
    local(net, n);
}

fn read_many(net: &mut Net, n: usize, g: Tid, count: usize) -> Vec<Option<Value>> {
    (0..count).map(|i| net.eph_read(n, g, &format!("/x/a{i:04}"))).collect()
}

// spec/sync.md §9 (own covers), spec/commits.md §2 (no list by link): an author's commits and
// covers over more aspects than inline header lists hold go as several commits, each covering
// the own commits on its aspects; the author's held commits, a holder's lane and the server stay
// within a few covers, holders converge, and a restarted holder gets it all back
#[test]
fn own_cover_split_by_aspect_spec_sync_9() {
    const N: usize = 2000;
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let l = net.label(a);
    for round in 0..8 {
        // every aspect, or a slice of them
        let keys: Vec<usize> = if round % 2 == 0 { (0..N).collect() } else { (round * 100..round * 100 + 300).collect() };
        set_many(&mut net, a, g, keys.into_iter(), &format!("r{round}"));
        net.run();
        let load = net.engine(a).own_ephemeral_load();
        let [(_, held, cover, largest)] = load[..] else { panic!("one actor: {load:?}") };
        assert!(held <= osis_node::ephemeral::COVER_FACTOR * cover + largest, "round {round}: {held} B of own commits, cover {cover} B");
        let (at_b, at_sv) = (net.sync(b).ephemeral_bytes(&l) as usize, net.servers[sv].hub.store().ephemeral_bytes(&l) as usize);
        assert!(at_b <= 3 * cover && at_sv <= 4 * cover, "round {round}: holder {at_b} B, server {at_sv} B, cover {cover} B");
        assert_eq!(read_many(&mut net, b, g, N), read_many(&mut net, a, g, N), "round {round}");
    }
    assert_eq!(net.eph_read(b, g, "/x/a0000"), Some(s("r6")));
    // a cover of it all goes as several commits, which together absorb every other own one
    let acts = net.sync(a).compact_ephemeral_now().unwrap();
    net.actions(a, acts);
    net.run();
    let own: Vec<usize> = net.engine(a).held_ephemeral().into_iter().filter(|x| x.2).map(|x| net.engine(a).ephemeral_header(&x.0).unwrap().aspects.len()).collect();
    assert!(own.len() > 1 && own.iter().all(|n| *n < N) && own.iter().sum::<usize>() >= N, "a split cover: {own:?}");
    assert_eq!(net.sync(b).ephemeral_entries(&l), own.len(), "the holder dropped what the covers absorb");
    let want = read_many(&mut net, a, g, N);
    assert_eq!(read_many(&mut net, b, g, N), want);
    net.restart(b, 22);
    net.run();
    assert_eq!(read_many(&mut net, b, g, N), want);
}

// spec/sync.md §9 (an aspect's own delta past a blob): a batch whose delta of one aspect does
// not fit a blob is not sent; its writes stay unsent, the aspect's other writes are refused
// while its own state does not fit unless they shrink it, and a write that makes it fit is taken
// and sends it all
#[test]
fn aspect_past_a_blob_refuses_writes_spec_sync_9() {
    let mut net = Net::new();
    let cap: u64 = 64 << 20;
    let sv = net.add_server_with(osis_server::Policy { ephemeral_bytes: cap, ..osis_server::Policy::default() });
    let a = net.node(1, &[sv]);
    let b = net.add_node(2, SyncConfig { servers: vec![net.address(sv)], ephemeral_bytes: cap, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let big = "v".repeat(5 << 20);
    let mut m = Mutation::new();
    for k in ["x", "y", "u"] {
        m.op(w, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s(k))], op: Op::Set(s(&big)) }).unwrap();
    }
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    assert!(notes(&mut net, b, w).is_empty(), "past a blob: not sent");
    // the window's other aspect still syncs
    let mut m = Mutation::new();
    m.set(w, &eph(STATE), &s("next")).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    assert_eq!(net.eph_read(b, w, STATE), Some(s("next")));
    // a write that leaves the state past a blob is refused
    let mut m = Mutation::new();
    m.op(w, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s("z"))], op: Op::Set(s("small")) }).unwrap();
    let err = net.engine(a).write(m).unwrap_err().to_string();
    assert!(err.contains("does not fit a blob"), "{err}");
    // one that shrinks it is taken, though it still does not fit: nothing goes yet
    let mut m = Mutation::new();
    m.op(w, &eph(NOTES), PathOp { path: Vec::new(), op: Op::Remove(s("u")) }).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    assert!(notes(&mut net, b, w).is_empty(), "still past a blob: not sent");
    // one that makes it fit goes, with what waited
    let mut m = Mutation::new();
    m.op(w, &eph(NOTES), PathOp { path: Vec::new(), op: Op::Remove(s("x")) }).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    assert_eq!(notes(&mut net, b, w).get("y").map(String::len), Some(big.len()));
    assert_eq!(notes(&mut net, b, w), notes(&mut net, a, w));
    note(&mut net, a, w, "z", "small");
    net.run();
    assert_eq!(notes(&mut net, b, w), notes(&mut net, a, w));
}

// spec/sync.md §9 (deletes wait for the covers in the label's closure): a commit under two labels
// whose cover splits into pieces each under one label is deleted under each label once the piece
// on that label's things is held there, never before, and without waiting for the other piece
#[test]
fn split_cover_pieces_under_different_labels_spec_sync_9() {
    const N: usize = 1500;
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g1 = net.group(a, &[(b, Role::Write)], &[sv]);
    let g2 = net.group_seeded(a, &[(b, Role::Write)], vec![net.address(sv)], 12);
    net.run();
    let labels: BTreeMap<Tid, osis_base::LabelId> = net.sync(a).labels().into_iter().map(|(g, gl)| (g, gl.id)).collect();
    for g in [g1, g2] {
        set_many(&mut net, a, g, 0..N, "old");
        net.run();
    }
    // one commit on both groups' things: an entry under each label
    let mut m = Mutation::new();
    for g in [g1, g2] {
        m.set(g, &eph("/x/a0000"), &s("both")).unwrap();
    }
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    let tids = |net: &mut Net, c: &osis_base::CommitId| -> BTreeSet<Tid> { net.engine(a).ephemeral_header(c).unwrap().aspects.iter().map(|x| x.tid).collect() };
    let own: Vec<osis_base::CommitId> = net.engine(a).held_ephemeral().into_iter().filter(|x| x.2).map(|x| x.0).collect();
    let both: Vec<_> = own.iter().filter(|c| net.engine(a).ephemeral_header(c).unwrap().aspects.len() == 2).copied().collect();
    let [c] = both[..] else { panic!("one commit on both: {both:?}") };
    assert_eq!(tids(&mut net, &c), BTreeSet::from([g1, g2]));
    let entries: BTreeMap<osis_base::LabelId, osis_base::BlobId> = net.sync(a).ephemeral_entries_of(&c).into_iter().map(|(l, b, _)| (l, b)).collect();
    assert_eq!(entries.len(), 2, "under both labels");
    for (l, b) in &entries {
        assert!(net.server_ids(sv, l).contains(b));
    }
    // the server's answers held back: nothing tells the author its pieces are held there
    net.held_servers.insert(sv);
    let acts = net.sync(a).compact_ephemeral_now().unwrap();
    net.actions(a, acts);
    // the pieces that absorb `c`, each on one group's things only
    let pieces: Vec<osis_base::CommitId> = net.engine(a).held_ephemeral().into_iter().filter(|x| x.2).map(|x| x.0).collect();
    assert!(!pieces.contains(&c), "covered");
    let mut on: BTreeMap<Tid, osis_base::CommitId> = BTreeMap::new();
    for p in &pieces {
        let ts = tids(&mut net, p);
        assert_eq!(ts.len(), 1, "a piece on one group's things");
        let h = net.engine(a).ephemeral_header(p).unwrap();
        if h.aspects.iter().any(|x| x.ak.as_str() == "/x/a0000") {
            on.insert(*ts.iter().next().unwrap(), *p);
        }
    }
    assert_eq!(on.len(), 2, "two pieces absorb it: {on:?}");
    let piece_blobs = |net: &mut Net, p: &osis_base::CommitId, l: &osis_base::LabelId| -> Vec<osis_base::BlobId> { net.sync(a).ephemeral_entries_of(p).into_iter().filter(|x| x.0 == *l).map(|x| x.1).collect() };
    // an entry goes only with (or after) its piece under that label: the piece's upload names it
    // as replaced, so the server removes it as it admits the piece, answered or not
    let check = |net: &mut Net| {
        for g in [g1, g2] {
            let l = labels[&g];
            let ids = net.server_ids(sv, &l);
            if !ids.contains(&entries[&l]) {
                let pb = piece_blobs(net, &on[&g], &l);
                assert!(!pb.is_empty() && pb.iter().all(|b| ids.contains(b)), "deleted under {g:?} before its piece was held there");
            }
        }
    };
    for _ in 0..20 {
        net.feed(a, Event::Local);
        net.round();
        check(&mut net);
    }
    net.release();
    for _ in 0..2000 {
        net.round();
        check(&mut net);
    }
    net.run();
    for g in [g1, g2] {
        let l = labels[&g];
        assert!(!net.server_ids(sv, &l).contains(&entries[&l]), "deleted under {g:?}");
        assert_eq!(read_many(&mut net, b, g, N), read_many(&mut net, a, g, N));
    }
}


// spec/sync.md §5 (a new sync key ends an open), §6 (a first Sync lists the held ephemeral
// entries as gained): a Sync refused 8 because a read rotation landed between its Open and it
// listed nothing to the server, so the Sync after the reopen on the same connection lists them
// again (it counted the refused list as held there and never uploaded b's offline note).
// End to end (c reads the note) waits on issues/eph-own-entry-not-head.md.
#[test]
fn gained_announced_again_after_refused_sync_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let x = net.node(4, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write), (x, Role::Read)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    net.set_online(b, false);
    net.run();
    note(&mut net, b, w, "b", "1");
    net.hold_opened.insert(b);
    net.set_online(b, true);
    net.advance(10_000);
    let conn = net.conn_to(b, sv);
    assert!(net.gained.get(&b).is_none_or(|v| v.is_empty()), "the first Sync waits behind the held Opened");
    let (at, bt, ct, xt) = (net.tid(a), net.tid(b), net.tid(c), net.tid(x));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write), (ct, Role::Write)]);
    remove_member(e, g, xt, &rs, 9);
    net.run();
    net.release();
    net.run();
    assert_eq!(net.conn_to(b, sv), conn, "same connection");
    let sent = &net.gained[&b];
    assert_eq!(sent.len(), 2, "listed again after the refused Sync: {sent:?}");
    assert_eq!(sent[0], sent[1]);
}
