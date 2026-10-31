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

/// Node `n` makes an ephemeral window owned by `g`, placed in `g` (its `/placed`), with `/win/state` = `v`.
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
    m.op(w, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s(k))], op: Op::Put(s(v)) }).unwrap();
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

/// The encoded bytes of the ephemeral entries node `n` holds from others under `l`.
fn encoded_held(net: &mut Net, n: usize, l: &osis_base::LabelId) -> usize {
    net.sync(n).ephemeral_held_from_others(l).iter().map(|h| h.0).sum()
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

// spec/sync.md §9 (a thing entering a labeled closure goes out whole): an own expiring write
// made while its thing was in no labeled closure (after a restart, before its placement came
// back: `ephemeral::random_churn_converges_large` seed 203) goes with it, under its expiry
#[test]
fn expiring_write_before_entering_closure_goes_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let e = net.engine(a);
    let mut m = Mutation::new();
    let w = e.new_thing(&mut m, g);
    m.set(w, &eph(STATE), &s("local")).unwrap();
    e.write(m).unwrap();
    let mut m = Mutation::new();
    m.op(w, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s("k"))], op: Op::Put(s("v")) }).unwrap();
    m.expires(w, &eph(NOTES), osis_base::WallMs(net.now() + 60_000)).unwrap();
    net.engine(a).write(m).unwrap();
    assert!(!net.engine(a).ephemeral_synced(&w), "written in no labeled closure");
    let mut m = Mutation::new();
    m.op(g, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(Value::Tid(w)) }).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    assert_eq!(net.eph_read(b, w, STATE), Some(s("local")));
    assert_eq!(notes(&mut net, b, w), BTreeMap::from([("k".to_string(), "v".to_string())]));
    net.advance(61_000);
    assert_eq!(notes(&mut net, b, w), BTreeMap::new(), "expired there too");
    assert_eq!(notes(&mut net, a, w), BTreeMap::new());
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
    let l = net.label(a);
    let theirs: Vec<_> = net.engine(a).held_ephemeral().into_iter().filter(|h| !h.2).map(|h| h.0).collect();
    assert!(!theirs.is_empty() && net.sync(a).ephemeral_bytes(&l) > 0, "b's commits held and counted");
    let bt = net.tid(b);
    let me = net.tid(a);
    let e = net.engine(a);
    let rs = recipients_of(e, &[(me, Role::Admin)]);
    remove_member(e, g, bt, &rs, 9);
    net.run();
    assert_eq!(notes(&mut net, a, w), map(&[("a", "1")]), "b's ephemeral write is un-merged");
    // issues/eph-node-cost-bounds.md: invalid now, they are let go at once (kept and counted
    // until restart, and listed as gained at every first Sync)
    net.advance(60_000);
    for c in &theirs {
        assert!(!net.engine(a).holds_ephemeral(c), "not held");
        assert!(net.sync(a).ephemeral_entries_of(c).is_empty(), "not kept in the lane");
    }
    assert_eq!(net.sync(a).ephemeral_bytes(&l), 0, "not counted");
    assert_eq!(notes(&mut net, a, w), map(&[("a", "1")]));
}

// notes/ephemeral.md Bounds (server ephemeral bytes per label): past the cap uploads are refused;
// the writer compacts, deletes what the compaction covers and the label syncs again
#[test]
fn server_cap_compaction_frees_it_spec_sync_5() {
    let mut net = Net::new();
    // a few entries with their per-entry overhead (about 900 bytes each); tuned so one upload is
    // refused and the writer's own compaction later makes room (a refused write left alone with
    // no compaction due stays refused: issues/eph-unify.md step 5, Replace at cap)
    let sv = net.add_server_with(osis_server::Policy { ephemeral_bytes: 6_300, ..osis_server::Policy::default() });
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
    assert!(net.servers[sv].hub.store().ephemeral_bytes(&l) <= 6_300);
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

// spec/sync.md §9 (caps), notes/ephemeral.md Node cap: the node cap counts what a held commit
// takes in memory, not its encoded bytes, and a commit is checked against the room left before it
// is decoded (`Engine::ephemeral_bound`): one of many tiny entries (about 200 times its size
// decoded) is refused whole and reported, never held past the cap; a small one is held, counted
// at its decoded size
#[test]
fn node_cap_bounds_decoded_size_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let cap = 236_000;
    let b = net.add_node(2, SyncConfig { servers: vec![net.address(sv)], ephemeral_bytes: cap, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "doc");
    net.run();
    let l = net.label(a);
    let rx = net.listen(b);
    let tiny = |net: &mut Net, from: usize, n: usize| {
        let mut m = Mutation::new();
        for k in from..from + n {
            m.op(t, &eph(NOTES), PathOp { path: vec![PathSeg::Key(Value::Int(k as i64))], op: Op::Set(Value::Int(1)) }).unwrap();
        }
        net.engine(a).write(m).unwrap();
        local(net, a);
        net.run();
    };
    tiny(&mut net, 0, 500);
    let at_server = net.servers[sv].hub.store().ephemeral_bytes(&l);
    assert!(at_server < 40_000, "{at_server} B at the server: fits the cap encoded");
    assert_eq!(net.sync(b).ephemeral_bytes(&l), 0, "refused before decoding");
    assert_eq!(net.eph_read(b, t, NOTES), None);
    assert!(rx.try_iter().any(|e| matches!(e, osis_node::Event::Diagnostic(d) if d.kind == osis_node::DiagnosticKind::EphemeralRefused)), "reported");
    assert!(net.diagnostics(b).iter().any(|d| d.starts_with("EphemeralRefused")), "the harness lists it");
    tiny(&mut net, 500, 3);
    let held = net.sync(b).ephemeral_bytes(&l);
    assert!(held > 3 * 2048 && held <= cap, "{held} counted here");
    match net.eph_read(b, t, NOTES) {
        Some(Value::Map(m)) => assert_eq!(m.len(), 3, "the small one held"),
        v => panic!("{v:?}"),
    }
}

// notes/ephemeral.md Bounds (node ephemeral bytes per label held from others): a writer flooding
// a label with ephemeral commits fills at most the cap at another node; the rest is refused
// (`EphemeralRefused`)
#[test]
fn ephemeral_flood_bounded_spec_requirements_scale() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.add_node(2, SyncConfig { servers: vec![net.address(sv)], ephemeral_bytes: 400_000, ..SyncConfig::default() });
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
    // each admitted only when its bound fit the room left: never past the cap
    let held = net.sync(b).ephemeral_held_from_others(&l);
    let charged: u64 = held.iter().map(|h| h.1).sum();
    assert_eq!(charged, net.sync(b).ephemeral_bytes(&l));
    assert!(charged <= 400_000, "{held:?}");
    let n = notes(&mut net, b, w).len();
    assert!(n > 0 && n < 40, "{n}");
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

// spec/sync.md §5 (a signal is delivered once): a relay-only commit whose parts go as several
// blobs (projections for different readers) delivers every blob's signals, each once
#[test]
fn signal_commit_in_several_blobs_all_delivered_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t1 = net.item(a, g, g, "x");
    let t2 = net.item(a, g, g, "y");
    net.run();
    let mut m = Mutation::new();
    m.set(t1, &ukey("/t/ring", Lifetime::Signal), &s("one")).unwrap();
    m.set(t2, &ukey("/t/ring", Lifetime::Signal), &s("two")).unwrap();
    net.engine(a).write(m).unwrap();
    let cs = net.engine(a).take_ephemeral().unwrap();
    let blob = cs.iter().find(|c| c.class == osis_commit::EphClass::Relay).unwrap().blob.clone();
    assert_eq!(blob.parts.len(), 2);
    let rb = net.listen(b);
    let mut fires = Vec::new();
    for p in &blob.parts {
        let one = osis_commit::CommitBlob { header: blob.header.clone(), signature: blob.signature, parts: vec![p.clone()] };
        net.engine(b).ingest_ephemeral(one.clone()).unwrap();
        assert_eq!(net.engine(b).ingest_ephemeral(one).unwrap(), osis_node::ephemeral::EphIngest::Dropped, "a copy");
        fires.extend(fired(&rb).into_iter().map(|(t, _, v, _)| (t, v)));
    }
    fires.sort();
    let mut want = vec![(t1, s("one")), (t2, s("two"))];
    want.sort();
    assert_eq!(fires, want);
    assert_eq!(net.engine(b).ingest_ephemeral(blob).unwrap(), osis_node::ephemeral::EphIngest::Dropped, "the whole commit again");
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

// spec/crdt.md §4.7 (expiry), spec/sync.md §9 (notes/ephemeral.md Values that live while their
// author is there): a cursor (a map entry under the author's key, expiring 30 s after each write)
// its author rewrites every 15 s stays up at B without a gap, the server holding at most a few
// of its entries; once the author goes away the refreshes stop and the cursor is gone at B and
// at the server by the last write's expiry, with nobody noticing the departure
#[test]
fn refreshed_value_lives_while_author_present_spec_crdt_4_7() {
    const E: u64 = 30_000;
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let l = net.label(a);
    let me = s(&net.tid(a).to_string());
    // what `osis::KeepAlive` writes: a fresh entry at the key (an entry an expiring write created
    // goes at its expiry with every later write into it)
    let refresh = |net: &mut Net, v: &str| {
        let mut m = Mutation::new();
        m.op(w, &eph(CURSOR), PathOp { path: vec![PathSeg::Key(me.clone())], op: Op::Put(s(v)) }).unwrap();
        m.expires(w, &eph(CURSOR), osis_base::WallMs(net.now() + E)).unwrap();
        net.engine(a).write(m).unwrap();
        local(net, a);
    };
    let entries = |net: &Net| osis_proto::LabelStore::live_ids(net.servers[sv].hub.store(), &l).unwrap().len();
    let base = entries(&net);
    refresh(&mut net, "c1");
    net.run();
    let want = Some(Value::Map([(me.clone(), s("c1"))].into()));
    assert_eq!(net.eph_read(a, w, CURSOR), want, "at a");
    assert_eq!(net.eph_read(b, w, CURSOR), want);
    for _ in 0..6 {
        // the last write's expiry passes now but for the refresh at half of it
        net.advance(E / 2);
        assert_eq!(net.eph_read(b, w, CURSOR), want, "no gap between refreshes");
        refresh(&mut net, "c1");
        net.run();
        assert_eq!(net.eph_read(b, w, CURSOR), want);
        assert!(entries(&net) <= base + 3, "the server holds the writes of one expiry window: {}", entries(&net) - base);
    }
    // the author's device goes away: no departure is seen, the last write expires
    net.set_online(a, false);
    net.advance(E - 1);
    assert_eq!(net.eph_read(b, w, CURSOR), want, "until the last write's expiry");
    net.advance(1);
    assert_eq!(net.eph_read(b, w, CURSOR), None);
    assert_eq!(entries(&net), base, "the server dropped every one of its entries");
}

// spec/crdt.md §5.1 (a nested register carries no reset): a `Replace` at a map key of an
// ephemeral aspect reads at a holder too (its delta once carried a reset there and was refused)
#[test]
fn eph_replace_at_map_key_read_at_holder_spec_crdt_5_1() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let mut m = Mutation::new();
    m.op(w, &eph(CURSOR), PathOp { path: vec![PathSeg::Key(s("k"))], op: Op::Replace(s("v")) }).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    let want = Some(Value::Map([(s("k"), s("v"))].into()));
    assert_eq!(net.eph_read(a, w, CURSOR), want);
    assert_eq!(net.eph_read(b, w, CURSOR), want);
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

// spec/commits.md §4, spec/sync.md §9 (only verified commits are held): a copy of a waiting
// commit with the real header but a junk delta or signature, arriving before the real one (its
// author's and thing's records not here yet), does not evict the real copy: once the records are
// here the real part is held
#[test]
fn junk_copy_of_waiting_commit_evicts_nothing_spec_sync_9() {
    for junk_sig in [false, true] {
        let mut net = Net::new();
        let sv = net.add_server();
        let a = net.node(1, &[sv]);
        let b = net.node(2, &[]);
        let c = net.node(3, &[sv]);
        let g = net.group(a, &[(c, Role::Write)], &[sv]);
        let t = net.item(c, g, g, "durable");
        net.run();
        let mut m = Mutation::new();
        m.set(t, &eph("/doc/cursor"), &Value::Int(7)).unwrap();
        net.engine(c).write(m).unwrap();
        let cs = net.engine(c).take_ephemeral().unwrap();
        let blob = cs[0].blob.clone();
        let mut junk = blob.clone();
        junk.parts[0].delta.push(0);
        if junk_sig {
            junk.signature = osis_crypto::Signature([0; 64]);
        }
        let ct = net.engine(c).tid();
        assert!(net.engine(b).core.created(&ct).is_none() && net.engine(b).core.created(&t).is_none(), "author and thing unknown");
        assert_eq!(net.engine(b).ingest_ephemeral(junk).unwrap(), osis_node::ephemeral::EphIngest::Pending);
        assert_eq!(net.engine(b).ingest_ephemeral(blob.clone()).unwrap(), osis_node::ephemeral::EphIngest::Pending);
        // the records arrive (out of band here)
        net.pair(a, b);
        net.engine(b).rejudge_ephemeral().unwrap();
        assert_eq!(net.read(b, t), Some(s("durable")));
        assert_eq!(net.eph_read(b, t, "/doc/cursor"), Some(Value::Int(7)), "junk_sig {junk_sig}");
    }
}

// spec/commits.md §4, spec/sync.md §9 (only verified commits are held and spread): a junk copy of
// a commit by an author whose record is not here yet, pushed before the real one, is not kept in
// the lane once the real copy makes the commit held (both wait apart; promotion kept every blob of
// a held commit unchecked)
#[test]
fn junk_copy_of_waiting_commit_not_kept_once_held_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let x = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "durable");
    net.run();
    // b hears nothing from the server: x joins unseen by it
    net.deaf.insert(b);
    net.pair(x, a);
    let (at, bt, xt) = (net.tid(a), net.tid(b), net.tid(x));
    let e = net.engine(a);
    set_edge(e, g, xt, Role::Write);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write), (xt, Role::Write)]);
    rotation(e, g, &rs, 7, false);
    local(&mut net, a);
    net.run();
    net.pair(a, x);
    assert!(net.engine(b).core.created(&xt).is_none() && net.read(x, t) == Some(s("durable")));
    let ak = osis_base::Ak::new("/doc/cursor").unwrap();
    let blob = net.engine(x).forge_ephemeral(t, &ak, Value::Int(7)).unwrap().unwrap().blob;
    let mut junk = blob.clone();
    let last = junk.parts[0].delta.len() - 1;
    junk.parts[0].delta[last] ^= 1;
    // sealed under the label keys b holds
    let wk = write_key(&mut net, b, g);
    let l = net.label(b);
    let (_, jev) = sealed(&mut net, b, g, &junk, Some(&wk), 1);
    let (real, ev) = sealed(&mut net, b, g, &blob, Some(&wk), 2);
    let acts = push(&mut net, b, sv, l, vec![jev, ev]);
    net.actions(b, acts);
    assert!(net.sync(b).ephemeral_pending_bytes(&l) > 0, "both wait apart");
    // the records arrive (out of band here)
    net.deaf.remove(&b);
    net.pair(x, b);
    net.pair(a, b);
    net.engine(b).rejudge_ephemeral().unwrap();
    net.advance(10_000);
    assert_eq!(net.eph_read(b, t, "/doc/cursor"), Some(Value::Int(7)));
    let kept: Vec<_> = net.sync(b).ephemeral_entries_of(&blob.id()).into_iter().map(|(_, x, _)| x).collect();
    assert_eq!(kept, vec![real], "only the real copy is kept");
    assert_eq!(net.sync(b).ephemeral_pending_bytes(&l), 0);
}

/// A commit by `a` on a durable thing `b` has not heard of (b deaf to the server): (thing, real
/// blob, a junk copy with the real header and signature).
fn waiting_on_thing(net: &mut Net, a: usize, b: usize, g: Tid, v: &Value) -> (Tid, osis_commit::CommitBlob, osis_commit::CommitBlob) {
    net.deaf.insert(b);
    let t = net.item(a, g, g, "durable");
    net.run();
    let at = net.tid(a);
    assert!(net.engine(b).core.created(&t).is_none() && net.engine(b).core.created(&at).is_some(), "author known, thing not");
    let mut m = Mutation::new();
    m.set(t, &eph("/doc/cursor"), v).unwrap();
    net.engine(a).write(m).unwrap();
    let blob = net.engine(a).take_ephemeral().unwrap().remove(0).blob;
    let mut junk = blob.clone();
    let last = junk.parts[0].delta.len() - 1;
    junk.parts[0].delta[last] ^= 1;
    (t, blob, junk)
}

// spec/commits.md §4, spec/sync.md §9 (only verified commits are held and spread): with the
// author's record here but the part's thing's missing, a junk copy pushed first is not held, kept
// or spread (it held the commit with no part verified and kept the blob unchecked); once the
// record is here only the real copy is kept
#[test]
fn junk_copy_waiting_on_thing_not_kept_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let (t, blob, junk) = waiting_on_thing(&mut net, a, b, g, &Value::Int(7));
    let wk = write_key(&mut net, b, g);
    let l = net.label(b);
    let (_, jev) = sealed(&mut net, b, g, &junk, Some(&wk), 1);
    let acts = push(&mut net, b, sv, l, vec![jev]);
    net.actions(b, acts);
    assert!(!net.engine(b).holds_ephemeral(&blob.id()), "nothing of it verified: not held");
    assert!(net.sync(b).ephemeral_entries_of(&blob.id()).is_empty(), "not kept");
    let (real, ev) = sealed(&mut net, b, g, &blob, Some(&wk), 2);
    let acts = push(&mut net, b, sv, l, vec![ev]);
    net.actions(b, acts);
    assert!(net.sync(b).ephemeral_entries_of(&blob.id()).is_empty(), "both wait apart");
    // the record arrives (out of band here)
    net.deaf.remove(&b);
    net.pair(a, b);
    net.engine(b).rejudge_ephemeral().unwrap();
    net.advance(10_000);
    assert_eq!(net.read(b, t), Some(s("durable")));
    assert_eq!(net.eph_read(b, t, "/doc/cursor"), Some(Value::Int(7)));
    let kept: Vec<_> = net.sync(b).ephemeral_entries_of(&blob.id()).into_iter().map(|(_, x, _)| x).collect();
    assert_eq!(kept, vec![real], "only the real copy is kept");
    assert_eq!(net.sync(b).ephemeral_pending_bytes(&l), 0);
}

// notes/ephemeral.md Node cap: a blob kept apart (its part's thing's record missing, so not
// decoded) is decoded at its retry only within the room it was given: past it, it is reported and
// not held
#[test]
fn waiting_blob_retried_within_its_room_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let v = Value::Map((0..500).map(|i| (Value::Int(i), Value::Int(1))).collect());
    let (t, blob, _) = waiting_on_thing(&mut net, a, b, g, &v);
    let r = net.engine(b).ingest_ephemeral_within(blob.clone(), true, 50_000).unwrap();
    assert!(matches!(r, osis_node::ephemeral::EphIngest::Pending), "{r:?}");
    let rx = net.listen(b);
    net.deaf.remove(&b);
    net.pair(a, b);
    net.engine(b).rejudge_ephemeral().unwrap();
    net.advance(10_000);
    assert_eq!(net.read(b, t), Some(s("durable")));
    assert!(!net.engine(b).holds_ephemeral(&blob.id()) && !net.engine(b).pending_ephemeral(&blob.id()), "not held");
    assert!(rx.try_iter().any(|e| matches!(e, osis_node::Event::Diagnostic(d) if d.kind == osis_node::DiagnosticKind::EphemeralRefused)), "reported");
}

// spec/sync.md §9 (unverified commits wait apart, bounded): a blob with one part verified and
// one waiting for its thing's record is held nowhere past the share for waiting blobs (its
// verified part was held, counted by no cap); within it, it counts what the engine holds of it
#[test]
fn partly_verified_blob_counted_or_not_held_spec_sync_9() {
    // 2400: the blob fits the cap but not its share (a quarter)
    for cap in [2400, SyncConfig::default().ephemeral_bytes] {
        let mut net = Net::new();
        let sv = net.add_server();
        let a = net.node(1, &[sv]);
        let b = net.add_node(2, SyncConfig { servers: vec![net.address(sv)], ephemeral_bytes: cap, ..SyncConfig::default() });
        let g = net.group(a, &[(b, Role::Write)], &[sv]);
        net.run();
        net.deaf.insert(b);
        let t = net.item(a, g, g, "durable");
        net.run();
        let mut m = Mutation::new();
        m.set(g, &eph("/doc/cursor"), &Value::Int(1)).unwrap();
        m.set(t, &eph("/doc/cursor"), &Value::Int(7)).unwrap();
        net.engine(a).write(m).unwrap();
        let blob = net.engine(a).take_ephemeral().unwrap().remove(0).blob;
        assert_eq!(blob.parts.len(), 2);
        let wk = write_key(&mut net, b, g);
        let l = net.label(b);
        let (_, ev) = sealed(&mut net, b, g, &blob, Some(&wk), 1);
        let osis_proto::Event::Added { blob: Some(bytes), .. } = &ev else { unreachable!() };
        let len = bytes.len();
        assert!(len <= 2400 && 4 * len > 2400, "blob of {len} bytes");
        let acts = push(&mut net, b, sv, l, vec![ev]);
        net.actions(b, acts);
        assert!(net.sync(b).ephemeral_entries_of(&blob.id()).is_empty(), "not kept");
        let pending = net.sync(b).ephemeral_pending_bytes(&l);
        if cap == 2400 {
            assert!(!net.engine(b).holds_ephemeral(&blob.id()), "nothing of it held");
            assert_eq!(pending, 0);
            assert_eq!(net.eph_read(b, g, "/doc/cursor"), None);
        } else {
            assert!(net.engine(b).holds_ephemeral(&blob.id()), "its verified part held");
            assert_eq!(net.eph_read(b, g, "/doc/cursor"), Some(Value::Int(1)));
            assert!(pending >= net.engine(b).ephemeral_charge(&blob.id(), &[]) && pending > 2048, "{pending}");
        }
    }
}

// spec/sync.md §9 (unverified commits wait apart, bounded): a copy past the share for waiting
// blobs is refused without touching what waits: the honest copy that came first is held once its
// thing's record is here (the overflow forgot the whole waiting commit)
#[test]
fn waiting_share_overflow_keeps_honest_copy_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    // the share (a quarter of the cap) fits one blob of the commit by its bound, not two; the
    // cap fits the blob decoded (`osis_crdt::decoded_bound`: a string, about 6 times its bytes)
    let cap = 1_000_000;
    let b = net.add_node(2, SyncConfig { servers: vec![net.address(sv)], ephemeral_bytes: cap, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let v = s(&"c".repeat(30_000));
    let (t, blob, junk) = waiting_on_thing(&mut net, a, b, g, &v);
    let wk = write_key(&mut net, b, g);
    let l = net.label(b);
    let (real, ev) = sealed(&mut net, b, g, &blob, Some(&wk), 2);
    let (_, jev) = sealed(&mut net, b, g, &junk, Some(&wk), 1);
    let osis_proto::Event::Added { blob: Some(bytes), .. } = &ev else { unreachable!() };
    let bound = osis_node::Engine::ephemeral_bound(&blob).0.max(bytes.len() as u64);
    assert!(bound <= cap / 4 && 2 * bound > cap / 4, "blob of bound {bound}");
    let acts = push(&mut net, b, sv, l, vec![ev, jev]);
    net.actions(b, acts);
    assert_eq!(net.sync(b).ephemeral_pending_bytes(&l), bound, "the junk copy past the share is not kept");
    // the record arrives (out of band here)
    net.deaf.remove(&b);
    net.pair(a, b);
    net.engine(b).rejudge_ephemeral().unwrap();
    net.advance(10_000);
    assert_eq!(net.read(b, t), Some(s("durable")));
    assert_eq!(net.eph_read(b, t, "/doc/cursor"), Some(v), "the honest copy waited on");
    let kept: Vec<_> = net.sync(b).ephemeral_entries_of(&blob.id()).into_iter().map(|(_, x, _)| x).collect();
    assert_eq!(kept, vec![real]);
}

/// Node `b` (cap `cap`) deaf to the server while writer `x` joins `g`, so `x`'s record is not
/// there: (server, a, b, x, g, a durable thing of `g` all know).
fn unknown_writer(net: &mut Net, cap: u64) -> (usize, usize, usize, usize, Tid, Tid) {
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.add_node(2, SyncConfig { servers: vec![net.address(sv)], ephemeral_bytes: cap, ..SyncConfig::default() });
    let x = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "durable");
    net.run();
    net.deaf.insert(b);
    net.pair(x, a);
    let (at, bt, xt) = (net.tid(a), net.tid(b), net.tid(x));
    let e = net.engine(a);
    set_edge(e, g, xt, Role::Write);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write), (xt, Role::Write)]);
    rotation(e, g, &rs, 7, false);
    local(net, a);
    net.run();
    net.pair(a, x);
    assert!(net.engine(b).core.created(&xt).is_none() && net.read(x, t) == Some(s("durable")));
    (sv, a, b, x, g, t)
}

// spec/sync.md §9 (caps), notes/ephemeral.md Node cap: a writer queues a blob while the label is
// empty (its record held back), fills the label, then lets the record through: the commit the
// engine then holds is counted by the node, even past the cap (it was held uncounted: the
// promotion was refused at the cap check)
#[test]
fn promoted_waiting_blob_counted_spec_sync_9() {
    let mut net = Net::new();
    let cap = 1_200_000;
    let (sv, a, b, x, g, t) = unknown_writer(&mut net, cap);
    let ak = osis_base::Ak::new("/doc/cursor").unwrap();
    let blob = net.engine(x).forge_ephemeral(t, &ak, s(&"c".repeat(40_000))).unwrap().unwrap().blob;
    assert!(osis_node::Engine::ephemeral_bound(&blob).0 <= cap / 4, "waits within the share");
    let wk = write_key(&mut net, b, g);
    let l = net.label(b);
    let (_, ev) = sealed(&mut net, b, g, &blob, Some(&wk), 1);
    let osis_proto::Event::Added { blob: Some(bytes), .. } = &ev else { unreachable!() };
    let size = bytes.len() as u64;
    let acts = push(&mut net, b, sv, l, vec![ev]);
    net.actions(b, acts);
    assert!(net.sync(b).ephemeral_pending_bytes(&l) > 0, "waits apart");
    // the label fills with small commits of a's until one is refused
    for i in 0..1000 {
        let ak = osis_base::Ak::new(format!("/doc/f{i}")).unwrap();
        let c = net.engine(a).forge_ephemeral(t, &ak, s("ffff")).unwrap().unwrap().blob;
        let before = net.sync(b).ephemeral_bytes(&l);
        let (_, ev) = sealed(&mut net, b, g, &c, Some(&wk), 10 + i);
        let acts = push(&mut net, b, sv, l, vec![ev]);
        net.actions(b, acts);
        if net.sync(b).ephemeral_bytes(&l) == before {
            break;
        }
    }
    let used = net.sync(b).ephemeral_bytes(&l);
    assert!(used <= cap && cap - used < size, "{used} of {cap}: no room for {size} bytes");
    // the records arrive (out of band here)
    net.deaf.remove(&b);
    net.pair(x, b);
    net.pair(a, b);
    net.engine(b).rejudge_ephemeral().unwrap();
    net.advance(10_000);
    assert_eq!(net.eph_read(b, t, "/doc/cursor"), Some(s(&"c".repeat(40_000))), "held");
    assert!(!net.sync(b).ephemeral_entries_of(&blob.id()).is_empty(), "counted");
    let held: Vec<_> = net.engine(b).held_ephemeral().into_iter().filter(|h| !h.2).map(|h| h.0).collect();
    let charged: u64 = held.iter().map(|c| net.engine(b).ephemeral_charge(c, &[])).sum();
    assert!(net.sync(b).ephemeral_bytes(&l) >= charged, "every held commit counted");
    assert!(net.sync(b).ephemeral_bytes(&l) <= cap + cap / 4, "past the cap by the share at most");
}

// spec/sync.md §9 (unverified commits wait apart, bounded), notes/ephemeral.md Node cap: a blob
// waiting for its author's record counts against the share by what it could cost decoded, not
// its bytes: one of tiny map entries small in bytes but past the share decoded is not kept apart
// (the share in bytes let a quarter of the cap in such blobs decode at the record)
#[test]
fn waiting_blob_charged_by_bound_spec_sync_9() {
    let mut net = Net::new();
    let cap = 600_000;
    let (sv, _, b, x, g, t) = unknown_writer(&mut net, cap);
    let ak = osis_base::Ak::new("/doc/cursor").unwrap();
    let v = Value::Map((0..25).map(|i| (Value::Int(i), Value::Int(1))).collect());
    let blob = net.engine(x).forge_ephemeral(t, &ak, v).unwrap().unwrap().blob;
    let (bound, part) = osis_node::Engine::ephemeral_bound(&blob);
    assert!(bound > cap / 4 && part <= cap, "past the share decoded ({bound}), not the cap");
    let wk = write_key(&mut net, b, g);
    let l = net.label(b);
    let (_, ev) = sealed(&mut net, b, g, &blob, Some(&wk), 1);
    let osis_proto::Event::Added { blob: Some(bytes), .. } = &ev else { unreachable!() };
    assert!((bytes.len() as u64) < cap / 4, "fits the share in bytes");
    let acts = push(&mut net, b, sv, l, vec![ev]);
    net.actions(b, acts);
    assert_eq!(net.sync(b).ephemeral_pending_bytes(&l), 0, "not kept apart");
    assert!(!net.engine(b).pending_ephemeral(&blob.id()));
}

// notes/ephemeral.md Node cap: a blob that could never fit the label's cap (its bound past the
// whole cap) is remembered: a drop under the cap reconciles the label without fetching it again
#[test]
fn never_fitting_blob_not_fetched_again_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let x = net.node(2, &[sv]);
    let cap = 330_000;
    let b = net.add_node(3, SyncConfig { servers: vec![net.address(sv)], ephemeral_bytes: cap, ..SyncConfig::default() });
    let g = net.group(a, &[(x, Role::Write), (b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "doc");
    net.run();
    let l = net.label(a);
    net.eph_write_expiring(x, t, &eph("/doc/cursor"), s(&"c".repeat(50_000)), Some(5_000));
    net.run();
    assert!(net.eph_read(b, t, "/doc/cursor").is_some());
    let v = Value::Map((0..2000).map(|i| (Value::Int(i), Value::Int(1))).collect());
    net.eph_write(a, t, &ukey("/doc/tiny", Lifetime::Ephemeral), v);
    net.run();
    assert_eq!(net.eph_read(b, t, "/doc/tiny"), None, "refused for the cap");
    net.fetched.insert(b, Vec::new());
    net.advance(5_000);
    assert_eq!(net.eph_read(b, t, "/doc/cursor"), None);
    assert!(net.sync(b).ephemeral_bytes(&l) < 1_000);
    net.advance(SyncConfig::default().resync_ms + 1_000);
    assert_eq!(net.fetched[&b], Vec::new(), "not fetched again");
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

// spec/sync.md §4 (blob ID = BLAKE3 of the bytes), spec/requirements.md ("Nothing trusts a
// server's word"): a server pushing a held ephemeral blob again under other IDs (the wrap's
// nonce is only the ID's first 24 bytes, so it still opens) adds no entry and charges nothing
#[test]
fn ephemeral_blob_under_wrong_id_dropped_spec_sync_4() {
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
    let wk = write_key(&mut net, a, g);
    let (id, ev) = sealed(&mut net, a, g, &cs[0].blob, Some(&wk), 9);
    let l = net.label(a);
    push(&mut net, b, sv, l, vec![ev.clone()]);
    assert_eq!(net.eph_read(b, t, "/doc/cursor"), Some(Value::Int(7)));
    let held = (net.sync(b).ephemeral_bytes(&l), net.sync(b).ephemeral_held_entries(&l));
    assert_eq!(held.1.iter().map(|e| e.0).collect::<Vec<_>>(), vec![id]);
    for n in 0..4u8 {
        let osis_proto::Event::Added { blob, wrap, stamp, .. } = ev.clone() else { unreachable!() };
        let mut forged = id;
        forged.0[31] ^= 1 + n;
        let stamp = stamp.map(|_| osis_label::sign_stamp(&wk, &l, &forged, &wrap));
        push(&mut net, b, sv, l, vec![osis_proto::Event::Added { blob_id: forged, blob, wrap, stamp }]);
    }
    assert_eq!((net.sync(b).ephemeral_bytes(&l), net.sync(b).ephemeral_held_entries(&l)), held);
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

// spec/crdt.md §2.1: a write's session names its node, so a node's own writes are its sessions'
// (the dots of `node`'s writes on `(t, ak)` here)
fn session_dots(net: &mut Net, n: usize, t: Tid, ak: &str) -> Vec<(osis_crdt::Session, u64)> {
    let ak = osis_base::Ak::new(ak).unwrap();
    let f = net.engine(n).ephemeral_state(&t, &ak).cloned().unwrap_or_default();
    let mut out: Vec<(osis_crdt::Session, u64)> = f.writes().into_iter().filter_map(|(d, _)| d.src.as_session().map(|s| (s, d.ctr))).collect();
    out.sort();
    out.dedup();
    out
}

// spec/crdt.md §2.1: a restart starts a new session of the same node; counters run per aspect
// from 1, contiguous, in each session
#[test]
fn restart_starts_a_new_session_spec_crdt_2_1() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    net.run();
    let first = net.engine(a).ephemeral_session();
    assert_eq!(first.node, net.tid(a));
    let w = window(&mut net, a, g, "w");
    note(&mut net, a, w, "k1", "v");
    note(&mut net, a, w, "k2", "v");
    net.run();
    // the window's state and its notes count apart, from 1
    assert_eq!(session_dots(&mut net, a, w, STATE), vec![(first, 1)]);
    assert_eq!(session_dots(&mut net, a, w, NOTES), vec![(first, 1), (first, 2)]);
    net.restart(a, 11);
    net.run();
    let second = net.engine(a).ephemeral_session();
    assert_eq!(second.node, first.node, "the same node");
    assert_ne!(second.nonce, first.nonce, "a new session");
    assert_eq!(notes(&mut net, a, w), map(&[("k1", "v"), ("k2", "v")]), "the earlier session's writes back from the server");
    note(&mut net, a, w, "k3", "v");
    net.run();
    assert_eq!(session_dots(&mut net, a, w, NOTES), vec![(first, 1), (first, 2), (second, 1)]);
}

// spec/crdt.md §2.1: two sessions of one node never collide: the same counter of one aspect in
// each makes two elements, everywhere
#[test]
fn sessions_of_one_node_never_collide_spec_crdt_2_1() {
    const ITEMS: &str = "/win/items";
    // a list of `v` (on an empty state: its element takes the aspect's first counter)
    let list = |net: &mut Net, n: usize, w: Tid, v: &str| {
        let mut m = Mutation::new();
        m.set(w, &eph(ITEMS), &Value::List(vec![s(v)])).unwrap();
        net.engine(n).write(m).unwrap();
        local(net, n);
    };
    let items = |net: &mut Net, n: usize, w: Tid| match net.eph_read(n, w, ITEMS) {
        Some(Value::List(l)) => l.into_iter().collect::<BTreeSet<Value>>(),
        x => panic!("node {n}: {x:?}"),
    };
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    // an ephemeral aspect of the (durable) group: writable at once after a restart
    let w = g;
    list(&mut net, a, w, "x");
    net.run();
    net.restart(a, 12);
    // written before the earlier session's state is back: counter 1 again, another element
    list(&mut net, a, w, "y");
    net.run();
    let want = BTreeSet::from([s("x"), s("y")]);
    for n in [a, b] {
        assert_eq!(items(&mut net, n, w), want, "node {n}");
        let ctrs: Vec<u64> = session_dots(&mut net, n, w, ITEMS).into_iter().map(|(_, c)| c).collect();
        assert_eq!(ctrs, vec![1, 1], "node {n}: two sessions, one counter each");
    }
    net.restart(b, 13);
    net.run();
    assert_eq!(items(&mut net, b, w), want, "a restarted holder, from the server");
}

// spec/crdt.md §2.1 (counters never reused within a session): a thing freed here while others
// hold its writes, received again and written, takes the session's next counters, not 1 again
#[test]
fn freed_thing_received_again_keeps_counters_spec_crdt_2_1() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    note(&mut net, a, w, "k1", "v1");
    net.run();
    assert_eq!(notes(&mut net, b, w), map(&[("k1", "v1")]));
    // a unplaces and frees it; b still holds its writes and places it again
    let mut m = Mutation::new();
    m.op(g, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(Value::Tid(w)) }).unwrap();
    m.free(w);
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    assert!(net.engine(a).ephemeral_thing(&w).is_none(), "freed at a");
    let mut m = Mutation::new();
    m.op(g, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(Value::Tid(w)) }).unwrap();
    net.engine(b).write(m).unwrap();
    local(&mut net, b);
    net.run();
    assert!(net.engine(a).ephemeral_thing(&w).is_some(), "received again at a");
    note(&mut net, a, w, "k2", "v2");
    net.run();
    let s1 = net.engine(a).ephemeral_session();
    assert_eq!(session_dots(&mut net, a, w, NOTES), vec![(s1, 2)], "the next counter");
    assert_eq!(notes(&mut net, b, w), map(&[("k1", "v1"), ("k2", "v2")]));
    assert_eq!(session_dots(&mut net, b, w, NOTES), vec![(s1, 1), (s1, 2)], "two writes, two dots");
}

// spec/sync.md §9 (an ephemeral commit carries only its author's writes): a write under another
// node's source or another node's session is not joined either
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
    let v = Value::Map(BTreeMap::from([(s("y"), s("forged"))]));
    let forged = net.engine(b).forge_ephemeral_as_session(w, &ak, v, at).unwrap().unwrap();
    net.engine(a).ingest_ephemeral(forged.blob).unwrap();
    assert_eq!(notes(&mut net, a, w), map(&[("a", "1")]), "b passed a write off as one of a's sessions'");
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

// spec/sync.md §5 (code 4: the delete rate is used up, replacements counting), §9 (absorbed
// entries leave a server once the cover is held there): a cover refused for the rate goes again
// at the periodic pass, and what it absorbs leaves the server then
#[test]
fn cover_refused_for_rate_retried_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server_with(osis_server::Policy { deletes: 3, ..osis_server::Policy::default() });
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let l = net.label(a);
    let cover = |net: &mut Net, keys: std::ops::Range<u32>| {
        for i in keys {
            note(net, a, w, &format!("k{i}"), "v");
            net.run();
        }
        let acts = net.sync(a).compact_ephemeral_now().unwrap();
        net.actions(a, acts);
        net.run();
    };
    // two absorbed (two deletes of three), then three more: refused 4
    cover(&mut net, 0..2);
    let one = net.servers[sv].hub.store().ephemeral_bytes(&l);
    cover(&mut net, 2..4);
    let refused = net.servers[sv].hub.store().ephemeral_bytes(&l);
    assert!(refused > one, "the second cover is not there: its absorbed entries stay");
    net.advance(130_000);
    let after = net.servers[sv].hub.store().ephemeral_bytes(&l);
    assert!(after < refused, "the cover went again and replaced what it absorbs: {after} {refused}");
    assert_eq!(net.sync(a).ephemeral_held_entries(&l).len(), 1);
    net.restart(a, 31);
    net.advance(10_000);
    assert_eq!(notes(&mut net, a, w).len(), 4);
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
    // in-flight steps from a stream of their own as well
    let mut z = seed.wrapping_mul(0x94d0_49bb_1331_11eb) | 1;
    let mut irnd = move || {
        z ^= z << 13;
        z ^= z >> 7;
        z ^= z << 17;
        z.is_multiple_of(2)
    };
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
            let entries: Vec<(osis_base::BlobId, usize)> = nodes.iter().filter_map(|n| net.nodes[*n].sync.as_ref()).flat_map(|x| x.ephemeral_held_entries(&l)).collect();
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
            for (b, size) in net.nodes[*n].sync.as_ref().unwrap().ephemeral_held_entries(&l) {
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
        let held: BTreeSet<osis_base::BlobId> = nodes.iter().flat_map(|n| net.nodes[*n].sync.as_ref().unwrap().ephemeral_held_entries(&l).into_iter().map(|x| x.0)).collect();
        let stale: Vec<_> = plain.iter().filter(|b| !held.contains(b)).collect();
        if !stale.is_empty() {
            panic!("seed {seed}: the full server keeps entries {stale:?} no node holds (cap {cap})\n{}\n{}", log.join("\n"), lane_dump(&mut net, &nodes, &servers, &l, w));
        }
    }
    // past a refusal, holders of the same plain commits still read alike (a node's state is its
    // own commits and the valid ones it received)
    let held = |net: &mut Net, n: usize| -> BTreeSet<osis_base::CommitId> {
        let e = net.engine(n);
        e.held_ephemeral().into_iter().map(|x| x.0).collect()
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
        let n = notes(net, *m, w);
        out.push_str(&format!("node {m} {:?} reads {n:?}\n{}", net.tid(*m), net.nodes[*m].sync.as_ref().unwrap().ephemeral_dump(l)));
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
// writes, partitions and restarts heal (5327166: a restarted author's re-cover stamped below its
// earlier session's cover of the same content; each held one took the other for redundant and
// both were deleted at the servers)
#[test]
fn random_window_converges_spec_sync_6() {
    for seed in [0, 1, 2, 3, 5327166] {
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

const FLAG: &str = "/win/flag";

/// One random run of superseded expiring writes (spec/sync.md §9): four writers on two servers
/// make expiring and plain writes at a few shared and own keys of a map and to a register
/// (several ops per batch, sometimes two aspects), removals and replaces (resets), undos of
/// their own changes, demotions and promotions of writers, with partitions and node and server
/// restarts; once every writer may write again and the network healed, every holder never
/// demoted reads the same. Whether a node drops a superseded commit must depend only on what it holds.
fn random_churn_run(seed: u64) {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut rnd = move |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let mut net = Net::new();
    let servers = vec![net.add_server(), net.add_server()];
    let nodes: Vec<usize> = (0..4).map(|i| net.node(1 + i, &servers)).collect();
    let members: Vec<(usize, Role)> = nodes[1..].iter().map(|n| (*n, Role::Write)).collect();
    let g = net.group(nodes[0], &members, &servers);
    net.run();
    let w = window(&mut net, nodes[0], g, "w");
    net.run();
    let tids: Vec<Tid> = nodes.iter().map(|n| net.tid(*n)).collect();
    let edge = |role| osis_schema::core_types::Edge { role, until: None, invite: None, since: None, tied: None };
    let mut demoted: BTreeSet<usize> = BTreeSet::new();
    // nodes once demoted: a demoted author's view of its own writes differs from the others'
    // (issues/eph-demoted-own-writes.md), so only the others' reads are compared
    let mut ever: BTreeSet<usize> = BTreeSet::new();
    let mut last: BTreeMap<usize, osis_node::ChangeId> = BTreeMap::new();
    let mut restarts = 100;
    let mut log = Vec::new();
    for step in 0..60 {
        let i = rnd(4) as usize;
        let n = nodes[i];
        let has = net.engine(n).ephemeral_thing(&w).is_some();
        // 90 s expires before the end; the others outlive the run
        let exp = [Some(90_000), Some(1_200_000), Some(2_400_000), None][rnd(4) as usize];
        let key = |r: u64| if r == 0 { s(&tids[i].to_string()) } else { s(&format!("k{r}")) };
        let mut m = Mutation::new();
        let what = match rnd(12) {
            _ if !has => "",
            0..=4 => {
                for _ in 0..1 + rnd(2) {
                    // no `Set` into an entry: one into an entry that expired or was superseded
                    // reads only where the entry was never held (issues/eph-set-into-dead-entry.md)
                    let op = Op::Put(s(&format!("v{step}")));
                    let k = key(rnd(3));
                    log.push(format!("  {k:?} {op:?}"));
                    m.op(w, &eph(CURSOR), PathOp { path: vec![PathSeg::Key(k)], op }).unwrap();
                }
                if rnd(4) == 0 {
                    m.set(w, &eph(FLAG), &s(&format!("f{step}"))).unwrap();
                }
                "writes"
            }
            5 => {
                m.set(w, &eph(FLAG), &s(&format!("f{step}"))).unwrap();
                "flags"
            }
            6 => {
                let op = if rnd(4) == 0 { Op::Replace(Value::Map([(key(rnd(3)), s(&format!("r{step}")))].into())) } else { Op::Remove(key(rnd(3))) };
                log.push(format!("  {op:?}"));
                m.op(w, &eph(CURSOR), PathOp { path: vec![], op }).unwrap();
                "resets"
            }
            7 => {
                if let Some(c) = last.remove(&n) {
                    let r = net.engine(n).revert_change(c, tids[i]);
                    log.push(format!("{n} undoes its last: {r:?}"));
                }
                ""
            }
            8 if i > 0 && net.nodes[nodes[0]].online => {
                let done = if demoted.remove(&i) {
                    log.push(format!("{n} promoted"));
                    net.engine(nodes[0]).grant(&g, &tids[i], &edge(Role::Write)).unwrap()
                } else {
                    demoted.insert(i);
                    ever.insert(nodes[i]);
                    log.push(format!("{n} demoted"));
                    let d = osis_node::flows::Demotion { member: tids[i], new: Some(edge(Role::Read)), presync: osis_node::flows::PreSync::Synced };
                    net.engine(nodes[0]).demote(&g, &d).unwrap()
                };
                let acts = net.sync(nodes[0]).carry_out(done).unwrap();
                net.actions(nodes[0], acts);
                ""
            }
            8 | 9 => {
                match rnd(4) {
                    0 => {
                        let on = !net.nodes[n].online;
                        log.push(format!("{n} online {on}"));
                        net.set_online(n, on);
                    }
                    1 => {
                        let sv = servers[rnd(2) as usize];
                        let blocked = !net.blocked.remove(&(n, sv));
                        if blocked {
                            net.blocked.insert((n, sv));
                            if net.conn_to(n, sv).is_some() {
                                let on = net.nodes[n].online;
                                net.set_online(n, false);
                                net.set_online(n, on);
                            }
                        }
                        log.push(format!("{n} blocked from {sv} {blocked}"));
                    }
                    2 => {
                        restarts += 1;
                        log.push(format!("{n} restarts"));
                        last.remove(&n);
                        let on = net.nodes[n].online;
                        net.restart(n, restarts);
                        net.set_online(n, on);
                    }
                    _ => {
                        let sv = servers[rnd(2) as usize];
                        log.push(format!("server {sv} restarts"));
                        net.restart_server(sv);
                    }
                }
                ""
            }
            _ => {
                log.push("advance".into());
                net.advance(500 + rnd(10_000));
                continue;
            }
        };
        if !what.is_empty() {
            if let Some(e) = exp {
                for ak in [CURSOR, FLAG] {
                    let _ = m.expires(w, &eph(ak), osis_base::WallMs(net.now() + e));
                }
            }
            // a demoted writer that knows it is refused
            let r = net.engine(n).write(m);
            log.push(format!("{n} {what} step {step} expiring {exp:?}: {}", if r.is_ok() { "ok" } else { "refused" }));
            if let Ok(Some(wr)) = r {
                last.insert(n, wr.id);
            }
        }
        if rnd(2) == 0 {
            net.feed(n, Event::Local);
            net.round();
        } else {
            net.run();
        }
        net.clock.advance(1 + rnd(40));
    }
    // every writer may write again, the network heals
    for i in std::mem::take(&mut demoted) {
        log.push(format!("{} promoted", nodes[i]));
        let done = net.engine(nodes[0]).grant(&g, &tids[i], &edge(Role::Write)).unwrap();
        let acts = net.sync(nodes[0]).carry_out(done).unwrap();
        net.actions(nodes[0], acts);
    }
    net.blocked.clear();
    net.release();
    for n in &nodes {
        net.set_online(*n, true);
    }
    for _ in 0..4 {
        net.advance(15_000);
    }
    net.advance(61_000);
    let holders: Vec<usize> = nodes.iter().copied().filter(|n| !ever.contains(n) && syncs(&mut net, *n, w)).collect();
    let Some(&h0) = holders.first() else { return };
    let l = net.label(h0);
    let held = |net: &mut Net, n: usize| -> BTreeSet<osis_base::CommitId> { net.engine(n).held_ephemeral().into_iter().map(|x| x.0).collect() };
    let mut reads = Vec::new();
    for n in &holders {
        reads.push((*n, net.eph_read(*n, w, CURSOR), net.eph_read(*n, w, FLAG), held(&mut net, *n)));
    }
    let all: Vec<String> = reads.iter().map(|(n, c, f, h)| format!("node {n}: {c:?} {f:?} holds {}", h.len())).collect();
    let (m, c0, f0, h0) = reads[0].clone();
    for (n, c, f, h) in &reads[1..] {
        if (c, f) != (&c0, &f0) {
            panic!(
                "seed {seed}: node {n} reads {c:?} {f:?}, node {m} {c0:?} {f0:?}\nheld only at {n}: {:?}\nheld only at {m}: {:?}\n{}\n{}\n{}",
                h.difference(&h0).collect::<Vec<_>>(),
                h0.difference(h).collect::<Vec<_>>(),
                all.join("\n"),
                log.join("\n"),
                lane_dump(&mut net, &nodes, &servers, &l, w)
            );
        }
    }
}

// spec/sync.md §9 (superseded expiring writes, randomized): holders read alike after random
// expiring writes, removals, resets, undos, demotions, partitions and restarts
#[test]
fn random_churn_converges_spec_sync_9() {
    for seed in 0..4 {
        random_churn_run(seed);
    }
}

// the same over more seeds (tier 2): OSIS_EPH_SEEDS (default 200) from OSIS_EPH_START
#[test]
#[ignore]
fn random_churn_converges_large() {
    let name = "ephemeral::random_churn_converges_large";
    let s = osis_base::testenv::Seeds::from_env("OSIS_EPH_START", "OSIS_EPH_SEEDS", 0..200);
    let seeds: Vec<u64> = s.range.clone().collect();
    let replay = |seed: u64| format!("OSIS_EPH_START={seed} OSIS_EPH_SEEDS=1 cargo test --workspace --test it {name} -- --ignored --exact");
    crate::common::run_seeds_noted(name, &seeds, s.overridden, "OSIS_EPH_THREADS", replay, random_churn_run);
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
    let cap = 400_000;
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
        let c = net.engine(x).forge_ephemeral(xt, &ak, s(&format!("junk {i} {}", "j".repeat(2_000)))).unwrap().unwrap();
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

// spec/sync.md §9 (a commit contained in held commits of its author is not held),
// notes/ephemeral.md Own covers: a replay of an entry from several covers back (its first cover
// gone everywhere) is neither held, counted nor spread again, reads change nothing, and a
// writer deletes it where it came back
#[test]
fn replay_from_covers_back_not_held_spec_sync_9() {
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
    for k in ["x", "y", "z"] {
        let acts = net.sync(a).compact_ephemeral_now().unwrap();
        net.actions(a, acts);
        net.run();
        note(&mut net, a, w, k, "1");
        net.run();
    }
    let acts = net.sync(a).compact_ephemeral_now().unwrap();
    net.actions(a, acts);
    net.run();
    let at = net.tid(a);
    let by_a = |net: &mut Net| {
        let e = net.engine(b);
        e.held_ephemeral().into_iter().filter(|(c, _, _)| e.ephemeral_header(c).is_some_and(|h| h.author == at)).count()
    };
    assert_eq!(by_a(&mut net), 1, "one cover of a's left");
    let (bytes, before) = (net.sync(b).ephemeral_bytes(&l), notes(&mut net, b, w));
    let acts = push(&mut net, b, sv, l, vec![ev]);
    assert!(!net.engine(b).holds_ephemeral(&old.id), "not held again");
    assert_eq!(net.sync(b).ephemeral_bytes(&l), bytes, "nor counted");
    let conn = net.conn_to(b, sv).unwrap();
    let msgs = sent(&acts, conn);
    let deletes: Vec<osis_base::BlobId> = msgs.iter().flat_map(|m| if let osis_proto::Message::Delete { items, .. } = m { items.iter().map(|i| i.blob).collect() } else { vec![] }).collect();
    assert_eq!(deletes, vec![id], "deleted where it came back");
    assert!(!msgs.iter().any(|m| matches!(m, osis_proto::Message::Upload { .. })), "not spread");
    net.actions(b, acts);
    net.run();
    assert_eq!(by_a(&mut net), 1);
    assert_eq!(notes(&mut net, b, w), before);
    // the author drops it too
    net.engine(a).ingest_ephemeral(old.blob).unwrap();
    assert!(!net.engine(a).holds_ephemeral(&old.id));
}

// spec/sync.md §9 (a cover drops only what it contains), notes/ephemeral.md Own covers: a
// writer's "cover" listing its earlier commit without carrying its writes drops nothing: holders
// keep the commit, and nodes getting the two in either order read alike
#[test]
fn cover_without_its_commits_drops_nothing_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let wr = net.node(2, &[sv]);
    let b = net.node(3, &[sv]);
    let c = net.node(4, &[sv]);
    let g = net.group(a, &[(wr, Role::Write), (b, Role::Write), (c, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let ak = osis_base::Ak::new(NOTES).unwrap();
    let w1 = net.engine(wr).forge_ephemeral(w, &ak, Value::Map(BTreeMap::from([(s("k"), s("a"))]))).unwrap().unwrap();
    let cv = net.engine(wr).forge_cover(w, &ak, Value::Map(BTreeMap::from([(s("j"), s("b"))])), &[w1.id]).unwrap().unwrap();
    assert!(net.engine(wr).holds_ephemeral(&w1.id), "at its writer too");
    net.engine(b).ingest_ephemeral(w1.blob.clone()).unwrap();
    net.engine(b).ingest_ephemeral(cv.blob.clone()).unwrap();
    assert!(net.engine(b).holds_ephemeral(&w1.id), "not contained: kept");
    assert_eq!(net.engine(c).ingest_ephemeral(cv.blob).unwrap(), osis_node::ephemeral::EphIngest::Held { new: true });
    assert_eq!(net.engine(c).ingest_ephemeral(w1.blob).unwrap(), osis_node::ephemeral::EphIngest::Held { new: true }, "not covered by it");
    let want = notes(&mut net, b, w);
    assert!(want.contains_key("k"), "{want:?}");
    assert_eq!(notes(&mut net, c, w), want, "either order");
}

// spec/sync.md §9 (parts are judged; a commit none of whose parts is valid is not held),
// notes/ephemeral.md Own covers: a commit invalid on arrival is neither held nor counted; it is
// held once the durable set makes it valid (a promotion the node had not seen)
#[test]
fn invalid_on_arrival_held_once_valid_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[sv]);
    let d = net.node(3, &[sv]);
    let g = net.group(a, &[(r, Role::Read), (d, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let ak = osis_base::Ak::new(NOTES).unwrap();
    let junk = net.engine(r).forge_ephemeral(w, &ak, Value::Map(BTreeMap::from([(s("r"), s("junk"))]))).unwrap().unwrap();
    assert_eq!(net.engine(d).ingest_ephemeral(junk.blob).unwrap(), osis_node::ephemeral::EphIngest::Pending);
    assert!(!net.engine(d).holds_ephemeral(&junk.id), "a reader's write: not held");
    net.set_online(d, false);
    // the promotion strictly after the junk write (r's clock has seen a's commits, so at one
    // wall time its next stamp can equal a's)
    net.clock.advance(1);
    let (at, rt, dt) = (net.tid(a), net.tid(r), net.tid(d));
    let e = net.engine(a);
    set_edge(e, g, rt, Role::Write);
    let rs = recipients_of(e, &[(at, Role::Admin), (rt, Role::Write), (dt, Role::Write)]);
    rotation(e, g, &rs, 7, false);
    net.run();
    let ok = net.engine(r).forge_ephemeral(w, &ak, Value::Map(BTreeMap::from([(s("r"), s("ok"))]))).unwrap().unwrap();
    assert_eq!(net.engine(d).ingest_ephemeral(ok.blob.clone()).unwrap(), osis_node::ephemeral::EphIngest::Pending, "promotion not seen here yet");
    assert!(!net.engine(d).holds_ephemeral(&ok.id));
    net.set_online(d, true);
    net.run();
    net.advance(60_000);
    assert!(net.engine(d).holds_ephemeral(&ok.id), "valid now: held");
    assert!(!net.engine(d).holds_ephemeral(&junk.id), "still invalid");
}

// notes/ephemeral.md Bounds, notes/ephemeral.md Own covers: entries refused for a node's cap are
// fetched again once its bytes drop (here another's write expires): the label is reconciled at
// the next periodic pass instead of staying short until a restart. The cap fits the cursor and
// the big write decoded (`osis_crdt::decoded_bound`: strings, so mostly their bytes), not both
#[test]
fn capped_label_reconciles_once_room_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let x = net.node(2, &[sv]);
    let b = net.add_node(3, SyncConfig { servers: vec![net.address(sv)], ephemeral_bytes: 330_000, ..SyncConfig::default() });
    let g = net.group(a, &[(x, Role::Write), (b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "doc");
    net.run();
    let l = net.label(a);
    net.eph_write_expiring(x, t, &eph("/doc/cursor"), s(&"c".repeat(50_000)), Some(5_000));
    net.run();
    assert!(net.eph_read(b, t, "/doc/cursor").is_some());
    net.eph_write(a, t, &ukey("/doc/big", Lifetime::Ephemeral), s(&"b".repeat(40_000)));
    net.run();
    assert_eq!(net.eph_read(b, t, "/doc/big"), None, "refused for the cap");
    net.advance(5_000);
    assert_eq!(net.eph_read(b, t, "/doc/cursor"), None);
    assert!(net.sync(b).ephemeral_bytes(&l) < 1_000);
    net.advance(SyncConfig::default().resync_ms + 1_000);
    assert_eq!(net.eph_read(b, t, "/doc/big"), Some(s(&"b".repeat(40_000))), "fetched again");
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

/// `authors` nodes in one group move their cursors every 33 ms (30 a second) for `secs`
/// simulated seconds, each move a fresh entry under the author's own key of one cursor map
/// expiring 30 s out (what `osis::KeepAlive::set` writes), messages taking one 33 ms round per hop
/// (a 66 ms round trip), at a server whose delete rates and ephemeral cap are the defaults scaled
/// to the run (the rates to its share of their minute window, the cap to its share of the
/// expiry, what the entries of a run that short would fill): no upload is refused, every author
/// stays visible at every node throughout, and at the end every node reads every author's latest
/// cursor and the server holds one entry per author. Returns (uploads, deletes, the server's peak
/// ephemeral bytes, its cap).
fn many_authors_run(authors: usize, secs: u64) -> (usize, usize, u64, u64) {
    const E: u64 = 30_000;
    let mut net = Net::new();
    let window_ms = secs * 1000;
    let d = osis_server::Policy::default();
    let (deletes, replacements) = ((d.deletes as u64 * window_ms / 60_000) as u32, (d.replacements as u64 * window_ms / 60_000) as u32);
    let cap = d.ephemeral_bytes * window_ms.min(E) / E;
    let sv = net.add_server_with(osis_server::Policy { window_ms, deletes, replacements, ephemeral_bytes: cap, ..d });
    let ns: Vec<usize> = (0..authors).map(|i| net.node(1 + i as u64, &[sv])).collect();
    let members: Vec<(usize, Role)> = ns[1..].iter().map(|n| (*n, Role::Write)).collect();
    let g = net.group(ns[0], &members, &[sv]);
    let t = net.item(ns[0], g, g, "doc");
    net.run();
    let l = net.label(ns[0]);
    let live = |net: &Net| osis_proto::LabelStore::live_ids(net.servers[sv].hub.store(), &l).unwrap().len();
    let held = live(&net);
    let up_del = |net: &Net| (uploads_sent(net), net.sent_kinds.get(&14).copied().unwrap_or(0));
    let (up, del) = up_del(&net);
    let keys: Vec<Value> = ns.iter().map(|n| s(&net.tid(*n).to_string())).collect();
    let cursor_of = |net: &mut Net, x: usize, k: &Value| match net.eph_read(x, t, CURSOR) {
        Some(Value::Map(m)) => m.get(k).cloned(),
        _ => None,
    };
    let rounds = window_ms / 33;
    let mut peak = 0;
    for r in 0..rounds {
        net.clock.advance(33);
        for (n, k) in ns.iter().zip(&keys) {
            let mut m = Mutation::new();
            m.op(t, &eph(CURSOR), PathOp { path: vec![PathSeg::Key(k.clone())], op: Op::Put(s(&format!("{n}@{r}"))) }).unwrap();
            m.expires(t, &eph(CURSOR), osis_base::WallMs(net.now() + E)).unwrap();
            net.engine(*n).write(m).unwrap();
            local(&mut net, *n);
        }
        net.round();
        peak = peak.max(net.servers[sv].hub.store().ephemeral_bytes(&l));
        if r % 30 == 29 {
            for x in &ns {
                for (n, k) in ns.iter().zip(&keys) {
                    assert!(cursor_of(&mut net, *x, k).is_some(), "round {r}: author {n} not visible at {x}");
                }
            }
        }
    }
    net.run();
    let (up2, del2) = up_del(&net);
    for x in &ns {
        for (n, k) in ns.iter().zip(&keys) {
            assert_eq!(cursor_of(&mut net, *x, k), Some(s(&format!("{n}@{}", rounds - 1))), "author {n} at {x}");
        }
    }
    assert_eq!(live(&net), held + authors, "one entry per author");
    assert!(((del2 - del) as u64) < u64::from(deletes), "{} deletes against a limit of {deletes}", del2 - del);
    // at most one commit per author per round trip (two rounds), and one more at the end
    let most = authors * (rounds as usize / 2 + 2);
    assert!(up2 - up <= most, "{} uploads: more than one per round trip ({most})", up2 - up);
    assert!(peak < cap, "the server's ephemeral bytes reached {peak} of its cap {cap}");
    (up2 - up, del2 - del, peak, cap)
}

// spec/sync.md §9 (an expiring commit superseded by its author's later writes is dropped and its
// author deletes it, coalescing while an upload is in flight), §5 (servers rate-limit deletes and
// cap ephemeral bytes per label): 4 authors at 30 cursor moves a second, scaled to a 1 s window
// (10 authors took 4.5-12 s: tier 2 below)
#[test]
fn many_authors_under_server_rates_spec_sync_9() {
    let (up, del, peak, cap) = many_authors_run(4, 1);
    eprintln!("4 authors, 1 s: {up} uploads, {del} deletes, peak {peak} of {cap} ephemeral bytes");
}

// tier 2: 10 authors for 1 s, then for a whole simulated minute at the default policy
#[test]
#[ignore]
fn many_authors_under_server_rates_large() {
    let (up, del, peak, cap) = many_authors_run(10, 1);
    eprintln!("10 authors, 1 s: {up} uploads, {del} deletes, peak {peak} of {cap} ephemeral bytes");
    let (up, del, peak, cap) = many_authors_run(10, 60);
    eprintln!("10 authors, 60 s: {up} uploads, {del} deletes, peak {peak} of {cap} ephemeral bytes");
}

// spec/sync.md §9 (an unsent write superseded by a later one expiring no earlier is not sent):
// cursor moves made before the next take (an upload in flight), each expiring at its own time,
// go as one commit, the last move's, not one per expiry
#[test]
fn superseded_unsent_moves_one_commit_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let me = s(&net.tid(a).to_string());
    let mut last = 0;
    for i in 0..5 {
        last = net.now() + 30_000;
        let mut m = Mutation::new();
        m.op(w, &eph(CURSOR), PathOp { path: vec![PathSeg::Key(me.clone())], op: Op::Put(s(&format!("c{i}"))) }).unwrap();
        m.expires(w, &eph(CURSOR), osis_base::WallMs(last)).unwrap();
        net.engine(a).write(m).unwrap();
        net.clock.advance(33);
    }
    let cs = net.engine(a).take_ephemeral().unwrap();
    assert_eq!(cs.len(), 1, "one commit for five moves");
    assert_eq!(cs[0].blob.header.aspects.iter().map(|x| x.expires).collect::<Vec<_>>(), vec![Some(last)], "the last move's");
}

// spec/sync.md §9 (a superseded commit's writes are held value-less at every node, its author
// included): once a holder removes the newer entry at the key, the author and the holder both read
// the key gone; the older entry does not show again at the author
#[test]
fn superseded_stays_gone_when_newer_removed_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let me = s(&net.tid(a).to_string());
    let write = |net: &mut Net, n: usize, op: Op| {
        let mut m = Mutation::new();
        m.op(w, &eph(CURSOR), PathOp { path: vec![PathSeg::Key(me.clone())], op }).unwrap();
        m.expires(w, &eph(CURSOR), osis_base::WallMs(net.now() + 30_000)).unwrap();
        net.engine(n).write(m).unwrap();
        local(net, n);
        net.run();
    };
    write(&mut net, a, Op::Put(s("c0")));
    net.advance(33);
    write(&mut net, a, Op::Put(s("c1")));
    // and a move superseded while unsent (never sent) goes from the author's state too
    let mut m = Mutation::new();
    m.op(w, &eph(CURSOR), PathOp { path: vec![PathSeg::Key(me.clone())], op: Op::Put(s("u")) }).unwrap();
    m.expires(w, &eph(CURSOR), osis_base::WallMs(net.now() + 20_000)).unwrap();
    net.engine(a).write(m).unwrap();
    net.clock.advance(33);
    write(&mut net, a, Op::Put(s("c1")));
    let want = Some(Value::Map([(me.clone(), s("c1"))].into()));
    assert_eq!((net.eph_read(a, w, CURSOR), net.eph_read(b, w, CURSOR)), (want.clone(), want));
    // at the same wall time: the removal stamps above what it removes (spec/crdt.md §2.2)
    let mut m = Mutation::new();
    m.op(w, &eph(CURSOR), PathOp { path: vec![], op: Op::Remove(me.clone()) }).unwrap();
    net.engine(b).write(m).unwrap();
    local(&mut net, b);
    net.run();
    let gone = Some(Value::Map(BTreeMap::new()));
    assert_eq!((net.eph_read(a, w, CURSOR), net.eph_read(b, w, CURSOR)), (gone.clone(), gone));
}

// spec/sync.md §9 (a superseding part's writes are all later than the superseded part's and it
// carries no reset): an equal earlier write expiring later supersedes no later one, and a replace
// of the aspect (a reset) supersedes nothing, so each stays held at the author and the holder
#[test]
fn superseding_needs_later_stamps_and_no_reset_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let me = s(&net.tid(a).to_string());
    let held = |net: &mut Net, n: usize| net.engine(n).held_ephemeral().len();
    let (ha, hb) = (held(&mut net, a), held(&mut net, b));
    let write = |net: &mut Net, path: Vec<PathSeg>, op: Op, ms: u64| {
        let mut m = Mutation::new();
        m.op(w, &eph(CURSOR), PathOp { path, op }).unwrap();
        m.expires(w, &eph(CURSOR), osis_base::WallMs(net.now() + ms)).unwrap();
        net.engine(a).write(m).unwrap();
        local(net, a);
        net.run();
        net.advance(33);
    };
    let key = vec![PathSeg::Key(me.clone())];
    write(&mut net, key.clone(), Op::Put(s("x")), 60_000);
    write(&mut net, key, Op::Put(s("x")), 30_000);
    assert_eq!((held(&mut net, a) - ha, held(&mut net, b) - hb), (2, 2), "neither supersedes");
    write(&mut net, Vec::new(), Op::Replace(Value::Map([(me.clone(), s("y"))].into())), 90_000);
    assert_eq!((held(&mut net, a) - ha, held(&mut net, b) - hb), (3, 3), "a replace supersedes nothing");
    let want = Some(Value::Map([(me, s("y"))].into()));
    assert_eq!((net.eph_read(a, w, CURSOR), net.eph_read(b, w, CURSOR)), (want.clone(), want));
}

// spec/sync.md §9 (a superseding part expires): a plain move after an expiring one supersedes
// nothing. Else: b drops the expiring move for the plain one, a's cover absorbs the plain one,
// and c, offline meanwhile, gets only the cover beside the move it held; b's removal of the key
// tombstones the plain entry alone and the expiring move read again at c alone
#[test]
fn superseding_part_expires_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let me = s(&net.tid(a).to_string());
    let put = |net: &mut Net, v: &str, ms: Option<u64>| {
        let mut m = Mutation::new();
        m.op(w, &eph(CURSOR), PathOp { path: vec![PathSeg::Key(me.clone())], op: Op::Put(s(v)) }).unwrap();
        if let Some(ms) = ms {
            m.expires(w, &eph(CURSOR), osis_base::WallMs(net.now() + ms)).unwrap();
        }
        net.engine(a).write(m).unwrap();
        local(net, a);
        net.run();
        net.advance(33);
    };
    // a plain write of a's at another key before, which the cover's part carries
    let mut m = Mutation::new();
    m.op(w, &eph(CURSOR), PathOp { path: vec![PathSeg::Key(s("z"))], op: Op::Put(s("old")) }).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    net.advance(33);
    put(&mut net, "moving", Some(600_000));
    net.set_online(c, false);
    put(&mut net, "plain", None);
    let acts = net.sync(a).compact_ephemeral_now().unwrap();
    net.actions(a, acts);
    net.run();
    net.set_online(c, true);
    net.advance(30_000);
    let mut m = Mutation::new();
    m.op(w, &eph(CURSOR), PathOp { path: vec![], op: Op::Remove(me.clone()) }).unwrap();
    net.engine(b).write(m).unwrap();
    local(&mut net, b);
    net.run();
    let reads: Vec<Option<Value>> = [a, b, c].iter().map(|n| net.eph_read(*n, w, CURSOR)).collect();
    assert!(reads.iter().all(|r| *r == reads[0]), "alike: {reads:?}");
}

// spec/sync.md §9 (only a later write expiring no earlier, none of whose writes is into a record
// it did not create, supersedes): a move expiring sooner than the one before leaves that one
// held, so it reads again once the sooner one expires; a `Set` into the entry a move created
// supersedes nothing (it goes with that entry); holders read as the author throughout
#[test]
fn superseding_needs_later_expiry_and_own_records_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let me = s(&net.tid(a).to_string());
    let write = |net: &mut Net, op: Op, ms: u64| {
        let mut m = Mutation::new();
        m.op(w, &eph(CURSOR), PathOp { path: vec![PathSeg::Key(me.clone())], op }).unwrap();
        m.expires(w, &eph(CURSOR), osis_base::WallMs(net.now() + ms)).unwrap();
        net.engine(a).write(m).unwrap();
        local(net, a);
        net.run();
    };
    let at = |net: &mut Net, n: usize| net.eph_read(n, w, CURSOR);
    let want = |v: &str| Some(Value::Map([(me.clone(), s(v))].into()));
    write(&mut net, Op::Put(s("long")), 30_000);
    write(&mut net, Op::Put(s("short")), 5_000);
    assert_eq!((at(&mut net, a), at(&mut net, b)), (want("short"), want("short")));
    net.advance(6_000);
    assert_eq!((at(&mut net, a), at(&mut net, b)), (want("long"), want("long")), "the earlier move reads again");
    write(&mut net, Op::Set(s("into")), 60_000);
    assert_eq!((at(&mut net, a), at(&mut net, b)), (want("into"), want("into")));
    net.advance(30_000);
    let gone = Some(Value::Map(BTreeMap::new()));
    assert_eq!((at(&mut net, a), at(&mut net, b)), (gone.clone(), gone), "gone with the entry it wrote into");
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
        let (at_b, at_sv) = (encoded_held(&mut net, b, &l), net.servers[sv].hub.store().ephemeral_bytes(&l) as usize);
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
    // the holder's share for waiting blobs does not fit a blob's bound (about 6 times a
    // string's bytes): after the restart the second blob may come first, is refused for the
    // share, and is fetched again once the record the first carries is here (`eph_refetch`)
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
    // the second blob may come first: refused for the share, it comes again with the record
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
            assert_eq!(net.engine(b).ingest_ephemeral(bl.clone()).unwrap(), osis_node::ephemeral::EphIngest::Dropped);
            assert_eq!(net.engine(a).ingest_ephemeral(bl.clone()).unwrap(), osis_node::ephemeral::EphIngest::Dropped);
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
        let (at_b, at_sv) = (encoded_held(&mut net, b, &l), net.servers[sv].hub.store().ephemeral_bytes(&l) as usize);
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
    net.advance(60_000);
    assert_eq!(notes(&mut net, c, w).get("b").map(String::as_str), Some("1"), "b's offline note reaches c");
}

// spec/sync.md §5, §9: a writer's note built offline under
// the write key of a head the label rotated past meanwhile is refused 9 at its reconnection;
// stamped again under the new head's key and sent again, it reaches the other readers there.
#[test]
fn offline_entry_across_rotation_restamped_spec_sync_5() {
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
    let (at, bt, ct, xt) = (net.tid(a), net.tid(b), net.tid(c), net.tid(x));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write), (ct, Role::Write)]);
    remove_member(e, g, xt, &rs, 9);
    net.run();
    net.set_online(b, true);
    net.run();
    net.advance(60_000);
    assert_eq!(notes(&mut net, c, w).get("b").map(String::as_str), Some("1"), "b's offline note reaches c");
}

// spec/sync.md §5, §9: a writer demoted to reader while its note waited offline holds no write
// key of the new head: once it sees it no longer writes the label it stops trying (reported
// when the entry was already waiting for a key then), and the note reaches nobody.
#[test]
fn demoted_writer_entry_stops_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    net.set_online(b, false);
    net.run();
    note(&mut net, b, w, "b", "1");
    let bt = net.tid(b);
    let edge = osis_schema::core_types::Edge { role: Role::Read, until: None, invite: None, since: None, tied: None };
    let d = osis_node::flows::Demotion { member: bt, new: Some(edge), presync: osis_node::flows::PreSync::Synced };
    let done = net.engine(a).demote(&g, &d).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    net.set_online(b, true);
    net.run();
    net.advance(60_000);
    assert_eq!(net.engine(b).role_on(&g), Some(Role::Read));
    assert_eq!(notes(&mut net, c, w).get("b"), None, "the demoted writer's note never reaches c");
}

// spec/sync.md §5, §9: a writer compacts before it reads a rotation: the cover and the deletes
// of what it absorbs (carried as replacements) are signed under the old write key and refused 9;
// once the writer reads the rotation the cover lands and the absorbed entries go at the server.
// Code 9 carries no head (spec/wire.md §11.2): the writer learns it by push, or unsubscribed by
// its next resync's Sync.
#[test]
fn cover_across_unread_rotation_lands_spec_sync_9() {
    cover_across_unread_rotation(true);
    cover_across_unread_rotation(false);
}

fn cover_across_unread_rotation(subscribe: bool) {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.add_node(2, SyncConfig { servers: vec![net.address(sv)], subscribe, ..SyncConfig::default() });
    let c = net.node(3, &[sv]);
    let x = net.node(4, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write), (x, Role::Read)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    if !subscribe {
        // the window reaches b by its resync
        net.advance(60_000);
    }
    for i in 0..4 {
        note(&mut net, b, w, &format!("k{i}"), &format!("v{i}"));
        net.run();
    }
    net.held_to.insert(b);
    let (at, bt, ct, xt) = (net.tid(a), net.tid(b), net.tid(c), net.tid(x));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write), (ct, Role::Write)]);
    remove_member(e, g, xt, &rs, 9);
    net.run();
    let l = net.label(a);
    let before: BTreeSet<osis_base::BlobId> = net.server_ids(sv, &l).into_iter().collect();
    let acts = net.sync(b).compact_ephemeral_now().unwrap();
    net.actions(b, acts);
    net.run();
    net.release();
    net.run();
    net.advance(60_000);
    let held_b = |net: &mut Net, n: usize| {
        let e = net.engine(n);
        e.held_ephemeral().into_iter().filter(|(id, _, _)| e.ephemeral_header(id).is_some_and(|h| h.author == bt)).count()
    };
    assert_eq!(held_b(&mut net, c), 1, "c holds b's cover alone");
    assert_eq!(notes(&mut net, c, w).len(), 4);
    let after: BTreeSet<osis_base::BlobId> = net.server_ids(sv, &l).into_iter().collect();
    assert_eq!(after.difference(&before).count(), 1, "the cover landed");
    assert!(before.difference(&after).count() > 0, "what it absorbs is deleted at the server");
}

// spec/sync.md §5, §9: a plain delete of an absorbed entry sent before the writer reads a
// rotation is refused 9; it goes again under the next key and the entry leaves the server. The
// writer's last note is in flight when it compacts: its delete waits for the OK, then for the
// cover's (`orphans`, `waiting`), so it goes alone after the rotation. The admin holds no
// ephemeral entries of others, nor the writer it removes: the writer alone deletes.
#[test]
fn delete_across_unread_rotation_retried_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.add_node(1, SyncConfig { servers: vec![net.address(sv)], ephemeral_bytes: 0, ..SyncConfig::default() });
    let b = net.node(2, &[sv]);
    let c = net.add_node(3, SyncConfig { servers: vec![net.address(sv)], ephemeral_bytes: 0, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    for i in 0..4 {
        note(&mut net, b, w, &format!("k{i}"), &format!("v{i}"));
        net.run();
    }
    let l = net.label(a);
    let before: BTreeSet<osis_base::BlobId> = net.server_ids(sv, &l).into_iter().collect();
    net.held_to.insert(b);
    note(&mut net, b, w, "k4", "v4");
    net.run();
    let k4: Vec<osis_base::BlobId> = net.server_ids(sv, &l).into_iter().filter(|i| !before.contains(i)).collect();
    assert_eq!(k4.len(), 1, "the last note landed");
    let acts = net.sync(b).compact_ephemeral_now().unwrap();
    net.actions(b, acts);
    net.run();
    let (at, bt, ct) = (net.tid(a), net.tid(b), net.tid(c));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write)]);
    remove_member(e, g, ct, &rs, 9);
    net.run();
    net.release();
    net.run();
    net.advance(60_000);
    let after: BTreeSet<osis_base::BlobId> = net.server_ids(sv, &l).into_iter().collect();
    assert!(!after.contains(&k4[0]), "the plain delete refused 9 went again under the next key");
}

// spec/sync.md §9 (an own cover is placed under every label its absorbed commits were under),
// issue eph-cover-partial-label: after a restart, the author held its earlier note on a window
// placed in two groups while the placement in the second (and the note's entry there) was still
// being fetched; its cover went under the first label only and the note's entry under the second
// was deleted, so a reader of the second group alone lost the note
#[test]
fn restarted_cover_waits_for_every_label_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let g1 = net.group(a, &[(b, Role::Write)], &[sv]);
    let g2 = net.group_seeded(a, &[(c, Role::Read)], vec![net.address(sv)], 12);
    // g2 reads g1: g1's things placed in g2 go under g2's label too
    let (at, bt) = (net.tid(a), net.tid(b));
    let e = net.engine(a);
    set_edge(e, g1, g2, Role::Read);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write), (g2, Role::Read)]);
    rotation(e, g1, &rs, 5, false);
    net.run();
    let labels: BTreeMap<Tid, osis_base::LabelId> = net.sync(a).labels().into_iter().map(|(g, gl)| (g, gl.id)).collect();
    let w = window(&mut net, a, g1, "w");
    net.run();
    // the window placed in g2 too, in a commit of its own
    let mut m = Mutation::new();
    m.op(g2, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(Value::Tid(w)) }).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    note(&mut net, a, w, "a", "1");
    net.run();
    assert_eq!(notes(&mut net, c, w), map(&[("a", "1")]), "g2's reader reads the note");
    // the placement in g2 and the note's entry there: fetched late after the restart
    let own: Vec<osis_base::CommitId> = net.engine(a).held_ephemeral().into_iter().filter(|x| x.2).map(|x| x.0).collect();
    let l2 = labels[&g2];
    // (separate commits, or one cover of them, whichever the author's trigger left)
    let (mut slow, mut placed, mut noted) = (BTreeSet::new(), false, false);
    for id in &own {
        let h = net.engine(a).ephemeral_header(id).unwrap();
        let placing = h.aspects.iter().any(|x| x.tid == g2);
        let noting = h.aspects.iter().any(|x| x.ak.as_str() == NOTES);
        let under: Vec<osis_base::BlobId> = net.sync(a).ephemeral_entries_of(id).into_iter().filter(|x| x.0 == l2).map(|x| x.1).collect();
        if placing || noting {
            placed |= placing && !under.is_empty();
            noted |= noting && !under.is_empty();
            slow.extend(under);
        }
    }
    assert!(placed && noted, "the placement and the note under g2's label");
    net.restart(a, 31);
    net.hold_blobs = slow;
    for _ in 0..200 {
        net.feed(a, Event::Local);
        net.round();
    }
    assert_eq!(notes(&mut net, a, w), map(&[("a", "1")]), "the note is back through g1's label");
    let acts = net.sync(a).compact_ephemeral_now().unwrap();
    net.actions(a, acts);
    for _ in 0..200 {
        net.round();
    }
    net.release();
    net.run();
    net.restart(c, 33);
    net.advance(10_000);
    assert_eq!(notes(&mut net, c, w), map(&[("a", "1")]), "g2's reader gets the note back after a restart");
    // caught up: covered now, under both labels
    let acts = net.sync(a).compact_ephemeral_now().unwrap();
    net.actions(a, acts);
    net.run();
    let held = net.engine(a).held_ephemeral();
    assert!(held.iter().all(|x| x.2), "a's earlier session's commits covered: {held:?}");
    let under: BTreeSet<osis_base::LabelId> = held.iter().flat_map(|x| net.sync(a).ephemeral_entries_of(&x.0)).map(|x| x.0).collect();
    assert_eq!(under, labels.values().copied().collect(), "the cover is under both labels");
    net.restart(c, 34);
    net.advance(10_000);
    assert_eq!(notes(&mut net, c, w), map(&[("a", "1")]), "and from the cover");
}

// spec/sync.md §9 (an earlier session's commits are covered once each label at a server caught
// up): a label at no server catches up nowhere and does not hold the author's covers back
#[test]
fn restarted_cover_skips_label_at_no_server_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g1 = net.group(a, &[], &[sv]);
    net.group_seeded(a, &[], vec![], 12);
    net.run();
    let w = window(&mut net, a, g1, "w");
    net.run();
    for i in 0..6 {
        note(&mut net, a, w, &format!("k{i}"), "v");
        net.run();
    }
    net.restart(a, 31);
    net.run();
    let held = net.engine(a).held_ephemeral();
    assert!(!held.is_empty() && held.iter().all(|x| !x.2), "the earlier session's commits are back: {held:?}");
    let acts = net.sync(a).compact_ephemeral_now().unwrap();
    net.actions(a, acts);
    net.run();
    let held = net.engine(a).held_ephemeral();
    assert!(held.iter().all(|x| x.2), "the earlier session's commits covered: {held:?}");
}

// issues/eph-unify.md step 2 (write cost): `OSIS_BENCH_N` local sets of one string register, each
// its own batch, by `OSIS_BENCH_MODE`: `ephemeral` (today's local ephemeral write, `Engine::write`),
// `memory` (an ordinary commit through Core with every row in the store's memory overlay,
// `Engine::commit_in_memory`) or `durable` (an ordinary commit, in-memory backend). Compare with
// tools/icount on a release build, subtracting a run with `OSIS_BENCH_N=0` (notes/testing.md);
// `-- --nocapture` prints wall time per write and the phase spans. spec: none (cost)
#[test]
#[ignore = "bench: release, by hand"]
fn bench_local_writes() {
    let n: u32 = std::env::var("OSIS_BENCH_N").ok().and_then(|v| v.parse().ok()).unwrap_or(2000);
    let mode = std::env::var("OSIS_BENCH_MODE").unwrap_or_else(|_| "memory".into());
    let mut lp = crate::common::net(1, 5);
    // a thing whose `/t/reg` holds no durable row
    let mut m = Mutation::new();
    let me = lp.peers[0].engine.tid();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &crate::common::TAGS, &Value::Set(Default::default())).unwrap();
    lp.peers[0].commit(m).unwrap();
    let reg = crate::common::ak("/t/reg");
    let eph = osis_schema::Untyped::new(reg.clone(), Lifetime::Ephemeral);
    osis_node::costs::take();
    let start = std::time::Instant::now();
    for i in 0..n {
        let mut m = Mutation::new();
        let v = Value::Str(format!("v{i}"));
        let e = &mut lp.peers[0].engine;
        match mode.as_str() {
            "ephemeral" => {
                m.set(t, &eph, &v).unwrap();
                e.write(m).unwrap();
            }
            "memory" => {
                m.set(t, &eph, &v).unwrap();
                e.commit_in_memory(m).unwrap();
            }
            _ => {
                m.set(t, &crate::common::REG, &v).unwrap();
                e.commit(m).unwrap();
            }
        }
    }
    let per = start.elapsed() / n.max(1);
    eprintln!("{mode}: {per:?} per write");
    for (k, d, c) in osis_node::costs::take() {
        eprintln!("  {k:28} {:>9.1} us/write (x{c})", d.as_secs_f64() * 1e6 / f64::from(n.max(1)));
    }
    let got = lp.peers[0].engine.get(&t, &reg).unwrap();
    assert_eq!(got, n.checked_sub(1).map(|i| Value::Str(format!("v{i}"))));
}

// spec/commits.md §3 (session form), issues/eph-unify.md step 3: a memory commit is session
// form under the open's session with the ephemeral marker; its dots are `(Session(node,
// nonce), ctr)`, counted per aspect from 1, received and owned by that source, never a node's.
#[test]
fn memory_commit_session_form_spec_commits_3() {
    let mut lp = crate::common::net(1, 5);
    let t = crate::common::new_thing(&mut lp, 0);
    let reg = crate::common::ak("/t/tags");
    let e = &mut lp.peers[0].engine;
    let me = e.tid();
    let session = e.ephemeral_session();
    let mut ids = Vec::new();
    for i in 0..2 {
        let mut m = Mutation::new();
        m.set(t, &eph("/t/tags"), &Value::Set([Value::Str(format!("v{i}"))].into())).unwrap();
        ids.push(e.commit_in_memory(m).unwrap().unwrap());
    }
    let h = e.header(&ids[1]).unwrap();
    assert_eq!(h.form, osis_commit::Form::Session(session.nonce));
    assert_eq!(h.ephemeral, Some(osis_commit::EphClass::Plain));
    let a = h.aspects.iter().find(|a| a.ak == reg).unwrap();
    assert_eq!((a.lo, a.hi), (2, 3), "counters per aspect and session, from 1");
    let src = osis_crdt::Source::session(session);
    let r = e.receipt(&t, &reg).unwrap();
    assert_eq!(r.contiguous(&src, u64::MAX), 2);
    assert_eq!(r.contiguous(&osis_crdt::Source::node(me), u64::MAX), 0, "no node counters");
    assert_eq!(e.core.commit_of(&t, &reg, &osis_crdt::Dot::new(src.clone(), 1)), Some(ids[0]));
    assert_eq!(e.core.commit_of(&t, &reg, &osis_crdt::Dot::new(src, 2)), Some(ids[1]));
    assert_eq!(e.get(&t, &reg).unwrap(), Some(Value::Set([Value::Str("v1".into())].into())));
}

// spec/commits.md §2 (records beside the deltas), spec/data-model.md §1: a thing a memory commit
// makes is held as a memory-class record; the commit carries no `/created` aspect, its parts carry
// the thing's record and its memory owner chain; the first durable write on the thing persists
// the chain (`/created` in that commit); a restart keeps only what was persisted.
#[test]
fn memory_records_beside_deltas_spec_commits_2() {
    let mut lp = crate::common::net(1, 5);
    let t = crate::common::new_thing(&mut lp, 0);
    let tags = crate::common::ak("/t/tags");
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let top = e.new_thing(&mut m, t);
    let leaf = e.new_thing(&mut m, top);
    let lone = e.new_thing(&mut m, t);
    m.set(leaf, &eph("/t/tags"), &Value::Set([Value::Str("x".into())].into())).unwrap();
    let id = e.commit_in_memory(m).unwrap().unwrap();
    let blob = e.run(|tx| tx.get_commit(&id)).unwrap().unwrap();
    assert!(blob.header.aspects.iter().all(|a| a.ak.as_str() != "/created"));
    let carried: Vec<osis_base::Tid> = blob.parts.iter().flat_map(|p| p.records.iter().map(|r| r.tid())).collect();
    assert!(carried.contains(&leaf) && carried.contains(&top) && !carried.contains(&lone), "{carried:?}");
    for x in [top, leaf, lone] {
        assert!(e.core.created(&x).is_some() && e.core.durable_created(&x).is_none(), "memory-class record");
    }
    assert_eq!(e.get(&leaf, &tags).unwrap(), Some(Value::Set([Value::Str("x".into())].into())));
    // a durable write persists the chain
    let mut m = Mutation::new();
    m.set(leaf, &crate::common::REG, &Value::Str("d".into())).unwrap();
    let d = lp.peers[0].commit(m).unwrap().unwrap();
    let e = &mut lp.peers[0].engine;
    let h = e.header(&d).unwrap();
    let created: Vec<osis_base::Tid> = h.aspects.iter().filter(|a| a.ak.as_str() == "/created").map(|a| a.tid).collect();
    assert_eq!(created.len(), 2);
    assert!(created.contains(&leaf) && created.contains(&top));
    assert!(e.core.durable_created(&leaf).is_some() && e.core.durable_created(&top).is_some() && e.core.durable_created(&lone).is_none());
    lp.peers[0].restart(6).unwrap();
    let e = &mut lp.peers[0].engine;
    assert!(e.core.durable_created(&leaf).is_some() && e.core.durable_created(&top).is_some());
    assert!(e.core.created(&lone).is_none(), "an unpersisted memory thing is gone at restart");
    assert_eq!(e.get(&leaf, &crate::common::ak("/t/reg")).unwrap(), Some(Value::Str("d".into())));
}

// issues/eph-unify.md step 3: a memory commit is nothing durable to node-sync: no change mark,
// no generation step, not among `commit_ids` or a thing's durable commits, an `Ephemeral`
// event (none on a durable subscription), no demotion frontier entry. spec: none (internal)
#[test]
fn memory_commit_not_durable_to_sync() {
    let mut lp = crate::common::net(1, 5);
    let t = crate::common::new_thing(&mut lp, 0);
    let e = &mut lp.peers[0].engine;
    e.take_changed();
    let all = e.subscribe();
    let durable = e.subscribe_durable();
    let (generation, ids) = (e.core.generation, e.commit_ids());
    let mut m = Mutation::new();
    m.set(t, &eph("/t/tags"), &Value::Set([Value::Str("x".into())].into())).unwrap();
    let id = e.commit_in_memory(m).unwrap().unwrap();
    assert!(e.take_changed().is_empty());
    assert_eq!(e.core.generation, generation);
    assert!(e.core.memory_generation > 0);
    assert_eq!(e.commit_ids(), ids);
    assert_eq!(e.core.durable_on(&(t, crate::common::ak("/t/tags"))).count(), 0);
    let evs: Vec<_> = all.try_iter().collect();
    assert!(evs.iter().any(|ev| matches!(ev, osis_node::events::Event::Ephemeral { id: c, .. } if c.commit() == Some(id))), "{evs:?}");
    assert!(!evs.iter().any(|ev| matches!(ev, osis_node::events::Event::Applied { .. })));
    assert_eq!(durable.try_iter().count(), 0);
    // a durable write still marks
    let mut m = Mutation::new();
    m.set(t, &crate::common::REG, &Value::Str("d".into())).unwrap();
    lp.peers[0].commit(m).unwrap();
    let e = &mut lp.peers[0].engine;
    assert!(!e.take_changed().is_empty());
    assert!(e.core.generation > generation);
}

// issues/eph-unify.md step 3: work on a memory commit inside a durable transaction stays in
// memory: its expiry's tick writes nothing durable and steps no durable generation, and the
// value expires. spec: none (internal)
#[test]
fn memory_commit_expiry_stays_in_memory() {
    let mut lp = crate::common::net(1, 5);
    let t = crate::common::new_thing(&mut lp, 0);
    let tags = crate::common::ak("/t/tags");
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    m.set(t, &eph("/t/tags"), &Value::Set([Value::Str("x".into())].into())).unwrap();
    let at = osis_base::WallMs(e.now().0 + 1000);
    m.expires(t, &eph("/t/tags"), at).unwrap();
    e.commit_in_memory(m).unwrap().unwrap();
    assert!(e.get(&t, &tags).unwrap().is_some());
    let writes = lp.peers[0].backend.faults().writes();
    let generation = lp.peers[0].engine.core.generation;
    lp.advance(2000);
    let e = &mut lp.peers[0].engine;
    e.tick().unwrap();
    assert!(e.get(&t, &tags).unwrap().is_none_or(|v| v == Value::Set(Default::default())), "expired");
    assert_eq!(e.core.generation, generation);
    assert_eq!(lp.peers[0].backend.faults().writes(), writes, "nothing durable written");
}

// spec/commits.md §2 (records beside a delta of the things it places with its reader): an
// ephemeral thing under another reader placed into a group goes with its record beside its own
// deltas only, never beside the group's `/placed` delta (its nonce, its dedup secret, would show
// to the group's readers)
#[test]
fn placed_record_only_to_its_reader_spec_commits_2() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let e = net.engine(a);
    let me = e.tid();
    let mut m = Mutation::new();
    let p = e.new_thing(&mut m, me);
    m.set(p, &ct::NAME, &"private".to_string()).unwrap();
    e.write(m).unwrap();
    let mut m = Mutation::new();
    let w = e.new_thing(&mut m, p);
    m.op(g, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(Value::Tid(w)) }).unwrap();
    m.set(w, &eph(STATE), &s("hi")).unwrap();
    e.write(m).unwrap();
    assert_ne!(e.ephemeral_reader(&w), e.ephemeral_reader(&g));
    let built = e.take_ephemeral().unwrap();
    let parts: Vec<(String, Tid, Vec<Tid>)> = built.iter().flat_map(|c| c.blob.parts.iter().map(|p| { let a = &c.blob.header.aspects[p.ai]; (a.ak.as_str().to_string(), a.tid, p.records.iter().map(|r| r.tid()).collect()) }).collect::<Vec<_>>()).collect();
    assert!(parts.iter().any(|(ak, t, rs)| ak == "/placed" && *t == g && !rs.contains(&w)), "{parts:?}");
    assert!(parts.iter().any(|(ak, t, rs)| ak == STATE && *t == w && rs.contains(&w)), "{parts:?}");
}

// spec/sync.md §9 (Caps: held ephemeral bodies counted at an estimate of what they take held):
// records beside a part are held as ephemeral things with it, so the pre-decode bound and the
// node cap count them (a member padding a commit's parts with records cannot pass the cap)
#[test]
fn records_beside_parts_counted_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "x");
    let ak = osis_base::Ak::new(STATE).unwrap();
    let c = net.engine(a).forge_ephemeral(w, &ak, s("y")).unwrap().unwrap();
    let mut padded = c.blob.clone();
    let mut junk: Vec<osis_base::CreationRecord> = (0..200u8).map(|n| osis_base::CreationRecord::Thing { owner: g, nonce: [n; 32], creator: None }).collect();
    junk.append(&mut padded.parts[0].records);
    junk.sort_by_key(osis_base::CreationRecord::tid);
    padded.parts[0].records = junk;
    let (plain, _) = osis_node::Engine::ephemeral_bound(&c.blob);
    let (more, _) = osis_node::Engine::ephemeral_bound(&padded);
    assert!(more >= plain + 200 * 50, "{plain} {more}");
    net.engine(b).ingest_ephemeral(padded).unwrap();
    assert!(net.engine(b).ephemeral_charge(&c.id, &[]) >= 200 * 50 * 2);
}

// spec/data-model.md §1 (an aspect's class is its schema lifetime; a durable write on an
// ephemeral thing persists it): a memory commit writing a durable-schema aspect is refused,
// nothing of it applied; the same value written durably on the memory thing persists the thing
// and survives a restart beside nothing of the thing's memory-class aspect
#[test]
fn memory_commit_durable_aspect_refused_spec_data_model_1() {
    let mut lp = crate::common::net(1, 5);
    let t = crate::common::new_thing(&mut lp, 0);
    let reg = crate::common::ak("/t/reg");
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let leaf = e.new_thing(&mut m, t);
    m.set(leaf, &crate::common::REG, &Value::Str("m".into())).unwrap();
    assert!(matches!(e.commit_in_memory(m), Err(osis_node::Error::Misuse(_))));
    assert!(e.core.created(&leaf).is_none(), "nothing of a refused memory commit applies");
    let mut m = Mutation::new();
    let leaf = e.new_thing(&mut m, t);
    m.set(leaf, &eph("/t/tags"), &s("m")).unwrap();
    e.commit_in_memory(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.set(leaf, &crate::common::REG, &Value::Str("d".into())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[0].restart(6).unwrap();
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.get(&leaf, &reg).unwrap(), Some(Value::Str("d".into())));
    assert_eq!(e.get(&leaf, &crate::common::ak("/t/tags")).unwrap(), None, "the memory aspect is gone at restart");
}

/// Peers 0 and 1, durable state synced; 0 owns `d` and grants 1 write. Returns `d`.
fn memory_pair(seed: u64) -> (osis_node::local_peer::LocalPeer, Tid) {
    let mut lp = crate::common::net(2, seed);
    lp.sync_all().unwrap();
    let d = crate::common::new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    crate::common::set_edge(&mut lp.peers[0].engine, d, b, Some(crate::common::edge(Role::Write)), None);
    lp.sync_all().unwrap();
    (lp, d)
}

/// Peer `i` writes `v` into the ephemeral `/t/tags` of `t` as a memory commit.
fn memory_write(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: Tid, v: &str) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.op(t, &eph("/t/tags"), PathOp { path: Vec::new(), op: Op::Add(s(v)) }).unwrap();
    lp.peers[i].engine.commit_in_memory(m).unwrap().unwrap()
}

fn memory_tags(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: Tid) -> Option<Value> {
    lp.peers[i].engine.get(&t, &crate::common::ak("/t/tags")).unwrap()
}

// spec/commits.md §4 (a received commit is verified, pending or applied; memory class),
// issues/eph-unify.md step 3: a received memory commit goes through `ingest` and applies with
// every row in memory (no durable write while it waits or applies), its records held as memory
// class; again it is a duplicate; a restart forgets it
#[test]
fn received_memory_commit_in_memory_spec_commits_4() {
    let mut lp = crate::common::net(2, 31);
    let d = crate::common::new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    let w = lp.peers[0].engine.new_thing(&mut m, d);
    m.set(w, &eph("/t/tags"), &s("x")).unwrap();
    let id = lp.peers[0].engine.commit_in_memory(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
    let faults = lp.peers[1].backend.faults().clone();
    faults.forbid_writes(true);
    // the durable path refuses it (no production caller yet: a writer cannot slip one in there)
    assert!(matches!(lp.deliver(1, &pk), Err(osis_node::Error::BadInput(_))));
    // the author is not known yet: pending, in memory
    let got = lp.peers[1].engine.ingest_memory(&pk.bytes).unwrap();
    assert!(matches!(got, osis_node::Ingested::Pending(..)), "{got:?}");
    assert_eq!(faults.forbidden(), 0);
    faults.forbid_writes(false);
    lp.sync_all().unwrap();
    assert_eq!(memory_tags(&mut lp, 1, w), Some(s("x")), "applied once the author's chain arrived");
    let e = &mut lp.peers[1].engine;
    assert!(e.core.created(&w).is_some() && e.core.durable_created(&w).is_none());
    assert!(e.run(|tx| Ok(tx.txn.pending(None, 16)?)).unwrap().is_empty());
    faults.forbid_writes(true);
    assert!(matches!(lp.peers[1].engine.ingest_memory(&pk.bytes).unwrap(), osis_node::Ingested::Duplicate(_)));
    let id2 = {
        let mut m = Mutation::new();
        m.set(w, &eph("/t/tags"), &s("y")).unwrap();
        lp.peers[0].engine.commit_in_memory(m).unwrap().unwrap()
    };
    let pk2 = lp.peers[0].engine.package(&id2).unwrap().unwrap();
    assert!(matches!(lp.peers[1].engine.ingest_memory(&pk2.bytes).unwrap(), osis_node::Ingested::Applied(_)));
    assert_eq!(memory_tags(&mut lp, 1, w), Some(s("y")));
    // one waiting for drift is re-examined and applied in memory too
    lp.peers[0].clock.advance(2 * osis_base::format::MAX_DRIFT_MS);
    let id3 = memory_write(&mut lp, 0, w, "z");
    let pk3 = lp.peers[0].engine.package(&id3).unwrap().unwrap();
    assert!(matches!(lp.peers[1].engine.ingest_memory(&pk3.bytes).unwrap(), osis_node::Ingested::Pending(_, osis_node::Reason::Drift)));
    lp.peers[1].clock.advance(2 * osis_base::format::MAX_DRIFT_MS);
    lp.peers[1].engine.reexamine().unwrap();
    assert!(lp.peers[1].engine.core.ix.commits.contains_key(&id3), "applied at re-examination");
    assert_eq!(faults.forbidden(), 0, "nothing durable written for a memory commit");
    faults.forbid_writes(false);
    lp.peers[1].restart(32).unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.core.created(&w).is_none() && ![id, id2, id3].iter().any(|c| e.core.ix.commits.contains_key(c)));
    assert!(e.run(|tx| Ok(tx.txn.pending(None, 16)?)).unwrap().is_empty());
    assert_no_durable_trace(e, &[id, id2, id3]);
}

/// No durable row (local record, or commit index row) names any of `ids` (after a restart: the
/// memory overlay is empty).
fn assert_no_durable_trace(e: &mut osis_node::Engine, ids: &[osis_base::CommitId]) {
    let mut hits = Vec::new();
    e.run(|tx| {
        tx.scan(b"", |k, v| {
            if ids.iter().any(|c| k.windows(32).chain(v.windows(32)).any(|w| w == c.0)) {
                hits.push(k.to_vec());
            }
            Ok(())
        })?;
        let t = tx.txn.index(b"node/metas")?;
        for c in ids {
            if tx.txn.table_get(t, &c.0)?.is_some() {
                hits.push(c.0.to_vec());
            }
        }
        Ok(())
    })
    .unwrap();
    assert!(hits.is_empty(), "durable rows naming a memory commit: {hits:?}");
}

// spec/data-model.md §1 (one storage class per aspect): a received memory part on an aspect of
// durable deltas here is dropped alone, never shadowing the durable state
#[test]
fn received_memory_part_on_durable_aspect_dropped_spec_data_model_1() {
    let (mut lp, d) = memory_pair(33);
    let mut m = Mutation::new();
    m.set(d, &crate::common::TAGS, &Value::Set([s("durable")].into())).unwrap();
    lp.peers[1].commit(m).unwrap();
    // 0 has not seen 1's durable write: writes the aspect as memory
    let id = memory_write(&mut lp, 0, d, "memory");
    let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
    lp.peers[1].engine.ingest_memory(&pk.bytes).unwrap();
    assert_eq!(memory_tags(&mut lp, 1, d), Some(Value::Set([s("durable")].into())));
    lp.peers[1].restart(34).unwrap();
    assert_eq!(memory_tags(&mut lp, 1, d), Some(Value::Set([s("durable")].into())));
}

// issues/eph-unify.md step 3 (freeing): a thing freed while a received memory commit on it is
// pending takes that commit with it: it never applies later and brings the thing back
#[test]
fn freed_thing_drops_pending_memory_commit() {
    let (mut lp, d) = memory_pair(35);
    let mut m = Mutation::new();
    let w = lp.peers[0].engine.new_thing(&mut m, d);
    m.set(w, &eph("/t/tags"), &s("x")).unwrap();
    let id = lp.peers[0].engine.commit_in_memory(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
    lp.peers[1].engine.ingest_memory(&pk.bytes).unwrap();
    assert_eq!(memory_tags(&mut lp, 1, w), Some(s("x")));
    // a later one from 0's clock far ahead waits for drift
    lp.peers[0].clock.advance(2 * osis_base::format::MAX_DRIFT_MS);
    let later = memory_write(&mut lp, 0, w, "y");
    let pk = lp.peers[0].engine.package(&later).unwrap().unwrap();
    assert!(matches!(lp.peers[1].engine.ingest_memory(&pk.bytes).unwrap(), osis_node::Ingested::Pending(_, osis_node::Reason::Drift)));
    let e = &mut lp.peers[1].engine;
    e.free_memory(&BTreeSet::from([w])).unwrap();
    assert!(e.core.created(&w).is_none() && !e.core.ix.pending.contains_key(&later));
    lp.peers[1].clock.advance(2 * osis_base::format::MAX_DRIFT_MS);
    let e = &mut lp.peers[1].engine;
    e.reexamine().unwrap();
    assert!(e.core.created(&w).is_none() && !e.core.ix.commits.contains_key(&later), "the freed thing stays gone");
}

// spec/permissions.md §5.2 (a removed writer's writes un-merged; a demotion frontier lists no
// session source): a writer's received memory commits are valid while it may write, and their
// writes go when it is removed
#[test]
fn removed_writer_memory_commits_unmerged_spec_permissions_5_2() {
    let (mut lp, d) = memory_pair(37);
    memory_write(&mut lp, 0, d, "own");
    let id = memory_write(&mut lp, 1, d, "theirs");
    let pk = lp.peers[1].engine.package(&id).unwrap().unwrap();
    assert!(matches!(lp.peers[0].engine.ingest_memory(&pk.bytes).unwrap(), osis_node::Ingested::Applied(_)));
    assert_eq!(memory_tags(&mut lp, 0, d), Some(Value::Set([s("own"), s("theirs")].into())));
    let b = lp.peers[1].engine.tid();
    let scope = osis_perm::DemotionScope { membership: BTreeMap::from([(b, BTreeSet::from([d]))]), content: BTreeMap::from([(b, BTreeSet::from([d]))]) };
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&scope, now).unwrap();
    crate::common::set_edge(&mut lp.peers[0].engine, d, b, None, Some(osis_schema::Codec::to_value(&f)));
    assert_eq!(memory_tags(&mut lp, 0, d), Some(Value::Set([s("own")].into())), "the removed writer's memory writes go");
    assert!(lp.peers[0].engine.core.ix.commits.get(&id).is_some_and(|m| m.valid.iter().all(|v| !v)));
    // the un-merge, done in the removal's durable transaction, wrote nothing durable about it
    lp.peers[0].restart(38).unwrap();
    assert_no_durable_trace(&mut lp.peers[0].engine, &[id]);
}

// issues/eph-unify.md (Left: class by AK): a memory commit on an aspect with no durable delta here
// yet marks it memory; a later durable write on it then routes to memory and is lost at restart,
// and sync never brings it back (the node holds the commit). Reachable once received memory
// commits get a production caller; the receiver rule needs the class from the key, not local state
#[test]
#[ignore = "issues/eph-unify.md: durable write on a memory-marked aspect lost at restart"]
fn repro_durable_write_on_memory_marked_aspect_lost() {
    let (mut lp, d) = memory_pair(41);
    let id = memory_write(&mut lp, 1, d, "memory");
    let pk = lp.peers[1].engine.package(&id).unwrap().unwrap();
    lp.peers[0].engine.ingest_memory(&pk.bytes).unwrap();
    let mut m = Mutation::new();
    m.set(d, &crate::common::TAGS, &Value::Set([s("durable")].into())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[0].restart(42).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(memory_tags(&mut lp, 0, d), Some(Value::Set([s("durable")].into())));
}

// spec/sync.md §9 (an expiring commit superseded by its author's later writes is dropped and
// deleted by its author; superseded unsent writes are not sent): a cursor moved 30 times a second,
// each move a fresh entry at the author's key expiring 30 s out (what `osis::KeepAlive::set`
// writes), costs about one held commit at every node and one entry at the server, not one per
// move until each expires (was issues/eph-expiring-churn.md: 60 here)
#[test]
fn moving_cursor_one_entry_per_author_spec_sync_9() {
    const E: u64 = 30_000;
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let l = net.label(a);
    let me = s(&net.tid(a).to_string());
    let entries = |net: &Net| osis_proto::LabelStore::live_ids(net.servers[sv].hub.store(), &l).unwrap().len();
    let base = entries(&net);
    let held = |net: &mut Net, n: usize| net.engine(n).held_ephemeral().len();
    let (ha, hb) = (held(&mut net, a), held(&mut net, b));
    for i in 0..60 {
        let mut m = Mutation::new();
        m.op(w, &eph(CURSOR), PathOp { path: vec![PathSeg::Key(me.clone())], op: Op::Put(s(&format!("c{i}"))) }).unwrap();
        m.expires(w, &eph(CURSOR), osis_base::WallMs(net.now() + E)).unwrap();
        net.engine(a).write(m).unwrap();
        local(&mut net, a);
        net.advance(33);
        assert!(entries(&net) - base <= 3, "move {i}: the server holds {} entries of one cursor", entries(&net) - base);
    }
    net.run();
    assert_eq!(net.eph_read(b, w, CURSOR), Some(Value::Map([(me.clone(), s("c59"))].into())));
    assert_eq!(net.eph_read(a, w, CURSOR), Some(Value::Map([(me, s("c59"))].into())));
    assert_eq!(entries(&net) - base, 1, "one entry of the cursor at the server");
    assert_eq!((held(&mut net, a) - ha, held(&mut net, b) - hb), (1, 1), "one commit of it held at the author and the holder");
    // the last move still expires everywhere
    net.advance(E);
    assert_eq!(net.eph_read(b, w, CURSOR), None);
    assert_eq!(entries(&net), base);
}

// issues/eph-set-into-dead-entry.md: b's `Set` into a's entry outlives the entry's expiry; a and
// b, which held the entry, read the key absent, c restarted after the expiry reads b's value
#[test]
#[ignore]
fn repro_set_into_expired_entry_differs() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[sv]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let wr = |net: &mut Net, n: usize, op: Op, ms: u64| {
        let mut m = Mutation::new();
        m.op(w, &eph(CURSOR), PathOp { path: vec![PathSeg::Key(s("k"))], op }).unwrap();
        m.expires(w, &eph(CURSOR), osis_base::WallMs(net.now() + ms)).unwrap();
        net.engine(n).write(m).unwrap();
        local(net, n);
        net.run();
        net.advance(33);
    };
    wr(&mut net, a, Op::Put(s("v")), 5_000);
    wr(&mut net, b, Op::Set(s("s")), 600_000);
    net.advance(6_000);
    net.restart(c, 77);
    net.advance(10_000);
    let reads: Vec<Option<Value>> = [a, b, c].iter().map(|n| net.eph_read(*n, w, CURSOR)).collect();
    assert!(reads.iter().all(|r| *r == reads[0]), "alike: {reads:?}");
}
