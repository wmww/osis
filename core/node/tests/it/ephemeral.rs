//! Synced ephemeral data (notes/ephemeral.md step 3, spec/sync.md §4-§6): ephemeral commits held
//! in memory at nodes and hosts, carried by the ordinary sync path; signals as relay-only
//! commits.

use crate::net;
use net::*;
use osis_base::{Role, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use osis_node::sync::{Event, SyncConfig};
use osis_schema::core_types as ct;
use osis_store::Backend;
use std::collections::{BTreeMap, BTreeSet};

/// The label write key node `n` stamps with (the group's newest write epoch, label index 0).
pub(crate) fn write_key(net: &mut Net, n: usize, g: Tid) -> osis_crypto::SigningSecret {
    let w = net.engine(n).epochs(&g).unwrap().write.newest_held().unwrap().1.clone();
    osis_crypto::label_role_key(osis_crypto::LabelRole::Write, &w, 0)
}

/// Seals ephemeral commit `c` under `g`'s label as node `w` would, stamped with `stamp` when
/// given: (blob ID, the log event a host pushes).
pub(crate) fn sealed(net: &mut Net, w: usize, g: Tid, c: &osis_commit::CommitBlob, stamp: Option<&osis_crypto::SigningSecret>, seed: u64) -> (osis_base::BlobId, osis_proto::Event) {
    let p = osis_commit::project(c, |_| ()).unwrap().remove(0);
    let class = osis_label::Class::of_marker(c.header.ephemeral);
    let body = osis_node::labeling::Body { commit: c.id(), reader: g, parts: p.parts, expires: p.expires, keys: p.keys, blind: c.header.blind, plaintext: p.plaintext, role_commit: false, order: 1 };
    let s = osis_node::labeling::seal_body_as(&body, class, &mut osis_crypto::SeededRng::from_u64(seed)).unwrap();
    let secret = net.engine(w).wrap_secret(&g, None).unwrap().unwrap();
    let wrap = osis_crypto::wrap(&secret, &s.id, &s.key, 1).unwrap();
    let l = net.label(w);
    let stamp = stamp.map(|k| osis_label::sign_stamp(k, &l, &s.id, &wrap));
    (s.id, osis_proto::Event::Added { blob_id: s.id, blob: Some(s.blob), wrap, stamp })
}

/// Host `host` pushes `events` of label `l` to node `n` (a replay or a hostile host's push);
/// the node's actions.
pub(crate) fn push(net: &mut Net, n: usize, host: usize, l: osis_base::LabelId, events: Vec<osis_proto::Event>) -> Vec<osis_node::sync::Action> {
    let conn = net.conn_to(n, host).unwrap();
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

const STATE: &str = "win:state.0~";
const NOTES: &str = "win:notes.0~";
const CURSOR: &str = "win:cursor.0~";

fn eph(ak: &str) -> osis_base::Ak {
    crate::common::ak(ak)
}

fn local(net: &mut Net, n: usize) {
    let acts = net.sync(n).handle(Event::Local);
    net.actions(n, acts);
}

/// Node `n` makes an ephemeral window owned by `g`, placed in `g` (its `placed.0~`), with `win:state.0` = `v`.
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

/// Node `n` sets key `k` of `win:notes.0` of `w` to `v`.
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

/// Node `n`'s own memory commits not yet taken by its lane, with their blobs (what the lane
/// would place): taken here instead.
fn take_memory(net: &mut Net, n: usize) -> Vec<(osis_base::CommitId, osis_commit::CommitBlob)> {
    let e = net.engine(n);
    let ids = e.take_memory_commits(&BTreeSet::new()).unwrap();
    ids.into_iter().filter_map(|c| e.memory_blob(&c).unwrap().map(|b| (c, b))).collect()
}

/// Node `n` receives memory commit `blob` directly (no room limit).
fn deliver(net: &mut Net, n: usize, blob: &osis_commit::CommitBlob) -> osis_node::Ingested {
    net.engine(n).ingest_memory(&blob.encode(), u64::MAX).unwrap()
}

/// A memory commit built here: its ID and blob.
struct Forged {
    id: osis_base::CommitId,
    blob: osis_commit::CommitBlob,
}

/// A memory commit by node `n` setting `(tid, ak)` to `v` with no rights or class check (a
/// forged write, to test receivers), as sent; `n`'s own copy may hold nothing of it.
fn forge_memory(net: &mut Net, n: usize, tid: Tid, ak: &osis_base::Ak, v: Value) -> Forged {
    let e = net.engine(n);
    let mut m = Mutation::new();
    m.op(tid, ak, PathOp { path: Vec::new(), op: Op::Set(v) }).unwrap();
    let id = e.commit_in_memory_hostile(m).unwrap().unwrap();
    let bytes = e.take_forged().unwrap();
    Forged { id, blob: osis_commit::CommitBlob::decode(&bytes).unwrap() }
}

pub(crate) fn rows(b: &osis_store::MemoryBackend) -> usize {
    b.scan(&[], None, usize::MAX).unwrap().len()
}

// notes/ephemeral.md step 3, spec/sync.md §4: an ephemeral window placed in a synced group
// reaches the other holder's reads and watches; neither its store nor the host's gains a row
// (the host reserves log numbers in its label meta, the same row)
#[test]
fn window_reaches_holder_no_store_rows_spec_sync_4() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let (rb, rs) = (rows(&net.nodes[b].backend), rows(&net.hosts[host].backend));
    let commits = net.engine(b).commit_ids().len();
    let rx = net.listen(b);
    let w = window(&mut net, a, g, "hello");
    net.run();
    assert_eq!(net.eph_read(b, w, STATE), Some(s("hello")));
    assert!(net.engine(b).groups_of(&w).contains(&g), "the placement came along");
    let changed: Vec<_> = rx.try_iter().filter_map(|e| if let osis_node::Event::Ephemeral { changed, origin: osis_node::Origin::Remote, .. } = e { Some(changed) } else { None }).flatten().collect();
    assert!(changed.iter().any(|(t, ak)| *t == w && ak.as_str() == STATE), "{changed:?}");
    assert_eq!(rows(&net.nodes[b].backend), rb, "nothing stored at the holder");
    assert_eq!(rows(&net.hosts[host].backend), rs, "nothing stored at the host");
    assert_eq!(net.engine(b).commit_ids().len(), commits);
}

// spec/sync.md §9 (a thing entering a labeled closure goes out whole): an own expiring write
// made while its thing was in no labeled closure (after a restart, before its placement came
// back: `ephemeral::random_churn_converges_large` seed 203) goes with it, under its expiry
#[test]
fn expiring_write_before_entering_closure_goes_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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

// notes/ephemeral.md Tess's direction (the shared window): two holders keep editing while one is
// offline; on reconnect both converge on the merge, through a host
#[test]
fn shared_window_merges_after_offline_spec_sync_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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

// the shared window over a direct peer link (a co-reader peer serving the label, spec/sync.md §5):
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
// the host (its first sync of the label reconciles: its cursor had passed those entries)
#[test]
fn restarted_node_gets_state_back_spec_sync_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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

// notes/ephemeral.md At hosts: a host restart loses its ephemeral entries; the holders bring
// them back (they list what they hold in their first Sync, the host wants what it lacks), so a
// node arriving later still gets the state
#[test]
fn host_restart_holders_upload_again_spec_sync_4() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read)], &[host]);
    net.set_online(c, false);
    net.run();
    let w = window(&mut net, a, g, "survives");
    net.run();
    let l = net.label(a);
    assert!(net.hosts[host].hub.store().ephemeral_bytes(&l) > 0);
    net.restart_host(host);
    assert_eq!(net.hosts[host].hub.store().ephemeral_bytes(&l), 0);
    net.run();
    net.advance(10_000);
    assert!(net.hosts[host].hub.store().ephemeral_bytes(&l) > 0, "uploaded again");
    net.set_online(a, false);
    net.set_online(b, false);
    net.set_online(c, true);
    net.advance(10_000);
    assert_eq!(net.eph_read(c, w, STATE), Some(s("survives")));
}

// notes/ephemeral.md Convergence (a holder bridging two hosts carries ephemeral state across):
// A only on host 1 and C only on host 2 converge through B on both
#[test]
fn bridge_node_carries_between_hosts_spec_sync_6() {
    let mut net = Net::new();
    let (s1, s2) = (net.add_host(), net.add_host());
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

// spec/data-model.md §1 (persistence): an ephemeral thing syncs with its record; the other holder
// persists it with a durable write, keeping its tid; the first node sees it durable then
#[test]
fn ephemeral_thing_persists_same_tid_elsewhere_spec_data_model_1() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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
// the node restarted and its ephemeral writes back from the host: no undo log, nothing marks
// it a draft) gets that placement converted by its next durable write, as at its first; the
// other holder sees it placed durably again
#[test]
fn ephemeral_placement_of_durable_thing_converts_spec_data_model_8() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    note(&mut net, a, w, "a", "1");
    net.run();
    note(&mut net, b, w, "b", "2");
    net.run();
    assert_eq!(notes(&mut net, a, w), map(&[("a", "1"), ("b", "2")]));
    let l = net.label(a);
    let theirs: Vec<_> = net.engine(a).memory_commits().into_iter().filter(|h| !h.2).map(|h| h.0).collect();
    assert!(!theirs.is_empty() && net.sync(a).ephemeral_bytes(&l) > 0, "b's commits held and counted");
    let bt = net.tid(b);
    let me = net.tid(a);
    let e = net.engine(a);
    let rs = recipients_of(e, &[(me, Role::Admin)]);
    remove_holder(e, g, bt, &rs, 9);
    net.run();
    assert_eq!(notes(&mut net, a, w), map(&[("a", "1")]), "b's ephemeral write is un-merged");
    // invalid now, they stay held and un-merged like durable commits (a later grant would
    // re-merge them)
    net.advance(60_000);
    for c in &theirs {
        assert!(net.engine(a).holds_memory(c), "held, un-merged");
    }
    assert_eq!(notes(&mut net, a, w), map(&[("a", "1")]));
}

// notes/ephemeral.md Bounds (host ephemeral bytes per label): past the cap uploads are refused;
// the writer compacts, deletes what the compaction covers and the label syncs again
#[test]
fn host_cap_compaction_frees_it_spec_sync_5() {
    let mut net = Net::new();
    // a few entries with their per-entry overhead (about 900 bytes each); tuned so one upload is
    // refused and the writer's own compaction later makes room (a refused write left alone with
    // no compaction due stays refused: issues/eph-unify.md step 5, Replace at cap)
    let host = net.add_host_with(osis_host::HostPolicy { ephemeral_bytes: 6_300, ..osis_host::HostPolicy::default() });
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "busy");
    net.run();
    for i in 0..30 {
        note(&mut net, a, w, &format!("k{i}"), "v");
        net.run();
    }
    let l = net.label(a);
    assert!(net.hosts[host].hub.store().ephemeral_bytes(&l) <= 6_300);
    assert!(net.engine(a).memory_commits().len() < 30, "compacted: {}", net.engine(a).memory_commits().len());
    let want: BTreeMap<String, String> = (0..30).map(|i| (format!("k{i}"), "v".to_string())).collect();
    assert_eq!(notes(&mut net, b, w), want);
    // a node arriving now gets the whole state from what the host kept
    net.restart(b, 23);
    net.advance(10_000);
    assert_eq!(notes(&mut net, b, w), want);
}

// a host cap too small for the compacted state: the writer compacts, the cover is refused, and
// it reports instead of compacting the cover into the next cover forever (a livelock found while
// charging per-entry overhead at hosts)
#[test]
fn host_cap_below_state_reports_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host_with(osis_host::HostPolicy { ephemeral_bytes: 2_500, ..osis_host::HostPolicy::default() });
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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

// notes/ephemeral.md Bounds (host cap): one write too large for the cap has nothing to compact
// (one held part): the label reports and that write stays out of the host, the defined outcome;
// later writes that fit still sync
#[test]
fn host_cap_one_huge_write_reports_spec_sync_5() {
    let mut net = Net::new();
    // room for the window's two entries (its placement and its state) and a note, not for the
    // 6000-byte write
    let host = net.add_host_with(osis_host::HostPolicy { ephemeral_bytes: 8_000, ..osis_host::HostPolicy::default() });
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let rx = net.listen(a);
    let mut m = Mutation::new();
    m.op(w, &eph("win:big.0~"), PathOp { path: Vec::new(), op: Op::Set(s(&"x".repeat(6_000))) }).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    let refused = rx.try_iter().any(|e| matches!(e, osis_node::Event::Diagnostic(d) if d.kind == osis_node::DiagnosticKind::EphemeralRefused));
    assert!(refused, "reported");
    assert_eq!(net.eph_read(b, w, "win:big.0~"), None);
    note(&mut net, a, w, "k", "v");
    net.run();
    assert_eq!(notes(&mut net, b, w), map(&[("k", "v")]), "a later write that fits syncs");
}

// spec/sync.md §9 (caps), notes/ephemeral.md Node cap: the node cap counts what a held commit
// takes in memory, not its encoded bytes, and a commit is checked against the room left before it
// is decoded (`Engine::memory_bound`): one of many tiny entries (about 200 times its size
// decoded) is refused whole and reported, never held past the cap; a small one is held, counted
// at its decoded size
#[test]
fn node_cap_bounds_decoded_size_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let cap = 236_000;
    let b = net.add_node(2, SyncConfig { hosts: vec![net.address(host)], ephemeral_bytes: cap, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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
    let at_host = net.hosts[host].hub.store().ephemeral_bytes(&l);
    assert!(at_host < 40_000, "{at_host} B at the host: fits the cap encoded");
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
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.add_node(2, SyncConfig { hosts: vec![net.address(host)], ephemeral_bytes: 400_000, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let r = net.node(2, &[host]);
    let g = net.group(a, &[(r, Role::Read)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "mine");
    net.run();
    assert_eq!(net.eph_read(r, w, STATE), Some(s("mine")), "the reader reads it");
    let mut m = Mutation::new();
    m.set(w, &eph(STATE), &s("theirs")).unwrap();
    assert!(net.engine(r).write(m).is_err(), "refused at the writer");
    let ak = osis_base::Ak::new(STATE).unwrap();
    let forged = forge_memory(&mut net, r, w, &ak, s("forged"));
    deliver(&mut net, a, &forged.blob);
    assert_eq!(net.eph_read(a, w, STATE), Some(s("mine")), "invalid: not joined");
    local(&mut net, r);
    net.run();
    assert_eq!(net.eph_read(a, w, STATE), Some(s("mine")));
}

// spec/commits.md §2 (class from the key): an ephemeral commit's part on an
// unmarked key is invalid at the receiver; the same forged write on a `~` key joins
#[test]
fn ephemeral_part_on_unmarked_key_invalid_spec_commits_2() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "mine");
    net.run();
    for (k, joins) in [("win:plain.0", false), ("win:other.0~", true)] {
        let ak = osis_base::Ak::new(k).unwrap();
        let forged = forge_memory(&mut net, b, w, &ak, s("forged"));
        deliver(&mut net, a, &forged.blob);
        assert_eq!(net.eph_read(a, w, k), joins.then(|| s("forged")), "{k}");
    }
}

// notes/ephemeral.md Signals: a signal reaches each device connected now once, also over two
// hosts (no duplicate); a device connecting later never gets it; no host holds an entry; a
// restarted node does not see it again
#[test]
fn signal_once_to_connected_devices_spec_sync_5() {
    let mut net = Net::new();
    let (s1, s2) = (net.add_host(), net.add_host());
    let a = net.node(1, &[s1, s2]);
    let b = net.node(2, &[s1, s2]);
    let c = net.node(3, &[s1]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read)], &[s1, s2]);
    let t = net.item(a, g, g, "x");
    net.set_online(c, false);
    net.run();
    let held = (rows(&net.hosts[s1].backend), rows(&net.hosts[s2].backend));
    let (ra, rb, rc) = (net.listen(a), net.listen(b), net.listen(c));
    net.eph_write(a, t, &crate::common::ak("t:ring.0*"), s("ding"));
    net.run();
    assert_eq!(fired(&rb).len(), 1, "once, though both hosts pushed it");
    assert_eq!(fired(&ra).len(), 1, "once at the sender (no echo)");
    assert_eq!((rows(&net.hosts[s1].backend), rows(&net.hosts[s2].backend)), held, "no host holds it");
    let l = net.label(a);
    assert_eq!(net.hosts[s1].hub.store().ephemeral_bytes(&l), 0);
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
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t1 = net.item(a, g, g, "x");
    let t2 = net.item(a, g, g, "y");
    net.run();
    let mut m = Mutation::new();
    m.set(t1, &crate::common::ak("t:ring.0*"), &s("one")).unwrap();
    m.set(t2, &crate::common::ak("t:ring.0*"), &s("two")).unwrap();
    net.engine(a).write(m).unwrap();
    let cs = net.engine(a).take_signals().unwrap();
    let blob = cs[0].blob.clone();
    assert_eq!(blob.parts.len(), 2);
    let rb = net.listen(b);
    let mut fires = Vec::new();
    for p in &blob.parts {
        let one = osis_commit::CommitBlob { header: blob.header.clone(), signature: blob.signature, parts: vec![p.clone()] };
        assert!(net.engine(b).ingest_relay(one.clone()).unwrap());
        assert!(!net.engine(b).ingest_relay(one).unwrap(), "a copy");
        fires.extend(fired(&rb).into_iter().map(|(t, _, v, _)| (t, v)));
    }
    fires.sort();
    let mut want = vec![(t1, s("one")), (t2, s("two"))];
    want.sort();
    assert_eq!(fires, want);
    assert!(!net.engine(b).ingest_relay(blob).unwrap(), "the whole commit again");
}

// spec/crdt.md §4.7, spec/sync.md §1 (an ephemeral commit's expiry rides in its header and its
// blob prefix): a typing indicator written with an expiry reaches the other holder and is gone
// everywhere at its time, hosts included
#[test]
fn ephemeral_expiry_everywhere_spec_crdt_4_7() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let mut m = Mutation::new();
    m.set(w, &eph("win:typing.0~"), &Value::Bool(true)).unwrap();
    m.expires(w, &eph("win:typing.0~"), osis_base::WallMs(net.now() + 5_000)).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    assert_eq!(net.eph_read(b, w, "win:typing.0~"), Some(Value::Bool(true)));
    let l = net.label(a);
    let before = net.hosts[host].hub.store().ephemeral_bytes(&l);
    net.advance(6_000);
    assert_eq!(net.eph_read(a, w, "win:typing.0~"), None);
    assert_eq!(net.eph_read(b, w, "win:typing.0~"), None);
    assert!(net.hosts[host].hub.store().ephemeral_bytes(&l) < before, "the host dropped it unattended");
}

// spec/crdt.md §4.7 (ephemeral data: an expired write vanishes whole): B removes A's note with
// an expiry; at its time the removal goes too and the note reads again at B (its author), at A
// (held the removal then) and at C (offline meanwhile, never held it): two nodes holding the
// same ephemeral commits read the same, whatever expired when
#[test]
fn expired_removal_vanishes_everywhere_spec_crdt_4_7() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    note(&mut net, a, w, "k", "v");
    net.run();
    let v = Some(Value::Map([(s("k"), s("v"))].into()));
    for n in [a, b, c] {
        assert_eq!(net.eph_read(n, w, NOTES), v, "node {n} has the note");
    }
    net.set_online(c, false);
    let mut m = Mutation::new();
    m.op(w, &eph(NOTES), PathOp { path: vec![], op: Op::Remove(s("k")) }).unwrap();
    m.expires(w, &eph(NOTES), osis_base::WallMs(net.now() + 5_000)).unwrap();
    net.engine(b).write(m).unwrap();
    local(&mut net, b);
    net.run();
    let none = Some(Value::Map(BTreeMap::new()));
    assert_eq!((net.eph_read(a, w, NOTES), net.eph_read(b, w, NOTES)), (none.clone(), none), "removed until its expiry");
    net.advance(6_000);
    assert_eq!((net.eph_read(a, w, NOTES), net.eph_read(b, w, NOTES)), (v.clone(), v.clone()), "the removal vanished with its expiry");
    net.set_online(c, true);
    net.advance(30_000);
    for n in [a, b, c] {
        assert_eq!(net.eph_read(n, w, NOTES), v, "node {n} reads the note again");
    }
}

// spec/crdt.md §4.6, §4.7 (an undo never extends a value's lifetime past its original expiry):
// A undoes its removal of its expiring note; the note comes back at A and at B, expiring at the
// note's time, not the undo's or never
#[test]
fn undo_of_removal_keeps_expiry_spec_crdt_4_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let t = net.now() + 5_000;
    let mut m = Mutation::new();
    m.op(w, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s("k"))], op: Op::Put(s("v")) }).unwrap();
    m.expires(w, &eph(NOTES), osis_base::WallMs(t)).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    let mut m = Mutation::new();
    m.op(w, &eph(NOTES), PathOp { path: vec![], op: Op::Remove(s("k")) }).unwrap();
    let rm = net.engine(a).write(m).unwrap().unwrap().id;
    local(&mut net, a);
    net.run();
    net.advance(1_000);
    let me = net.tid(a);
    net.engine(a).revert_change(rm, me).unwrap();
    local(&mut net, a);
    net.run();
    for n in [a, b] {
        assert_eq!(notes(&mut net, n, w), map(&[("k", "v")]), "node {n}: the note is back");
    }
    net.advance(t + 1_000 - net.now());
    for n in [a, b] {
        assert_eq!(notes(&mut net, n, w), BTreeMap::new(), "node {n}: gone at the note's expiry");
    }
}

// spec/crdt.md §4.6, §4.7: past the note's expiry, undoing its removal brings nothing back
#[test]
fn undo_of_removal_past_expiry_restores_nothing_spec_crdt_4_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    // B's note, removed by A: a remote write, its part dropped at its time
    let mut m = Mutation::new();
    m.op(w, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s("k"))], op: Op::Put(s("v")) }).unwrap();
    m.expires(w, &eph(NOTES), osis_base::WallMs(net.now() + 5_000)).unwrap();
    net.engine(b).write(m).unwrap();
    local(&mut net, b);
    // and A's own
    let mut m = Mutation::new();
    m.op(w, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s("j"))], op: Op::Put(s("u")) }).unwrap();
    m.expires(w, &eph(NOTES), osis_base::WallMs(net.now() + 5_000)).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    assert_eq!(notes(&mut net, a, w).len(), 2);
    let mut m = Mutation::new();
    m.op(w, &eph(NOTES), PathOp { path: vec![], op: Op::Remove(s("k")) }).unwrap();
    m.op(w, &eph(NOTES), PathOp { path: vec![], op: Op::Remove(s("j")) }).unwrap();
    let rm = net.engine(a).write(m).unwrap().unwrap().id;
    local(&mut net, a);
    net.run();
    net.advance(6_000);
    let me = net.tid(a);
    let _ = net.engine(a).revert_change(rm, me).unwrap();
    local(&mut net, a);
    net.run();
    for n in [a, b] {
        assert_eq!(notes(&mut net, n, w), BTreeMap::new(), "node {n}: nothing came back");
    }
}

// spec/crdt.md §4.6, §4.7 (random churn seed 79 shrunk): A's `Set` into B's entry at a key
// shadowing A's own older entry there, both expiring; past both, undoing the `Set` strips B's
// value from what it restores, which then finds A's, also gone: neither comes back (the `Set`
// stays, reading alone: nothing before to restore, and a nested register takes no reset)
#[test]
fn undo_of_set_past_expiry_restores_no_shadowed_entry_spec_crdt_4_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let t = net.now() + 5_000;
    for (n, v) in [(a, "v1"), (b, "v2")] {
        let mut m = Mutation::new();
        m.op(w, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s("k"))], op: Op::Put(s(v)) }).unwrap();
        m.expires(w, &eph(NOTES), osis_base::WallMs(t)).unwrap();
        net.engine(n).write(m).unwrap();
        local(&mut net, n);
        net.run();
    }
    assert_eq!(notes(&mut net, a, w), map(&[("k", "v2")]));
    let mut m = Mutation::new();
    m.op(w, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s("k"))], op: Op::Set(s("v3")) }).unwrap();
    let set = net.engine(a).write(m).unwrap().unwrap().id;
    local(&mut net, a);
    net.run();
    net.advance(t + 1_000 - net.now());
    let me = net.tid(a);
    let _ = net.engine(a).revert_change(set, me).unwrap();
    local(&mut net, a);
    net.run();
    for n in [a, b] {
        assert_eq!(notes(&mut net, n, w), map(&[("k", "v3")]), "node {n}: no expired value came back");
    }
}

// spec/crdt.md §4.7 (expiry), spec/sync.md §9 (notes/ephemeral.md Values that live while their
// author is there): a cursor (a map entry under the author's key, expiring 30 s after each write)
// its author rewrites every 15 s stays up at B without a gap, the host holding at most a few
// of its entries; once the author goes away the refreshes stop and the cursor is gone at B and
// at the host by the last write's expiry, with nobody noticing the departure
#[test]
fn refreshed_value_lives_while_author_present_spec_crdt_4_7() {
    const E: u64 = 30_000;
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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
    let entries = |net: &Net| osis_proto::LabelStore::live_ids(net.hosts[host].hub.store(), &l).unwrap().len();
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
        assert!(entries(&net) <= base + 3, "the host holds the writes of one expiry window: {}", entries(&net) - base);
    }
    // the author's device goes away: no departure is seen, the last write expires
    net.set_online(a, false);
    net.advance(E - 1);
    assert_eq!(net.eph_read(b, w, CURSOR), want, "until the last write's expiry");
    net.advance(1);
    assert_eq!(net.eph_read(b, w, CURSOR), None);
    assert_eq!(entries(&net), base, "the host dropped every one of its entries");
}

// spec/crdt.md §5.1 (a nested register carries no reset): a `Replace` at a map key of an
// ephemeral aspect reads at a holder too (its delta once carried a reset there and was refused)
#[test]
fn eph_replace_at_map_key_read_at_holder_spec_crdt_5_1() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    net.set_online(b, false);
    let t = net.item(a, g, g, "durable");
    net.run();
    let mut m = Mutation::new();
    m.set(t, &eph("doc:cursor.0~"), &Value::Int(7)).unwrap();
    net.engine(a).write(m).unwrap();
    let cs = take_memory(&mut net, a);
    assert_eq!(cs.len(), 1);
    assert!(net.engine(b).core.created(&t).is_none());
    deliver(&mut net, b, &cs[0].1.clone());
    assert_eq!(net.eph_read(b, t, "doc:cursor.0~"), None, "waits for the record");
    net.set_online(b, true);
    net.advance(10_000);
    assert_eq!(net.read(b, t), Some(s("durable")));
    assert_eq!(net.eph_read(b, t, "doc:cursor.0~"), Some(Value::Int(7)));
}

// notes/ephemeral.md Node cap: a blob that could never fit the label's cap (its bound past the
// whole cap) is remembered: a drop under the cap reconciles the label without fetching it again
#[test]
fn never_fitting_blob_not_fetched_again_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let x = net.node(2, &[host]);
    let cap = 330_000;
    let b = net.add_node(3, SyncConfig { hosts: vec![net.address(host)], ephemeral_bytes: cap, ..SyncConfig::default() });
    let g = net.group(a, &[(x, Role::Write), (b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "doc");
    net.run();
    let l = net.label(a);
    net.eph_write_expiring(x, t, &eph("doc:cursor.0~"), s(&"c".repeat(50_000)), Some(5_000));
    net.run();
    assert!(net.eph_read(b, t, "doc:cursor.0~").is_some());
    let v = Value::Map((0..2000).map(|i| (Value::Int(i), Value::Int(1))).collect());
    net.eph_write(a, t, &crate::common::ak("doc:tiny.0~"), v);
    net.run();
    assert_eq!(net.eph_read(b, t, "doc:tiny.0~"), None, "refused for the cap");
    net.fetched.insert(b, Vec::new());
    net.advance(5_000);
    assert_eq!(net.eph_read(b, t, "doc:cursor.0~"), None);
    assert!(net.sync(b).ephemeral_bytes(&l) < 1_000);
    net.advance(SyncConfig::default().resync_ms + 1_000);
    assert_eq!(net.fetched[&b], Vec::new(), "not fetched again");
}

// spec/commits.md §4, spec/sync.md §9 (only verified commits are held and spread): another blob
// of a held ephemeral commit, the same header with a junk delta or signature, is refused
#[test]
fn forged_copy_of_held_commit_refused_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "durable");
    net.run();
    let mut m = Mutation::new();
    m.set(t, &eph("doc:cursor.0~"), &Value::Int(7)).unwrap();
    net.engine(a).write(m).unwrap();
    let cs = take_memory(&mut net, a);
    let blob = cs[0].1.clone();
    assert!(matches!(deliver(&mut net, b, &blob), osis_node::Ingested::Applied(_)));
    assert!(matches!(deliver(&mut net, b, &blob), osis_node::Ingested::Duplicate(_)), "a true copy");
    assert_eq!(net.engine(b).parts_genuine(&blob), Some(true));
    let mut junk = blob.clone();
    junk.parts[0].delta.push(0);
    assert_eq!(net.engine(b).parts_genuine(&junk), Some(false), "a junk delta");
    let mut unsigned = blob;
    unsigned.signature = osis_crypto::Signature([0; 64]);
    assert_eq!(net.engine(b).parts_genuine(&unsigned), Some(false), "a junk signature");
}

// spec/sync.md §4 (blob ID = BLAKE3 of the bytes), spec/requirements.md ("Nothing trusts a
// host's word"): a host pushing a held ephemeral blob again under other IDs (the wrap's
// nonce is only the ID's first 24 bytes, so it still opens) adds no entry and charges nothing
#[test]
fn ephemeral_blob_under_wrong_id_dropped_spec_sync_4() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "durable");
    net.run();
    let mut m = Mutation::new();
    m.set(t, &eph("doc:cursor.0~"), &Value::Int(7)).unwrap();
    net.engine(a).write(m).unwrap();
    let cs = take_memory(&mut net, a);
    let wk = write_key(&mut net, a, g);
    let (id, ev) = sealed(&mut net, a, g, &cs[0].1, Some(&wk), 9);
    let l = net.label(a);
    push(&mut net, b, host, l, vec![ev.clone()]);
    assert_eq!(net.eph_read(b, t, "doc:cursor.0~"), Some(Value::Int(7)));
    let held = (net.sync(b).ephemeral_bytes(&l), net.sync(b).ephemeral_held_entries(&l));
    assert_eq!(held.1.iter().map(|e| e.0).collect::<Vec<_>>(), vec![id]);
    for n in 0..4u8 {
        let osis_proto::Event::Added { blob, wrap, stamp, .. } = ev.clone() else { unreachable!() };
        let mut forged = id;
        forged.0[31] ^= 1 + n;
        let stamp = stamp.map(|_| osis_label::sign_stamp(&wk, &l, &forged, &wrap));
        push(&mut net, b, host, l, vec![osis_proto::Event::Added { blob_id: forged, blob, wrap, stamp }]);
    }
    assert_eq!((net.sync(b).ephemeral_bytes(&l), net.sync(b).ephemeral_held_entries(&l)), held);
}

// spec/crdt.md §4.6 (un-merge rebuilds from what is held), spec/permissions.md §5.2 (a valid
// snapshot vouches for what it carries): a restarted node gets its old commits back and its
// compaction snapshot covers them (an earlier session's are its own); a later removal on the
// aspect un-merges only what the snapshot does not carry, so the old writes and the removed
// writer's compacted one stay, and the holders agree
#[test]
fn snapshot_survives_rebuild_spec_crdt_4_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[host]);
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
    // a's earlier session's note: covered at a by a's snapshot, at b by whichever snapshot
    // came first (any author's covers another's writes)
    let by_a = |net: &mut Net, n: usize| {
        let e = net.engine(n);
        e.memory_commits().into_iter().filter(|(id, _, _)| e.header(id).is_some_and(|h| h.author == at && !h.kind.is_compaction() && h.aspects.iter().any(|x| x.ak.as_str() == NOTES))).count()
    };
    assert_eq!(by_a(&mut net, a), 0, "a's snapshot covered its earlier session's note");
    assert_eq!(by_a(&mut net, b), 0, "and b dropped it");
    note(&mut net, c, w, "c2", "2");
    net.run();
    let ct = net.tid(c);
    let bt = net.tid(b);
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write)]);
    remove_holder(e, g, ct, &rs, 9);
    net.run();
    let at_a = notes(&mut net, a, w);
    assert_eq!(at_a, notes(&mut net, b, w), "holders agree");
    assert_eq!(at_a, map(&[("a", "1"), ("b", "1"), ("c", "1")]), "a's covered write stays, c's compacted one too; c's later one goes");
}

// spec/permissions.md §5.2 (a valid snapshot vouches for the writes it carries, "except those
// another writer compacted before it learned of the revocation, which stay"): a holder's write
// compacted by others before its removal stays at every holder and at a node arriving later
// Shape: c's automatic compaction is stamped last, so its snapshot covers every snapshot and
// body at d and at the host (writers deleted them there); c's removal invalidates it, and d
// holds nothing until a and b, still holding their own, snapshot afresh
// (`Engine::take_memory_invalidated`; a re-upload of the deleted entries would meet the host's
// delete tombstone).
#[test]
fn compacted_write_of_removed_holder_stays_spec_permissions_5_2() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let d = net.node(4, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write), (d, Role::Read)], &[host]);
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
    remove_holder(e, g, ct, &rs, 9);
    net.run();
    for n in [a, b, d] {
        assert_eq!(notes(&mut net, n, w), all, "node {n}: c's compacted write stays");
    }
    net.restart(d, 41);
    net.advance(10_000);
    assert_eq!(notes(&mut net, d, w), all, "a node arriving later agrees");
}

// spec/requirements.md Convergence, spec/permissions.md §5.2 (the residual of a snapshot turning
// invalid): writer w writes X, removes itself from the group (no demotion frontier), then
// snapshots X's aspect as C stamped after the removal, so C is invalid wherever the removal is
// known and X stays valid. Holder a gets C before the removal (drops X as covered, then C
// turns invalid: X's writes are gone there until a copy arrives again), holder b the removal
// first (C invalid on arrival, X kept). Both stay connected past the host's ephemeral tombstone
// and must read alike: a reconciles the label (`Engine::take_memory_invalidated`) and gets X
// back from the host, which w (no writer any more) never deleted.
#[test]
fn snapshot_invalidated_by_self_removal_reads_alike_spec_permissions_5_2() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let w = net.node(2, &[host]);
    let b = net.node(3, &[host]);
    let g = net.group(a, &[(w, Role::Write), (b, Role::Read)], &[host]);
    net.run();
    let wn = window(&mut net, a, g, "w");
    net.run();
    note(&mut net, w, wn, "x", "X");
    net.run();
    let x = map(&[("x", "X")]);
    assert_eq!((notes(&mut net, a, wn), notes(&mut net, b, wn)), (x.clone(), x.clone()));
    net.set_online(a, false);
    net.set_online(b, false);
    let wt = net.tid(w);
    let d = osis_node::flows::Demotion { holder: wt, new: None, presync: osis_node::flows::PreSync::Synced, keep: None };
    let done = net.engine(w).demote(&g, &d).unwrap();
    let r = *done.commits.last().unwrap();
    let ak = osis_base::Ak::new(NOTES).unwrap();
    net.engine(w).core.skip_writer_rules = true;
    let c = net.engine(w).snapshot(&wn, &ak).unwrap().unwrap();
    net.engine(w).core.skip_writer_rules = false;
    let cb = net.engine(w).memory_blob(&c).unwrap().unwrap();
    let acts = net.sync(w).carry_out(done).unwrap();
    net.actions(w, acts);
    local(&mut net, w);
    net.run();
    let rp = net.engine(w).package(&r).unwrap().unwrap();
    // a: C, then the removal
    deliver(&mut net, a, &cb);
    net.engine(a).ingest(&rp.bytes, rp.blobs.clone()).unwrap();
    // b: the removal, then C
    net.engine(b).ingest(&rp.bytes, rp.blobs.clone()).unwrap();
    deliver(&mut net, b, &cb);
    net.set_online(a, true);
    net.set_online(b, true);
    assert_eq!((notes(&mut net, a, wn), notes(&mut net, b, wn)), (BTreeMap::new(), x.clone()), "the split: a lost X with C, b kept it");
    for _ in 0..(osis_base::format::MAX_DRIFT_MS / 60_000 + 5) {
        net.advance(60_000);
    }
    assert_eq!((notes(&mut net, a, wn), notes(&mut net, b, wn)), (x.clone(), x), "holders of the same commits read alike");
}

// spec/crdt.md §2.1: a write's session names its node, so a node's own writes are its sessions'
// (the dots of `node`'s writes on `(t, ak)` here)
fn session_dots(net: &mut Net, n: usize, t: Tid, ak: &str) -> Vec<(osis_crdt::Session, u64)> {
    let ak = osis_base::Ak::new(ak).unwrap();
    let f = net.engine(n).state(&t, &ak).unwrap().unwrap_or_default();
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
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
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
    assert_eq!(notes(&mut net, a, w), map(&[("k1", "v"), ("k2", "v")]), "the earlier session's writes back from the host");
    note(&mut net, a, w, "k3", "v");
    net.run();
    assert_eq!(session_dots(&mut net, a, w, NOTES), vec![(first, 1), (first, 2), (second, 1)]);
}

// spec/crdt.md §2.1: two sessions of one node never collide: the same counter of one aspect in
// each makes two elements, everywhere
#[test]
fn sessions_of_one_node_never_collide_spec_crdt_2_1() {
    const ITEMS: &str = "win:items.0~";
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
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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
    assert_eq!(items(&mut net, b, w), want, "a restarted holder, from the host");
}

// spec/crdt.md §2.1 (counters never reused within a session): a thing freed here while others
// hold its writes, received again and written, takes the session's next counters, not 1 again
#[test]
fn freed_thing_received_again_keeps_counters_spec_crdt_2_1() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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

// spec/sync.md §9 (what a cover absorbs is deleted at a host once the cover is held there):
// the author crashes before its cover reaches the host; nothing was deleted, so the state
// stays at the host for holders, a restarted holder and the author itself (deleting first
// lost those writes there for good: the tombstones keep holders from bringing them back)
#[test]
fn author_crash_before_cover_lands_keeps_state_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    // two notes: under the compaction trigger, so the snapshot is this test's
    for i in 0..2 {
        note(&mut net, a, w, &format!("k{i}"), "v");
        net.run();
    }
    let want = notes(&mut net, a, w);
    assert_eq!(want.len(), 2);
    let conn = net.conn_to(a, host).unwrap();
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
    assert_eq!(notes(&mut net, b, w), want, "the host still holds them");
}

// spec/sync.md §5 (code 4: the delete rate is used up, replacements counting), §9 (absorbed
// entries leave a host once the cover is held there): a cover refused for the rate goes again
// at the periodic pass, and what it absorbs leaves the host then
#[test]
fn cover_refused_for_rate_retried_spec_sync_9() {
    let mut net = Net::new();
    // the first compaction replaces four entries (two notes and the window's other aspects'
    // bodies, one snapshot per aspect), the second three more in the same window: refused 4
    let host = net.add_host_with(osis_host::HostPolicy { deletes: 4, ..osis_host::HostPolicy::default() });
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
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
    cover(&mut net, 0..2);
    let one = net.hosts[host].hub.store().ephemeral_bytes(&l);
    cover(&mut net, 2..4);
    let refused = net.hosts[host].hub.store().ephemeral_bytes(&l);
    assert!(refused > one, "the second cover is not there: its absorbed entries stay");
    net.advance(130_000);
    let after = net.hosts[host].hub.store().ephemeral_bytes(&l);
    assert!(after < refused, "the cover went again and replaced what it absorbs: {after} {refused}");
    // one snapshot per aspect, no write body left
    let e = net.engine(a);
    assert!(e.memory_commits().iter().all(|(c, _, _)| e.header(c).is_some_and(|h| h.kind.is_compaction())), "{:?}", e.memory_commits());
    net.restart(a, 31);
    net.advance(10_000);
    assert_eq!(notes(&mut net, a, w).len(), 4);
}

// harness (random_window_inflight seed 173899): bytes a slow host held back for a connection
// that closed when it restarted never reach the restarted node's new connection of that number
// (they carried another connection's challenge: every open there was refused)
#[test]
fn restarted_node_gets_no_old_host_bytes() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    // b's first connection since a restart (numbered 1): the host's greeting held back
    net.set_online(b, false);
    net.restart(b, 49);
    net.held_hosts.insert(host);
    net.set_online(b, true);
    net.run();
    // the host restarts (b redials, connection 2), then b (connection 1 again): the old
    // greeting must not reach it
    net.restart_host(host);
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
/// hosts (odd seeds: one with a random ephemeral cap, 0 and below one cover included), random
/// ephemeral writes, partitions (offline, one host blocked), node restarts and host
/// restarts; after healing every holder reads the same notes (through the uncapped host), and
/// each writer's own held commits cost at most twice their cover (spec/sync.md §9).
fn random_window_run(seed: u64) {
    random_window_run_on(seed, false, false)
}

/// `single`: one host only, always capped (what it holds is all others get): holders read
/// alike unless an entry a holder has stays out of it because it genuinely does not fit there.
/// `inflight`: half the steps end after one hop of delivery instead of settling, so later
/// writes meet uploads still in flight (coalesced, spec/sync.md §9), and the second host is
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
    // odd seeds (and `single`): a random ephemeral cap at the first host, from nothing fitting
    // to the whole state fitting
    let cap = [0, 1_500, 4_000, 8_000, 16_000, 64_000][(seed / 2 % 6) as usize];
    let s1 = if single || seed % 2 == 1 { net.add_host_with(osis_host::HostPolicy { ephemeral_bytes: cap, ..osis_host::HostPolicy::default() }) } else { net.add_host() };
    let s2 = net.add_host();
    let hosts: Vec<usize> = if single { vec![s1] } else { vec![s1, s2] };
    let nodes: Vec<usize> = (0..4).map(|i| net.node(1 + i, &hosts)).collect();
    let grants: Vec<(usize, Role)> = nodes[1..].iter().map(|n| (*n, Role::Write)).collect();
    let g = net.group(nodes[0], &grants, &hosts);
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
                log.push(format!("host {s} restarts"));
                net.restart_host(s);
            }
            _ => {
                log.push("advance".into());
                net.advance(1_000 + rnd(20_000));
                continue;
            }
        }
        // a slow host: its answers and pushes held back for a while
        if inflight && !single && irnd() && irnd() {
            if net.held_hosts.remove(&s2) {
                log.push(format!("host {s2} answers"));
                net.release();
            } else {
                log.push(format!("host {s2} slow"));
                net.held_hosts.insert(s2);
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
    // one more periodic pass: entries a full host refused go again once room appeared
    net.advance(61_000);
    // and more while room appeared only after a pass (deletes of what an entry accepted at that
    // pass absorbs): the retry is the next pass's (spec/sync.md §9, "later"). Each such pass
    // lets in an entry that fits (or another takes its room), so at most one per entry.
    if single {
        let l = net.label(nodes[0]);
        let pending = |net: &mut Net| {
            let ids: BTreeSet<osis_base::BlobId> = net.host_ids(s1, &l).into_iter().collect();
            let store = net.hosts[s1].hub.store();
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
        // held it restarted since (a host holding it would have handed it back)
        assert!(kept.is_empty(), "seed {seed}: nobody holds the window, though nodes {kept:?} held it and never restarted since\n{}", log.join("\n"));
        return;
    };
    let l = net.label(h0);
    // spec/sync.md §5 (defined outcome past a cap): an entry some holder has that the only host
    // lacks and could not fit
    let refused = single && {
        let ids: BTreeSet<osis_base::BlobId> = net.host_ids(s1, &l).into_iter().collect();
        let store = net.hosts[s1].hub.store();
        let mut out = false;
        for n in &holders {
            for (b, size) in net.nodes[*n].sync.as_ref().unwrap().ephemeral_held_entries(&l) {
                out |= !ids.contains(&b) && !store.ephemeral_fits(&l, size as u64);
            }
        }
        out
    };
    // and the refusal is genuine: the host keeps no plain entry that no node holds (one every
    // holder dropped as absorbed, whose deletion never came, would fill it and excuse divergence)
    if refused {
        let store = net.hosts[s1].hub.store();
        let plain: Vec<osis_base::BlobId> = net.host_ids(s1, &l).into_iter().filter(|b| osis_proto::LabelStore::blob(store, b).ok().flatten().and_then(|x| osis_label::Prefix::parse(&x).ok()).is_some_and(|p| p.class() == osis_label::Class::Ephemeral)).collect();
        let held: BTreeSet<osis_base::BlobId> = nodes.iter().flat_map(|n| net.nodes[*n].sync.as_ref().unwrap().ephemeral_held_entries(&l).into_iter().map(|x| x.0)).collect();
        let stale: Vec<_> = plain.iter().filter(|b| !held.contains(b)).collect();
        if !stale.is_empty() {
            panic!("seed {seed}: the full host keeps entries {stale:?} no node holds (cap {cap})\n{}\n{}", log.join("\n"), lane_dump(&mut net, &nodes, &hosts, &l, w));
        }
    }
    // past a refusal, holders of the same plain commits still read alike (a node's state is its
    // own commits and the valid ones it received)
    let held = |net: &mut Net, n: usize| -> BTreeSet<osis_base::CommitId> {
        let e = net.engine(n);
        e.memory_commits().into_iter().map(|x| x.0).collect()
    };
    let mut reads: Vec<(usize, BTreeMap<String, String>, BTreeSet<osis_base::CommitId>)> = Vec::new();
    for n in &holders {
        reads.push((*n, notes(&mut net, *n, w), held(&mut net, *n)));
    }
    for (n, got, h) in &reads[1..] {
        let Some((m, want, _)) = reads.iter().find(|(_, _, h2)| !refused || h2 == h) else { continue };
        if got != want {
            panic!("seed {seed}: node {n} differs from node {m} (cap {cap})\n{}\n{}", log.join("\n"), lane_dump(&mut net, &nodes, &hosts, &l, w));
        }
    }
    // spec/sync.md §9 (compaction): the bodies each writer holds of an aspect within `FACTOR`
    // times a snapshot of it and one in flight
    for n in &nodes {
        for x in net.engine(*n).memory_load().unwrap() {
            assert!(x.held <= osis_node::ephemeral::FACTOR * x.snapshot + x.largest, "seed {seed}: node {n} holds {} B of {} on {:?}, snapshot {} B\n{}", x.held, x.ak, x.tid, x.snapshot, log.join("\n"));
        }
    }
}

/// Whether node `n` holds ephemeral thing `w` in a labeled closure (it syncs it: a record that
/// came without its placement, which a full host kept out, leaves the node writing it locally).
fn syncs(net: &mut Net, n: usize, w: Tid) -> bool {
    let e = net.engine(n);
    e.ephemeral_thing(&w).is_some() && e.ephemeral_synced(&w)
}

/// Failure detail: each node's reads and lane, each host's entries.
fn lane_dump(net: &mut Net, nodes: &[usize], hosts: &[usize], l: &osis_base::LabelId, w: Tid) -> String {
    let mut out = String::new();
    for m in nodes {
        let n = notes(net, *m, w);
        out.push_str(&format!("node {m} {:?} reads {n:?}\n{}", net.tid(*m), net.nodes[*m].sync.as_ref().unwrap().ephemeral_dump(l)));
        for d in net.nodes[*m].sync.as_ref().unwrap().describe() {
            out.push_str(&format!("  {d}\n"));
        }
        let e = net.engine(*m);
        for (id, bytes, own) in e.memory_commits() {
            let h = e.header(&id).unwrap();
            out.push_str(&format!("  held {id:?} by {:?} {:?} own {own} {bytes} B\n", h.author, h.ephemeral));
        }
    }
    for host in hosts {
        out.push_str(&format!("host {host} holds {:?}, {} B\n", net.host_ids(*host, l), net.hosts[*host].hub.store().ephemeral_bytes(l)));
    }
    out
}

// the same with one capped host (caps 0 to fitting all; 10, 63, 105, 162: concurrent covers to
// one full host; 173658: room appears only after the last periodic pass; other seeds: `_large`)
#[test]
fn random_window_one_capped_host_spec_sync_9() {
    for seed in [0, 10, 63, 105, 162, 173658] {
        random_window_run_on(seed, true, false);
    }
}

/// A tier-2 random-window run: OSIS_EPH_SEEDS (default 200) from OSIS_EPH_START (default 0).
fn eph_large(name: &str, single: bool, inflight: bool) {
    eph_seeds().run(name, |seed| eph_replay(name, seed), |seed| random_window_run_on(seed, single, inflight));
}

fn eph_seeds() -> osis_base::testenv::Seeds {
    osis_base::testenv::Seeds::from_env("OSIS_EPH_START", "OSIS_EPH_SEEDS", 0..200)
}

fn eph_replay(name: &str, seed: u64) -> String {
    format!("OSIS_EPH_START={seed} OSIS_EPH_SEEDS=1 cargo test --workspace --test it {name} -- --ignored --exact")
}

// the same with one capped host: holders converge through what it holds, or an entry stays out
// of it that genuinely does not fit
#[test]
#[ignore]
fn random_window_one_capped_host_large() {
    eph_large("ephemeral::random_window_one_capped_host_large", true, false);
}

// notes/ephemeral.md Convergence (randomized): holders of a shared window converge after random
// writes, partitions and restarts heal (5327166: a restarted author's re-cover stamped below its
// earlier session's cover of the same content; each held one took the other for redundant and
// both were deleted at the hosts)
#[test]
fn random_window_converges_spec_sync_6() {
    for seed in [0, 1, 5327166] {
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
    for seed in 0..2 {
        random_window_run_on(seed, false, true);
    }
}

// the same over more seeds (tier 2): OSIS_EPH_SEEDS (default 200) from OSIS_EPH_START
#[test]
#[ignore]
fn random_window_inflight_large() {
    eph_large("ephemeral::random_window_inflight_large", false, true);
}

const FLAG: &str = "win:flag.0~";

/// One random run of superseded expiring writes (spec/sync.md §9): four writers on two hosts
/// make expiring and plain writes at a few shared and own keys of a map and to a register
/// (several ops per batch, sometimes two aspects), removals and replaces (resets), undos of
/// their own changes, demotions and promotions of writers, with partitions and node and host
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
    let hosts = vec![net.add_host(), net.add_host()];
    let nodes: Vec<usize> = (0..4).map(|i| net.node(1 + i, &hosts)).collect();
    let grants: Vec<(usize, Role)> = nodes[1..].iter().map(|n| (*n, Role::Write)).collect();
    let g = net.group(nodes[0], &grants, &hosts);
    net.run();
    let w = window(&mut net, nodes[0], g, "w");
    net.run();
    let tids: Vec<Tid> = nodes.iter().map(|n| net.tid(*n)).collect();
    let edge = |role| osis_schema::core_types::Edge { role, until: None, invite: None, since: None, tied: None, keyset: None };
    let mut demoted: BTreeSet<usize> = BTreeSet::new();
    // nodes once demoted: a demoted author's view of its own writes differs from the others'
    // (issues/eph-demoted-own-writes.md), so only the others' reads are compared
    let mut ever: BTreeSet<usize> = BTreeSet::new();
    let mut last: BTreeMap<usize, osis_node::ChangeId> = BTreeMap::new();
    let mut restarts = 100;
    let mut log = Vec::new();
    // when each expiring value dies (`v{step}`, `f{step}`, `r{step}`): no node reads one at or past it
    let mut dies: BTreeMap<String, u64> = BTreeMap::new();
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
                    // a `Set` writes into the entry at the key, another writer's included
                    let v = s(&format!("v{step}"));
                    let op = if rnd(3) == 0 { Op::Set(v) } else { Op::Put(v) };
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
                    let d = osis_node::flows::Demotion { holder: tids[i], new: Some(edge(Role::Read)), presync: osis_node::flows::PreSync::Synced, keep: None };
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
                        let host = hosts[rnd(2) as usize];
                        let blocked = !net.blocked.remove(&(n, host));
                        if blocked {
                            net.blocked.insert((n, host));
                            if net.conn_to(n, host).is_some() {
                                let on = net.nodes[n].online;
                                net.set_online(n, false);
                                net.set_online(n, on);
                            }
                        }
                        log.push(format!("{n} blocked from {host} {blocked}"));
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
                        let host = hosts[rnd(2) as usize];
                        log.push(format!("host {host} restarts"));
                        net.restart_host(host);
                    }
                }
                ""
            }
            _ => {
                log.push("advance".into());
                net.advance(500 + rnd(10_000));
                churn_expiry_check(&mut net, &nodes, w, &dies, seed, step, &log);
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
            if let (Ok(_), Some(e)) = (&r, exp) {
                for v in ["v", "f", "r"] {
                    dies.insert(format!("{v}{step}"), net.now() + e);
                }
            }
        }
        if rnd(2) == 0 {
            net.feed(n, Event::Local);
            net.round();
        } else {
            net.run();
        }
        net.clock.advance(1 + rnd(40));
        churn_expiry_check(&mut net, &nodes, w, &dies, seed, step, &log);
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
    let held = |net: &mut Net, n: usize| -> BTreeSet<osis_base::CommitId> { net.engine(n).memory_commits().into_iter().map(|x| x.0).collect() };
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
                lane_dump(&mut net, &nodes, &hosts, &l, w)
            );
        }
    }
}

/// Expiry is a hard upper bound on visibility (spec/crdt.md §4.7): read as the API reads (after
/// `expire_due`), no node shows a value at or past its write's expiry, online or not.
fn churn_expiry_check(net: &mut Net, nodes: &[usize], w: Tid, dies: &BTreeMap<String, u64>, seed: u64, step: u64, log: &[String]) {
    let now = net.now();
    for &n in nodes {
        net.sync(n).expire_due();
        for ak in [CURSOR, FLAG] {
            let read = format!("{:?}", net.eph_read(n, w, ak));
            for (v, at) in dies {
                if *at <= now && read.contains(&format!("{v:?}")) {
                    panic!("seed {seed} step {step}: node {n} reads {v} {} ms past its expiry: {read}\n{}", now - at, log.join("\n"));
                }
            }
        }
    }
}

// spec/sync.md §9 (superseded expiring writes, randomized): holders read alike after random
// expiring writes, removals, resets, undos, demotions, partitions and restarts
#[test]
fn random_churn_converges_spec_sync_9() {
    for seed in 0..2 {
        random_churn_run(seed);
    }
}

// the same over more seeds (tier 2): OSIS_EPH_SEEDS (default 200) from OSIS_EPH_START
#[test]
#[ignore]
fn random_churn_converges_large() {
    let name = "ephemeral::random_churn_converges_large";
    eph_seeds().run(name, |seed| eph_replay(name, seed), random_churn_run);
}

// spec/sync.md §6 (a writer stamps every ephemeral entry it uploads; held at a host only as
// learned on the current connection; random churn seed 154 shrunk): a restarted author's
// commit, invalid while it is demoted, is fetched back by the holders to wait apart; the hosts
// restart and lose it, the admin too; once the author is promoted the holders hold it valid
// again under a stamp of a write key from before, and must put it back (not marked present at
// the host it waited on, stamped under the current key), so a node offline all along and
// restarted gets it at the end
#[test]
fn promoted_after_hosts_restart_reaches_hosts_spec_sync_6() {
    let mut net = Net::new();
    let hosts = vec![net.add_host(), net.add_host()];
    let nodes: Vec<usize> = (0..4).map(|i| net.node(1 + i, &hosts)).collect();
    let (a, b, d) = (nodes[0], nodes[1], nodes[3]);
    let g = net.group(a, &[(b, Role::Write), (nodes[2], Role::Write), (d, Role::Write)], &hosts);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let mut m = Mutation::new();
    m.set(w, &eph(FLAG), &s("kept")).unwrap();
    net.engine(b).write(m).unwrap();
    net.feed(b, Event::Local);
    net.run();
    assert_eq!(net.eph_read(d, w, FLAG), Some(s("kept")));
    // the author holds it as an earlier session's commit
    net.restart(b, 50);
    net.set_online(d, false);
    // from here every node reaches host 0 only, where the holders wait on it
    for n in &nodes {
        net.blocked.insert((*n, hosts[1]));
        net.drop_link(*n, hosts[1]);
    }
    net.advance(15_000);
    let tb = net.tid(b);
    let edge = |role| osis_schema::core_types::Edge { role, until: None, invite: None, since: None, tied: None, keyset: None };
    let demote = osis_node::flows::Demotion { holder: tb, new: Some(edge(Role::Read)), presync: osis_node::flows::PreSync::Synced, keep: None };
    let done = net.engine(a).demote(&g, &demote).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    for _ in 0..3 {
        net.advance(15_000);
    }
    assert_eq!(net.eph_read(a, w, FLAG), None, "invalid while its author is demoted");
    for h in &hosts {
        net.restart_host(*h);
    }
    // the admin forgets it: only the waiting holders can put it back
    net.restart(a, 52);
    net.advance(15_000);
    let done = net.engine(a).grant(&g, &tb, &edge(Role::Write)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    for _ in 0..3 {
        net.advance(15_000);
    }
    assert_eq!(net.eph_read(nodes[2], w, FLAG), Some(s("kept")), "valid again");
    // memory lost: only the hosts can give it back
    net.restart(d, 51);
    net.set_online(d, true);
    for _ in 0..3 {
        net.advance(15_000);
    }
    assert_eq!(net.eph_read(d, w, FLAG), Some(s("kept")), "back at the hosts");
}

// the harness: a node restarted while its host's Hello is still on the way gets nothing of
// the old connection on the new one of the same number (`random_window_inflight_large` seed
// 3300065: the stale Hello's challenge made every Open there refused, so the restarted node never
// reopened the label at that host)
#[test]
fn restart_mid_handshake_reopens() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    net.restart(a, 50);
    net.feed(a, Event::Local);
    assert!(net.conn_to(a, host).is_some(), "dialed, the Hello queued");
    net.restart(a, 51);
    net.run();
    let d = net.sync(a).describe();
    assert!(!d.is_empty() && d.iter().all(|x| x.contains(": Open")), "{d:?}");
}

// spec/data-model.md §1 (two nodes persisting one ephemeral thing both carry its record,
// idempotent): a synced window under an ephemeral workspace is persisted by both holders while
// apart; on reconnect both hold one durable thing (same tid, chain durable), one placement, and
// the ephemeral aspects still merged
#[test]
fn concurrent_persist_one_thing_spec_data_model_1() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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
    let (s1, s2) = (net.add_host(), net.add_host());
    let a = net.node(1, &[s1]);
    let cap = 400_000;
    let b = net.add_node(2, SyncConfig { hosts: vec![net.address(s1), net.address(s2)], ephemeral_bytes: cap, ..SyncConfig::default() });
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
    let future = forge_memory(&mut net, a, w, &ak, s("from the future"));
    net.engine(a).set_clock_offset(0);
    let (_, ev) = sealed(&mut net, a, g, &future.blob, Some(&wk), 1);
    let acts = push(&mut net, b, s1, l, vec![ev]);
    net.actions(b, acts);
    net.run();
    assert!(!net.engine(b).holds_memory(&future.id), "not held");
    assert_eq!(net.eph_read(b, w, STATE), Some(s("w")));
    let entries = net.sync(b).ephemeral_entries(&l);
    let at_s2 = net.hosts[s2].hub.store().ephemeral_bytes(&l);
    // commits under an author nobody here knows, stamped by a writer
    let rx = net.listen(b);
    let xt = net.tid(x);
    for i in 0..60 {
        let c = forge_memory(&mut net, x, xt, &ak, s(&format!("junk {i} {}", "j".repeat(2_000))));
        let (_, ev) = sealed(&mut net, a, g, &c.blob, Some(&wk), 10 + i);
        let acts = push(&mut net, b, s1, l, vec![ev]);
        net.actions(b, acts);
    }
    net.run();
    assert!(net.sync(b).ephemeral_pending_bytes(&l) <= cap / 4, "a share of the cap: {}", net.sync(b).ephemeral_pending_bytes(&l));
    assert!(net.sync(b).ephemeral_pending_bytes(&l) > 0, "kept apart while it waits");
    assert!(rx.try_iter().any(|e| matches!(e, osis_node::Event::Diagnostic(d) if d.kind == osis_node::DiagnosticKind::EphemeralRefused)), "reported");
    assert_eq!(net.sync(b).ephemeral_entries(&l), entries, "nothing unverified in the lane");
    assert_eq!(net.hosts[s2].hub.store().ephemeral_bytes(&l), at_s2, "nothing spread to the other host");
}

// spec/sync.md §9 (security review L2): a replay of an entry its author's held valid cover
// absorbs is not held again, and a writer deletes it where it was found
#[test]
fn replayed_covered_entry_dropped_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let l = net.label(a);
    let wk = write_key(&mut net, a, g);
    let ak = osis_base::Ak::new(NOTES).unwrap();
    let old = forge_memory(&mut net, a, w, &ak, Value::Map(BTreeMap::from([(s("k"), s("old"))])));
    let (id, ev) = sealed(&mut net, a, g, &old.blob, Some(&wk), 1);
    let acts = push(&mut net, b, host, l, vec![ev.clone()]);
    net.actions(b, acts);
    net.run();
    assert!(net.engine(b).holds_memory(&old.id));
    let acts = net.sync(a).compact_ephemeral_now().unwrap();
    net.actions(a, acts);
    net.run();
    assert!(!net.engine(b).holds_memory(&old.id), "covered by its author");
    let acts = push(&mut net, b, host, l, vec![ev]);
    assert!(!net.engine(b).holds_memory(&old.id), "a replay is not held again");
    let conn = net.conn_to(b, host).unwrap();
    let deletes: Vec<osis_base::BlobId> = sent(&acts, conn).into_iter().flat_map(|m| if let osis_proto::Message::Delete { items, .. } = m { items.into_iter().map(|i| i.blob).collect() } else { vec![] }).collect();
    assert_eq!(deletes, vec![id], "deleted where it came back");
    net.actions(b, acts);
    net.run();
}

// spec/permissions.md §5.2 (parts are judged by what the holder has of the timeline): a memory
// commit invalid on arrival joins nothing; one by a writer promoted meanwhile (a promotion the
// node had not seen) joins once the durable set makes it valid
#[test]
fn invalid_on_arrival_held_once_valid_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let r = net.node(2, &[host]);
    let d = net.node(3, &[host]);
    let g = net.group(a, &[(r, Role::Read), (d, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let ak = osis_base::Ak::new(NOTES).unwrap();
    let junk = forge_memory(&mut net, r, w, &ak, Value::Map(BTreeMap::from([(s("r"), s("junk"))])));
    deliver(&mut net, d, &junk.blob);
    assert_eq!(notes(&mut net, d, w).get("r"), None, "a reader's write: not joined");
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
    let ok = forge_memory(&mut net, r, w, &ak, Value::Map(BTreeMap::from([(s("r"), s("ok"))])));
    deliver(&mut net, d, &ok.blob);
    assert_eq!(notes(&mut net, d, w).get("r"), None, "promotion not seen here yet");
    net.set_online(d, true);
    net.run();
    net.advance(60_000);
    assert_eq!(notes(&mut net, d, w).get("r").map(String::as_str), Some("ok"), "valid now: joined; the earlier one still invalid");
}

// notes/ephemeral.md Bounds, notes/ephemeral.md Own covers: entries refused for a node's cap are
// fetched again once its bytes drop (here another's write expires): the label is reconciled at
// the next periodic pass instead of staying short until a restart. The cap fits the cursor and
// the big write decoded (`osis_crdt::decoded_bound`: strings, so mostly their bytes), not both
#[test]
fn capped_label_reconciles_once_room_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let x = net.node(2, &[host]);
    let b = net.add_node(3, SyncConfig { hosts: vec![net.address(host)], ephemeral_bytes: 330_000, ..SyncConfig::default() });
    let g = net.group(a, &[(x, Role::Write), (b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "doc");
    net.run();
    let l = net.label(a);
    net.eph_write_expiring(x, t, &eph("doc:cursor.0~"), s(&"c".repeat(50_000)), Some(5_000));
    net.run();
    assert!(net.eph_read(b, t, "doc:cursor.0~").is_some());
    net.eph_write(a, t, &crate::common::ak("doc:big.0~"), s(&"b".repeat(40_000)));
    net.run();
    assert_eq!(net.eph_read(b, t, "doc:big.0~"), None, "refused for the cap");
    net.advance(5_000);
    assert_eq!(net.eph_read(b, t, "doc:cursor.0~"), None);
    assert!(net.sync(b).ephemeral_bytes(&l) < 1_000);
    net.advance(SyncConfig::default().resync_ms + 1_000);
    assert_eq!(net.eph_read(b, t, "doc:big.0~"), Some(s(&"b".repeat(40_000))), "fetched again");
}

// spec/sync.md §9 (ephemeral parts on core aspects; security review L3): a writer's ephemeral
// part on a core aspect other than `group.0` (here `reach.0`) is invalid: never joined
#[test]
fn core_aspect_part_refused_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "durable");
    net.run();
    let ak = osis_base::Ak::new("reach.0").unwrap();
    let forged = forge_memory(&mut net, a, t, &ak, osis_schema::Codec::to_value(&ct::Reach { dialable: [1; 32], relays: vec![], lan_secret: [2; 32] }));
    deliver(&mut net, b, &forged.blob);
    assert_eq!(net.eph_read(b, t, "reach.0"), None, "not joined");
}

// open question of the step 3 review: a device reachable only through a co-reader peer gets the
// signals that peer receives from a host, and its own reach the host's devices; each once
#[test]
fn signals_through_co_reader_peer_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    for (n, k) in [(b, 0xb5), (c, 0xc5)] {
        let acts = net.sync(n).publish_reach([k; 32], vec!["https://relay.example".into()]).unwrap();
        net.actions(n, acts);
    }
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    // c loses the host: only b's peer link is left
    net.blocked.insert((c, host));
    net.restart(c, 33);
    net.advance(10_000);
    let (ra, rb, rc) = (net.listen(a), net.listen(b), net.listen(c));
    net.eph_write(a, t, &crate::common::ak("t:ring.0*"), s("from a"));
    net.run();
    assert_eq!(fired(&rb).len(), 1);
    assert_eq!(fired(&rc).len(), 1, "through the co-reader peer, once");
    net.eph_write(c, t, &crate::common::ak("t:ring.0*"), s("from c"));
    net.run();
    assert_eq!(fired(&rb).len(), 1);
    assert_eq!(fired(&ra).iter().filter(|x| x.2 == s("from c")).count(), 1, "the peer passes it to the host, once");
}

// spec/sync.md §4 (ephemeral entries are held in memory only): an ephemeral entry announced
// without its bytes (above the inline limit) is fetched and goes to the lane once its prefix
// shows its class; no sync record of it stays (one did, and a restart then counted it as held)
#[test]
fn announced_ephemeral_leaves_no_sync_record_spec_sync_4() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.add_node(2, SyncConfig { hosts: vec![net.address(host)], inline_limit: 0, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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

/// Bytes nodes send to the host while `b` writes 20 notes one by one, after `a` wrote `stuck`
/// bytes in one write (`a` holds an own entry the host refuses for good when it exceeds the cap).
fn bytes_under_stuck_entry(stuck: usize) -> usize {
    let mut net = Net::new();
    let host = net.add_host_with(osis_host::HostPolicy { ephemeral_bytes: 12_000, ..osis_host::HostPolicy::default() });
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let mut m = Mutation::new();
    m.op(w, &eph("win:big.0~"), PathOp { path: Vec::new(), op: Op::Set(s(&"x".repeat(stuck))) }).unwrap();
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

// spec/sync.md §5 (a refusal triggers nothing but the periodic retry): an own entry the host
// refuses for good (one write over the cap) is not re-uploaded at every other node's write (it
// was, by the compaction a refusal triggered: 5.5x the bytes)
#[test]
fn host_cap_stuck_entry_no_churn_spec_sync_9() {
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

// spec/sync.md §9 (holders upload what a host lacks): an entry a full host refused, that no
// compaction can cover (it expires), goes up again once room is made without a deletion (b's
// entries expire there), at the periodic pass (it stayed out until a reconnect: sim
// `ephemeral_capped` seed 14)
#[test]
fn host_cap_refused_entry_retried_spec_sync_9() {
    let cap = 8_000;
    let mut net = Net::new();
    let host = net.add_host_with(osis_host::HostPolicy { ephemeral_bytes: cap, ..osis_host::HostPolicy::default() });
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    let held = |net: &Net| net.hosts[host].hub.store().ephemeral_bytes(&l);
    // b fills it with entries that expire soon, until one is refused
    for i in 0.. {
        assert!(i < 20, "nothing refused under a {cap} B cap");
        let before = held(&net);
        expiring(&mut net, b, t, &format!("win:b{i}.0~"), 1_500, 20_000);
        net.run();
        if held(&net) == before {
            break;
        }
    }
    expiring(&mut net, a, t, "win:a.0~", 1_500, 600_000);
    net.run();
    assert!(net.eph_read(b, t, "win:a.0~").is_none(), "refused ({} B held, cap {cap})", held(&net));
    net.advance(61_000);
    assert!(net.eph_read(b, t, "win:a.0~").is_some(), "a's write reached b");
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
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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
    // a restarted holder gets the same back from the host
    net.restart(b, 21);
    net.advance(10_000);
    assert_eq!(notes(&mut net, b, w), want);
}

/// `authors` nodes in one group move their cursors every 33 ms (30 a second) for `secs`
/// simulated seconds, each move a fresh entry under the author's own key of one cursor map
/// expiring 30 s out (what `osis::KeepAlive::set` writes), messages taking one 33 ms round per hop
/// (a 66 ms round trip), at a host whose delete rates and ephemeral cap are the defaults scaled
/// to the run (the rates to its share of their minute window, the cap to its share of the
/// expiry, what the entries of a run that short would fill): no upload is refused, every author
/// stays visible at every node throughout, and at the end every node reads every author's latest
/// cursor and the host holds one entry per author. Returns (uploads, deletes, the host's peak
/// ephemeral bytes, its cap).
fn many_authors_run(authors: usize, secs: u64) -> (usize, usize, u64, u64) {
    const E: u64 = 30_000;
    let mut net = Net::new();
    let window_ms = secs * 1000;
    let d = osis_host::HostPolicy::default();
    let deletes = (d.deletes as u64 * window_ms / 60_000) as u32;
    let cap = d.ephemeral_bytes * window_ms.min(E) / E;
    let host = net.add_host_with(osis_host::HostPolicy { window_ms, deletes, ephemeral_bytes: cap, ..d });
    let ns: Vec<usize> = (0..authors).map(|i| net.node(1 + i as u64, &[host])).collect();
    let grants: Vec<(usize, Role)> = ns[1..].iter().map(|n| (*n, Role::Write)).collect();
    let g = net.group(ns[0], &grants, &[host]);
    let t = net.item(ns[0], g, g, "doc");
    net.run();
    let l = net.label(ns[0]);
    let live = |net: &Net| osis_proto::LabelStore::live_ids(net.hosts[host].hub.store(), &l).unwrap().len();
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
        peak = peak.max(net.hosts[host].hub.store().ephemeral_bytes(&l));
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
    assert!(peak < cap, "the host's ephemeral bytes reached {peak} of its cap {cap}");
    (up2 - up, del2 - del, peak, cap)
}

// spec/sync.md §9 (an expiring commit superseded by its author's later writes is dropped and its
// author deletes it, coalescing while an upload is in flight), §5 (hosts rate-limit deletes and
// cap ephemeral bytes per label): 4 authors at 30 cursor moves a second, scaled to a 1 s window
// (10 authors took 4.5-12 s: tier 2 below)
#[test]
fn many_authors_under_host_rates_spec_sync_9() {
    let (up, del, peak, cap) = many_authors_run(4, 1);
    eprintln!("4 authors, 1 s: {up} uploads, {del} deletes, peak {peak} of {cap} ephemeral bytes");
}

// tier 2: 10 authors for 1 s, then for a whole simulated minute at the default policy
#[test]
#[ignore]
fn many_authors_under_host_rates_large() {
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
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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
    let cs = take_memory(&mut net, a);
    assert_eq!(cs.len(), 1, "one commit for five moves");
    assert_eq!(cs[0].1.header.aspects.iter().map(|x| x.expires).collect::<Vec<_>>(), vec![Some(last)], "the last move's");
}

// spec/sync.md §9 (a superseded commit's writes are held value-less at every node, its author
// included): once a holder removes the newer entry at the key, the author and the holder both read
// the key gone; the older entry does not show again at the author
#[test]
fn superseded_stays_gone_when_newer_removed_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let me = s(&net.tid(a).to_string());
    let held = |net: &mut Net, n: usize| net.engine(n).memory_commits().len();
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

// spec/sync.md §9 (superseded expiring writes, core keys alike): a placement (`placed.0~`) made
// again after an expiring unplace supersedes the first placement at every node. Once the unplace
// expired and the second placement is undone, the item is unplaced at the author and the holder
// alike (a node keeping the first placement read it placed again until that one expired)
#[test]
fn placement_superseded_like_any_write_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let write = |net: &mut Net, op: Op, ms: u64| {
        let mut m = Mutation::new();
        m.op(g, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op }).unwrap();
        m.expires(g, &ct::GROUP, osis_base::WallMs(net.now() + ms)).unwrap();
        let id = net.engine(a).write(m).unwrap().unwrap().id;
        local(net, a);
        net.run();
        net.advance(33);
        id
    };
    // the window's own placement (no expiry) goes first: unplaced, then placed expiring
    write(&mut net, Op::Remove(Value::Tid(w)), 60_000);
    write(&mut net, Op::Add(Value::Tid(w)), 60_000);
    write(&mut net, Op::Remove(Value::Tid(w)), 5_000);
    let again = write(&mut net, Op::Add(Value::Tid(w)), 60_000);
    let placed = |net: &mut Net, n: usize| net.engine(n).groups_of(&w).contains(&g);
    assert!(placed(&mut net, a) && placed(&mut net, b));
    let me = net.tid(a);
    net.engine(a).revert_change(again, me).unwrap();
    local(&mut net, a);
    net.run();
    net.advance(10_000);
    net.run();
    for n in [a, b] {
        assert!(!placed(&mut net, n), "node {n}: the first expiring placement went with the second");
    }
}

// spec/sync.md §9 (a superseding part expires): a plain move after an expiring one supersedes
// nothing. Else: b drops the expiring move for the plain one, a's cover absorbs the plain one,
// and c, offline meanwhile, gets only the cover beside the move it held; b's removal of the key
// tombstones the plain entry alone and the expiring move read again at c alone
#[test]
fn superseding_part_expires_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[host]);
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
// supersedes nothing (it outlives that entry); holders read as the author throughout
#[test]
fn superseding_needs_later_expiry_and_own_records_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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
    // the entry's creation vanishes at its expiry, the `Set` stays (spec/crdt.md §4.7,
    // ephemeral data: as if the move had never been applied, its record repeats the key)
    net.advance(30_000);
    assert_eq!((at(&mut net, a), at(&mut net, b)), (want("into"), want("into")), "the set outlives the entry it wrote into");
    net.advance(31_000);
    assert_eq!((at(&mut net, a), at(&mut net, b)), (None, None), "every write gone: the aspect as never written");
}

// spec/sync.md §9: signals are never held back or merged: each signal write sent while a plain
// upload of the label is in flight is its own relay-only commit at once, and each fires once at B
#[test]
fn signals_not_held_back_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let w = window(&mut net, a, g, "busy");
    let up = uploads_sent(&net);
    let rb = net.listen(b);
    for i in 0..5 {
        net.eph_write(a, t, &crate::common::ak("t:ring.0*"), s(&format!("ding {i}")));
    }
    assert_eq!(uploads_sent(&net) - up, 5, "one relay-only upload per signal, none waits");
    net.run();
    let got: Vec<Value> = fired(&rb).into_iter().filter(|(x, ak, _, _)| *x == t && ak == "t:ring.0*").map(|(_, _, v, _)| v).collect();
    assert_eq!(got.len(), 5, "{got:?}");
    assert_eq!(net.eph_read(b, w, STATE), Some(s("busy")));
}

// spec/sync.md §9 (own plain writes wait only while every connection of the label has an own
// upload unanswered): with one host slow to answer, each edit reaches B through the other at
// once
#[test]
fn slow_host_holds_nothing_back_spec_sync_9() {
    let mut net = Net::new();
    let (fast, slow) = (net.add_host(), net.add_host());
    let a = net.node(1, &[fast, slow]);
    let b = net.node(2, &[fast]);
    let g = net.group(a, &[(b, Role::Write)], &[fast, slow]);
    net.run();
    let w = window(&mut net, a, g, "shared");
    net.run();
    net.held_hosts.insert(slow);
    let mut want = BTreeMap::new();
    for i in 0..5 {
        note(&mut net, a, w, &format!("k{i}"), &format!("v{i}"));
        want.insert(format!("k{i}"), format!("v{i}"));
        net.run();
        assert_eq!(notes(&mut net, b, w), want, "edit {i} reached B through the fast host");
    }
    net.release();
    net.run();
    assert_eq!(notes(&mut net, b, w), want);
}

/// A writes notes while host `slow` holds its answers, then compacts: the covered entries'
/// uploads are unanswered there. `reconnect`: the connection to `slow` ends before it answers
/// and is made again; else `slow` answers. B only reads (it deletes nothing). Returns what each
/// host then holds under the label.
fn covered_while_slow(reconnect: bool) -> (BTreeSet<osis_base::BlobId>, BTreeSet<osis_base::BlobId>) {
    let mut net = Net::new();
    let (fast, slow) = (net.add_host(), net.add_host());
    let a = net.node(1, &[fast, slow]);
    let b = net.node(2, &[fast]);
    let g = net.group(a, &[(b, Role::Read)], &[fast, slow]);
    net.run();
    let w = window(&mut net, a, g, "shared");
    net.run();
    net.held_hosts.insert(slow);
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
    (net.host_ids(fast, &l).into_iter().collect(), net.host_ids(slow, &l).into_iter().collect())
}

// spec/sync.md §9 (a covered entry deleted where it was uploaded, once that upload is
// answered): a slow host ends holding what the fast one does
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


// spec/crdt.md §4.7, spec/sync.md §9 (a commit's records serve its other parts): an
// ephemeral commit whose expiring parts went is dropped with its `created.0` parts, at its author
// and at holders, and the record of a thing nothing else uses goes with it; a copy received
// again after its expiry is not held. Expiring things do not pile up in memory.
#[test]
fn expired_commit_leaves_no_records_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let held = |net: &mut Net, n: usize| net.engine(n).memory_commits().len();
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
            blobs.extend(take_memory(&mut net, a).into_iter().map(|c| c.1));
            made.push(w);
        }
        // taken by hand: b gets them directly
        for bl in &blobs {
            deliver(&mut net, b, &bl.clone());
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
            deliver(&mut net, b, bl);
            deliver(&mut net, a, bl);
            assert!(!net.engine(b).holds_memory(&bl.id()) && !net.engine(a).holds_memory(&bl.id()), "a copy after expiry vanishes at once");
        }
        net.run();
        assert_eq!((held(&mut net, a), held(&mut net, b)), base, "a copy after expiry is not held");
        assert!(made.iter().all(|w| net.engine(b).ephemeral_thing(w).is_none()));
        // a later write of a thing whose record went at b carries the record again (placed
        // again: its placement expired, so it was in no labeled closure)
        let mut m = Mutation::new();
        m.op(g, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(Value::Tid(made[0])) }).unwrap();
        m.set(made[0], &eph(STATE), &s("late")).unwrap();
        net.engine(a).write(m).unwrap();
        for c in take_memory(&mut net, a) {
            deliver(&mut net, b, &c.1);
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

// spec/commits.md §2 (a memory delta is never paged: it must fit a blob alone): a batch whose
// delta of one aspect does not fit a blob is refused whole, nothing of it applied or sent; one
// whose delta fits goes
#[test]
fn delta_past_a_blob_refused_spec_commits_2() {
    let mut net = Net::new();
    let cap: u64 = 64 << 20;
    let host = net.add_host_with(osis_host::HostPolicy { ephemeral_bytes: cap, ..osis_host::HostPolicy::default() });
    let a = net.node(1, &[host]);
    let b = net.add_node(2, SyncConfig { hosts: vec![net.address(host)], ephemeral_bytes: cap, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let big = "v".repeat(5 << 20);
    let mut m = Mutation::new();
    for k in ["x", "y"] {
        m.op(w, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s(k))], op: Op::Set(s(&big)) }).unwrap();
    }
    m.set(w, &eph(STATE), &s("next")).unwrap();
    let err = net.engine(a).write(m).unwrap_err().to_string();
    assert!(err.contains("does not fit a blob"), "{err}");
    assert_eq!(net.eph_read(a, w, STATE), Some(s("w")), "nothing of the batch applied");
    local(&mut net, a);
    net.run();
    assert!(notes(&mut net, b, w).is_empty());
    let fits = "v".repeat(1 << 20);
    let mut m = Mutation::new();
    m.op(w, &eph(NOTES), PathOp { path: vec![PathSeg::Key(s("y"))], op: Op::Set(s(&fits)) }).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    assert_eq!(notes(&mut net, b, w).get("y").map(String::len), Some(fits.len()), "one that fits goes");
}


// spec/permissions.md §1 (`MAX_OWNER_DEPTH`): an ephemeral thing's whole owner chain counts,
// its durable part included: a write on one at the cap applies at its author and a receiver, one
// a link past it is refused at its author and, forged, invalid at a receiver (the old lane
// counted only the links above the nearest durable thing, issues/eph-write-depth.md)
#[test]
fn ephemeral_chain_depth_counts_durable_links_spec_permissions_1() {
    use osis_base::format::MAX_OWNER_DEPTH;
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    // g is one link below a's key; durable things down to one link above the cap
    let mut owner = g;
    for _ in 2..MAX_OWNER_DEPTH {
        owner = net.item(a, g, owner, "d");
    }
    net.run();
    let e = net.engine(a);
    let mut m = Mutation::new();
    let at_cap = e.new_thing(&mut m, owner);
    m.set(at_cap, &eph(STATE), &s("ok")).unwrap();
    e.write(m).unwrap();
    let mut m = Mutation::new();
    let past = e.new_thing(&mut m, at_cap);
    m.set(past, &eph(STATE), &s("deep")).unwrap();
    let err = e.write(m).unwrap_err().to_string();
    assert!(err.contains("no permission"), "past the cap at its author: {err}");
    for (_, blob) in take_memory(&mut net, a) {
        deliver(&mut net, b, &blob);
    }
    assert_eq!(net.eph_read(b, at_cap, STATE), Some(s("ok")), "at the cap: held at a receiver");
    let e = net.engine(a);
    let mut m = Mutation::new();
    let past = e.new_thing(&mut m, at_cap);
    m.set(past, &eph(STATE), &s("deep")).unwrap();
    e.commit_in_memory_hostile(m).unwrap().unwrap();
    let forged = osis_commit::CommitBlob::decode(&e.take_forged().unwrap()).unwrap();
    deliver(&mut net, b, &forged);
    assert_eq!(net.eph_read(b, past, STATE), None, "past the cap: invalid at a receiver");
}

// spec/sync.md §5 (a new sync key ends an open), §6 (a first Sync lists the held ephemeral
// entries as gained): a Sync refused 8 because a read rotation landed between its Open and it
// listed nothing to the host, so the Sync after the reopen on the same connection lists them
// again (it counted the refused list as held there and never uploaded b's offline note).
#[test]
fn gained_announced_again_after_refused_sync_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let x = net.node(4, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write), (x, Role::Read)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    net.set_online(b, false);
    net.run();
    note(&mut net, b, w, "b", "1");
    net.hold_opened.insert(b);
    net.set_online(b, true);
    net.advance(10_000);
    let conn = net.conn_to(b, host);
    assert!(net.gained.get(&b).is_none_or(|v| v.is_empty()), "the first Sync waits behind the held Opened");
    let (at, bt, ct, xt) = (net.tid(a), net.tid(b), net.tid(c), net.tid(x));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write), (ct, Role::Write)]);
    remove_holder(e, g, xt, &rs, 9);
    net.run();
    net.release();
    net.run();
    assert_eq!(net.conn_to(b, host), conn, "same connection");
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
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let x = net.node(4, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write), (x, Role::Read)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    net.set_online(b, false);
    net.run();
    note(&mut net, b, w, "b", "1");
    let (at, bt, ct, xt) = (net.tid(a), net.tid(b), net.tid(c), net.tid(x));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write), (ct, Role::Write)]);
    remove_holder(e, g, xt, &rs, 9);
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
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    net.set_online(b, false);
    net.run();
    note(&mut net, b, w, "b", "1");
    let bt = net.tid(b);
    let edge = osis_schema::core_types::Edge { role: Role::Read, until: None, invite: None, since: None, tied: None, keyset: None };
    let d = osis_node::flows::Demotion { holder: bt, new: Some(edge), presync: osis_node::flows::PreSync::Synced, keep: None };
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
// once the writer reads the rotation the cover lands and the absorbed entries go at the host.
// Code 9 carries no head (spec/wire.md §11.2): the writer learns it by push, or unsubscribed by
// its next resync's Sync.
#[test]
fn cover_across_unread_rotation_lands_spec_sync_9() {
    cover_across_unread_rotation(true);
    cover_across_unread_rotation(false);
}

fn cover_across_unread_rotation(subscribe: bool) {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.add_node(2, SyncConfig { hosts: vec![net.address(host)], subscribe, ..SyncConfig::default() });
    let c = net.node(3, &[host]);
    let x = net.node(4, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write), (x, Role::Read)], &[host]);
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
    remove_holder(e, g, xt, &rs, 9);
    net.run();
    let l = net.label(a);
    let before: BTreeSet<osis_base::BlobId> = net.host_ids(host, &l).into_iter().collect();
    let acts = net.sync(b).compact_ephemeral_now().unwrap();
    net.actions(b, acts);
    net.run();
    net.release();
    net.run();
    net.advance(60_000);
    let held_b = |net: &mut Net, n: usize| {
        let e = net.engine(n);
        e.memory_commits().into_iter().filter(|(id, _, _)| e.header(id).is_some_and(|h| h.author == bt && h.aspects.iter().any(|x| x.ak.as_str() == NOTES))).map(|(id, _, _)| e.header(&id).is_some_and(|h| h.kind.is_compaction())).collect::<Vec<bool>>()
    };
    assert_eq!(held_b(&mut net, c), vec![true], "c holds b's snapshot of the notes alone");
    assert_eq!(notes(&mut net, c, w).len(), 4);
    let after: BTreeSet<osis_base::BlobId> = net.host_ids(host, &l).into_iter().collect();
    assert!(after.difference(&before).count() >= 1, "the snapshot landed");
    assert!(before.difference(&after).count() > 0, "what it absorbs is deleted at the host");
}

// spec/sync.md §5, §9: a plain delete of an absorbed entry sent before the writer reads a
// rotation is refused 9; it goes again under the next key and the entry leaves the host. The
// writer's last note is in flight when it compacts: its delete waits for the OK, then for the
// cover's (`orphans`, `waiting`), so it goes alone after the rotation. The admin holds no
// ephemeral entries of others, nor the writer it removes: the writer alone deletes.
#[test]
fn delete_across_unread_rotation_retried_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.add_node(1, SyncConfig { hosts: vec![net.address(host)], ephemeral_bytes: 0, ..SyncConfig::default() });
    let b = net.node(2, &[host]);
    let c = net.add_node(3, SyncConfig { hosts: vec![net.address(host)], ephemeral_bytes: 0, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    for i in 0..4 {
        note(&mut net, b, w, &format!("k{i}"), &format!("v{i}"));
        net.run();
    }
    let l = net.label(a);
    let before: BTreeSet<osis_base::BlobId> = net.host_ids(host, &l).into_iter().collect();
    net.held_to.insert(b);
    note(&mut net, b, w, "k4", "v4");
    net.run();
    let k4: Vec<osis_base::BlobId> = net.host_ids(host, &l).into_iter().filter(|i| !before.contains(i)).collect();
    assert_eq!(k4.len(), 1, "the last note landed");
    let acts = net.sync(b).compact_ephemeral_now().unwrap();
    net.actions(b, acts);
    net.run();
    let (at, bt, ct) = (net.tid(a), net.tid(b), net.tid(c));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write)]);
    remove_holder(e, g, ct, &rs, 9);
    net.run();
    net.release();
    net.run();
    net.advance(60_000);
    let after: BTreeSet<osis_base::BlobId> = net.host_ids(host, &l).into_iter().collect();
    assert!(!after.contains(&k4[0]), "the plain delete refused 9 went again under the next key");
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
    // `t:reg.0~` for the memory modes, `t:reg.0` durable
    let mut m = Mutation::new();
    let me = lp.peers[0].engine.tid();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &crate::common::TAGS, &Value::Set(Default::default())).unwrap();
    lp.peers[0].commit(m).unwrap();
    let eph = crate::common::ak("t:reg.0~");
    let reg = if matches!(mode.as_str(), "ephemeral" | "memory") { eph.clone() } else { crate::common::ak("t:reg.0") };
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
// nonce), ctr)`, counted per aspect from 1, owned by that source, never a node's; no demotion
// frontier lists it.
#[test]
fn memory_commit_session_form_spec_commits_3() {
    let mut lp = crate::common::net(1, 5);
    let t = crate::common::new_thing(&mut lp, 0);
    let reg = crate::common::ak("t:tags.0~");
    let e = &mut lp.peers[0].engine;
    let me = e.tid();
    let session = e.ephemeral_session();
    let mut ids = Vec::new();
    for i in 0..2 {
        let mut m = Mutation::new();
        m.set(t, &eph("t:tags.0~"), &Value::Set([Value::Str(format!("v{i}"))].into())).unwrap();
        ids.push(e.commit_in_memory(m).unwrap().unwrap());
    }
    let h = e.header(&ids[1]).unwrap();
    assert_eq!(h.form, osis_commit::Form::Session(session.nonce));
    assert_eq!(h.ephemeral, Some(osis_commit::EphClass::Plain));
    let a = h.aspects.iter().find(|a| a.ak == reg).unwrap();
    assert_eq!((a.lo, a.hi), (2, 3), "counters per aspect and session, from 1");
    let src = osis_crdt::Source::session(session);
    // a demotion's frontier lists no memory commit (spec/permissions.md §5.2)
    let scope = osis_perm::DemotionScope { roles: Default::default(), content: [(me, [t].into())].into() };
    let now = e.now();
    assert!(e.frontier(&scope, now).unwrap().commits.iter().all(|c| !ids.contains(c)));
    assert_eq!(e.core.commit_of(&t, &reg, &osis_crdt::Dot::new(src.clone(), 1)), Some(ids[0]));
    assert_eq!(e.core.commit_of(&t, &reg, &osis_crdt::Dot::new(src, 2)), Some(ids[1]));
    assert_eq!(e.get(&t, &reg).unwrap(), Some(Value::Set([Value::Str("v1".into())].into())));
}

// spec/commits.md §2 (records beside the deltas), spec/data-model.md §1: a thing a memory commit
// makes is held as a memory-class record; the commit carries no `created.0` aspect, its parts carry
// the thing's record and its memory owner chain; the first durable write on the thing persists
// the chain (`created.0` in that commit); a restart keeps only what was persisted.
#[test]
fn memory_records_beside_deltas_spec_commits_2() {
    let mut lp = crate::common::net(1, 5);
    let t = crate::common::new_thing(&mut lp, 0);
    let tags = crate::common::ak("t:tags.0~");
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let top = e.new_thing(&mut m, t);
    let leaf = e.new_thing(&mut m, top);
    let lone = e.new_thing(&mut m, t);
    m.set(leaf, &eph("t:tags.0~"), &Value::Set([Value::Str("x".into())].into())).unwrap();
    let id = e.commit_in_memory(m).unwrap().unwrap();
    let blob = e.run(|tx| tx.get_commit(&id)).unwrap().unwrap();
    assert!(blob.header.aspects.iter().all(|a| a.ak.as_str() != "created.0"));
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
    let created: Vec<osis_base::Tid> = h.aspects.iter().filter(|a| a.ak.as_str() == "created.0").map(|a| a.tid).collect();
    assert_eq!(created.len(), 2);
    assert!(created.contains(&leaf) && created.contains(&top));
    assert!(e.core.durable_created(&leaf).is_some() && e.core.durable_created(&top).is_some() && e.core.durable_created(&lone).is_none());
    lp.peers[0].restart(6).unwrap();
    let e = &mut lp.peers[0].engine;
    assert!(e.core.durable_created(&leaf).is_some() && e.core.durable_created(&top).is_some());
    assert!(e.core.created(&lone).is_none(), "an unpersisted memory thing is gone at restart");
    assert_eq!(e.get(&leaf, &crate::common::ak("t:reg.0")).unwrap(), Some(Value::Str("d".into())));
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
    m.set(t, &eph("t:tags.0~"), &Value::Set([Value::Str("x".into())].into())).unwrap();
    let id = e.commit_in_memory(m).unwrap().unwrap();
    assert!(e.take_changed().is_empty());
    assert_eq!(e.core.generation, generation);
    assert!(e.core.memory_generation > 0);
    assert_eq!(e.commit_ids(), ids);
    assert_eq!(e.core.durable_on(&(t, crate::common::ak("t:tags.0~"))).count(), 0);
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
    let tags = crate::common::ak("t:tags.0~");
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    m.set(t, &eph("t:tags.0~"), &Value::Set([Value::Str("x".into())].into())).unwrap();
    let at = osis_base::WallMs(e.now().0 + 1000);
    m.expires(t, &eph("t:tags.0~"), at).unwrap();
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
// deltas only, never beside the group's `placed.0~` delta (its nonce, its dedup secret, would show
// to the group's readers)
#[test]
fn placed_record_only_to_its_reader_spec_commits_2() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
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
    let built = take_memory(&mut net, a);
    let parts: Vec<(String, Tid, Vec<Tid>)> = built.iter().flat_map(|c| c.1.parts.iter().map(|p| { let a = &c.1.header.aspects[p.ai]; (a.ak.as_str().to_string(), a.tid, p.records.iter().map(|r| r.tid()).collect()) }).collect::<Vec<_>>()).collect();
    assert!(parts.iter().any(|(ak, t, rs)| ak == "placed.0~" && *t == g && !rs.contains(&w)), "{parts:?}");
    assert!(parts.iter().any(|(ak, t, rs)| ak == STATE && *t == w && rs.contains(&w)), "{parts:?}");
}

// spec/sync.md §9 (Caps: held ephemeral bodies counted at an estimate of what they take held):
// records beside a part are held as ephemeral things with it, so the pre-decode bound and the
// node cap count them (a holder padding a commit's parts with records cannot pass the cap)
#[test]
fn records_beside_parts_counted_spec_sync_9() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "x");
    let ak = osis_base::Ak::new(STATE).unwrap();
    let c = forge_memory(&mut net, a, w, &ak, s("y"));
    let mut padded = c.blob.clone();
    let mut junk: Vec<osis_base::CreationRecord> = (0..200u8).map(|n| osis_base::CreationRecord::Thing { owner: g, nonce: [n; 32], creator: None }).collect();
    junk.append(&mut padded.parts[0].records);
    junk.sort_by_key(osis_base::CreationRecord::tid);
    padded.parts[0].records = junk;
    let (plain, _) = osis_node::Engine::memory_bound(&c.blob);
    let (more, _) = osis_node::Engine::memory_bound(&padded);
    assert!(more >= plain + 200 * 50, "{plain} {more}");
    deliver(&mut net, b, &padded);
    assert!(net.engine(b).memory_charge(&c.id).unwrap() >= 200 * 50 * 2);
}

// spec/data-model.md §1 (an aspect's class is its schema lifetime; a durable write on an
// ephemeral thing persists it): a memory commit writing a durable-schema aspect is refused,
// nothing of it applied; the same value written durably on the memory thing persists the thing
// and survives a restart beside nothing of the thing's memory-class aspect
#[test]
fn memory_commit_durable_aspect_refused_spec_data_model_1() {
    let mut lp = crate::common::net(1, 5);
    let t = crate::common::new_thing(&mut lp, 0);
    let reg = crate::common::ak("t:reg.0");
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let leaf = e.new_thing(&mut m, t);
    m.set(leaf, &crate::common::REG, &Value::Str("m".into())).unwrap();
    assert!(matches!(e.commit_in_memory(m), Err(osis_node::Error::Misuse(_))));
    assert!(e.core.created(&leaf).is_none(), "nothing of a refused memory commit applies");
    let mut m = Mutation::new();
    let leaf = e.new_thing(&mut m, t);
    m.set(leaf, &eph("t:tags.0~"), &s("m")).unwrap();
    e.commit_in_memory(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.set(leaf, &crate::common::REG, &Value::Str("d".into())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[0].restart(6).unwrap();
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.get(&leaf, &reg).unwrap(), Some(Value::Str("d".into())));
    assert_eq!(e.get(&leaf, &crate::common::ak("t:tags.0~")).unwrap(), None, "the memory aspect is gone at restart");
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

/// Peer `i` writes `v` into the ephemeral `t:tags.0` of `t` as a memory commit.
fn memory_write(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: Tid, v: &str) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.op(t, &eph("t:tags.0~"), PathOp { path: Vec::new(), op: Op::Add(s(v)) }).unwrap();
    lp.peers[i].engine.commit_in_memory(m).unwrap().unwrap()
}

fn durable_tags(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: Tid) -> Option<Value> {
    lp.peers[i].engine.get(&t, &crate::common::ak("t:tags.0")).unwrap()
}

/// `memory_write` on the durable key `t:tags.0`: a writer breaking the marker rule (forged past
/// its own node's refusal).
fn memory_write_unmarked(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: Tid, v: &str) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.op(t, &crate::common::TAGS, PathOp { path: Vec::new(), op: Op::Add(s(v)) }).unwrap();
    let e = &mut lp.peers[i].engine;
    assert!(matches!(e.commit_in_memory(m.clone()), Err(osis_node::Error::Misuse(_))), "the writer refuses it");
    e.core.skip_writer_rules = true;
    let id = e.commit_in_memory(m).unwrap().unwrap();
    e.core.skip_writer_rules = false;
    id
}

fn memory_tags(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: Tid) -> Option<Value> {
    lp.peers[i].engine.get(&t, &crate::common::ak("t:tags.0~")).unwrap()
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
    m.set(w, &eph("t:tags.0~"), &s("x")).unwrap();
    let id = lp.peers[0].engine.commit_in_memory(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
    let faults = lp.peers[1].backend.faults().clone();
    faults.forbid_writes(true);
    // the durable path refuses it (no production caller yet: a writer cannot slip one in there)
    assert!(matches!(lp.deliver(1, &pk), Err(osis_node::Error::BadInput(_))));
    // the author is not known yet: pending, in memory
    let got = lp.peers[1].engine.ingest_memory(&pk.bytes, u64::MAX).unwrap();
    assert!(matches!(got, osis_node::Ingested::Pending(..)), "{got:?}");
    assert_eq!(faults.forbidden(), 0);
    faults.forbid_writes(false);
    lp.sync_all().unwrap();
    assert_eq!(memory_tags(&mut lp, 1, w), Some(s("x")), "applied once the author's chain arrived");
    let e = &mut lp.peers[1].engine;
    assert!(e.core.created(&w).is_some() && e.core.durable_created(&w).is_none());
    assert!(e.run(|tx| Ok(tx.txn.pending(None, 16)?)).unwrap().is_empty());
    faults.forbid_writes(true);
    assert!(matches!(lp.peers[1].engine.ingest_memory(&pk.bytes, u64::MAX).unwrap(), osis_node::Ingested::Duplicate(_)));
    let id2 = {
        let mut m = Mutation::new();
        m.set(w, &eph("t:tags.0~"), &s("y")).unwrap();
        lp.peers[0].engine.commit_in_memory(m).unwrap().unwrap()
    };
    let pk2 = lp.peers[0].engine.package(&id2).unwrap().unwrap();
    assert!(matches!(lp.peers[1].engine.ingest_memory(&pk2.bytes, u64::MAX).unwrap(), osis_node::Ingested::Applied(_)));
    assert_eq!(memory_tags(&mut lp, 1, w), Some(s("y")));
    // one waiting for drift is re-examined and applied in memory too
    lp.peers[0].clock.advance(2 * osis_base::format::MAX_DRIFT_MS);
    let id3 = memory_write(&mut lp, 0, w, "z");
    let pk3 = lp.peers[0].engine.package(&id3).unwrap().unwrap();
    assert!(matches!(lp.peers[1].engine.ingest_memory(&pk3.bytes, u64::MAX).unwrap(), osis_node::Ingested::Pending(_, osis_node::Reason::Drift)));
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

/// Peers 0, 1 and 2, durable state synced; 0 owns `d` and grants 1 and 2 write. Returns `d`.
fn memory_trio(seed: u64) -> (osis_node::local_peer::LocalPeer, Tid) {
    let mut lp = crate::common::net(3, seed);
    lp.sync_all().unwrap();
    let d = crate::common::new_thing(&mut lp, 0);
    for i in [1, 2] {
        let n = lp.peers[i].engine.tid();
        crate::common::set_edge(&mut lp.peers[0].engine, d, n, Some(crate::common::edge(Role::Write)), None);
    }
    lp.sync_all().unwrap();
    (lp, d)
}

// spec/commits.md §2 (class from the key): an aspect's storage class is its AK's lifetime marker,
// alike at every node: a memory part on an unmarked key is dropped alone whatever the receiver holds, at a node
// holding the aspect's durable deltas and at one holding none, which then writes the aspect
// durably and keeps it across a restart (was `repro_durable_write_on_memory_marked_aspect_lost`:
// the held-state rule kept the part there, and the later durable write went to memory)
#[test]
fn memory_part_on_unmarked_key_dropped_spec_commits_2() {
    let (mut lp, d) = memory_trio(33);
    let tags = crate::common::ak("t:tags.0");
    // 1 holds a durable delta of `t:tags.0`, 0 none
    let mut m = Mutation::new();
    m.set(d, &crate::common::TAGS, &Value::Set([s("durable")].into())).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    let id = memory_write_unmarked(&mut lp, 2, d, "memory");
    let pk = lp.peers[2].engine.package(&id).unwrap().unwrap();
    for i in [0, 1] {
        lp.peers[i].engine.ingest_memory(&pk.bytes, u64::MAX).unwrap();
        assert!(!lp.peers[i].engine.run(|tx| Ok(tx.txn.is_memory_aspect(&d, &tags))).unwrap(), "{i}: the aspect turned memory class");
    }
    assert_eq!(durable_tags(&mut lp, 0, d), None);
    assert_eq!(durable_tags(&mut lp, 1, d), Some(Value::Set([s("durable")].into())));
    let mut m = Mutation::new();
    m.set(d, &crate::common::TAGS, &Value::Set([s("zero")].into())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    for i in [0, 1] {
        lp.peers[i].restart(34 + i as u64).unwrap();
    }
    assert_eq!(durable_tags(&mut lp, 0, d), Some(Value::Set([s("zero")].into())), "the durable write survives a restart");
    assert_eq!(durable_tags(&mut lp, 1, d), Some(Value::Set([s("durable")].into())));
}

// spec/commits.md §2 (class from the key): the writer refuses a durable commit
// writing a `~` key; one forged past that has its part dropped alone at every receiver, the rest
// of the commit applies
#[test]
fn durable_part_on_ephemeral_key_dropped_spec_commits_2() {
    let (mut lp, d) = memory_trio(39);
    let key = crate::common::ak("t:tags.0~");
    let mut m = Mutation::new();
    m.op(d, &key, PathOp { path: Vec::new(), op: Op::Add(s("durable")) }).unwrap();
    m.set(d, &crate::common::REG, &s("kept")).unwrap();
    let e = &mut lp.peers[2].engine;
    assert!(matches!(e.commit(m.clone()), Err(osis_node::Error::Misuse(_))), "the writer refuses it");
    e.core.skip_writer_rules = true;
    e.commit(m).unwrap().unwrap();
    e.core.skip_writer_rules = false;
    lp.sync_all().unwrap();
    for i in [0, 1] {
        let e = &mut lp.peers[i].engine;
        assert_eq!(e.get(&d, &key).unwrap(), None, "{i}: a durable delta of a `~` key applied");
        assert_eq!(e.get(&d, &crate::common::ak("t:reg.0")).unwrap(), Some(s("kept")), "{i}");
    }
}

// issues/eph-unify.md step 3 (freeing): a thing freed while a received memory commit on it is
// pending takes that commit with it: it never applies later and brings the thing back
#[test]
fn freed_thing_drops_pending_memory_commit() {
    let (mut lp, d) = memory_pair(35);
    let mut m = Mutation::new();
    let w = lp.peers[0].engine.new_thing(&mut m, d);
    m.set(w, &eph("t:tags.0~"), &s("x")).unwrap();
    let id = lp.peers[0].engine.commit_in_memory(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
    lp.peers[1].engine.ingest_memory(&pk.bytes, u64::MAX).unwrap();
    assert_eq!(memory_tags(&mut lp, 1, w), Some(s("x")));
    // a later one from 0's clock far ahead waits for drift
    lp.peers[0].clock.advance(2 * osis_base::format::MAX_DRIFT_MS);
    let later = memory_write(&mut lp, 0, w, "y");
    let pk = lp.peers[0].engine.package(&later).unwrap().unwrap();
    assert!(matches!(lp.peers[1].engine.ingest_memory(&pk.bytes, u64::MAX).unwrap(), osis_node::Ingested::Pending(_, osis_node::Reason::Drift)));
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
    assert!(matches!(lp.peers[0].engine.ingest_memory(&pk.bytes, u64::MAX).unwrap(), osis_node::Ingested::Applied(_)));
    assert_eq!(memory_tags(&mut lp, 0, d), Some(Value::Set([s("own"), s("theirs")].into())));
    let b = lp.peers[1].engine.tid();
    let scope = osis_perm::DemotionScope { roles: BTreeMap::from([(b, BTreeSet::from([d]))]), content: BTreeMap::from([(b, BTreeSet::from([d]))]) };
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&scope, now).unwrap();
    crate::common::set_edge(&mut lp.peers[0].engine, d, b, None, Some(osis_schema::Codec::to_value(&f)));
    assert_eq!(memory_tags(&mut lp, 0, d), Some(Value::Set([s("own")].into())), "the removed writer's memory writes go");
    assert!(lp.peers[0].engine.core.ix.commits.get(&id).is_some_and(|m| m.valid.iter().all(|v| !v)));
    // the un-merge, done in the removal's durable transaction, wrote nothing durable about it
    lp.peers[0].restart(38).unwrap();
    assert_no_durable_trace(&mut lp.peers[0].engine, &[id]);
}

/// Peer `i` applies `op` at `path` of the ephemeral `ak` of `t` as a memory commit, expiring
/// `ms` from its clock's now when given: its ID and blob.
fn memory_op(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: Tid, ak: &str, path: Vec<PathSeg>, op: Op, ms: Option<u64>) -> (osis_base::CommitId, Vec<u8>) {
    let e = &mut lp.peers[i].engine;
    let mut m = Mutation::new();
    m.op(t, &eph(ak), PathOp { path, op }).unwrap();
    if let Some(ms) = ms {
        m.expires(t, &eph(ak), osis_base::WallMs(e.now().0 + ms)).unwrap();
    }
    let id = e.commit_in_memory(m).unwrap().unwrap();
    (id, e.package(&id).unwrap().unwrap().bytes)
}

/// Peer `to` receives memory commit blob `c` (no room limit).
fn memory_deliver(lp: &mut osis_node::local_peer::LocalPeer, to: usize, c: &(osis_base::CommitId, Vec<u8>)) -> osis_node::Ingested {
    lp.peers[to].engine.ingest_memory(&c.1, u64::MAX).unwrap()
}

fn holds_commit(lp: &osis_node::local_peer::LocalPeer, i: usize, id: &osis_base::CommitId) -> bool {
    lp.peers[i].engine.core.ix.commits.contains_key(id)
}

// spec/crdt.md §4.7 (Ephemeral data: an expired delta vanishes whole, its resets included, at
// every node): 1's expiring replace of the set 0 added to reads until T; past it the replace is
// gone whole at its author, at 0 (held it at T) and at 2 (got it only after T): all read 0's
// element again, the expired commit forgotten everywhere (a copy arriving again goes again),
// nothing durable written
#[test]
fn memory_expiry_vanishes_whole_spec_crdt_4_7() {
    let (mut lp, d) = memory_trio(41);
    let faults: Vec<_> = lp.peers.iter().map(|p| p.backend.faults().clone()).collect();
    faults.iter().for_each(|f| f.forbid_writes(true));
    let add = memory_op(&mut lp, 0, d, "t:tags.0~", Vec::new(), Op::Add(s("a")), None);
    for i in [1, 2] {
        assert!(matches!(memory_deliver(&mut lp, i, &add), osis_node::Ingested::Applied(_)));
    }
    let rep = memory_op(&mut lp, 1, d, "t:tags.0~", Vec::new(), Op::Replace(Value::Set([s("b")].into())), Some(1000));
    memory_deliver(&mut lp, 0, &rep);
    let b = Some(Value::Set([s("b")].into()));
    assert_eq!((memory_tags(&mut lp, 0, d), memory_tags(&mut lp, 1, d)), (b.clone(), b));
    lp.advance(2000);
    for i in 0..3 {
        lp.peers[i].engine.tick().unwrap();
    }
    assert!(matches!(memory_deliver(&mut lp, 2, &rep), osis_node::Ingested::Applied(_)));
    let a = Some(Value::Set([s("a")].into()));
    for i in 0..3 {
        assert_eq!(memory_tags(&mut lp, i, d), a, "{i}: the expired replace vanished whole");
        assert!(!holds_commit(&lp, i, &rep.0), "{i}: the expired commit is forgotten");
        assert!(holds_commit(&lp, i, &add.0));
    }
    memory_deliver(&mut lp, 0, &rep);
    assert!(!holds_commit(&lp, 0, &rep.0));
    assert_eq!(memory_tags(&mut lp, 0, d), a);
    assert!(faults.iter().all(|f| f.forbidden() == 0), "nothing durable written");
}

// spec/sync.md §9 (Superseded expiring writes): an expiring move of 0's cursor entry vanishes
// once its later move (expiring no earlier) is held: at the author, at 1 (older first) and at 2
// (newer first: the older one is not kept); one expiring earlier supersedes nothing; once the
// newer entries are removed the superseded move does not read again anywhere
#[test]
fn memory_superseded_expiring_write_vanishes_spec_sync_9() {
    let (mut lp, d) = memory_trio(43);
    let me = s(&lp.peers[0].engine.tid().to_string());
    let key = vec![PathSeg::Key(me.clone())];
    let old = memory_op(&mut lp, 0, d, "t:big.0~", key.clone(), Op::Put(s("c0")), Some(30_000));
    lp.advance(10);
    memory_deliver(&mut lp, 1, &old);
    let new = memory_op(&mut lp, 0, d, "t:big.0~", key.clone(), Op::Put(s("c1")), Some(30_000));
    assert!(!holds_commit(&lp, 0, &old.0) && holds_commit(&lp, 0, &new.0), "the author drops the superseded move");
    assert!(holds_commit(&lp, 1, &old.0));
    memory_deliver(&mut lp, 1, &new);
    memory_deliver(&mut lp, 2, &new);
    memory_deliver(&mut lp, 2, &old);
    let c1 = Some(Value::Map([(me.clone(), s("c1"))].into()));
    for i in 0..3 {
        assert!(!holds_commit(&lp, i, &old.0) && holds_commit(&lp, i, &new.0), "{i}");
        assert_eq!(lp.peers[i].engine.get(&d, &eph("t:big.0~")).unwrap(), c1, "{i}");
    }
    lp.advance(10);
    let short = memory_op(&mut lp, 0, d, "t:big.0~", key, Op::Put(s("c2")), Some(1_000));
    assert!(holds_commit(&lp, 0, &new.0) && holds_commit(&lp, 0, &short.0), "expiring earlier: supersedes nothing");
    memory_deliver(&mut lp, 1, &short);
    let rm = memory_op(&mut lp, 1, d, "t:big.0~", Vec::new(), Op::Remove(me), None);
    for i in [0, 2] {
        memory_deliver(&mut lp, i, &short);
        memory_deliver(&mut lp, i, &rm);
    }
    for i in 0..3 {
        let v = lp.peers[i].engine.get(&d, &eph("t:big.0~")).unwrap();
        assert!(v.as_ref().is_none_or(|v| *v == Value::Map(BTreeMap::new())), "{i}: {v:?}");
    }
}

// spec/sync.md §9 (Superseded expiring writes, a function of the commits held): 2 holds 1's
// two moves while a removal of 1 by admin 3 makes them invalid there: nothing is superseded;
// once 0's earlier removal of 3 arrives, 3's removal is invalid, the moves valid again, and the
// older move goes there too
#[test]
fn memory_superseded_once_superseder_valid_spec_sync_9() {
    let mut lp = crate::common::net(4, 45);
    lp.sync_all().unwrap();
    let d = crate::common::new_thing(&mut lp, 0);
    let [w, h, x] = [1, 2, 3].map(|i| lp.peers[i].engine.tid());
    for (t, r) in [(w, Role::Write), (h, Role::Write), (x, Role::Admin)] {
        crate::common::set_edge(&mut lp.peers[0].engine, d, t, Some(crate::common::edge(r)), None);
    }
    lp.sync_all().unwrap();
    let me = s(&w.to_string());
    let key = vec![PathSeg::Key(me.clone())];
    let old = memory_op(&mut lp, 1, d, "t:big.0~", key.clone(), Op::Put(s("c0")), Some(30_000));
    lp.advance(10);
    let new = memory_op(&mut lp, 1, d, "t:big.0~", key, Op::Put(s("c1")), Some(30_000));
    crate::common::set_edge(&mut lp.peers[0].engine, d, x, None, None);
    lp.advance(10);
    let scope = osis_perm::DemotionScope { roles: BTreeMap::from([(w, BTreeSet::from([d]))]), content: BTreeMap::from([(w, BTreeSet::from([d]))]) };
    let now = lp.peers[3].engine.now();
    let f = lp.peers[3].engine.frontier(&scope, now).unwrap();
    crate::common::set_edge(&mut lp.peers[3].engine, d, w, None, Some(osis_schema::Codec::to_value(&f)));
    lp.sync(3, 2).unwrap();
    memory_deliver(&mut lp, 2, &old);
    memory_deliver(&mut lp, 2, &new);
    let valid = |lp: &osis_node::local_peer::LocalPeer, c: &osis_base::CommitId| lp.peers[2].engine.core.ix.commits.get(c).is_some_and(|m| m.valid.iter().all(|v| *v));
    assert!(holds_commit(&lp, 2, &old.0) && holds_commit(&lp, 2, &new.0) && !valid(&lp, &new.0), "both invalid at 2: neither supersedes");
    lp.sync(0, 2).unwrap();
    assert!(valid(&lp, &new.0), "3's removal of 1 is invalid at 2");
    assert!(!holds_commit(&lp, 2, &old.0) && holds_commit(&lp, 2, &new.0), "the older move goes once the newer is valid");
    assert_eq!(lp.peers[2].engine.get(&d, &eph("t:big.0~")).unwrap(), Some(Value::Map([(me, s("c1"))].into())));
}

// spec/sync.md §9 (Caps: a holder decodes nothing past the room its cap leaves): a memory commit
// whose parts could cost more decoded than the room given is refused before decoding, nothing
// of it held or kept waiting; within the room it applies, charged its decoded size per copy
// kept and less than its bound; a copy of it again needs no room
#[test]
fn memory_ingest_within_room_spec_sync_9() {
    let (mut lp, d) = memory_pair(47);
    let mut m = Mutation::new();
    let w = lp.peers[0].engine.new_thing(&mut m, d);
    m.set(w, &eph("t:tags.0~"), &Value::Set((0..200).map(|n| s(&format!("e{n}"))).collect())).unwrap();
    let id = lp.peers[0].engine.commit_in_memory(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
    let blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let (bound, _) = osis_node::Engine::memory_bound(&blob);
    let e = &mut lp.peers[1].engine;
    assert!(matches!(e.ingest_memory(&pk.bytes, bound - 1).unwrap(), osis_node::Ingested::TooLarge(c) if c == id));
    assert!(!e.core.ix.commits.contains_key(&id) && !e.core.ix.pending.contains_key(&id) && e.core.created(&w).is_none(), "nothing of it held");
    assert!(matches!(e.ingest_memory(&pk.bytes, bound).unwrap(), osis_node::Ingested::Applied(_)));
    let charge = e.memory_charge(&id).unwrap();
    let delta: usize = blob.parts.iter().map(|p| p.delta.len()).sum();
    assert!(charge >= (2 * delta + osis_node::apply::PART_OVERHEAD) as u64 && charge < bound, "{charge} {delta} {bound}");
    assert!(matches!(e.ingest_memory(&pk.bytes, 0).unwrap(), osis_node::Ingested::Duplicate(_)), "held parts need no room");
}

// spec/sync.md §9 (an expiring commit superseded by its author's later writes is dropped and
// deleted by its author; superseded unsent writes are not sent): a cursor moved 30 times a second,
// each move a fresh entry at the author's key expiring 30 s out (what `osis::KeepAlive::set`
// writes), costs about one held commit at every node and one entry at the host, not one per
// move until each expires (was issues/eph-expiring-churn.md: 60 here)
#[test]
fn moving_cursor_one_entry_per_author_spec_sync_9() {
    const E: u64 = 30_000;
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let w = window(&mut net, a, g, "w");
    net.run();
    let l = net.label(a);
    let me = s(&net.tid(a).to_string());
    let entries = |net: &Net| osis_proto::LabelStore::live_ids(net.hosts[host].hub.store(), &l).unwrap().len();
    let base = entries(&net);
    let held = |net: &mut Net, n: usize| net.engine(n).memory_commits().len();
    let (ha, hb) = (held(&mut net, a), held(&mut net, b));
    for i in 0..60 {
        let mut m = Mutation::new();
        m.op(w, &eph(CURSOR), PathOp { path: vec![PathSeg::Key(me.clone())], op: Op::Put(s(&format!("c{i}"))) }).unwrap();
        m.expires(w, &eph(CURSOR), osis_base::WallMs(net.now() + E)).unwrap();
        net.engine(a).write(m).unwrap();
        local(&mut net, a);
        net.advance(33);
        assert!(entries(&net) - base <= 3, "move {i}: the host holds {} entries of one cursor", entries(&net) - base);
    }
    net.run();
    assert_eq!(net.eph_read(b, w, CURSOR), Some(Value::Map([(me.clone(), s("c59"))].into())));
    assert_eq!(net.eph_read(a, w, CURSOR), Some(Value::Map([(me, s("c59"))].into())));
    assert_eq!(entries(&net) - base, 1, "one entry of the cursor at the host");
    assert_eq!((held(&mut net, a) - ha, held(&mut net, b) - hb), (1, 1), "one commit of it held at the author and the holder");
    // the last move still expires everywhere
    net.advance(E);
    assert_eq!(net.eph_read(b, w, CURSOR), None);
    assert_eq!(entries(&net), base);
}

// spec/crdt.md §4.7 (ephemeral data: an expired delta vanishes whole): b's `Set` into a's entry
// outlives the entry; once the entry expires a and b, which held it, read b's value as c does,
// restarted after the expiry and never holding the entry (was issues/eph-set-into-dead-entry.md)
#[test]
fn set_into_expired_entry_reads_alike_spec_crdt_4_7() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[host]);
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
    let want = Some(Value::Map([(s("k"), s("s"))].into()));
    let reads: Vec<Option<Value>> = [a, b, c].iter().map(|n| net.eph_read(*n, w, CURSOR)).collect();
    assert_eq!(reads, vec![want.clone(), want.clone(), want], "b's write reads everywhere");
    // and goes at its own expiry
    net.advance(600_000);
    let reads: Vec<Option<Value>> = [a, b, c].iter().map(|n| net.eph_read(*n, w, CURSOR)).collect();
    assert_eq!(reads, vec![None, None, None]);
}

// spec/crdt.md §4.7 (Ephemeral data), spec/sync.md §9 (Superseded expiring writes), issues/
// eph-unify.md Step A (review differential): random memory histories (expiring and plain puts
// at shared keys, removals, replaces, two writers) reach four nodes through the Core hooks in
// random orders, ticked at random times: once all are delivered, every node reads alike at each
// later tick, whatever expired, was superseded or forgotten where first (300 seeds checked in
// review; a few here)
#[test]
fn memory_random_histories_read_alike_spec_crdt_4_7() {
    memory_random_histories(0..6, false);
}

// spec/sync.md §9 (Compaction, memory class), spec/commits.md §5 (covered), issues/eph-unify.md
// step B: `memory_random_histories_read_alike_spec_crdt_4_7` with memory snapshots among the
// writes (any writer or the admin, of the aspect's whole state at that node): each holder drops
// what the snapshots it holds cover and forgets it, and all still read alike
#[test]
fn memory_random_histories_with_snapshots_read_alike_spec_sync_9() {
    memory_random_histories(0..6, true);
}

/// Random memory histories over four nodes (`memory_random_histories_read_alike_spec_crdt_4_7`),
/// with memory snapshots among the writes when `snapshots`.
fn memory_random_histories(seeds: std::ops::Range<u64>, snapshots: bool) {
    for seed in seeds {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut rnd = move |n: u64| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x % n };
        let mut lp = crate::common::net(4, 1000 + seed);
        lp.sync_all().unwrap();
        let d = crate::common::new_thing(&mut lp, 0);
        for i in [1, 2, 3] {
            let n = lp.peers[i].engine.tid();
            crate::common::set_edge(&mut lp.peers[0].engine, d, n, Some(crate::common::edge(Role::Write)), None);
        }
        lp.sync_all().unwrap();
        let ak = "t:big.0~";
        let mut queue: Vec<(u64, usize, (osis_base::CommitId, Vec<u8>))> = Vec::new();
        let mut log = Vec::new();
        let steps = 14;
        for step in 0..steps {
            let w = 1 + rnd(2) as usize;
            if snapshots && rnd(4) == 0 {
                let by = if rnd(3) == 0 { 0 } else { w };
                let e = &mut lp.peers[by].engine;
                // none when a held covered-equal snapshot with a lower ID made it go at once
                let c = e.snapshot(&d, &eph(ak)).unwrap().and_then(|id| e.package(&id).unwrap().map(|p| (id, p.bytes)));
                log.push(format!("{step}: snapshot by {by}: {:?}", c.as_ref().map(|c| c.0)));
                for to in (0..4).filter(|to| *to != by) {
                    if let Some(c) = &c {
                        queue.push((step + rnd(6), to, c.clone()));
                    }
                }
                lp.advance(1 + rnd(300));
                continue;
            }
            let k = s(&format!("k{}", rnd(3)));
            let exp = if rnd(if snapshots { 2 } else { 5 }) == 0 { None } else { Some(200 + rnd(3000)) };
            let (path, op) = match rnd(10) {
                0 => (Vec::new(), Op::Remove(k)),
                1 => (Vec::new(), Op::Replace(Value::Map([(k, s(&format!("r{step}")))].into()))),
                _ => (vec![PathSeg::Key(k)], Op::Put(s(&format!("v{step}w{w}")))),
            };
            // sometimes a second part, expiring sooner: what is left may be superseded later
            let side = (rnd(3) == 0).then(|| 50 + rnd(1000));
            log.push(format!("{step}: w{w} {path:?} {op:?} exp {exp:?} side {side:?}"));
            let c = {
                let e = &mut lp.peers[w].engine;
                let mut m = Mutation::new();
                m.op(d, &eph(ak), PathOp { path, op }).unwrap();
                if let Some(ms) = exp {
                    m.expires(d, &eph(ak), osis_base::WallMs(e.now().0 + ms)).unwrap();
                }
                if let Some(ms) = side {
                    m.op(d, &eph("t:tags.0~"), PathOp { path: Vec::new(), op: Op::Add(s(&format!("t{step}"))) }).unwrap();
                    m.expires(d, &eph("t:tags.0~"), osis_base::WallMs(e.now().0 + ms)).unwrap();
                }
                match e.commit_in_memory(m) {
                    Ok(Some(id)) => (id, e.package(&id).unwrap().unwrap().bytes),
                    _ => {
                        log.push("  (refused)".into());
                        lp.advance(1 + rnd(300));
                        continue;
                    }
                }
            };
            for to in 0..4 {
                if to != w {
                    queue.push((step + rnd(6), to, c.clone()));
                }
            }
            lp.advance(1 + rnd(300));
            for to in 0..4 {
                if rnd(3) == 0 {
                    lp.peers[to].engine.tick().unwrap();
                }
            }
            let due: Vec<_> = queue.iter().filter(|q| q.0 <= step).cloned().collect();
            queue.retain(|q| q.0 > step);
            for (_, to, c) in due {
                memory_deliver(&mut lp, to, &c);
            }
        }
        for (_, to, c) in std::mem::take(&mut queue) {
            memory_deliver(&mut lp, to, &c);
        }
        for round in 0..8 {
            for to in 0..4 {
                lp.peers[to].engine.tick().unwrap();
            }
            let reads: Vec<_> = (0..4).map(|i| (lp.peers[i].engine.get(&d, &eph(ak)).unwrap(), lp.peers[i].engine.get(&d, &eph("t:tags.0~")).unwrap())).collect();
            assert!(reads.iter().all(|r| *r == reads[0]), "seed {seed} round {round}: {reads:?}\n{}", log.join("\n"));
            lp.advance(1 + rnd(800));
        }
    }
}

// spec/sync.md §9 (Superseded expiring writes, judged again when a part of the superseded commit
// expires): 1's commit c moves its cursor entry (expiring late) and adds a tag (expiring soon);
// its later move supersedes only the first part. 0 holds both before the tag expires, 2 gets
// them after: both drop c (at 0 once the tag part vanished), so 2's removal of the entry it saw
// leaves nothing at either (review eph-unify-a: 0 kept c's move and read it again)
#[test]
fn memory_partly_expired_commit_superseded_alike_spec_sync_9() {
    let (mut lp, d) = memory_trio(47);
    let k = s("k");
    let mk = |lp: &mut osis_node::local_peer::LocalPeer, ops: Vec<(&str, Vec<PathSeg>, Op, u64)>| {
        let e = &mut lp.peers[1].engine;
        let mut m = Mutation::new();
        for (ak, path, op, ms) in ops {
            m.op(d, &eph(ak), PathOp { path, op }).unwrap();
            m.expires(d, &eph(ak), osis_base::WallMs(e.now().0 + ms)).unwrap();
        }
        let id = e.commit_in_memory(m).unwrap().unwrap();
        (id, e.package(&id).unwrap().unwrap().bytes)
    };
    let c = mk(&mut lp, vec![("t:big.0~", vec![PathSeg::Key(k.clone())], Op::Put(s("a")), 10_000), ("t:tags.0~", Vec::new(), Op::Add(s("y")), 1_000)]);
    lp.advance(10);
    let q = mk(&mut lp, vec![("t:big.0~", vec![PathSeg::Key(k.clone())], Op::Put(s("b")), 10_000)]);
    memory_deliver(&mut lp, 0, &c);
    memory_deliver(&mut lp, 0, &q);
    lp.advance(2000);
    for i in 0..3 {
        lp.peers[i].engine.tick().unwrap();
    }
    memory_deliver(&mut lp, 2, &q);
    memory_deliver(&mut lp, 2, &c);
    assert!(!holds_commit(&lp, 0, &c.0) && !holds_commit(&lp, 2, &c.0));
    let rm = memory_op(&mut lp, 2, d, "t:big.0~", Vec::new(), Op::Remove(k), None);
    memory_deliver(&mut lp, 0, &rm);
    for i in [0, 2] {
        assert_eq!(lp.peers[i].engine.get(&d, &eph("t:big.0~")).unwrap(), Some(Value::Map(BTreeMap::new())), "{i}");
    }
}

/// Peer `i` snapshots `t:tags.0~` of `t` (a memory compaction snapshot), packaged.
fn memory_snapshot(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: Tid) -> (osis_base::CommitId, Vec<u8>) {
    let e = &mut lp.peers[i].engine;
    let id = e.snapshot(&t, &eph("t:tags.0~")).unwrap().unwrap();
    (id, e.package(&id).unwrap().unwrap().bytes)
}

// spec/sync.md §9 (Compaction, memory class), spec/commits.md §5 (covered): a memory snapshot of
// an aspect's whole state is a memory commit; each holder drops the bodies it covers at once and
// forgets their headers, at the writer, at a holder of them all and at one receiving them after
// the snapshot; an expiring write is neither carried nor covered and vanishes at T alike;
// nothing durable written
#[test]
fn memory_snapshot_covers_held_bodies_spec_sync_9() {
    let (mut lp, d) = memory_trio(49);
    let faults: Vec<_> = lp.peers.iter().map(|p| p.backend.faults().clone()).collect();
    faults.iter().for_each(|f| f.forbid_writes(true));
    let a1 = memory_op(&mut lp, 0, d, "t:tags.0~", Vec::new(), Op::Add(s("a1")), None);
    let a2 = memory_op(&mut lp, 0, d, "t:tags.0~", Vec::new(), Op::Add(s("a2")), None);
    let b1 = memory_op(&mut lp, 1, d, "t:tags.0~", Vec::new(), Op::Add(s("b1")), None);
    let e1 = memory_op(&mut lp, 1, d, "t:tags.0~", Vec::new(), Op::Add(s("e1")), Some(30_000));
    for c in [&a1, &a2, &e1] {
        memory_deliver(&mut lp, 1, c);
    }
    for c in [&b1, &e1] {
        memory_deliver(&mut lp, 0, c);
    }
    memory_deliver(&mut lp, 2, &a1);
    let snap = memory_snapshot(&mut lp, 0, d);
    assert!(lp.peers[0].engine.core.ix.commits.get(&snap.0).is_some_and(|m| m.view.memory && m.header.ephemeral.is_some()));
    for c in [&a1, &a2, &b1] {
        assert!(!holds_commit(&lp, 0, &c.0), "the writer drops what its snapshot covers");
    }
    assert!(holds_commit(&lp, 0, &e1.0), "an expiring write is not covered");
    memory_deliver(&mut lp, 1, &snap);
    memory_deliver(&mut lp, 2, &snap);
    assert!(!holds_commit(&lp, 2, &a1.0));
    for c in [&a2, &b1, &e1] {
        memory_deliver(&mut lp, 2, c);
    }
    let all = Some(Value::Set([s("a1"), s("a2"), s("b1"), s("e1")].into()));
    for i in 0..3 {
        for c in [&a1, &a2, &b1] {
            // an author keeps its own body until one of its own snapshots covers it
            // (issues/eph-unify.md decision 1)
            assert_eq!(holds_commit(&lp, i, &c.0), i == 1 && c.0 == b1.0, "{i}: covered, forgotten");
        }
        assert!(holds_commit(&lp, i, &snap.0) && holds_commit(&lp, i, &e1.0), "{i}");
        assert_eq!(memory_tags(&mut lp, i, d), all, "{i}");
    }
    // a covered commit arriving again is covered again
    memory_deliver(&mut lp, 1, &a1);
    assert!(!holds_commit(&lp, 1, &a1.0));
    // a later snapshot covers the earlier one, whose bodies are forgotten
    let a3 = memory_op(&mut lp, 0, d, "t:tags.0~", Vec::new(), Op::Add(s("a3")), None);
    let snap2 = memory_snapshot(&mut lp, 0, d);
    assert!(!holds_commit(&lp, 0, &snap.0) && !holds_commit(&lp, 0, &a3.0), "the newer snapshot covers the older one");
    for i in [1, 2] {
        memory_deliver(&mut lp, i, &a3);
        memory_deliver(&mut lp, i, &snap2);
        assert!(!holds_commit(&lp, i, &snap.0) && !holds_commit(&lp, i, &a3.0), "{i}");
    }
    lp.advance(31_000);
    let left = Some(Value::Set([s("a1"), s("a2"), s("a3"), s("b1")].into()));
    for i in 0..3 {
        lp.peers[i].engine.tick().unwrap();
        assert_eq!(memory_tags(&mut lp, i, d), left, "{i}: the expiring write vanished");
    }
    assert!(faults.iter().all(|f| f.forbidden() == 0), "nothing durable written");
}

// spec/sync.md §7 (covered-equal snapshots: only the higher commit ID goes), memory class: two
// writers snapshot the same state; a holder keeps the lower one; each writer keeps its own
// (until one of its own snapshots covers it, issues/eph-unify.md decision 1) and the other's
// when it is the lower
#[test]
fn memory_covered_equal_snapshots_keep_lower_spec_sync_7() {
    let (mut lp, d) = memory_trio(51);
    let a = memory_op(&mut lp, 0, d, "t:tags.0~", Vec::new(), Op::Add(s("a")), None);
    memory_deliver(&mut lp, 1, &a);
    let s0 = memory_snapshot(&mut lp, 0, d);
    let s1 = memory_snapshot(&mut lp, 1, d);
    memory_deliver(&mut lp, 1, &s0);
    memory_deliver(&mut lp, 0, &s1);
    memory_deliver(&mut lp, 2, &s1);
    memory_deliver(&mut lp, 2, &s0);
    let (lo, hi) = if s0.0 < s1.0 { (s0.0, s1.0) } else { (s1.0, s0.0) };
    assert!(holds_commit(&lp, 2, &lo) && !holds_commit(&lp, 2, &hi), "a holder keeps the lower");
    for (i, own) in [(0, s0.0), (1, s1.0)] {
        assert!(holds_commit(&lp, i, &own), "{i} keeps its own");
        assert_eq!(holds_commit(&lp, i, &if own == lo { hi } else { lo }), own == hi, "{i}: the other's only when lower");
    }
    for i in 0..3 {
        assert_eq!(memory_tags(&mut lp, i, d), Some(Value::Set([s("a")].into())), "{i}");
    }
}

// spec/permissions.md §5.2 (a snapshot turning invalid gives nothing; a body dropped under its
// cover counts as never received and joins when it arrives again), memory class
// (issues/eph-cover-invalidated-loses-absorbed.md at Core level): w writes X, removes itself,
// then snapshots X past the removal. Holder a gets the snapshot before the removal (drops X as
// covered, then the snapshot turns invalid), b the removal first (snapshot invalid on arrival, X
// kept). Each reads what it holds; once X arrives again a reads as b.
#[test]
fn memory_cover_invalidated_rejoins_spec_permissions_5_2() {
    let (mut lp, d) = memory_trio(53);
    let wt = lp.peers[1].engine.tid();
    let x = memory_op(&mut lp, 1, d, "t:tags.0~", Vec::new(), Op::Add(s("X")), None);
    lp.advance(10);
    let dm = osis_node::flows::Demotion { holder: wt, new: None, presync: osis_node::flows::PreSync::Synced, keep: None };
    let r = *lp.peers[1].engine.demote(&d, &dm).unwrap().commits.last().unwrap();
    let rp = lp.peers[1].engine.package(&r).unwrap().unwrap();
    lp.advance(10);
    lp.peers[1].engine.core.skip_writer_rules = true;
    let c = memory_snapshot(&mut lp, 1, d);
    lp.peers[1].engine.core.skip_writer_rules = false;
    let (a, b) = (0, 2);
    memory_deliver(&mut lp, a, &x);
    memory_deliver(&mut lp, a, &c);
    assert!(!holds_commit(&lp, a, &x.0), "a drops X under the snapshot");
    lp.deliver(a, &rp).unwrap();
    memory_deliver(&mut lp, b, &x);
    lp.deliver(b, &rp).unwrap();
    memory_deliver(&mut lp, b, &c);
    assert!(holds_commit(&lp, b, &x.0));
    let xs = Some(Value::Set([s("X")].into()));
    assert_eq!(memory_tags(&mut lp, b, d), xs);
    assert_eq!(memory_tags(&mut lp, a, d), None, "the invalid snapshot gives nothing, X is not held");
    memory_deliver(&mut lp, a, &x);
    assert!(holds_commit(&lp, a, &x.0), "an invalid snapshot covers nothing");
    assert_eq!(memory_tags(&mut lp, a, d), xs, "a reads as b once X is back");
}

// spec/permissions.md §5.2 (a snapshot turning invalid gives nothing), memory class (eph-unify-b
// review): random memory histories with snapshots (`memory_random_histories`) on two aspects,
// set adds and removals, and an admin demoting one writer mid-history, so memory snapshots turn
// invalid after holders dropped and forgot what they covered; every blob is delivered again at
// the end (to its author too: the B2 lane's job). Then every node reads alike and holds the same
// memory commits, whatever arrived when (400 seeds in review)
#[test]
fn memory_random_snapshots_demotion_redelivered_alike_spec_permissions_5_2() {
    for seed in 0..5 {
        memory_random_demotion(seed);
    }
}

fn memory_random_demotion(seed: u64) {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut rnd = move |n: u64| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x % n };
    let mut lp = crate::common::net(4, 5000 + seed);
    lp.sync_all().unwrap();
    let d = crate::common::new_thing(&mut lp, 0);
    for i in [1, 2, 3] {
        let n = lp.peers[i].engine.tid();
        crate::common::set_edge(&mut lp.peers[0].engine, d, n, Some(crate::common::edge(Role::Write)), None);
    }
    lp.sync_all().unwrap();
    let aks = ["t:big.0~", "t:tags.0~"];
    let mut queue: Vec<(u64, usize, (osis_base::CommitId, Vec<u8>))> = Vec::new();
    let mut sent: Vec<(osis_base::CommitId, Vec<u8>)> = Vec::new();
    let mut log = Vec::new();
    let demote_at = 4 + rnd(14);
    let mut dq: Vec<(u64, usize, osis_node::local_peer::Package)> = Vec::new();
    for step in 0..24 {
        if step == demote_at {
            let who = 1 + rnd(3) as usize;
            let holder = lp.peers[who].engine.tid();
            let dm = osis_node::flows::Demotion { holder, new: None, presync: osis_node::flows::PreSync::Synced, keep: None };
            let r = *lp.peers[0].engine.demote(&d, &dm).unwrap().commits.last().unwrap();
            let rp = lp.peers[0].engine.package(&r).unwrap().unwrap();
            log.push(format!("{step}: demote {who}"));
            for to in 1..4 {
                dq.push((step + rnd(8), to, rp.clone()));
            }
        }
        let due: Vec<_> = dq.iter().filter(|q| q.0 <= step).cloned().collect();
        dq.retain(|q| q.0 > step);
        for (_, to, p) in due {
            log.push(format!("  demotion to {to}"));
            lp.deliver(to, &p).unwrap();
        }
        let w = 1 + rnd(3) as usize;
        let ak = aks[rnd(2) as usize];
        let c = if rnd(4) == 0 {
            let by = if rnd(4) == 0 { 0 } else { w };
            let e = &mut lp.peers[by].engine;
            // refused once the demotion reached the snapshotter
            let c = e.snapshot(&d, &eph(ak)).ok().flatten().and_then(|id| e.package(&id).unwrap().map(|p| (id, p.bytes)));
            log.push(format!("{step}: snapshot {ak} by {by}: {:?}", c.as_ref().map(|c| c.0)));
            c.map(|c| (by, c))
        } else {
            let k = s(&format!("k{}", rnd(3)));
            let exp = (rnd(3) == 0).then(|| 200 + rnd(4000));
            let (path, op) = match (ak, rnd(10)) {
                ("t:big.0~", 0) => (Vec::new(), Op::Remove(k)),
                ("t:big.0~", 1) => (Vec::new(), Op::Replace(Value::Map([(k, s(&format!("r{step}")))].into()))),
                ("t:big.0~", _) => (vec![PathSeg::Key(k)], Op::Put(s(&format!("v{step}w{w}")))),
                (_, 0..=3) => (Vec::new(), Op::Remove(k)),
                _ => (Vec::new(), Op::Add(k)),
            };
            log.push(format!("{step}: w{w} {ak} {path:?} {op:?} exp {exp:?}"));
            let e = &mut lp.peers[w].engine;
            let mut m = Mutation::new();
            m.op(d, &eph(ak), PathOp { path, op }).unwrap();
            if let Some(ms) = exp {
                m.expires(d, &eph(ak), osis_base::WallMs(e.now().0 + ms)).unwrap();
            }
            e.commit_in_memory(m).ok().flatten().map(|id| (w, (id, e.package(&id).unwrap().unwrap().bytes)))
        };
        if let Some((from, c)) = c {
            sent.push(c.clone());
            for to in (0..4).filter(|to| *to != from) {
                queue.push((step + rnd(8), to, c.clone()));
            }
        }
        // a copy of an earlier blob again (a forgotten one applies and goes again)
        if !sent.is_empty() && rnd(3) == 0 {
            queue.push((step + rnd(4), rnd(4) as usize, sent[rnd(sent.len() as u64) as usize].clone()));
        }
        lp.advance(1 + rnd(400));
        for to in 0..4 {
            if rnd(3) == 0 {
                lp.peers[to].engine.tick().unwrap();
            }
        }
        let due: Vec<_> = queue.iter().filter(|q| q.0 <= step).cloned().collect();
        queue.retain(|q| q.0 > step);
        for (_, to, c) in due {
            log.push(format!("  {:?} to {to}", c.0));
            memory_deliver(&mut lp, to, &c);
        }
    }
    for (_, to, p) in std::mem::take(&mut dq) {
        lp.deliver(to, &p).unwrap();
    }
    for (_, to, c) in std::mem::take(&mut queue) {
        memory_deliver(&mut lp, to, &c);
    }
    for c in &sent {
        for to in 0..4 {
            memory_deliver(&mut lp, to, c);
        }
    }
    for round in 0..6 {
        for to in 0..4 {
            lp.peers[to].engine.tick().unwrap();
        }
        let reads: Vec<_> = (0..4).map(|i| aks.iter().map(|ak| lp.peers[i].engine.get(&d, &eph(ak)).unwrap()).collect::<Vec<_>>()).collect();
        assert!(reads.iter().all(|r| *r == reads[0]), "seed {seed} round {round}: {reads:?}\n{}", log.join("\n"));
        // alike at every node but an author's own bodies, which it keeps until its own snapshot
        // covers them (issues/eph-unify.md decision 1): per author, the other nodes agree
        let held: Vec<BTreeMap<Tid, BTreeSet<osis_base::CommitId>>> = (0..4)
            .map(|i| {
                let mut by: BTreeMap<Tid, BTreeSet<osis_base::CommitId>> = BTreeMap::new();
                for (c, m) in lp.peers[i].engine.core.ix.commits.iter().filter(|(_, m)| m.view.memory && (0..m.view.aspects.len()).any(|ai| !m.dropped.contains_key(&ai) && !m.missing.contains(&ai))) {
                    by.entry(m.view.author).or_default().insert(*c);
                }
                by
            })
            .collect();
        for a in 0..4 {
            let at = lp.peers[a].engine.tid();
            let others: Vec<BTreeSet<osis_base::CommitId>> = (0..4).filter(|i| *i != a).map(|i| held[i].get(&at).cloned().unwrap_or_default()).collect();
            assert!(others.iter().all(|h| *h == others[0]), "seed {seed} round {round}: author {a}'s commits held {others:?}\n{}", log.join("\n"));
        }
        lp.advance(1 + rnd(1500));
    }
}

// spec/permissions.md §5.2 (an explicit demotion invalidates all the demoted node's ephemeral
// commits, its memory snapshots included), spec/requirements.md Convergence (eph-unify-b review,
// pinned for B2): 2 writes X; 1 snapshots it and every holder, 2 included, drops X as covered
// and forgets it; the admin then removes 1. X, a valid write of a node still writing, must still
// read; today it is gone everywhere with no copy left to bring it back
#[test]
fn memory_compactor_demoted_keeps_others_writes_spec_permissions_5_2() {
    let (mut lp, d) = memory_trio(61);
    let w1 = lp.peers[1].engine.tid();
    let x = memory_op(&mut lp, 2, d, "t:tags.0~", Vec::new(), Op::Add(s("X")), None);
    memory_deliver(&mut lp, 0, &x);
    memory_deliver(&mut lp, 1, &x);
    lp.advance(10);
    let c = memory_snapshot(&mut lp, 1, d);
    memory_deliver(&mut lp, 0, &c);
    memory_deliver(&mut lp, 2, &c);
    lp.advance(10);
    let dm = osis_node::flows::Demotion { holder: w1, new: None, presync: osis_node::flows::PreSync::Synced, keep: None };
    let r = *lp.peers[0].engine.demote(&d, &dm).unwrap().commits.last().unwrap();
    let rp = lp.peers[0].engine.package(&r).unwrap().unwrap();
    lp.deliver(1, &rp).unwrap();
    lp.deliver(2, &rp).unwrap();
    // the author kept its own body (issues/eph-unify.md decision 1): X reads there, and
    // everywhere again once its copy arrives (the lane reconciles the label,
    // `Engine::take_memory_invalidated`)
    assert!(holds_commit(&lp, 2, &x.0) && !holds_commit(&lp, 0, &x.0), "the author alone kept X");
    assert_eq!(memory_tags(&mut lp, 2, d), Some(Value::Set([s("X")].into())));
    assert!(lp.peers[0].engine.take_memory_invalidated().unwrap().contains(&(d, eph("t:tags.0~"))), "the holder reconciles");
    memory_deliver(&mut lp, 0, &x);
    memory_deliver(&mut lp, 1, &x);
    for i in 0..3 {
        assert_eq!(memory_tags(&mut lp, i, d), Some(Value::Set([s("X")].into())), "{i}");
    }
}

// spec/sync.md §9 (Compaction, memory class), notes/growth.md (eph-unify-b review, pinned for
// B2): a session's expiring write on an aspect leaves out its counters from every snapshot's
// frontier (and, once vanished, a gap no frontier passes), so none of that session's later
// plain writes there is ever covered: held for the session's life, and a size trigger fires on
// every write. A snapshot past the expiry must cover them
#[test]
fn memory_snapshot_covers_plain_after_expired_spec_sync_9() {
    let (mut lp, d) = memory_trio(63);
    memory_op(&mut lp, 1, d, "t:tags.0~", Vec::new(), Op::Add(s("E")), Some(1000));
    let ps: Vec<_> = (0..3).map(|i| memory_op(&mut lp, 1, d, "t:tags.0~", Vec::new(), Op::Add(s(&format!("p{i}"))), None)).collect();
    lp.advance(2000);
    lp.peers[1].engine.tick().unwrap();
    memory_snapshot(&mut lp, 1, d);
    for p in &ps {
        assert!(!holds_commit(&lp, 1, &p.0), "covered");
    }
}

// spec/sync.md §9 (Compaction, memory class), spec/commits.md §5 (covered): a memory snapshot
// and the body it covers, both invalid on arrival (their author's new write edge not yet known
// there), turn valid with the edge; the holder then drops the covered body as one that knew the
// edge first did (eph-unify-b review: no test reached `drop_covered` on a rise)
#[test]
fn memory_snapshot_turned_valid_covers_spec_sync_9() {
    let (mut lp, d) = memory_trio(67);
    let n1 = lp.peers[1].engine.tid();
    let edge = |lp: &mut osis_node::local_peer::LocalPeer, e: Option<ct::Edge>| {
        lp.advance(10);
        let id = crate::common::set_edge(&mut lp.peers[0].engine, d, n1, e, None);
        lp.peers[0].engine.package(&id).unwrap().unwrap()
    };
    let gone = edge(&mut lp, None);
    let back = edge(&mut lp, Some(crate::common::edge(Role::Write)));
    for i in [1, 2] {
        lp.deliver(i, &gone).unwrap();
    }
    lp.deliver(1, &back).unwrap();
    lp.advance(10);
    let x = memory_op(&mut lp, 1, d, "t:tags.0~", Vec::new(), Op::Add(s("X")), None);
    let c = memory_snapshot(&mut lp, 1, d);
    for i in [0, 2] {
        memory_deliver(&mut lp, i, &x);
        memory_deliver(&mut lp, i, &c);
    }
    assert!(!holds_commit(&lp, 0, &x.0));
    assert!(holds_commit(&lp, 2, &x.0), "invalid: covers nothing yet");
    lp.deliver(2, &back).unwrap();
    assert!(!holds_commit(&lp, 2, &x.0), "covered once valid");
    for i in 0..3 {
        assert_eq!(memory_tags(&mut lp, i, d), Some(Value::Set([s("X")].into())), "{i}");
    }
}

// spec/sync.md §9 (Compaction, memory class), spec/crdt.md §2.1, spec/permissions.md §5.2: 1 is
// demoted and granted write again with an `until` (no re-grant: its earlier memory body stays
// invalid, a demotion lists no memory commit); what it writes after that goes under a fresh
// session (`Core::fresh_session`), so snapshots' frontiers pass it and every holder drops it as
// covered. Under the old session it stayed held uncovered at every holder until 1 restarted
#[test]
fn memory_regranted_writer_covered_spec_sync_9() {
    let (mut lp, d) = memory_trio(71);
    let n1 = lp.peers[1].engine.tid();
    let x = memory_op(&mut lp, 1, d, "t:tags.0~", Vec::new(), Op::Add(s("X")), None);
    for i in [0, 2] {
        memory_deliver(&mut lp, i, &x);
    }
    let session = lp.peers[1].engine.ephemeral_session();
    lp.advance(10);
    let dm = osis_node::flows::Demotion { holder: n1, new: None, presync: osis_node::flows::PreSync::Synced, keep: None };
    let r = *lp.peers[0].engine.demote(&d, &dm).unwrap().commits.last().unwrap();
    let gone = lp.peers[0].engine.package(&r).unwrap().unwrap();
    lp.advance(10);
    let until = osis_base::WallMs(lp.peers[0].engine.now().0 + 86_400_000);
    let id = crate::common::set_edge(&mut lp.peers[0].engine, d, n1, Some(ct::Edge { until: Some(until), ..crate::common::edge(Role::Write) }), None);
    let back = lp.peers[0].engine.package(&id).unwrap().unwrap();
    for i in [1, 2] {
        lp.deliver(i, &gone).unwrap();
        lp.deliver(i, &back).unwrap();
    }
    assert_ne!(lp.peers[1].engine.ephemeral_session(), session, "its own write fell: a fresh session");
    lp.advance(10);
    let ys: Vec<_> = (0..2).map(|i| memory_op(&mut lp, 1, d, "t:tags.0~", Vec::new(), Op::Add(s(&format!("y{i}"))), None)).collect();
    for i in [0, 2] {
        for y in &ys {
            memory_deliver(&mut lp, i, y);
        }
    }
    // an author drops its own bodies under its own snapshot only, others under any
    let s1 = memory_snapshot(&mut lp, 1, d);
    let s0 = memory_snapshot(&mut lp, 0, d);
    for (to, c) in [(0, &s1), (2, &s1), (1, &s0), (2, &s0)] {
        memory_deliver(&mut lp, to, c);
    }
    for i in 0..3 {
        // the invalid body alone stays held (a grant could still make it valid)
        let bodies: Vec<osis_base::CommitId> = lp.peers[i].engine.core.ix.commits.iter().filter(|(_, m)| m.view.memory && !m.view.kind.is_compaction()).map(|(c, _)| *c).collect();
        assert_eq!(bodies, vec![x.0], "{i}: the later writes are covered");
        assert_eq!(memory_tags(&mut lp, i, d), Some(Value::Set([s("y0"), s("y1")].into())), "{i}");
    }
}

// spec/sync.md §4: a window placed in a group that a labeled group lists as an item is in a labeled
// closure: what the node syncs reads that group's `group.0`, and the window's placement.
#[test]
fn window_in_an_item_group_is_synced_spec_sync_4() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
    let me = net.tid(a);
    let u = net.item(a, g, me, "u");
    net.run();
    let w = window(&mut net, a, u, "hello");
    net.run();
    assert!(net.engine(a).core.syncs(&u));
    assert!(net.engine(a).ephemeral_synced(&w));
}
