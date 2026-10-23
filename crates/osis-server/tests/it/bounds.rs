//! Resource bounds and replication robustness (spec/sync.md §5: servers cap storage; spec/wire.md
//! §11.2 Register Error 12): connection cap, Hello deadline, node-wide caps, bounded sweeps,
//! sweep failures, retry after refusals, mutual replication.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use osis_core::{BlobId, ManualClock, WallMs};
use osis_crypto::SeededRng;
use osis_proto::*;
use osis_server::{BackendStore, Hub, HubOutput, Policy};
use osis_store::{Backend, Fault, Faults, MemoryBackend, WriteBatch};
use std::sync::Arc;

fn live(w: &World, h: usize, l: &Label) -> Vec<BlobId> {
    LabelStore::live_ids(w.hubs[h].store(), &l.id).unwrap()
}

// spec: none (server policy): connections beyond `max_connections` are closed; one without a Hello within `hello_ms` is closed
#[test]
fn connection_cap_and_hello_deadline() {
    let mut w = World::new();
    let h = w.add_hub(Policy { max_connections: 2, hello_ms: 5_000, ..Policy::default() });
    w.connect(h);
    let (silent, _) = w.connect_silent(h);
    let (refused, _) = w.connect_silent(h);
    assert!(!w.link_open(refused));
    assert!(w.link_open(silent));
    assert_eq!(w.hubs[h].connections(), 2);
    w.advance(4_999);
    assert!(w.link_open(silent));
    w.advance(1);
    assert!(!w.link_open(silent));
    assert_eq!(w.hubs[h].connections(), 1);
}

// spec/wire.md §11.1 (a Hello lists at most 16 versions), spec/requirements.md (peer input never
// causes unbounded allocation): a first frame above a Hello's size is refused before its body
// arrives; partial frames over all connections stay under `max_buffered_bytes`, the connection
// holding the largest closed first.
#[test]
fn partial_frames_bounded() {
    let mut w = World::new();
    let budget = 20 << 20;
    let h = w.add_hub(Policy { max_buffered_bytes: budget, ..Policy::default() });
    let now = w.now();
    let hub = &mut w.hubs[h];
    // before Hello: a frame header of MAX_MESSAGE closes at once
    hub.accept(now, 1, [1; 32]);
    let out = hub.input(now, 1, (osis_core::format::MAX_MESSAGE as u32).to_be_bytes().to_vec());
    assert!(out.contains(&HubOutput::Close(1)), "{out:?}");
    assert_eq!(hub.buffered(), 0);
    // after Hello: each connection starts a MAX_MESSAGE frame and sends 8 MiB of it
    let mut closed = 0;
    for id in 10..14u64 {
        hub.accept(now, id, [id as u8; 32]);
        hub.input(now, id, encode_frame(&Hello::new(now, [2; 32]).encode()));
        let mut bytes = (osis_core::format::MAX_MESSAGE as u32).to_be_bytes().to_vec();
        bytes.extend(vec![0u8; 8 << 20]);
        let out = hub.input(now, id, bytes);
        closed += out.iter().filter(|o| matches!(o, HubOutput::Close(_))).count();
        assert!(hub.buffered() <= budget, "{} buffered", hub.buffered());
    }
    assert_eq!(closed, 2, "two of four over the budget");
}

// spec/wire.md §11.2 Register, spec/sync.md §5: node-wide caps refuse new labels (Error 12) and new entries (code 12)
#[test]
fn node_wide_caps() {
    let mut w = World::new();
    let h = w.add_hub(Policy { max_labels: 2, max_entries: 3, ..Policy::default() });
    let c = w.connect(h);
    let (l1, l2, l3) = (Label::new(3), Label::new(4), Label::new(5));
    w.setup(c, &l1);
    w.setup(c, &l2);
    let ev = w.run(c, l3.register_cmd(0));
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::STORAGE_CAP, .. }]), "{ev:?}");
    let ev = w.run(c, Command::Upload { label: l1.id, entries: (0..2).map(|n| l1.entry(blob(n))).collect() });
    assert_eq!(statuses(&ev), vec![Code::OK; 2]);
    let ev = w.run(c, Command::Upload { label: l2.id, entries: (2..4).map(|n| l2.entry(blob(n))).collect() });
    assert_eq!(statuses(&ev), vec![Code::OK, Code::STORAGE_CAP]);
    assert_eq!(w.hubs[h].store().totals().unwrap().entries, 3);
}

// spec/sync.md §5 Expiry: sweeps run in bounded steps; the hub asks for another tick at once while work remains
#[test]
fn sweeps_are_bounded() {
    let mut w = World::new();
    let h = w.add_hub(Policy::default());
    let c = w.connect(h);
    let l = Label::new(3);
    w.setup(c, &l);
    let t = w.now() + 1_000;
    w.run(c, Command::Upload { label: l.id, entries: (0..2500).map(|n| l.entry(blob_with(n, t, vec![]))).collect() });
    w.clock.advance(1_000);
    let now = w.now();
    w.hubs[h].tick(now);
    assert_eq!(live(&w, h, &l).len(), 2500 - 1024);
    assert_eq!(w.hubs[h].next_due(now), Some(now));
    w.settle();
    assert!(live(&w, h, &l).is_empty());
    assert_eq!(w.hubs[h].store().totals().unwrap().entries, 0);
}

// spec: none (sweep robustness): an unparsable index row is dropped; a failing sweep backs off instead of spinning
#[test]
fn sweep_junk_and_failures() {
    let faults = Faults::new();
    let mut backend = MemoryBackend::with_faults(faults.clone());
    let clock = Arc::new(ManualClock::new(WallMs(T0)));
    let mut b = WriteBatch::new();
    b.put([&b"X"[..], &0u64.to_be_bytes(), &[1, 2, 3]].concat(), vec![]);
    backend.commit(b).unwrap();
    let store = BackendStore::open(backend.clone(), clock, Policy::default(), &mut SeededRng::from_seed([1; 32])).unwrap();
    let mut hub = Hub::new(store, [1; 32], Box::new(SeededRng::from_seed([2; 32])));
    assert_eq!(hub.next_due(T0), Some(0));
    faults.at(0, Fault::Fail);
    let out = hub.tick(T0);
    assert!(out.iter().any(|o| matches!(o, HubOutput::Diagnostic(d) if d.starts_with("sweep"))), "{out:?}");
    assert_eq!(hub.next_due(T0), Some(T0 + 1_000));
    assert!(hub.tick(T0 + 999).is_empty());
    assert!(hub.tick(T0 + 1_000).is_empty());
    assert_eq!(hub.next_due(T0 + 1_000), None);
    assert!(backend.scan_prefix(b"X", 10).unwrap().is_empty());
}

// spec/sync.md §5: a replication batch refused for now (code 12) does not advance the position; the label is retried and converges once the peer has room
#[test]
fn replication_retries_after_refusal() {
    let mut w = World::new();
    let (s1, s2) = (w.add_hub(Policy::default()), w.add_hub(Policy { cap_entries: 3, ..Policy::default() }));
    let a = w.connect(s1);
    let l = Label::new(3);
    w.setup(a, &l);
    w.run(a, Command::Upload { label: l.id, entries: (0..5).map(|n| l.entry(blob(n))).collect() });
    w.peer(s1, s2);
    assert_eq!(live(&w, s2, &l).len(), 3);
    let head = LabelStore::log_head(w.hubs[s1].store(), &l.id).unwrap();
    let pos = w.hubs[s1].store().replica_pos(&hub_key(s2), &l.id).unwrap();
    assert!(pos.is_none_or(|p| p.1 < head.1), "{pos:?}");
    assert!(w.diagnostics.iter().any(|d| d.contains("retrying")), "{:?}", w.diagnostics);
    // a retry while the peer is still full changes nothing
    w.advance(1_000);
    assert_eq!(live(&w, s2, &l).len(), 3);
    w.restart(s2, Policy::default());
    w.peer(s1, s2);
    assert_eq!(live(&w, s2, &l), sorted((0..5).map(bid).collect()));
    assert_eq!(w.hubs[s1].store().replica_pos(&hub_key(s2), &l.id).unwrap(), Some(head));
}

// spec/sync.md §5: two servers replicating to each other converge without sending entries back; one entry with two wraps settles
#[test]
fn mutual_replication_settles() {
    let mut w = World::new();
    let (s1, s2) = (w.add_hub(Policy::default()), w.add_hub(Policy::default()));
    let (a, b) = (w.connect(s1), w.connect(s2));
    let l = Label::new(3);
    w.setup(a, &l);
    w.setup(b, &l);
    let x = blob(100);
    let e1 = l.entry(x.clone());
    let mut e2 = e1.clone();
    e2.wrap = [0x77; 49];
    e2.stamp = osis_label::sign_stamp(&l.head_keys().write, &l.id, &osis_label::blob_id(&x), &e2.wrap);
    w.peer(s1, s2);
    w.peer(s2, s1);
    // both wraps arrive at once, each at one side
    w.send(a, Command::Upload { label: l.id, entries: vec![e1] });
    w.send(b, Command::Upload { label: l.id, entries: vec![e2] });
    w.pump();
    w.settle();
    w.run(a, Command::Upload { label: l.id, entries: (0..10).map(|n| l.entry(blob(n))).collect() });
    let heads = |w: &World| [s1, s2].map(|h| LabelStore::log_head(w.hubs[h].store(), &l.id).unwrap().1);
    let settled = heads(&w);
    // genesis, 11 adds, at most one wrap replacement each side
    assert!(settled.iter().all(|h| *h <= 13), "{settled:?}");
    assert_eq!(live(&w, s1, &l), live(&w, s2, &l));
    w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(blob(50))] });
    let after = heads(&w);
    assert_eq!(after, [settled[0] + 1, settled[1] + 1], "one add each, no echo");
    assert!(w.diagnostics.is_empty(), "{:?}", w.diagnostics);
}
