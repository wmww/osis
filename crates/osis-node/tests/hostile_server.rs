#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A malicious blind node against a node's sync engine (spec/requirements.md: "Nothing trusts a
//! server's word"; "Peer input never causes unbounded allocation, work, storage or
//! diagnostics"): frames injected on a node's server connection, or a scripted server.

mod net;
use net::*;
use osis_core::format::MAX_DRIFT_MS;
use osis_core::{Ak, LabelId, Role, Value};
use osis_crypto::{Epoch, LabelRole, Secret32, SeededRng, label_role_key};
use osis_label::{Parent, StepKeys, genesis_label, register};
use osis_node::sync::{Action, ConnId, Event, SyncEngine};
use osis_proto::{Cursor, FrameDecoder, Hello, Message, encode_frame};

fn frame(m: Message) -> Vec<u8> {
    encode_frame(&m.encode())
}

/// Messages a node sent in `acts` on `conn`.
fn sent(acts: &[Action], conn: ConnId) -> Vec<Message> {
    let mut out = Vec::new();
    for a in acts {
        if let Action::Send { conn: c, bytes } = a
            && *c == conn
        {
            let mut d = FrameDecoder::new();
            d.push(bytes);
            while let Ok(Some(body)) = d.next_frame() {
                if let Ok(m) = Message::decode(&body) {
                    out.push(m);
                }
            }
        }
    }
    out
}

/// A valid genesis step of some other label.
fn foreign_step(b: u8) -> osis_label::Step {
    let (read, write, admin, dep) = (Secret32::from_bytes([b; 32]), Secret32::from_bytes([b + 1; 32]), Secret32::from_bytes([b + 2; 32]), Secret32::from_bytes([b + 3; 32]));
    let keys = StepKeys::derive(&read, &write, &admin, 0, &dep, &genesis_label(&admin, 0));
    let delete = label_role_key(LabelRole::Delete, &admin, 0);
    register(Parent::Genesis(&delete), keys, &[], (Epoch::new(0, [0; 16]).unwrap(), &read), &mut SeededRng::from_u64(b as u64)).unwrap().0
}

// spec/wire.md §11.2 (Push: "the peer then sends Push" for subscribed labels only), spec/
// requirements.md (peer input never causes unbounded storage): a Push for a label the node never
// opened on that connection stores no entry and no blob.
#[test]
fn unsolicited_push_stores_nothing_spec_wire_11_2() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    net.item(a, g, g, "x");
    net.run();
    let conn = net.conn_to(a, sv).expect("connected");
    let junk = LabelId([0x77; 16]);
    let blobs: Vec<Vec<u8>> = (0..50u8).map(|i| vec![i; 64]).collect();
    let events = blobs.iter().map(|b| osis_proto::Event::Added { blob_id: osis_label::blob_id(b), blob: Some(b.clone()), wrap: [1; 49], stamp: None }).collect();
    net.feed(a, Event::Bytes { conn, bytes: frame(Message::Push { label: junk, events, cursor: Cursor { log_id: [0; 16], seq: 1 } }) });
    net.settle(10_000);
    assert!(net.sync(a).entries(&junk).is_empty(), "no entry under a label not opened");
    for b in &blobs {
        assert!(!net.sync(a).holds_blob(&osis_label::blob_id(b)), "no blob stored");
    }
}

// spec/sync.md §5 (walk: "verifying each step under its parent's delete key, the genesis step
// against the label ID"), spec/requirements.md (no unbounded allocation): a server path that
// does not verify is refused at its first page, not buffered until the server ends it.
#[test]
fn bad_path_refused_at_first_page_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let _g = net.group(a, &[], &[sv]);
    let mut se: SyncEngine = net.take(a);
    let acts = se.handle(Event::Local);
    let conn = acts.iter().find_map(|x| if let Action::Dial { conn, .. } = x { Some(*conn) } else { None }).expect("dial");
    se.handle(Event::Up { conn });
    let acts = se.handle(Event::Bytes { conn, bytes: encode_frame(&Hello::new(net.now(), [9; 32]).encode()) });
    let (id, label) = sent(&acts, conn).into_iter().find_map(|m| if let Message::Open { id, label, .. } = m { Some((id, label)) } else { None }).expect("open");
    // an unrecorded head: the node asks for the path to verify it
    let acts = se.handle(Event::Bytes { conn, bytes: frame(Message::Opened { id, head: foreign_step(40), entry_box: None }) });
    let pid = sent(&acts, conn).into_iter().find_map(|m| if let Message::Path { id, label: l, .. } = m { (l == label).then_some(id) } else { None }).expect("path");
    se.take_diagnostics();
    se.handle(Event::Bytes { conn, bytes: frame(Message::PathReply { id: pid, steps: vec![foreign_step(50); 4], more: true }) });
    let d = se.take_diagnostics();
    assert!(d.iter().any(|x| x.contains("server path does not verify")), "refused at the first page: {d:?}");
}

// spec/sync.md §9 (receivers drop a signal whose `ts` is more than `MAX_DRIFT` from their
// corrected clock): a server replaying a captured signal later fires nothing.
#[test]
fn replayed_signal_dropped_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "x");
    net.run();
    let acts = net.sync(a).signal(&t, Ak::new("/t/typing").unwrap(), Value::Bool(true), None).unwrap();
    let conn_a = net.conn_to(a, sv).unwrap();
    let captured = sent(&acts, conn_a).into_iter().find(|m| matches!(m, Message::Signal { .. })).expect("signal sent");
    net.actions(a, acts);
    net.settle(10_000);
    assert_eq!(net.sync(b).take_signals().len(), 1, "delivered once");
    net.clock.advance(MAX_DRIFT_MS + 60_000);
    let conn_b = net.conn_to(b, sv).unwrap();
    net.feed(b, Event::Bytes { conn: conn_b, bytes: frame(captured) });
    assert!(net.sync(b).take_signals().is_empty(), "a stale replay fires nothing");
}
