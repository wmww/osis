//! Client engines against host engines over in-memory byte queues, with a `MemoryLabelStore`
//! (spec/sync.md §4-§9, spec/wire.md §11).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_base::{LabelId, Value, cbor};
use osis_crypto::{Secret32, SigningSecret};
use osis_proto::msg::DeleteItem;
use osis_proto::*;
use osis_proto::examples::{Label, bid, blob, blob_with, salt};
use osis_proto::client::SMALL_REPLY;
use std::collections::VecDeque;

fn s32(b: u8) -> Secret32 {
    Secret32::from_bytes([b; 32])
}

const T0: u64 = 1_700_000_000_000;

/// Clients each on their own connection to one host store.
struct Net {
    now: u64,
    host_skew: u64,
    store: MemoryLabelStore,
    hosts: Vec<ServingSession>,
    clients: Vec<ClientSession>,
    events: Vec<Vec<ClientEvent>>,
    to_host: Vec<VecDeque<Vec<u8>>>,
    to_client: Vec<VecDeque<Vec<u8>>>,
    /// Events of the handshake, per client.
    handshake: Vec<Vec<ClientEvent>>,
    /// Message flights delivered by `pump` (one direction each).
    flights: usize,
}

impl Net {
    fn new(n: usize, host_skew: u64) -> Net {
        let mut net = Net { now: T0, host_skew, store: MemoryLabelStore::new(), hosts: vec![], clients: vec![], events: vec![], to_host: vec![], to_client: vec![], handshake: vec![], flights: 0 };
        for i in 0..n {
            net.hosts.push(ServingSession::new(ServingConfig { static_key: [0x5e; 32], challenge: [0x40 + i as u8; 32] }));
            net.clients.push(ClientSession::new(ClientConfig { peer_static_key: [0x5e; 32], challenge: [0x80 + i as u8; 32] }));
            net.events.push(vec![]);
            net.to_host.push(VecDeque::new());
            net.to_client.push(VecDeque::new());
            let so = net.hosts[i].handle(T0 + host_skew, &mut net.store, ServingInput::Start);
            net.host_out(i, so);
            let co = net.clients[i].handle(T0, ClientInput::Start);
            net.client_out(i, co);
        }
        net.pump();
        net.handshake = net.events.iter_mut().map(std::mem::take).collect();
        net
    }

    fn client_out(&mut self, i: usize, out: Vec<ClientOutput>) {
        for o in out {
            match o {
                ClientOutput::Send(b) => self.to_host[i].push_back(b),
                ClientOutput::Event(e) => self.events[i].push(e),
                ClientOutput::Close | ClientOutput::SetTimer(_) => {}
            }
        }
    }

    fn host_out(&mut self, i: usize, out: Vec<ServingOutput>) {
        for o in out {
            match o {
                ServingOutput::Send(b) => self.to_client[i].push_back(b),
                ServingOutput::Close | ServingOutput::PeerError(_) | ServingOutput::Request(_) | ServingOutput::Room { .. } | ServingOutput::Peer(_) => {}
                ServingOutput::StoreError(e) => panic!("{e}"),
            }
        }
    }

    fn pump(&mut self) {
        loop {
            let mut moved = false;
            for i in 0..self.clients.len() {
                let bytes: Vec<u8> = self.to_host[i].drain(..).flatten().collect();
                if !bytes.is_empty() {
                    moved = true;
                    let so = self.hosts[i].handle(self.now + self.host_skew, &mut self.store, ServingInput::Bytes(bytes));
                    self.host_out(i, so);
                }
            }
            if moved {
                self.flights += 1;
            }
            let mut back = false;
            for i in 0..self.clients.len() {
                let bytes: Vec<u8> = self.to_client[i].drain(..).flatten().collect();
                if !bytes.is_empty() {
                    back = true;
                    let co = self.clients[i].handle(self.now, ClientInput::Bytes(bytes));
                    self.client_out(i, co);
                }
            }
            if back {
                self.flights += 1;
            }
            if !moved && !back {
                return;
            }
        }
    }

    /// Runs a command to quiescence and returns the events it produced.
    fn run(&mut self, i: usize, c: Command) -> Vec<ClientEvent> {
        let co = self.clients[i].handle(self.now, ClientInput::Command(c));
        self.client_out(i, co);
        self.pump();
        std::mem::take(&mut self.events[i])
    }


    fn setup(&mut self, l: &Label) {
        let ev = self.run(0, Command::Register { label: l.id, step: l.steps[0].clone(), claim_set: Some(l.sets[0].clone()) });
        assert_eq!(ev, vec![ClientEvent::Registered { label: l.id }]);
    }

    /// Holds `blob` under `l`, stamped by the head's write key (as node sync's pull puts one).
    fn hold(&mut self, l: &Label, blob: &[u8]) {
        let e = l.entry(blob.to_vec());
        let put = Put { blob_id: osis_label::blob_id(blob), blob, wrap: e.wrap, stamp: Some(e.stamp), expiry: None, ephemeral: false, now: self.now, role: false };
        assert_eq!(self.store.put(&l.id, put).unwrap(), Code::OK);
    }

    /// Node sync's open of `l` on connection `i` (a sync-key or static-entry Hit there).
    fn open(&mut self, i: usize, l: &Label) {
        let so = self.hosts[i].handle(self.now + self.host_skew, &mut self.store, ServingInput::Open(l.id));
        self.host_out(i, so);
    }
}

fn statuses(ev: &[ClientEvent]) -> Vec<Code> {
    ev.iter()
        .flat_map(|e| match e {
            ClientEvent::DeleteStatus { codes, .. } => codes.clone(),
            _ => vec![],
        })
        .collect()
}

// spec/wire.md §11.1, spec/sync.md §6: Hellos at once, clock offset from three round trips, diagnostic above a few seconds
/// A header blind (spec/crypto.md §7).
const HB: [u8; 16] = [0x4b; 16];

#[test]
fn handshake_and_clock_offset() {
    let net = Net::new(1, 3_000);
    let ev = net.handshake[0].clone();
    assert!(matches!(ev[0], ClientEvent::Ready { version: 1 }));
    let offsets: Vec<_> = ev.iter().filter(|e| matches!(e, ClientEvent::ClockOffset { .. })).collect();
    assert_eq!(offsets, vec![&ClientEvent::ClockOffset { offset_ms: 3_000, diagnostic: false }]);
    let mut net = Net::new(1, 60_000);
    assert!(net.handshake[0].contains(&ClientEvent::ClockOffset { offset_ms: 60_000, diagnostic: true }));
    let out = net.clients[0].handle(T0 + 1, ClientInput::Timer);
    assert!(out.iter().any(|o| matches!(o, ClientOutput::SetTimer(t) if *t > T0)));
}

// spec/sync.md §5 (Register): a step that is no child of the head is refused with code 9 alone,
// never the head; the head itself is answered Ok
#[test]
fn a_step_off_the_head_is_refused_9_alone_spec_sync_5() {
    let mut net = Net::new(1, 0);
    let mut l = Label::new(3);
    net.setup(&l);
    let (child, cs) = l.rotate(20);
    let ev = net.run(0, Command::Register { label: l.id, step: child.clone(), claim_set: Some(cs) });
    assert_eq!(ev, vec![ClientEvent::Registered { label: l.id }]);
    let ev = net.run(0, Command::Register { label: l.id, step: child, claim_set: None });
    assert_eq!(ev, vec![ClientEvent::Registered { label: l.id }]);
    let mut fork = Label::new(3);
    let (other, _) = fork.rotate(40);
    let ev = net.run(0, Command::Register { label: l.id, step: other, claim_set: None });
    assert!(matches!(&ev[..], [ClientEvent::Refused { kind: osis_proto::Request::Register, code: Code::NOT_HEAD, .. }]), "{ev:?}");
}

// spec/sync.md §5, spec/crypto.md §7: deletes by key and by a level's delete key (level 3 write key, levels 1-2 sync key)
#[test]
fn deletes() {
    let mut net = Net::new(1, 0);
    let l = Label::new(3);
    net.setup(&l);
    net.open(0, &l);
    let dk = |t: &Secret32| osis_crypto::DeleteSecret::derive(t);
    let commit = |level: u8, t: &Secret32, n: u64| osis_crypto::commitment(level, &dk(t).verifying_key(), &salt(n), &HB).unwrap();
    let (t1, t3, t9) = (s32(1), s32(3), s32(9));
    let b3 = blob_with(10, 0, vec![commit(3, &t3, 10)]);
    let b1 = blob_with(11, 0, vec![commit(1, &t1, 11)]);
    let b_plain = blob(12);
    for b in [&b3, &b1, &b_plain] {
        net.hold(&l, b);
    }
    let k = l.head_keys().clone();
    let item = |b: &[u8], n: u64, by: (u8, &Secret32), signer: &SigningSecret| DeleteItem::sign_by(signer, &[(by.0, &dk(by.1))], &salt(n), &HB, &l.id, osis_label::blob_id(b)).unwrap();
    let ev = net.run(0, Command::Delete { label: l.id, items: vec![item(&b3, 10, (3, &t3), &k.sync), item(&b3, 10, (3, &t9), &k.write), item(&b3, 10, (1, &t3), &k.sync), item(&b1, 11, (1, &t1), &k.sync)] });
    assert_eq!(statuses(&ev), vec![Code::REFUSED, Code::REFUSED, Code::REFUSED, Code::OK]);
    let ev = net.run(0, Command::Delete { label: l.id, items: vec![item(&b3, 10, (3, &t3), &k.write)] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    let ev = net.run(0, Command::Delete { label: l.id, items: vec![DeleteItem::sign(&k.delete, &l.id, osis_label::blob_id(&b_plain)).unwrap()] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    for b in [&b3, &b1, &b_plain] {
        let id = osis_label::blob_id(b);
        assert!(net.store.entry(&l.id, &id).unwrap().is_none() && net.store.tombstoned(&l.id, &id).unwrap());
    }
}

// spec/sync.md §5 (Delete, an open holds under the head's sync key): a Delete is taken only
// where node sync opened the label by a sync-key or static-entry Hit; a head with another sync
// key ends that open on every connection, the registrar's included, until node sync opens it
// again. A step keeping the sync key keeps them; Register needs no open.
// spec/sync.md §5 (delete opened)
#[test]
fn deletes_need_an_open_under_the_heads_sync_key_spec_sync_5() {
    let mut net = Net::new(2, 0);
    let mut l = Label::new(3);
    net.setup(&l);
    let mut n = 0;
    let mut delete = |net: &mut Net, i: usize, l: &Label| {
        n += 1;
        let b = blob(100 + n);
        net.hold(l, &b);
        let item = DeleteItem::sign(&l.head_keys().delete, &l.id, osis_label::blob_id(&b)).unwrap();
        net.run(i, Command::Delete { label: l.id, items: vec![item] })
    };
    let refused = |ev: &[ClientEvent]| matches!(ev, [ClientEvent::Refused { kind: Request::Delete, code: Code::NOT_OPENED, .. }]);
    let ev = delete(&mut net, 0, &l);
    assert!(refused(&ev), "not opened: {ev:?}");
    for i in 0..2 {
        net.open(i, &l);
    }
    // a step without a read rotation: the opens hold
    let (same, cs) = l.rotate(1);
    assert_eq!(same.keys.sync, l.steps[0].keys.sync);
    net.run(0, Command::Register { label: l.id, step: same, claim_set: Some(cs) });
    for i in 0..2 {
        assert_eq!(statuses(&delete(&mut net, i, &l)), vec![Code::OK]);
    }
    // a read rotation, registered by client 0: both opens end
    let (child, cs) = l.rotate(20);
    let ev = net.run(0, Command::Register { label: l.id, step: child, claim_set: Some(cs) });
    assert_eq!(ev, vec![ClientEvent::Registered { label: l.id }]);
    for i in 0..2 {
        let ev = delete(&mut net, i, &l);
        assert!(refused(&ev), "{ev:?}");
    }
    // opened again under the new key; a shut one refuses again
    net.open(1, &l);
    assert_eq!(statuses(&delete(&mut net, 1, &l)), vec![Code::OK]);
    let so = net.hosts[1].handle(net.now, &mut net.store, ServingInput::Shut(l.id));
    net.host_out(1, so);
    let ev = delete(&mut net, 1, &l);
    assert!(refused(&ev), "{ev:?}");
}

// spec/wire.md §11.1, §11.2: unknown kind gets Error 11, a malformed request Error 2 (both sides), a bad frame Error 2 and close
#[test]
fn bad_frames() {
    let mut net = Net::new(1, 0);
    let raw = |v: Value| encode_frame(&cbor::encode(&v));
    let mut bytes = raw(Value::List(vec![Value::Int(99), Value::Int(5)]));
    bytes.extend(raw(Value::List(vec![Value::Int(19), Value::Int(6), Value::Bytes(vec![0; 16]), Value::List(vec![])])));
    let decode_sent = |out: Vec<Vec<u8>>| out.iter().map(|f| Message::decode(&f[4..]).unwrap()).collect::<Vec<_>>();
    let so = net.hosts[0].handle(T0, &mut net.store, ServingInput::Bytes(bytes.clone()));
    let want = vec![Message::Error { id: 5, code: Code::UNSUPPORTED }, Message::Error { id: 6, code: Code::MALFORMED }];
    assert_eq!(decode_sent(so.into_iter().filter_map(|o| if let ServingOutput::Send(f) = o { Some(f) } else { None }).collect()), want);
    let co = net.clients[0].handle(T0, ClientInput::Bytes(bytes));
    assert_eq!(decode_sent(co.into_iter().filter_map(|o| if let ClientOutput::Send(f) = o { Some(f) } else { None }).collect()), want);
    let so = net.hosts[0].handle(T0, &mut net.store, ServingInput::Bytes(vec![0, 0, 0, 0]));
    assert!(so.contains(&ServingOutput::Close));
    assert!(net.hosts[0].is_closed());
    let mut s = ServingSession::new(ServingConfig { static_key: [0; 32], challenge: [0; 32] });
    let h = Hello { versions: vec![7], wall_ms: 0, challenge: [0; 32] };
    let so = s.handle(T0, &mut net.store, ServingInput::Bytes(encode_frame(&h.encode())));
    assert!(so.contains(&ServingOutput::Close));
}

// spec/wire.md §11.2 (retired kinds): a request of a retired kind in its old layout (an Upload
// of a stamped entry, a Deposit, a Sync from no cursor, a Subscribe) on an opened label is
// answered Error 11 and changes nothing: no entry, no event, no push
#[test]
fn retired_kinds_change_nothing_spec_wire_11_2() {
    let mut net = Net::new(1, 0);
    let l = Label::new(3);
    net.setup(&l);
    net.open(0, &l);
    let b = blob(40);
    let e = l.entry(b.clone());
    let id = Value::bytes(&l.id.0);
    let entry = Value::List(vec![Value::bytes(&b), Value::bytes(&e.wrap), Value::bytes(&e.stamp.0)]);
    let dep = l.deposit(b.clone(), &l.head_keys().deposit.clone());
    let osis_proto::msg::OfferItem::Deposit { wrap, sig, .. } = dep else { panic!("a deposit") };
    let reqs = [
        vec![Value::Int(10), Value::Int(5), id.clone(), Value::List(vec![entry.clone()])],
        vec![Value::Int(12), Value::Int(6), id.clone(), Value::bytes(&b), Value::bytes(&wrap), Value::bytes(&sig.0)],
        vec![Value::Int(15), Value::Int(7), id.clone(), Value::opt(None), Value::Int(0), Value::Int(SMALL_REPLY as i64), Value::List(vec![entry]), Value::List(vec![])],
        vec![Value::Int(21), Value::Int(8), Value::List(vec![id])],
    ];
    let bytes: Vec<u8> = reqs.into_iter().flat_map(|r| encode_frame(&cbor::encode(&Value::List(r)))).collect();
    let so = net.hosts[0].handle(T0, &mut net.store, ServingInput::Bytes(bytes));
    let sent: Vec<Message> = so.iter().filter_map(|o| if let ServingOutput::Send(f) = o { Message::decode(&f[4..]).ok() } else { None }).collect();
    assert_eq!(sent, (5..=8).map(|id| Message::Error { id, code: Code::UNSUPPORTED }).collect::<Vec<_>>());
    assert!(so.iter().all(|o| matches!(o, ServingOutput::Send(_) | ServingOutput::PeerError(_))), "{so:?}");
    assert_eq!(net.store.live_ids(&l.id).unwrap(), vec![]);
    assert!(net.store.blob(&osis_label::blob_id(&b)).unwrap().is_none());
    assert!(!net.hosts[0].is_closed());
}

/// The frames a session sent in `out`, decoded.
fn sent_msgs<'a>(out: impl IntoIterator<Item = &'a ClientOutput>) -> Vec<Message> {
    out.into_iter().filter_map(|o| if let ClientOutput::Send(f) = o { Message::decode(&f[4..]).ok() } else { None }).collect()
}

/// Relay-only Stream frames, each carrying an 8 MiB blob, at least `total` bytes in all.
fn filler(total: usize) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    let mut n = 0;
    while n < total {
        let ev = Event::Added { blob_id: bid(frames.len() as u64), blob: Some(vec![0; 8 << 20]), wrap: [0; osis_crypto::WRAP_LEN], stamp: None };
        let f = encode_frame(&stream(LabelId([7; 16]), ev, None).encode());
        n += f.len();
        frames.push(f);
    }
    frames
}

/// A Stream of one event.
fn stream(l: LabelId, ev: Event, cursor: Option<Vec<u8>>) -> Message {
    Message::Stream(Box::new(osis_proto::msg::Stream { events: vec![(l, ev)], cursor, report: false }))
}

/// A node's Fetch of one blob asking `max_reply`.
fn node_fetch(k: u32, max_reply: usize) -> Message {
    Message::Fetch { id: osis_proto::msg::NODE_IDS | k, label: LabelId([7; 16]), max_reply: max_reply as u64, ids: vec![bid(1)] }
}

/// Whether `out` carries the answer to a node's Fetch.
fn fetched(out: &[ClientOutput]) -> bool {
    out.iter().any(|o| matches!(o, ClientOutput::Event(ClientEvent::Peer(m)) if matches!(**m, Message::FetchReply { .. })))
}

/// A session past its Hello with its clock pings answered: nothing of its own in flight.
fn quiet_session() -> ClientSession {
    let mut c = ClientSession::new(ClientConfig { peer_static_key: [1; 32], challenge: [2; 32] });
    c.handle(T0, ClientInput::Start);
    let mut out = c.handle(T0, ClientInput::Bytes(encode_frame(&Hello::new(T0, [3; 32]).encode())));
    loop {
        let pongs: Vec<u8> = sent_msgs(&out).into_iter().filter_map(|m| if let Message::Ping { id, .. } = m { Some(encode_frame(&Message::Pong { id, wall_ms: T0 }.encode())) } else { None }).flatten().collect();
        if pongs.is_empty() {
            break;
        }
        out = c.handle(T0, ClientInput::Bytes(pongs));
    }
    assert_eq!((c.outstanding(), c.in_flight()), (0, 0));
    c
}

// spec/sync.md §6 (stall): the oldest request in flight not moving closes the connection at the
// deadline (the node redials). Its frame taken by the transport moves it, and so do the first
// bytes of a reply to it; a reply to a later request moves nothing, other bytes (a push, the
// peer's own request) only until `MAX_AHEAD` of them arrived since it last moved by its own
#[test]
fn stalled_requests_time_out() {
    let t = client::STALL_TIMEOUT_MS;
    let mut c = ClientSession::new(ClientConfig { peer_static_key: [1; 32], challenge: [2; 32] });
    c.handle(T0, ClientInput::Start);
    let hello = encode_frame(&Hello::new(T0, [3; 32]).encode());
    let out = c.handle(T0, ClientInput::Bytes(hello));
    assert!(out.iter().any(|o| matches!(o, ClientOutput::SetTimer(x) if *x == T0 + t)), "{out:?}");
    let pings: Vec<u32> = sent_msgs(&out).iter().filter_map(|m| if let Message::Ping { id, .. } = m { Some(*id) } else { None }).collect();
    assert_eq!(pings.len(), 3);
    // the transport takes part of the pings: they had not all left yet
    let out = c.handle(T0 + t - 1, ClientInput::Taken(5));
    assert!(out.iter().any(|o| matches!(o, ClientOutput::SetTimer(x) if *x == T0 + 2 * t - 1)), "{out:?}");
    // a push backlog moves it while within `MAX_AHEAD`: an honest peer's reply can be behind it
    let mut moved = false;
    for f in filler(client::MAX_AHEAD + 1) {
        let out = c.handle(T0 + t, ClientInput::Bytes(f));
        moved |= out.iter().any(|o| matches!(o, ClientOutput::SetTimer(x) if *x == T0 + 2 * t));
    }
    assert!(moved, "the push backlog moved it");
    // past it bytes of other kinds move nothing: a push, the peer's own request, a later ping's
    // answer
    let push = stream(LabelId([7; 16]), Event::Deleted(bid(1)), Some(vec![1; 72]));
    let mut other = encode_frame(&push.encode());
    other.extend(encode_frame(&Message::Ping { id: 9, wall_ms: T0 }.encode()));
    other.extend(encode_frame(&Message::Pong { id: pings[2], wall_ms: T0 }.encode()));
    let out = c.handle(T0 + 2 * t - 3, ClientInput::Bytes(other));
    assert!(!out.iter().any(|o| matches!(o, ClientOutput::SetTimer(_))), "{out:?}");
    // the first bytes of the oldest's answer move it
    let pong = encode_frame(&Message::Pong { id: pings[0], wall_ms: T0 }.encode());
    c.handle(T0 + 2 * t - 2, ClientInput::Bytes(pong[..7].to_vec()));
    let early = c.handle(T0 + 3 * t - 3, ClientInput::Timer);
    assert!(!early.iter().any(|o| matches!(o, ClientOutput::Close)));
    let late = c.handle(T0 + 3 * t - 2, ClientInput::Timer);
    assert!(late.iter().any(|o| matches!(o, ClientOutput::Close)), "{late:?}");
    assert!(c.is_closed());
}

// spec/sync.md §6 (stall, honest slow peers): a reply trickling in over many stall times keeps
// the connection, as do answers one after another each within the stall time
#[test]
fn slow_replies_keep_the_connection_spec_sync_6() {
    let t = client::STALL_TIMEOUT_MS;
    let mut c = ClientSession::new(ClientConfig { peer_static_key: [1; 32], challenge: [2; 32] });
    c.handle(T0, ClientInput::Start);
    let out = c.handle(T0, ClientInput::Bytes(encode_frame(&Hello::new(T0, [3; 32]).encode())));
    let pings: Vec<u32> = sent_msgs(&out).iter().filter_map(|m| if let Message::Ping { id, .. } = m { Some(*id) } else { None }).collect();
    let mut now = T0;
    for id in &pings[..2] {
        now += t - 1;
        c.handle(now, ClientInput::Bytes(encode_frame(&Message::Pong { id: *id, wall_ms: now }.encode())));
        assert!(!c.handle(now, ClientInput::Timer).iter().any(|o| matches!(o, ClientOutput::Close)));
    }
    let l = LabelId([7; 16]);
    let out = c.handle(now, ClientInput::Command(Command::Peer(Box::new(Message::Fetch { id: osis_proto::msg::NODE_IDS | 1, label: l, max_reply: osis_proto::serving::REPLY_BUDGET as u64, ids: vec![bid(1)] }))));
    let fetch = sent_msgs(&out).iter().find_map(|m| if let Message::Fetch { id, .. } = m { Some(*id) } else { None }).unwrap();
    c.handle(now, ClientInput::Bytes(encode_frame(&Message::Pong { id: pings[2], wall_ms: now }.encode())));
    // a 60 KiB answer at 1 KiB per 100 s
    let reply = encode_frame(&Message::FetchReply { id: fetch, items: vec![Fetched { blob_id: bid(1), entry: Some((vec![5; 60 << 10], [0; osis_crypto::WRAP_LEN], None)) }] }.encode());
    let mut got = false;
    for piece in reply.chunks(1024) {
        now += t - 20_000;
        let out = c.handle(now, ClientInput::Bytes(piece.to_vec()));
        got |= fetched(&out);
        assert!(!c.handle(now, ClientInput::Timer).iter().any(|o| matches!(o, ClientOutput::Close)), "closed at {} s", (now - T0) / 1000);
    }
    assert!(got, "the answer arrived");
    assert!(!c.is_closed());
}

// spec/sync.md §6 (stall, honest slow peers): a reply queued behind a full push backlog (pushes
// held within `REPLY_BUDGET`, one push frame past it) on a link far slower than that backlog per
// stall time keeps the connection: the pushes move the oldest request while within `MAX_AHEAD`
#[test]
fn a_slow_reply_behind_a_full_push_backlog_keeps_the_connection_spec_sync_6() {
    let t = client::STALL_TIMEOUT_MS;
    let mut c = quiet_session();
    let out = c.handle(T0, ClientInput::Command(Command::Peer(Box::new(node_fetch(1, client::FIRST_REPLY)))));
    let fetch = sent_msgs(&out).iter().find_map(|m| if let Message::Fetch { id, .. } = m { Some(*id) } else { None }).unwrap();
    let blob = vec![5; osis_proto::serving::REPLY_BUDGET - 1024];
    let push = |seq| encode_frame(&stream(LabelId([8; 16]), Event::Added { blob_id: bid(seq), blob: Some(blob.clone()), wrap: [0; osis_crypto::WRAP_LEN], stamp: None }, Some(seq.to_be_bytes().to_vec())).encode());
    let mut link = push(1);
    link.extend(push(2));
    link.extend(encode_frame(&Message::FetchReply { id: fetch, items: vec![] }.encode()));
    // 64 KiB every 4 s (16 KB/s): the backlog alone takes about 20 min
    let mut now = T0;
    let mut answered = false;
    for piece in link.chunks(64 << 10) {
        now += 4000;
        let out = c.handle(now, ClientInput::Bytes(piece.to_vec()));
        answered |= fetched(&out);
        assert!(!c.handle(now, ClientInput::Timer).iter().any(|o| matches!(o, ClientOutput::Close)), "closed at {} s", (now - T0) / 1000);
    }
    assert!(now - T0 > 4 * t, "slower than the stall time");
    assert!(answered && !c.is_closed());
}

// spec/sync.md §6 (stall): a peer pushing at full speed while answering nothing is closed one
// stall time after `MAX_AHEAD` bytes, however much it pushes on
#[test]
fn a_pusher_answering_nothing_is_closed_after_max_ahead_spec_sync_6() {
    let t = client::STALL_TIMEOUT_MS;
    let mut c = quiet_session();
    c.handle(T0, ClientInput::Command(Command::Peer(Box::new(node_fetch(1, client::FIRST_REPLY)))));
    let mut bytes = 0;
    for f in filler(client::MAX_AHEAD + 1) {
        bytes += f.len();
        c.handle(T0 + 1, ClientInput::Bytes(f));
    }
    assert!(bytes <= client::MAX_AHEAD + (9 << 20), "{bytes}");
    let small = encode_frame(&stream(LabelId([8; 16]), Event::Deleted(bid(1)), Some(vec![1; 72])).encode());
    let mut now = T0 + 1;
    while now < T0 + 1 + t - 1000 {
        now += 1000;
        c.handle(now, ClientInput::Bytes(small.clone()));
        assert!(!c.handle(now, ClientInput::Timer).iter().any(|o| matches!(o, ClientOutput::Close)), "closed early at {} s", (now - T0) / 1000);
    }
    let late = c.handle(T0 + 1 + t, ClientInput::Timer);
    assert!(late.iter().any(|o| matches!(o, ClientOutput::Close)), "{late:?}");
}

// spec/sync.md §6 (stall: replies to other requests move nothing): a peer that answers every
// later request, whole or in pieces, while the oldest goes unanswered is closed at the stall time;
// Notifies beside those replies (a client-port `settle` waiting behind them) keep it
#[test]
fn answering_later_requests_holds_no_older_one_spec_sync_6() {
    let t = client::STALL_TIMEOUT_MS;
    let fetch = |id| Message::Fetch { id: osis_proto::msg::NODE_IDS | id, label: LabelId([7; 16]), max_reply: client::FIRST_REPLY as u64, ids: vec![bid(1)] };
    let closed = |out: &[ClientOutput]| out.iter().any(|o| matches!(o, ClientOutput::Close));
    for notifies in [false, true] {
        let mut c = quiet_session();
        c.handle(T0 + 1, ClientInput::Command(Command::Peer(Box::new(fetch(1)))));
        let (mut now, mut k) = (T0 + 1, 2);
        while now < T0 + 1 + t - 10_000 {
            now += 10_000;
            c.handle(now, ClientInput::Command(Command::Peer(Box::new(fetch(k)))));
            let reply = encode_frame(&Message::FetchReply { id: osis_proto::msg::NODE_IDS | k, items: Vec::new() }.encode());
            // the first piece holds its kind and id
            let (a, b) = reply.split_at(reply.len() - 1);
            c.handle(now, ClientInput::Bytes(a.to_vec()));
            c.handle(now, ClientInput::Bytes(b.to_vec()));
            if notifies {
                c.handle(now, ClientInput::Bytes(encode_frame(&Message::Notify { sub: 1, payload: osis_proto::api::Payload::Lapsed }.encode())));
            }
            k += 1;
            assert!(!closed(&c.handle(now, ClientInput::Timer)), "notifies {notifies}: closed early at {} s", (now - T0) / 1000);
        }
        assert!(c.in_flight() < 2 * client::FIRST_REPLY, "notifies {notifies}: the later ones answered");
        let late = c.handle(T0 + 1 + t, ClientInput::Timer);
        assert_eq!(closed(&late), !notifies, "notifies {notifies}: {late:?}");
    }
}

// spec/sync.md §6 (a node's own requests count as any): a peer silent on a stream Fetch is
// closed at the stall deadline, and the quiet ping sends nothing meanwhile
#[test]
fn a_silent_node_request_times_out_spec_sync_6() {
    let t = client::STALL_TIMEOUT_MS;
    let mut c = ClientSession::new(ClientConfig { peer_static_key: [1; 32], challenge: [2; 32] });
    c.handle(T0, ClientInput::Start);
    let mut out = c.handle(T0, ClientInput::Bytes(encode_frame(&Hello::new(T0, [3; 32]).encode())));
    // the clock pings answered: nothing of the session's own in flight
    loop {
        let pongs: Vec<u8> = out.iter().filter_map(|o| if let ClientOutput::Send(f) = o { Message::decode(&f[4..]).ok() } else { None }).filter_map(|m| if let Message::Ping { id, .. } = m { Some(encode_frame(&Message::Pong { id, wall_ms: T0 }.encode())) } else { None }).flatten().collect();
        if pongs.is_empty() {
            break;
        }
        out = c.handle(T0, ClientInput::Bytes(pongs));
    }
    assert_eq!((c.outstanding(), c.in_flight()), (0, 0));
    let fetch = Message::Fetch { id: osis_proto::msg::NODE_IDS | 1, label: LabelId([7; 16]), max_reply: client::FIRST_REPLY as u64, ids: vec![bid(1)] };
    let out = c.handle(T0 + 1, ClientInput::Command(Command::Peer(Box::new(fetch))));
    assert!(out.iter().any(|o| matches!(o, ClientOutput::SetTimer(x) if *x == T0 + 1 + t)), "{out:?}");
    let quiet = c.ping_if_quiet(T0 + t, 1000);
    assert!(!quiet.iter().any(|o| matches!(o, ClientOutput::Send(_))), "{quiet:?}");
    let late = c.handle(T0 + 1 + t, ClientInput::Timer);
    assert!(late.iter().any(|o| matches!(o, ClientOutput::Close)), "{late:?}");
}

// spec/sync.md §6 (stall, whichever side dialed): the listener's own request to the dialer
// stalls as the dialer's would, however much the dialer pushes and asks meanwhile; an answer's
// first bytes move it, and the transport taking its frame does too
#[test]
fn a_listener_request_stalls_while_the_dialer_answers_nothing_spec_sync_6() {
    let t = client::STALL_TIMEOUT_MS;
    let mut store = MemoryLabelStore::new();
    let mut s = ServingSession::new(ServingConfig { static_key: [1; 32], challenge: [2; 32] });
    let bytes = |out: Vec<ServingOutput>| out.iter().map(|o| if let ServingOutput::Send(f) = o { f.len() } else { 0 }).sum::<usize>();
    let mut written = bytes(s.handle(T0, &mut store, ServingInput::Start));
    written += bytes(s.handle(T0, &mut store, ServingInput::Bytes(encode_frame(&Hello::new(T0, [3; 32]).encode()))));
    assert_eq!(s.stall_at(), None, "nothing asked");
    let fetch = |id| Message::Fetch { id: osis_proto::msg::NODE_IDS | id, label: LabelId([7; 16]), max_reply: client::FIRST_REPLY as u64, ids: vec![bid(1)] };
    written += bytes(s.handle(T0, &mut store, ServingInput::Peer(Box::new(fetch(1)))));
    s.handle(T0 + 1, &mut store, ServingInput::Peer(Box::new(fetch(2))));
    assert_eq!(s.stall_at(), Some(T0 + t));
    // the transport takes the first request's frame (the Hello before it): it was not out yet
    s.handle(T0 + 10, &mut store, ServingInput::Taken(written as u64));
    assert_eq!(s.stall_at(), Some(T0 + 10 + t));
    // later takes are of the second request: the first is with the peer
    s.handle(T0 + 20, &mut store, ServingInput::Taken(written as u64 + 5));
    assert_eq!(s.stall_at(), Some(T0 + 10 + t));
    // the dialer's own messages move it until `MAX_AHEAD` of them came (one per input: what a
    // single input may carry is bounded apart)
    for f in filler(client::MAX_AHEAD + 1) {
        s.handle(T0 + 30, &mut store, ServingInput::Bytes(f));
    }
    assert_eq!(s.stall_at(), Some(T0 + 30 + t));
    // past it the dialer pings and asks, and answers the second request only: nothing moves
    let mut other = encode_frame(&Message::Ping { id: 1, wall_ms: T0 }.encode());
    other.extend(encode_frame(&Message::Pull(Box::new(osis_proto::msg::Pull { id: osis_proto::msg::NODE_IDS | 1, cursor: None, joins: vec![], inline_limit: 0, max_reply: client::FIRST_REPLY as u64, follow: true, ephemeral: false })).encode()));
    other.extend(encode_frame(&Message::FetchReply { id: osis_proto::msg::NODE_IDS | 2, items: vec![] }.encode()));
    s.handle(T0 + t - 1, &mut store, ServingInput::Bytes(other));
    assert_eq!(s.stall_at(), Some(T0 + 30 + t));
    // the first one's answer starting moves it; the rest of it answers it and none is out
    let reply = encode_frame(&Message::FetchReply { id: osis_proto::msg::NODE_IDS | 1, items: vec![] }.encode());
    s.handle(T0 + t, &mut store, ServingInput::Bytes(reply[..11].to_vec()));
    assert_eq!(s.stall_at(), Some(T0 + 2 * t));
    s.handle(T0 + t + 1, &mut store, ServingInput::Bytes(reply[11..].to_vec()));
    assert_eq!(s.stall_at(), None);
    assert!(!s.is_closed());
}

// spec/sync.md §6 (flow control): a client within its window never sends more unanswered
// requests than `MAX_UNANSWERED`, so a host delivering everything it sent in one input (as
// `pump` does) closes nothing: deletes past a window's worth queued at once all complete
#[test]
fn queued_requests_stay_within_the_unanswered_bound() {
    let mut net = Net::new(2, 0);
    let l = Label::new(3);
    net.setup(&l);
    net.open(1, &l);
    let n = 4 * client::WINDOW / SMALL_REPLY;
    let mut co = Vec::new();
    for k in 0..n as u64 {
        let c = &mut net.clients[1];
        let item = DeleteItem::sign(&l.head_keys().delete, &l.id, bid(k)).unwrap();
        co.extend(c.handle(net.now, ClientInput::Command(Command::Delete { label: l.id, items: vec![item] })));
    }
    assert!(net.clients[1].unsent() > 0, "the window holds some back");
    net.client_out(1, co);
    net.pump();
    assert!(!net.hosts[1].is_closed());
    let ev = std::mem::take(&mut net.events[1]);
    assert_eq!(ev.iter().filter(|e| matches!(e, ClientEvent::DeleteStatus { .. })).count(), n, "deletes");
    assert_eq!(net.clients[1].outstanding(), 0);
}

/// A node's own requests (spec/wire.md §11.2: a Pull and top-bit Fetches of several labels),
/// all asking `REPLY_BUDGET`, made at once.
fn node_requests() -> Vec<Message> {
    use osis_proto::msg::{NODE_IDS, Pull};
    let budget = osis_proto::serving::REPLY_BUDGET as u64;
    let id = |k: u32| NODE_IDS | (1 << 30) | k;
    let mut reqs = vec![Message::Pull(Box::new(Pull { id: id(1), cursor: None, joins: vec![], inline_limit: 0, max_reply: budget, follow: true, ephemeral: true }))];
    reqs.extend((2..10u32).map(|k| Message::Fetch { id: id(k), label: LabelId([k as u8; 16]), max_reply: budget, ids: vec![bid(u64::from(k))] }));
    reqs
}

/// The node's answer to one of `node_requests`.
fn node_answer(m: &Message) -> Message {
    match m {
        Message::Pull(p) => Message::PullReply(Box::new(osis_proto::msg::PullReply { id: p.id, events: vec![], cursor: None, whole: true, trimmed: false, more: false, report: false, joins: vec![] })),
        Message::Fetch { id, .. } => Message::FetchReply { id: *id, items: vec![] },
        m => panic!("{m:?}"),
    }
}

/// Frame bytes plus reply allowances of the requests in `bytes` (`MAX_UNANSWERED`'s count).
fn charged(bytes: &[u8]) -> usize {
    let mut d = FrameDecoder::new();
    d.push(bytes);
    let mut n = 0;
    while let Ok(Some(body)) = d.next_frame() {
        n += body.len() + 4 + osis_proto::client::allowance(&Message::decode(&body).unwrap());
    }
    n
}

// spec/sync.md §6 (flow control), spec/wire.md §11.2 (Pull): a node's own requests go within the
// request window with every other, from the dialer's session and from the listener's: a Pull
// and stream Fetches of several labels made at once, everything sent delivered as one input (a
// real driver's read of several frames), close nothing and are all answered
#[test]
fn node_requests_stay_within_the_unanswered_bound_spec_sync_6() {
    // dialer to listener: the listener closes a connection past `MAX_UNANSWERED`
    let mut net = Net::new(1, 0);
    let mut co = Vec::new();
    for m in node_requests() {
        co.extend(net.clients[0].handle(net.now, ClientInput::Command(Command::Peer(Box::new(m)))));
    }
    net.client_out(0, co);
    let mut answered = 0;
    loop {
        let bytes: Vec<u8> = net.to_host[0].drain(..).flatten().collect();
        if bytes.is_empty() {
            break;
        }
        let so = net.hosts[0].handle(net.now, &mut net.store, ServingInput::Bytes(bytes));
        assert!(!net.hosts[0].is_closed(), "closed past the unanswered bound");
        for o in so {
            if let ServingOutput::Peer(m) = o {
                let so = net.hosts[0].handle(net.now, &mut net.store, ServingInput::Peer(Box::new(node_answer(&m))));
                net.host_out(0, so);
            }
        }
        let bytes: Vec<u8> = net.to_client[0].drain(..).flatten().collect();
        let co = net.clients[0].handle(net.now, ClientInput::Bytes(bytes));
        answered += co.iter().filter(|o| matches!(o, ClientOutput::Event(ClientEvent::Peer(m)) if matches!(**m, Message::PullReply(_) | Message::FetchReply { .. }))).count();
        net.client_out(0, co);
    }
    assert_eq!(answered, node_requests().len());
    assert_eq!(net.clients[0].in_flight(), 0);
    // listener to dialer: no input the dialer gets carries more
    let mut net = Net::new(1, 0);
    let mut so = Vec::new();
    for m in node_requests() {
        so.extend(net.hosts[0].handle(net.now, &mut net.store, ServingInput::Peer(Box::new(m))));
    }
    net.host_out(0, so);
    let mut answered = 0;
    loop {
        let bytes: Vec<u8> = net.to_client[0].drain(..).flatten().collect();
        if bytes.is_empty() {
            break;
        }
        assert!(charged(&bytes) <= osis_proto::client::MAX_UNANSWERED, "past the unanswered bound");
        let co = net.clients[0].handle(net.now, ClientInput::Bytes(bytes));
        for o in co {
            if let ClientOutput::Event(ClientEvent::Peer(m)) = o {
                let co = net.clients[0].handle(net.now, ClientInput::Command(Command::Peer(Box::new(node_answer(&m)))));
                net.client_out(0, co);
            }
        }
        let bytes: Vec<u8> = net.to_host[0].drain(..).flatten().collect();
        let so = net.hosts[0].handle(net.now, &mut net.store, ServingInput::Bytes(bytes));
        answered += so.iter().filter(|o| matches!(o, ServingOutput::Peer(m) if matches!(**m, Message::PullReply(_) | Message::FetchReply { .. }))).count();
        net.host_out(0, so);
    }
    assert_eq!(answered, node_requests().len());
}

/// Ids of the requests whole frames `bytes` hold.
fn request_ids(bytes: &[u8]) -> Vec<u32> {
    let mut d = FrameDecoder::new();
    d.push(bytes);
    let mut ids = Vec::new();
    while let Ok(Some(body)) = d.next_frame() {
        let m = Message::decode(&body).unwrap();
        if m.is_request() {
            ids.push(m.id());
        }
    }
    ids
}

// spec/sync.md §6 (Requester: in the order made), spec/wire.md §11.2 (Pull: a stream request
// still out when a later one's answer arrives was skipped): the window holds back whole-budget
// Fetches, and a Pull made after them, though it would fit, waits its turn, from either side.
// So a peer answering in arrival order answers in the order made, and a held-back request is
// never counted skipped
#[test]
fn held_back_node_requests_keep_their_order_spec_sync_6() {
    use osis_proto::msg::{NODE_IDS, Pull};
    let budget = osis_proto::serving::REPLY_BUDGET as u64;
    let id = |k: u32| NODE_IDS | (1 << 30) | k;
    let mut reqs: Vec<Message> = (1..=3u32).map(|k| Message::Fetch { id: id(k), label: LabelId([k as u8; 16]), max_reply: budget, ids: vec![bid(u64::from(k))] }).collect();
    reqs.push(Message::Pull(Box::new(Pull { id: id(4), cursor: None, joins: vec![], inline_limit: 0, max_reply: SMALL_REPLY as u64, follow: true, ephemeral: false })));
    let made: Vec<u32> = reqs.iter().map(Message::id).collect();
    // dialer's requests
    let mut net = Net::new(1, 0);
    let mut co = Vec::new();
    for m in reqs.clone() {
        co.extend(net.clients[0].handle(net.now, ClientInput::Command(Command::Peer(Box::new(m)))));
    }
    net.client_out(0, co);
    let (mut sent, mut answered) = (Vec::new(), Vec::new());
    loop {
        let bytes: Vec<u8> = net.to_host[0].drain(..).flatten().collect();
        if bytes.is_empty() {
            break;
        }
        sent.push(request_ids(&bytes));
        let so = net.hosts[0].handle(net.now, &mut net.store, ServingInput::Bytes(bytes));
        for o in so {
            if let ServingOutput::Peer(m) = o {
                let so = net.hosts[0].handle(net.now, &mut net.store, ServingInput::Peer(Box::new(node_answer(&m))));
                net.host_out(0, so);
            }
        }
        let bytes: Vec<u8> = net.to_client[0].drain(..).flatten().collect();
        let co = net.clients[0].handle(net.now, ClientInput::Bytes(bytes));
        answered.extend(co.iter().filter_map(|o| if let ClientOutput::Event(ClientEvent::Peer(m)) = o { Some(m.id()) } else { None }));
        net.client_out(0, co);
    }
    assert_eq!(sent[0], made[..2], "the window holds back the rest");
    assert_eq!(answered, made, "dialer");
    // listener's requests
    let mut net = Net::new(1, 0);
    let mut so = Vec::new();
    for m in reqs {
        so.extend(net.hosts[0].handle(net.now, &mut net.store, ServingInput::Peer(Box::new(m))));
    }
    net.host_out(0, so);
    let (mut sent, mut answered) = (Vec::new(), Vec::new());
    loop {
        let bytes: Vec<u8> = net.to_client[0].drain(..).flatten().collect();
        if bytes.is_empty() {
            break;
        }
        sent.push(request_ids(&bytes));
        let co = net.clients[0].handle(net.now, ClientInput::Bytes(bytes));
        for o in co {
            if let ClientOutput::Event(ClientEvent::Peer(m)) = o {
                let co = net.clients[0].handle(net.now, ClientInput::Command(Command::Peer(Box::new(node_answer(&m)))));
                net.client_out(0, co);
            }
        }
        let bytes: Vec<u8> = net.to_host[0].drain(..).flatten().collect();
        let so = net.hosts[0].handle(net.now, &mut net.store, ServingInput::Bytes(bytes));
        answered.extend(so.iter().filter_map(|o| if let ServingOutput::Peer(m) = o { Some(m.id()) } else { None }));
        net.host_out(0, so);
    }
    assert_eq!(sent[0], made[..2], "the window holds back the rest");
    assert_eq!(answered, made, "listener");
}
