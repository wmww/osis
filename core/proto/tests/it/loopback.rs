//! Client engines against host engines over in-memory byte queues, with a `MemoryLabelStore`
//! (spec/sync.md §4-§9, spec/wire.md §11).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_base::{BlobId, LabelId, Value, WallMs, cbor, hash::hash};
use osis_crypto::{Secret32, SigningSecret};
use osis_label::{Prefix, sign_deposit};
use osis_proto::msg::{DeleteItem, Wrap};
use osis_proto::*;
use osis_proto::examples::{Label, bid, blob, blob_sized, blob_with, salt};
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
        let mut net = Net { now: T0, host_skew, store: MemoryLabelStore::new([9; 32]), hosts: vec![], clients: vec![], events: vec![], to_host: vec![], to_client: vec![], handshake: vec![], flights: 0 };
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
                ServingOutput::Changed(l) => {
                    for j in 0..self.hosts.len() {
                        let so = self.hosts[j].handle(self.now + self.host_skew, &mut self.store, ServingInput::Changed(l));
                        self.host_out(j, so);
                    }
                }
                ServingOutput::Relay(r) => {
                    for j in (0..self.hosts.len()).filter(|j| *j != i) {
                        let so = self.hosts[j].handle(self.now + self.host_skew, &mut self.store, ServingInput::Relay(r.clone()));
                        self.host_out(j, so);
                    }
                }
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

    fn open(&mut self, i: usize, l: &Label) {
        let ev = self.run(i, Command::Open { label: l.id, key: OpenKey::Sync { step: None, key: l.head_keys().sync.clone() } });
        assert!(matches!(&ev[..], [ClientEvent::Opened { .. }]), "{ev:?}");
    }
}

fn events_of(ev: &[ClientEvent]) -> (Vec<Event>, Option<Cursor>) {
    let mut all = vec![];
    let mut cursor = None;
    for e in ev {
        if let ClientEvent::Events { events, cursor: c, .. } = e {
            all.extend(events.iter().cloned());
            cursor = *c;
        }
    }
    (all, cursor)
}

fn statuses(ev: &[ClientEvent]) -> Vec<Code> {
    ev.iter()
        .flat_map(|e| match e {
            ClientEvent::EntryStatus { codes, .. } | ClientEvent::DeleteStatus { codes, .. } => codes.clone(),
            _ => vec![],
        })
        .collect()
}

fn added(evs: &[Event]) -> Vec<BlobId> {
    evs.iter().filter_map(|e| if let Event::Added { blob_id, .. } = e { Some(*blob_id) } else { None }).collect()
}

fn sync(label: LabelId, cursor: Option<Cursor>, entries: Vec<Entry>, gained: Vec<BlobId>) -> Command {
    Command::Sync { label, cursor, inline_limit: 1 << 20, entries, gained }
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

// spec/sync.md §5, §6: register, open, upload inline with Sync, download by replay, cursor sync with gained and want
#[test]
fn register_open_sync_download() {
    let mut net = Net::new(2, 0);
    let l = Label::new(3);
    net.setup(&l);
    net.open(0, &l);
    net.open(1, &l);
    let ev = net.run(0, sync(l.id, None, (0..50).map(|n| l.entry(blob(n))).collect(), vec![]));
    assert_eq!(statuses(&ev), vec![Code::OK; 50]);
    // the uploader gets no add events for what it sent
    let (evs, c0) = events_of(&ev);
    assert!(evs.is_empty(), "{evs:?}");
    assert!(c0.is_some());
    // B replays every live entry in blob ID order, blobs inline, stamps and wraps
    let ev = net.run(1, sync(l.id, None, vec![], vec![]));
    let (evs, cursor) = events_of(&ev);
    let mut want: Vec<BlobId> = (0..50).map(bid).collect();
    want.sort();
    assert_eq!(added(&evs), want);
    let Event::Added { blob: Some(b), wrap, stamp: Some(s), .. } = &evs[0] else { panic!() };
    let e = l.entry(b.clone());
    assert_eq!((*wrap, *s), (e.wrap, e.stamp));
    assert!(ev.contains(&ClientEvent::Synced { label: l.id }));
    // A adds 5 more; B's cursor sync returns exactly those, minus what B gained elsewhere
    net.run(0, Command::Upload { label: l.id, entries: (50..55).map(|n| l.entry(blob(n))).collect() });
    let ev = net.run(1, sync(l.id, cursor, vec![], vec![bid(52), bid(100), bid(101)]));
    assert_eq!(added(&events_of(&ev).0), [50, 51, 53, 54].map(bid));
    assert!(ev.contains(&ClientEvent::Want { label: l.id, ids: vec![bid(100), bid(101)] }));
}

// spec/wire.md §11.2 Sync: a replay pages by blob ID position and ends with the log cursor taken at its start
#[test]
fn replay_on_a_truncated_log_ends_with_a_cursor() {
    let mut net = Net::new(2, 0);
    let l = Label::new(3);
    net.setup(&l);
    net.open(0, &l);
    net.open(1, &l);
    for n in 0..3 {
        let ev = net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob_sized(n, 0, vec![], 4 << 20))] });
        assert_eq!(statuses(&ev), vec![Code::OK]);
    }
    let head = net.store.log_head(&l.id).unwrap().1;
    net.store.truncate_log(&l.id, head);
    let ev = net.run(1, Command::Sync { label: l.id, cursor: None, inline_limit: u64::MAX, entries: vec![], gained: vec![] });
    let pages = ev.iter().filter(|e| matches!(e, ClientEvent::Events { .. })).count();
    assert!(pages >= 2, "{pages} pages");
    assert_eq!(added(&events_of(&ev).0).len(), 3);
    assert!(ev.contains(&ClientEvent::Synced { label: l.id }));
    let cursor = events_of(&ev).1.unwrap();
    assert_eq!(cursor.seq, head);
    // the cursor works: a later upload arrives by it
    net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(9))] });
    let ev = net.run(1, sync(l.id, Some(cursor), vec![], vec![]));
    assert_eq!(added(&events_of(&ev).0), vec![bid(9)]);
}

// spec/sync.md §6, spec/wire.md §11.2: a cursor the log was trimmed past gets Error 15 (one of another log or past the head, 10); the Sync's entries still go up; reconciliation finds both differences
#[test]
fn lost_cursor_falls_back_to_reconciliation() {
    let mut net = Net::new(2, 0);
    let l = Label::new(3);
    net.setup(&l);
    net.open(0, &l);
    net.open(1, &l);
    net.run(0, Command::Upload { label: l.id, entries: (0..300).map(|n| l.entry(blob(n))).collect() });
    let ev = net.run(1, sync(l.id, None, vec![], vec![]));
    let (_, cursor) = events_of(&ev);
    net.run(0, Command::Upload { label: l.id, entries: (300..340).map(|n| l.entry(blob(n))).collect() });
    let c = cursor.unwrap();
    for other in [Cursor { log_id: [9; 16], ..c }, Cursor { seq: c.seq + 1000, ..c }] {
        let ev = net.run(1, sync(l.id, Some(other), vec![], vec![]));
        assert_eq!(ev, vec![ClientEvent::NeedReconcile { label: l.id, trimmed: false }]);
    }
    net.store.truncate_log(&l.id, c.seq + 1);
    let ev = net.run(1, sync(l.id, cursor, vec![l.entry(blob(2000))], vec![]));
    assert!(ev.contains(&ClientEvent::NeedReconcile { label: l.id, trimmed: true }), "{ev:?}");
    assert_eq!(statuses(&ev), vec![Code::OK]);
    // B holds 0..300, 2000 and 1000..1010 of its own
    let ids: Vec<BlobId> = (0..300).chain(1000..1010).chain([2000]).map(bid).collect();
    let ev = net.run(1, Command::Reconcile { label: l.id, ids });
    let mut need: Vec<BlobId> = (300..340).map(bid).collect();
    let mut have: Vec<BlobId> = (1000..1010).map(bid).collect();
    need.sort();
    have.sort();
    assert_eq!(ev, vec![ClientEvent::Reconciled { label: l.id, need, have }]);
}

// spec/sync.md §6: a gained list over a message (4096 IDs) falls back to reconciliation
#[test]
fn oversized_gained_list_reconciles() {
    let mut net = Net::new(1, 0);
    let l = Label::new(3);
    net.setup(&l);
    net.open(0, &l);
    let gained: Vec<BlobId> = (0..4097u64).map(|n| BlobId(hash(&n.to_le_bytes()))).collect();
    let ev = net.run(0, sync(l.id, Some(Cursor { log_id: [0; 16], seq: 0 }), vec![], gained));
    assert_eq!(ev, vec![ClientEvent::NeedReconcile { label: l.id, trimmed: false }]);
    assert_eq!(net.clients[0].outstanding(), 0);
}

// spec/sync.md §5: a superseded sync key gets the child step and nothing else; the child verifies under its parent's delete key
// spec/sync.md §5 (stale sync key), §5 (register)
#[test]
fn stale_sync_key_gets_one_signed_step() {
    let mut net = Net::new(1, 0);
    let mut l = Label::new(3);
    net.setup(&l);
    let old = l.head_keys().clone();
    let (child, cs) = l.rotate(20);
    let ev = net.run(0, Command::Register { label: l.id, step: child.clone(), claim_set: Some(cs) });
    assert_eq!(ev, vec![ClientEvent::Registered { label: l.id }]);
    let ev = net.run(0, Command::Open { label: l.id, key: OpenKey::Sync { step: None, key: old.sync.clone() } });
    let [ClientEvent::Step { step, .. }] = &ev[..] else { panic!("{ev:?}") };
    assert_eq!(step, &child);
    step.verify_child(&l.steps[0]).unwrap();
    // not opened: reads refused
    let ev = net.run(0, sync(l.id, None, vec![], vec![]));
    assert!(matches!(&ev[..], [ClientEvent::Refused { kind: osis_proto::Request::Sync, code: Code::NOT_OPENED, .. }]), "{ev:?}");
    let ev = net.run(0, Command::Open { label: l.id, key: OpenKey::Sync { step: None, key: SigningSecret::from_seed(&s32(99)) } });
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::REFUSED, .. }]));
    // a step on another branch is refused with code 9 alone, never the head (spec/sync.md §5)
    let mut fork = Label::new(3);
    let (other, _) = fork.rotate(40);
    let ev = net.run(0, Command::Register { label: l.id, step: other, claim_set: None });
    assert!(matches!(&ev[..], [ClientEvent::Refused { kind: osis_proto::Request::Register, code: Code::NOT_HEAD, .. }]), "{ev:?}");
    net.open(0, &l);
    let ev = net.run(0, Command::Path { label: l.id, after: None });
    assert_eq!(ev, vec![ClientEvent::PathSteps { label: l.id, steps: l.steps.clone(), more: false }]);
    let ev = net.run(0, Command::Path { label: l.id, after: Some(l.steps[0].id()) });
    assert_eq!(ev, vec![ClientEvent::PathSteps { label: l.id, steps: vec![child], more: false }]);
}

// spec/sync.md §5: claim keys open at the head or get the child; static entries open with the entry box; a dropped set serves no claims
// spec/sync.md §5 (claim refusals), §5 (dropped claim set)
#[test]
fn claim_and_static_opens() {
    let mut net = Net::new(1, 0);
    let mut l = Label::new(3);
    net.setup(&l);
    let claim = |l: &Label, i: usize| Command::Open { label: l.id, key: OpenKey::Claim { step: l.steps[i].id(), key: l.steps[i].claim_key(&l.reader).unwrap() } };
    let ev = net.run(0, claim(&l, 0));
    assert!(matches!(&ev[..], [ClientEvent::Opened { entry_box: None, .. }]), "{ev:?}");
    let ev = net.run(0, Command::Open { label: l.id, key: OpenKey::Static(l.key_actor.clone()) });
    let want_box = l.sets[0].entry_box(&l.id, &l.key_actor.verifying_key()).cloned();
    assert!(want_box.is_some());
    assert!(matches!(&ev[..], [ClientEvent::Opened { entry_box, .. }] if *entry_box == want_box), "{ev:?}");
    let ev = net.run(0, Command::Open { label: l.id, key: OpenKey::Claim { step: l.steps[0].id(), key: SigningSecret::from_seed(&s32(0x77)) } });
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::REFUSED, .. }]));
    let (child, _) = l.rotate(20);
    net.run(0, Command::Register { label: l.id, step: child.clone(), claim_set: None });
    let ev = net.run(0, claim(&l, 0));
    assert!(matches!(&ev[..], [ClientEvent::Step { step, .. }] if *step == child), "{ev:?}");
    // the head was registered without its set; then the genesis set is dropped
    let ev = net.run(0, claim(&l, 1));
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::REFUSED, .. }]));
    net.store.drop_claim_set(&l.id, &l.steps[0].id());
    let ev = net.run(0, claim(&l, 0));
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::REFUSED, .. }]));
}

// spec/sync.md §5: stamps under the head's write key; an old key gets 9 alone; expiry, tombstone, unknown label; identical re-uploads log nothing
// spec/sync.md §5 (upload refusals): bad stamp, expired, tombstoned
#[test]
fn upload_rules() {
    let mut net = Net::new(1, 0);
    let mut l = Label::new(3);
    net.setup(&l);
    let old = l.head_keys().clone();
    let mut bad = l.entry(blob(2));
    bad.stamp.0[0] ^= 1;
    let ev = net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(1)), bad, l.entry(blob_with(3, T0 - 1, vec![])), l.entry(blob_with(4, T0 + 1000, vec![]))] });
    assert_eq!(statuses(&ev), vec![Code::OK, Code::REFUSED, Code::EXPIRED, Code::OK]);
    let seq = net.store.log_head(&l.id).unwrap().1;
    let ev = net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(1))] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    assert_eq!(net.store.log_head(&l.id).unwrap().1, seq);
    let (child, cs) = l.rotate(20);
    net.run(0, Command::Register { label: l.id, step: child.clone(), claim_set: Some(cs) });
    let ev = net.run(0, Command::Upload { label: l.id, entries: vec![l.entry_by(blob(5), &old.write), l.entry(blob(6))] });
    assert!(matches!(&ev[..], [ClientEvent::EntryStatus { codes, .. }] if *codes == vec![Code::NOT_HEAD, Code::OK]), "{ev:?}");
    net.open(0, &l);
    let item = DeleteItem::sign(&l.head_keys().delete, &l.id, bid(6)).unwrap();
    let ev = net.run(0, Command::Delete { label: l.id, items: vec![item] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    let ev = net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(6))] });
    assert_eq!(statuses(&ev), vec![Code::TOMBSTONED]);
    let ev = net.run(0, Command::Upload { label: LabelId([0xee; 16]), entries: vec![l.entry(blob(7))] });
    assert_eq!(statuses(&ev), vec![Code::UNKNOWN_LABEL]);
    // a prefix without room for a ciphertext is malformed
    let mut short = Prefix::new(salt(8), None, vec![]).unwrap().to_bytes();
    short.push(0);
    let ev = net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(short)] });
    assert_eq!(statuses(&ev), vec![Code::MALFORMED]);
}

// spec/sync.md §5 (upload refusals): an oversized blob is refused by the session (the message
// decoder's cap is the only check: `accept` has none of its own) and nothing is logged
#[test]
fn oversized_upload_refused_spec_sync_5() {
    let mut net = Net::new(1, 0);
    let l = Label::new(3);
    net.setup(&l);
    let seq = net.store.log_head(&l.id).unwrap().1;
    let big = l.entry(blob_sized(1, 0, vec![], osis_base::format::MAX_BLOB));
    let body = Message::Upload { id: 77, label: l.id, entries: vec![big] }.encode();
    assert!(body.len() < osis_base::format::MAX_MESSAGE);
    let so = net.hosts[0].handle(T0, &mut net.store, ServingInput::Bytes(encode_frame(&body)));
    net.host_out(0, so);
    let reply: Vec<u8> = net.to_client[0].drain(..).flatten().collect();
    let mut d = FrameDecoder::new();
    d.set_max(osis_base::format::MAX_MESSAGE);
    d.push(&reply);
    let m = Message::decode(&d.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(m, Message::Error { id: 77, code: Code::MALFORMED });
    assert_eq!(net.store.log_head(&l.id).unwrap().1, seq);
}

// spec/sync.md §5: an Error reply to a deposit (the host's store failed) is a refusal for now: the
// node holds it as unanswered otherwise, and `send_outbox` paces the label's others behind it
#[test]
fn deposit_answered_by_an_error_is_refused_for_now_spec_sync_5() {
    let mut net = Net::new(1, 0);
    let l = Label::new(3);
    net.setup(&l);
    let (b, wrap): (Vec<u8>, Wrap) = (blob(0), [7; osis_crypto::WRAP_LEN]);
    let blob_id = osis_label::blob_id(&b);
    let sig = sign_deposit(&l.head_keys().deposit, &l.id, &blob_id, &wrap);
    let co = net.clients[0].handle(net.now, ClientInput::Command(Command::Deposit { label: l.id, blob: b, wrap, sig }));
    net.client_out(0, co);
    let mut d = FrameDecoder::default();
    d.push(&net.to_host[0].pop_front().unwrap());
    let id = Message::decode(&d.next_frame().unwrap().unwrap()).unwrap().id();
    let co = net.clients[0].handle(net.now, ClientInput::Bytes(encode_frame(&Message::Error { id, code: Code::REFUSED }.encode())));
    net.client_out(0, co);
    let ev = std::mem::take(&mut net.events[0]);
    assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::RATE_LIMITED, budget: None, blob_id: x, .. }] if *x == blob_id), "{ev:?}");
}

// spec/sync.md §5: deposits by the deposit key within the budget (64 + 4 x claim slots), refused when full
#[test]
fn deposit_budget() {
    let mut net = Net::new(1, 0);
    let l = Label::new(3);
    net.setup(&l);
    let max = 64 + 4 * l.sets[0].claims.len() as u64;
    let deposit = |l: &Label, n: u64, k: &SigningSecret| {
        let b = blob(n);
        let wrap: Wrap = [7; osis_crypto::WRAP_LEN];
        let sig = sign_deposit(k, &l.id, &osis_label::blob_id(&b), &wrap);
        Command::Deposit { label: l.id, blob: b, wrap, sig }
    };
    let dk = l.head_keys().deposit.clone();
    let ev = net.run(0, deposit(&l, 0, &dk));
    assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::OK, budget: Some((n, _)), .. }] if *n == max - 1), "{ev:?}");
    // a deposit not signed by the deposit key learns its code only, not the budget
    let ev = net.run(0, deposit(&l, 1, &l.head_keys().write.clone()));
    assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::REFUSED, budget: None, .. }]), "{ev:?}");
    for n in 1..max {
        net.run(0, deposit(&l, n, &dk));
    }
    let ev = net.run(0, deposit(&l, 500, &dk));
    assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::BUDGET_FULL, budget: Some((0, _)), .. }]), "{ev:?}");
    // stamping a deposited entry takes it out of the budget
    let ev = net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(0))] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    let ev = net.run(0, deposit(&l, 500, &dk));
    assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::OK, budget: Some((0, _)), .. }]), "{ev:?}");
    net.open(0, &l);
    let (evs, _) = events_of(&net.run(0, sync(l.id, None, vec![], vec![])));
    assert!(evs.iter().any(|e| matches!(e, Event::Added { stamp: None, .. })));
}

// spec/sync.md §5 (readers write no ephemeral data; security review M5): an ephemeral or
// relay-only blob deposited (no stamp) is refused by the host engine itself, whatever the store
// behind it checks (a co-reader peer's store did not), and nothing is stored or pushed
#[test]
fn ephemeral_deposit_refused_spec_sync_5() {
    let mut net = Net::new(2, 0);
    let l = Label::new(3);
    net.setup(&l);
    net.open(1, &l);
    net.run(1, Command::Subscribe { labels: vec![l.id] });
    let dk = l.head_keys().deposit.clone();
    for (n, class) in [(1u8, osis_label::Class::Ephemeral), (2, osis_label::Class::Relay)] {
        let p = Prefix::new(salt(u64::from(n)), Some(WallMs(T0 + osis_base::format::MAX_DRIFT_MS)), vec![]).unwrap().with_class(class);
        let b = osis_label::frame(&p, &[n; 50], &mut osis_crypto::SeededRng::from_seed([n; 32])).unwrap().1;
        let wrap: Wrap = [7; osis_crypto::WRAP_LEN];
        let sig = sign_deposit(&dk, &l.id, &osis_label::blob_id(&b), &wrap);
        let ev = net.run(0, Command::Deposit { label: l.id, blob: b.clone(), wrap, sig });
        assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::REFUSED, .. }]), "{ev:?}");
        assert!(net.store.entry(&l.id, &osis_label::blob_id(&b)).unwrap().is_none());
    }
    assert!(net.events[1].is_empty(), "nothing pushed");
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
    net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(b3.clone()), l.entry(b1.clone()), l.entry(b_plain.clone())] });
    let k = l.head_keys().clone();
    let item = |b: &[u8], n: u64, by: (u8, &Secret32), signer: &SigningSecret| DeleteItem::sign_by(signer, &[(by.0, &dk(by.1))], &salt(n), &HB, &l.id, osis_label::blob_id(b)).unwrap();
    let ev = net.run(0, Command::Delete { label: l.id, items: vec![item(&b3, 10, (3, &t3), &k.sync), item(&b3, 10, (3, &t9), &k.write), item(&b3, 10, (1, &t3), &k.sync), item(&b1, 11, (1, &t1), &k.sync)] });
    assert_eq!(statuses(&ev), vec![Code::REFUSED, Code::REFUSED, Code::REFUSED, Code::OK]);
    let ev = net.run(0, Command::Delete { label: l.id, items: vec![item(&b3, 10, (3, &t3), &k.write)] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    let (_, cursor) = events_of(&net.run(0, sync(l.id, None, vec![], vec![])));
    let ev = net.run(0, Command::Delete { label: l.id, items: vec![DeleteItem::sign(&k.delete, &l.id, osis_label::blob_id(&b_plain)).unwrap()] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    let (evs, _) = events_of(&net.run(0, sync(l.id, cursor, vec![], vec![])));
    assert_eq!(evs, vec![Event::Deleted(osis_label::blob_id(&b_plain))]);
}

// spec/sync.md §5, §8, spec/wire.md §11.2: pushes in the cursor-reply format under the last Sync's inline limit; a relay-only entry reaches other subscribers and is stored nowhere
#[test]
fn subscribe_push_and_relays() {
    let mut net = Net::new(2, 0);
    let l = Label::new(3);
    net.setup(&l);
    net.open(0, &l);
    net.open(1, &l);
    net.run(1, Command::Sync { label: l.id, cursor: None, inline_limit: 0, entries: vec![], gained: vec![] });
    let ev = net.run(1, Command::Subscribe { labels: vec![l.id, LabelId([0xee; 16])] });
    assert_eq!(ev, vec![ClientEvent::Subscribed { labels: vec![l.id, LabelId([0xee; 16])], codes: vec![Code::OK, Code::NOT_OPENED] }]);
    let (_, c1) = events_of(&net.run(1, sync(l.id, None, vec![], vec![])));
    net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(1)), l.entry(blob(2))] });
    let ev = std::mem::take(&mut net.events[1]);
    let (evs, cursor) = events_of(&ev);
    assert_eq!(evs.len(), 2);
    // the last Sync asked for 1 MiB inline: pushes carry the blobs
    assert!(matches!(&evs[0], Event::Added { blob: Some(_), .. }));
    assert!(cursor.unwrap().seq > c1.unwrap().seq);
    let (evs, _) = events_of(&net.run(1, sync(l.id, cursor, vec![], vec![])));
    assert!(evs.is_empty());
    let p = Prefix::new(salt(9), Some(WallMs(T0 + osis_base::format::MAX_DRIFT_MS)), vec![]).unwrap().with_class(osis_label::Class::Relay);
    let env = osis_label::frame(&p, &[0x5a; 100], &mut osis_crypto::SeededRng::from_seed([9; 32])).unwrap().1;
    let e = l.entry(env.clone());
    let ev = net.run(0, Command::Upload { label: l.id, entries: vec![e.clone()] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    let (evs, _) = events_of(&std::mem::take(&mut net.events[1]));
    assert_eq!(evs, vec![Event::Added { blob_id: osis_label::blob_id(&env), blob: Some(env.clone()), wrap: e.wrap, stamp: Some(e.stamp) }]);
    assert!(net.store.entry(&l.id, &osis_label::blob_id(&env)).unwrap().is_none(), "held by nobody");
    let mut bad = e.clone();
    bad.stamp = osis_proto::msg::Signature([0; 64]);
    net.run(0, Command::Upload { label: l.id, entries: vec![bad] });
    assert!(net.events[1].is_empty());
    net.run(1, Command::Unsubscribe { labels: vec![l.id] });
    net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(3))] });
    assert!(net.events[1].is_empty());
}

// spec/sync.md §5 (an open holds under the head's sync key), §8: a head with another sync key
// ends the label's opens and subscriptions on every connection, the registrar's included: one
// push ending with that head, then nothing, every read refused 8 until opened again under the
// new key (which resumes from the cursor). A step keeping the sync key keeps them.
#[test]
fn new_sync_key_ends_opens_spec_sync_5() {
    let mut net = Net::new(2, 0);
    let mut l = Label::new(3);
    net.setup(&l);
    let mut cursors = vec![];
    for i in 0..2 {
        net.open(i, &l);
        let (_, c) = events_of(&net.run(i, sync(l.id, None, vec![], vec![])));
        cursors.push(c);
        let ev = net.run(i, Command::Subscribe { labels: vec![l.id] });
        assert_eq!(ev, vec![ClientEvent::Subscribed { labels: vec![l.id], codes: vec![Code::OK] }]);
    }
    // a step without a read rotation: the opens hold
    let (same, cs) = l.rotate(1);
    assert_eq!(same.keys.sync, l.steps[0].keys.sync);
    net.run(0, Command::Register { label: l.id, step: same.clone(), claim_set: Some(cs) });
    assert_eq!(events_of(&std::mem::take(&mut net.events[1])).0, vec![Event::Head(same)]);
    net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(1))] });
    assert_eq!(added(&events_of(&std::mem::take(&mut net.events[1])).0), vec![bid(1)]);
    // a read rotation, registered by client 0: both pushed the head last, then nothing
    let (child, cs) = l.rotate(20);
    let ev = net.run(0, Command::Register { label: l.id, step: child.clone(), claim_set: Some(cs) });
    assert!(ev.contains(&ClientEvent::Registered { label: l.id }), "{ev:?}");
    assert_eq!(events_of(&ev).0, vec![Event::Head(child.clone())]);
    assert_eq!(events_of(&std::mem::take(&mut net.events[1])).0, vec![Event::Head(child.clone())]);
    let ev = net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(2))] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    assert_eq!(events_of(&ev).0, vec![], "no push to the registrar");
    assert!(net.events[1].is_empty(), "{:?}", net.events[1]);
    for (i, cursor) in cursors.iter().enumerate() {
        let ev = net.run(i, sync(l.id, *cursor, vec![], vec![]));
        assert!(matches!(&ev[..], [ClientEvent::Refused { kind: Request::Sync, code: Code::NOT_OPENED, .. }]), "{ev:?}");
        let ev = net.run(i, Command::Fetch { label: l.id, ids: vec![bid(2)] });
        assert_eq!(ev, vec![ClientEvent::Refused { label: Some(l.id), kind: Request::Fetch, code: Code::NOT_OPENED, fetch: vec![bid(2)] }]);
        let ev = net.run(i, Command::Path { label: l.id, after: None });
        assert!(matches!(&ev[..], [ClientEvent::Refused { kind: Request::Path, code: Code::NOT_OPENED, .. }]), "{ev:?}");
        let ev = net.run(i, Command::Subscribe { labels: vec![l.id] });
        assert_eq!(ev, vec![ClientEvent::Subscribed { labels: vec![l.id], codes: vec![Code::NOT_OPENED] }]);
    }
    assert_eq!(net.hosts[1].opened().count(), 0);
    // the old key gets the child only; the new one opens and syncs on from the cursor
    let ev = net.run(1, Command::Open { label: l.id, key: OpenKey::Sync { step: None, key: l.keys[0].sync.clone() } });
    assert!(matches!(&ev[..], [ClientEvent::Step { .. }]), "{ev:?}");
    net.open(1, &l);
    let (evs, _) = events_of(&net.run(1, sync(l.id, cursors[1], vec![], vec![])));
    assert_eq!(added(&evs), vec![bid(1), bid(2)]);
    net.run(1, Command::Subscribe { labels: vec![l.id] });
    net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(3))] });
    assert_eq!(added(&events_of(&std::mem::take(&mut net.events[1])).0), vec![bid(3)]);
}

// spec/sync.md §5, spec/wire.md §11.2: fetch by ID of opened labels only, items in request order
#[test]
fn fetch() {
    let mut net = Net::new(1, 0);
    let l = Label::new(3);
    net.setup(&l);
    net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(1))] });
    let ids = vec![bid(1), bid(2)];
    let ev = net.run(0, Command::Fetch { label: l.id, ids: ids.clone() });
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::NOT_OPENED, .. }]));
    net.open(0, &l);
    let ev = net.run(0, Command::Fetch { label: l.id, ids });
    let [ClientEvent::Fetched { items, .. }] = &ev[..] else { panic!("{ev:?}") };
    assert_eq!(items[0].entry.as_ref().unwrap().0, blob(1));
    assert_eq!(items[1].entry, None);
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

// spec/wire.md §11.2: a peer whose Sync pages make no progress is dropped, not followed forever
#[test]
fn client_stops_on_a_stuck_sync() {
    let mut net = Net::new(1, 0);
    let l = Label::new(3);
    let cursor = Cursor { log_id: [1; 16], seq: 5 };
    let out = net.clients[0].handle(T0, ClientInput::Command(sync(l.id, Some(cursor), vec![], vec![])));
    let sends: Vec<&Vec<u8>> = out.iter().filter_map(|o| if let ClientOutput::Send(f) = o { Some(f) } else { None }).collect();
    let [f] = &sends[..] else { panic!("{out:?}") };
    let Message::Sync { id, .. } = Message::decode(&f[4..]).unwrap() else { panic!() };
    // an empty page under the small first cap is asked on under the whole budget
    let reply = Message::SyncReply { id, events: vec![], want: vec![], codes: vec![], cursor, more: true };
    let out = net.clients[0].handle(T0, ClientInput::Bytes(encode_frame(&reply.encode())));
    let sends: Vec<&Vec<u8>> = out.iter().filter_map(|o| if let ClientOutput::Send(f) = o { Some(f) } else { None }).collect();
    let [f] = &sends[..] else { panic!("{out:?}") };
    let Message::Sync { id, max_reply, .. } = Message::decode(&f[4..]).unwrap() else { panic!() };
    assert_eq!(max_reply, serving::REPLY_BUDGET as u64);
    let reply = Message::SyncReply { id, events: vec![], want: vec![], codes: vec![], cursor, more: true };
    let out = net.clients[0].handle(T0, ClientInput::Bytes(encode_frame(&reply.encode())));
    assert!(out.iter().any(|o| matches!(o, ClientOutput::Event(ClientEvent::PeerError(_)))));
    assert!(!out.iter().any(|o| matches!(o, ClientOutput::Send(_))));
}

// spec/sync.md §6, spec/requirements.md cost goals: a common-case sync converges in one round trip
#[test]
fn round_trips_are_constant_in_the_common_case() {
    for n in [10u64, 400] {
        let mut net = Net::new(2, 0);
        let l = Label::new(3);
        net.setup(&l);
        net.open(0, &l);
        net.open(1, &l);
        net.run(0, sync(l.id, None, (0..n).map(|i| l.entry(blob(i))).collect(), vec![]));
        let (_, cursor) = events_of(&net.run(1, sync(l.id, None, vec![], vec![])));
        net.run(0, Command::Upload { label: l.id, entries: (n..n + 5).map(|i| l.entry(blob(i))).collect() });
        net.flights = 0;
        let (evs, _) = events_of(&net.run(1, sync(l.id, cursor, vec![l.entry(blob(10_000))], vec![])));
        assert_eq!(evs.len(), 5);
        assert_eq!(net.flights, 2, "one round trip");
    }
}

// spec/sync.md §6, spec/wire.md §11.3: N random entries converge; the reconciliation fallback takes about log16(n) round trips (tier 2)
#[test]
#[ignore]
fn loopback_converges_at_size() {
    let n = 20_000u64;
    let mut net = Net::new(2, 0);
    let l = Label::new(3);
    net.setup(&l);
    net.open(0, &l);
    net.open(1, &l);
    net.run(0, Command::Upload { label: l.id, entries: (0..n).map(|i| l.entry(blob(i))).collect() });
    let ev = net.run(1, Command::Sync { label: l.id, cursor: None, inline_limit: 0, entries: vec![], gained: vec![] });
    assert_eq!(events_of(&ev).0.len() as u64, n);
    net.flights = 0;
    let ids: Vec<BlobId> = (0..n).filter(|i| i % 1000 != 0).chain(n..n + 20).map(bid).collect();
    let ev = net.run(1, Command::Reconcile { label: l.id, ids });
    let [ClientEvent::Reconciled { need, have, .. }] = &ev[..] else { panic!("{ev:?}") };
    assert_eq!((need.len(), have.len()), (20, 20));
    assert!(net.flights <= 8, "{} flights", net.flights);
}

/// The frames a session sent in `out`, decoded.
fn sent_msgs<'a>(out: impl IntoIterator<Item = &'a ClientOutput>) -> Vec<Message> {
    out.into_iter().filter_map(|o| if let ClientOutput::Send(f) = o { Message::decode(&f[4..]).ok() } else { None }).collect()
}

// spec/sync.md §6 (stall): the oldest request in flight not moving closes the connection at the
// deadline (the node redials). Its frame taken by the transport moves it, and so do the first
// bytes of a reply to it; a push, the peer's own request or a reply to a later request does not
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
    // bytes of other kinds move nothing: a push, the peer's own request, a later ping's answer
    let push = Message::Push { label: LabelId([7; 16]), events: vec![Event::Deleted(bid(1))], cursor: Cursor { log_id: [1; 16], seq: 1 } };
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
    let out = c.handle(now, ClientInput::Command(Command::Fetch { label: l, ids: vec![bid(1)] }));
    let fetch = sent_msgs(&out).iter().find_map(|m| if let Message::Fetch { id, .. } = m { Some(*id) } else { None }).unwrap();
    c.handle(now, ClientInput::Bytes(encode_frame(&Message::Pong { id: pings[2], wall_ms: now }.encode())));
    // a 60 KiB answer at 1 KiB per 100 s
    let reply = encode_frame(&Message::FetchReply { id: fetch, items: vec![Fetched { blob_id: bid(1), entry: Some((vec![5; 60 << 10], [0; osis_crypto::WRAP_LEN], None)) }] }.encode());
    let mut fetched = false;
    for piece in reply.chunks(1024) {
        now += t - 20_000;
        let out = c.handle(now, ClientInput::Bytes(piece.to_vec()));
        fetched |= out.iter().any(|o| matches!(o, ClientOutput::Event(ClientEvent::Fetched { .. })));
        assert!(!c.handle(now, ClientInput::Timer).iter().any(|o| matches!(o, ClientOutput::Close)), "closed at {} s", (now - T0) / 1000);
    }
    assert!(fetched, "the answer arrived");
    assert!(!c.is_closed());
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
    let mut store = MemoryLabelStore::new([9; 32]);
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
    // the dialer pings and asks, and answers the second request only: nothing moves
    let mut other = encode_frame(&Message::Ping { id: 1, wall_ms: T0 }.encode());
    other.extend(encode_frame(&Message::Pull(Box::new(osis_proto::msg::Pull { id: osis_proto::msg::NODE_IDS | 1, cursor: None, joins: vec![], inline_limit: 0, max_reply: client::FIRST_REPLY as u64, follow: true, ephemeral: false })).encode()));
    other.extend(encode_frame(&Message::FetchReply { id: osis_proto::msg::NODE_IDS | 2, items: vec![] }.encode()));
    s.handle(T0 + t - 1, &mut store, ServingInput::Bytes(other));
    assert_eq!(s.stall_at(), Some(T0 + 10 + t));
    // the first one's answer starting moves it; the rest of it answers it and none is out
    let reply = encode_frame(&Message::FetchReply { id: osis_proto::msg::NODE_IDS | 1, items: vec![] }.encode());
    s.handle(T0 + t, &mut store, ServingInput::Bytes(reply[..11].to_vec()));
    assert_eq!(s.stall_at(), Some(T0 + 2 * t));
    s.handle(T0 + t + 1, &mut store, ServingInput::Bytes(reply[11..].to_vec()));
    assert_eq!(s.stall_at(), None);
    assert!(!s.is_closed());
}

// spec/sync.md §6 (a replay's pages bring the live entries, the last page the log cursor), §8
// (pushes carry cursors): a Push arriving while a Sync of its label runs gives no cursor to keep,
// so a connection lost before the Sync ends never skips the entries its later pages held
#[test]
fn push_during_sync_keeps_no_cursor() {
    let mut c = ClientSession::new(ClientConfig { peer_static_key: [1; 32], challenge: [2; 32] });
    c.handle(T0, ClientInput::Start);
    c.handle(T0, ClientInput::Bytes(encode_frame(&Hello::new(T0, [3; 32]).encode())));
    let l = LabelId([7; 16]);
    let out = c.handle(T0, ClientInput::Command(sync(l, None, vec![], vec![])));
    let id = out.iter().find_map(|o| if let ClientOutput::Send(f) = o { if let Ok(Message::Sync { id, .. }) = Message::decode(&f[4..]) { Some(id) } else { None } } else { None }).unwrap();
    let head = Cursor { log_id: [1; 16], seq: 9 };
    let push = |c: &mut ClientSession| {
        let out = c.handle(T0, ClientInput::Bytes(encode_frame(&Message::Push { label: l, events: vec![Event::Deleted(bid(1))], cursor: head }.encode())));
        out.into_iter().find_map(|o| if let ClientOutput::Event(ClientEvent::Events { cursor, .. }) = o { Some(cursor) } else { None }).unwrap()
    };
    assert_eq!(push(&mut c), None, "no cursor while the replay runs");
    c.handle(T0, ClientInput::Bytes(encode_frame(&Message::SyncReply { id, events: vec![], want: vec![], codes: vec![], cursor: Cursor { log_id: [1; 16], seq: 8 }, more: false }.encode())));
    assert_eq!(push(&mut c), Some(head), "kept once it ended");
}

// the same while a reconciliation of the label runs (a node's first sync after a start
// reconciles, then syncs from its kept cursor): a push's cursor kept then skipped the entries
// between the old cursor and the push for good when the connection ended first
#[test]
fn push_during_reconcile_keeps_no_cursor() {
    let mut c = ClientSession::new(ClientConfig { peer_static_key: [1; 32], challenge: [2; 32] });
    c.handle(T0, ClientInput::Start);
    c.handle(T0, ClientInput::Bytes(encode_frame(&Hello::new(T0, [3; 32]).encode())));
    let l = LabelId([7; 16]);
    let out = c.handle(T0, ClientInput::Command(Command::Reconcile { label: l, ids: vec![bid(1)] }));
    assert!(out.iter().any(|o| matches!(o, ClientOutput::Send(f) if matches!(Message::decode(&f[4..]), Ok(Message::Reconcile { .. })))));
    let out = c.handle(T0, ClientInput::Bytes(encode_frame(&Message::Push { label: l, events: vec![Event::Deleted(bid(2))], cursor: Cursor { log_id: [1; 16], seq: 9 } }.encode())));
    let cursor = out.into_iter().find_map(|o| if let ClientOutput::Event(ClientEvent::Events { cursor, .. }) = o { Some(cursor) } else { None }).unwrap();
    assert_eq!(cursor, None, "no cursor while the reconciliation runs");
}

// spec/sync.md §6 (flow control): a client within its window never sends more unanswered
// requests than `MAX_UNANSWERED`, so a host delivering everything it sent in one input (as
// `pump` does) closes nothing: many reconciliations, fetches, paths and pings queued at once
// all complete
#[test]
fn queued_requests_stay_within_the_unanswered_bound() {
    let mut net = Net::new(2, 0);
    let l = Label::new(3);
    net.setup(&l);
    net.open(0, &l);
    net.open(1, &l);
    net.run(0, Command::Upload { label: l.id, entries: (0..100).map(|n| l.entry(blob(n))).collect() });
    let mut co = Vec::new();
    for k in 0..8u64 {
        let c = &mut net.clients[1];
        co.extend(c.handle(net.now, ClientInput::Command(Command::Reconcile { label: l.id, ids: (k..90 + k).map(bid).collect() })));
        co.extend(c.handle(net.now, ClientInput::Command(Command::Fetch { label: l.id, ids: vec![bid(k)] })));
        co.extend(c.handle(net.now, ClientInput::Command(Command::Path { label: l.id, after: None })));
        co.extend(c.handle(net.now, ClientInput::Command(sync(l.id, None, vec![], vec![]))));
    }
    net.client_out(1, co);
    net.pump();
    assert!(!net.hosts[1].is_closed());
    let ev = std::mem::take(&mut net.events[1]);
    // reconciliations of one label: the last one given is the one that reports
    assert_eq!(ev.iter().filter(|e| matches!(e, ClientEvent::Reconciled { .. })).count(), 1, "{ev:?}");
    assert_eq!(ev.iter().filter(|e| matches!(e, ClientEvent::Fetched { .. })).count(), 8, "{ev:?}");
    assert_eq!(ev.iter().filter(|e| matches!(e, ClientEvent::PathSteps { .. })).count(), 8, "{ev:?}");
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
        Message::Pull(p) => Message::PullReply(Box::new(osis_proto::msg::PullReply { id: p.id, events: vec![], cursor: None, whole: true, more: false, report: false, joins: vec![] })),
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

// spec/sync.md §6, spec/wire.md §11.2 (Sync, Fetch `max_reply`): a request's allowance is what it
// asks, so a connection opens and syncs many labels in a few round trips, not two labels per trip.
#[test]
fn many_labels_sync_in_few_round_trips() {
    let mut net = Net::new(1, 0);
    let labels: Vec<Label> = (0..=255).map(Label::new).collect();
    for l in &labels {
        net.setup(l);
        net.open(0, l);
    }
    let ids: Vec<LabelId> = labels.iter().map(|l| l.id).collect();
    let n = ids.len();
    let start = net.flights;
    let mut out = vec![];
    for id in &ids {
        out.extend(net.clients[0].handle(net.now, ClientInput::Command(sync(*id, None, vec![], vec![]))));
    }
    net.client_out(0, out);
    net.pump();
    let synced = net.events[0].iter().filter(|e| matches!(e, ClientEvent::Synced { .. })).count();
    assert_eq!(synced, n);
    assert!(net.flights - start <= 4, "{} flights for {n} labels", net.flights - start);
}

// spec/wire.md §11.2 Sync: a first page stays under a small `max_reply`, an inline blob that does
// not fit waits for the next page (a page with no event, not a stuck peer), nothing is lost.
#[test]
fn small_first_page_then_the_whole_budget() {
    let mut net = Net::new(2, 0);
    let l = Label::new(3);
    net.setup(&l);
    net.open(0, &l);
    net.open(1, &l);
    let big: Vec<Vec<u8>> = (0..4).map(|i| blob_sized(i, 0, vec![], 5 * SMALL_REPLY)).collect();
    let entries: Vec<Entry> = big.iter().map(|b| l.entry(b.clone())).collect();
    net.run(0, Command::Upload { label: l.id, entries });
    let start = net.flights;
    let ev = net.run(1, sync(l.id, None, vec![], vec![]));
    let (evs, _) = events_of(&ev);
    assert_eq!(added(&evs).len(), 4);
    assert!(evs.iter().all(|e| matches!(e, Event::Added { blob: Some(_), .. })), "inline");
    assert!(ev.contains(&ClientEvent::Synced { label: l.id }));
    assert!(!ev.iter().any(|e| matches!(e, ClientEvent::PeerError(_))), "{ev:?}");
    assert_eq!(net.flights - start, 4, "the small page, then one under the whole budget");
}

// spec/wire.md §11.2 Fetch: a blob over a small `max_reply` is asked again under the whole budget.
#[test]
fn fetch_over_a_small_cap_asks_again() {
    let mut net = Net::new(1, 0);
    let l = Label::new(3);
    net.setup(&l);
    net.open(0, &l);
    let b = blob_sized(9, 0, vec![], 5 * SMALL_REPLY);
    let id = osis_label::blob_id(&b);
    let small = blob(1);
    net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(small.clone()), l.entry(b)] });
    let start = net.flights;
    let ev = net.run(0, Command::Fetch { label: l.id, ids: vec![id] });
    assert_eq!(net.flights - start, 4, "asked twice");
    let got: Vec<_> = ev.iter().filter_map(|e| if let ClientEvent::Fetched { items, .. } = e { Some(items.clone()) } else { None }).flatten().collect();
    assert_eq!(got.len(), 1);
    assert!(got[0].entry.is_some());
    // a small one in one trip
    let start = net.flights;
    net.run(0, Command::Fetch { label: l.id, ids: vec![osis_label::blob_id(&small)] });
    assert_eq!(net.flights - start, 2);
}
