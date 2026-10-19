//! Client engines against server engines over in-memory byte queues, with a `MemoryLabelStore`
//! (spec/sync.md §4-§9, spec/wire.md §11).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_core::{BlobId, LabelId, Value, cbor, hash::hash};
use osis_crypto::{Domain, Secret32, SigningSecret};
use osis_proto::label::{ClaimSet, NewStep, StepInfo, delete_digest, entry_digest, sign};
use osis_proto::msg::{Code, Cursor, DeleteItem, Entry, Event, SignalAuth, Wrap};
use osis_proto::*;
use std::collections::{BTreeMap, VecDeque};

fn key(b: u8) -> SigningSecret {
    SigningSecret::from_seed(&Secret32::from_bytes([b; 32]))
}

/// One label's keys at one step.
#[derive(Clone)]
struct Keys {
    sync: SigningSecret,
    write: SigningSecret,
    delete: SigningSecret,
    deposit: SigningSecret,
}

impl Keys {
    fn new(b: u8) -> Keys {
        Keys { sync: key(b), write: key(b + 1), delete: key(b + 2), deposit: key(b + 3) }
    }
}

struct Label {
    id: LabelId,
    keys: Vec<Keys>,
    steps: Vec<StepInfo>,
    claim_sets: Vec<Vec<u8>>,
}

const CLAIM: u8 = 0x60;
const STATIC: u8 = 0x61;
const ENTRY_BOX: [u8; 49] = [0xe0; 49];

impl Label {
    fn new() -> Label {
        let k = Keys::new(1);
        let id = osis_crypto::label_id(&k.delete.verifying_key());
        let mut l = Label { id, keys: vec![], steps: vec![], claim_sets: vec![] };
        l.step(k, None);
        l
    }

    /// A step with keys `k` (genesis when `signer` is none), claim set: one claim key and one static entry.
    fn step(&mut self, k: Keys, signer: Option<&SigningSecret>) -> (Vec<u8>, Vec<u8>) {
        let entry = osis_crypto::static_entry(&self.id, &key(STATIC).verifying_key());
        let cs = ClaimSet {
            claims: vec![key(CLAIM).verifying_key().to_bytes(), entry],
            boxes: BTreeMap::from([(entry, cbor::encode(&Value::Bytes(ENTRY_BOX.to_vec())))]),
        };
        let cs = cs.to_bytes().unwrap();
        let p = |k: &SigningSecret| k.verifying_key().to_bytes();
        let step = NewStep {
            label: self.id,
            prev: self.steps.last().map(|s| s.id),
            sync: p(&k.sync),
            write: p(&k.write),
            delete: p(&k.delete),
            deposit: p(&k.deposit),
            step_key: [5; 32],
            claims_hash: hash(&cs),
            signer: signer.unwrap_or(&k.delete),
        }
        .sign();
        self.steps.push(StepInfo::parse(&step).unwrap());
        self.claim_sets.push(cs.clone());
        self.keys.push(k);
        (step, cs)
    }

    fn head_keys(&self) -> &Keys {
        self.keys.last().unwrap()
    }

    fn entry(&self, blob: Vec<u8>) -> Entry {
        self.entry_by(blob, &self.head_keys().write.clone())
    }

    fn entry_by(&self, blob: Vec<u8>, write: &SigningSecret) -> Entry {
        let wrap: Wrap = [blob.len() as u8; 49];
        let stamp = sign(write, Domain::Upload, &entry_digest(&self.id, &osis_crypto::blob_id(&blob), &wrap));
        Entry { blob, wrap, stamp }
    }
}

/// A framed blob: version 1 prefix (salt from `n`, expiry, commitments), then `n`-derived bytes.
fn blob_with(n: u64, expiry: u64, commitments: &[[u8; 17]]) -> Vec<u8> {
    let mut b = vec![1u8];
    b.extend_from_slice(&salt(n));
    b.extend_from_slice(&expiry.to_le_bytes());
    b.push(commitments.len() as u8);
    for c in commitments {
        b.extend_from_slice(c);
    }
    b.extend_from_slice(&hash(&n.to_le_bytes())[..(n % 32) as usize + 1]);
    b
}

fn salt(n: u64) -> [u8; 16] {
    hash(&n.to_be_bytes())[..16].try_into().unwrap()
}

fn blob(n: u64) -> Vec<u8> {
    blob_with(n, 0, &[])
}

const T0: u64 = 1_700_000_000_000;

/// Clients each on their own connection to one server store.
struct Net {
    now: u64,
    server_skew: u64,
    store: MemoryLabelStore,
    servers: Vec<ServerConnection>,
    clients: Vec<ClientSession>,
    events: Vec<Vec<ClientEvent>>,
    to_server: Vec<VecDeque<Vec<u8>>>,
    to_client: Vec<VecDeque<Vec<u8>>>,
    /// Events of the handshake, per client.
    handshake: Vec<Vec<ClientEvent>>,
    /// Message flights delivered by `pump` (one direction each).
    flights: usize,
}

impl Net {
    fn new(n: usize, server_skew: u64) -> Net {
        let mut net = Net { now: T0, server_skew, store: MemoryLabelStore::new([9; 32]), servers: vec![], clients: vec![], events: vec![], to_server: vec![], to_client: vec![], handshake: vec![], flights: 0 };
        for i in 0..n {
            net.servers.push(ServerConnection::new(ServerConfig { static_key: [0x5e; 32], challenge: [0x40 + i as u8; 32] }));
            net.clients.push(ClientSession::new(ClientConfig { peer_static_key: [0x5e; 32], challenge: [0x80 + i as u8; 32] }));
            net.events.push(vec![]);
            net.to_server.push(VecDeque::new());
            net.to_client.push(VecDeque::new());
            let so = net.servers[i].handle(T0 + server_skew, &mut net.store, ServerInput::Start);
            net.server_out(i, so);
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
                ClientOutput::Send(b) => self.to_server[i].push_back(b),
                ClientOutput::Event(e) => self.events[i].push(e),
                ClientOutput::Close | ClientOutput::SetTimer(_) => {}
            }
        }
    }

    fn server_out(&mut self, i: usize, out: Vec<ServerOutput>) {
        for o in out {
            match o {
                ServerOutput::Send(b) => self.to_client[i].push_back(b),
                ServerOutput::Changed(l) => {
                    for j in 0..self.servers.len() {
                        let so = self.servers[j].handle(self.now + self.server_skew, &mut self.store, ServerInput::Changed(l));
                        self.server_out(j, so);
                    }
                }
                ServerOutput::Signal { label, blob, wrap, auth } => {
                    for j in (0..self.servers.len()).filter(|j| *j != i) {
                        let so = self.servers[j].handle(self.now + self.server_skew, &mut self.store, ServerInput::Signal { label, blob: blob.clone(), wrap, auth });
                        self.server_out(j, so);
                    }
                }
                ServerOutput::Close | ServerOutput::PeerError(_) => {}
                ServerOutput::StoreError(e) => panic!("{e}"),
            }
        }
    }

    fn pump(&mut self) {
        loop {
            let mut moved = false;
            for i in 0..self.clients.len() {
                let bytes: Vec<u8> = self.to_server[i].drain(..).flatten().collect();
                if !bytes.is_empty() {
                    moved = true;
                    let so = self.servers[i].handle(self.now + self.server_skew, &mut self.store, ServerInput::Bytes(bytes));
                    self.server_out(i, so);
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
        let (step, cs) = (l.steps[0].bytes.clone(), l.claim_sets[0].clone());
        let ev = self.run(0, Command::Register { label: l.id, step, claim_set: Some(cs) });
        assert_eq!(ev, vec![ClientEvent::Registered { label: l.id }]);
    }

    fn open(&mut self, i: usize, l: &Label) {
        let ev = self.run(i, Command::Open { label: l.id, key: OpenKey::Sync(l.head_keys().sync.clone()) });
        assert!(matches!(&ev[..], [ClientEvent::Opened { .. }]), "{ev:?}");
    }
}

fn events_of(ev: &[ClientEvent]) -> (Vec<Event>, Option<Cursor>) {
    let mut all = vec![];
    let mut cursor = None;
    for e in ev {
        if let ClientEvent::Events { events, cursor: c, .. } = e {
            all.extend(events.iter().cloned());
            cursor = Some(*c);
        }
    }
    (all, cursor)
}

fn statuses(ev: &[ClientEvent]) -> Vec<Code> {
    ev.iter().flat_map(|e| match e {
        ClientEvent::EntryStatus { codes, .. } | ClientEvent::DeleteStatus { codes, .. } => codes.clone(),
        _ => vec![],
    }).collect()
}

fn sync(label: LabelId, cursor: Option<Cursor>, entries: Vec<Entry>, gained: Vec<BlobId>) -> Command {
    Command::Sync { label, cursor, inline_limit: 1 << 20, entries, gained }
}

// spec/wire.md §11.1, spec/sync.md §6: Hellos at once, clock offset from round trips, diagnostic above a few seconds
#[test]
fn handshake_and_clock_offset() {
    let net = Net::new(1, 3_000);
    let ev = net.handshake[0].clone();
    assert!(matches!(ev[0], ClientEvent::Ready { version: 1 }));
    assert!(ev.contains(&ClientEvent::ClockOffset { offset_ms: 3_000, diagnostic: false }), "{ev:?}");
    let mut net = Net::new(1, 60_000);
    assert!(net.handshake[0].contains(&ClientEvent::ClockOffset { offset_ms: 60_000, diagnostic: true }));
    // a ping on the timer
    let out = net.clients[0].handle(T0 + 1, ClientInput::Timer);
    assert!(out.iter().any(|o| matches!(o, ClientOutput::SetTimer(t) if *t > T0)));
}

// spec/sync.md §5, §6: register, open, upload inline with Sync, download by replay, cursor sync with gained and want
#[test]
fn register_open_sync_download() {
    let mut net = Net::new(2, 0);
    let l = Label::new();
    net.setup(&l);
    net.open(0, &l);
    net.open(1, &l);
    let entries: Vec<Entry> = (0..50).map(|n| l.entry(blob(n))).collect();
    let ev = net.run(0, sync(l.id, None, entries, vec![]));
    assert_eq!(statuses(&ev), vec![Code::OK; 50]);
    // the uploader gets no add events for what it sent
    let (evs, c0) = events_of(&ev);
    assert!(evs.iter().all(|e| matches!(e, Event::Head(_))), "{evs:?}");
    assert!(c0.is_some());
    // B replays: every live entry, blobs inline, stamps and wraps
    let ev = net.run(1, sync(l.id, None, vec![], vec![]));
    let (evs, cursor) = events_of(&ev);
    assert_eq!(evs.len(), 50);
    for (n, e) in evs.iter().enumerate() {
        let b = blob(n as u64);
        let want = l.entry(b.clone());
        assert_eq!(e, &Event::Added { blob_id: osis_crypto::blob_id(&b), blob: Some(b), wrap: want.wrap, stamp: Some(want.stamp) });
    }
    assert!(ev.contains(&ClientEvent::Synced { label: l.id }));
    // A adds 5 more; B's cursor sync returns exactly those
    net.run(0, Command::Upload { label: l.id, entries: (50..55).map(|n| l.entry(blob(n))).collect() });
    let gained = vec![osis_crypto::blob_id(&blob(52)), osis_crypto::blob_id(&blob(100)), osis_crypto::blob_id(&blob(101))];
    let ev = net.run(1, sync(l.id, cursor, vec![], gained));
    let (evs, _) = events_of(&ev);
    let added: Vec<BlobId> = evs.iter().filter_map(|e| if let Event::Added { blob_id, .. } = e { Some(*blob_id) } else { None }).collect();
    // 52 was gained elsewhere: left out
    assert_eq!(added, [50, 51, 53, 54].map(|n| osis_crypto::blob_id(&blob(n))));
    assert!(ev.contains(&ClientEvent::Want { label: l.id, ids: vec![osis_crypto::blob_id(&blob(100)), osis_crypto::blob_id(&blob(101))] }));
}

// spec/sync.md §6, spec/wire.md §11.2: a cursor the log no longer reaches gets Error 10; reconciliation finds both differences
#[test]
fn lost_cursor_falls_back_to_reconciliation() {
    let mut net = Net::new(2, 0);
    let l = Label::new();
    net.setup(&l);
    net.open(0, &l);
    net.open(1, &l);
    net.run(0, Command::Upload { label: l.id, entries: (0..300).map(|n| l.entry(blob(n))).collect() });
    let ev = net.run(1, sync(l.id, None, vec![], vec![]));
    let (_, cursor) = events_of(&ev);
    net.run(0, Command::Upload { label: l.id, entries: (300..340).map(|n| l.entry(blob(n))).collect() });
    net.store.truncate_log(&l.id, cursor.unwrap().seq + 1);
    let ev = net.run(1, sync(l.id, cursor, vec![], vec![]));
    assert_eq!(ev, vec![ClientEvent::NeedReconcile { label: l.id }]);
    // B holds 0..300 and 1000..1010 of its own
    let ids: Vec<BlobId> = (0..300).chain(1000..1010).map(|n| osis_crypto::blob_id(&blob(n))).collect();
    let ev = net.run(1, Command::Reconcile { label: l.id, ids });
    let mut need: Vec<BlobId> = (300..340).map(|n| osis_crypto::blob_id(&blob(n))).collect();
    let mut have: Vec<BlobId> = (1000..1010).map(|n| osis_crypto::blob_id(&blob(n))).collect();
    need.sort();
    have.sort();
    assert_eq!(ev, vec![ClientEvent::Reconciled { label: l.id, need, have }]);
}

// spec/sync.md §6: a gained list over a message (4096 IDs) falls back to reconciliation
#[test]
fn oversized_gained_list_reconciles() {
    let mut net = Net::new(1, 0);
    let l = Label::new();
    net.setup(&l);
    net.open(0, &l);
    let gained: Vec<BlobId> = (0..4097).map(|n| BlobId(hash(&(n as u64).to_le_bytes()))).collect();
    let ev = net.run(0, sync(l.id, Some(Cursor { log_id: [0; 16], seq: 0 }), vec![], gained));
    assert_eq!(ev, vec![ClientEvent::NeedReconcile { label: l.id }]);
    assert_eq!(net.clients[0].outstanding(), 0);
}

// spec/sync.md §5: a superseded sync key gets the child step and nothing else; the child verifies under its parent's delete key
#[test]
fn stale_sync_key_gets_one_signed_step() {
    let mut net = Net::new(1, 0);
    let mut l = Label::new();
    net.setup(&l);
    let old = l.head_keys().clone();
    let (child, cs) = l.step(Keys::new(20), Some(&old.delete));
    let ev = net.run(0, Command::Register { label: l.id, step: child.clone(), claim_set: Some(cs) });
    assert_eq!(ev, vec![ClientEvent::Registered { label: l.id }]);
    let ev = net.run(0, Command::Open { label: l.id, key: OpenKey::Sync(old.sync.clone()) });
    let [ClientEvent::Step { step, .. }] = &ev[..] else { panic!("{ev:?}") };
    assert_eq!(step, &child);
    assert!(l.steps[0].is_parent_of(&StepInfo::parse(step).unwrap()));
    // not opened: reads refused
    let ev = net.run(0, sync(l.id, None, vec![], vec![]));
    assert!(matches!(&ev[..], [ClientEvent::Refused { kind: 15, code: Code::NOT_OPENED, .. }]), "{ev:?}");
    // a key of no step
    let ev = net.run(0, Command::Open { label: l.id, key: OpenKey::Sync(key(99)) });
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::REFUSED, .. }]));
    // a re-register of a stale branch is answered with the head
    let mut fork = Label::new();
    let (other, _) = fork.step(Keys::new(30), Some(&old.delete));
    let ev = net.run(0, Command::Register { label: l.id, step: other, claim_set: None });
    assert!(matches!(&ev[..], [ClientEvent::Head { head, .. }] if *head == child));
    // the current key opens; Path lists both steps
    net.open(0, &l);
    let ev = net.run(0, Command::Path { label: l.id, after: None });
    assert_eq!(ev, vec![ClientEvent::PathSteps { label: l.id, steps: vec![l.steps[0].bytes.clone(), child.clone()], more: false }]);
    let ev = net.run(0, Command::Path { label: l.id, after: Some(l.steps[0].id) });
    assert_eq!(ev, vec![ClientEvent::PathSteps { label: l.id, steps: vec![child], more: false }]);
}

// spec/sync.md §5: claim keys open at the head or get the child; static entries open with the entry box
#[test]
fn claim_and_static_opens() {
    let mut net = Net::new(1, 0);
    let mut l = Label::new();
    net.setup(&l);
    let claim = |l: &Label, i: usize| Command::Open { label: l.id, key: OpenKey::Claim { step_id: l.steps[i].id, key: key(CLAIM) } };
    let ev = net.run(0, claim(&l, 0));
    assert!(matches!(&ev[..], [ClientEvent::Opened { entry_box: None, .. }]), "{ev:?}");
    let ev = net.run(0, Command::Open { label: l.id, key: OpenKey::Static(key(STATIC)) });
    let want_box = cbor::encode(&Value::Bytes(ENTRY_BOX.to_vec()));
    assert!(matches!(&ev[..], [ClientEvent::Opened { entry_box: Some(b), .. }] if *b == want_box), "{ev:?}");
    let ev = net.run(0, Command::Open { label: l.id, key: OpenKey::Claim { step_id: l.steps[0].id, key: key(0x77) } });
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::REFUSED, .. }]));
    let parent = l.head_keys().delete.clone();
    let (child, _) = l.step(Keys::new(20), Some(&parent));
    net.run(0, Command::Register { label: l.id, step: child.clone(), claim_set: None });
    let ev = net.run(0, claim(&l, 0));
    assert!(matches!(&ev[..], [ClientEvent::Step { step, .. }] if *step == child), "{ev:?}");
    // the head was registered without its set: no claims there
    let ev = net.run(0, claim(&l, 1));
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::REFUSED, .. }]));
}

// spec/sync.md §5: stamps under the head's write key; old key 9 with the head; expiry, tombstone, unknown label
#[test]
fn upload_rules() {
    let mut net = Net::new(1, 0);
    let mut l = Label::new();
    net.setup(&l);
    let old = l.head_keys().clone();
    let e_old = l.entry(blob(1));
    let mut bad = l.entry(blob(2));
    bad.stamp[0] ^= 1;
    let expired = l.entry(blob_with(3, T0 - 1, &[]));
    let ev = net.run(0, Command::Upload { label: l.id, entries: vec![e_old, bad, expired, l.entry(blob_with(4, T0 + 1000, &[]))] });
    assert_eq!(statuses(&ev), vec![Code::OK, Code::REFUSED, Code::EXPIRED, Code::OK]);
    let (child, cs) = l.step(Keys::new(20), Some(&old.delete));
    net.run(0, Command::Register { label: l.id, step: child.clone(), claim_set: Some(cs) });
    let ev = net.run(0, Command::Upload { label: l.id, entries: vec![l.entry_by(blob(5), &old.write), l.entry(blob(6))] });
    assert!(matches!(&ev[..], [ClientEvent::EntryStatus { codes, head: Some(h), .. }] if *codes == vec![Code::NOT_HEAD, Code::OK] && *h == child), "{ev:?}");
    // delete then re-upload: tombstoned
    net.open(0, &l);
    let id6 = osis_crypto::blob_id(&blob(6));
    let sig = sign(&l.head_keys().delete, Domain::Delete, &delete_digest(&l.id, &id6, None, None));
    let ev = net.run(0, Command::Delete { label: l.id, items: vec![DeleteItem { blob_id: id6, at: None, token: None, sig }] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    let ev = net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(6))] });
    assert_eq!(statuses(&ev), vec![Code::TOMBSTONED]);
    let ev = net.run(0, Command::Upload { label: LabelId([0xee; 16]), entries: vec![l.entry(blob(7))] });
    assert_eq!(statuses(&ev), vec![Code::UNKNOWN_LABEL]);
}

// spec/sync.md §5: deposits by the deposit key within the budget (64 + 4 x claim slots), refused when full
#[test]
fn deposit_budget() {
    let mut net = Net::new(1, 0);
    let l = Label::new();
    net.setup(&l);
    let deposit = |l: &Label, n: u64, k: &SigningSecret| {
        let b = blob(n);
        let wrap: Wrap = [7; 49];
        let sig = sign(k, Domain::Deposit, &entry_digest(&l.id, &osis_crypto::blob_id(&b), &wrap));
        Command::Deposit { label: l.id, blob: b, wrap, sig }
    };
    let dk = l.head_keys().deposit.clone();
    let ev = net.run(0, deposit(&l, 0, &dk));
    assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::OK, entries_left: 71, .. }]), "{ev:?}");
    let ev = net.run(0, deposit(&l, 1, &l.head_keys().write.clone()));
    assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::REFUSED, .. }]));
    for n in 1..72 {
        net.run(0, deposit(&l, n, &dk));
    }
    let ev = net.run(0, deposit(&l, 500, &dk));
    assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::BUDGET_FULL, entries_left: 0, .. }]), "{ev:?}");
    // stamping a deposited entry takes it out of the budget
    let ev = net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(0))] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    let ev = net.run(0, deposit(&l, 500, &dk));
    assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::OK, entries_left: 0, .. }]), "{ev:?}");
    // deposited entries sync without a stamp
    net.open(0, &l);
    let (evs, _) = events_of(&net.run(0, sync(l.id, None, vec![], vec![])));
    assert!(evs.iter().any(|e| matches!(e, Event::Added { stamp: None, .. })));
}

// spec/sync.md §5, spec/crypto.md §7: deletes by key and by token (level 3 write key, levels 1-2 sync key), timed deletes
#[test]
fn deletes() {
    let mut net = Net::new(1, 0);
    let l = Label::new();
    net.setup(&l);
    net.open(0, &l);
    let token = |n: u8| [n; 32];
    let commit = |level: u8, t: [u8; 32], n: u64| osis_crypto::commitment(level, &osis_crypto::token_hash(&t), &salt(n)).unwrap();
    let b3 = blob_with(10, 0, &[commit(3, token(3), 10)]);
    let b1 = blob_with(11, 0, &[commit(1, token(1), 11)]);
    let b_timed = blob(12);
    net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(b3.clone()), l.entry(b1.clone()), l.entry(b_timed.clone())] });
    let k = l.head_keys().clone();
    let item = |b: &[u8], at: Option<u64>, t: Option<[u8; 32]>, signer: &SigningSecret| {
        let id = osis_crypto::blob_id(b);
        DeleteItem { blob_id: id, at, token: t, sig: sign(signer, Domain::Delete, &delete_digest(&l.id, &id, at, t.as_ref())) }
    };
    // a level 3 token needs the write key, not the sync key; a level 1 token the sync key
    let ev = net.run(0, Command::Delete { label: l.id, items: vec![item(&b3, None, Some(token(3)), &k.sync), item(&b3, None, Some(token(9)), &k.write), item(&b1, None, Some(token(1)), &k.sync)] });
    assert_eq!(statuses(&ev), vec![Code::REFUSED, Code::REFUSED, Code::OK]);
    let ev = net.run(0, Command::Delete { label: l.id, items: vec![item(&b3, None, Some(token(3)), &k.write)] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    // timed: pending event now, deletion at the time
    let (_, cursor) = events_of(&net.run(0, sync(l.id, None, vec![], vec![])));
    let ev = net.run(0, Command::Delete { label: l.id, items: vec![item(&b_timed, Some(T0 + 5000), None, &k.delete)] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    net.store.sweep(T0 + 5000);
    let (evs, _) = events_of(&net.run(0, sync(l.id, cursor, vec![], vec![])));
    let id = osis_crypto::blob_id(&b_timed);
    assert_eq!(evs, vec![Event::Pending { blob_id: id, at: T0 + 5000 }, Event::Deleted(id)]);
}

// spec/sync.md §8, §9: subscriptions push new log events in the cursor-reply format; signals reach other subscribers
#[test]
fn subscribe_push_and_signals() {
    let mut net = Net::new(2, 0);
    let l = Label::new();
    net.setup(&l);
    net.open(0, &l);
    net.open(1, &l);
    let (_, c1) = events_of(&net.run(1, sync(l.id, None, vec![], vec![])));
    let ev = net.run(1, Command::Subscribe { labels: vec![l.id, LabelId([0xee; 16])] });
    assert_eq!(ev, vec![ClientEvent::Subscribed { labels: vec![l.id, LabelId([0xee; 16])], codes: vec![Code::OK, Code::NOT_OPENED] }]);
    net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(1)), l.entry(blob(2))] });
    let ev = std::mem::take(&mut net.events[1]);
    let (evs, cursor) = events_of(&ev);
    assert_eq!(evs.len(), 2);
    assert!(matches!(&evs[0], Event::Added { blob: Some(_), .. }));
    // the push cursor continues the sync cursor: a later Sync from it returns nothing new
    assert!(cursor.unwrap().seq > c1.unwrap().seq);
    let (evs, _) = events_of(&net.run(1, sync(l.id, cursor, vec![], vec![])));
    assert!(evs.is_empty());
    // signal under the write key reaches the other subscriber; a bad one is dropped
    let env = vec![0x5a; 100];
    let wrap: Wrap = [3; 49];
    let digest = entry_digest(&l.id, &osis_crypto::blob_id(&env), &wrap);
    let auth = SignalAuth { deposit: false, sig: sign(&l.head_keys().write, Domain::SignalPublish, &digest) };
    net.run(0, Command::Signal { label: l.id, blob: env.clone(), wrap, auth });
    assert_eq!(std::mem::take(&mut net.events[1]), vec![ClientEvent::Signal { label: l.id, blob: env.clone(), wrap, auth }]);
    let bad = SignalAuth { deposit: true, sig: auth.sig };
    net.run(0, Command::Signal { label: l.id, blob: env, wrap, auth: bad });
    assert!(net.events[1].is_empty());
    // unsubscribed: no more pushes
    net.run(1, Command::Unsubscribe { labels: vec![l.id] });
    net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(3))] });
    assert!(net.events[1].is_empty());
}

// spec/sync.md §5, spec/wire.md §11.2: fetch by ID of opened labels only, items in request order
#[test]
fn fetch() {
    let mut net = Net::new(1, 0);
    let l = Label::new();
    net.setup(&l);
    net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(1))] });
    let ids = vec![osis_crypto::blob_id(&blob(1)), osis_crypto::blob_id(&blob(2))];
    let ev = net.run(0, Command::Fetch { label: l.id, ids: ids.clone() });
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::NOT_OPENED, .. }]));
    net.open(0, &l);
    let ev = net.run(0, Command::Fetch { label: l.id, ids: ids.clone() });
    let [ClientEvent::Fetched { items, .. }] = &ev[..] else { panic!("{ev:?}") };
    assert_eq!(items[0].entry.as_ref().unwrap().0, blob(1));
    assert_eq!(items[1].entry, None);
}

// spec/wire.md §11.1, §11.2: unknown kind gets Error 11, a malformed message Error 2, a bad frame Error 2 and close
#[test]
fn bad_frames() {
    let mut net = Net::new(1, 0);
    let raw = |v: Value| encode_frame(&cbor::encode(&v));
    net.to_server[0].push_back(raw(Value::List(vec![Value::Int(99), Value::Int(5)])));
    net.to_server[0].push_back(raw(Value::List(vec![Value::Int(19), Value::Int(6), Value::Bytes(vec![0; 16]), Value::List(vec![])])));
    let so = net.servers[0].handle(T0, &mut net.store, ServerInput::Bytes(net.to_server[0].drain(..).flatten().collect()));
    let replies: Vec<Message> = so.iter().filter_map(|o| if let ServerOutput::Send(f) = o { Some(Message::decode(&f[4..]).unwrap()) } else { None }).collect();
    assert_eq!(replies, vec![Message::Error { id: 5, code: Code::UNSUPPORTED }, Message::Error { id: 6, code: Code::MALFORMED }]);
    let so = net.servers[0].handle(T0, &mut net.store, ServerInput::Bytes(vec![0, 0, 0, 0]));
    assert!(so.contains(&ServerOutput::Close));
    assert!(net.servers[0].is_closed());
    // a Hello without a common version closes
    let mut s = ServerConnection::new(ServerConfig { static_key: [0; 32], challenge: [0; 32] });
    let h = Hello { versions: vec![7], wall_ms: 0, challenge: [0; 32] };
    let so = s.handle(T0, &mut net.store, ServerInput::Bytes(encode_frame(&h.encode())));
    assert!(so.contains(&ServerOutput::Close));
}

// spec/sync.md §6, spec/requirements.md cost goals: a common-case sync converges in a constant number of round trips
#[test]
fn round_trips_are_constant_in_the_common_case() {
    for n in [10u64, 400] {
        let mut net = Net::new(2, 0);
        let l = Label::new();
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
    let l = Label::new();
    net.setup(&l);
    net.open(0, &l);
    net.open(1, &l);
    net.run(0, Command::Upload { label: l.id, entries: (0..n).map(|i| l.entry(blob(i))).collect() });
    let ev = net.run(1, Command::Sync { label: l.id, cursor: None, inline_limit: 0, entries: vec![], gained: vec![] });
    assert_eq!(events_of(&ev).0.len() as u64, n);
    net.flights = 0;
    let ids: Vec<BlobId> = (0..n).filter(|i| i % 1000 != 0).chain(n..n + 20).map(|i| osis_crypto::blob_id(&blob(i))).collect();
    let ev = net.run(1, Command::Reconcile { label: l.id, ids });
    let [ClientEvent::Reconciled { need, have, .. }] = &ev[..] else { panic!("{ev:?}") };
    assert_eq!((need.len(), have.len()), (20, 20));
    assert!(net.flights <= 8, "{} flights", net.flights);
}
