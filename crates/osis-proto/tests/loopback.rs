//! Client engines against server engines over in-memory byte queues, with a `MemoryLabelStore`
//! (spec/sync.md §4-§9, spec/wire.md §11).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_core::{BlobId, LabelId, Value, WallMs, cbor, hash::hash};
use osis_crypto::{Epoch, LabelRole, SeededRng, Secret32, SigningSecret, X25519Secret, label_role_key};
use osis_label::step::EntryTo;
use osis_label::{Parent, Prefix, Reader, StepKeys, genesis_label, register, sign_deposit, sign_stamp};
use osis_proto::msg::{ClaimSet, DeleteItem, PublishAuth, PublishKey, Step, Wrap};
use osis_proto::*;
use std::collections::VecDeque;

fn s32(b: u8) -> Secret32 {
    Secret32::from_bytes([b; 32])
}

/// One label's signing keys at one step.
#[derive(Clone)]
struct Keys {
    sync: SigningSecret,
    write: SigningSecret,
    delete: SigningSecret,
    deposit: SigningSecret,
}

/// A label with its path, claim sets and keys; group secrets from a byte each.
struct Label {
    id: LabelId,
    keys: Vec<Keys>,
    steps: Vec<Step>,
    sets: Vec<ClaimSet>,
    reader: X25519Secret,
    key_actor: SigningSecret,
}

const DEPOSIT_SEED: u8 = 0x30;
const ADMIN: u8 = 3;

impl Label {
    fn new() -> Label {
        let id = genesis_label(&s32(ADMIN), 0);
        let mut l = Label { id, keys: vec![], steps: vec![], sets: vec![], reader: X25519Secret::from_secret(&s32(0x31)), key_actor: SigningSecret::from_seed(&s32(0x32)) };
        l.step_with(1, None);
        l
    }

    /// A step with read secret `b`, write `b + 1`, the fixed admin secret (a child of the head
    /// signed by `parent`, else the genesis step).
    fn step_with(&mut self, b: u8, parent: Option<SigningSecret>) -> (Step, ClaimSet) {
        let (read, write, adm) = (s32(b), s32(b + 1), s32(ADMIN));
        let pk = StepKeys::derive(&read, &write, &adm, 0, &s32(DEPOSIT_SEED), &self.id);
        let keys = Keys {
            sync: label_role_key(LabelRole::Sync, &read, 0),
            write: label_role_key(LabelRole::Write, &write, 0),
            delete: label_role_key(LabelRole::Delete, &adm, 0),
            deposit: osis_crypto::deposit_key(&s32(DEPOSIT_SEED), &self.id),
        };
        let s = s32(0x33);
        let readers = [Reader::Dh(self.reader.public()), Reader::Static { signing: self.key_actor.verifying_key(), entry: EntryTo::Symmetric { s: &s, epoch_s: Epoch::new(0, [0; 16]).unwrap() } }];
        let mut rng = SeededRng::from_seed([b; 32]);
        let read_epoch = (Epoch::new(1, [b; 16]).unwrap(), &read);
        let (step, set) = match (&parent, self.steps.last()) {
            (Some(d), Some(prev)) => register(Parent::Child { step: prev, delete: d }, pk, &readers, read_epoch, &mut rng).unwrap(),
            _ => register(Parent::Genesis(&keys.delete), pk, &readers, read_epoch, &mut rng).unwrap(),
        };
        self.steps.push(step.clone());
        self.sets.push(set.clone());
        self.keys.push(keys);
        (step, set)
    }

    /// A child step under new read and write secrets (`b`, `b + 1`).
    fn rotate(&mut self, b: u8) -> (Step, ClaimSet) {
        let parent = self.head_keys().delete.clone();
        self.step_with(b, Some(parent))
    }

    fn head_keys(&self) -> &Keys {
        self.keys.last().unwrap()
    }

    fn entry(&self, blob: Vec<u8>) -> Entry {
        self.entry_by(blob, &self.head_keys().write.clone())
    }

    fn entry_by(&self, blob: Vec<u8>, write: &SigningSecret) -> Entry {
        let wrap: Wrap = [(blob.len() % 251) as u8; 49];
        let stamp = sign_stamp(write, &self.id, &osis_label::blob_id(&blob), &wrap);
        Entry { blob, wrap, stamp }
    }
}

fn salt(n: u64) -> [u8; 16] {
    hash(&n.to_be_bytes())[..16].try_into().unwrap()
}

/// A blob with a version 1 prefix (salt from `n`, expiry, commitments), then `size` body bytes.
fn blob_sized(n: u64, expiry: u64, commitments: Vec<[u8; 17]>, size: usize) -> Vec<u8> {
    let mut b = Prefix::new(salt(n), (expiry != 0).then_some(WallMs(expiry)), commitments).unwrap().to_bytes();
    let h = hash(&n.to_le_bytes());
    b.extend((0..size).map(|i| h[i % 32]));
    b
}

fn blob_with(n: u64, expiry: u64, commitments: Vec<[u8; 17]>) -> Vec<u8> {
    blob_sized(n, expiry, commitments, 20 + (n % 32) as usize)
}

fn blob(n: u64) -> Vec<u8> {
    blob_with(n, 0, vec![])
}

fn bid(n: u64) -> BlobId {
    osis_label::blob_id(&blob(n))
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
                        let so = self.servers[j].handle(self.now + self.server_skew, &mut self.store, ServerInput::Signal { label, blob: blob.clone(), wrap, auth: auth.clone() });
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
        let ev = self.run(0, Command::Register { label: l.id, step: l.steps[0].clone(), claim_set: Some(l.sets[0].clone()) });
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
    let l = Label::new();
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
    let l = Label::new();
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

// spec/sync.md §6, spec/wire.md §11.2: a cursor the log no longer reaches gets Error 10; the Sync's entries still go up; reconciliation finds both differences
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
    let ev = net.run(1, sync(l.id, cursor, vec![l.entry(blob(2000))], vec![]));
    assert!(ev.contains(&ClientEvent::NeedReconcile { label: l.id }), "{ev:?}");
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
    let l = Label::new();
    net.setup(&l);
    net.open(0, &l);
    let gained: Vec<BlobId> = (0..4097u64).map(|n| BlobId(hash(&n.to_le_bytes()))).collect();
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
    let (child, cs) = l.rotate(20);
    let ev = net.run(0, Command::Register { label: l.id, step: child.clone(), claim_set: Some(cs) });
    assert_eq!(ev, vec![ClientEvent::Registered { label: l.id }]);
    let ev = net.run(0, Command::Open { label: l.id, key: OpenKey::Sync(old.sync.clone()) });
    let [ClientEvent::Step { step, .. }] = &ev[..] else { panic!("{ev:?}") };
    assert_eq!(step, &child);
    step.verify_child(&l.steps[0]).unwrap();
    // not opened: reads refused
    let ev = net.run(0, sync(l.id, None, vec![], vec![]));
    assert!(matches!(&ev[..], [ClientEvent::Refused { kind: 15, code: Code::NOT_OPENED, .. }]), "{ev:?}");
    let ev = net.run(0, Command::Open { label: l.id, key: OpenKey::Sync(SigningSecret::from_seed(&s32(99))) });
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::REFUSED, .. }]));
    // a step on another branch is answered with the head
    let mut fork = Label::new();
    let (other, _) = fork.rotate(40);
    let ev = net.run(0, Command::Register { label: l.id, step: other, claim_set: None });
    assert!(matches!(&ev[..], [ClientEvent::Head { head, .. }] if *head == child));
    net.open(0, &l);
    let ev = net.run(0, Command::Path { label: l.id, after: None });
    assert_eq!(ev, vec![ClientEvent::PathSteps { label: l.id, steps: l.steps.clone(), more: false }]);
    let ev = net.run(0, Command::Path { label: l.id, after: Some(l.steps[0].id()) });
    assert_eq!(ev, vec![ClientEvent::PathSteps { label: l.id, steps: vec![child], more: false }]);
}

// spec/sync.md §5: claim keys open at the head or get the child; static entries open with the entry box; a dropped set serves no claims
#[test]
fn claim_and_static_opens() {
    let mut net = Net::new(1, 0);
    let mut l = Label::new();
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

// spec/sync.md §5: stamps under the head's write key; an old key gets 9 with the head; expiry, tombstone, unknown label; identical re-uploads log nothing
#[test]
fn upload_rules() {
    let mut net = Net::new(1, 0);
    let mut l = Label::new();
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
    assert!(matches!(&ev[..], [ClientEvent::EntryStatus { codes, head: Some(h), .. }] if *codes == vec![Code::NOT_HEAD, Code::OK] && *h == child), "{ev:?}");
    net.open(0, &l);
    let item = DeleteItem::sign(&l.head_keys().delete, &l.id, bid(6), None, None).unwrap();
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

// spec/sync.md §5: deposits by the deposit key within the budget (64 + 4 x claim slots), refused when full
#[test]
fn deposit_budget() {
    let mut net = Net::new(1, 0);
    let l = Label::new();
    net.setup(&l);
    let max = 64 + 4 * l.sets[0].claims.len() as u64;
    let deposit = |l: &Label, n: u64, k: &SigningSecret| {
        let b = blob(n);
        let wrap: Wrap = [7; 49];
        let sig = sign_deposit(k, &l.id, &osis_label::blob_id(&b), &wrap);
        Command::Deposit { label: l.id, blob: b, wrap, sig }
    };
    let dk = l.head_keys().deposit.clone();
    let ev = net.run(0, deposit(&l, 0, &dk));
    assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::OK, entries_left, .. }] if *entries_left == max - 1), "{ev:?}");
    let ev = net.run(0, deposit(&l, 1, &l.head_keys().write.clone()));
    assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::REFUSED, .. }]));
    for n in 1..max {
        net.run(0, deposit(&l, n, &dk));
    }
    let ev = net.run(0, deposit(&l, 500, &dk));
    assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::BUDGET_FULL, entries_left: 0, .. }]), "{ev:?}");
    // stamping a deposited entry takes it out of the budget
    let ev = net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(blob(0))] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    let ev = net.run(0, deposit(&l, 500, &dk));
    assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::OK, entries_left: 0, .. }]), "{ev:?}");
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
    let commit = |level: u8, t: &Secret32, n: u64| osis_crypto::commitment(level, &osis_crypto::token_hash(t.expose()), &salt(n)).unwrap();
    let (t1, t3, t9) = (s32(1), s32(3), s32(9));
    let b3 = blob_with(10, 0, vec![commit(3, &t3, 10)]);
    let b1 = blob_with(11, 0, vec![commit(1, &t1, 11)]);
    let b_timed = blob(12);
    net.run(0, Command::Upload { label: l.id, entries: vec![l.entry(b3.clone()), l.entry(b1.clone()), l.entry(b_timed.clone())] });
    let k = l.head_keys().clone();
    let item = |b: &[u8], at: Option<u64>, t: Option<&Secret32>, signer: &SigningSecret| DeleteItem::sign(signer, &l.id, osis_label::blob_id(b), at.map(WallMs), t).unwrap();
    let ev = net.run(0, Command::Delete { label: l.id, items: vec![item(&b3, None, Some(&t3), &k.sync), item(&b3, None, Some(&t9), &k.write), item(&b1, None, Some(&t1), &k.sync)] });
    assert_eq!(statuses(&ev), vec![Code::REFUSED, Code::REFUSED, Code::OK]);
    let ev = net.run(0, Command::Delete { label: l.id, items: vec![item(&b3, None, Some(&t3), &k.write)] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    let (_, cursor) = events_of(&net.run(0, sync(l.id, None, vec![], vec![])));
    let ev = net.run(0, Command::Delete { label: l.id, items: vec![item(&b_timed, Some(T0 + 5000), None, &k.delete)] });
    assert_eq!(statuses(&ev), vec![Code::OK]);
    net.store.sweep(T0 + 5000);
    let (evs, _) = events_of(&net.run(0, sync(l.id, cursor, vec![], vec![])));
    let id = osis_label::blob_id(&b_timed);
    assert_eq!(evs, vec![Event::Pending { blob_id: id, at: T0 + 5000 }, Event::Deleted(id)]);
}

// spec/sync.md §8, §9, spec/wire.md §11.2: pushes in the cursor-reply format under the last Sync's inline limit; signals reach other subscribers
#[test]
fn subscribe_push_and_signals() {
    let mut net = Net::new(2, 0);
    let l = Label::new();
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
    let env = vec![0x5a; 100];
    let wrap: Wrap = [3; 49];
    let auth = PublishAuth::sign(PublishKey::Write, &l.head_keys().write, &l.id, &osis_label::blob_id(&env), &wrap);
    net.run(0, Command::Signal { label: l.id, blob: env.clone(), wrap, auth: auth.clone() });
    assert_eq!(std::mem::take(&mut net.events[1]), vec![ClientEvent::Signal { label: l.id, blob: env.clone(), wrap, auth: auth.clone() }]);
    let bad = PublishAuth { key: PublishKey::Deposit, sig: auth.sig };
    net.run(0, Command::Signal { label: l.id, blob: env, wrap, auth: bad });
    assert!(net.events[1].is_empty());
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
    let so = net.servers[0].handle(T0, &mut net.store, ServerInput::Bytes(bytes.clone()));
    let want = vec![Message::Error { id: 5, code: Code::UNSUPPORTED }, Message::Error { id: 6, code: Code::MALFORMED }];
    assert_eq!(decode_sent(so.into_iter().filter_map(|o| if let ServerOutput::Send(f) = o { Some(f) } else { None }).collect()), want);
    let co = net.clients[0].handle(T0, ClientInput::Bytes(bytes));
    assert_eq!(decode_sent(co.into_iter().filter_map(|o| if let ClientOutput::Send(f) = o { Some(f) } else { None }).collect()), want);
    let so = net.servers[0].handle(T0, &mut net.store, ServerInput::Bytes(vec![0, 0, 0, 0]));
    assert!(so.contains(&ServerOutput::Close));
    assert!(net.servers[0].is_closed());
    let mut s = ServerConnection::new(ServerConfig { static_key: [0; 32], challenge: [0; 32] });
    let h = Hello { versions: vec![7], wall_ms: 0, challenge: [0; 32] };
    let so = s.handle(T0, &mut net.store, ServerInput::Bytes(encode_frame(&h.encode())));
    assert!(so.contains(&ServerOutput::Close));
}

// spec/wire.md §11.2: a peer whose Sync pages make no progress is dropped, not followed forever
#[test]
fn client_stops_on_a_stuck_sync() {
    let mut net = Net::new(1, 0);
    let l = Label::new();
    let cursor = Cursor { log_id: [1; 16], seq: 5 };
    let out = net.clients[0].handle(T0, ClientInput::Command(sync(l.id, Some(cursor), vec![], vec![])));
    let sends: Vec<&Vec<u8>> = out.iter().filter_map(|o| if let ClientOutput::Send(f) = o { Some(f) } else { None }).collect();
    let [f] = &sends[..] else { panic!("{out:?}") };
    let Message::Sync { id, .. } = Message::decode(&f[4..]).unwrap() else { panic!() };
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
    let ids: Vec<BlobId> = (0..n).filter(|i| i % 1000 != 0).chain(n..n + 20).map(bid).collect();
    let ev = net.run(1, Command::Reconcile { label: l.id, ids });
    let [ClientEvent::Reconciled { need, have, .. }] = &ev[..] else { panic!("{ev:?}") };
    assert_eq!((need.len(), have.len()), (20, 20));
    assert!(net.flights <= 8, "{} flights", net.flights);
}

// spec/sync.md §6: a request left unanswered on an open stream closes the session at its
// deadline (the node redials); answered ones never do
#[test]
fn unanswered_request_times_out() {
    let mut c = ClientSession::new(ClientConfig { peer_static_key: [1; 32], challenge: [2; 32] });
    c.handle(T0, ClientInput::Start);
    let hello = encode_frame(&Hello::new(T0, [3; 32]).encode());
    let out = c.handle(T0, ClientInput::Bytes(hello));
    assert!(out.iter().any(|o| matches!(o, ClientOutput::SetTimer(t) if *t == T0 + client::REQUEST_TIMEOUT_MS)), "{out:?}");
    // the initial pings stay unanswered
    let early = c.handle(T0 + client::REQUEST_TIMEOUT_MS - 1, ClientInput::Timer);
    assert!(!early.iter().any(|o| matches!(o, ClientOutput::Close)));
    let late = c.handle(T0 + client::REQUEST_TIMEOUT_MS, ClientInput::Timer);
    assert!(late.iter().any(|o| matches!(o, ClientOutput::Close)), "{late:?}");
    assert!(c.is_closed());
}
