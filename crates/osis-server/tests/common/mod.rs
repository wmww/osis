//! Scripted clients (osis-proto `ClientSession`) and blind nodes (`Hub` over `BackendStore` on
//! `MemoryBackend`) wired by in-memory byte queues; a label with rotations; blobs.
#![allow(dead_code)]

use osis_core::{BlobId, Clock, LabelId, ManualClock, WallMs, hash::hash};
use osis_crypto::{Epoch, LabelRole, SeededRng, Secret32, SigningSecret, X25519Secret, label_role_key};
use osis_label::step::EntryTo;
use osis_label::{Parent, Prefix, Reader, StepKeys, genesis_label, register, sign_deposit, sign_stamp};
use osis_proto::msg::{ClaimSet, Step, Wrap};
use osis_proto::*;
use osis_server::{BackendStore, ConnId, Hub, HubOutput, Policy};
use osis_store::MemoryBackend;
use std::collections::VecDeque;
use std::sync::Arc;

#[cfg(feature = "driver")]
pub mod driven;

pub const T0: u64 = 1_700_000_000_000;

pub fn s32(b: u8) -> Secret32 {
    Secret32::from_bytes([b; 32])
}

#[derive(Clone)]
pub struct Keys {
    pub sync: SigningSecret,
    pub write: SigningSecret,
    pub delete: SigningSecret,
    pub deposit: SigningSecret,
}

/// A label with its path, claim sets and keys; group secrets from a byte each.
pub struct Label {
    pub id: LabelId,
    pub keys: Vec<Keys>,
    pub steps: Vec<Step>,
    pub sets: Vec<ClaimSet>,
    pub reader: X25519Secret,
    pub admin: u8,
}

const DEPOSIT_SEED: u8 = 0x30;

impl Label {
    pub fn new(admin: u8) -> Label {
        let id = genesis_label(&s32(admin), 0);
        let mut l = Label { id, keys: vec![], steps: vec![], sets: vec![], reader: X25519Secret::from_secret(&s32(0x31)), admin };
        l.step_with(1, None);
        l
    }

    fn step_with(&mut self, b: u8, parent: Option<SigningSecret>) -> (Step, ClaimSet) {
        let (read, write, adm) = (s32(b), s32(b + 1), s32(self.admin));
        let pk = StepKeys::derive(&read, &write, &adm, 0, &s32(DEPOSIT_SEED), &self.id);
        let keys = Keys {
            sync: label_role_key(LabelRole::Sync, &read, 0),
            write: label_role_key(LabelRole::Write, &write, 0),
            delete: label_role_key(LabelRole::Delete, &adm, 0),
            deposit: osis_crypto::deposit_key(&s32(DEPOSIT_SEED), &self.id),
        };
        let key_actor = SigningSecret::from_seed(&s32(0x32));
        let s = s32(0x33);
        let readers = [Reader::Dh(self.reader.public()), Reader::Static { signing: key_actor.verifying_key(), entry: EntryTo::Symmetric { s: &s, epoch_s: Epoch::new(0, [0; 16]).unwrap() } }];
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
    pub fn rotate(&mut self, b: u8) -> (Step, ClaimSet) {
        let parent = self.head_keys().delete.clone();
        self.step_with(b, Some(parent))
    }

    pub fn head_keys(&self) -> &Keys {
        self.keys.last().unwrap()
    }

    pub fn entry(&self, blob: Vec<u8>) -> Entry {
        self.entry_by(blob, &self.head_keys().write.clone())
    }

    pub fn entry_by(&self, blob: Vec<u8>, write: &SigningSecret) -> Entry {
        let wrap: Wrap = [(blob.len() % 251) as u8; 49];
        let stamp = sign_stamp(write, &self.id, &osis_label::blob_id(&blob), &wrap);
        Entry { blob, wrap, stamp }
    }

    pub fn deposit(&self, blob: Vec<u8>, key: &SigningSecret) -> Command {
        let wrap: Wrap = [7; 49];
        let sig = sign_deposit(key, &self.id, &osis_label::blob_id(&blob), &wrap);
        Command::Deposit { label: self.id, blob, wrap, sig }
    }

    pub fn register_cmd(&self, i: usize) -> Command {
        Command::Register { label: self.id, step: self.steps[i].clone(), claim_set: Some(self.sets[i].clone()) }
    }
}

pub fn salt(n: u64) -> [u8; 16] {
    hash(&n.to_be_bytes())[..16].try_into().unwrap()
}

/// A blob with a version 1 prefix (salt from `n`, expiry, commitments), then body bytes.
pub fn blob_with(n: u64, expiry: u64, commitments: Vec<[u8; 17]>) -> Vec<u8> {
    let mut b = Prefix::new(salt(n), (expiry != 0).then_some(WallMs(expiry)), commitments).unwrap().to_bytes();
    let h = hash(&n.to_le_bytes());
    b.extend((0..20 + (n % 32) as usize).map(|i| h[i % 32]));
    b
}

pub fn blob(n: u64) -> Vec<u8> {
    blob_with(n, 0, vec![])
}

pub fn bid(n: u64) -> BlobId {
    osis_label::blob_id(&blob(n))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Client(usize),
    /// Reads and drops everything, says nothing.
    Sink(usize),
    Hub(usize, ConnId),
}

struct Link {
    a: End,
    b: End,
    to_b: VecDeque<u8>,
    to_a: VecDeque<u8>,
    open: bool,
}

/// Blind nodes and clients over in-memory links. One clock for all.
pub struct World {
    pub clock: Arc<ManualClock>,
    pub hubs: Vec<Hub<MemoryBackend>>,
    pub backends: Vec<MemoryBackend>,
    pub clients: Vec<ClientSession>,
    pub events: Vec<Vec<ClientEvent>>,
    pub diagnostics: Vec<String>,
    links: Vec<Link>,
    next_conn: ConnId,
}

pub fn hub_key(i: usize) -> [u8; 32] {
    [0x50 + i as u8; 32]
}

impl World {
    pub fn new() -> World {
        World { clock: Arc::new(ManualClock::new(WallMs(T0))), hubs: vec![], backends: vec![], clients: vec![], events: vec![], diagnostics: vec![], links: vec![], next_conn: 1 }
    }

    pub fn now(&self) -> u64 {
        self.clock.now_wall_ms().0
    }

    pub fn add_hub(&mut self, policy: Policy) -> usize {
        let i = self.hubs.len();
        let backend = MemoryBackend::new();
        self.backends.push(backend.clone());
        let store = BackendStore::open(backend, self.clock.clone(), policy, &mut SeededRng::from_seed([i as u8; 32])).unwrap();
        self.hubs.push(Hub::new(store, hub_key(i), Box::new(SeededRng::from_seed([0x70 + i as u8; 32]))));
        i
    }

    /// Replaces hub `i` by a fresh one over the same backend: every connection of it is gone.
    pub fn restart(&mut self, i: usize, policy: Policy) {
        for l in self.links.iter_mut() {
            if matches!(l.a, End::Hub(h, _) if h == i) || matches!(l.b, End::Hub(h, _) if h == i) {
                l.open = false;
            }
        }
        let store = BackendStore::open(self.backends[i].clone(), self.clock.clone(), policy, &mut SeededRng::from_seed([0xff; 32])).unwrap();
        self.hubs[i] = Hub::new(store, hub_key(i), Box::new(SeededRng::from_seed([0x90 + i as u8; 32])));
    }

    /// A client connected to hub `h`; returns the client index.
    pub fn connect(&mut self, h: usize) -> usize {
        let c = self.clients.len();
        self.clients.push(ClientSession::new(ClientConfig { peer_static_key: hub_key(h), challenge: [0xc0 + c as u8; 32] }));
        self.events.push(vec![]);
        let conn = self.next_conn;
        self.next_conn += 1;
        self.links.push(Link { a: End::Client(c), b: End::Hub(h, conn), to_b: VecDeque::new(), to_a: VecDeque::new(), open: true });
        let now = self.now();
        let out = self.hubs[h].accept(now, conn, [0xe0 + c as u8; 32]);
        self.hub_out(h, out);
        let out = self.clients[c].handle(now, ClientInput::Start);
        self.client_out(c, out);
        self.pump();
        let ev = std::mem::take(&mut self.events[c]);
        assert!(matches!(ev.first(), Some(ClientEvent::Ready { .. })), "{ev:?}");
        c
    }

    /// Hub `from` dials hub `to` as its replication peer; returns the link index.
    pub fn peer(&mut self, from: usize, to: usize) -> usize {
        let (ca, cb) = (self.next_conn, self.next_conn + 1);
        self.next_conn += 2;
        self.links.push(Link { a: End::Hub(from, ca), b: End::Hub(to, cb), to_b: VecDeque::new(), to_a: VecDeque::new(), open: true });
        let now = self.now();
        let out = self.hubs[to].accept(now, cb, hub_key(from));
        self.hub_out(to, out);
        let out = self.hubs[from].peer_up(now, ca, hub_key(to));
        self.hub_out(from, out);
        self.pump();
        self.settle();
        self.links.len() - 1
    }

    /// Drops a link (both sides see the close).
    pub fn cut(&mut self, link: usize) {
        let l = &mut self.links[link];
        l.open = false;
        for e in [l.a, l.b] {
            if let End::Hub(h, c) = e {
                self.hubs[h].closed(c);
            }
        }
    }

    fn route(&mut self, from: End, bytes: Vec<u8>) {
        if let Some(l) = self.links.iter_mut().find(|l| l.open && (l.a == from || l.b == from)) {
            if l.a == from {
                l.to_b.extend(bytes)
            } else {
                l.to_a.extend(bytes)
            }
        }
    }

    fn close(&mut self, from: End) {
        if let Some(i) = self.links.iter().position(|l| l.open && (l.a == from || l.b == from)) {
            self.cut(i);
        }
    }

    fn client_out(&mut self, c: usize, out: Vec<ClientOutput>) {
        for o in out {
            match o {
                ClientOutput::Send(b) => self.route(End::Client(c), b),
                ClientOutput::Event(e) => self.events[c].push(e),
                ClientOutput::Close => self.close(End::Client(c)),
                ClientOutput::SetTimer(_) => {}
            }
        }
    }

    fn hub_out(&mut self, h: usize, out: Vec<HubOutput>) {
        for o in out {
            match o {
                HubOutput::Send(c, b) => self.route(End::Hub(h, c), b),
                HubOutput::Close(c) => self.close(End::Hub(h, c)),
                HubOutput::Diagnostic(d) => self.diagnostics.push(d),
            }
        }
    }

    fn deliver(&mut self, to: End, bytes: Vec<u8>) {
        let now = self.now();
        match to {
            End::Sink(_) => {}
            End::Client(c) => {
                let out = self.clients[c].handle(now, ClientInput::Bytes(bytes));
                self.client_out(c, out);
            }
            End::Hub(h, c) => {
                let out = self.hubs[h].input(now, c, bytes);
                self.hub_out(h, out);
            }
        }
    }

    /// Delivers bytes until every queue is empty.
    pub fn pump(&mut self) {
        loop {
            let mut moved = false;
            for i in 0..self.links.len() {
                if !self.links[i].open {
                    continue;
                }
                let to_b: Vec<u8> = self.links[i].to_b.drain(..).collect();
                let to_a: Vec<u8> = self.links[i].to_a.drain(..).collect();
                let (a, b) = (self.links[i].a, self.links[i].b);
                if !to_b.is_empty() {
                    moved = true;
                    self.deliver(b, to_b);
                }
                if !to_a.is_empty() {
                    moved = true;
                    self.deliver(a, to_a);
                }
            }
            if !moved {
                return;
            }
        }
    }

    /// Hands a command to client `c` without delivering anything yet.
    pub fn send(&mut self, c: usize, cmd: Command) {
        let now = self.now();
        let out = self.clients[c].handle(now, ClientInput::Command(cmd));
        self.client_out(c, out);
    }

    /// Runs a command to quiescence (hubs' due work included) and returns the client's events.
    pub fn run(&mut self, c: usize, cmd: Command) -> Vec<ClientEvent> {
        let now = self.now();
        let out = self.clients[c].handle(now, ClientInput::Command(cmd));
        self.client_out(c, out);
        self.pump();
        self.settle();
        std::mem::take(&mut self.events[c])
    }

    /// Advances the clock and ticks every hub while it has work due (sweeps, timers).
    pub fn advance(&mut self, ms: u64) {
        self.clock.advance(ms);
        self.settle();
    }

    /// Ticks hubs with work due now until none has any (at most 1000 rounds).
    pub fn settle(&mut self) {
        let now = self.now();
        for _ in 0..1000 {
            let due: Vec<usize> = (0..self.hubs.len()).filter(|h| self.hubs[*h].next_due(now).is_some_and(|t| t <= now)).collect();
            if due.is_empty() {
                return;
            }
            for h in due {
                let out = self.hubs[h].tick(now);
                self.hub_out(h, out);
            }
            self.pump();
        }
        panic!("hubs never settle");
    }

    /// A raw connection to hub `h` that never speaks; returns its link index.
    pub fn connect_silent(&mut self, h: usize) -> (usize, ConnId) {
        let conn = self.next_conn;
        self.next_conn += 1;
        self.links.push(Link { a: End::Sink(self.links.len()), b: End::Hub(h, conn), to_b: VecDeque::new(), to_a: VecDeque::new(), open: true });
        let now = self.now();
        let out = self.hubs[h].accept(now, conn, [0xd0; 32]);
        self.hub_out(h, out);
        self.pump();
        (self.links.len() - 1, conn)
    }

    pub fn link_open(&self, link: usize) -> bool {
        self.links[link].open
    }

    pub fn take(&mut self, c: usize) -> Vec<ClientEvent> {
        std::mem::take(&mut self.events[c])
    }

    pub fn setup(&mut self, c: usize, l: &Label) {
        let ev = self.run(c, l.register_cmd(0));
        assert_eq!(ev, vec![ClientEvent::Registered { label: l.id }]);
    }

    pub fn open(&mut self, c: usize, l: &Label) {
        let ev = self.run(c, Command::Open { label: l.id, key: OpenKey::Sync(l.head_keys().sync.clone()) });
        assert!(matches!(&ev[..], [ClientEvent::Opened { .. }]), "{ev:?}");
    }
}

pub fn events_of(ev: &[ClientEvent]) -> (Vec<Event>, Option<Cursor>) {
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

pub fn statuses(ev: &[ClientEvent]) -> Vec<Code> {
    ev.iter()
        .flat_map(|e| match e {
            ClientEvent::EntryStatus { codes, .. } | ClientEvent::DeleteStatus { codes, .. } => codes.clone(),
            ClientEvent::Budget { code, .. } => vec![*code],
            _ => vec![],
        })
        .collect()
}

pub fn added(evs: &[Event]) -> Vec<BlobId> {
    evs.iter().filter_map(|e| if let Event::Added { blob_id, .. } = e { Some(*blob_id) } else { None }).collect()
}

pub fn sync(label: LabelId, cursor: Option<Cursor>, entries: Vec<Entry>, gained: Vec<BlobId>) -> Command {
    Command::Sync { label, cursor, inline_limit: 1 << 20, entries, gained }
}

pub fn sorted(mut v: Vec<BlobId>) -> Vec<BlobId> {
    v.sort();
    v
}
