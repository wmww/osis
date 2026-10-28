//! Scripted clients (osis-proto `ClientSession`) and blind nodes (`Hub` over `BackendStore` on
//! `MemoryBackend`) wired by in-memory byte queues; a label with rotations; blobs.
#![allow(dead_code)]

use osis_base::{BlobId, Clock, LabelId, ManualClock, WallMs};
use osis_crypto::{SeededRng, Secret32};
use osis_proto::*;
pub use osis_proto::examples::{Label, bid, blob, blob_with, salt};
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
