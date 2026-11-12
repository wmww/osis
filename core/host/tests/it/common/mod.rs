//! Scripted clients (osis-proto `ClientSession`) and hosts (`Hub` over `HostStore` on a
//! `MemoryBackend` and `MemoryRoot` sharing a fault plan) wired by in-memory byte queues; entries
//! put as node sync puts them (`pull`, `deposit`); a label with rotations; blobs.
#![allow(dead_code)]

use osis_base::{BlobId, Clock, ManualClock, WallMs};
use osis_crypto::{SeededRng, Secret32};
use osis_proto::*;
pub use osis_proto::examples::{Label, Stamped, bid, blob, blob_with, salt};
use osis_host::{HostStore, ConnId, Down, Hub, HubOutput, HostPolicy, Up};
use osis_store::{Faults, MemoryBackend, MemoryRoot, Store, StoreConfig};
use std::collections::VecDeque;
use std::sync::Arc;

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

/// Hosts and clients over in-memory links. One clock for all.
pub struct World {
    pub clock: Arc<ManualClock>,
    pub hubs: Vec<Hub>,
    /// Each hub's store device: rows, key root, and their fault plan.
    pub backends: Vec<MemoryBackend>,
    pub roots: Vec<MemoryRoot>,
    pub faults: Vec<Faults>,
    pub clients: Vec<ClientSession>,
    pub events: Vec<Vec<ClientEvent>>,
    pub diagnostics: Vec<String>,
    /// What hubs handed up for node sync (none runs here): (hub, connection, up).
    pub ups: Vec<(usize, ConnId, Up)>,
    links: Vec<Link>,
    next_conn: ConnId,
}

pub fn hub_key(i: usize) -> [u8; 32] {
    [0x50 + i as u8; 32]
}

impl World {
    pub fn new() -> World {
        World { clock: Arc::new(ManualClock::new(WallMs(T0))), hubs: vec![], backends: vec![], roots: vec![], faults: vec![], clients: vec![], events: vec![], diagnostics: vec![], ups: vec![], links: vec![], next_conn: 1 }
    }

    pub fn now(&self) -> u64 {
        self.clock.now_wall_ms().0
    }

    pub fn add_hub(&mut self, policy: HostPolicy) -> usize {
        let i = self.hubs.len();
        let faults = Faults::new();
        self.backends.push(MemoryBackend::with_faults(faults.clone()));
        self.roots.push(MemoryRoot::with_faults(faults.clone()));
        self.faults.push(faults);
        let store = self.host_store(i, policy, i as u8);
        self.hubs.push(Hub::new(std::sync::Arc::new(std::sync::Mutex::new(store)), Box::new(SeededRng::from_seed([0x70 + i as u8; 32]))));
        i
    }

    /// A host store over hub `i`'s device (created on first use), its rng from `seed`.
    pub fn host_store(&self, i: usize, policy: HostPolicy, seed: u8) -> HostStore {
        let (b, r) = (Box::new(self.backends[i].clone()), Box::new(self.roots[i].clone()));
        let store = Store::open_or_create(b, r, StoreConfig::default(), &mut SeededRng::from_seed([seed; 32])).unwrap();
        HostStore::open(store, self.clock.clone(), policy, Box::new(SeededRng::from_seed([seed ^ 0x55; 32]))).unwrap()
    }

    /// Replaces hub `i` by a fresh one over the same store: every connection of it is gone.
    pub fn restart(&mut self, i: usize, policy: HostPolicy) {
        for l in self.links.iter_mut() {
            if matches!(l.a, End::Hub(h, _) if h == i) || matches!(l.b, End::Hub(h, _) if h == i) {
                l.open = false;
            }
        }
        let store = self.host_store(i, policy, 0xff);
        self.hubs[i] = Hub::new(std::sync::Arc::new(std::sync::Mutex::new(store)), Box::new(SeededRng::from_seed([0x90 + i as u8; 32])));
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
        let out = self.hubs[h].accept(now, conn, hub_key(h), osis_host::Remote::key([0xe0 + c as u8; 32]));
        self.hub_out(h, out);
        let out = self.clients[c].handle(now, ClientInput::Start);
        self.client_out(c, out);
        self.pump();
        let ev = std::mem::take(&mut self.events[c]);
        assert!(matches!(ev.first(), Some(ClientEvent::Ready { .. })), "{ev:?}");
        c
    }

    /// Drops a link (both sides see the close).
    pub fn cut(&mut self, link: usize) {
        let l = &mut self.links[link];
        l.open = false;
        for e in [l.a, l.b] {
            if let End::Hub(h, c) = e {
                let out = self.hubs[h].closed(c);
                self.hub_out(h, out);
            }
        }
        self.pump();
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
                HubOutput::Up(c, u) => self.ups.push((h, c, u)),
                HubOutput::Moved => {}
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

    /// Hands hub `h` what node sync would (`Hub::down`) and delivers what follows.
    pub fn down(&mut self, h: usize, downs: Vec<(ConnId, Down)>) {
        let now = self.now();
        let out = self.hubs[h].down(now, downs);
        self.hub_out(h, out);
        self.pump();
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
        let out = self.hubs[h].accept(now, conn, hub_key(h), osis_host::Remote::key([0xd0; 32]));
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

    /// Registers `l`'s genesis step by client `c`, and opens it on `c`'s connection.
    pub fn setup(&mut self, c: usize, l: &Label) {
        let ev = self.run(c, l.register_cmd(0));
        assert_eq!(ev, vec![ClientEvent::Registered { label: l.id }]);
        self.open(c, l);
    }

    /// Node sync's open of `l` on client `c`'s connection (a sync-key Hit there): its Deletes
    /// are taken.
    pub fn open(&mut self, c: usize, l: &Label) {
        let (h, conn) = self.links.iter().find_map(|k| match (k.a, k.b) {
            (End::Client(x), End::Hub(h, conn)) if x == c => Some((h, conn)),
            _ => None,
        }).expect("a client's link");
        self.down(h, vec![(conn, Down::Open(l.id))]);
    }
}

pub fn statuses(ev: &[ClientEvent]) -> Vec<Code> {
    ev.iter()
        .flat_map(|e| match e {
            ClientEvent::DeleteStatus { codes, .. } => codes.clone(),
            _ => vec![],
        })
        .collect()
}

pub fn sorted(mut v: Vec<BlobId>) -> Vec<BlobId> {
    v.sort();
    v
}

/// Stamped entry `e` of `l` put at hub `h` as node sync's pull puts it (`serving::pulled`: its
/// stamp checked under the head keys).
pub fn pull_taken(w: &World, h: usize, l: &Label, e: &Stamped) -> serving::Taken {
    let mut s = w.hubs[h].store();
    let k = s.head_keys(&l.id).unwrap().expect("a registered label");
    serving::pulled(&mut *s, w.now(), &l.id, &k, &e.blob, e.wrap, e.stamp, &mut false).unwrap()
}

/// `pull_taken`'s code (a relay-only blob passed on: OK).
pub fn pull(w: &World, h: usize, l: &Label, e: &Stamped) -> Code {
    match pull_taken(w, h, l, e) {
        serving::Taken::Code(c) => c,
        serving::Taken::Relay(_) => Code::OK,
    }
}

/// Entries `ns` of `l` (`blob(n)` under the head's write key) pulled at hub `h`: their codes.
pub fn pull_all(w: &World, h: usize, l: &Label, ns: impl IntoIterator<Item = u64>) -> Vec<Code> {
    ns.into_iter().map(|n| pull(w, h, l, &l.entry(blob(n)))).collect()
}

/// A Deposit item put at hub `h` as node sync puts one (`serving::deposit`): its code, and whether
/// its signature verified (only then may the depositor learn more than the code).
pub fn deposit_verified(w: &World, h: usize, item: msg::OfferItem) -> (Code, bool) {
    let msg::OfferItem::Deposit { label, blob, wrap, sig } = item else { panic!("not a deposit") };
    let mut s = w.hubs[h].store();
    let k = s.head_keys(&label).unwrap().expect("a registered label");
    serving::deposit(&mut *s, w.now(), &label, &k, &blob, wrap, &sig, &mut false).unwrap()
}

/// `deposit_verified`'s code.
pub fn deposit(w: &World, h: usize, item: msg::OfferItem) -> Code {
    deposit_verified(w, h, item).0
}

/// The live entries of `l` at hub `h`, ascending.
pub fn live(w: &World, h: usize, l: &Label) -> Vec<BlobId> {
    w.hubs[h].store().live_ids(&l.id).unwrap()
}
