//! The async driver over in-process links: scripted clients end to end, subscription pushes,
//! two servers replicating through dialed links, shutdown and restart (spec/sync.md §5-§9).
//! Event-driven only: nothing sleeps; a timeout guards against a hang.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::*;
use osis_core::ManualClock;
use osis_core::WallMs;
use osis_crypto::SeededRng;
use osis_label::Address;
use osis_proto::*;
use osis_server::{BackendStore, Control, Hub, Link, MemNet, Policy, run};
use osis_store::MemoryBackend;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const GUARD: Duration = Duration::from_secs(20);

struct Client {
    s: ClientSession,
    link: Link,
    events: Vec<ClientEvent>,
}

impl Client {
    async fn connect(net: &MemNet, key: [u8; 32]) -> Client {
        let link = net.connect(key).await.unwrap();
        let mut c = Client { s: ClientSession::new(ClientConfig { peer_static_key: key, challenge: [9; 32] }), link, events: vec![] };
        let out = c.s.handle(T0, ClientInput::Start);
        c.out(out);
        while !c.s.is_ready() {
            c.recv().await;
        }
        c.wait().await;
        c.events.clear();
        c
    }

    fn out(&mut self, out: Vec<ClientOutput>) {
        for o in out {
            match o {
                ClientOutput::Send(b) => self.link.tx.try_send(b).unwrap(),
                ClientOutput::Event(e) => self.events.push(e),
                _ => {}
            }
        }
    }

    async fn recv(&mut self) {
        let b = tokio::time::timeout(GUARD, self.link.rx.recv()).await.expect("no reply").expect("link closed");
        let out = self.s.handle(T0, ClientInput::Bytes(b));
        self.out(out);
    }

    async fn wait(&mut self) {
        while self.s.outstanding() > 0 {
            self.recv().await;
        }
    }

    async fn run(&mut self, cmd: Command) -> Vec<ClientEvent> {
        let out = self.s.handle(T0, ClientInput::Command(cmd));
        self.out(out);
        self.wait().await;
        std::mem::take(&mut self.events)
    }

    /// Bytes already queued on the link.
    fn drain(&mut self) -> Vec<ClientEvent> {
        while let Ok(b) = self.link.rx.try_recv() {
            let out = self.s.handle(T0, ClientInput::Bytes(b));
            self.out(out);
        }
        std::mem::take(&mut self.events)
    }

    /// Waits for the next events (a push).
    async fn next(&mut self) -> Vec<ClientEvent> {
        while self.events.is_empty() {
            self.recv().await;
        }
        std::mem::take(&mut self.events)
    }
}

struct Server {
    control: mpsc::Sender<Control>,
    task: JoinHandle<Hub<MemoryBackend>>,
}

fn start(net: &MemNet, key: [u8; 32], backend: MemoryBackend, peers: Vec<Address>) -> Server {
    let clock = Arc::new(ManualClock::new(WallMs(T0)));
    let store = BackendStore::open(backend, clock.clone(), Policy::default(), &mut SeededRng::from_seed(key)).unwrap();
    let listener = net.listen(key);
    let hub = Hub::new(store, listener.local_key, Box::new(SeededRng::from_seed([1; 32])));
    let (control, rx) = mpsc::channel(4);
    let task = tokio::spawn(run(hub, listener, peers, Arc::new(net.clone()), clock, rx, Arc::new(|m: &str| eprintln!("{m}"))));
    Server { control, task }
}

// spec/sync.md §5, §8: clients through the driver: register, open, upload, download, subscription push
#[tokio::test]
async fn clients_end_to_end() {
    let net = MemNet::new();
    let key = [0x51; 32];
    let server = start(&net, key, MemoryBackend::new(), vec![]);
    let (mut a, mut b) = (Client::connect(&net, key).await, Client::connect(&net, key).await);
    let l = Label::new(3);
    assert_eq!(a.run(l.register_cmd(0)).await, vec![ClientEvent::Registered { label: l.id }]);
    for c in [&mut a, &mut b] {
        let ev = c.run(Command::Open { label: l.id, key: OpenKey::Sync(l.head_keys().sync.clone()) }).await;
        assert!(matches!(&ev[..], [ClientEvent::Opened { .. }]), "{ev:?}");
    }
    b.run(Command::Subscribe { labels: vec![l.id] }).await;
    let ev = a.run(sync(l.id, None, (0..20).map(|n| l.entry(blob(n))).collect(), vec![])).await;
    assert_eq!(statuses(&ev), vec![Code::OK; 20]);
    // the push to b went out before a's reply
    assert_eq!(sorted(added(&events_of(&b.drain()).0)), sorted((0..20).map(bid).collect()));
    let (evs, _) = events_of(&b.run(sync(l.id, None, vec![], vec![])).await);
    assert_eq!(added(&evs), sorted((0..20).map(bid).collect()));
    server.control.send(Control::Shutdown).await.unwrap();
    let hub = server.task.await.unwrap();
    assert_eq!(hub.connections(), 0);
}

// spec/sync.md §5: a server configured with a peer dials it and pushes stamped entries; after a restart over the same storage it resumes
#[tokio::test]
async fn servers_replicate_through_dialed_links() {
    let net = MemNet::new();
    let (k1, k2) = ([0x51; 32], [0x52; 32]);
    let s2 = start(&net, k2, MemoryBackend::new(), vec![]);
    let l = Label::new(3);
    // a reader of the label waits at the peer, subscribed
    let mut b = Client::connect(&net, k2).await;
    b.run(l.register_cmd(0)).await;
    b.run(Command::Open { label: l.id, key: OpenKey::Sync(l.head_keys().sync.clone()) }).await;
    b.run(Command::Subscribe { labels: vec![l.id] }).await;
    let backend = MemoryBackend::new();
    let s1 = start(&net, k1, backend.clone(), vec![Address { url: "mem://s2".into(), key: k2 }]);
    let mut a = Client::connect(&net, k1).await;
    a.run(l.register_cmd(0)).await;
    a.run(Command::Upload { label: l.id, entries: (0..5).map(|n| l.entry(blob(n))).collect() }).await;
    let mut got = vec![];
    while got.len() < 5 {
        got.extend(added(&events_of(&b.next().await).0));
    }
    assert_eq!(sorted(got), sorted((0..5).map(bid).collect()));
    // restart s1 over the same storage: only the new entry travels
    s1.control.send(Control::Shutdown).await.unwrap();
    s1.task.await.unwrap();
    let s1 = start(&net, k1, backend, vec![Address { url: "mem://s2".into(), key: k2 }]);
    let mut a = Client::connect(&net, k1).await;
    a.run(Command::Upload { label: l.id, entries: vec![l.entry(blob(5))] }).await;
    let (evs, _) = events_of(&b.next().await);
    assert_eq!(added(&evs), vec![bid(5)]);
    for s in [s1, s2] {
        s.control.send(Control::Shutdown).await.unwrap();
        s.task.await.unwrap();
    }
}
