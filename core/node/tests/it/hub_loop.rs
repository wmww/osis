//! The hub in the node driver's loop over osis-transport's `InProcess` (perfect network: under
//! tokio nothing needs stepping): a node hosting by its `host^.0` serves scripted host clients
//! (osis-proto `ClientSession`) end to end, replicates to a peer host through `dial_as`
//! sessions across a restart, and serves connections in turns (spec/sync.md §5-§10).
//! Event-driven only: a timeout guards against a hang. The slow-reader cap is a unit test of
//! `osis_transport::link` (`InProcess` has no flow control to stall a writer).

use crate::net::{Net, T0};
use osis_base::{BlobId, Clock, LabelId};
use osis_label::Address;
use osis_node::sync::driver::{self, Control, Shared};
use osis_node::sync::{Action, Event as SyncEvent, HostStatus, SyncEngine};
use osis_proto::examples::{Label, bid, blob};
use osis_proto::*;
use osis_schema::core_types as ct;
use osis_store::{MemoryBackend, MemoryRoot, StoreConfig};
use osis_transport::{Link, Transport};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const GUARD: Duration = Duration::from_secs(30);

/// An engine holder whose host store lives in one memory backend across driver runs.
struct Keep {
    engine: Mutex<SyncEngine>,
    backend: MemoryBackend,
    root: MemoryRoot,
}

impl Shared for Keep {
    fn with(&self, f: &mut dyn FnMut(&mut SyncEngine) -> Vec<Action>) -> Option<Vec<Action>> {
        Some(f(&mut self.engine.lock().unwrap()))
    }
    fn host_store(&self) -> Result<osis_store::Store, String> {
        osis_store::Store::open_or_create(Box::new(self.backend.clone()), Box::new(self.root.clone()), StoreConfig::default(), &mut osis_crypto::OsRng).map_err(|e| e.to_string())
    }
}

/// A node hosting (`host^.0`: listening at its URL, any label admitted, replicating to `peers`)
/// under the tokio driver.
struct Host {
    addr: Address,
    ctl: mpsc::UnboundedSender<Control>,
    task: tokio::task::JoinHandle<Keep>,
}

impl Host {
    fn node(net: &mut Net, seed: u64, url: &str, peers: Vec<Address>) -> Keep {
        let n = net.add_node(seed, Default::default());
        let me = net.node_tid(n);
        let mut m = osis_node::Mutation::new();
        let replicate = peers.into_iter().map(|a| ct::Address { url: a.url, key: a.key }).collect();
        m.replace(me, &ct::HOST, &ct::Host { listen: vec![url.into()], admit: ct::Admit::Open, replicate, ..Default::default() }).unwrap();
        net.engine(n).commit(m).unwrap();
        Keep { engine: Mutex::new(net.take(n)), backend: MemoryBackend::new(), root: MemoryRoot::new() }
    }

    /// Runs the driver for `keep` on `transport` until it hosts.
    async fn start<T: Transport>(keep: Keep, transport: T, clock: Arc<dyn Clock>) -> Host {
        let (ctl, rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(driver::run_shared(keep, transport, Vec::new(), clock, rx, Arc::new(|m: &str| eprintln!("{m}"))));
        let addr = tokio::time::timeout(GUARD, async {
            loop {
                let (tx, rx) = oneshot::channel();
                let c: driver::Call = Box::new(move |s: &mut SyncEngine| {
                    let _ = tx.send(s.host_status().clone());
                    s.handle(SyncEvent::Local)
                });
                assert!(ctl.send(Control::Call(c)).is_ok());
                if let HostStatus::Listening(a) = rx.await.unwrap() {
                    return a[0].clone();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        Host { addr, ctl, task }
    }

    /// A host client dialed on `transport` with an ephemeral key.
    async fn client<T: Transport>(&self, transport: &T) -> Client {
        let target = osis_transport::Address { url: self.addr.url.clone(), key: self.addr.key };
        let link = osis_transport::link::dial(transport, &target, None, GUARD).await.unwrap();
        Client::start(link, self.addr.key).await
    }

    /// Shuts the driver down; returns its holder.
    async fn stop(self) -> Keep {
        assert!(self.ctl.send(Control::Shutdown).is_ok());
        self.task.await.unwrap()
    }
}

/// A scripted `ClientSession` over a `Link`.
struct Client {
    s: ClientSession,
    link: Link,
    events: Vec<ClientEvent>,
}

impl Client {
    async fn start(link: Link, key: [u8; 32]) -> Client {
        assert_eq!(link.peer_key, key);
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
                ClientOutput::Send(b) => assert!(self.link.tx.send(b, usize::MAX)),
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

    async fn next(&mut self) -> Vec<ClientEvent> {
        while self.events.is_empty() {
            self.recv().await;
        }
        std::mem::take(&mut self.events)
    }

    /// Waits until pushes added `n` entries; returns their blob IDs sorted.
    async fn pushed(&mut self, n: usize) -> Vec<BlobId> {
        let mut got = vec![];
        while got.len() < n {
            got.extend(added(&self.next().await));
        }
        sorted(got)
    }
}

fn added(ev: &[ClientEvent]) -> Vec<BlobId> {
    ev.iter().flat_map(|e| if let ClientEvent::Events { events, .. } = e { events.clone() } else { vec![] }).filter_map(|e| if let osis_proto::Event::Added { blob_id, .. } = e { Some(blob_id) } else { None }).collect()
}

fn statuses(ev: &[ClientEvent]) -> Vec<Code> {
    ev.iter().flat_map(|e| if let ClientEvent::EntryStatus { codes, .. } = e { codes.clone() } else { vec![] }).collect()
}

fn sync(label: LabelId, entries: Vec<Entry>) -> Command {
    Command::Sync { label, cursor: None, inline_limit: 1 << 20, entries, gained: vec![] }
}

fn sorted(mut v: Vec<BlobId>) -> Vec<BlobId> {
    v.sort();
    v
}

fn open(l: &Label) -> Command {
    Command::Open { label: l.id, key: OpenKey::Sync { step: None, key: l.head_keys().sync.clone() } }
}

// spec/sync.md §5, §8, §10: host clients of a hosting node (multi-thread runtime: hub calls in block_in_place): register, open, upload, download, subscription push
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clients_end_to_end() {
    let tnet = osis_transport::Net::new(1);
    let mut net = Net::new();
    let keep = Host::node(&mut net, 1, "mem://s", vec![]);
    let host = Host::start(keep, tnet.endpoint("s"), net.clock.clone()).await;
    let clients = tnet.endpoint("clients");
    let (mut a, mut b) = (host.client(&clients).await, host.client(&clients).await);
    let l = Label::new(3);
    assert_eq!(a.run(l.register_cmd(0)).await, vec![ClientEvent::Registered { label: l.id }]);
    for c in [&mut a, &mut b] {
        let ev = c.run(open(&l)).await;
        assert!(matches!(&ev[..], [ClientEvent::Opened { .. }]), "{ev:?}");
    }
    b.run(Command::Subscribe { labels: vec![l.id] }).await;
    let ev = a.run(sync(l.id, (0..20).map(|n| l.entry(blob(n))).collect())).await;
    assert_eq!(statuses(&ev), vec![Code::OK; 20]);
    assert_eq!(b.pushed(20).await, sorted((0..20).map(bid).collect()));
    assert_eq!(added(&b.run(sync(l.id, vec![])).await), sorted((0..20).map(bid).collect()));
    host.stop().await;
}

// spec/sync.md §5, §10: a host configured with a peer dials it as its own static key and pushes stamped entries; after a restart over the same storage it resumes
#[tokio::test]
async fn hosts_replicate_through_dialed_links() {
    let tnet = osis_transport::Net::new(1);
    let mut net = Net::new();
    let clients = tnet.endpoint("clients");
    let k2 = Host::node(&mut net, 2, "mem://s2", vec![]);
    let s2 = Host::start(k2, tnet.endpoint("s2"), net.clock.clone()).await;
    let l = Label::new(3);
    // a reader of the label waits at the peer, subscribed
    let mut b = s2.client(&clients).await;
    b.run(l.register_cmd(0)).await;
    b.run(open(&l)).await;
    b.run(Command::Subscribe { labels: vec![l.id] }).await;
    let k1 = Host::node(&mut net, 1, "mem://s1", vec![s2.addr.clone()]);
    let s1 = Host::start(k1, tnet.endpoint("s1"), net.clock.clone()).await;
    let mut a = s1.client(&clients).await;
    a.run(l.register_cmd(0)).await;
    a.run(Command::Upload { label: l.id, entries: (0..5).map(|n| l.entry(blob(n))).collect() }).await;
    assert_eq!(b.pushed(5).await, sorted((0..5).map(bid).collect()));
    // restart s1 over the same storage: only the new entry travels
    let k1 = s1.stop().await;
    let s1 = Host::start(k1, tnet.endpoint("s1"), net.clock.clone()).await;
    let mut a = s1.client(&clients).await;
    a.run(Command::Upload { label: l.id, entries: vec![l.entry(blob(5))] }).await;
    assert_eq!(added(&b.next().await), vec![bid(5)]);
    s1.stop().await;
    s2.stop().await;
}

// spec: none (driver policy, notes/flow-control.md Hub stall bounds): connections take turns per input,
// so one connection's backlog of inputs does not delay another's request: an opener writes a
// flood of uploads at once (many 64 KiB reads queued behind its reader); a reader's Sync, sent
// while the flood runs, waits a few of its inputs, not the backlog
#[tokio::test]
async fn flood_does_not_delay_others() {
    const BLOB: usize = 16 << 10;
    const FLOOD: u64 = 1500;
    let tnet = osis_transport::Net::new(1);
    let mut net = Net::new();
    let keep = Host::node(&mut net, 1, "mem://s", vec![]);
    let host = Host::start(keep, tnet.endpoint("s"), net.clock.clone()).await;
    let l = Label::new(3);
    let mut a = host.client(&tnet.endpoint("a")).await;
    a.run(l.register_cmd(0)).await;
    a.run(open(&l)).await;
    let mut b = host.client(&tnet.endpoint("b")).await;
    b.run(open(&l)).await;
    let count = |ev: &[ClientEvent]| added(ev).len() as u64;
    let probe = || Command::Sync { label: l.id, cursor: None, inline_limit: 0, entries: vec![], gained: vec![] };
    // the flood: one upload frame per blob, written at once, its replies never read
    let mut flood = Vec::new();
    for n in 0..FLOOD {
        let entry = l.entry(osis_proto::examples::blob_sized(1000 + n, 0, vec![], BLOB));
        flood.extend(encode_frame(&Message::Upload { id: (1 << 30) + n as u32, label: l.id, entries: vec![entry] }.encode()));
    }
    assert!(a.link.tx.send(flood, usize::MAX));
    let c0 = count(&b.run(probe()).await);
    let c1 = count(&b.run(probe()).await);
    assert!(c1 < FLOOD, "the flood ended before the probes: {c1}");
    // a read is at most 64 KiB, 4 blobs; the flood gets one read per scheduler round while the
    // probe travels there and back (48 blobs; 760 when the reader queued reads ahead)
    assert!(c1 - c0 <= 100, "the second probe waited {} flood entries (first: {c0})", c1 - c0);
    host.stop().await;
}

// spec/sync.md §5, §8, §10: the same over QUIC on localhost (by hand: touches the network): two hosting nodes, a client at one, the other dialed with the first's static key pushes to its subscriber.
// Run: `cargo test -p osis-node --test it -- --ignored hub_loop::`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn quic_clients_and_replication() {
    use osis_transport::Quic;
    let mut net = Net::new();
    let k2 = Host::node(&mut net, 2, "quic://127.0.0.1:0", vec![]);
    let s2 = Host::start(k2, Quic::new(), net.clock.clone()).await;
    let k1 = Host::node(&mut net, 1, "quic://127.0.0.1:0", vec![s2.addr.clone()]);
    let s1 = Host::start(k1, Quic::new(), net.clock.clone()).await;
    let l = Label::new(3);
    let mut b = s2.client(&Quic::new()).await;
    b.run(l.register_cmd(0)).await;
    b.run(open(&l)).await;
    b.run(Command::Subscribe { labels: vec![l.id] }).await;
    let mut a = s1.client(&Quic::new()).await;
    assert_eq!(a.run(l.register_cmd(0)).await, vec![ClientEvent::Registered { label: l.id }]);
    let ev = a.run(open(&l)).await;
    assert!(matches!(&ev[..], [ClientEvent::Opened { .. }]), "{ev:?}");
    let ev = a.run(sync(l.id, (0..5).map(|n| l.entry(blob(n))).collect())).await;
    assert_eq!(statuses(&ev), vec![Code::OK; 5]);
    assert_eq!(b.pushed(5).await, sorted((0..5).map(bid).collect()));
    assert_eq!(added(&a.run(sync(l.id, vec![])).await), sorted((0..5).map(bid).collect()));
    s1.stop().await;
    s2.stop().await;
}
