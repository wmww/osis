//! The hub in the node driver's loop over osis-transport's `InProcess` (perfect network: under
//! tokio nothing needs stepping): a node keeping labels by its `host^.0` serves scripted clients
//! (osis-proto `ClientSession`) end to end, with node sync above every hub session (proofs, the
//! shared set, the stream), and serves connections in turns (spec/sync.md §5-§10).
//! Event-driven only: a timeout guards against a hang. The slow-reader cap is a unit test of
//! `osis_transport::link` (`InProcess` has no flow control to stall a writer).

use crate::net::{Net, T0};
use crate::peers::reach_ed;
use crate::shared::read_value;
use osis_base::{BlobId, Clock, LabelId, Role};
use osis_crypto::kdf::{beacon, beacon_hit, beacon_reply, pair_key};
use osis_proto::msg::{NODE_IDS, OfferItem, Pull};
use osis_label::Address;
use osis_node::sync::driver::{self, Control, Shared};
use osis_node::sync::{Action, Event as SyncEvent, SyncEngine};
use osis_proto::examples::{Label, bid, blob};
use osis_proto::*;
use osis_schema::core_types as ct;
use osis_transport::{Link, Transport};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const GUARD: Duration = Duration::from_secs(30);

/// An engine holder (its one store, the hub's, lives with the engine across driver runs).
struct Keep {
    engine: Mutex<SyncEngine>,
    /// Where the driver listens (`Control::Listen`).
    url: String,
}

impl Shared for Keep {
    fn with(&self, f: &mut dyn FnMut(&mut SyncEngine) -> Vec<Action>) -> Option<Vec<Action>> {
        Some(f(&mut self.engine.lock().unwrap()))
    }
}

/// A node hosting (`host^.0`: any label admitted) under the tokio driver, listening at its URL.
struct Host {
    addr: Address,
    ctl: mpsc::UnboundedSender<Control>,
    task: tokio::task::JoinHandle<Keep>,
}

impl Host {
    fn node(net: &mut Net, seed: u64, url: &str) -> Keep {
        let n = net.add_node(seed, Default::default());
        Host::keep(net, n, url)
    }

    /// Node `n` of `net` set to host (any label admitted), taken out of `net` for a driver.
    fn keep(net: &mut Net, n: usize, url: &str) -> Keep {
        let me = net.node_tid(n);
        let mut m = osis_node::Mutation::new();
        m.replace(me, &ct::HOST, &ct::Host { admit: ct::Admit::Open, ..Default::default() }).unwrap();
        net.engine(n).commit(m).unwrap();
        Keep { engine: Mutex::new(net.take(n)), url: url.into() }
    }

    /// Runs the driver for `keep` on `transport`, listening at its URL.
    async fn start<T: Transport>(keep: Keep, transport: T, clock: Arc<dyn Clock>) -> Host {
        let (ctl, rx) = mpsc::unbounded_channel();
        let url = keep.url.clone();
        let task = tokio::spawn(driver::run_shared(keep, transport, Vec::new(), clock, rx, Arc::new(|m: &str| eprintln!("{m}"))));
        let (tx, reply) = oneshot::channel();
        assert!(ctl.send(Control::Listen { urls: vec![url], reply: tx }).is_ok());
        let a = tokio::time::timeout(GUARD, reply).await.unwrap().unwrap().unwrap();
        let addr = Address { url: a[0].url.clone(), key: a[0].key };
        Host { addr, ctl, task }
    }

    /// Runs `f` on the engine (then `Event::Local`), returning its result.
    async fn call<R: Send + 'static>(&self, f: impl FnOnce(&mut SyncEngine) -> R + Send + 'static) -> R {
        let (tx, rx) = oneshot::channel();
        let mut f = Some(f);
        let c: driver::Call = Box::new(move |s: &mut SyncEngine| {
            if let Some(f) = f.take() {
                let _ = tx.send(f(s));
            }
            s.handle(SyncEvent::Local)
        });
        assert!(self.ctl.send(Control::Call(c)).is_ok());
        rx.await.unwrap()
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
    /// The connection's shared set started (its NoRecord answered).
    shared: bool,
}

impl Client {
    async fn start(link: Link, key: [u8; 32]) -> Client {
        assert_eq!(link.peer_key, key);
        let mut c = Client { s: ClientSession::new(ClientConfig { peer_static_key: key, challenge: [9; 32] }), link, events: vec![], shared: false };
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

    /// A Hit on `l`'s head sync key with its open signature, as a reader opens a label the node
    /// keeps unread (spec/sync.md §10, Shared set); the shared set started first. Its answer.
    async fn hit(&mut self, l: &Label, id: u32) -> osis_proto::msg::SharedCode {
        if !self.shared {
            let got = self.peer(Message::NoRecord { id: NODE_IDS }).await;
            assert!(matches!(got.last(), Some(Message::Shared { codes, .. }) if codes[0].0 == Code::OK), "{got:?}");
            self.shared = true;
        }
        let (dialer, listener, key) = self.s.binding().unwrap();
        let r = *pair_key(&dialer, &listener).expose();
        let sync = l.head_keys().sync.clone();
        let value = sync.verifying_key().to_bytes();
        let b = beacon(&value, &l.id.0, &r);
        let hit = beacon_hit(&value, &l.id.0, &b, (false, &key, &dialer, &listener));
        let sig = osis_crypto::sign_open(&sync, &l.id, &listener, &key);
        let got = self.peer(Message::Offer { id: NODE_IDS | id, items: vec![OfferItem::Hit(hit, Some(sig))] }).await;
        let Some(Message::Shared { codes, .. }) = got.last() else { panic!("{got:?}") };
        let code = codes[0].clone();
        if code.0 == Code::OK {
            assert_eq!(code.1, Some(beacon_reply(&value, &l.id.0, &b, (true, &key, &dialer, &listener))), "tagged");
        }
        code
    }

    /// Opens `l` here by a Hit (`hit`): its Deletes are taken.
    async fn open(&mut self, l: &Label) {
        let code = self.hit(l, 7).await;
        assert_eq!(code.0, Code::OK, "{code:?}");
    }

    /// Sends a node-kind message; returns the node-kind messages that came, up to its answer.
    async fn peer(&mut self, m: Message) -> Vec<Message> {
        let id = m.id();
        let out = self.s.handle(T0, ClientInput::Command(Command::Peer(Box::new(m))));
        self.out(out);
        let mut got = vec![];
        loop {
            for e in self.next().await {
                if let ClientEvent::Peer(m) = e {
                    let done = m.id() == id && !m.is_request();
                    got.push(*m);
                    if done {
                        return got;
                    }
                }
            }
        }
    }

}

fn sorted(mut v: Vec<BlobId>) -> Vec<BlobId> {
    v.sort();
    v
}

/// Live entries of `l` in the node's store.
async fn held(host: &Host, l: LabelId) -> Vec<BlobId> {
    host.call(move |s| osis_proto::LabelStore::live_ids(&*s.hub_store().lock().unwrap(), &l).unwrap()).await
}

/// Stamped entries of `l` taken into the node's store by its rules, as pulled from a reader.
async fn take(host: &Host, l: &Label, blobs: Vec<Vec<u8>>) {
    let (id, entries) = (l.id, blobs.into_iter().map(|b| l.entry(b)).collect::<Vec<_>>());
    host.call(move |s| {
        let now = s.engine_mut().now().0;
        let hub = s.hub_store();
        let mut hub = hub.lock().unwrap();
        let k = osis_proto::LabelStore::head_keys(&*hub, &id).unwrap().unwrap();
        for e in entries {
            let t = osis_proto::serving::pulled(&mut *hub, now, &id, &k, &e.blob, e.wrap, e.stamp, &mut false).unwrap();
            assert!(matches!(t, osis_proto::serving::Taken::Code(Code::OK)));
        }
    })
    .await;
}

/// A Register of `l`'s head again: answered Ok, a probe that reads nothing much.
fn probe(l: &Label) -> Command {
    Command::Register { label: l.id, step: l.steps.last().unwrap().clone(), claim_set: None }
}

// spec/sync.md §5, §10: clients of a node keeping a label it cannot read (multi-thread runtime:
// hub calls in block_in_place): register, a delete refused unopened, open by a Hit, a delete by
// the delete key
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clients_end_to_end() {
    let tnet = osis_transport::Net::new(0);
    let mut net = Net::new();
    let keep = Host::node(&mut net, 1, "mem://s");
    let host = Host::start(keep, tnet.endpoint("s"), net.clock.clone()).await;
    let clients = tnet.endpoint("clients");
    let (mut a, mut b) = (host.client(&clients).await, host.client(&clients).await);
    let l = Label::new(3);
    assert_eq!(a.run(l.register_cmd(0)).await, vec![ClientEvent::Registered { label: l.id }]);
    take(&host, &l, (0..3).map(blob).collect()).await;
    assert_eq!(held(&host, l.id).await, sorted((0..3).map(bid).collect()));
    let item = osis_label::DeleteItem::sign(&l.head_keys().delete, &l.id, bid(1)).unwrap();
    let ev = b.run(Command::Delete { label: l.id, items: vec![item.clone()] }).await;
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::NOT_OPENED, .. }]), "{ev:?}");
    for c in [&mut a, &mut b] {
        c.open(&l).await;
    }
    let ev = a.run(Command::Delete { label: l.id, items: vec![item] }).await;
    assert!(matches!(&ev[..], [ClientEvent::DeleteStatus { codes, .. }] if codes == &[Code::OK]), "{ev:?}");
    assert_eq!(held(&host, l.id).await, sorted([0, 2].into_iter().map(bid).collect()));
    host.stop().await;
}


// spec/data-model.md §9, spec/sync.md §5: hosting stopping closes the connections that opened
// something of the host store; the others stay, served an empty store on the same listener and
// key
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopping_closes_what_opened_the_host_store() {
    let tnet = osis_transport::Net::new(0);
    let mut net = Net::new();
    let keep = Host::node(&mut net, 1, "mem://s");
    let host = Host::start(keep, tnet.endpoint("s"), net.clock.clone()).await;
    let clients = tnet.endpoint("clients");
    let mut a = host.client(&clients).await;
    let mut idle = host.client(&clients).await;
    let l = Label::new(3);
    a.run(l.register_cmd(0)).await;
    a.open(&l).await;
    host.call(|s: &mut SyncEngine| {
        let me = s.engine_mut().tid();
        let mut m = osis_node::Mutation::new();
        m.remove_aspect(me, &ct::HOST).unwrap();
        s.engine_mut().commit(m).unwrap();
    })
    .await;
    // the session with an open is closed
    assert!(tokio::time::timeout(GUARD, async { while a.link.rx.recv().await.is_some() {} }).await.is_ok());
    // the other stays, and finds nothing: not hosting, no label
    assert_eq!(idle.hit(&l, 8).await.0, Code::NOT_ADMITTED);
    host.stop().await;
}

// spec: none (driver policy, notes/flow-control.md Hub stall bounds): connections take turns per input,
// so one connection's backlog of inputs does not delay another's request: an opener writes a
// flood of deletes at once (many 64 KiB reads queued behind its reader, each 16 KiB frame removing
// one held entry and checking more signatures); a reader's Register, sent while the flood runs,
// waits a few of its inputs, not the backlog
#[tokio::test]
async fn flood_does_not_delay_others() {
    const FLOOD: u64 = 1500;
    let tnet = osis_transport::Net::new(0);
    let mut net = Net::new();
    let keep = Host::node(&mut net, 1, "mem://s");
    let host = Host::start(keep, tnet.endpoint("s"), net.clock.clone()).await;
    let l = Label::new(3);
    let mut a = host.client(&tnet.endpoint("a")).await;
    a.run(l.register_cmd(0)).await;
    a.open(&l).await;
    take(&host, &l, (0..FLOOD).map(|n| blob(1000 + n)).collect()).await;
    let mut b = host.client(&tnet.endpoint("b")).await;
    let probe = || probe(&l);
    let done = |held: usize| FLOOD - held as u64;
    // the flood: one delete frame per held entry, padded with items to 16 KiB, written at once,
    // its replies never read
    let junk = osis_label::DeleteItem::sign(&l.head_keys().delete, &l.id, BlobId([0xee; 32])).unwrap();
    let frame = |n: u64, pad: usize| {
        let mut items = vec![osis_label::DeleteItem::sign(&l.head_keys().delete, &l.id, bid(1000 + n)).unwrap()];
        items.extend(std::iter::repeat_n(junk.clone(), pad));
        encode_frame(&Message::Delete { id: (1 << 30) + n as u32, label: l.id, items }.encode())
    };
    let pad = (0..1024).find(|p| frame(0, *p).len() >= 16 << 10).unwrap();
    let flood: Vec<u8> = (0..FLOOD).flat_map(|n| frame(n, pad)).collect();
    assert!(a.link.tx.send(flood, usize::MAX));
    b.run(probe()).await;
    let c0 = done(held(&host, l.id).await.len());
    b.run(probe()).await;
    let c1 = done(held(&host, l.id).await.len());
    assert!(c1 < FLOOD, "the flood ended before the probes: {c1}");
    // a read is at most 64 KiB, 4 frames; the flood gets one read per scheduler round while the
    // probe travels there and back (48 frames; 760 when the reader queued reads ahead)
    assert!(c1 - c0 <= 100, "the second probe waited {} flood frames (first: {c0})", c1 - c0);
    host.stop().await;
}


// issues/net-one-peer.md 3c, spec/sync.md §5, §10: node sync above the hub. One connection to the
// key of a node carries a label the node keeps and cannot read (Register, a Hit, Delete: the hub's
// store) and a group the node reads (proofs, NoRecord, a Hit, the stream: node sync), each
// answered by its layer
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_connection_serves_hosted_and_read_labels() {
    let tnet = osis_transport::Net::new(0);
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let n = net.node(2, &[]);
    reach_ed(&mut net, n);
    let g = net.group_at(n, &[(a, Role::Read)], vec![]);
    let t = net.item(n, g, g, "read here");
    net.run();
    let m = net.engine(n).labels_of(&g)[0].id;
    let held: Vec<BlobId> = sorted(net.sync(n).entries(&m).into_iter().map(|(b, _)| b).collect());
    assert!(!held.is_empty());
    let provers = net.sync(a).provers(false).unwrap();
    let value = read_value(&mut net, a, m);
    let keep = Host::keep(&mut net, n, "mem://s");
    let host = Host::start(keep, tnet.endpoint("s"), net.clock.clone()).await;
    let mut c = host.client(&tnet.endpoint("clients")).await;
    // L, which the node cannot read: the hub's store
    let l = Label::new(3);
    assert_eq!(c.run(l.register_cmd(0)).await, vec![ClientEvent::Registered { label: l.id }]);
    // M, which it reads: node sync proves to a dialer it knows and runs the shared set
    let ev = c.run(Command::Prove(provers)).await;
    assert!(matches!(&ev[..], [ClientEvent::Proved { proofs }] if !proofs.is_empty()), "{ev:?}");
    let got = c.peer(Message::NoRecord { id: 1 << 31 }).await;
    assert!(matches!(got.last(), Some(Message::Shared { codes, .. }) if codes[0].0 == Code::OK), "{got:?}");
    c.shared = true;
    c.open(&l).await;
    let (dialer, listener, key) = c.s.binding().unwrap();
    let r = *pair_key(&dialer, &listener).expose();
    let hit = beacon_hit(&value, &m.0, &beacon(&value, &m.0, &r), (false, &key, &dialer, &listener));
    let got = c.peer(Message::Offer { id: NODE_IDS | 77, items: vec![OfferItem::Hit(hit, None)] }).await;
    assert!(matches!(got.last(), Some(Message::Shared { codes, .. }) if codes[0].0 == Code::OK), "{got:?}");
    let pull = Pull { id: NODE_IDS | 1 << 30 | 7, cursor: None, joins: vec![(m, None)], inline_limit: 1 << 20, max_reply: 1 << 20, follow: true, ephemeral: true };
    let got = c.peer(Message::Pull(Box::new(pull))).await;
    let Some(Message::PullReply(reply)) = got.last() else { panic!("{got:?}") };
    let pulled: Vec<BlobId> = sorted(reply.events.iter().filter_map(|(x, e)| if let osis_proto::Event::Added { blob_id, .. } = e { (*x == m).then_some(*blob_id) } else { None }).collect());
    assert_eq!(pulled, held);
    // a write after it comes as a push, within the room the hub's session granted
    host.call(move |s| {
        let mut w = osis_node::Mutation::new();
        w.set(t, &crate::net::REG, &crate::net::s("again")).unwrap();
        s.engine_mut().commit(w).unwrap();
    })
    .await;
    let pushed = tokio::time::timeout(GUARD, async {
        loop {
            for e in c.next().await {
                if let ClientEvent::Peer(x) = e
                    && let Message::Stream(st) = *x
                    && st.cursor.is_some()
                {
                    return st.events;
                }
            }
        }
    })
    .await
    .unwrap();
    assert!(pushed.iter().any(|(x, e)| *x == m && matches!(e, osis_proto::Event::Added { blob_id, .. } if !held.contains(blob_id))), "{pushed:?}");
    // and L still, on the same connection: open there (its Deletes taken)
    let item = osis_label::DeleteItem::sign(&l.head_keys().delete, &l.id, bid(5)).unwrap();
    let ev = c.run(Command::Delete { label: l.id, items: vec![item] }).await;
    assert!(matches!(&ev[..], [ClientEvent::DeleteStatus { .. }]), "{ev:?}");
    host.stop().await;
}

// spec/sync.md §10 (Connection proofs, Pair key): a dialer at the node's key proving an actor the
// node does not know gets no proof back, no record and no shared set
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stranger_gets_no_proof_spec_sync_10() {
    let tnet = osis_transport::Net::new(0);
    let mut net = Net::new();
    let z = net.node(1, &[]);
    let n = net.node(2, &[]);
    net.group_at(n, &[], vec![]);
    net.run();
    let provers = net.sync(z).provers(false).unwrap();
    let keep = Host::keep(&mut net, n, "mem://s");
    let host = Host::start(keep, tnet.endpoint("s"), net.clock.clone()).await;
    let mut c = host.client(&tnet.endpoint("clients")).await;
    let ev = c.run(Command::Prove(provers)).await;
    assert!(matches!(&ev[..], [ClientEvent::Proved { proofs }] if proofs.is_empty()), "{ev:?}");
    let ev = c.run(Command::Resume { nonce: [5; 32], tags: vec![[6; 32]] }).await;
    assert!(matches!(&ev[..], [ClientEvent::Refused { kind: Request::Resume, code: Code::REFUSED, .. }]), "{ev:?}");
    // its NoRecord starts the set: a filter of nothing the node reads (it keeps nothing unread)
    let got = c.peer(Message::NoRecord { id: 1 << 31 }).await;
    assert!(got.iter().any(|m| matches!(m, Message::Beacons { gcs, .. } if gcs.is_empty())), "{got:?}");
    // node sync keeps the session while the connection lasts and forgets it at its end
    assert_eq!(host.call(|s| s.served_opened().len()).await, 1);
    drop(c);
    tokio::time::timeout(GUARD, async {
        while host.call(|s| s.served_opened().len()).await != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    host.stop().await;
}
