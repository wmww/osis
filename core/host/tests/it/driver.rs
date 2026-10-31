//! The async driver over osis-transport's `InProcess` (perfect network: under tokio nothing needs
//! stepping): scripted clients end to end, subscription pushes, two servers replicating through
//! `dial_as` sessions, shutdown and restart (spec/sync.md §5-§10). Event-driven only: nothing
//! sleeps; a timeout guards against a hang. The slow-reader cap is a unit test of
//! `osis_transport::link` (`InProcess` has no flow control to stall a writer).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::driven::Server;
use common::*;
use osis_proto::*;
use osis_store::MemoryBackend;
use osis_transport::Net;

// spec/sync.md §5, §8, §10: clients through the driver (multi-thread runtime: hub calls in block_in_place): register, open, upload, download, subscription push
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clients_end_to_end() {
    let net = Net::new(1);
    let server = Server::start(net.endpoint("s"), "mem://s", 0x51, MemoryBackend::new(), vec![]).await;
    let clients = net.endpoint("clients");
    let (mut a, mut b) = (server.client(&clients).await, server.client(&clients).await);
    let l = Label::new(3);
    assert_eq!(a.run(l.register_cmd(0)).await, vec![ClientEvent::Registered { label: l.id }]);
    for c in [&mut a, &mut b] {
        let ev = c.run(Command::Open { label: l.id, key: OpenKey::Sync(l.head_keys().sync.clone()) }).await;
        assert!(matches!(&ev[..], [ClientEvent::Opened { .. }]), "{ev:?}");
    }
    b.run(Command::Subscribe { labels: vec![l.id] }).await;
    let ev = a.run(sync(l.id, None, (0..20).map(|n| l.entry(blob(n))).collect(), vec![])).await;
    assert_eq!(statuses(&ev), vec![Code::OK; 20]);
    assert_eq!(b.pushed(20).await, sorted((0..20).map(bid).collect()));
    let (evs, _) = events_of(&b.run(sync(l.id, None, vec![], vec![])).await);
    assert_eq!(added(&evs), sorted((0..20).map(bid).collect()));
    let hub = server.stop().await;
    assert_eq!(hub.connections(), 0);
}

// spec/sync.md §5, §10: a server configured with a peer dials it as its own static key and pushes stamped entries; after a restart over the same storage it resumes
#[tokio::test]
async fn servers_replicate_through_dialed_links() {
    let net = Net::new(1);
    let clients = net.endpoint("clients");
    let s2 = Server::start(net.endpoint("s2"), "mem://s2", 0x52, MemoryBackend::new(), vec![]).await;
    let l = Label::new(3);
    // a reader of the label waits at the peer, subscribed
    let mut b = s2.client(&clients).await;
    b.run(l.register_cmd(0)).await;
    b.run(Command::Open { label: l.id, key: OpenKey::Sync(l.head_keys().sync.clone()) }).await;
    b.run(Command::Subscribe { labels: vec![l.id] }).await;
    let backend = MemoryBackend::new();
    let s1 = Server::start(net.endpoint("s1"), "mem://s1", 0x51, backend.clone(), vec![s2.addr.clone()]).await;
    let mut a = s1.client(&clients).await;
    a.run(l.register_cmd(0)).await;
    a.run(Command::Upload { label: l.id, entries: (0..5).map(|n| l.entry(blob(n))).collect() }).await;
    assert_eq!(b.pushed(5).await, sorted((0..5).map(bid).collect()));
    // restart s1 over the same storage: only the new entry travels
    s1.stop().await;
    let s1 = Server::start(net.endpoint("s1"), "mem://s1", 0x51, backend, vec![s2.addr.clone()]).await;
    let mut a = s1.client(&clients).await;
    a.run(Command::Upload { label: l.id, entries: vec![l.entry(blob(5))] }).await;
    let (evs, _) = events_of(&b.next().await);
    assert_eq!(added(&evs), vec![bid(5)]);
    s1.stop().await;
    s2.stop().await;
}

// spec: none (driver policy, notes/sync.md Hub stall bounds): connections take turns per input,
// so one connection's backlog of inputs does not delay another's request: an opener writes a
// flood of uploads at once (many 64 KiB reads queued behind its reader); a reader's Sync, sent
// while the flood runs, waits a few of its inputs, not the backlog
#[tokio::test]
async fn flood_does_not_delay_others() {
    const BLOB: usize = 16 << 10;
    const FLOOD: u64 = 1500;
    let net = Net::new(1);
    let server = Server::start(net.endpoint("s"), "mem://s", 0x51, MemoryBackend::new(), vec![]).await;
    let l = Label::new(3);
    let mut a = server.client(&net.endpoint("a")).await;
    a.run(l.register_cmd(0)).await;
    let open = Command::Open { label: l.id, key: OpenKey::Sync(l.head_keys().sync.clone()) };
    a.run(open.clone()).await;
    let mut b = server.client(&net.endpoint("b")).await;
    b.run(open).await;
    let count = |ev: &[ClientEvent]| added(&events_of(ev).0).len() as u64;
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
    server.stop().await;
}
