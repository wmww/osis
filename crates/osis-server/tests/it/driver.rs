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
