//! The driver over QUIC on localhost (tier 2: touches the network), and `osis serve`'s key file.
//! Run: `cargo test --workspace --test it quic:: -- --ignored`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::driven::Server;
use common::*;
use osis_proto::*;
use osis_store::MemoryBackend;
use osis_transport::Quic;

// spec/sync.md §5, §8, §10: two drivers on QUIC; a client registers, opens, uploads and syncs at one; the other, dialed with the first's static key, pushes to its subscriber
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn quic_clients_and_replication() {
    let s2 = Server::start(Quic::new(), "quic://127.0.0.1:0", 0x52, MemoryBackend::new(), vec![]).await;
    let s1 = Server::start(Quic::new(), "quic://127.0.0.1:0", 0x51, MemoryBackend::new(), vec![s2.addr.clone()]).await;
    let l = Label::new(3);
    let mut b = s2.client(&Quic::new()).await;
    b.run(l.register_cmd(0)).await;
    b.run(Command::Open { label: l.id, key: OpenKey::Sync(l.head_keys().sync.clone()) }).await;
    b.run(Command::Subscribe { labels: vec![l.id] }).await;
    let mut a = s1.client(&Quic::new()).await;
    assert_eq!(a.run(l.register_cmd(0)).await, vec![ClientEvent::Registered { label: l.id }]);
    let ev = a.run(Command::Open { label: l.id, key: OpenKey::Sync(l.head_keys().sync.clone()) }).await;
    assert!(matches!(&ev[..], [ClientEvent::Opened { .. }]), "{ev:?}");
    let ev = a.run(sync(l.id, None, (0..5).map(|n| l.entry(blob(n))).collect(), vec![])).await;
    assert_eq!(statuses(&ev), vec![Code::OK; 5]);
    assert_eq!(b.pushed(5).await, sorted((0..5).map(bid).collect()));
    let (evs, _) = events_of(&a.run(sync(l.id, None, vec![], vec![])).await);
    assert_eq!(added(&evs), sorted((0..5).map(bid).collect()));
    s1.stop().await;
    s2.stop().await;
}

// spec/sync.md §10: the static key file `osis serve` uses is created owner-only (0600) and read
// back unchanged (`osis serve` itself: osis-cli tests/it/localhost.rs)
#[cfg(feature = "driver")]
#[test]
#[ignore]
fn static_key_file_created_owner_only() {
    let dir = std::env::temp_dir().join(format!("osis-host-key-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("key");
    let log: osis_host::Log = std::sync::Arc::new(|m: &str| eprintln!("{m}"));
    let k = osis_host::serve::static_secret(&path, &log).unwrap();
    #[cfg(unix)]
    assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&path).unwrap().permissions()) & 0o777, 0o600);
    assert_eq!(osis_host::serve::static_secret(&path, &log).unwrap(), k);
    let _ = std::fs::remove_dir_all(&dir);
}
