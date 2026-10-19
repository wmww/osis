//! The driver over QUIC on localhost (tier 2: touches the network), and the binary itself.
//! Run: `cargo test -p osis-server --features bin -- --ignored`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
#![cfg(feature = "quic")]

mod common;

use common::driven::{Client, GUARD, Server};
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

// spec/sync.md §10: the binary listens on QUIC, prints its address (URL and static key), serves a client, creates its key file 0600
#[cfg(feature = "bin")]
#[test]
#[ignore]
fn binary_serves_quic() {
    use std::io::BufRead;
    let dir = std::env::temp_dir().join(format!("osis-server-quic-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("server.conf");
    std::fs::write(&cfg, format!("listen = quic://127.0.0.1:0\nkey = {}\ndata = {}\n", dir.join("key").display(), dir.join("data").display())).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_osis-server")).arg(&cfg).stderr(std::process::Stdio::piped()).spawn().unwrap();
    let mut lines = std::io::BufReader::new(child.stderr.take().unwrap()).lines();
    let addr = loop {
        let line = lines.next().expect("binary exited").unwrap();
        if let Some(a) = line.strip_prefix("osis-server: address ") {
            break osis_label::address_from_text(a).unwrap();
        }
    };
    #[cfg(unix)]
    assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(dir.join("key")).unwrap().permissions()) & 0o777, 0o600);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let target = osis_transport::Address { url: addr.url.clone(), key: addr.key };
        let link = osis_transport::link::dial(&Quic::new(), &target, None, GUARD).await.unwrap();
        let mut a = Client::start(link, addr.key).await;
        let l = Label::new(3);
        assert_eq!(a.run(l.register_cmd(0)).await, vec![ClientEvent::Registered { label: l.id }]);
        let ev = a.run(Command::Upload { label: l.id, entries: vec![l.entry(blob(0))] }).await;
        assert_eq!(statuses(&ev), vec![Code::OK]);
    });
    child.kill().unwrap();
    child.wait().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
