//! The driver's view of the network: a `Link` is one authenticated connection's ordered byte
//! stream as a pair of channels, a `Listener` yields incoming links, a `Dialer` opens links to
//! peer servers. In-process links (`link_pair`, `MemNet`) drive tier-1 tests.
//!
//! This is the one adapter between the driver and osis-transport (notes/architecture.md §2:
//! `Transport`, `Connection`, streams): until that crate's traits land, nothing here names them,
//! and the binary has no network transport (`listen` fails). Mapping a transport `Connection`
//! to a `Link` is two pump tasks over one stream (opened by the dialer, accepted by the listener).

use osis_label::Address;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Frames (or any byte runs) queued per direction before a slow reader is dropped.
pub const LINK_QUEUE: usize = 1024;

/// One connection: the peer's authenticated static key and its byte stream. Dropping `tx` ends
/// the stream; `rx` ends when the peer's side is gone.
pub struct Link {
    pub peer_key: [u8; 32],
    pub tx: mpsc::Sender<Vec<u8>>,
    pub rx: mpsc::Receiver<Vec<u8>>,
}

/// Incoming links and the key this node is reached under (its address key).
pub struct Listener {
    pub local_key: [u8; 32],
    pub incoming: mpsc::Receiver<Link>,
}

pub type DialFuture<'a> = Pin<Box<dyn Future<Output = Result<Link, String>> + Send + 'a>>;

/// Opens links to peer servers; checks the peer's key against the address (spec/sync.md §10).
pub trait Dialer: Send + Sync {
    fn dial<'a>(&'a self, addr: &'a Address) -> DialFuture<'a>;
}

/// Two connected in-process links: `a` sees `b_key` as its peer and the reverse.
pub fn link_pair(a_key: [u8; 32], b_key: [u8; 32]) -> (Link, Link) {
    let (to_b, from_a) = mpsc::channel(LINK_QUEUE);
    let (to_a, from_b) = mpsc::channel(LINK_QUEUE);
    (Link { peer_key: b_key, tx: to_b, rx: from_b }, Link { peer_key: a_key, tx: to_a, rx: from_a })
}

/// In-process listeners by address key; dials from an ephemeral key per link.
#[derive(Clone, Default)]
pub struct MemNet {
    listeners: Arc<Mutex<HashMap<[u8; 32], mpsc::Sender<Link>>>>,
    next: Arc<Mutex<u64>>,
}

impl MemNet {
    pub fn new() -> MemNet {
        MemNet::default()
    }

    /// A listener reached under `key`.
    pub fn listen(&self, key: [u8; 32]) -> Listener {
        let (tx, incoming) = mpsc::channel(64);
        self.lock().insert(key, tx);
        Listener { local_key: key, incoming }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], mpsc::Sender<Link>>> {
        self.listeners.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn ephemeral(&self) -> [u8; 32] {
        let mut n = self.next.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *n += 1;
        let mut k = [0xe0; 32];
        if let Some(d) = k.get_mut(..8) {
            d.copy_from_slice(&n.to_be_bytes());
        }
        k
    }

    /// A client link to the listener under `key`.
    pub async fn connect(&self, key: [u8; 32]) -> Result<Link, String> {
        let listener = self.lock().get(&key).cloned().ok_or("no listener under that key")?;
        let (ours, theirs) = link_pair(self.ephemeral(), key);
        listener.send(theirs).await.map_err(|_| "listener closed".to_string())?;
        Ok(ours)
    }
}

impl Dialer for MemNet {
    fn dial<'a>(&'a self, addr: &'a Address) -> DialFuture<'a> {
        Box::pin(self.connect(addr.key))
    }
}

/// The network listener of the binary: no transport is built in until osis-transport lands.
pub fn listen(url: &str, _secret: &[u8; 32]) -> Result<(Listener, Arc<dyn Dialer>), String> {
    Err(format!("cannot listen on {url}: no network transport in this build (osis-transport pending)"))
}
