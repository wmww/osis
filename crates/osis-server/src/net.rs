//! The driver's view of the network: a `Link` is one authenticated connection's ordered byte
//! stream as a pair of channel ends counting the bytes queued between them, a `Listener` yields
//! incoming links, a `Dialer` opens links to peer servers. In-process links (`link_pair`,
//! `MemNet`) drive tier-1 tests.
//!
//! This is the one adapter between the driver and osis-transport (notes/architecture.md §2:
//! `Transport`, `Connection`, streams): until that crate's traits land, nothing here names them,
//! and the binary has no network transport (`listen` fails). Mapping a transport `Connection`
//! to a `Link` is two pump tasks over one stream (opened by the dialer, accepted by the listener).

use osis_label::Address;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// The sending end of a link. Dropping every clone ends the stream.
#[derive(Clone, Debug)]
pub struct LinkTx {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    queued: Arc<AtomicUsize>,
}

impl LinkTx {
    /// Queues `bytes` unless more than `cap` bytes would then wait unread (one run always fits
    /// an empty queue) or the other end is gone; false when refused.
    #[must_use]
    pub fn send(&self, bytes: Vec<u8>, cap: usize) -> bool {
        let n = bytes.len();
        let q = self.queued.load(Ordering::Acquire);
        if q > 0 && q.saturating_add(n) > cap {
            return false;
        }
        self.queued.fetch_add(n, Ordering::AcqRel);
        self.tx.send(bytes).is_ok()
    }

    /// Bytes sent and not yet received.
    pub fn queued(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }
}

/// The receiving end of a link: `None` once the other end is gone and the queue drained.
#[derive(Debug)]
pub struct LinkRx {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    queued: Arc<AtomicUsize>,
}

impl LinkRx {
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        let b = self.rx.recv().await?;
        self.queued.fetch_sub(b.len(), Ordering::AcqRel);
        Some(b)
    }

    /// A run already queued, if any.
    pub fn try_recv(&mut self) -> Option<Vec<u8>> {
        let b = self.rx.try_recv().ok()?;
        self.queued.fetch_sub(b.len(), Ordering::AcqRel);
        Some(b)
    }
}

fn half() -> (LinkTx, LinkRx) {
    let (tx, rx) = mpsc::unbounded_channel();
    let queued = Arc::new(AtomicUsize::new(0));
    (LinkTx { tx, queued: queued.clone() }, LinkRx { rx, queued })
}

/// One connection: the peer's authenticated static key and its byte stream.
pub struct Link {
    pub peer_key: [u8; 32],
    pub tx: LinkTx,
    pub rx: LinkRx,
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
    let (to_b, from_a) = half();
    let (to_a, from_b) = half();
    (Link { peer_key: b_key, tx: to_b, rx: from_b }, Link { peer_key: a_key, tx: to_a, rx: from_a })
}

/// In-process listeners by address key.
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

    /// A link to the listener under `key`, authenticated as `own` (an ephemeral key if none).
    pub async fn connect_as(&self, key: [u8; 32], own: Option<[u8; 32]>) -> Result<Link, String> {
        let listener = self.lock().get(&key).cloned().ok_or("no listener under that key")?;
        let (ours, theirs) = link_pair(own.unwrap_or_else(|| self.ephemeral()), key);
        listener.send(theirs).await.map_err(|_| "listener closed".to_string())?;
        Ok(ours)
    }

    /// A client link to the listener under `key` (ephemeral key).
    pub async fn connect(&self, key: [u8; 32]) -> Result<Link, String> {
        self.connect_as(key, None).await
    }

    /// A dialer for a server reached under `own`, authenticating with that key.
    pub fn dialer(&self, own: [u8; 32]) -> MemDialer {
        MemDialer { net: self.clone(), own: Some(own) }
    }
}

/// Dials in-process listeners (with a fixed key, or an ephemeral one per link).
#[derive(Clone)]
pub struct MemDialer {
    net: MemNet,
    own: Option<[u8; 32]>,
}

impl Dialer for MemDialer {
    fn dial<'a>(&'a self, addr: &'a Address) -> DialFuture<'a> {
        Box::pin(self.net.connect_as(addr.key, self.own))
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
