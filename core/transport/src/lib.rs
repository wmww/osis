//! osis-transport: `Transport`: confidential authenticated byte streams; `InProcess`, QUIC (`quic`), iroh (`iroh`), `Multi` (by scheme); `link` sessions for tokio drivers (`link`) (spec/sync.md §10).
//! Layer 1 (notes/architecture.md). Notes: notes/networking.md (Implementation); P2P: notes/networking.md, issues/p2p-followups.md.
//!
//! Traits use `impl Future + Send` returns and no runtime types: `InProcess` and `Sched` run
//! without tokio; the QUIC transport needs a tokio runtime. Framing is proto's job.
#![forbid(unsafe_code)]

mod error;
pub mod link;
pub mod mem;
pub mod quic;
pub mod sched;
mod util;
pub mod manage;
pub mod multi;

pub use error::Error;
pub use mem::{Faults, InProcess, MemConn, MemListener, MemRecv, MemSend, Net};
pub use sched::{Sched, Spawner};
pub use manage::{close_gracefully, connect, Backoff};
pub use multi::{Multi, MultiConn, MultiListener, MultiRecv, MultiSend};
pub use link::{Link, LinkRx, LinkTx};
pub use quic::{Quic, QuicConn, QuicListener, QuicRecv, QuicSend};
// codec always; the socket with feature `lan`
pub mod lan;
#[cfg(feature = "iroh")]
pub mod iroh;
#[cfg(feature = "iroh")]
pub use crate::iroh::{Iroh, IrohConn, IrohListener, IrohRecv, IrohSend};
#[cfg(feature = "relay")]
pub use crate::iroh::TestRelay;

use std::future::Future;

/// A transport's 32-byte static public key (spec/wire.md §11.1).
pub type PublicKey = [u8; 32];

/// Where a connection comes from, as far as the transport can tell: an IPv4 address (as
/// IPv4-mapped IPv6), the /64 of an IPv6 address (the usual allocation to one site; minor: a
/// holder of a larger prefix counts as many sources), an in-process endpoint's name hashed. A
/// server shares its connection slots by it (`evict_for`). Connections whose source is unknown
/// count as one source.
pub type Source = [u8; 16];

/// The source of a connection from `ip`.
pub fn ip_source(ip: std::net::IpAddr) -> Source {
    match ip {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_ipv6_mapped().octets(),
            None => {
                let mut s = [0u8; 16];
                if let (Some(d), Some(o)) = (s.get_mut(..8), v6.octets().get(..8)) {
                    d.copy_from_slice(o);
                }
                s
            }
        },
    }
}

/// Fair shares of a full set of connection slots, without a per-source number to pick: when a
/// connection from `new` arrives and every slot is taken (`held`: the slots per source), the
/// source holding the most gives one up if it holds at least two more than `new` (ties: the
/// greatest source); otherwise the newcomer is refused. Repeated, every source that keeps
/// connecting ends up with an equal share (max-min fairness), however many connections one
/// source opens.
pub fn evict_for<K: Ord + Copy>(held: &std::collections::BTreeMap<K, usize>, new: &K) -> Option<K> {
    let (top, n) = held.iter().max_by_key(|(k, n)| (**n, **k))?;
    let mine = held.get(new).copied().unwrap_or(0);
    (*n >= mine.saturating_add(2)).then_some(*top)
}

/// Where to dial: a transport URL and the key the peer must authenticate with (spec/sync.md §10).
/// Mirrors the schema's `address` type; the scheme picks the implementation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    pub url: String,
    pub key: PublicKey,
}

impl Address {
    /// The URL scheme (before `://`), if any.
    pub fn scheme(&self) -> Option<&str> {
        self.url.split_once("://").map(|(s, _)| s)
    }
}

/// Scheme of P2P addresses (spec/sync.md §10): a node dialed by its dialable key, through the
/// relays the URL lists (`peer://` then relay URLs separated by single spaces; none: direct or
/// LAN only). The transport finds the peer; the key is `Address::key`.
pub const PEER_SCHEME: &str = "peer";

/// The address URL of a peer reachable through `relays`.
pub fn peer_url(relays: &[String]) -> String {
    format!("{PEER_SCHEME}://{}", relays.join(" "))
}

/// The relays of a `peer://` URL; none for another scheme.
pub fn peer_relays(url: &str) -> Option<Vec<String>> {
    let rest = url.strip_prefix(PEER_SCHEME)?.strip_prefix("://")?;
    Some(rest.split(' ').filter(|r| !r.is_empty()).map(str::to_owned).collect())
}

/// URLs longer than `MAX_URL_BYTES` are refused (spec/wire.md §13).
pub(crate) fn check_url(url: &str) -> Result<(), Error> {
    if url.len() > osis_base::format::MAX_URL_BYTES { Err(Error::BadUrl(format!("{} bytes", url.len()))) } else { Ok(()) }
}

/// A listener's static secret: 32 seed bytes from which each transport derives its key pair.
/// Wiped on drop; `Debug` is redacted.
#[derive(Clone)]
pub struct StaticSecret(zeroize::Zeroizing<[u8; 32]>);

impl StaticSecret {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        StaticSecret(zeroize::Zeroizing::new(b))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for StaticSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StaticSecret(..)")
    }
}

/// What to listen on: a URL (`mem://name`, `quic://host:port`) and the static secret.
#[derive(Clone, Debug)]
pub struct ListenConfig {
    pub url: String,
    pub secret: StaticSecret,
}

/// Dials and listens. Dialing checks the peer's key against `Address::key` (spec/sync.md §10)
/// and uses a fresh ephemeral key (and, for QUIC, UDP socket) of its own per connection.
pub trait Transport: Send + Sync + 'static {
    type Conn: Connection;
    type Listener: Listener<Conn = Self::Conn>;
    fn dial(&self, addr: &Address) -> impl Future<Output = Result<Self::Conn, Error>> + Send;
    /// Dials authenticating with the static key of `secret` instead of an ephemeral one: for a
    /// server dialing a peer server, which must see the dialer's own key (echo suppression).
    fn dial_as(&self, addr: &Address, secret: &StaticSecret) -> impl Future<Output = Result<Self::Conn, Error>> + Send;
    fn listen(&self, cfg: ListenConfig) -> impl Future<Output = Result<Self::Listener, Error>> + Send;
}

/// Incoming connections.
pub trait Listener: Send + 'static {
    type Conn: Connection;
    /// Next connection; `Err(Closed)` once the listener is closed.
    fn accept(&mut self) -> impl Future<Output = Result<Self::Conn, Error>> + Send;
    /// The address to dial this listener at (bound URL, public key).
    fn address(&self) -> Address;
    fn close(&self);
}

/// An authenticated, confidential connection carrying ordered bidirectional streams.
/// Clones share the connection; it closes on `close` or when the last handle (streams included) drops.
pub trait Connection: Clone + Send + Sync + 'static {
    type Send: SendStream;
    type Recv: RecvStream;
    /// The key the transport authenticated for the peer: a server's address key, a client's
    /// per-connection ephemeral key, a peer's dialable key (spec/wire.md §11.1).
    fn peer_key(&self) -> PublicKey;
    /// Where the connection comes from, when the transport can tell (`Source`).
    fn source(&self) -> Option<Source>;
    /// A new stream. The peer's `accept_stream` sees it once data (or finish) is sent on it.
    fn open_stream(&self) -> impl Future<Output = Result<(Self::Send, Self::Recv), Error>> + Send;
    fn accept_stream(&self) -> impl Future<Output = Result<(Self::Send, Self::Recv), Error>> + Send;
    /// Abrupt close: pending and later operations on both sides fail with `Closed`;
    /// data not yet read is lost. A graceful end finishes streams and waits for the peer first.
    fn close(&self);
}

/// The sending half of a stream. Dropping it finishes the stream.
pub trait SendStream: Send + 'static {
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = Result<(), Error>> + Send;
    /// End of stream: the peer reads `Ok(0)` after the data. Completes once the peer's transport
    /// has received everything (or stopped reading), so a `close` after it loses nothing of ours.
    /// Finishing twice is a no-op.
    fn finish(&mut self) -> impl Future<Output = Result<(), Error>> + Send;
}

/// The receiving half of a stream: bytes in order, `Ok(0)` after the peer finished.
pub trait RecvStream: Send + 'static {
    fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize, Error>> + Send;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::collections::BTreeMap;

    // spec: none (server policy): full slots go to the source holding the most only while it holds
    // two more than the newcomer's; repeated arrivals end in equal shares
    #[test]
    fn evict_for_shares_fairly() {
        let mut held: BTreeMap<u8, usize> = BTreeMap::from([(1, 8)]);
        let cap = 8;
        // sources 2, 3 and 4 keep arriving; 1 holds every slot at first
        for _ in 0..20 {
            for s in [2u8, 3, 4] {
                if held.values().sum::<usize>() >= cap {
                    match evict_for(&held, &s) {
                        Some(v) => *held.get_mut(&v).unwrap() -= 1,
                        None => continue,
                    }
                }
                *held.entry(s).or_insert(0) += 1;
            }
        }
        assert_eq!(held.values().sum::<usize>(), cap);
        assert!(held.values().all(|n| (2..=3).contains(n)), "{held:?}");
        // the source holding the most never gives one up to itself, nor at a difference of one
        assert_eq!(evict_for(&BTreeMap::from([(1u8, 5)]), &1), None);
        assert_eq!(evict_for(&BTreeMap::from([(1u8, 3), (2, 2)]), &2), None);
        assert_eq!(evict_for(&BTreeMap::from([(1u8, 3), (2, 1)]), &2), Some(1));
        assert_eq!(evict_for(&BTreeMap::<u8, usize>::new(), &1), None);
        // sources: an IPv4 address and its mapped form are one; an IPv6 /64 is one
        let v4 = ip_source("192.0.2.1".parse().unwrap());
        assert_eq!(v4, ip_source("::ffff:192.0.2.1".parse().unwrap()));
        assert_eq!(ip_source("2001:db8::1".parse().unwrap()), ip_source("2001:db8::ffff:2".parse().unwrap()));
        assert_ne!(ip_source("2001:db8::1".parse().unwrap()), ip_source("2001:db8:0:1::1".parse().unwrap()));
    }
}
