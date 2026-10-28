//! `Iroh`: the P2P transport (feature `iroh`; spec/sync.md §10, notes/networking.md decision 2):
//! `peer://` addresses, a node dialed by its dialable key (the iroh endpoint key: the Ed25519 key
//! of the 32-byte static secret, as `Quic` derives it), through the relays the URL lists, with
//! iroh's hole punching. No n0 infrastructure: no address lookup, no default relays; relays are
//! the self-hosted `iroh-relay` URLs from `/reach`. Items of a `peer://` URL that parse as socket
//! addresses are direct addresses (a LAN announcement's, a loopback test's); the rest are relay
//! URLs. A listener binds the addresses its URL lists and registers at the relays it lists, and
//! nowhere else (a LAN listener lists none: a relay would link its fresh key to the node's). ALPN `osis`. The authenticated
//! peer key is the iroh endpoint key, checked against `Address::key` by iroh's handshake.
//!
//! `dial` binds an endpoint with a fresh key per connection (it lives as long as the
//! connection); `dial_as` dials from the listening endpoint of that secret, and fails when this
//! transport has none (a second endpoint with a listener's key could take its relay
//! registration). Needs a tokio runtime.

use crate::{Address, Connection, Error, ListenConfig, Listener, PublicKey, RecvStream, SendStream, StaticSecret, Transport};
use iroh::endpoint::{presets, ConnectionError, QuicTransportConfig, VarInt};
use iroh::{Endpoint, EndpointAddr, RelayMode, RelayUrl, SecretKey, TransportAddr};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub use crate::quic::ALPN;
use crate::quic::{CONN_WINDOW, IDLE_TIMEOUT, KEEP_ALIVE, MAX_INCOMING, MAX_STREAMS, STREAM_WINDOW};

/// A handshake not done in this time is dropped (provisional).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The P2P transport. Clones share the listening endpoints.
#[derive(Clone, Default)]
pub struct Iroh {
    /// Listening endpoints by key (`dial_as` reuses them).
    listening: Arc<Mutex<HashMap<PublicKey, Endpoint>>>,
}

/// Direct addresses and relays of a `peer://` URL.
fn hints(url: &str) -> Result<(Vec<SocketAddr>, Vec<RelayUrl>), Error> {
    crate::check_url(url)?;
    let Some(items) = crate::peer_relays(url) else {
        return Err(match url.split_once("://") {
            Some((s, _)) => Error::UnknownScheme(s.to_owned()),
            None => Error::BadUrl(url.to_owned()),
        });
    };
    let (mut ips, mut relays) = (Vec::new(), Vec::new());
    for i in items {
        match i.parse::<SocketAddr>() {
            Ok(a) => ips.push(a),
            Err(_) => relays.push(i.parse::<RelayUrl>().map_err(|_| Error::BadUrl(url.to_owned()))?),
        }
    }
    Ok((ips, relays))
}

fn io(e: impl std::fmt::Display) -> Error {
    Error::Io(e.to_string())
}

/// Bounded per-connection memory: no uni streams or datagrams, few bidi streams, small windows.
fn transport_config() -> QuicTransportConfig {
    let mut b = QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_STREAMS))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(STREAM_WINDOW))
        .receive_window(VarInt::from_u32(CONN_WINDOW))
        .datagram_receive_buffer_size(None)
        .keep_alive_interval(KEEP_ALIVE);
    if let Ok(t) = IDLE_TIMEOUT.try_into() {
        b = b.max_idle_timeout(Some(t));
    }
    b.build()
}

/// An endpoint with `secret` (fresh when none), the given relays as home relays, bound to
/// `bind` (all interfaces when none).
async fn endpoint(secret: Option<&StaticSecret>, relays: Vec<RelayUrl>, bind: &[SocketAddr], alpn: bool) -> Result<Endpoint, Error> {
    let mut b = Endpoint::builder(presets::Minimal).transport_config(transport_config()).max_tls_tickets(0);
    if let Some(s) = secret {
        b = b.secret_key(SecretKey::from_bytes(s.as_bytes()));
    }
    if !relays.is_empty() {
        b = b.relay_mode(RelayMode::custom(relays));
    }
    if !bind.is_empty() {
        b = b.clear_ip_transports();
        for a in bind {
            b = b.bind_addr(*a).map_err(io)?;
        }
    }
    if alpn {
        b = b.alpns(vec![ALPN.to_vec()]);
    }
    b.bind().await.map_err(io)
}

/// Closes an endpoint in the background (connections close gracefully); dropped outside a
/// runtime, it just drops.
fn spawn_close(ep: Endpoint) {
    if let Ok(h) = tokio::runtime::Handle::try_current() {
        h.spawn(async move { ep.close().await });
    }
}

fn conn_err(e: ConnectionError) -> Error {
    use ConnectionError as E;
    match e {
        E::LocallyClosed | E::ApplicationClosed(_) | E::ConnectionClosed(_) | E::Reset | E::TimedOut => Error::Closed,
        E::VersionMismatch | E::TransportError(_) => Error::Protocol(e.to_string()),
        E::CidsExhausted => Error::Io(e.to_string()),
    }
}

impl Iroh {
    /// A transport whose listeners use no relay (direct and LAN only).
    pub fn new() -> Iroh {
        Iroh::default()
    }

    /// The key a listener with `secret` presents.
    pub fn public_key(secret: &StaticSecret) -> PublicKey {
        *SecretKey::from_bytes(secret.as_bytes()).public().as_bytes()
    }

    async fn dial_inner(&self, addr: &Address, own: Option<&StaticSecret>) -> Result<IrohConn, Error> {
        let (ips, relays) = hints(&addr.url)?;
        let id = iroh::PublicKey::from_bytes(&addr.key).map_err(|_| Error::BadUrl("peer key is not an Ed25519 key".into()))?;
        let target = EndpointAddr::from_parts(id, ips.into_iter().map(TransportAddr::Ip).chain(relays.iter().cloned().map(TransportAddr::Relay)));
        let shared = own.and_then(|s| crate::util::lock(&self.listening).get(&Iroh::public_key(s)).cloned());
        let (ep, owned) = match (shared, own) {
            (Some(ep), _) => (ep, false),
            (None, Some(_)) => return Err(Error::Unreachable("dial_as: no listener with that key".into())),
            (None, None) => (endpoint(None, relays, &[], false).await?, true),
        };
        let c = match tokio::time::timeout(HANDSHAKE_TIMEOUT, ep.connect(target, ALPN)).await {
            Ok(Ok(c)) => c,
            r => {
                if owned {
                    ep.close().await;
                }
                return Err(Error::Unreachable(match r {
                    Ok(Err(e)) => e.to_string(),
                    _ => "handshake timed out".into(),
                }));
            }
        };
        let peer = *c.remote_id().as_bytes();
        if peer != addr.key {
            c.close(0u32.into(), b"key");
            return Err(Error::KeyMismatch);
        }
        Ok(IrohConn { c, peer, ep: owned.then_some(ep) })
    }

    async fn listen_inner(&self, cfg: ListenConfig) -> Result<IrohListener, Error> {
        let (bind, relays) = hints(&cfg.url)?;
        let home: Vec<String> = relays.iter().map(|r| r.to_string()).collect();
        let ep = endpoint(Some(&cfg.secret), relays, &bind, true).await?;
        let key = *ep.id().as_bytes();
        crate::util::lock(&self.listening).insert(key, ep.clone());
        // handshakes run concurrently, each under a deadline, so a silent dialer blocks nobody
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let e2 = ep.clone();
        let pending = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tokio::spawn(async move {
            while let Some(inc) = e2.accept().await {
                if pending.load(std::sync::atomic::Ordering::Acquire) >= MAX_INCOMING {
                    drop(inc);
                    continue;
                }
                pending.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                let (tx, pending) = (tx.clone(), pending.clone());
                tokio::spawn(async move {
                    let r = tokio::time::timeout(HANDSHAKE_TIMEOUT, inc).await;
                    pending.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                    let Ok(Ok(c)) = r else { return };
                    let peer = *c.remote_id().as_bytes();
                    let _ = tx.send(IrohConn { c, peer, ep: None }).await;
                });
            }
        });
        let mut items: Vec<String> = ep.bound_sockets().iter().map(|a| a.to_string()).collect();
        items.extend(home);
        Ok(IrohListener { ep, rx, addr: Address { url: crate::peer_url(&items), key }, listening: self.listening.clone() })
    }
}

impl Transport for Iroh {
    type Conn = IrohConn;
    type Listener = IrohListener;

    async fn dial(&self, addr: &Address) -> Result<IrohConn, Error> {
        self.dial_inner(addr, None).await
    }

    async fn dial_as(&self, addr: &Address, secret: &StaticSecret) -> Result<IrohConn, Error> {
        self.dial_inner(addr, Some(secret)).await
    }

    /// `cfg.url`: `peer://` with the socket addresses to bind (none: all interfaces, any port).
    /// The listener's `address().url` lists bound IP addresses: never publish it in `/reach`
    /// (spec/sync.md §10); a peer learns direct addresses by LAN announcement or hole punching.
    async fn listen(&self, cfg: ListenConfig) -> Result<IrohListener, Error> {
        self.listen_inner(cfg).await
    }
}

pub struct IrohListener {
    ep: Endpoint,
    rx: tokio::sync::mpsc::Receiver<IrohConn>,
    /// Bound sockets and home relays.
    addr: Address,
    listening: Arc<Mutex<HashMap<PublicKey, Endpoint>>>,
}

impl Listener for IrohListener {
    type Conn = IrohConn;

    /// Dialers whose handshake fails or stalls are skipped.
    async fn accept(&mut self) -> Result<IrohConn, Error> {
        self.rx.recv().await.ok_or(Error::Closed)
    }

    fn address(&self) -> Address {
        self.addr.clone()
    }

    fn close(&self) {
        crate::util::lock(&self.listening).remove(&self.addr.key);
        let ep = self.ep.clone();
        spawn_close(ep);
    }
}

impl Drop for IrohListener {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Clone)]
pub struct IrohConn {
    c: iroh::endpoint::Connection,
    peer: PublicKey,
    /// The dialing endpoint this connection owns (`dial`): closed with it.
    ep: Option<Endpoint>,
}

impl Connection for IrohConn {
    type Send = IrohSend;
    type Recv = IrohRecv;

    fn peer_key(&self) -> PublicKey {
        self.peer
    }

    async fn open_stream(&self) -> Result<(IrohSend, IrohRecv), Error> {
        let (s, r) = self.c.open_bi().await.map_err(conn_err)?;
        Ok((IrohSend(s), IrohRecv(r)))
    }

    async fn accept_stream(&self) -> Result<(IrohSend, IrohRecv), Error> {
        let (s, r) = self.c.accept_bi().await.map_err(conn_err)?;
        Ok((IrohSend(s), IrohRecv(r)))
    }

    fn close(&self) {
        self.c.close(0u32.into(), b"");
        if let Some(ep) = self.ep.clone() {
            spawn_close(ep);
        }
    }
}

pub struct IrohSend(iroh::endpoint::SendStream);

impl SendStream for IrohSend {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.0.write_all(buf).await.map_err(|_| Error::Closed)
    }

    async fn finish(&mut self) -> Result<(), Error> {
        let _ = self.0.finish(); // Err only when already finished
        self.0.stopped().await.map(|_| ()).map_err(|_| Error::Closed)
    }
}

pub struct IrohRecv(iroh::endpoint::RecvStream);

impl RecvStream for IrohRecv {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match self.0.read(buf).await {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0),
            Err(_) => Err(Error::Closed),
        }
    }
}

/// A self-hosted `iroh-relay` on localhost for tier-2 tests (feature `relay`): plain HTTP, no
/// QUIC address discovery; shut down when dropped. `url` is the relay URL for `/reach` and
/// a listener's URL.
#[cfg(feature = "relay")]
pub struct TestRelay {
    _server: iroh_relay::server::Server,
    pub url: String,
}

#[cfg(feature = "relay")]
impl TestRelay {
    pub async fn spawn() -> Result<TestRelay, Error> {
        let mut cfg = iroh_relay::server::ServerConfig::default();
        cfg.relay = Some(iroh_relay::server::RelayConfig::new((std::net::Ipv4Addr::LOCALHOST, 0)));
        let server = iroh_relay::server::Server::spawn(cfg).await.map_err(io)?;
        let addr = server.http_addr().ok_or_else(|| Error::Io("relay without an http address".into()))?;
        Ok(TestRelay { url: format!("http://{addr}"), _server: server })
    }
}

#[cfg(test)]
mod tests {
    //! Tier 2 (localhost sockets, `--ignored`). spec/sync.md §10.
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    // spec/sync.md §10: a peer dialed by its key (direct address in the URL, no relay) is
    // authenticated with that key; the listener sees the dialer's fresh key, or its static key
    // with `dial_as`; bytes cross both ways and the end of a stream reads as 0.
    #[test]
    #[ignore]
    fn loopback_spec_sync_10() {
        rt().block_on(async {
            let t = Iroh::new();
            let secret = StaticSecret::from_bytes([7; 32]);
            let mut l = t.listen(ListenConfig { url: "peer://127.0.0.1:0".into(), secret: secret.clone() }).await.unwrap();
            let addr = l.address();
            assert_eq!(addr.key, Iroh::public_key(&secret));
            let srv = tokio::spawn(async move {
                let c = l.accept().await.unwrap();
                let (mut s, mut r) = c.accept_stream().await.unwrap();
                let mut buf = [0u8; 5];
                let mut got = 0;
                while got < 5 {
                    got += r.read(&mut buf[got..]).await.unwrap();
                }
                s.write_all(&buf).await.unwrap();
                s.finish().await.unwrap();
                let peer = c.peer_key();
                let c2 = l.accept().await.unwrap();
                (peer, c2.peer_key(), l)
            });
            let c = t.dial(&addr).await.unwrap();
            assert_eq!(c.peer_key(), addr.key);
            let (mut s, mut r) = c.open_stream().await.unwrap();
            s.write_all(b"hello").await.unwrap();
            let mut out = Vec::new();
            let mut buf = [0u8; 16];
            loop {
                let n = r.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            assert_eq!(out, b"hello");
            let me = StaticSecret::from_bytes([8; 32]);
            assert!(t.dial_as(&addr, &me).await.is_err(), "no listener with that key");
            let _mine = t.listen(ListenConfig { url: "peer://127.0.0.1:0".into(), secret: me.clone() }).await.unwrap();
            let c2 = t.dial_as(&addr, &me).await.unwrap();
            let (_s2, _r2) = c2.open_stream().await.unwrap();
            let mut s2 = _s2;
            s2.write_all(b"x").await.unwrap();
            let (first, second, _l) = srv.await.unwrap();
            assert_ne!(first, Iroh::public_key(&me));
            assert_eq!(second, Iroh::public_key(&me));
            // a wrong key is refused
            let bad = Address { url: addr.url.clone(), key: Iroh::public_key(&StaticSecret::from_bytes([9; 32])) };
            assert!(t.dial(&bad).await.is_err());
            c.close();
            c2.close();
        });
    }

    // spec/sync.md §10: a peer registered at a self-hosted relay is dialed by key through the
    // relay alone (the URL lists no direct address) and authenticated with that key.
    #[cfg(feature = "relay")]
    #[test]
    #[ignore]
    fn through_relay_spec_sync_10() {
        rt().block_on(async {
            let relay = TestRelay::spawn().await.unwrap();
            let t = Iroh::new();
            let secret = StaticSecret::from_bytes([10; 32]);
            let mut l = t.listen(ListenConfig { url: format!("peer://127.0.0.1:0 {}", relay.url), secret }).await.unwrap();
            assert_eq!(l.address().url.split(' ').count(), 2, "the bound socket and the URL's relay");
            let key = l.address().key;
            let srv = tokio::spawn(async move {
                let c = l.accept().await.unwrap();
                let (mut s, mut r) = c.accept_stream().await.unwrap();
                let mut buf = [0u8; 2];
                let mut got = 0;
                while got < 2 {
                    got += r.read(&mut buf[got..]).await.unwrap();
                }
                s.write_all(&buf).await.unwrap();
                s.finish().await.unwrap();
                l
            });
            let addr = Address { url: crate::peer_url(std::slice::from_ref(&relay.url)), key };
            let c = Iroh::new().dial(&addr).await.unwrap();
            assert_eq!(c.peer_key(), key);
            let (mut s, mut r) = c.open_stream().await.unwrap();
            s.write_all(b"hi").await.unwrap();
            let mut out = Vec::new();
            let mut buf = [0u8; 8];
            loop {
                let n = r.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            assert_eq!(out, b"hi");
            let _l = srv.await.unwrap();
            c.close();
        });
    }

    // spec/sync.md §10: the URL forms (direct addresses and relays) parse; other schemes are
    // refused as unknown.
    #[test]
    fn url_forms() {
        let (ips, relays) = hints("peer://127.0.0.1:4 https://relay.example./").unwrap();
        assert_eq!(ips, vec!["127.0.0.1:4".parse::<SocketAddr>().unwrap()]);
        assert_eq!(relays.len(), 1);
        assert!(matches!(hints("quic://x:1"), Err(Error::UnknownScheme(_))));
        assert!(matches!(hints("peer://not a url"), Err(Error::BadUrl(_))));
    }

    // spec/sync.md §10 (LAN discovery on both families): the LAN listener binds IPv4 and IPv6
    // and lists one socket of each, whose ports the announcements carry.
    #[test]
    #[ignore]
    fn listens_on_both_families_spec_sync_10() {
        rt().block_on(async {
            let t = Iroh::new();
            let l = t.listen(ListenConfig { url: "peer://0.0.0.0:0 [::]:0".into(), secret: StaticSecret::from_bytes([8; 32]) }).await.unwrap();
            let socks: Vec<SocketAddr> = crate::peer_relays(&l.address().url).unwrap().iter().filter_map(|x| x.parse().ok()).collect();
            assert!(socks.iter().any(|a| a.is_ipv4() && a.port() != 0), "{socks:?}");
            assert!(socks.iter().any(|a| a.is_ipv6() && a.port() != 0), "{socks:?}");
        });
    }
}
