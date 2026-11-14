//! `Quic`: a direct transport, `quic://host:port` (spec/sync-transport.md §2).
//! QUIC v1 (quinn) with TLS 1.3 (rustls, ring provider), ALPN `osis`, both sides authenticated by
//! RFC 7250 raw Ed25519 public keys: the listener's is its address key (pinned by the dialer), the
//! dialer's a fresh key per connection. No certificates, no CA. Needs a tokio runtime.

use crate::{Address, Connection, Error, ListenConfig, Listener, PublicKey, Transport};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature_with_raw_key, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const SCHEME: &str = "quic";
/// TLS ALPN protocol ID (spec/sync-transport.md §2).
pub const ALPN: &[u8] = b"osis";
/// SNI sent by clients; not checked (the key is).
pub(crate) const SNI_NAME: &str = "osis";
// QUIC settings (all provisional):
/// Keep-alive so idle subscriptions survive NAT and the idle timeout.
pub(crate) const KEEP_ALIVE: Duration = Duration::from_secs(15);
/// A connection silent this long is dropped; also bounds a handshake, which has no deadline of
/// its own (any link speed passes, spec/sync-transport.md §1).
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Flow-control windows per stream and per connection: the reader drains frames incrementally,
/// so a window need not hold a whole frame; these bound what a peer makes us buffer, and the
/// send window (the connection window's size) what a peer that does not acknowledge makes us
/// keep. A session is one stream, so the connection window is one stream's: streams of one
/// connection share it. Resource bound against throughput (`link::CONN_MEMORY`): a session moves
/// at most this per round trip; 0: nothing flows; unbounded: a peer makes us buffer without bound.
pub const STREAM_WINDOW: u32 = 1 << 20;
pub const CONN_WINDOW: u32 = STREAM_WINDOW;
/// Concurrent bidirectional streams a peer may open.
pub const MAX_STREAMS: u32 = 16;
/// Handshakes in progress per listener: past it the oldest is dropped (`Handshakes`).
pub(crate) const MAX_INCOMING: usize = 1024;

/// A listener's handshakes in progress, oldest first: each runs in its own task, ends at the QUIC
/// idle timeout when the peer goes silent, and is aborted when `MAX_INCOMING` newer ones start
/// (half-open handshakes stay bounded without a deadline that refuses slow links).
struct Handshakes {
    cap: usize,
    q: std::sync::Mutex<std::collections::VecDeque<(u64, tokio::task::AbortHandle)>>,
    next: std::sync::atomic::AtomicU64,
}

impl Handshakes {
    fn new(cap: usize) -> Arc<Handshakes> {
        Arc::new(Handshakes { cap, q: Default::default(), next: Default::default() })
    }

    fn spawn(self: &Arc<Self>, f: impl std::future::Future<Output = ()> + Send + 'static) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let me = self.clone();
        // held across the spawn, so the task's removal comes after its insertion
        let mut q = crate::util::lock(&self.q);
        let h = tokio::spawn(async move {
            f.await;
            crate::util::lock(&me.q).retain(|(x, _)| *x != id);
        });
        q.push_back((id, h.abort_handle()));
        while q.len() > self.cap {
            if let Some((_, a)) = q.pop_front() {
                a.abort();
            }
        }
    }
}

/// An endpoint's accept loop: every incoming connection's `handshake` in its own task
/// (`Handshakes`, at most `MAX_INCOMING` at once), so a silent or slow client blocks nobody; the
/// connections it yields go into the returned channel for `accept`.
fn accept_loop<C, HF>(ep: quinn::Endpoint, handshake: impl Fn(quinn::Incoming) -> HF + Send + 'static) -> tokio::sync::mpsc::Receiver<C>
where
    HF: std::future::Future<Output = Option<C>> + Send + 'static,
    C: Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let hs = Handshakes::new(MAX_INCOMING);
    tokio::spawn(async move {
        while let Some(inc) = ep.accept().await {
            let (tx, hand) = (tx.clone(), handshake(inc));
            hs.spawn(async move {
                if let Some(c) = hand.await {
                    let _ = tx.send(c).await;
                }
            });
        }
    });
    rx
}

fn conn_err(e: quinn::ConnectionError) -> Error {
    use quinn::ConnectionError as E;
    match e {
        E::LocallyClosed | E::ApplicationClosed(_) | E::ConnectionClosed(_) | E::Reset | E::TimedOut => Error::Closed,
        E::VersionMismatch | E::TransportError(_) => Error::Protocol(e.to_string()),
        E::CidsExhausted => Error::Io(e.to_string()),
    }
}

pub struct QuicSend(quinn::SendStream);

impl crate::SendStream for QuicSend {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.0.write_all(buf).await.map_err(|_| Error::Closed)
    }

    async fn finish(&mut self) -> Result<(), Error> {
        let _ = self.0.finish(); // Err only when already finished
        self.0.stopped().await.map(|_| ()).map_err(|_| Error::Closed)
    }
}

pub struct QuicRecv(quinn::RecvStream);

impl crate::RecvStream for QuicRecv {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match self.0.read(buf).await {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0),
            Err(_) => Err(Error::Closed),
        }
    }
}

/// DER SubjectPublicKeyInfo prefix of an Ed25519 key (RFC 8410).
const SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
/// DER PKCS#8 v1 prefix of an Ed25519 seed (RFC 8410).
const PKCS8_PREFIX: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

fn spki(pk: &PublicKey) -> Vec<u8> {
    [&SPKI_PREFIX[..], &pk[..]].concat()
}

/// The Ed25519 key of an SPKI, if it is exactly one.
pub(crate) fn key_of_spki(der: &[u8]) -> Option<PublicKey> {
    let rest = der.strip_prefix(&SPKI_PREFIX[..])?;
    rest.try_into().ok()
}

/// Public key and rustls signer for an Ed25519 seed.
pub(crate) fn keypair(seed: &[u8; 32]) -> Result<(PublicKey, Arc<CertifiedKey>), Error> {
    use ring::signature::KeyPair;
    let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed).map_err(|e| Error::Io(e.to_string()))?;
    let pk: PublicKey = kp.public_key().as_ref().try_into().map_err(|_| Error::Io("ed25519 key length".into()))?;
    let der = zeroize::Zeroizing::new([&PKCS8_PREFIX[..], &seed[..]].concat());
    let signer = rustls::crypto::ring::sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(der.as_slice()))
        .map_err(|e| Error::Io(e.to_string()))?;
    Ok((pk, Arc::new(CertifiedKey::new(vec![CertificateDer::from(spki(&pk))], signer))))
}

fn algs() -> WebPkiSupportedAlgorithms {
    rustls::crypto::ring::default_provider().signature_verification_algorithms
}

fn tls_err(m: &str) -> rustls::Error {
    rustls::Error::General(m.to_owned())
}

fn verify_sig(msg: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
    if dss.scheme != SignatureScheme::ED25519 {
        return Err(tls_err("ed25519 only"));
    }
    verify_tls13_signature_with_raw_key(msg, &SubjectPublicKeyInfoDer::from(cert.as_ref()), dss, &algs())
}

/// The signature checks of every verifier here: TLS 1.3, Ed25519 raw public keys only.
macro_rules! raw_ed25519_only {
    () => {
        fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(tls_err("tls 1.3 only"))
        }
        fn verify_tls13_signature(&self, msg: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_sig(msg, cert, dss)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    };
}

/// Dialing side: accepts exactly the pinned key.
#[derive(Debug)]
pub(crate) struct PinnedKey {
    key: PublicKey,
    mismatch: AtomicBool,
}

impl PinnedKey {
    pub(crate) fn new(key: PublicKey) -> Arc<PinnedKey> {
        Arc::new(PinnedKey { key, mismatch: AtomicBool::new(false) })
    }

    /// Whether the listener presented another key.
    pub(crate) fn mismatched(&self) -> bool {
        self.mismatch.load(Ordering::Relaxed)
    }
}

impl ServerCertVerifier for PinnedKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if key_of_spki(end_entity.as_ref()) == Some(self.key) {
            Ok(ServerCertVerified::assertion())
        } else {
            self.mismatch.store(true, Ordering::Relaxed);
            Err(tls_err("key does not match the address"))
        }
    }
    raw_ed25519_only!();
}

/// Serving side: any Ed25519 client key (clients are ephemeral; authorization is above the transport).
#[derive(Debug)]
struct AnyClientKey;

impl ClientCertVerifier for AnyClientKey {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: UnixTime) -> Result<ClientCertVerified, rustls::Error> {
        match key_of_spki(end_entity.as_ref()) {
            Some(_) => Ok(ClientCertVerified::assertion()),
            None => Err(tls_err("client key is not ed25519")),
        }
    }
    raw_ed25519_only!();
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Bounded per-connection memory: no uni streams or datagrams, and the peer may open `streams`
/// bidi streams at once and send `stream_window` per stream, `conn_window` in all, unread.
fn transport_config((streams, stream_window, conn_window): (u32, u32, u64)) -> Result<Arc<quinn::TransportConfig>, Error> {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(KEEP_ALIVE));
    t.max_idle_timeout(Some(IDLE_TIMEOUT.try_into().map_err(|_| Error::Io("idle timeout".into()))?));
    t.max_concurrent_uni_streams(0u32.into());
    t.max_concurrent_bidi_streams(streams.into());
    t.datagram_receive_buffer_size(None);
    t.stream_receive_window(stream_window.into());
    t.receive_window(quinn::VarInt::from_u64(conn_window).map_err(|_| Error::Io("window".into()))?);
    // unacknowledged bytes kept for the peer: as much as it may make us buffer
    t.send_window(conn_window);
    Ok(Arc::new(t))
}

/// The port of a `quic://` URL that names none (spec/sync-transport.md §2).
pub const DEFAULT_PORT: u16 = 4040;

/// `url` with `:DEFAULT_PORT` appended when it is a `quic://` URL naming no port (one host,
/// one address text); any other URL unchanged.
pub fn explicit_port(url: &str) -> String {
    match url.strip_prefix("quic://") {
        Some(hp) if !hp.is_empty() && (hp.ends_with(']') || !hp.contains(':')) => format!("{url}:{DEFAULT_PORT}"),
        _ => url.to_owned(),
    }
}

/// `host:port` of a `quic://` URL: port `DEFAULT_PORT` when absent, IPv6 addresses in brackets.
fn host_port(url: &str) -> Result<String, Error> {
    crate::check_url(url)?;
    let bad = || Error::BadUrl(url.to_owned());
    let hp = match url.split_once("://") {
        Some((SCHEME, hp)) => hp,
        Some((s, _)) => return Err(Error::UnknownScheme(s.to_owned())),
        None => return Err(bad()),
    };
    let (host, port) = match hp.rsplit_once(':') {
        Some((h, p)) if !hp.ends_with(']') => (h, p.parse::<u16>().map_err(|_| bad())?),
        _ => (hp, DEFAULT_PORT),
    };
    let v6 = host.starts_with('[') && host.ends_with(']');
    if host.is_empty() || hp.contains('/') || (host.contains(':') && !v6) {
        return Err(bad());
    }
    Ok(format!("{host}:{port}"))
}

async fn resolve(url: &str) -> Result<SocketAddr, Error> {
    let hp = host_port(url)?;
    let mut it = tokio::net::lookup_host(&hp).await.map_err(|e| Error::Unreachable(format!("{url}: {e}")))?;
    it.next().ok_or_else(|| Error::Unreachable(url.to_owned()))
}

/// TLS 1.3 client settings: raw key `me`, the listener's key checked by `verifier`, offering the
/// protocols `alpn`, no SNI, no early data.
pub(crate) fn client_tls(me: Arc<CertifiedKey>, verifier: Arc<dyn ServerCertVerifier>, alpn: &[&[u8]]) -> Result<rustls::ClientConfig, Error> {
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Io(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(rustls::client::AlwaysResolvesClientRawPublicKeys::new(me)));
    tls.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    tls.enable_sni = false;
    tls.enable_early_data = false;
    Ok(tls)
}

/// TLS 1.3 serving settings: raw key `me`, any Ed25519 client key, the protocols `alpn`, no
/// session tickets or early data.
pub(crate) fn server_tls(me: Arc<CertifiedKey>, alpn: &[&[u8]]) -> Result<rustls::ServerConfig, Error> {
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Io(e.to_string()))?
        .with_client_cert_verifier(Arc::new(AnyClientKey))
        .with_cert_resolver(Arc::new(rustls::server::AlwaysResolvesServerRawPublicKeys::new(me)));
    tls.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    tls.send_tls13_tickets = 0;
    tls.max_early_data_size = 0;
    Ok(tls)
}

/// quinn client settings over `client_tls`; the server may open streams and send within
/// `limits` (`p2p::dialer_limits`).
fn client_config(me: Arc<CertifiedKey>, verifier: Arc<dyn ServerCertVerifier>, alpn: &[&[u8]], limits: (u32, u32, u64)) -> Result<quinn::ClientConfig, Error> {
    let qc = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(me, verifier, alpn)?).map_err(|e| Error::Io(e.to_string()))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(qc));
    cfg.transport_config(transport_config(limits)?);
    Ok(cfg)
}

/// quinn serving settings over `server_tls`.
pub(crate) fn server_config(me: Arc<CertifiedKey>, alpn: &[&[u8]]) -> Result<quinn::ServerConfig, Error> {
    let qs = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls(me, alpn)?).map_err(|e| Error::Io(e.to_string()))?;
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(qs));
    sc.transport_config(transport_config((MAX_STREAMS, STREAM_WINDOW, u64::from(CONN_WINDOW)))?);
    sc.max_incoming(MAX_INCOMING);
    Ok(sc)
}

/// A fresh Ed25519 seed from the OS.
pub(crate) fn random_seed() -> Result<zeroize::Zeroizing<[u8; 32]>, Error> {
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed[..]).map_err(|_| Error::Io("rng".into()))?;
    Ok(seed)
}

/// A connection the serving side accepted, with its client's key; closed when the key is no
/// Ed25519 key.
fn keyed(c: quinn::Connection) -> Option<QuicConn> {
    let peer = c.peer_identity().and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok()).and_then(|certs| certs.first().and_then(|d| key_of_spki(d.as_ref())));
    match peer {
        Some(peer) => Some(QuicConn { c, peer }),
        None => {
            c.close(0u32.into(), b"key");
            None
        }
    }
}

/// A client handshake on `ep` to `to`, which must present `key` (ends at `IDLE_TIMEOUT` of
/// silence): as `own`'s static key, else a fresh one, offering `offer`; the server may open
/// streams and send within `dialer_limits`. The connection and the protocol the server chose.
async fn connect(ep: &quinn::Endpoint, to: SocketAddr, key: PublicKey, own: Option<&crate::StaticSecret>, alpn: crate::p2p::Alpn, offer: &[&[u8]]) -> Result<(QuicConn, Vec<u8>), Error> {
    let limits = crate::p2p::dialer_limits(alpn, own.is_some());
    let me = match own {
        Some(s) => keypair(s.as_bytes())?.1,
        None => keypair(&*random_seed()?)?.1,
    };
    let pin = PinnedKey::new(key);
    let cfg = client_config(me, pin.clone(), offer, limits)?;
    let connecting = ep.connect_with(cfg, to, SNI_NAME).map_err(|e| Error::BadUrl(format!("{to}: {e}")))?;
    match connecting.await {
        Ok(c) => {
            let proto = protocol(&c).unwrap_or_default();
            Ok((QuicConn { c, peer: key }, proto))
        }
        Err(_) if pin.mismatched() => Err(Error::KeyMismatch),
        Err(e) => Err(handshake_err(e)),
    }
}

/// The QUIC transport. Each dial uses its own UDP socket, so a listener cannot link a dialer's
/// connections by source port.
#[derive(Clone, Copy, Debug, Default)]
pub struct Quic;

impl Quic {
    pub fn new() -> Quic {
        Quic
    }

}

impl Transport for Quic {
    type Conn = QuicConn;
    type Listener = QuicListener;

    /// Dials from a fresh UDP socket.
    async fn dial(&self, addr: &Address) -> Result<QuicConn, Error> {
        let sa = resolve(&addr.url).await?;
        let bind: SocketAddr = if sa.is_ipv6() { (std::net::Ipv6Addr::UNSPECIFIED, 0).into() } else { (std::net::Ipv4Addr::UNSPECIFIED, 0).into() };
        let ep = quinn::Endpoint::client(bind).map_err(|e| Error::Io(e.to_string()))?;
        connect(&ep, sa, addr.key, None, crate::p2p::Alpn::Osis, &[ALPN]).await.map(|(c, _)| c)
    }

    async fn listen(&self, cfg: ListenConfig) -> Result<QuicListener, Error> {
        let sa = resolve(&cfg.url).await?;
        let (pk, me) = keypair(cfg.secret.as_bytes())?;
        let sc = server_config(me, &[ALPN])?;
        let ep = quinn::Endpoint::server(sc, sa).map_err(|e| Error::Io(e.to_string()))?;
        let local = ep.local_addr().map_err(|e| Error::Io(e.to_string()))?;
        let rx = accept_loop(ep.clone(), |inc: quinn::Incoming| async move { keyed(inc.await.ok()?) });
        Ok(QuicListener { ep, rx, addr: Address { url: format!("{SCHEME}://{local}"), key: pk } })
    }
}

pub struct QuicListener {
    ep: quinn::Endpoint,
    rx: tokio::sync::mpsc::Receiver<QuicConn>,
    addr: Address,
}

impl Listener for QuicListener {
    type Conn = QuicConn;

    /// Clients whose handshake fails or stalls are skipped.
    async fn accept(&mut self) -> Result<QuicConn, Error> {
        self.rx.recv().await.ok_or(Error::Closed)
    }

    fn address(&self) -> Address {
        self.addr.clone()
    }

    fn close(&self) {
        self.ep.close(0u32.into(), b"");
    }
}

impl Drop for QuicListener {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Clone)]
pub struct QuicConn {
    pub(crate) c: quinn::Connection,
    pub(crate) peer: PublicKey,
}

/// A failed handshake: the peer's protocol or TLS failures are `Protocol` (BadInput, not
/// retried), loss of contact `Unreachable`.
fn handshake_err(e: quinn::ConnectionError) -> Error {
    use quinn::ConnectionError as E;
    match e {
        E::VersionMismatch | E::TransportError(_) | E::ConnectionClosed(_) | E::ApplicationClosed(_) => Error::Protocol(e.to_string()),
        E::Reset | E::TimedOut => Error::Unreachable(e.to_string()),
        E::LocallyClosed => Error::Closed,
        E::CidsExhausted => Error::Io(e.to_string()),
    }
}

impl Connection for QuicConn {
    type Send = QuicSend;
    type Recv = QuicRecv;

    fn peer_key(&self) -> PublicKey {
        self.peer
    }

    fn source(&self) -> Option<crate::Source> {
        Some(crate::ip_source(self.c.remote_address().ip()))
    }

    async fn open_stream(&self) -> Result<(QuicSend, QuicRecv), Error> {
        let (s, r) = self.c.open_bi().await.map_err(conn_err)?;
        Ok((QuicSend(s), QuicRecv(r)))
    }

    async fn accept_stream(&self) -> Result<(QuicSend, QuicRecv), Error> {
        let (s, r) = self.c.accept_bi().await.map_err(conn_err)?;
        Ok((QuicSend(s), QuicRecv(r)))
    }

    fn close(&self) {
        self.c.close(0u32.into(), b"");
    }
}

/// UDP sockets for `p2p` over QUIC: each socket one quinn endpoint, which dials and, when bound
/// with a secret, accepts (ALPN `osis` or `osis-relay`; a LAN listener's `osis-lan` only) on the
/// same port. Needs a tokio runtime.
#[derive(Clone, Debug)]
pub struct QuicUdp {
    start: std::time::Instant,
}

impl Default for QuicUdp {
    fn default() -> QuicUdp {
        QuicUdp { start: std::time::Instant::now() }
    }
}

impl QuicUdp {
    pub fn new() -> QuicUdp {
        QuicUdp::default()
    }
}

/// An address as quinn reports it on a dual-stack socket, IPv4-mapped addresses as IPv4.
fn canonical(a: SocketAddr) -> SocketAddr {
    SocketAddr::new(a.ip().to_canonical(), a.port())
}

impl crate::p2p::Udp for QuicUdp {
    type Sock = QuicSock;

    async fn lan(&self, port: u16) -> Result<std::sync::Arc<dyn crate::lan::LanSocket>, Error> {
        crate::lan::Lan::bind(port).await.map(|s| std::sync::Arc::new(s) as std::sync::Arc<dyn crate::lan::LanSocket>)
    }

    fn bind(&self, at: SocketAddr, secret: Option<&crate::StaticSecret>) -> Result<QuicSock, Error> {
        bind_sock(at, secret, &[ALPN, crate::p2p::RELAY_ALPN])
    }

    fn bind_lan(&self, at: SocketAddr, secret: &crate::StaticSecret) -> Result<QuicSock, Error> {
        bind_sock(at, Some(secret), &[crate::p2p::LAN_ALPN])
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn sleep_ms(&self, ms: u64) -> impl std::future::Future<Output = ()> + Send + 'static {
        tokio::time::sleep(Duration::from_millis(ms))
    }

    fn spawn(&self, f: impl std::future::Future<Output = ()> + Send + 'static) {
        tokio::spawn(f);
    }

    fn seed(&self) -> Result<[u8; 32], Error> {
        random_seed().map(|s| *s)
    }
}

/// A `QuicUdp` socket at `at`; with `secret` it accepts connections of the protocols `serves`.
fn bind_sock(at: SocketAddr, secret: Option<&crate::StaticSecret>, serves: &[&[u8]]) -> Result<QuicSock, Error> {
    let server = match secret {
        Some(s) => Some(server_config(keypair(s.as_bytes())?.1, serves)?),
        None => None,
    };
    // bound here, as quinn binds (an IPv6 socket serves both families), so punches can go
    // out of the same socket
    let raw = socket2::Socket::new(socket2::Domain::for_address(at), socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if at.is_ipv6() {
        let _ = raw.set_only_v6(false);
    }
    raw.bind(&at.into())?;
    let udp: std::net::UdpSocket = raw.into();
    let punch = udp.try_clone()?;
    let ep = quinn::Endpoint::new(quinn::EndpointConfig::default(), server, udp, std::sync::Arc::new(quinn::TokioRuntime))?;
    let local = ep.local_addr()?;
    let rx = match secret {
        Some(_) => accept_loop(ep.clone(), |inc: quinn::Incoming| async move {
            use crate::p2p::Alpn;
            let from = canonical(inc.remote_address());
            let c = inc.await.ok()?;
            let alpn = Alpn::of(&protocol(&c)?)?;
            Some((keyed(c)?, alpn, from))
        }),
        None => tokio::sync::mpsc::channel(1).1,
    };
    Ok(QuicSock { ep, punch, local, rx: tokio::sync::Mutex::new(rx) })
}

/// The protocol a connection's handshake settled on.
fn protocol(c: &quinn::Connection) -> Option<Vec<u8>> {
    c.handshake_data().and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok()).and_then(|h| h.protocol)
}

/// One quinn endpoint (`QuicUdp`). Dropping it leaves its connections up (quinn's endpoint
/// lives while they do); `close` ends them all.
pub struct QuicSock {
    ep: quinn::Endpoint,
    /// The endpoint's socket, for punches.
    punch: std::net::UdpSocket,
    local: SocketAddr,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(QuicConn, crate::p2p::Alpn, SocketAddr)>>,
}

impl crate::p2p::Sock for QuicSock {
    type Conn = QuicConn;

    fn local(&self) -> SocketAddr {
        self.local
    }

    async fn dial(&self, to: SocketAddr, key: PublicKey, own: Option<crate::StaticSecret>, alpn: crate::p2p::Alpn) -> Result<(QuicConn, crate::p2p::Alpn), Error> {
        let (c, proto) = connect(&self.ep, to, key, own.as_ref(), alpn, alpn.offer()).await?;
        let got = crate::p2p::Alpn::of(&proto).ok_or_else(|| Error::Protocol("no protocol".into()))?;
        Ok((c, got))
    }

    async fn accept(&self) -> Result<(QuicConn, crate::p2p::Alpn, SocketAddr), Error> {
        self.rx.lock().await.recv().await.ok_or(Error::Closed)
    }

    /// Best effort, as any UDP datagram: a send that fails is a punch lost on the way.
    fn punch(&self, to: SocketAddr) {
        let to = match to {
            SocketAddr::V4(v) if self.local.is_ipv6() => SocketAddr::new(std::net::IpAddr::V6(v.ip().to_ipv6_mapped()), v.port()),
            _ => to,
        };
        let _ = self.punch.send_to(&crate::p2p::PUNCH, to);
    }

    fn close(&self) {
        self.ep.close(0u32.into(), b"");
    }
}


#[cfg(test)]
mod tests {
    //! Handshake failure modes (by hand: localhost sockets). spec/sync-transport.md §2.
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::{Listener, StaticSecret, Transport};

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    async fn listener(seed: u8) -> (QuicListener, SocketAddr) {
        let cfg = ListenConfig { url: "quic://127.0.0.1:0".into(), secret: StaticSecret::from_bytes([seed; 32]) };
        let l = Quic::new().listen(cfg).await.unwrap();
        let sa = resolve(&l.address().url).await.unwrap();
        (l, sa)
    }

    /// Accepts any listener key; optionally blocks its thread (a client that never finishes).
    #[derive(Debug)]
    struct Lax(bool);

    impl ServerCertVerifier for Lax {
        fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
            if self.0 {
                std::thread::sleep(Duration::from_secs(8));
            }
            Ok(ServerCertVerified::assertion())
        }
        raw_ed25519_only!();
    }

    // spec/sync-transport.md §2: a peer failing the protocol (wrong ALPN) is a protocol error, not retried.
    #[test]
    #[ignore]
    fn wrong_alpn_is_protocol_error() {
        rt().block_on(async {
            let (_l, sa) = listener(1).await;
            let me = keypair(&[2; 32]).unwrap().1;
            let r = handshake(sa, me, Arc::new(Lax(false)), b"nope").await;
            let e = r.err().unwrap();
            assert!(matches!(e, Error::Protocol(_)), "{e:?}");
            assert_eq!(osis_base::Classified::class(&e), osis_base::ErrorClass::BadInput);
        });
    }

    // spec/sync-transport.md §1: a stalled handshake does not block accepting others.
    #[test]
    #[ignore]
    fn stalled_handshake_does_not_block_accept() {
        let main = rt();
        let (mut l, sa) = main.block_on(listener(3));
        // the stalled client runs on its own thread and runtime; its verifier blocks it
        let stall = std::thread::spawn(move || {
            rt().block_on(async move {
                let me = keypair(&[4; 32]).unwrap().1;
                let _ = handshake(sa, me, Arc::new(Lax(true)), ALPN).await;
            })
        });
        main.block_on(async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let addr = l.address();
            let c = Quic::new().dial(&addr).await.unwrap();
            let s = tokio::time::timeout(Duration::from_secs(2), l.accept()).await.unwrap().unwrap();
            assert_ne!(s.peer_key(), addr.key);
            drop(c);
        });
        stall.join().unwrap();
    }

    fn lax_client(early: bool, me: Option<Arc<CertifiedKey>>) -> quinn::ClientConfig {
        let b = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Lax(false)));
        let mut tls = match me {
            Some(me) => b.with_client_cert_resolver(Arc::new(rustls::client::AlwaysResolvesClientRawPublicKeys::new(me))),
            None => b.with_no_client_auth(),
        };
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.enable_early_data = early;
        quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap()))
    }

    fn endpoint() -> quinn::Endpoint {
        quinn::Endpoint::client((std::net::Ipv4Addr::UNSPECIFIED, 0).into()).unwrap()
    }

    /// A client handshake to `sa` from a fresh socket, the listener's key checked by `verifier`.
    async fn handshake(sa: SocketAddr, me: Arc<CertifiedKey>, verifier: Arc<dyn ServerCertVerifier>, alpn: &[u8]) -> Result<quinn::Connection, Error> {
        let cfg = client_config(me, verifier, &[alpn], (MAX_STREAMS, STREAM_WINDOW, u64::from(CONN_WINDOW))).unwrap();
        endpoint().connect_with(cfg, sa, SNI_NAME).unwrap().await.map_err(handshake_err)
    }

    // spec/sync-transport.md §1: handshakes have no deadline; past the cap the oldest in progress goes
    #[test]
    fn handshakes_evict_oldest() {
        rt().block_on(async {
            let hs = Handshakes::new(2);
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let gates: Vec<_> = (0..3)
                .map(|i| {
                    let (g, w) = tokio::sync::oneshot::channel::<()>();
                    let tx = tx.clone();
                    hs.spawn(async move {
                        let _ = w.await;
                        let _ = tx.send(i);
                    });
                    g
                })
                .collect();
            drop(tx);
            assert_eq!(crate::util::lock(&hs.q).len(), 2);
            for g in gates {
                let _ = g.send(());
            }
            let mut done = Vec::new();
            while let Some(i) = rx.recv().await {
                done.push(i);
            }
            done.sort();
            assert_eq!(done, vec![1, 2]);
            assert!(crate::util::lock(&hs.q).is_empty());
        });
    }

    // spec/sync-transport.md §2 (mutual auth): a client presenting no key is refused: the serving side yields
    // no connection and the client's is closed.
    #[test]
    #[ignore]
    fn client_without_key_refused() {
        rt().block_on(async {
            let (mut l, sa) = listener(6).await;
            let ep = endpoint();
            let connecting = ep.connect_with(lax_client(false, None), sa, SNI_NAME).unwrap();
            if let Ok(Ok(c)) = tokio::time::timeout(Duration::from_secs(5), connecting).await {
                tokio::time::timeout(Duration::from_secs(5), c.closed()).await.unwrap();
            }
            assert!(!matches!(tokio::time::timeout(Duration::from_secs(1), l.accept()).await, Ok(Ok(_))));
        });
    }

    // spec/sync-transport.md §2 (mutual auth, Ed25519 only): a client presenting a P-256 raw key is refused.
    #[test]
    #[ignore]
    fn client_p256_key_refused() {
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING as P256};
        const P256_SPKI: [u8; 26] = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00];
        let rng = ring::rand::SystemRandom::new();
        let pk8 = EcdsaKeyPair::generate_pkcs8(&P256, &rng).unwrap();
        let point = EcdsaKeyPair::from_pkcs8(&P256, pk8.as_ref(), &rng).unwrap().public_key().as_ref().to_vec();
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pk8.as_ref().to_vec()));
        let signer = rustls::crypto::ring::sign::any_ecdsa_type(&der).unwrap();
        let me = Arc::new(CertifiedKey::new(vec![CertificateDer::from([&P256_SPKI[..], &point].concat())], signer));
        rt().block_on(async {
            let (mut l, sa) = listener(9).await;
            let ep = endpoint();
            let connecting = ep.connect_with(lax_client(false, Some(me)), sa, SNI_NAME).unwrap();
            if let Ok(Ok(c)) = tokio::time::timeout(Duration::from_secs(5), connecting).await {
                tokio::time::timeout(Duration::from_secs(5), c.closed()).await.unwrap();
            }
            assert!(!matches!(tokio::time::timeout(Duration::from_secs(1), l.accept()).await, Ok(Ok(_))));
        });
    }

    // spec/sync-transport.md §2 (raw Ed25519 keys only; the dialer pins the listener's key): the dialing
    // verifier takes exactly the pinned key, the listening one any Ed25519 key; both offer only
    // the ed25519 scheme and need raw keys.
    #[test]
    fn verifiers_take_ed25519_keys_only() {
        let (k, other) = (keypair(&[1; 32]).unwrap().0, keypair(&[2; 32]).unwrap().0);
        // an X25519 SPKI (OID 1.3.101.110): Ed25519's shape, not a signing key
        let x25519 = CertificateDer::from([&[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00][..], &k[..]].concat());
        let long = CertificateDer::from([&spki(&k)[..], &[0]].concat());
        let name = ServerName::try_from(SNI_NAME).unwrap();
        let dialing = |c: &CertificateDer<'_>| {
            let pin = PinnedKey::new(k);
            let ok = pin.verify_server_cert(c, &[], &name, &[], UnixTime::now()).is_ok();
            assert_eq!(pin.mismatched(), !ok);
            ok
        };
        assert!(dialing(&CertificateDer::from(spki(&k))));
        assert!(!dialing(&CertificateDer::from(spki(&other))));
        assert!(!dialing(&x25519));
        assert!(!dialing(&long));
        let listening = |c: &CertificateDer<'_>| AnyClientKey.verify_client_cert(c, &[], UnixTime::now()).is_ok();
        assert!(listening(&CertificateDer::from(spki(&other))));
        assert!(!listening(&x25519));
        assert!(!listening(&long));
        assert!(AnyClientKey.offer_client_auth() && AnyClientKey.client_auth_mandatory());
        let pin = PinnedKey::new(k);
        assert_eq!((pin.supported_verify_schemes(), pin.requires_raw_public_keys()), (vec![SignatureScheme::ED25519], true));
        assert_eq!((AnyClientKey.supported_verify_schemes(), AnyClientKey.requires_raw_public_keys()), (vec![SignatureScheme::ED25519], true));
    }

    // spec/sync-transport.md §2 (no 0-rtt): the serving side issues no session tickets, so a client asking for
    // 0-RTT cannot use it on its next connection.
    #[test]
    #[ignore]
    fn no_zero_rtt() {
        rt().block_on(async {
            let (mut l, sa) = listener(7).await;
            let me = keypair(&[8; 32]).unwrap().1;
            let cfg = lax_client(true, Some(me));
            let ep = endpoint();
            let c1 = ep.connect_with(cfg.clone(), sa, SNI_NAME).unwrap().await.unwrap();
            let _s = tokio::time::timeout(Duration::from_secs(2), l.accept()).await.unwrap().unwrap();
            // a round trip, so post-handshake messages (tickets, were any sent) have arrived
            let _ = c1.open_bi().await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            c1.close(0u32.into(), b"");
            let connecting = ep.connect_with(cfg, sa, SNI_NAME).unwrap();
            assert!(connecting.into_0rtt().is_err(), "0-RTT offered");
        });
    }

    // spec/sync-transport.md §2 (uRL form: port 4040 when absent, IPv6 in brackets), length cap
    #[test]
    fn url_forms_spec_sync_10() {
        assert_eq!(host_port("quic://example.org:4433").unwrap(), "example.org:4433");
        assert_eq!(host_port("quic://[::1]:4433").unwrap(), "[::1]:4433");
        assert!(host_port("quic://::1:4433").is_err());
        assert!(host_port("quic://::1").is_err());
        assert_eq!(host_port("quic://example.org").unwrap(), "example.org:4040");
        assert_eq!(host_port("quic://[::1]").unwrap(), "[::1]:4040");
        assert!(host_port("quic://example.org:").is_err());
        assert!(host_port("quic://example.org:x").is_err());
        assert!(host_port("quic://example.org:4433/x").is_err());
        assert!(host_port(&format!("quic://{}:1", "a".repeat(300))).is_err());
        assert_eq!(explicit_port("quic://example.org"), "quic://example.org:4040");
        assert_eq!(explicit_port("quic://[::1]"), "quic://[::1]:4040");
        for u in ["quic://example.org:4433", "quic://[::1]:1", "mem://x", "quic://"] {
            assert_eq!(explicit_port(u), u);
        }
    }
}
