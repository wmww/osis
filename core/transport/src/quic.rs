//! `Quic`: direct host transport, `quic://host:port` (spec/sync.md §10).
//! QUIC v1 (quinn) with TLS 1.3 (rustls, ring provider), ALPN `osis`, both sides authenticated by
//! RFC 7250 raw Ed25519 public keys: the host's is its address key (pinned by the client), the
//! client's a fresh key per connection. No certificates, no CA. Needs a tokio runtime.

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
/// TLS ALPN protocol ID (spec/sync.md §10), also iroh's.
pub const ALPN: &[u8] = b"osis";
/// SNI sent by clients; not checked (the key is).
pub(crate) const SNI_NAME: &str = "osis";
// QUIC settings shared with `iroh` (all provisional):
/// Keep-alive so idle subscriptions survive NAT and the idle timeout.
pub(crate) const KEEP_ALIVE: Duration = Duration::from_secs(15);
/// A connection silent this long is dropped; also bounds a handshake, which has no deadline of
/// its own (any link speed passes, spec/sync.md §10).
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Flow-control windows per stream and per connection: the reader drains frames incrementally,
/// so a window need not hold a whole frame; these bound what a peer makes us buffer.
pub(crate) const STREAM_WINDOW: u32 = 1 << 20;
pub(crate) const CONN_WINDOW: u32 = 4 << 20;
/// Concurrent bidirectional streams a peer may open.
pub(crate) const MAX_STREAMS: u32 = 16;
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

/// A listener's accept loop: every incoming connection's `handshake` in its own task
/// (`Handshakes`, at most `MAX_INCOMING` at once), the connections it yields into the returned
/// channel for `accept`.
pub(crate) fn accept_loop<I, C, AF, HF>(mut incoming: impl FnMut() -> AF + Send + 'static, handshake: impl Fn(I) -> HF + Send + 'static) -> tokio::sync::mpsc::Receiver<C>
where
    AF: std::future::Future<Output = Option<I>> + Send,
    I: Send + 'static,
    HF: std::future::Future<Output = Option<C>> + Send + 'static,
    C: Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let hs = Handshakes::new(MAX_INCOMING);
    tokio::spawn(async move {
        while let Some(inc) = incoming().await {
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

/// The parts of a `Connection` over a crate with quinn's API (`quinn`, or iroh's fork `noq`
/// through `iroh::endpoint`): the stream wrappers `$send` and `$recv`, `conn_err`, and
/// `open_bi`/`accept_bi` on its connection.
macro_rules! quic_streams {
    ($($m:ident)::+; $send:ident, $recv:ident) => {
        fn conn_err(e: $($m)::+::ConnectionError) -> $crate::Error {
            use $($m)::+::ConnectionError as E;
            match e {
                E::LocallyClosed | E::ApplicationClosed(_) | E::ConnectionClosed(_) | E::Reset | E::TimedOut => $crate::Error::Closed,
                E::VersionMismatch | E::TransportError(_) => $crate::Error::Protocol(e.to_string()),
                E::CidsExhausted => $crate::Error::Io(e.to_string()),
            }
        }

        async fn open_bi(c: &$($m)::+::Connection) -> Result<($send, $recv), $crate::Error> {
            let (s, r) = c.open_bi().await.map_err(conn_err)?;
            Ok(($send(s), $recv(r)))
        }

        async fn accept_bi(c: &$($m)::+::Connection) -> Result<($send, $recv), $crate::Error> {
            let (s, r) = c.accept_bi().await.map_err(conn_err)?;
            Ok(($send(s), $recv(r)))
        }

        pub struct $send($($m)::+::SendStream);

        impl $crate::SendStream for $send {
            async fn write_all(&mut self, buf: &[u8]) -> Result<(), $crate::Error> {
                self.0.write_all(buf).await.map_err(|_| $crate::Error::Closed)
            }

            async fn finish(&mut self) -> Result<(), $crate::Error> {
                let _ = self.0.finish(); // Err only when already finished
                self.0.stopped().await.map(|_| ()).map_err(|_| $crate::Error::Closed)
            }
        }

        pub struct $recv($($m)::+::RecvStream);

        impl $crate::RecvStream for $recv {
            async fn read(&mut self, buf: &mut [u8]) -> Result<usize, $crate::Error> {
                match self.0.read(buf).await {
                    Ok(Some(n)) => Ok(n),
                    Ok(None) => Ok(0),
                    Err(_) => Err($crate::Error::Closed),
                }
            }
        }
    };
}
#[cfg(feature = "iroh")]
pub(crate) use quic_streams;

quic_streams!(quinn; QuicSend, QuicRecv);

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

/// Client side: accepts exactly the pinned host key.
#[derive(Debug)]
pub(crate) struct PinnedHost {
    key: PublicKey,
    mismatch: AtomicBool,
}

impl PinnedHost {
    pub(crate) fn new(key: PublicKey) -> Arc<PinnedHost> {
        Arc::new(PinnedHost { key, mismatch: AtomicBool::new(false) })
    }

    /// Whether the host presented another key.
    pub(crate) fn mismatched(&self) -> bool {
        self.mismatch.load(Ordering::Relaxed)
    }
}

impl ServerCertVerifier for PinnedHost {
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
            Err(tls_err("host key does not match the address"))
        }
    }
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
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Bounded per-connection memory: no uni streams or datagrams, few bidi streams, small windows.
fn transport_config() -> Result<Arc<quinn::TransportConfig>, Error> {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(KEEP_ALIVE));
    t.max_idle_timeout(Some(IDLE_TIMEOUT.try_into().map_err(|_| Error::Io("idle timeout".into()))?));
    t.max_concurrent_uni_streams(0u32.into());
    t.max_concurrent_bidi_streams(MAX_STREAMS.into());
    t.datagram_receive_buffer_size(None);
    t.stream_receive_window(STREAM_WINDOW.into());
    t.receive_window(CONN_WINDOW.into());
    Ok(Arc::new(t))
}

/// The port of a `quic://` URL that names none (spec/sync.md §10).
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

/// TLS 1.3 client settings: raw key `me`, the host's key checked by `verifier`, `alpn`, no
/// SNI, no early data.
pub(crate) fn client_tls(me: Arc<CertifiedKey>, verifier: Arc<dyn ServerCertVerifier>, alpn: &[u8]) -> Result<rustls::ClientConfig, Error> {
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Io(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(rustls::client::AlwaysResolvesClientRawPublicKeys::new(me)));
    tls.alpn_protocols = vec![alpn.to_vec()];
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

/// quinn client settings over `client_tls`.
pub(crate) fn client_config(me: Arc<CertifiedKey>, verifier: Arc<dyn ServerCertVerifier>, alpn: &[u8]) -> Result<quinn::ClientConfig, Error> {
    let qc = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(me, verifier, alpn)?).map_err(|e| Error::Io(e.to_string()))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(qc));
    cfg.transport_config(transport_config()?);
    Ok(cfg)
}

/// quinn serving settings over `server_tls`.
pub(crate) fn server_config(me: Arc<CertifiedKey>, alpn: &[&[u8]]) -> Result<quinn::ServerConfig, Error> {
    let qs = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls(me, alpn)?).map_err(|e| Error::Io(e.to_string()))?;
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(qs));
    sc.transport_config(transport_config()?);
    sc.max_incoming(MAX_INCOMING);
    Ok(sc)
}

/// A fresh Ed25519 seed from the OS.
pub(crate) fn random_seed() -> Result<zeroize::Zeroizing<[u8; 32]>, Error> {
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed[..]).map_err(|_| Error::Io("rng".into()))?;
    Ok(seed)
}

/// The client key of a connection the serving side accepted.
pub(crate) fn client_key(c: &quinn::Connection) -> Option<PublicKey> {
    c.peer_identity()
        .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|certs| certs.first().and_then(|d| key_of_spki(d.as_ref())))
}

/// A client handshake from a fresh UDP socket (ends at `IDLE_TIMEOUT` of silence).
async fn handshake(
    sa: SocketAddr,
    url: &str,
    me: Arc<CertifiedKey>,
    verifier: Arc<dyn ServerCertVerifier>,
    alpn: &[u8],
) -> Result<quinn::Connection, Error> {
    let cfg = client_config(me, verifier, alpn)?;
    let bind: SocketAddr = if sa.is_ipv6() { (std::net::Ipv6Addr::UNSPECIFIED, 0).into() } else { (std::net::Ipv4Addr::UNSPECIFIED, 0).into() };
    let ep = quinn::Endpoint::client(bind).map_err(|e| Error::Io(e.to_string()))?;
    let connecting = ep.connect_with(cfg, sa, SNI_NAME).map_err(|e| Error::BadUrl(format!("{url}: {e}")))?;
    connecting.await.map_err(handshake_err)
}

/// The QUIC transport. Each dial uses its own UDP socket, so a host cannot link a client's
/// connections by source port.
#[derive(Clone, Copy, Debug, Default)]
pub struct Quic;

impl Quic {
    pub fn new() -> Quic {
        Quic
    }

    /// The public key a listener with `secret` presents (its Ed25519 key).
    pub fn public_key(secret: &crate::StaticSecret) -> Result<PublicKey, Error> {
        keypair(secret.as_bytes()).map(|k| k.0)
    }

    async fn dial_inner(&self, addr: &Address, own: Option<&crate::StaticSecret>) -> Result<QuicConn, Error> {
        let sa = resolve(&addr.url).await?;
        let me = match own {
            Some(s) => keypair(s.as_bytes())?.1,
            None => keypair(&*random_seed()?)?.1,
        };
        let pin = PinnedHost::new(addr.key);
        match handshake(sa, &addr.url, me, pin.clone(), ALPN).await {
            Ok(c) => Ok(QuicConn { c, peer: addr.key }),
            Err(_) if pin.mismatched() => Err(Error::KeyMismatch),
            Err(e) => Err(e),
        }
    }

    async fn listen_inner(&self, cfg: ListenConfig) -> Result<QuicListener, Error> {
        let sa = resolve(&cfg.url).await?;
        let (pk, me) = keypair(cfg.secret.as_bytes())?;
        let sc = server_config(me, &[ALPN])?;
        let ep = quinn::Endpoint::server(sc, sa).map_err(|e| Error::Io(e.to_string()))?;
        let local = ep.local_addr().map_err(|e| Error::Io(e.to_string()))?;
        // handshakes run concurrently (`accept_loop`), so a silent or slow client blocks nobody
        let e2 = ep.clone();
        let incoming = move || {
            let e = e2.clone();
            async move { e.accept().await }
        };
        let rx = accept_loop(incoming, |inc: quinn::Incoming| async move {
            let c = inc.await.ok()?;
            match client_key(&c) {
                Some(peer) => Some(QuicConn { c, peer }),
                None => {
                    c.close(0u32.into(), b"key");
                    None
                }
            }
        });
        Ok(QuicListener { ep, rx, addr: Address { url: format!("{SCHEME}://{local}"), key: pk } })
    }
}

impl Transport for Quic {
    type Conn = QuicConn;
    type Listener = QuicListener;

    async fn dial(&self, addr: &Address) -> Result<QuicConn, Error> {
        self.dial_inner(addr, None).await
    }

    async fn dial_as(&self, addr: &Address, secret: &crate::StaticSecret) -> Result<QuicConn, Error> {
        self.dial_inner(addr, Some(secret)).await
    }

    async fn listen(&self, cfg: ListenConfig) -> Result<QuicListener, Error> {
        self.listen_inner(cfg).await
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
        self.ep.close(0u32.into(), b"");
    }
}

#[derive(Clone)]
pub struct QuicConn {
    pub(crate) c: quinn::Connection,
    pub(crate) peer: PublicKey,
}

/// A failed handshake: the peer's protocol or TLS failures are `Protocol` (BadInput, not
/// retried), loss of contact `Unreachable`.
pub(crate) fn handshake_err(e: quinn::ConnectionError) -> Error {
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
        open_bi(&self.c).await
    }

    async fn accept_stream(&self) -> Result<(QuicSend, QuicRecv), Error> {
        accept_bi(&self.c).await
    }

    fn close(&self) {
        self.c.close(0u32.into(), b"");
    }
}

/// UDP sockets for `p2p` over QUIC: each socket one quinn endpoint, which dials and, when bound
/// with a secret, accepts (ALPN `osis` or `osis-relay`) on the same port. Needs a tokio runtime.
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

    fn bind(&self, at: SocketAddr, secret: Option<&crate::StaticSecret>) -> Result<QuicSock, Error> {
        let ep = match secret {
            Some(s) => quinn::Endpoint::server(server_config(keypair(s.as_bytes())?.1, &[ALPN, crate::p2p::RELAY_ALPN])?, at),
            None => quinn::Endpoint::client(at),
        }
        .map_err(|e| Error::Io(e.to_string()))?;
        let local = ep.local_addr().map_err(|e| Error::Io(e.to_string()))?;
        let rx = match secret {
            Some(_) => {
                let e2 = ep.clone();
                let incoming = move || {
                    let e = e2.clone();
                    async move { e.accept().await }
                };
                accept_loop(incoming, |inc: quinn::Incoming| async move {
                    use crate::p2p::Alpn;
                    let from = canonical(inc.remote_address());
                    let c = inc.await.ok()?;
                    let proto = c.handshake_data().and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok()).and_then(|h| h.protocol);
                    let alpn = match proto.as_deref() {
                        Some(a) if a == ALPN => Alpn::Osis,
                        Some(a) if a == crate::p2p::RELAY_ALPN => Alpn::Relay,
                        _ => None?,
                    };
                    match client_key(&c) {
                        Some(peer) => Some((QuicConn { c, peer }, alpn, from)),
                        None => {
                            c.close(0u32.into(), b"key");
                            None
                        }
                    }
                })
            }
            None => tokio::sync::mpsc::channel(1).1,
        };
        Ok(QuicSock { ep, local, rx: tokio::sync::Mutex::new(rx) })
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

/// One quinn endpoint (`QuicUdp`). Dropping it leaves its connections up (quinn's endpoint
/// lives while they do); `close` ends them all.
pub struct QuicSock {
    ep: quinn::Endpoint,
    local: SocketAddr,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(QuicConn, crate::p2p::Alpn, SocketAddr)>>,
}

impl crate::p2p::Sock for QuicSock {
    type Conn = QuicConn;

    fn local(&self) -> SocketAddr {
        self.local
    }

    async fn dial(&self, to: SocketAddr, key: PublicKey, own: Option<crate::StaticSecret>, alpn: crate::p2p::Alpn) -> Result<QuicConn, Error> {
        let me = match own {
            Some(s) => keypair(s.as_bytes())?.1,
            None => keypair(&*random_seed()?)?.1,
        };
        let pin = PinnedHost::new(key);
        let cfg = client_config(me, pin.clone(), alpn.bytes())?;
        let connecting = self.ep.connect_with(cfg, to, SNI_NAME).map_err(|e| Error::BadUrl(format!("{to}: {e}")))?;
        match connecting.await {
            Ok(c) => Ok(QuicConn { c, peer: key }),
            Err(_) if pin.mismatched() => Err(Error::KeyMismatch),
            Err(e) => Err(handshake_err(e)),
        }
    }

    async fn accept(&self) -> Result<(QuicConn, crate::p2p::Alpn, SocketAddr), Error> {
        self.rx.lock().await.recv().await.ok_or(Error::Closed)
    }

    /// A QUIC handshake toward `to` that nobody completes (the peer's dialing socket accepts no
    /// connections, and the pinned key is none): its Initial packets open this socket's NAT.
    fn punch(&self, to: SocketAddr) {
        let cfg = random_seed().and_then(|s| keypair(&s)).and_then(|(_, me)| client_config(me, PinnedHost::new([0; 32]), ALPN));
        if let Some(connecting) = cfg.ok().and_then(|cfg| self.ep.connect_with(cfg, to, SNI_NAME).ok()) {
            tokio::spawn(async move {
                if let Ok(c) = connecting.await {
                    c.close(0u32.into(), b"");
                }
            });
        }
    }

    fn close(&self) {
        self.ep.close(0u32.into(), b"");
    }
}


#[cfg(test)]
mod tests {
    //! Handshake failure modes (tier 2: localhost sockets). spec/sync.md §10.
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

    /// Accepts any host key; optionally blocks its thread (a client that never finishes).
    #[derive(Debug)]
    struct Lax(bool);

    impl ServerCertVerifier for Lax {
        fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
            if self.0 {
                std::thread::sleep(Duration::from_secs(8));
            }
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(tls_err("tls 1.3 only"))
        }
        fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_sig(m, c, d)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }

    // spec/sync.md §10: a peer failing the protocol (wrong ALPN) is a protocol error, not retried.
    #[test]
    #[ignore]
    fn wrong_alpn_is_protocol_error() {
        rt().block_on(async {
            let (_l, sa) = listener(1).await;
            let me = keypair(&[2; 32]).unwrap().1;
            let r = handshake(sa, "x", me, Arc::new(Lax(false)), b"nope").await;
            let e = r.err().unwrap();
            assert!(matches!(e, Error::Protocol(_)), "{e:?}");
            assert_eq!(osis_base::Classified::class(&e), osis_base::ErrorClass::BadInput);
        });
    }

    // spec/sync.md §10: a stalled handshake does not block accepting others.
    #[test]
    #[ignore]
    fn stalled_handshake_does_not_block_accept() {
        let main = rt();
        let (mut l, sa) = main.block_on(listener(3));
        // the stalled client runs on its own thread and runtime; its verifier blocks it
        let stall = std::thread::spawn(move || {
            rt().block_on(async move {
                let me = keypair(&[4; 32]).unwrap().1;
                let _ = handshake(sa, "x", me, Arc::new(Lax(true)), ALPN).await;
            })
        });
        main.block_on(async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let addr = l.address();
            let secret = StaticSecret::from_bytes([5; 32]);
            let c = Quic::new().dial_as(&addr, &secret).await.unwrap();
            let s = tokio::time::timeout(Duration::from_secs(2), l.accept()).await.unwrap().unwrap();
            assert_eq!(s.peer_key(), Quic::public_key(&secret).unwrap());
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

    // spec/sync.md §10: handshakes have no deadline; past the cap the oldest in progress goes
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

    // spec/sync.md §10 (mutual auth): a client presenting no key is refused: the serving side yields
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

    // spec/sync.md §10 (no 0-rtt): the serving side issues no session tickets, so a client asking for
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

    // spec/sync.md §10 (URL form: port 4040 when absent, IPv6 in brackets), length cap
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
