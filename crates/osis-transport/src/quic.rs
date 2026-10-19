//! `Quic`: direct server transport, `quic://host:port` (feature `quic`; spec/sync.md §10).
//! QUIC v1 (quinn) with TLS 1.3 (rustls, ring provider), ALPN `osis`, both sides authenticated by
//! RFC 7250 raw Ed25519 public keys: the server's is its address key (pinned by the client), the
//! client's a fresh key per connection. No certificates, no CA. Needs a tokio runtime.

use crate::{Address, Connection, Error, ListenConfig, Listener, PublicKey, RecvStream, SendStream, Transport};
use crate::util::lock;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature_with_raw_key, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const SCHEME: &str = "quic";
/// TLS ALPN protocol ID (spec/sync.md §10).
pub const ALPN: &[u8] = b"osis";
/// SNI sent by clients; not checked (the key is).
const SERVER_NAME: &str = "osis";
/// Keep-alive so idle subscriptions survive NAT and the idle timeout (provisional).
const KEEP_ALIVE: Duration = Duration::from_secs(15);

/// DER SubjectPublicKeyInfo prefix of an Ed25519 key (RFC 8410).
const SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
/// DER PKCS#8 v1 prefix of an Ed25519 seed (RFC 8410).
const PKCS8_PREFIX: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

fn spki(pk: &PublicKey) -> Vec<u8> {
    [&SPKI_PREFIX[..], &pk[..]].concat()
}

/// The Ed25519 key of an SPKI, if it is exactly one.
fn key_of_spki(der: &[u8]) -> Option<PublicKey> {
    let rest = der.strip_prefix(&SPKI_PREFIX[..])?;
    rest.try_into().ok()
}

/// Public key and rustls signer for an Ed25519 seed.
fn keypair(seed: &[u8; 32]) -> Result<(PublicKey, Arc<CertifiedKey>), Error> {
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

/// Client side: accepts exactly the pinned server key.
#[derive(Debug)]
struct PinnedServer {
    key: PublicKey,
    mismatch: AtomicBool,
}

impl ServerCertVerifier for PinnedServer {
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
            Err(tls_err("server key does not match the address"))
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

/// Server side: any Ed25519 client key (clients are ephemeral; authorization is above the transport).
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

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(KEEP_ALIVE));
    Arc::new(t)
}

/// `host:port` of a `quic://` URL.
fn host_port(url: &str) -> Result<&str, Error> {
    match url.split_once("://") {
        Some((SCHEME, hp)) if !hp.is_empty() && !hp.contains('/') => Ok(hp),
        Some((SCHEME, _)) | None => Err(Error::BadUrl(url.to_owned())),
        Some((s, _)) => Err(Error::UnknownScheme(s.to_owned())),
    }
}

async fn resolve(url: &str) -> Result<SocketAddr, Error> {
    let hp = host_port(url)?;
    let mut it = tokio::net::lookup_host(hp).await.map_err(|e| Error::Unreachable(format!("{url}: {e}")))?;
    it.next().ok_or_else(|| Error::Unreachable(url.to_owned()))
}

/// The QUIC transport. Clones share the client endpoints (one UDP socket per address family).
#[derive(Clone, Default)]
pub struct Quic {
    clients: Arc<Mutex<[Option<quinn::Endpoint>; 2]>>,
}

impl Quic {
    pub fn new() -> Quic {
        Quic::default()
    }

    /// The public key a listener with `secret` presents (its Ed25519 key).
    pub fn public_key(secret: &crate::StaticSecret) -> Result<PublicKey, Error> {
        keypair(secret.as_bytes()).map(|k| k.0)
    }

    fn client(&self, v6: bool) -> Result<quinn::Endpoint, Error> {
        let mut c = lock(&self.clients);
        let slot = c.get_mut(usize::from(v6)).ok_or(Error::Closed)?;
        if let Some(e) = slot {
            return Ok(e.clone());
        }
        let bind: SocketAddr = if v6 { (std::net::Ipv6Addr::UNSPECIFIED, 0).into() } else { (std::net::Ipv4Addr::UNSPECIFIED, 0).into() };
        let e = quinn::Endpoint::client(bind).map_err(|e| Error::Io(e.to_string()))?;
        *slot = Some(e.clone());
        Ok(e)
    }

    async fn dial_inner(&self, addr: &Address) -> Result<QuicConn, Error> {
        let sa = resolve(&addr.url).await?;
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed[..]).map_err(|_| Error::Io("rng".into()))?;
        let (_, me) = keypair(&seed)?;
        let pin = Arc::new(PinnedServer { key: addr.key, mismatch: AtomicBool::new(false) });
        let mut tls = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::Io(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(pin.clone())
            .with_client_cert_resolver(Arc::new(rustls::client::AlwaysResolvesClientRawPublicKeys::new(me)));
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let qc = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|e| Error::Io(e.to_string()))?;
        let mut cfg = quinn::ClientConfig::new(Arc::new(qc));
        cfg.transport_config(transport_config());
        let ep = self.client(sa.is_ipv6())?;
        let connecting = ep.connect_with(cfg, sa, SERVER_NAME).map_err(|e| Error::Unreachable(e.to_string()))?;
        match connecting.await {
            Ok(c) => Ok(QuicConn { c, peer: addr.key }),
            Err(_) if pin.mismatch.load(Ordering::Relaxed) => Err(Error::KeyMismatch),
            Err(e) => Err(Error::Unreachable(e.to_string())),
        }
    }

    async fn listen_inner(&self, cfg: ListenConfig) -> Result<QuicListener, Error> {
        let sa = resolve(&cfg.url).await?;
        let (pk, me) = keypair(cfg.secret.as_bytes())?;
        let mut tls = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::Io(e.to_string()))?
            .with_client_cert_verifier(Arc::new(AnyClientKey))
            .with_cert_resolver(Arc::new(rustls::server::AlwaysResolvesServerRawPublicKeys::new(me)));
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let qs = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| Error::Io(e.to_string()))?;
        let mut sc = quinn::ServerConfig::with_crypto(Arc::new(qs));
        sc.transport_config(transport_config());
        let ep = quinn::Endpoint::server(sc, sa).map_err(|e| Error::Io(e.to_string()))?;
        let local = ep.local_addr().map_err(|e| Error::Io(e.to_string()))?;
        Ok(QuicListener { ep, addr: Address { url: format!("{SCHEME}://{local}"), key: pk } })
    }
}

impl Transport for Quic {
    type Conn = QuicConn;
    type Listener = QuicListener;

    async fn dial(&self, addr: &Address) -> Result<QuicConn, Error> {
        self.dial_inner(addr).await
    }

    async fn listen(&self, cfg: ListenConfig) -> Result<QuicListener, Error> {
        self.listen_inner(cfg).await
    }
}

pub struct QuicListener {
    ep: quinn::Endpoint,
    addr: Address,
}

impl Listener for QuicListener {
    type Conn = QuicConn;

    /// Skips clients whose handshake fails.
    async fn accept(&mut self) -> Result<QuicConn, Error> {
        loop {
            let inc = self.ep.accept().await.ok_or(Error::Closed)?;
            let Ok(c) = inc.await else { continue };
            let key = c
                .peer_identity()
                .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok())
                .and_then(|certs| certs.first().and_then(|d| key_of_spki(d.as_ref())));
            match key {
                Some(peer) => return Ok(QuicConn { c, peer }),
                None => c.close(0u32.into(), b"key"),
            }
        }
    }

    fn address(&self) -> Address {
        self.addr.clone()
    }

    fn close(&self) {
        self.ep.close(0u32.into(), b"");
    }
}

#[derive(Clone)]
pub struct QuicConn {
    c: quinn::Connection,
    peer: PublicKey,
}

fn conn_err(e: quinn::ConnectionError) -> Error {
    match e {
        quinn::ConnectionError::LocallyClosed
        | quinn::ConnectionError::ApplicationClosed(_)
        | quinn::ConnectionError::ConnectionClosed(_)
        | quinn::ConnectionError::Reset
        | quinn::ConnectionError::TimedOut => Error::Closed,
        e => Error::Io(e.to_string()),
    }
}

impl Connection for QuicConn {
    type Send = QuicSend;
    type Recv = QuicRecv;

    fn peer_key(&self) -> PublicKey {
        self.peer
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

pub struct QuicSend(quinn::SendStream);

impl SendStream for QuicSend {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.0.write_all(buf).await.map_err(|_| Error::Closed)
    }

    async fn finish(&mut self) -> Result<(), Error> {
        let _ = self.0.finish(); // Err only when already finished
        self.0.stopped().await.map(|_| ()).map_err(|_| Error::Closed)
    }
}

pub struct QuicRecv(quinn::RecvStream);

impl RecvStream for QuicRecv {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match self.0.read(buf).await {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0),
            Err(_) => Err(Error::Closed),
        }
    }
}
