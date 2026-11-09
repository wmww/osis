//! `P2p`: nodes dialed by dialable key (`peer://`, spec/sync.md §10) over UDP sockets: direct
//! QUIC, relaying by any willing node, hole punching through the relay, switching to a direct
//! connection by reconnecting. Generic over the sockets (`Udp`, `Sock`): QUIC (`QuicUdp`) and
//! the in-process NAT model (`nat::MemUdp`), so tier 1 runs the same code through NATs.
//!
//! - **Listener**: one socket, bound at the URL's socket address, accepting QUIC connections
//!   with ALPN `osis` (sessions) and, when this transport relays, `osis-relay`. It registers at
//!   every relay its URL lists from that socket, so a relay sees the address its peers punch to.
//! - **Dial**: a fresh socket per dial and address family its items use. Every direct address of the URL and every relay is tried
//!   at once (dialing an address shows ours there: the caller chooses the URL); the first
//!   connection up is returned. A direct one that completes after a relayed
//!   one was returned, its stream opened, is parked and the relayed one closed: the caller dials
//!   again and gets the parked one (switching; sync reconciles after a reconnect).
//! - **Relayed connection**: one stream, end-to-end TLS 1.3 with raw keys (as `quic://`) over
//!   bytes the relay forwards; the relay sees addresses and volume, never keys or data. The relay
//!   tells neither side the other's address. After the TLS handshake each side sends its own
//!   observed address; the target punches and the dialer dials direct from the same socket.

use crate::quic::{self, PinnedHost, ALPN, IDLE_TIMEOUT, SNI_NAME};
use crate::util::lock;
use crate::{evict_for, ip_source, Address, Backoff, Connection, Error, ListenConfig, Listener, PublicKey, RecvStream, SendStream, Source, StaticSecret, Transport};
use std::collections::BTreeMap;
use std::future::{poll_fn, Future};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::sync::mpsc;

/// ALPN of relay connections (spec/sync.md §10).
pub const RELAY_ALPN: &[u8] = b"osis-relay";

/// Relay stream kinds and answers (spec/sync.md §10).
const REGISTER: u8 = 1;
const DIAL: u8 = 2;
const OK: u8 = 0;
const REFUSED: u8 = 1;
const UNKNOWN: u8 = 2;
const BUSY: u8 = 3;

/// Items of a `peer://` URL looked at (resource bound: a published URL cannot make a dialer
/// start more attempts; past it items are ignored; 0 would dial nothing).
pub const MAX_ITEMS: usize = 16;
/// Per-source relaying rate, bytes per second (resource bound, provisional: forwarding past it
/// waits, so a source cannot take a relay's whole link; 0 is taken as 1; unbounded: one source
/// can). A source's burst is one second of it.
pub const RELAY_RATE: u64 = 1 << 20;
/// Relay connections at once (resource bound, provisional: past it the source holding the most
/// gives one up, `evict_for`, or the newcomer is refused; 0: relays nothing).
pub const RELAY_CONNS: usize = 1024;
/// Bytes a relay reads before forwarding, per direction of a forwarded stream (minor: memory per
/// stream against system calls per byte).
const COPY_BUF: usize = 16 * 1024;
/// A direct connection found after a relayed one was returned waits this long for the next dial
/// (minor: past it the next dial goes through a relay and punches again): QUIC's idle timeout.
const PARK_MS: u64 = IDLE_TIMEOUT.as_secs() * 1000;
/// Connections waiting for `accept` (resource bound: past it relayed ones wait, counted in
/// `MAX_FORWARDED`, each holding its own stream's window, and direct ones pause the socket's
/// accepting; 0: tokio refuses it; unbounded: queued connections without bound).
const ACCEPT_QUEUE: usize = 64;
/// Forwarded streams a listener holds that `accept` has not handed out (handshaking, or waiting
/// for room in its queue), over all its registrations (resource bound: past it the oldest is
/// ended, so streams a dialer opens and never uses cannot fill the relay's grant; 0: no relayed
/// connection could complete; unbounded: they could). As `quic`'s handshakes in progress.
pub const MAX_FORWARDED: usize = 1024;
/// Streams a registration lets its relay open at once (resource bound: past it the relay
/// answers busy; 0: no relayed connection; unbounded: a relay's streams cost the target memory
/// without bound). Twice `MAX_FORWARDED`: as many again for the relayed connections `accept` handed
/// out (a node serves at most `SyncConfig.max_served`) and ended streams the relay has not yet
/// seen end.
pub const REG_STREAMS: u32 = 2 * MAX_FORWARDED as u32;
/// Receive window per stream of a registration's relay connection (resource bound against
/// throughput: a relayed session moves at most this per round trip on the relay's hop; 0:
/// nothing flows; unbounded: a relay makes its registrants buffer without bound). The
/// connection window is `REG_STREAMS` times it, so no stream's unread bytes hold another's.
pub const RELAY_STREAM_WINDOW: u32 = 64 * 1024;
/// The port a node's P2P listener takes when it is free, else any (minor: a fixed port keeps a
/// node's socket address across restarts; 0: a new port per run).
pub const PORT: u16 = 47381;

/// What a connection's dialer lets the other side do at once: open streams, and send per stream
/// and per connection without our reading. A relay forwards dials over a registration (a relay
/// connection dialed with a static key: `REG_STREAMS`, each with its own `RELAY_STREAM_WINDOW`);
/// one dialed ephemerally (a dial through the relay, which opens its one stream itself) lets
/// the relay open none; otherwise as `quic://`.
pub(crate) fn dialer_limits(alpn: Alpn, registers: bool) -> (u32, u32, u64) {
    let quic = (quic::MAX_STREAMS, quic::STREAM_WINDOW, u64::from(quic::CONN_WINDOW));
    match alpn {
        Alpn::Relay if registers => (REG_STREAMS, RELAY_STREAM_WINDOW, u64::from(REG_STREAMS) * u64::from(RELAY_STREAM_WINDOW)),
        Alpn::Relay => (0, quic.1, quic.2),
        Alpn::Osis => quic,
    }
}

/// The protocol of a connection on a P2P socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alpn {
    /// Sync sessions (`osis`).
    Osis,
    /// The relay protocol (`osis-relay`).
    Relay,
}

impl Alpn {
    pub fn bytes(self) -> &'static [u8] {
        match self {
            Alpn::Osis => ALPN,
            Alpn::Relay => RELAY_ALPN,
        }
    }
}

/// Sockets, time and tasks for `P2p`.
pub trait Udp: Clone + Send + Sync + 'static {
    type Sock: Sock;
    /// A socket at `at` (port 0: any free one). With `secret` it accepts connections
    /// authenticating with that key; without, it only dials.
    fn bind(&self, at: SocketAddr, secret: Option<&StaticSecret>) -> Result<Self::Sock, Error>;
    fn now_ms(&self) -> u64;
    fn sleep_ms(&self, ms: u64) -> impl Future<Output = ()> + Send + 'static;
    fn spawn(&self, f: impl Future<Output = ()> + Send + 'static);
    /// 32 random bytes (an ephemeral key's seed).
    fn seed(&self) -> Result<[u8; 32], Error>;
    /// The LAN loop's announcement socket on this machine at `port`.
    fn lan(&self, port: u16) -> impl Future<Output = Result<Arc<dyn crate::lan::LanSocket>, Error>> + Send;
}

/// One UDP socket: dials and accepts QUIC connections from the same port, and punches.
pub trait Sock: Send + Sync + 'static {
    type Conn: Connection;
    fn local(&self) -> SocketAddr;
    /// A connection to `to` authenticating `key`, as `own`'s key or a fresh one. Gives up as a
    /// QUIC handshake does (idle timeout).
    fn dial(&self, to: SocketAddr, key: PublicKey, own: Option<StaticSecret>, alpn: Alpn) -> impl Future<Output = Result<Self::Conn, Error>> + Send;
    /// The next connection that reached this socket, its protocol and where it came from.
    fn accept(&self) -> impl Future<Output = Result<(Self::Conn, Alpn, SocketAddr), Error>> + Send;
    /// Sends a packet to `to`, so this socket's NAT lets `to`'s packets in.
    fn punch(&self, to: SocketAddr);
    fn close(&self);
}

pub(crate) type SConn<U> = <<U as Udp>::Sock as Sock>::Conn;

/// A relay in a `peer://` URL: a node's dialable key and its socket address, written
/// `<64 hex key>@<socket address>`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Relay {
    pub key: PublicKey,
    pub addr: SocketAddr,
}

impl Relay {
    pub fn item(&self) -> String {
        format!("{}@{}", osis_base::hex::encode(&self.key), self.addr)
    }

    pub fn parse(s: &str) -> Option<Relay> {
        let (k, a) = s.split_once('@')?;
        let key = osis_base::hex::decode(k)?.try_into().ok()?;
        Some(Relay { key, addr: a.parse().ok()? })
    }
}

/// What a `peer://` URL lists: the peer's socket addresses and its relays, in order; items of
/// other forms are skipped, and items past `MAX_ITEMS`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Items {
    pub direct: Vec<SocketAddr>,
    pub relays: Vec<Relay>,
}

pub fn items(url: &str) -> Result<Items, Error> {
    let list = crate::peer_items(url).ok_or_else(|| Error::BadUrl(url.to_owned()))?;
    let mut out = Items::default();
    for i in list.iter().take(MAX_ITEMS) {
        if let Ok(a) = i.parse::<SocketAddr>() {
            out.direct.push(a);
        } else if let Some(r) = Relay::parse(i) {
            out.relays.push(r);
        }
    }
    Ok(out)
}

/// What a node lists in `reach.0` for its listener at `listener` (the listener's `peer://`
/// address): each socket address it is bound to that `lan::is_global` passes, an unspecified IP
/// standing for `routes` of the families it serves (the routes' local addresses,
/// `lan::route_ips`; `[::]` serves both), then its relays. Another scheme lists nothing.
pub fn reach_items(listener: &str, routes: &[IpAddr]) -> Vec<String> {
    let Ok(it) = items(listener) else { return Vec::new() };
    let mut direct: Vec<SocketAddr> = Vec::new();
    for a in it.direct {
        let ips: Vec<IpAddr> = match a.ip() {
            IpAddr::V4(v) if v.is_unspecified() => routes.iter().filter(|r| r.is_ipv4()).copied().collect(),
            IpAddr::V6(v) if v.is_unspecified() => routes.to_vec(),
            ip => vec![ip],
        };
        for ip in ips.into_iter().filter(|ip| crate::lan::is_global(*ip)) {
            let s = SocketAddr::new(ip, a.port());
            if !direct.contains(&s) {
                direct.push(s);
            }
        }
    }
    direct.iter().map(SocketAddr::to_string).chain(it.relays.iter().map(Relay::item)).collect()
}

// ---- relay wire ----

/// An address on the relay wire: 16-byte IPv6 address (IPv4 as IPv4-mapped) || be16 port.
fn put_addr(out: &mut Vec<u8>, a: SocketAddr) {
    let ip = match a.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    out.extend_from_slice(&ip.octets());
    out.extend_from_slice(&a.port().to_be_bytes());
}

async fn read_exact<R: RecvStream>(r: &mut R, buf: &mut [u8]) -> Result<(), Error> {
    let mut at = 0;
    while let Some(rest) = buf.get_mut(at..).filter(|b| !b.is_empty()) {
        match r.read(rest).await? {
            0 => return Err(Error::Closed),
            n => at += n,
        }
    }
    Ok(())
}

async fn read_u8<R: RecvStream>(r: &mut R) -> Result<u8, Error> {
    let mut b = [0u8; 1];
    read_exact(r, &mut b).await?;
    Ok(b[0])
}

async fn read_addr<R: RecvStream>(r: &mut R) -> Result<SocketAddr, Error> {
    let (mut ip, mut port) = ([0u8; 16], [0u8; 2]);
    read_exact(r, &mut ip).await?;
    read_exact(r, &mut port).await?;
    let ip = Ipv6Addr::from(ip);
    let ip = ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4);
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}

// ---- a close signal ----

/// Set once; wakes whoever waits for it.
#[derive(Default)]
struct Gate(Mutex<(bool, Vec<Waker>)>);

impl Gate {
    fn close(&self) {
        let ws = {
            let mut g = lock(&self.0);
            g.0 = true;
            std::mem::take(&mut g.1)
        };
        ws.into_iter().for_each(Waker::wake);
    }

    fn is_closed(&self) -> bool {
        lock(&self.0).0
    }

    fn poll_closed(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut g = lock(&self.0);
        if g.0 {
            return Poll::Ready(());
        }
        if !g.1.iter().any(|w| w.will_wake(cx.waker())) {
            g.1.push(cx.waker().clone());
        }
        Poll::Pending
    }

    async fn closed(&self) {
        poll_fn(|cx| self.poll_closed(cx)).await
    }
}

/// `f`'s output if it is ready when first polled.
fn ready_now<F: Future>(f: F) -> Option<F::Output> {
    let mut f = std::pin::pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// `f`, or `Err(Closed)` once `gate` closes.
async fn race<T>(gate: &Gate, f: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
    let mut f = std::pin::pin!(f);
    poll_fn(|cx| if gate.poll_closed(cx).is_ready() { Poll::Ready(Err(Error::Closed)) } else { f.as_mut().poll(cx) }).await
}

// ---- TLS over a forwarded stream ----

type Tls = Arc<Mutex<rustls::Connection>>;

/// TLS bytes rustls has to send.
fn drain(tls: &mut rustls::Connection) -> Vec<u8> {
    let mut out = Vec::new();
    while tls.wants_write() {
        if tls.write_tls(&mut out).is_err() {
            break;
        }
    }
    out
}

/// Hands `raw` to rustls as far as it takes it.
fn feed(tls: &mut rustls::Connection, raw: &mut Vec<u8>) -> Result<(), Error> {
    let mut sl = raw.as_slice();
    let n = tls.read_tls(&mut sl).map_err(|e| Error::Protocol(e.to_string()))?;
    raw.drain(..n);
    tls.process_new_packets().map(|_| ()).map_err(|e| Error::Protocol(e.to_string()))
}

/// Runs the TLS handshake over `s`/`r`; returns bytes read past it.
async fn handshake<S: SendStream, R: RecvStream>(tls: &mut rustls::Connection, s: &mut S, r: &mut R) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; COPY_BUF];
    let mut raw = Vec::new();
    loop {
        let out = drain(tls);
        if !out.is_empty() {
            s.write_all(&out).await?;
        }
        if !tls.is_handshaking() {
            return Ok(raw);
        }
        if raw.is_empty() {
            let n = r.read(&mut buf).await?;
            raw.extend_from_slice(buf.get(..n).ok_or(Error::Closed)?);
            if n == 0 {
                return Err(Error::Closed);
            }
        }
        if let Err(e) = feed(tls, &mut raw) {
            let alert = drain(tls);
            let _ = s.write_all(&alert).await;
            return Err(e);
        }
    }
}

/// The sending half of a relayed connection's stream.
pub struct TlsSend<S> {
    tls: Tls,
    inner: S,
    gate: Arc<Gate>,
    fin: bool,
}

impl<S: SendStream> SendStream for TlsSend<S> {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        if self.fin || self.gate.is_closed() {
            return Err(Error::Closed);
        }
        let out = {
            let mut t = lock(&self.tls);
            t.writer().write_all(buf).map_err(|e| Error::Io(e.to_string()))?;
            drain(&mut t)
        };
        race(&self.gate, self.inner.write_all(&out)).await
    }

    /// Sends TLS close_notify, then finishes the forwarded stream. Dropping without `finish`
    /// ends the stream without close_notify: the peer reads `Closed`, not the end.
    async fn finish(&mut self) -> Result<(), Error> {
        if !self.fin {
            self.fin = true;
            let out = {
                let mut t = lock(&self.tls);
                t.send_close_notify();
                drain(&mut t)
            };
            race(&self.gate, self.inner.write_all(&out)).await?;
        }
        race(&self.gate, self.inner.finish()).await
    }
}

/// The receiving half of a relayed connection's stream: `Ok(0)` only after the peer's TLS
/// close_notify (a stream the relay cut reads `Closed`).
pub struct TlsRecv<R> {
    tls: Tls,
    inner: R,
    gate: Arc<Gate>,
    raw: Vec<u8>,
    eof: bool,
    buf: Vec<u8>,
}

impl<R: RecvStream> RecvStream for TlsRecv<R> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.gate.is_closed() {
                return Err(Error::Closed);
            }
            {
                let mut t = lock(&self.tls);
                match t.reader().read(buf) {
                    Ok(n) => return Ok(n),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err(Error::Closed),
                }
                if !self.raw.is_empty() {
                    feed(&mut t, &mut self.raw)?;
                    continue;
                }
                if self.eof {
                    return Err(Error::Closed);
                }
            }
            let n = race(&self.gate, self.inner.read(&mut self.buf)).await?;
            match self.buf.get(..n) {
                Some([]) | None => self.eof = true,
                Some(b) => self.raw.extend_from_slice(b),
            }
        }
    }
}

/// A relayed connection's one stream.
type Stream<C> = (TlsSend<<C as Connection>::Send>, TlsRecv<<C as Connection>::Recv>);

/// A connection through a relay: one stream.
pub struct Relayed<C: Connection> {
    peer: PublicKey,
    source: Source,
    dialer: bool,
    stream: Mutex<Option<Stream<C>>>,
    /// The dialer's connection to the relay, which serves only this one.
    under: Option<C>,
    gate: Arc<Gate>,
}

/// The stream of a relayed connection whose TLS handshake is done (`raw`: bytes read past it).
fn tls_stream<S: SendStream, R: RecvStream>(tls: rustls::Connection, s: S, r: R, raw: Vec<u8>) -> (TlsSend<S>, TlsRecv<R>) {
    let (tls, gate) = (Arc::new(Mutex::new(tls)), Arc::new(Gate::default()));
    let send = TlsSend { tls: tls.clone(), inner: s, gate: gate.clone(), fin: false };
    let recv = TlsRecv { tls, inner: r, gate, raw, eof: false, buf: vec![0u8; COPY_BUF] };
    (send, recv)
}

/// The address exchange that opens a relayed session (IP consent, spec/sync.md §10): sends
/// `mine`, reads the peer's. Inside TLS, so the peer's key is proven; the relay never forwards
/// an address (a Dial answer carries the dialer's own, the target's stream starts with an
/// opaque tag). Whom a node dials, and who knows its key and relays to dial it, is the caller's
/// choice.
async fn exchange<S: SendStream, R: RecvStream>(s: &mut TlsSend<S>, r: &mut TlsRecv<R>, mine: SocketAddr) -> Result<SocketAddr, Error> {
    let mut out = Vec::new();
    put_addr(&mut out, mine);
    s.write_all(&out).await?;
    read_addr(r).await
}

impl<C: Connection> Relayed<C> {
    fn new(peer: PublicKey, source: Source, dialer: bool, stream: Stream<C>, under: Option<C>) -> Relayed<C> {
        let gate = stream.0.gate.clone();
        Relayed { peer, source, dialer, stream: Mutex::new(Some(stream)), under, gate }
    }

    fn close(&self) {
        self.gate.close();
        if let Some(c) = &self.under {
            c.close();
        }
    }
}

/// A P2P connection: direct, or through a relay.
pub enum P2pConn<C: Connection> {
    Direct(C),
    Relayed(Arc<Relayed<C>>),
}

impl<C: Connection> Clone for P2pConn<C> {
    fn clone(&self) -> Self {
        match self {
            P2pConn::Direct(c) => P2pConn::Direct(c.clone()),
            P2pConn::Relayed(r) => P2pConn::Relayed(r.clone()),
        }
    }
}

impl<C: Connection> P2pConn<C> {
    pub fn is_relayed(&self) -> bool {
        matches!(self, P2pConn::Relayed(_))
    }
}

pub enum P2pSend<C: Connection> {
    Direct(C::Send),
    Relayed(TlsSend<C::Send>),
}

pub enum P2pRecv<C: Connection> {
    Direct(C::Recv),
    Relayed(TlsRecv<C::Recv>),
}

impl<C: Connection> Connection for P2pConn<C> {
    type Send = P2pSend<C>;
    type Recv = P2pRecv<C>;

    fn peer_key(&self) -> PublicKey {
        match self {
            P2pConn::Direct(c) => c.peer_key(),
            P2pConn::Relayed(r) => r.peer,
        }
    }

    /// A relayed connection's source: at the target the relay's tag for the dialer's source, at
    /// the dialer the relay's address.
    fn source(&self) -> Option<Source> {
        match self {
            P2pConn::Direct(c) => c.source(),
            P2pConn::Relayed(r) => Some(r.source),
        }
    }

    /// A relayed connection carries one stream, which its dialer opens.
    async fn open_stream(&self) -> Result<(P2pSend<C>, P2pRecv<C>), Error> {
        match self {
            P2pConn::Direct(c) => c.open_stream().await.map(|(s, r)| (P2pSend::Direct(s), P2pRecv::Direct(r))),
            P2pConn::Relayed(r) if r.gate.is_closed() => Err(Error::Closed),
            P2pConn::Relayed(r) => match lock(&r.stream).take().filter(|_| r.dialer) {
                Some((s, rx)) => Ok((P2pSend::Relayed(s), P2pRecv::Relayed(rx))),
                None => Err(Error::Protocol("a relayed connection carries one stream".into())),
            },
        }
    }

    async fn accept_stream(&self) -> Result<(P2pSend<C>, P2pRecv<C>), Error> {
        match self {
            P2pConn::Direct(c) => c.accept_stream().await.map(|(s, r)| (P2pSend::Direct(s), P2pRecv::Direct(r))),
            P2pConn::Relayed(r) => {
                let taken = if r.dialer { None } else { lock(&r.stream).take() };
                match taken {
                    Some((s, rx)) if !r.gate.is_closed() => Ok((P2pSend::Relayed(s), P2pRecv::Relayed(rx))),
                    _ => {
                        r.gate.closed().await;
                        Err(Error::Closed)
                    }
                }
            }
        }
    }

    fn close(&self) {
        match self {
            P2pConn::Direct(c) => c.close(),
            P2pConn::Relayed(r) => r.close(),
        }
    }
}

impl<C: Connection> SendStream for P2pSend<C> {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        match self {
            P2pSend::Direct(s) => s.write_all(buf).await,
            P2pSend::Relayed(s) => s.write_all(buf).await,
        }
    }

    async fn finish(&mut self) -> Result<(), Error> {
        match self {
            P2pSend::Direct(s) => s.finish().await,
            P2pSend::Relayed(s) => s.finish().await,
        }
    }
}

impl<C: Connection> RecvStream for P2pRecv<C> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match self {
            P2pRecv::Direct(r) => r.read(buf).await,
            P2pRecv::Relayed(r) => r.read(buf).await,
        }
    }
}

// ---- relaying ----

/// Relaying for others (a node mode, off unless configured).
#[derive(Clone)]
pub struct RelayConfig {
    /// Which dialable keys may register: the node's co-readers by default, any when its user
    /// relays for strangers. Asked at registration and at each dial of the key (a key no longer
    /// allowed loses its registration), and by `P2p::recheck_relayed`. Dialers need no
    /// permission: they reach only registered keys.
    pub allow: Arc<dyn Fn(&PublicKey) -> bool + Send + Sync>,
    /// `RELAY_RATE`.
    pub rate: u64,
    /// `RELAY_CONNS`.
    pub max_conns: usize,
}

impl RelayConfig {
    pub fn new(allow: Arc<dyn Fn(&PublicKey) -> bool + Send + Sync>) -> RelayConfig {
        RelayConfig { allow, rate: RELAY_RATE, max_conns: RELAY_CONNS }
    }
}

/// Bytes a source may still send, in thousandths of a byte, and when that was reckoned.
struct Bucket {
    units: i128,
    at: u64,
}

struct RelayState<C> {
    next: u64,
    /// Relay connections by arrival: their source and handle.
    conns: BTreeMap<u64, (Source, C)>,
    /// Registered keys: the registering connection and its observed address.
    regs: BTreeMap<PublicKey, (u64, C, SocketAddr)>,
    buckets: BTreeMap<Source, Bucket>,
}

struct RelayServer<U: Udp> {
    udp: U,
    cfg: RelayConfig,
    st: Mutex<RelayState<SConn<U>>>,
    /// Keys the tags of dialers' sources (`tag`).
    tag_key: [u8; 32],
}

impl<U: Udp> RelayServer<U> {
    /// Serves relay connection `c` from `from`, within `max_conns` (fair shares by source).
    fn serve(self: &Arc<Self>, c: SConn<U>, from: SocketAddr) {
        let src = ip_source(from.ip());
        let id = {
            let mut st = lock(&self.st);
            if st.conns.len() >= self.cfg.max_conns {
                let mut held: BTreeMap<Source, usize> = BTreeMap::new();
                for (s, _) in st.conns.values() {
                    *held.entry(*s).or_insert(0) += 1;
                }
                let Some(v) = evict_for(&held, &src) else {
                    drop(st);
                    c.close();
                    return;
                };
                let oldest = st.conns.iter().find(|(_, (s, _))| *s == v).map(|(i, _)| *i);
                if let Some((i, (_, vc))) = oldest.and_then(|i| st.conns.remove(&i).map(|e| (i, e))) {
                    st.regs.retain(|_, r| r.0 != i);
                    vc.close();
                }
            }
            st.next += 1;
            let id = st.next;
            st.conns.insert(id, (src, c.clone()));
            id
        };
        let me = self.clone();
        self.udp.spawn(async move {
            while let Ok((s, r)) = c.accept_stream().await {
                let (m, c2) = (me.clone(), c.clone());
                me.udp.spawn(async move { m.stream(id, c2, from, s, r).await });
            }
            let mut st = lock(&me.st);
            st.conns.remove(&id);
            st.regs.retain(|_, r| r.0 != id);
            if !st.conns.values().any(|(s, _)| *s == src) {
                st.buckets.remove(&src);
            }
        });
    }

    /// One relay stream: a registration or a dial.
    async fn stream(self: Arc<Self>, id: u64, c: SConn<U>, from: SocketAddr, mut s: <SConn<U> as Connection>::Send, mut r: <SConn<U> as Connection>::Recv) {
        match read_u8(&mut r).await {
            Ok(REGISTER) => {
                let key = c.peer_key();
                // a newer registration of the key replaces an older one
                let ok = (self.cfg.allow)(&key) && {
                    let mut st = lock(&self.st);
                    let live = st.conns.contains_key(&id);
                    if live {
                        st.regs.insert(key, (id, c.clone(), from));
                    }
                    live
                };
                if !ok {
                    let _ = s.write_all(&[REFUSED]).await;
                    let _ = s.finish().await;
                    return;
                }
                let mut msg = vec![OK];
                put_addr(&mut msg, from);
                // registered while the stream stays open
                if s.write_all(&msg).await.is_ok() {
                    let mut b = [0u8; 64];
                    while matches!(r.read(&mut b).await, Ok(n) if n > 0) {}
                }
                let mut st = lock(&self.st);
                if st.regs.get(&key).is_some_and(|e| e.0 == id) {
                    st.regs.remove(&key);
                }
            }
            Ok(DIAL) => {
                let mut key = [0u8; 32];
                if read_exact(&mut r, &mut key).await.is_err() {
                    return;
                }
                let reg = lock(&self.st).regs.get(&key).map(|(i, c, a)| (*i, c.clone(), *a));
                // a key no longer allowed loses its registration
                let reg = reg.filter(|(i, c, _)| {
                    let ok = (self.cfg.allow)(&key);
                    if !ok {
                        self.unregister(&key, *i, c);
                    }
                    ok
                });
                // never waits for the target: a stream it cannot open at once is busy
                let (answer, opened) = match reg {
                    None => (UNKNOWN, None),
                    Some((_, tc, at)) => match ready_now(tc.open_stream()) {
                        Some(Ok(o)) => (OK, Some((o, at))),
                        Some(Err(_)) => (UNKNOWN, None),
                        None => (BUSY, None),
                    },
                };
                let Some(((mut ts, tr), at)) = opened else {
                    let _ = s.write_all(&[answer]).await;
                    let _ = s.finish().await;
                    return;
                };
                // neither side learns the other's address here (the TLS exchange gives it)
                let mut msg = vec![OK];
                put_addr(&mut msg, from);
                if ts.write_all(&self.tag(from)).await.is_err() || s.write_all(&msg).await.is_err() {
                    return;
                }
                tokio::join!(self.copy(r, ts, ip_source(from.ip())), self.copy(tr, s, ip_source(at.ip())));
            }
            _ => {}
        }
    }

    /// The tag of `from`'s source: the same for every dial from one source, unlinkable to its
    /// address without `tag_key`, so a target can share its slots by source.
    fn tag(&self, from: SocketAddr) -> Source {
        let h = osis_base::hash::keyed_hash(&self.tag_key, &ip_source(from.ip()));
        h.first_chunk::<16>().copied().unwrap_or_default()
    }

    /// Forwards `from` to `to` until it ends, charging `src`.
    async fn copy(&self, mut from: impl RecvStream, mut to: impl SendStream, src: Source) {
        let mut buf = vec![0u8; COPY_BUF];
        loop {
            match from.read(&mut buf).await {
                Ok(0) => {
                    let _ = to.finish().await;
                    return;
                }
                Ok(n) => {
                    self.take(src, n).await;
                    let Some(b) = buf.get(..n) else { return };
                    if to.write_all(b).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    }

    /// Ends the registration of `key` by connection `id`, and that connection.
    fn unregister(&self, key: &PublicKey, id: u64, c: &SConn<U>) {
        let mut st = lock(&self.st);
        if st.regs.get(key).is_some_and(|e| e.0 == id) {
            st.regs.remove(key);
        }
        st.conns.remove(&id);
        c.close();
    }

    /// Charges `n` bytes to `src`; waits while it is past its rate. Only a source holding a
    /// relay connection keeps a bucket (forwarding that outlives its connections is charged
    /// against a full one).
    async fn take(&self, src: Source, n: usize) {
        let wait = {
            let mut st = lock(&self.st);
            let now = self.udp.now_ms();
            let rate = i128::from(self.cfg.rate.max(1));
            let burst = rate.saturating_mul(1000);
            let mut b = st.buckets.remove(&src).unwrap_or(Bucket { units: burst, at: now });
            b.units = b.units.saturating_add(i128::from(now.saturating_sub(b.at)).saturating_mul(rate)).min(burst);
            b.at = now;
            b.units = b.units.saturating_sub((n as i128).saturating_mul(1000));
            let wait = if b.units < 0 { u64::try_from(b.units.saturating_neg() / rate + 1).unwrap_or(u64::MAX) } else { 0 };
            if st.conns.values().any(|(s, _)| *s == src) {
                st.buckets.insert(src, b);
            }
            wait
        };
        if wait > 0 {
            self.udp.sleep_ms(wait).await;
        }
    }
}

// ---- the transport ----

/// Parked direct connections by (peer key, dialer's own key if not ephemeral).
struct Parked<C> {
    next: u64,
    conns: BTreeMap<(PublicKey, Option<PublicKey>), (u64, C)>,
}

/// The P2P transport over `U`'s sockets (module comment).
#[derive(Clone)]
pub struct P2p<U: Udp> {
    udp: U,
    relay: Option<Arc<RelayServer<U>>>,
    parked: Arc<Mutex<Parked<SConn<U>>>>,
}

impl<U: Udp> P2p<U> {
    pub fn new(udp: U) -> P2p<U> {
        P2p { udp, relay: None, parked: Arc::new(Mutex::new(Parked { next: 0, conns: BTreeMap::new() })) }
    }

    /// Its listeners also relay, by `cfg`.
    pub fn relaying(mut self, cfg: RelayConfig) -> Result<P2p<U>, Error> {
        let st = RelayState { next: 0, conns: BTreeMap::new(), regs: BTreeMap::new(), buckets: BTreeMap::new() };
        self.relay = Some(Arc::new(RelayServer { udp: self.udp.clone(), cfg, st: Mutex::new(st), tag_key: self.udp.seed()? }));
        Ok(self)
    }

    /// Keys registered here as a relay.
    pub fn relayed_keys(&self) -> Vec<PublicKey> {
        self.relay.as_ref().map(|r| lock(&r.st).regs.keys().copied().collect()).unwrap_or_default()
    }

    /// Ends the registrations here of keys `RelayConfig::allow` no longer allows (call when
    /// its answer may have changed).
    pub fn recheck_relayed(&self) {
        let Some(r) = &self.relay else { return };
        let regs: Vec<_> = lock(&r.st).regs.iter().map(|(k, (i, c, _))| (*k, *i, c.clone())).collect();
        for (k, i, c) in regs {
            if !(r.cfg.allow)(&k) {
                r.unregister(&k, i, &c);
            }
        }
    }

    fn park(&self, tag: (PublicKey, Option<PublicKey>), c: SConn<U>) {
        let id = {
            let mut p = lock(&self.parked);
            p.next += 1;
            let id = p.next;
            if let Some((_, old)) = p.conns.insert(tag, (id, c)) {
                old.close();
            }
            id
        };
        let (parked, sleep) = (self.parked.clone(), self.udp.sleep_ms(PARK_MS));
        self.udp.spawn(async move {
            sleep.await;
            let gone = {
                let mut p = lock(&parked);
                match p.conns.get(&tag) {
                    Some((i, _)) if *i == id => p.conns.remove(&tag),
                    _ => None,
                }
            };
            if let Some((_, c)) = gone {
                c.close();
            }
        });
    }

    async fn dial_inner(&self, addr: &Address, own: Option<StaticSecret>) -> Result<P2pConn<SConn<U>>, Error> {
        let tag = (addr.key, own.as_ref().map(crate::InProcess::public_key));
        if let Some((_, c)) = lock(&self.parked).conns.remove(&tag) {
            return Ok(P2pConn::Direct(c));
        }
        let it = items(&addr.url)?;
        if it.direct.is_empty() && it.relays.is_empty() {
            return Err(Error::Unreachable(addr.url.clone()));
        }
        // a socket per address family the items use (a socket reaches its own family only); an
        // item whose family cannot bind fails alone
        type Slot<S> = Option<Result<Arc<S>, Error>>;
        let (mut v4, mut v6): (Slot<U::Sock>, Slot<U::Sock>) = (None, None);
        let mut sock_for = |to: SocketAddr| {
            let (slot, any): (_, IpAddr) = if to.is_ipv4() { (&mut v4, Ipv4Addr::UNSPECIFIED.into()) } else { (&mut v6, Ipv6Addr::UNSPECIFIED.into()) };
            slot.get_or_insert_with(|| self.udp.bind(SocketAddr::new(any, 0), None).map(Arc::new)).clone()
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        let stop = Arc::new(Gate::default());
        for d in it.direct {
            match sock_for(d) {
                Ok(sock) => direct(&self.udp, &sock, d, addr.key, own.clone(), tx.clone()),
                Err(e) => drop(tx.send(Err(e))),
            }
        }
        for r in it.relays {
            match sock_for(r.addr) {
                Ok(sock) => self.udp.spawn(relayed(self.udp.clone(), sock, r, addr.key, own.clone(), tx.clone(), stop.clone())),
                Err(e) => drop(tx.send(Err(e))),
            }
        }
        drop(tx);
        let mut err = Error::Unreachable(addr.url.clone());
        let first = loop {
            match rx.recv().await {
                Some(Ok(c)) => break c,
                Some(Err(e)) => {
                    if err != Error::KeyMismatch {
                        err = e;
                    }
                }
                None => return Err(err),
            }
        };
        // relayed attempts end; direct ones run on: one completing replaces a relayed connection
        stop.close();
        let me = self.clone();
        let mut relayed = match &first {
            P2pConn::Relayed(r) => Some(Arc::downgrade(r)),
            P2pConn::Direct(_) => None,
        };
        self.udp.spawn(async move {
            while let Some(r) = rx.recv().await {
                let Ok(c) = r else { continue };
                // the relayed connection returned, while its user holds it open with its stream
                // opened (`open_stream` right after `dial` must not fail: closed before that, the
                // caller would take a switch for a failed dial and wait out its retry pause)
                let rel = relayed.as_ref().and_then(std::sync::Weak::upgrade).filter(|r| !r.gate.is_closed() && lock(&r.stream).is_none());
                match (c, rel) {
                    (P2pConn::Direct(d), Some(rel)) => {
                        relayed = None;
                        me.park(tag, d);
                        rel.close();
                    }
                    (c, _) => c.close(),
                }
            }
        });
        Ok(first)
    }

    async fn listen_inner(&self, cfg: ListenConfig) -> Result<P2pListener<U>, Error> {
        let it = items(&cfg.url)?;
        let [bind] = it.direct.as_slice() else { return Err(Error::BadUrl(format!("{}: one socket address to bind", cfg.url))) };
        let sock = Arc::new(self.udp.bind(*bind, Some(&cfg.secret))?);
        let key = crate::InProcess::public_key(&cfg.secret);
        let (tx, rx) = mpsc::channel(ACCEPT_QUEUE);
        let stop = Arc::new(Gate::default());
        let observed = Arc::new(Mutex::new(BTreeMap::new()));
        let (s2, tx2, relay) = (sock.clone(), tx.clone(), self.relay.clone());
        self.udp.spawn(async move {
            loop {
                match s2.accept().await {
                    Ok((c, Alpn::Osis, _)) => {
                        if tx2.send(P2pConn::Direct(c)).await.is_err() {
                            return;
                        }
                    }
                    Ok((c, Alpn::Relay, from)) => match &relay {
                        Some(r) => r.serve(c, from),
                        None => c.close(),
                    },
                    Err(_) => return,
                }
            }
        });
        let mut list = vec![sock.local().to_string()];
        let fwd = Arc::new(Forwarded::default());
        for r in it.relays {
            list.push(r.item());
            let reg = Registration { udp: self.udp.clone(), sock: sock.clone(), relay: r, secret: cfg.secret.clone(), tx: tx.clone(), observed: observed.clone(), fwd: fwd.clone() };
            self.udp.spawn(reg.run(stop.clone()));
        }
        Ok(P2pListener { rx, addr: Address { url: crate::peer_url(&list), key }, stop, sock, observed })
    }
}

/// A direct attempt from `sock` to `to`; its result goes to `tx`.
fn direct<U: Udp>(udp: &U, sock: &Arc<U::Sock>, to: SocketAddr, key: PublicKey, own: Option<StaticSecret>, tx: mpsc::UnboundedSender<Result<P2pConn<SConn<U>>, Error>>) {
    let s = sock.clone();
    udp.spawn(async move {
        let _ = tx.send(s.dial(to, key, own, Alpn::Osis).await.map(P2pConn::Direct));
    });
}

/// An attempt through `relay`: ask it for a stream to `key`, run TLS over the stream, exchange
/// addresses and dial the peer's from the same socket (the peer punches back). Ends early once
/// `stop` closes or the dial is no longer waited for.
async fn relayed<U: Udp>(udp: U, sock: Arc<U::Sock>, relay: Relay, key: PublicKey, own: Option<StaticSecret>, tx: mpsc::UnboundedSender<Result<P2pConn<SConn<U>>, Error>>, stop: Arc<Gate>) {
    let work = async {
        let rc = sock.dial(relay.addr, relay.key, None, Alpn::Relay).await?;
        let (mut s, mut r) = rc.open_stream().await?;
        let mut req = vec![DIAL];
        req.extend_from_slice(&key);
        s.write_all(&req).await?;
        match read_u8(&mut r).await? {
            OK => {}
            UNKNOWN => return Err(Error::Unreachable(format!("{}: not registered at relay {}", osis_base::hex::encode(&key), relay.addr))),
            BUSY => return Err(Error::Unreachable(format!("relay {}: {} busy", relay.addr, osis_base::hex::encode(&key)))),
            _ => return Err(Error::Unreachable(format!("relay {} refused", relay.addr))),
        }
        let seen = read_addr(&mut r).await?;
        let seed = zeroize::Zeroizing::new(match &own {
            Some(s) => *s.as_bytes(),
            None => udp.seed()?,
        });
        let pin = PinnedHost::new(key);
        let cfg = Arc::new(quic::client_tls(quic::keypair(&seed)?.1, pin.clone(), ALPN)?);
        let name = rustls::pki_types::ServerName::try_from(SNI_NAME).map_err(|e| Error::Io(e.to_string()))?;
        let mut tls = rustls::Connection::Client(rustls::ClientConnection::new(cfg, name).map_err(|e| Error::Io(e.to_string()))?);
        tls.set_buffer_limit(None);
        let raw = match handshake(&mut tls, &mut s, &mut r).await {
            Err(_) if pin.mismatched() => return Err(Error::KeyMismatch),
            x => x?,
        };
        let (mut ts, mut tr) = tls_stream(tls, s, r, raw);
        let theirs = exchange(&mut ts, &mut tr, seen).await?;
        direct(&udp, &sock, theirs, key, own.clone(), tx.clone());
        Ok(P2pConn::Relayed(Arc::new(Relayed::new(key, ip_source(relay.addr.ip()), true, (ts, tr), Some(rc)))))
    };
    let r = tokio::select! {
        biased;
        _ = stop.closed() => return,
        _ = tx.closed() => return,
        r = work => r,
    };
    let _ = tx.send(r);
}

/// A listener's registration at one relay, renewed (with backoff) whenever it ends.
struct Registration<U: Udp> {
    udp: U,
    sock: Arc<U::Sock>,
    relay: Relay,
    secret: StaticSecret,
    tx: mpsc::Sender<P2pConn<SConn<U>>>,
    observed: Arc<Mutex<BTreeMap<Relay, SocketAddr>>>,
    fwd: Arc<Forwarded>,
}

/// A listener's forwarded streams that `accept` has not handed out, oldest first, each with the
/// gate that ends it: past `MAX_FORWARDED` the oldest ends.
#[derive(Default)]
struct Forwarded(Mutex<(u64, Ends)>);

/// Forwarded streams by id, oldest first, with the gates that end them.
type Ends = std::collections::VecDeque<(u64, Arc<Gate>)>;

impl Forwarded {
    fn start(&self) -> (u64, Arc<Gate>) {
        let gate = Arc::new(Gate::default());
        let mut g = lock(&self.0);
        g.0 += 1;
        let id = g.0;
        g.1.push_back((id, gate.clone()));
        while g.1.len() > MAX_FORWARDED {
            if let Some((_, old)) = g.1.pop_front() {
                old.close();
            }
        }
        (id, gate)
    }

    fn end(&self, id: u64) {
        lock(&self.0).1.retain(|(i, _)| *i != id);
    }
}

impl<U: Udp> Registration<U> {
    async fn run(self, stop: Arc<Gate>) {
        let seed = self.udp.seed().unwrap_or_default();
        let mut backoff = Backoff::new(u64::from_le_bytes([seed[0], seed[1], seed[2], seed[3], seed[4], seed[5], seed[6], seed[7]]));
        while !stop.is_closed() {
            let _ = race(&stop, self.once(&mut backoff)).await;
            lock(&self.observed).remove(&self.relay);
            let sleep = self.udp.sleep_ms(backoff.next_delay_ms());
            let _ = race(&stop, async {
                sleep.await;
                Ok(())
            })
            .await;
        }
    }

    /// Registers, then hands over the streams the relay forwards until the registration ends.
    async fn once(&self, backoff: &mut Backoff) -> Result<(), Error> {
        let c = self.sock.dial(self.relay.addr, self.relay.key, Some(self.secret.clone()), Alpn::Relay).await?;
        let (mut s, mut r) = c.open_stream().await?;
        s.write_all(&[REGISTER]).await?;
        if read_u8(&mut r).await? != OK {
            return Err(Error::Unreachable(format!("relay {} refused the registration", self.relay.addr)));
        }
        let at = read_addr(&mut r).await?;
        lock(&self.observed).insert(self.relay.clone(), at);
        backoff.reset();
        let held = async {
            let mut b = [0u8; 64];
            while r.read(&mut b).await? > 0 {}
            Ok::<(), Error>(())
        };
        let incoming = async {
            loop {
                match c.accept_stream().await {
                    Ok((bs, br)) => {
                        self.udp.spawn(incoming::<U>(self.sock.clone(), self.secret.clone(), at, bs, br, self.tx.clone(), self.fwd.clone()));
                    }
                    Err(e) => return Err::<(), Error>(e),
                }
            }
        };
        let res = tokio::select! {
            biased;
            r = held => r,
            r = incoming => r,
        };
        c.close();
        drop(s);
        res
    }
}

/// A stream a relay forwarded: serve TLS over it, exchange addresses (ours `at`, as that relay
/// sees it) and punch to the dialer's, then queue the connection for `accept`. Counted in `fwd`
/// until queued, which may end it first.
async fn incoming<U: Udp>(sock: Arc<U::Sock>, secret: StaticSecret, at: SocketAddr, s: <SConn<U> as Connection>::Send, r: <SConn<U> as Connection>::Recv, tx: mpsc::Sender<P2pConn<SConn<U>>>, fwd: Arc<Forwarded>) {
    let (id, gate) = fwd.start();
    let _ = race(&gate, serve_forwarded::<U>(sock, secret, at, s, r, tx)).await;
    fwd.end(id);
}

async fn serve_forwarded<U: Udp>(sock: Arc<U::Sock>, secret: StaticSecret, at: SocketAddr, mut s: <SConn<U> as Connection>::Send, mut r: <SConn<U> as Connection>::Recv, tx: mpsc::Sender<P2pConn<SConn<U>>>) -> Result<(), Error> {
    let res: Result<Relayed<SConn<U>>, Error> = async {
        let mut tag: Source = [0; 16];
        read_exact(&mut r, &mut tag).await?;
        let cfg = Arc::new(quic::server_tls(quic::keypair(secret.as_bytes())?.1, &[ALPN])?);
        let mut tls = rustls::Connection::Server(rustls::ServerConnection::new(cfg).map_err(|e| Error::Io(e.to_string()))?);
        tls.set_buffer_limit(None);
        let raw = handshake(&mut tls, &mut s, &mut r).await?;
        let peer = tls.peer_certificates().and_then(|c| c.first()).and_then(|d| quic::key_of_spki(d.as_ref())).ok_or_else(|| Error::Protocol("no client key".into()))?;
        let (mut ts, mut tr) = tls_stream(tls, s, r, raw);
        sock.punch(exchange(&mut ts, &mut tr, at).await?);
        Ok(Relayed::new(peer, tag, false, (ts, tr), None))
    }
    .await;
    tx.send(P2pConn::Relayed(Arc::new(res?))).await.map_err(|_| Error::Closed)
}

impl<U: Udp> Transport for P2p<U> {
    type Conn = P2pConn<SConn<U>>;
    type Listener = P2pListener<U>;

    async fn dial(&self, addr: &Address) -> Result<Self::Conn, Error> {
        self.dial_inner(addr, None).await
    }

    async fn dial_as(&self, addr: &Address, secret: &StaticSecret) -> Result<Self::Conn, Error> {
        self.dial_inner(addr, Some(secret.clone())).await
    }

    async fn listen(&self, cfg: ListenConfig) -> Result<P2pListener<U>, Error> {
        self.listen_inner(cfg).await
    }

    async fn lan(&self, port: u16) -> Result<Arc<dyn crate::lan::LanSocket>, Error> {
        self.udp.lan(port).await
    }
}

/// A P2P listener (`peer://<socket address> <relays>...`): its address lists the bound socket
/// and the relays it registers at.
pub struct P2pListener<U: Udp> {
    rx: mpsc::Receiver<P2pConn<SConn<U>>>,
    addr: Address,
    stop: Arc<Gate>,
    sock: Arc<U::Sock>,
    observed: Arc<Mutex<BTreeMap<Relay, SocketAddr>>>,
}

impl<U: Udp> P2pListener<U> {
    /// This socket's address as each relay it is registered at sees it.
    pub fn observed(&self) -> Vec<(Relay, SocketAddr)> {
        lock(&self.observed).iter().map(|(r, a)| (r.clone(), *a)).collect()
    }
}

impl<U: Udp> Listener for P2pListener<U> {
    type Conn = P2pConn<SConn<U>>;

    async fn accept(&mut self) -> Result<Self::Conn, Error> {
        self.rx.recv().await.ok_or(Error::Closed)
    }

    fn address(&self) -> Address {
        self.addr.clone()
    }

    fn close(&self) {
        self.stop.close();
        self.sock.close();
    }
}

impl<U: Udp> Drop for P2pListener<U> {
    fn drop(&mut self) {
        self.close();
    }
}
