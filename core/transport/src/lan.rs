//! LAN discovery (spec/sync-transport.md §4): announcements of a transport key fresh per
//! network join, never the dialable key, and nothing else (no tag, secret or signature): a
//! datagram `"osis lan 2"` || key || be16 port, broadcast on the IPv4 LAN and multicast to the
//! IPv6 all-nodes group. `LanSocket` sends and hears them (`Lan`: UDP sockets; `nat::MemLan`: a
//! LAN segment of the NAT model) and tells a network change. `Joined` is one join's state: its own
//! key and the keys it handed up lately. `P2p::discover` runs the loop. A LAN listener serves
//! ALPN `osis-lan` only, so a connection's rank (`p2p::Alpn::rank`) needs no record of what was
//! heard and is the same at both ends whatever an announcement claims.

use crate::{Address, Error, PublicKey};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::task::Poll;

const MAGIC: &[u8; 10] = b"osis lan 2";
/// Datagram length.
pub const LEN: usize = 10 + 32 + 2;
/// The UDP port announcements go to.
pub const PORT: u16 = 47_380;

/// Where IPv4 announcements are sent: the limited broadcast address at `port`.
pub fn broadcast(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::BROADCAST), port)
}

/// The IPv6 link-local all-nodes group.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Where IPv6 announcements are sent: the all-nodes group at `port`, no interface named
/// (`Lan`'s `announce` sends it on every interface, `targets`).
pub fn multicast(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(ALL_NODES), port)
}

/// The all-nodes group at `port` on the interface with index `scope`.
pub fn multicast_on(port: u16, scope: u32) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(ALL_NODES, port, 0, scope))
}

/// Where an announcement to `to` goes: the all-nodes group with no interface named goes to it
/// on each interface of `scopes` (spec/sync-transport.md §4: every link the machine is on), or out the
/// default multicast interface when there is none; any other address as it is.
pub fn targets(to: SocketAddr, scopes: &[u32]) -> Vec<SocketAddr> {
    match to {
        SocketAddr::V6(v) if *v.ip() == ALL_NODES && v.scope_id() == 0 && !scopes.is_empty() => scopes.iter().map(|s| multicast_on(v.port(), *s)).collect(),
        _ => vec![to],
    }
}

/// The interfaces IPv6 announcements go out on, from the machine's IPv6 addresses with their
/// interface indexes: the index of each interface with a link-local address, sorted, once each.
/// Loopback has none.
pub fn link_scopes(addrs: impl IntoIterator<Item = (Ipv6Addr, u32)>) -> Vec<u32> {
    let mut out: Vec<u32> = addrs.into_iter().filter(|(ip, scope)| *scope != 0 && ip.segments().first().is_some_and(|f| f & 0xffc0 == 0xfe80)).map(|(_, scope)| scope).collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The machine's interfaces for IPv6 announcements now: `link_scopes` over the kernel's IPv6
/// address list (`/proc/net/if_inet6`, Linux and Android; elsewhere none, so announcements go
/// out the default interface only).
pub async fn v6_scopes() -> Vec<u32> {
    let text = std::fs::read_to_string("/proc/net/if_inet6").unwrap_or_default();
    link_scopes(if_inet6(&text))
}

/// The addresses and interface indexes of `/proc/net/if_inet6` lines (32 hex digits of address,
/// then the index in hex, then other fields); malformed lines are skipped.
pub fn if_inet6(text: &str) -> Vec<(Ipv6Addr, u32)> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let ip = u128::from_str_radix(f.next().filter(|a| a.len() == 32)?, 16).ok()?;
            let index = u32::from_str_radix(f.next()?, 16).ok()?;
            Some((Ipv6Addr::from(ip), index))
        })
        .collect()
}

/// One announcement: a join's transport key and its listener's port on the datagram's family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Announce {
    pub key: PublicKey,
    pub port: u16,
}

impl Announce {
    pub fn encode(&self) -> [u8; LEN] {
        let mut b = [0u8; LEN];
        let (m, rest) = b.split_at_mut(MAGIC.len());
        let (k, p) = rest.split_at_mut(32);
        m.copy_from_slice(MAGIC);
        k.copy_from_slice(&self.key);
        p.copy_from_slice(&self.port.to_be_bytes());
        b
    }

    /// None for any other datagram.
    pub fn decode(b: &[u8]) -> Option<Announce> {
        let rest = b.strip_prefix(&MAGIC[..])?;
        let (key, port) = rest.split_first_chunk::<32>()?;
        let port: [u8; 2] = port.try_into().ok()?;
        Some(Announce { key: *key, port: u16::from_be_bytes(port) })
    }

    /// Where to dial the announcer, given the datagram's source address (an IPv6 link-local
    /// source keeps its interface scope).
    pub fn address(&self, from: SocketAddr) -> Address {
        let mut at = from;
        at.set_port(self.port);
        Address { url: crate::peer_url(&[at.to_string()]), key: self.key }
    }
}

/// One network join's state (spec/sync-transport.md §4): its listener's key (none while it has
/// no listener) and the last `cap` keys it handed up (`LanConfig::recent`), so the repeats of
/// one announcer's join are dialed once. Bounded whatever a LAN sends.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Joined {
    own: Option<PublicKey>,
    recent: VecDeque<PublicKey>,
    cap: usize,
}

impl Joined {
    /// A join listening under `own`, nothing heard yet, remembering `cap` keys.
    pub fn new(own: Option<PublicKey>, cap: usize) -> Joined {
        Joined { own, recent: VecDeque::new(), cap }
    }

    /// An announcement heard from `from`: where to dial its key; none for a source that cannot
    /// be on the LAN (`is_local`), this join's own key, or a key among the last `cap` handed up.
    pub fn heard(&mut self, a: &Announce, from: SocketAddr) -> Option<Address> {
        if !is_local(from.ip()) || self.own == Some(a.key) || self.recent.contains(&a.key) {
            return None;
        }
        if self.cap > 0 {
            if self.recent.len() == self.cap {
                self.recent.pop_front();
            }
            self.recent.push_back(a.key);
        }
        Some(a.address(from))
    }
}

/// Announcements after the first in a join (minor: more ride out more loss; 0: one datagram,
/// lost now and then; unbounded: announcing forever, which nothing needs, since every node
/// dials every announcer).
pub const JOIN_REPEATS: u32 = 3;
/// Milliseconds between a join's announcements (minor: its first seconds, spec/sync-transport.md
/// §4; 0: a burst one loss event takes whole).
pub const JOIN_GAP_MS: u64 = 1000;
/// Milliseconds the loop waits after handing up a key to dial (pacing, spec/sync-transport.md §4;
/// 0: a flood of announcements is a flood of dials; unbounded: one dial ever).
pub const PACE_MS: u64 = 50;

/// How a node runs LAN discovery (`P2p::discover`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanConfig {
    /// The port announcements are heard on (`PORT`; 0: any, for tests).
    pub port: u16,
    /// Where announcements go: the broadcast address and the all-nodes group at `PORT`, then
    /// any further addresses configured. An IPv6 one goes only when the socket has IPv6.
    pub to: Vec<SocketAddr>,
    /// Where each join's listener binds, tried in order (`peer://[::]:0`, both families; then
    /// `peer://0.0.0.0:0`).
    pub listen: Vec<String>,
    /// `JOIN_REPEATS`, `JOIN_GAP_MS`, `PACE_MS`.
    pub repeats: u32,
    pub gap_ms: u64,
    pub pace_ms: u64,
}

impl LanConfig {
    /// How many keys a join remembers having handed up (`Joined`): those of one join's
    /// announcements, `repeats` more `gap_ms` apart, plus one gap of slack, at one key handed
    /// up per `pace_ms` (at least 1 ms). Derived, not picked: a repeat heard within that span
    /// finds its key still remembered; one heard later, or under a flood, is dialed again, which
    /// costs a dial the pacing already allows.
    pub fn recent(&self) -> usize {
        let span = u64::from(self.repeats).saturating_add(1).saturating_mul(self.gap_ms);
        usize::try_from(span / self.pace_ms.max(1)).unwrap_or(usize::MAX).saturating_add(1)
    }
}

impl Default for LanConfig {
    fn default() -> LanConfig {
        LanConfig { port: PORT, to: vec![broadcast(PORT), multicast(PORT)], listen: vec!["peer://[::]:0".into(), "peer://0.0.0.0:0".into()], repeats: JOIN_REPEATS, gap_ms: JOIN_GAP_MS, pace_ms: PACE_MS }
    }
}

/// What discovery hands up (spec/sync-transport.md §1): a dial candidate, or a connection its
/// own listener accepted, with that listener's key (this join's transport key: the static key
/// of the connection's sessions, spec/wire.md §11.1).
pub enum Found<C> {
    Dial(Address),
    Conn(C, crate::PublicKey),
}

/// A running discovery (`Transport::discover`): its events in order. Dropping it stops the loop
/// and closes its listener.
pub struct Discovery<C> {
    pub(crate) rx: tokio::sync::mpsc::Receiver<Found<C>>,
    pub(crate) rejoin: std::sync::Arc<tokio::sync::Notify>,
    pub(crate) stop: std::sync::Arc<crate::util::Gate>,
}

impl<C> Discovery<C> {
    /// The next event; none once the loop ended (its announcement socket failed).
    pub async fn next(&mut self) -> Option<Found<C>> {
        self.rx.recv().await
    }

    /// Starts afresh now: the network may have changed (an OS network-change callback). For LAN
    /// discovery a fresh key and listener, announced. Calls made while one is pending make one
    /// join; no other limit is needed, since only the local node calls it and each join replaces
    /// the last.
    pub fn rejoin(&self) {
        self.rejoin.notify_one();
    }
}

impl<C> Drop for Discovery<C> {
    fn drop(&mut self) {
        self.stop.close();
    }
}

/// A boxed future of a `LanSocket` call.
pub type LanFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, crate::Error>> + Send + 'a>>;

/// Where the LAN loop (`P2p::discover`) sends and hears announcements: UDP sockets (`Lan`) or a
/// LAN segment of the NAT model (`nat::MemLan`); see `p2p::Udp::lan`.
pub trait LanSocket: Send + Sync + 'static {
    /// Whether IPv6 announcements go out and are heard.
    fn has_v6(&self) -> bool;
    /// Sends an announcement to `to`: the broadcast address or all-nodes group at the
    /// announcement port, or one address.
    fn announce<'a>(&'a self, a: &'a Announce, to: SocketAddr) -> LanFuture<'a, ()>;
    /// The next announcement heard, and its sender's address.
    fn recv(&self) -> LanFuture<'_, (Announce, SocketAddr)>;
    /// Resolves when the machine's network may have changed since the last time it resolved (or
    /// since the socket was made): the node then joins anew.
    fn changed(&self) -> LanFuture<'_, ()>;
}

/// UDP sockets sending and receiving announcements: IPv4 (broadcast) and, where
/// the machine has IPv6, IPv6 (all-nodes multicast).
pub struct Lan {
    v4: tokio::net::UdpSocket,
    v6: Option<tokio::net::UdpSocket>,
    port: u16,
    /// Which socket `recv` looks at first (alternates, so a flood on one starves neither).
    turn: std::sync::atomic::AtomicBool,
    /// The routes' networks as `changed` last saw them (`route_networks`).
    route: std::sync::Mutex<(Option<IpAddr>, Option<IpAddr>)>,
}

/// A nonblocking UDP socket of `family` that shares its port with other nodes on the machine
/// (`SO_REUSEADDR`: on Linux each socket on the port gets every broadcast and multicast).
fn shared_udp(family: socket2::Domain) -> std::io::Result<socket2::Socket> {
    let s = socket2::Socket::new(family, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    Ok(s)
}

/// An IPv4 UDP socket at `port`, allowed to broadcast.
fn bind_v4(port: u16) -> std::io::Result<tokio::net::UdpSocket> {
    let s = shared_udp(socket2::Domain::IPV4)?;
    s.set_broadcast(true)?;
    s.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port).into())?;
    tokio::net::UdpSocket::from_std(s.into())
}

/// An IPv6-only UDP socket at `port`, in the all-nodes group.
fn bind_v6(port: u16) -> std::io::Result<tokio::net::UdpSocket> {
    let s = shared_udp(socket2::Domain::IPV6)?;
    // beside the IPv4 socket of the same port
    s.set_only_v6(true)?;
    s.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
    // IPv6 machines are in the group anyway; joining makes delivery explicit where that matters
    let _ = s.join_multicast_v6(&ALL_NODES, 0);
    tokio::net::UdpSocket::from_std(s.into())
}

impl Lan {
    /// Binds the announcement port on all IPv4 interfaces and, when the machine has IPv6, on all
    /// IPv6 interfaces (`port` 0: any, for tests; IPv6 then takes the port IPv4 got). Other nodes
    /// on this machine can bind the same port.
    pub async fn bind(port: u16) -> Result<Lan, Error> {
        let v4 = bind_v4(port)?;
        let port = v4.local_addr()?.port();
        Ok(Lan { v4, v6: bind_v6(port).ok(), port, turn: Default::default(), route: std::sync::Mutex::new(route_networks().await) })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl LanSocket for Lan {
    fn has_v6(&self) -> bool {
        self.v6.is_some()
    }

    /// Sends an announcement to `to` (the broadcast address or the all-nodes group at the
    /// announcement port, or one address) on the socket of its family. The all-nodes group with no
    /// interface named goes out every up interface with IPv6, each with its scope (`targets`,
    /// `v6_scopes`, looked up at each call: interfaces come and go); if every one of those
    /// sends fails, it goes out the default multicast interface. The socket joins the group on
    /// each of those interfaces at each call ("already joined" ignored): Linux delivers to it
    /// anyway (`IPV6_MULTICAST_ALL`), BSD stacks only on interfaces it joined, and interfaces
    /// come and go under one socket.
    fn announce<'a>(&'a self, a: &'a Announce, to: SocketAddr) -> LanFuture<'a, ()> {
        Box::pin(async move {
            let s = match (to, &self.v6) {
                (SocketAddr::V4(_), _) => &self.v4,
                (SocketAddr::V6(_), Some(s)) => s,
                (SocketAddr::V6(_), None) => return Err(Error::Unreachable("no IPv6 socket".into())),
            };
            let scopes = if to == multicast(to.port()) { v6_scopes().await } else { Vec::new() };
            for sc in &scopes {
                let _ = s.join_multicast_v6(&ALL_NODES, *sc);
            }
            let bytes = a.encode();
            let mut res = Ok(());
            let mut sent = false;
            for t in targets(to, &scopes) {
                match s.send_to(&bytes, t).await {
                    Ok(_) => sent = true,
                    Err(e) => res = Err(e.into()),
                }
            }
            if !sent && !scopes.is_empty() {
                res = s.send_to(&bytes, to).await.map(|_| ()).map_err(Error::from);
                sent = res.is_ok();
            }
            if sent { Ok(()) } else { res }
        })
    }

    /// The next announcement heard on either socket and its sender's address. Other datagrams
    /// are skipped.
    fn recv(&self) -> LanFuture<'_, (Announce, SocketAddr)> {
        Box::pin(async move {
            let mut b4 = [0u8; LEN + 1];
            let mut b6 = [0u8; LEN + 1];
            loop {
                let v6_first = self.turn.fetch_xor(true, std::sync::atomic::Ordering::Relaxed);
                let got = std::future::poll_fn(|cx| {
                    for v6 in [v6_first, !v6_first] {
                        let (sock, buf) = if v6 { (self.v6.as_ref(), &mut b6) } else { (Some(&self.v4), &mut b4) };
                        let Some(sock) = sock else { continue };
                        let mut r = tokio::io::ReadBuf::new(buf);
                        if let Poll::Ready(x) = sock.poll_recv_from(cx, &mut r) {
                            return Poll::Ready(x.map(|from| (r.filled().len(), from, v6)));
                        }
                    }
                    Poll::Pending
                })
                .await;
                // an error one datagram caused (an ICMP answer to an announcement, an oversized
                // datagram where the OS reports it) is skipped; any other ends the loop
                let (n, from, v6) = match got {
                    Ok(x) => x,
                    Err(e) if datagram_error(&e) => continue,
                    Err(e) => return Err(e.into()),
                };
                let buf = if v6 { &b6[..] } else { &b4[..] };
                if let Some(a) = buf.get(..n).and_then(Announce::decode) {
                    return Ok((a, from));
                }
            }
        })
    }

    /// Polls the routes' local addresses every `ROUTE_POLL` (`route_networks`): another network
    /// with the same addressing goes unseen; a P2P listener's registrations renew themselves
    /// after such a change once their relay connections time out. OS network events (netlink
    /// and the like) are not watched: no dependency for them.
    fn changed(&self) -> LanFuture<'_, ()> {
        Box::pin(async move {
            loop {
                tokio::time::sleep(ROUTE_POLL).await;
                let r = route_networks().await;
                let mut was = crate::util::lock(&self.route);
                if *was != r {
                    *was = r;
                    return Ok(());
                }
            }
        })
    }
}

/// Whether a UDP receive error belongs to one datagram, so the socket reads on: an ICMP answer
/// to something sent (reported as reset or refused) or a datagram larger than the buffer.
fn datagram_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{ConnectionRefused, ConnectionReset, Interrupted, WouldBlock};
    // "message too long": WSAEMSGSIZE, EMSGSIZE (Linux and Android; the BSDs)
    const EMSGSIZE: i32 = if cfg!(windows) { 10040 } else if cfg!(any(target_os = "linux", target_os = "android")) { 90 } else { 40 };
    matches!(e.kind(), ConnectionRefused | ConnectionReset | Interrupted | WouldBlock) || e.raw_os_error() == Some(EMSGSIZE)
}

/// The local IP addresses of the IPv4 and IPv6 routes to the internet, if any. No packet is sent.
pub async fn route_ips() -> (Option<IpAddr>, Option<IpAddr>) {
    async fn via(local: IpAddr, to: IpAddr) -> Option<IpAddr> {
        let s = tokio::net::UdpSocket::bind(SocketAddr::new(local, 0)).await.ok()?;
        // documentation prefixes (RFC 5737, RFC 3849): connecting a UDP socket only picks the route
        s.connect(SocketAddr::new(to, 9)).await.ok()?;
        s.local_addr().ok().map(|a| a.ip())
    }
    let v4 = via(IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).await;
    let v6 = via(IpAddr::V6(Ipv6Addr::UNSPECIFIED), IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))).await;
    (v4, v6)
}

/// What identifies the network the routes go out on: the IPv4 address, the IPv6 /64 prefix
/// (`network_of`); a change means another network.
async fn route_networks() -> (Option<IpAddr>, Option<IpAddr>) {
    let (v4, v6) = route_ips().await;
    (v4, v6.map(network_of))
}

/// How often `Lan::changed` looks at the routes' local addresses (minor: a change is seen this
/// much later; 0: a busy loop; unbounded: no fresh LAN key per network, and registrations renew
/// only at their relay connections' idle timeout).
pub const ROUTE_POLL: std::time::Duration = std::time::Duration::from_secs(5);

/// What identifies the network of a local address: an IPv4 address itself, an IPv6 address's
/// /64 prefix (its interface part may be a temporary address that rotates).
pub fn network_of(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v) => {
            let [a, b, c, d, ..] = v.segments();
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
        }
    }
}

/// Whether `ip` may be reached from other networks: none of unspecified, multicast, IPv4
/// broadcast, `is_local`, or IPv4 shared address space (100.64/10, carrier NAT).
pub fn is_global(ip: IpAddr) -> bool {
    let shared = matches!(ip, IpAddr::V4(v) if matches!(v.octets(), [100, b, ..] if b & 0xc0 == 64));
    let broadcast = matches!(ip, IpAddr::V4(v) if v.is_broadcast());
    !(ip.is_unspecified() || ip.is_multicast() || broadcast || shared || is_local(ip))
}

/// Whether `ip` can be a LAN neighbour's source address: loopback, private or link-local
/// (IPv4), unique-local or link-local (IPv6).
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_loopback() || v.is_private() || v.is_link_local(),
        IpAddr::V6(v) => {
            let first = v.segments().first().copied().unwrap_or(0);
            v.is_loopback() || first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::net::Ipv4Addr;

    // spec/sync-transport.md §4 (announcement): exactly 44 bytes, `"osis lan 2"`, the join's key,
    // the be16 port, nothing else; dialed at the sender's address and the announced port with
    // the announced key; any other datagram is ignored.
    #[test]
    fn announce_round_trip() {
        let a = Announce { key: [2; 32], port: 4433 };
        let b = a.encode();
        assert_eq!(b.len(), 44);
        assert_eq!(&b[..10], b"osis lan 2");
        assert_eq!(&b[10..42], &[2; 32]);
        assert_eq!(&b[42..], &4433u16.to_be_bytes());
        assert_eq!(Announce::decode(&b), Some(a));
        assert_eq!(Announce::decode(&b[..LEN - 1]), None);
        assert_eq!(Announce::decode(&[&b[..], &[0]].concat()), None);
        let mut bad = b;
        bad[9] = b'1';
        assert_eq!(Announce::decode(&bad), None);
        let addr = a.address("192.168.1.5:47380".parse().unwrap());
        assert_eq!(addr, Address { url: "peer://192.168.1.5:4433".into(), key: [2; 32] });
        // an IPv6 link-local source keeps its interface, and the URL item parses back
        let addr = a.address("[fe80::1%3]:47380".parse().unwrap());
        assert_eq!(addr.url, "peer://[fe80::1%3]:4433");
        let back: SocketAddr = "[fe80::1%3]:4433".parse().unwrap();
        assert!(matches!(back, SocketAddr::V6(v) if v.scope_id() == 3));
    }

    // spec/sync-transport.md §4 (a receiver ignores; dialing): a source that cannot be on the LAN
    // and the join's own key are ignored; each other key is dialed once while remembered; a new
    // join dials it again; a join with nothing to remember dials every announcement.
    #[test]
    fn heard_once_per_join() {
        let mut j = Joined::new(Some([1; 32]), 4);
        let other = Announce { key: [2; 32], port: 9 };
        let from: SocketAddr = "192.168.1.5:47380".parse().unwrap();
        assert_eq!(j.heard(&Announce { key: [1; 32], port: 9 }, from), None, "own key");
        assert_eq!(j.heard(&other, "8.8.8.8:47380".parse().unwrap()), None, "not on the LAN");
        assert_eq!(j.heard(&other, from), Some(Address { url: "peer://192.168.1.5:9".into(), key: [2; 32] }));
        assert_eq!(j.heard(&other, "10.0.0.7:47380".parse().unwrap()), None, "once per join");
        let mut j = Joined::new(Some([4; 32]), 4);
        assert!(j.heard(&other, from).is_some(), "a new join dials it again");
        assert!(Joined::new(None, 4).heard(&other, from).is_some(), "a join without a listener still dials");
    }

    // spec/sync-transport.md §4: IPv6 announcements go to the all-nodes group on every link the machine is
    // on, each send naming its interface; with no interface known, out the default one.
    #[test]
    fn v6_targets_per_interface_spec_sync_10() {
        let proc = "00000000000000000000000000000001 01 80 10 80       lo\n\
                    20010db8000000000000000000000005 02 40 00 00     eth0\n\
                    fe800000000000000000000000000001 02 40 20 80     eth0\n\
                    fe800000000000000000000000000002 0a 40 20 80    wlan0\n\
                    fe800000000000000000000000000003 0a 40 20 80    wlan0\n\
                    fd000000000000000000000000000001 0b 40 00 00      vpn\n\
                    garbage\n";
        let addrs = if_inet6(proc);
        assert_eq!(addrs.len(), 6);
        assert_eq!(addrs[2], ("fe80::1".parse().unwrap(), 2));
        let scopes = link_scopes(addrs);
        assert_eq!(scopes, vec![2, 10]);
        let t = targets(multicast(PORT), &scopes);
        assert_eq!(t, vec![multicast_on(PORT, 2), multicast_on(PORT, 10)]);
        assert!(t.iter().all(|a| matches!(a, SocketAddr::V6(v) if *v.ip() == ALL_NODES && v.port() == PORT)));
        assert_eq!(t[1].to_string(), "[ff02::1%10]:47380");
        assert_eq!(targets(multicast(PORT), &[]), vec![multicast(PORT)]);
        // a scoped group, the IPv4 broadcast and one address go as they are
        for to in [multicast_on(PORT, 7), broadcast(PORT), "[fe80::9%2]:5".parse().unwrap()] {
            assert_eq!(targets(to, &scopes), vec![to]);
        }
    }

    // spec/sync-transport.md §4: only addresses that can be on the LAN are heard.
    #[test]
    fn local_sources_spec_sync_10() {
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.9", "169.254.1.1", "::1", "fd00::1", "fe80::1"] {
            assert!(is_local(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "100.64.0.1", "2001:db8::1", "ff02::1"] {
            assert!(!is_local(ip.parse().unwrap()), "{ip}");
        }
    }

    // spec/sync-transport.md §4: an announcement sent over UDP is heard (by hand: localhost socket).
    #[tokio::test]
    #[ignore]
    async fn announce_over_udp_spec_sync_10() {
        let rx = Lan::bind(0).await.unwrap();
        let tx = Lan::bind(0).await.unwrap();
        let a = Announce { key: [4; 32], port: 9 };
        tx.announce(&a, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rx.port())).await.unwrap();
        let (got, from) = rx.recv().await.unwrap();
        assert_eq!(got, a);
        assert!(from.ip().is_loopback());
        // and over IPv6 on the same port (spec/sync-transport.md §4: both families)
        if rx.has_v6() && tx.has_v6() {
            tx.announce(&a, SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), rx.port())).await.unwrap();
            let (got, from) = rx.recv().await.unwrap();
            assert_eq!(got, a);
            assert!(from.is_ipv6() && from.ip().is_loopback());
        }
    }

    // spec/sync-transport.md §4: two nodes on one machine both bind the announcement port and both hear
    // a broadcast to it (by hand: real sockets).
    #[tokio::test]
    #[ignore]
    async fn two_nodes_share_the_port_spec_sync_10() {
        let a = Lan::bind(0).await.unwrap();
        let b = Lan::bind(a.port()).await.unwrap();
        let tx = Lan::bind(0).await.unwrap();
        let msg = Announce { key: [8; 32], port: 7 };
        tx.announce(&msg, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255)), a.port())).await.unwrap();
        for s in [&a, &b] {
            let (got, _) = tokio::time::timeout(std::time::Duration::from_secs(5), s.recv()).await.unwrap().unwrap();
            assert_eq!(got, msg);
        }
    }

    // spec/sync-transport.md §4: an announcement to the all-nodes group goes out every IPv6 link, each
    // send naming its interface (a scope no interface has fails); copies looped back are heard
    // from that link's address (by hand: real sockets and interfaces; a machine whose firewall drops
    // multicast, as the dev VM's, hears none, so hearing is checked only when something comes).
    // The one test that sends on the real network (every real link is its point), to a free port no
    // node listens on; run it through tools/heavy with the networking check (notes/testing.md, By hand).
    #[tokio::test]
    #[ignore]
    async fn announce_v6_every_interface_spec_sync_10() {
        let rx = Lan::bind(0).await.unwrap();
        let tx = Lan::bind(0).await.unwrap();
        let scopes = v6_scopes().await;
        if !rx.has_v6() || scopes.is_empty() {
            return;
        }
        let a = Announce { key: [7; 32], port: 9 };
        for sc in &scopes {
            tx.announce(&a, multicast_on(rx.port(), *sc)).await.unwrap();
        }
        assert!(tx.announce(&a, multicast_on(rx.port(), 999_999)).await.is_err());
        tx.announce(&a, multicast(rx.port())).await.unwrap();
        let mut heard = std::collections::BTreeSet::new();
        while let Ok(r) = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await {
            let (got, from) = r.unwrap();
            assert_eq!(got, a);
            let SocketAddr::V6(v) = from else { panic!("{from}") };
            assert!(is_local(from.ip()));
            heard.insert(v.scope_id());
        }
        assert!(heard.iter().all(|s| scopes.contains(s)), "{heard:?} {scopes:?}");
    }

    // spec/sync-transport.md §4 (joining): a socket's network watch starts and polls the routes
    // (by hand: real sockets).
    #[tokio::test]
    #[ignore]
    async fn net_watch_starts_spec_sync_10() {
        let l = Lan::bind(0).await.unwrap();
        // nothing changes here within a short wait
        assert!(tokio::time::timeout(std::time::Duration::from_millis(200), l.changed()).await.is_err());
    }
}
