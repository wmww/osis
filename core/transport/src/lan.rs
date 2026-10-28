//! LAN announcements (spec/sync.md §10; the sockets with feature `lan`): a UDP datagram carrying
//! the node's current LAN tag, the transport key it listens with on this network (fresh per
//! network join, never the dialable key), that listener's port on the datagram's address family
//! and a signature under the node's dialable key binding the three, sealed under the lan secret
//! and window; broadcast on the IPv4 LAN, multicast to the IPv6 all-nodes group. A receiver that
//! knows the tag's lan secret and the node's dialable key checks the signature and dials
//! `peer://<sender address>:<port>` with the announced key. Not mDNS: the announcement carries
//! nothing stable across windows or networks, nor anything a holder of the dialable key alone
//! can check. Tag and signature are made and checked by the node (osis-crypto `seal_lan_sig`).
//! `NetWatch` tells a network change (the node then joins with a fresh key).
//!
//! Datagram (spec/sync.md §10, provisional): `"osis lan 1"` (10 bytes), tag (16), key (32),
//! port (2, big-endian), signature (64).

use crate::{Address, PublicKey};
#[cfg(feature = "lan")]
use crate::Error;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
#[cfg(feature = "lan")]
use std::net::Ipv4Addr;
#[cfg(feature = "lan")]
use std::task::Poll;

const MAGIC: &[u8; 10] = b"osis lan 1";
/// Datagram length.
pub const LEN: usize = 10 + 16 + 32 + 2 + 64;
/// Default UDP port announcements go to (provisional).
pub const PORT: u16 = 47_380;

/// Where IPv4 announcements are sent: the limited broadcast address at `port`.
pub fn broadcast(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::BROADCAST), port)
}

/// The IPv6 link-local all-nodes group.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Where IPv6 announcements are sent: the all-nodes group at `port`, no interface named
/// (`Lan::announce` sends it on every interface, `targets`).
pub fn multicast(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(ALL_NODES), port)
}

/// The all-nodes group at `port` on the interface with index `scope`.
pub fn multicast_on(port: u16, scope: u32) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(ALL_NODES, port, 0, scope))
}

/// Where an announcement to `to` goes: the all-nodes group with no interface named goes to it
/// on each interface of `scopes` (spec/sync.md §10: every link the host is on), or out the
/// default multicast interface when there is none; any other address as it is.
pub fn targets(to: SocketAddr, scopes: &[u32]) -> Vec<SocketAddr> {
    match to {
        SocketAddr::V6(v) if *v.ip() == ALL_NODES && v.scope_id() == 0 && !scopes.is_empty() => scopes.iter().map(|s| multicast_on(v.port(), *s)).collect(),
        _ => vec![to],
    }
}

/// The interfaces IPv6 announcements go out on, from (up, IPv6 addresses with their scope IDs)
/// per interface: the scope (interface index) of each up interface's link-local addresses,
/// sorted, once each. Loopback has none.
pub fn link_scopes(ifaces: impl IntoIterator<Item = (bool, Vec<(Ipv6Addr, u32)>)>) -> Vec<u32> {
    let mut out: Vec<u32> = ifaces
        .into_iter()
        .filter(|(up, _)| *up)
        .flat_map(|(_, addrs)| addrs.into_iter().filter(|(ip, scope)| *scope != 0 && ip.segments().first().is_some_and(|f| f & 0xffc0 == 0xfe80)).map(|(_, scope)| scope))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The host's interfaces for IPv6 announcements now (`link_scopes` over netwatch's list).
#[cfg(feature = "lan")]
pub async fn v6_scopes() -> Vec<u32> {
    let st = netwatch::interfaces::State::new().await;
    link_scopes(st.interfaces.values().map(|i| {
        let v6 = i.addrs().filter_map(|a| match a {
            netwatch::interfaces::IpNet::V6 { net, scope_id, .. } => Some((net.addr(), scope_id)),
            netwatch::interfaces::IpNet::V4(_) => None,
        });
        (i.is_up(), v6.collect())
    }))
}

/// One announcement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Announce {
    pub tag: [u8; 16],
    pub key: PublicKey,
    pub port: u16,
    /// The sealed Ed25519 signature under the announcer's dialable key (spec/sync.md §10).
    pub sig: [u8; 64],
}

impl Announce {
    pub fn encode(&self) -> [u8; LEN] {
        let mut b = [0u8; LEN];
        let parts: [&[u8]; 5] = [MAGIC, &self.tag, &self.key, &self.port.to_be_bytes(), &self.sig];
        let mut at = 0;
        for p in parts {
            if let Some(d) = b.get_mut(at..at + p.len()) {
                d.copy_from_slice(p);
            }
            at += p.len();
        }
        b
    }

    /// None for anything but an announcement of this version.
    pub fn decode(b: &[u8]) -> Option<Announce> {
        if b.len() != LEN {
            return None;
        }
        let rest = b.strip_prefix(&MAGIC[..])?;
        let (tag, rest) = rest.split_first_chunk::<16>()?;
        let (key, rest) = rest.split_first_chunk::<32>()?;
        let (port, rest) = rest.split_first_chunk::<2>()?;
        let sig = rest.first_chunk::<64>()?;
        Some(Announce { tag: *tag, key: *key, port: u16::from_be_bytes(*port), sig: *sig })
    }

    /// The signed bytes: tag || key || port (be16).
    pub fn signed(&self) -> [u8; 50] {
        let mut b = [0u8; 50];
        let (t, rest) = b.split_at_mut(16);
        let (k, p) = rest.split_at_mut(32);
        t.copy_from_slice(&self.tag);
        k.copy_from_slice(&self.key);
        p.copy_from_slice(&self.port.to_be_bytes());
        b
    }

    /// Where to dial the announcer, given the datagram's source address (an IPv6 link-local
    /// source keeps its interface scope).
    pub fn address(&self, from: SocketAddr) -> Address {
        let mut at = from;
        at.set_port(self.port);
        Address { url: crate::peer_url(&[at.to_string()]), key: self.key }
    }
}

/// UDP sockets sending and receiving announcements (feature `lan`): IPv4 (broadcast) and, where
/// the host has IPv6, IPv6 (all-nodes multicast).
#[cfg(feature = "lan")]
pub struct Lan {
    v4: tokio::net::UdpSocket,
    v6: Option<tokio::net::UdpSocket>,
    port: u16,
    /// Which socket `recv` looks at first (alternates, so a flood on one starves neither).
    turn: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "lan")]
fn io(e: std::io::Error) -> Error {
    Error::Io(e.to_string())
}

/// An IPv6-only UDP socket at `port`, in the all-nodes group.
#[cfg(feature = "lan")]
fn bind_v6(port: u16) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    // beside the IPv4 socket of the same port
    s.set_only_v6(true)?;
    s.set_nonblocking(true)?;
    s.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
    // hosts are in the group anyway; joining makes delivery explicit where that matters
    let _ = s.join_multicast_v6(&ALL_NODES, 0);
    tokio::net::UdpSocket::from_std(s.into())
}

#[cfg(feature = "lan")]
impl Lan {
    /// Binds the announcement port on all IPv4 interfaces and, when the host has IPv6, on all
    /// IPv6 interfaces (`port` 0: any, for tests; IPv6 then takes the port IPv4 got).
    pub async fn bind(port: u16) -> Result<Lan, Error> {
        let v4 = tokio::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)).await.map_err(io)?;
        v4.set_broadcast(true).map_err(io)?;
        let port = v4.local_addr().map_err(io)?.port();
        Ok(Lan { v4, v6: bind_v6(port).ok(), port, turn: Default::default() })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether IPv6 announcements go out and are heard.
    pub fn has_v6(&self) -> bool {
        self.v6.is_some()
    }

    /// Sends an announcement to `to` (the broadcast address or the all-nodes group at the
    /// announcement port, or one host) on the socket of its family. The all-nodes group with no
    /// interface named goes out every up interface with IPv6, each with its scope (`targets`,
    /// `v6_scopes`, looked up at each call: interfaces come and go); if every one of those
    /// sends fails, it goes out the default multicast interface. The socket joins the group on
    /// each of those interfaces at each call ("already joined" ignored): Linux delivers to it
    /// anyway (`IPV6_MULTICAST_ALL`), BSD stacks only on interfaces it joined, and interfaces
    /// come and go under one socket.
    pub async fn announce(&self, a: &Announce, to: SocketAddr) -> Result<(), Error> {
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
                Err(e) => res = Err(io(e)),
            }
        }
        if !sent && !scopes.is_empty() {
            res = s.send_to(&bytes, to).await.map(|_| ()).map_err(io);
            sent = res.is_ok();
        }
        if sent { Ok(()) } else { res }
    }

    /// The next announcement heard on either socket and its sender's address. Other datagrams,
    /// and announcements from addresses that cannot be on the LAN (`is_local`), are skipped.
    pub async fn recv(&self) -> Result<(Announce, SocketAddr), Error> {
        let mut b4 = [0u8; LEN + 1];
        let mut b6 = [0u8; LEN + 1];
        loop {
            let v6_first = self.turn.fetch_xor(true, std::sync::atomic::Ordering::Relaxed);
            let (n, from, v6) = std::future::poll_fn(|cx| {
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
            .await
            .map_err(io)?;
            if !is_local(from.ip()) {
                continue;
            }
            let buf = if v6 { &b6[..] } else { &b4[..] };
            if let Some(a) = buf.get(..n).and_then(Announce::decode) {
                return Ok((a, from));
            }
        }
    }
}

/// The local IP address of the IPv4 route to the internet and the /64 prefix of the IPv6 one,
/// if any: a change means another network. No packet is sent.
#[cfg(feature = "lan")]
pub async fn route_ip() -> (Option<IpAddr>, Option<IpAddr>) {
    async fn via(local: IpAddr, to: IpAddr) -> Option<IpAddr> {
        let s = tokio::net::UdpSocket::bind(SocketAddr::new(local, 0)).await.ok()?;
        // documentation prefixes (RFC 5737, RFC 3849): connecting a UDP socket only picks the route
        s.connect(SocketAddr::new(to, 9)).await.ok()?;
        s.local_addr().ok().map(|a| a.ip())
    }
    let v4 = via(IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).await;
    let v6 = via(IpAddr::V6(Ipv6Addr::UNSPECIFIED), IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))).await;
    (v4, v6.map(network_of))
}

/// How often `NetWatch` looks at the routes' local addresses (provisional).
#[cfg(feature = "lan")]
pub const ROUTE_POLL: std::time::Duration = std::time::Duration::from_secs(5);

/// Tells network changes (feature `lan`): the routes' local addresses, polled every
/// `ROUTE_POLL`, and with feature `iroh` also iroh's netwatch (interface, address and route
/// events from the OS, and waking from sleep): the default route's interface, whether it is up,
/// its addresses, or a wake changed. Joining another network that keeps the same addressing is
/// seen through netwatch only (the interface goes down and up), or not at all where its OS
/// events are missing.
#[cfg(feature = "lan")]
pub struct NetWatch {
    route: (Option<IpAddr>, Option<IpAddr>),
    /// netwatch's changes, and the task owning its monitor.
    events: Option<tokio::sync::mpsc::Receiver<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

#[cfg(feature = "lan")]
impl Drop for NetWatch {
    fn drop(&mut self) {
        if let Some(t) = &self.task {
            t.abort();
        }
    }
}

#[cfg(feature = "lan")]
impl NetWatch {
    /// Starts watching (needs a tokio runtime); the current network is the baseline.
    pub async fn new() -> NetWatch {
        let route = route_ip().await;
        #[cfg(feature = "iroh")]
        if let Some((rx, t)) = netwatch_events().await {
            return NetWatch { route, events: Some(rx), task: Some(t) };
        }
        NetWatch { route, events: None, task: None }
    }

    /// Whether OS network events are watched (feature `iroh`), not only the routes polled.
    pub fn has_events(&self) -> bool {
        self.events.is_some()
    }

    /// Resolves at the next network change.
    pub async fn changed(&mut self) {
        loop {
            // Some(event) from netwatch (None inside: it ended), None: the poll is due
            let ev = match &mut self.events {
                Some(rx) => tokio::time::timeout(ROUTE_POLL, rx.recv()).await.ok(),
                None => {
                    tokio::time::sleep(ROUTE_POLL).await;
                    None
                }
            };
            match ev {
                Some(Some(())) => {
                    self.route = route_ip().await;
                    return;
                }
                // the monitor ended: polling only
                Some(None) => self.events = None,
                None => {
                    let r = route_ip().await;
                    if r != self.route {
                        self.route = r;
                        return;
                    }
                }
            }
        }
    }
}

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

/// netwatch's state changes that matter for the LAN: the default route's interface, its being
/// up and its addresses, and wakes from sleep.
#[cfg(all(feature = "lan", feature = "iroh"))]
async fn netwatch_events() -> Option<(tokio::sync::mpsc::Receiver<()>, tokio::task::JoinHandle<()>)> {
    use iroh::Watcher;
    let mon = netwatch::netmon::Monitor::new().await.ok()?;
    let mut w = mon.interface_state();
    let print = |s: &netwatch::netmon::State| {
        let iface = s.default_route_interface.as_ref().and_then(|n| s.interfaces.get(n));
        // IPv6 by /64 prefix: temporary (privacy) addresses rotate within one network
        let mut addrs: Vec<IpAddr> = iface.map(|i| i.addrs().map(|a| network_of(a.addr())).collect()).unwrap_or_default();
        addrs.sort();
        addrs.dedup();
        (s.default_route_interface.clone(), iface.map(|i| i.is_up()), addrs, s.last_unsuspend)
    };
    let mut last = print(&w.get());
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move {
        let _mon = mon;
        while let Ok(s) = w.updated().await {
            let now = print(&s);
            if now != last {
                last = now;
                // one pending change is enough
                if let Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) = tx.try_send(()) {
                    return;
                }
            }
        }
    });
    Some((rx, task))
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
    #[cfg(feature = "lan")]
    use std::net::Ipv4Addr;

    // spec/sync.md §10: an announcement carries the tag and a transport key, and is dialed at
    // the sender's address with that key; anything else is ignored.
    #[test]
    fn announce_round_trip_spec_sync_10() {
        let a = Announce { tag: [1; 16], key: [2; 32], port: 4433, sig: [3; 64] };
        let b = a.encode();
        assert_eq!(Announce::decode(&b), Some(a));
        assert_eq!(Announce::decode(&b[..LEN - 1]), None);
        let mut bad = b;
        bad[0] ^= 1;
        assert_eq!(Announce::decode(&bad), None);
        let addr = a.address("192.168.1.5:47380".parse().unwrap());
        assert_eq!(addr, Address { url: "peer://192.168.1.5:4433".into(), key: [2; 32] });
        // an IPv6 link-local source keeps its interface, and the URL item parses back
        let addr = a.address("[fe80::1%3]:47380".parse().unwrap());
        assert_eq!(addr.url, "peer://[fe80::1%3]:4433");
        let back: SocketAddr = "[fe80::1%3]:4433".parse().unwrap();
        assert!(matches!(back, SocketAddr::V6(v) if v.scope_id() == 3));
        assert_eq!(&b[..10], b"osis lan 1");
        assert_eq!(b.len(), 124);
        assert_eq!(&b[LEN - 66..LEN - 64], &4433u16.to_be_bytes());
        assert_eq!(&b[LEN - 64..], &[3; 64]);
        assert_eq!(&a.signed()[..16], &[1; 16]);
        assert_eq!(&a.signed()[48..], &4433u16.to_be_bytes());
    }

    // spec/sync.md §10: IPv6 announcements go to the all-nodes group on every link the host is
    // on, each send naming its interface; with no interface known, out the default one.
    #[test]
    fn v6_targets_per_interface_spec_sync_10() {
        let ll = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        let ifaces = vec![
            (true, vec![(ll("::1"), 0)]),
            (true, vec![(ll("2001:db8::5"), 0), (ll("fe80::1"), 2)]),
            (true, vec![(ll("fe80::2"), 3), (ll("fe80::3"), 3)]),
            (false, vec![(ll("fe80::4"), 4)]),
            (true, vec![(ll("fd00::1"), 0)]),
        ];
        let scopes = link_scopes(ifaces);
        assert_eq!(scopes, vec![2, 3]);
        let t = targets(multicast(PORT), &scopes);
        assert_eq!(t, vec![multicast_on(PORT, 2), multicast_on(PORT, 3)]);
        assert!(t.iter().all(|a| matches!(a, SocketAddr::V6(v) if *v.ip() == ALL_NODES && v.port() == PORT)));
        assert_eq!(t[1].to_string(), "[ff02::1%3]:47380");
        assert_eq!(targets(multicast(PORT), &[]), vec![multicast(PORT)]);
        // a scoped group, the IPv4 broadcast and one host go as they are
        for to in [multicast_on(PORT, 7), broadcast(PORT), "[fe80::9%2]:5".parse().unwrap()] {
            assert_eq!(targets(to, &scopes), vec![to]);
        }
    }

    // spec/sync.md §10: only addresses that can be on the LAN are heard.
    #[test]
    fn local_sources_spec_sync_10() {
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.9", "169.254.1.1", "::1", "fd00::1", "fe80::1"] {
            assert!(is_local(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "100.64.0.1", "2001:db8::1", "ff02::1"] {
            assert!(!is_local(ip.parse().unwrap()), "{ip}");
        }
    }

    // spec/sync.md §10: an announcement sent over UDP is heard (tier 2: localhost socket).
    #[cfg(feature = "lan")]
    #[tokio::test]
    #[ignore]
    async fn announce_over_udp_spec_sync_10() {
        let rx = Lan::bind(0).await.unwrap();
        let tx = Lan::bind(0).await.unwrap();
        let a = Announce { tag: [3; 16], key: [4; 32], port: 9, sig: [5; 64] };
        tx.announce(&a, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rx.port())).await.unwrap();
        let (got, from) = rx.recv().await.unwrap();
        assert_eq!(got, a);
        assert!(from.ip().is_loopback());
        // and over IPv6 on the same port (spec/sync.md §10: both families)
        if rx.has_v6() && tx.has_v6() {
            tx.announce(&a, SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), rx.port())).await.unwrap();
            let (got, from) = rx.recv().await.unwrap();
            assert_eq!(got, a);
            assert!(from.is_ipv6() && from.ip().is_loopback());
        }
    }

    // spec/sync.md §10: an announcement to the all-nodes group goes out every IPv6 link, each
    // send naming its interface (a scope no interface has fails); copies looped back are heard
    // from that link's address (tier 2: real sockets and interfaces; a host whose firewall drops
    // multicast, as the dev VM's, hears none, so hearing is checked only when something comes).
    #[cfg(feature = "lan")]
    #[tokio::test]
    #[ignore]
    async fn announce_v6_every_interface_spec_sync_10() {
        let rx = Lan::bind(0).await.unwrap();
        let tx = Lan::bind(0).await.unwrap();
        let scopes = v6_scopes().await;
        if !rx.has_v6() || scopes.is_empty() {
            return;
        }
        let a = Announce { tag: [6; 16], key: [7; 32], port: 9, sig: [8; 64] };
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

    // spec/sync.md §10: a network watch starts and polls without OS events where it has none
    // (tier 2: real sockets and interfaces).
    #[cfg(feature = "lan")]
    #[tokio::test]
    #[ignore]
    async fn net_watch_starts_spec_sync_10() {
        let mut w = NetWatch::new().await;
        assert_eq!(w.has_events(), cfg!(all(feature = "iroh", target_os = "linux")));
        // nothing changes here within a short wait
        assert!(tokio::time::timeout(std::time::Duration::from_millis(200), w.changed()).await.is_err());
    }
}
