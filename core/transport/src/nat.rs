//! The NAT model of `InProcess` (a test network; spec: none): hosts with IP addresses, some
//! behind NATs (RFC 4787 mapping and filtering behaviour), and UDP sockets (`MemUdp`, `MemSock`)
//! whose dials, accepts and hole punches pass through them, for `p2p` over the in-process net.
//!
//! A dial is a packet from a socket to an address, resent every `RESEND_MS` until it reaches a
//! socket that accepts connections or the net's give-up passes (`DIAL_MS` unless
//! `Net::set_dial_ms`; QUIC's retransmission and idle timeout);
//! the first packet that arrives makes the connection, which then carries data both ways (the
//! reply goes back through the mapping the packet came in on). A punch is one packet, kept by
//! nobody. NAT mappings never expire; two hosts behind one NAT reach each other only at their
//! own addresses (no hairpinning). Streams per connection are limited as `QuicUdp` limits them
//! (`p2p::dialer_limits`). Model time is the net's steps, one per millisecond.
//!
//! A LAN segment is a broadcast domain a host joins at an address of its own there
//! (`MemUdp::on_lan`, several for a host on several links): an announcement socket (`MemLan`)
//! delivers one sent to the broadcast address or the all-nodes group to every socket at that
//! port on each segment the sender is on, showing the sender's address there, subject to the
//! segment's loss (`Net::set_lan_loss`). Packets between two hosts' addresses on a shared
//! segment pass directly, whatever NATs they are behind.

use crate::mem::{MemConn, Net, State};
use crate::p2p::{Alpn, Sock, Udp as UdpT};
use crate::lan::{Announce, LanFuture, LanSocket, ALL_NODES};
use crate::{Error, PublicKey, StaticSecret};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::{poll_fn, Future};
use std::net::{IpAddr, SocketAddr};
use std::task::{Poll, Waker};

/// What a NAT's mappings or filters depend on besides the inside socket (RFC 4787 §4.1, §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dep {
    /// Nothing: one mapping per inside socket; any outside address may send to it.
    Endpoint,
    /// The remote IP address.
    Address,
    /// The remote IP address and port.
    AddressPort,
}

/// A NAT's behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nat {
    pub mapping: Dep,
    pub filtering: Dep,
}

impl Nat {
    /// Endpoint-independent mapping, address-and-port-dependent filtering (port-restricted
    /// cone): hole punching gets through.
    pub const CONE: Nat = Nat { mapping: Dep::Endpoint, filtering: Dep::AddressPort };
    /// Address-dependent mapping and filtering.
    pub const ADDRESS: Nat = Nat { mapping: Dep::Address, filtering: Dep::Address };
    /// A new mapping per remote address and port (symmetric): hole punching fails against
    /// another filtering NAT.
    pub const SYMMETRIC: Nat = Nat { mapping: Dep::AddressPort, filtering: Dep::AddressPort };
}

/// Whether a punch between a dialer and a target (`None`: no NAT) ends in a direct connection
/// (spec/sync.md §10): the dialer sends to the address the target's NAT showed the relay while
/// the target punches back to the one the dialer's NAT showed it. The observed port is the
/// relay's mapping. A filter open to any source lets the packet through; a filter that lets in
/// only sources the mapping sent to needs the target's punch to leave on that same port
/// (mapping independent of the remote), and, filtering by port too, the dialer's packet to show
/// the port the target punched to. The one rule of the punch; the packet machine below enforces
/// it (`punch_rule_matches_the_packet_machine`) and `osis_sim::reach` applies it.
pub fn punch_opens(dialer: Option<Nat>, target: Option<Nat>) -> bool {
    let Some(t) = target else { return true };
    match t.filtering {
        Dep::Endpoint => true,
        Dep::Address => t.mapping == Dep::Endpoint,
        Dep::AddressPort => t.mapping == Dep::Endpoint && dialer.is_none_or(|d| d.mapping == Dep::Endpoint),
    }
}

/// Model constants (minor: they only shape test timing). A dial's packet is resent this often...
pub const RESEND_MS: u64 = 100;
/// ...until this long has passed: QUIC's idle timeout, which ends a silent handshake.
pub const DIAL_MS: u64 = crate::quic::IDLE_TIMEOUT.as_secs() * 1000;

/// The model's hosts, NATs and bound sockets.
#[derive(Default)]
pub(crate) struct Udp {
    hosts: BTreeMap<IpAddr, Host>,
    nats: BTreeMap<IpAddr, NatState>,
    socks: BTreeMap<SocketAddr, Entry>,
    /// Announcement sockets, by host and port.
    lan_socks: BTreeMap<SocketAddr, LanEntry>,
    /// Per segment: percent of deliveries lost (`Net::set_lan_loss`), and how many were.
    lan_loss: BTreeMap<String, (u64, u64)>,
    /// `Net::set_dial_ms`; `None`: `DIAL_MS`.
    dial_ms: Option<u64>,
}

struct Host {
    /// The NAT the host is behind, by its public address.
    nat: Option<IpAddr>,
    /// The LAN segments it is on and its address on each.
    lans: BTreeMap<String, IpAddr>,
}

/// A bound announcement socket: its endpoint (for partitions and `kill`), what it heard.
struct LanEntry {
    id: u64,
    endpoint: String,
    heard: VecDeque<(Announce, SocketAddr)>,
    waker: Option<Waker>,
}

/// A bound socket: its endpoint (for partitions), the key it accepts with (none: dials only),
/// and connections that reached it, not yet accepted (connection id, ALPN, where it came from).
struct Entry {
    id: u64,
    endpoint: String,
    key: Option<PublicKey>,
    queue: VecDeque<(u64, Alpn, SocketAddr)>,
    waker: Option<Waker>,
}

struct NatState {
    nat: Nat,
    /// Public port per (inside socket, remote as far as the mapping depends on it).
    ports: BTreeMap<(SocketAddr, Option<SocketAddr>), u16>,
    back: BTreeMap<u16, SocketAddr>,
    /// (public port, remote) pairs packets went out to: what the filter lets back in.
    out: BTreeSet<(u16, SocketAddr)>,
    next: u16,
}

impl NatState {
    /// The public port a packet from inside socket `from` to `to` leaves on.
    fn out(&mut self, from: SocketAddr, to: SocketAddr) -> u16 {
        let k = match self.nat.mapping {
            Dep::Endpoint => None,
            Dep::Address => Some(SocketAddr::new(to.ip(), 0)),
            Dep::AddressPort => Some(to),
        };
        let p = match self.ports.get(&(from, k)) {
            Some(p) => *p,
            None => {
                self.next = self.next.wrapping_add(1).max(1024);
                self.ports.insert((from, k), self.next);
                self.back.insert(self.next, from);
                self.next
            }
        };
        self.out.insert((p, to));
        p
    }

    /// The inside socket a packet from `src` to public port `port` reaches, if the filter lets it.
    fn inbound(&self, port: u16, src: SocketAddr) -> Option<SocketAddr> {
        let inside = *self.back.get(&port)?;
        let ok = match self.nat.filtering {
            Dep::Endpoint => true,
            Dep::Address => self.out.iter().any(|(p, r)| *p == port && r.ip() == src.ip()),
            Dep::AddressPort => self.out.contains(&(port, src)),
        };
        ok.then_some(inside)
    }
}

impl Udp {
    /// On a segment host `from` is on: the host whose address there is `to`, and `from`'s address
    /// there.
    fn on_lan(&self, from: IpAddr, to: IpAddr) -> Option<(IpAddr, IpAddr)> {
        let mine = &self.hosts.get(&from)?.lans;
        self.hosts.iter().find_map(|(ip, h)| h.lans.iter().find(|(_, a)| **a == to).and_then(|(s, _)| Some((*ip, *mine.get(s)?))))
    }

    /// Where a packet from socket `from` to `to` arrives and the source it shows there; `None`:
    /// dropped. Records the NAT state it passes.
    fn route(&mut self, from: SocketAddr, to: SocketAddr) -> Option<(SocketAddr, SocketAddr)> {
        if let Some((host, src)) = self.on_lan(from.ip(), to.ip()) {
            return Some((SocketAddr::new(host, to.port()), SocketAddr::new(src, from.port())));
        }
        let mine = self.hosts.get(&from.ip())?.nat;
        let leave = |u: &mut Udp| match mine {
            Some(n) => u.nats.get_mut(&n).map(|s| SocketAddr::new(n, s.out(from, to))),
            None => Some(from),
        };
        if let Some(h) = self.hosts.get(&to.ip()) {
            return match (mine, h.nat) {
                (a, Some(b)) if a == Some(b) => Some((to, from)),
                (_, Some(_)) => None,
                (_, None) => leave(self).map(|src| (to, src)),
            };
        }
        if !self.nats.contains_key(&to.ip()) || mine == Some(to.ip()) {
            return None;
        }
        let src = leave(self)?;
        let inside = self.nats.get(&to.ip())?.inbound(to.port(), src)?;
        Some((inside, src))
    }
}

impl State {
    /// Closes the sockets of endpoint `a`.
    pub(crate) fn kill_socks(&mut self, a: &str) {
        let at: Vec<SocketAddr> = self.udp.socks.iter().filter(|(_, e)| e.endpoint == a).map(|(s, _)| *s).collect();
        for s in at {
            self.unbind(s, None);
        }
        let at: Vec<SocketAddr> = self.udp.lan_socks.iter().filter(|(_, e)| e.endpoint == a).map(|(s, _)| *s).collect();
        for s in at {
            self.lan_unbind(s, None);
        }
    }

    /// Removes announcement socket `at` (if `id` matches) and wakes its receiver.
    fn lan_unbind(&mut self, at: SocketAddr, id: Option<u64>) {
        if self.udp.lan_socks.get(&at).is_some_and(|e| id.is_none_or(|i| i == e.id))
            && let Some(mut e) = self.udp.lan_socks.remove(&at)
            && let Some(w) = e.waker.take()
        {
            w.wake();
        }
    }

    /// Delivers an announcement from the host at `from` to `to` on each segment it is on.
    fn lan_send(&mut self, name: &str, from: SocketAddr, a: &Announce, to: SocketAddr) {
        let Some(host) = self.udp.hosts.get(&from.ip()) else { return };
        let every = to.ip() == IpAddr::V4(std::net::Ipv4Addr::BROADCAST) || to.ip() == IpAddr::V6(ALL_NODES);
        let mut to_each = Vec::new();
        for (seg, own) in host.lans.iter().filter(|(_, own)| own.is_ipv6() == to.is_ipv6()) {
            for (at, h) in self.udp.lan_socks.keys().filter(|s| s.port() == to.port()).filter_map(|s| Some((*s, self.udp.hosts.get(&s.ip())?))) {
                // broadcast and multicast stop at the segment; one address is routed to
                let reached = if every { h.lans.get(seg).is_some_and(|a| a.is_ipv6() == to.is_ipv6()) } else { h.lans.values().any(|a| *a == to.ip()) };
                if reached {
                    to_each.push((seg.clone(), at, SocketAddr::new(*own, from.port())));
                }
            }
            // one address is sent once, from the first segment
            if !every && !to_each.is_empty() {
                break;
            }
        }
        for (seg, at, src) in to_each {
            let endpoint = self.udp.lan_socks.get(&at).map(|e| e.endpoint.clone()).unwrap_or_default();
            let loss = self.udp.lan_loss.get(&seg).map_or(0, |l| l.0);
            let lost = loss > 0 && self.rng().below(100) < loss;
            if lost && let Some(l) = self.udp.lan_loss.get_mut(&seg) {
                l.1 += 1;
            }
            if lost || self.cut(name, &endpoint) {
                continue;
            }
            if let Some(e) = self.udp.lan_socks.get_mut(&at) {
                e.heard.push_back((*a, src));
                if let Some(w) = e.waker.take() {
                    w.wake();
                }
            }
        }
    }

    /// Removes socket `at` (if `id` matches) and resets the connections waiting on it.
    fn unbind(&mut self, at: SocketAddr, id: Option<u64>) {
        if self.udp.socks.get(&at).is_some_and(|e| id.is_none_or(|i| i == e.id))
            && let Some(mut e) = self.udp.socks.remove(&at)
        {
            if let Some(w) = e.waker.take() {
                w.wake();
            }
            for (c, _, _) in e.queue {
                self.close(c);
            }
        }
    }
}

impl Net {
    /// How long a dial is resent before it fails, on this net, in place of `DIAL_MS` (a test whose
    /// dials wait for nothing's answer, on a net where model time is wall time). 0: one packet;
    /// `u64::MAX`: a dial nothing answers never ends.
    pub fn set_dial_ms(&self, ms: u64) {
        self.state().udp.dial_ms = Some(ms);
    }

    /// Adds a NAT whose public address is `public`.
    pub fn add_nat(&self, public: IpAddr, nat: Nat) {
        self.state().udp.nats.insert(public, NatState { nat, ports: BTreeMap::new(), back: BTreeMap::new(), out: BTreeSet::new(), next: 40000 });
    }

    /// Loses `pct` percent (seeded; 0..=100) of what is delivered on LAN segment `segment` from
    /// now on.
    pub fn set_lan_loss(&self, segment: &str, pct: u64) {
        self.state().udp.lan_loss.entry(segment.to_owned()).or_default().0 = pct;
    }

    /// How many deliveries segment `segment` has lost.
    pub fn lan_lost(&self, segment: &str) -> u64 {
        self.state().udp.lan_loss.get(segment).map_or(0, |l| l.1)
    }

    /// A host at `ip` (behind the NAT whose public address is `nat`, if any) whose sockets belong
    /// to endpoint `name` (partitions and `kill` apply to them).
    pub fn udp(&self, name: &str, ip: IpAddr, nat: Option<IpAddr>) -> MemUdp {
        self.state().udp.hosts.insert(ip, Host { nat, lans: BTreeMap::new() });
        MemUdp { net: self.clone(), name: name.to_owned(), ip }
    }
}

/// A host of the NAT model: binds sockets; its tasks run on the net's `Sched`.
#[derive(Clone)]
pub struct MemUdp {
    net: Net,
    name: String,
    ip: IpAddr,
}

impl MemUdp {
    /// Puts this host on LAN segment `segment` at address `ip`.
    pub fn on_lan(&self, segment: &str, ip: IpAddr) {
        if let Some(h) = self.net.state().udp.hosts.get_mut(&self.ip) {
            h.lans.insert(segment.to_owned(), ip);
        }
    }

    /// An announcement socket of this host, whose segments it hears, at `port`.
    pub fn lan_socket(&self, port: u16) -> Result<MemLan, Error> {
        let mut st = self.net.state();
        let port = match port {
            0 => (50000..=u16::MAX).find(|p| !st.udp.lan_socks.contains_key(&SocketAddr::new(self.ip, *p))).ok_or_else(|| Error::Io("no free port".into()))?,
            p => p,
        };
        let addr = SocketAddr::new(self.ip, port);
        if st.udp.lan_socks.contains_key(&addr) {
            return Err(Error::Io(format!("address in use: {addr}")));
        }
        let id = st.id();
        st.udp.lan_socks.insert(addr, LanEntry { id, endpoint: self.name.clone(), heard: VecDeque::new(), waker: None });
        Ok(MemLan { net: self.net.clone(), name: self.name.clone(), addr, id })
    }
}

impl UdpT for MemUdp {
    type Sock = MemSock;

    /// The host's own address only (an unspecified one means it); port 0: the next free one.
    fn bind(&self, at: SocketAddr, secret: Option<&StaticSecret>) -> Result<MemSock, Error> {
        if !at.ip().is_unspecified() && at.ip() != self.ip {
            return Err(Error::Io(format!("{at} is not this host's")));
        }
        let mut st = self.net.state();
        let port = match at.port() {
            0 => (50000..=u16::MAX).find(|p| !st.udp.socks.contains_key(&SocketAddr::new(self.ip, *p))).ok_or_else(|| Error::Io("no free port".into()))?,
            p => p,
        };
        let addr = SocketAddr::new(self.ip, port);
        if st.udp.socks.contains_key(&addr) {
            return Err(Error::Io(format!("address in use: {addr}")));
        }
        let id = st.id();
        let key = secret.map(crate::InProcess::public_key);
        st.udp.socks.insert(addr, Entry { id, endpoint: self.name.clone(), key, queue: VecDeque::new(), waker: None });
        Ok(MemSock { net: self.net.clone(), name: self.name.clone(), addr, id })
    }

    fn now_ms(&self) -> u64 {
        self.net.now()
    }

    fn sleep_ms(&self, ms: u64) -> impl Future<Output = ()> + Send + 'static {
        self.net.sleep(ms)
    }

    fn spawn(&self, f: impl Future<Output = ()> + Send + 'static) {
        self.net.spawn(f)
    }

    fn seed(&self) -> Result<[u8; 32], Error> {
        Ok(self.net.state().rng().bytes32())
    }

    async fn lan(&self, port: u16) -> Result<std::sync::Arc<dyn LanSocket>, Error> {
        Ok(std::sync::Arc::new(self.lan_socket(port)?))
    }
}

/// An announcement socket on a host's LAN segments (`Udp::lan`). Dropping it unbinds it.
pub struct MemLan {
    net: Net,
    name: String,
    addr: SocketAddr,
    id: u64,
}

impl LanSocket for MemLan {
    fn has_v6(&self) -> bool {
        self.net.state().udp.hosts.get(&self.addr.ip()).is_some_and(|h| h.lans.values().any(IpAddr::is_ipv6))
    }

    fn announce<'a>(&'a self, a: &'a Announce, to: SocketAddr) -> LanFuture<'a, ()> {
        Box::pin(async move {
            self.net.state().lan_send(&self.name, self.addr, a, to);
            Ok(())
        })
    }

    fn recv(&self) -> LanFuture<'_, (Announce, SocketAddr)> {
        Box::pin(poll_fn(|cx| {
            let mut st = self.net.state();
            let Some(e) = st.udp.lan_socks.get_mut(&self.addr).filter(|e| e.id == self.id) else { return Poll::Ready(Err(Error::Closed)) };
            match e.heard.pop_front() {
                Some(x) => Poll::Ready(Ok(x)),
                None => {
                    e.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        }))
    }
}

impl Drop for MemLan {
    fn drop(&mut self) {
        self.net.state().lan_unbind(self.addr, Some(self.id));
    }
}

/// A bound socket of the NAT model. Dropping it unbinds it; its connections stay.
pub struct MemSock {
    net: Net,
    name: String,
    addr: SocketAddr,
    id: u64,
}

impl MemSock {
    /// One attempt: the connection, if this packet got through.
    fn try_dial(&self, to: SocketAddr, key: PublicKey, own: Option<&StaticSecret>, alpn: Alpn) -> Result<Option<MemConn>, Error> {
        let mut st = self.net.state();
        if st.udp.socks.get(&self.addr).is_none_or(|e| e.id != self.id) {
            return Err(Error::Closed);
        }
        let Some((at, src)) = st.udp.route(self.addr, to) else { return Ok(None) };
        let Some(e) = st.udp.socks.get(&at) else { return Ok(None) };
        let (Some(theirs), endpoint) = (e.key, e.endpoint.clone()) else { return Ok(None) };
        if st.cut(&self.name, &endpoint) {
            return Ok(None);
        }
        if theirs != key {
            return Err(Error::KeyMismatch);
        }
        let mine = match own {
            Some(s) => crate::InProcess::public_key(s),
            None => st.rng().bytes32(),
        };
        let limit = [crate::quic::MAX_STREAMS as usize, crate::p2p::dialer_limits(alpn, own.is_some()).0 as usize];
        let (id, c) = st.new_conn(&self.net, [self.name.clone(), endpoint], [mine, theirs], limit, to);
        if let Some(e) = st.udp.socks.get_mut(&at) {
            e.queue.push_back((id, alpn, src));
            if let Some(w) = e.waker.take() {
                w.wake();
            }
        }
        Ok(Some(c))
    }
}

impl Sock for MemSock {
    type Conn = MemConn;

    fn local(&self) -> SocketAddr {
        self.addr
    }

    async fn dial(&self, to: SocketAddr, key: PublicKey, own: Option<StaticSecret>, alpn: Alpn) -> Result<MemConn, Error> {
        let give_up = self.net.state().udp.dial_ms.unwrap_or(DIAL_MS);
        let end = self.net.now().saturating_add(give_up);
        loop {
            if let Some(c) = self.try_dial(to, key, own.as_ref(), alpn)? {
                return Ok(c);
            }
            if self.net.now() >= end {
                return Err(Error::Unreachable(to.to_string()));
            }
            self.net.sleep(RESEND_MS).await;
        }
    }

    fn accept(&self) -> impl Future<Output = Result<(MemConn, Alpn, SocketAddr), Error>> + Send {
        poll_fn(|cx| {
            let mut st = self.net.state();
            loop {
                let Some(e) = st.udp.socks.get_mut(&self.addr).filter(|e| e.id == self.id) else { return Poll::Ready(Err(Error::Closed)) };
                let Some((c, alpn, src)) = e.queue.pop_front() else {
                    e.waker = Some(cx.waker().clone());
                    return Poll::Pending;
                };
                if let Some(conn) = st.accept_conn(&self.net, c, src) {
                    return Poll::Ready(Ok((conn, alpn, src)));
                }
            }
        })
    }

    fn punch(&self, to: SocketAddr) {
        let _ = self.net.state().udp.route(self.addr, to);
    }

    fn close(&self) {
        self.net.state().unbind(self.addr, Some(self.id));
    }
}

impl Drop for MemSock {
    fn drop(&mut self) {
        self.close();
    }
}
