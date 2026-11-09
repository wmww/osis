//! The NAT model of `InProcess` (a test network; spec: none): hosts with IP addresses, some
//! behind NATs (RFC 4787 mapping and filtering behaviour), and UDP sockets (`MemUdp`, `MemSock`)
//! whose dials, accepts and hole punches pass through them, for `p2p` over the in-process net.
//!
//! A dial is a packet from a socket to an address, resent every `RESEND_MS` until it reaches a
//! socket that accepts connections or `DIAL_MS` passes (QUIC's retransmission and idle timeout);
//! the first packet that arrives makes the connection, which then carries data both ways (the
//! reply goes back through the mapping the packet came in on). A punch is one packet, kept by
//! nobody. NAT mappings never expire; two hosts behind one NAT reach each other only at their
//! own addresses (no hairpinning). Streams per connection are limited as `QuicUdp` limits them
//! (`p2p::dialer_limits`). Model time is the net's steps, one per millisecond.

use crate::mem::{MemConn, Net, State};
use crate::p2p::{Alpn, Sock, Udp as UdpT};
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
/// the target punches back to the one the dialer's NAT showed it. The packet passes where the
/// target's mapping is independent of the remote (else the observed port is the relay's alone) and
/// its filter lets the dialer's source in: any source, one whose IP it punched, or, filtering
/// by port too, one whose mapping shows that same port. The one rule of the punch; the packet
/// machine below enforces it (`punch_by_nat_type`) and `osis_sim::reach` applies it.
pub fn punch_opens(dialer: Option<Nat>, target: Option<Nat>) -> bool {
    let Some(t) = target else { return true };
    t.mapping == Dep::Endpoint
        && match t.filtering {
            Dep::Endpoint | Dep::Address => true,
            Dep::AddressPort => dialer.is_none_or(|d| d.mapping == Dep::Endpoint),
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
}

struct Host {
    /// The NAT the host is behind, by its public address.
    nat: Option<IpAddr>,
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
    /// Where a packet from socket `from` to `to` arrives and the source it shows there; `None`:
    /// dropped. Records the NAT state it passes.
    fn route(&mut self, from: SocketAddr, to: SocketAddr) -> Option<(SocketAddr, SocketAddr)> {
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
    /// Adds a NAT whose public address is `public`.
    pub fn add_nat(&self, public: IpAddr, nat: Nat) {
        self.state().udp.nats.insert(public, NatState { nat, ports: BTreeMap::new(), back: BTreeMap::new(), out: BTreeSet::new(), next: 40000 });
    }

    /// A host at `ip` (behind the NAT whose public address is `nat`, if any) whose sockets belong
    /// to endpoint `name` (partitions and `kill` apply to them).
    pub fn udp(&self, name: &str, ip: IpAddr, nat: Option<IpAddr>) -> MemUdp {
        self.state().udp.hosts.insert(ip, Host { nat });
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
        let end = self.net.now().saturating_add(DIAL_MS);
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
