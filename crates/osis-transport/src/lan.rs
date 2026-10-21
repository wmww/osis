//! LAN announcements (spec/sync.md §10; the socket with feature `lan`): a UDP datagram carrying the node's
//! current LAN tag, the transport key it listens with on this network (fresh per network join,
//! never the dialable key), that listener's port and a signature under the node's dialable key
//! binding the three, sealed under the lan secret and window; broadcast on the LAN. A receiver
//! that knows the tag's lan secret and the node's dialable key checks the signature and dials
//! `peer://<sender ip>:<port>` with the announced key. Not mDNS: the announcement carries nothing
//! stable across windows or networks, nor anything a holder of the dialable key alone can check.
//! Tag and signature are made and checked by the node (osis-crypto `seal_lan_sig`).
//!
//! Datagram (spec/sync.md §10, provisional): `"osis lan 1"` (10 bytes), tag (16), key (32),
//! port (2, big-endian), signature (64).

use crate::{Address, PublicKey};
#[cfg(feature = "lan")]
use crate::Error;
use std::net::{IpAddr, SocketAddr};
#[cfg(feature = "lan")]
use std::net::Ipv4Addr;

const MAGIC: &[u8; 10] = b"osis lan 1";
/// Datagram length.
pub const LEN: usize = 10 + 16 + 32 + 2 + 64;
/// Default UDP port announcements go to (provisional).
pub const PORT: u16 = 47_380;

/// Where announcements are sent: the limited broadcast address at `port`.
pub fn broadcast(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::BROADCAST), port)
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

    /// Where to dial the announcer, given the datagram's source address.
    pub fn address(&self, from: IpAddr) -> Address {
        Address { url: crate::peer_url(&[SocketAddr::new(from, self.port).to_string()]), key: self.key }
    }
}

/// A UDP socket sending and receiving announcements (feature `lan`).
#[cfg(feature = "lan")]
pub struct Lan {
    sock: tokio::net::UdpSocket,
    port: u16,
}

#[cfg(feature = "lan")]
impl Lan {
    /// Binds the announcement port on all IPv4 interfaces (`port` 0: any, for tests).
    pub async fn bind(port: u16) -> Result<Lan, Error> {
        let sock = tokio::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)).await.map_err(|e| Error::Io(e.to_string()))?;
        sock.set_broadcast(true).map_err(|e| Error::Io(e.to_string()))?;
        let port = sock.local_addr().map_err(|e| Error::Io(e.to_string()))?.port();
        Ok(Lan { sock, port })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Sends an announcement to `to` (the LAN broadcast address and announcement port, or one
    /// host).
    pub async fn announce(&self, a: &Announce, to: SocketAddr) -> Result<(), Error> {
        self.sock.send_to(&a.encode(), to).await.map(|_| ()).map_err(|e| Error::Io(e.to_string()))
    }

    /// The next announcement heard and its sender's IP. Other datagrams, and announcements from
    /// addresses that cannot be on the LAN (`is_local`), are skipped.
    pub async fn recv(&self) -> Result<(Announce, IpAddr), Error> {
        let mut buf = [0u8; LEN + 1];
        loop {
            let (n, from) = self.sock.recv_from(&mut buf).await.map_err(|e| Error::Io(e.to_string()))?;
            if !is_local(from.ip()) {
                continue;
            }
            if let Some(a) = buf.get(..n).and_then(Announce::decode) {
                return Ok((a, from.ip()));
            }
        }
    }
}

/// The local IP address of the route to the internet, if any: a change means another network
/// (the LAN loop re-keys). No packet is sent.
#[cfg(feature = "lan")]
pub async fn route_ip() -> Option<IpAddr> {
    let s = tokio::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await.ok()?;
    // TEST-NET-1 (RFC 5737): connecting a UDP socket only picks the route
    s.connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9)).await.ok()?;
    s.local_addr().ok().map(|a| a.ip())
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
        let addr = a.address("192.168.1.5".parse().unwrap());
        assert_eq!(addr, Address { url: "peer://192.168.1.5:4433".into(), key: [2; 32] });
        assert_eq!(&b[..10], b"osis lan 1");
        assert_eq!(b.len(), 124);
        assert_eq!(&b[LEN - 66..LEN - 64], &4433u16.to_be_bytes());
        assert_eq!(&b[LEN - 64..], &[3; 64]);
        assert_eq!(&a.signed()[..16], &[1; 16]);
        assert_eq!(&a.signed()[48..], &4433u16.to_be_bytes());
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
        assert!(from.is_loopback());
    }
}
