//! LAN announcements (spec/sync.md §10; the socket with feature `lan`): a UDP datagram carrying the node's
//! current LAN tag, the transport key it listens with on this network (fresh per network join,
//! never the dialable key) and that listener's port; broadcast on the LAN. A receiver that knows
//! the tag's lan secret dials `peer://<sender ip>:<port>` with the announced key. Not mDNS: the
//! announcement carries nothing stable across windows or networks.
//!
//! Datagram (provisional, not yet in the spec): `"osis lan 1"` (10 bytes), tag (16), key (32),
//! port (2, big-endian).

use crate::{Address, PublicKey};
#[cfg(feature = "lan")]
use crate::Error;
use std::net::{IpAddr, SocketAddr};
#[cfg(feature = "lan")]
use std::net::Ipv4Addr;

const MAGIC: &[u8; 10] = b"osis lan 1";
/// Datagram length.
pub const LEN: usize = 10 + 16 + 32 + 2;
/// Default UDP port announcements go to (provisional).
pub const PORT: u16 = 47_380;

/// One announcement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Announce {
    pub tag: [u8; 16],
    pub key: PublicKey,
    pub port: u16,
}

impl Announce {
    pub fn encode(&self) -> [u8; LEN] {
        let mut b = [0u8; LEN];
        let parts: [&[u8]; 4] = [MAGIC, &self.tag, &self.key, &self.port.to_be_bytes()];
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
        let port = u16::from_be_bytes(*rest.first_chunk::<2>()?);
        Some(Announce { tag: *tag, key: *key, port })
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

    /// The next announcement heard (other datagrams are skipped) and its sender's IP.
    pub async fn recv(&self) -> Result<(Announce, IpAddr), Error> {
        let mut buf = [0u8; LEN + 1];
        loop {
            let (n, from) = self.sock.recv_from(&mut buf).await.map_err(|e| Error::Io(e.to_string()))?;
            if let Some(a) = buf.get(..n).and_then(Announce::decode) {
                return Ok((a, from.ip()));
            }
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
        let a = Announce { tag: [1; 16], key: [2; 32], port: 4433 };
        let b = a.encode();
        assert_eq!(Announce::decode(&b), Some(a));
        assert_eq!(Announce::decode(&b[..LEN - 1]), None);
        let mut bad = b;
        bad[0] ^= 1;
        assert_eq!(Announce::decode(&bad), None);
        let addr = a.address("192.168.1.5".parse().unwrap());
        assert_eq!(addr, Address { url: "peer://192.168.1.5:4433".into(), key: [2; 32] });
    }

    // spec/sync.md §10: an announcement sent over UDP is heard (tier 2: localhost socket).
    #[cfg(feature = "lan")]
    #[tokio::test]
    #[ignore]
    async fn announce_over_udp_spec_sync_10() {
        let rx = Lan::bind(0).await.unwrap();
        let tx = Lan::bind(0).await.unwrap();
        let a = Announce { tag: [3; 16], key: [4; 32], port: 9 };
        tx.announce(&a, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rx.port())).await.unwrap();
        let (got, from) = rx.recv().await.unwrap();
        assert_eq!(got, a);
        assert!(from.is_loopback());
    }
}
