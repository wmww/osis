//! `Multi`: one transport over several, picked by URL scheme (spec/sync.md §10): `mem://` to
//! `InProcess`, `quic://` to `Quic`, `peer://` to `P2p` (over `QuicUdp`, or `MemUdp` in a test
//! net), `unix://` to `Unix` (listen only). A scheme without its transport is `UnknownScheme`.
//! Lets one driver reach hosts and peers.

use crate::{Address, Connection, Error, InProcess, ListenConfig, Listener, MemConn, MemListener, MemRecv, MemSend, PublicKey, RecvStream, SendStream, StaticSecret, Transport};
use crate::p2p::{P2pRecv, P2pSend};
use crate::p2p::{SConn, Udp};
use crate::{P2p, P2pConn, P2pListener, QuicUdp};
use crate::{Quic, QuicConn, QuicListener, QuicRecv, QuicSend};
use crate::{Unix, UnixConn, UnixListener, UnixRecv, UnixSend};

/// The transports a `Multi` dispatches to; `None`: that scheme is unknown.
#[derive(Clone)]
pub struct Multi<U: Udp = QuicUdp> {
    pub mem: Option<InProcess>,
    pub quic: Option<Quic>,
    pub p2p: Option<P2p<U>>,
    pub unix: Option<Unix>,
}

impl<U: Udp> Default for Multi<U> {
    fn default() -> Self {
        Multi { mem: None, quic: None, p2p: None, unix: None }
    }
}

enum Pick<'a, U: Udp> {
    Mem(&'a InProcess),
    Quic(&'a Quic),
    P2p(&'a P2p<U>),
    Unix(&'a Unix),
}

impl<U: Udp> Multi<U> {
    fn pick(&self, url: &str) -> Result<Pick<'_, U>, Error> {
        let scheme = url.split_once("://").map(|(s, _)| s).ok_or_else(|| Error::BadUrl(url.to_owned()))?;
        let unknown = || Error::UnknownScheme(scheme.to_owned());
        match scheme {
            "quic" => self.quic.as_ref().map(Pick::Quic).ok_or_else(unknown),
            crate::unix::SCHEME => self.unix.as_ref().map(Pick::Unix).ok_or_else(unknown),
            crate::PEER_SCHEME => self.p2p.as_ref().map(Pick::P2p).ok_or_else(unknown),
            crate::mem::SCHEME => self.mem.as_ref().map(Pick::Mem).ok_or_else(unknown),
            _ => Err(unknown()),
        }
    }

    /// `pick` for a dial: never `unix://`.
    fn pick_dial(&self, url: &str) -> Result<Pick<'_, U>, Error> {
        match self.pick(url)? {
            Pick::Unix(_) => Err(Error::UnknownScheme(crate::unix::SCHEME.to_owned())),
            p => Ok(p),
        }
    }
}

/// Defines an enum over the per-transport types, with `From` each of them.
macro_rules! either {
    ($name:ident, $mem:ty, $quic:ty, $p2p:ty, $unix:ty) => {
        pub enum $name<U: Udp = QuicUdp> {
            Mem($mem),
            Quic($quic),
            P2p($p2p),
            Unix($unix),
        }
        impl<U: Udp> From<$unix> for $name<U> {
            fn from(x: $unix) -> Self {
                Self::Unix(x)
            }
        }
        impl<U: Udp> From<$mem> for $name<U> {
            fn from(x: $mem) -> Self {
                Self::Mem(x)
            }
        }
        impl<U: Udp> From<$quic> for $name<U> {
            fn from(x: $quic) -> Self {
                Self::Quic(x)
            }
        }
        impl<U: Udp> From<$p2p> for $name<U> {
            fn from(x: $p2p) -> Self {
                Self::P2p(x)
            }
        }
    };
}

/// Forwards a body to whichever transport's value is inside (`Self`, or the enum named).
macro_rules! each {
    ($v:expr, $x:ident => $body:expr) => {
        each!(Self; $v, $x => $body)
    };
    ($e:ident; $v:expr, $x:ident => $body:expr) => {
        match $v {
            $e::Mem($x) => $body,
            $e::Quic($x) => $body,
            $e::P2p($x) => $body,
            $e::Unix($x) => $body,
        }
    };
}

either!(MultiConn, MemConn, QuicConn, P2pConn<SConn<U>>, UnixConn);
either!(MultiListener, MemListener, QuicListener, P2pListener<U>, UnixListener);
either!(MultiSend, MemSend, QuicSend, P2pSend<SConn<U>>, UnixSend);
either!(MultiRecv, MemRecv, QuicRecv, P2pRecv<SConn<U>>, UnixRecv);

impl<U: Udp> Clone for MultiConn<U> {
    fn clone(&self) -> Self {
        each!(self, c => Self::from(c.clone()))
    }
}

impl<U: Udp> Transport for Multi<U> {
    type Conn = MultiConn<U>;
    type Listener = MultiListener<U>;

    /// `unix://` is listened on only (the client port, notes/client-port.md §5): an address
    /// another node published never makes this process dial a local socket.
    async fn dial(&self, addr: &Address) -> Result<MultiConn<U>, Error> {
        let p = self.pick_dial(&addr.url)?;
        each!(Pick; p, t => t.dial(addr).await.map(Into::into))
    }

    async fn dial_as(&self, addr: &Address, secret: &StaticSecret) -> Result<MultiConn<U>, Error> {
        let p = self.pick_dial(&addr.url)?;
        each!(Pick; p, t => t.dial_as(addr, secret).await.map(Into::into))
    }

    async fn listen(&self, cfg: ListenConfig) -> Result<MultiListener<U>, Error> {
        let p = self.pick(&cfg.url)?;
        each!(Pick; p, t => t.listen(cfg).await.map(Into::into))
    }

    /// The LAN loop runs over the peer transport.
    async fn lan(&self, port: u16) -> Result<std::sync::Arc<dyn crate::lan::LanSocket>, Error> {
        match &self.p2p {
            Some(p) => p.lan(port).await,
            None => Err(Error::UnknownScheme(crate::PEER_SCHEME.to_owned())),
        }
    }
}

impl<U: Udp> Listener for MultiListener<U> {
    type Conn = MultiConn<U>;

    async fn accept(&mut self) -> Result<MultiConn<U>, Error> {
        each!(self, l => l.accept().await.map(MultiConn::from))
    }

    fn address(&self) -> Address {
        each!(self, l => l.address())
    }

    fn close(&self) {
        each!(self, l => l.close())
    }
}

impl<U: Udp> Connection for MultiConn<U> {
    type Send = MultiSend<U>;
    type Recv = MultiRecv<U>;

    fn peer_key(&self) -> PublicKey {
        each!(self, c => c.peer_key())
    }

    fn peer(&self) -> crate::Peer {
        each!(self, c => c.peer())
    }

    fn source(&self) -> Option<crate::Source> {
        each!(self, c => c.source())
    }

    fn relayed(&self) -> bool {
        each!(self, c => c.relayed())
    }

    async fn open_stream(&self) -> Result<(MultiSend<U>, MultiRecv<U>), Error> {
        each!(self, c => c.open_stream().await.map(|(s, r)| (s.into(), r.into())))
    }

    async fn accept_stream(&self) -> Result<(MultiSend<U>, MultiRecv<U>), Error> {
        each!(self, c => c.accept_stream().await.map(|(s, r)| (s.into(), r.into())))
    }

    fn close(&self) {
        each!(self, c => c.close())
    }
}

impl<U: Udp> SendStream for MultiSend<U> {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        each!(self, s => s.write_all(buf).await)
    }

    async fn finish(&mut self) -> Result<(), Error> {
        each!(self, s => s.finish().await)
    }
}

impl<U: Udp> RecvStream for MultiRecv<U> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        each!(self, r => r.read(buf).await)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{Net, Sched};

    fn me2() -> StaticSecret {
        StaticSecret::from_bytes([7; 32])
    }

    // spec/sync.md §10: the URL scheme picks the transport; `peer://` without `P2p` is a scheme
    // without its transport, which is unknown (parked); unix:// is never dialed.
    #[test]
    fn dispatch_by_scheme_spec_sync_10() {
        let net = Net::new(0);
        let mut sched = Sched::new(0, Some(net.clone()));
        let (a, b): (Multi, Multi) = (Multi { mem: Some(net.endpoint("a")), ..Multi::default() }, Multi { mem: Some(net.endpoint("b")), ..Multi::default() });
        let secret = StaticSecret::from_bytes([5; 32]);
        let done = sched.block_on(async move {
            let l = b.listen(ListenConfig { url: "mem://b".into(), secret: secret.clone() }).await.unwrap();
            let key = l.address().key;
            assert_eq!(key, InProcess::public_key(&secret));
            let c = a.dial(&Address { url: "mem://b".into(), key }).await.unwrap();
            assert_eq!(c.peer_key(), key);
            let me = StaticSecret::from_bytes([6; 32]);
            assert!(matches!(a.dial_as(&Address { url: crate::peer_url(&[]), key }, &me).await, Err(Error::UnknownScheme(_))));
            let none: Multi = Multi::default();
            assert!(matches!(none.dial(&Address { url: "mem://b".into(), key }).await, Err(Error::UnknownScheme(_))));
            assert!(matches!(a.dial(&Address { url: "quic://x:1".into(), key }).await, Err(Error::UnknownScheme(_))));
            assert!(matches!(a.dial(&Address { url: "nothing".into(), key }).await, Err(Error::BadUrl(_))));
            // unix:// is listened on, never dialed through a Multi (a published address cannot reach a local socket)
            let u: Multi = Multi { unix: Some(Unix), ..Multi::default() };
            assert!(matches!(u.dial(&Address { url: "unix:///tmp/x.sock".into(), key }).await, Err(Error::UnknownScheme(_))));
            assert!(matches!(u.dial_as(&Address { url: "unix:///tmp/x.sock".into(), key }, &me2()).await, Err(Error::UnknownScheme(_))));
            drop(l);
        });
        assert!(done.is_some());
    }
}
