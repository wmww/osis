//! `Multi`: one transport over several, picked by URL scheme (spec/sync.md §10): `mem://` to
//! `InProcess`, `quic://` to `Quic`, `peer://` to `Iroh` (feature `iroh`), else to
//! `InProcess` (which finds a `peer://` listener by key). A scheme without its transport is
//! `UnknownScheme`. Lets one driver reach servers and peers.

use crate::{Address, Connection, Error, InProcess, ListenConfig, Listener, MemConn, MemListener, MemRecv, MemSend, PublicKey, RecvStream, SendStream, StaticSecret, Transport};
#[cfg(feature = "iroh")]
use crate::{Iroh, IrohConn, IrohListener, IrohRecv, IrohSend};
use crate::{Quic, QuicConn, QuicListener, QuicRecv, QuicSend};

/// The transports a `Multi` dispatches to; `None`: that scheme is unknown.
#[derive(Clone, Default)]
pub struct Multi {
    pub mem: Option<InProcess>,
    pub quic: Option<Quic>,
    #[cfg(feature = "iroh")]
    pub iroh: Option<Iroh>,
}

enum Pick<'a> {
    Mem(&'a InProcess),
    Quic(&'a Quic),
    #[cfg(feature = "iroh")]
    Iroh(&'a Iroh),
}

impl Multi {
    fn pick(&self, url: &str) -> Result<Pick<'_>, Error> {
        let scheme = url.split_once("://").map(|(s, _)| s).ok_or_else(|| Error::BadUrl(url.to_owned()))?;
        let unknown = || Error::UnknownScheme(scheme.to_owned());
        match scheme {
            "quic" => self.quic.as_ref().map(Pick::Quic).ok_or_else(unknown),
            #[cfg(feature = "iroh")]
            crate::PEER_SCHEME if self.iroh.is_some() => self.iroh.as_ref().map(Pick::Iroh).ok_or_else(unknown),
            "mem" | crate::PEER_SCHEME => self.mem.as_ref().map(Pick::Mem).ok_or_else(unknown),
            _ => Err(unknown()),
        }
    }
}

/// Defines an enum over the per-transport types, with `From` each of them.
macro_rules! either {
    ($name:ident, $mem:ty, $quic:ty, $iroh:ty) => {
        pub enum $name {
            Mem($mem),
            Quic($quic),
            #[cfg(feature = "iroh")]
            Iroh($iroh),
        }
        impl From<$mem> for $name {
            fn from(x: $mem) -> Self {
                Self::Mem(x)
            }
        }
        impl From<$quic> for $name {
            fn from(x: $quic) -> Self {
                Self::Quic(x)
            }
        }
        #[cfg(feature = "iroh")]
        impl From<$iroh> for $name {
            fn from(x: $iroh) -> Self {
                Self::Iroh(x)
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
            #[cfg(feature = "iroh")]
            $e::Iroh($x) => $body,
        }
    };
}

either!(MultiConn, MemConn, QuicConn, IrohConn);
either!(MultiListener, MemListener, QuicListener, IrohListener);
either!(MultiSend, MemSend, QuicSend, IrohSend);
either!(MultiRecv, MemRecv, QuicRecv, IrohRecv);

impl Clone for MultiConn {
    fn clone(&self) -> Self {
        each!(self, c => Self::from(c.clone()))
    }
}

impl Transport for Multi {
    type Conn = MultiConn;
    type Listener = MultiListener;

    async fn dial(&self, addr: &Address) -> Result<MultiConn, Error> {
        let p = self.pick(&addr.url)?;
        each!(Pick; p, t => t.dial(addr).await.map(Into::into))
    }

    async fn dial_as(&self, addr: &Address, secret: &StaticSecret) -> Result<MultiConn, Error> {
        let p = self.pick(&addr.url)?;
        each!(Pick; p, t => t.dial_as(addr, secret).await.map(Into::into))
    }

    async fn listen(&self, cfg: ListenConfig) -> Result<MultiListener, Error> {
        let p = self.pick(&cfg.url)?;
        each!(Pick; p, t => t.listen(cfg).await.map(Into::into))
    }
}

impl Listener for MultiListener {
    type Conn = MultiConn;

    async fn accept(&mut self) -> Result<MultiConn, Error> {
        each!(self, l => l.accept().await.map(MultiConn::from))
    }

    fn address(&self) -> Address {
        each!(self, l => l.address())
    }

    fn close(&self) {
        each!(self, l => l.close())
    }
}

impl Connection for MultiConn {
    type Send = MultiSend;
    type Recv = MultiRecv;

    fn peer_key(&self) -> PublicKey {
        each!(self, c => c.peer_key())
    }

    async fn open_stream(&self) -> Result<(MultiSend, MultiRecv), Error> {
        each!(self, c => c.open_stream().await.map(|(s, r)| (s.into(), r.into())))
    }

    async fn accept_stream(&self) -> Result<(MultiSend, MultiRecv), Error> {
        each!(self, c => c.accept_stream().await.map(|(s, r)| (s.into(), r.into())))
    }

    fn close(&self) {
        each!(self, c => c.close())
    }
}

impl SendStream for MultiSend {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        each!(self, s => s.write_all(buf).await)
    }

    async fn finish(&mut self) -> Result<(), Error> {
        each!(self, s => s.finish().await)
    }
}

impl RecvStream for MultiRecv {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        each!(self, r => r.read(buf).await)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{Net, Sched};

    // spec/sync.md §10: the URL scheme picks the transport; `peer://` without iroh goes to the
    // in-process listener of that key; a scheme without its transport is unknown (parked).
    #[test]
    #[allow(clippy::needless_update)] // the other fields exist with feature `iroh`
    fn dispatch_by_scheme_spec_sync_10() {
        let net = Net::new(3);
        let mut sched = Sched::new(3, Some(net.clone()));
        let (a, b) = (Multi { mem: Some(net.endpoint("a")), ..Multi::default() }, Multi { mem: Some(net.endpoint("b")), ..Multi::default() });
        let secret = StaticSecret::from_bytes([5; 32]);
        let done = sched.block_on(async move {
            let l = b.listen(ListenConfig { url: "mem://b".into(), secret: secret.clone() }).await.unwrap();
            let key = l.address().key;
            assert_eq!(key, InProcess::public_key(&secret));
            let c = a.dial(&Address { url: "mem://b".into(), key }).await.unwrap();
            assert_eq!(c.peer_key(), key);
            let me = StaticSecret::from_bytes([6; 32]);
            let c = a.dial_as(&Address { url: crate::peer_url(&[]), key }, &me).await.unwrap();
            assert_eq!(c.peer_key(), key);
            let none = Multi::default();
            assert!(matches!(none.dial(&Address { url: "mem://b".into(), key }).await, Err(Error::UnknownScheme(_))));
            assert!(matches!(a.dial(&Address { url: "quic://x:1".into(), key }).await, Err(Error::UnknownScheme(_))));
            assert!(matches!(a.dial(&Address { url: "nothing".into(), key }).await, Err(Error::BadUrl(_))));
            drop(l);
        });
        assert!(done.is_some());
    }
}
