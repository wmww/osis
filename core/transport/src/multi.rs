//! `Multi`: one transport over several, picked by URL scheme (spec/sync-transport.md §1):
//! `quic://` to `Quic`, `peer://` to `P2p`, `unix://` to `Unix` (listened on; dialed only with
//! `unix_dial`). A scheme without its transport is `UnknownScheme`.

use crate::{Address, Connection, Error, ListenConfig, Listener, PublicKey, RecvStream, SendStream, Transport};
use crate::p2p::{P2pRecv, P2pSend, SConn};
use crate::{P2p, P2pConn, P2pListener, QuicUdp};
use crate::{Quic, QuicConn, QuicListener, QuicRecv, QuicSend};
use crate::{Unix, UnixConn, UnixListener, UnixRecv, UnixSend};

/// The transports a `Multi` dispatches to; `None`: that scheme is unknown.
#[derive(Clone, Default)]
pub struct Multi {
    pub quic: Option<Quic>,
    pub p2p: Option<P2p<QuicUdp>>,
    pub unix: Option<Unix>,
    /// `unix://` is dialed too: a local client of a node's socket (spec/sync-transport.md §6),
    /// which syncs nothing. Never on a node's own transports: an address another node published
    /// must not make a node dial a local socket.
    pub unix_dial: bool,
}

enum Pick<'a> {
    Quic(&'a Quic),
    P2p(&'a P2p<QuicUdp>),
    Unix(&'a Unix),
}

impl Multi {
    fn pick(&self, url: &str) -> Result<Pick<'_>, Error> {
        let scheme = url.split_once("://").map(|(s, _)| s).ok_or_else(|| Error::BadUrl(url.to_owned()))?;
        let unknown = || Error::UnknownScheme(scheme.to_owned());
        match scheme {
            "quic" => self.quic.as_ref().map(Pick::Quic).ok_or_else(unknown),
            crate::unix::SCHEME => self.unix.as_ref().map(Pick::Unix).ok_or_else(unknown),
            crate::PEER_SCHEME => self.p2p.as_ref().map(Pick::P2p).ok_or_else(unknown),
            _ => Err(unknown()),
        }
    }

    /// `pick` for a dial: `unix://` only with `unix_dial`.
    fn pick_dial(&self, url: &str) -> Result<Pick<'_>, Error> {
        match self.pick(url)? {
            Pick::Unix(_) if !self.unix_dial => Err(Error::UnknownScheme(crate::unix::SCHEME.to_owned())),
            p => Ok(p),
        }
    }
}

/// Defines an enum over the per-transport types, with `From` each of them.
macro_rules! either {
    ($name:ident, $quic:ty, $p2p:ty, $unix:ty) => {
        pub enum $name {
            Quic($quic),
            P2p($p2p),
            Unix($unix),
        }
        impl From<$unix> for $name {
            fn from(x: $unix) -> Self {
                Self::Unix(x)
            }
        }
        impl From<$quic> for $name {
            fn from(x: $quic) -> Self {
                Self::Quic(x)
            }
        }
        impl From<$p2p> for $name {
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
            $e::Quic($x) => $body,
            $e::P2p($x) => $body,
            $e::Unix($x) => $body,
        }
    };
}

either!(MultiConn, QuicConn, P2pConn<SConn<QuicUdp>>, UnixConn);
either!(MultiListener, QuicListener, P2pListener<QuicUdp>, UnixListener);
either!(MultiSend, QuicSend, P2pSend<SConn<QuicUdp>>, UnixSend);
either!(MultiRecv, QuicRecv, P2pRecv<SConn<QuicUdp>>, UnixRecv);

impl Clone for MultiConn {
    fn clone(&self) -> Self {
        each!(self, c => Self::from(c.clone()))
    }
}

impl Transport for Multi {
    type Conn = MultiConn;
    type Listener = MultiListener;

    /// `unix://` is listened on, and dialed only with `unix_dial` (the client port,
    /// notes/client-port.md §5): an address another node published never makes a node dial a
    /// local socket.
    async fn dial(&self, addr: &Address) -> Result<MultiConn, Error> {
        let p = self.pick_dial(&addr.url)?;
        each!(Pick; p, t => t.dial(addr).await.map(Into::into))
    }

    async fn listen(&self, cfg: ListenConfig) -> Result<MultiListener, Error> {
        let p = self.pick(&cfg.url)?;
        each!(Pick; p, t => t.listen(cfg).await.map(Into::into))
    }

    /// LAN discovery runs over the peer transport.
    async fn discover(&self) -> Result<crate::Discovery<MultiConn>, Error> {
        match &self.p2p {
            Some(p) => p.discover_as(MultiConn::P2p).await,
            None => Err(Error::UnknownScheme(crate::PEER_SCHEME.to_owned())),
        }
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

    /// A URL of another scheme names another listener's socket.
    async fn relisten(&mut self, cfg: &ListenConfig) -> Result<bool, Error> {
        let mine = match self {
            Self::Quic(_) => crate::quic::SCHEME,
            Self::P2p(_) => crate::PEER_SCHEME,
            Self::Unix(_) => crate::unix::SCHEME,
        };
        if cfg.url.split_once("://").map(|(s, _)| s) != Some(mine) {
            return Ok(false);
        }
        each!(self, l => l.relisten(cfg).await)
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

    fn peer(&self) -> crate::Peer {
        each!(self, c => c.peer())
    }

    fn source(&self) -> Option<crate::Source> {
        each!(self, c => c.source())
    }

    fn rank(&self) -> crate::Rank {
        each!(self, c => c.rank())
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

    // spec/sync-transport.md §1: the URL scheme picks the transport; a scheme without its transport
    // is unknown (parked); unix:// is dialed only by a local client.
    #[test]
    fn dispatch_by_scheme_spec_sync_10() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let key = [5; 32];
            let none = Multi::default();
            for url in [crate::peer_url(&[]), "quic://x:1".into(), "mem://b".into()] {
                assert!(matches!(none.dial(&Address { url, key }).await, Err(Error::UnknownScheme(_))));
            }
            assert!(matches!(none.dial(&Address { url: "nothing".into(), key }).await, Err(Error::BadUrl(_))));
            // unix:// is listened on, never dialed through a Multi (a published address cannot reach a local socket)
            let u = Multi { unix: Some(Unix), ..Multi::default() };
            assert!(matches!(u.dial(&Address { url: "unix:///tmp/x.sock".into(), key }).await, Err(Error::UnknownScheme(_))));
            // a local client dials it (no socket there: an error of the socket's, not the scheme's)
            let c = Multi { unix: Some(Unix), unix_dial: true, ..Multi::default() };
            assert!(!matches!(c.dial(&Address { url: "unix:///nonexistent/x.sock".into(), key }).await, Err(Error::UnknownScheme(_)) | Ok(_)));
        });
    }
}
