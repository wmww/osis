//! `Unix`: unix-domain path sockets (`unix:///abs/path`; notes/client-port.md §5): no TLS, the
//! kernel authenticates. Both sides read the other's uid with `SO_PEERCRED` and accept only their
//! own (a listener drops another uid's connection, a dialer refuses another uid's listener); the
//! peer is `Peer::Unix { uid }`. A side's key is derived from its uid (`uid_key`), so the
//! dialer's pinned-key check works as for any address. One stream per connection (the link's
//! session). Path sockets only: the Linux abstract namespace (ignoring mount namespaces and file
//! modes) is refused, as is a path longer than `sun_path` holds.

use crate::{Address, Connection, Error, ListenConfig, Listener, Peer, PublicKey, RecvStream, SendStream, StaticSecret, Transport};
use std::future::poll_fn;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::AsyncWrite;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener as TokioListener, UnixStream};
use tokio::sync::watch;

/// URL scheme: `unix:///abs/path`.
pub const SCHEME: &str = "unix";
/// Bytes of a socket path, NUL excluded (`sun_path` is 108 bytes on Linux).
pub const MAX_PATH: usize = 107;
/// Wait before accepting again after an accept error (out of descriptors or memory: they
/// persist a while). Minor consequence: a client may wait this long once the cause is gone; 0
/// spins on a lasting error, infinity ends the listener at the first one.
const ACCEPT_RETRY: std::time::Duration = std::time::Duration::from_millis(100);

/// The key standing for uid `uid`: a name, never a secret (the kernel authenticates).
pub fn uid_key(uid: u32) -> PublicKey {
    osis_base::hash::hash(&[b"osis v1 unix peer".as_slice(), &uid.to_be_bytes()].concat())
}

/// This process's effective uid, read as `SO_PEERCRED` of a socket pair (no unsafe code; the
/// first call outside a tokio runtime starts a small one for it).
pub fn own_uid() -> Result<u32, Error> {
    static UID: OnceLock<u32> = OnceLock::new();
    if let Some(u) = UID.get() {
        return Ok(*u);
    }
    let rt = match tokio::runtime::Handle::try_current() {
        Ok(_) => None,
        Err(_) => Some(tokio::runtime::Builder::new_current_thread().enable_io().build().map_err(io)?),
    };
    let _g = rt.as_ref().map(|r| r.enter());
    let (a, _b) = UnixStream::pair().map_err(io)?;
    let uid = a.peer_cred().map_err(io)?.uid();
    Ok(*UID.get_or_init(|| uid))
}

fn io(e: std::io::Error) -> Error {
    Error::Io(e.to_string())
}

/// The path of a `unix://` URL: absolute, no NUL, at most `MAX_PATH` bytes.
pub fn url_path(url: &str) -> Result<PathBuf, Error> {
    crate::check_url(url)?;
    let p = url.strip_prefix("unix://").ok_or_else(|| Error::BadUrl(url.to_owned()))?;
    if !p.starts_with('/') || p.contains('\0') || p.len() > MAX_PATH {
        return Err(Error::BadUrl(format!("{url}: an absolute path of at most {MAX_PATH} bytes")));
    }
    Ok(PathBuf::from(p))
}

/// The `unix://` URL of `path`.
pub fn url_of(path: &Path) -> String {
    format!("unix://{}", path.display())
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Unix;

/// A connection: one stream, its uid.
#[derive(Clone)]
pub struct UnixConn {
    uid: u32,
    halves: Arc<Mutex<Option<(OwnedReadHalf, OwnedWriteHalf)>>>,
    closed: watch::Sender<bool>,
}

impl UnixConn {
    fn new(s: UnixStream, uid: u32) -> UnixConn {
        let (r, w) = s.into_split();
        UnixConn { uid, halves: Arc::new(Mutex::new(Some((r, w)))), closed: watch::Sender::new(false) }
    }

    fn take(&self) -> Result<(UnixSend, UnixRecv), Error> {
        let h = self.halves.lock().unwrap_or_else(|p| p.into_inner()).take();
        let (r, w) = h.ok_or(Error::Closed)?;
        Ok((UnixSend { w: Some(w), closed: self.closed.subscribe() }, UnixRecv { r, closed: self.closed.subscribe() }))
    }
}

pub struct UnixSend {
    w: Option<OwnedWriteHalf>,
    closed: watch::Receiver<bool>,
}

pub struct UnixRecv {
    r: OwnedReadHalf,
    closed: watch::Receiver<bool>,
}

pub struct UnixListener {
    l: TokioListener,
    path: PathBuf,
    /// The socket file's (device, inode): removed on drop only while it is still this one.
    file: Option<(u64, u64)>,
    key: PublicKey,
    uid: u32,
}

/// Fails with `Closed` once `closed` is set.
async fn until_closed(closed: &mut watch::Receiver<bool>) -> Error {
    let _ = closed.wait_for(|c| *c).await;
    Error::Closed
}

impl Transport for Unix {
    type Conn = UnixConn;
    type Listener = UnixListener;

    async fn dial(&self, addr: &Address) -> Result<UnixConn, Error> {
        let path = url_path(&addr.url)?;
        let s = UnixStream::connect(&path).await.map_err(|e| Error::Unreachable(format!("{}: {e}", path.display())))?;
        let uid = s.peer_cred().map_err(io)?.uid();
        // another uid's listener is not ours, whatever key it would stand for
        if uid != own_uid()? || uid_key(uid) != addr.key {
            return Err(Error::KeyMismatch);
        }
        Ok(UnixConn::new(s, uid))
    }

    async fn dial_as(&self, addr: &Address, _secret: &StaticSecret) -> Result<UnixConn, Error> {
        self.dial(addr).await
    }

    /// Binds `cfg.url` (the secret is unused: the key stands for the uid). A socket file left by
    /// a process that is gone is replaced; one something answers on is `Io("in use")`, any other
    /// file there `Io` (never removed).
    async fn listen(&self, cfg: ListenConfig) -> Result<UnixListener, Error> {
        use std::os::unix::fs::FileTypeExt;
        let path = url_path(&cfg.url)?;
        if let Ok(m) = std::fs::symlink_metadata(&path) {
            if !m.file_type().is_socket() {
                return Err(Error::Io(format!("{}: exists and is no socket", path.display())));
            }
            if UnixStream::connect(&path).await.is_ok() {
                return Err(Error::Io(format!("{}: in use", path.display())));
            }
            std::fs::remove_file(&path).map_err(io)?;
        }
        let l = TokioListener::bind(&path).map_err(io)?;
        let uid = own_uid()?;
        Ok(UnixListener { l, file: file_id(&path), path, key: uid_key(uid), uid })
    }
}

impl Listener for UnixListener {
    type Conn = UnixConn;

    async fn accept(&mut self) -> Result<UnixConn, Error> {
        loop {
            // an accept error (EMFILE, ECONNABORTED, ...) is the moment's, never the listener's end
            let s = match self.l.accept().await {
                Ok((s, _)) => s,
                Err(_) => {
                    tokio::time::sleep(ACCEPT_RETRY).await;
                    continue;
                }
            };
            // another uid is dropped on arrival
            match s.peer_cred() {
                Ok(c) if c.uid() == self.uid => return Ok(UnixConn::new(s, self.uid)),
                _ => drop(s),
            }
        }
    }

    fn address(&self) -> Address {
        Address { url: url_of(&self.path), key: self.key }
    }

    fn close(&self) {}
}

/// A file's (device, inode), not following a symlink.
fn file_id(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

impl Drop for UnixListener {
    /// Removes the socket file unless another listener has replaced it since.
    fn drop(&mut self) {
        if self.file.is_some() && file_id(&self.path) == self.file {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Connection for UnixConn {
    type Send = UnixSend;
    type Recv = UnixRecv;

    fn peer_key(&self) -> PublicKey {
        uid_key(self.uid)
    }

    fn peer(&self) -> Peer {
        Peer::Unix { uid: self.uid }
    }

    fn source(&self) -> Option<crate::Source> {
        None
    }

    async fn open_stream(&self) -> Result<(UnixSend, UnixRecv), Error> {
        self.take()
    }

    /// The connection's one stream; after it, waits until the connection closes.
    async fn accept_stream(&self) -> Result<(UnixSend, UnixRecv), Error> {
        match self.take() {
            Ok(s) => Ok(s),
            Err(_) => Err(until_closed(&mut self.closed.subscribe()).await),
        }
    }

    fn close(&self) {
        self.closed.send_replace(true);
    }
}

impl SendStream for UnixSend {
    async fn write_all(&mut self, mut buf: &[u8]) -> Result<(), Error> {
        while !buf.is_empty() {
            let w = self.w.as_ref().ok_or(Error::Closed)?;
            tokio::select! {
                e = until_closed(&mut self.closed) => return Err(e),
                r = w.writable() => r.map_err(|_| Error::Closed)?,
            }
            match w.try_write(buf) {
                Ok(0) => return Err(Error::Closed),
                Ok(n) => buf = buf.get(n..).unwrap_or_default(),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err(Error::Closed),
            }
        }
        Ok(())
    }

    async fn finish(&mut self) -> Result<(), Error> {
        if let Some(mut w) = self.w.take() {
            let _ = poll_fn(|cx| Pin::new(&mut w).poll_shutdown(cx)).await;
        }
        Ok(())
    }
}

impl RecvStream for UnixRecv {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        loop {
            tokio::select! {
                e = until_closed(&mut self.closed) => return Err(e),
                r = self.r.readable() => r.map_err(|_| Error::Closed)?,
            }
            match self.r.try_read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err(Error::Closed),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::link;
    use std::time::Duration;

    const W: Duration = Duration::from_secs(5);

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("osis-unix-{}-{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rand_suffix() -> u64 {
        use std::hash::{BuildHasher, RandomState};
        RandomState::new().hash_one(std::time::SystemTime::now())
    }

    // notes/client-port.md §5: a unix session carries bytes both ways, each side sees Peer::Unix with its own uid, the dialer pins the uid key
    #[tokio::test]
    async fn round_trip_with_uid_peers() {
        let d = dir();
        let url = url_of(&d.join("s.sock"));
        let l = Unix.listen(ListenConfig { url: url.clone(), secret: StaticSecret::from_bytes([0; 32]) }).await.unwrap();
        let addr = l.address();
        let uid = own_uid().unwrap();
        assert_eq!(addr.key, uid_key(uid));
        let (out, mut incoming) = tokio::sync::mpsc::channel(4);
        tokio::spawn(link::serve(l, W, W, out));
        let mut a = link::dial(&Unix, &addr, None, W).await.unwrap();
        assert_eq!(a.peer, Peer::Unix { uid });
        assert!(a.tx.send(b"hi".to_vec(), usize::MAX));
        let mut b = incoming.recv().await.unwrap();
        assert_eq!(b.peer, Peer::Unix { uid });
        assert_eq!(b.rx.recv().await.unwrap(), b"hi");
        assert!(b.tx.send(b"yo".to_vec(), usize::MAX));
        assert_eq!(a.rx.recv().await.unwrap(), b"yo");
        drop(a.tx);
        assert_eq!(b.rx.recv().await, None);
        // a wrong pinned key is refused
        let bad = Address { url: url.clone(), key: uid_key(uid.wrapping_add(1)) };
        assert!(matches!(Unix.dial(&bad).await, Err(Error::KeyMismatch)));
        let _ = std::fs::remove_dir_all(&d);
    }

    // notes/client-port.md §5: a listener drops a peer of another uid before reading anything (the uid it expects stands in for another process's)
    #[tokio::test]
    async fn listener_drops_another_uid() {
        let d = dir();
        let url = url_of(&d.join("s.sock"));
        let mut l = Unix.listen(ListenConfig { url, secret: StaticSecret::from_bytes([0; 32]) }).await.unwrap();
        let addr = l.address();
        l.uid = l.uid.wrapping_add(1);
        let (out, mut incoming) = tokio::sync::mpsc::channel(4);
        tokio::spawn(link::serve(l, W, W, out));
        let mut a = link::dial(&Unix, &addr, None, W).await.unwrap();
        assert!(a.tx.send(b"hi".to_vec(), usize::MAX));
        assert_eq!(tokio::time::timeout(W, a.rx.recv()).await.unwrap(), None, "closed by the listener");
        assert!(tokio::time::timeout(Duration::from_millis(200), incoming.recv()).await.is_err(), "no session");
        let _ = std::fs::remove_dir_all(&d);
    }

    // notes/client-port.md §5: path sockets only: relative, abstract (NUL or no leading slash) and over-long paths are refused; a stale socket file is replaced, a live one is in use, another file is kept
    #[tokio::test]
    async fn path_rules() {
        for bad in ["unix://rel.sock", "unix://@abstract", "unix:///a\0b", "quic://x"] {
            assert!(url_path(bad).is_err(), "{bad}");
        }
        let long = format!("unix:///{}", "a".repeat(MAX_PATH));
        assert!(url_path(&long).is_err());
        assert!(url_path(&format!("unix:///{}", "a".repeat(MAX_PATH - 1))).is_ok());
        let d = dir();
        let url = url_of(&d.join("s.sock"));
        let cfg = || ListenConfig { url: url.clone(), secret: StaticSecret::from_bytes([0; 32]) };
        // a socket file nobody answers on (a crashed daemon's) is replaced
        drop(std::os::unix::net::UnixListener::bind(d.join("s.sock")).unwrap());
        assert!(d.join("s.sock").exists());
        let l = Unix.listen(cfg()).await.unwrap();
        assert!(matches!(Unix.listen(cfg()).await, Err(Error::Io(_))));
        drop(l);
        assert!(!d.join("s.sock").exists());
        // a file that is no socket is never replaced
        std::fs::write(d.join("s.sock"), b"keep").unwrap();
        assert!(matches!(Unix.listen(cfg()).await, Err(Error::Io(_))));
        assert_eq!(std::fs::read(d.join("s.sock")).unwrap(), b"keep");
        let _ = std::fs::remove_dir_all(&d);
    }

    // notes/client-port.md §5: a listener dropped after another replaced its socket file leaves the new one in place; dropped while its own, it removes it
    #[tokio::test]
    async fn drop_removes_only_its_own_socket() {
        let d = dir();
        let path = d.join("s.sock");
        let cfg = || ListenConfig { url: url_of(&path), secret: StaticSecret::from_bytes([0; 32]) };
        let old = Unix.listen(cfg()).await.unwrap();
        std::fs::remove_file(&path).unwrap();
        let new = Unix.listen(cfg()).await.unwrap();
        drop(old);
        assert!(path.exists(), "the replacing listener's socket stays");
        drop(new);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
