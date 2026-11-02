//! The client side of the client port (notes/client-port.md §1, §2): `Osis::attach` dials a node
//! (step (b): its unix socket, as Owner) and every tid-addressed call of the handle goes there
//! (`Source::Remote`). One connection per attachment, driven by a proto `ClientSession` on a
//! thread of its own; a call blocks its caller until its Reply. Watches are subscriptions whose
//! Reply and Notifies enter the handle's dispatcher queue in wire order, so remote callbacks run
//! on the dispatcher like local ones. Writes carry a nonce from 1 per session.

use super::codec::{self as c, u};
use super::method;
use crate::error::{Error, Result};
use crate::handle::{Config, Osis, WeakOsis};
use crate::watch::{Callback, Filter, Msg, PortEvent, Subscription, lock};
use osis_base::{Clock, Tid, Value};
use osis_proto::client::SMALL_REPLY;
use osis_proto::serving::REPLY_BUDGET;
use osis_proto::{ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Code, Command, Outcome, Payload};
use osis_transport::{Address, Unix};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// Bytes queued for the node and not yet taken before the connection is dropped (as the
/// driver's `MAX_QUEUED`; a session within its window never comes near it).
const MAX_QUEUED: usize = 64 * 1024 * 1024;
/// The name of the file in a store directory naming the socket a daemon listens on.
pub const SOCK_FILE: &str = "sock";

/// The socket a daemon serving `store` listens on (notes/client-port.md §5): in osis's own
/// directory under `$XDG_RUNTIME_DIR` (`osis/`), else `/tmp/osis-<uid>/`, named by the store
/// path's hash (`sun_path` holds 108 bytes, a store path may not). The directory is created 0700
/// and checked: owned by this uid, mode 0700, not a symlink.
pub fn socket_path(store: &Path) -> Result<PathBuf> {
    let uid = own_uid()?;
    let dir = match std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        Some(d) => PathBuf::from(d).join("osis"),
        None => PathBuf::from(format!("/tmp/osis-{uid}")),
    };
    socket_dir(&dir, uid)?;
    let abs = std::path::absolute(store).map_err(|e| Error::Storage(e.to_string()))?;
    let h = osis_base::hash::hash(abs.as_os_str().as_encoded_bytes());
    let name: String = h.iter().take(8).map(|b| format!("{b:02x}")).collect();
    Ok(dir.join(format!("{name}.sock")))
}

/// Creates `dir` 0700 if missing, then checks it is a directory of `uid`'s, mode 0700, not a
/// symlink; refuses it otherwise (another user's or a planted directory).
pub fn socket_dir(dir: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let mut b = std::fs::DirBuilder::new();
    b.mode(0o700);
    match b.create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(Error::Storage(format!("{}: {e}", dir.display()))),
    }
    let m = std::fs::symlink_metadata(dir).map_err(|e| Error::Storage(format!("{}: {e}", dir.display())))?;
    if m.file_type().is_symlink() || !m.is_dir() || m.uid() != uid || m.mode() & 0o777 != 0o700 {
        return Err(Error::Storage(format!("{}: not a directory of this user's with mode 0700", dir.display())));
    }
    Ok(())
}

/// This process's uid (`SO_PEERCRED` of a socket pair, on a small runtime of its own).
pub fn own_uid() -> Result<u32> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_io().build().map_err(|e| Error::Storage(e.to_string()))?;
    let _g = rt.enter();
    osis_transport::unix::own_uid().map_err(|e| Error::Storage(e.to_string()))
}

/// The node's person and node actors (`Osis::me`, `node`, `home` of an attached handle).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Who {
    pub me: Tid,
    pub node: Tid,
    pub home: Tid,
}

type CallReply = std::sync::mpsc::Sender<std::result::Result<Outcome, Code>>;
type Sink = Box<dyn FnMut(PortEvent) + Send>;

enum Cmd {
    Auth { session: [u8; 16], reply: CallReply },
    Call { token: u64, max_reply: usize, method: u64, args: Vec<Value>, reply: CallReply },
    Sub { token: u64, filter: Value, sink: Sink },
    Unsub { token: u64 },
}

/// One attachment: the connection's command channel and the session's state.
pub(crate) struct Remote {
    pub who: Who,
    /// The node epoch Auth returned (a retry after a reconnect is safe only under the same one).
    pub epoch: [u8; 16],
    tx: mpsc::UnboundedSender<Cmd>,
    tokens: AtomicU64,
    nonces: AtomicU64,
    /// The materialization bound of reads.
    limit: usize,
}

/// A call sent whose connection ended before its reply.
const LOST: &str = "connection to the node ended before the reply";

/// A nonce'd call's error: one whose reply was lost may or may not have applied (no reconnect
/// in step (b), so no retry under its nonce).
fn once_err(e: Error) -> Error {
    match e {
        Error::Network(m) if m == LOST => Error::Invalid("outcome unknown".into()),
        e => e,
    }
}

fn net(m: impl std::fmt::Display) -> Error {
    Error::Network(m.to_string())
}

impl Remote {
    fn token(&self) -> u64 {
        self.tokens.fetch_add(1, Ordering::AcqRel)
    }

    /// The next write nonce of this session.
    pub fn nonce(&self) -> u64 {
        self.nonces.fetch_add(1, Ordering::AcqRel)
    }

    /// One Call, waited for: its result value; a `TooLarge` reply under the small allowance is
    /// asked again under the whole reply budget (a write again under its nonce).
    pub fn call(&self, m: u64, args: Vec<Value>) -> Result<Value> {
        match self.call_with(m, args.clone(), SMALL_REPLY) {
            Err(Error::TooLarge { limit }) if limit == SMALL_REPLY => self.call_with(m, args, REPLY_BUDGET.min(self.limit.saturating_add(SMALL_REPLY)).max(SMALL_REPLY)),
            r => r,
        }
    }

    /// A Call whose reply may take `max_reply` bytes (a `stream_read` page).
    pub fn call_big(&self, m: u64, args: Vec<Value>, max_reply: usize) -> Result<Value> {
        self.call_with(m, args, max_reply.clamp(SMALL_REPLY, REPLY_BUDGET))
    }

    fn call_with(&self, m: u64, args: Vec<Value>, max_reply: usize) -> Result<Value> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.tx.send(Cmd::Call { token: self.token(), max_reply, method: m, args, reply: tx }).map_err(|_| net("connection to the node closed"))?;
        match crate::net::blocking(|| rx.recv()) {
            Ok(Ok(Outcome::Ok { value, .. })) => Ok(value),
            Ok(Ok(Outcome::Err { code, detail })) => Err(c::error_of(code, detail)),
            Ok(Err(Code::REFUSED)) => Err(Error::Unsupported("refused by the node (no Owner session)".into())),
            Ok(Err(Code::UNSUPPORTED)) => Err(Error::Unsupported("node too old".into())),
            Ok(Err(code)) => Err(net(format!("node answered error {}", code.0))),
            Err(_) => Err(net(LOST)),
        }
    }

    pub fn unsub(&self, token: u64) {
        let _ = self.tx.send(Cmd::Unsub { token });
    }
}

/// The session driver: the proto client session over a unix link, on its own thread.
struct Io {
    cs: ClientSession,
    calls: BTreeMap<u64, CallReply>,
    sinks: BTreeMap<u64, Sink>,
    timer: Option<u64>,
    taken: u64,
}

impl Io {
    /// Carries out the session's outputs; `false` once it closed.
    fn outputs(&mut self, link: &osis_transport::link::LinkTx, out: Vec<ClientOutput>) -> bool {
        for o in out {
            match o {
                ClientOutput::Send(b) => {
                    if !link.send(b, MAX_QUEUED) {
                        return false;
                    }
                }
                ClientOutput::Close => return false,
                ClientOutput::SetTimer(t) => self.timer = Some(t),
                ClientOutput::Event(ClientEvent::Reply { token, reply }) => {
                    if let Some(r) = self.calls.remove(&token) {
                        let _ = r.send(reply);
                    } else if let Some(s) = self.sinks.get_mut(&token) {
                        match reply {
                            Ok(Outcome::Ok { value, .. }) => s(PortEvent::Initial(value)),
                            Ok(Outcome::Err { code, detail }) => {
                                s(PortEvent::Initial(c::outcome_err(&c::error_of(code, detail)).to_value()));
                                self.sinks.remove(&token);
                            }
                            Err(_) => {
                                s(PortEvent::Closed);
                                self.sinks.remove(&token);
                            }
                        }
                    }
                }
                ClientOutput::Event(ClientEvent::Notify { token, payload }) => {
                    let lapsed = payload == Payload::Lapsed;
                    if let Some(s) = self.sinks.get_mut(&token) {
                        s(PortEvent::Notify(payload));
                    }
                    if lapsed {
                        self.sinks.remove(&token);
                    }
                }
                ClientOutput::Event(_) => {}
            }
        }
        true
    }

    fn command(&mut self, now: u64, cmd: Cmd) -> Vec<ClientOutput> {
        let c = match cmd {
            Cmd::Auth { session, reply } => {
                self.calls.insert(0, reply);
                Command::Auth { token: 0, session }
            }
            Cmd::Call { token, max_reply, method, args, reply } => {
                self.calls.insert(token, reply);
                Command::Call { token, max_reply: max_reply as u64, method, args }
            }
            Cmd::Sub { token, filter, sink } => {
                self.sinks.insert(token, sink);
                Command::Sub { token, max_reply: REPLY_BUDGET as u64, filter }
            }
            Cmd::Unsub { token } => {
                self.sinks.remove(&token);
                Command::Unsub { token }
            }
        };
        self.cs.handle(now, ClientInput::Command(c))
    }

    fn close(&mut self) {
        self.calls.clear();
        for (_, mut s) in std::mem::take(&mut self.sinks) {
            s(PortEvent::Closed);
        }
    }
}

/// Runs the connection until it or the handle ends.
async fn run(addr: Address, clock: Arc<dyn Clock>, mut io: Io, mut rx: mpsc::UnboundedReceiver<Cmd>, ready: std::sync::mpsc::Sender<std::result::Result<(), String>>) {
    let link = match osis_transport::link::dial(&Unix, &addr, None, Duration::from_secs(10)).await {
        Ok(l) => l,
        Err(e) => {
            let _ = ready.send(Err(e.to_string()));
            return;
        }
    };
    let _ = ready.send(Ok(()));
    let osis_transport::Link { tx, rx: mut lrx, .. } = link;
    let now = || clock.now_wall_ms().0;
    let start = io.cs.handle(now(), ClientInput::Start);
    let mut up = io.outputs(&tx, start);
    while up {
        let wait = io.timer.map_or(Duration::from_secs(60), |t| Duration::from_millis(t.saturating_sub(now())));
        tokio::select! {
            b = lrx.recv() => match b {
                Some(b) => {
                    let o = io.cs.handle(now(), ClientInput::Bytes(b));
                    up = io.outputs(&tx, o);
                }
                None => up = false,
            },
            c = rx.recv() => match c {
                Some(c) => {
                    let o = io.command(now(), c);
                    up = io.outputs(&tx, o);
                }
                None => up = false,
            },
            _ = tokio::time::sleep(wait) => {
                if tx.taken() != io.taken {
                    io.taken = tx.taken();
                    let o = io.cs.handle(now(), ClientInput::Sent);
                    up = io.outputs(&tx, o);
                }
                io.timer = None;
                let o = io.cs.handle(now(), ClientInput::Timer);
                up = up && io.outputs(&tx, o);
            }
        }
    }
    io.close();
}

impl Osis {
    /// Attaches to the node serving the unix socket at `socket` (notes/client-port.md §1):
    /// every call addressed by a tid or group goes there as Owner (the socket's peer has this
    /// process's uid), `me`/`node`/`home` are the node's; `settle` waits for the node's
    /// deliveries too. Process-wide calls the port does not carry (pairing, devices, hosting,
    /// links, cards, bundles, `read(|r| ..)`, `Internals`) fail `Unsupported`. `cfg` gives the
    /// clock, dispatcher and materialization bound; its store is not used (a scratch memory
    /// database stands in until the no-store profile, step (f)).
    pub fn attach(socket: &Path, cfg: Config) -> Result<Osis> {
        let limit = cfg.materialize_limit;
        let scratch = Config { store: crate::StoreAt::Memory(crate::MemStore::new()), runtime: crate::Runtime::None, hosts: Vec::new(), transport: None, ..cfg };
        let (db, _) = Osis::create(scratch)?;
        let uid = own_uid()?;
        let addr = Address { url: osis_transport::unix::url_of(socket), key: osis_transport::unix::uid_key(uid) };
        let (tx, rx) = mpsc::unbounded_channel();
        let mut challenge = [0u8; 32];
        let mut session = [0u8; 16];
        {
            use osis_crypto::RngCore;
            osis_crypto::OsRng.fill_bytes(&mut challenge);
            osis_crypto::OsRng.fill_bytes(&mut session);
        }
        let io = Io { cs: ClientSession::new(ClientConfig { peer_static_key: addr.key, challenge }), calls: BTreeMap::new(), sinks: BTreeMap::new(), timer: None, taken: 0 };
        let clock = db.inner.clock.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("osis-port-client".into())
            .spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
                rt.block_on(run(addr, clock, io, rx, ready_tx));
            })
            .map_err(|e| Error::Storage(e.to_string()))?;
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(net(e)),
            Err(_) => return Err(net("no connection")),
        }
        // Auth without a key (the Owner tier): the node's epoch; then who the node is
        let (atx, arx) = std::sync::mpsc::channel();
        tx.send(Cmd::Auth { session, reply: atx }).map_err(|_| net("connection to the node closed"))?;
        let epoch = match arx.recv() {
            Ok(Ok(Outcome::Ok { value, .. })) => value.as_array::<16>().ok_or_else(|| net("bad node epoch"))?,
            Ok(Err(Code::REFUSED)) => return Err(Error::Unsupported("the node refused this session (not its uid)".into())),
            Ok(Err(Code::UNSUPPORTED)) => return Err(Error::Unsupported("node too old".into())),
            _ => return Err(net("no answer to Auth")),
        };
        let r = Remote { who: Who { me: db.me(), node: db.node(), home: db.home() }, epoch, tx, tokens: AtomicU64::new(1), nonces: AtomicU64::new(1), limit };
        let w = r.call(method::WHOAMI, vec![])?;
        let mut a = c::Args::new(w)?;
        let who = Who { me: a.tid()?, node: a.tid()?, home: a.tid()? };
        let r = Remote { who, ..r };
        let _ = db.inner.remote.set(Arc::new(r));
        Ok(db)
    }

    /// Whether this handle is attached to a node (`Osis::attach`).
    pub fn is_attached(&self) -> bool {
        self.attached()
    }

    /// The attached node, or `Unsupported` naming `what`.
    pub(crate) fn rem(&self) -> &Remote {
        self.remote().map(|r| &**r).unwrap_or_else(|| unreachable!("routed remote without an attachment"))
    }

    /// A call at the attached node.
    pub(crate) fn rcall(&self, m: u64, args: Vec<Value>) -> Result<Value> {
        self.rem().call(m, args)
    }

    /// Fails `Unsupported` on an attached handle: a process-wide call the port does not carry.
    pub(crate) fn local_only(&self, what: &str) -> Result<()> {
        if self.attached() { Err(Error::Unsupported(format!("{what} on a handle attached to a node"))) } else { Ok(()) }
    }

    /// A write batch at the attached node, under a fresh nonce (a reply lost to a `TooLarge`
    /// retry is answered again from the node's memory).
    pub(crate) fn remote_write(&self, mut wire: Vec<Value>) -> Result<Option<crate::write::Committed>> {
        let r = self.rem();
        wire.insert(0, u(r.nonce()));
        let v = r.call(method::WRITE, wire).map_err(once_err)?;
        let o = c::Args::of(vec![v]).opt()?;
        o.map(c::committed).transpose()
    }

    /// A nonce'd undo/redo/revert at the attached node.
    pub(crate) fn remote_once(&self, m: u64, arg: Value) -> Result<Value> {
        let r = self.rem();
        r.call(m, vec![u(r.nonce()), arg]).map_err(once_err)
    }

    /// Registers `cb` for a subscription at the attached node: its Reply (`PortEvent::Initial`)
    /// and Notifies reach `cb` through the dispatcher, in wire order. Returns the subscription
    /// and the initial value (or the Sub's error).
    pub(crate) fn remote_sub(&self, filter: Value, cb: Callback) -> Result<(Subscription, Value)> {
        let r = self.remote().ok_or(Error::Closed)?.clone();
        let token = r.token();
        let mut sub = self.locked(|l| self.inner.dispatch.register(l.seq + 1, Filter::Port(token), cb));
        sub.port = Some((Arc::downgrade(&r), token));
        let weak: WeakOsis = self.downgrade();
        let (itx, irx) = std::sync::mpsc::channel::<Value>();
        let first = Mutex::new(Some(itx));
        let sink: Sink = Box::new(move |ev: PortEvent| {
            if let PortEvent::Initial(v) = &ev
                && let Some(tx) = lock(&first).take()
            {
                let _ = tx.send(v.clone());
            }
            if let Some(db) = weak.hold() {
                db.locked(|l| {
                    l.seq += 1;
                    db.inner.dispatch.send(l.seq, Msg::Port(token, ev));
                });
            }
        });
        r.tx.send(Cmd::Sub { token, filter, sink }).map_err(|_| net("connection to the node closed"))?;
        let v = crate::net::blocking(|| irx.recv()).map_err(|_| net("connection to the node closed"))?;
        // a Sub answered by an error: `[1, code, detail*]`
        if let Value::List(l) = &v
            && l.first().and_then(Value::as_uint) == Some(1)
            && let Ok(Err(e)) = c::read(v.clone())
        {
            return Err(e);
        }
        Ok((sub, v))
    }

    /// Waits for the attached node's deliveries for changes made so far to reach the
    /// dispatcher queue (`settle` then runs them).
    pub(crate) fn remote_settle(&self) {
        if let Some(r) = self.remote() {
            let _ = r.call(method::SETTLE, vec![]);
        }
    }
}

/// An aspect delivery `[tid, ak, read, source]`, or a fired signal `[.., true]`.
/// What an aspect delivery holds: thing, aspect, read result, source, fired.
type Delivered = (Tid, osis_base::Ak, Result<Option<Value>>, crate::watch::Source, bool);

fn delivery(v: Value) -> Result<Delivered> {
    let mut a = c::Args::new(v)?;
    let (t, ak, r, s) = (a.tid()?, a.ak()?, c::read(a.next()?)?, c::source(a.next()?)?);
    let fired = a.rest().first() == Some(&Value::Bool(true));
    Ok((t, ak, r, s, fired))
}


/// A remote callback of `T`s.
pub(crate) type CallbackOf<T> = Box<dyn FnMut(&Osis, T) + Send>;
/// A remote callback of `Change<Value>`s.
pub(crate) type ChangeFn = CallbackOf<crate::watch::Change<Value>>;

impl Osis {
    /// `get` / `get_path` at the attached node.
    pub(crate) fn remote_get(&self, tid: Tid, ak: &osis_base::Ak, path: &osis_schema::Path) -> Result<Option<Value>> {
        let v = self.rcall(method::GET, vec![Value::Tid(tid), c::ak_v(ak), c::path_v(path)])?;
        c::read(v)?
    }

    /// The length of a string or blob at the attached node (`None`: absent).
    pub(crate) fn remote_len(&self, tid: Tid, ak: &osis_base::Ak, path: &osis_schema::Path) -> Result<Option<u64>> {
        let v = self.rcall(method::LEN, vec![Value::Tid(tid), c::ak_v(ak), c::path_v(path)])?;
        c::Args::of(vec![v]).opt()?.map(|n| n.as_uint().ok_or_else(|| c::bad("length"))).transpose()
    }

    /// One `stream_read` page.
    pub(crate) fn remote_read(&self, tid: Tid, ak: &osis_base::Ak, path: &osis_schema::Path, offset: u64, n: usize) -> Result<Vec<u8>> {
        let v = self.rem().call_big(method::STREAM_READ, vec![Value::Tid(tid), c::ak_v(ak), c::path_v(path), u(offset), u(n as u64)], n.saturating_add(SMALL_REPLY))?;
        c::Args::of(vec![v]).bytes()
    }

    /// `AspectRef::on_change` at the attached node: the initial value, then each change that
    /// differs from the last delivered (an error always), signals as they fire.
    pub(crate) fn remote_on_change(&self, tid: Tid, ak: osis_base::Ak, mut f: ChangeFn) -> Result<Subscription> {
        use crate::watch::{Change, Delivery, PortEvent, Source};
        let mut last: Option<Result<Option<Value>>> = None;
        let ak2 = ak.clone();
        let cb: Callback = Box::new(move |db, d| {
            let Delivery::Port(ev) = d else { return };
            match ev {
                PortEvent::Initial(v) => {
                    let value = c::read(v).unwrap_or_else(Err);
                    last = Some(value.clone());
                    f(db, Change { tid, ak: ak2.clone(), value, source: Source::Initial });
                }
                PortEvent::Notify(Payload::Delivery { value, .. }) => {
                    let Ok((t, ak, value, source, fired)) = delivery(value) else { return };
                    if fired {
                        f(db, Change { tid: t, ak, value, source });
                    } else if value.is_err() || last.as_ref() != Some(&value) {
                        last = Some(value.clone());
                        f(db, Change { tid: t, ak, value, source });
                    }
                }
                PortEvent::Notify(Payload::TooLarge { source, .. }) => {
                    let source = c::source(source).unwrap_or(Source::Initial);
                    last = None;
                    f(db, Change { tid, ak: ak2.clone(), value: Err(Error::TooLarge { limit: REPLY_BUDGET }), source });
                }
                PortEvent::Notify(Payload::Lapsed) | PortEvent::Closed => {
                    f(db, Change { tid, ak: ak2.clone(), value: Err(net("the node's subscription ended")), source: Source::Initial });
                }
            }
        });
        Ok(self.remote_sub(Value::List(vec![u(super::filter::ASPECT), Value::Tid(tid), c::ak_v(&ak)]), cb)?.0)
    }

    /// `AspectRef::watch` at the attached node: the state holds the latest value that `valid`
    /// accepts (else absent), set from the Sub's reply before this returns.
    pub(crate) fn remote_watch(&self, tid: Tid, ak: osis_base::Ak, valid: Box<dyn Fn(&Value) -> bool + Send>) -> Result<(Arc<crate::watch::WatchState>, Subscription)> {
        use crate::watch::{Delivery, PortEvent, WatchState};
        let st = WatchState::new(Ok(None));
        let s2 = st.clone();
        let check = move |r: Result<Option<Value>>| r.map(|v| v.filter(|x| valid(x)));
        let cb: Callback = Box::new(move |_, d| {
            let Delivery::Port(ev) = d else { return };
            match ev {
                PortEvent::Initial(v) => s2.update(check(c::read(v).unwrap_or_else(Err))),
                PortEvent::Notify(Payload::Delivery { value, .. }) => {
                    if let Ok((_, _, v, _, false)) = delivery(value) {
                        s2.update(check(v));
                    }
                }
                PortEvent::Notify(Payload::TooLarge { .. }) => s2.update(Err(Error::TooLarge { limit: REPLY_BUDGET })),
                PortEvent::Notify(Payload::Lapsed) | PortEvent::Closed => s2.update(Err(net("the node's subscription ended"))),
            }
        });
        let (sub, initial) = self.remote_sub(Value::List(vec![u(super::filter::ASPECT), Value::Tid(tid), c::ak_v(&ak)]), cb)?;
        // the value at registration, before this returns (the dispatcher's copy is the same)
        st.update(c::read(initial)?);
        Ok((st, sub))
    }

    /// `watch_thing` at the attached node.
    pub(crate) fn remote_watch_thing(&self, tid: Tid, mut f: ChangeFn) -> Subscription {
        use crate::watch::{Change, Delivery, PortEvent, Source};
        let mut last: BTreeMap<osis_base::Ak, Result<Option<Value>>> = BTreeMap::new();
        let cb: Callback = Box::new(move |db, d| {
            let Delivery::Port(ev) = d else { return };
            match ev {
                PortEvent::Initial(v) => {
                    for x in c::Args::of(vec![v]).list().unwrap_or_default() {
                        let Ok(mut a) = c::Args::new(x) else { continue };
                        let (Ok(ak), Ok(Ok(value))) = (a.ak(), a.next().map(c::read)) else { continue };
                        last.insert(ak.clone(), value.clone());
                        f(db, Change { tid, ak, value, source: Source::Initial });
                    }
                }
                PortEvent::Notify(Payload::Delivery { value, .. }) => {
                    let Ok((t, ak, value, source, fired)) = delivery(value) else { return };
                    if fired || value.is_err() || last.get(&ak) != Some(&value) {
                        last.insert(ak.clone(), value.clone());
                        f(db, Change { tid: t, ak, value, source });
                    }
                }
                _ => {}
            }
        });
        self.remote_sub(Value::List(vec![u(super::filter::THING), Value::Tid(tid)]), cb).map(|x| x.0).unwrap_or_else(|_| self.dead_sub())
    }

    /// `watch_roster` at the attached node.
    pub(crate) fn remote_watch_roster(&self, actor: Tid, mut f: CallbackOf<crate::read::Roster>) -> Subscription {
        use crate::watch::{Delivery, PortEvent};
        let mut last = None;
        let cb: Callback = Box::new(move |db, d| {
            let Delivery::Port(PortEvent::Initial(v) | PortEvent::Notify(Payload::Delivery { value: v, .. })) = d else { return };
            if let Ok(r) = c::roster(v)
                && last.as_ref() != Some(&r)
            {
                last = Some(r.clone());
                f(db, r);
            }
        });
        self.remote_sub(Value::List(vec![u(super::filter::ROSTER), Value::Tid(actor)]), cb).map(|x| x.0).unwrap_or_else(|_| self.dead_sub())
    }

    /// `on_diagnostic` at the attached node (its diagnostics; this process's own go nowhere).
    pub(crate) fn remote_on_diagnostic(&self, mut f: CallbackOf<osis_node::Diagnostic>) -> Subscription {
        use crate::watch::{Delivery, PortEvent};
        let cb: Callback = Box::new(move |db, d| {
            if let Delivery::Port(PortEvent::Notify(Payload::Delivery { value, .. })) = d
                && let Ok(x) = c::diag(value)
            {
                f(db, x);
            }
        });
        self.remote_sub(Value::List(vec![u(super::filter::DIAGNOSTICS)]), cb).map(|x| x.0).unwrap_or_else(|_| self.dead_sub())
    }

    /// `watch_status` at the attached node.
    pub(crate) fn remote_watch_status(&self, mut f: CallbackOf<crate::share::Status>) -> Subscription {
        use crate::watch::{Delivery, PortEvent};
        let cb: Callback = Box::new(move |db, d| {
            if let Delivery::Port(PortEvent::Initial(v) | PortEvent::Notify(Payload::Delivery { value: v, .. })) = d
                && let Ok(s) = c::status(v)
            {
                f(db, s);
            }
        });
        self.remote_sub(Value::List(vec![u(super::filter::STATUS)]), cb).map(|x| x.0).unwrap_or_else(|_| self.dead_sub())
    }

    /// A subscription that never fires (a remote watch whose Sub failed on a call that cannot
    /// return an error).
    fn dead_sub(&self) -> Subscription {
        self.inner.dispatch.register(u64::MAX, Filter::Port(u64::MAX), Box::new(|_, _| {}))
    }
}

