//! The client side of the client port (notes/client-port.md §1, §2, §6): a `Connection` is one
//! connection to a node: a dialer `osis_proto::Session` (over a store that admits nothing) on a
//! thread of its own that a call blocks on until its Reply. A handle sends tid-addressed calls to it (`crate::sources`). Watches are
//! subscriptions whose Reply and Notifies enter the handle's dispatcher queue in wire order, so
//! node callbacks run on the dispatcher like local ones. Writes carry a nonce from 1 per session.
//!
//! **Reconnect contract** (§1): a dropped connection is redialed with back-off, under the same
//! session id. Once up: Auth, schemas again, every live subscription again (its new Reply closes the
//! gap; signals in the gap are lost), and writes still unanswered are sent again under their nonce,
//! marked (the node answers a nonce it remembers with its first result, and never runs one it
//! cannot tell apart from a repeat: `OutcomeUnknown`). What the caller sees:
//! - a call while the connection is down: `Network` at once; it was not sent;
//! - a read in flight when it drops: `Network`;
//! - a write in flight when it drops: blocks until reconnected, then its one result;
//!   `OutcomeUnknown` if the node restarted, forgot the nonce, refused the session or
//!   `CONNECTION_WAIT` passed with no connection;
//! - a watch: `Err(Network)` while down, then the value again as a new `Origin::Initial`;
//! - a watch started while down: `Err(Network)` from the call, except what does not need the node
//!   to answer: `on_status_change`, which reports it down, and `on_diagnostic`, quiet until it is up
//!   (`Refused` once the node has ended the session: it will never be up).
//!
//! `OutcomeUnknown` means the write may or may not have applied. Repeating it is a new write (a
//! new nonce), so a blind repeat can apply it twice: read what it wrote first, and repeat only if
//! that is not there.

use super::codec::{self as c, outcome_err, u};
use super::method;
use crate::error::{Error, Result};
use crate::handle::{AppConfig, Config, Osis, WeakOsis};
use crate::watch::{Callback, Change, Delivery, Filter, Msg, PortEvent, Origin, Subscription, lock};
use osis_base::{Clock, Tid, Value};
use osis_proto::window::SMALL_REPLY;
use osis_proto::session::REPLY_BUDGET;
use osis_proto::hello::PING_INTERVAL_MS;
use osis_proto::msg::{Id, NODE_IDS};
use osis_proto::{Code, MemoryLabelStore, Message, Outcome, Payload, Session, SessionConfig, SessionInput, SessionOutput};
use osis_transport::{Address, Unix};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// Bytes queued for the node and not yet taken before the connection is dropped: what a session
/// within its window can have unwritten (`SEND_QUEUE`), so a compliant one never reaches it.
const MAX_QUEUED: usize = osis_proto::session::SEND_QUEUE;
/// First pause before a redial, doubled after each failure up to `RETRY_MAX`. Minor: 0 redials in
/// a tight loop (each dial is real work on both sides); infinity never redials, so a dropped
/// connection stays `Network`; `RETRY_MAX` is how late a client notices its node came back.
const RETRY_MIN: Duration = Duration::from_millis(100);
const RETRY_MAX: Duration = Duration::from_secs(30);
/// How long one attempt to reach a node lasts, and how long a write in flight waits across a dropped
/// connection before it is `OutcomeUnknown`: a sync call has no future to drop. Minor: at 0 nothing
/// connects and every write across a drop is unknown; at infinity a node that takes the connection
/// and never answers holds its attempt, and the write, for good.
pub(crate) const CONNECTION_WAIT: Duration = Duration::from_secs(30);
/// The tokens of a connection's own Auth and `whoami`; every other comes from `TOKENS`.
const AUTH_TOKEN: u64 = 0;
const WHO_TOKEN: u64 = 1;
/// Subscription and call tokens, unique in the process (the dispatcher's `Filter::Port` holds
/// subscriptions of every connection).
static TOKENS: AtomicU64 = AtomicU64::new(16);

fn next_token() -> u64 {
    TOKENS.fetch_add(1, Ordering::AcqRel)
}

/// The socket a node on `store` listens on: in osis's own
/// directory under `$XDG_RUNTIME_DIR` (`osis/`), else `/tmp/osis-<uid>/`, named by the store
/// path's hash (`sun_path` holds 108 bytes, a store path may not). However the path is spelled, one
/// store has one socket: symlinks are followed, and a store not there yet is named as it stands. The
/// directory is created 0700 and checked: owned by this uid, mode 0700, not a symlink. `Storage` when
/// it is not, or the path would not fit a socket.
pub fn socket_path(store: &Path) -> Result<PathBuf> {
    socket_path_under(std::env::var_os("XDG_RUNTIME_DIR").as_deref().map(Path::new), store)
}

/// `socket_path` with `runtime_dir` as `$XDG_RUNTIME_DIR`.
pub fn socket_path_under(runtime_dir: Option<&Path>, store: &Path) -> Result<PathBuf> {
    let uid = own_uid()?;
    let dir = match runtime_dir.filter(|d| !d.as_os_str().is_empty()) {
        Some(d) => d.join("osis"),
        None => PathBuf::from(format!("/tmp/osis-{uid}")),
    };
    socket_dir(&dir, uid)?;
    let abs = std::fs::canonicalize(store).or_else(|_| std::path::absolute(store)).map_err(|e| Error::Storage(e.to_string()))?;
    let h = osis_base::hash::hash(abs.as_os_str().as_encoded_bytes());
    let name: String = h.iter().take(8).map(|b| format!("{b:02x}")).collect();
    let sock = dir.join(format!("{name}.sock"));
    if sock.as_os_str().len() > osis_transport::unix::MAX_PATH {
        return Err(Error::Storage(format!("{}: too long a path for a socket", sock.display())));
    }
    Ok(sock)
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

/// This process's uid (`SO_PEERCRED` of a socket pair).
pub fn own_uid() -> Result<u32> {
    osis_transport::unix::own_uid().map_err(|e| Error::Storage(e.to_string()))
}

/// The node's account and node actors (`Osis::me`, `node` of a thin client).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Who {
    pub me: Tid,
    pub node: Tid,
    pub home: Tid,
}

type CallReply = std::sync::mpsc::Sender<std::result::Result<Outcome, Code>>;
type Sink = Box<dyn FnMut(PortEvent) + Send>;

enum Cmd {
    /// `nonce`: a write's slot, its nonce taken on the I/O thread when first sent (0 until
    /// then) and put first in `args`, so nonces go out in the order the node must see them.
    Call { token: u64, max_reply: usize, method: u64, args: Vec<Value>, nonce: Option<Arc<AtomicU64>>, reply: CallReply },
    /// `again`: subscribed again on each reconnect (not a `wait_synced`, which answers once).
    Sub { token: u64, filter: Value, again: bool, sink: Sink },
    Unsub { token: u64 },
    /// Registered again on each reconnect.
    Schema { file: String, src: String },
}

/// Marks a write's nonce as sent again (spec/wire.md §11.2): a node that holds no state for the
/// session must not take it for new, since it may have run before that state was evicted.
pub(crate) const NONCE_RESENT: u64 = 1 << 62;

/// What the connection is doing, for callers and for `status`.
#[derive(Default)]
struct LinkInner {
    up: bool,
    /// How the latest connection attempt ended (none yet).
    tried: Option<Result<()>>,
    /// Never up again: the node refused this session, or there is no connection.
    ended: Option<Error>,
    who: Option<Who>,
    /// Waiting for the first attempt's end (`Connection::first`).
    wakers: Vec<std::task::Waker>,
}

impl LinkInner {
    fn wake(&mut self) {
        for w in self.wakers.drain(..) {
            w.wake();
        }
    }
}

#[derive(Default)]
struct LinkState {
    m: Mutex<LinkInner>,
}

impl LinkState {
    fn tried(&self, r: Result<()>) {
        let mut g = lock(&self.m);
        g.up = r.is_ok();
        g.tried = Some(r);
        g.wake();
    }

    fn end(&self, e: Error) {
        let mut g = lock(&self.m);
        g.up = false;
        g.tried = Some(Err(e.clone()));
        g.ended = Some(e);
        g.wake();
    }
}

/// `Connection::first`.
struct FirstAttempt(Arc<LinkState>);

impl std::future::Future for FirstAttempt {
    type Output = Result<()>;
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<()>> {
        let mut g = lock(&self.0.m);
        if let Some(r) = &g.tried {
            return std::task::Poll::Ready(r.clone());
        }
        if !g.wakers.iter().any(|w| w.will_wake(cx.waker())) {
            g.wakers.push(cx.waker().clone());
        }
        std::task::Poll::Pending
    }
}

/// A subscription at a node that a future holds: ended when the future goes.
struct Unsub(Arc<Connection>, u64);

impl Drop for Unsub {
    fn drop(&mut self) {
        self.0.unsub(self.1);
    }
}

/// One connection: its command channel and the session's state.
pub(crate) struct Connection {
    /// What group sources name.
    pub addr: crate::Address,
    /// Its command channel; none once `end` closed it, which ends the connection's thread.
    tx: Mutex<Option<mpsc::UnboundedSender<Cmd>>>,
    link: Arc<LinkState>,
    /// The materialization bound of reads.
    limit: usize,
    /// By a secret (not the socket's client, which acts as the account).
    keyed: bool,
    /// The secret it logs in with: `connect_node` tells a second login at this address from this one.
    secret: Option<osis_crypto::Secret32>,
    /// What the node last said of sync, for every status read of this process (`crate::sources`).
    pub heard: Mutex<crate::sources::Heard>,
}

/// A call sent whose connection ended before its reply.
const LOST: &str = "connection to the node ended before the reply";

fn net(m: impl std::fmt::Display) -> Error {
    Error::Network(m.to_string())
}

impl Connection {
    /// A group source's stand-in for a node no connection names (notes/client-port.md §6): every call
    /// fails `Network`, never reaches another source.
    pub fn absent(addr: &crate::Address) -> Arc<Connection> {
        Connection::failing(addr, net(format!("not connected to node {addr}")))
    }

    /// A stand-in whose every call fails `e`.
    pub fn failing(addr: &crate::Address, e: Error) -> Arc<Connection> {
        let (tx, _) = mpsc::unbounded_channel();
        let link = Arc::new(LinkState::default());
        lock(&link.m).ended = Some(e);
        Arc::new(Connection { addr: addr.clone(), tx: Mutex::new(Some(tx)), link, limit: 0, keyed: false, secret: None, heard: Default::default() })
    }

    /// Hands the connection's thread a command; fails once it ended.
    fn send(&self, c: Cmd) -> Result<()> {
        lock(&self.tx).as_ref().ok_or(()).and_then(|t| t.send(c).map_err(|_| ())).map_err(|()| net("connection to the node closed"))
    }

    /// Ends the connection now, whoever still holds this: what waits on it hears so.
    pub fn end(&self) {
        self.link.end(net(format!("disconnected from node {}", self.addr)));
        lock(&self.tx).take();
    }

    /// Whether the connection is up now.
    pub fn connected(&self) -> bool {
        lock(&self.link.m).up
    }

    /// Why this connection will never come up again, if so.
    fn ended(&self) -> Option<Error> {
        lock(&self.link.m).ended.clone()
    }

    /// Why a call fails now, if it does: the connection is down.
    fn down(&self) -> Option<Error> {
        let g = lock(&self.link.m);
        if g.up {
            return None;
        }
        Some(g.ended.clone().unwrap_or_else(|| net(format!("node {} not connected", self.addr))))
    }

    /// The latest connection attempt's outcome, once there is one (each is bounded by
    /// `CONNECTION_WAIT`).
    pub fn first(&self) -> impl std::future::Future<Output = Result<()>> + Send + use<> {
        FirstAttempt(self.link.clone())
    }

    fn who(&self) -> Option<Who> {
        lock(&self.link.m).who
    }

    /// Who this process is at the node: its actor there.
    pub fn acts_as(&self) -> Option<Tid> {
        self.who().map(|w| w.me)
    }

    /// One Call, waited for: its result value; a `TooLarge` reply under the small allowance is
    /// asked again under the whole reply budget.
    pub fn call(&self, m: u64, args: Vec<Value>) -> Result<Value> {
        self.call_n(m, args, None)
    }

    /// `call` as a future, on a thread of its own: its caller may give up while the node says
    /// nothing. A dropped future leaves the thread to end with the call.
    pub fn call_pending(self: &Arc<Self>, m: u64, args: Vec<Value>) -> crate::net::Pending<Result<Value>> {
        let (pending, slot) = crate::net::Pending::new();
        let r = self.clone();
        std::thread::spawn(move || slot.put(r.call(m, args)));
        pending
    }

    /// `call` of a write under a fresh nonce (the next of this session, taken when sent); a
    /// `TooLarge` retry goes under the same nonce.
    pub fn call_once(&self, m: u64, args: Vec<Value>) -> Result<Value> {
        self.call_n(m, args, Some(Arc::new(AtomicU64::new(0))))
    }

    fn call_n(&self, m: u64, args: Vec<Value>, nonce: Option<Arc<AtomicU64>>) -> Result<Value> {
        match self.call_with(m, args.clone(), SMALL_REPLY, nonce.clone()) {
            Err(Error::TooLarge { limit }) if limit == SMALL_REPLY => {
                let once = nonce.is_some();
                match self.call_with(m, args, REPLY_BUDGET.min(self.limit.saturating_add(SMALL_REPLY)).max(SMALL_REPLY), nonce) {
                    // the first send ran: the node's answer to it is what was lost
                    Err(Error::Network(_)) if once => Err(Error::OutcomeUnknown),
                    r => r,
                }
            }
            r => r,
        }
    }

    /// A Call whose reply may take `max_reply` bytes (a `stream_read` page).
    pub fn call_big(&self, m: u64, args: Vec<Value>, max_reply: usize) -> Result<Value> {
        self.call_with(m, args, max_reply.clamp(SMALL_REPLY, REPLY_BUDGET), None)
    }

    fn call_with(&self, m: u64, args: Vec<Value>, max_reply: usize, nonce: Option<Arc<AtomicU64>>) -> Result<Value> {
        if let Some(e) = self.down() {
            return Err(e);
        }
        let once = nonce.is_some();
        let (tx, rx) = std::sync::mpsc::channel();
        self.send(Cmd::Call { token: next_token(), max_reply, method: m, args, nonce, reply: tx })?;
        match crate::net::blocking(|| rx.recv()) {
            Ok(Ok(Outcome::Ok { value })) => Ok(value),
            Ok(Ok(Outcome::Err { code, detail })) => Err(c::error_of(code, detail)),
            Ok(Err(Code::REFUSED)) => Err(Error::Refused("no session, or revoked".into())),
            Ok(Err(Code::UNSUPPORTED)) => Err(Error::Refused(NO_PORT.into())),
            Ok(Err(code)) => Err(net(format!("node answered error {}", code.0))),
            // a write whose reply was lost may or may not have applied
            Err(_) if once => Err(Error::OutcomeUnknown),
            Err(_) => Err(net(LOST)),
        }
    }

    pub fn unsub(&self, token: u64) {
        let _ = self.send(Cmd::Unsub { token });
    }

    /// Whether a schema's source is registered on each reconnect from now on.
    pub fn remember_schema(&self, file: &str, src: &str) {
        let _ = self.send(Cmd::Schema { file: file.into(), src: src.into() });
    }
}

/// A write sent and not yet answered.
struct Held {
    method: u64,
    max_reply: usize,
    /// The nonce first.
    args: Vec<Value>,
    /// Sent before: an earlier send may have run, so a refusal of this one says nothing of it.
    resent: bool,
    reply: CallReply,
}

struct SubEntry {
    filter: Value,
    again: bool,
    sink: Sink,
}

/// A protocol Error 11 to a request: what answered serves sync at that address, not the client port.
const NO_PORT: &str = "this address serves no client port";

/// How a connection's start ended.
enum Started {
    Up,
    /// Try again later.
    Failed(Error),
    /// The node will not take this session: no redial.
    Refused(Error),
    HandleGone,
}

/// A request on the connection's session, by id: what its answer goes to.
enum Asked {
    /// An Auth or Call: its token.
    Call(u64),
    /// A Sub: its token (the subscription's id is the request's).
    Sub(u64),
    /// An Unsub of this subscription id.
    Unsub(Id),
    /// A keepalive: while it is out the stall clock runs.
    Ping,
}

/// The session driver: a dialer session over a link, on its own thread; survives reconnects,
/// the session and its ids (`sess`, `asked`, `sub_ids`) renewed per connection.
struct Io {
    sess: Session,
    /// The dialer's store: empty, so the node's Register or Delete here is refused.
    store: MemoryLabelStore,
    peer_key: [u8; 32],
    secret: Option<osis_crypto::Secret32>,
    /// The client's 16 random bytes in Auth: the same across reconnects.
    session: [u8; 16],
    /// The last request id taken (ids below `NODE_IDS`).
    next_id: Id,
    /// Requests sent (or waiting in the session's window) and not answered.
    asked: BTreeMap<Id, Asked>,
    /// Subscription ids reserved (spec/wire.md §11.1): from their Sub until a refusal, a
    /// `Lapsed` Notify or the Unsub's answer; the token while delivered (none once unsubscribing).
    sub_ids: BTreeMap<Id, Option<u64>>,
    /// When to ping if nothing is asked: so a dead idle connection stalls.
    next_ping: u64,
    calls: BTreeMap<u64, CallReply>,
    writes: BTreeMap<u64, Held>,
    /// While down: when held writes fail.
    give_up: Option<Instant>,
    subs: BTreeMap<u64, SubEntry>,
    schemas: Vec<(String, String)>,
    taken: u64,
    /// The next write nonce of this session (from 1).
    nonce: u64,
    wait: Duration,
    clock: Arc<dyn Clock>,
    link: Arc<LinkState>,
}

fn random<const N: usize>() -> [u8; N] {
    use osis_crypto::RngCore;
    let mut b = [0u8; N];
    osis_crypto::OsRng.fill_bytes(&mut b);
    b
}

fn new_session(listener_key: [u8; 32]) -> Session {
    Session::new(SessionConfig { listener_key, challenge: random(), dialed: true })
}

/// How a session ends when its Auth is not answered by a Reply. `keyed`: it sent a secret.
fn not_authed(r: std::result::Result<Outcome, Code>, keyed: bool) -> Started {
    match r {
        Err(Code::REFUSED) if keyed => Started::Refused(Error::Refused("this client secret".into())),
        Err(Code::RATE_LIMITED) => Started::Failed(net("the node holds as many connections of this client as it takes")),
        Err(Code::REFUSED) => Started::Refused(Error::Refused("this session (not its uid)".into())),
        Err(Code::UNSUPPORTED) => Started::Refused(Error::Refused(NO_PORT.into())),
        _ => Started::Failed(net("no answer to Auth")),
    }
}

/// A `whoami` reply.
fn who_of(r: std::result::Result<Outcome, Code>) -> Result<Who> {
    match r {
        Ok(Outcome::Ok { value }) => c::Args::new(value).and_then(|mut a| Ok(Who { me: a.tid()?, node: a.tid()?, home: a.tid()? })),
        Ok(Outcome::Err { code, detail }) => Err(c::error_of(code, detail)),
        Err(c) => Err(net(format!("node answered error {}", c.0))),
    }
}

impl Io {
    fn now(&self) -> u64 {
        self.clock.now_wall_ms().0
    }

    /// Puts a write's nonce first in its args: the slot's, marked as sent again (a `TooLarge`
    /// retry), else the next of the session, kept in the slot for a retry. Run as each command is
    /// sent, so nonces go out in order. Whether it was sent before.
    fn stamp(&mut self, slot: &AtomicU64, args: &mut Vec<Value>) -> bool {
        let n = slot.load(Ordering::Acquire);
        if n != 0 {
            args.insert(0, u(n | NONCE_RESENT));
            return true;
        }
        let n = self.nonce;
        self.nonce += 1;
        slot.store(n, Ordering::Release);
        args.insert(0, u(n));
        false
    }

    fn feed(&mut self, input: SessionInput) -> Vec<SessionOutput> {
        let now = self.now();
        self.sess.handle(now, &mut self.store, input)
    }

    /// Sends request `m` under a free id: below `NODE_IDS`, neither asked nor a subscription's.
    fn request(&mut self, asked: Asked, m: impl FnOnce(Id) -> Message) -> Vec<SessionOutput> {
        loop {
            self.next_id = self.next_id.wrapping_add(1) & !NODE_IDS;
            if self.next_id != 0 && !self.asked.contains_key(&self.next_id) && !self.sub_ids.contains_key(&self.next_id) {
                break;
            }
        }
        let id = self.next_id;
        if let Asked::Sub(token) = asked {
            self.sub_ids.insert(id, Some(token));
        }
        self.asked.insert(id, asked);
        self.feed(SessionInput::Peer(Box::new(m(id))))
    }

    fn call(&mut self, token: u64, max_reply: usize, method: u64, args: Vec<Value>) -> Vec<SessionOutput> {
        self.request(Asked::Call(token), |id| Message::Call { id, max_reply: max_reply as u64, method, args })
    }

    fn sub(&mut self, token: u64, filter: Value) -> Vec<SessionOutput> {
        self.request(Asked::Sub(token), |id| Message::Sub { id, max_reply: REPLY_BUDGET as u64, filter })
    }

    /// Carries out the session's outputs; `false` once it closed.
    fn outputs(&mut self, link: &osis_transport::link::LinkTx, out: Vec<SessionOutput>) -> bool {
        let mut out = std::collections::VecDeque::from(out);
        while let Some(o) = out.pop_front() {
            match o {
                SessionOutput::Send(b) => {
                    if !link.send(b, MAX_QUEUED) {
                        return false;
                    }
                }
                SessionOutput::Close => return false,
                SessionOutput::Peer(m) => out.extend(self.peer(*m)),
                // the node's client-port request: a client serves none (an Unsub is answered already)
                SessionOutput::Request(m) if !matches!(*m, Message::Unsub { .. }) => out.extend(self.feed(SessionInput::Reply { id: m.id(), reply: Err(Code::UNSUPPORTED) })),
                SessionOutput::Request(_) | SessionOutput::PeerError(_) | SessionOutput::StoreError(_) | SessionOutput::Room { .. } => {}
            }
        }
        true
    }

    /// A message the session hands up: an answer to a request of this side's, a Notify, or a
    /// request of the node's kinds (refused: the session answers Pings itself).
    fn peer(&mut self, m: Message) -> Vec<SessionOutput> {
        use Message as M;
        match m {
            M::Notify { sub, payload } => {
                let lapsed = payload == Payload::Lapsed;
                if let Some(Some(token)) = self.sub_ids.get(&sub).copied() {
                    self.notify(token, payload);
                }
                if lapsed {
                    self.sub_ids.remove(&sub);
                }
            }
            m if m.is_request() => return self.feed(SessionInput::Peer(Box::new(M::Error { id: m.id(), code: Code::UNSUPPORTED }))),
            m => {
                let id = m.id();
                let r = match m {
                    M::Reply { outcome, .. } => Ok(outcome),
                    M::Error { code, .. } => Err(code),
                    _ => Err(Code::MALFORMED),
                };
                match self.asked.remove(&id) {
                    Some(Asked::Call(token)) => self.reply(token, r),
                    Some(Asked::Sub(token)) => {
                        let live = self.sub_ids.get(&id).copied();
                        if !matches!(r, Ok(Outcome::Ok { .. })) {
                            self.sub_ids.remove(&id);
                        }
                        // a Sub unsubscribed before its reply: nobody waits for it any more
                        if live != Some(None) {
                            self.reply(token, r);
                        }
                    }
                    Some(Asked::Unsub(sub)) => {
                        if self.sub_ids.get(&sub) == Some(&None) {
                            self.sub_ids.remove(&sub);
                        }
                    }
                    Some(Asked::Ping) | None => {}
                }
            }
        }
        Vec::new()
    }

    /// The answer to the Auth, Call or Sub of `token`.
    fn reply(&mut self, token: u64, reply: std::result::Result<Outcome, Code>) {
        if let Some(h) = self.writes.remove(&token) {
            // a protocol error answers this send only: an earlier one may have run
            let _ = h.reply.send(if h.resent && reply.is_err() { Ok(outcome_err(&Error::OutcomeUnknown)) } else { reply });
        } else if let Some(r) = self.calls.remove(&token) {
            let _ = r.send(reply);
        } else if let Some(s) = self.subs.get_mut(&token) {
            match reply {
                Ok(Outcome::Ok { value }) => (s.sink)(PortEvent::Initial(value)),
                Ok(Outcome::Err { code, detail }) => {
                    (s.sink)(PortEvent::Initial(outcome_err(&c::error_of(code, detail)).to_value()));
                    self.subs.remove(&token);
                }
                Err(_) => {
                    (s.sink)(PortEvent::Closed);
                    self.subs.remove(&token);
                }
            }
        }
    }

    fn notify(&mut self, token: u64, payload: Payload) {
        let lapsed = payload == Payload::Lapsed;
        if let Some(s) = self.subs.get_mut(&token) {
            (s.sink)(PortEvent::Notify(payload));
        }
        if lapsed {
            self.subs.remove(&token);
        }
    }

    /// A command while the connection is up.
    fn command(&mut self, cmd: Cmd) -> Vec<SessionOutput> {
        match cmd {
            Cmd::Call { token, max_reply, method, mut args, nonce, reply } => {
                if let Some(slot) = nonce {
                    let resent = self.stamp(&slot, &mut args);
                    self.writes.insert(token, Held { method, max_reply, args: args.clone(), resent, reply });
                } else {
                    self.calls.insert(token, reply);
                }
                self.call(token, max_reply, method, args)
            }
            Cmd::Sub { token, filter, again, sink } => {
                self.subs.insert(token, SubEntry { filter: filter.clone(), again, sink });
                self.sub(token, filter)
            }
            Cmd::Unsub { token } => {
                self.subs.remove(&token);
                let Some(sub) = self.sub_ids.iter().find(|(_, t)| **t == Some(token)).map(|(i, _)| *i) else { return Vec::new() };
                self.sub_ids.insert(sub, None);
                // a Sub still unanswered: its reply comes first, the id stays reserved until this one's
                self.request(Asked::Unsub(sub), |id| Message::Unsub { id, sub })
            }
            Cmd::Schema { file, src } => {
                if !self.schemas.iter().any(|(f, s)| *f == file && *s == src) {
                    self.schemas.push((file, src));
                }
                Vec::new()
            }
        }
    }

    /// A command while the connection is down: never sent (so a write's failure is definite).
    fn command_down(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Call { reply, .. } => {
                let _ = reply.send(Ok(outcome_err(&lock(&self.link.m).ended.clone().unwrap_or_else(|| net("node not connected")))));
            }
            // one that comes back lives on the next connection, unless there will be none
            Cmd::Sub { token, filter, again, mut sink } => {
                sink(PortEvent::Closed);
                if again && lock(&self.link.m).ended.is_none() {
                    self.subs.insert(token, SubEntry { filter, again, sink });
                }
            }
            Cmd::Unsub { token } => {
                self.subs.remove(&token);
            }
            Cmd::Schema { .. } => {
                let _ = self.command(cmd);
            }
        }
    }

    /// `fut`'s output, commands failing meanwhile; `None` once the handle is gone.
    async fn while_down<F: std::future::Future>(&mut self, rx: &mut mpsc::UnboundedReceiver<Cmd>, fut: F) -> Option<F::Output> {
        tokio::pin!(fut);
        loop {
            let give_up = self.give_up;
            tokio::select! {
                biased;
                r = &mut fut => return Some(r),
                c = rx.recv() => self.command_down(c?),
                () = async { tokio::time::sleep_until(give_up.unwrap_or_else(Instant::now)).await }, if give_up.is_some() => self.fail_writes(),
            }
        }
    }

    /// Unanswered writes get their one answer: unknown.
    fn fail_writes(&mut self) {
        self.give_up = None;
        for (_, h) in std::mem::take(&mut self.writes) {
            let _ = h.reply.send(Ok(outcome_err(&Error::OutcomeUnknown)));
        }
    }

    /// Reports what the transport took, if it took more.
    fn report_taken(&mut self, tx: &osis_transport::link::LinkTx) -> bool {
        if tx.taken() == self.taken {
            return true;
        }
        self.taken = tx.taken();
        let o = self.feed(SessionInput::Taken(self.taken));
        self.outputs(tx, o)
    }

    /// Bytes from the node.
    fn bytes(&mut self, tx: &osis_transport::link::LinkTx, b: Vec<u8>) -> bool {
        if !self.report_taken(tx) {
            return false;
        }
        let o = self.feed(SessionInput::Bytes(b));
        self.outputs(tx, o)
    }

    /// The timer: reports what the transport took; closes a stalled connection; pings one with
    /// nothing asked, so the stall clock runs on it.
    fn timer_fired(&mut self, tx: &osis_transport::link::LinkTx) -> bool {
        if !self.report_taken(tx) {
            return false;
        }
        let now = self.now();
        if self.sess.stall_at().is_some_and(|t| t <= now) {
            return false;
        }
        if self.next_ping <= now {
            self.next_ping = now.saturating_add(PING_INTERVAL_MS);
            if self.asked.is_empty() {
                let o = self.request(Asked::Ping, |id| Message::Ping { id, wall_ms: now });
                return self.outputs(tx, o);
            }
        }
        true
    }

    /// Until the next ping, or the oldest request's stall.
    fn wake_in(&self) -> Duration {
        let t = self.sess.stall_at().map_or(self.next_ping, |s| s.min(self.next_ping));
        Duration::from_millis(t.saturating_sub(self.now()))
    }

    /// Auth and `whoami` on a new connection, within `wait`.
    async fn start(&mut self, tx: &osis_transport::link::LinkTx, lrx: &mut osis_transport::link::LinkRx, rx: &mut mpsc::UnboundedReceiver<Cmd>) -> Started {
        self.sess = new_session(self.peer_key);
        self.asked.clear();
        self.sub_ids.clear();
        self.taken = 0;
        self.next_ping = self.now().saturating_add(PING_INTERVAL_MS);
        let keyed = self.secret.is_some();
        let o = self.feed(SessionInput::Start);
        let mut up = self.outputs(tx, o);
        let (rtx, rrx) = std::sync::mpsc::channel();
        self.calls.insert(AUTH_TOKEN, rtx.clone());
        let (secret, session) = (self.secret.clone(), self.session);
        let o = self.request(Asked::Call(AUTH_TOKEN), |id| Message::Auth { id, secret, session });
        up = up && self.outputs(tx, o);
        let end = Instant::now() + self.wait;
        let mut authed = false;
        loop {
            // nothing counts past the deadline, what already arrived included: a wait of 0 connects nothing
            if Instant::now() >= end {
                return Started::Failed(net("the node did not answer in time"));
            }
            while let Ok(r) = rrx.try_recv() {
                if !authed {
                    if !matches!(r, Ok(Outcome::Ok { .. })) {
                        return not_authed(r, keyed);
                    }
                    authed = true;
                    self.calls.insert(WHO_TOKEN, rtx.clone());
                    let o = self.call(WHO_TOKEN, SMALL_REPLY, method::WHOAMI, Vec::new());
                    up = up && self.outputs(tx, o);
                    continue;
                }
                let who = match who_of(r) {
                    Ok(w) => w,
                    Err(e) => return Started::Failed(e),
                };
                {
                    let mut g = lock(&self.link.m);
                    // the pinned key answers as someone else: never mix two identities in one connection
                    if g.who.is_some_and(|w| w != who) {
                        return Started::Refused(Error::Invalid("the node at this address now answers as another identity".into()));
                    }
                    g.who = Some(who);
                }
                self.reconnect_state(tx);
                return Started::Up;
            }
            if !up {
                return Started::Failed(net("connection to the node ended"));
            }
            let wake = self.wake_in();
            tokio::select! {
                b = lrx.recv() => match b {
                    Some(b) => up = self.bytes(tx, b),
                    None => up = false,
                },
                c = rx.recv() => match c {
                    Some(c) => self.command_down(c),
                    None => return Started::HandleGone,
                },
                () = tokio::time::sleep(wake) => up = self.timer_fired(tx),
                () = tokio::time::sleep_until(end) => return Started::Failed(net("the node did not answer in time")),
            }
        }
    }

    /// Serves a connection that is up until it ends; `false` once the handle is gone.
    async fn connected(&mut self, tx: &osis_transport::link::LinkTx, lrx: &mut osis_transport::link::LinkRx, rx: &mut mpsc::UnboundedReceiver<Cmd>) -> bool {
        let mut up = true;
        while up {
            let wake = self.wake_in();
            tokio::select! {
                b = lrx.recv() => match b {
                    Some(b) => up = self.bytes(tx, b),
                    None => up = false,
                },
                c = rx.recv() => match c {
                    Some(c) => {
                        let o = self.command(c);
                        up = self.outputs(tx, o);
                    }
                    None => return false,
                },
                () = tokio::time::sleep(wake) => up = self.timer_fired(tx),
            }
        }
        true
    }

    /// On a new connection, once Auth answered: schemas, subscriptions and unanswered writes again.
    fn reconnect_state(&mut self, tx: &osis_transport::link::LinkTx) {
        self.give_up = None;
        for (file, src) in self.schemas.clone() {
            let (rtx, _) = std::sync::mpsc::channel();
            let token = next_token();
            self.calls.insert(token, rtx);
            let o = self.call(token, SMALL_REPLY, method::REGISTER_SCHEMA, vec![Value::Str(file), Value::Str(src)]);
            self.outputs(tx, o);
        }
        let subs: Vec<(u64, Value)> = self.subs.iter().map(|(t, s)| (*t, s.filter.clone())).collect();
        for (token, filter) in subs {
            let o = self.sub(token, filter);
            self.outputs(tx, o);
        }
        // in nonce order, marked: the first send may have run, the node's memory tells
        let mut held: Vec<(u64, u64)> = self.writes.iter().filter_map(|(t, h)| Some((h.args.first()?.as_uint()? & !NONCE_RESENT, *t))).collect();
        held.sort_unstable();
        for (n, token) in held {
            let Some(h) = self.writes.get_mut(&token) else { continue };
            h.resent = true;
            let mut args = h.args.clone();
            if let Some(first) = args.first_mut() {
                *first = u(n | NONCE_RESENT);
            }
            let (max_reply, method) = (h.max_reply, h.method);
            let o = self.call(token, max_reply, method, args);
            self.outputs(tx, o);
        }
    }

    /// The connection ended: reads fail, subscriptions hear of it, writes wait for the next one.
    fn dropped(&mut self) {
        self.calls.clear();
        self.give_up = (!self.writes.is_empty()).then(|| Instant::now() + self.wait);
        self.subs.retain(|_, s| {
            (s.sink)(PortEvent::Closed);
            s.again
        });
    }
}

/// The handle is gone, or the thread died of a panic: calls and writes fail, subscriptions
/// (a `node_task` waiting) hear `Closed`. A sink panicking again here is caught: escaping a
/// drop during unwinding aborts the process.
impl Drop for Io {
    fn drop(&mut self) {
        {
            let mut g = lock(&self.link.m);
            if g.tried.is_none() {
                g.tried = Some(Err(net("connection to the node closed")));
                g.wake();
            }
        }
        self.calls.clear();
        self.writes.clear();
        for (_, mut s) in std::mem::take(&mut self.subs) {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (s.sink)(PortEvent::Closed)));
        }
    }
}

/// How a connection dials its node: the daemon's unix socket, or a node address over the
/// in-process transport (tests) or QUIC (`quic://`, `peer://`), the key pinned.
enum Via {
    Unix,
    Mem(osis_transport::InProcess),
    Net,
}

async fn dial_via(via: &Via, addr: &Address, wait: Duration) -> std::result::Result<osis_transport::Link, String> {
    let d = async {
        match via {
            Via::Unix => osis_transport::link::dial(&Unix, addr, wait).await,
            Via::Mem(m) => osis_transport::link::dial(&osis_transport::Multi::<osis_transport::QuicUdp> { mem: Some(m.clone()), ..Default::default() }, addr, wait).await,
            Via::Net => {
                let m = osis_transport::Multi { quic: Some(osis_transport::Quic::new()), p2p: Some(osis_transport::P2p::new(osis_transport::QuicUdp::new())), ..Default::default() };
                osis_transport::link::dial(&m, addr, wait).await
            }
        }
    };
    match tokio::time::timeout(wait, d).await {
        Ok(r) => r.map_err(|e| e.to_string()),
        Err(_) => Err("the node did not answer in time".into()),
    }
}

/// Keeps the connection connected until the handle ends (module comment).
async fn run(via: Via, addr: Address, mut io: Io, mut rx: mpsc::UnboundedReceiver<Cmd>) {
    let mut backoff = RETRY_MIN;
    let wait = io.wait;
    let link = io.link.clone();
    loop {
        let Some(dialed) = io.while_down(&mut rx, dial_via(&via, &addr, wait)).await else { return };
        match dialed {
            Err(e) => link.tried(Err(net(e))),
            Ok(l) => {
                let osis_transport::Link { tx, rx: mut lrx, .. } = l;
                match io.start(&tx, &mut lrx, &mut rx).await {
                    Started::HandleGone => return,
                    Started::Failed(e) => link.tried(Err(e)),
                    Started::Refused(e) => {
                        drop((tx, lrx));
                        link.end(e);
                        io.fail_writes();
                        io.dropped();
                        while let Some(c) = rx.recv().await {
                            io.command_down(c);
                        }
                        return;
                    }
                    Started::Up => {
                        link.tried(Ok(()));
                        backoff = RETRY_MIN;
                        if !io.connected(&tx, &mut lrx, &mut rx).await {
                            return;
                        }
                        link.tried(Err(net("connection to the node ended")));
                        io.dropped();
                    }
                }
            }
        }
        let pause = tokio::time::sleep(backoff);
        backoff = (backoff * 2).min(RETRY_MAX);
        if io.while_down(&mut rx, pause).await.is_none() {
            return;
        }
    }
}

/// Starts a connection's thread; the connection comes up behind it.
fn spawn_connection(via: Via, addr: Address, shown: crate::Address, secret: Option<osis_crypto::Secret32>, limit: usize, wait: Duration, clock: Arc<dyn Clock>) -> Result<Arc<Connection>> {
    let (tx, rx) = mpsc::unbounded_channel();
    let session = random();
    let link = Arc::new(LinkState::default());
    let (keyed, kept) = (secret.is_some(), secret.clone());
    let io = Io { sess: new_session(addr.key), store: MemoryLabelStore::new(), peer_key: addr.key, secret, session, next_id: 0, asked: BTreeMap::new(), sub_ids: BTreeMap::new(), next_ping: 0, calls: BTreeMap::new(), writes: BTreeMap::new(), give_up: None, subs: BTreeMap::new(), schemas: Vec::new(), taken: 0, nonce: 1, wait, clock, link: link.clone() };
    std::thread::Builder::new()
        .name("osis-port-client".into())
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
            rt.block_on(run(via, addr, io, rx));
        })
        .map_err(|e| Error::Storage(e.to_string()))?;
    Ok(Arc::new(Connection { addr: shown, tx: Mutex::new(Some(tx)), link, limit, keyed, secret: kept, heard: Default::default() }))
}

/// A connection to the node at `login`'s address as the client its secret stands for.
pub(crate) fn spawn_client(login: &crate::NodeLogin, transport: &Option<osis_transport::InProcess>, limit: usize, wait: Duration, clock: Arc<dyn Clock>) -> Result<Arc<Connection>> {
    let addr = &login.addr;
    // the secret goes only over a transport pinned to the node's key
    if addr.0.url.starts_with("unix://") {
        return Err(Error::Invalid("a client secret goes only to a key-pinned transport, not a unix socket".into()));
    }
    let via = match transport {
        Some(t) => Via::Mem(t.clone()),
        None => Via::Net,
    };
    let a = Address { url: addr.0.url.clone(), key: addr.0.key };
    spawn_connection(via, a, addr.clone(), Some(login.secret.0.clone()), limit, wait, clock)
}

impl Osis {
    /// Makes a thin client of the node running on the store at `store_dir`, over its unix socket
    /// (`Osis::listen_socket`). A node offers its socket to its own user, by default, with no authentication and as its main actor, so `me()`
    /// and `node()` are the node's. Every call addressed by a tid or group goes there, and `settle`
    /// waits for the node's deliveries too. What needs this process to be the node fails
    /// `Unsupported`.
    ///
    /// A thin client can do nothing without its node, and `me()` must be its node's answer, so this
    /// returns once connected or fails with why the one attempt it makes did not connect (`Network`
    /// for a node not there; call again to try again): nothing stays behind. Connected, it
    /// reconnects by itself.
    pub async fn connect_socket(store_dir: &Path, cfg: AppConfig) -> Result<Osis> {
        Osis::connect_socket_at(&socket_path(store_dir)?, cfg).await
    }

    pub(crate) async fn connect_socket_at(socket: &Path, cfg: AppConfig) -> Result<Osis> {
        let uid = own_uid()?;
        let url = osis_transport::unix::url_of(socket);
        let addr = Address { url: url.clone(), key: osis_transport::unix::uid_key(uid) };
        let shown = crate::Address(osis_label::Address { url, key: addr.key });
        let limit = cfg.read_limit;
        let db = Osis::scratch(cfg)?;
        let r = spawn_connection(Via::Unix, addr, shown, None, limit, db.inner.connection_wait, db.inner.clock.clone())?;
        db.client_over(vec![r]).await?;
        Ok(db)
    }

    /// Makes a thin client of the nodes it logs in to, each dialed at its address, which pins the node's key. Every call goes to them: the
    /// first in `logins` that holds a thing answers for it, the first for what is not about one
    /// thing. A listener lets a client act, by default, only as actors it has authenticated for: a
    /// node says which actor a login makes this program, `me()` (one made for its secret by
    /// `add_client`). What that actor may not read reads as unknown, and calls only the node's main
    /// actor may make fail `Unsupported`. All must answer as one actor (`Invalid`; no login is
    /// `Invalid` too).
    ///
    /// Returns once connected to all, as `connect_socket`: `Refused` when a node refuses the secret,
    /// `Invalid` for a unix address (the secret goes only over a keyed transport), `Network` past
    /// its connection cap or when it cannot be reached.
    pub async fn connect(logins: &[crate::NodeLogin], cfg: AppConfig) -> Result<Osis> {
        if logins.is_empty() {
            return Err(Error::Invalid("connect needs a node to log in to".into()));
        }
        let (transport, limit) = (cfg.internals.transport.clone(), cfg.read_limit);
        let db = Osis::scratch(cfg)?;
        let list = logins.iter().map(|x| spawn_client(x, &transport, limit, db.inner.connection_wait, db.inner.clock.clone())).collect::<Result<Vec<_>>>()?;
        db.client_over(list).await?;
        Ok(db)
    }

    /// The stand-in node of a process without a store.
    fn scratch(cfg: AppConfig) -> Result<Osis> {
        Osis::create(crate::Store::Memory(crate::MemStore::new()), &[], Config { app: cfg, ..Config::default() })
    }

    /// Makes this handle a process with no store of its own over `list`, each up.
    async fn client_over(&self, list: Vec<Arc<Connection>>) -> Result<()> {
        let mut who = None;
        for r in &list {
            r.first().await?;
            let w = r.who().ok_or_else(|| net("no connection"))?;
            if who.is_some_and(|x| x != w) {
                return Err(Error::Invalid("connected nodes answer as different actors: one acting actor per process".into()));
            }
            who = Some(w);
        }
        let (Some(primary), Some(who)) = (list.first().cloned(), who) else { return Err(net("no connection")) };
        self.locked(|l| l.connections = list);
        let _ = self.inner.client.set(crate::handle::ClientOf { primary, who });
        self.inner.has_sources.store(true, Ordering::Release);
        Ok(())
    }

    /// Makes this node a client of the node at `login`'s address, beside its own store:
    /// `group_source` can then make it the source of groups, and a call on a thing known nowhere here goes there.
    /// Stays connected, reconnecting by itself, until `disconnect_node`.
    ///
    /// `Ok` once the first attempt to reach it ended and left the connection in place, up or not:
    /// `status` shows which, and this keeps trying while it is down. `Refused`: it refuses the
    /// secret, and nothing stays. `Invalid` for a unix address, and for a login at an address connected
    /// now by another secret (`disconnect_node` first); `Unsupported` on a thin client. Connected
    /// already by this one: `Ok`. Dropped during that first attempt, the connection is in place
    /// as if this had returned: `disconnect_node` ends it. A refusal after that attempt, as one
    /// after a later reconnect, shows in what goes there (`Refused`), and it stops trying.
    pub async fn connect_node(&self, login: &crate::NodeLogin) -> Result<()> {
        self.local_only("connect_node")?;
        // one that is down by an old secret (rotated, say) may never come up: the new login replaces it
        let same = |r: &Connection| r.secret.as_ref() == Some(&login.secret.0);
        let known = self.locked(|l| {
            let was = l.connections.len();
            l.connections.retain(|r| r.addr != login.addr || r.ended().is_none() && (r.connected() || same(r)));
            l.remerge = l.connections.len() != was;
            l.connections.iter().find(|r| r.addr == login.addr).cloned()
        });
        let r = match known {
            Some(r) if !same(&r) => return Err(Error::Invalid(format!("connected to {} by another secret: `disconnect_node` first", login.addr))),
            Some(r) => r,
            None => {
                let r = spawn_client(login, &self.inner.transport, self.inner.limit, self.inner.connection_wait, self.inner.clock.clone())?;
                self.locked(|l| {
                    l.connections.push(r.clone());
                    l.remerge = true;
                });
                self.inner.has_sources.store(true, Ordering::Release);
                r
            }
        };
        let first = r.first().await;
        // known to be no use: it goes; else it stays and keeps trying
        match r.ended().or_else(|| first.err().filter(|e| matches!(e, Error::Refused(_) | Error::Invalid(_)))) {
            Some(e) => {
                self.locked(|l| {
                    l.connections.retain(|x| !Arc::ptr_eq(x, &r));
                    l.remerge = true;
                });
                Err(e)
            }
            None => Ok(()),
        }
    }

    /// A test's way to panic the connection thread: a subscription whose sink
    /// panics at its first event (its reply, or `Closed` while down).
    #[allow(clippy::panic)]
    pub(crate) fn panic_client_thread(&self) {
        let sink: Sink = Box::new(|_| panic!("test: the client port's connection thread panics"));
        let _ = self.primary().send(Cmd::Sub { token: next_token(), filter: Value::List(Vec::new()), again: false, sink });
    }

    /// Whether this handle is a client by a secret: no store, an actor of its own at the node.
    pub(crate) fn secret_client(&self) -> bool {
        self.inner.client.get().is_some_and(|t| t.primary.keyed)
    }

    /// Fails `Unsupported` on a thin client: a call that needs this process to be the node.
    pub(crate) fn local_only(&self, what: &str) -> Result<()> {
        if !self.has_store() { Err(Error::Unsupported(format!("{what} on a thin client"))) } else { Ok(()) }
    }

    /// A write at `r`, under a fresh nonce (a reply lost to a `TooLarge` retry is answered
    /// again from the node's memory).
    pub(crate) fn node_write(&self, r: &Connection, wire: Vec<Value>) -> Result<Option<crate::Commit>> {
        Ok(c::of::<Option<crate::Commit>>(r.call_once(method::WRITE, wire)?)?.map(|c| c.reporting(self)))
    }

    /// Waits for the connected node's deliveries for changes made so far to reach the
    /// dispatcher queue (`settle` then runs them).
    pub(crate) fn node_settle(&self) {
        for r in self.locked(|l| l.connections.clone()) {
            let _ = r.call(method::SETTLE, vec![]);
        }
    }
}

/// The error a Sub was answered by: `[1, code, detail*]`.
fn sub_error(v: &Value) -> Option<Error> {
    if let Value::List(l) = v
        && l.first().and_then(Value::as_uint) == Some(1)
        && let Ok(Err(e)) = c::of::<Result<Value>>(v.clone())
    {
        return Some(e);
    }
    None
}

/// What an aspect delivery holds: thing, aspect, read result, source.
type Delivered = (Tid, osis_base::Ak, Result<Option<Value>>, crate::watch::Origin);

/// An aspect delivery `[tid, ak, read, source]`.
fn delivery(v: Value) -> Result<Delivered> {
    let mut a = c::Args::new(v)?;
    let (t, ak, r, s) = (a.tid()?, a.ak()?, a.get()?, a.get()?);
    a.end()?;
    Ok((t, ak, r, s))
}

/// More than one commit's encoding takes beside its bodies (IDs, times, kind, relations, the
/// heads of its parts).
const COMMIT_HEAD: usize = 512;

/// A commit subscription's Notify.
fn commit_note(v: Value) -> Result<(crate::CommitId, Option<crate::Commit>)> {
    let mut a = c::Args::new(v)?;
    let id = a.get()?;
    let commit = a.opt()?.map(c::of).transpose()?;
    a.end()?;
    Ok((id, commit))
}

/// What a watch hears when its subscription ends.
fn sub_ended() -> Error {
    net("the node's subscription ended")
}

fn aspect_filter(tid: Tid, ak: &osis_base::Ak, path: &osis_schema::Path) -> Value {
    Value::List(vec![u(super::filter::ASPECT), Value::Tid(tid), c::v(ak), c::v(path)])
}

pub(crate) fn grants_filter(thing: Tid) -> Value {
    Value::List(vec![u(super::filter::GRANTS), Value::Tid(thing)])
}

/// A node's callback of `T`s.
pub(crate) type CallbackOf<T> = Box<dyn FnMut(&Osis, T) + Send>;
/// A node's callback of `Change<Value>`s.
pub(crate) type ChangeFn = CallbackOf<crate::watch::Change<Value>>;

impl Osis {
    /// `on_diagnostic` at the connected node (its diagnostics; this process's own go nowhere).
    pub(crate) fn node_on_diagnostic(&self, mut f: CallbackOf<crate::Diagnostic>) -> Result<Subscription> {
        if let Some(e) = self.primary().ended() {
            return Err(e);
        }
        let cb: Callback = Box::new(move |db, d| {
            if let Delivery::Port(PortEvent::Notify(Payload::Delivery { value })) = d
                && let Ok(x) = c::of::<osis_node::Diagnostic>(value)
            {
                f(db, x.into());
            }
        });
        self.node_sub_kept(self.primary(), None, Value::List(vec![u(super::filter::DIAGNOSTICS)]), cb)
    }

    /// A row that waits, at `r` (`filter::TASK`): a subscription the node answers once with the
    /// outcome of its own async call (its rule, its clock); no Call waits and nothing holds the
    /// node's worker. The answer goes straight to this future, not by the dispatcher: nothing but
    /// the connection has to run for it. Dropping this future ends it there, as a local one's drop.
    /// The connection ending is `Network`, and what it had done stays done (a redeem may have joined).
    pub(crate) async fn node_task(&self, r: &Arc<Connection>, m: u64, args: Vec<Value>) -> Result<Value> {
        if let Some(e) = r.down() {
            return Err(e);
        }
        let (pending, slot) = crate::net::Pending::new();
        // the first outcome stands (a later end of the connection does not replace it)
        let mut slot = Some(slot);
        let mut put = move |r: Result<Value>| {
            if let Some(s) = slot.take() {
                s.put(r);
            }
        };
        let sink: Sink = Box::new(move |ev| match ev {
            PortEvent::Initial(v) => {
                if let Some(e) = sub_error(&v) {
                    return put(Err(e));
                }
                match c::of::<Option<Result<Value>>>(v) {
                    Ok(Some(o)) => put(o),
                    Ok(None) => {}
                    Err(e) => put(Err(e)),
                }
            }
            PortEvent::Notify(Payload::Delivery { value }) => {
                if let Ok(Some(o)) = c::of::<Option<Value>>(value) {
                    put(c::of(o).unwrap_or_else(Err));
                }
            }
            PortEvent::Notify(Payload::Lapsed | Payload::TooLarge { .. }) | PortEvent::Closed => put(Err(net(LOST))),
        });
        let token = next_token();
        let _end = Unsub(r.clone(), token);
        r.send(Cmd::Sub { token, filter: Value::List(vec![u(super::filter::TASK), u(m), Value::List(args)]), again: false, sink })?;
        pending.await
    }

    /// Waits until `r` reports `g` synced: nothing written there waits. Done at once when it is
    /// down, or goes down, or does not report the group (a client's actor no longer reads it):
    /// nothing more can be learned from it. `Unsynced` when it never can be (stranded
    /// there). A status subscription, not a `wait_synced`: a client by a secret has no rows that wait.
    pub(crate) async fn node_synced(&self, r: &Arc<Connection>, g: Tid) -> Result<()> {
        if r.down().is_some() {
            return Ok(());
        }
        let (pending, slot) = crate::net::Pending::new();
        let mut slot = Some(slot);
        let mut put = move |r: Result<()>| {
            if let Some(s) = slot.take() {
                s.put(r);
            }
        };
        let judge = move |v: Value| -> Option<Result<()>> {
            use crate::share::SyncState as S;
            // a Notify naming no status: the node's store could not say
            match c::of::<crate::Status>(v).ok()?.groups.get(&g).map(|s| s.state) {
                None | Some(S::Synced) => Some(Ok(())),
                Some(S::Stranded) => Some(Err(Error::Unsynced { groups: vec![g] })),
                Some(_) => None,
            }
        };
        let sink: Sink = Box::new(move |ev| match ev {
            PortEvent::Initial(v) if sub_error(&v).is_some() => put(sub_error(&v).map_or(Ok(()), Err)),
            PortEvent::Initial(value) | PortEvent::Notify(Payload::Delivery { value }) => {
                if let Some(x) = judge(value) {
                    put(x);
                }
            }
            PortEvent::Notify(Payload::Lapsed | Payload::TooLarge { .. }) => put(Err(net("the node's status subscription ended: call again"))),
            PortEvent::Closed => put(Ok(())),
        });
        let token = next_token();
        let _end = Unsub(r.clone(), token);
        r.send(Cmd::Sub { token, filter: Value::List(vec![u(super::filter::STATUS)]), again: false, sink })?;
        pending.await
    }

    /// `node_task` at the node of a handle with no store. A client by a secret has no such
    /// rows: refused here too (the node's gate is `Worker::sub`), so a link's or card's secret never
    /// goes to a node that would only refuse it.
    pub(crate) async fn rtask(&self, m: u64, args: Vec<Value>) -> Result<Value> {
        if self.primary().keyed {
            return Err(Error::Unsupported("a client with an actor of its own: only the node's main actor runs this".into()));
        }
        self.node_task(self.primary(), m, args).await
    }
}

impl crate::handle::ReadOnly {
    /// The length of a string or blob at the connected node (`None`: absent).
    pub(crate) fn node_len(&self, r: &Connection, tid: Tid, ak: &osis_base::Ak, path: &osis_schema::Path) -> Result<Option<u64>> {
        let v = r.call(method::BYTE_LEN, vec![Value::Tid(tid), c::v(ak), c::v(path)])?;
        c::of(v)
    }

    /// `get` / `get_path` at `r`.
    pub(crate) fn node_get(&self, r: &Connection, tid: Tid, ak: &osis_base::Ak, path: &osis_schema::Path) -> Result<Option<Value>> {
        c::of(r.call(method::GET, vec![Value::Tid(tid), c::v(ak), c::v(path)])?)?
    }

    /// Whether this handle has a store of its own: `false` on a thin client (`connect`,
    /// `connect_socket`).
    #[inline]
    pub fn has_store(&self) -> bool {
        self.inner.client.get().is_none()
    }

    /// A process-wide call at the node of a handle with no store.
    pub(crate) fn rcall(&self, m: u64, args: Vec<Value>) -> Result<Value> {
        self.primary().call(m, args)
    }

    /// One `stream_read` page.
    pub(crate) fn node_read(&self, r: &Connection, tid: Tid, ak: &osis_base::Ak, path: &osis_schema::Path, offset: u64, n: usize) -> Result<Vec<u8>> {
        let v = r.call_big(method::STREAM_READ, vec![Value::Tid(tid), c::v(ak), c::v(path), u(offset), u(n as u64)], n.saturating_add(SMALL_REPLY))?;
        c::bytes(v)
    }

    /// `on_write` / `on_fire` at the connected node. A reconnect's Reply says `Reread`: what changed
    /// in the gap was not told.
    pub(crate) fn node_on_commits(&self, r: &Arc<Connection>, at: crate::commits::Address, mut f: CallbackOf<crate::CommitEvent>) -> Result<Subscription> {
        let mut first = true;
        let cb: Callback = Box::new(move |db, d| {
            let Delivery::Port(ev) = d else { return };
            match ev {
                PortEvent::Initial(_) => {
                    if !std::mem::take(&mut first) {
                        f(db, crate::CommitEvent::Reread);
                    }
                }
                PortEvent::Notify(Payload::Delivery { value }) => match commit_note(value) {
                    Ok((id, commit)) => f(db, crate::CommitEvent::Commit { id, commit: commit.map(|c| c.reporting(db)) }),
                    Err(_) => f(db, crate::CommitEvent::Reread),
                },
                PortEvent::Notify(Payload::TooLarge { .. }) | PortEvent::Closed => f(db, crate::CommitEvent::Reread),
                PortEvent::Notify(Payload::Lapsed) => f(db, crate::CommitEvent::Ended(sub_ended())),
            }
        });
        let filter = Value::List(vec![u(super::filter::COMMITS), c::v(&at)]);
        Ok(self.node_sub(r, at.things().first().copied(), filter, true, cb)?.0)
    }

    /// A status subscription at `r` (`filter::STATUS`) for `cb`, kept across reconnects; it waits
    /// for nothing.
    pub(crate) fn node_status_sub(&self, r: &Arc<Connection>, cb: Callback) -> Subscription {
        self.node_sub_quiet(r, None, Value::List(vec![u(super::filter::STATUS)]), cb)
    }

    /// `on_change` at `path` at a connected node: the initial value, then each change that
    /// differs from the last delivered (an error always).
    pub(crate) fn node_on_change(&self, r: &Arc<Connection>, tid: Tid, ak: osis_base::Ak, path: osis_schema::Path, mut f: ChangeFn) -> Result<Subscription> {
        let mut last: Option<Result<Option<Value>>> = None;
        let ak2 = ak.clone();
        let cb: Callback = Box::new(move |db, d| {
            let Delivery::Port(ev) = d else { return };
            match ev {
                PortEvent::Initial(v) => {
                    let value = c::of(v).unwrap_or_else(Err);
                    last = Some(value.clone());
                    f(db, Change { tid, ak: ak2.clone(), value, origin: Origin::Initial });
                }
                PortEvent::Notify(Payload::Delivery { value }) => {
                    let Ok((t, ak, value, source)) = delivery(value) else { return };
                    if value.is_err() || last.as_ref() != Some(&value) {
                        last = Some(value.clone());
                        f(db, Change { tid: t, ak, value, origin: source });
                    }
                }
                PortEvent::Notify(Payload::TooLarge { source }) => {
                    let source = c::of(source).unwrap_or(Origin::Initial);
                    last = None;
                    f(db, Change { tid, ak: ak2.clone(), value: Err(Error::TooLarge { limit: REPLY_BUDGET }), origin: source });
                }
                PortEvent::Notify(Payload::Lapsed) | PortEvent::Closed => {
                    f(db, Change { tid, ak: ak2.clone(), value: Err(sub_ended()), origin: Origin::Initial });
                }
            }
        });
        Ok(self.node_sub(r, Some(tid), aspect_filter(tid, &ak, &path), true, cb)?.0)
    }

    /// `on_thing_change` at the connected node.
    pub(crate) fn node_on_thing_change(&self, r: &Arc<Connection>, tid: Tid, mut f: ChangeFn) -> Result<Subscription> {
        let mut last: BTreeMap<osis_base::Ak, Result<Option<Value>>> = BTreeMap::new();
        let cb: Callback = Box::new(move |db, d| {
            let Delivery::Port(ev) = d else { return };
            match ev {
                // the first, or again after a reconnect: what changed in the gap, what went too
                PortEvent::Initial(v) => {
                    let mut now: BTreeMap<osis_base::Ak, Result<Option<Value>>> = BTreeMap::new();
                    for x in c::list(v).unwrap_or_default() {
                        let Ok(mut a) = c::Args::new(x) else { continue };
                        let (Ok(ak), Ok(value)) = (a.ak(), a.get()) else { continue };
                        now.insert(ak, value);
                    }
                    for ak in std::mem::take(&mut last).into_keys() {
                        if !now.contains_key(&ak) {
                            f(db, Change { tid, ak, value: Ok(None), origin: Origin::Initial });
                        }
                    }
                    for (ak, value) in &now {
                        f(db, Change { tid, ak: ak.clone(), value: value.clone(), origin: Origin::Initial });
                    }
                    last = now;
                }
                PortEvent::Notify(Payload::Delivery { value }) => {
                    let Ok((t, ak, value, source)) = delivery(value) else { return };
                    if value.is_err() || last.get(&ak) != Some(&value) {
                        last.insert(ak.clone(), value.clone());
                        f(db, Change { tid: t, ak, value, origin: source });
                    }
                }
                PortEvent::Notify(Payload::TooLarge { .. }) => {}
                // what the callback sees of an end: an error on the thing's own `tid.0`
                PortEvent::Notify(Payload::Lapsed) | PortEvent::Closed => f(db, Change { tid, ak: osis_schema::core_types::TID.name(), value: Err(sub_ended()), origin: Origin::Initial }),
            }
        });
        Ok(self.node_sub(r, Some(tid), Value::List(vec![u(super::filter::THING), Value::Tid(tid)]), true, cb)?.0)
    }

    /// A watch at the connected node of an answer told whole (`on_grants_change`,
    /// `on_backlinks_change`): `f` hears it when it differs from the last told.
    pub(crate) fn node_on_answer<T: c::Port + PartialEq + Clone + Send + 'static>(&self, r: &Arc<Connection>, on: Tid, filter: Value, mut f: CallbackOf<Result<T>>) -> Result<Subscription> {
        let mut last = None;
        let cb: Callback = Box::new(move |db, d| {
            let Delivery::Port(ev) = d else { return };
            match ev {
                PortEvent::Initial(v) | PortEvent::Notify(Payload::Delivery { value: v }) => match c::of::<T>(v) {
                    Ok(x) if last.as_ref() == Some(&x) => {}
                    Ok(x) => {
                        last = Some(x.clone());
                        f(db, Ok(x));
                    }
                    Err(e) => f(db, Err(e)),
                },
                PortEvent::Notify(Payload::TooLarge { .. }) => f(db, Err(Error::TooLarge { limit: REPLY_BUDGET })),
                // what comes back after it is told again, even if equal
                PortEvent::Notify(Payload::Lapsed) | PortEvent::Closed => {
                    last = None;
                    f(db, Err(sub_ended()));
                }
            }
        });
        Ok(self.node_sub(r, Some(on), filter, true, cb)?.0)
    }

    /// `backlinks` at the connected node, bounded by the largest page: a page always fits.
    pub(crate) fn node_backlinks(&self, r: &Connection, tid: Tid, q: &crate::BacklinkQuery) -> Result<crate::BacklinkPage> {
        // a backlink's encoding: its AK and a tid, each with a few bytes of framing
        const PAGE_BYTES: usize = crate::backlinks::BACKLINK_PAGE * (osis_base::format::MAX_AK_BYTES + 64) + SMALL_REPLY;
        const _: () = assert!(PAGE_BYTES <= REPLY_BUDGET);
        c::of(r.call_big(method::BACKLINKS, vec![Value::Tid(tid), c::v(q)], PAGE_BYTES)?)
    }

    /// The connection of a handle with no store: where its process-wide calls go.
    pub(crate) fn primary(&self) -> &Arc<Connection> {
        self.inner.client.get().map(|t| &t.primary).unwrap_or_else(|| unreachable!("a process-wide node call on a node's own handle"))
    }

    /// A page of the commits at `at` at the connected node, within what one reply carries.
    /// `LISTED_COMMIT`: commit `id` as listed at `at` at the node.
    pub(crate) fn node_listed_commit(&self, r: &Connection, at: &crate::commits::Address, id: crate::CommitId) -> Result<Option<crate::Commit>> {
        Ok(c::of::<Option<crate::Commit>>(r.call(method::LISTED_COMMIT, vec![c::v(at), c::v(&id)])?)?.map(|x| x.reporting(self)))
    }

    pub(crate) fn node_listing(&self, r: &Connection, at: &crate::commits::Address, q: &crate::CommitQuery) -> Result<crate::CommitPage> {
        // a page ends past this, so it holds up to twice it, and every commit's head: it must fit
        // one reply, or nothing could page past those commits
        let bytes = self.inner.limit.min(REPLY_BUDGET.saturating_sub(crate::commits::COMMIT_PAGE * COMMIT_HEAD) / 2);
        let mut page = c::of::<crate::CommitPage>(r.call(method::LISTING, vec![c::v(at), c::v(q), u(bytes as u64)])?)?;
        page.commits = page.commits.into_iter().map(|c| c.reporting(self)).collect();
        Ok(page)
    }

    /// Registers `cb` for a subscription at the connected node: its Reply (`PortEvent::Initial`)
    /// and Notifies reach `cb` through the dispatcher, in wire order. Returns the subscription
    /// and the initial value (or the Sub's error).
    pub(crate) fn node_sub(&self, r: &Arc<Connection>, on: Option<Tid>, filter: Value, again: bool, cb: Callback) -> Result<(Subscription, Value)> {
        if let Some(e) = r.down() {
            return Err(e);
        }
        let token = next_token();
        let sub = self.port_register(r, token, on, cb);
        let (itx, irx) = std::sync::mpsc::channel::<Value>();
        let sink = self.port_sink(token, Some(itx));
        r.send(Cmd::Sub { token, filter, again, sink })?;
        let v = crate::net::blocking(|| irx.recv()).map_err(|_| net("connection to the node closed"))?;
        if let Some(e) = sub_error(&v) {
            return Err(e);
        }
        Ok((sub, v))
    }

    /// `node_sub` for a watch that needs no answer to start: with the node down the callback
    /// hears `Closed` now and the first value when it is up (a live one's reconnect).
    fn node_sub_kept(&self, r: &Arc<Connection>, on: Option<Tid>, filter: Value, cb: Callback) -> Result<Subscription> {
        if r.down().is_none() {
            return Ok(self.node_sub(r, on, filter, true, cb)?.0);
        }
        Ok(self.node_sub_quiet(r, on, filter, cb))
    }

    /// A subscription at `r` that waits for nothing: the callback hears its first value, or `Closed`
    /// while down and the first value when it is up.
    fn node_sub_quiet(&self, r: &Arc<Connection>, on: Option<Tid>, filter: Value, cb: Callback) -> Subscription {
        let token = next_token();
        let sub = self.port_register(r, token, on, cb);
        // the handle of a stand-in has no connection to tell it
        if r.send(Cmd::Sub { token, filter, again: true, sink: self.port_sink(token, None) }).is_err() {
            self.port_sink(token, None)(PortEvent::Closed);
        }
        sub
    }

    /// The dispatcher's side of a subscription at `r`.
    fn port_register(&self, r: &Arc<Connection>, token: u64, on: Option<Tid>, cb: Callback) -> Subscription {
        let mut sub = self.locked(|l| self.inner.dispatch.register(l.seq + 1, Filter::Port(token, on), cb));
        sub.port = Some((Arc::downgrade(r), token));
        sub
    }

    /// What a subscription's events do: reach the dispatcher in wire order; the first value also
    /// goes to `first`, whose end says it will not come.
    fn port_sink(&self, token: u64, first: Option<std::sync::mpsc::Sender<Value>>) -> Sink {
        let weak = WeakOsis(Arc::downgrade(&self.inner));
        let first = Mutex::new(first);
        Box::new(move |ev: PortEvent| {
            match &ev {
                PortEvent::Initial(v) => {
                    if let Some(tx) = lock(&first).take() {
                        let _ = tx.send(v.clone());
                    }
                }
                // nobody waits for the first value any more
                PortEvent::Closed => drop(lock(&first).take()),
                PortEvent::Notify(_) => {}
            }
            if let Some(db) = weak.hold() {
                db.locked(|l| {
                    l.seq += 1;
                    db.inner.dispatch.send(l.seq, Msg::Port(token, ev));
                });
            }
        })
    }
}
