//! The handle (notes/api.md Handle and lifecycle): `Osis` over one node's sync engine (which owns
//! the engine) behind one lock; every call drains the engine's events into the dispatcher queue
//! before the lock is released, so the queue is in commit order, and lets the sync engine look
//! at what changed. Network actions leave through `Net` under the same lock, so they keep their
//! order.

use crate::error::{Error, Result};
use crate::net::{Net, Runtime, Waiter};
use crate::share::{Address, Status};
use crate::watch::{Dispatch, Dispatcher, Msg, lock};
use osis_base::{Clock, SystemClock, Tid};
use osis_crypto::{CryptoRngCore, OsRng, SeededRng};
use osis_node::sync::{Action, Event as SyncEvent, SyncConfig, SyncEngine};
use osis_node::{Engine, Event};
use osis_schema::Schema;
use osis_schema::core_types as ct;
use osis_store::{MemoryBackend, MemoryRoot};
use std::collections::BTreeMap;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Default bound on what one read holds in memory: 64 MiB.
const DEFAULT_LIMIT: usize = 64 << 20;
/// Default inactivity before a text session commits.
const DEFAULT_IDLE_COMMIT: Duration = Duration::from_secs(2);

/// A store in memory; clones share it, so a test can close a node and open it again.
#[derive(Clone, Debug, Default)]
pub struct MemStore {
    backend: MemoryBackend,
    root: MemoryRoot,
    /// The store of the node's host, its own key root beside it, while it serves (`set_serving`).
    pub(crate) host: MemoryBackend,
    /// Opens under a test seed, this store's and its backups' (`open_salt`).
    opens: Arc<std::sync::atomic::AtomicU64>,
    pub(crate) host_root: MemoryRoot,
}

impl MemStore {
    /// An empty store.
    pub fn new() -> MemStore {
        MemStore::default()
    }
    /// The bytes the node's store holds (`internals::MemStoreMeasures`).
    pub(crate) fn held_bytes(&self) -> u64 {
        self.backend.held_bytes()
    }
    pub(crate) fn rows(&self) -> usize {
        self.backend.dump().len()
    }
    pub(crate) fn held_split(&self) -> (u64, u64, u64) {
        self.backend.held_split()
    }
    pub(crate) fn backup(&self) -> MemStore {
        MemStore { backend: self.backend.copy(), root: self.root.copy(), opens: self.opens.clone(), ..MemStore::default() }
    }
}

/// Where a node's data lives.
#[derive(Clone, Debug)]
pub enum Store {
    /// In memory, gone with the last clone of the `MemStore`.
    Memory(MemStore),
    /// In this directory.
    Dir(std::path::PathBuf),
}

/// How a node with a store of its own runs (`Osis::create`, `open`, `pair`).
#[derive(Clone)]
pub struct Config {
    /// How this handle behaves, as a thin client's does.
    pub app: AppConfig,
    /// Where background sync runs (default `Runtime::None`: no network; `Invalid` with peers given).
    pub runtime: Runtime,
    /// Sync directly with other nodes that read the same data (default on): this node listens,
    /// tells them how to reach it and relays for them, and finds nodes on its local network (`lan`).
    /// Turn it off to sync only with saved peers.
    pub direct_sync: bool,
    /// Nodes that relay for this one, which it tells those nodes it can be reached through: each
    /// `peer://<ip>:<port>#<key>`, a node listening there with that key (any other form is
    /// `Invalid`).
    pub relays: Vec<Address>,
    /// Finding other nodes on the local network, with `direct_sync` and a runtime (default on).
    pub lan: crate::Lan,
}

impl Default for Config {
    fn default() -> Config {
        Config { app: AppConfig::default(), runtime: Runtime::None, direct_sync: true, relays: Vec::new(), lan: crate::Lan::default() }
    }
}

impl Config {
    /// `Invalid` for what would silently do nothing: peers with no runtime to reach them, LAN
    /// targets with nothing to announce (no runtime, no direct sync) or naming no place, a relay
    /// not named by one socket address.
    pub(crate) fn check(&self, peers: &[Address]) -> Result<()> {
        if !peers.is_empty() && matches!(self.runtime, Runtime::None) {
            return Err(Error::Invalid("peers with Runtime::None: nothing would sync; set Config.runtime".into()));
        }
        if let crate::Lan::On { also_announce_to } = &self.lan {
            if let Some(a) = also_announce_to.iter().find(|a| a.ip().is_unspecified() || a.port() == 0) {
                return Err(Error::Invalid(format!("LAN announcement target {a}: needs an address and a port")));
            }
            if !also_announce_to.is_empty() && (matches!(self.runtime, Runtime::None) || !self.direct_sync) {
                return Err(Error::Invalid("LAN announcement targets with no runtime or direct sync: nothing would announce".into()));
            }
        }
        if let Some(r) = self.relays.iter().find(|r| r.relay_item().is_none()) {
            return Err(Error::Invalid(format!("relay {r}: needs peer://<ip>:<port>#<key>")));
        }
        Ok(())
    }
}

/// How one `Osis` handle behaves, whether its data is here or at another node: all of a thin
/// client's config (`Osis::connect`, `connect_socket`), and `Config::app` of a node.
#[derive(Clone)]
pub struct AppConfig {
    /// Reads of values larger than this many bytes fail `TooLarge` (read those by stream or path).
    pub read_limit: usize,
    /// A text session commits after this much inactivity.
    pub idle_commit: Duration,
    /// Where watch callbacks run (default: a dispatcher thread).
    pub dispatch: Dispatcher,
    /// Test hooks.
    #[doc(hidden)]
    pub internals: crate::internals::Knobs,
}

impl Default for AppConfig {
    fn default() -> AppConfig {
        AppConfig { read_limit: DEFAULT_LIMIT, idle_commit: DEFAULT_IDLE_COMMIT, dispatch: Dispatcher::Thread, internals: Default::default() }
    }
}

/// A share link this node made: K and L (spec/permissions.md §7).
#[derive(Clone, Copy, Debug)]
pub(crate) struct MadeLink {
    pub l: Tid,
    pub target: Tid,
    pub single_use: bool,
    /// The link text carries this node's dialable key (`LinkOpts.direct`).
    pub direct: bool,
    /// A direct link that ended (revoked, finalized, expired): the key it carried was rotated.
    pub ended: bool,
}

/// The sync engine with its event channel, the dispatcher sequence number and the handle's
/// bookkeeping, all under one lock.
pub(crate) struct Locked {
    pub sync: SyncEngine,
    events: Receiver<Event>,
    pub seq: u64,
    pub waiters: Vec<Waiter>,
    pub status: Status,
    /// Pairing offers not yet used: secret, expiry (wall ms).
    pub offers: Vec<([u8; 32], u64)>,
    /// Links made here, by K.
    pub links: BTreeMap<Tid, MadeLink>,
    /// This process's connections to other nodes, in the order they connected.
    pub connections: Vec<Arc<crate::port::client::Connection>>,
    /// Groups this node reads and writes at another node: its address, persisted as the `sources`
    /// record. See `crate::sources`.
    pub group_sources: BTreeMap<Tid, Address>,
    /// The store failure the last status change met, told to status watches once.
    pub status_failed: bool,
    /// The own serving address in the saved peers (`SERVING_PEER`).
    pub serving_peer: Option<Address>,
}

impl Locked {
    pub fn engine(&mut self) -> &mut Engine {
        self.sync.engine_mut()
    }
}

impl Inner {
    /// Hands the sync engine's actions on, in order: network actions to the driver, client-port
    /// ones to the port (run after the lock is released).
    pub(crate) fn apply(&self, acts: Vec<Action>) {
        if acts.iter().any(crate::port::serve::is_port) {
            let (port, net): (Vec<Action>, Vec<Action>) = acts.into_iter().partition(crate::port::serve::is_port);
            self.port.queue(port);
            self.net.apply(net);
        } else {
            self.net.apply(acts);
        }
    }
}

/// A process with no store of its own: where its process-wide calls go, and who it is there.
pub(crate) struct ClientOf {
    pub primary: Arc<crate::port::client::Connection>,
    pub who: crate::port::client::Who,
}

pub(crate) struct Inner {
    pub eng: Mutex<Locked>,
    pub dispatch: Dispatch,
    pub node: Tid,
    pub me: Tid,
    pub home: Tid,
    pub limit: usize,
    pub idle_commit: Duration,
    /// `Knobs::text_save`.
    pub text_save: Option<Arc<dyn Fn() + Send + Sync>>,
    /// A test's in-process endpoints in place of QUIC, for this handle's every dial.
    pub transport: Option<osis_transport::InProcess>,
    /// The store's directory: what names its client socket (`Osis::listen_socket`).
    pub store_dir: Option<std::path::PathBuf>,
    /// Whether this node can dial another by its key alone (`Config::direct_sync`).
    pub dials_peers: bool,
    /// How long a connection's attempt, or a write across a drop, lasts (`CONNECTION_WAIT`).
    pub connection_wait: Duration,
    pub clock: Arc<dyn Clock>,
    pub schemas: Mutex<Vec<Arc<Schema>>>,
    /// Serializes undo and redo: candidate selection and commit.
    pub undo: Mutex<()>,
    pub net: Net,
    /// The client port this node serves: requests its served sessions make.
    pub port: crate::port::serve::Port,
    /// A process with no store of its own (`Osis::connect`): the scratch node stands in.
    pub client: std::sync::OnceLock<ClientOf>,
    /// Any connection or group source exists: only then is a source looked up (no cost on a local path).
    pub routing: std::sync::atomic::AtomicBool,
    /// User handles and whether the store closed (the last field: it drops after `eng`).
    pub life: LifeGuard,
}

/// What `close` waits on: the count of user handles (clones, `WeakOsis::upgrade`, streams,
/// text sessions; not the dispatcher's, the driver's or timers' short-lived ones) and whether
/// `Inner` is gone.
#[derive(Default)]
pub(crate) struct Life {
    m: Mutex<(usize, bool)>,
    cv: std::sync::Condvar,
}

impl Life {
    /// Changes the count of user handles, returning it.
    fn users(&self, d: isize) -> usize {
        let mut g = lock(&self.m);
        g.0 = g.0.saturating_add_signed(d);
        self.cv.notify_all();
        g.0
    }

    pub(crate) fn users_now(&self) -> usize {
        lock(&self.m).0
    }
}

/// Marks the store closed when `Inner` drops.
pub(crate) struct LifeGuard(pub(crate) Arc<Life>);

impl Drop for LifeGuard {
    fn drop(&mut self) {
        lock(&self.0.m).1 = true;
        self.0.cv.notify_all();
    }
}

/// What `Osis::close` found. Either way this handle is gone.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Close {
    /// The node is closed: its store can be opened again.
    Closed,
    /// `handles` other handles keep the node open.
    StillOpen {
        /// How many.
        handles: usize,
    },
}

/// A handle to a node, or for a thin client to a node elsewhere. Clones share it, and it closes
/// with the last one. Every read is on `ReadOnly`, which this derefs to.
#[derive(Clone)]
pub struct Osis(ReadOnly);

impl std::ops::Deref for Osis {
    type Target = ReadOnly;
    fn deref(&self) -> &ReadOnly {
        &self.0
    }
}

/// What a `ReadOnly` cannot do, checked at compile time; what it can:
/// ```
/// use osis::{Config, MemStore, Osis, ReadSet, Store};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\naspect t:n.0: int;\n");
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let set = ReadSet::new(|_| {});
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// # w.commit().unwrap();
/// # let r = db.tracking(&set);
///
/// let _ = r.at(t, N).get().unwrap();
/// let _ = r.me();
/// ```
///
/// writes:
/// ```compile_fail,E0599
/// use osis::{Config, MemStore, Osis, ReadSet, Store};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\naspect t:n.0: int;\n");
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let set = ReadSet::new(|_| {});
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// # w.commit().unwrap();
/// # let r = db.tracking(&set);
///
/// let _ = r.write();
/// ```
///
/// listeners:
/// ```compile_fail,E0599
/// use osis::{Config, MemStore, Osis, ReadSet, Store};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\naspect t:n.0: int;\n");
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let set = ReadSet::new(|_| {});
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// # w.commit().unwrap();
/// # let r = db.tracking(&set);
///
/// let _ = r.at(t, N).on_change(|_, _| {});
/// ```
///
/// a listener at a path:
/// ```compile_fail,E0599
/// use osis::{Config, MemStore, Osis, ReadSet, Store};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\naspect t:n.0: int;\n");
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let set = ReadSet::new(|_| {});
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// # w.commit().unwrap();
/// # let r = db.tracking(&set);
///
/// let _ = r.at(t, N).path(osis::p![]).on_change::<i64>(|_, _| {});
/// ```
///
/// text sessions:
/// ```compile_fail,E0599
/// use osis::{Config, MemStore, Osis, ReadSet, Store};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\naspect t:n.0: int;\n");
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let set = ReadSet::new(|_| {});
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// # w.commit().unwrap();
/// # let r = db.tracking(&set);
///
/// let _ = r.at(t, N).path(osis::p![]).edit_text();
/// ```
///
/// the clock:
/// ```compile_fail,E0599
/// use osis::{Config, MemStore, Osis, ReadSet, Store};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\naspect t:n.0: int;\n");
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let set = ReadSet::new(|_| {});
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// # w.commit().unwrap();
/// # let r = db.tracking(&set);
///
/// let _ = r.now();
/// ```
///
/// creating the profile:
/// ```compile_fail,E0599
/// use osis::{Config, MemStore, Osis, ReadSet, Store};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\naspect t:n.0: int;\n");
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let set = ReadSet::new(|_| {});
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// # w.commit().unwrap();
/// # let r = db.tracking(&set);
///
/// let _ = r.profile();
/// ```
///
/// escalating to a full handle:
/// ```compile_fail,E0599
/// use osis::{Config, MemStore, Osis, ReadSet, Store};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\naspect t:n.0: int;\n");
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let set = ReadSet::new(|_| {});
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// # w.commit().unwrap();
/// # let r = db.tracking(&set);
///
/// let _ = r.downgrade();
/// ```
///
/// tracking again:
/// ```compile_fail,E0599
/// use osis::{Config, MemStore, Osis, ReadSet, Store};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\naspect t:n.0: int;\n");
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let set = ReadSet::new(|_| {});
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// # w.commit().unwrap();
/// # let r = db.tracking(&set);
///
/// let _ = r.tracking(&set);
/// ```
#[cfg(doctest)]
pub struct ReadOnlyChecks;

impl std::borrow::Borrow<ReadOnly> for Osis {
    fn borrow(&self) -> &ReadOnly {
        &self.0
    }
}

/// A handle that reads and does nothing else: writes, listeners and sessions do not compile on
/// it. An `&Osis` is one (`Deref`); `tracking` makes one whose reads keep their listeners.
pub struct ReadOnly {
    pub(crate) inner: Arc<Inner>,
    /// Counted in `Life` (an app's handle; internal short-lived ones are not).
    user: bool,
    /// The actor this handle acts as (`act_as`): `me()`, and every read and write held to that
    /// actor's rights. `None`: this node's own.
    pub(crate) acting: Option<Tid>,
    /// The set this handle's reads are tracked in (`tracking`).
    pub(crate) tracking: Option<Arc<crate::track::SetInner>>,
}

impl Clone for ReadOnly {
    /// Always a user handle (a callback may keep a clone of the `&Osis` it is passed).
    fn clone(&self) -> ReadOnly {
        let mut o = ReadOnly::user(self.inner.clone());
        o.acting = self.acting;
        o.tracking = self.tracking.clone();
        o
    }
}

impl Drop for ReadOnly {
    fn drop(&mut self) {
        if self.user && self.inner.life.0.users(-1) == 0 {
            self.inner.port.closing();
        }
    }
}

impl std::fmt::Debug for ReadOnly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReadOnly({})", self.inner.node)
    }
}

impl std::fmt::Debug for Osis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Osis({})", self.inner.node)
    }
}

/// A handle that does not keep the node open (`Osis::downgrade`).
#[derive(Clone, Debug)]
pub struct WeakOsis(pub(crate) std::sync::Weak<Inner>);

impl WeakOsis {
    /// The node, if still open.
    pub fn upgrade(&self) -> Option<Osis> {
        self.0.upgrade().map(Osis::user)
    }

    /// For osis's own short-lived use (an engine call, a timer): not counted as a user handle,
    /// so `close` waits for it to end.
    pub(crate) fn hold(&self) -> Option<Osis> {
        self.0.upgrade().map(Osis::internal)
    }
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Inner({})", self.node)
    }
}

pub(crate) const SAVED_PEERS: &str = "saved_peers";
pub(crate) const LINKS: &str = "links";
/// The own serving address this node added to its saved peers (`Osis::upkeep_serving_peer`).
pub(crate) const SERVING_PEER: &str = "serving_peer";

fn parts(store: &Store) -> Result<(Box<dyn osis_store::Backend>, Box<dyn osis_store::RootStorage>)> {
    match store {
        Store::Memory(m) => Ok((Box::new(m.backend.clone()), Box::new(m.root.clone()))),
        Store::Dir(p) => {
            let mut d = std::fs::DirBuilder::new();
            d.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut d, 0o700);
            let bad = |e: &dyn std::fmt::Display| Error::Storage(format!("{}: {e}", p.display()));
            d.create(p).map_err(|e| bad(&e))?;
            let b = osis_store::RedbBackend::open(&p.join("db.redb")).map_err(|e| bad(&e))?;
            Ok((Box::new(b), Box::new(osis_store::FileRoot::new(p.join("root")))))
        }
    }
}

fn rng(cfg: &Config, salt: u64) -> Box<dyn CryptoRngCore + Send> {
    match cfg.app.internals.seed {
        Some(s) => Box::new(SeededRng::from_u64(s.wrapping_add(salt))),
        None => Box::new(OsRng),
    }
}

/// The rng salt of an open under a test seed: differs per open of a store, or every open would
/// draw one session nonce and void its earlier commits (spec/crdt.md §2.1). Deterministic per
/// store, kept beside it. Without a seed the rng is the OS's, so nothing is counted.
fn open_salt(store: &Store, cfg: &Config) -> Result<u64> {
    if cfg.app.internals.seed.is_none() {
        return Ok(0);
    }
    let n = match store {
        Store::Memory(m) => m.opens.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        Store::Dir(p) => {
            let f = p.join("seeded-opens");
            let n = std::fs::read_to_string(&f).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            std::fs::write(&f, n.wrapping_add(1).to_string()).map_err(|e| Error::Storage(format!("{}: {e}", f.display())))?;
            n
        }
    };
    Ok(n.wrapping_add(1).wrapping_mul(0x9e37_79b9_7f4a_7c15))
}

fn clock(cfg: &Config) -> Arc<dyn Clock> {
    cfg.app.internals.clock.clone().unwrap_or_else(|| Arc::new(SystemClock))
}

fn engine_cfg() -> osis_node::Config {
    osis_node::Config { software: format!("osis {}", env!("CARGO_PKG_VERSION")), ..Default::default() }
}

/// The saved peers as one local record (text lines).
pub(crate) fn save_peers(e: &mut Engine, s: &[Address]) -> Result<()> {
    let text: Vec<String> = s.iter().map(|a| a.to_string()).collect();
    e.set_app_record(SAVED_PEERS, text.join("\n").as_bytes())?;
    Ok(())
}

fn load_peers(e: &mut Engine) -> Result<Option<Vec<Address>>> {
    let Some(b) = e.app_record(SAVED_PEERS)? else { return Ok(None) };
    let s = String::from_utf8(b).map_err(|_| Error::Storage("saved peers record".into()))?;
    Ok(Some(s.lines().filter(|l| !l.is_empty()).map(|l| l.parse()).collect::<Result<_>>()?))
}

/// A sync engine over an engine, from the first commit on (it sees every event).
pub(crate) struct Fresh {
    pub sync: SyncEngine,
    pub clock: Arc<dyn Clock>,
}

fn sync_over(engine: Engine, clock: &Arc<dyn Clock>, cfg: &Config, hosts: &[Address]) -> Result<SyncEngine> {
    let scfg = SyncConfig { hosts: hosts.iter().map(|s| s.0.clone()).collect(), peers: cfg.direct_sync, ..SyncConfig::default() };
    Ok(SyncEngine::new(engine, clock.clone(), rng(cfg, 7), scfg)?)
}

/// A new store's sync engine (its hosts set later by `set_hosts` where they change).
pub(crate) fn fresh_engine(store: &Store, cfg: &Config, hosts: &[Address]) -> Result<Fresh> {
    let (b, r) = parts(store)?;
    let clock = clock(cfg);
    let engine = Engine::create(b, r, engine_cfg(), clock.clone(), rng(cfg, 0))?;
    Ok(Fresh { sync: sync_over(engine, &clock, cfg, hosts)?, clock })
}

impl Osis {
    /// Creates a node and a new account with this node its admin. The account is also its home group,
    /// synced with `peers`. Peers need `Config::runtime` (`Invalid`).
    pub fn create(store: Store, peers: &[Address], cfg: Config) -> Result<Osis> {
        cfg.check(peers)?;
        let Fresh { mut sync, clock } = fresh_engine(&store, &cfg, peers)?;
        let engine = sync.engine_mut();
        let addrs: Vec<osis_label::Address> = peers.iter().map(|s| s.0.clone()).collect();
        let (a, done) = engine.create_account(&addrs)?;
        let mut m = osis_node::Mutation::new();
        m.set(a.devices, &ct::GROUP, &ct::Group::default())?;
        engine.commit(m)?;
        save_peers(engine, peers)?;
        let db = Osis::start(sync, clock, store, &cfg, a.account, a.devices)?;
        db.carry(done)?;
        Ok(db)
    }

    /// Opens an existing store. Its peers are those saved in it (`add_peer`, `remove_peer`).
    pub fn open(store: Store, cfg: Config) -> Result<Osis> {
        cfg.check(&[])?;
        let (b, r) = parts(&store)?;
        let clock = clock(&cfg);
        let mut e = Engine::open(b, r, engine_cfg(), clock.clone(), rng(&cfg, open_salt(&store, &cfg)?))?;
        let (me, home) = e.account()?.ok_or_else(|| Error::Storage("no account record".into()))?;
        let peers = load_peers(&mut e)?.unwrap_or_default();
        let sync = sync_over(e, &clock, &cfg, &peers)?;
        let db = Osis::start(sync, clock, store, &cfg, me, home)?;
        db.load_links()?;
        Ok(db)
    }

    pub(crate) fn start(mut sync: SyncEngine, clock: Arc<dyn Clock>, store: Store, cfg: &Config, me: Tid, home: Tid) -> Result<Osis> {
        // store files open to group or others: tightened where possible (best effort), else
        // reported
        if let Store::Dir(p) = &store {
            for f in [p.clone(), p.join("db.redb"), p.join("root")] {
                if let Some(why) = osis_store::restrict_to_owner(&f) {
                    sync.engine_mut().report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::Storage, tids: Vec::new(), commit: None, peer: None, detail: why });
                }
            }
        }
        let node = sync.engine().tid();
        let events = sync.engine_mut().subscribe();
        let dispatch = Dispatch::new(&cfg.app.dispatch);
        let (net, ctl) = Net::new(&cfg.runtime)?;
        let group_sources = crate::sources::load_sources(sync.engine_mut())?;
        sync.engine_mut().core.routed_away = group_sources.keys().copied().collect();
        let routing = !group_sources.is_empty();
        let serving_peer = match sync.engine_mut().app_record(SERVING_PEER)? {
            Some(b) if !b.is_empty() => Some(String::from_utf8(b).map_err(|_| Error::Storage("serving peer record".into()))?.parse()?),
            _ => None,
        };
        let locked = Locked { sync, events, seq: 0, waiters: Vec::new(), status: Status::default(), offers: Vec::new(), links: BTreeMap::new(), connections: Vec::new(), group_sources, status_failed: false, serving_peer };
        let port = crate::port::serve::Port::new();
        let inner = Arc::new(Inner { eng: Mutex::new(locked), dispatch, node, me, home, limit: cfg.app.read_limit, idle_commit: cfg.app.idle_commit, text_save: cfg.app.internals.text_save.clone(), transport: cfg.app.internals.transport.clone(), store_dir: match &store { Store::Dir(p) => Some(p.clone()), Store::Memory(_) => None }, dials_peers: cfg.direct_sync, connection_wait: cfg.app.internals.connection_wait.unwrap_or(crate::port::client::CONNECTION_WAIT), clock: clock.clone(), schemas: Mutex::new(Vec::new()), undo: Mutex::new(()), net, port, client: std::sync::OnceLock::new(), routing: routing.into(), life: LifeGuard(Arc::default()) });
        inner.dispatch.start(Arc::downgrade(&inner))?;
        if let Some(ctl) = ctl {
            inner.net.spawn_driver(ctl, store, cfg, clock, WeakOsis(Arc::downgrade(&inner)))?;
        }
        let db = Osis::user(inner);
        if let Runtime::Manual(m) = &cfg.runtime {
            m.register(db.downgrade());
        }
        db.locked(|_| ());
        Ok(db)
    }

    fn user(inner: Arc<Inner>) -> Osis {
        Osis(ReadOnly::user(inner))
    }

    /// A handle for osis's own short-lived use (the dispatcher running callbacks), not counted.
    pub(crate) fn internal(inner: Arc<Inner>) -> Osis {
        Osis(ReadOnly { inner, user: false, acting: None, tracking: None })
    }

    /// A handle acting as `actor`, an actor this node administers (notes/client-port.md §3): `me()`
    /// is that actor, a read shows what it may read and nothing else (what it may not reads as a
    /// thing this node does not know), a write or revert needs its rights, not this node's. Calls
    /// on the tid-addressed read and write paths only: the sharing, sync and process-wide calls do
    /// not honour it yet (issues/grant-rename-multi-actor.md), so it stays inside the crate, used
    /// by the port worker's client rows (`port::method::for_client`).
    pub(crate) fn act_as(&self, actor: Tid) -> Osis {
        Osis(ReadOnly { inner: self.inner.clone(), user: false, acting: Some(actor), tracking: None })
    }

    /// A handle that does not keep the node open (for the rare callback that must capture
    /// one; callbacks are passed `&Osis`).
    pub fn downgrade(&self) -> WeakOsis {
        WeakOsis(Arc::downgrade(&self.inner))
    }

    /// Closes this handle. With no other handle left (clones, upgraded `WeakOsis`, value streams,
    /// text sessions, a `Joining`), returns once the node is closed (every commit is already
    /// durable), so the store can be opened again at once; a callback or sync engine call still
    /// running ends first, and so does background sync, serving for others included: with `Runtime::Own` its runtime is
    /// shut down (about 10 s at worst; a task still running then may keep the store of what it serves
    /// a little longer), with `Runtime::Tokio` on a
    /// multi-thread runtime its task ends (so the app may shut that runtime down); on a
    /// current-thread runtime `close` does not wait for sync, which ends once the app drives that
    /// runtime again. While other handles keep it open, this one is closed and it returns
    /// `Close::StillOpen` at once. From a callback (the dispatcher, which holds the node while it
    /// runs) it fails `Invalid` at once: drop the handle instead. Never call it while holding
    /// something a running callback may wait for (a lock, a channel it awaits): close waits for
    /// that callback.
    pub fn close(self) -> Result<Close> {
        if self.inner.dispatch.shared.on_dispatcher() {
            return Err(Error::Invalid("close() from a callback would wait on itself; drop the handle".into()));
        }
        let life = self.inner.life.0.clone();
        let ended = self.inner.net.ended();
        drop(self);
        // what still holds it besides user handles (a callback, an engine call, a timer) ends
        // (in place on a multi-thread runtime: the holder may need that worker's tasks)
        let (users, closed) = crate::net::blocking(|| *life.cv.wait_while(lock(&life.m), |(users, closed)| *users == 0 && !*closed).unwrap_or_else(|e| e.into_inner()));
        if !closed {
            return Ok(Close::StillOpen { handles: users });
        }
        if let Some(e) = ended {
            // the driver, and the host with it, is gone: the host store is free and the app may
            // shut its runtime down
            crate::net::wait_ended(&e);
        }
        Ok(Close::Closed)
    }

}

impl ReadOnly {
    fn user(inner: Arc<Inner>) -> ReadOnly {
        inner.life.0.users(1);
        ReadOnly { inner, user: true, acting: None, tracking: None }
    }

    /// This node's own identity, an actor apart from its account (a thin client: its node's).
    pub fn node(&self) -> Tid {
        self.inner.client.get().map_or(self.inner.node, |t| t.who.node)
    }

    /// The account this node belongs to (a thin client: the actor its node acts as for it): the
    /// author of its writes and the holder of its roles.
    pub fn me(&self) -> Tid {
        self.acting.unwrap_or_else(|| self.inner.client.get().map_or(self.inner.me, |t| t.who.me))
    }

    /// The group private to this account: what is in it reaches every node of the account and
    /// nobody else. On a client with its own actor it is that actor.
    pub fn home(&self) -> Tid {
        self.acting.unwrap_or_else(|| self.inner.client.get().map_or(self.inner.home, |t| t.who.home))
    }

    /// Runs `f` on the engine under the node lock, then queues its events for the
    /// dispatcher (`internals::Internals::engine` outside the crate).
    pub(crate) fn engine<R>(&self, f: impl FnOnce(&mut Engine) -> R) -> R {
        self.locked(|l| f(l.engine()))
    }

    /// Runs `f` on the sync engine as the network driver does: its actions go out, and the
    /// events it caused were already seen by the sync engine.
    pub(crate) fn handled(&self, f: impl FnOnce(&mut Locked) -> Vec<Action>) {
        self.locked_in(true, |l| {
            let acts = f(l);
            self.inner.apply(acts);
        })
    }

    pub(crate) fn locked<R>(&self, f: impl FnOnce(&mut Locked) -> R) -> R {
        self.locked_in(false, f)
    }

    fn locked_in<R>(&self, handled: bool, f: impl FnOnce(&mut Locked) -> R) -> R {
        let mut g = lock(&self.inner.eng);
        let holder = &self.inner.dispatch.shared.holder;
        *lock(holder) = Some(std::thread::current().id());
        // nothing past its expiry is seen, however late the driver's Tick
        g.sync.expire_due();
        let r = f(&mut g);
        self.after(&mut g, handled);
        *lock(holder) = None;
        drop(g);
        self.inner.dispatch.wake();
        self.inner.port.kick(&self.inner);
        r
    }

    /// Queues events for the dispatcher; `true` when there were any events other than
    /// ephemeral ones (local ephemeral writes reach the sync engine only when they wait to be
    /// sent, `after`).
    fn drain(&self, l: &mut Locked) -> bool {
        let mut any = false;
        while let Ok(e) = l.events.try_recv() {
            any |= !matches!(e, Event::Ephemeral { .. });
            l.seq += 1;
            self.inner.dispatch.send(l.seq, Msg::Event(e));
        }
        any
    }

    /// After every call under the lock: events to the dispatcher; local changes shown to the
    /// sync engine; then status, link upkeep and waiters.
    fn after(&self, l: &mut Locked, handled: bool) {
        // ephemeral writes on things in a labeled closure go out as ephemeral commits
        let any = self.drain(l) || l.sync.engine().has_memory_changes();
        if any && !handled {
            let acts = l.sync.handle(SyncEvent::Local);
            self.inner.apply(acts);
            self.drain(l);
        }
        if !(any || handled) {
            // nothing changed: a waiter whose future was dropped still goes
            if !l.waiters.is_empty() {
                let Locked { waiters, sync, status, .. } = l;
                waiters.retain_mut(|w| !w.poll(sync, status));
            }
            return;
        }
        self.upkeep_serving_peer(l);
        self.upkeep_links(l);
        match crate::share::status_of(&mut l.sync) {
            Ok(status) if status != l.status || l.status_failed => {
                for (g, s) in &status.groups {
                    if s.state == crate::share::SyncState::Stranded && l.status.groups.get(g).is_none_or(|o| o.state != s.state) {
                        l.engine().report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::Stranded, tids: vec![*g], commit: None, peer: None, detail: "stranded: waiting for a re-seal".into() });
                    }
                }
                l.status = status.clone();
                l.status_failed = false;
                l.seq += 1;
                self.inner.dispatch.send(l.seq, Msg::Status(Ok(status)));
            }
            Ok(_) => {}
            // once: a store that cannot answer fails every call that asks it anyway
            Err(e) if !l.status_failed => {
                l.status_failed = true;
                l.seq += 1;
                self.inner.dispatch.send(l.seq, Msg::Status(Err(e)));
            }
            Err(_) => {}
        }
        self.drain(l);
        let Locked { waiters, sync, status, .. } = l;
        waiters.retain_mut(|w| !w.poll(sync, status));
    }

    /// Runs `f` under the lock and hands the actions it returns to the network, in order.
    pub(crate) fn act(&self, f: impl FnOnce(&mut Locked) -> Vec<Action>) {
        self.locked(|l| {
            let acts = f(l);
            self.inner.apply(acts);
        })
    }

    /// `act` for a fallible `f`.
    pub(crate) fn try_act(&self, f: impl FnOnce(&mut Locked) -> Result<Vec<Action>>) -> Result<()> {
        self.locked(|l| {
            let acts = f(l)?;
            self.inner.apply(acts);
            Ok(())
        })
    }

    /// Carries out a flow's result (deliveries) under the lock.
    pub(crate) fn carry(&self, done: osis_node::flows::Done) -> Result<()> {
        self.try_act(|l| Ok(l.sync.carry_out(done)?))
    }

}

impl Osis {
    /// Returns once every callback for commits made so far has run: with
    /// `Dispatcher::Thread` it waits for the dispatcher thread (tests and scripts wait this
    /// way without sleeping); with `Dispatcher::Pump` it runs them on this thread, which is
    /// how the app pumps (after its wake callback). Returns at once inside a callback.
    // Never inside an `Internals::engine` closure: a callback may need the lock it holds (deadlock).
    pub fn settle(&self) {
        // connected nodes' deliveries so far reach the queue first (not from a callback: the reply
        // would wait for this very dispatcher)
        if self.routing() && self.may_wait() {
            self.node_settle();
        }
        self.inner.dispatch.settle(Arc::downgrade(&self.inner));
    }

    /// Registers a `*.osis` schema source, here and at any connected node: `aspect_key` then types its
    /// aspects, and undo and large values follow the schema. `name` appears in its errors
    /// (name:line:col). Generated keys carry their schema and need no registration. The newest
    /// registration of an aspect types `aspect_key` for this session; the store keeps the highest version.
    /// A schema of an app declares no core aspect.
    pub fn register_schema(&self, name: &str, source: &str) -> Result<()> {
        let s = osis_schema::parse(name, source).map_err(|e| Error::Invalid(e.to_string()))?;
        if s.declares_core() {
            return Err(Error::Invalid("an app schema declares no core AK".into()));
        }
        // the nodes need it for structural diffs and undo write-back
        self.mirror_schema(name, source)?;
        let s = Arc::new(s);
        self.engine(|e| e.register_schema(s.clone()))?;
        let mut v = lock(&self.inner.schemas);
        v.retain(|x| x.aspects.keys().any(|k| !s.aspects.contains_key(k)));
        v.push(s);
        Ok(())
    }

}

impl ReadOnly {
    /// The key named `ak`: typed by the registered schema that declares it, else untyped.
    pub fn aspect_key(&self, ak: &str) -> Result<crate::DynamicAspectKey> {
        let ak = osis_base::Ak::new(ak).map_err(|_| Error::Invalid(format!("bad AK {ak:?}")))?;
        let core = crate::keys::core_schema();
        let schema = if core.aspects.contains_key(ak.as_str()) {
            Some(core)
        } else {
            lock(&self.inner.schemas).iter().rev().find(|s| s.aspects.contains_key(ak.as_str())).cloned()
        };
        Ok(crate::DynamicAspectKey { ak, schema })
    }
}
