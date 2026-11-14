//! The handle (notes/api.md Handle and lifecycle): `Osis` over one node's engine behind one lock;
//! every call drains the engine's events into the dispatcher queue before the lock is released,
//! so the queue is in commit order.

use crate::error::{Error, Result};
use crate::net::Runtime;
use crate::share::Address;
use crate::watch::{Dispatch, Dispatcher, Msg, lock};
use osis_base::{Clock, SystemClock, Tid};
use osis_crypto::{OsRng, SeededRng};
use osis_engine::{Engine, Event};
use osis_schema::Schema;
use osis_schema::core_types as ct;
use osis_store::{MemoryBackend, MemoryRoot};
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
    pub(crate) backend: MemoryBackend,
    pub(crate) root: MemoryRoot,
    /// The engine's ciphertext store (`osis_store::BlobArea`), its own key root beside it.
    pub(crate) blobs: MemoryBackend,
    pub(crate) blobs_root: MemoryRoot,
    /// Opens under a test seed, this store's and its backups' (`open_salt`).
    pub(crate) opens: Arc<std::sync::atomic::AtomicU64>,
}

impl MemStore {
    /// An empty store.
    pub fn new() -> MemStore {
        MemStore::default()
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
    /// Turn it off to sync only with the peers it is given.
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

/// The engine with its event channel, the dispatcher sequence number and the handle's
/// bookkeeping, all under one lock.
pub(crate) struct Locked {
    pub engine: Engine,
    pub events: Receiver<Event>,
    pub seq: u64,
    /// Pairing offers not yet used: secret, expiry (wall ms).
    pub offers: Vec<([u8; 32], u64)>,
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
    pub clock: Arc<dyn Clock>,
    pub schemas: Mutex<Vec<Arc<Schema>>>,
    /// Serializes undo and redo: candidate selection and commit.
    pub undo: Mutex<()>,
    /// A runtime is configured (`Config::runtime`): timers run (`Inner::after`).
    pub timers: bool,
    /// User handles and whether the store closed (the last field: it drops after `eng`).
    pub life: LifeGuard,
}

impl Inner {
    /// Runs `f` once `d` has passed, on a thread of its own; `false` with no runtime configured
    /// (`Runtime::None`: nothing runs in the background).
    pub(crate) fn after(&self, d: Duration, f: Box<dyn FnOnce() + Send>) -> bool {
        self.timers
            && std::thread::Builder::new()
                .name("osis-timer".into())
                .spawn(move || {
                    std::thread::sleep(d);
                    f()
                })
                .is_ok()
    }
}

/// What `close` waits on: the count of user handles (clones, `WeakOsis::upgrade`, streams,
/// text sessions; not the dispatcher's or timers' short-lived ones) and whether
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
        if self.user {
            self.inner.life.0.users(-1);
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

/// A store's backend and key root: the engine's (`<store>/db.redb`, `<store>/root`), or with
/// `blobs` its ciphertext store's (`blobs.redb`, `blobs.root`).
fn parts(store: &Store, blobs: bool) -> Result<(Box<dyn osis_store::Backend>, Box<dyn osis_store::RootStorage>)> {
    match store {
        Store::Memory(m) if blobs => Ok((Box::new(m.blobs.clone()), Box::new(m.blobs_root.clone()))),
        Store::Memory(m) => Ok((Box::new(m.backend.clone()), Box::new(m.root.clone()))),
        Store::Dir(p) => {
            let mut d = std::fs::DirBuilder::new();
            d.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut d, 0o700);
            let bad = |e: &dyn std::fmt::Display| Error::Storage(format!("{}: {e}", p.display()));
            d.create(p).map_err(|e| bad(&e))?;
            let (db, root) = if blobs { ("blobs.redb", "blobs.root") } else { ("db.redb", "root") };
            let b = osis_store::RedbBackend::open(&p.join(db)).map_err(|e| match e {
                osis_store::BackendError::InUse => Error::InUse,
                e => bad(&e),
            })?;
            Ok((Box::new(b), Box::new(osis_store::FileRoot::new(p.join(root)))))
        }
    }
}

fn rng(cfg: &Config, salt: u64) -> Box<dyn osis_crypto::NodeRng> {
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

/// The engine's ciphertext store (`Engine::open`).
fn blob_store(store: &Store) -> Result<Arc<dyn osis_store::Ciphertext>> {
    let (b, r) = parts(store, true)?;
    Ok(osis_store::BlobArea::open(b, r, Box::new(OsRng)).map_err(osis_engine::Error::from)?)
}

fn clock(cfg: &Config) -> Arc<dyn Clock> {
    cfg.app.internals.clock.clone().unwrap_or_else(|| Arc::new(SystemClock))
}

fn engine_cfg() -> osis_engine::Config {
    osis_engine::Config { software: format!("osis {}", env!("CARGO_PKG_VERSION")), ..Default::default() }
}

/// A new store's engine, from the first commit on (it sees every event).
pub(crate) struct Fresh {
    pub engine: Engine,
    pub clock: Arc<dyn Clock>,
}

/// A new store's engine.
pub(crate) fn fresh_engine(store: &Store, cfg: &Config) -> Result<Fresh> {
    let (b, r) = parts(store, false)?;
    let clock = clock(cfg);
    let engine = Engine::create(b, r, blob_store(store)?, engine_cfg(), clock.clone(), rng(cfg, 0))?;
    Ok(Fresh { engine, clock })
}

impl Osis {
    /// Creates a node and a new account with this node its admin. The account is also its home group,
    /// synced with `peers` (`NotBuilt` with any). Peers need `Config::runtime` (`Invalid`).
    pub fn create(store: Store, peers: &[Address], cfg: Config) -> Result<Osis> {
        cfg.check(peers)?;
        if !peers.is_empty() {
            return Err(Error::NotBuilt);
        }
        let Fresh { mut engine, clock } = fresh_engine(&store, &cfg)?;
        let (a, _) = engine.create_account(&[])?;
        let mut m = osis_engine::Mutation::new();
        m.set(a.devices, &ct::GROUP, &ct::Group::default())?;
        engine.commit(m)?;
        Osis::start(engine, clock, store, &cfg, a.account, a.devices)
    }

    /// Opens an existing store.
    pub fn open(store: Store, cfg: Config) -> Result<Osis> {
        cfg.check(&[])?;
        let (b, r) = parts(&store, false)?;
        let clock = clock(&cfg);
        let mut e = Engine::open(b, r, blob_store(&store)?, engine_cfg(), clock.clone(), rng(&cfg, open_salt(&store, &cfg)?))?;
        let (me, home) = e.account()?.ok_or_else(|| Error::Storage("no account record".into()))?;
        Osis::start(e, clock, store, &cfg, me, home)
    }

    pub(crate) fn start(mut engine: Engine, clock: Arc<dyn Clock>, store: Store, cfg: &Config, me: Tid, home: Tid) -> Result<Osis> {
        // store files open to group or others: tightened where possible (best effort), else
        // reported
        if let Store::Dir(p) = &store {
            for f in [p.clone(), p.join("db.redb"), p.join("root"), p.join("blobs.redb"), p.join("blobs.root")] {
                if let Some(why) = osis_store::restrict_to_owner(&f) {
                    engine.report(osis_engine::Diagnostic { kind: osis_engine::DiagnosticKind::Storage, tids: Vec::new(), commit: None, peer: None, detail: why });
                }
            }
        }
        let node = engine.tid();
        let events = engine.subscribe();
        let dispatch = Dispatch::new(&cfg.app.dispatch);
        let locked = Locked { engine, events, seq: 0, offers: Vec::new() };
        let inner = Arc::new(Inner { eng: Mutex::new(locked), dispatch, node, me, home, limit: cfg.app.read_limit, idle_commit: cfg.app.idle_commit, text_save: cfg.app.internals.text_save.clone(), clock: clock.clone(), schemas: Mutex::new(Vec::new()), undo: Mutex::new(()), timers: !matches!(cfg.runtime, Runtime::None), life: LifeGuard(Arc::default()) });
        inner.dispatch.start(Arc::downgrade(&inner))?;
        let db = Osis::user(inner);
        db.locked(|_| ());
        Ok(db)
    }

    pub(crate) fn user(inner: Arc<Inner>) -> Osis {
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
    /// not honour it yet (issues/grant-rename-multi-actor.md), so it stays inside the crate.
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
    /// durable), so the store can be opened again at once; a callback still running ends first.
    /// While other handles keep it open, this one is closed and it returns
    /// `Close::StillOpen` at once. From a callback (the dispatcher, which holds the node while it
    /// runs) it fails `Invalid` at once: drop the handle instead. Never call it while holding
    /// something a running callback may wait for (a lock, a channel it awaits): close waits for
    /// that callback.
    pub fn close(self) -> Result<Close> {
        if self.inner.dispatch.shared.on_dispatcher() {
            return Err(Error::Invalid("close() from a callback would wait on itself; drop the handle".into()));
        }
        let life = self.inner.life.0.clone();
        drop(self);
        // what still holds it besides user handles (a callback, an engine call, a timer) ends
        // (in place on a multi-thread runtime: the holder may need that worker's tasks)
        let (users, closed) = crate::net::blocking(|| *life.cv.wait_while(lock(&life.m), |(users, closed)| *users == 0 && !*closed).unwrap_or_else(|e| e.into_inner()));
        if !closed {
            return Ok(Close::StillOpen { handles: users });
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
        self.inner.node
    }

    /// The account this node belongs to (a thin client: the actor its node acts as for it): the
    /// author of its writes and the holder of its roles.
    pub fn me(&self) -> Tid {
        self.acting.unwrap_or(self.inner.me)
    }

    /// The group private to this account: what is in it reaches every node of the account and
    /// nobody else. On a client with its own actor it is that actor.
    pub fn home(&self) -> Tid {
        self.acting.unwrap_or(self.inner.home)
    }

    /// Runs `f` on the engine under the node lock, then queues its events for the
    /// dispatcher (`internals::Internals::engine` outside the crate).
    pub(crate) fn engine<R>(&self, f: impl FnOnce(&mut Engine) -> R) -> R {
        self.locked(|l| f(&mut l.engine))
    }

    pub(crate) fn locked<R>(&self, f: impl FnOnce(&mut Locked) -> R) -> R {
        let mut g = lock(&self.inner.eng);
        let holder = &self.inner.dispatch.shared.holder;
        *lock(holder) = Some(std::thread::current().id());
        expire_due(&mut g.engine);
        let r = f(&mut g);
        lifetimes(&mut g.engine);
        self.drain(&mut g);
        *lock(holder) = None;
        drop(g);
        self.inner.dispatch.wake();
        r
    }

    /// Queues the engine's events for the dispatcher.
    fn drain(&self, l: &mut Locked) {
        while let Ok(e) = l.events.try_recv() {
            l.seq += 1;
            self.inner.dispatch.send(l.seq, Msg::Event(e));
        }
    }
}

/// Runs the engine's due expiry timers (spec/commits.md §6), so nothing past its expiry is seen. A
/// failure is a diagnostic; the timers stay due.
fn expire_due(e: &mut Engine) {
    if e.timers_due()
        && let Err(x) = e.tick()
    {
        e.report(osis_engine::Diagnostic { kind: osis_engine::DiagnosticKind::Storage, tids: Vec::new(), commit: None, peer: None, detail: format!("expiry timers: {x}") });
    }
}

/// Judges thing lifetimes when work is queued (notes/lifetimes.md, The release): a thing is
/// judged once every group holding it is heard out; with no sync, a group with a sync ID never
/// is, so nothing under one is released. A failure is a diagnostic; the work stays queued.
fn lifetimes(e: &mut Engine) {
    let r = e.lifetimes_due().and_then(|(due, _)| {
        if !due {
            return Ok(());
        }
        let synced: std::collections::BTreeSet<Tid> = e.labeled_groups().into_iter().collect();
        e.judge_lifetimes(&|g| !synced.contains(g), false).map(drop)
    });
    if let Err(x) = r {
        e.report(osis_engine::Diagnostic { kind: osis_engine::DiagnosticKind::Storage, tids: Vec::new(), commit: None, peer: None, detail: format!("lifetimes: {x}") });
    }
}

impl Osis {
    /// Returns once every callback for commits made so far has run: with
    /// `Dispatcher::Thread` it waits for the dispatcher thread (tests and scripts wait this
    /// way without sleeping); with `Dispatcher::Pump` it runs them on this thread, which is
    /// how the app pumps (after its wake callback). Returns at once inside a callback.
    // Never inside an `Internals::engine` closure: a callback may need the lock it holds (deadlock).
    pub fn settle(&self) {
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
