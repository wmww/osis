//! The handle (notes/api.md Handle and lifecycle): `Osis` over one node's sync engine (which owns
//! the engine) behind one lock; every call drains the engine's events into the dispatcher queue
//! before the lock is released, so the queue is in commit order, and lets the sync engine look
//! at what changed. Network actions leave through `Net` under the same lock, so they keep their
//! order.

use crate::error::{Error, Result};
use crate::net::{Net, Runtime, Transport, Waiter};
use crate::share::{RecoveryCard, ServerAddr, Status};
use crate::watch::{Dispatch, Dispatcher, Msg, lock};
use osis_base::{Clock, SystemClock, Tid};
use osis_crypto::{CryptoRngCore, OsRng, SeededRng};
use osis_node::sync::{Action, Event as SyncEvent, SyncConfig, SyncEngine};
use osis_node::{Engine, Event};
use osis_schema::Schema;
use osis_schema::core_types as ct;
use osis_store::{MemoryBackend, MemoryRoot};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Default materialization bound: 64 MiB (notes/api.md Reads).
pub const DEFAULT_LIMIT: usize = 64 << 20;
/// Default wait for another node (`Config::wait_timeout`).
pub const DEFAULT_WAIT: Duration = Duration::from_secs(60);
/// Default inactivity before a text session commits.
pub const DEFAULT_IDLE_COMMIT: Duration = Duration::from_secs(2);

/// An in-memory store; clones share it, so a test can close a database and open it again.
#[derive(Clone, Debug, Default)]
pub struct MemStore {
    backend: MemoryBackend,
    root: MemoryRoot,
}

impl MemStore {
    pub fn new() -> MemStore {
        MemStore::default()
    }
}

/// Where the database lives.
#[derive(Clone, Debug)]
pub enum StoreAt {
    Memory(MemStore),
    /// A directory: `db.redb` and the key root `root`.
    Dir(std::path::PathBuf),
}

/// How to open a database.
#[derive(Clone)]
pub struct Config {
    pub store: StoreAt,
    /// Reads of values larger than this many canonical bytes fail `TooLarge`.
    pub materialize_limit: usize,
    /// Wall clock (default the system clock); tests pass a `ManualClock`.
    pub clock: Option<Arc<dyn Clock>>,
    /// Seed for a deterministic rng (tests only; default OS randomness).
    pub seed: Option<u64>,
    /// Where background sync runs (default `Runtime::None`: no network).
    pub runtime: Runtime,
    /// How servers and co-reader nodes are dialed (default: QUIC).
    pub transport: Option<Transport>,
    /// Sync with co-reader nodes directly (spec/sync.md §5, §10; default on): listen with the
    /// dialable key, publish `/reach`, and with feature `lan` announce on the LAN.
    pub peers: bool,
    /// Relay URLs published in `/reach` (self-hosted `iroh-relay`s; feature `iroh`).
    pub relays: Vec<String>,
    /// Servers for `create`, `restore` and `pair`; an opened database keeps its stored list.
    pub servers: Vec<ServerAddr>,
    /// A text session commits after this much inactivity.
    pub idle_commit: Duration,
    /// How long a call that waits for another node (`redeem`, `import_contact`, `restore`)
    /// waits before failing `Network`.
    pub wait_timeout: Duration,
    /// Bytes of this session's ephemeral changes kept for undo (default 16 MiB); older ones are
    /// `NotUndoable{Compacted}` (notes/ephemeral.md Bounds).
    pub ephemeral_history: usize,
    /// Where watch callbacks run (default: a dispatcher thread).
    pub dispatch: Dispatcher,
}

impl Config {
    /// A fresh in-memory store.
    pub fn memory() -> Config {
        Config::at(StoreAt::Memory(MemStore::new()))
    }

    pub fn at(store: StoreAt) -> Config {
        Config { store, materialize_limit: DEFAULT_LIMIT, clock: None, seed: None, runtime: Runtime::None, transport: None, peers: true, relays: Vec::new(), servers: Vec::new(), idle_commit: DEFAULT_IDLE_COMMIT, wait_timeout: DEFAULT_WAIT, ephemeral_history: osis_node::engine::DEFAULT_EPHEMERAL_HISTORY, dispatch: Dispatcher::Thread }
    }

    pub fn dir(path: impl Into<std::path::PathBuf>) -> Config {
        Config::at(StoreAt::Dir(path.into()))
    }
}

/// A share link this node made: K and L (spec/permissions.md §9).
#[derive(Clone, Copy, Debug)]
pub(crate) struct MadeLink {
    pub l: Tid,
    pub target: Tid,
    pub single_use: bool,
    /// Its single-use redemption was finalized here.
    pub finalized: bool,
    /// The link text carries this device's dialable key (`LinkOpts.direct`).
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
}

impl Locked {
    pub fn engine(&mut self) -> &mut Engine {
        self.sync.engine_mut()
    }
}

pub(crate) struct Inner {
    pub eng: Mutex<Locked>,
    pub dispatch: Dispatch,
    pub node: Tid,
    pub me: Tid,
    pub limit: usize,
    pub idle_commit: Duration,
    pub wait_timeout: Duration,
    pub clock: Arc<dyn Clock>,
    pub schemas: Mutex<Vec<Arc<Schema>>>,
    /// Serializes undo and redo: candidate selection and commit.
    pub undo: Mutex<()>,
    pub net: Net,
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
    fn users(&self, d: isize) {
        let mut g = lock(&self.m);
        g.0 = g.0.saturating_add_signed(d);
        self.cv.notify_all();
    }
}

/// Marks the store closed when `Inner` drops.
pub(crate) struct LifeGuard(Arc<Life>);

impl Drop for LifeGuard {
    fn drop(&mut self) {
        lock(&self.0.m).1 = true;
        self.0.cv.notify_all();
    }
}

/// A database handle: `Clone + Send + Sync`; clones share one database, which closes with the
/// last handle.
pub struct Osis {
    pub(crate) inner: Arc<Inner>,
    /// Counted in `Life` (an app's handle; internal short-lived ones are not).
    user: bool,
}

impl Clone for Osis {
    /// Always a user handle (a callback may keep a clone of the `&Osis` it is passed).
    fn clone(&self) -> Osis {
        Osis::user(self.inner.clone())
    }
}

impl Drop for Osis {
    fn drop(&mut self) {
        if self.user {
            self.inner.life.0.users(-1);
        }
    }
}

impl std::fmt::Debug for Osis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Osis({})", self.inner.node)
    }
}

/// A non-owning handle (`Osis::downgrade`).
#[derive(Clone, Debug)]
pub struct WeakOsis(pub(crate) std::sync::Weak<Inner>);

impl WeakOsis {
    /// The database, if still open.
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

pub(crate) const PERSON: &str = "person";
pub(crate) const SERVERS: &str = "servers";
pub(crate) const LINKS: &str = "links";

fn parts(cfg: &Config) -> Result<(Box<dyn osis_store::Backend>, Box<dyn osis_store::RootStorage>)> {
    match &cfg.store {
        StoreAt::Memory(m) => Ok((Box::new(m.backend.clone()), Box::new(m.root.clone()))),
        StoreAt::Dir(p) => {
            let mut d = std::fs::DirBuilder::new();
            d.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut d, 0o700);
            d.create(p).map_err(|e| Error::Storage(e.to_string()))?;
            let b = osis_store::RedbBackend::open(&p.join("db.redb")).map_err(|e| Error::Storage(e.to_string()))?;
            Ok((Box::new(b), Box::new(osis_store::FileRoot::new(p.join("root")))))
        }
    }
}

fn rng(cfg: &Config, salt: u64) -> Box<dyn CryptoRngCore + Send> {
    match cfg.seed {
        Some(s) => Box::new(SeededRng::from_u64(s.wrapping_add(salt))),
        None => Box::new(OsRng),
    }
}

fn clock(cfg: &Config) -> Arc<dyn Clock> {
    cfg.clock.clone().unwrap_or_else(|| Arc::new(SystemClock))
}

fn engine_cfg(cfg: &Config) -> osis_node::Config {
    osis_node::Config { software: format!("osis {}", env!("CARGO_PKG_VERSION")), ephemeral_history: cfg.ephemeral_history, ..Default::default() }
}

fn tid_record(e: &mut Engine, name: &str) -> Result<Tid> {
    let b = e.app_record(name)?.ok_or(Error::Storage(format!("no {name} record: not an osis database")))?;
    let a: [u8; osis_base::format::TID_LEN] = b.as_slice().try_into().map_err(|_| Error::Storage(format!("{name} record")))?;
    Ok(Tid::from_bytes(a))
}

/// Server addresses as one local record (text lines).
pub(crate) fn save_servers(e: &mut Engine, s: &[ServerAddr]) -> Result<()> {
    let text: Vec<String> = s.iter().map(|a| a.to_string()).collect();
    e.set_app_record(SERVERS, text.join("\n").as_bytes())?;
    Ok(())
}

fn load_servers(e: &mut Engine) -> Result<Option<Vec<ServerAddr>>> {
    let Some(b) = e.app_record(SERVERS)? else { return Ok(None) };
    let s = String::from_utf8(b).map_err(|_| Error::Storage("servers record".into()))?;
    Ok(Some(s.lines().filter(|l| !l.is_empty()).map(|l| l.parse()).collect::<Result<_>>()?))
}

/// A sync engine over an engine, from the first commit on (it sees every event).
pub(crate) struct Fresh {
    pub sync: SyncEngine,
    pub clock: Arc<dyn Clock>,
}

fn sync_over(engine: Engine, clock: &Arc<dyn Clock>, cfg: &Config, servers: &[ServerAddr]) -> Result<SyncEngine> {
    let scfg = SyncConfig { servers: servers.iter().map(|s| s.0.clone()).collect(), peers: cfg.peers, ..SyncConfig::default() };
    Ok(SyncEngine::new(engine, clock.clone(), rng(cfg, 7), scfg)?)
}

/// A new store's sync engine (its servers set later by `set_servers` where they change).
pub(crate) fn fresh_engine(cfg: &Config, servers: &[ServerAddr]) -> Result<Fresh> {
    let (b, r) = parts(cfg)?;
    let clock = clock(cfg);
    let engine = Engine::create(b, r, engine_cfg(cfg), clock.clone(), rng(cfg, 0))?;
    Ok(Fresh { sync: sync_over(engine, &clock, cfg, servers)?, clock })
}

impl Osis {
    /// Creates a database (notes/api.md, spec/permissions.md §1): a new node and a new person
    /// actor owned by a fresh recovery key, this node its admin, its home group (the person
    /// itself, spec/sync.md §2) labeled on `Config.servers`. Returns the recovery card, the only
    /// copy of the recovery key: show or store it, osis keeps none of it. Without servers there
    /// is nothing to restore from: no card (the key is discarded).
    pub fn create(cfg: Config) -> Result<(Osis, Option<RecoveryCard>)> {
        let Fresh { mut sync, clock } = fresh_engine(&cfg, &cfg.servers)?;
        let engine = sync.engine_mut();
        let servers: Vec<osis_label::Address> = cfg.servers.iter().map(|s| s.0.clone()).collect();
        let (p, done) = engine.create_person(&servers)?;
        let mut m = osis_node::Mutation::new();
        m.set(p.person, &ct::GROUP, &ct::Group::default())?;
        engine.commit(m)?;
        engine.set_app_record(PERSON, p.person.as_bytes())?;
        save_servers(engine, &cfg.servers)?;
        let card = if servers.is_empty() { None } else { Some(RecoveryCard(p.card.to_text().map_err(|e| Error::Invalid(e.to_string()))?)) };
        let db = Osis::start(sync, clock, &cfg, p.person)?;
        db.carry(done)?;
        Ok((db, card))
    }

    /// Opens an existing database.
    pub fn open(cfg: Config) -> Result<Osis> {
        let (b, r) = parts(&cfg)?;
        let clock = clock(&cfg);
        let mut e = Engine::open(b, r, engine_cfg(&cfg), clock.clone(), rng(&cfg, 0))?;
        let me = tid_record(&mut e, PERSON)?;
        let servers = load_servers(&mut e)?.unwrap_or_else(|| cfg.servers.clone());
        let sync = sync_over(e, &clock, &cfg, &servers)?;
        let db = Osis::start(sync, clock, &cfg, me)?;
        db.load_links()?;
        Ok(db)
    }

    pub(crate) fn start(mut sync: SyncEngine, clock: Arc<dyn Clock>, cfg: &Config, me: Tid) -> Result<Osis> {
        // store files open to group or others: tightened where possible (best effort), else
        // reported
        if let StoreAt::Dir(p) = &cfg.store {
            for f in [p.clone(), p.join("db.redb"), p.join("root")] {
                if let Some(why) = osis_store::restrict_to_owner(&f) {
                    sync.engine_mut().report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::Storage, tids: Vec::new(), commit: None, peer: None, detail: why });
                }
            }
        }
        let node = sync.engine().tid();
        let events = sync.engine_mut().subscribe();
        let dispatch = Dispatch::new(&cfg.dispatch);
        let (net, ctl) = Net::new(&cfg.runtime)?;
        let locked = Locked { sync, events, seq: 0, waiters: Vec::new(), status: Status::default(), offers: Vec::new(), links: BTreeMap::new() };
        let inner = Arc::new(Inner { eng: Mutex::new(locked), dispatch, node, me, limit: cfg.materialize_limit, idle_commit: cfg.idle_commit, wait_timeout: cfg.wait_timeout, clock: clock.clone(), schemas: Mutex::new(Vec::new()), undo: Mutex::new(()), net, life: LifeGuard(Arc::default()) });
        inner.dispatch.start(Arc::downgrade(&inner))?;
        if let Some(ctl) = ctl {
            inner.net.spawn_driver(ctl, cfg.transport.clone(), cfg.peers, cfg.relays.clone(), clock, WeakOsis(Arc::downgrade(&inner)))?;
        }
        let db = Osis::user(inner);
        if let Runtime::Manual(m) = &cfg.runtime {
            m.register(db.downgrade());
        }
        db.locked(|_| ());
        Ok(db)
    }

    fn user(inner: Arc<Inner>) -> Osis {
        inner.life.0.users(1);
        Osis { inner, user: true }
    }

    /// A handle for osis's own short-lived use (the dispatcher running callbacks), not counted.
    pub(crate) fn internal(inner: Arc<Inner>) -> Osis {
        Osis { inner, user: false }
    }

    /// A handle that does not keep the database open (for the rare callback that must capture
    /// one; callbacks are passed `&Osis`).
    pub fn downgrade(&self) -> WeakOsis {
        WeakOsis(Arc::downgrade(&self.inner))
    }

    /// Closes this handle. With no other handle left (clones, upgraded `WeakOsis`, value streams,
    /// text sessions, a `Joining`), returns once the database is closed (every commit is already
    /// durable), so the store can be opened again at once; a callback or sync engine call still
    /// running ends first (with `Runtime::Tokio` on a multi-thread runtime, also its sync task, so
    /// the app may shut that runtime down). While other handles keep it open, this one is closed
    /// and it fails `StillOpen` at once. From a callback (the dispatcher, which holds the database
    /// while it runs) it fails `Invalid` at once: drop the handle instead. Never call it while
    /// holding something a running callback may wait for (a lock, a channel it awaits): close
    /// waits for that callback.
    pub fn close(self) -> Result<()> {
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
            return Err(Error::StillOpen { handles: users });
        }
        if let Some(e) = ended {
            // on the app's runtime: the driver ended, so the app may shut its runtime down
            crate::net::wait_ended(&e);
        }
        Ok(())
    }

    /// This device's node tid.
    pub fn node(&self) -> Tid {
        self.inner.node
    }

    /// The person actor this database belongs to: the usual owner of what the app creates.
    pub fn me(&self) -> Tid {
        self.inner.me
    }

    /// The person's home group: the person actor itself, synced under its home label
    /// (spec/sync.md §2); things placed in it reach every device of the person.
    pub fn home(&self) -> Tid {
        self.inner.me
    }

    /// The materialization bound in bytes.
    pub fn materialize_limit(&self) -> usize {
        self.inner.limit
    }

    /// Runs `f` on the engine under the database lock, then queues its events for the
    /// dispatcher (`internals::Internals::engine` outside the crate).
    pub(crate) fn engine<R>(&self, f: impl FnOnce(&mut Engine) -> R) -> R {
        self.locked(|l| f(l.engine()))
    }

    /// Runs `f` on the sync engine as the network driver does: its actions go out, and the
    /// events it caused were already seen by the sync engine.
    pub(crate) fn handled(&self, f: impl FnOnce(&mut Locked) -> Vec<Action>) {
        self.locked_in(true, |l| {
            let acts = f(l);
            self.inner.net.apply(acts);
        })
    }

    pub(crate) fn locked<R>(&self, f: impl FnOnce(&mut Locked) -> R) -> R {
        self.locked_in(false, f)
    }

    fn locked_in<R>(&self, handled: bool, f: impl FnOnce(&mut Locked) -> R) -> R {
        let mut g = lock(&self.inner.eng);
        let holder = &self.inner.dispatch.shared.holder;
        *lock(holder) = Some(std::thread::current().id());
        let r = f(&mut g);
        self.after(&mut g, handled);
        *lock(holder) = None;
        drop(g);
        self.inner.dispatch.wake();
        r
    }

    /// Queues events for the dispatcher, collecting the things whose roster changed into
    /// `roster`; `true` when there were any events other than ephemeral ones (local ephemeral
    /// writes reach the sync engine only when they wait to be sent, `after`).
    fn drain(&self, l: &mut Locked, roster: &mut BTreeSet<Tid>) -> bool {
        let mut any = false;
        while let Ok(e) = l.events.try_recv() {
            any |= !matches!(e, Event::Ephemeral { .. });
            if let Event::Roster { thing } = &e {
                roster.insert(*thing);
            }
            l.seq += 1;
            self.inner.dispatch.send(l.seq, Msg::Event(e));
        }
        any
    }

    /// After every call under the lock: events to the dispatcher; local changes shown to the
    /// sync engine; then status, link upkeep and waiters.
    fn after(&self, l: &mut Locked, handled: bool) {
        let mut roster = BTreeSet::new();
        // ephemeral writes on things in a labeled closure go out as ephemeral commits
        let any = self.drain(l, &mut roster) || l.sync.engine().has_unsent();
        if any && !handled {
            let acts = l.sync.handle(SyncEvent::Local);
            self.inner.net.apply(acts);
            self.drain(l, &mut roster);
        }
        if !(any || handled) {
            // nothing changed, but deadlines may have passed
            if !l.waiters.is_empty() {
                let now = self.inner.clock.now_wall_ms().0;
                let Locked { waiters, sync, status, .. } = l;
                waiters.retain_mut(|w| !w.poll(sync, status, now));
            }
            return;
        }
        self.upkeep_links(l, &roster, false);
        let status = crate::share::status_of(&mut l.sync);
        if status != l.status {
            for (g, s) in &status.groups {
                if s.state == crate::share::SyncState::Stranded && l.status.groups.get(g).is_none_or(|o| o.state != s.state) {
                    l.engine().report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::Stranded, tids: vec![*g], commit: None, peer: None, detail: "stranded: waiting for a re-seal".into() });
                }
            }
            l.status = status.clone();
            l.seq += 1;
            self.inner.dispatch.send(l.seq, Msg::Status(status));
        }
        self.drain(l, &mut roster);
        let now = self.inner.clock.now_wall_ms().0;
        let Locked { waiters, sync, status, .. } = l;
        waiters.retain_mut(|w| !w.poll(sync, status, now));
    }

    /// Runs `f` under the lock and hands the actions it returns to the network, in order.
    pub(crate) fn act(&self, f: impl FnOnce(&mut Locked) -> Vec<Action>) {
        self.locked(|l| {
            let acts = f(l);
            self.inner.net.apply(acts);
        })
    }

    /// `act` for a fallible `f`.
    pub(crate) fn try_act(&self, f: impl FnOnce(&mut Locked) -> Result<Vec<Action>>) -> Result<()> {
        self.locked(|l| {
            let acts = f(l)?;
            self.inner.net.apply(acts);
            Ok(())
        })
    }

    /// Carries out a flow's result (deliveries) under the lock.
    pub(crate) fn carry(&self, done: osis_node::flows::Done) -> Result<()> {
        self.try_act(|l| Ok(l.sync.carry_out(done)?))
    }

    /// Returns once every callback for changes made so far has run: with
    /// `Dispatcher::Thread` it waits for the dispatcher thread (tests and scripts wait this
    /// way without sleeping); with `Dispatcher::Pump` it runs them on this thread, which is
    /// how the app pumps (after its wake callback). Returns at once inside a callback. Never
    /// call it inside an `Osis::read` or `Internals::engine` closure: a callback may need the lock
    /// that closure holds (deadlock).
    pub fn settle(&self) {
        self.inner.dispatch.settle(Arc::downgrade(&self.inner));
    }

    /// Registers a schema: typed views for its AKs (`key`, this session), undo and large-value
    /// write-back (the engine keeps those in the store). Generated keys carry their schema and
    /// need no registration.
    pub fn register_schema(&self, s: Schema) -> Result<Arc<Schema>> {
        let s = Arc::new(s);
        self.engine(|e| e.register_schema(s.clone()))?;
        let mut v = lock(&self.inner.schemas);
        v.retain(|x| x.id != s.id);
        v.push(s.clone());
        Ok(s)
    }

    /// Parses and registers a `*.osis` source (errors carry file:line:col).
    pub fn register_schema_source(&self, file: &str, src: &str) -> Result<Arc<Schema>> {
        let s = osis_schema::parse(file, src).map_err(|e| Error::Invalid(e.to_string()))?;
        self.register_schema(s)
    }

    /// Reads, parses and registers a `*.osis` file.
    pub fn register_schema_file(&self, path: &std::path::Path) -> Result<Arc<Schema>> {
        let src = std::fs::read_to_string(path).map_err(|e| Error::Invalid(format!("{}: {e}", path.display())))?;
        let file = path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
        self.register_schema_source(&file, &src)
    }

    /// The key for `ak`: typed by the registered schema that declares it, else untyped.
    pub fn key(&self, ak: &str) -> Result<crate::Key> {
        let ak = osis_base::Ak::new(ak).map_err(|_| Error::Invalid(format!("bad AK {ak:?}")))?;
        static CORE: std::sync::OnceLock<Arc<Schema>> = std::sync::OnceLock::new();
        let core = CORE.get_or_init(|| Arc::new(osis_schema::core_schema().clone()));
        let schema = if core.aspects.contains_key(ak.as_str()) {
            Some(core.clone())
        } else {
            lock(&self.inner.schemas).iter().find(|s| s.aspects.contains_key(ak.as_str())).cloned()
        };
        Ok(crate::Key { ak, schema })
    }
}
