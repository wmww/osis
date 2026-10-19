//! The handle (notes/api.md Handle and lifecycle): `Osis` over one node engine behind one lock;
//! every engine call drains the engine's events into the dispatcher queue before the lock is
//! released, so the queue is in commit order.

use crate::error::{Error, Result};
use crate::watch::{Dispatch, Msg, lock};
use osis_core::{Clock, SystemClock, Tid};
use osis_crypto::{CryptoRngCore, OsRng, SeededRng};
use osis_node::{Engine, Event};
use osis_schema::Schema;
use osis_store::{MemoryBackend, MemoryRoot};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

/// Default materialization bound: 64 MiB (notes/api.md Reads).
pub const DEFAULT_LIMIT: usize = 64 << 20;

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
    /// A directory (feature `file-store`): `db.redb` and the key root `root`.
    #[cfg(feature = "file-store")]
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
}

impl Config {
    /// A fresh in-memory store.
    pub fn memory() -> Config {
        Config::at(StoreAt::Memory(MemStore::new()))
    }

    pub fn at(store: StoreAt) -> Config {
        Config { store, materialize_limit: DEFAULT_LIMIT, clock: None, seed: None }
    }

    #[cfg(feature = "file-store")]
    pub fn dir(path: impl Into<std::path::PathBuf>) -> Config {
        Config::at(StoreAt::Dir(path.into()))
    }
}

/// The engine with its event channel and the dispatcher sequence number.
pub(crate) struct Locked {
    pub engine: Engine,
    events: Receiver<Event>,
    pub seq: u64,
}

pub(crate) struct Inner {
    pub eng: Mutex<Locked>,
    pub dispatch: Dispatch,
    pub node: Tid,
    pub me: Tid,
    pub home: Tid,
    pub limit: usize,
    pub schemas: Mutex<Vec<Arc<Schema>>>,
}

/// A database handle: `Clone + Send + Sync`; clones share one database, which closes with the
/// last handle.
#[derive(Clone)]
pub struct Osis {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for Osis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Osis({})", self.inner.node)
    }
}

const PERSON: &str = "person";
const HOME: &str = "home";

fn parts(cfg: &Config) -> Result<(Box<dyn osis_store::Backend>, Box<dyn osis_store::RootStorage>)> {
    match &cfg.store {
        StoreAt::Memory(m) => Ok((Box::new(m.backend.clone()), Box::new(m.root.clone()))),
        #[cfg(feature = "file-store")]
        StoreAt::Dir(p) => {
            std::fs::create_dir_all(p).map_err(|e| Error::Storage(e.to_string()))?;
            let b = osis_store::RedbBackend::open(&p.join("db.redb")).map_err(|e| Error::Storage(e.to_string()))?;
            Ok((Box::new(b), Box::new(osis_store::FileRoot::new(p.join("root")))))
        }
    }
}

fn rng(cfg: &Config) -> Box<dyn CryptoRngCore + Send> {
    match cfg.seed {
        Some(s) => Box::new(SeededRng::from_u64(s)),
        None => Box::new(OsRng),
    }
}

fn clock(cfg: &Config) -> Arc<dyn Clock> {
    cfg.clock.clone().unwrap_or_else(|| Arc::new(SystemClock))
}

fn engine_cfg() -> osis_node::Config {
    osis_node::Config { software: format!("osis {}", env!("CARGO_PKG_VERSION")), ..Default::default() }
}

fn tid_record(e: &mut Engine, name: &str) -> Result<Tid> {
    let b = e.app_record(name)?.ok_or(Error::Storage(format!("no {name} record: not an osis database")))?;
    let a: [u8; osis_core::format::TID_LEN] = b.as_slice().try_into().map_err(|_| Error::Storage(format!("{name} record")))?;
    Ok(Tid::from_bytes(a))
}

impl Osis {
    /// Creates a database: a new node, a person actor and its home group (notes/api.md).
    /// Until membership flows land, the person actor is owned by this node and no recovery
    /// card is produced (plans/api.md second half).
    pub fn create(cfg: Config) -> Result<Osis> {
        let (b, r) = parts(&cfg)?;
        let mut e = Engine::create(b, r, engine_cfg(), clock(&cfg), rng(&cfg))?;
        let node = e.tid();
        let mut m = osis_node::Mutation::new();
        let me = e.new_thing(&mut m, node);
        e.commit(m)?;
        // the person must exist before this node's rights through it count
        let mut m = osis_node::Mutation::new();
        let home = e.new_thing(&mut m, me);
        m.set(home, &osis_schema::core_types::GROUP, &osis_schema::core_types::Group::default())?;
        e.commit(m)?;
        e.set_app_record(PERSON, me.as_bytes())?;
        e.set_app_record(HOME, home.as_bytes())?;
        Osis::start(e, me, home, cfg.materialize_limit)
    }

    /// Opens an existing database.
    pub fn open(cfg: Config) -> Result<Osis> {
        let (b, r) = parts(&cfg)?;
        let mut e = Engine::open(b, r, engine_cfg(), clock(&cfg), rng(&cfg))?;
        let me = tid_record(&mut e, PERSON)?;
        let home = tid_record(&mut e, HOME)?;
        Osis::start(e, me, home, cfg.materialize_limit)
    }

    fn start(mut engine: Engine, me: Tid, home: Tid, limit: usize) -> Result<Osis> {
        let node = engine.tid();
        let events = engine.subscribe();
        let (dispatch, queue) = Dispatch::new();
        let inner = Arc::new(Inner { eng: Mutex::new(Locked { engine, events, seq: 0 }), dispatch, node, me, home, limit, schemas: Mutex::new(Vec::new()) });
        inner.dispatch.spawn(queue, Arc::downgrade(&inner))?;
        Ok(Osis { inner })
    }

    pub(crate) fn from_inner(inner: Arc<Inner>) -> Osis {
        Osis { inner }
    }

    /// Closes this handle (the database closes with the last one; every commit is already
    /// durable).
    pub fn close(self) {}

    /// This device's node tid.
    pub fn node(&self) -> Tid {
        self.inner.node
    }

    /// The person actor this database belongs to: the usual owner of what the app creates.
    pub fn me(&self) -> Tid {
        self.inner.me
    }

    /// The person's home group.
    pub fn home(&self) -> Tid {
        self.inner.home
    }

    /// The materialization bound in bytes.
    pub fn materialize_limit(&self) -> usize {
        self.inner.limit
    }

    /// Runs `f` on the engine under the database lock, then queues its events for the
    /// dispatcher. For inspection (the CLI's `inspect`) and tests; apps never need it.
    pub fn engine<R>(&self, f: impl FnOnce(&mut Engine) -> R) -> R {
        self.locked(|l| f(&mut l.engine))
    }

    pub(crate) fn locked<R>(&self, f: impl FnOnce(&mut Locked) -> R) -> R {
        let mut g = lock(&self.inner.eng);
        let r = f(&mut g);
        let l = &mut *g;
        for e in l.events.try_iter() {
            l.seq += 1;
            self.inner.dispatch.send(l.seq, Msg::Event(e));
        }
        r
    }

    /// Blocks until every callback for changes made so far has run (returns at once on the
    /// dispatcher thread). Tests and scripts use it to wait without sleeping.
    pub fn settle(&self) {
        self.inner.dispatch.settle();
    }

    /// Registers a schema: typed views for its AKs (`key`), undo and snapshot defaults.
    /// Generated keys carry their schema and need no registration.
    pub fn register_schema(&self, s: Schema) -> Arc<Schema> {
        let s = Arc::new(s);
        self.engine(|e| e.register_schema(s.clone()));
        let mut v = lock(&self.inner.schemas);
        v.retain(|x| x.id != s.id);
        v.push(s.clone());
        s
    }

    /// Parses and registers a `*.osis` source (errors carry file:line:col).
    pub fn register_schema_source(&self, file: &str, src: &str) -> Result<Arc<Schema>> {
        let s = osis_schema::parse(file, src).map_err(|e| Error::Invalid(e.to_string()))?;
        Ok(self.register_schema(s))
    }

    /// Reads, parses and registers a `*.osis` file.
    pub fn register_schema_file(&self, path: &std::path::Path) -> Result<Arc<Schema>> {
        let src = std::fs::read_to_string(path).map_err(|e| Error::Invalid(format!("{}: {e}", path.display())))?;
        let file = path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
        self.register_schema_source(&file, &src)
    }

    /// The key for `ak`: typed by the registered schema that declares it, else untyped.
    pub fn key(&self, ak: &str) -> Result<crate::Key> {
        let ak = osis_core::Ak::new(ak).map_err(|_| Error::Invalid(format!("bad AK {ak:?}")))?;
        let core = osis_schema::core_schema();
        let schema = if core.aspects.contains_key(ak.as_str()) {
            Some(Arc::new(core.clone()))
        } else {
            lock(&self.inner.schemas).iter().find(|s| s.aspects.contains_key(ak.as_str())).cloned()
        };
        Ok(crate::Key { ak, schema })
    }
}
