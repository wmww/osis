//! Shared test helpers: deterministic databases, waiting on channels (never on time).
#![allow(dead_code)]


use osis::internals::Internals as _;
use osis::schema::core_types as ct;
use osis::{Ak, AspectKey, Config, LinkInfo, ManualClock, MemStore, Osis, Result, StoreAt, Subscription, Tid, WallMs, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

pub const T0: u64 = 1_700_000_000_000;

pub fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(WallMs(T0)))
}

pub fn cfg(seed: u64, store: MemStore, clock: &Arc<ManualClock>) -> Config {
    let mut c = Config::at(StoreAt::Memory(store));
    c.seed = Some(seed);
    c.clock = Some(clock.clone());
    c
}

/// A fresh database at `T0`.
pub fn db(seed: u64) -> Osis {
    Osis::create(cfg(seed, MemStore::new(), &clock())).unwrap().0
}

pub fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

/// Shorthands for tests whose point is what a write does, not how it is spelled.
pub trait TestWrites {
    /// `write()`, `f`, `commit()`: for a batch whose outcome the test inspects as one `Result`.
    fn batch<R>(&self, f: impl FnOnce(&mut Write<'_>) -> Result<R>) -> Result<R>;
    /// A batch of one `at(t, key).set(v)`.
    fn commit_set<K: AspectKey>(&self, t: Tid, key: K, v: &K::T) -> Result<()>;
    /// `required.0^`'s `keep`, its other rules as they are.
    fn set_keep_default(&self, t: Tid, keep: bool) -> Result<()>;
    /// The links to `t`.
    fn links_of(&self, t: Tid) -> Result<Vec<LinkInfo>>;
}

impl TestWrites for Osis {
    fn batch<R>(&self, f: impl FnOnce(&mut Write<'_>) -> Result<R>) -> Result<R> {
        let mut w = self.write();
        let r = f(&mut w)?;
        w.commit()?;
        Ok(r)
    }
    fn commit_set<K: AspectKey>(&self, t: Tid, key: K, v: &K::T) -> Result<()> {
        self.batch(|w| w.at(t, key).set(v))
    }
    fn set_keep_default(&self, t: Tid, keep: bool) -> Result<()> {
        let rules = self.at(t, ct::REQUIRED).get()?.unwrap_or_default();
        self.commit_set(t, ct::REQUIRED, &ct::RequiredRules { keep, ..rules })
    }
    fn links_of(&self, t: Tid) -> Result<Vec<LinkInfo>> {
        Ok(self.links()?.into_iter().filter(|l| l.target == t).collect())
    }
}

/// The latest value of an aspect, from `on_change`: the value at registration before this returns,
/// no later change missed. Unsubscribes when dropped.
pub struct Watched<T> {
    state: Arc<(Mutex<Latest<T>>, Condvar)>,
    seen: AtomicU64,
    _sub: Subscription,
}

struct Latest<T> {
    value: Option<Result<Option<T>>>,
    /// Changes after the first value.
    version: u64,
}

pub fn watched<K>(db: &Osis, t: Tid, key: K) -> Result<Watched<K::T>>
where
    K: AspectKey + Clone + Send + 'static,
    K::T: PartialEq + Clone + Send + 'static,
{
    let state = Arc::new((Mutex::new(Latest { value: None, version: 0 }), Condvar::new()));
    let st = state.clone();
    let sub = db.at(t, key).on_change(move |_, c| {
        let mut l = st.0.lock().unwrap();
        // what a repeated value (a reconnect's first value) leaves unchanged counts for nothing
        if c.value.is_err() || l.value.as_ref() != Some(&c.value) {
            if l.value.is_some() {
                l.version += 1;
            }
            l.value = Some(c.value);
            st.1.notify_all();
        }
    })?;
    db.settle();
    let w = Watched { state, seen: AtomicU64::new(0), _sub: sub };
    let (mut l, cv) = (w.state.0.lock().unwrap(), &w.state.1);
    while l.value.is_none() {
        let (g, out) = cv.wait_timeout(l, Duration::from_secs(20)).unwrap();
        l = g;
        assert!(!out.timed_out(), "no first value");
    }
    drop(l);
    Ok(w)
}

impl<T: Clone> Watched<T> {
    /// The latest value (`None`: absent).
    pub fn current(&self) -> Result<Option<T>> {
        self.state.0.lock().unwrap().value.clone().unwrap_or(Ok(None))
    }

    /// Whether the value changed since the last `changed*` call returned; marks it seen.
    pub fn try_changed(&self) -> bool {
        let v = self.state.0.lock().unwrap().version;
        self.seen.swap(v, Ordering::AcqRel) < v
    }

    /// Blocks until the value changes or `d` passes; `true` if it changed.
    pub fn changed_timeout(&self, d: Duration) -> bool {
        let end = std::time::Instant::now() + d;
        let mut l = self.state.0.lock().unwrap();
        loop {
            if l.version > self.seen.load(Ordering::Acquire) {
                self.seen.store(l.version, Ordering::Release);
                return true;
            }
            let left = end.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            l = self.state.1.wait_timeout(l, left).unwrap().0;
        }
    }
}

/// Waits for the next message; a missing callback fails the test instead of hanging.
pub fn recv<T>(rx: &Receiver<T>) -> T {
    rx.recv_timeout(Duration::from_secs(20)).expect("callback did not run")
}

/// Delivers every commit `from` holds to `to` (the engine-level path `LocalPeer` uses).
pub fn deliver(from: &Osis, to: &Osis) {
    let pks = from.engine(|e| {
        let ids = e.commit_ids();
        ids.iter().filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>()
    });
    for pk in pks {
        to.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
    }
}

/// Runs a future to completion on this thread (no runtime: the API's futures are resolved by
/// the database, notes/api.md Design rules).
pub fn block_on<F: std::future::Future>(f: F) -> F::Output {
    struct Unpark(std::thread::Thread);
    impl std::task::Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    let mut f = std::pin::pin!(f);
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::park_timeout(Duration::from_millis(50));
    }
}

/// Commits the ops `f` makes in one batch; the commit.
pub fn commit_with(db: &Osis, f: impl FnOnce(&mut osis::Write<'_>) -> osis::Result<()>) -> osis::Committed {
    let mut w = db.write();
    f(&mut w).unwrap();
    w.commit().unwrap().unwrap()
}

/// `create` and `place` into `groups` in one batch.
pub trait CreateIn {
    fn create_in(&mut self, owner: osis::Tid, groups: &[osis::Tid]) -> osis::Result<osis::Tid>;
    /// `create` with a durable write (`t:made.0`), so the thing is persisted by this batch.
    fn create_durable(&mut self, owner: osis::Tid) -> osis::Result<osis::Tid>;
}

impl CreateIn for osis::Write<'_> {
    fn create_in(&mut self, owner: osis::Tid, groups: &[osis::Tid]) -> osis::Result<osis::Tid> {
        let t = self.create(owner)?;
        for g in groups {
            self.place(t, *g)?;
        }
        Ok(t)
    }
    fn create_durable(&mut self, owner: osis::Tid) -> osis::Result<osis::Tid> {
        let t = self.create(owner)?;
        self.at(t, ak("t:made.0")).set(&osis::Value::Bool(true))?;
        Ok(t)
    }
}

/// `create` and `place_expiring` into `g` in one batch.
pub trait CreateExpiringIn {
    fn create_expiring_in(&mut self, owner: osis::Tid, g: osis::Tid, d: Option<std::time::Duration>) -> osis::Result<osis::Tid>;
}

impl CreateExpiringIn for osis::Write<'_> {
    fn create_expiring_in(&mut self, owner: osis::Tid, g: osis::Tid, d: Option<std::time::Duration>) -> osis::Result<osis::Tid> {
        let t = self.create(owner)?;
        self.place_expiring(t, g, d)?;
        Ok(t)
    }
}
