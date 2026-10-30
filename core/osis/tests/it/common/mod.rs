//! Shared test helpers: deterministic databases, waiting on channels (never on time).
#![allow(dead_code)]

pub mod world;

use osis::internals::Internals as _;
use osis::{Ak, Config, ManualClock, MemStore, Osis, StoreAt, WallMs};
use std::sync::Arc;
use std::sync::mpsc::Receiver;
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
    /// `create` with a durable write (`/t/made`), so the thing is persisted by this batch.
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
        self.at(t, ak("/t/made")).set(&osis::Value::Bool(true))?;
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
