//! Shared test helpers: deterministic databases, waiting on channels (never on time).
#![allow(dead_code)]

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
    Osis::create(cfg(seed, MemStore::new(), &clock())).unwrap()
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
