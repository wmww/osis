//! osis-chat's shared rules at the osis API (notes/chat.md, The osis-chat crate): creation, the
//! edit model, reading by arrival. Nodes in memory on one manual clock; commits travel between
//! them by hand (`deliver`), as no sync is needed for what is checked here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod chat;

use osis::internals::{Internals as _, ManualClock};
use osis::{MemStore, Osis, Store, Time};
use std::sync::Arc;

pub const T0: u64 = 1_700_000_000_000;

pub fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(Time(T0)))
}

/// A fresh node `seed` on clock `c`.
pub fn node(seed: u64, c: &Arc<ManualClock>) -> Osis {
    let mut o = osis::internals::Opening::at(Store::Memory(MemStore::new()));
    o.app.internals.seed = Some(seed);
    o.app.internals.clock = Some(c.clone());
    osis::internals::create(o).unwrap()
}

/// Delivers every commit `from` holds to `to`.
pub fn deliver(from: &Osis, to: &Osis) {
    let pks = from.engine(|e| e.commit_ids().iter().filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        to.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
    }
}

/// How many commits `db` holds.
pub fn commits(db: &Osis) -> usize {
    db.engine(|e| e.commit_ids().len())
}
