//! osis-chat's shared rules at the osis API (notes/chat.md, The osis-chat crate): creation, the
//! edit model, reading by arrival, holding. Nodes in memory on one manual clock; commits travel
//! between them by hand (`deliver`) where no sync is needed for what is checked, else over an
//! in-process test network (`ManualNet`, `drive`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod chat;

use osis::internals::{Internals as _, ManualClock, ManualNet};
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

/// A fresh node `seed` on `net`, at `c`.
pub fn on(net: &ManualNet, seed: u64, c: &Arc<ManualClock>) -> Osis {
    let mut o = osis::internals::Opening::at(Store::Memory(MemStore::new()));
    o.app.internals.seed = Some(seed);
    o.app.internals.clock = Some(c.clone());
    o.app.internals.net = Some(net.clone());
    osis::internals::create(o).unwrap()
}

/// Two paired nodes of one account on `net`, the second dialing the first (listening).
pub fn paired(net: &ManualNet, c: &Arc<ManualClock>, seed: u64) -> (Osis, Osis) {
    let a = on(net, seed, c);
    let addr = a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap().remove(0);
    let mut o = osis::internals::Opening::at(Store::Memory(MemStore::new()));
    o.app.internals.seed = Some(seed + 1);
    o.app.internals.clock = Some(c.clone());
    o.app.internals.net = Some(net.clone());
    o.cfg.dial = vec![addr];
    let join = osis::internals::pair(o, &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(join.request()).unwrap();
    (a, join.finish(&reply).unwrap())
}

/// Runs `f` to its end, running `net` between polls.
pub fn drive<T>(net: &ManualNet, f: impl std::future::Future<Output = T>) -> T {
    let mut f = std::pin::pin!(f);
    for _ in 0..20 {
        if let std::task::Poll::Ready(r) = f.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop())) {
            return r;
        }
        net.run();
    }
    panic!("did not resolve");
}

/// Delivers every commit `from` holds to `to`, `to`'s account keeping `from`'s (a strong in its
/// account root's `holds.0`: spec/commits.md §5 What a held thing needs).
pub fn deliver(from: &Osis, to: &Osis) {
    let (root, who) = (to.account_root(), from.me());
    if who != to.me() && !to.engine(|e| e.references_from(&root).unwrap().iter().any(|r| r.target == who && r.kind == osis::RefKind::Strong && r.ak.as_str() == "holds.0")) {
        let mut w = to.write();
        w.at(root, osis::core::HOLDS).path(osis::p![]).add(&osis::Ref::Strong(osis::Strong(who))).unwrap();
        w.commit().unwrap();
    }
    let pks = from.engine(|e| e.commit_ids().iter().filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        to.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
    }
}

/// How many commits `db` holds.
pub fn commits(db: &Osis) -> usize {
    db.engine(|e| e.commit_ids().len())
}
