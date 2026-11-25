//! osis-account at the osis API: making an account, pairing and removing a node, contact cards, realms.
//! Nodes in memory on one manual clock, over an in-process test network (`ManualNet`, `drive`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod account;

use osis::internals::{ManualClock, ManualNet, Opening};
use osis::{MemStore, Osis, Store, Time};
use osis_account::Account;
use std::sync::Arc;

pub const T0: u64 = 1_700_000_000_000;

pub fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(Time(T0)))
}

/// A fresh store's opening, seeded `seed`, on `net` at `c`, dialing `dial`.
pub fn opening(net: &ManualNet, seed: u64, c: &Arc<ManualClock>, dial: Vec<osis::Address>) -> Opening {
    let mut o = Opening::at(Store::Memory(MemStore::new()));
    o.app.internals.seed = Some(seed);
    o.app.internals.clock = Some(c.clone());
    o.app.internals.net = Some(net.clone());
    o.cfg.dial = dial;
    o
}

/// A fresh node `seed` on `net` with an account of its own, listening at the address returned.
pub fn person(net: &ManualNet, seed: u64, c: &Arc<ManualClock>) -> (Osis, Account, osis::Address) {
    let db = osis::internals::create(opening(net, seed, c, Vec::new())).unwrap();
    let a = Account::make(&db).unwrap();
    let addr = db.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap().remove(0);
    (db, a, addr)
}

/// A new node `seed` paired into `a`'s account at `db`, configured to dial nothing: it reaches
/// `db` as the offer says; synced.
pub fn pair(net: &ManualNet, (db, a, _): &(Osis, Account, osis::Address), seed: u64, c: &Arc<ManualClock>) -> Osis {
    let o = opening(net, seed, c, Vec::new());
    let offering = a.offer_pairing(db).unwrap();
    let join = osis_account::pair(o.store, offering.offer(), o.cfg).unwrap();
    let (node, reply) = offering.accept(db, join.request()).unwrap();
    let (b, got) = join.finish(&reply).unwrap();
    assert_eq!((got, node), (*a, b.node()));
    drive(net, b.wait_synced(osis::SyncScope::All)).unwrap();
    b
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
