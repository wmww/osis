#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Crashes at every durable write of a node transaction: a local commit that also purges (a
//! shredding transaction: counters, commit record, state, death records, deletion log), then
//! reopen. spec/commits.md §4: a node applies all the parts it may read at once, or none of
//! them; spec/crdt.md §2.3: counters are never reused by anything signed that left the node.

use crate::common;
use common::*;
use osis_commit::PurgeItem;
use osis_core::{Clock, ManualClock, Tid, Value};
use osis_crypto::SeededRng;
use osis_node::{Config, Engine, Mutation};
use osis_store::{Fault, Faults, MemoryBackend, MemoryRoot};
use std::sync::Arc;

struct Dev {
    faults: Faults,
    backend: MemoryBackend,
    root: MemoryRoot,
    clock: Arc<ManualClock>,
}

impl Dev {
    fn new() -> Dev {
        let faults = Faults::new();
        Dev { backend: MemoryBackend::with_faults(faults.clone()), root: MemoryRoot::with_faults(faults.clone()), faults, clock: Arc::new(ManualClock::new(T0)) }
    }
    fn create(&self) -> Engine {
        let c: Arc<dyn Clock> = self.clock.clone();
        Engine::create(Box::new(self.backend.clone()), Box::new(self.root.clone()), Config::default(), c, Box::new(SeededRng::from_u64(9))).unwrap()
    }
    fn open(&self) -> osis_node::Result<Engine> {
        let c: Arc<dyn Clock> = self.clock.clone();
        Engine::open(Box::new(self.backend.clone()), Box::new(self.root.clone()), Config::default(), c, Box::new(SeededRng::from_u64(10)))
    }
}

fn set(e: &mut Engine, t: Tid, v: &str) -> osis_core::CommitId {
    let mut m = Mutation::new();
    m.set(t, &REG, &s(v)).unwrap();
    e.commit(m).unwrap().unwrap()
}

/// The state before the transaction under test: a thing with a secret write to purge.
fn setup(dev: &Dev) -> (Engine, Tid, osis_core::CommitId) {
    let mut e = dev.create();
    let mut m = Mutation::new();
    let me = e.tid();
    let t = e.new_thing(&mut m, me);
    m.set(t, &REG, &s("one")).unwrap();
    e.commit(m).unwrap();
    dev.clock.advance(5);
    let secret = set(&mut e, t, "secret");
    dev.clock.advance(5);
    (e, t, secret)
}

fn purge(t: Tid, secret: osis_core::CommitId) -> Mutation {
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("/t/reg") });
    m
}

// spec/commits.md §4 (all or none), §5 (purge), spec/crdt.md §2.3 (counters): a crash at any
// write of a purging commit leaves the node, reopened, at the state before or after it, never
// between; it then commits on, and a commit that did land keeps its counters
#[test]
fn crash_every_write_of_a_purging_commit() {
    let reg = ak("/t/reg");
    for n in 0.. {
        let dev = Dev::new();
        let (mut e, t, secret) = setup(&dev);
        let before = e.commit_ids().len();
        dev.faults.at(n, Fault::Crash);
        let r = e.commit(purge(t, secret));
        let crashed = dev.faults.crashed();
        assert_eq!(r.is_err(), crashed, "write {n}");
        drop(e);
        dev.faults.revive();
        // a crash during recovery as well
        dev.faults.at(0, Fault::Crash);
        drop(dev.open());
        dev.faults.revive();
        let mut e = dev.open().unwrap();
        let v = e.get(&t, &reg).unwrap();
        let landed = v == Some(s("public"));
        assert!(landed || v == Some(s("secret")), "torn state after a crash at write {n}: {v:?}");
        assert_eq!(e.holds_body(&secret, &t, &reg), !landed, "write {n}");
        assert_eq!(e.commit_ids().len(), before + usize::from(landed), "write {n}");
        if !crashed {
            assert!(landed);
            assert!(n >= 3, "a shredding commit is at least batch, root, cleanup: {n}");
            return;
        }
        // The node works on; a landed commit's counters are not handed out again.
        dev.clock.advance(5);
        let later = set(&mut e, t, "later");
        let h = e.header(&later).unwrap();
        let ids: Vec<_> = e.commit_ids();
        for id in ids.iter().filter(|c| **c != later) {
            let o = e.header(id).unwrap();
            if o.author == h.author {
                for a in &o.aspects {
                    for b in h.aspects.iter().filter(|b| b.tid == a.tid && b.ak == a.ak && b.lo < b.hi && a.lo < a.hi) {
                        assert!(a.lo >= b.hi || b.lo >= a.hi, "counters reused after a crash at write {n}");
                    }
                }
            }
        }
        drop(e);
        let mut e = dev.open().unwrap();
        assert_eq!(e.get(&t, &reg).unwrap(), Some(Value::Str("later".into())));
    }
}
