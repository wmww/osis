#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Crashes at every durable write of a node transaction: a local commit that also purges (a
//! shredding transaction: counters, commit record, state, death records, deletion log), then
//! reopen. spec/commits.md §4: a node applies all the parts it may read at once, or none of
//! them; spec/crdt.md §2.3: counters are never reused by anything signed that left the node.

use crate::common;
use common::*;
use osis_commit::PurgeItem;
use osis_base::{Clock, ManualClock, Tid, Value};
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

fn set(e: &mut Engine, t: Tid, v: &str) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.set(t, &REG, &s(v)).unwrap();
    e.commit(m).unwrap().unwrap()
}

/// The state before the transaction under test: a thing with a secret write to purge.
fn setup(dev: &Dev) -> (Engine, Tid, osis_base::CommitId) {
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

fn purge(t: Tid, secret: osis_base::CommitId) -> Mutation {
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("t:reg.0") });
    m
}

// spec/commits.md §4 (all or none), §5 (purge), spec/crdt.md §2.3 (counters): a crash at any
// write of a purging commit leaves the node, reopened, at the state before or after it, never
// between; it then commits on, and a commit that did land keeps its counters
#[test]
fn crash_every_write_of_a_purging_commit() {
    let reg = ak("t:reg.0");
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
        assert_eq!(e.body_not_dropped(&secret, &t, &reg), !landed, "write {n}");
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

// spec/crdt.md §2.1: a store restored from a backup that receives only a valid snapshot of the
// commits it lost (their bodies dropped after compaction) takes its counter from the
// snapshot's frontier for its own node: its next commit overlaps none of them, and when they
// arrive after all, nothing is void (spec/commits.md §4).
#[test]
fn restored_counter_from_snapshot_frontier_spec_crdt_2_1() {
    let dev = Dev::new();
    let mut e = dev.create();
    let mut m = Mutation::new();
    let me = e.tid();
    let t = e.new_thing(&mut m, me);
    m.set(t, &REG, &s("one")).unwrap();
    e.commit(m).unwrap();
    let backup = (dev.backend.copy(), dev.root.copy());
    let lost: Vec<osis_base::CommitId> = (0..3)
        .map(|i| {
            dev.clock.advance(5);
            set(&mut e, t, &format!("lost {i}"))
        })
        .collect();
    let ak = osis_base::Ak::new(osis_schema::AspectKey::ak(&REG)).unwrap();
    let snap = e.compaction_snapshot(&t, &ak).unwrap().expect("a snapshot");
    let packages: Vec<_> = std::iter::once(snap).chain(lost.iter().copied()).map(|c| e.package(&c).unwrap().unwrap()).collect();
    let last_hi = lost.iter().map(|c| e.header(c).unwrap().aspects.iter().find(|a| a.ak == ak).unwrap().hi).max().unwrap();
    drop(e);

    let c: Arc<dyn Clock> = dev.clock.clone();
    let mut r = Engine::open(Box::new(backup.0), Box::new(backup.1), Config::default(), c, Box::new(SeededRng::from_u64(11))).unwrap();
    let [sp, rest @ ..] = packages.as_slice() else { unreachable!() };
    r.ingest(&sp.bytes, sp.blobs.clone()).unwrap();
    dev.clock.advance(5);
    let mine = set(&mut r, t, "restored");
    let lo = r.header(&mine).unwrap().aspects.iter().find(|a| a.ak == ak).unwrap().lo;
    assert!(lo >= last_hi, "the restored node's counter {lo} is past the lost commits' {last_hi}");
    for p in rest {
        r.ingest(&p.bytes, p.blobs.clone()).unwrap();
    }
    assert!(r.core.ix.void.is_empty(), "void: {:?}", r.core.ix.void.iter().collect::<Vec<_>>());
    assert_eq!(r.get_typed(&t, &REG).unwrap(), Some(s("restored")));
}
