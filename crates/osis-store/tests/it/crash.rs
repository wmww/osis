#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Crash safety: a crash at any durable write of a transaction (or of the recovery after it)
//! leaves the store as before or as after, never between; a shredding transaction counts as
//! committed exactly when its new root record is durable (spec/commits.md §4: one storage
//! transaction per atomic apply; notes/local-store.md, Key tree: crash safety).

use crate::common;

use common::*;
use osis_crypto::SeededRng;
use osis_store::{Error, Fault, MemoryRoot, RootStorage, Shred, Store, StoreConfig, Transaction};
use proptest::prelude::*;
use std::collections::BTreeMap;

type State = (Vec<(Vec<u8>, Vec<u8>)>, Vec<(Vec<u8>, Vec<u8>)>);

fn crash_cfg() -> StoreConfig {
    StoreConfig { spill_bytes: 3000, ..cfg() }
}

fn snapshot(s: &mut Store) -> State {
    let mut rng = SeededRng::from_u64(99);
    let mut t = s.transaction(&mut rng).unwrap();
    let locals = t.scan_local(b"", b"", usize::MAX).unwrap();
    let table = match t.table(&tid(1), &ak("/t"), 0).unwrap() {
        Some(tb) => t.table_range(tb, b"", None, usize::MAX).unwrap(),
        None => Vec::new(),
    };
    (locals, table)
}

fn setup(s: &mut Store, rng: &mut SeededRng) {
    let mut t = s.transaction(rng).unwrap();
    for i in 0..30u8 {
        t.put_local(&[b'k', i], &[i; 20], Shred::No).unwrap();
    }
    let tb = t.create_table(&tid(1), &ak("/t"), 0).unwrap();
    for i in 0..200u32 {
        t.table_put(tb, &i.to_be_bytes(), vec![1; 24], Shred::No).unwrap();
    }
    t.commit().unwrap();
}

/// Transaction shapes: 0 plain, 1 shredding, 2 large (spills) and shredding.
fn scenario(t: &mut Transaction, kind: u8) -> Result<(), Error> {
    let tb = t.table(&tid(1), &ak("/t"), 0)?.unwrap();
    let shred = if kind == 0 { Shred::No } else { Shred::Yes };
    for i in 0..10u8 {
        t.put_local(&[b'k', i], b"changed", shred)?;
    }
    t.remove_local(&[b'k', 20], shred)?;
    t.put_local(b"new", b"value", Shred::No)?;
    for i in (0..200u32).step_by(7) {
        t.table_remove(tb, &i.to_be_bytes(), shred)?;
    }
    if kind == 2 {
        for i in 1000..1300u32 {
            t.table_put(tb, &i.to_be_bytes(), vec![2; 24], Shred::No)?;
        }
    }
    Ok(())
}

fn no_leftovers(s: &Store) {
    assert!(s.backend().scan_prefix(b"j", 10).unwrap().is_empty(), "journal left");
    assert!(s.backend().get(b"p").unwrap().is_none(), "pending pointer left");
}

fn crash_every_write(dev_name: &str, kind: u8) {
    // Reference run without faults.
    let reference = MemDevice::new();
    let mut rng = SeededRng::from_u64(1);
    let mut s = Store::create(reference.backend(), reference.root(), crash_cfg(), &mut rng).unwrap();
    setup(&mut s, &mut rng);
    let before = snapshot(&mut s);
    let mut t = s.transaction(&mut rng).unwrap();
    scenario(&mut t, kind).unwrap();
    t.commit().unwrap();
    let after = snapshot(&mut s);
    assert_ne!(before, after);

    let mut crashed_after_root = false;
    for n in 0.. {
        let dev = devices(&format!("crash-{kind}-{n}")).into_iter().find(|d| d.name() == dev_name).unwrap();
        let mut rng = SeededRng::from_u64(1);
        let mut s = Store::create(dev.backend(), dev.root(), crash_cfg(), &mut rng).unwrap();
        setup(&mut s, &mut rng);
        let epoch = dev.root().load().unwrap().unwrap().epoch;
        dev.faults().at(n, Fault::Crash);
        let mut t = s.transaction(&mut rng).unwrap();
        let result = match scenario(&mut t, kind) {
            Ok(()) => t.commit(),
            Err(e) => Err(e),
        };
        let crashed = dev.faults().crashed();
        assert_eq!(result.is_err(), crashed, "write {n}");
        drop(s);
        dev.faults().revive();
        let rooted = dev.root().load().unwrap().unwrap().epoch > epoch;
        // A crash during recovery too, when recovery has work.
        dev.faults().at(0, Fault::Crash);
        let s = Store::open(dev.backend(), dev.root(), crash_cfg());
        dev.faults().revive();
        drop(s);
        let mut s = Store::open(dev.backend(), dev.root(), crash_cfg()).unwrap();
        no_leftovers(&s);
        let state = snapshot(&mut s);
        if !crashed {
            assert_eq!(state, after);
            // Writes: plain 1; shredding 3 (batch, root, cleanup); spilling more.
            assert!(n >= [1, 3, 4][usize::from(kind)], "{dev_name} kind {kind}: {n} writes");
            assert_eq!(crashed_after_root, kind > 0, "{dev_name} kind {kind}: a crash after the root write");
            return;
        }
        assert!(state == before || state == after, "{dev_name} kind {kind}: torn state after crash at write {n}");
        crashed_after_root |= rooted;
        if kind > 0 {
            assert_eq!(state == after, rooted, "kind {kind}: committed exactly when the new root is durable (crash at {n})");
        }
        // The store works on.
        let mut t = s.transaction(&mut rng).unwrap();
        t.put_local(b"later", b"x", Shred::Yes).unwrap();
        t.commit().unwrap();
        drop(s);
        let mut s = reopen_cfg(&*dev);
        assert_eq!(snapshot(&mut s).0.iter().find(|(k, _)| k == b"later").map(|(_, v)| v.clone()), Some(b"x".to_vec()));
    }
}

fn reopen_cfg(dev: &dyn Device) -> Store {
    Store::open(dev.backend(), dev.root(), crash_cfg()).unwrap()
}

// spec/commits.md §4: all or nothing at every crash point.
#[test]
fn crash_plain_transaction() {
    for d in devices("names-plain") {
        crash_every_write(d.name(), 0);
    }
}

// notes/local-store.md, Key tree: deletion counts only after the root replacement is durable.
#[test]
fn crash_shredding_transaction() {
    for d in devices("names-shred") {
        crash_every_write(d.name(), 1);
    }
}

// spec/crdt.md §8: a commit has no size limit; a large transaction spills and stays atomic.
#[test]
fn crash_spilling_transaction() {
    for d in devices("names-spill") {
        crash_every_write(d.name(), 2);
    }
}

#[derive(Clone, Debug)]
enum Op {
    Put(u8, u8, bool),
    Remove(u8, bool),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![(0u8..40, any::<u8>(), any::<bool>()).prop_map(|(k, v, s)| Op::Put(k, v, s)), (0u8..40, any::<bool>()).prop_map(|(k, s)| Op::Remove(k, s))]
}

fn shred(b: bool) -> Shred {
    if b { Shred::Yes } else { Shred::No }
}

// spec/commits.md §4: random transactions with random crashes match an in-memory oracle.
proptest! {
    #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]
    #[test]
    fn random_ops_with_crashes(txns in proptest::collection::vec((proptest::collection::vec(op(), 1..30), proptest::option::of(0u64..4)), 1..12)) {
        let dev = MemDevice::new();
        let mut rng = SeededRng::from_u64(5);
        let cfg = StoreConfig { spill_bytes: 600, ..cfg() };
        let mut s = Some(Store::create(dev.backend(), dev.root(), cfg, &mut rng).unwrap());
        let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        for (ops, crash) in txns {
            let mut next = model.clone();
            if let Some(n) = crash {
                dev.faults.at(n, Fault::Crash);
            }
            let store = s.as_mut().unwrap();
            let mut t = store.transaction(&mut rng).unwrap();
            for o in &ops {
                let r = match o {
                    Op::Put(k, v, sh) => {
                        next.insert(vec![*k], vec![*v; 40]);
                        t.put_local(&[*k], &[*v; 40], shred(*sh))
                    }
                    Op::Remove(k, sh) => {
                        next.remove(&vec![*k]);
                        t.remove_local(&[*k], shred(*sh)).map(|_| ())
                    }
                };
                if r.is_err() {
                    break;
                }
            }
            let ok = t.commit().is_ok();
            if dev.faults.crashed() || !ok {
                drop(s.take());
                dev.faults.revive();
                let mut reopened = Store::open(dev.backend(), dev.root(), cfg).unwrap();
                let state: BTreeMap<_, _> = snapshot(&mut reopened).0.into_iter().collect();
                prop_assert!(state == model || state == next, "torn state");
                model = state;
                s = Some(reopened);
            } else {
                dev.faults.revive();
                model = next;
                prop_assert_eq!(snapshot(s.as_mut().unwrap()).0.into_iter().collect::<BTreeMap<_, _>>(), model.clone());
            }
        }
        drop(s);
        let mut s = Store::open(dev.backend(), dev.root(), cfg).unwrap();
        prop_assert_eq!(snapshot(&mut s).0.into_iter().collect::<BTreeMap<_, _>>(), model);
    }
}

// spec: none (root storage rule: MemoryRoot keeps only the current record)
#[test]
fn memory_root_replaces() {
    let mut r = MemoryRoot::new();
    let rec = |e| osis_store::RootRecord { epoch: e, key: osis_crypto::Secret32::from_bytes([e as u8; 32]) };
    r.store(&rec(1)).unwrap();
    r.store(&rec(2)).unwrap();
    assert_eq!(r.load().unwrap(), Some(rec(2)));
}
