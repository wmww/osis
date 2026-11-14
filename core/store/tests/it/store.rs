#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Typed units and transactions (notes/local-store.md, Units) on every backend.

use crate::common;

use common::*;
use osis_base::{BlobId, CommitId};
use osis_crypto::SeededRng;
use osis_store::{AspectUnit, Error, Fault, MemoryBackend, MemoryRoot, PendingKind, Shred, Store, StoreConfig};

// spec/commits.md §4: all writes of a transaction commit together; dropping it aborts.
#[test]
fn transactions_commit_or_abort() {
    for dev in devices("txn") {
        let mut rng = SeededRng::from_u64(0);
        let mut s = create(&*dev, &mut rng);
        let (t1, a) = (tid(1), ak("name.0"));
        let unit = AspectUnit { state: b"state".to_vec() };
        {
            let mut t = s.transaction(&mut rng).unwrap();
            t.put_aspect(&t1, &a, &unit, Shred::No).unwrap();
            assert_eq!(t.get_aspect(&t1, &a).unwrap(), Some(unit.clone()), "reads see own writes");
            // Dropped: aborted.
        }
        let mut t = s.transaction(&mut rng).unwrap();
        assert_eq!(t.get_aspect(&t1, &a).unwrap(), None);
        t.put_aspect(&t1, &a, &unit, Shred::No).unwrap();
        t.put_local(b"secret", b"secret", Shred::No).unwrap();
        t.commit().unwrap();
        drop(s);
        let mut s = reopen(&*dev);
        let mut t = s.transaction(&mut rng).unwrap();
        assert_eq!(t.get_aspect(&t1, &a).unwrap(), Some(unit), "{}", dev.name());
        assert_eq!(t.get_local(b"secret").unwrap(), Some(b"secret".to_vec()));
        assert_eq!(t.get_aspect(&t1, &ak("other.0")).unwrap(), None);
    }
}

// spec/crdt.md §2.1, §2.3: a session's counters never repeat within the open, also across a
// whole-aspect purge and an aborted transaction; they are memory only, so a reopen (a new
// session) starts from 1 again.
#[test]
fn counters() {
    let (dev, mut rng, mut s) = fresh(cfg());
    let (t1, a) = (tid(1), ak("c.0"));
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.counter(&t1, &a, &[7u8; 16]).unwrap(), 1);
    assert_eq!(t.reserve_counters(&t1, &a, &[7u8; 16], 5).unwrap(), 1);
    assert_eq!(t.reserve_counters(&t1, &a, &[7u8; 16], 2).unwrap(), 6);
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.reserve_counters(&t1, &a, &[7u8; 16], 3).unwrap(), 8);
    drop(t);
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.counter(&t1, &a, &[7u8; 16]).unwrap(), 8, "an aborted transaction gives its counters back");
    t.drop_aspect(&t1, &a).unwrap();
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.counter(&t1, &a, &[7u8; 16]).unwrap(), 8, "a purge keeps the session's counters");
    drop(t);
    drop(s);
    let mut s = reopen(&dev);
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.counter(&t1, &a, &[7u8; 16]).unwrap(), 1, "a new session");
}

// spec/commits.md §4: pending and parked commits are stored as bytes until applied.
#[test]
fn pending_commits() {
    let (_dev, mut rng, mut s) = fresh(cfg());
    let mut t = s.transaction(&mut rng).unwrap();
    for i in 0..10u8 {
        let k = if i % 3 == 0 { PendingKind::Parked } else { PendingKind::Pending };
        t.put_pending(&CommitId([i; 32]), k, &vec![i; 300]).unwrap();
    }
    assert_eq!(t.get_pending(&CommitId([3; 32])).unwrap(), Some((PendingKind::Parked, vec![3; 300])));
    let page = t.pending(Some(&CommitId([4; 32])), 3).unwrap();
    assert_eq!(page.iter().map(|(c, _, _)| c.0[0]).collect::<Vec<_>>(), vec![5, 6, 7]);
    assert!(t.remove_pending(&CommitId([5; 32]), Shred::No).unwrap());
    assert!(!t.remove_pending(&CommitId([5; 32]), Shred::No).unwrap());
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.pending(None, 100).unwrap().len(), 9);
}

// spec/commits.md §5: dropping destroys every local copy; notes/local-store.md, Units: the
// shredded drops of one transaction rewrite their pages under one key-tree rotation.
#[test]
fn shredded_drops_rotate_once() {
    let (_dev, mut rng, mut s) = fresh(cfg());
    let mut t = s.transaction(&mut rng).unwrap();
    for b in 0..20u8 {
        t.put_local(&[b"a/", &[b][..]].concat(), &[b; 49], Shred::No).unwrap();
    }
    t.put_local(b"b/0", &[0xee; 49], Shred::No).unwrap();
    t.commit().unwrap();
    let e = s.epoch();
    let mut t = s.transaction(&mut rng).unwrap();
    assert!(t.remove_local(b"a/\x03", Shred::Yes).unwrap());
    assert!(t.remove_local(b"b/0", Shred::Yes).unwrap());
    t.commit().unwrap();
    assert_eq!(s.epoch(), e + 1, "one rotation for the whole transaction");
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.get_local(b"a/\x03").unwrap(), None);
    assert_eq!(t.get_local(b"a/\x04").unwrap(), Some(vec![4; 49]));
    assert_eq!(t.scan_local(b"a/", b"", 100).unwrap().len(), 19);
    assert_eq!(t.scan_local(b"b/", b"", 100).unwrap(), vec![]);
}

// spec: none (node-local bookkeeping); notes/local-store.md, Units: `*_local` records.
#[test]
fn local_records() {
    let (_dev, mut rng, mut s) = fresh(cfg());
    let mut t = s.transaction(&mut rng).unwrap();
    t.put_local(b"roster/1", b"a", Shred::No).unwrap();
    t.put_local(b"roster/2", b"b", Shred::No).unwrap();
    t.put_local(b"zzz", b"c", Shred::No).unwrap();
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.scan_local(b"roster/", b"", 10).unwrap(), vec![(b"roster/1".to_vec(), b"a".to_vec()), (b"roster/2".to_vec(), b"b".to_vec())]);
    assert!(t.remove_local(b"zzz", Shred::No).unwrap());
}

// spec/commits.md §4: one storage transaction per commit applied; notes/local-store.md, Units: blob ciphertexts sit beside the units, inside transactions.
#[test]
fn blobs() {
    for dev in devices("blobs") {
        let mut rng = SeededRng::from_u64(0);
        let mut s = create(&*dev, &mut rng);
        let id = BlobId([5; 32]);
        let mut t = s.transaction(&mut rng).unwrap();
        t.put_blob(&id, vec![1, 2, 3, 4, 5]).unwrap();
        assert_eq!(t.read_blob(&id, 1, 2).unwrap(), Some(vec![2, 3]));
        drop(t);
        let mut t = s.transaction(&mut rng).unwrap();
        assert_eq!(t.get_blob(&id).unwrap(), None, "aborted");
        t.put_blob(&id, vec![1, 2, 3, 4, 5]).unwrap();
        t.commit().unwrap();
        let mut t = s.transaction(&mut rng).unwrap();
        assert_eq!(t.read_blob(&id, 3, 10).unwrap(), Some(vec![4, 5]));
        t.delete_blob(&id);
        assert_eq!(t.get_blob(&id).unwrap(), None);
        t.commit().unwrap();
        assert_eq!(s.backend().get_blob(&id).unwrap(), None);
    }
}

// spec: none (store lifecycle)
#[test]
fn lifecycle_errors() {
    let (b, r) = (MemoryBackend::new(), MemoryRoot::new());
    let mut rng = SeededRng::from_u64(0);
    assert_eq!(Store::open(Box::new(b.clone()), Box::new(r.clone()), cfg()).err(), Some(Error::NoStore));
    Store::create(Box::new(b.clone()), Box::new(r.clone()), cfg(), &mut rng).unwrap();
    assert_eq!(Store::create(Box::new(b.clone()), Box::new(r.clone()), cfg(), &mut rng).err(), Some(Error::Exists));
    let mut s = Store::open(Box::new(b), Box::new(r), Default::default()).unwrap();
    assert_eq!(s.config().arity, 8);
    let mut t = s.transaction(&mut rng).unwrap();
    let big_ak = ak(&format!("{}.0", "a".repeat(200)));
    assert!(matches!(t.put_aspect(&tid(1), &big_ak, &AspectUnit::default(), Shred::No), Err(Error::Misuse(_))));
}

// spec/commits.md §4: an aborted transaction that spilled leaves nothing that harms later commits.
#[test]
fn abort_after_spill() {
    let cfg = StoreConfig { spill_bytes: 100, ..cfg() };
    let (dev, mut rng, mut s) = fresh(cfg);
    let mut t = s.transaction(&mut rng).unwrap();
    let tb = t.create_table(&tid(1), &ak("t.0"), 0).unwrap();
    for i in 0..20u32 {
        t.table_put(tb, &i.to_be_bytes(), vec![1; 30], Shred::No).unwrap();
    }
    drop(t);
    let mut t = s.transaction(&mut rng).unwrap();
    let tb = t.create_table(&tid(1), &ak("t.0"), 0).unwrap();
    t.table_put(tb, b"k", vec![2; 5], Shred::No).unwrap();
    t.commit().unwrap();
    assert!(s.backend().scan_prefix(b"j", 10).unwrap().is_empty(), "aborted spill rolled back");
    drop(s);
    let mut s = Store::open(dev.backend(), dev.root(), cfg).unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    let tb = t.table(&tid(1), &ak("t.0"), 0).unwrap().unwrap();
    assert_eq!(t.table_get(tb, b"k").unwrap(), Some(vec![2; 5]));
    assert_eq!(t.table_len(tb).unwrap(), 1);
}

// spec/commits.md §4: rolling back a transaction never deletes a blob committed before it
// (content-addressed re-puts are normal).
#[test]
fn rollback_keeps_committed_blob() {
    for shredding in [false, true] {
        let cfg = StoreConfig { spill_bytes: 100, ..cfg() };
        let (dev, mut rng, mut s) = fresh(cfg);
        let id = BlobId([7; 32]);
        let mut t = s.transaction(&mut rng).unwrap();
        t.put_blob(&id, vec![9; 50]).unwrap();
        t.put_local(b"x", b"1", Shred::No).unwrap();
        t.commit().unwrap();
        let mut t = s.transaction(&mut rng).unwrap();
        if shredding {
            // Crash after the shredding commit's first batch: rolled back on open.
            t.put_blob(&id, vec![9; 50]).unwrap();
            t.put_local(b"x", b"2", Shred::Yes).unwrap();
            dev.faults.at(1, Fault::Crash);
            assert!(t.commit().is_err());
            dev.faults.revive();
        } else {
            t.put_blob(&id, vec![9; 500]).unwrap();
            drop(t);
        }
        drop(s);
        let mut s = Store::open(dev.backend(), dev.root(), cfg).unwrap();
        let mut t = s.transaction(&mut rng).unwrap();
        assert!(t.get_blob(&id).unwrap().is_some(), "committed blob lost by rollback (shredding {shredding})");
        assert_eq!(t.get_local(b"x").unwrap(), Some(b"1".to_vec()));
    }
}

// spec: none (store lifecycle: a crash at any write of create leaves a store that opens or can
// be created again)
#[test]
fn crash_during_create() {
    for n in 0..4 {
        let dev = MemDevice::new();
        let mut rng = SeededRng::from_u64(0);
        dev.faults.at(n, Fault::Crash);
        let crashed = Store::create(dev.backend(), dev.root(), cfg(), &mut rng).is_err();
        dev.faults.revive();
        let mut s = match Store::open(dev.backend(), dev.root(), cfg()) {
            Ok(s) => s,
            Err(Error::NoStore) => {
                assert!(crashed);
                Store::create(dev.backend(), dev.root(), cfg(), &mut rng).unwrap()
            }
            Err(e) => panic!("crash at {n}: {e:?}"),
        };
        let mut t = s.transaction(&mut rng).unwrap();
        t.put_local(b"k", b"v", Shred::No).unwrap();
        t.commit().unwrap();
    }
}

// notes/local-store.md, Memory overlay: rows written in memory mode, and every row of a memory-class
// aspect, stay in memory (no backend write), read merged with durable rows, roll back with an
// aborted transaction and are gone after a reopen; durable rows beside them persist.
// spec/commits.md §1
#[test]
fn memory_overlay_rows() {
    let (dev, mut rng, mut s) = fresh(cfg());
    let (t1, a, b) = (tid(1), ak("mem+.0"), ak("dur.0"));
    let unit = AspectUnit { state: b"m".to_vec() };
    {
        let mut t = s.transaction(&mut rng).unwrap();
        t.put_local(b"z/1", b"durable", Shred::No).unwrap();
        t.put_aspect(&t1, &b, &unit, Shred::No).unwrap();
        t.commit().unwrap();
    }
    let writes = dev.faults.writes();
    let ix;
    {
        let mut t = s.transaction(&mut rng).unwrap();
        ix = t.index(b"ix").unwrap();
        t.commit().unwrap();
    }
    let writes = writes.max(dev.faults.writes());
    {
        let mut t = s.transaction(&mut rng).unwrap();
        t.set_memory(true);
        t.put_local(b"z/2", b"memory", Shred::No).unwrap();
        t.put_aspect(&t1, &a, &unit, Shred::No).unwrap();
        t.put_blob(&BlobId([7; 32]), b"blob".to_vec()).unwrap();
        t.table_put(ix, b"k2", b"m".to_vec(), Shred::No).unwrap();
        let tab = t.create_table(&t1, &a, 0).unwrap();
        t.table_put(tab, b"x", b"y".to_vec(), Shred::No).unwrap();
        t.commit().unwrap();
    }
    assert_eq!(dev.faults.writes(), writes, "memory rows reach no backend");
    {
        // a memory-class aspect's rows stay memory in a durable-mode transaction
        let mut t = s.transaction(&mut rng).unwrap();
        t.reserve_counters(&t1, &a, &[7u8; 16], 3).unwrap();
        t.put_local(b"z/3", b"durable", Shred::No).unwrap();
        t.table_put(ix, b"k1", b"d".to_vec(), Shred::No).unwrap();
        t.table_put(ix, b"k3", b"d".to_vec(), Shred::No).unwrap();
        let keys: Vec<_> = t.scan_local(b"z/", b"", 10).unwrap().into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec![b"z/1".to_vec(), b"z/2".to_vec(), b"z/3".to_vec()], "merged in key order");
        let rows: Vec<_> = t.table_range(ix, b"", None, 10).unwrap().into_iter().map(|(k, _)| k).collect();
        assert_eq!(rows, vec![b"k1".to_vec(), b"k2".to_vec(), b"k3".to_vec()]);
        assert_eq!((t.table_len(ix).unwrap(), t.table_rank(ix, b"k3").unwrap()), (3, 2));
        assert_eq!(t.table_range(ix, b"", None, 2).unwrap().len(), 2, "limit over both layers");
        t.commit().unwrap();
    }
    {
        // dropped: the memory changes roll back
        let mut t = s.transaction(&mut rng).unwrap();
        t.set_memory(true);
        t.put_local(b"z/4", b"memory", Shred::No).unwrap();
        assert!(t.remove_local(b"z/2", Shred::No).unwrap());
        // a whole memory table dropped and a new one made, read back in the same transaction
        t.drop_table(&t1, &a, 0).unwrap();
        assert_eq!(t.table(&t1, &a, 0).unwrap(), None);
        let tab = t.create_table(&t1, &a, 1).unwrap();
        t.table_put(tab, b"n", b"1".to_vec(), Shred::No).unwrap();
        assert_eq!(t.table_get(tab, b"n").unwrap(), Some(b"1".to_vec()));
        assert!(t.table_remove(ix, b"k2", Shred::No).unwrap());
    }
    {
        let mut t = s.transaction(&mut rng).unwrap();
        assert_eq!(t.get_local(b"z/2").unwrap(), Some(b"memory".to_vec()));
        assert_eq!(t.get_local(b"z/4").unwrap(), None);
        assert_eq!(t.get_blob(&BlobId([7; 32])).unwrap(), Some(b"blob".to_vec()));
        assert_eq!(t.counter(&t1, &a, &[7u8; 16]).unwrap(), 4);
        let tab = t.table(&t1, &a, 0).unwrap().expect("dropped table restored");
        assert_eq!(t.table_get(tab, b"x").unwrap(), Some(b"y".to_vec()));
        assert_eq!(t.table(&t1, &a, 1).unwrap(), None);
        assert_eq!(t.table_len(ix).unwrap(), 3);
    }
    drop(s);
    let mut s = reopen(&dev);
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.get_local(b"z/2").unwrap(), None);
    assert_eq!(t.get_aspect(&t1, &a).unwrap(), None);
    assert_eq!(t.counter(&t1, &a, &[7u8; 16]).unwrap(), 1);
    assert_eq!(t.get_blob(&BlobId([7; 32])).unwrap(), None);
    assert_eq!(t.table(&t1, &a, 0).unwrap(), None);
    assert_eq!(t.get_local(b"z/3").unwrap(), Some(b"durable".to_vec()));
    assert_eq!(t.get_aspect(&t1, &b).unwrap(), Some(unit));
    let rows: Vec<_> = t.table_range(ix, b"", None, 10).unwrap().into_iter().map(|(k, _)| k).collect();
    assert_eq!(rows, vec![b"k1".to_vec(), b"k3".to_vec()]);
}

// notes/local-store.md, Memory overlay: a memory-mode transaction far past the spill threshold
// writes nothing to the backend (memory rows never join the early write-out).
// spec/commits.md §1
#[test]
fn memory_rows_never_spill() {
    let cfg = StoreConfig { spill_bytes: 100, ..cfg() };
    let (dev, mut rng, mut s) = fresh(cfg);
    let ix = {
        let mut t = s.transaction(&mut rng).unwrap();
        let ix = t.index(b"ix").unwrap();
        t.commit().unwrap();
        ix
    };
    let writes = dev.faults.writes();
    let mut t = s.transaction(&mut rng).unwrap();
    t.set_memory(true);
    let tb = t.create_table(&tid(1), &ak("m.0"), 0).unwrap();
    for i in 0..200u32 {
        t.table_put(tb, &i.to_be_bytes(), vec![1; 300], Shred::No).unwrap();
        t.table_put(ix, &i.to_be_bytes(), vec![2; 300], Shred::No).unwrap();
        t.put_local(&[b"m/".as_slice(), &i.to_be_bytes()].concat(), &[3; 300], Shred::No).unwrap();
        t.put_blob(&BlobId([i as u8; 32]), vec![4; 300]).unwrap();
    }
    t.commit().unwrap();
    assert_eq!(dev.faults.writes(), writes, "no backend write");
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.table_len(tb).unwrap(), 200);
    assert_eq!(t.table_len(ix).unwrap(), 200);
}

// spec/commits.md §4: a transaction set aside (`suspend`) and continued (`resume`) across calls
// is one transaction: its reads see its writes, spills included, and it commits or aborts whole
#[test]
fn suspended_transaction_is_one() {
    let dev = MemDevice::new();
    let mut rng = SeededRng::from_u64(0);
    let cfg = StoreConfig { spill_bytes: 100, ..cfg() };
    let mut s = Store::open_or_create(dev.backend(), dev.root(), cfg, &mut rng).unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    let tb = t.create_table(&tid(1), &ak("t.0"), 0).unwrap();
    let mut held = t.suspend().unwrap();
    for i in 0..20u32 {
        let mut t = s.resume(held, &mut rng);
        t.table_put(tb, &i.to_be_bytes(), vec![1; 30], Shred::No).unwrap();
        t.put_blob(&BlobId([i as u8; 32]), vec![i as u8; 40]).unwrap();
        assert_eq!(t.table_len(tb).unwrap(), u64::from(i) + 1);
        held = t.suspend().unwrap();
    }
    // dropped while set aside: aborted, the spills rolled back by the next transaction
    drop(held);
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.table(&tid(1), &ak("t.0"), 0).unwrap(), None);
    assert_eq!(t.get_blob(&BlobId([3; 32])).unwrap(), None);
    let tb = t.create_table(&tid(1), &ak("t.0"), 0).unwrap();
    let mut held = t.suspend().unwrap();
    for i in 0..20u32 {
        let mut t = s.resume(held, &mut rng);
        t.table_put(tb, &i.to_be_bytes(), vec![2; 30], Shred::No).unwrap();
        held = t.suspend().unwrap();
    }
    s.resume(held, &mut rng).commit().unwrap();
    assert!(s.backend().scan_prefix(b"j", 10).unwrap().is_empty(), "no journal left");
    drop(s);
    let mut s = Store::open_or_create(dev.backend(), dev.root(), cfg, &mut rng).unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    let tb = t.table(&tid(1), &ak("t.0"), 0).unwrap().unwrap();
    assert_eq!(t.table_len(tb).unwrap(), 20);
    assert_eq!(t.table_get(tb, &7u32.to_be_bytes()).unwrap(), Some(vec![2; 30]));
    // a crash while set aside, spills on disk: the next open rolls them back
    let mut held = t.suspend().unwrap();
    for i in 0..20u32 {
        let mut t = s.resume(held, &mut rng);
        t.table_put(tb, &(100 + i).to_be_bytes(), vec![3; 30], Shred::No).unwrap();
        held = t.suspend().unwrap();
    }
    assert!(!s.backend().scan_prefix(b"j", 10).unwrap().is_empty(), "spilled");
    drop((held, s));
    let mut s = Store::open_or_create(dev.backend(), dev.root(), cfg, &mut rng).unwrap();
    assert!(s.backend().scan_prefix(b"j", 10).unwrap().is_empty(), "no journal left");
    let mut t = s.transaction(&mut rng).unwrap();
    let tb = t.table(&tid(1), &ak("t.0"), 0).unwrap().unwrap();
    assert_eq!(t.table_len(tb).unwrap(), 20);
    // memory rows cannot be set aside: refused, and the transaction aborted
    t.set_memory(true);
    t.create_table(&tid(2), &ak("m.0"), 0).unwrap();
    assert_eq!(t.suspend().err(), Some(Error::Misuse("suspend with memory rows")));
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.table(&tid(2), &ak("m.0"), 0).unwrap(), None);
}

// spec/commits.md §4: a failed commit recovers the store in place and reports its outcome: `Err`
// leaves the store as before it (earlier commits kept) and the next transaction works, with no
// reopen; a shredding commit failing after its root record was stored landed, so it is `Ok`. On
// redb too, where the fault is a failed write of the file (redb refuses every call after one
// until opened again)
#[test]
fn failed_commit_recovers_in_place() {
    for dev in devices("failed-commit") {
        failed_commit_recovers_in_place_on(&*dev);
    }
}

fn failed_commit_recovers_in_place_on(dev: &dyn Device) {
    let name = dev.name();
    let mut rng = SeededRng::from_u64(0);
    let mut s = create(dev, &mut rng);
    // writes `k`, removing `gone` when `shred` is given
    let put = |s: &mut Store, rng: &mut SeededRng, k: &[u8], shred: Option<Shred>| {
        let mut t = s.transaction(rng).unwrap();
        let tb = t.create_table(&tid(1), &ak("t.0"), 0).unwrap();
        t.table_put(tb, k, k.to_vec(), Shred::No).unwrap();
        if let Some(shred) = shred {
            t.table_remove(tb, b"gone", shred).unwrap();
        }
        t.commit()
    };
    put(&mut s, &mut rng, b"gone", None).unwrap();
    for (n, shred) in [(0, Shred::No), (0, Shred::Yes), (1, Shred::Yes), (2, Shred::Yes)] {
        dev.faults().at(n, Fault::Fail);
        // a shredding commit writes batch A, the root (its commit point), then batch B
        let landed = n == 2;
        assert_eq!(put(&mut s, &mut rng, b"failed", Some(shred)).is_ok(), landed, "{name}: fault at {n}");
        let mut t = s.transaction(&mut rng).unwrap();
        let tb = t.table(&tid(1), &ak("t.0"), 0).unwrap().unwrap();
        assert_eq!(t.table_get(tb, b"failed").unwrap().is_some(), landed, "{name}: fault at {n}");
        assert_eq!(t.table_get(tb, b"gone").unwrap().is_some(), !landed, "{name}: fault at {n}");
        if landed {
            t.table_remove(tb, b"failed", Shred::No).unwrap();
            t.table_put(tb, b"gone", vec![], Shred::No).unwrap();
        }
        t.commit().unwrap();
    }
    // a failed spill fails its transaction; the next one recovers
    let mut small = cfg();
    small.spill_bytes = 64;
    drop(s);
    let mut s = Store::open(dev.backend(), dev.root(), small).unwrap();
    dev.faults().at(0, Fault::Fail);
    let mut t = s.transaction(&mut rng).unwrap();
    let tb = t.table(&tid(1), &ak("t.0"), 0).unwrap().unwrap();
    let r = (0..64u8).try_for_each(|i| t.table_put(tb, &[b'x', i], vec![i; 32], Shred::No).map(drop));
    assert!(r.is_err(), "a spill fails");
    assert!(t.table_put(tb, b"y", vec![], Shred::No).is_err(), "its transaction goes no further");
    assert_eq!(t.commit(), Err(Error::Broken));
    let mut t = s.transaction(&mut rng).unwrap();
    let tb = t.table(&tid(1), &ak("t.0"), 0).unwrap().unwrap();
    assert_eq!(t.table_get(tb, &[b'x', 0]).unwrap(), None);
    drop(t);
    put(&mut s, &mut rng, b"after", None).unwrap();
    drop(s);
    let mut s = reopen(dev);
    let mut t = s.transaction(&mut rng).unwrap();
    let tb = t.table(&tid(1), &ak("t.0"), 0).unwrap().unwrap();
    assert_eq!(t.table_get(tb, b"after").unwrap(), Some(b"after".to_vec()));
    // spec/requirements.md, Deletion: failed writes and their recovery leave ciphertext only
    if let Some(raw) = dev.file() {
        for marker in [&b"failed"[..], b"gone", b"after"] {
            assert!(!raw.windows(marker.len()).any(|w| w == marker), "{name}: plaintext in the file");
        }
    }
}

/// Commits `k` and, shredding, overwrites `x`; whether `commit` answered `Ok`.
fn put_k(s: &mut Store, rng: &mut SeededRng, k: &[u8], shred: Shred) -> bool {
    let mut t = s.transaction(rng).unwrap();
    let tb = t.table(&tid(1), &ak("t.0"), 0).unwrap().unwrap();
    t.table_put(tb, k, vec![1], Shred::No).unwrap();
    t.table_put(tb, b"x", k.to_vec(), shred).unwrap();
    t.commit().is_ok()
}

fn has(s: &mut Store, rng: &mut SeededRng, k: &[u8]) -> bool {
    let mut t = s.transaction(rng).unwrap();
    let tb = t.table(&tid(1), &ak("t.0"), 0).unwrap().unwrap();
    t.table_get(tb, k).unwrap().is_some()
}

/// A store holding `x` among filler rows enough for many units, so a later commit leaves some
/// of the backend's pages as an earlier one wrote them.
fn put_x(dev: &dyn Device, rng: &mut SeededRng) -> Store {
    let mut s = create(dev, rng);
    let mut t = s.transaction(rng).unwrap();
    let tb = t.create_table(&tid(1), &ak("t.0"), 0).unwrap();
    t.table_put(tb, b"x", vec![], Shred::No).unwrap();
    for i in 0..200u32 {
        t.table_put(tb, format!("m{i:03}").as_bytes(), vec![7; 40], Shred::No).unwrap();
    }
    t.commit().unwrap();
    s
}

// spec/commits.md §4 (notes/local-store.md, Failed writes): a commit reported landed is
// durable. A write whose sync fails reads as written but a power cut drops it (as a failed fsync
// does), at any durable write of a commit, plain or shredding: the outcome is unknown (`Err`),
// the store recovers in place on its own at the next transaction, reading what the disk holds,
// and works on with no reopen; every commit reported landed, those after the failure included,
// survives a later power cut, and the store opens after it.
#[test]
fn a_commit_whose_sync_failed_is_never_reported_landed() {
    for dev in devices("unsynced") {
        let name = dev.name();
        let mut rng = SeededRng::from_u64(0);
        let mut s = put_x(&*dev, &mut rng);
        let mut kept = Vec::new();
        for shred in [Shred::No, Shred::Yes] {
            let (mut landed, mut lost) = (false, false);
            for n in 0.. {
                let k = format!("k-{shred:?}-{n}").into_bytes();
                let unknown = s.writes().unknown;
                dev.faults().at(n, Fault::Unsynced);
                let ok = put_k(&mut s, &mut rng, &k, shred);
                let reached = dev.faults().writes() > n;
                dev.faults().revive();
                if !reached {
                    assert!(ok, "{name} {shred:?}: no fault, committed");
                    break;
                }
                let unsure = s.writes().unknown > unknown;
                assert!(!unsure || !ok, "{name} {shred:?}: an unknown outcome is Err (write {n})");
                (landed, lost) = (landed || ok, lost || unsure);
                if ok {
                    kept.push(k.clone());
                }
                // no reopen: the store recovers on its own and works on
                let after = format!("after-{shred:?}-{n}").into_bytes();
                assert!(put_k(&mut s, &mut rng, &after, shred), "{name} {shred:?}: works on after write {n}'s sync failed");
                kept.push(after);
                drop(s);
                dev.power_cut();
                s = reopen(&*dev);
                for k in &kept {
                    assert!(has(&mut s, &mut rng, k), "{name} {shred:?}: {} reported landed, lost to a power cut after write {n}'s sync failed", String::from_utf8_lossy(k));
                }
            }
            assert!(lost, "{name} {shred:?}: a failed backend sync leaves the outcome unknown");
            if shred == Shred::Yes {
                assert!(landed, "{name}: a failed root sync is written again: the commit lands");
            }
        }
    }
}

// spec/commits.md §4 (notes/local-store.md, Failed writes): a spill whose sync failed leaves
// what the backend reads unknown as a commit's does; the next transaction recovers in place at
// the last commit, and what it commits survives a power cut.
#[test]
fn a_spill_whose_sync_failed_recovers_in_place() {
    for dev in devices("unsynced-spill") {
        let name = dev.name();
        let mut rng = SeededRng::from_u64(0);
        drop(put_x(&*dev, &mut rng));
        let cfg = StoreConfig { spill_bytes: 100, ..cfg() };
        let mut s = Store::open(dev.backend(), dev.root(), cfg).unwrap();
        dev.faults().at(0, Fault::Unsynced);
        let mut t = s.transaction(&mut rng).unwrap();
        let tb = t.table(&tid(1), &ak("t.0"), 0).unwrap().unwrap();
        let r = (0..20u32).try_for_each(|i| t.table_put(tb, &i.to_be_bytes(), vec![1; 30], Shred::No).map(drop));
        assert!(r.is_err() && dev.faults().writes() == 1, "{name}: the first spill's sync failed");
        drop(t);
        dev.faults().revive();
        assert_eq!(s.writes().unknown, 1, "{name}: outcome unknown");
        assert!(has(&mut s, &mut rng, b"x") && !has(&mut s, &mut rng, &0u32.to_be_bytes()), "{name}: recovered at the last commit");
        assert!(put_k(&mut s, &mut rng, b"k", Shred::Yes), "{name}: works on");
        drop(s);
        dev.power_cut();
        let mut s = Store::open(dev.backend(), dev.root(), cfg).unwrap();
        assert!(has(&mut s, &mut rng, b"k") && !has(&mut s, &mut rng, &0u32.to_be_bytes()), "{name}: the commit after survives a power cut");
    }
}

// spec: none (notes/local-store.md, Failed writes): while the device still fails, a store whose write's
// outcome is unknown fails `Broken` at once, touching nothing, until its retry is due; the
// first retry comes at the next transaction.
#[test]
fn a_lost_store_retries_after_a_wait() {
    let dev = MemDevice::new();
    let mut rng = SeededRng::from_u64(0);
    let mut s = put_x(&dev, &mut rng);
    // a shredding commit's last batch: recovery finishes it from the journal, a write
    dev.faults.at(2, Fault::Unsynced);
    assert!(!put_k(&mut s, &mut rng, b"k", Shred::Yes));
    assert_eq!(s.writes().unknown, 1);
    // that write fails too: the device is still down
    dev.faults.at(0, Fault::Crash);
    assert!(s.transaction(&mut rng).is_err());
    assert!(dev.faults.crashed(), "the first retry ran at once");
    dev.faults.revive();
    let io = dev.backend.io();
    assert_eq!(s.transaction(&mut rng).err(), Some(Error::Broken), "the next waits");
    assert_eq!(dev.backend.io(), io, "touching nothing");
}

// spec/commits.md §4 on redb: a write of the file can fail anywhere in redb's commit, its sync
// included (which drops the writes since the last sync at a power cut). A failed write reports
// the outcome it leaves; a failed sync leaves it unknown (`Err`) and the store recovers in place
// at the next call, reading what the disk holds; with no reopen, every `Ok` commit, those after
// a failed sync included, survives a power cut. Each fault point starts from the same store: a
// fault that lands changes the next commit's write count (redb flushes its pages in no fixed
// order, so a fault after its header write can land), and the sweep must reach the sync.
#[test]
fn a_failed_redb_write_anywhere_in_a_commit_reports_its_outcome() {
    use std::sync::atomic::Ordering::SeqCst;
    for shred in [Shred::No, Shred::Yes] {
        let (mut landed, mut failed, mut lost) = (false, false, false);
        for n in 1.. {
            let dev = FileDevice::new(&format!("redb-any-write-{shred:?}-{n}"));
            let mut rng = SeededRng::from_u64(0);
            let mut s = put_x(&dev, &mut rng);
            let unknown = s.writes().unknown;
            dev.trap.store(n, SeqCst);
            let ok = put_k(&mut s, &mut rng, b"k", shred);
            let reached = dev.trap.swap(0, SeqCst) == 0;
            let unsure = s.writes().unknown > unknown;
            assert!(!unsure || !ok, "{shred:?}: fault at file write {n}: an unknown outcome is Err");
            // the store recovers at once (the trap is off)
            let present = has(&mut s, &mut rng, b"k");
            assert!(ok || unsure || !present, "{shred:?}: fault at file write {n}: Err, yet landed");
            assert!(!ok || present, "{shred:?}: fault at file write {n}: Ok, yet absent");
            assert!(put_k(&mut s, &mut rng, b"after", shred), "{shred:?}: works on after a fault at file write {n}");
            drop(s);
            dev.power_cut();
            let mut s = reopen(&dev);
            assert!(!ok || has(&mut s, &mut rng, b"k"), "{shred:?}: fault at file write {n}: reported landed, lost to a power cut");
            assert!(has(&mut s, &mut rng, b"after"), "{shred:?}: the commit after a fault at file write {n} lost to a power cut");
            if !reached {
                assert!(ok, "{shred:?}: no fault, committed");
                break;
            }
            (landed, failed, lost) = (landed || ok, failed || !ok, lost || unsure);
        }
        assert!(failed && lost, "{shred:?}: faults both before the commit point and at its sync");
        if shred == Shred::Yes {
            assert!(landed, "a fault after the root record was stored: landed");
        }
    }
}

/// What a test can read of a store: every local record, every row of table 0 of `(tid(1), t.0)`,
/// blobs 1..=4, the counter of `(tid(1), mem+.0)`, and the backend's row names.
type Observed = (Vec<osis_store::KeyValue>, Vec<osis_store::KeyValue>, Vec<Option<Vec<u8>>>, u64, Vec<Vec<u8>>);

fn observed(s: &mut Store, rng: &mut SeededRng) -> Observed {
    let rows: Vec<Vec<u8>> = s.backend().scan_prefix(b"", usize::MAX).unwrap().into_iter().map(|(k, _)| k).collect();
    let mut t = s.transaction(rng).unwrap();
    let local = t.scan_local(b"", b"", usize::MAX).unwrap();
    let table = match t.table(&tid(1), &ak("t.0"), 0).unwrap() {
        Some(tb) => t.table_range(tb, b"", None, usize::MAX).unwrap(),
        None => Vec::new(),
    };
    let blobs = (1..=4u8).map(|i| t.get_blob(&BlobId([i; 32])).unwrap()).collect();
    let ctr = t.counter(&tid(1), &ak("mem+.0"), b"n").unwrap();
    (local, table, blobs, ctr, rows)
}

/// Every kind of change a step can make.
fn step_writes(t: &mut osis_store::Transaction<'_>) {
    t.set_memory(false);
    let tb = t.create_table(&tid(1), &ak("t.0"), 0).unwrap();
    for i in 0..40u32 {
        t.table_put(tb, &i.to_be_bytes(), vec![3; 40], Shred::No).unwrap();
    }
    t.table_remove(tb, &5u32.to_be_bytes(), Shred::Yes).unwrap();
    t.put_local(b"a", b"step", Shred::Yes).unwrap();
    t.remove_local(b"b", Shred::No).unwrap();
    t.put_blob(&BlobId([2; 32]), vec![2; 300]).unwrap();
    t.delete_blob(&BlobId([1; 32]));
    t.put_blob(&BlobId([3; 32]), vec![3; 10]).unwrap();
    t.reserve_counters(&tid(1), &ak("mem+.0"), b"n", 5).unwrap();
    t.set_memory(true);
    t.put_local(b"m", b"memory row", Shred::No).unwrap();
    t.put_blob(&BlobId([4; 32]), vec![4; 10]).unwrap();
    t.create_table(&tid(2), &ak("x+.0"), 0).unwrap();
}

// spec/commits.md §4: a rolled-back savepoint leaves the transaction as if the steps after it never ran: every
// write kind, both layers, blobs, counters and spills, on every backend.
#[test]
fn savepoint_rollback_is_no_step() {
    for (kind, (with_step, without)) in devices("sp-step").into_iter().zip(devices("sp-none")).enumerate() {
        let mut out = Vec::new();
        for (dev, step) in [(&with_step, true), (&without, false)] {
            let mut rng = SeededRng::from_u64(0);
            let cfg = StoreConfig { spill_bytes: 600, ..cfg() };
            let mut s = Store::create(dev.backend(), dev.root(), cfg, &mut rng).unwrap();
            let mut t = s.transaction(&mut rng).unwrap();
            t.put_local(b"b", b"before", Shred::No).unwrap();
            t.put_blob(&BlobId([1; 32]), vec![1; 50]).unwrap();
            t.commit().unwrap();
            let mut t = s.transaction(&mut rng).unwrap();
            // spilled before the step: the step overwrites and deletes spilled units
            let w0 = dev.faults().writes();
            let tb = t.create_table(&tid(1), &ak("t.0"), 0).unwrap();
            for i in 0..30u32 {
                t.table_put(tb, &i.to_be_bytes(), vec![1; 40], Shred::No).unwrap();
            }
            t.reserve_counters(&tid(1), &ak("mem+.0"), b"n", 2).unwrap();
            assert!(dev.faults().writes() > w0, "the setup spills");
            let written = dev.faults().writes();
            if step {
                let outer = t.savepoint();
                let inner = t.savepoint();
                step_writes(&mut t);
                t.release(inner).unwrap();
                step_writes(&mut t);
                assert_eq!(dev.faults().writes(), written, "nothing spills under a savepoint");
                t.rollback_to(outer);
                assert!(!t.is_memory(), "memory mode restored");
            }
            // after the step: the transaction goes on
            t.put_local(b"c", b"after", Shred::No).unwrap();
            t.table_put(tb, b"z", vec![9; 40], Shred::No).unwrap();
            t.commit().unwrap();
            out.push(observed(&mut s, &mut rng));
            drop(s);
            let mut s = Store::open(dev.backend(), dev.root(), cfg).unwrap();
            out.push(observed(&mut s, &mut rng));
        }
        assert_eq!(out[0].0, out[2].0, "{kind}: local records");
        assert_eq!(out[0].1, out[2].1, "{kind}: table rows");
        assert_eq!(out[0], out[2], "{kind}: committed");
        // the reopened store: memory rows and counters gone alike
        assert_eq!(out[1], out[3], "{kind}: reopened");
    }
}

// spec: none (internal: notes/local-store.md, Savepoints). What waited to spill under a
// savepoint spills at the outermost release.
#[test]
fn savepoint_release_spills() {
    let dev = MemDevice::new();
    let mut rng = SeededRng::from_u64(0);
    let cfg = StoreConfig { spill_bytes: 600, ..cfg() };
    let mut s = Store::create(dev.backend(), dev.root(), cfg, &mut rng).unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    let w0 = dev.faults.writes();
    let sp = t.savepoint();
    step_writes(&mut t);
    assert_eq!(dev.faults.writes(), w0);
    t.release(sp).unwrap();
    assert!(dev.faults.writes() > w0, "released: spilled");
    t.commit().unwrap();
}

// spec: none (internal: notes/local-store.md, Savepoints). Table pages a transaction changed
// and keeps unencoded (`DirtyUnit::Page`) change again under a savepoint and roll back to it,
// and removals of absent keys change nothing: what the transaction then reads, commits and
// reopens is the model's.
#[test]
fn unspilled_pages_roll_back_and_absent_removals_change_nothing() {
    let (dev, mut rng, mut s) = fresh(cfg());
    let mut t = s.transaction(&mut rng).unwrap();
    let tb = t.create_table(&tid(1), &ak("t.0"), 0).unwrap();
    let mut model = std::collections::BTreeMap::new();
    // several leaves and an interior level (page_max 512), none spilled
    for i in 0..120u32 {
        let (k, v) = ((i * 2).to_be_bytes().to_vec(), vec![i as u8; 20]);
        t.table_put(tb, &k, v.clone(), Shred::No).unwrap();
        model.insert(k, v);
    }
    let rows = |t: &mut osis_store::Transaction<'_>| t.table_range(tb, &[], None, usize::MAX).unwrap();
    let want: Vec<_> = model.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    // absent: between keys, below the first, past the last
    for k in [7u32, 0x8000_0001, 1_000_000] {
        assert!(!t.table_remove(tb, &k.to_be_bytes(), Shred::No).unwrap());
    }
    assert_eq!(rows(&mut t), want, "absent removals");
    let sp = t.savepoint();
    for i in 0..120u32 {
        let k = (i * 2).to_be_bytes();
        if i % 3 == 0 {
            t.table_remove(tb, &k, Shred::Yes).unwrap();
        } else {
            t.table_put(tb, &k, vec![0xee; 30], Shred::No).unwrap();
        }
        t.table_put(tb, &(i * 2 + 1).to_be_bytes(), vec![1; 10], Shred::No).unwrap();
    }
    t.rollback_to(sp);
    assert_eq!(rows(&mut t), want, "rolled back");
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(rows(&mut t), want, "committed");
    drop(t);
    drop(s);
    let mut s = reopen(&dev);
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(rows(&mut t), want, "reopened");
}

// spec: none (notes/local-store.md, Stamps): a memo reading the store holds until a row it read
// changes: a write, and the undo of one (a savepoint rolled back, an aborted transaction); a scan
// moves with a row under its prefix, a table's read with a row of the table or its aspect's unit;
// a row elsewhere moves nothing. A removal, a table dropped, a transaction set aside and
// dropped, and a failed commit each move what read their rows.
#[test]
fn a_memo_over_the_store_moves_with_the_rows_it_read() {
    use osis_base::memo::Memo;
    use osis_store::Transaction;
    let (dev, mut rng, mut s) = fresh(cfg());
    let (t1, a) = (tid(1), ak("name.0"));
    let memo: Memo<u8, Vec<u8>> = Memo::new("test store read");
    // 0: a row, 1: a scan, 2: a table row
    let ask = |t: &mut Transaction<'_>, k: u8| -> Vec<u8> {
        Memo::get_in(&mut (&memo, t), |c| c.0, &k, |(_, t)| {
            Ok::<_, Error>(match k {
                0 => t.get_local(b"r/a")?.unwrap_or_default(),
                1 => t.scan_local(b"r/", b"", 100)?.into_iter().flat_map(|(k, v)| [k, v].concat()).collect(),
                _ => match t.table(&t1, &a, 0)? {
                    Some(tb) => t.table_get(tb, b"k")?.unwrap_or_default(),
                    None => Vec::new(),
                },
            })
        })
        .unwrap()
    };
    let runs = || osis_base::costs::take().iter().filter(|x| x.0 == "test store read").map(|x| x.2).sum::<u64>();
    {
        let mut t = s.transaction(&mut rng).unwrap();
        t.put_local(b"r/a", b"1", Shred::No).unwrap();
        let tb = t.create_table(&t1, &a, 0).unwrap();
        t.table_put(tb, b"k", b"v".to_vec(), Shred::No).unwrap();
        t.commit().unwrap();
    }
    let mut t = s.transaction(&mut rng).unwrap();
    osis_base::costs::take();
    assert_eq!((ask(&mut t, 0), ask(&mut t, 1), ask(&mut t, 2)), (b"1".to_vec(), b"r/a1".to_vec(), b"v".to_vec()));
    assert_eq!(runs(), 3);
    t.put_local(b"q/x", b"x", Shred::No).unwrap();
    t.put_aspect(&tid(2), &a, &AspectUnit { state: b"s".to_vec() }, Shred::No).unwrap();
    assert_eq!((ask(&mut t, 0), ask(&mut t, 1), ask(&mut t, 2)), (b"1".to_vec(), b"r/a1".to_vec(), b"v".to_vec()));
    assert_eq!(runs(), 0, "rows elsewhere");
    t.put_local(b"r/b", b"2", Shred::No).unwrap();
    assert_eq!((ask(&mut t, 0), ask(&mut t, 1)), (b"1".to_vec(), b"r/a1r/b2".to_vec()));
    assert_eq!(runs(), 1, "a row under the scanned prefix");
    let sp = t.savepoint();
    t.put_local(b"r/a", b"3", Shred::No).unwrap();
    assert_eq!(ask(&mut t, 0), b"3".to_vec());
    t.rollback_to(sp);
    assert_eq!(ask(&mut t, 0), b"1".to_vec());
    assert_eq!(runs(), 2, "a write and its rollback");
    t.put_aspect(&t1, &a, &AspectUnit { state: b"u".to_vec() }, Shred::No).unwrap();
    assert_eq!(ask(&mut t, 2), b"v".to_vec());
    let tb = t.table(&t1, &a, 0).unwrap().unwrap();
    t.table_put(tb, b"k", b"w".to_vec(), Shred::No).unwrap();
    assert_eq!(ask(&mut t, 2), b"w".to_vec());
    assert_eq!(runs(), 2, "the table's aspect unit, a row of the table");
    t.put_local(b"r/a", b"4", Shred::No).unwrap();
    assert_eq!(ask(&mut t, 0), b"4".to_vec());
    drop(t);
    assert_eq!(memo.held(&0), None, "aborted, before another transaction");
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!((ask(&mut t, 0), ask(&mut t, 2)), (b"1".to_vec(), b"v".to_vec()));
    assert_eq!(runs(), 3, "a write, and the abort of it and of a table row");
    t.remove_local(b"r/a", Shred::No).unwrap();
    assert_eq!((ask(&mut t, 0), ask(&mut t, 1)), (Vec::new(), Vec::new()));
    let tb = t.table(&t1, &a, 0).unwrap().unwrap();
    let rows: Memo<(), Vec<u8>> = Memo::new("test table rows");
    let got = Memo::get_in(&mut (&rows, &mut t), |c| c.0, &(), |(_, t)| t.table_get(tb, b"k").map(Option::unwrap_or_default)).unwrap();
    assert_eq!(got, b"v".to_vec());
    t.drop_table(&t1, &a, 0).unwrap();
    assert_eq!(rows.held(&()), None, "a table dropped, read by its handle");
    assert_eq!(ask(&mut t, 2), Vec::new());
    assert_eq!(runs(), 3, "a removal, a table dropped");
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    t.put_local(b"r/a", b"5", Shred::No).unwrap();
    assert_eq!(ask(&mut t, 0), b"5".to_vec());
    drop(t.suspend().unwrap());
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(ask(&mut t, 0), Vec::new(), "a transaction set aside and dropped");
    t.put_local(b"r/a", b"6", Shred::No).unwrap();
    assert_eq!(ask(&mut t, 0), b"6".to_vec());
    dev.faults.at(0, Fault::Fail);
    assert!(t.commit().is_err());
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(ask(&mut t, 0), Vec::new(), "a failed commit");
    assert_eq!(runs(), 4);
}
