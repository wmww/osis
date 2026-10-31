#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Typed units and transactions (notes/local-store.md, Units) on every backend.

use crate::common;

use common::*;
use osis_base::{BlobId, CommitId, LabelId, Ts};
use osis_crypto::SeededRng;
use osis_store::{AspectUnit, Deaths, Error, Fault, MemoryBackend, MemoryRoot, PendingKind, Shred, Store, StoreConfig};

fn ts(n: u64) -> Ts {
    Ts::from_u64(n).unwrap()
}

// spec/commits.md §4: all writes of a transaction commit together; dropping it aborts.
#[test]
fn transactions_commit_or_abort() {
    for dev in devices("txn") {
        let mut rng = SeededRng::from_u64(1);
        let mut s = create(&*dev, &mut rng);
        let (t1, a) = (tid(1), ak("/name"));
        let unit = AspectUnit { state: b"state".to_vec(), undo: b"undo".to_vec(), snapshots: vec![] };
        {
            let mut t = s.transaction(&mut rng).unwrap();
            t.put_aspect(&t1, &a, &unit, Shred::No).unwrap();
            assert_eq!(t.get_aspect(&t1, &a).unwrap(), Some(unit.clone()), "reads see own writes");
            // Dropped: aborted.
        }
        let mut t = s.transaction(&mut rng).unwrap();
        assert_eq!(t.get_aspect(&t1, &a).unwrap(), None);
        t.put_aspect(&t1, &a, &unit, Shred::No).unwrap();
        t.put_secrets(&tid(2), b"secret", Shred::No).unwrap();
        t.commit().unwrap();
        drop(s);
        let mut s = reopen(&*dev);
        let mut t = s.transaction(&mut rng).unwrap();
        assert_eq!(t.get_aspect(&t1, &a).unwrap(), Some(unit), "{}", dev.name());
        assert_eq!(t.get_secrets(&tid(2)).unwrap(), Some(b"secret".to_vec()));
        assert_eq!(t.get_aspect(&t1, &ak("/other")).unwrap(), None);
    }
}

// spec/commits.md §5: per body the node tracks the first and last death so far.
#[test]
fn death_records() {
    let dev = MemDevice::new();
    let mut rng = SeededRng::from_u64(2);
    let mut s = create(&dev, &mut rng);
    let mut t = s.transaction(&mut rng).unwrap();
    let (t1, a) = (tid(1), ak("/m"));
    let body = BlobId([9; 32]);
    assert_eq!(t.note_death(&t1, &a, &body, ts(50)).unwrap(), Deaths { first: ts(50), last: ts(50) });
    t.note_death(&t1, &a, &body, ts(70)).unwrap();
    assert_eq!(t.note_death(&t1, &a, &body, ts(40)).unwrap(), Deaths { first: ts(40), last: ts(70) });
    for b in 0..5u8 {
        t.note_death(&t1, &a, &BlobId([b; 32]), ts(1)).unwrap();
    }
    t.note_death(&t1, &ak("/n"), &BlobId([1; 32]), ts(1)).unwrap();
    let all = t.deaths(&t1, &a, None, 100).unwrap();
    assert_eq!(all.len(), 6);
    let after = t.deaths(&t1, &a, Some(&BlobId([2; 32])), 2).unwrap();
    assert_eq!(after.iter().map(|(b, _)| b.0[0]).collect::<Vec<_>>(), vec![3, 4]);
    t.drop_body(&body, &[(t1, a.clone())]).unwrap();
    assert_eq!(t.death(&t1, &a, &body).unwrap(), None);
    t.commit().unwrap();
    assert_eq!(s.epoch(), 2, "drop_body shreds");
}

// spec/crdt.md §2.3: counters never repeat, also across a whole-aspect purge and reopen.
#[test]
fn counters() {
    let dev = MemDevice::new();
    let mut rng = SeededRng::from_u64(3);
    let mut s = create(&dev, &mut rng);
    let (t1, a) = (tid(1), ak("/c"));
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.counter(&t1, &a).unwrap(), 1);
    assert_eq!(t.reserve_counters(&t1, &a, 5).unwrap(), 1);
    assert_eq!(t.reserve_counters(&t1, &a, 2).unwrap(), 6);
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    t.drop_aspect(&t1, &a).unwrap();
    t.commit().unwrap();
    drop(s);
    let mut s = reopen(&dev);
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.counter(&t1, &a).unwrap(), 8);
}

// spec/commits.md §4: pending and parked commits are stored as bytes until applied.
#[test]
fn pending_commits() {
    let dev = MemDevice::new();
    let mut rng = SeededRng::from_u64(4);
    let mut s = create(&dev, &mut rng);
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

// spec/commits.md §5: dropping destroys every local copy; notes/local-store.md, Units: wraps live in label pages; dropping one shreds its page.
#[test]
fn wraps_and_secrets() {
    let dev = MemDevice::new();
    let mut rng = SeededRng::from_u64(5);
    let mut s = create(&dev, &mut rng);
    let (l1, l2) = (LabelId([1; 16]), LabelId([2; 16]));
    let mut t = s.transaction(&mut rng).unwrap();
    for b in 0..20u8 {
        t.put_wrap(&l1, &BlobId([b; 32]), &[b; 49]).unwrap();
    }
    t.put_wrap(&l2, &BlobId([0; 32]), &[0xee; 49]).unwrap();
    t.put_secrets(&tid(7), b"role secrets", Shred::No).unwrap();
    t.commit().unwrap();
    let e = s.epoch();
    let mut t = s.transaction(&mut rng).unwrap();
    assert!(t.drop_wrap(&l1, &BlobId([3; 32])).unwrap());
    assert!(t.drop_actor_secrets(&tid(7)).unwrap());
    t.commit().unwrap();
    assert_eq!(s.epoch(), e + 1, "one rotation for the whole transaction");
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.get_wrap(&l1, &BlobId([3; 32])).unwrap(), None);
    assert_eq!(t.get_wrap(&l1, &BlobId([4; 32])).unwrap(), Some(vec![4; 49]));
    assert_eq!(t.wraps(&l1, None, 100).unwrap().len(), 19);
    assert_eq!(t.wraps(&l2, None, 100).unwrap(), vec![(BlobId([0; 32]), vec![0xee; 49])]);
    assert_eq!(t.get_secrets(&tid(7)).unwrap(), None);
}

// spec: none (node-local bookkeeping); notes/local-store.md, Units: cursor logs and the IDs-gained list.
#[test]
fn cursors_logs_local() {
    let dev = MemDevice::new();
    let mut rng = SeededRng::from_u64(6);
    let mut s = create(&dev, &mut rng);
    let mut t = s.transaction(&mut rng).unwrap();
    t.put_cursor(b"server", b"c1").unwrap();
    for i in 0..10u8 {
        assert_eq!(t.log_append(b"gained", &[i; 32]).unwrap(), u64::from(i));
    }
    t.log_append(b"other", b"x").unwrap();
    t.log_truncate(b"gained", 4).unwrap();
    let rest = t.log_scan(b"gained", 0, 100).unwrap();
    assert_eq!(rest.iter().map(|(s, _)| *s).collect::<Vec<_>>(), (4..10).collect::<Vec<_>>());
    assert_eq!(t.log_scan(b"gained", 8, 100).unwrap().len(), 2);
    assert_eq!(t.log_append(b"gained", b"y").unwrap(), 10);
    t.put_local(b"roster/1", b"a", Shred::No).unwrap();
    t.put_local(b"roster/2", b"b", Shred::No).unwrap();
    t.put_local(b"zzz", b"c", Shred::No).unwrap();
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.get_cursor(b"server").unwrap(), Some(b"c1".to_vec()));
    assert_eq!(t.scan_local(b"roster/", b"", 10).unwrap(), vec![(b"roster/1".to_vec(), b"a".to_vec()), (b"roster/2".to_vec(), b"b".to_vec())]);
    assert!(t.remove_local(b"zzz", Shred::No).unwrap());
}

// spec/commits.md §4: one storage transaction per atomic apply; notes/local-store.md, Units: blob ciphertexts sit beside the units, inside transactions.
#[test]
fn blobs() {
    for dev in devices("blobs") {
        let mut rng = SeededRng::from_u64(7);
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
    let mut rng = SeededRng::from_u64(8);
    assert_eq!(Store::open(Box::new(b.clone()), Box::new(r.clone()), cfg()).err(), Some(Error::NoStore));
    Store::create(Box::new(b.clone()), Box::new(r.clone()), cfg(), &mut rng).unwrap();
    assert_eq!(Store::create(Box::new(b.clone()), Box::new(r.clone()), cfg(), &mut rng).err(), Some(Error::Exists));
    let mut s = Store::open(Box::new(b), Box::new(r), Default::default()).unwrap();
    assert_eq!(s.config().arity, 8);
    let mut t = s.transaction(&mut rng).unwrap();
    let big_ak = ak(&format!("/{}", "a".repeat(200)));
    assert!(matches!(t.put_aspect(&tid(1), &big_ak, &AspectUnit::default(), Shred::No), Err(Error::Misuse(_))));
}

// spec/commits.md §4: an aborted transaction that spilled leaves nothing that harms later commits.
#[test]
fn abort_after_spill() {
    let dev = MemDevice::new();
    let mut rng = SeededRng::from_u64(10);
    let cfg = StoreConfig { spill_bytes: 100, ..cfg() };
    let mut s = Store::create(dev.backend(), dev.root(), cfg, &mut rng).unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    let tb = t.create_table(&tid(1), &ak("/t"), 0).unwrap();
    for i in 0..20u32 {
        t.table_put(tb, &i.to_be_bytes(), vec![1; 30], Shred::No).unwrap();
    }
    drop(t);
    let mut t = s.transaction(&mut rng).unwrap();
    let tb = t.create_table(&tid(1), &ak("/t"), 0).unwrap();
    t.table_put(tb, b"k", vec![2; 5], Shred::No).unwrap();
    t.commit().unwrap();
    assert!(s.backend().scan_prefix(b"j", 10).unwrap().is_empty(), "aborted spill rolled back");
    drop(s);
    let mut s = Store::open(dev.backend(), dev.root(), cfg).unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    let tb = t.table(&tid(1), &ak("/t"), 0).unwrap().unwrap();
    assert_eq!(t.table_get(tb, b"k").unwrap(), Some(vec![2; 5]));
    assert_eq!(t.table_len(tb).unwrap(), 1);
}

// spec/commits.md §4: rolling back a transaction never deletes a blob committed before it
// (content-addressed re-puts are normal).
#[test]
fn rollback_keeps_committed_blob() {
    for shredding in [false, true] {
        let dev = MemDevice::new();
        let mut rng = SeededRng::from_u64(11);
        let cfg = StoreConfig { spill_bytes: 100, ..cfg() };
        let mut s = Store::create(dev.backend(), dev.root(), cfg, &mut rng).unwrap();
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
        let mut rng = SeededRng::from_u64(12);
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
    let dev = MemDevice::new();
    let mut rng = SeededRng::from_u64(3);
    let mut s = create(&dev, &mut rng);
    let (t1, a, b) = (tid(1), ak("/mem"), ak("/dur"));
    let unit = AspectUnit { state: b"m".to_vec(), undo: vec![], snapshots: vec![] };
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
        assert!(t.is_memory_aspect(&t1, &a) && !t.is_memory_aspect(&t1, &b));
        t.reserve_counters(&t1, &a, 3).unwrap();
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
        assert_eq!(t.counter(&t1, &a).unwrap(), 4);
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
    assert_eq!(t.counter(&t1, &a).unwrap(), 1);
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
    let dev = MemDevice::new();
    let mut rng = SeededRng::from_u64(12);
    let cfg = StoreConfig { spill_bytes: 100, ..cfg() };
    let mut s = Store::create(dev.backend(), dev.root(), cfg, &mut rng).unwrap();
    let ix = {
        let mut t = s.transaction(&mut rng).unwrap();
        let ix = t.index(b"ix").unwrap();
        t.commit().unwrap();
        ix
    };
    let writes = dev.faults.writes();
    let mut t = s.transaction(&mut rng).unwrap();
    t.set_memory(true);
    let tb = t.create_table(&tid(1), &ak("/m"), 0).unwrap();
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
