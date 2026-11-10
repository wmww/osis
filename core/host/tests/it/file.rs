//! HostStore over the redb file backend and a file key root: state survives closing and
//! reopening the files (spec/sync.md §4). By hand (disk): `cargo test -p osis-host --test it -- --ignored file::`; the batch-write count runs on
//! the memory backend (default tests).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_base::{LabelId, ManualClock, WallMs};
use osis_crypto::{SeededRng, Signature};
use osis_proto::examples::Fixture;
use osis_proto::{Code, LabelStore, LogRecord, Put};
use osis_host::{HostStore, HostPolicy};
use osis_store::{FileRoot, RedbBackend, Store, StoreConfig};
use std::sync::Arc;

const T0: u64 = 1_700_000_000_000;

/// The host store in `dir` (`host.redb`, key root `host.root`), created on first use.
fn open(dir: &std::path::Path, clock: Arc<ManualClock>, policy: HostPolicy, seed: u8) -> HostStore {
    let (b, r) = (Box::new(RedbBackend::open(&dir.join("host.redb")).unwrap()), Box::new(FileRoot::new(dir.join("host.root"))));
    let store = Store::open_or_create(b, r, StoreConfig::default(), &mut SeededRng::from_seed([seed; 32])).unwrap();
    HostStore::open(store, clock, policy, Box::new(SeededRng::from_seed([seed; 32]))).unwrap()
}

fn put(b: &[u8]) -> Put<'_> {
    Put { blob_id: osis_label::blob_id(b), blob: b, wrap: [1; osis_crypto::WRAP_LEN], stamp: Some(Signature([2; 64])), expiry: None, ephemeral: false, replaces: &[], now: 0 }
}

// spec/sync.md §4: registration path, entries, pending deletions, tombstones and the log persist in the file; a reopened node resumes sweeps
#[test]
#[ignore]
fn redb_store_survives_reopen() {
    let dir = std::env::temp_dir().join(format!("osis-host-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let clock = Arc::new(ManualClock::new(WallMs(T0)));
    let f = Fixture::new(0x10);
    let l: LabelId = f.label;
    let blobs: Vec<Vec<u8>> = (1..=3).map(Fixture::blob).collect();
    let (log_id, head) = {
        let mut s = open(&dir, clock.clone(), HostPolicy::default(), 1);
        s.push_step(&l, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
        for b in &blobs {
            assert_eq!(s.put(&l, put(b)).unwrap(), Code::OK);
        }
        s.delete(&l, &osis_label::blob_id(&blobs[0]), T0).unwrap();
        s.log_head(&l).unwrap()
    };
    let mut s = open(&dir, clock, HostPolicy::default(), 9);
    assert_eq!(s.log_head(&l).unwrap(), (log_id, head));
    assert_eq!(s.path(&l).unwrap(), vec![f.genesis.clone()]);
    assert!(s.claim_set(&l, &f.genesis.id()).unwrap().is_some());
    assert!(s.tombstoned(&l, &osis_label::blob_id(&blobs[0])).unwrap());
    assert_eq!(s.blob(&osis_label::blob_id(&blobs[2])).unwrap().as_deref(), Some(&blobs[2][..]));
    assert_eq!(s.blob(&osis_label::blob_id(&blobs[0])).unwrap(), None);
    s.delete(&l, &osis_label::blob_id(&blobs[1]), T0 + 100).unwrap();
    let last = s.log_after(&l, head, 10).unwrap().unwrap();
    assert_eq!(last.iter().map(|r| r.1.clone()).collect::<Vec<_>>(), vec![LogRecord::Deleted(osis_label::blob_id(&blobs[1]))]);
    assert_eq!(s.live_ids(&l).unwrap(), vec![osis_label::blob_id(&blobs[2])]);
    drop(s);
    std::fs::remove_dir_all(&dir).unwrap();
}

// spec: none (cost, spec/requirements.md Scale; notes/testing.md Performance budgets, host): a
// hub-sized batch is one store commit whatever the store holds: durable writes (backend commits
// and key-root writes) for 64 uploads in one batch, 64 deletes in one batch, and a single upload
// then its delete (each delete batch a shredding commit) are the same at n and 10n entries held.
// Counted over the memory backend (default tests).
#[test]
fn host_batch_writes_do_not_grow_with_entries() {
    use osis_store::{Faults, MemoryBackend, MemoryRoot};
    let writes = |held: u64| {
        let faults = Faults::new();
        let (b, r) = (MemoryBackend::with_faults(faults.clone()), MemoryRoot::with_faults(faults.clone()));
        let store = Store::create(Box::new(b), Box::new(r), StoreConfig::default(), &mut SeededRng::from_seed([1; 32])).unwrap();
        let mut s = HostStore::open(store, Arc::new(ManualClock::new(WallMs(T0))), HostPolicy::unlimited(), Box::new(SeededRng::from_seed([1; 32]))).unwrap();
        let f = Fixture::new(0x10);
        let l: LabelId = f.label;
        s.push_step(&l, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
        let blobs: Vec<Vec<u8>> = (0..held + 65).map(|i| osis_proto::examples::blob_sized(i, 0, vec![], 1024)).collect();
        let id = |i: u64| osis_label::blob_id(&blobs[i as usize]);
        let batch = |s: &mut HostStore, f: &mut dyn FnMut(&mut HostStore)| {
            let w0 = faults.writes();
            s.defer_durability();
            f(s);
            s.durable().unwrap();
            faults.writes() - w0
        };
        for k in 0..held.div_ceil(64) {
            batch(&mut s, &mut |s| {
                for i in k * 64..held.min((k + 1) * 64) {
                    assert_eq!(s.put(&l, put(&blobs[i as usize])).unwrap(), Code::OK);
                }
            });
        }
        let up = batch(&mut s, &mut |s| {
            for i in held..held + 64 {
                assert_eq!(s.put(&l, put(&blobs[i as usize])).unwrap(), Code::OK);
            }
        });
        let del = batch(&mut s, &mut |s| {
            for i in held..held + 64 {
                assert_eq!(s.delete(&l, &id(i), T0).unwrap(), Code::OK);
            }
        });
        let one = held + 64;
        let pair = batch(&mut s, &mut |s| assert_eq!(s.put(&l, put(&blobs[one as usize])).unwrap(), Code::OK)) + batch(&mut s, &mut |s| assert_eq!(s.delete(&l, &id(one), T0).unwrap(), Code::OK));
        assert_eq!(s.live_ids(&l).unwrap().len() as u64, held);
        (up, del, pair)
    };
    let (small, big) = (writes(100), writes(1000));
    assert_eq!(small, big, "(64 uploads, 64 deletes, one upload and its delete): durable writes at 100 and 1000 entries");
    assert!(small.0 <= 3 && small.1 <= 3 && small.2 <= 5, "a batch is one store commit (a delete's with its shredding root writes): {small:?}");
}
