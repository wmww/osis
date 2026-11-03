//! HostStore over the redb file backend and a file key root: state survives closing and
//! reopening the files (spec/sync.md §4). Tier 2 (disk): `cargo test --workspace --test it file:: -- --ignored`.
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
        s.schedule_delete(&l, &osis_label::blob_id(&blobs[1]), T0 + 100).unwrap();
        s.log_head(&l).unwrap()
    };
    let mut s = open(&dir, clock, HostPolicy::default(), 9);
    assert_eq!(s.log_head(&l).unwrap(), (log_id, head));
    assert_eq!(s.path(&l).unwrap(), vec![f.genesis.clone()]);
    assert!(s.claim_set(&l, &f.genesis.id()).unwrap().is_some());
    assert!(s.tombstoned(&l, &osis_label::blob_id(&blobs[0])).unwrap());
    assert_eq!(s.blob(&osis_label::blob_id(&blobs[2])).unwrap().as_deref(), Some(&blobs[2][..]));
    assert_eq!(s.blob(&osis_label::blob_id(&blobs[0])).unwrap(), None);
    s.sweep(T0 + 100, 1024).unwrap();
    let last = s.log_after(&l, head, 10).unwrap().unwrap();
    assert_eq!(last.iter().map(|r| r.1.clone()).collect::<Vec<_>>(), vec![LogRecord::Deleted(osis_label::blob_id(&blobs[1]))]);
    assert_eq!(s.live_ids(&l).unwrap(), vec![osis_label::blob_id(&blobs[2])]);
    drop(s);
    std::fs::remove_dir_all(&dir).unwrap();
}

// spec: none (cost, notes/sync.md Hub stall bounds): one whole-space Reconcile over a label of
// `OSIS_SCALE_N` (default 10^5) live entries on redb, against 1024 puts in one store transaction. By hand,
// release: `cargo test --release -p osis-host --test it -- --ignored reconcile_whole_space_budget --nocapture`
#[test]
#[ignore]
fn reconcile_whole_space_budget() {
    use osis_proto::rbsr::{self, Bound};
    use osis_proto::{Mode, Range};
    let n = osis_base::testenv::u64_var("OSIS_SCALE_N").unwrap_or(100_000);
    let dir = std::env::temp_dir().join(format!("osis-host-rfp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let f = Fixture::new(0x10);
    let l: LabelId = f.label;
    let mut s = open(&dir, Arc::new(ManualClock::new(WallMs(T0))), HostPolicy::unlimited(), 1);
    s.push_step(&l, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
    let puts = |s: &mut HostStore, r: std::ops::Range<u64>| {
        s.defer_durability();
        let t = std::time::Instant::now();
        for i in r {
            assert_eq!(s.put(&l, put(&osis_proto::examples::blob(i))).unwrap(), Code::OK);
        }
        s.durable().unwrap();
        t.elapsed()
    };
    eprintln!("fill {n}: {:?}", puts(&mut s, 0..n));
    let ranges = vec![Range { lower: Bound::empty(), upper: Bound::empty(), mode: Mode::Fingerprint([0; 16]) }];
    for _ in 0..3 {
        let t = std::time::Instant::now();
        let ids = s.live_ids_in(&l, &osis_base::BlobId([0; 32]), None).unwrap();
        assert_eq!(ids.len() as u64, n);
        let out = rbsr::respond_in(&ranges, &[ids]).unwrap();
        assert_eq!(out.len(), rbsr::SPLIT);
        eprintln!("whole-space Reconcile: {:?}", t.elapsed());
    }
    eprintln!("1024 puts, one commit: {:?}", puts(&mut s, n..n + 1024));
    drop(s);
    std::fs::remove_dir_all(&dir).unwrap();
}

// spec: none (cost, notes/testing.md Performance budgets, host): hub-sized batches on redb with
// its fsyncs, one store commit each: 1 KiB entries uploaded 64 per batch, deleted 64 per batch,
// and single-entry batches (an upload, then its delete: each delete batch a shredding commit).
// By hand, release: `cargo test --release -p osis-host --test it -- --ignored host_throughput_budget --nocapture`
#[test]
#[ignore]
fn host_throughput_budget() {
    const BATCH: u64 = 64;
    const BATCHES: u64 = 40;
    const SINGLES: u64 = 200;
    let dir = std::env::temp_dir().join(format!("osis-host-tput-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let f = Fixture::new(0x10);
    let l: LabelId = f.label;
    let mut s = open(&dir, Arc::new(ManualClock::new(WallMs(T0))), HostPolicy::unlimited(), 1);
    s.push_step(&l, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
    let blobs: Vec<Vec<u8>> = (0..BATCH * BATCHES + SINGLES).map(|i| osis_proto::examples::blob_sized(i, 0, vec![], 1024)).collect();
    let id = |i: u64| osis_label::blob_id(&blobs[i as usize]);
    let t = std::time::Instant::now();
    for b in 0..BATCHES {
        s.defer_durability();
        for i in b * BATCH..(b + 1) * BATCH {
            assert_eq!(s.put(&l, put(&blobs[i as usize])).unwrap(), Code::OK);
        }
        s.durable().unwrap();
    }
    let up = t.elapsed();
    let t = std::time::Instant::now();
    for b in 0..BATCHES {
        s.defer_durability();
        for i in b * BATCH..(b + 1) * BATCH {
            assert_eq!(s.delete(&l, &id(i), T0).unwrap(), Code::OK);
        }
        s.durable().unwrap();
    }
    let del = t.elapsed();
    let t = std::time::Instant::now();
    for i in BATCH * BATCHES..BATCH * BATCHES + SINGLES {
        s.defer_durability();
        assert_eq!(s.put(&l, put(&blobs[i as usize])).unwrap(), Code::OK);
        s.durable().unwrap();
        s.defer_durability();
        assert_eq!(s.delete(&l, &id(i), T0).unwrap(), Code::OK);
        s.durable().unwrap();
    }
    let single = t.elapsed();
    let n = (BATCH * BATCHES) as f64;
    let (up_rate, del_rate, single_ms) = (n / up.as_secs_f64(), n / del.as_secs_f64(), single.as_secs_f64() * 1e3 / SINGLES as f64);
    eprintln!("uploads {up_rate:.0}/s, deletes {del_rate:.0}/s (batches of {BATCH}); one upload batch and one delete batch: {single_ms:.2} ms");
    assert!(up_rate >= 1000.0 && del_rate >= 1000.0 && single_ms < 20.0, "over the host budget");
    drop(s);
    std::fs::remove_dir_all(&dir).unwrap();
}
