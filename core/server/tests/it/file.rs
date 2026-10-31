//! BackendStore over the redb file backend: state survives closing and reopening the file
//! (spec/sync.md §4). Tier 2 (disk): `cargo test --workspace --test it file:: -- --ignored`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_base::{LabelId, ManualClock, WallMs};
use osis_crypto::{SeededRng, Signature};
use osis_proto::examples::Fixture;
use osis_proto::{Code, LabelStore, LogRecord, Put};
use osis_server::{BackendStore, Policy};
use osis_store::RedbBackend;
use std::sync::Arc;

const T0: u64 = 1_700_000_000_000;

fn put(b: &[u8]) -> Put<'_> {
    Put { blob_id: osis_label::blob_id(b), blob: b, wrap: [1; 49], stamp: Some(Signature([2; 64])), expiry: None, ephemeral: false, presence: false, tie: 0, replaces: &[], now: 0 }
}

// spec/sync.md §4: registration path, entries, pending deletions, tombstones and the log persist in the file; a reopened node resumes sweeps
#[test]
#[ignore]
fn redb_store_survives_reopen() {
    let dir = std::env::temp_dir().join(format!("osis-server-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("server.redb");
    let _ = std::fs::remove_file(&path);
    let clock = Arc::new(ManualClock::new(WallMs(T0)));
    let f = Fixture::new(0x10);
    let l: LabelId = f.label;
    let blobs: Vec<Vec<u8>> = (1..=3).map(Fixture::blob).collect();
    let (log_id, head) = {
        let mut s = BackendStore::open(RedbBackend::open(&path).unwrap(), clock.clone(), Policy::default(), &mut SeededRng::from_seed([1; 32])).unwrap();
        s.push_step(&l, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
        for b in &blobs {
            assert_eq!(s.put(&l, put(b)).unwrap(), Code::OK);
        }
        s.delete(&l, &osis_label::blob_id(&blobs[0]), T0).unwrap();
        s.schedule_delete(&l, &osis_label::blob_id(&blobs[1]), T0 + 100).unwrap();
        s.log_head(&l).unwrap()
    };
    let mut s = BackendStore::open(RedbBackend::open(&path).unwrap(), clock, Policy::default(), &mut SeededRng::from_seed([9; 32])).unwrap();
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
// `OSIS_SCALE_N` (default 10^5) live entries on redb, against 1024 lazily committed puts. By hand,
// release: `cargo test --release -p osis-server --test it -- --ignored reconcile_whole_space_budget --nocapture`
#[test]
#[ignore]
fn reconcile_whole_space_budget() {
    use osis_proto::rbsr::{self, Bound};
    use osis_proto::{Mode, Range};
    let n = osis_base::testenv::u64_var("OSIS_SCALE_N").unwrap_or(100_000);
    let dir = std::env::temp_dir().join(format!("osis-server-rfp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("server.redb");
    let _ = std::fs::remove_file(&path);
    let f = Fixture::new(0x10);
    let l: LabelId = f.label;
    let mut s = BackendStore::open(RedbBackend::open(&path).unwrap(), Arc::new(ManualClock::new(WallMs(T0))), Policy::unlimited(), &mut SeededRng::from_seed([1; 32])).unwrap();
    s.push_step(&l, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
    let puts = |s: &mut BackendStore<RedbBackend>, r: std::ops::Range<u64>| {
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
    eprintln!("1024 puts, one fsync: {:?}", puts(&mut s, n..n + 1024));
    drop(s);
    std::fs::remove_dir_all(&dir).unwrap();
}
