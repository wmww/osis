//! BackendStore over the redb file backend: state survives closing and reopening the file
//! (spec/sync.md §4). Tier 2 (disk): `cargo test -p osis-server --features file-backend -- --ignored`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
#![cfg(feature = "file-backend")]

use osis_core::{LabelId, ManualClock, WallMs};
use osis_crypto::{SeededRng, Signature};
use osis_proto::examples::Fixture;
use osis_proto::{Code, LabelStore, LogRecord, Put};
use osis_server::{BackendStore, Policy};
use osis_store::RedbBackend;
use std::sync::Arc;

const T0: u64 = 1_700_000_000_000;

fn put(b: &[u8]) -> Put<'_> {
    Put { blob_id: osis_label::blob_id(b), blob: b, wrap: [1; 49], stamp: Some(Signature([2; 64])), expiry: None }
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
    s.sweep(T0 + 100).unwrap();
    let last = s.log_after(&l, head, 10).unwrap().unwrap();
    assert_eq!(last.iter().map(|r| r.1.clone()).collect::<Vec<_>>(), vec![LogRecord::Deleted(osis_label::blob_id(&blobs[1]))]);
    assert_eq!(s.live_ids(&l).unwrap(), vec![osis_label::blob_id(&blobs[2])]);
    drop(s);
    std::fs::remove_dir_all(&dir).unwrap();
}
