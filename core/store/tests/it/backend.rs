#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The trait-generic `Backend` suite, run against every backend (notes/architecture.md §2).
//! spec: none (storage abstraction; spec/commits.md §4 needs atomic batches).

use osis_base::BlobId;
use osis_store::{Backend, BackendError, Fault, Faults, MemoryBackend, WriteBatch};

fn suite(b: &mut dyn Backend) {
    // Empty.
    assert_eq!(b.get(b"a").unwrap(), None);
    assert!(b.scan(b"", None, 10).unwrap().is_empty());

    // Batch puts, ordered scans, ranges, limits, prefixes.
    let mut w = WriteBatch::new();
    for k in [&b"b"[..], b"a", b"ab", b"c", b"\xff\xff"] {
        w.put(k.to_vec(), [k, b"!"].concat());
    }
    b.commit(w).unwrap();
    assert_eq!(b.get(b"ab").unwrap(), Some(b"ab!".to_vec()));
    let keys = |v: Vec<(Vec<u8>, Vec<u8>)>| v.into_iter().map(|(k, _)| k).collect::<Vec<_>>();
    assert_eq!(keys(b.scan(b"", None, 10).unwrap()), vec![b"a".to_vec(), b"ab".to_vec(), b"b".to_vec(), b"c".to_vec(), b"\xff\xff".to_vec()]);
    assert_eq!(keys(b.scan(b"ab", Some(b"c"), 10).unwrap()), vec![b"ab".to_vec(), b"b".to_vec()]);
    assert_eq!(keys(b.scan(b"a", None, 2).unwrap()), vec![b"a".to_vec(), b"ab".to_vec()]);
    assert!(b.scan(b"c", Some(b"a"), 10).unwrap().is_empty());
    assert_eq!(keys(b.scan_prefix(b"a", 10).unwrap()), vec![b"a".to_vec(), b"ab".to_vec()]);
    assert_eq!(keys(b.scan_prefix(b"\xff", 10).unwrap()), vec![b"\xff\xff".to_vec()]);

    // Overwrite and delete in one batch apply in order.
    let mut w = WriteBatch::new();
    w.put(b"a".to_vec(), b"1".to_vec());
    w.delete(b"b".to_vec());
    w.put(b"d".to_vec(), b"x".to_vec());
    w.delete(b"d".to_vec());
    b.commit(w).unwrap();
    assert_eq!(b.get(b"a").unwrap(), Some(b"1".to_vec()));
    assert_eq!(b.get(b"b").unwrap(), None);
    assert_eq!(b.get(b"d").unwrap(), None);

    // Blobs.
    let id = BlobId([7; 32]);
    assert_eq!(b.get_blob(&id).unwrap(), None);
    let mut w = WriteBatch::new();
    w.put_blob(id, b"hello world".to_vec());
    b.commit(w).unwrap();
    assert_eq!(b.get_blob(&id).unwrap(), Some(b"hello world".to_vec()));
    assert_eq!(b.blob_len(&id).unwrap(), Some(11));
    assert_eq!(b.read_blob(&id, 6, 100).unwrap(), Some(b"world".to_vec()));
    assert_eq!(b.read_blob(&id, 20, 1).unwrap(), Some(Vec::new()));
    let mut w = WriteBatch::new();
    w.delete_blob(id);
    b.commit(w).unwrap();
    assert_eq!(b.get_blob(&id).unwrap(), None);
    assert_eq!(b.blob_len(&id).unwrap(), None);

    // Large values.
    let big = vec![0xa5u8; 1 << 20];
    let mut w = WriteBatch::new();
    w.put(b"big".to_vec(), big.clone());
    b.commit(w).unwrap();
    assert_eq!(b.get(b"big").unwrap(), Some(big));
}

// spec: none (backend conformance)
#[test]
fn memory_backend_suite() {
    suite(&mut MemoryBackend::new());
}

// spec/commits.md §4: one storage transaction per atomic apply; a failed or crashed batch has no effect.
#[test]
fn memory_faults() {
    let faults = Faults::new();
    let mut b = MemoryBackend::with_faults(faults.clone());
    let batch = |k: &[u8]| {
        let mut w = WriteBatch::new();
        w.put(k.to_vec(), b"v".to_vec());
        w.put([k, b"2"].concat(), b"v".to_vec());
        w
    };
    faults.at(1, Fault::Fail);
    b.commit(batch(b"a")).unwrap();
    assert_eq!(b.commit(batch(b"b")), Err(BackendError::Fault));
    b.commit(batch(b"c")).unwrap();
    assert_eq!(b.get(b"b").unwrap(), None);
    assert_eq!(b.get(b"b2").unwrap(), None);
    faults.at(0, Fault::Crash);
    assert_eq!(b.commit(batch(b"d")), Err(BackendError::Crashed));
    assert_eq!(b.commit(batch(b"e")), Err(BackendError::Crashed));
    assert!(faults.crashed());
    faults.revive();
    let reopened = b.clone();
    assert_eq!(reopened.get(b"c2").unwrap(), Some(b"v".to_vec()));
    assert_eq!(reopened.get(b"d").unwrap(), None);
}

mod file {
    use super::*;
    use osis_store::RedbBackend;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("osis-store-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // spec: none (backend conformance)
    #[test]
    fn redb_backend_suite() {
        let dir = temp_dir("suite");
        suite(&mut RedbBackend::open(&dir.join("db")).unwrap());
        // Durable across reopen.
        let b = RedbBackend::open(&dir.join("db")).unwrap();
        assert_eq!(b.get(b"a").unwrap(), Some(b"1".to_vec()));
        drop(b);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // spec/requirements.md Deletion (forward secure: nothing on the device yields what it may no
    // longer read): store files made before files were created owner-only become so on open.
    #[cfg(unix)]
    #[test]
    fn existing_store_files_become_owner_only_spec_requirements_deletion() {
        use osis_store::{FileRoot, RootStorage};
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("modes");
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let open = |p: &std::path::Path| std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
        drop(RedbBackend::open(&dir.join("db")).unwrap());
        let mut r = FileRoot::new(dir.join("root"));
        r.store(&osis_store::RootRecord { epoch: 1, key: osis_crypto::Secret32::from_bytes([1; 32]) }).unwrap();
        for p in [dir.join("db"), dir.join("root")] {
            open(&p);
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        drop(RedbBackend::open(&dir.join("db")).unwrap());
        assert!(FileRoot::new(dir.join("root")).load().unwrap().is_some());
        assert_eq!(osis_store::restrict_to_owner(&dir), None);
        assert_eq!(mode(&dir.join("db")), 0o600);
        assert_eq!(mode(&dir.join("root")), 0o600);
        assert_eq!(mode(&dir), 0o700);
        // a symlink is never followed; a missing file is no error
        let other = dir.join("other");
        std::fs::write(&other, b"x").unwrap();
        open(&other);
        std::os::unix::fs::symlink(&other, dir.join("link")).unwrap();
        assert_eq!(osis_store::restrict_to_owner(&dir.join("link")), None);
        assert_eq!(mode(&other), 0o644);
        assert_eq!(osis_store::restrict_to_owner(&dir.join("missing")), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
