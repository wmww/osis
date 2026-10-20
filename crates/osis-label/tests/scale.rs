#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Multi-GB large value streamed within a memory bound (tier 2, release; numbers in
//! notes/testing.md, "Scale checks"): `OSIS_LARGE_MIB=1024 cargo test --release -p osis-label
//! --test scale -- --ignored --nocapture`. Blobs go to files under the target dir.

use osis_core::BlobId;
use osis_core::hash::Hasher;
use osis_crypto::{Secret32, SeededRng};
use osis_label::{BlobFetch, BlobReader, BlobSink, BlobWriter, Error, Framing, LargeParams, StringReader, ValueWriter};
use std::io::Read;
use std::path::PathBuf;
use std::time::Instant;

/// Blobs as files named by blob ID.
struct DiskBlobs(PathBuf);

impl DiskBlobs {
    fn path(&self, id: &BlobId) -> PathBuf {
        self.0.join(id.0.iter().map(|b| format!("{b:02x}")).collect::<String>())
    }
}

impl BlobSink for DiskBlobs {
    fn put(&mut self, id: BlobId, blob: Vec<u8>) -> Result<(), Error> {
        std::fs::write(self.path(&id), blob).map_err(|_| Error::Storage)
    }
}

impl BlobFetch for DiskBlobs {
    fn fetch(&mut self, id: &BlobId) -> Result<Vec<u8>, Error> {
        std::fs::read(self.path(id)).map_err(|_| Error::Missing)
    }
}

/// Peak resident set (VmHWM) in KiB.
fn peak_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = s.lines().find(|l| l.starts_with("VmHWM:")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// Resets VmHWM to the current RSS (Linux: `5` to clear_refs).
fn reset_peak() {
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
}

/// Block `i` of the seeded stream (1 MiB).
fn block(i: u64, out: &mut [u8]) {
    Hasher::new().update(b"osis scale large").update(&i.to_le_bytes()).finalize_xof(out);
}

const MIB: usize = 1 << 20;

// spec/requirements.md, Scale: multi-GB single values; large values stream, no whole value is
// ever needed in memory. spec/data-model.md §6: written with `ValueWriter` and read back with
// `StringReader`/`LargeReader`, peak RSS stays within a fixed bound.
#[test]
#[ignore]
fn multi_gb_value_streams() {
    let mib: u64 = std::env::var("OSIS_LARGE_MIB").ok().and_then(|s| s.parse().ok()).unwrap_or(1024);
    let len = mib * MIB as u64;
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("large-value");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut store = DiskBlobs(dir.clone());
    let framing = Framing { dedup: Secret32::from_bytes([7; 32]), expiry: None, tokens: Vec::new() };
    let mut rng = SeededRng::from_u64(1);
    let mut buf = vec![0u8; MIB];
    reset_peak();
    let base = peak_kib();
    let t0 = Instant::now();
    let mut want = Hasher::new();
    let (root, chunks, buffered) = {
        let mut sink = BlobWriter::new(&framing, &mut store, &mut rng);
        let mut w = ValueWriter::bytes(LargeParams::FORMAT, len);
        let mut max_buffered = 0;
        for i in 0..mib {
            block(i, &mut buf);
            want.update(&buf);
            w.write(&mut sink, &buf).unwrap();
            max_buffered = max_buffered.max(w.buffered());
        }
        let root = match w.finish(&mut sink).unwrap() {
            osis_core::Value::Link(l) => l,
            v => panic!("not a link: {v:?}"),
        };
        (root, sink.written().len(), max_buffered)
    };
    let write = t0.elapsed();
    let write_peak = peak_kib().saturating_sub(base);
    let want = want.finalize();
    reset_peak();
    let base = peak_kib();
    let t1 = Instant::now();
    let mut got = Hasher::new();
    let mut src = BlobReader::new(&framing.dedup, &mut store);
    let mut r = StringReader::open(root, &framing.dedup, &mut src, LargeParams::FORMAT, usize::MAX).unwrap();
    assert_eq!(r.len(), len);
    let mut read = 0u64;
    loop {
        let n = r.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        got.update(&buf[..n]);
        read += n as u64;
    }
    let readt = t1.elapsed();
    let read_peak = peak_kib().saturating_sub(base);
    assert_eq!(read, len);
    assert_eq!(got.finalize(), want);
    println!(
        "large value {mib} MiB: {chunks} blobs; write {write:?} ({:.0} MB/s), writer buffered at most {buffered} B, peak RSS growth {write_peak} KiB; read {readt:?} ({:.0} MB/s), peak RSS growth {read_peak} KiB",
        len as f64 / write.as_secs_f64() / 1e6,
        len as f64 / readt.as_secs_f64() / 1e6
    );
    let _ = std::fs::remove_dir_all(&dir);
    // Fixed bound, independent of the value size: one chunk (256 KiB max) plus the tree path in
    // the codec; the per-blob `written` list of the writer is 13k entries per GiB.
    assert!(write_peak < 64 * 1024 && read_peak < 64 * 1024, "peak RSS growth {write_peak} / {read_peak} KiB");
}
