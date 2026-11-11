//! Large values stream (spec/requirements.md Scale): work counted at n and 10n MiB (default tests), and a
//! multi-GB value's peak memory by hand: `OSIS_LARGE_MIB=1024 cargo test --release -p osis-label
//! --test it -- --ignored scale::multi_gb_value_streams --nocapture` (blobs as files under the
//! target dir).

use osis_base::BlobId;
use osis_base::hash::Hasher;
use osis_crypto::{Secret32, SeededRng};
use osis_label::{BlobFetch, BlobReader, BlobSink, BlobWriter, Error, Framing, LargeParams, StringReader, ValueWriter};
use std::io::Read;
use std::path::PathBuf;
use std::collections::HashMap;

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

/// Blobs in memory, counting puts, the largest one and fetches.
#[derive(Default)]
struct Counted {
    blobs: HashMap<BlobId, Vec<u8>>,
    puts: usize,
    largest: usize,
    fetches: usize,
}

impl BlobSink for Counted {
    fn put(&mut self, id: BlobId, blob: Vec<u8>) -> Result<(), Error> {
        self.puts += 1;
        self.largest = self.largest.max(blob.len());
        self.blobs.insert(id, blob);
        Ok(())
    }
}

impl BlobFetch for Counted {
    fn fetch(&mut self, id: &BlobId) -> Result<Vec<u8>, Error> {
        self.fetches += 1;
        self.blobs.get(id).cloned().ok_or(Error::Missing)
    }
}

/// Writes a value of `mib` MiB of the seeded stream into `store` and reads it back whole,
/// checking its bytes: the writer's largest buffer.
fn stream<S: BlobSink + BlobFetch>(mib: u64, store: &mut S) -> usize {
    let len = mib * MIB as u64;
    let framing = Framing { dedup: Secret32::from_bytes([7; 32]), expiry: None, keys: Vec::new(), blind: [0; 16] };
    let mut rng = SeededRng::from_u64(0);
    let mut buf = vec![0u8; MIB];
    let mut want = Hasher::new();
    let (root, buffered) = {
        let mut sink = BlobWriter::new(&framing, store, &mut rng);
        let mut w = ValueWriter::bytes(LargeParams::FORMAT, len);
        let mut max_buffered = 0;
        for i in 0..mib {
            block(i, &mut buf);
            want.update(&buf);
            w.write(&mut sink, &buf).unwrap();
            max_buffered = max_buffered.max(w.buffered());
        }
        let root = match w.finish(&mut sink).unwrap() {
            osis_base::Value::Link(l) => *l,
            v => panic!("not a link: {v:?}"),
        };
        (root, max_buffered)
    };
    let mut got = Hasher::new();
    let mut src = BlobReader::new(&framing.dedup, store);
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
    assert_eq!(read, len);
    assert_eq!(got.finalize(), want.finalize());
    buffered
}

// spec/requirements.md, Scale: large values stream; spec/data-model.md §6: from n to 10n MiB the
// blobs written grow linearly, reading back fetches each blob once, and neither the writer's
// buffer nor the largest blob grows (no whole value held). Counted.
#[test]
fn large_value_work_is_linear() {
    let run = |mib: u64| {
        let mut c = Counted::default();
        let buffered = stream(mib, &mut c);
        assert_eq!(c.fetches, c.puts, "{mib} MiB: each blob fetched once");
        (c.puts, c.largest, buffered)
    };
    let (small, big) = (run(2), run(20));
    assert!(big.0 >= 8 * small.0 && big.0 <= 12 * small.0, "blobs {} at 2 MiB, {} at 20", small.0, big.0);
    // one chunk (at most 256 KiB) and its framing
    assert!(small.1.max(big.1) <= 320 * 1024, "largest blob {} at 2 MiB, {} at 20", small.1, big.1);
    assert!(big.2 <= small.2.max(256 * 1024), "writer buffered {} at 2 MiB, {} at 20", small.2, big.2);
}

// spec/requirements.md, Scale: multi-GB single values; large values stream, no whole value is
// ever needed in memory. spec/data-model.md §6: written with `ValueWriter` and read back with
// `StringReader`/`LargeReader`, peak RSS stays within a fixed bound.
#[test]
#[ignore = "memory: by hand, release"]
fn multi_gb_value_streams() {
    let mib: u64 = std::env::var("OSIS_LARGE_MIB").ok().and_then(|s| s.parse().ok()).unwrap_or(1024);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("large-value");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut store = DiskBlobs(dir.clone());
    reset_peak();
    let base = peak_kib();
    let buffered = stream(mib, &mut store);
    let peak = peak_kib().saturating_sub(base);
    println!("large value {mib} MiB: writer buffered at most {buffered} B, peak RSS growth {peak} KiB (write and read)");
    let _ = std::fs::remove_dir_all(&dir);
    // Fixed bound, independent of the value size: one chunk (256 KiB max) plus the tree path in
    // the codec; the per-blob `written` list of the writer is 13k entries per GiB.
    assert!(peak < 64 * 1024, "peak RSS growth {peak} KiB");
}
