//! Scale checks over the crdt paging (tier 2, release; numbers in notes/testing.md, "Scale
//! checks"): `cargo test --release -p osis-bench --test scale -- --ignored --nocapture`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_core::{Link, Tid, Ts, Value};
use osis_crdt::{AnyView, CounterRange, DeltaCtx, DeltaKind, Fragment, Frontiers, MemoryPages, PageError, PageSink, Snapshot, Source, Writer, create, encode_snapshot};
use std::collections::HashSet;
use std::time::Instant;

/// Pages by content hash: counts pages and bytes not seen before.
struct Seen {
    inner: MemoryPages,
    hashes: HashSet<[u8; 32]>,
    new_pages: usize,
    new_bytes: usize,
    puts: usize,
}

impl PageSink for Seen {
    fn put(&mut self, plaintext: &[u8]) -> Result<Link, PageError> {
        self.puts += 1;
        if self.hashes.insert(osis_core::hash::hash(plaintext)) {
            self.new_pages += 1;
            self.new_bytes += plaintext.len();
        }
        self.inner.put(plaintext)
    }
}

fn ts(t: u64) -> Ts {
    Ts::from_u64(t << 16).unwrap_or_default()
}

fn snapshot(state: &Fragment, pages: &mut Seen) -> usize {
    let cx = DeltaCtx { ts: ts(1 << 30), own: Source::node(Tid::from_bytes([9; 15])), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
    let s = Snapshot { absorbed: Default::default(), authors: Default::default(), nonce: [0; 16], fragment: state.clone(), frontiers: Frontiers::default() };
    encode_snapshot(&s, &cx, Some(pages)).unwrap().len()
}

// spec/crdt.md §8, spec/requirements.md (Scale: a change inside a huge value costs O(change)): a
// paged snapshot of a map at 10^4..10^6 keys, one entry changed, re-encoded: only the pages
// around the change (and the link path) are new. `OSIS_SCALE_MAX` caps the size.
#[test]
#[ignore]
fn big_map_snapshot_rewrite() {
    let max: usize = std::env::var("OSIS_SCALE_MAX").ok().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let mut n = 10_000usize;
    while n <= max {
        let kv = (0..n as i64).map(|i| (Value::Int(i), Value::Int(i))).collect();
        let mut w = Writer::new(ts(1), Source::node(Tid::from_bytes([1; 15])), 1);
        let mut st = Fragment::default();
        st.join(create(&mut w, &AnyView, &Value::Map(kv)).unwrap());
        let mut pages = Seen { inner: MemoryPages::new(), hashes: HashSet::new(), new_pages: 0, new_bytes: 0, puts: 0 };
        let t0 = Instant::now();
        let top = snapshot(&st, &mut pages);
        let full = t0.elapsed();
        let (all_pages, all_bytes) = (pages.new_pages, pages.new_bytes);
        // One entry changed by another writer.
        let mut w2 = Writer::new(ts(2), Source::node(Tid::from_bytes([2; 15])), 1);
        let one = [(Value::Int(n as i64 / 2), Value::Int(-1))].into_iter().collect();
        st.join(create(&mut w2, &AnyView, &Value::Map(one)).unwrap());
        (pages.new_pages, pages.new_bytes, pages.puts) = (0, 0, 0);
        let t1 = Instant::now();
        snapshot(&st, &mut pages);
        let again = t1.elapsed();
        println!(
            "map {n} keys: snapshot {all_pages} pages {all_bytes} B (+{top} B top) in {full:?}; after one change {} new pages {} B of {} written, re-encode {again:?}",
            pages.new_pages, pages.new_bytes, pages.puts
        );
        assert!(pages.new_pages <= 8, "{} new pages", pages.new_pages);
        n *= 10;
    }
}
