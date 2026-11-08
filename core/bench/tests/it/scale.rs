//! Scale checks over the crdt paging: work counted at n and 10n (tier 1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_base::{Link, Tid, Ts, Value};
use osis_crdt::{AnyView, CounterRange, DeltaCtx, DeltaKind, Fragment, Frontiers, MemoryPages, PageError, PageSink, Snapshot, Source, Writer, create, encode_snapshot};
use std::collections::HashSet;

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
        if self.hashes.insert(osis_base::hash::hash(plaintext)) {
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
    let cx = DeltaCtx { ts: ts(1 << 30), own: Source::session(osis_crdt::Session { node: Tid::from_bytes([9; 15]), nonce: [0; osis_crdt::SESSION_NONCE_LEN] }), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
    let s = Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: state.clone(), frontiers: Frontiers::default() };
    encode_snapshot(&s, &cx, Some(pages)).unwrap().len()
}

/// Pages written for one paged snapshot of an `n`-key map, then (new pages, puts) for its
/// snapshot again after one entry changed.
fn rewrite(n: usize) -> (usize, usize, usize) {
    let kv = (0..n as i64).map(|i| (Value::Int(i), Value::Int(i))).collect();
    let mut w = Writer::new(ts(1), Source::session(osis_crdt::Session { node: Tid::from_bytes([1; 15]), nonce: [0; osis_crdt::SESSION_NONCE_LEN] }), 1);
    let mut st = Fragment::default();
    st.join(create(&mut w, &AnyView, &Value::Map(kv)).unwrap());
    let mut pages = Seen { inner: MemoryPages::new(), hashes: HashSet::new(), new_pages: 0, new_bytes: 0, puts: 0 };
    snapshot(&st, &mut pages);
    let all = pages.new_pages;
    // one entry changed by another writer
    let mut w2 = Writer::new(ts(2), Source::session(osis_crdt::Session { node: Tid::from_bytes([2; 15]), nonce: [0; osis_crdt::SESSION_NONCE_LEN] }), 1);
    let one = [(Value::Int(n as i64 / 2), Value::Int(-1))].into_iter().collect();
    st.join(create(&mut w2, &AnyView, &Value::Map(one)).unwrap());
    (pages.new_pages, pages.new_bytes, pages.puts) = (0, 0, 0);
    snapshot(&st, &mut pages);
    (all, pages.new_pages, pages.puts)
}

// spec/crdt.md §8, spec/requirements.md (Scale: a change inside a huge value costs O(change)): a
// paged snapshot of a map re-encoded after one entry changed writes only the pages around the
// change and the link path: new pages do not grow from n to 10n keys (counted pages, both sizes
// many pages).
#[test]
fn big_map_snapshot_rewrite() {
    let (n, big) = (10_000, 100_000);
    let (all_n, new_n, _) = rewrite(n);
    let (all_big, new_big, _) = rewrite(big);
    assert!(all_n >= 3 && all_big >= 5 * all_n, "paged at both sizes: {all_n} / {all_big} pages");
    assert!(new_n <= 4 && new_big <= new_n + 1, "new pages after one change: {new_n} at {n} keys, {new_big} at {big}");
}
