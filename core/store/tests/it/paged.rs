#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Paged large aspect state (notes/local-store.md, Units; spec/requirements.md, Scale: a change
//! inside a huge value costs O(change); large values stream).

use crate::common;

use common::*;
use osis_crypto::SeededRng;
use osis_store::{MemoryBackend, Shred, Store, StoreConfig};
use std::collections::HashSet;

/// Unit rows that differ between two dumps (new or rewritten).
fn changed_units(before: &[(Vec<u8>, Vec<u8>)], after: &[(Vec<u8>, Vec<u8>)]) -> usize {
    let old: HashSet<&(Vec<u8>, Vec<u8>)> = before.iter().collect();
    after.iter().filter(|kv| kv.0[0] == b'u' && !old.contains(kv)).count()
}

/// Fills a map aspect: table 0 holds elements by map key, table 1 indexes dot -> key.
fn fill(s: &mut Store, rng: &mut SeededRng, n: u32, batch: u32) {
    let (t1, a) = (tid(1), ak("big.0"));
    for chunk in 0..n.div_ceil(batch) {
        let mut t = s.transaction(rng).unwrap();
        let elems = t.create_table(&t1, &a, 0).unwrap();
        let dots = t.create_table(&t1, &a, 1).unwrap();
        for i in chunk * batch..((chunk + 1) * batch).min(n) {
            let key = format!("key{i:08}");
            t.table_put(elems, key.as_bytes(), format!("value of {i}").into_bytes(), Shred::No).unwrap();
            t.table_put(dots, &u64::from(i).to_be_bytes(), key.into_bytes(), Shred::No).unwrap();
        }
        t.commit().unwrap();
    }
}

// spec/crdt.md §8: large states page; spec/requirements.md, Scale: large values stream; no API materializes a whole state.
#[test]
fn stream_and_positions() {
    let dev = MemDevice::new();
    let mut rng = SeededRng::from_u64(2);
    let mut s = create(&dev, &mut rng);
    fill(&mut s, &mut rng, 1500, 1500);
    let mut t = s.transaction(&mut rng).unwrap();
    let elems = t.table(&tid(1), &ak("big.0"), 0).unwrap().unwrap();
    let mut from = Vec::new();
    let mut seen = 0u32;
    loop {
        let page = t.table_range(elems, &from, None, 100).unwrap();
        if page.is_empty() {
            break;
        }
        for (k, _) in &page {
            assert_eq!(k, format!("key{seen:08}").as_bytes());
            seen += 1;
        }
        from = [page.last().unwrap().0.as_slice(), &[0]].concat();
    }
    assert_eq!(seen, 1500);
    // Positions (text dot -> position needs rank; position -> element needs nth).
    assert_eq!(t.table_rank(elems, b"key00000777").unwrap(), 777);
    assert_eq!(t.table_nth(elems, 1234).unwrap().unwrap().0, b"key00001234");
    t.table_remove(elems, b"key00000010", Shred::Yes).unwrap();
    assert_eq!(t.table_rank(elems, b"key00000777").unwrap(), 776);
    let bounded = t.table_range(elems, b"key00000005", Some(b"key00000012"), 100).unwrap();
    assert_eq!(bounded.len(), 6);
    // Dropping the aspect drops every page of both tables.
    t.drop_aspect(&tid(1), &ak("big.0")).unwrap();
    t.commit().unwrap();
    let units = dev.backend.dump().iter().filter(|(k, _)| k[0] == b'u').count();
    assert!(units <= 3, "{units} unit rows left (catalog)");
}

/// One edit of a table of n keys and its index of n (the element shredded, the index entry
/// not): (unit rows rewritten, rows written, bytes written).
fn table_edit(n: u32) -> (usize, u64, u64) {
    let b = MemoryBackend::new();
    let mut rng = SeededRng::from_u64(3);
    let mut s = Store::create(Box::new(b.clone()), Box::new(osis_store::MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
    fill(&mut s, &mut rng, n, 50_000);
    let before = b.dump();
    let io = b.io();
    let mut t = s.transaction(&mut rng).unwrap();
    let elems = t.table(&tid(1), &ak("big.0"), 0).unwrap().unwrap();
    let dots = t.table(&tid(1), &ak("big.0"), 1).unwrap().unwrap();
    assert_eq!(t.table_len(elems).unwrap(), u64::from(n));
    let key = format!("key{:08}", n / 2);
    t.table_put(elems, key.as_bytes(), b"edited".to_vec(), Shred::Yes).unwrap();
    t.table_put(dots, &u64::from(n + 1000).to_be_bytes(), key.into_bytes(), Shred::No).unwrap();
    t.commit().unwrap();
    let w = b.io() - io;
    (changed_units(&before, &b.dump()), w.writes, w.written_bytes)
}

// spec/crdt.md §8: large states page; spec/requirements.md, Scale: maps with millions of keys; one
// edit touches O(1) pages. One edit of a table of n and 10n keys and its index rewrites a page
// per table plus the index path (at most 8 unit rows); rows written stay flat, and bytes within a
// few pages (a B-tree level more at 10n rewrites one more node).
#[test]
fn table_edit_is_flat() {
    let (a, b) = (table_edit(3_000), table_edit(30_000));
    println!("one edit (unit rows, rows, bytes): {a:?} at n, {b:?} at 10n");
    assert!(a.0 <= 8 && b.0 <= 8, "unit rows rewritten: {a:?}, {b:?}");
    assert!(b.1 <= 2 * a.1 + 2 && a.2 <= 64 * 1024 && b.2 <= 64 * 1024, "rows and bytes written grow with the table: {a:?}, {b:?}");
}


// spec: none (internal: notes/local-store.md, Implementation). A table page is decoded once per
// write of its unit: lookups after the first decode none, in a later transaction too; a write
// decodes nothing of the pages it rewrites again, and the lookups after it nothing at all (the
// pages written stay decoded).
#[test]
fn a_table_page_is_decoded_once_per_write() {
    let b = MemoryBackend::new();
    let mut rng = SeededRng::from_u64(5);
    let mut s = Store::create(Box::new(b.clone()), Box::new(osis_store::MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
    fill(&mut s, &mut rng, 3_000, 50_000);
    let key = |i: u32| format!("key{i:08}").into_bytes();
    let gets = |s: &mut Store, rng: &mut SeededRng| {
        let before = s.pages_decoded();
        let mut t = s.transaction(rng).unwrap();
        let elems = t.table(&tid(1), &ak("big.0"), 0).unwrap().unwrap();
        for i in (0..3_000).step_by(7) {
            assert!(t.table_get(elems, &key(i)).unwrap().is_some());
        }
        drop(t);
        s.pages_decoded() - before
    };
    gets(&mut s, &mut rng);
    assert_eq!(gets(&mut s, &mut rng), 0, "pages read before");
    let before = s.pages_decoded();
    let mut t = s.transaction(&mut rng).unwrap();
    let elems = t.table(&tid(1), &ak("big.0"), 0).unwrap().unwrap();
    for i in 0..50 {
        t.table_put(elems, &key(1_500), vec![i], Shred::No).unwrap();
    }
    t.commit().unwrap();
    assert_eq!(s.pages_decoded() - before, 0, "a write of pages held decoded");
    assert_eq!(gets(&mut s, &mut rng), 0, "pages a transaction wrote");
}
