#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Paged large aspect state (notes/local-store.md, Units; spec/requirements.md, Scale: a change
//! inside a huge value costs O(change); large values stream).

mod common;

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
    let (t1, a) = (tid(1), ak("/big"));
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

// spec/crdt.md §8: large states page; spec/requirements.md, Scale: one edit of a large paged state rewrites one page per table plus
// the index path, not the state.
#[test]
fn edit_is_o_change() {
    let dev = MemDevice::new();
    let mut rng = SeededRng::from_u64(1);
    let mut s = create(&dev, &mut rng);
    fill(&mut s, &mut rng, 4000, 1000);
    let before = dev.backend.dump();
    let mut t = s.transaction(&mut rng).unwrap();
    let (t1, a) = (tid(1), ak("/big"));
    let elems = t.table(&t1, &a, 0).unwrap().unwrap();
    let dots = t.table(&t1, &a, 1).unwrap().unwrap();
    assert_eq!(t.table_len(elems).unwrap(), 4000);
    t.table_put(elems, b"key00002000", b"edited".to_vec(), Shred::No).unwrap();
    t.table_put(dots, &5000u64.to_be_bytes(), b"key00002000".to_vec(), Shred::No).unwrap();
    t.commit().unwrap();
    let changed = changed_units(&before, &dev.backend.dump());
    // Two tables of height <= 3 at 512-byte pages, plus a catalog page at most.
    assert!(changed <= 8, "{changed} unit rows rewritten");
}

// spec/crdt.md §8: large states page; spec/requirements.md, Scale: large values stream; no API materializes a whole state.
#[test]
fn stream_and_positions() {
    let dev = MemDevice::new();
    let mut rng = SeededRng::from_u64(2);
    let mut s = create(&dev, &mut rng);
    fill(&mut s, &mut rng, 1500, 1500);
    let mut t = s.transaction(&mut rng).unwrap();
    let elems = t.table(&tid(1), &ak("/big"), 0).unwrap().unwrap();
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
    t.drop_aspect(&tid(1), &ak("/big")).unwrap();
    t.commit().unwrap();
    let units = dev.backend.dump().iter().filter(|(k, _)| k[0] == b'u').count();
    assert!(units <= 3, "{units} unit rows left (catalog)");
}

// spec/crdt.md §8: large states page; spec/requirements.md, Scale: maps with millions of keys; a million small units; one edit
// touches O(1) pages.
#[test]
#[ignore]
fn million_keys() {
    let b = MemoryBackend::new();
    let mut rng = SeededRng::from_u64(3);
    let mut s = Store::create(Box::new(b.clone()), Box::new(osis_store::MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
    fill(&mut s, &mut rng, 1_000_000, 50_000);
    let before = b.dump();
    let mut t = s.transaction(&mut rng).unwrap();
    let elems = t.table(&tid(1), &ak("/big"), 0).unwrap().unwrap();
    assert_eq!(t.table_len(elems).unwrap(), 1_000_000);
    t.table_put(elems, b"key00500000", b"edited".to_vec(), Shred::Yes).unwrap();
    t.commit().unwrap();
    let changed = changed_units(&before, &b.dump());
    assert!(changed <= 5, "{changed} unit rows rewritten");
}

