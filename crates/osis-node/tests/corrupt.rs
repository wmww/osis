#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Stored bytes corrupted (a bit flip in any row, key or value, or the root): opening and
//! reading the node fails with an error or reads what was written, never panics
//! (notes/architecture.md §3: no panics on data; spec/requirements.md, Deletion relies on AEAD
//! units, which also authenticate).

mod common;
use common::*;
use osis_core::{Clock, ManualClock};
use osis_crypto::{RngCore, SeededRng};
use osis_node::local_peer::LocalPeer;
use osis_node::{Config, Engine};
use osis_store::{Backend, MemoryBackend, MemoryRoot, RootStorage, WriteBatch};
use std::sync::Arc;

fn reopen(rows: &[(Vec<u8>, Vec<u8>)], root: &osis_store::RootRecord) -> osis_node::Result<Engine> {
    let mut b = MemoryBackend::new();
    let mut batch = WriteBatch::new();
    for (k, v) in rows {
        batch.put(k.clone(), v.clone());
    }
    b.commit(batch).unwrap();
    let mut r = MemoryRoot::new();
    r.store(root).unwrap();
    let c: Arc<dyn Clock> = Arc::new(ManualClock::new(T0));
    Engine::open(Box::new(b), Box::new(r), Config::default(), c, Box::new(SeededRng::from_u64(3)))
}

// notes/architecture.md §3 (no panics on data): seeded bit flips across every row and the root
#[test]
fn bit_flips_error_never_panic() {
    let mut lp: LocalPeer = net(1, 81);
    let t = new_thing(&mut lp, 0);
    let mut m = osis_node::Mutation::new();
    m.set(t, &REG, &s("value")).unwrap();
    lp.peers[0].commit(m).unwrap();
    let rows = lp.peers[0].backend.dump();
    let root = lp.peers[0].root.load().unwrap().unwrap();
    assert!(reopen(&rows, &root).is_ok());
    let mut rng = SeededRng::from_u64(5);
    let mut errors = 0;
    for _ in 0..300 {
        let mut rows = rows.clone();
        let mut root = root.clone();
        let which = rng.next_u32() as usize % (rows.len() + 1);
        if which == rows.len() {
            let mut k = *root.key.expose();
            k[rng.next_u32() as usize % 32] ^= 1 << (rng.next_u32() % 8);
            root.key = osis_crypto::Secret32::from_bytes(k);
        } else {
            let (k, v) = &mut rows[which];
            let target = if rng.next_u32() % 4 == 0 { k } else { v };
            if target.is_empty() {
                continue;
            }
            let i = rng.next_u32() as usize % target.len();
            target[i] ^= 1 << (rng.next_u32() % 8);
        }
        match reopen(&rows, &root) {
            Err(_) => errors += 1,
            Ok(mut e) => {
                // whatever opens reads the value written or fails
                match e.get(&t, &ak("/t/reg")) {
                    Ok(Some(v)) => assert_eq!(v, s("value")),
                    Ok(None) | Err(_) => errors += 1,
                }
            }
        }
    }
    assert!(errors > 0);
}
