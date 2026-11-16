#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Synthetic aspects, diagnostics.

use crate::common;
use common::*;
use osis_engine::Event;

// notes/architecture.md §3: diagnostics are deduped.
// spec: none (diagnostics are local, notes/architecture.md)
#[test]
fn diagnostics_deduped() {
    let mut lp = net(2, 0);
    new_thing(&mut lp, 0);
    let pk = lp.packages(0).unwrap().pop().unwrap();
    // malformed: the blob's outer array one short
    let mut bad = pk.bytes.clone();
    bad[0] ^= 1;
    for _ in 0..3 {
        let _ = lp.peers[1].receive(&bad, Vec::new());
    }
    let d = lp.peers[1].drain_events().into_iter().filter(|e| matches!(e, Event::Diagnostic(_))).count();
    assert_eq!(d, 1);
}
