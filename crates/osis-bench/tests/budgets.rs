//! Size budgets (tier 2: `cargo test -p osis-bench -- --ignored`). Each budget is a number from
//! notes or spec plus a margin, cites its source, and fails on regression. Pending budgets (their
//! crates have not landed) are listed in notes/testing.md, "Size budgets".
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_bench::assert_budget;
use osis_core::{CreationRecord, Tid, encode};

// spec/wire.md §3: a creation record is a 3-entry struct around a tid or key and a 32-byte nonce;
// an ordinary thing's encodes in under 64 bytes.
#[test]
#[ignore]
fn budget_creation_record() {
    let rec = CreationRecord::Thing { owner: Tid::from_bytes([1; 15]), nonce: [2; 32] };
    assert_budget("creation record (thing)", encode(&rec.to_value()).len(), 64);
}
