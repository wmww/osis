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

// notes/crdt.md, Text size: a text's snapshot is at most 3.5x the plain text at 100 edits per
// commit and 7x at 10 (automerge-paper trace: 3.2x, 6.6x). Replays that trace if
// `OSIS_TEXT_TRACE` names it, else a synthetic typist of the same shape (osis_bench::text;
// measured 2.9x, 6.7x).
#[test]
#[ignore]
fn budget_text_snapshot_ratio() {
    use osis_bench::text::{final_text, from_env, replay, snapshot_len, synthetic};
    let edits = match from_env() {
        Some(e) => e,
        None => synthetic(20_000, 7),
    };
    let want = final_text(&edits);
    for (per_commit, ratio) in [(100usize, 3.5f64), (10, 7.0)] {
        let (state, commits) = replay(&edits, per_commit);
        assert_eq!(state.read(), Some(osis_core::Value::Str(want.clone())), "replay reads the final text");
        let len = snapshot_len(&state);
        println!("text {per_commit} edits/commit: {} edits, {commits} commits, text {} B, snapshot {len} B, ratio {:.2}", edits.len(), want.len(), len as f64 / want.len() as f64);
        assert_budget(&format!("text snapshot, {per_commit} edits per commit"), len, (want.len() as f64 * ratio) as usize);
    }
}
