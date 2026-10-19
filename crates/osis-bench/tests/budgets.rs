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

struct Secrets;

impl osis_commit::Secrets for Secrets {
    fn dedup(&self, _: &Tid) -> Option<osis_crypto::Secret32> {
        Some(osis_crypto::Secret32::from_bytes([1; 32]))
    }
    fn admin(&self, _: &Tid) -> Option<osis_crypto::Secret32> {
        Some(osis_crypto::Secret32::from_bytes([2; 32]))
    }
    fn chain_write(&self) -> Option<osis_crypto::Secret32> {
        Some(osis_crypto::Secret32::from_bytes([3; 32]))
    }
    fn write(&self, _: &Tid) -> Option<osis_crypto::Secret32> {
        Some(osis_crypto::Secret32::from_bytes([4; 32]))
    }
}

// spec/commits.md §1: a minimal content commit (header plus one register delta, untyped `author`
// retention) is about 300 bytes before encryption (notes/crdt.md, Commit floor).
#[test]
#[ignore]
fn budget_minimal_commit() {
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
    use osis_core::{Ak, Ts, Value, WallMs};
    use osis_crdt::{AnyView, Delta, Source, Writer, create, encode_delta};
    let (author, at) = (Tid::from_bytes([1; 15]), Ts::make(WallMs(1_700_000_000_000), 0).unwrap());
    let mut w = Writer::new(at, Source::node(author), 1);
    let fragment = create(&mut w, &AnyView, &Value::Str("hello".into())).unwrap();
    let d = encode_delta(&Delta { nonce: [1; 16], fragment }, &writer_ctx(Kind::Content, at, author, 1, 2), None).unwrap();
    let mut b = CommitBuilder::new(Kind::Content, at, author, Tid::from_bytes([2; 15]), Form::Node);
    b.aspects.push(AspectWrite::new(Tid::from_bytes([3; 15]), Ak::new("/app/title").unwrap(), 1, 2, d));
    let key = osis_crypto::SigningSecret::from_seed(&osis_crypto::Secret32::from_bytes([5; 32]));
    let c = b.build(&key, &Secrets, &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(1)).unwrap().commit;
    assert_budget("minimal content commit plaintext", c.encode().len(), 330);
}

// spec: none (budget from notes/crdt.md, Text size): a text's snapshot is at most 3.5x the plain text at 100 edits per
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
