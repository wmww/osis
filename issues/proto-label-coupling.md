# osis-proto carries its own label objects until osis-label lands
> Summary: `crates/osis-proto/src/label.rs` parses and signs steps, parses claim sets, reads the blob prefix and computes the stamp, deposit, delete and signal-publish digests; `bundle.rs` decodes bundle records. All of it belongs to osis-label (plans/label.md). When label merges, replace these with its types and reader, keeping `StepInfo`-style accessors the engines use, and check the vectors still match.
> Tags: proto, label

- Engines use: `StepInfo::{parse, is_valid_genesis, is_parent_of, key}`, `ClaimSet::parse` (claims, entry boxes as canonical bytes), `prefix` (salt, expiry, commitments), `entry_digest`, `delete_digest`, `verify`.
- Tests use `NewStep::sign` and `ClaimSet::to_bytes` as builders.
- `BundleImport` verifies stamps under any write key of the bundled path (stamps accepted earlier stay valid across re-registration, spec/sync.md §5); a label reader should keep that.
