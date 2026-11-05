# api-one-commit
- `cargo test --workspace` stops at the first failing test binary; a rename touching many crates needed `--no-fail-fast` to see them all at once.
- A rename across `osis_base::CommitId` and the API's `CommitId` needs a two-step sed; the `use osis_node::{ChangeId, ..}` form slipped past a path-based pattern.
