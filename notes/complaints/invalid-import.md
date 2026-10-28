# invalid-import
- `cargo test --workspace` stops at the first failing binary; after the core schema text changed, a stale vector (`schema/core.vec`) hid every later binary until `--no-fail-fast`. Regenerate vectors with `cargo run --bin gen-vectors`, not `OSIS_REGEN_VECTORS=1` on the vectors test (that env var only regenerates `osis-schema` codegen).
- `rebuild` joins the current state with the bodies, so un-merge is only ever by dot predicate: a design that "rebuilds" to drop a previously joined body's extra dots does nothing. Worth a line in notes/node.md for whoever next touches import validity.
- The first cold `cargo build --workspace --all-targets` in the worktree took ~8 min at load 40.
- The walks `_moves` generator cannot easily make a foreign (non-creator) import: building one fails with "admin delete key not supplied" (imports carry their origins' retention, admin purge needs the admin delete key), so it was left out; the dedicated walks tests cover it.
