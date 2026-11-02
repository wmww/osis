# engine-audit-fix
- A probe test meant to fail without its fix passed twice for reasons unrelated to the bug (a no-op register write elided by the writer; a hand-built commit-form delta rejected for "foreign stamps" because `writer_ctx` defaults to node form). Print the error/state before trusting a "fails without fix" run.
- `cargo test --workspace` took over 10 min wall at load (moved to background); the first build after rebase was 5.5 min.
- tools/gate.sh took 848 s at load 34-45 (notes say about 90 s warm).
- Review: `cargo test --workspace --no-run` prints every test binary as `tests/it/main.rs` with no crate name; finding the osis-node and osis-perm `it` binaries to copy took a `--list` probe of each.
- Gate: `cargo deny check` failed on a network fetch of the advisory db (github.com unresolvable), so the sweep and kit steps never ran; ran `cargo deny --offline check`, the sweep and the kit check by hand. The gate could fall back to `--offline` when the fetch fails.
