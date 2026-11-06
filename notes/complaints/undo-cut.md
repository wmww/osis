# undo-cut
- `cargo test --workspace` without `--no-fail-fast` stops at the first failing test binary, so one run hid three node failures behind two osis ones; a second 5 min run was needed. Worth saying in notes/build.md for dev-loop runs.
- Editing tests while a background tier-1 run compiles makes its results a mix of old and new sources; easy to misread which version failed.
- Gate took 1159 s at load 30-36 (notes say about 4 min quiet); tier 1 took 611 s at the same load.
- Review: `cargo test --no-run | grep -o '/[^ ]*/it-…'` loses the path (cargo prints it relative: `target/debug/deps/it-…`); copy from the worktree's `target/` instead.
