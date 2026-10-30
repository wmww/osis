# key-trust
> Summary: Mishaps met fixing the history-box poison and entry-box trust issues.

- `cargo test --workspace` stops at the first failing test binary (osis's `it` hid osis-node's failures); a fix run needs `--no-fail-fast` to see every failing test at once.
- Tier 1 took 287 s at load 32 (other agents' gates), 6x the quiet figure.
- Review: the perm tier-2 filter run prints a dozen `0 passed` result lines from other crates' binaries; the one with `15 passed` is easy to miss.
