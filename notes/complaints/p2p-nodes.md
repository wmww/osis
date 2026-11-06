# p2p-nodes
- Removing iroh's `skip-tree` from deny.toml exposed five older duplicates it had been masking (cpufeatures, getrandom, shlex, syn, windows-sys); each needed its own `skip` line.
- `cargo test --workspace` stops at the first failing test binary; a failure in osis hid every crate after it. Use `--no-fail-fast` when a run is meant to show everything.
- A tier-1 flood test against the 1024-stream cap needs ~1100 raw dials; fine in the NAT model (well under a second), but the cap constants are not configurable per test.
- Review: `grep -E "^test "` on a test-net log matched nothing (the agent shell's grep shim); the filtered run looked like it ran zero tests. Read the `Running`/`running 1 test` lines with `command grep` or sed.
