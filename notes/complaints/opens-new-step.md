# opens-new-step
- `cargo test --workspace` stops at the first failing crate: a failure in osis-server hid whether osis-node's tests ran (only 24 result lines). Use `--no-fail-fast` when checking a cross-crate change, or count the `test result` lines.
- Edited a source while a background test chain ran (footgun already in notes/build.md); had to stop and rerun.
- Review: `Net::set_online(n, true)` then `run()` does not reconnect (the dial waits for a retry tick): use `advance`. Cost a confusing "no gained Sync" detour.
