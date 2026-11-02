# client-port complaints
> Summary: Workflow notes from the client-port (b) branch.

- A killed `osis serve` (SIGKILL, or SIGINT's default action) leaves `<store>/sock` behind: clients then exit 8 as for any lock; a test that restarts `serve` must remove the stale pointer before waiting for the new one (cost one failed run).
- The CLI's command-table test scanned only core/osis/src files and failed with `IsADirectory` once a module directory (`port/`) existed: now recursive.
- `bench_worst_rows` setup (10^4 single commits on a node with `Runtime::Own`) takes minutes in release: per-commit sync-engine work grows with the store; batch setup commits where the measured row allows.
- Review: the uid comparison of the unix transport could not fail any test (every test runs as one uid); a listener whose expected uid is changed in-module now stands in for another user's process. The dialer side stays covered only through the pinned uid key.
- Review: the gate's `cargo check --locked` failed on kit/Cargo.lock (osis gained osis-proto as a normal dependency; the GUI workspace's lock is separate). Any core dependency change needs kit/Cargo.lock refreshed too.
