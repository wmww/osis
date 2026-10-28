# crdt-cleanup
> Summary: Mishaps and slow spots met on the crdt-cleanup branch.

- `MCommit` (testutil) has no source, and `Tid` has no public constructor from 16 bytes (`Tid::from_bytes([n; 15])`): a temporary differential test took two compile rounds to find the helpers other tests use.
- Old-vs-new release timing needs two binaries; checking `main`'s `core/crdt/src` out over the worktree, building, and checking `HEAD` back out works without stash, but rebuilds the crate both ways.
- The `seq_ops` fuzz target builds its own target dir under `core/test/fuzz/target` per worktree (a cold nightly build, a couple of minutes).
- `claudewait` reported "exit code unknown, finished earlier" at once for a background command that began with `uptime;` (it seems to track the first process), while the loop after it ran two more minutes: read the log instead.
