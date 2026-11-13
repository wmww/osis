# evil-host
- A minimal node test for the fix was not found after several setups (see issues/promote-tombstone-reproducer.md): the node's immediate fresh re-upload on a host Deleted hides the promoted-tombstone path in every simple setup. Most of the task's time went there.
- `cargo test -q` hides eprintln of passing tests; probes need `-- --nocapture`.
- Backtraces from release-ish inlined frames named only the leaf (`with_work<...>`); `eprintln` at each caller was faster.
