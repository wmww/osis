# delete-holes
- `cargo test --workspace` stops at the first failing binary, and its output read twice cost a second run moved to background: use `--no-fail-fast` when checking a change.
- `judgment_vectors` says "a spec change" when any snapshot's `ts` moves: a stray `hlc.next()` in a probe tripped it.
- `make_valueless` carries a `#[cfg(test)]` oracle for a residue; `strip` vs `expire` had to be told apart at about ten sites by reading each one.
- `osis runtime::driver_panic_fails_waiters` failed once in a full tier-1 run (runtime.rs:673, the SyncStopped detail) and passed in one other full run, one crate run and six alone: looks like a flake.
- Review: `history` (testutil) stamps writes below what the writer saw, so a removal can be older than its creation; fine for lattice laws, a false alarm for anything about what a removal means. `history_honest` added.
