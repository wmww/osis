# cleanup-crdt
- On osis-crdt the probes give little again: `--dead` found 5 items (all test helpers or a `len`'s clippy-required `is_empty`), `dup_windows.py` only match arms and test setup. The crate is dense and already compact; real wins need a long read per module (a session's worth for seq_lin/seq/state alone).
- A `Result` that never errs is hard to find by grep: every candidate delegated to a call that can fail. A rustc/clippy lint for it would help.
- `tools/claim` printed a base commit (origin/main) different from the local main checkout's HEAD; harmless, but confusing at first.
