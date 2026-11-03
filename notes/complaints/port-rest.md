# port-rest
- A warm worktree's `cargo test -p osis --test it` failed linking: `rust-lld: undefined hidden symbol anon...llvm...` in osis-node's incremental state (median3_rec, BlobId), with `--workspace` too; touching sources did not help; `cargo clean -p osis-node` did (4.1 GB, 40 s rebuild). A confusing first failure, not from the change.
