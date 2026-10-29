# perm-joint-model
- The task named issues/perm-joint-model-mismatch.md, but that file lives only on the unmerged snapshot-receipts branch (d513aa61), not on main: found it with `git log --all -- <path>`. Not deleted here; whoever merges both drops it.
- The gate took 521 s warm (clippy and clippy-net 51 s each, the sim sweep), not the 1.5 min notes/build.md quotes; the new test first failed `spec_map.py --uncited` (a pinned test needs a `spec/...` citation in its doc comment).
- Review: the first gate stopped at `spec_map.py --uncited` again (a new differential test without a `spec/...` doc citation). The second gate took 532 s, `cargo test --workspace` alone 338 s (rebuild after the rebase onto main, box shared).
