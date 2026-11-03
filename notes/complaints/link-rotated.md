# link-rotated
> Summary: Mishaps on the link-after-rotation work.

- The issue lived on an unmerged branch, and `member_links` too: based the worktree on `chat-gaps` to have them. A rebase after a chat-gaps amend needs `--onto`.
- `cargo test -p osis --test it a b` takes one filter only; a second is an error.
- Stopping a background `cargo test` mid-compile left osis-engine's incremental cache inconsistent: every later link failed with `rust-lld: undefined hidden symbol ... .llvm.<hash>`. Cure: delete `target/debug/incremental/osis_engine-*` and touch its lib.rs.
