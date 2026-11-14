# walk-stop
- `cargo test -p osis-sync --no-fail-fast` inside a `( ...; echo $? )` subshell reported the background task as exit 0 while a test failed: read the `test result` lines, not the task's exit.
- `NodeHolds::verify_steps`/`step_creds` were stubs: a walk-stop test through the product cannot pass until a Behind answer's steps are known, so building the stop meant building them too.
- (review) The rebase onto sync-rebuild conflicted in store/rows.rs's tag comment (streams' `JOIN_FROM` rewrite beside the new `WALK`): a comment block shared by two modules' tags draws conflicts.
