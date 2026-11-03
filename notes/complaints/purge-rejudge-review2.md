# purge-rejudge-review2
> Summary: Workflow notes from the second purge re-judge review.

- A rebase mid-review onto a branch that moved the same lists (`p/` to `pn/`) compiles after a plain resolution and silently stops re-judging: the coordinator's warning is what caught it.
- `cargo test --workspace --test it --no-run` prints ten `Executable tests/it/main.rs` lines, none naming the crate: use `-p osis-node` to get the path.
- A foreground run over 180 s moves to the background with its later pipeline stages still pending: split long runs from the start.
