# undo-whole
> Summary: workflow notes from the undo-whole task.

- Box load ~35: a 3-crate tier-1 run took ~7 min and a 3-filter targeted rerun ~11 min (three separate `cargo test -p` builds in a row; one `-p a -p b -p c` invocation with filters would have shared the link step).
- No helper for "deliver a commit with some parts left out"; tests hand-roll `osis_commit::rewrite` over `lp.packages` (rotation tests, undo tests).
