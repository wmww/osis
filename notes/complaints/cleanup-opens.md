# cleanup-opens
> Summary: Workflow notes from the opens/pull cleanup reading.

- Line-by-line reading found what the probe tools miss: write-only fields (`WalkState::asked`) and parameters threaded through but never used (`Opens::test`/`run`'s `moved`, kept quiet by `let _ = &moved;`). rustc does not warn on a write-only struct field that is also read by `Clone`/`Debug` derives; a grep for `\.field\b` reads is the quick check.
