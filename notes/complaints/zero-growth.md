# zero-growth
- `wt release` ran a workspace build ("marking build") for about 9 minutes after a change to one model crate.
- A `cargo test | grep; git commit` chain committed past a failing test: nothing stops a chain on the test's result. Check the test line first.
- The growth census (`local_census`) groups rows by key prefix only: finding which commits stay needed a throwaway per-commit dump (kind, drop reason, cover author). A doc-hidden helper for it would have saved a round.
- roles-model `forget` (the exhaustive family, 8 policies) holds the heavy lock about 11 min; a single-threaded search over the whole member family is far slower, so `forget-any` samples one world in 200.
- `roles-model forget` (mode as the first argument) parses `forget` as the sample count, ignores it and runs the default search for 45 s with no error: the mode is the second argument (`roles-model 0 forget`). main.rs's doc line also omits the forget modes.
