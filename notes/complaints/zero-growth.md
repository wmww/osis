# zero-growth
- `wt release` ran a workspace build ("marking build") for about 9 minutes after a change to one model crate.
- A `cargo test | grep; git commit` chain committed past a failing test: nothing stops a chain on the test's result. Check the test line first.
