# engine-core-cleanup
> Summary: Cleanup worker notes: finding dead pub items in osis-engine, test cost of a single-crate run.

- `cargo test -p osis-engine` takes about 4 minutes wall here; a cleanup that touches only `engine/` has no narrower suite to run per commit.
