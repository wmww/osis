# engine-core-cleanup
> Summary: Cleanup worker notes: finding dead pub items in osis-engine, test cost of a single-crate run.

- Finding unused `pub fn`s by `rg` per name drowns in name collisions (`now`, `get`, `run`). Faster: in a throwaway branch `sed` every `pub fn` in the module to `pub(crate) fn`, `cargo check -p <crate> --lib --message-format json`, take the `dead_code` spans, then grep each name outside the crate's lib (tests, other crates). In `engine/` it found two dead accessors only; most "dead" items are test hooks for `tests/it` or the facade.
- `cargo test -p osis-engine` takes about 4 minutes wall here; a cleanup that touches only `engine/` has no narrower suite to run per commit.
