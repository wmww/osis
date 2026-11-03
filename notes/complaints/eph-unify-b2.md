# eph-unify-b2
> Summary: workflow notes from the B2 swap: two module runs on one log name, a killed build's stale link artifacts, traces left in code.

- Two background runs of the same test module redirected to the same log file (one started before a fix, one after): the file was a mix of both and the first failure read was stale. Name logs per run.
- Killing a cargo build mid-link left "undefined hidden symbol" errors on the next build; `cargo clean -p osis-node` fixed it.
- Temporary `eprintln!` traces under `OSIS_EPH_TRACE` crept into engine code during debugging; grep for `eprintln` before committing.
- The full `ephemeral::` module takes over ten minutes in dev on a loaded box; narrow with name filters while iterating.
- Main moved twice under the branch (seed-34000 and order-seeds-b): the first rebase landed on a main whose new order test failed on the branch for a reason unrelated to it, and only a second fetch showed main had since changed. Fetch right before judging a post-rebase failure.
- A second rng draw at open (the expiring session's nonce) moved every later tid and blind: seed-pinned order tests and the judgment vectors changed outcome by commit-ID ties. The nonce is derived now; anything that draws from the engine rng at open is a tie-break change for pinned seeds.
