# eph-unify-b2
> Summary: workflow notes from the B2 swap: two module runs on one log name, a killed build's stale link artifacts, traces left in code.

- Two background runs of the same test module redirected to the same log file (one started before a fix, one after): the file was a mix of both and the first failure read was stale. Name logs per run.
- Killing a cargo build mid-link left "undefined hidden symbol" errors on the next build; `cargo clean -p osis-node` fixed it.
- Temporary `eprintln!` traces under `OSIS_EPH_TRACE` crept into engine code during debugging; grep for `eprintln` before committing.
- The full `ephemeral::` module takes over ten minutes in dev on a loaded box; narrow with name filters while iterating.
