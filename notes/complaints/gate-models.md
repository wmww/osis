# gate-models
> Summary: Footguns met while making every property's CPU visible and narrowing the gate's selection.

- The four KNOWN roles-model story searches cost about 1,700 CPU-s of every gate selecting roles-model (two family runs at 550 each), more than the issue's estimate for all 55 uncosted tests; the per-test table was the first place that showed it.
- `tools/heavy CMD` records a direct `cargo test` and runs the copies itself, dropping any `CARGO_TARGET_*_RUNNER` the command set: wrap such a run in `sh -c` (or a script) so heavy leaves cargo alone.
- tools/policy.py's env check reads tools/ tests too: a fixture variable named `OSIS_X` fails policy; use a listed name.
- The gate (tools-only branch, default tests only) hit a fresh-seed proptest failure in osis-crdt that fails on main's code (`winners_from_scratch_spec_4_8`): filed issues/crdt-first-superseding-disagrees.md with a `rate:` line; with it the summary reads exit 3. A default proptest drawing fresh seeds can fail any branch's gate.
