# gate-models
> Summary: Footguns met while making every property's CPU visible and narrowing the gate's selection.

- The four KNOWN roles-model story searches cost about 1,700 CPU-s of every gate selecting roles-model (two family runs at 550 each), more than the issue's estimate for all 55 uncosted tests; the per-test table was the first place that showed it.
- `tools/heavy CMD` records a direct `cargo test` and runs the copies itself, dropping any `CARGO_TARGET_*_RUNNER` the command set: wrap such a run in `sh -c` (or a script) so heavy leaves cargo alone.
- tools/policy.py's env check reads tools/ tests too: a fixture variable named `OSIS_X` fails policy; use a listed name.
