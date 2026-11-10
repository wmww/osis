# zero-growth-1
- A store dump shows encrypted units, not rows: no way to count what grows row by row. Added `Engine::local_census` and `HostStore::all_rows` (test helpers).
- `cargo run -p roles-model` needs `-- [samples] <mode>`: one missing `--` argument ran the default search for minutes.
- Review: `tools/test_select.py --run` found 18 sim failures on this branch: the branch had not run the sim sweep; the worker's checks did not catch that.
- The sim's testenv refuses any unlisted `OSIS_*` variable by exiting 101 with no message: a debug toggle named `OSIS_...` looked like a crash. Name probes otherwise.
- No way to replay one sim seed from the command line: `sim-sweep --seeds 1 --from S --only X` works but prints no trace; a throwaway `#[ignore]` test calling `osis_sim::replay(..).unwrap()` with `OSIS_SIM_TRACE=1` was needed.
- Review: sim oracles have no record of the random writes `run` makes, so an excuse about later writes (own replaces) had been read from the node under test; `NetSim::written` now logs every commit.
- Review: `sim-sweep` prints a failure's message only with `--seeds 1`; a many-seed run lists only `failing:` lines.
- `tools/bin-at REV` builds the crate's bins too: after it, `target/debug/sim-sweep` is REV's build, not the branch's (a later run silently tested main).
- `OSIS_SIM_TRACE` shows wire messages and rounds only; tracing a stuck key path (who rotated, who left whom out, which deposit was refused) took temporary eprintln probes across engine and node.
