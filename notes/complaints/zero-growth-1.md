# zero-growth-1
- A store dump shows encrypted units, not rows: no way to count what grows row by row. Added `Engine::local_census` and `HostStore::all_rows` (test helpers).
- `cargo run -p roles-model` needs `-- [samples] <mode>`: one missing `--` argument ran the default search for minutes.
- Review: `tools/test_select.py --run` found 18 sim failures on this branch: the branch had not run the sim sweep; the worker's checks did not catch that.
