# zero-growth-1
- A store dump shows encrypted units, not rows: no way to count what grows row by row. Added `Engine::local_census` and `HostStore::all_rows` (test helpers).
- `cargo run -p roles-model` needs `-- [samples] <mode>`: one missing `--` argument ran the default search for minutes.
