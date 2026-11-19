# tooling-aids
- tools/heavy reads `rustc -vV` for the runner variable; a test that overrides HOME breaks rustup's rustc (set RUSTUP_HOME/CARGO_HOME explicitly, as tools/heavy_test.py does).
- tools/limits.py prints its `limit` line to the command's stdout when no --log is given, so a caller reading the command's stdout sees one extra line.
