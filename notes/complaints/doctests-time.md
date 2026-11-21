# doctests-time
> Summary: Footguns met while investigating the `gate.doctests` overrun.

- `cargo test --doc -p X` on a crate whose `[lib]` sets `doctest = false` still builds X (and what is stale below it) and runs rustdoc on 0 tests: the explicit `--doc` overrides the flag. The gate's comments path paid that for every crate but osis and osis-base.
