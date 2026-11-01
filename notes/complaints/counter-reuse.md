# counter-reuse
> Summary: footguns met while fixing restored-store counter reuse.

- `cargo test --workspace 2>&1 > log` sends stderr (the build lines) to the console and stdout to the log: write `> log 2>&1`.
- osis tests: a restored store opened at the same world time writes with a lower HLC `logical` than the commits it lost, so LWW picks the lost value; advance the clock before a restore.
- Review: the LocalPeer oracles (order, walks, deaths, undoexp) run without a sync layer, so `counters_unsure` is `None` and none of them reaches the commit-form gate or commit-form undo; only the sim sweep and the new tests do.
