# The gate's sweep deletes the build's incremental caches, so every gate build on main compiles from scratch
> Summary: `tools/sweep-target.py` keeps per crate name as many `incremental/` dirs as it counts live units, but its unit key (package, target, profile, features) does not tell a build unit from a clippy check unit of the same crate, so it keeps clippy-net's dirs (the last step) and deletes the build's; the next gate's `cargo build --workspace --all-targets` then compiles every changed crate without incremental state: 15x the CPU.
> Tags: tests, tools, performance

Measured (16-thread laptop, load ~30, a one-line `pub fn` added to osis-crdt, `cargo build --workspace --all-targets`):
- main right after a gate's sweep: 270 s wall, 1252 s CPU.
- main after one rebuild (caches exist again): 21 s wall, 81 s CPU.
- a slot (never swept): 61 s wall, 90 s CPU.
- The gate's own clippy step on the same tree: 21 s (its incremental dirs survive, being newest).
Gate builds on main were 4-7 min; after a sweep main holds 26 `it-*` incremental dirs against 52 in a slot, all with the clippy steps' mtime.

Fix: make the unit key include the artifact kind (check units emit only `.rmeta`; the compiler-artifact message's `filenames` suffixes tell them apart), or count incremental dirs per name from the units of every shape without deduplicating across modes. Then verify with the probe above: main's build after a sweep should match the slot's.

Related, from the same look at where wall time goes (notes/mvp-progress.md round 12): worker agents lose 30-80 min each in `until ... sleep` polling loops that hit the 10-minute Bash timeout (patterns that never match, `pgrep -f` matching its own shell); workers build the tree in release for timing checks and delete `target/release` after, so the next one rebuilds it; the gate on main repeats the reviewer's build (gate in the slot after rebasing on main, then fast-forward main, would drop it); notes/testing-map.md is generated and conflicts on every merge or rebase (stop tracking it; `tools/spec_map.py` answers "what checks §X").
