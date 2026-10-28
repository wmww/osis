# feature-unification
> Summary: workflow mishaps met while making feature unification selection-invariant.

- The brief said `tools/wt claim` would give wt3; it gave wt2 (listed free). Harmless, but briefs naming the slot can mislead.
- wt2's warm target was 15 GB, 11 GB of it `incremental/` dirs of dead unit hashes (60 for `it` alone): every feature change to a workspace crate leaves the old ones. Deleted and rebuilt cold; noted in notes/build.md.
- `core/test/fuzz` builds with one pre-existing warning (unused import `Codec` in fuzz_targets/box.rs), not from this branch.
- `run_in_background` jobs run under SCHED_IDLE (checked with `chrt -p`), foreground cargo under SCHED_OTHER: at load 60-75 from other agents a cold gate in the background starved (osis-engine's rustc 15 min wall for 2.5 min CPU). Waiting "properly" makes builds the slowest on the box.
- Release builds warn: `joins` unused in core/perm/src/timeline.rs:195 (only read under `cfg(debug_assertions)`). Pre-existing on main.
