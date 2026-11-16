# keel-refgraph-tests2
- A shrunk differential script drops the history's trailing heal/power-on/run, so the first shrinks "failed" at a world that never ran to quiet: the player (`differential::holds`) must append the quiet ending itself, never the generator.
- `tools/mutate.py` over a mutation that storms (release made a no-op) ran 10+ minutes at 1000% CPU with no seed timeout; kill by PID. Set `OSIS_SEED_TIMEOUT_SECS` for mutation runs of seeded tests. Its table row lists only what failed before the kill.
- Mutating with the differential already failing on one default seed confounds every row: run mutations on a seed range that passes first.
- Main was red in osis-sync (10 failures in deletes/growth/links/keep/destruction, another worker's) while writing these; a full `-p osis-sync` run cannot tell new failures from theirs without a diff of names.
