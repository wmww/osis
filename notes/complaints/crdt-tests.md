# crdt-tests
> Summary: Footguns met while slimming osis-crdt's default tests.

- `tools/mutate.py` with one plant builds it as a plain edit into the worktree's own target: the `deps/osis_crdt-*` binary left behind is the mutant until the next build. A copy taken right after for a property run reported failures that were the plant's. Rebuild before copying a binary after mutate.py.
- `.cargo/config.toml`'s `PROPTEST_CASES=32` overrides each proptest's `with_cases(12)`/`(48)`: tests_stream's "12-case" proptest ran 32 cases (26.8 G, not the 12.5 G issues/test-time.md listed).
- crdt properties drew from `testutil::rng` (xored with `OSIS_CRDT_SEED`), so a replay line naming only `OSIS_CRDT_START` replays another history whenever the gate set `OSIS_CRDT_SEED`. Properties now draw from `testutil::fixed`.
- A loop's index moved into a seed keeps everything it fed: the edit-window rounds stamped their concurrent changes at `10 + round * 10`, so a gate-sized offset put them above the local edit's stamp and failed the property. Check what else a round index feeds before making it a seed.
- `inputs(seed | 1)` in tests_stream gave seeds 2k and 2k + 1 the same history (half the property's seeds and two of stream_seams' four were repeats).
- Another branch converted four of the same crdt loops (stream coverage, re-cuts, decoded bound, cached moves) while this one ran, with its own `OSIS_*` names and default-range-only tallies: a squashed rebase took this branch's versions and dropped the six names. A brief overlapping a running job's crate would save the merge.
- A reach floor set on the default seeds (decoded bound: 160 of 200 unpaged) failed at 4 of 12 gate-sized offsets (152-160): a floor scaled by seed count still needs slack for other ranges.
