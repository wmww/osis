# The models still read chained sets
> Summary: spec/permissions.md §4 has no chained writes, but roles-model `paths::chained` and held-model `World::chained` are live: the spec's own rule in held-model (`Stage::E1`, the engine evidence differential's oracle) reads them to find the entry a reset names; removing them takes a model change first.
> Priority: normal
> Tags: permissions, tests

**What reads them.** roles-model `paths::chained` (the writes whose author holds what each hop needs, in key order) feeds held-model `World::chained`, which is read by:
- `World::creation` (`creations_of`): the creation of the entry a reset names is taken as the first chained grant on its edge before it. Every closure variant sets `World::creations`, `Stage::E1` among them, so the engine's evidence differential (osis-engine `tests/it/evidence`) reads it. spec/permissions.md §2 has the reset name its entry's creation outright.
- Closure variants (ii) to (vi) (`Variant`, `Takes::Chained`, `Closure::joined`, `Pend::Granted`, `Join`) and the stages built on (iv) (`Stage::A2`, `Stage::A2Actor`: `spec_reach`, `spec_gaps`, `spec_story`, the reach and gaps properties).
- The checks `p0_applied_chained`, `p9_leak` (`roster_reach`) and `p10_junk`.

**What removing them takes.** The model's edge writes name the entry they reset (the writer's view of its edge), so `World::creation` reads it off the write as the spec does; the reach and gaps stages rebuilt on E1 (notes/a2-spec/README.md Open 2: the design), with their hand worlds and properties re-read; P9 and P10 restated without "a write no walk applies" or dropped as E1's stated limits (spec/sync-hostile.md §2). Then `paths::chained` and the (ii) to (vi) variants go. After any change run osis-perm `paths::` and osis-engine `evidence::` differentials.
