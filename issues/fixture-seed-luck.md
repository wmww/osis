# Default tests on random-world fixtures reach their case by the seed's draws
> Summary: osis-sync's `three`, `shared` and other fixtures build `world_of(0, ..)`, a random world at seed 0, so a test on them reaches its case only if that seed's draws (IDs, keys, tie-breaks, fetch order) happen to: a pinned-seed test in disguise. Known: the wanted-blob handover (`Engine::take_wanted`) is reached by no default test.
> Priority: normal
> Tags: tests, sync

notes/testing.md (Seeds are 0) allows seed 0 only where the case is constructed. These fixtures construct the steps, not the draws, and a transaction more or less moves the store rng and the outcome.

- **Wanted-blob handover untested**: `Engine::take_wanted` and `store::Follow::settle` hand a blob sync's store holds unopened to a commit that comes to want it (a header list's chunk fetched before the node above it). Without it the commit pends `WaitBlobs` for good. `delete_keys::nothing_deletes_a_header_lists_chunks_by_level_2_spec_crypto_7` reaches the chunk-first order only at some seeds of the `three` fixture, not at 0; the harness's quiet check (`wanted_blobs_in_reach`) then catches the handover undone. Wanted: a constructed seed-0 test reaching the order (a `Follow` over a fake ground, or a scripted peer serving the chunk first), asserting the commit applies, checked to fail with the `take_wanted` loop removed. What decides the fetch order of two blobs announced in one batch is not known.
- **Finding the rest**: let the fixtures take their seed from an `OSIS_*` variable and run the default sync tests at a few seeds; a test whose verdict moves constructs its case (the order or tie it means) so it holds at every seed.
