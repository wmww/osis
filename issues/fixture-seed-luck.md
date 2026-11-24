# Default tests on random-world fixtures reach their case by the seed's draws
> Summary: osis-sync's `three`, `shared` and other fixtures build `world_of(0, ..)`, a random world at seed 0, so a default test on them passes or fails by what that seed drew (a transaction more or less moves the store rng and the outcome): seen for three default tests that failed after an unrelated delete, and for tests passing at 2 of 8 seeds under either rule. Each is a pinned-seed test in disguise.
> Priority: normal
> Tags: tests, sync

notes/testing.md (Seeds are 0) allows seed 0 only where the case is constructed. These fixtures construct the steps but not the draws (IDs, keys, tie-breaks), and the case several tests check rests on them: `delete_keys::nothing_deletes_a_header_lists_chunks_by_level_2_spec_crypto_7`, `growth::several_writers_grow_nothing_spec_commits_5` and `pieces::a_small_edit_to_a_large_value_costs_its_new_pieces` failed together once a delete removed a few transactions (seeds 1, 2, 5, 6 passed all three, 0 failed all, 3 and 4 one); issues/wanted-blob-handover-untested.md is the same shape (the chunk-first order reached only at seeds 1, 2, 5, 6).

What fixes it: each such test constructs its case (the order or the tie it means), so it holds at every seed. A cheap way to find them: let the fixtures take their seed from an `OSIS_*` variable and run the default sync tests at a few seeds; a test whose verdict moves is on this list.
