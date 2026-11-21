# A commit awaiting its ts whose expiry passes flags its aspect
> Summary: spec/commits.md §4 says a commit that awaits and whose expiry passes counts as never received and flags nothing; the engine flags the aspect in that case (seen in engine `shred::part_pending_for_its_ts_goes_at_its_expiry_ticked_or_not`, which asserts neither way). Decide which is right by the model (a user observes a flag as a dispute/suspect marker: spec/permissions.md §4 Suspect) and make the other follow.
> Priority: normal
> Tags: engine, retention, spec

Found by mizzen-engine-tests-3 while writing the test above (cf5190cc5). Then assert the decided behaviour in that test.
