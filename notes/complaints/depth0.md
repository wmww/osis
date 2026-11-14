# depth0
> Summary: Workflow mishaps met on the depth0 branch (carried demotions, Possession removed).

- The study claimed Possession redundant; it also published, through its proofs, which keyset of a holder actor each epoch boxes, which a sealer holding none of the actor's boxes judges staleness by. Only an osis World test (`team_left_out_by_a_sealer_reading_none_of_it_reads_again`) caught its removal; the Depth0 model has no such sealer. Kept as an unsigned `sealed_at` record.
- `Core::keysets_of` filtered by held demotions was used by `rebuild_keysets` to clear the index, leaving unheld keysets in it; only `check_index` after a sampled transaction showed it, as a want/got dump of the whole keyset table (a diff of the two maps would read faster).
- The rebuild load noted keysets of every body before judging; it only matched the live index while validity read keysets (Possession). Load now rebuilds keysets after judging.
