# first-superseding
> Summary: mishaps met fixing the hiders dating gap.

- The sibling proptest `seq_winners_from_scratch_spec_4_8` failed on main at a fresh seed with no known_failures line: its "dies by a winning write" index still modelled the engine before dating by any held write. A stale test model of the engine reads as a product bug; the test's engine-model index should be built from the engine's own call (`Killed::note`'s three fragments), not a copy.
- A permission prompt denied a compound command because a harmless `git stash list` crept into it; keep stash out even as a read.
- A swap-old-code probe (checkout main's `winners.rs`/`bounds.rs`, rebuild osis-engine tests) took ~3.5 min of build; fine but run it in the background from the start.
