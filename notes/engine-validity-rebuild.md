# Engine: un-merge and the one rebuild path
> Summary: How the engine un-merges and re-merges (spec/crdt.md §4.6): every validity flip, valid body drop, strip and re-arrival rebuilds the aspect from its held valid bodies; an invalid part rebuilds nothing; where a rebuild stops; checks; cost.

## Un-merge is skipping invalid bodies
- Un-merge is by invalid delta, not by author (spec/crdt.md §4.6). Invalid bodies never travel, so a rule taking more than the delta's own writes would make reads depend on whom a node met first.
- A non-snapshot delta carries no foreign stamps (spec/crdt.md §3.3; overlapping session ranges void both commits), so an invalid body holds only its own writes and a valid one none of an invalid delta's. So `rebuilt` joins every held valid body whole, leftovers included, and nothing of an invalid part.

## One path
- Every validity flip, valid body drop, strip and re-arrival rebuilds the aspect (`apply::rebuild` → `rebuilt`; issues/drop-rejoin-robust.md item 1). No in-place un-merge: re-merging needs the bodies (a register's earlier value comes back only from them), and one path keeps every case alike.
- An invalid part changes no state, so its arrival, its drop (`drop_invalid`, unless it uncovers a part) and a valid snapshot joining with copies of invalid writes rebuild nothing.
- Mid-transaction, between an overlap voiding a held commit and the re-judge flipping it, the state still holds that commit's writes; the flip's rebuild takes them before the transaction ends.
- The rebuild writes the state shredded; members gone by expiry, purge, keep bound or validity leave the group index (`group.0`) with it.

## Where a rebuild stops
Newest body first, `rebuilt` stops once the state's root reset or register write is past the next body's `ts` (`Fragment::settled_above`; spec/crdt.md §7 One reset per position): older writes are pruned (spec/crdt.md §4.2). A debug build reads them all anyway and checks the skipped state equal. So a chat kick reads down to the winner only, flat in length.

## Checks
Debug builds check after every transaction that the state equals a rebuild (`apply::check_rebuilt`: every aspect changed other than by a valid join, and a sample of those). osis-crdt `unmerge_spec_4_6` checks un-merge per delta (`Fragment::remove_writes`) on random histories.

## Cost
O(aspect history) per flip (`scale::validity_flip_is_linear_and_invalid_arrival_flat_spec_permissions_5_2`: n + 1 body reads, commits re-judged flat). Accepted as rare (issues/node-core-gaps.md). An invalid arrival reads no other body (the same test).
