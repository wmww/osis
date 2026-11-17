# Purge-on-replace strip loses its proof
> Summary: A part stripped as covered under purge on replace counts never received, for good, at a new reader once its reaching snapshot is covered by one whose tables no longer name the part's session.
> Priority: normal
> Tags: engine, sync

A part dropped as covered strips only under purge on replace, and only while a held valid snapshot reaches it by its tables (spec/sync-judgement.md §2 Per blob), so a new reader counts it covered (spec/commits.md §5 Covered). That proof does not last: the reacher X is covered by a later snapshot Y (by the join), X goes, and Y's tables name only sessions with a write left in its fragment (spec/crdt.md §8 Absence), so Y does not reach the part. A reader joining after holds Y and the stripped commit, counts the part never received, and no node has it. A missing part stops its session's frontier in that reader's snapshots. Without purge on replace the part stays in its blobs (notes/whole-commits.md, Why no cover strip without purge on replace), which closed the OSIS_FULL seeds that showed this.

Untested: no test makes a purge-on-replace part's reacher covered before a new reader joins (`deletes::replaced_beside_a_kept_part` plus a concurrent replace from a sibling, as in `deletes::a_reader_receives_a_part_whose_cover_was_covered_whole_*`).

Fixes considered, none built:
- Tables name every session of a held commit with a part on the aspect, not only those with a write left (crdt codec and §8 change; bounded by held commits, not history). Y then reaches the part.
- X is covered only by a snapshot reaching every held commit's part X reaches (X stays beside Y). Order-dependent at a new reader that drops X before the commit arrives, unless that drop is undone when the commit comes.
