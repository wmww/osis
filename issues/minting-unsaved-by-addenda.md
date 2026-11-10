# A writer's creation lost to a removal is not saved by addenda
> Summary: With a minting judged as a write (spec/commits.md §5 Ending), a writer's creation commit its removal's frontier does not list loses its `created.0`: `validity::plain_part` and `addenda::plain_ak` exclude `created.0`, so a witness's addendum vouches for the thing's content but not its minting, and the thing reads absent. Fails `osis` `sync::removal_from_partial_node_keeps_unheld_edits_spec_permissions_5_2`. Making the minting vouchable (dropping the exclusion in `plain_part`) makes that test spin without end (20 min at full CPU, no result): a loop between minting validity, the ending check and rejudging, not yet root-caused.
> Priority: critical
> Tags: engine, permissions, tests

- Blocks branch `ending-fixes`: its gate fails on this test.
- Spec §5.2 Addenda already counts a minting as plain content (no role-class or admin-only aspect); only the code excludes it.
- Root-cause the loop before choosing: a minting flipping valid sets `valueless_dirty` (`rejudge_once`), and `end_ended` asks `Core::ended` over `mintings`, which reads validity.
