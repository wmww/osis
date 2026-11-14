# A released team not listed in a group: the request misses co-admins, then a label-step loop
> Summary: A team (`mint_actor`, first admin g, not in g's `group.0`) released by admin c: the request reaches neither co-admin a nor writer b, c forgets the team, learns it back from a without its forgotten rotation, and a and c then write a `label.0` step on the team on every pass, without end.
> Priority: normal
> Tags: node-sync, lifetimes, keys

- Shape: `destruction::a_forgotten_teams_rotation_leaves_no_index_row_spec_commits_5` with the team left out of g's `group.0` (drop the `items` lines). After `release` and `run`, only c holds the request header (a and b: none), though a holds the team as admin. Two gaps, maybe two issues:
  - The release request of a thing under its own label alone does not reach its other holders. A thing listed in g's `group.0` gets it everywhere (the test as written).
  - At the request's expiry c forgets the team whole: its rotation commit goes as `MemoryDrop::Gone` (must-not-hold). a still holds the team, so c learns its record back. c now has the team's epochs (`ix.secrets`) but no keysets (the rotation is not held). `issue_step` then finds something newer than the head on every pass, and a and c each commit a new `label.0` step per pass. `settle` never quiesces (10+ minutes in a debug test). Before `unindex_commit` re-derived keysets this case panicked in the index check instead.
- Questions: should a forgotten thing coming back from a holder make its forgotten commits fetchable again? And should a thing whose record arrives after its forget be judged destroyed again (the request is gone here)?
