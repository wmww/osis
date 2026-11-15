# sibling-home
- The issue named the missing part as `account.0` on D; it was `keys.0` on P (sealed under the epoch the rotation mints), and neither was the cause: the home went first, by the roster reading P alone. A probe opening each new home blob at the sibling with the network partitioned (`open_entry` by hand) found it in minutes; the trace alone did not.
- `World::flush()` after a write delivers to every peer: to hand blobs over by hand, partition first.
- A trial merge of the branch with origin/main (fork-sides) conflicts in a dozen engine files; the removed-node test waits on that merge.
- Review: the brief's base moved mid-review (thing-lists-w landed as identical trees under new IDs); one `git rebase --onto` fixed it, but a run started before it builds the same tree under the old IDs.
- Review: `OpenedBlob::ais` lists every section's aspects, opened or not; a test checking what a node read must use `commit.parts`. A probe first passed for the wrong reason.
