# rebuild-notes
> Summary: Workflow notes from the rebuild-dropped-body-notes branch.

- The issue guessed all five notes were one problem; one (an epoch's snapshot mark) was a plain persistence bug: set in memory, saved only when establishment changed, so even a fast reopen lost it. Diffing the full `IndexDigest` first (with `show`) sorted them in one run.
- Review: the walks oracle printed a whole `IndexDigest` tuple on mismatch (850 KB of output); `open_equals_rebuild` now asserts `first_diff` first. A randomized secrets-compaction walk found three more open/rebuild gaps in a few minutes that the hand-written test did not.
