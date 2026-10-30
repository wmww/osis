# rebuild-notes
> Summary: Workflow notes from the rebuild-dropped-body-notes branch.

- The issue guessed all five notes were one problem; one (an epoch's snapshot mark) was a plain persistence bug: set in memory, saved only when establishment changed, so even a fast reopen lost it. Diffing the full `IndexDigest` first (with `show`) sorted them in one run.
