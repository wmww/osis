# m1-mono-review
- A mutation reverted with `git checkout <file>` also reverted review edits to that file not yet committed: wip-commit before every mutation, not once per batch.
- `tools/heavy --short` stops a run at 115 CPU-s with no partial output; 100,000 story worlds of a probe test (283 CPU-s) needed the plain lane. Size probes by the README's CPU-s per world first.
- A `tiny`/story check labelled `T` (trusting) counted worlds whose trusted write ended void, which read as trusting nothing: the "stray at trusting nodes" figures mixed the two. Label by what the reading trusts in effect.
