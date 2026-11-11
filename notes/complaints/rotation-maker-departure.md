# rotation-maker-departure
> Summary: workflow notes from the rotation-maker-departure task.

- The seed was briefed as an engine bug; it was the oracle missing the stated invalid-grant limit (spec/crypto.md §4 Boxes). A failure message naming which box (commit, author, validity) gave the party the epoch would have shown that at once; tracing it took an ad-hoc debug patch.
- Bisecting by checkout across today's commits cost about 4 min of rebuilds and only showed the seed predates them: a fresh seed offset hitting an old shape.
