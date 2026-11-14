# mintings
> Summary: Footguns met on the minting-copies branch.

- tools/spec_map.py splits a citation's parenthesis on `;` into rule names, so a gloss with a `;` reads as a stray anchor naming no rule; the message quotes the whole parenthesis and does not say which piece failed.
- `Mutation::expires_all` covers only the aspects written so far: a mutation that only creates a thing (`new_thing`) gets no expiry on its `created.0`, silently. Set a value first.
- A thing known by its record alone reads `None` from `get_typed(t, CREATED)`; the record is `engine.core.created(t)`.
- (review) The worker's cross-node minting test passed with the drop rule's expiry check removed: an e2e for a cross-node rule needs a mutation row of its own, not only the fake-ground unit's.
