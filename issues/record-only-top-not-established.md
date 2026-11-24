# A record-only top's read epochs never establish at the order harness's node
> Summary: In `order::a_removal_ordered_before_a_forgery_is_evidence_on_two_record_linked_things_spec_commits_4` the node under test holds a top thing's record, its three valid role commits (`keys.0`, `roles.0`, `secrets.0`), two read secrets and a node-root strong to it, yet records no rotation for either read epoch, so the thing counts as dependent and outside its node closure, where `held::Walk` counts it in. Which is right needs spec/crypto.md §4 Established read against those commits.
> Priority: low
> Tags: engine, keys, tests

No test fails either way: the model judges the thing's content absent. Seen by a probe in `held::compare` printing, per thing, `Walk::closure` against the engine's closure, the held commits and the epochs (`rotations` empty at both read epochs).

To do: find whether the role commits are the rotations of the held epochs (then the engine misses establishment, perhaps because the trimmed delivery's `secrets.0` part lacks the keyset epoch's history box), or whether the held secrets came from another commit's box (then `Walk` must model establishment, or skip such things). Re-check after accounts piece 1 (minting with a key), which changes how such a thing gets its epochs.
