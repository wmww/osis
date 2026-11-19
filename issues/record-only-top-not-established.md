# A record-only top's read epochs never establish at the order harness's node
> Summary: In `order::a_removal_leads_no_forger_to_two_record_linked_things_spec_commits_4` the node under test holds a top thing's record, its three role commits (keys.0, roles.0, secrets.0, all valid), two read secrets and a node-root strong to it, yet records no rotation for either read epoch, so the thing counts as dependent and is outside its node closure; `held::Walk` counts it in. On main's binary the same node holds it in 10 of 16 judged states (one rotation recorded at n 1). Which is right needs spec/crypto.md §4 Established read against those commits.
> Priority: low
> Tags: engine, keys, tests

## How it shows
Seen with a probe in `held::compare` printing, per thing, `Walk::closure` against `closure_holds`, the record, the held commits on it and `ActorEpochs` (branch: `rotations` empty at both read epochs, `established: None`; three other commits pend for the record of a thing never delivered). No test fails either way: the model judges the thing's content as absent from the history.

## To do
Find whether the three role commits are the rotations of the held epochs (then the epochs are established by spec/crypto.md §4 and the engine misses it, perhaps because the history box of the keyset epoch is not in the `secrets.0` part the trimmed delivery sends), or whether the held secrets came from a box of another commit (then the engine is right and `Walk` must model establishment, or skip such things).
