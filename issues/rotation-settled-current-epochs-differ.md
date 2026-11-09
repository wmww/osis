# Settled holders count different current epochs of one actor
> Summary: The rotation property (`rotation::tests_property`, plain size from 48213) fails seed 48269: one actor, peers only, after settling the first admin counts two current admin epochs (peer 1's n2 and the withheld admin's n3) while peer 1, which made n2, counts n3 alone. Nobody merges: peer 0 is not the merger (n2's maker may rotate) and peer 1 sees no fork. Fails before the half-valid change too (rotation-gen tip). Not root-caused.
> Priority: normal
> Tags: keys, engine, tests

## Shape
Replay: `OSIS_ROTATION_START=48269 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_tier2_spec_crypto_4` (seeds go stale: if it passes, run a few hundred plain-size seeds from fresh offsets). One actor G owned by peer 0, every holder a peer, no forgeries in the failing history. Peer 1 rotates admin (n2); peer 4, given everything but 13 withheld commits, rotates admin to n3, presumably not listing n2. After settling, peer 0 counts {n2, n3} current, peer 1 counts {n3}. Supersession by history box (spec/crypto.md §4 Supersedes: at a node holding e's secret, the epochs e's history box lists) or a history add seen by one side only is the first suspect: the two views make the merge rule wait at both nodes.

Start from a minimal reproducer of the views, then decide whether supersession may differ between holders of e's secret (it must not, or the merger rule needs to read the same set at each).
