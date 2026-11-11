# A leaver cannot confirm its removal once the source has rotated
> Summary: A leaver whose removal reached an admin by the admin's own pull from its log: the admin rotates, the leaver's host upload answers code 9 and every reopen code 1, so `placed` never holds and `leaving` and its secrets stay though the removal arrived. Recommended: `placed` also counts a co-reader's Applied (its reported position past the entry), the acknowledgment the stream already has; no wire change.
> Priority: normal
> Tags: sync, node, security

Repro: `repro_leaving_stays_until_a_source_has_the_removal` (core/test/sim/tests/it/no_server.rs).

`drop_left` forgets a leaver's secrets once its self-removal is `placed` (spec/sync.md §5): present at a host of each label. In the no-server shape Alice is the label's `peer://` host and also a co-reader: she pulls the removal from Bob's node log by her stream and rotates at once, so Bob's upload to her as host answers code 9 and his reopens code 1. `placed` stays false, `LabelStatus::leaving` stays set, and Bob keeps his old secrets and keeps dialing. The same happens in any shape where the removal leaves by a co-reader's stream and an admin's rotation reaches the hosts before the leaver's upload.

## What the leaver needs
Only what any own write needs: a source took the removal and will pass it on. Nothing about rotations: rotating is the job of whoever may rotate (spec/permissions.md §3).
- **Forgetting too early**: the removal may never leave the node. The leave silently does not happen: others keep listing the account as a member, keep sealing to it and may grant through it. This is a correctness failure of the user's action.
- **Keeping too long**: the leaver keeps secrets it already had, gets nothing newer once anyone rotates (rotations leave it out), and keeps dialing. This costs the leaver privacy and resources, but the group loses no confidentiality.

So the leaver keeps waiting until a source acknowledges, and it must see every acknowledgment the protocol already gives. A commit leaves a node by one of two routes: a host upload, acknowledged by the host's OK (presence), or a co-reader's stream, acknowledged by Applied (spec/sync.md §10 Reports: sent once the requester applied the message's bodies and stored its cursor). `placed` counts only the first route. That gap is the bug.

## Recommended
Count a co-reader's report in `placed`. Under a label L, an entry of the commit counts as held at a source when a peer the node served L to has a reported position (spec/sync.md §10 Lost: the first Pull's cursor, then each Applied's) at or past the position where the node's log first held that entry. Spec change: spec/sync.md §5 Placed says "present at one of its hosts, or reported by a co-reader sharing L (§10)".
- **The no-host clause follows the same rule.** The node's own store stops counting: with no host, only a co-reader's report counts. Today a leaver with `reach.0` published counts its own store as placed and forgets a removal nobody pulled.
- **Durable**: reported positions last only for the connection. When a report covers an own commit that `placed` waits on (`Leaving::actors`, almost always none), record it with the presence rows in that step, keyed by the source. The per-report cost is O(waiting commits), and nothing is kept outside leaving.
- **Who can lie**: only a peer that proved it reads L (the stream serves L only to such peers), or a host, as today. A false report makes the leaver forget before its removal spreads, which leaves it listed as a member. That is the same trust `placed` already gives a host's OK, and that member could just as well drop the removal after taking it.
- **Wire**: no change; Applied, its cursor and the Lost/Stop positions already exist.
- **Closes the repro**: Alice applies the removal from Bob's stream, stores her cursor and answers Applied whatever she does next. Her rotation ending Bob's membership does not withdraw the Applied, and a Lost or Stop carries the same position. Bob then records the removal as held at Alice and drops it. If the connection drops before the Applied arrives, Alice's stored cursor comes back in the first Pull of the next connection, provided her record of Bob survives. The worker should check that Alice answers Applied in the step she rotates. The test then loses its `#[ignore]`.
- `placing` (spec/crypto.md §4, the leaver's own departure blocks nothing until placed) uses the same `placed` and needs no other change.

## Rejected
- A code 1 or 9 refusal, or a step without the leaver, as the signal: these answer any rotation the leaver is not in yet, and a hostile host can send them for nothing.
- Names of the rotation's departures in a new `InboxPayload` position, checked against the `keys.0` digest: a wire change, it leaks other departures' names to the leaver, and it proves more than the leaver needs. It also needs the deposit seed out of the rotation's `keys.0` delta (the delta cannot be split, and a copy hands the leaver the fresh seed).
- Recomputing the names digest from the leaver's own timeline: it fails whenever the rotator held a lowering the leaver lacks, and it needs the same seed split.
- Writing the deposit seed in a commit of its own, or encrypting it in `keys.0` under the new read epoch: these only enable the two options above, reshaping rotations for one feature's need.
- The leaver uploading the removal first at connect and waiting for the OK: its own ordering does not control a peer's pull. Another admin's rotation reaching the host first still gives code 9. Holding the removal out of its own stream until the OK arrives would be a carve-out.
- A bounded leaving period: a picked number that fails the 0/infinity test (notes/arbitrary-values.md). Any bound loses the leave for a node offline longer than it. Giving up is the user's call (issues/api-leaving-give-up.md).
