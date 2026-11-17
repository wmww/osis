# A removed holder keeping S unread that no reader registers at never stops
> Summary: A node keeping S unread stops (drops its entries) only when a Register moves its head past its sync secrets (spec/sync-judgement.md §6 Stops). Readers register only at open members, and a member J judges departed closes at once with no Register. A removed holder that opens S only after its readers know the removal (its ticket came late), but takes entries from a reader that did not yet know (J unknown blocks nothing), keeps those entries and S unread for good. OSIS_FULL differential seeds 1 and 39.
> Priority: normal
> Tags: sync, tests

## Seen
OSIS_FULL seed 1 (`differential::histories_hold_their_closure`), exposed by 8d4075946 (strip per blob: the new reader's fresh encryptions are entries the removed node takes); passes at 39a5d091c. Shrunk on its world (debugging aid, not a test): `[New(0), Run, Give(0, 0, Holder::Node(1), Syncs), Skew(3, 45000), Strong(1, None, 0), Give(0, 0, Holder::Node(2), Reads), Revoke(3, 0, Holder::Node(1)), Disk(1, 0, Fail), Rotate(3, 0), Run, Strong(2, None, 0)]`.

Seed 39 (likely the same; checked only as far as the shrunk script): `[New(1), NewIn(1, 0), Give(1, 0, Holder::Node(2), Reads), Strong(2, None, 0), Give(1, 1, Holder::Node(0), Syncs), Run, Strong(0, None, 1), Give(1, 1, Holder::Node(2), Reads), Revoke(1, 1, Holder::Node(0)), PowerOff(0), Lower(1, 1, Holder::Node(2), Reads), PowerOff(2)]`: node 3, node 0's sibling, keeps 12 entries of T1's sync ID after its account's sync grant is removed.

## What happens (seed 1)
- Bob (node 1) is granted sync on T and accepts, but T's sync ID S reaches him only by the ticket's deposit. Alice's sibling removes him and rotates.
- The deposit's write fails at Bob (code 4, refused for now); its retry lands after Alice's nodes know the removal, so they refuse his Hit (J departed) and register nothing at him.
- Carol (node 2) accepts T and opens S toward Bob before she holds T's roster (J unknown), registers the genesis step and streams entries; Bob takes three. Once she holds the roster she closes S at once (J departed) with a Lost and no further Register.
- Bob keeps S unread at the genesis step with three entries, for good: nothing moves his head.

Without the disk fault Alice's node registers the path at Bob while he is still an open member and he stops at the rotation's step (the event that ends sharing is still sent, spec/sync-opens.md §6).

## Candidate rule (not built)
Closing a store-class member because J turned departed first registers the recorded path past the peer's step, up to the first step whose sync key its credential cannot derive, so it stops. Open points: a Register waits for the step's role commits to show at the source (`Engine::step_needs`), which a departed peer no longer gets; and whether "departed" should end a member at `until` (as a credential no longer admissible does) instead of closing at once.
