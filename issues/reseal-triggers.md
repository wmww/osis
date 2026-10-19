# Re-seal: a residual wrongful re-seal across a fork, and members no automatic trigger reaches
> Summary: After the model-checking fixes (a removal travels in its rotation; stranded heartbeats also on a refused claim; deposit-seed refresh is a MAY) two residues remain: (R1) a node that reads a fork-merging rotation before the branch carrying the removal can re-seal the removed member; (R2) a member whose deposits are refused (seed refreshed) or that cannot deposit at all has no automatic re-seal trigger and depends on a human. Both sit inside spec/requirements.md's accepted limits for re-seal, but R1 touches the removal guarantee. Owner to pick: accept for the MVP (recommended) or add a mechanism.
> Tags: owner-call, security, permissions, crypto, sync

## Background
TLC (models/tla/rotation, R1 and R2 in its AMBIGUITIES.md) found: an admin that downloads a rotation before the removal it covers re-seals the removed member at the new epoch, and the member then reads post-removal content from an honest server (it holds the current sync key); and a member whose next step's claim set the server dropped can neither walk to the head nor heartbeat, so nobody re-seals it.

Fixed in the spec (conservative reading, implemented by membership-flows and node-sync):
- spec/permissions.md §3, spec/commits.md §2: the removal or demotion and the rotation of the target's roles it requires are one membership commit. A held rotation therefore omits a current member only when its author did not know the member (grant raced), which is exactly the legitimate re-seal case.
- spec/permissions.md §3: a re-seal decision is taken after a sync pass of the actor's labels that fetched everything; no automatic re-seal of a member whose `until` is within `MAX_DRIFT`; re-seal boxes go to the member's newest keyset the node holds; delivery by inbox blob (nodes: direct connection); label delivery dropped (the member could not open the label anyway).
- spec/permissions.md §4: the stranded heartbeat is also placed when a claim on the walk is refused, wrapped under the newest secret the node holds (spec/crypto.md §5), so it can be placed without opening the label.
- spec/crypto.md §3: the deposit-seed refresh on rotation is a MAY (was SHOULD): refreshing silently refuses the stranded heartbeats of members that missed the rotation.
- spec/crypto.md §4: a grant or re-seal re-writes the history boxes of the epochs it boxes, so the recipient reads older content (R3).

## Residue 1 (R1 across a fork)
Trace in plain words: a1 removes m1 and rotates to e1 in one commit. Concurrently a3 rotates to e1' (boxing m1; it did not know). a4, holding both, rotates to e2 superseding e1 and e1'; the rotation commit is wrapped under one of them (the newest, ties by nonce), say e1'. a2 holds e1' but has not yet received e1's commit (it is under the label at every server a1 used, but a2 synced a peer or server that had e2 and e1' first). a2 reads e2: m1 is current in a2's timeline (no removal) and has no box at e2, so a2 re-seals m1 at e2 by inbox; m1 reads e2 content until a1 sees m1's box and rotates again. Needs a fork, a reorder, and a2 acting on a partial state; the "after a full sync pass" rule closes it at any server holding e1.

Options:
- (a) Accept: record as a limit (notes/permissions.md). Cost: a rare wrongful re-seal, healed by the next rotation; violates "the member stops reading new content once a writer has written after the removal" in that corner.
- (b) Pending-chain rule: a rotation is pending (not applied, not a re-seal trigger) until the node holds the rotation commits of every epoch it supersedes, or a `/secrets` snapshot covering them. Closes the corner; cost: a definition of "covering" for rotation chains after compaction, and rotations stuck pending at nodes that joined after the compaction of a superseded branch.
- (c) Explicit exclusion marker: a third `box` enum case `excluded` written by a rotation for each departed member it knows; a node never re-seals a member marked excluded at a current epoch unless a later edge write re-grants it. Precise per epoch, no ordering dependence; cost: a new enum case (wire), and later rotations must re-list departures or the marker expires with the branch.

Recommendation: (a) for the MVP; revisit with (c) if the simulator or an app shows the corner.

## Residue 2 (R2 with refused deposits)
A member that reaches a refused claim places a stranded heartbeat by deposit. The deposit is refused when the admins refreshed the deposit seed since the member last read `/keys` (now a MAY), or when the label's budget is full. Then no automatic trigger exists: the member is boxed at every epoch (no "missing box") and heartbeats nothing. It is reached only when a human asks a co-member to re-seal (the client offers it), or through a direct connection to a co-member that may rotate.

Options:
- (a) Accept: within spec/requirements.md "re-sealing is triggered, never guaranteed"; the recommended default is not to refresh the seed except against abuse.
- (b) Claim events in the label log: the server logs a verified claim (step ID, slot) and admins map the slot to the member through the claim set they hold in `/label`, re-sealing claimants whose next rotation is compacted. Reliable and deposit-free; cost: a new log event kind (wire), and the server learns nothing new (it already sees which slots claim).
- (c) Servers keep claim sets for the whole path (32 B per padded reader per step, never dropped): the walk always reaches the head, where the member can at least open and download; the heartbeat problem stays.

Recommendation: (a) now; (b) is the right mechanism if stranded members turn out common.

## Conservative reading meanwhile
Implement the spec as edited (above). Clients: offer "re-share with M" by hand to any member that may rotate; do not refresh the deposit seed on rotation by default. notes/permissions.md and notes/sync.md record both residues under accepted limits until the owner decides.
