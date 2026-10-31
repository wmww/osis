# A commit's partial copy pends forever when its full commit never reaches its things' labels
> Summary: A node that syncs K and holds only part of a commit on K (a `/members` chain copy, an edge-only inbox blob) waits for the rest from K's label; authors place the full commit there first (spec/sync.md §5 Order), but past `PLACE_WAIT` or in the exempt cases the copies go anyway, and a full commit that never lands leaves the receiver waiting forever. Every remaining fix is a policy trade: owner call.
> Tags: node, sync

## Where it still happens
- Bound (`PLACE_WAIT_MS`, 5 min of connected time): the full commit not at any server of K's labels by then (server down, deposit refused for good), the copies go with a diagnostic. Test `deposit_queue::projections_go_after_the_bound_spec_sync_5`: the sharer pends `WaitDeltas` until the deposit lands. Forever only if it never lands (author's disk lost, or it lost the right to deposit).
- Exempt by design: removals and `/keys` writes (spec/permissions.md §3), and every `carry_out` placement (a removal's First copies, a grantee's home copy, L's card). The full commit follows in the same sync; forever only on author loss in between.
- Copies by non-authors (a grantee's chain naming the grant) rely on the author's order; author disk loss before the commit is accepted anywhere leaves them pending.

Not seen in the sim since the placement order: `link_race`, `link_redeem` seeds 5000..6500 green. Effect when forever: K-syncers never apply the commit, nor the author's later writes whose chain runs through it (`MissingChain`), while readers of the copy's label that do not sync K apply the copy alone (spec/permissions.md §4) and see those writes: the two groups read differently.

## Why there is no narrow fix
Every forever case is "the full commit exists nowhere a K-syncer can fetch". So:
- Fetch the rest elsewhere: nowhere holds it (the author's node is gone, or never got it to K).
- Sender sends the whole commit with the projection: the projection's label has readers who may not read K. A whole copy under it gives them K's non-membership deltas (content leak) and `/secrets` boxes (size, spec/permissions.md §4). Safe only for commits touching only membership aspects; even then it costs a box set per copy and duplicates bodies under K.
- The projection applies alone at K-syncers: that is weakening atomic apply (below).

## Options (owner call)
- (a) Unbounded hold: `PLACE_WAIT` = infinity (keep the diagnostic). Closes the bound case; exempt and author-loss cases remain. Cost: while K's labels cannot take the commit, the author's copies, inbox blobs and its writes under other labels that the chain verifies wait (a dead K server blocks that member's writes in the target until K's label is replaced). The bound is on the sign-off list (notes/arbitrary-values-table.md). Arguably more consistent: today past the bound the two reader groups above diverge; with (a) nobody sees the writes.
- (b) Membership-only commits go whole: a projection of a commit touching only membership-class aspects carries every delta K-syncers wait for. Closes all three cases for such commits (redemptions, grants, rotations are membership-only). Cost: box bytes per copy; the spec §4 "projected to edge deltas" rule changes; mixed commits keep the residue.
- (c) Receiver rule: a part on a synced thing that the receiver holds only as a projection counts as held for atomic apply (joins on arrival, as a late delta of an applied commit does). Weakens atomic apply for membership commits (a K-syncer applies a grant before its boxes); no timeout state.
- Rejected: a receiver timeout (treat a part no reachable entry supplies as never coming): a timeout state.


Owner decision (round 13): option (c), consistent with cover-deleted-part-pends: a part on a synced thing that the receiver holds only as a projection counts as held for atomic apply; the rest joins on arrival. No timers, no extra bytes. Accepted cost: a K-syncer may see a grant before it holds the grant's boxes (an admin may re-seal needlessly).
