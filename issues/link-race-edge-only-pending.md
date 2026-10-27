# A commit's partial copy can still pend for ever in a few residual cases
> Summary: A node that syncs thing K and receives only part of a commit on K (a chain certificate projected to its `/members` deltas, an edge-only inbox blob) waits for the rest from K's label; authors now place the full commit there before any projection elsewhere (spec/sync.md §5 Order, notes/sync.md Placement order), leaving the residues below.
> Tags: node, sync

## Residues
- The wait is bounded (`PLACE_WAIT_MS`, 5 min after the commit): if the full commit is still not at a server of its things' labels then (server down, deposit refused for good at every server), the copies go anyway with a diagnostic and receivers that sync K pend until it arrives, as before.
- Exempt by design: removals and `/keys` writes (spec/permissions.md §3), and every `carry_out` placement (a removal's First copies, a grantee's home copy, L's card). Their partial copies can still precede the full commit.
- Copies by non-authors (a grantee's chain naming the grant) are not ordered; they rely on the author's order (the grantee received the commit after it was placed). Disk loss of the author before the commit is accepted anywhere leaves them pending.
- Rejected: the receiver-side rule (treat a part no reachable entry supplies as never coming): a timeout state.
