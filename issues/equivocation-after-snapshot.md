# Equivocation under a snapshot's carried dot breaks un-merge
> Summary: A writer signs a second node-form commit on the counters of a first one a held valid snapshot carries; the receiver voids both but keeps the second's write (the snapshot "carries a write under its dot"), and debug builds panic "in-place un-merge differs from a rebuild". Pre-existing on main. Found by session-1.
> Tags: security, engine, perm

## Repro (fails on main and on session-1)
In `core/node/tests/it/validity.rs` (`setup`, `forge_reg` from session-1):
1. Bob (writer) sets `t:reg.0` = "bob" (commit c1, counters `lo..lo+1`); sync to Alice.
2. Alice compacts `t:reg.0` (snapshot Z carries Bob's write under `(Bob, lo)`).
3. Bob signs c2 on `(Bob, lo)` with a newer `ts`, value "forged" (`forge_reg`); Alice ingests it.

Debug build: panic at `apply/atomic.rs` "in-place un-merge of ... differs from a rebuild". With a removal of Bob between 2 and 3 (frontier not listing c1) Alice reads "forged" though c1 and c2 are both void (`body_valid` false).

## Expected (spec/permissions.md §5.2)
c1 and c2 are void (one dot, one write). Z misstates c2 (another `ts` and value under c2's dot) and Alice holds c2's body, so c2's writes under that dot count for nothing and Z's copy joins: "bob". The un-merge test "no held valid snapshot carries a write under its dot" is by dot, so it keeps c2's write; the misstatement path apparently does not run for a delta arriving after the snapshot when the dot's owner (`ix.ranges`) is the other commit.

## Notes
- Only a still-valid writer (or one whose demotion did not list c1) can do this; issues/session-sources.md "Equivocation by a valid writer" accepts the node split but expects the misstatement rule to hold where the snapshot carries the first write.
- Goes away for durable commits with session form (step 2 of issues/session-sources.md: a fresh nonce per start, so honest copies never overlap), but a malicious writer can still equivocate within one session.

Frontier study (notes/frontier-study.md): the frontier rule does not touch this; under it c1 is listed unless droppable, so a post-demotion c2 is unlisted and invalid, and where c1 was compacted both are invalid and Z's copy stands. The un-merge misstatement bug is the whole issue.
