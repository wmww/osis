# Churn seed 9130190: a compaction snapshot storm (upload and delete without end)
> Summary: Compaction snapshot storm (churn seed 9130190, still hanging on main): valid writes nested in a demoted creator's un-merged record are counted by the trigger but no snapshot covers them, so a writer uploads a snapshot and deletes the previous one every pass, forever. Needs a study of the class, not a patch; drop-rejoin items 1+2 (its prerequisite) are built.
> Priority: normal
> Tags: ephemeral, engine, tests

Replay: `OSIS_SEED_TIMEOUT_SECS=15 OSIS_EPH_START=9130190 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large`. 1 of 300 seeds from 9130000; it hits the 15 CPU-s limit ("hung"). Node 0 on host 0 alternates Upload of a fresh `ContentSnapshot` of `win:cursor.0~` with a Delete of the previous one (about 2400 uploads in 15 CPU-s; not re-traced since memory bodies moved onto the durable sync path).

## Mechanism (traced before the memory path moved onto durable sync)
Steps (seed's log): node 1 `Set k1` (step 3), node 1 `Remove(<node 1's key>)` (4) undone (10), node 0 `Set k1` (6), node 1 `Put k1, Set k2` (12) undone (13), expiring writes by 0, 2, 3, node 0 restarts (26), node 2 demoted (27), node 0 `Set k1` (29, its new session).

After the restart node 0 holds, of `win:cursor.0~`, two valid non-expiring plain bodies whose sessions leave no trace in its state: node 1's step-3 body and its own old session's step-6 body (both `Set k1`, overwritten by the step-29 `Set k1`). `held_cost` counts them (`frontiers_now` reflects them: valid, contiguous from counter 1): 2 bodies, 6404 > 2 x 3168. The snapshot it then writes (`snapshot_if`) prunes their sessions from its frontier (`frontiers.retain(&traced)`: spec/crdt.md §8, a session with no write left in the fragment is absent), and `covered(snapshot, body)` says `Some(false)` for both: the source is unlisted, so the join test decides, and joining the old `Set` into the fragment changes its canonical bytes. So the snapshot drops neither body, only the previous snapshot (covered-equal, higher ID), the aspect is dirty again, and the next pass writes the next snapshot: a storm of one upload and one delete per pass at every host, from a node that may write the aspect, forever.

Not every `Set` over sessions does it: a one-node, three-session `Set k` repro (two restarts, a co-writer holding) was covered fine by one snapshot. The seed's shape has the undone `Remove` and the undone `Put` on the same keys; which of them makes the join change the bytes was not traced.

## What is wrong
The trigger and the cover disagree on what a snapshot built now reflects: `held_cost` uses `frontiers_now`'s reflected set, `snapshot_if` then drops the sources that do not occur in the state, and `covered` for an unlisted source falls back to a raw join that does not apply the Absence rule (a reader takes an absent source as "no write left"). Either:
- the trigger counts only bodies whose source the snapshot would list (`sources_of` the state, as `snapshot_if` does): no storm, but those bodies stay held and must-hold at hosts for good (a leak per session whose writes all died); or
- `covered` applies the Absence rule: a held body stamped no later than a valid snapshot whose frontier does not list its source is covered (its writes are dead at every reader by spec/crdt.md §8). Then readers' `apply` must treat such a body the same way (never resurrect it on a raw join), or holders of the snapshot and late receivers of the body diverge.
Which one is right is a question for spec/crdt.md §8 and spec/commits.md §5 together (the second seed-found fix rule of notes/coordination.md: a study, not a patch). The first keeps the data model as it is and ends the storm.

## In real time
A writer that holds two such bodies of one aspect snapshots at every pass: a steady storm of one upload plus one delete per round trip per host, until it restarts (its memory goes) or the bodies expire (they never do: no `expires`). Users reach it by resets and undos on a shared map key across restarts; typing and presence (a register `set`) were not seen to.

## Next
A fix along the first option above (the trigger counts only listed sources) worked but was not merged: it makes durable snapshot cost bodies × state, and holds a session's later bodies for the whole demotion. The fix branch is gone; no third patch of that kind. Candidates for the study: an aspect whose state hides a valid held body is not compacted at all (no storm, no frontier walk; same growth bound as that fix); a node whose own write is un-merged starts a new session; dropping such bodies under the drop-rejoin refetch rule (issues/drop-rejoin-robust.md item 4).
