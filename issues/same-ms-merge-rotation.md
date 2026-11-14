# A sibling's removal arriving in the ms of the own one leaves the merge rotation owed
> Summary: osis-sync `duties::a_rotation_owed_by_the_account_is_made_at_a_pass_end_spec_permissions_3` fails without `w.advance(1)` between node 1's removal and node 0 ingesting it: node 0's pass of D after the ingest ends (by `PASS_WAIT_MS`, nodes 2 and 3 off) yet `signing_due` still owes the merge rotation. Passes are ordered by pass place, not ms, so something else compares engine ms; a candidate is `flows::signing::nameable` (named "received before the earliest closer", `m.received < x`).
> Priority: low
> Tags: engine, sync

Not traced. Remove the `advance` and trace `pass_end` → `signing_due` at node 0 to find the ms comparison.
