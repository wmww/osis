# Local-dating no-churn test no longer tests different datings
> Summary: `negative::deletion_across_local_dating_no_churn_spec_sync_6` meant two right holders with different death dates for X; both end up dating at Y before the crossing, and with the dates really different the `must_carry` healing rule (spec/sync.md §6) says the later-dating node should place X again, against the test's claim.
> Tags: sync, tests

Deaths are dated per node, but any recompute (`replay_all`) dates from the held bodies in `ts` order, so two nodes holding the same bodies converge. In the test, once B syncs (A's compaction snapshot arriving), B dates X's death at Y like A: its keep-at-least equals A's when the loop starts, so it passes whoever wrote X.

Tried: B never holds Y (Y with no keep-at-least, `by: author`, covered by A's snapshot compacted before A goes online). B does date X at Z until A's drop time, but in the pass that places A's snapshot A also uploads Y (no snapshot under the label covers Y yet in that pass: established uncovered), B fetches it and redates at Y before A deletes X. So the dates still agree when it matters.

The real question is the rule: if B dates X 2 h later than A, then when A deletes X (past A's bound + `MAX_DRIFT`) B is still before its keep-at-least, so X is kept for B (`part_kept`), `must_carry`, and `delete_stands` is false: B uploads X again. That is the healing rule working as written, but the test asserts no re-upload. Needs a rule call: either dating differences are healing (and the test's claim changes to a bounded number of re-uploads, which loosens it), or a delete by a right holder past its own bound stands against another's local dating (no signed reason exists to check, as for keep-at-most).
