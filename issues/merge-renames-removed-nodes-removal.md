# A merge names a removed node's removal of a sibling, past the cutoff
> Summary: a removal from D that a removed node's fork names counts in the fork window, and the merger's `rotations_due` names it again in the merge (`also`), though the merger received it after its own rotation closed its epoch. A removed node (which still holds its old epoch's key) can so remove any device for good.
> Priority: critical
> Tags: security, engine, accounts

## Shape
`rotation::tests_signing` world(3, 3): laptop (node 2) removes tablet (node 1) with its rotation x0; phone (node 0) removes the laptop (rotation R); the phone gets the laptop's removal and x0 after R; its `signing_due` re-keys D without the tablet and merges, superseding x0 unnamed but naming the laptop's removal of the tablet in its thing list for D. The tablet is off D's roster at the phone after a rebuild too. The laptop need not be unaware: one that knows of its removal signs the same removal at its old epoch and a fork naming it.

## Why
- `flows::signing::rotations_due` re-names every counting removal from D that no authorized counting rotation on the open line names; x0 counts until the merge, so its list makes the removal count, and the merge names it outside the cutoff (spec/permissions.md §5.5: a list names another's commit at e only if received before the earliest closer of e).
- The re-naming rule is not in the spec.

## Options
- Re-name only removals the merger may name by the cutoff (or its own); a removal named only by a fork the merge leaves unnamed falls with it, as the honest-write case does (the remover's listings save its own).
