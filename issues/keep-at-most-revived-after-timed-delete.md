# A body that regains a live write after its timed delete was sent loses it at the server
> Summary: Under a relative keep-at-most, a right holder sends a delete timed at the plain bound once a body has no live write; if a validity flip (or redo) later revives one of its writes, the node now keeps the body (bound plus `AT_MOST_GRACE`, `retention::recheck_at_most`, and timers re-judge when due), but the server still deletes at the plain bound with no carrier under the label. Also on main.
> Tags: node, sync, retention

Repro: none yet (needs an author revoked after a body's writes died, then re-granted, with a timed delete pending at a server).

## Technical details
Locally the bound follows liveness: a validity flip re-runs `check_at_most` for the aspect's held bodies, and a due keep-at-most timer re-judges instead of dropping blindly. At the server a timed delete cannot be withdrawn (spec/sync.md §5: one pending time per entry, the earliest wins). Options: a carrier snapshot written when a body with a pending timed delete turns live (the pass could check `state.timed` entries against `body_live`), or re-uploading the body under a fresh blob ID after the delete (must-hold already does this once the entry is gone, so the residue may be a window, not a loss: confirm).
