# current-epochs-converge
- The task's issue (issues/rotation-current-epochs-differ-seeds.md) and its known_failures lines exist only on the unmerged forged-epoch-opens branch, not on main where the worktree was claimed: found by searching other worktrees. Whichever of the two branches lands second deletes them.
- The property's failure prints `left` as the peer being compared and `right` as the first admin, opposite to the message's "peers 0 and 2" order: misread at first which peer counted the extra epoch.
