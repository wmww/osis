# codec-direct
- The measurement's `tools/heavy` waited a long time for another branch's gate; the task worktree could not be rebased meanwhile (the copied test binaries read fixtures from it), so the rebase waited on the lock too.
- A `Value`-tree oracle copied from four files needs every format change on main ported into it by hand: keep such oracles only while a change is in flight.
