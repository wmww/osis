# codec-direct
- The measurement's `tools/heavy` waited a long time for another branch's gate; the task worktree could not be rebased meanwhile (the copied test binaries read fixtures from it), so the rebase waited on the lock too.
- A `Value`-tree oracle copied from four files needs every format change on main ported into it by hand: keep such oracles only while a change is in flight.
- Review: generated vectors are not committed, so "byte-identical" needed a throwaway test dumping every generator's file, run on the branch and on a detached main in the same worktree, then diffed. A by-hand `vectors --dump <dir>` would make this one command.
- `cargo fuzz build` takes one target per call (several names: usage error, exit 2, easy to miss in a background run).
