# sheave-r18-engine
> Summary: `merge-branch gate --plan` without a branch name printed tools/claim's help and failed; with the name it moved the worktree's branch onto a fresh origin/main.

- `tools/merge-branch gate --plan` (as the brief worded it) fails with tools/claim's usage text, not merge-branch's: the branch name is required but the message names the wrong tool. With the name, the plan run re-claimed the branch, which rebased my unpushed local commit onto the newer origin/main mid-task (fine here, surprising for a "prints and exits" flag). A plan-only path that neither claims nor moves the branch, or a usage line from merge-branch itself, would have saved the detour.
- Integration tests cannot write an invalid part (`Mutation::unchecked` is crate-private), so a reproducer needing "a part dropped while invalid" had to find another route (dropped as covered). A test-only public way to forge a write would make such reproducers direct.
