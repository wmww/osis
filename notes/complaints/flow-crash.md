# flow-crash
> Summary: mishaps met while making flows' deliveries crash-safe.

- A test filter by a shared word (`survive_a_crash`) silently missed half of the new tests (`survives_a_crash`): read the `test result` counts, not just "ok".
- A crash test asserting "some entry of the commit under the label" passed without the fix: another path (the holder's keyset certificate) places a different part of the same commit. Assert on the part the delivery owns.
- Review: rebase onto main conflicted only in notes/sync.md (one long Implementation line per topic: any neighbouring edit conflicts the whole paragraph); the gate after the rebase took 302 s, recompiling dependencies (thiserror etc.) in the warm worktree.
