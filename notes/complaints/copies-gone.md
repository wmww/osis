# copies-gone
> Summary: footguns met building the copy invariant (copies-outlive-purge-expiry).

- I checked main before starting and it had not moved; list-expiry landed minutes later. I then spent a bisect on a "rebuild differs" failure (seed 9260000) that was list-expiry's class 1, already fixed on main. Before blaming your own diff, `git log main -1` again and rebase.
- A writer rule that changes commits (here: copy-expiry splitting a write into its own commit) moves seed-pinned order tests onto other histories (`held` index lists go out of bounds). `Step::Old` replays a step as a writer before the rule.
- Review: checking a probe against main means `git checkout main -- core/engine core/crdt` in the worktree and a 2 to 5 min rebuild each way (release: twice that); a wip commit first keeps the restore safe.
- Partial strip: `engine.commit` refuses a write that splits, so a test of the per-write copy-expiry split must write through `engine.write` (`Written::also`); the order harness's `commit` steps refuse such writes silently (a `why` reason).
- Two "fix-disabled" probes per test (reader whole-strip, writer whole-delta T) each cost a 1-2 min rebuild; an env-var guard in the probed function (reverted after) let one build serve several probes.
