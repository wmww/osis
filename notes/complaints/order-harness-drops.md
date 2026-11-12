# order-harness-drops
> Summary: footguns met wiring node-sync's covered drops into the order harness's bare-engine nodes.

- node-sync's `drop_covered` mixed the spec judgment with sync bookkeeping (`forget_due`, carriers, `touched`), so a bare engine could not run it; split as `CoverPass` (engine + settled pairs), the loop body left in place so concurrent node-sync rewrites rebase cleanly.
- An icount baseline needs the old test binary: built by checking out main's copies of the touched files in the worktree, building, `git reset --hard`. Doing that while `main` had moved (or mid-rebase) checked out other branches' files too; a `tools/icount` mode taking two revs would save the dance.
- `held::compare`'s drop check judged a drop by "the body as last seen held", which a missing part, a waiting placeholder or an expired leftover between two compares made wrong: 27 of 300 plain seeds failed on the oracle, not the node, before the drop judgment read each part's state just before the drop pass.
- Each heavy hold for a by-hand seed replay waited up to 25 min for other agents' gates.
