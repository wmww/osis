# invalid-body
- order.rs `alike_exchanged`'s families give bodies again only by `held`; a part reopened to missing reads as held, so `drop_flips` needed a `missing` case. Easy to miss.
- A disabled fix passed the main oracle at first: the "no death, no bound" excuse also relied on the keep-everything node's deaths, which the fix moves. Worth probing every oracle check with the fix off.
- Review: `.worktrees/` was removed by hand mid-build (compiler panics, then a failed manifest load; git then silently acted on the main checkout). The rebased commit survived on its branch; a new `wt claim` was a cold build, under 2 minutes here. Uncommitted probes went with it: keep them in the scratch dir.
- Review: a seed failing in a `_large` order oracle shrinks silently for many minutes per seed (5 min at best, 30+ with several), which looked like a hang; run a stuck oracle with `OSIS_ORDER_SHRINK=0` to see the failure at once.
