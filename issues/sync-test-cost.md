# The differential and the simulations cost about ten times their budget
> Summary: with content flowing, one differential history costs 31 G instructions (clean) to 55 G (with faults) and the 9 simulations 2,469 G at 8 seeds, against notes/sync-test-harness.md's 4 G a history and 350 G for the simulations; the defaults are cut to fit (4 histories each, 1 seed per simulation) until the cost is found.
> Priority: normal
> Tags: sync, tests

- Measured (`tools/icount`, debug, one process, sync-integrate-4): a differential world of 3 nodes with contacts introduced (`history::world`) 5.2 G; `clean_histories_converge` at 10 seeds 310 G, `histories_converge` at 10 seeds 551 G; `sims::` (8 seeds, one ignored) 2,469 G; the rest of the binary 230 G.
- So setup is a sixth of a history; the 40 steps (a few grants, rotations, writes, runs to quiet) are the rest. Count the work per step (deliveries, settle rounds, engine transactions, judgements) at n and 10n writes to find what grows; candidates: read judging every commit at each start or restart, opens testing every sync ID at each connection, the profile sync IDs `introduce` adds to every node.
- Defaults until then: `convergence::{clean_histories_converge, histories_converge}` 4 seeds each, each simulation 1 seed; `OSIS_FULL=1` keeps the large sizes (1,000 histories, 80 seeds a simulation). 200 histories ran clean of all but the three reproducers in issues/sync-convergence-leftovers.md.
