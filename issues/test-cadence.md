# Test cadence and tier-1 cost
> Summary: Act on notes/test-value-study.md: big random runs find few bugs (reading, new targeted tests and dogfooding find most), and where seeds find bugs a rule was missing. Cut per-branch oracle sizes, stop rerunning old ranges, one all-core run per box, study after a second seed fix in one area, bring tier 1 back under its rule.
> Tags: tests

1. Per-branch oracles (notes/testing.md Tiers): the touched area only, at about a tenth of today's default sizes, on a fresh offset; breadth only in periodic runs when the box is idle; never rerun already-run ranges (found about 2 bugs in about 200 tasks). Update notes/testing.md and notes/coordination.md (Test budget, briefs).
2. One all-core test run at a time per box (three agents in oracles made gates 13 min and tier 1 11 min).
3. Rule for coordinators: a second seed-found fix in one area stops patching; the next task is a study of the class (every chase so far ended that way: notes/order-study.md, notes/epoch-establishment-study.md, eph-unify).
4. Tier 1 back under "a few seconds per test": 22 pinned `seed_<n>` tests in osis-node `it` take 10-30 s each (180 thread-s): pin shrunk histories in their one failing order instead; `order::arrival_order_settled_small_spec_commits_5` (38 s, sets the binary's wall) to a smaller default with a `_large` twin. Then refresh the stale cost figures (notes/testing.md, notes/build.md, CLAUDE.md "about 80 s": now 152 s, 1900 CPU-s quiet).
5. notes/testing.md's per-branch rotation line: add `--skip repro_` (open-issue repros fail by design).
