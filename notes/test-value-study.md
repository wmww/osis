# Test value study: what the heavy runs cost and what they find

> Summary: quiet-box costs of tier 1, the gate and every per-branch oracle (main aa4592a6); which kind of check first found each product bug over about 200 merged tasks; the finding that seed-found bugs cluster where a rule was missing (arrival order × retention × validity, epochs, ephemeral) and chases ended only by studies; recommended changes.

## Cost (quiet 16-core box, load under 1, warm target, main aa4592a6)
- Gate (on main, so everything, 5-seed sweep): 237 s. Tier 1 143 s / 1761 CPU-s inside it; sim sweep 26 s / 396; kit tests 46 s / 287; the rest about 20 s.
- Tier 1 alone: 152 s wall, 1900 CPU-s, 2834 tests. osis-node `it` 65 s wall / 985 CPU-s, of which `order::` 421 thread-s (42%) and `fill::` 113. Under the parallel run `order::arrival_order_settled_small_spec_commits_5` showed 38 s and the 22 pinned `seed_<n>` tests 10-30 s each, but alone they take 7.9 s / 18 CPU-s and 2-7 s: contention, not outliers (settled_small went to 2 seeds; the pinned ones stay, being regression guards that can no longer be shrunk). notes/testing.md's tier-1 figures (45 s / 476 CPU-s, then 868 CPU-s after slim-tests) are stale.
- Per-branch oracles at default sizes (wall s / CPU-s): order alike 52/763 (testing.md said 13/187), exhaustive 136/1897, purge 83/1236, purge_import 40/565, purge_rows 27/382, required 29/405, removed_author 3/37, keep 6/87, eph random_window 33/518, eph churn 25/388, perm tier 2 217/3387 (said 1860 CPU-s), crdt large set 30/42, paged apply 82/1026, rotation harnesses 34/529, sim eph 30 seeds 8/108, TLA small 213/294. All of them: 13.4 min wall, 11,370 CPU-s (a fifth of a box-hour); the `order::` family alone 6 min, 5250 CPU-s.
- Most are all-core: three agents each in an oracle run at a third of the speed, which is why history shows gates of 13 min and tier 1 of 11 min (tools/agent-times.py; Nov 3 medians). The rotation set without `--skip repro_` fails on the pinned open issue keyset-name-later-admin-path (expected).
- Session ced816f8 (635 agents): oracles 25% of agent time, gate 13%, filtered tests 13%, tier 1 8%, sim-sweep 7%; model 30%.

## What found the bugs (items 150-268, d1-d78; counts ±15%)
| first found by | bugs |
|---|---|
| reading in review, audits, simplification passes | ~180 |
| a new targeted test or differential for the branch | ~45 |
| per-branch tier-2 at default size (fresh offsets) | ~25 |
| larger ranges, periodic runs, wide sweeps | ~9-13 |
| dogfooding / real use | ~10 |
| tier 1 | 2 |
| TLA | 0 new |
Re-running already-run ranges found about 2 (both regressions). Periodic runs 5, 6, 7, 13 and periodic-d found no product bug.

Of the ~38 seed-found bugs, ~14 were slips against a clear rule (paged equals whole, etc.) and ~24 had no rule yet: the fix wrote a new spec sentence, a stated limit, an accepted divergence or a redesign. They cluster: arrival order × retention × validity (~30 items, ending in the oracle narrowing d73 and five accepted requirement exceptions; spec/commits.md 388 words on Oct 16 to 6936 now, unchanged by the spec refactor, carve-out phrases 10 to 37), epochs/rotation (~10 rounds, ended by notes/epoch-establishment-study.md), ephemeral (~12 rounds, ended by eph-unify). Each chase ended with a study that found one root shape, never with more seeds. The shape of the first: validity is non-monotone in the held set and nodes drop data (keep bounds, expiry, purge), so "what a node reads" is defined only as what it computes from what it happens to hold (notes/convergence-study.md §0); there is no reference model of that, unlike crdt-model and roles-model.

## Done (issue test-cadence)
Per-branch sizes are a tenth of full by default (`osis_base::testenv::large`, `OSIS_FULL=1` for periodic): the whole per-branch set 13.4 min / 11,370 CPU-s to about 2.5 min / 950 CPU-s quiet. Rules in notes/coordination.md: no rerun of run ranges, one all-core run per box, a study after the second seed fix in an area. Cost figures refreshed in notes/build.md, notes/testing.md, CLAUDE.md.

## Recommendations
1. A reference model for retention, validity and apply (what a node holding set H reads, deaths, drops), written from spec/ alone by a fresh agent like the TLA method (notes/testing.md, Models); the order oracle compares each node with it, not only orders with each other. Its ambiguity list is the rule backlog, found before seeds find it.
2. Rule: a second seed-found fix in one area stops patching; the next task is a study of the class (every chase so far ended that way, after 10-30 patches).
3. Cadence: the per-branch oracle set at a tenth of today's (one area, small default, fresh offset); breadth only in periodic runs when idle; never rerun old ranges. One all-core run at a time per box.
4. Tier 1 back under its few-seconds-per-test rule: pinned seeds as shrunk histories in the one failing order, `settled_small` to a smaller default (its range in a `_large` twin).
5. Spend the saved time where bugs come from: reviews that read, audits, simplification passes, dogfooding, new targeted differentials.
6. For Tess: options 3-5 of notes/order-study.md (expiry exception, nesting rule, dropping relative keep-at-most D > 0) cut the rule surface that produced the chase.
