# Finding disputes costs one walk per unapplied removal
> Summary: `Timeline::disputes` walks once more for every unapplied trustable op with seeds, so a removed admin signing k removals of its remover makes the scan k walks (quadratic in held ops) on every re-evaluation that asks; harmless while nothing calls it, a bound is needed before step 4 asks at detection.
> Tags: security, perm

notes/owner-removal-plan.md step 3: a dispute candidate is a held edge write with a frontier on another holder's edge that the settled walk did not apply, whose seeds are not empty; each costs one walk. Honest histories have none. A removed admin can sign any number: n0 removed by n1 at 10^4, then k removals of n1 stamped after it, each not listing n1's removal. Only the first is a dispute (the rest find n1's edge already gone), but each costs a walk. Measured (debug, k honest background writes plus k such removals): k = 50, 100, 200, 400: `disputes()` 4.7, 18, 70, 279 ms against `evaluate` 1.8, 3.3, 12, 53 ms. At 10^4 edge writes a walk is 0.3-0.5 s (release), so 10^3 such removals cost minutes, again on every held-set change once step 4 records defaults at detection.

Bound today: walks = 1 + void-shrink rounds (at most the trusted ops held) for `evaluate_with`; plus one per candidate for `disputes`. Grouping candidates by seed set does not help: seeds carry R's point.

Possible rules (none checked against the model): a candidate only when its author held admin authority over the holder's edge at some point the seeds could restore (static, like the victim set); or one walk per (author, holder) with the union of the candidates' seeds at the earliest point, then per candidate a cheap check.
