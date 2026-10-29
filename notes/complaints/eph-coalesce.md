# eph-coalesce
- The tier-1 `Net` harness only settled everything, so no test (the random ephemeral differentials included) ever wrote while an upload was in flight; added `Net::round` (one hop per call) and an in-flight variant of the random window run.
- A node-sync step costs about 0.4 ms in dev even with nothing to do: 10 nodes at 30 writes/s for 6 simulated s took 30 s of test time (the tier-1 rate test is 1 s; the minute is tier 2).
- The presence review's figure (10 authors at 30/s over the 20 000/min delete limit) did not hold as stated: one commit per write is about 17 400 deletes/min at 10 authors; the limit is reached at about 12.
