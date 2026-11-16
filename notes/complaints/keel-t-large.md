# keel-t-large
- One-seed custody replays took 3-4 minutes each under a box load of 40-60 (8-25 s idle); triage of ten seeds was mostly waiting.
- The custody mirror's failure dump shows only the model's items: what the engine actually boxed (a t commit's box records, an epoch's history list) needed ad hoc probes each time. Classifying t commits by their header aspects (keys.0) silently mistook re-seals for rotations.
- After rebasing, main's own custody differential failed 3 of 200 at small size (clean at ac45a7ca4); separating my changes from main's took a run with main's harness swapped in. Filed issues/custody-differential-main-regression.md.
