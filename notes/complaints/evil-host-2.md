# evil-host-2
- sim-sweep's summary `0 failing` leaves out KNOWN failures; only the `failing: osis_sim::replay(...)` line shows a KNOWN seed still fails. A bisect script grepping ` 0 failing` read every commit as passing. Grep for `failing: osis_sim` instead.
- The sim's "not quiescent ... one more round changes" list held every host log event since the wait began, not one round's; it made a node stuck busy toward the evil host read as churn at the honest host, and the issue was filed on that reading. Fixed on this branch.
- Bisecting the sim across ~180 commits took about 15 min of builds; two commits mid-refactor (net-3i3b) did not build and had to be skipped.
