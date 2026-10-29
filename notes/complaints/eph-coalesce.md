# eph-coalesce
- The tier-1 `Net` harness only settled everything, so no test (the random ephemeral differentials included) ever wrote while an upload was in flight; added `Net::round` (one hop per call) and an in-flight variant of the random window run.
- A node-sync step costs about 0.4 ms in dev even with nothing to do: 10 nodes at 30 writes/s for 6 simulated s took 30 s of test time (the tier-1 rate test is 1 s; the minute is tier 2).
- The presence review's figure (10 authors at 30/s over the 20 000/min delete limit) did not hold as stated: one commit per write is about 17 400 deletes/min at 10 authors; the limit is reached at about 12.
- Review: the worker's commit failed `cargo clippy --workspace --all-targets` (`manual_is_multiple_of` in a test, clippy of rust 1.99): run clippy before committing.
- Review: `Net` had no way to make one server slow while others answer; added `held_servers` (released by `release`). The worker's in-flight differential only delayed whole rounds, so a slow-vs-fast server split never happened.
- (re-review) `Net::node(n, &[fast])` still dials every server the group lists, so a "fast-only" member was connected to the slow server too and, as a writer, deleted covered entries there itself: a test meant to pin the node's own reconnect cleanup passed with that path disabled. Make such members readers, and mutation-check new tests.
