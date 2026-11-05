# held-model and the engine differ on a dropped snapshot body (purge seed 3039)
> Summary: At full size `arrival_order_purge_large_spec_commits_5` fails seed 3039 on the held-model check: a node dropped a compaction snapshot's `t:gone.0` body (keep at most 0 after replaced) that the model keeps (`Keep(Plain)`); engine bug or model gap, undiagnosed.
> Tags: tests, engine

Replay: `OSIS_ORDER_SEED=3039 OSIS_ORDER_LEN=60 OSIS_ORDER_SHRINK=0 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_purge_large_spec_commits_5` (8 s; the shrink runs over half an hour and barely shrinks). Fails with the adapter as first written and after leftovers became held bodies, so the default per-branch range (6 seeds) hid it; `OSIS_FULL=1` periodic runs will fail on it.

What the model sees at the failing node: thing owned by node 2; content commit #3 by node 1 sets `t:gone.0` (writer, at most 0); snapshot #71 by node 0, stamped after #3, its body dropped at the node. Given back, the model judges #71 `Keep(Plain)`: no death for its writes. Leads: the snapshot's author's write right at its `ts` (an invalid snapshot is dated by its fall at the engine, AMBIGUITIES 23; the model may date no fall), or a cover the model does not see. Find which side is wrong; fix the engine, or the model and note it in AMBIGUITIES.md.
