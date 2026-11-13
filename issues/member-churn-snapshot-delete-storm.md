# member_churn: a content snapshot's blobs deleted in a storm
> Summary: sim `member_churn` setup 478483357567 seed 478483357569 (on main alike) storms at step 46: s0 deletes, under one label, blob after blob of one commit's ContentSnapshot (`s:reg.0`) without the queue emptying. Not studied; maybe the place/delete alternation of issues/team-reads-local-snaps-storm.md.
> Priority: normal
> Tags: sync, sim, tests

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 478483357569 --setup 478483357567 --only member_churn`; `OSIS_SIM_TRACE=1` for the trace.
