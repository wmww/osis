# work_sets: a content snapshot re-placed and deleted forever
> Summary: sim `work_sets` ends in a message storm in about 1 seed in 100 (4 of 300 on main, setups 736047789870, 7000, 911499435371; alike with the contact-card `introduce`): one node places a copy of a content snapshot (`ContentSnapshot` on an item's `s:reg.0`, `s:map.0` or `s:tags.0`) under the group's label, another writer fetches it and deletes it, the first places a new copy (a fresh blob ID) at once. Two writers' must-hold verdicts on one snapshot disagree. Not studied.
> Priority: normal
> Tags: sync, tests

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 7010 --setup 7000 --only work_sets` (main), `--from 736047789878 --setup 736047789870` (contact-card setup); `OSIS_SIM_TRACE=1` shows the loop: `Stream L+X` from the placer, the deleter's `Fetch X` then `Delete X`, the placer's `Stream L+Y L-X`.
- Start at: why the deleter judges the copy must-not-hold while the placer re-places it (`encrypt_again` re-places where its delete does not stand; spec/sync.md §6 verdicts). The scenario compacts `s:reg.0` and `s:tags.0` under purge-on-replace retention.
- Both listed repros (`--from 7010 --setup 7000`, `--from 736047789878 --setup 736047789870`) pass on main at 2f6cb5d04: a wider sweep should say whether the class is still live. Not the cause of churn seed 807204137413 (a held-again memory commit judged by its forgotten cover; this storm is on durable content).
- Setup 963785799942: seeds 963785799948 (the loop on a plain `Content` commit on `s:count.0`, as issues/snapshot-rights-delete-storm.md) and 963785799951 (`ContentSnapshot` on `s:map.0`) storm on main alike.
- Not the cause of churn seed 913562400022 either (a held memory body judged uncovered by a snapshot's frontier while others dropped it under that snapshot's chain of covers): that shortcut in `covered` took memory bodies only; this storm is on durable content, where a held body is judged by the join.
