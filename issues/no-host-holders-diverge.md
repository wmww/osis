# Holders with no host diverge after crashes
> Summary: In the sim's `no_host` and `no_host_chain` scenarios (readers only, crashes, restarts, partitions), a writer ends holding its own commits with no entry under any label, so no reader can pull them, and the holders read differently at quiescence. Writes can be lost to readers, whatever the rate. Replays: `osis_sim::replay("no_host", 4)`, `osis_sim::replay("no_host_chain", 0)`.
> Priority: critical
> Tags: sync, node, tests

## What the runs show
- `no_host` seed 4 (punched topology): node 1 writes `92a911..` and `d1c73a..` (the second as it crashes mid-write); its first entry is pushed and fetched by both readers. After the crashes and restarts node 1 holds both commits but no entry for them ("at []"), its log carries `Deleted` for their entries, and nodes 0 and 2 lack them at quiescence (`s:hi.0` 822 against 917).
- `no_host_chain` seed 0 fails the same way (commits only one side holds, both ways) on net-pull2 before its third part; `no_host` seed 4 started failing with stream reports (Applied), which add messages and so move timing: it passes with reports switched off, and reports change no data.

## Questions for whoever takes it
- Which drop removed node 1's own entries (`local_deletions`, a junk drop at restart, compaction) while the commits stay live and must-hold, and why the next local pass does not place them again.
- Why the readers no longer hold commits they fetched (a crash rolling back the bodies but not the record's cursor would do it: the cursor then skips them).
