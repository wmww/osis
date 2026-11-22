# A complete pass's wait starts again at every restart
> Summary: `PASS_WAIT_MS` runs on the monotonic clock and a pass lives in memory, so a node restarting more often than `PASS_WAIT_MS` while a recorded peer holding S is away never ends a pass of S: others' bodies under a new S are never logged, and every decision taken at a pass's end waits for good.
> Priority: normal
> Tags: sync

spec/sync-streams.md §1 Waits lists a pass's `PASS_WAIT_MS` among the waits a node keeps only while it runs; spec/sync-status.md §1 bounds a pass by `PASS_WAIT_MS` since it began. A restart begins a new pass with a new deadline. At infinity (restarts more often than `PASS_WAIT_MS`, recommended an hour, as a phone whose app is killed often may) the bound never applies: spec/sync-judgement.md §3 Own store's hold on another's body under a new S, and the re-seal, rotation and link-finalize decisions that wait on a pass (notes/arbitrary-values-table.md, `PASS_WAIT_MS`), never end while that peer stays away. An unbounded stall is not an accepted limit.

Fix direction: date a pass's start so it outlives a restart (a wall-dated row, judged by the latest wall reading, as spec/sync-streams.md §1 dates what outlives a restart), so a restarted node's wait is bounded by the first pass's deadline; or count the restarted node's earlier running time toward it.
