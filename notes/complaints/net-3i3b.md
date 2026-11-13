# net-3i3b
- `tools/bin-at` checks REV out in the worktree it runs in: unusable while other agents edit that worktree; a baseline needed a second `wt claim` and a cold-ish build (load 50).
- Test helpers that call `SyncEngine::handle` directly and read the returned actions (ephemeral `push`, hostile_host `sent`, net_records `refused_dial`) bypass the driver's routing: every change of what a driver does between bytes and the engine touches each of them by hand.
- Disk filled (0 bytes free) during a second worktree's build while five others held 11-13 GB targets each; the build failed with ENOSPC, nothing said so until it was read.
- Changing which rng draws a connection's challenge (node sync's to the hub's) shifted every later key and blob ID, so timing-fragile tests (fill holds, sharing cut points) moved: their stretches are tuned to one rng stream.
- Review: `sharing::retry_after_a_stalled_pull` picks step counts with no check that each lands inside the stretch it names; a cut before the stretch passes silently. It now asserts K's head is at the host; mapping the stretch took a throwaway probe over 40 worlds (`World::tally` per cut).
- Review: an edit made in the worktree while `tools/gate.sh` built it broke the gate's build (one wasted start); edit nothing in a gating worktree, draft in the scratchpad.
