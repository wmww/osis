# snapshot_rights: a writer-bound body stays at the host
> Summary: sim `snapshot_rights` fails on main at seeds 43, 49, 99 of the default sweep: "Writer bound 0: body of node 2 at the host false, should be gone true" (seed 49 at step 40, with "delete refused: code 1" diagnostics before). Not studied.
> Priority: normal
> Tags: sync, retention, tests

Replay: `osis_sim::replay("snapshot_rights", 49)` (also 43, 99). Found by the full `sim-sweep` on branch leaving-study; the same seeds fail with main's core/node, core/engine and core/test/sim/src checked out.
