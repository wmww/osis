# A host at its ephemeral cap keeps a dropped ephemeral body
> Summary: sim `ephemeral` and `ephemeral_capped` fail at quiescence: host 0 (ephemeral cap 8000 B, charged about 7.8 KB) still holds a blob its node judges must-not-hold (Dropped) and may delete now, while the same host keeps out newer bodies for its cap (uploads refused, code 12). 3 of about 150 ephemeral seeds. Cause not traced.
> Priority: normal
> Tags: ephemeral, node-sync, tests

Found by the periodic sweep from 691637290070 on main e3cdd005f; all three still fail on 8f3cd8d05. Replay (each fails in 3-5 s; `OSIS_SIM_TRACE=1` prints every step):
- `cargo run --bin sim-sweep -- --seeds 1 --from 691637290085 --only ephemeral_capped` (node 1's must-not-hold)
- `cargo run --bin sim-sweep -- --seeds 1 --from 691637290087 --only ephemeral` (node 0's)
- `cargo run --bin sim-sweep -- --seeds 1 --from 691637290199 --only ephemeral` (node 0's)
or `osis_sim::replay("<scenario>", <seed>)` from a test in `cargo test -p osis-sim --test it`.

Shared shape: the failing host is the capped one, full to within 200 B of its 8000 B cap, refusing uploads (code 12) and keeping out several newer bodies of the same node; host or node crashes and restarts earlier in each history. In the `ephemeral` seeds another node logs `delete refused: code 1` on each pass. `Verdicts::must_not` lists only blobs the node may delete now (`converge::may_delete`), so the node claims it can delete this one, yet it stays. Suspects: the delete travels with an upload (Replace, or a carrier) the cap refuses, or a delete the host refuses (code 1) for a blob re-placed after a restart. Not compared with an older main (sim-sweep is not a `tools/bin-at` target).
