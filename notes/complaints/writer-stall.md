# writer-stall
- The net harness's loop guard (`SETTLE_ROUNDS` 2000) did not fire on an endless rotation exchange: each round's rotations cost more than the last (more epochs, history), so 2000 rounds looked like a hang. Lowering it to 60 by hand gave the panic in 2 s. A guard on new role commits per settle, or a lower round bound, would catch this class at once.
- `OSIS_SYNC_TRACE` shows only wire messages; finding the loop needed printing each node's new commits (author, aspects) per round, which the trace could carry.
