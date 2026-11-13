# evil_host_drops: a message storm at seed 455770489005
> Summary: sim `evil_host_drops` setup 455770488995 seed 455770489005 fails at step 200, "message storm: 5000 deliveries without the queue emptying" (main alike, d129673c6). Not studied; the trace's tail is host 1 dropping messages on two connections and "malformed reply to no request" there.
> Priority: normal
> Tags: sync, tests

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 455770489005 --setup 455770488995 --only evil_host_drops` (about 5 s).
- Found by the unread-enclosers gate. Main just took the sim's hub-down ordering (d018978c0); not checked whether the seed failed before it.
- Also setup 941804269790 seed 941804269794 (capped-eph review gate; fails on main alike, 1ef46d9d9): "not quiescent after 60 rounds; one more round changes []". Not studied.
