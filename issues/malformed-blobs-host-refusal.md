# malformed_blobs: the host refuses a malformed blob with code 2
> Summary: sim `malformed_blobs` setup 72407225782 seed 72407225792 fails at step 30, "the host refused a malformed blob: Code(2)" (on main alike). Not studied: whether the scenario's expectation (a malformed blob is stored as opaque bytes) or the host's check is wrong.
> Priority: normal
> Tags: sync, tests

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 72407225792 --setup 72407225782 --only malformed_blobs` (under a second).
