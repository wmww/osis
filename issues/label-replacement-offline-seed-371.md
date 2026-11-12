# label_replacement_offline: a content entry stays under the replaced label
> Summary: sim seed 911499435371 of `label_replacement_offline` ends quiescent with 1 content entry (of 15 live) still under the replaced label. Fails on main as on branch chunk-release-one-rule (found by its gate). Not studied.
> Priority: normal
> Tags: sync, tests

- Repro: `cargo run --bin sim-sweep -- --only label_replacement_offline --seeds 1 --from 911499435371` (0.5 s); `osis_sim::replay("label_replacement_offline", 911499435371, 911499435371)` (setup: `--from`).
- The run: link cuts, writes by both nodes, node 1 restarts at step 100 (node 0 logs `host: proto: malformed reply to no request` twice), then quiescent; the check at step 100 finds the old label not emptied.
