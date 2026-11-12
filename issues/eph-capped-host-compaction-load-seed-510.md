# Capped-host window run fails a seed on main: a writer holds past its compaction bound
> Summary: Seed 780551881510 of `ephemeral::random_window_one_capped_host_large` ends with node 0 holding 12518 B of `win:notes+.0` against a 3592 B snapshot, past `FACTOR` times the snapshot plus the largest body (spec/sync.md §9, compaction trigger). Fails alike on main at e1a8cae38; not looked into.
> Priority: normal
> Tags: tests, retention, ephemeral

- Replay: `OSIS_EPH_START=780551881510 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_window_one_capped_host_large`.
