# Two seeds never go quiet: an ephemeral capped-host window and an evil host dropping
> Summary: On main two seeds fail by never settling: `ephemeral::random_window_one_capped_host_large` seed 889902233287 (node net: "no quiescence after 2000 rounds (25477 messages): a loop") and sim `evil_host_drops` setup 889902233282 seed 889902233296 (step 200: "not quiescent after 60 rounds"; node 0 and node 1 each hold a connection with `outstanding 1`, one more round changes nothing). Both deterministic; maybe one cause. Not looked into.
> Priority: normal
> Tags: node-sync, tests

Replays (in tools/known_failures.txt):
- `OSIS_EPH_START=889902233287 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_window_one_capped_host_large` (about 30 s).
- `cargo run --bin sim-sweep -- --seeds 1 --from 889902233296 --setup 889902233282 --only evil_host_drops` (about 3 s).

Found by the test-optimizer-4 gate (main 237de242e; the branch changes tests and tools only). Next: check whether the cycle starts with efa01db10 (a commit's header waits for none of its parts), then name the messages that repeat and reduce each to a small reproducer.
