# evil_host_drops: commit bodies keep coming to honest host s0
> Summary: sim `evil_host_drops` setup 0 seeds 117 (ping-pong: a `keys.0` role part added at s0 after quiescence) and 138 (not quiescent: a `tags.0` content part added at s0 every round) fail on main: some node keeps adding commit bodies at the honest host while evil host 1 drops messages. Not studied.
> Priority: normal
> Tags: sync, tests

- Repro: `cargo run --bin sim-sweep -- --only evil_host_drops --seeds 1 --from 117 --setup 0` (and `--from 138`), about 1 s each.
- Not the record-blob churn of a promoted tombstoned entry (fixed: `would_promote` refuses entries in the node's tombstones); these add commit bodies. Start by checking whether the adding node's view of host 1 (what it holds there, whether it is connected) flips the decision.
