# expiry-8
- `tools/bin-at` checks main out in the worktree: no edits while it builds (easy to forget mid-debug). Two old-vs-new comparisons cost about 4 min each at load 60.
- Fill-order tests (`fill::newest_first_after_what_judging_needs`, `no_pass_before_order_0_at_two_hosts`) hang on which order-0 blobs share a batch (blob-ID order): adding any order-0 blob kind reshuffles them. An awaiting order-0 entry woken mid-fill was not fetched again in the fill's order (fixed: `reopen_awaiting` re-queues it).
- `redeem_held_joins_nothing` cost hours of instrumenting node, proto client and host to find where a grant stalls; a per-node "why is this commit not applied / this label stranded" dump would have saved most of it.
- Root-causing `redeem_held_joins_nothing` (fix round): a passing test's stderr is captured, so a main-vs-branch print comparison needs `-- --nocapture` on the passing side (cost one 4-min rerun). Switching the worktree between main and the branch rebuilds the whole tree each way (4-10 min at load 50).
- Review: a full `-p osis-node --test it` takes 4-7 min at load 33; each sabotage check of a one-line fix costs a rebuild of the node test binary (about 2-4 min).
- Networking tier 2: `osis sources::thin_client_over_quic` failed once (`watch.current()` not yet `Network` after `until("down")`), passed on rerun; real sockets, branch does not touch it.
