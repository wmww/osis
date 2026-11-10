# expiry-8
- `tools/bin-at` checks main out in the worktree: no edits while it builds (easy to forget mid-debug). Two old-vs-new comparisons cost about 4 min each at load 60.
- Fill-order tests (`fill::newest_first_after_what_judging_needs`, `no_pass_before_order_0_at_two_hosts`) hang on which order-0 blobs share a batch (blob-ID order): adding any order-0 blob kind reshuffles them. An awaiting order-0 entry woken mid-fill was not fetched again in the fill's order (fixed: `reopen_awaiting` re-queues it).
- `redeem_held_joins_nothing` cost hours of instrumenting node, proto client and host to find where a grant stalls; a per-node "why is this commit not applied / this label stranded" dump would have saved most of it.
