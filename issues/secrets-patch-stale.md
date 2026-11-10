# The in-place patch of decoded `secrets.0` goes stale
> Summary: `apply::keys::secrets_patch` (a join patches the decoded `secrets.0` kept by `Core::secrets_read` instead of decoding the state again) leaves a history box's bytes different from a fresh decode; the memo's debug comparison panics in sim `member_churn` seed 517046069431.
> Priority: normal
> Tags: engine, security

Replay: `cargo run --bin sim-sweep -- --seeds 1 --from 517046069431 --only member_churn` panics at step 0 with `memo secrets: decode: kept .. a fresh run gives ..`. The two differ in one history box (`HistoryKey` read, epoch 6): same keys, same boxes, other bytes for that entry. Older than the memo: on 6bed0b446 the same seed fails the cache's earlier check (`secrets_read of .. went stale`).

What to find: which join leaves the kept value behind. `secrets_patch` reads only the delta's keys again and gives up (decode) when a key does not read as one value; a history key with several live entries (`HistoryAlts`) whose winner moves without the delta naming it, or an entry on a page the join did not load, would do this. A release build has no comparison: it would open boxes from the stale decode.

Also seen in the same sweep, unrelated and also older than the memos: `no_host_chain` seed 517046069421 (`holders 0 and 1 of group .. read differently at quiescence`, s:count.0 0 vs 5, four commits held only by holder 1).
