# A split path's wake is missed on a Purges history
> Summary: osis-engine `order::held_set_decides_plain` at `OSIS_ORDER_SEED=134782623960 OSIS_ORDER_LEN=60` (Purges) panics in the debug missed-wake check (`Engine::check_missed_wakes`, `apply::paths::missed`): a commit waits in `paths_unknown` on a thing whose entry a fresh attempt opens (`Known(Path { things: [..] })`). With that check off, the index check fails on the same commit: its live view lacks the path a reload decides. Not shrunk; cause not read.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=134782623960 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` under `tools/heavy` (about 20 s of wall). Its orders fail so, on several commits: `after a transaction: a split path's wake missed: ... CommitId(..) waits on Tid(A), whose entry opens to Known(Path { purge: 0, things: [Tid(B)], direct: 0 })`, B the same thing each time. So some held change that lets a waiting split path open on A (the roles secret or edge on the hop through B) wakes no retry of the commits waiting on A.

A shrink keeping to this failure (`OSIS_SHRINK_MATCH="split path's wake missed"`) has not been tried: a shrink of this seed keeping to another failure made no progress in 119 candidates, every 45-step candidate failing with this one.
