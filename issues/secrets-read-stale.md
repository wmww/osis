# secrets_read cache goes stale in member_churn
> Summary: The debug cross-check of the engine's `secrets_read` cache (core/engine/src/flows/mod.rs, `Engine::recheck`) fails in the sim's `member_churn` at seed 743390088891: the cached `Secrets` of an actor differ from a fresh decode. A cache invalidation gap (issues/derived-state-recomputed.md owns the caches).
> Priority: normal
> Tags: engine, sim, tests

Repro: `osis_sim::replay("member_churn", 743390088891)` (main 7f0db4ff5; found by a gate's sim at 15 seeds from 743390088878). Panics at step 0 of the scenario's checks: `assertion left == right failed: secrets_read of Tid(BcqeEgBhZqHAyHaDnGn0) went stale`; the two `Secrets` share their first boxes (holder `AhdC7m05...`, read epoch 10) and differ later in the dump. Not traced: which write changes an actor's boxes without moving the key `secrets_read` caches under.
