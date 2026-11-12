# Forgetting commits leaves validity unjudged
> Summary: `Engine::forget_commits` (from `forget_forgettable` in the timers) can end its transaction with a thing in `stale_things`, tripping the debug assert "stale validity left unjudged" (engine/mod.rs). Seen at churn seed 807204138930. Not studied yet.
> Priority: normal
> Tags: ephemeral, retention, tests

Replay (about 2 s): `OSIS_EPH_START=807204138930 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large`. Stack: `random_churn_run` → `Net::advance` → `SyncEngine::handle` → `serve_timers` → `forget_forgettable` → `Engine::forget_commits` → `Engine::run` assert. Forgetting a commit (dropping its parts as `DropFor::Destroyed`, `unindex_commit`) marks a thing stale, and nothing in that transaction runs the validity pass. Either forgetting should not change validity (find which commit and why it marks the thing), or the transaction should judge what it marked.
