# durable-signals
- The first `cargo build -p osis-engine` in the claimed worktree took about 400 s (cold for this crate set); later test builds 40-70 s.
- Rebase on main: `app/src/chat.rs` moved to `app/src/facets/log.rs` (rename conflict, then a stale `chat:msgs.0` there), and the new `Core::rollback_classes` exhaustive pattern failed to compile on the branch's `rebuilds` field. Plain conflicts; just slow to notice the moved file.
