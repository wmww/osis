# eph-reread
> Summary: wt/claudewait off PATH in the worker shell; the issue's repro claimed a read at step 52 it never checked.

- `wt` was not on PATH in the worker shell (claudewait was); the plugin's `~/.claude/plugins/cache/wmww-agent-skills/reasonable-rust-builds/0.5.1/bin/wt` worked (the undo-expiry reviewer met the same).
- The issue said node 1 "read nothing of v5 at step 52": the repro check ran only after `net.clock.advance`, and step 52 was an `advance` step (`continue`), so it was never checked. Checking every step shows v5 visible from T on; the cause was the offline node getting no Tick, not a removal.
- `cargo build --workspace --all-targets 2>&1 | grep -E '^(error|warning)' | head` exited 0 with a test-target compile error unreported (the grep pattern missed it under `-A`?): read `cargo`'s own exit, not a grep's.
- Review: `wt` again off PATH in a fresh agent shell until the plugin bin dirs were exported by hand. A throwaway `assert!(timer_floor <= min stored timer)` at the end of every `Engine::run` was the cheapest differential for the floor: one edit, every tier-1 test and oracle exercises it.
