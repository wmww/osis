# eph-parity
- The `memory_in_closure` guard hid a durable sync gap (a subgroup's definition never reaches its parent's label): removing a "memory-only" guard is the quickest way to find what it papers over; issues/subgroup-outside-closure.md.
- `cargo build -p osis-engine` from a cold-ish worktree took 2.5 min and went past the Bash tool's 2-min foreground limit; start first builds in the background.
