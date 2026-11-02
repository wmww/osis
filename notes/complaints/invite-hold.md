# invite-hold complaints
> Summary: Mishaps met tracing and fixing the sync-oddities invite hold failures.

- Nothing prints every wire message of a `World` run: `OSIS_SIM_TRACE` is the scenario trace, and finding this bug took an ad hoc `eprintln!` in `World::step`. The diff between two runs then showed it in one read. Worth a built-in `World` message trace.
- A narrowed `cargo test --workspace --test it <filter>` prints a `0 passed` result line per crate, so `tail` shows only the last crates: grep for a non-zero `passed`.
