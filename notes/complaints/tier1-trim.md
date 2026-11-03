# tier1-trim review
- A new dependency of a core crate also changes kit/Cargo.lock (kit pulls core by path); the gate only finds it at its last step, `cargo check --locked` in kit, after ~10 min of tier 1 and the sweep. Refresh it with `cargo metadata --offline --format-version 1 >/dev/null` in kit/; the gate could check that lock first.
- The worker skipped the instant checks: policy.py failed on the missing notes/architecture.md §5 line for the new dependency.
