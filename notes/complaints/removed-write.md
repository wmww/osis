# removed-write
- The brief named a bug on main; it lived only in the sync rebuild's trace (v5 and the removal at one `ts`). The trace's `ts` values would have shown the tie at once.
- A planted fault that keeps a removal due (`addenda_due` never cleared) makes every transaction write another addendum and the node test spins for good instead of failing: plant faults that end.
- Review: `cargo test -p <crate> --lib a b` (two filters without `--`) is a cargo usage error; piped through grep it looked like a silent pass. Put filters after `--`.
- Review: the worker cut the destruction walk by `ts` but left `Destruction::after` on the full key: two halves of one rule must change together (the mismatch made nodes diverge and the net loop forever).
