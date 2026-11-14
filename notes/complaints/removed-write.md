# removed-write
- The brief named a bug on main; it lived only in the sync rebuild's trace (v5 and the removal at one `ts`). The trace's `ts` values would have shown the tie at once.
- A planted fault that keeps a removal due (`addenda_due` never cleared) makes every transaction write another addendum and the node test spins for good instead of failing: plant faults that end.
