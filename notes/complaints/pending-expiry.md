# pending-expiry
- The brief's fix sketch (strip pending parts at T) conflicts with arrival-order independence; tier 1's pinned order tests caught it only after implementing. A design-level check against spec/crdt.md §4.7 "non-value writes stay" in the issue would have saved the round.
- `cargo test --workspace --no-fail-fast` failed every `core/osis` doctest with E0460 (several `libosis_node-*` rlibs in target/debug/deps after `cargo test -p osis-node` runs): passed on a plain rerun (stale rmeta race, not the change).
