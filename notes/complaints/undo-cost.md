# undo-cost
> Summary: Workflow footguns met while bounding the undo check's cost.

- A `#[cfg(test)]` check in osis-engine runs only in its own 325 unit tests; most undo tests live in osis-node's `tests/it`, which build the engine without `cfg(test)`. The old `kept_before` whole-join assert was blind there. Equivalence checks that must see every scenario need `cfg(debug_assertions)` (sampled if costly).
- The `"commit read"` cost span counts only decoded-cache misses, so it under-counts bodies read; `held_parts_at` now counts `"part read"` per part returned.
