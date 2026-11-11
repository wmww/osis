# lifetimes-3c
- "Entry knowledge" had no node-sync path of its own for a durable commit the engine forgot; reusing the memory lane's `memory.dropped` (`MemoryDrop::Gone`) gave deletion at hosts and forgetting once gone for free, its record was in-memory only (review: persisted as `y/G`).
- `net.advance(ROLE_KEEP_MS)` (90 days in one step) works fine in node tests; no need to fear long-horizon tests.
- `made()`-style helpers put the group write in the creation commit, so "a commit only on x" needs its own setup; easy to test the mixed case by accident.
- Review: a store-wide scan for a thing's bytes (`Engine::local_rows_naming`) found a leftover row no targeted assert would have; worth reaching for in any "no trace" test.
