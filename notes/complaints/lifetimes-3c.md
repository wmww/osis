# lifetimes-3c
- "Entry knowledge" had no node-sync path of its own for a durable commit the engine forgot; reusing the memory lane's `memory.dropped` (`MemoryDrop::Gone`) gave deletion at hosts and forgetting once gone for free, but its record is in-memory only: after a restart a forgotten commit's leftover entries go unjudged at that node (others still delete them).
- `net.advance(ROLE_KEEP_MS)` (90 days in one step) works fine in node tests; no need to fear long-horizon tests.
- `made()`-style helpers put the group write in the creation commit, so "a commit only on x" needs its own setup; easy to test the mixed case by accident.
