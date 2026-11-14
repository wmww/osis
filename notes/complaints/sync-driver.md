# sync-driver
- `cat > file 2>/dev/null; ...` with no input in a backgrounded command waited on stdin for minutes before I noticed (my slip; a background run with no output looks the same as a slow build).
- The world harness had never connected two nodes: opens answered NoRecord with an empty Shared, which the wire refuses (a Shared holds at least one item), so every unrecorded connection stalled out every 2 min. Scripted opens tests never decode, so nothing caught it.
- osis-store's recovery backoff is on `Instant` (real time): a `Fault::Crash` in a simulated-time test never recovers within the test; `Faults::forbid_writes` makes a recoverable stretch instead.
- (review) Two crossed rebases mid-review (sync-rebuild moved twice); the second had a real conflict in `Node::moved` (streams' reports loop), easy to resolve wrongly by dropping the dial counting from the new loop.
- (review) Scripted opens tests now go through wire bytes (`scripted::incoming` encodes and decodes): that alone found a ByRole with no hits (spec/sync-opens.md allows it, spec/wire.md said `hit+`) and a fixture grant with no steps.
- (review) No cheap way to make the engine's own store fail inside a node step in the world harness, so "an engine commit ends a failure stretch" has no test of its own.
