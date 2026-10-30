# sync-flow-control
- `wt` and `claudewait` skill were not on PATH/registered as described: needed the plugin bin path by hand; `claudewait` exists as a binary but not as a Skill tool.
- The InProcess transport has no flow control (writes never block), so `LinkTx` queue caps can never trip in driver tests; flow-control tests had to model the queues in a sans-I/O harness.
