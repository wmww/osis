# keel-destroy-plain
- The sync `World` harness counts every dial tick toward a powered-off or partitioned peer against its delivery cap, so `advance(ROLE_KEEP)` with a node away storms out. Added `World::jump` (clock moves, no wake between, then `run`).
- Proving a new test fails before the change needs the old fake `Ground` too (tests/it/read.rs implements the trait), so checking out old `src/` alone does not compile the test binary.
