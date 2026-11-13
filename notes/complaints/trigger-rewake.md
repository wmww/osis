# trigger-rewake
- An engine-level test can't see a durable snapshot drop its covered bodies (node-sync does that), so `compaction_load` after a durable snapshot still shows every body: assert on the snapshot written, not on the load.
