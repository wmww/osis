# ephemeral
- `World::run()` with a partition jumps through an hour of dial ticks (~500 deliveries, ~0.5 G instructions): a rule test with a partitioned peer should `flush()` instead; nothing in the harness says so near `partition`.
- tools/policy.py reports stale `dead_pub_allow.txt` lines one batch at a time: dropping them took three rounds.
- (review) A reader keeping no entry of a held durable commit was invisible until counting blobs per commit across nodes: a per-commit entry count in a three-node test would have shown the second encryption at once.
