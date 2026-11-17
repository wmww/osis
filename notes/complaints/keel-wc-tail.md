# keel-wc-tail
- A store entry logged by hand in a sync test (`w.store(i).log`) does not wake the node: nothing is served or judged until a power cycle. A harness `touch(i)` would save the restart.
- A 3-node `world(0, 3)` with two grants costs about 4 s debug per test before anything is checked; a fixture for it would cut several tests.
