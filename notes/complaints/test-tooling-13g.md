# test-tooling-13g
- Testing the gate's docs-only path on this branch ran the full gate: the branch's own diff touches tools/ and core/, so `--plan` said core=1. Use a probe commit and `--base HEAD~1`.
- The brief named seed runners in "the osis test common module": core/osis/tests/it/common has none (only node's `run_seeds*`; perm's `sharded` is a different shape).
