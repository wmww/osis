# eph-unify-1
- A holder refusing an ephemeral commit for its node cap (`EphIngest::TooLarge`) is silent in node tests: two tests diverged and it took ad-hoc eprintlns in engine and node-sync to see the cap was the cause. A test helper listing a node's diagnostics (or a debug log of refusals) would have shown it at once.
