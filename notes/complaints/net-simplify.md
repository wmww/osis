# net-simplify
- `tools/wt claim <branch>` already checks the branch out; nothing says so in its output (I ran `git checkout -b` after it; harmless, it failed quietly).
- Box at load 20-25 from other agents: a crate's test binary took 3-11 s once and 0.3 s on rerun; timings of single runs mean little here.
- Proving a cost fix (blob reads per Delete item) needed a counter on `MemoryLabelStore` (`blob_reads`); there is no generic counting `LabelStore` wrapper for such tests.
- Review: a 23k-case delete differential (new `delete` vs a test-only copy of the old one) took 23 s, too slow for tier 1; kept in scratch, not committed. Building one store per case was the cost.
