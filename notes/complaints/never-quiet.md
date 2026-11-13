# never-quiet
- The brief's lead (held-order-seed) was wrong for both seeds: each fails the same way before it. A one-line bisect in the issue would have saved the chase.
- Shrinking the ephemeral seed by hand-building worlds took hours; logging the random run's steps (with advance amounts) and a greedy step-dropping script found an 11-write reproducer in minutes. The random tests' step log could print advance amounts so it replays as a script.
- Node `Net::settle` storms take 25 s to report at 2000 rounds; a failing reproducer is slow until fixed.
- Review: the fix held only through stale incremental aggregates (a forgotten snapshot never enters a rebuilt `w.snaps`), so `full_passes` still looped; a full-pass twin of a seed's reproducer catches that class cheaply.
