# perm-cert-90731
- The issue file named in the brief (issues/perm-certificates-joint-seed-90731.md) lives only on the unmerged branch membership-snapshot-roles, not main; had to read it via `git show 15142068:...`. It still needs deleting there (or on merge).
- osis-perm tier 2 (roster/differential/queries/incremental) took 277-354 s per seed at load 20-28 (notes say 2.4 min), running alongside a tier-1 run.
- Review: the gate took 343 s at load 13-20 (notes say about a minute warm); a first gate run silently wrote nowhere because its log dir did not exist (my mistake, cost a re-run).
