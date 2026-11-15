# cleanup-sync complaints
- `grep` in agent shells is a function running ugrep with `--ignore-files`: inside `.worktrees/` (gitignored in the main checkout) `grep -r` found nothing, so a scan for stale identifiers listed every name as missing. Use `rg` or `command grep`.
- tools/dead_pub.py lumps "used by its own crate's tests" with "used by nothing": two deletions (`coverers_of`, `Session::proofs_done`) broke own-crate tests and had to come back as test hooks. A flag saying which of the two each hit is would save the round trip.
