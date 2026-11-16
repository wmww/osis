# keel-refgraph-settle
> Summary: Mishaps while settling the reference-graph spec gaps.

- tools/policy.py is red on main, so "no new violations" means diffing its output against the parent commit by hand; a `--baseline` mode would save the two runs.
- A Bash call that merely contained `git stash list` was denied whole; keep stash out of every command, even read-only.
