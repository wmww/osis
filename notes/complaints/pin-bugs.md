# pin-bugs
- A sabotage that storms (`chain_held`) leaves the node suite hung for good: the run needs a `timeout`.
- `pkill -f <path>` from Bash matches its own shell and kills the call (exit 144).
- `-p osis-node` after a `core/node/src` sabotage rebuilds in about 45 s, so a sweep of the suite costs 75 s each.
