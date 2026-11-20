# purge-order
- The issue's reproducer delivered 0's copy of the purged commit after 0 had purged it: header-only, so it tested "never held the body", not "body arrived late". A late-order test must say which copy it delivers.
- `tools/bin-at` with a `--patch` built against an older rev failed to compile on struct-field drift in test helpers; a self-contained probe module (own world, no shared helpers) applies more often.
- `git reset --hard HEAD~1` to drop a wip commit also dropped uncommitted probe edits: wip-commit everything before resetting.
