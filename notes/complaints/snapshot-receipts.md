# snapshot-receipts
- Brief pointed to notes/testing.md for the sim `--only` list of permission scenarios; there is none. Picked 14 by name from `sim-sweep --list` (revoke/removal/demotion/compaction/coverer ones). A named list in notes/testing.md would make "permission scenarios" reproducible.
- A passing run of the order/walks harness through a copied test binary prints no seed-range summary (libtest captures stdout of passing tests), so the env vars' effect can only be judged by wall time; `--nocapture` would show it.
- Review: `sim-sweep --help` is "unknown argument" (briefs point at it); the flags are only in notes/testing.md.
