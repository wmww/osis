# eph-simplify
- `wt` not on PATH in the session (brief gave the plugin bin path); CLAUDE.md says to stop and ask in that case, the brief overrode it.
- A release icount baseline needs the old tree built before any edit (no stash): I built `target/release` first and copied the binary aside, then edited. Costs ~2.5 min up front; a `tools/` helper building main's test binary into scratch would make old-vs-new less order-dependent.
- notes/ephemeral.md is 75 KB on 213 lines (paragraph-long bullets): Read/cat output is truncated, needs offset reads.
