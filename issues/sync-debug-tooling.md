# Sync debugging tools that cost agents probe rebuilds
> Summary: no per-node cost attribution or NotOpen trace line, and `verify_stamp`'s bool reads as "verified"; each cost agents debugging rounds (osis-sync probe rebuilds take 1-2 min each; one branch spent about 50 of its 150 minutes on eprintln probes).
> Priority: low
> Tags: tests, tools, sync

Each met by two or more agents in the sync rebuild:
- **Per-node and per-caller costs**: `osis_base::costs` is thread-local and `World` steps every node on one thread, so counts mix nodes; attributing store commits to a module took a backtrace probe in `pager::commit`. A `costs::count_by` keyed by the stepping node (the harness sets it in `World::deliver`) and by caller would answer it in one run. `Effects::due`'s causes name the table, not the key that moved (absent-bucket stamps made one cost test flip 24 to 130 by hash luck).
- **Trace gaps** (notes/sync-test-harness.md, Trace): an entry that stays NotOpen shows `+entry` without `+commit` and nothing says why; one hour of tracing went into a sibling rotation that never opened.
- **`osis_blob::verify_stamp` returns `Ok(false)` for a good stamp** (the bool says "role entry"): read's deposit path read it with `.unwrap_or(false)` as "bad" and encrypted afresh every body it should have relayed. An enum (`Stamp::{Role, Entry}`) would make the misreading impossible.
