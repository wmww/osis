# Debugging and differential tooling gaps
> Summary: Tool gaps several agents met: no per-node cost attribution or NotOpen trace line, `verify_stamp`'s bool misread as "verified", no safe way to build main's library sources beside a branch's, `tools/bin-at` building only test binaries, comment-only manifest edits selecting the whole gate, run.sh negative controls passing on any failure, and cpuprof without a by-caller split.
> Priority: low
> Tags: tests, tools, sync

## Sync debugging tools that cost agents probe rebuilds
No per-node cost attribution or NotOpen trace line, and `verify_stamp`'s bool reads as "verified"; each cost agents debugging rounds (osis-sync probe rebuilds take 1-2 min each; one branch spent about 50 of its 150 minutes on eprintln probes).

Each met by two or more agents in the sync rebuild:
- **Per-node and per-caller costs**: `osis_base::costs` is thread-local and `World` steps every node on one thread, so counts mix nodes; attributing store commits to a module took a backtrace probe in `pager::commit`. A `costs::count_by` keyed by the stepping node (the harness sets it in `World::deliver`) and by caller would answer it in one run. `Effects::due`'s causes name the table, not the key that moved (absent-bucket stamps made one cost test flip 24 to 130 by hash luck).
- **Trace gaps** (notes/sync-test-harness.md, Trace): an entry that stays NotOpen shows `+entry` without `+commit` and nothing says why; one hour of tracing went into a sibling rotation that never opened.
- **`osis_blob::verify_stamp` returns `Ok(false)` for a good stamp** (the bool says "role entry"): read's deposit path read it with `.unwrap_or(false)` as "bad" and encrypted afresh every body it should have relayed. An enum (`Stamp::{Role, Entry}`) would make the misreading impossible.

## Tooling gaps that cost reviews and differentials time
No supported way to build main's library sources beside a branch's, `tools/bin-at` builds only test binaries, a comment-only manifest edit selects the whole gate, and run.sh judges a negative control by failing alone.

Each met by several agents:
- **Library differential**: comparing a library crate's behaviour with main's (not a binary, so `tools/bin-at` does not help) is done by `git checkout origin/main -- <crate>/src` and back, which twice dropped uncommitted edits and once pulled in main's newer sibling crate that did not build. A `tools/src-at REV <crate>` that wip-commits, swaps the sources in at the merge base, builds, and swaps back would make it safe. Until then: wip-commit first, check out from `$(git merge-base HEAD origin/main)`, and `git reset --hard` back (a path checkout leaves files the other side added).
- **`tools/bin-at --bin NAME`**: main's `osis` CLI binary for a text differential came from the `target/debug/osis` a test-binary build left behind. After any `bin-at`, `target/debug/deps/it-*` holds REV's build until the next `cargo test --no-run`: copy the branch's binary out first.
- **Comment-only manifest edits**: gate.sh and test_select.py treat any root `Cargo.toml`/`.cargo/` change as build configuration: every crate selected plus the unification check (about 2000 CPU-s), even for a comment (prose-testing; policy's pointer check can force such a comment edit). Ignoring a diff whose changed lines are all TOML comments or blank, in both places, would fix it.
- **run.sh negative controls**: an instance expected to `fail` passes as `ok` whatever it violates, so a control failing for another reason (or a TLC-level error of the wrong property) hides. An expectation `fail:<Invariant>` checked against TLC's `Invariant <name> is violated` line would pin it.
- **cpuprof by caller**: `cpuprof_report.py` filters by one frame; splitting a function's cost by caller or phase needed a private symbolizing script (`--callers FN` / `--under FN`).
