# Tooling gaps that cost reviews and differentials time
> Summary: No supported way to build main's library sources beside a branch's, `tools/bin-at` builds only test binaries, a comment-only manifest edit selects the whole gate, and run.sh judges a negative control by failing alone.
> Priority: low
> Tags: tests, tools

Each met by several agents:
- **Library differential**: comparing a library crate's behaviour with main's (not a binary, so `tools/bin-at` does not help) is done by `git checkout origin/main -- <crate>/src` and back, which twice dropped uncommitted edits and once pulled in main's newer sibling crate that did not build. A `tools/src-at REV <crate>` that wip-commits, swaps the sources in at the merge base, builds, and swaps back would make it safe. Until then: wip-commit first, check out from `$(git merge-base HEAD origin/main)`, and `git reset --hard` back (a path checkout leaves files the other side added).
- **`tools/bin-at --bin NAME`**: main's `osis` CLI binary for a text differential came from the `target/debug/osis` a test-binary build left behind. After any `bin-at`, `target/debug/deps/it-*` holds REV's build until the next `cargo test --no-run`: copy the branch's binary out first.
- **Comment-only manifest edits**: gate.sh and test_select.py treat any root `Cargo.toml`/`.cargo/` change as build configuration: every crate selected plus the unification check (about 2000 CPU-s), even for a comment (prose-testing; policy's pointer check can force such a comment edit). Ignoring a diff whose changed lines are all TOML comments or blank, in both places, would fix it.
- **run.sh negative controls**: an instance expected to `fail` passes as `ok` whatever it violates, so a control failing for another reason (or a TLC-level error of the wrong property) hides. An expectation `fail:<Invariant>` checked against TLC's `Invariant <name> is violated` line would pin it.
- **cpuprof by caller**: `cpuprof_report.py` filters by one frame; splitting a function's cost by caller or phase needed a private symbolizing script (`--callers FN` / `--under FN`).
