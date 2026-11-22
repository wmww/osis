# Debugging and differential tooling gaps
> Summary: Tool gaps several agents met: no per-node cost attribution or NotOpen trace line, `verify_stamp`'s bool misread as "verified", no safe way to build main's library sources beside a branch's, comment-only manifest edits selecting the whole gate, run.sh negative controls passing on any failure, cpuprof without a by-caller, callee or inline-aware split, and debug dumps missing kept copies, per-node sync IDs, commit names and round counts.
> Priority: low
> Tags: tests, tools, sync

## Sync debugging tools that cost agents probe rebuilds
No per-node cost attribution or NotOpen trace line, and `verify_stamp`'s bool reads as "verified"; each cost agents debugging rounds (osis-sync probe rebuilds take 1-2 min each; one branch spent about 50 of its 150 minutes on eprintln probes).

Each met by two or more agents in the sync rebuild:
- **Per-node and per-caller costs**: `osis_base::costs` is thread-local and `World` steps every node on one thread, so counts mix nodes; attributing store commits to a module took a backtrace probe in `pager::commit`. A `costs::count_by` keyed by the stepping node (the harness sets it in `World::deliver`) and by caller would answer it in one run. `Effects::due`'s causes name the table, not the key that moved (absent-bucket stamps made one cost test flip 24 to 130 by hash luck), and they overlap (one event moves several inputs of a key): two judge-cost rounds each built a throwaway per-`Dep` read-site label; the diagnostic that predicts a saving is, per due key, the set of read sites that moved.
- **Trace gaps** (notes/sync-test-harness.md, Trace): an entry that stays NotOpen shows `+entry` without `+commit` and nothing says why; one hour of tracing went into a sibling rotation that never opened.
- **`osis_blob::verify_stamp` returns `Ok(false)` for a good stamp** (the bool says "role entry"): read's deposit path read it with `.unwrap_or(false)` as "bad" and encrypted afresh every body it should have relayed. An enum (`Stamp::{Role, Entry}`) would make the misreading impossible.

## Tooling gaps that cost reviews and differentials time
No supported way to build main's library sources beside a branch's, a comment-only manifest edit selects the whole gate, and run.sh judges a negative control by failing alone.

Each met by several agents:
- **Library differential**: comparing a library crate's behaviour with main's (not a binary, so `tools/bin-at` does not help) is done by `git checkout origin/main -- <crate>/src` and back, which twice dropped uncommitted edits and once pulled in main's newer sibling crate that did not build. A `tools/src-at REV <crate>` that wip-commits, swaps the sources in at the merge base, builds, and swaps back would make it safe. Until then: wip-commit first, check out from `$(git merge-base HEAD origin/main)`, and `git reset --hard` back (a path checkout leaves files the other side added).
- **Comment-only manifest edits**: gate.sh and test_select.py treat any root `Cargo.toml`/`.cargo/` change as build configuration: every crate selected plus the unification check (about 2000 CPU-s), even for a comment (prose-testing; policy's pointer check can force such a comment edit). Ignoring a diff whose changed lines are all TOML comments or blank, in both places, would fix it.
- **run.sh negative controls**: an instance expected to `fail` passes as `ok` whatever it violates, so a control failing for another reason (or a TLC-level error of the wrong property) hides. An expectation `fail:<Invariant>` checked against TLC's `Invariant <name> is violated` line would pin it.
- **cpuprof by caller, callee and inlined frame**: `cpuprof_report.py` filters by one frame; splitting a function's cost by caller or phase needed a private symbolizing script (`--callers FN` / `--under FN`), and finding a probe's share inside its caller took an env-gated duplicate run (icount delta). It symbolizes with `--no-inlines`, so inlined walks and closures fold into their callers' self time: an inline-aware pass (`llvm-symbolizer --inlines`, counting each sample's innermost source line) found roles-model's real hot sites. Each `--report` re-reads the samples, so a loop over many filters takes minutes: several filters per read would fix it.
- **`tools/mutate.py` at a repeated site**: OLD must occur once, so a rule written at several identical sites (the driver's three `cx.engine.follow()` lines) took hand edits, a build and a copied-binary run per site. An occurrence selector (`OLD@N`) would plant each.

## Debug dumps that cost probe builds
Each cost a fix or review several probe builds (osis-sync and osis-engine builds take 1-5 min):
- **`why_role` shows no kept copy**: "content held, reads false" names no cause when the content is a retained copy (`Fate::Kept`); printing the kept marks (`ix.kept`) and each mark's holders would.
- **No per-node sync IDs per thing**: a reader syncing another sync ID of a thing than its writers (a sync ID fork) showed only through `OSIS_SYNC_TRACE` plus `Engine::carrying` per node; a `World` dump of each node's sync IDs for a thing beside `why_role` would show it at once.
- **No commit describer**: the trace's `+commit C..` lines are opaque; naming a commit (the grant, the rotation, the re-seal) took env-gated engine probes.
- **No round or follow counter outside `ROUND_CAP`**: measuring settle rounds per step across the osis-sync suite took a throwaway logger in the driver (`Node::rounds` is checked, never reported).
- **No census of what generators write**: which of a model's generators write a shape took a temporary panic in `World::put` plus the `_plain` runs.
- **Named order tests print no tallies**: "outputs identical" across a change needed a throwaway dump of each `check`'s `Seen` and the judgment files, built on both revisions.
- **No knob holding pushes back**: in the sync harness streams push in the settle round before `Life` drops, so an end-to-end test cannot tell an at-once lost-access drop from release's pass wait; a no-room knob would make such window tests discriminating.
- **Bare-bool misses**: a held-in-part placement reports misses and bail-outs as bools, so finding the bailing walk took a script rewriting every `return false` into a probe.
