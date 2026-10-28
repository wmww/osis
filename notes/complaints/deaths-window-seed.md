# deaths-window-seed
> Summary: Footguns met while fixing the walks seed 7204 deaths window.

- A one-seed walks run always fails the end coverage assertion, so a seed scan has to tell that panic from real ones by its message; an env knob to skip the coverage check would make scans plain pass/fail.
- Delivering a single late package to a fresh `LocalPeer` node leaves it pending silently when the writer's earlier commits are missing (the regression test first read deaths of an unapplied commit); deliver the writer's other packages first.
- Review: swapping one source file to an older commit's to test a differential against it (`git show rev:path > path`) and restoring with `git checkout HEAD -- other/path` silently reverted an uncommitted edit in that other file; commit first (a wip commit) before swapping files.
- Review: a cargo test command that ran past 180 s was moved to the background mid-loop while it still had file swaps to restore; long multi-step shell loops belong in `run_in_background` from the start.
- Review: the release scale test (`scale::late_delta_deaths_cost`, N=10^4) takes 2-4 min per binary under load; comparing base and head needs two release builds (~2.5 min each) plus runs, about 20 min in all.
- Review: engine-cleanup (the `core.ix.` rename) landed mid-review; the 6-commit branch conflicted per commit in deaths.rs, so it went onto main as one squashed commit (final files, perl rename per notes/complaints/engine-cleanup.md); a gate run on the old base was thrown away.
