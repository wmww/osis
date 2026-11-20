# direct-mark-review
> Summary: the reviewer's mishaps on windlass-direct-mark.

- `tools/claim direct-mark` failed while the worker's `wt release` of the same worktree was still running its pre-release clippy (`.claude/wt-mark`, about 2 minutes); retrying after `wt list` showed it free worked.
- `--include-ignored` over a module filter runs the by-hand ignored tests of every module the filter matches (`validity::record_then_edge_chain_applies_spec_perm_1`, ignored for an issue, fails on main too): read which ignored test failed before blaming a change.
