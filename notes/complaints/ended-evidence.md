# ended-evidence
- Checking whether a new test fails on the base meant a wip commit and `git checkout <base> -- core/...`: a full rebuild of the engine and node (about 2.5 min) each way. A per-test "against base" helper would save it.
- Spec section reads (`sed -n` over spec/commits.md §5) overflow the tool output limit: single lines run to several KB.
- The newcomer race (ending learned ahead of the dependent in one batch) was invisible until a test broke: `open_entries` orders commits by header aspects, so a header-only blob counts as carrying a creation.
- `tools/heavy` flagged a time-limit hit (2.7x CPU) for the asked-for few hundred seeds of `held_set_decides_plain` (200 seeds, 1300 s): the limit seems fixed per command, not scaled by the seed count asked for.
- Review: an `Outside`/may-hold verdict in `delete.rs::judge` without a `note.waits` entry is never judged again (no trigger), so a new may-hold rule silently stops a later delete; found only by a host-contents test.
- Review: rebasing onto main re-applied ended-keyed's commits (one test-file conflict); the `ended-keyed` ref still points at its old base.
