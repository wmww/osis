# ended-evidence
- Checking whether a new test fails on the base meant a wip commit and `git checkout <base> -- core/...`: a full rebuild of the engine and node (about 2.5 min) each way. A per-test "against base" helper would save it.
- Spec section reads (`sed -n` over spec/commits.md §5) overflow the tool output limit: single lines run to several KB.
- The newcomer race (ending learned ahead of the dependent in one batch) was invisible until a test broke: `open_entries` orders commits by header aspects, so a header-only blob counts as carrying a creation.
