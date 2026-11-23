# Complaints: a2-spec
> Summary: Workflow snags met writing stage A2 into spec/.

- A spec brief that rewrites spec/ ahead of the code cannot pass `tools/policy.py`: the spec_map check fails on every code/test citation of a retired anchor (93 lines here), so "commit chaining policy.py &&" is impossible without editing code outside the brief's scope. Spec-first briefs need either a policy mode that reports stale code citations without failing, or the citation retargeting as part of the spec brief.
- An unquoted heredoc ate backticked aspect names (`sync.0`) as command substitutions; quote heredocs (`<<'EOF'`) whenever the text holds backticks.
