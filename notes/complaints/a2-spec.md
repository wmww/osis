# Complaints: a2-spec
> Summary: Workflow snags met writing stage A2 into spec/.

- A spec brief that rewrites spec/ ahead of the code cannot pass `tools/policy.py`: the spec_map check fails on every code/test citation of a retired anchor (93 lines here), so "commit chaining policy.py &&" is impossible without editing code outside the brief's scope. Spec-first briefs need either a policy mode that reports stale code citations without failing, or the citation retargeting as part of the spec brief.
- An unquoted heredoc ate backticked aspect names (`sync.0`) as command substitutions; quote heredocs (`<<'EOF'`) whenever the text holds backticks.
- doc_refs reads `<spec file> §N, Interim (...)` as a section name "Interim" in §N (it passed only in permissions §4, which happens to have an "Interim" list item): mark retired-rule citations with `;` before `Interim`, never `,`.
- `tools/heavy --short` refuses a command by its CPU-s history from an older, slower build (2711 CPU-s); the same test took 26 CPU-s after the rewrite, so the refusal cost a full hold.
