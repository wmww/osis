# prose-engine-notes
- `tools/policy.py` doc_refs checks only `path, Section` and `path (Section` forms; the space form (`notes/engine.md Suspect repair`) went stale unnoticed. Several notes use it; policy could check it too.
- No tool checks that backticked names in notes still exist in code; I used a throwaway grep script (names whose last segment appears nowhere outside comments). Worth a `tools/` check for notes/arbitrary-values-table.md at least: 5 rows named removed constants.
