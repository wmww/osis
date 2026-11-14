# sync-spec complaints
- Renumbering spec/sync.md left about 2 000 `spec/sync.md §N` pointers in code (mostly code Phase 3 deletes) stale under tools/doc_refs.py; a throwaway repoint script was the only way to keep policy green. Splitting a spec file costs a repo-wide pointer sweep.
- tools/spec_map.py RULES are hand-kept substrings: every reworded MUST needs a matching RULES edit in the same commit.
