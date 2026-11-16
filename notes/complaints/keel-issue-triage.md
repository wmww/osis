# keel-issue-triage
- `tools/policy.py` has no `--baseline`; diffing against origin/main's output needs a second checkout (a scratch `git worktree add`).
- policy reads only git-tracked files: a new issue not yet `git add`ed makes its allow-list names read as "cited nowhere".
- Reading 150 issues needs chunked dumps; a one-line summary listing (`grep '^> Summary'`) alone is not enough to judge staleness.
