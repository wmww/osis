# keel-diff-bisect
- A commit-by-commit sweep says when a seed first fails, not what broke: a change of path moves a seed into an old class (seed 23's shrunk script fails before its "first bad" commit too). Shrink, then replay the shrunk script at the good end before blaming a commit.
- No engine debug view of one commit's parts (held, missing, dropped and by whom, reachers, the snapshots' tables): a throwaway `keel_debug` printing them from the must-hold check found the cause in one run.
