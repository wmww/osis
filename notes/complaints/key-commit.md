# key-commit
- `tools/mutate.py` plants one site at a time: a probe needing two sites off at once (a check and the assert behind it) is a hand edit on a wip commit, then `git checkout` of the files.
- A test's up-front assertion on the rule under probe masks whether its behavioural part has teeth: drop it for the probe too.
