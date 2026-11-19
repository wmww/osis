# tooling-3
- `tools/mutate.py` with several triples wraps each OLD as an expression: an OLD ending in `);` (a statement) fails to build and costs a build; a plain single triple takes any text.
- `git commit --amend -- <path>` commits only that path (staged deletions elsewhere stay staged): handy, but easy to misread as committing everything staged.
- I typed `git stash` into two compound commands out of habit; the settings deny rule caught both (whole call refused). Keep it out of every command, `list` included.
