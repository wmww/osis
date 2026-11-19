# s1-take
- Undoing a sed mutation with `git checkout <file>` threw away an hour of uncommitted edits to the same file (the brief warns; I did it anyway). Mutations go through `tools/mutate.py` or a wip commit first, then `git checkout` is safe.
