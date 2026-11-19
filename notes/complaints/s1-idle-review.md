# s1-idle-review
- A copied harness world shared its quiet-run reference (`Made::quiet`, an `Arc`) with the fixture and every other copy: copies fed one reference, and a second copy in one thread panicked slicing `handed` past its end. Cloning it now copies the reference.
- A whole-workspace mutation check of a fix needs a wip commit per probe; `tools/mutate.py` would have been quicker had I looked for it first.
