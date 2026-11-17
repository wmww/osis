# keel-acct-signing
- Comparing a model change against main's model needs main's model built: no second worktree may share the target, so I swapped the files in from `git show origin/main:` over a wip commit and back. A `tools/` way to build a file set from a ref into a scratch copy would be safer.
- The README's search sizes (epochs 2,000) hide rare holes: the overflow rule's safety hole showed at 8,000 only (1 world). Sizes in the README are not reach floors.
- The API tests the issue listed were mostly engine facts (inner signatures, blinds, commit bytes): the osis API exposes none of them, so "through osis" meant reaching into `internals`.
