# lifetimes-3b
- `git checkout <file>` to undo a probe edit (checking a test fails without a change) also threw away my other edits in that file; a probe is safer as a `sed` back and forth, or a wip commit first.
- The brief pointed at `git show 8a554db39` for Fathom's ending work, but that commit is only a complaint note; the work is the ended-evidence and ended-keyed commits before it (`git log 8a554db39~15..8a554db39`).
- Review: a store write failing (`Fault::Fail`) leaves the engine `Store(Broken)` until reopened, so a test of a refused second transaction must restart the node before reading anything.
