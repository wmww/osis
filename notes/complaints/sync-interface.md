# sync-interface complaints
> Summary: Workflow notes from writing the sync boundary's interface half.

- The spec files and notes put most of each rule on one very long line; `cat` of three spec files overflows the tool's output limit and lands in a file to Read again. Reading spec/ per file with Read is cheaper.
- `osis_base::memo` has no way to list the entries whose reads moved, so "work in proportion to change" had no mechanism to point at; the note proposes `Effects`/`Feed` (E2). Phase 3 cannot be proportional without it, so it should land first.
