# cleanup-3
- tools/mutate.py runs the binaries from target/ after its build, under the heavy lock, which can wait a long time: a rebuild of the same crate in that worktree meanwhile (editing on toward the "after" version) silently replaces what it runs. A before/after comparison needs a second worktree (`wt claim <name> origin/main`) for the "before" run, or mutate.py could copy the built binaries aside as tools/pertest.py does.
- A mutation of a method-call suffix (`.then_with(...)`) is not an expression: mutate.py says "does not build"; mutate the whole receiver expression instead.
