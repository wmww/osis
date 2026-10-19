# Format changes
> Summary: Log of changes to frozen conformance vectors. A frozen file's MANIFEST line names the entry here that last set its bytes; each entry names every file it changes and why. Entries are reviewed by the toplevel.

Entry form: `## FC-<n>: <title>`, then the files changed (paths as in MANIFEST) and a one-line reason. FC-1 is the initial freeze.

## FC-1: initial freeze
- cbor/values.vec, tid/thing.vec, chunker/gear.vec: first frozen bytes after the toplevel review of spec/wire.md §3, §6 and spec/data-model.md §5 and of osis-core.
