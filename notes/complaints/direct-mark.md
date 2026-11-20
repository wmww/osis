# direct-mark
> Summary: Workflow notes from the direct-mark branch (Open 21's marked hop end to end).

- Adding one field to `osis_perm::paths::Part` touched 26 struct literals across perm and engine tests (no constructor); a brace-matching script did it. A `Part::new` or builder would make the next input field cheap.
- Comparing story-gate counts with main's needs main's roles-model binary: built by checking main's `core/test/roles-model` out into the worktree after a wip commit, then restoring. A `tools/` helper building a main copy of one model binary would save the dance.
- `tiny` generators never let a party write its own edge (`tiny_commit` skips signer == holder), which hid finding 42 until `tiny_detached` allowed it.
