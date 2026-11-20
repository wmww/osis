# direct-mark
> Summary: Workflow notes from the direct-mark branch (Open 21's marked hop end to end).

- Adding one field to `osis_perm::paths::Part` touched 26 struct literals across perm and engine tests (no constructor); a brace-matching script did it. A `Part::new` or builder would make the next input field cheap.
- I built main's roles-model binary by checking main's `core/test/roles-model` out into the worktree after a wip commit, missing `tools/bin-at REV OUT --bin roles-model` (notes/build.md, Old vs new), which does exactly that.
- `tiny` generators never let a party write its own edge (`tiny_commit` skips signer == holder), which hid finding 42 until `tiny_detached` allowed it.
- One `tools/heavy` script running main's and the branch's story searches (four each) beside the perm, roles-model, held-set and rotation properties passed the hold's limits (CPU 8,259 / 5,060 s, wall 949 / 598 s, load 22): the side-by-side count comparison doubles the gate's roles-model cost; better split per hold.
