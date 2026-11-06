# A role shows before its delete keys: the first write fails opaquely
> Summary: A node can hold a write role on a thing (`role_on` says Write) and know it, yet hold neither its `keys.0` nor an inbox hint of its delete keys; its write then fails `Invalid("... admin delete key not supplied")`. `redeem` waits for the keys; other routes do not.
> Tags: osis, engine, crypto

A writer lists the target's delete keys (spec/crypto.md §7): from held secrets, `keys.0`, or an inbox hint (`Core::delete_hints`). A direct grant's inbox payload carries the hint with the role, and `redeem` of a write or admin link waits (`Engine::holds_delete_keys`). Routes with the role before the keys, unwaited:
- another node of the joiner's account: it learns the grant on K from the account's label (no hint for the target), the target's `keys.0` only when it syncs the target;
- likely any role learned from a certificate copy (a group's readers learn the group's grants that way) where the target's `keys.0` comes in a later batch. A probe (a writer of G, G granted write on a fresh T, first write at once) passed 4 of 4: there the grant commit carries T's `keys.0` itself.
The user sees `role_on` say Write and a write fail with a build error. Options: the write path reports this not-yet plainly (`Permission`-like, or `role_on` not counting a role whose keys are missing), or every grant route carries the hint. Next: a repro on the second-node route.
