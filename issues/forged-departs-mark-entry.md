# A self-removing member may forge a departs-mark entry
> Summary: Untested report (notes/handoff.md, Security first): a member removing itself may add a history entry saying its own removal is covered, so nobody rotates and it keeps reading. Confirm with a test, then fix, before other keys work.
> Tags: security, keys, tests

Named in notes/handoff.md (keys-tidy state) with no file behind it; this records it. Nothing is confirmed: the first step is a test in osis-keys or osis-node where a self-removing reader writes a history entry whose names (or departs mark, spec/crypto.md §4 covers by names) meet its own removal, and checks whether the next writer still rotates the read role (spec/permissions.md §3 required rotation).
