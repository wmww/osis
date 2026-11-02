# spec-audit-sync-fix
- An ephemeral re-`Add` of an element already in a set is a no-op write (`write` returns `None`), so a placement cannot be renewed by placing again; a supersession test needs an expiring unplace between the two placements.
- Review: `git diff main...HEAD` of a branch touching notes/node.md or notes/sync.md is ~80 KB (one-line paragraphs); `--word-diff=porcelain | grep '^[-+]'` reads it.
