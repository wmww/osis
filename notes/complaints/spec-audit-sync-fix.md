# spec-audit-sync-fix
- An ephemeral re-`Add` of an element already in a set is a no-op write (`write` returns `None`), so a placement cannot be renewed by placing again; a supersession test needs an expiring unplace between the two placements.
