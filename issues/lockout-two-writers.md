# Two colluding writers lock a thing for good
> Summary: writers V1 and V2 each rotate A's read and write concurrently from the same epoch, boxing only themselves; an admin lacks both current epochs, and a removal of either refuses on the epoch the other made, so no recovery exists.
> Tags: security, keys, engine

Lockout recovery (spec/permissions.md §3, spec/crypto.md §4 Boxes) lets a removal rotate while lacking current secrets only when every lacked epoch was made by a holder it removes. `set_role` removes one holder per commit (`remove_signed`'s `others` is used only by `revoke_joiner`), so a fork of two lockouts by different, unrelated writers is unrecoverable; one writer acting through two devices or its own team is covered (write on the removed holder counts).

Options, simplest first:
- `set_role` (or an engine call) removing several holders under one rotation, as `remove_signed` already does; the admin removes both. Needs an API change (notes/api-design.md).
- Count as made by a removed holder also an epoch whose maker holds no write on A any more, and let a removal lacking secrets go alone (its departure uncovered, like Seal waits); the second removal then recovers both. Changes the uniform rule; model it in Lockout.tla first (two writers).
