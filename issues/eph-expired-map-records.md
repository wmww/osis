# Expired map entries at fresh keys stay as whole records
> Summary: A map entry written at a fresh key by an expiring (ephemeral) delta stays, once expired, as its dot's key-erased record (a late write into it must still land and show as at a node that kept it; no lattice rule collects it), held decoded as a whole record: about 314 B in memory and 630 B charged at holders against 20 B encoded, so an ephemeral per-message map hits the 16 MiB node cap after about 27,000 lifetime keys. Lists and texts hold their value-less records in range records at about their encoded size (notes/crdt.md, Range records); maps have no such form.
> Priority: normal
> Tags: ephemeral, crdt

Measured (debug, crdt level): a map of registers, one fresh key per commit, every write expired: 314 B of `approx_bytes` per entry from 20 to 200 entries, decoded from the snapshot alike, 20 B per entry in the snapshot. A holder is charged each copy (`apply/memory.rs` `part_charge`: the decoded part and the joined state).

The fix is the lists' one in map form: key-erased value-less records (a creation stamp and a value-less register write at it) held per source as runs of consecutive dots with their `ts`, charged near their encoded size, every merge rule unchanged (`Map` storage, `join_entries`, `Map::of_dot`, the key index). Per entry it still grows with keys ever written (spec/requirements.md Scale), like issues/seq-dead-records-grow.md.
