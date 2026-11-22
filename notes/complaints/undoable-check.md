# Complaints: undoable-check
> Summary: a value check per key was out of reach (stamp keys are hashes, often virtual: `Keys`, `Row::Holders`), so the check is on undo stamps; finding which write a failure names needs a temporary backtrace in `undo_note`.

- The brief's "snapshot each written key's value" has no generic form: `Stamps` sees only key hashes, many of them virtual (`Keys`, `Run`, `Row::Holders`, `Facet::Parts`) with no value of their own, and the store's container sits beside its stamps. The check asks for an undo stamp per key instead; values stay with `check_index`.
- A failure names a container and a key hash; finding the write took a temporary `eprintln!` of a backtrace in `undo_note` filtered by table name. Two real asymmetries surfaced that way (`JMap`'s `Keys` on a came-and-went key, `Held::count`'s pair on a non-final naming taken).
- `UndoableStamps::default` names its table by the derive's line (`held.rs:27`), so three of `Held`'s fields read alike in a failure.
