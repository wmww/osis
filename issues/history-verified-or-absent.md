# History is verified or absent
> Summary: Tess (Q16): never store or use unverified history; expose history only where retention keeps it. Left to build: H3 `history()` shows only history-kept deltas so every synced node shows the same list. Vouching stays (it is "a snapshot speaks for state"), with its revocation gap stated in requirements.
> Tags: engine, crdt, api, spec, security

**H3 (API)**: history-kept = no keep-at-most bound and keep-at-least forever or an expiry (compaction never drops it). `history()`/`on_history` list only history-kept deltas: no snapshot entries, no memory commits; `Gone` only for expiry/purge; others' invalid entries left out, this actor's own kept and marked. `changed()` = newest stamp in the thing's state. Undo and `commits()` stay "what is held here", stated. Check chat `replaces`/resend, CLI `history`, sim scale tests.

**Requirements (for Tess's look, not blocking)**: a History line (H2+H3: per-write history only from signed originals; the API shows history only where retention keeps it). The Limit for a removed holder's write compacted before the removal reached the compactor is in spec/requirements.md Permissions (test `removed_holder_write_compacted_earlier_stays_alike_*`).
