# Roster snapshots are written as one delta per aspect
> Summary: spec/permissions.md §6 and spec/commits.md §2 want a roster snapshot's `/members` and `/tenures` as one reset-plus-full-state delta per edge and per ledger entry, so a certificate copy can carry only the edges a chain needs; `Engine::roster_snapshot` writes one replace delta per aspect, so certificate copies cannot be projected per edge yet.
> Tags: permissions, node

Repro: no failing test: `Engine::roster_snapshot` writes one replace delta per aspect.

The node's writer resolves ops into one delta per aspect (`commit_in`); several deltas for one `(tid, ak)` sharing the counter range and stamp need a writer path that splits a reset-plus-state delta by map entry (osis-crdt fragment split) and an `AspectWrite` with several deltas. Receivers already read several deltas (`apply/validity.rs`, roster parts). Until then a certificate copy of a roster snapshot carries the whole roster (a leak of the full device roster of a person actor to co-readers, notes/permissions.md Certificates), and a large roster's deltas may approach `MAX_BLOB`.

Fix: writer support for per-entry deltas in roster snapshots (node-core write path), then labeling projects certificate copies per edge.
