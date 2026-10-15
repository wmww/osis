# Set/map tombstones keep element identity after a purge
> Summary: LWW-element sets and maps need a removed element's identity (keyed value hash, or the map key itself) in state to settle concurrent adds, so a `purge`-class removal of one element leaves a fingerprint in every reader's state until the whole aspect is reset. Conflicts with the no-fingerprint deletion constraint. Needs owner.
> Tags: security, crdt

Context: notes/constraints.md (Deletion, tension 11), notes/crdt-sync.md (Removal, Merge per type).

Text/list elements have content-free IDs (dots), so dropping content on delete leaves nothing. Set elements are identified by value and map entries by key; the tombstone must carry that identity, and the dedup secret only hides it from non-readers. A later compromise of a reader confirms "tag X was removed" or sees the removed key in plaintext.

Options:
- Accept and document: `purge` guarantees apply to element values and aspect-level resets, not to set-element and map-key identity; apps with sensitive keys use a whole-aspect reset or a list.
- Hash map keys in tombstones too (removes plaintext keys, still a confirmable fingerprint for readers).
- Stability-based GC (notes/crdt-sync.md): drop tombstones once every writer has acknowledged; the fingerprint then lives only until all writers sync. Adds frontiers and stalls on offline members.
- Observed-remove with causal contexts: rejected 2026-10-14 (second conflict rule).
