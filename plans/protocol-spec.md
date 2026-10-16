# Spec the protocol bytes
> Summary: Fill every TBD in spec/ (byte layouts of everything on the wire or between nodes, format constants, sync messages, bundle format), close the protocol design gaps tracked as issues, and produce test vectors.
> Tags: sync, permissions, crypto

Output goes into the spec files themselves (new sections or a spec/wire.md if layouts get long), plus test vectors. `grep -n TBD spec/*.md` lists what is open.

## Permanent blob surface (readers accept forever)
1. **Value CBOR profile** (spec/data-model.md §5): tag numbers (check the IANA registry), `any` case IDs, STRUCT tag reservation.
2. **Commit header** (spec/commits.md §1): field order and encoding, kinds and markers, attestation entry format, signature domain digests, the hand-over identity hash input (spec/permissions.md §7).
3. **Blob framing** (spec/sync.md §1): prefix layout, commitment list cap, Padmé details, `MAX_BLOB`, `CHUNK_THRESHOLD`, chunker definition (gear table, mask, min/max) shared with spec/crdt.md §8; how purge rewrites, projections and certificate copies keep the commit ID; the delivery blob.
4. **Schemas**: core schema ID; schema-as-data canonical form (spec/data-model.md §10).
5. **Core aspects** (spec/data-model.md §9): exact types of `/created`, `/members`, `/keys`, `/secrets` (box enum, suite IDs), `/handover`, `/follows`, `/node`, `/reach`, `/group`, `/label` (steps, addresses with pinned keys); the contact profile thing.
6. **Signal envelope**, **link format** (spec/permissions.md §9), contact card, recovery card, link-key creation nonce derivation (spec/crypto.md §3).

## Node-to-node protocol (versioned separately; old clients must keep working with the official server)
7. Framing and version negotiation over the transport abstraction (spec/sync.md §10); fixed maximum message size; paging.
8. Messages (spec/sync.md §5, §6, §8): cursor sync, range reconciliation, upload with generation, retire, restore, hard delete (admin key; token plus upload-key signature), registration ("have k"), subscribe/push, signals, specific-blob fetch, bin listing, download.
9. File bundle format (spec/sync.md §11); an importer applies the re-tag rule to anything the bundle's generation claims are stale.

## Design gaps to close first
- issues/download-authorization.md (owner).
- issues/server-abuse-limits.md (owner).
- issues/chunk-delete-tokens.md.
- issues/label-replacement.md.
- First-contact invite format (notes/networking.md, Open).

## Then
Test vectors for every blob type; version-skew simulation as a test category (notes/versioning.md, Open details).
