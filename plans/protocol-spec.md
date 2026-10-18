# Spec the protocol bytes
> Summary: Fill every TBD in spec/ (byte layouts of everything on the wire or between nodes, format constants, sync messages, bundle format) and produce test vectors.
> Tags: sync, permissions, crypto, data-model

Output goes into the spec files themselves (new sections, or a spec/wire.md if layouts get long), plus test vectors. `grep -n TBD spec/*.md` lists what is open; every item below corresponds to one or more of those.

## Permanent blob surface (readers accept forever)
1. **Value CBOR profile** (spec/data-model.md §5): tag numbers TID, ENUM, LINK and the reserved STRUCT tag (check the IANA registry); `any` case IDs (§3).
2. **Creation record** layout (spec/data-model.md §1).
3. **Commit header** (spec/commits.md §1): field order and encoding, kinds and markers, the import origins table and the re-sourcing rank rule, the resolution hop bound (spec/permissions.md §7), the revoke frontier format, the token-hash list cap; one signature domain per signed object (spec/crypto.md §2).
4. **Blob framing** (spec/sync.md §1): prefix layout, commitment list cap, Padmé details, `MAX_BLOB`, `CHUNK_THRESHOLD`; the chunker (gear table, mask, min/max) shared by spec/data-model.md §6 and spec/crdt.md §8; the delivery blob and signal envelope (spec/crypto.md §5).
5. **Schemas**: the core schema ID; schema-as-data canonical form (spec/data-model.md §10).
6. **Core aspects** (spec/data-model.md §9): exact types of `/created`, `/members`, `/keys`, `/secrets` (box enum, suite IDs), `/moved`, `/was`, `/node`, `/reach`, `/group`, `/label` (steps, addresses with pinned keys); the contact profile thing (spec/sync.md §3).
7. **Link format**, recovery card (spec/permissions.md §9), link-key creation nonce derivation (spec/crypto.md §3).

## Node-to-node protocol (versioned separately; old clients must keep working with the official server)
8. Framing and version negotiation over the transport abstraction (spec/sync.md §6, §10); fixed maximum message size; paging; the handshake (clock, challenge, static key).
9. Messages (spec/sync.md §5, §6, §8): cursor sync, range reconciliation (choose and specify the RBSR variant), open (challenge signature, `stale`), upload (with stamps), deposit, delete (label delete key; token plus write- or sync-key signature, optionally timed), registration ("have k"), subscribe/push, signals, specific-blob fetch, download.
10. File bundle format (spec/sync.md §11); an importer treats the bundle's deletions as a peer's log events.

## Design gaps to close first
- First-contact invite format (notes/networking.md, Open).
- Any open issue tagged `sync`, `crypto` or `permissions` that changes bytes on the wire.

## Then
Test vectors for every blob type; version-skew simulation as a test category (notes/versioning.md, Open details).
