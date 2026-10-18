# Spec the protocol bytes
> Summary: Fill every TBD in spec/ (byte layouts of everything on the wire or between nodes, format constants, sync messages, bundle format) and produce test vectors.
> Tags: sync, permissions, crypto, data-model

Output goes into the spec files themselves (new sections, or a spec/wire.md if layouts get long), plus test vectors. `grep -n TBD spec/*.md` lists what is open; every item below corresponds to one or more of those.

## Permanent blob surface (readers accept forever)
1. **Value CBOR profile** (spec/data-model.md §5): tag numbers TID, ENUM, LINK and the reserved STRUCT tag (check the IANA registry); `any` case IDs (§3).
2. **Creation record** layout (spec/data-model.md §1).
3. **Commit header** (spec/commits.md §1): field order and encoding (the aspect list grouped per `(tid, ak)` with range, retention, expiry, schema index and a list of delta hashes), kinds and markers, the import origins table and the re-sourcing rank rule, the resolution hop bound (spec/permissions.md §7), the revoke frontier format (inline and as a link above `CHUNK_THRESHOLD`), the token-hash list with levels and its cap; one signature domain per signed object (spec/crypto.md §2).
4. **Blob framing** (spec/sync.md §1): prefix layout (salt, expiry, level-tagged commitments), commitment list cap, Padmé details including how the plaintext length is recovered after padding (chunk plaintexts are raw bytes, not self-delimiting CBOR), `MAX_BLOB`, `CHUNK_THRESHOLD`; the chunker (gear table, mask, min/max) shared by spec/data-model.md §6 and spec/crdt.md §8; the inbox blob (payload: commit plus label IDs and server addresses; `INBOX_LIFETIME`) and signal envelope (spec/crypto.md §5).
5. **Schemas**: the core schema ID; schema-as-data canonical form (spec/data-model.md §10).
6. **Core aspects** (spec/data-model.md §9): exact types of `/created`, `/members`, `/keys` (keysets, inbox, deposit seed), `/secrets` (box enum with the symmetric form's epoch, suite IDs), `/tenures` (frontier inline or link), `/moved`, `/was`, `/node`, `/reach`, `/seen`, `/group`, `/label` (steps keyed by step ID, addresses with pinned keys); the contact profile thing (spec/sync.md §3).
7. **Link format** (seed, target tid, K's tid, K's label ID, servers), recovery card (spec/permissions.md §9), link-key creation nonce derivation (spec/crypto.md §3).

## Node-to-node protocol (versioned separately; old clients must keep working with the official server)
8. Framing and version negotiation over the transport abstraction (spec/sync.md §6, §10); fixed maximum message size (`MAX_MESSAGE`) and decoder limits (nesting depth, list lengths) per object; paging; the handshake (clock, challenge, static key).
9. Messages (spec/sync.md §5, §6, §8): cursor sync, range reconciliation (choose and specify the RBSR variant), open (challenge signature, claims and step keys), upload (with stamps, no open), deposit (reply with remaining budget), delete (label delete key; token plus the signature its level needs, optionally timed, earliest wins), registration ("have k"), subscribe/push, signals (write or deposit key), specific-blob fetch, download.
10. File bundle format (spec/sync.md §11); an importer treats the bundle's deletions as a peer's log events.

## Design gaps to close first
- First-contact invite format (notes/networking.md, Open).
- Any open issue tagged `sync`, `crypto` or `permissions` that changes bytes on the wire.

## Then
Test vectors for every blob type (frozen through plans/test-infra.md's freeze mechanism; the toplevel of plans/mvp_meta.md reviews every layout before the freeze); version-skew simulation as a test category (notes/versioning.md, Open details).
