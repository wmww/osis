# Spec the protocol
> Summary: Write the byte-level spec of everything on the wire or between nodes (blob formats, commit header, wraps, core aspects, sync messages, blind-node operations) and close the remaining design gaps it exposes (download auth, server abuse limits).
> Tags: sync, permissions, serialization

Primitives and key formats: notes/crypto.md (decided 2026-10-16). Merge-type delta encodings are in spec/crdt.md (delta = `[nonce, commit table, fragment]`; the header tuple per delta is `(tid, ak, hash, lo, hi)` plus the sources table, spec §2.4; encoding IDs are inside the delta). Output: a spec document (`spec/protocol.md` or similar) plus test vectors.

## Permanent blob surface (readers accept forever)
1. **Value CBOR profile**: fix tag numbers (check IANA registry), link layout, STRUCT reservation.
2. **Commit header**: exact field order/IDs and encoding of every field in notes/crdt-sync.md (format version, author node, actor, HLC, type hash + schema revision, per-aspect counter ranges `[lo, hi)` and the sources table (spec/crdt.md §2.4), commit-ID dot marker, (tid, ak, delta hash) list, retention override, expiry, purge request, `undoes`, delete token salt and hashes, author table, per-AK type hash and revision, signature). Commit kinds: content, membership (including the roster snapshot: snapshot marker plus full membership-class states, notes/permissions.md), attestation (entry format, commit lists for commit-ID dots). Commit ID (unkeyed hash of the header without the signature; the signature is over it) and delta hash definitions (keyed, nonce placement). Algorithm enums for keys and signatures (notes/crypto.md).
3. **Blob framing**: header + deltas inside the ciphertext, Padmé padding, maximum blob size, chunk and prolly-tree node blobs, how a purged-delta rewrite or a per-label projection keeps the commit ID.
4. **Type hash**: exact canonical form of an AK's type closure.
5. **Core aspects**: final schemas for `/created` (creation record), `/members`, `/keys`, `/secrets` (sealed box and history box layouts, suite ids), `/handover` (record chain, authorization enum), `/follows`, `/node` (revisions, forms), `/reach` (dialable key, relays, addresses), `/group`, `/members` with `until`, `/label` (label IDs, registration chains, servers; notes/sync.md, Label discovery), the contact label (notes/crypto.md).
6. **Signal envelope** and **link format** (URL layout: L's seed, target tid, server, K's label) and the contact-card variant.

## Node-to-node protocol (versioned, may evolve, but the official server will see old clients)
7. Framing and version negotiation over the transport abstraction (notes/networking.md).
8. Messages: cursor sync, IDs-gained, range reconciliation fallback, upload, retire, hard delete (admin key or token + signature), label registration/re-registration (relayable; "have k" reply), subscribe/push, signals, specific-blob fetch.
9. Label entry metadata: blob ID, 49-byte wrap or chunk filler, generation, token hashes (list, format cap), expiry; generation rules. Label registration chain with the three Ed25519 role keys (upload key also gates download).
10. **Design gaps** to close here, owner calls where noted:
    - Download authorization at blind nodes and its bootstrap (grant commits under the grantee's label; notes/sync.md Open, owner to confirm).
    - Blind server abuse limits: who may create labels and store how much without the server learning identities; how paying accounts tie to labels (owner call, privacy tradeoff).
    - First-contact invite format (notes/networking.md Open).
11. File bundle format (sneakernet).

## Then
Test vectors for every blob type; version-skew simulation as a test category (notes/versioning.md).
