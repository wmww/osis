# Wire formats
> Summary: Byte layouts of everything that leaves a node: common encodings, format constants, creation records, commit headers and commit blobs, blob framing and padding, the chunker and chunk trees, boxes, registration steps and claim sets, inbox blobs and signal envelopes, links and recovery cards, the node-to-node protocol, bundles, decoder limits.

## 1. Conventions
- Every structure below is canonical CBOR in the profile of spec/data-model.md §5 unless it is given as a fixed byte layout. `[a, b]` is an array with exactly those positions; `Opt(X) := [] | [X]`; `X*` repeats X zero or more times, `X+` one or more. A decoder rejects any other length, a wrong major type, or an item outside its stated size.
- Inside structures (not values): a tid is a 15-byte byte string, a commit ID, blob ID, step ID or hash a 32-byte byte string, a label ID a 16-byte byte string, a time (wall ms) or `ts` an unsigned integer. A **value** (spec/data-model.md §4) embedded in a structure keeps its value encoding (tags included).
- A role in a structure is a uint: 0 read, 1 write, 2 admin. A purgeable-by class: 0 `nobody`, 1 `admin`, 2 `author`, 3 `writer`. A token level: 1, 2, 3 (spec/crypto.md §7).
- An epoch in a structure is `[n, nonce]` (uint, 16-byte byte string).
- **AD tuples**: an AEAD associated-data tuple `(a, b, ...)` written in spec/crypto.md is the canonical CBOR array of its items in the encodings of this section; layouts below give each one.
- Signed digests: a signature's digest (spec/crypto.md §2) is BLAKE3 of the canonical bytes of the array the layout names.
- Ed25519 keys and signatures in structures are raw (32 and 64 bytes) where a layout says `pk` or `sig`; where it says `signing_key` or `signature` it holds the agility enum value (§3).

## 2. Constants
Format constants (fixed by format version 1, spec/versioning.md §1):

| constant | value |
|---|---|
| format version | 1 |
| `MAX_BLOB` | 8 MiB (8 388 608 bytes), whole blob (prefix and ciphertext) |
| `CHUNK_THRESHOLD` | 128 KiB (131 072 bytes) |
| `PAGE_TARGET` | 64 KiB (65 536 bytes) |
| chunker | `CHUNK_MIN` 16 KiB, `CHUNK_MAX` 256 KiB, gear table and boundary rule §6 |
| tree fan-out | at most 512 links per interior node or link page (§6) |
| `MAX_COMMITMENTS` | 16 token commitments per blob prefix |
| `MAX_CLAIMS` | 65 536 keys per claim set |
| `MAX_DRIFT` | 1 hour |
| `MEMBERSHIP_KEEP` | 90 days |
| `INBOX_LIFETIME` | 90 days |
| `HEARTBEAT_MIN_LIFETIME`, `HEARTBEAT_MAX_LIFETIME`, `HEARTBEAT_MIN_INTERVAL` | 1 day, 14 days, 6 hours |
| `RESOLUTION_HOPS` | 8 (spec/permissions.md §7) |
| core schema ID | 16 zero bytes, revision 1 (spec/data-model.md §9) |

Blind-node policy (recommended): `TOMBSTONE_LIFETIME` 30 days; deposit budget spec/sync.md §5. Node-to-node protocol limits (version 1, not format constants): §11.

## 3. Creation records and agility enums
- Agility enums (spec/crypto.md §8) are values: `signing_key = enum { 1 ed25519(blob) }` (32 bytes), `signature = enum { 1 ed25519(blob) }` (64 bytes), `kem_key = enum { 1 x25519_mlkem768(blob) }` (`pk_x || pk_m`, 1216 bytes), `sealed = enum { 1 x25519_mlkem768(blob) }` (`ct_x || ct_m || AEAD`). Each encodes as `1617([1, h'...'])`.
- A **creation record** is the value `creation = struct { 0 owner: tid, 1 key: signing_key, 2 nonce: blob }` holding exactly one of fields 0 and 1, and a 32-byte nonce: an ordinary thing `{0: owner, 2: nonce}`, a key actor `{1: key, 2: nonce}`. Its canonical encoding is what the tid hashes: tid = first 15 bytes of BLAKE3(canonical bytes). `/created` holds this value (spec/data-model.md §9); a `/created` whose read does not hash to its tid, or holds both or neither of fields 0 and 1, is bad input.
- A link key's or recovery key's nonce is `kdf("creation nonce", seed, "")`; a node's is random.

## 4. Commits
```
Header    := [version, author, actor, kind, ts, form, schemas, aspects, chunks, purge,
              undoes, salt, tokens, frontier, origins]
Aspect    := [tid, ak, lo, hi, Retention, expires, schema, tokens, hashes]
Retention := [by, at_least, at_most]
Bound     := {? 0: abs, ? 1: rel}
Token     := [level, token_hash]
Chunk     := [blob_id, [[ti, token_hash]*]]
PurgeItem := [commit_id, tid, ak] | [tid, ak]
Origin    := [commit_id, author, actor, ts]
CommitBlobPlaintext := [Header, signature, [Part*]]
Part      := [ai, di, delta]
```
Header fields by position:
0. `version`: uint, the format version (1).
1. `author`: tid of the signing key actor. 2. `actor`: tid of the actor it acts for.
3. `kind`: 0 content, 1 membership, 2 content compaction snapshot, 3 membership compaction snapshot, 4 import, 5 roster snapshot (spec/commits.md §2).
4. `ts` (spec/crdt.md §2.2). 5. `form`: 0 node form, 1 commit form (spec/commits.md §3).
6. `schemas`: `[[schema_id (16 bytes), revision]*]`, sorted by schema ID, distinct, at most 256.
7. `aspects`: `[Aspect+]` sorted by the canonical bytes of `[tid, ak]`, distinct.
8. `chunks`: `[Chunk*]` sorted by blob ID, distinct: every chunk, tree-node and page blob the deltas introduce, with its chunk token hashes; `ti` is an index into `tokens`, ascending, one per token secret of the delta that created the blob.
9. `purge`: `[PurgeItem*]` sorted by canonical bytes, distinct; empty when there is no purge request. `[commit_id, tid, ak]` names that commit's deltas on that aspect; `[tid, ak]` names every delta on that aspect of every commit with a smaller `ts`.
10. `undoes`: `Opt(commit_id)`.
11. `salt`: 16 random bytes (spec/crypto.md §7).
12. `tokens`: `[Token*]` sorted by canonical bytes, distinct: one per token secret of the commit's deltas, `token_hash` 16 bytes.
13. `frontier`: `Opt(frontier)`, the frontier value (spec/data-model.md §9); present iff the commit is a membership commit carrying an explicit demotion (spec/permissions.md §5).
14. `origins`: `[Origin*]` sorted by commit ID, distinct; non-empty iff `kind` is 4 (spec/permissions.md §7).

Aspect fields: `tid`; `ak` (text, spec/data-model.md §2, at most 1024 bytes); `lo`, `hi`: the counter range (`lo = hi = 0` for kinds 2, 3, 4; else `1 <= lo < hi`); `Retention`: `by` (purgeable-by class), `at_least` and `at_most` bounds, each a map with optional `0: abs` (wall ms; `2^63 - 1` means forever) and `1: rel` (ms after the body is replaced), `{}` for no bound; `expires`: `Opt(T)`; `schema`: `Opt(index into schemas)`; `tokens`: `[ti*]`, ascending indices into the header's `tokens`, the token secrets this aspect's deltas call for; `hashes`: `[delta_hash+]` (32 bytes each), exactly one for kinds 0, 2, 3, 4, sorted and distinct for kinds 1 and 5.

- **Inline or link**: `aspects`, `chunks`, `purge`, `tokens`, `origins` and the frontier are each inline iff their canonical encoding is at most `CHUNK_THRESHOLD` bytes; otherwise the position holds a LINK value (`Opt(LINK)` for the frontier) to a chunk tree (§6) of that canonical encoding, its content hashes keyed by the dedup secret of the header's `actor`. A decoder rejects an inline list above the threshold or a link below it. Header-list chunks carry the token commitments of §5.
- **Commit ID** = BLAKE3(canonical bytes of `Header`). The signature is the `signature` value of the author's key under `"osis v1 commit" || commit ID`.
- **Commit blob** plaintext: `CommitBlobPlaintext`. A `Part` holds one delta: `ai` indexes `aspects`, `di` that aspect's `hashes`, `delta` is the embedded `Delta` or `Snapshot` array (spec/crdt.md §3.2, §8) whose canonical bytes hash to that delta hash. Parts sorted by `(ai, di)`, distinct; zero parts is allowed (every delta purged). The blob's prefix commitments are those of the tokens its parts' aspects list (§5); its expiry is their common `expires`.
- A header violating a rule of spec/commits.md §2 (an aspect of the wrong class for its kind, `expires` or a purge item on a membership commit, a frontier outside a demotion, more than one hash for a kind with one delta per aspect) is bad input.
