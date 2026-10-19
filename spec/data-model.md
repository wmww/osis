# Data model and value encoding
> Summary: Things and self-certifying tids, aspects and AKs, the type system, values and their canonical CBOR profile, large atomic values (chunk trees and links), hashing, groups, core aspects, schema identity.

## 1. Things and tids
- Every datum is an **aspect** of a **thing**. A thing holds aspects and nothing else.
- A **tid** is 120 bits: the first 120 bits of BLAKE3 over the canonical encoding of the thing's **creation record** (spec/wire.md §3). Text form: 20 characters of unpadded base64url, prefixed `osis://` where ambiguous or user-visible.
- Creation record of an ordinary thing: (owner actor tid, 32-byte random nonce). Of a **key actor** (node, recovery key, link key), which owns itself: (algorithm-tagged signing public key, 32-byte nonce). A link key's or recovery key's nonce derives from its seed (spec/crypto.md §3).
- A node checks a creation record by hashing when it receives the thing's data. A tid inside a value is a bare reference: it may dangle, and the thing may lack the expected aspects.
- A received record that hashes to a tid the node already holds a different record for is bad input: keep the held record, ignore the new one, report a diagnostic. Never panic on it.
- A thing never changes owner; moving it is a copy under a new tid (spec/permissions.md §7).

## 2. Aspects
- An aspect is identified by (tid, AK). An **AK** is a string, slash-prefixed and slash-separated (`/note/body`). AKs go on the wire as strings.
- Single-segment AKs belong to the core schema (§9). App AKs have two or more segments; the first is a namespace owned by the schema maintainer.
- An aspect is present iff its root fragment is present (spec/crdt.md §4.3).
- A schema declares per AK: the type, the default retention (purgeable by, keep at least, keep at most, in any form; spec/commits.md §5), which the writer puts into every delta, an optional default expiry duration measured from the write (spec/commits.md §6), and local flags (`ro`, `synthetic`, `guaranteed`, `indexed`) that nothing on the wire enforces.
- A schema also declares **signal kinds**, typed like AKs. Signals are never stored and are not aspects (spec/sync.md §9).

## 3. Types
- Scalars: `string` (UTF-8), `blob` (bytes), `bool`, `int` (i64), `float` (f64), `tid`.
- `enum { id case, id case(T), ... }`: cases with explicit non-negative integer IDs and optional payload type.
- `struct { id field: T, ... }`: fields with explicit non-negative integer IDs and an optional constant default.
- `list<T>`, `map<K, V>`, `set<T>`: any type as element, key or value.
- **Encoding wrappers** change only how concurrent writes merge; reads and writes see the inner type: `counter<int|float>` (sum of contributions), `max<int|float>`, `min<int|float>` (extreme of contributions), `text` (a string merged as a sequence). Every other type has one encoding (spec/crdt.md §3.1).
- Named types may take parameters and may be recursive. Standard named types:
  - `option<T>` = `enum { 0 none, 1 some(T) }`, default `none`.
  - `markdown` = `text`, content not guaranteed valid.
  - `timestamp` = `int`, milliseconds since the Unix epoch, UTC. `duration` = `int`, milliseconds.
  - `any`: the raw canonical value, self-describing by its CBOR encoding (§5); a map with int keys reads as `map<int, any>`, so a struct held in an `any` position reads back as a map.
- Field and case IDs are never reused (spec/versioning.md).
- Encoding wrappers are not allowed as set elements or map keys (those are atomic).

## 4. Values
- A value is a finite tree; never cyclic.
- Struct fields, enum payloads, map values and list elements are mergeable positions (spec/crdt.md). **Set elements and map keys are atomic**: identified by their whole value, compared by canonical bytes (large values: by keyed content hash, §6).
- Absence is expressed by `option<T>` or by a missing struct field, never by a null.

## 5. Canonical CBOR profile
Values are CBOR (RFC 8949) restricted to the following profile. A decoder MUST reject anything outside it, so canonical bytes are hashed and stored as received, never re-encoded.

| osis | CBOR |
|---|---|
| string | text string (major 3) |
| blob | byte string (major 2) |
| bool | simple 20/21 |
| int | major 0/1; values outside i64 rejected |
| float | always 8-byte float (0xfb) |
| list | array (major 4) |
| map | map (major 5), keys sorted by their canonical encoded bytes (bytewise lexicographic) |
| struct | map with int keys (field IDs); unknown IDs preserved |
| set | tag 258 around an array sorted by canonical encoded bytes of the elements |
| tid | tag 1616 (TID) around a 15-byte byte string |
| enum | tag 1617 (ENUM) around `[case_id]` or `[case_id, payload]` |
| link | tag 1618 (LINK) around `[content hash, blob ID, key]` (§6) |

- Tag numbers TID = 1616, ENUM = 1617, LINK = 1618 (unassigned in the IANA CBOR tags registry); 1619 (STRUCT) is reserved, unused. Each encodes as `0xd9` plus two big-endian bytes.
- RFC 8949 §4.2.1 core deterministic rules: shortest integer and length heads, definite lengths only, sorted map keys, no duplicate keys. Deviation: floats are always 8 bytes, so a float's bytes are its bit pattern.
- No `null`, `undefined` or simple values other than true and false.
- Depth: a value nests at most 64 arrays, maps and tags deep; writers refuse deeper values, decoders reject them. Decoder limits for every other object: spec/wire.md §13.
- Floats: value identity is the IEEE 754 bit pattern. NaN is normalized at construction to the positive quiet NaN with zero payload; a decoder rejects any other NaN. -0.0 and 0.0 are distinct.
- Unknown tags are not errors: the value keeps the tag and its content as raw canonical bytes, merges as an opaque register value and fails only a typed read. New osis types are added as new tags (spec/versioning.md).
- Names never go on the wire; struct fields and enum cases are integer IDs. A struct and a `map<int, T>` share an encoding; the schema decides.

## 6. Large atomic values
- A blob, a string in register encoding, or a set element or map key whose canonical encoding exceeds `CHUNK_THRESHOLD` (format constant, TBD, a few hundred KB) MUST be chunked; below it MUST NOT be.
- Chunking: content-defined boundaries over the canonical bytes, same chunker as spec/crdt.md §8 (gear table and mask TBD), giving a tree: leaves are chunks, interior nodes are canonical arrays of links (fan-out TBD; every node fits `MAX_BLOB`); the value's place in the enclosing CBOR holds the root link.
- Every chunk and interior node is a separate blob encrypted under a fresh random key (spec/sync.md §1). A **link** = (keyed content hash of the canonical value the subtree encodes, blob ID, suite byte || 32-byte blob key), 97 bytes of payload (spec/crypto.md §6).
- Equality of a large value is equality of its keyed content hash, never of its link bytes.
- Every blob is at most `MAX_BLOB` bytes (format constant, TBD, a few MB); a commit has no size limit (spec/commits.md §1). A revoke frontier (spec/permissions.md §5) above `CHUNK_THRESHOLD` is chunked the same way and referenced by link.

## 7. Hashing
- **Keyed content hashes** (delta hashes, link content hashes) are keyed BLAKE3 under the thing's **dedup secret** (spec/crypto.md §6), so only readers can compute or confirm them.
- Unkeyed BLAKE3: tids (over creation records), commit IDs (over headers), blob IDs (over prefix and ciphertext).
- There is no thing hash and no state hash.

## 8. Groups
- A **group** is a thing with a `/group` aspect: `items: set<tid>`, `subgroups: set<tid>`. Its members are its items plus, transitively, the members of its subgroups. Groups may overlap, nest and be cyclic; membership changes over time.
- Groups are the sync unit (spec/sync.md §3). Being in a group grants no rights (spec/permissions.md).
- `/groups` (synthetic) on a thing: the locally known groups containing it, directly or transitively.

## 9. Core schema
The core aspects form the core schema, with a well-known schema ID (TBD), evolving under spec/versioning.md. Exact types of the composite core aspects: TBD (plans/protocol-spec.md).

| AK | type | notes |
|---|---|---|
| `/tid` | tid | synthetic, guaranteed |
| `/aspects` | set<string> | synthetic, guaranteed: AKs present on the thing |
| `/created` | struct | guaranteed: the creation record; carried by the thing's first commit, retention `nobody` (spec/commits.md §2, §5) |
| `/members` | map<tid, struct { role, until: option<timestamp>, invite: option<role>, since: option<struct { ts, node: tid }> }> | membership edges (`since` only in roster snapshots, spec/permissions.md §6); read as the membership timeline's roster (spec/permissions.md §5) |
| `/keys` | struct { read, write, admin: { epoch, kem_key }, inbox, deposit seed } | an actor's current keysets per role, inbox and deposit seed (spec/crypto.md §3, spec/sync.md §2) |
| `/secrets` | struct { boxes: map<(member, role, epoch), box>, history: map<(role, epoch), history box> } | spec/crypto.md §4 |
| `/tenures` | set<struct { member: tid, role, since, until, frontier }> | tenure ledger, written only by roster snapshots (spec/permissions.md §6); a large frontier is a link |
| `/label` | map<label ID, struct { index, steps: map<step ID, step>, servers, replaced }> | labels of a synced group (spec/sync.md §2) |
| `/moved` | tid (register) | the thing this one continued as (spec/permissions.md §7) |
| `/was` | tid (register) | the thing this one continues (spec/permissions.md §7) |
| `/node` | struct { software revision, schemas: map<schema ID, revision> } | on a node thing |
| `/reach` | struct { dialable key, relays, lan secret } | on a node thing (spec/sync.md §10); never direct addresses |
| `/seen` | struct { ts: timestamp, stranded: bool } | on a node thing: heartbeat, always written with `expires` (spec/permissions.md §4) |
| `/group` | struct { items: set<tid>, subgroups: set<tid> } | §8 |
| `/groups` | set<tid> | synthetic, guaranteed, local |

**Membership-class aspects**: `/members`, `/secrets`, `/keys`, `/label`, `/tenures`, `/moved`, `/was`. Their rules: spec/commits.md §2, spec/permissions.md.

## 10. Schemas
- A schema has a **schema ID** (128 random bits, minted once, never changed) and a **revision** (integer, bumped on every publish).
- A parsed schema is itself an osis value (schema ID, revision, named types, aspects, signal kinds, doc comments); its canonical form is TBD. The core never distributes schemas.
