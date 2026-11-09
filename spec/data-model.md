# Data model and value encoding
> Summary: The data everything else carries: things, tids, aspects, types, canonical value encoding, large values, hashing, groups, core aspects and schemas.

## 1. Things and tids
- Every datum is an **aspect** of a **thing**. A thing holds aspects and nothing else.
- A **tid** is 120 bits: the first 120 bits of BLAKE3 over the canonical encoding of the thing's **creation record** (spec/wire.md §3). Text form: 20 characters of unpadded base64url, prefixed `osis://` where ambiguous or user-visible.
- Creation record of a thing: (first admin's tid, 32-byte random nonce) (spec/permissions.md §1), with a `link` flag on a link's actor K (spec/permissions.md §7). Of a **key actor** (account, node, link key), which holds admin on itself: (algorithm-tagged signing public key, 32-byte nonce), with an `account` flag on an account (spec/permissions.md §1). A link key's nonce derives from its seed (spec/crypto.md §3).
- A node checks a creation record by hashing when it receives the thing's data. A tid inside a value is a bare reference: it may dangle, and the thing may lack the expected aspects.
- A received record that hashes to a tid the node already holds a different record for is bad input: keep the held record, ignore the new one, report a diagnostic. Never panic on it.
- A thing never changes its record (its first admin is history; its admins change by grants).
- A thing is made by a durable commit carrying its `created.0` (spec/commits.md §2); no ephemeral commit carries a record. Ephemeral writes (§2) are on things already made.

## 2. Aspects
- An aspect is identified by (tid, AK). An **AK** is a string (text on the wire) of the grammar `ak = [":" tid ":"] name *(":" name) ["+"] ["^"] ("." / "~") version`, `name = [a-z_][a-z0-9_]*`, `tid` its 20-character text form (§1), `version` a decimal u64 without leading zeros: `name.0`, `contact:names.0`, `:<tid>:foo+^.1`, `call:ring+~0`. Anything else, or longer than the AK limit (spec/wire.md §4), is not an AK.
- The tid and name segments name the aspect; the **version** is its major version. A key with the same tid and name segments and a higher version is a **successor** of the lower: the form a breaking change takes (spec/versioning.md §4). A node may use the relation without any schema; it implies no conversion.
- **Markers**, independent of each other and alike for every AK, declared by a schema or not:
  - `+` **ephemeral**: writes of the aspect are held in memory by the nodes holding the thing, never in a durable commit (they sync as ephemeral commits, spec/commits.md §2, spec/sync.md §9). Without it, writes go in durable commits.
  - `^` **admin-only**: a write of the aspect needs admin on the thing (spec/permissions.md §5.2).
  - `~` in place of the `.` **signal**: the aspect has no current value. A write of it, a **fire**, is one whole-value set, never joined into state; the aspect always reads absent. An API keeps the two kinds apart: a signal is only fired and a value aspect only written; where a key's kind is not known until run time, a write of the other kind is refused before anything applies, and a read of the other kind finds nothing.
  - An ephemeral signal (`+` and `~`) is delivered here and on the nodes connected now, and held by none (relay-only commits, spec/sync.md §9). Listeners hear each fire once where it is fired and once where it is delivered, as its commit as written; no listing shows it.
  - A signal without `+` is written in durable commits: each write is history from the moment it is written, kept as long as its retention's keep history says, never joined, and heard by listeners as a listed commit (spec/commits.md §5 Signals).
  - A node decides an aspect's storage class from its AK alone (spec/commits.md §2).
  - Ephemeral writes carry no retention; expiry applies (spec/crdt.md §4.7, in memory).
  - Core aspects are durable, and none is a signal.
- AKs of one name segment and no tid belong to the core schema (§9); no other schema declares one. Every other AK has two or more name segments or a tid segment: first-party AKs live in the osis repository (`contact:names.0`); an app's start with a tid its maker administers, by convention (nothing checks it).
- An aspect is present iff its root fragment is present (spec/crdt.md §4.3).
- A schema declares per AK: the type, the default retention (purgeable by and history, in the forms spec/commits.md §5 allows; none given unless declared), which the writer puts into every delta, an optional default expiry duration measured from the write (spec/commits.md §6), and flags `synthetic`, `guaranteed`, which are local: nothing on the wire enforces them. An ephemeral AK declares no retention but keep history, an ephemeral signal neither retention nor expiry, and a signal without `+` declares a default history that keeps history (kept forever or for a positive duration). A schema's default history is kept forever, kept for a positive duration after being replaced, or purged on replace (no fixed date).
- A schema declares at most one AK per tid segment, name segments and version: keys differing only in markers are not both declared. Changing an aspect's markers takes a new version.

## 3. Types
- Scalars: `string` (UTF-8), `blob` (bytes), `bool`, `int` (i64), `float` (f64), `tid`.
- `enum { id case, id case(T), ... }`: cases with explicit non-negative integer IDs and optional payload type.
- `struct { id field: T, ... }`: fields with explicit non-negative integer IDs and an optional constant default.
- `list<T>`, `map<K, V>`, `set<T>`: any type as element, key or value.
- **Encoding wrappers** change only how concurrent writes merge; reads and writes see the inner type: `counter<int|float>` (sum of contributions), `max<int|float>`, `min<int|float>` (extreme of contributions), `text` (a string merged as a sequence). Every other type has one encoding (spec/crdt.md §3.1).
- Named types may take parameters and may be recursive. Standard named types:
  - `option<T>` = `enum { none 0, some 1 (T) }`, default `none`.
  - `markdown` = `text`, content not guaranteed valid.
  - `timestamp` = `int`, milliseconds since the Unix epoch, UTC. `duration` = `int`, milliseconds.
  - `date` = `int`, days since 1970-01-01 in the proleptic Gregorian calendar: a civil day, no zone.
  - `localtime` = `int`, milliseconds since 1970-01-01T00:00 of an unnamed zone, no leap seconds: a wall-clock time. With an IANA zone name it resolves to an instant at read time under the reader's zone rules; a wall time inside a gap (clocks moved forward) resolves forward by the gap, one inside an overlap (clocks moved back) to the earlier instant.
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
| enum | tag 1617 (ENUM) around `[case_id]` or `[case_id, payload]`; `case_id` a major-0 integer at most 2^63 - 1 |
| link | tag 1618 (LINK) around `[content hash, blob ID, suite byte || key]` (§6) |

- Tag numbers TID = 1616, ENUM = 1617, LINK = 1618 (unassigned in the IANA CBOR tags registry); 1619 (STRUCT) is reserved, unused. Each encodes as `0xd9` plus two big-endian bytes.
- RFC 8949 §4.2.1 core deterministic rules: shortest integer and length heads, definite lengths only, sorted map keys, no duplicate keys. Deviation: floats are always 8 bytes, so a float's bytes are its bit pattern.
- A set with two elements, or a map with two keys, that are equal under §4 and §6 (distinct bytes, links of one content hash) is rejected.
- No `null`, `undefined` or simple values other than true and false.
- Depth: a value nests at most 64 arrays, maps and tags deep; writers refuse deeper values, decoders reject them. Decoder limits for every other object: spec/wire.md §13.
- Floats: value identity is the IEEE 754 bit pattern. NaN is normalized at construction to the positive quiet NaN with zero payload; a decoder rejects any other NaN. -0.0 and 0.0 are distinct.
- Unknown tags are not errors: the value keeps the tag and its content as raw canonical bytes, merges as an opaque register value and fails only a typed read. New osis types are added as new tags (spec/versioning.md).
- Names never go on the wire; struct fields and enum cases are integer IDs. A struct and a `map<int, T>` share an encoding; the schema decides.

## 6. Large atomic values
- A blob, a string in register encoding, or a set element or map key whose canonical encoding exceeds `CHUNK_THRESHOLD` (format constant, spec/wire.md §2) MUST be chunked; one at or below it MUST NOT be. Only durable content answers to this:
  - A role-class aspect's values (§9) stay inline, whatever their size (a `label.0` claim set, a `secrets.0` history box).
  - An ephemeral commit has no chunks (spec/commits.md §2), so its values stay inline within its blob.
  - A durable delta on any other aspect holding such a value unchunked is bad by itself (spec/commits.md §4), judged without its type: a `Str` or `Bytes` in a register value, a set or bag element's whole value, a map key.
- Chunking: content-defined boundaries over the canonical bytes, chunker of spec/wire.md §6, giving a tree: leaves are chunks, interior nodes hold links with the plaintext length under each; the value's place in the enclosing CBOR holds the root link. Chunker, tree shape and node layout: spec/wire.md §6.
- Every chunk and interior node is a separate blob encrypted under a fresh random key (spec/sync.md §1). A **link** = (keyed content hash of the subtree, blob ID, suite byte || 32-byte blob key), 97 bytes of payload (spec/crypto.md §6); the root's content hash is a function of the value's canonical bytes alone (spec/wire.md §6).
- Equality of a large value is equality of its keyed content hash, never of its link bytes.
- A link stands only where the type takes one: a blob, string or `any` position, or a set element or map key (or a position inside one) whose type is not **small**.
  - Small types can never exceed `CHUNK_THRESHOLD`: `bool`, `int`, `float`, `tid`, counter, max, min, and an enum whose cases carry no payload.
  - A link anywhere else is a type mismatch (spec/versioning.md §5): a typed read reports it without fetching the link.
  - In a core aspect (§9) it is bad input (spec/crdt.md §3.3 rule 7).
- A read that materializes a link it cannot read (a blob of its tree not held, which includes a blob ID nothing holds, or failing to decrypt or verify under the thing's dedup secret, spec/crypto.md §6) MUST fail only that position: the link reads as absent (its list or set element, its map entry or struct field, and an enum whose payload it is, read as absent; at the aspect root the aspect reads absent), the rest of the value reads, and the node reports a diagnostic.
  - Every read of the value (typed, untyped, per path, watches) applies this rule alike.
  - A read of one commit's body (a listed part) holding such a link reads that body whole as not fetched.
  - When a blob such a read lacked arrives, the node delivers the aspect, or that commit, to its watches again.
- Every blob is at most `MAX_BLOB` bytes (format constant, spec/wire.md §2); a commit's limit is its header lists' (spec/commits.md §1). A revoke frontier (spec/permissions.md §5) above `CHUNK_THRESHOLD` is chunked the same way and referenced by link.

## 7. Hashing
- **Keyed content hashes** (delta hashes, link content hashes) are keyed BLAKE3 under the thing's **dedup secret** (spec/crypto.md §6), so only readers can compute or confirm them.
- Unkeyed BLAKE3: tids (over creation records), commit IDs (over headers), blob IDs (over prefix and ciphertext).
- There is no thing hash and no state hash.

## 8. Groups
- A **group** is a thing with a `group.0` aspect: `items: set<tid>`, `subgroups: set<tid>`. Its members are the items of its `group.0` plus, transitively, the members of their subgroups. Groups may overlap, nest and be cyclic; membership changes over time.
- Member, membership and member of a group mean only this listing, which grants no rights (spec/permissions.md §1). Groups are the sync unit (spec/sync.md §3).
- `groups.0` (synthetic) on a thing: the locally known groups containing it, directly or transitively.

## 9. Core schema
The core aspects form the core schema, evolving under spec/versioning.md. `schema/core.osis` (normative, in the DSL of notes/data-model.md) gives their exact types, flags and default retentions; `creation`, `signing_key`, `signature`, `kem_key`, `sealed` are spec/wire.md §3. Rules beyond the types:

- `roles.0` reads as the role timeline's roster (spec/permissions.md §5). `tied`: spec/permissions.md §2. `until` 0: a removal saying retain (spec/permissions.md §2).
- `addenda.0` is read per delta, never as state.
- `keys.0`: spec/crypto.md §3, spec/sync.md §2; `signing` is set only on an account's (the current epoch's signing key; `key` beside it is that epoch's KEM key). `secrets.0`: spec/crypto.md §4. `label.0`: spec/sync.md §2. `reach.0`: spec/sync.md §10. Box payloads, history box layout and AD tuples: spec/wire.md §7.
- `node.0`, `reach.0`, `host^.0`, `clients^.0` are written on node things. `node.0` and `reach.0` go under the node's account's D's home label only (spec/permissions.md §4; target, issues/account-signing.md steps 7, 8). The core schema has no heartbeat aspect: a node's last sync is its own record, stranded and suspect reports go over connections (spec/permissions.md §4; target, step 8: schema/core.osis still defines `seen.0`).
- **`account.0`** on an account's D: `struct { seeds 0: map<blob, blob> }`, per epoch of the account's signing chain its 32-byte signing public key (spec/crypto.md §3; not the epoch ID, which is the minting commit's own ID) to its 32-byte seed. Written by the account in the rotation that mints the epoch, as one entry put and nothing else on D (the first in the commit creating the account and D).
- **`listing.0`** (target, issues/account-signing.md step 6: in schema/core.osis, not yet written): `map<blob, set<blob>>`, a rotation's 32-byte commit ID to the 32-byte commit IDs a listing names (spec/permissions.md §5.5); entries only put, never reset. Read per delta, never as state.
- `required^.0`: the retention the thing requires (spec/commits.md §5) and its removal default (`retain`, spec/permissions.md §2, §3); a separate setting per thing.
- `purge.0`: the delta a purge request naming no aspect to reset carries (spec/commits.md §5).
- `group.0`, `groups.0`: §8. `tag.0` marks a group as a user-facing tag (§8).
- **`host^.0`** present: the node hosts (spec/sync.md §4). Absent: it does not, and holds no host store (stopping erases it, at the latest when the node next runs sync; a later start begins empty). Never placed under a label.
  - `admit` `own`: it takes registrations of the labels of its account's own groups whose hosts name its host address, and of `labels`. Its account's own group: its account (the account it is a node of) is on the group's record chain (spec/permissions.md §1) through record edges that stand at the node; no other role edge, on the group or a thing above it, held by the account, qualifies. The node judges `own` from what it holds (the label records it synced), so a label it has not learned yet is refused for now (code 14, spec/sync.md §5).
  - `admit` `open`: it takes registrations of any label.
  - `replicate`: peer hosts. `policy`, `caps`: local policy.
- **`clients^.0`**: clients with an actor of their own, by client actor (spec/sync.md §10). Never placed under a label.
  - `secret_hash`: BLAKE3 of the client's 32-byte bearer secret. `until`: when its sessions end.
  - The client actor is a thing whose first admin is the node's account, with secrets of its own, and what the client may do is that actor's roles.
- **Role-class aspects**: `roles.0`, `secrets.0`, `keys.0`, `label.0`, `account.0`, `listing.0`. Their rules: spec/commits.md §2, spec/permissions.md. `addenda.0` is content with the retention of a role-class aspect (spec/commits.md §5), never compacted. Role-class aspects, `addenda.0`, `required^.0` and `purge.0` have the fixed retention of spec/commits.md §5.
- `creation` holds exactly one of fields 0 and 1 (spec/wire.md §3): `created.0` is typed by that rule, not by the missing-field rule of spec/versioning.md §5.

## 10. Schemas
- A schema has a **revision** (integer, bumped on every publish), for people and tools only: no schema ID or revision travels on the wire or is attached to aspects (spec/versioning.md §3).
- A parsed schema is itself an osis value, of type `schema` in `schema/meta.osis` (normative); its canonical form is the canonical encoding of that value. The core never distributes schemas.
