# Data model and value encoding
> Summary: Things and self-certifying tids, aspects and AKs, the type system, values and their canonical CBOR profile, large atomic values (chunk trees and links), hashing, groups, core aspects, schema identity.

## 1. Things and tids
- Every datum is an **aspect** of a **thing**. A thing holds aspects and nothing else.
- A **tid** is 120 bits: the first 120 bits of BLAKE3 over the canonical encoding of the thing's **creation record** (spec/wire.md §3). Text form: 20 characters of unpadded base64url, prefixed `osis://` where ambiguous or user-visible.
- Creation record of an ordinary thing: (owner actor tid, 32-byte random nonce). Of a **key actor** (node, recovery key, link key), which owns itself: (algorithm-tagged signing public key, 32-byte nonce). A link key's or recovery key's nonce derives from its seed (spec/crypto.md §3).
- A node checks a creation record by hashing when it receives the thing's data. A tid inside a value is a bare reference: it may dangle, and the thing may lack the expected aspects.
- A received record that hashes to a tid the node already holds a different record for is bad input: keep the held record, ignore the new one, report a diagnostic. Never panic on it.
- A thing never changes owner; moving it is a copy under a new tid (spec/permissions.md §7).
- An **ephemeral thing** is one whose creation record no durable commit holds at the node: the record lives in memory, with the same tid derivation and owner. The durable set is closed under owner: the first commit with a durable delta on an ephemeral thing (or a durable placement into it, §8) carries `/created` of it and of every ephemeral thing on its owner chain (spec/commits.md §2), keeping the tids, and makes its ephemeral placements durable (§8). A durable thing never becomes ephemeral. An ephemeral thing never given durable data is gone when no node holds it.

## 2. Aspects
- An aspect is identified by (tid, AK). An **AK** is a string, slash-prefixed and slash-separated (`/note/body`). AKs go on the wire as strings.
- Single-segment AKs belong to the core schema (§9). App AKs have two or more segments; the first is a namespace owned by the schema maintainer.
- An aspect is present iff its root fragment is present (spec/crdt.md §4.3).
- A schema declares per AK: the type, the default retention (purgeable by, keep at least, keep at most, in any form; spec/commits.md §5), which the writer puts into every delta, an optional default expiry duration measured from the write (spec/commits.md §6), and flags. `ro`, `synthetic`, `guaranteed`, `indexed` are local; nothing on the wire enforces them. At most one **lifetime flag** decides where writes of the AK go: none, durable commits; `ephemeral`, a value held in memory by the nodes holding the thing, never in a durable commit (it syncs as ephemeral commits, spec/commits.md §2, spec/sync.md §9); `presence`, an `ephemeral` value tied to its author's presence (it goes at every holder once no path to its author is left, spec/sync.md §9; no expiry, default or written); `signal`, an ephemeral write with no lasting value (delivered to listeners here and on the devices connected now, never in state; only a whole-value set). Ephemeral writes carry no retention; expiry applies (spec/crdt.md §4.7, in memory). Core aspects are durable. An aspect reads the join of its durable and ephemeral states (spec/crdt.md §4.1).

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
| enum | tag 1617 (ENUM) around `[case_id]` or `[case_id, payload]` |
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
- A blob, a string in register encoding, or a set element or map key whose canonical encoding exceeds `CHUNK_THRESHOLD` (format constant, spec/wire.md §2) MUST be chunked; below it MUST NOT be. Exception: a `/tenures` element is never chunked whole; its frontier is (spec/permissions.md §6).
- Chunking: content-defined boundaries over the canonical bytes, same chunker as spec/crdt.md §8, giving a tree: leaves are chunks, interior nodes are `[level, [LINK+], [len+]]` (at most 512 links, each with the plaintext length under it, so a reader seeks without fetching what lies before); the value's place in the enclosing CBOR holds the root link. Chunker, tree shape and node layout: spec/wire.md §6.
- Every chunk and interior node is a separate blob encrypted under a fresh random key (spec/sync.md §1). A **link** = (keyed content hash of the subtree, blob ID, suite byte || 32-byte blob key), 97 bytes of payload (spec/crypto.md §6); the root's content hash is a function of the value's canonical bytes alone (spec/wire.md §6).
- Equality of a large value is equality of its keyed content hash, never of its link bytes.
- Every blob is at most `MAX_BLOB` bytes (format constant, spec/wire.md §2); a commit has no size limit (spec/commits.md §1). A revoke frontier (spec/permissions.md §5) above `CHUNK_THRESHOLD` is chunked the same way and referenced by link.

## 7. Hashing
- **Keyed content hashes** (delta hashes, link content hashes) are keyed BLAKE3 under the thing's **dedup secret** (spec/crypto.md §6), so only readers can compute or confirm them.
- Unkeyed BLAKE3: tids (over creation records), commit IDs (over headers), blob IDs (over prefix and ciphertext).
- There is no thing hash and no state hash.

## 8. Groups
- A **group** is a thing with a `/group` aspect: `items: set<tid>`, `subgroups: set<tid>`. Its members are its items plus, transitively, the members of its subgroups. Groups may overlap, nest and be cyclic; membership changes over time.
- Groups are the sync unit (spec/sync.md §3). Being in a group grants no rights (spec/permissions.md).
- `/groups` (synthetic) on a thing: the locally known groups containing it, directly or transitively, through both sides of `/group`.
- `/group` is the one core aspect with an ephemeral side. Adding or removing an item or subgroup that is ephemeral after the write is an ephemeral write of the group's `/group`, needing write on the group; any other write of an ephemeral group's `/group` is ephemeral too. Adding a durable item or subgroup is durable and persists the group (§1). When a thing persists, the persisting commit adds it durably to each group it is ephemerally placed in that the persisting node may write, with that placement's expiry, and the node removes the ephemeral element; a placement into a group it may not write stays ephemeral. Likewise every later content commit with a durable delta on a durable thing adds each of its ephemeral placements durably (a placement made while it persisted elsewhere, or restored by an undo), and removing a durable item or subgroup also removes its ephemeral element. A persisting thing with an ephemeral `/group` and no durable one gets an empty durable `/group` in that commit.

## 9. Core schema
The core aspects form the core schema, schema ID 16 zero bytes, revision 1, evolving under spec/versioning.md. Exact types below (DSL of notes/data-model.md); `creation`, `signing_key`, `kem_key`, `sealed` are spec/wire.md §3.

| AK | type | notes |
|---|---|---|
| `/tid` | tid | synthetic, guaranteed |
| `/aspects` | set<string> | synthetic, guaranteed: AKs present on the thing |
| `/created` | struct | guaranteed: the creation record; carried by the thing's first commit, retention `nobody` (spec/commits.md §2, §5) |
| `/members` | map<tid, struct { role, until: option<timestamp>, invite: option<role>, since: option<edge_key> }> | membership edges (`since` only in roster snapshots, spec/permissions.md §6); read as the membership timeline's roster (spec/permissions.md §5) |
| `/keys` | struct { read, write, admin: { epoch, kem_key, delete_key }, inbox, deposit seed } | an actor's current keysets per role, inbox and deposit seed (spec/crypto.md §3, spec/sync.md §2) |
| `/secrets` | struct { boxes: map<(member, role, epoch), box>, history: map<(role, epoch), history box> } | spec/crypto.md §4 |
| `/tenures` | set<struct { member: tid, role, since, until, frontier }> | tenure ledger, written only by roster snapshots (spec/permissions.md §6; an audit-only entry has `since` = `until`); a large frontier is a link |
| `/label` | map<label ID, struct { index, steps: map<step ID, step>, servers, replaced }> | labels of a synced group (spec/sync.md §2) |
| `/moved` | tid (register) | the thing this one continued as (spec/permissions.md §7) |
| `/was` | tid (register) | the thing this one continues (spec/permissions.md §7) |
| `/node` | struct { software revision, schemas: map<schema ID, revision> } | on a node thing |
| `/reach` | struct { dialable key, relays, lan secret } | on a node thing (spec/sync.md §10); never direct addresses |
| `/seen` | struct { ts: timestamp, stranded: bool } | on a node thing: heartbeat, always written with `expires` (spec/permissions.md §4) |
| `/group` | struct { items: set<tid>, subgroups: set<tid> } | §8 |
| `/groups` | set<tid> | synthetic, guaranteed, local |
| `/name` | string | what humans call the thing |
| `/body` | markdown | freeform content: a note's text, notes on anything |
| `/tag` | struct { color: option<string> } | marks a group as a user-facing tag: its items are the tag's contents, its subgroups its sub-tags (§8) |

**Membership-class aspects**: `/members`, `/secrets`, `/keys`, `/label`, `/tenures`, `/moved`, `/was`. Their rules: spec/commits.md §2, spec/permissions.md.

```
type role = enum { 0 read, 1 write, 2 admin };
type epoch = struct { 0 n: int, 1 nonce: blob };                 // nonce: 32 bytes (spec/crypto.md §4)
type address = struct { 0 url: string, 1 key: blob };            // transport URL, 32-byte server static key
type edge_key = struct { 0 ts: int, 1 node: tid, 2 commit: blob };   // (ts, author node, 32-byte commit ID) of a write
type edge = struct { 0 role: role, 1 until: option<timestamp>, 2 invite: option<role>, 3 since: option<edge_key> };
type keyset = struct { 0 epoch: epoch, 1 kem_key: kem_key, 2 suite: int, 3 delete_key: signing_key };   // suite ID of the epoch (spec/crypto.md §4, §8); delete key: spec/crypto.md §7
type inbox = struct { 0 label: blob, 1 servers: list<address> };  // label ID: 16 bytes
type box_key = struct { 0 member: tid, 1 role: role, 2 epoch: epoch };
type box = enum {
    0 sealed(struct { 0 keyset: option<epoch>, 1 suite: int, 2 box: sealed }),
    1 symmetric(struct { 0 epoch: epoch, 1 wrap: blob }),     // epoch of s; wrap: spec/wire.md §7
};
type history_key = struct { 0 role: role, 1 epoch: epoch };
type frontier = struct {
    0 writes: map<tid, map<string, map<tid, int>>>,           // tid -> AK -> author node -> last counter received contiguously (inclusive)
    1 commits: set<blob>,                                       // commit IDs of commit-form writes and the demoter's chain certificates
};
type tenure = struct { 0 member: tid, 1 role: role, 2 since: option<edge_key>, 3 until: edge_key, 4 frontier: option<frontier> };
type step_record = struct { 0 step: blob, 1 claims: option<blob> };   // spec/wire.md §8 bytes
type label = struct { 0 index: int, 1 steps: map<blob, step_record>, 2 servers: list<address>, 3 replaced: bool };

aspect /tid: tid [synthetic, guaranteed];
aspect /aspects: set<string> [synthetic, guaranteed];
aspect /created: creation [guaranteed];
aspect /members: map<tid, edge>;
aspect /keys: struct {
    0 read: option<keyset>, 1 write: option<keyset>, 2 admin: option<keyset>,   // actors other than key actors
    3 key: option<kem_key>,                                                       // a key actor's one KEM key
    4 inbox: option<inbox>, 5 deposit_seed: option<blob>,                        // deposit seed: 32 bytes
};
aspect /secrets: struct { 0 boxes: map<box_key, box>, 1 history: map<history_key, blob> };
aspect /tenures: set<tenure>;
aspect /label: map<blob, label>;                                // label ID -> label
aspect /moved: tid;
aspect /was: tid;
aspect /node: struct { 0 software: string, 1 schemas: map<blob, int> };   // schema ID -> revision
aspect /reach: struct { 0 dialable: blob, 1 relays: list<string>, 2 lan_secret: blob };   // 32-byte P2P key, relay URLs, 32 bytes
aspect /seen: struct { 0 ts: timestamp, 1 stranded: bool };    // ts: wall ms of the commit's ts
aspect /group: struct { 0 items: set<tid>, 1 subgroups: set<tid> };
aspect /groups: set<tid> [synthetic, guaranteed];
aspect /name: string;
aspect /body: markdown;
aspect /tag: struct { 0 color: option<string> };
```
- `creation`'s fields 0 and 1 are exclusive and field 3 needs field 0 (spec/wire.md §3): `/created` is typed by that rule, not by the missing-field rule of spec/versioning.md §5.
- `option` fields default to `none`. Default retention of `/node`, `/reach`, `/seen`, `/group`, `/name`, `/body` and `/tag`: `author`, no keep bounds; membership-class aspects and `/created` have the fixed retention of spec/commits.md §5.
- Box payloads, history box layout and AD tuples: spec/wire.md §7.

## 10. Schemas
- A schema has a **schema ID** (128 random bits, minted once, never changed) and a **revision** (integer, bumped on every publish).
- A parsed schema is itself an osis value, of type `schema` below; its canonical form is the canonical encoding of that value. The core never distributes schemas.
```
type schema = struct {
    0 id: blob, 1 revision: int,                                // id: 16 bytes
    2 types: map<string, type_def>, 3 aspects: map<string, aspect_def>,   // by type name, by AK
    5 doc: option<string>,                                       // 4 retired
};
type type_def = struct { 0 params: list<string>, 1 body: type_expr, 2 doc: option<string> };
type type_expr = enum {
    0 string, 1 blob, 2 bool, 3 int, 4 float, 5 tid, 6 any, 7 text,
    8 list(type_expr), 9 set(type_expr), 10 map(struct { 0 key: type_expr, 1 value: type_expr }),
    11 struct(struct { 0 fields: map<int, field_def>, 1 reserved: set<int> }),
    12 enum(struct { 0 cases: map<int, case_def>, 1 reserved: set<int> }),
    13 counter(type_expr), 14 max(type_expr), 15 min(type_expr),
    16 named(struct { 0 name: string, 1 args: list<type_expr> }),   // schema types and option, markdown, timestamp, duration
    17 param(string),                                            // a parameter of the enclosing type_def
};
type field_def = struct { 0 name: string, 1 type: type_expr, 2 default: option<any>, 3 succeeds: set<int>, 4 doc: option<string> };
type case_def = struct { 0 name: string, 1 payload: option<type_expr>, 2 succeeds: set<int>, 3 doc: option<string> };
type bound = struct { 0 abs: option<timestamp>, 1 rel: option<duration> };
type retention = struct { 0 by: enum { 0 nobody, 1 admin, 2 author, 3 writer }, 1 at_least: bound, 2 at_most: bound };
type flag = enum { 0 ro, 1 synthetic, 2 guaranteed, 3 indexed, 4 ephemeral, 5 presence, 6 signal };
type aspect_def = struct { 0 type: type_expr, 1 retention: retention, 2 expires: option<duration>, 3 flags: set<flag>, 4 succeeds: set<string>, 5 doc: option<string> };
```
