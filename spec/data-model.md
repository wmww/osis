# Data model and value encoding
> Summary: The data everything else carries: things, tids, aspects, types, canonical value encoding, large values, hashing, groups, core aspects and schemas.

## 1. Things and tids
- Every datum is an **aspect** of a **thing**. A thing holds aspects and nothing else.
- A **tid** is 120 bits: the first 120 bits of BLAKE3 over the canonical encoding of the thing's **creation record** (spec/wire.md §3). Text form: 20 characters of unpadded base64url, prefixed `osis://` where ambiguous or user-visible.
- Creation record of an ordinary thing: (owner actor tid, 32-byte random nonce). Of a **key actor** (node, recovery key, link key), which owns itself: (algorithm-tagged signing public key, 32-byte nonce). Of an **ownerless thing** (spec/permissions.md §1): (first admin's tid, 32-byte random nonce). A link key's or recovery key's nonce derives from its seed (spec/crypto.md §3).
- A node checks a creation record by hashing when it receives the thing's data. A tid inside a value is a bare reference: it may dangle, and the thing may lack the expected aspects.
- A received record that hashes to a tid the node already holds a different record for is bad input: keep the held record, ignore the new one, report a diagnostic. Never panic on it.
- A thing never changes owner; moving it is a copy under a new tid (spec/permissions.md §7).
- An **ephemeral thing** is one whose creation record no durable commit holds at the node: the record lives in memory, with the same tid derivation and owner, and travels beside the deltas of ephemeral commits (spec/commits.md §2).
  - The durable set is closed under owner: the first commit with a durable delta on an ephemeral thing (or a durable placement into it, §8) carries `created.0` of it and of every ephemeral thing on its owner chain (spec/commits.md §2), keeping the tids, and makes its ephemeral placements durable (§8).
  - A durable thing never becomes ephemeral.
  - An ephemeral thing never given durable data is gone when no node holds it.

## 2. Aspects
- An aspect is identified by (tid, AK). An **AK** is a string (text on the wire) of the grammar `ak = [":" tid ":"] name *(":" name) "." version ["^"] ["~" / "*"]`, `name = [a-z_][a-z0-9_]*`, `tid` its 20-character text form (§1), `version` a decimal u64 without leading zeros: `name.0`, `contact:names.0`, `:<tid>:foo.1^~`. Anything else, or longer than the AK limit (spec/wire.md §4), is not an AK.
- The tid and name segments name the aspect; the **version** is its major version. A key with the same tid and name segments and a higher version is a **successor** of the lower: the form a breaking change takes (spec/versioning.md §4). A node may use the relation without any schema; it implies no conversion.
- **Markers**:
  - `^` **admin-only**: a write of the aspect needs admin on the thing (spec/permissions.md §5.2).
  - The **lifetime marker** decides where writes of the AK go, for every AK alike, declared by a schema or not:
    - none: durable commits;
    - `~` **ephemeral**: a value held in memory by the nodes holding the thing, never in a durable commit (it syncs as ephemeral commits, spec/commits.md §2, spec/sync.md §9);
    - `*` **signal**: an ephemeral write with no lasting value (delivered to listeners here and on the devices connected now, never in state; only a whole-value set).
  - A node decides an aspect's storage class from its AK alone (spec/commits.md §2).
  - Ephemeral writes carry no retention; expiry applies (spec/crdt.md §4.7, in memory).
  - Core aspects are durable but `placed.0~` (§8), which is ephemeral.
- AKs of one name segment and no tid belong to the core schema (§9); no other schema declares one. Every other AK has two or more name segments or a tid segment: first-party AKs live in the osis repository (`contact:names.0`); an app's start with a tid its maker owns, by convention (nothing checks it).
- An aspect is present iff its root fragment is present (spec/crdt.md §4.3).
- A schema declares per AK: the type, the default retention (purgeable by, keep at least, keep at most, in any form; spec/commits.md §5), which the writer puts into every delta, an optional default expiry duration measured from the write (spec/commits.md §6), and flags `ro`, `synthetic`, `guaranteed`, `indexed`, which are local: nothing on the wire enforces them. A non-durable AK declares no retention, a signal AK no expiry.

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
  - A role-class aspect's values (§9) stay inline, whatever their size (a `label.0` claim set, a `secrets.0` history box), except a `tenures.0` frontier above the threshold, which is chunked (spec/permissions.md §6).
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
  - A read of one commit's body (its history entry) holding such a link reads that body whole as not fetched.
  - When a blob such a read lacked arrives, the node delivers the aspect, or that commit's history entry, to its watches again.
- Every blob is at most `MAX_BLOB` bytes (format constant, spec/wire.md §2); a commit's limit is its header lists' (spec/commits.md §1). A revoke frontier (spec/permissions.md §5) above `CHUNK_THRESHOLD` is chunked the same way and referenced by link.

## 7. Hashing
- **Keyed content hashes** (delta hashes, link content hashes) are keyed BLAKE3 under the thing's **dedup secret** (spec/crypto.md §6), so only readers can compute or confirm them.
- Unkeyed BLAKE3: tids (over creation records), commit IDs (over headers), blob IDs (over prefix and ciphertext).
- There is no thing hash and no state hash.

## 8. Groups
- A **group** is a thing with a `group.0` aspect: `items: set<tid>`, `subgroups: set<tid>`. Its members are the items of its `group.0` and `placed.0~` plus, transitively, the members of their subgroups. Groups may overlap, nest and be cyclic; membership changes over time.
- Member, membership and member of a group mean only this placement, which grants no rights (spec/permissions.md §1). Groups are the sync unit (spec/sync.md §3).
- `groups.0` (synthetic) on a thing: the locally known groups containing it, directly or transitively, through `group.0` and `placed.0~`.
- `placed.0~`, of `group.0`'s type, is the one ephemeral core aspect: the ephemeral placements into the group, written by group operations only.
- **Group writes**:
  - Adding or removing an item or subgroup that is ephemeral after the write is a write of the group's `placed.0~`, needing write on the group.
  - Any other write of an ephemeral group's `group.0` is ephemeral too and goes to `placed.0~`.
  - Adding a durable item or subgroup is durable and persists the group (§1).
  - Removing a durable item or subgroup also removes it from `placed.0~`.
- **When a thing persists**:
  - The persisting commit adds it durably to each group it is ephemerally placed in that the persisting node may write, with that placement's expiry, and the node removes it from `placed.0~`.
  - A placement into a group it may not write stays ephemeral.
  - A persisting thing with a `placed.0~` and no `group.0` gets an empty durable `group.0` in that commit.
  - Likewise every later content commit with a durable delta on a durable thing adds each of its ephemeral placements durably (a placement made while it persisted elsewhere, or restored by an undo).

## 9. Core schema
The core aspects form the core schema, evolving under spec/versioning.md. The block below (DSL of notes/data-model.md) gives their exact types and flags; `creation`, `signing_key`, `kem_key`, `sealed` are spec/wire.md §3.

| AK | what it is for |
|---|---|
| `tid.0` | the thing's tid |
| `aspects.0` | AKs present on the thing |
| `created.0` | the creation record (spec/commits.md §2, §5) |
| `roles.0` | role grants; read as the role timeline's roster (spec/permissions.md §5). `since`: only in roster snapshots (spec/permissions.md §6). `tied`: the placement the edge goes with (spec/permissions.md §2). `until` 0: a removal saying keep (spec/permissions.md §2). `keyset`: a holder actor's edge: the key of its `keys.0` commit the last grant or raise sealed to, kept by every later write of the edge and by roster snapshots (spec/crypto.md §4) |
| `keys.0` | an actor's current keysets per role, inbox and deposit seed (spec/crypto.md §3, spec/sync.md §2) |
| `secrets.0` | an actor's boxes and history boxes (spec/crypto.md §4) |
| `tenures.0` | tenure ledger, written only by roster snapshots (spec/permissions.md §6; an audit-only entry has `since` = `until`); a large frontier is a link |
| `label.0` | labels of a synced group (spec/sync.md §2) |
| `moved.0` | the thing this one continued as (spec/permissions.md §7) |
| `was.0` | the thing this one continues (spec/permissions.md §7) |
| `node.0` | on a node thing: its software version |
| `reach.0` | on a node thing (spec/sync.md §10); never direct addresses |
| `seen.0` | on a node thing: heartbeat, always written with `expires` (spec/permissions.md §4) |
| `host.0^` | on a node thing: the node hosts (below) |
| `clients.0^` | on a node thing: the thin clients it serves (below) |
| `required.0^` | `rules`: the retention the thing requires, by AK prefix (spec/commits.md §5); `keep`: a removal from the thing keeps by default (spec/permissions.md §2, §3); a separate setting per thing, a move carrying only `keep` (spec/permissions.md §7) |
| `purge.0` | when a purge request naming no aspect to reset was made here: the delta such a commit carries (spec/commits.md §5) |
| `group.0` | §8 |
| `placed.0~` | the ephemeral placements, §8 |
| `groups.0` | the locally known groups holding the thing, §8 |
| `name.0` | what humans call the thing |
| `body.0` | freeform content: a note's text, notes on anything |
| `tag.0` | marks a group as a user-facing tag: its items are the tag's contents, its subgroups its sub-tags (§8) |

- **`host.0^`** present: the node hosts (spec/sync.md §4). Absent: it does not, and holds no host store (stopping erases it, at the latest when the node next runs sync; a later start begins empty). Never part of the node card (spec/permissions.md §4).
  - `admit` `own`: it takes registrations of the labels of groups its person owns whose hosts name its host address, and of `labels`. A group its person owns: the node or its person (the person it was created or paired for) is on the group's owner chain; no role edge, on the group or an owner above it, held by the node or the person, qualifies. The node judges `own` from what it holds (the label records it synced), so a label it has not learned yet is refused for now (code 14, spec/sync.md §5).
  - `admit` `open`: it takes registrations of any label.
  - `replicate`: peer hosts. `policy`, `caps`: local policy.
- **`clients.0^`**: thin clients by client actor (spec/sync.md §10). Never part of the node card.
  - `secret_hash`: BLAKE3 of the client's 32-byte bearer secret. `until`: when its sessions end.
  - The client actor is a thing the node's person owns, with secrets of its own, and what the client may do is that actor's roles.

**Role-class aspects**: `roles.0`, `secrets.0`, `keys.0`, `label.0`, `tenures.0`, `moved.0`, `was.0`. Their rules: spec/commits.md §2, spec/permissions.md.

```
type role = enum { 0 read, 1 write, 2 admin };
type epoch = struct { 0 n: int, 1 nonce: blob };                 // nonce: 32 bytes (spec/crypto.md §4)
type address = struct { 0 url: string, 1 key: blob };            // transport URL, 32-byte host static key
type edge_key = struct { 0 ts: int, 1 node: tid, 2 commit: blob };   // (ts, author node, 32-byte commit ID) of a write
type source = enum { 0 commit(blob), 1 session(blob) };   // a dot's source (spec/crdt.md §2.1); commit: 32-byte commit ID; session: 31 bytes, the node's tid then its nonce (spec/crdt.md §3.2)
type suspect = struct { 0 thing: tid, 1 ak: string, 2 digest: blob };   // digest: 16 bytes (spec/permissions.md §4)
type tie = struct { 0 ts: int, 1 source: source, 2 ctr: int, 3 subgroup: bool };   // creation stamp of a group.0 element and its set
type edge = struct { 0 role: role, 1 until: option<timestamp>, 2 invite: option<role>, 3 since: option<edge_key>, 4 tied: option<tie>, 5 keyset: option<edge_key> };
type keyset = struct { 0 epoch: epoch, 1 kem_key: kem_key, 2 suite: int, 3 delete_key: signing_key, 4 supersedes: set<epoch> };   // suite ID of the epoch (spec/crypto.md §4, §8); delete key: spec/crypto.md §7; supersedes: superseded epochs (spec/crypto.md §4)
type inbox = struct { 0 label: blob, 1 hosts: list<address> };  // label ID: 16 bytes
type box_key = struct { 0 holder: tid, 1 role: role, 2 epoch: epoch };
type box = enum {
    0 sealed(struct { 0 keyset: option<epoch>, 1 suite: int, 2 box: sealed, 3 names: option<blob> }),
    1 symmetric(struct { 0 epoch: epoch, 1 wrap: blob, 2 names: option<blob> }),     // epoch of s; wrap, names: spec/wire.md §7
};
type history_key = struct { 0 role: role, 1 epoch: epoch };
type frontier = struct { 0 commits: set<blob> };   // 32-byte commit IDs the demoter lists (spec/permissions.md §5.1)
type tenure = struct { 0 holder: tid, 1 role: role, 2 since: option<edge_key>, 3 until: edge_key, 4 frontier: option<frontier> };
type step_record = struct { 0 step: blob, 1 claims: option<blob> };   // spec/wire.md §8 bytes
type label = struct { 0 index: int, 1 steps: map<blob, step_record>, 2 hosts: list<address>, 3 replaced: bool };
type admit = enum { 0 own, 1 open };
type host_caps = struct { 0 entries: int, 1 bytes: int };
type client = struct { 0 secret_hash: blob, 1 until: option<timestamp> };
type bound = struct { 0 abs: option<timestamp>, 1 rel: option<duration> };
type required = struct { 0 by: enum { 0 nobody, 1 admin, 2 author_or_admin, 3 writer, 4 author }, 1 at_least: bound, 2 at_most: bound, 3 expires: option<duration> };
type required_rules = struct { 0 rules: map<string, required>, 1 keep: bool };   // rules: by AK prefix

aspect tid.0: tid [synthetic, guaranteed];
aspect aspects.0: set<string> [synthetic, guaranteed];
aspect created.0: creation [guaranteed];
aspect roles.0: map<tid, edge>;
aspect keys.0: struct {
    0 read: option<keyset>, 1 write: option<keyset>, 2 admin: option<keyset>,   // actors other than key actors
    3 key: option<kem_key>,                                                       // a key actor's one KEM key
    4 inbox: option<inbox>, 5 deposit_seed: option<blob>,                        // deposit seed: 32 bytes
};
aspect secrets.0: struct { 0 boxes: map<box_key, box>, 1 history: map<history_key, blob> };
aspect tenures.0: set<tenure>;
aspect label.0: map<blob, label>;                                // label ID -> label
aspect moved.0: tid;
aspect was.0: tid;
aspect node.0: struct { 0 software: string };
aspect reach.0: struct { 0 dialable: blob, 1 relays: list<string>, 2 lan_secret: blob };   // 32-byte P2P key, relay URLs, 32 bytes
aspect seen.0: struct { 0 ts: timestamp, 1 stranded: bool, 2 suspect: set<suspect> };    // ts: wall ms of the commit's ts
aspect host.0^: struct { 0 listen: list<string>, 1 admit: admit, 2 labels: set<blob>, 3 replicate: list<address>, 4 policy: map<string, int>, 5 caps: map<blob, host_caps> };   // label IDs: 16 bytes
aspect clients.0^: map<tid, client>;
aspect required.0^: required_rules;
aspect purge.0: timestamp;
aspect group.0: struct { 0 items: set<tid>, 1 subgroups: set<tid> };
aspect placed.0~: struct { 0 items: set<tid>, 1 subgroups: set<tid> };
aspect groups.0: set<tid> [synthetic, guaranteed];
aspect name.0: string;
aspect body.0: markdown;
aspect tag.0: struct { 0 color: option<string> };
```
- `creation` holds exactly one of fields 0, 1 and 4 and field 3 needs field 0 (spec/wire.md §3): `created.0` is typed by that rule, not by the missing-field rule of spec/versioning.md §5.
- Default retention of `node.0`, `reach.0`, `seen.0`, `host.0^`, `clients.0^`, `group.0`, `name.0`, `body.0` and `tag.0`: `author_or_admin`, no keep bounds; role-class aspects, `created.0`, `required.0^` and `purge.0` have the fixed retention of spec/commits.md §5.
- Box payloads, history box layout and AD tuples: spec/wire.md §7.

## 10. Schemas
- A schema has a **version** (integer, bumped on every publish), for people and tools only: no schema ID or version travels on the wire or is attached to aspects (spec/versioning.md §3).
- A parsed schema is itself an osis value, of type `schema` below; its canonical form is the canonical encoding of that value. The core never distributes schemas.
```
type schema = struct {
    0 version: int, 1 types: map<string, type_def>, 2 aspects: map<string, aspect_def>,   // by type name, by AK
    3 doc: option<string>,
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
type retention = struct { 0 by: enum { 0 nobody, 1 admin, 2 author_or_admin, 3 writer, 4 author }, 1 at_least: bound, 2 at_most: bound };
type flag = enum { 0 ro, 1 synthetic, 2 guaranteed, 3 indexed };
type aspect_def = struct { 0 type: type_expr, 1 retention: retention, 2 expires: option<duration>, 3 flags: set<flag>, 4 succeeds: set<string>, 5 doc: option<string> };
```
