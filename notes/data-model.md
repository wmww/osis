# Data model: types, aspects, things, groups, storage
> Summary: Type system (scalars, composites, encoding wrappers, standard named types incl. `any`), value shape, aspect map and flags, AK namespaces, core aspects, schema files with schema IDs, self-certifying tids, hashing, groups, storage layering. Decided by owner unless marked proposal; review 2026-10-16 (agent) fixed gaps noted inline.

## Types
- Scalars: `string` (UTF-8), `blob` (bytes), `bool`, `int` (i64), `float` (f64), `tid`
- `enum { case, case(T), ... }`: 0+ cases, each with an integer ID (on the wire) and optional payload type. An unknown case fails the typed read.
- `struct { field: T, ... }`: named fields with small integer IDs that go on the wire instead of names. All fields required at write time; open at read time (unknown IDs preserved and ignored); optional reader-side default (notes/versioning.md).
- `list<T>`: ordered
- `map<K, V>`, `set<T>`: any type as key/value/member; deterministically ordered when serialized
- IDs (fields, cases) are non-negative integers, explicit in the schema, never reused.

### Encoding wrappers (review 2026-10-16: syntax proposal, semantics decided in notes/crdt-sync.md)
A type expression may name its merge encoding; the osis type (what reads and writes see) is the inner type, the wrapper only changes how concurrent writes merge:
- `counter<int>`, `counter<float>`: sum of contributions (increments instead of overwrites)
- `max<int|float>`, `min<int|float>`: extreme of contributions
- `text`: string merged as a text CRDT (collaborative editing)
Everything else has exactly one encoding. Wrapping an existing item is an additive change (upgrade edge in the encoding lattice, notes/versioning.md); unwrapping or changing between wrappers is not.

### Named types
Types can be named and referenced (recursion allowed, so a recursive type needs a base case through `list`/`map`/`set`/`option`) and may take type parameters. Standard ones:
- `option<T>`: `enum { 0 none, 1 some(T) }`; the only type with a built-in default (`none`)
- `markdown`: `text` holding markdown, not assumed valid
- `timestamp`: `int`, milliseconds since the Unix epoch (UTC); `duration`: `int`, milliseconds (both review 2026-10-16: used by `expires`, `/members` `until`, `/node`)
- `any` (shape proposal 2026-10-16): an enum with one case per type so an untyped value stays self-describing on the wire: `string(string)`, `blob(blob)`, `bool(bool)`, `int(int)`, `float(float)`, `tid(tid)`, `list(list<any>)`, `set(set<any>)`, `map(map<any, any>)`, `struct(map<int, any>)`, `enum(struct { 1 case: int, 2 payload: option<any> })`. Needed because struct and `map<int, T>` share a wire encoding (notes/serialization.md); merge sees the difference anyway (fragments carry encodings) so `any` matters only for values held atomically (below).

## Values
- Finite trees, never cyclic. Alternatives to cycles: tids of things with the same aspect, or a map whose values reference other keys.
- Serialization is CBOR (notes/serialization.md).
- Merge granularity (notes/crdt-sync.md): struct fields, enum payloads, map values and list elements nest as mergeable fragments, so a field deep inside a value can be edited concurrently. **Set elements and map keys are atomic values**: identified by their whole value, replaced rather than edited, and a composite there merges as one LWW value. Choose `map<K, struct>` over `set<struct>` when parts of the element should be editable.
- Large values: maps with millions of keys and single multi-GB blobs must work and sync efficiently. Large composites page their state (spec/crdt.md §8); large atomic values (blob, string register, large set elements or keys) chunk into links (notes/serialization.md).

## Aspects
An aspect has a key (AK) and a value. AK human-readable form: slash-prefixed, slash-separated, e.g. `/somenamespace/name`. AKs are strings on the wire and the stable identity of an aspect; the wire type never changes, only grows (notes/versioning.md).

**Namespaces** (review 2026-10-16, proposal): single-segment AKs (`/tid`, `/members`) belong to the core schema; app AKs have two or more segments and the first is a namespace the schema maintainer controls (app or org name). No registry exists (notes/constraints.md), so a collision between two schemas cannot be prevented, only detected: the writer's schema ID travels in the commit header and a reader whose schema claims the AK sees a foreign ID (notes/versioning.md). Until detected, the two schemas' writes merge like any concurrent writes (mismatched encodings resolve by the no-edge rule, spec/crdt.md §7), so pick namespaces that are unlikely to collide (constraints tension 20).

### Aspect map
Maps AKs to value types; built from loaded schemas. Flags per aspect (local to the aspect map, nothing on the wire enforces them; only membership restricts who writes):
- `ro`: read-only through the typed API (common for synthetic)
- `synthetic`: generated on the fly from other data
- `guaranteed`: exists on all things
- `indexed`: text-indexed for search
- Retention class (notes/crdt-sync.md): `preserve` keeps edit history until explicitly purged; `purge` drops superseded content immediately everywhere, at the cost of a snapshot upload and a blind-node retire per edit (use only where that is worth it); neither means `undefined`, nodes drop superseded content by local policy. Overridable per commit.
- `expires: duration` (2026-10-15): default expiry for writes to this AK, measured from the write; every node, blind ones included, drops the content at that time (notes/ephemeral.md). Overridable per commit.

Schemas also declare **signal kinds**: typed like an AK, but a signal is never stored and never an aspect (notes/ephemeral.md).

### Schema files
`*.osis` files define types and aspects for a use case/app, plus doc comments describing invariants. Loadable at runtime or at compile time via `load_schema!()`. Rust-like DSL, hand-written parser. Grammar sketch in notes/serialization.md. A file holds its **schema ID** (random 128-bit, minted once when the schema is created, never changes; review 2026-10-16), the current wire schema, reserved IDs, `succeeds` links and a revision number; the loader checks it is an additive superset of the last published version (notes/versioning.md). The core aspects below form the core schema, with a fixed well-known ID, evolving under the same rules.

### Core aspects (always in the aspect map)
- `/tid` (tid, synthetic, guaranteed)
- `/aspects` (set<string>, synthetic, guaranteed): AKs present on this thing
- `/created` (struct, ro, guaranteed; shape proposal): the creation record the tid hashes (owner actor tid, nonce; below)
- `/members` (map<tid, {role, until?}>; proposal): membership edges on this thing; read as the membership timeline's roster, the stored deltas are only the carrier (notes/permissions.md)
- `/keys` (keyset register, current epoch only; 2026-10-16): an actor's public KEM key per role (one for a key actor, whose signing key is in `/created`), so granters can seal secrets to it (notes/crypto.md)
- `/secrets` (2026-10-16): an actor's role secrets sealed to its members, one box per (member, role), plus history boxes per (epoch, role) (notes/crypto.md); `/handover` (proposal): hand-over records (notes/permissions.md)
- `/follows` (map<record hash, record hash>; proposal 2026-10-15): on a person actor, which successor its devices follow at a hand-over fork (notes/permissions.md, Resolution)
- `/node` (struct): a sync node. Fields (2026-10-15, notes/ephemeral.md; revised 2026-10-16): software revision, `schemas: map<schema id, revision>` (the highest revision of each schema any app on the node has loaded, which fixes the forms it reads); written on change. `/reach` (struct, 2026-10-16): its dialable key, preferred relays, direct addresses (notes/networking.md). Both published under every label the node tracks (notes/permissions.md, Nodes as things).
- `/label` (2026-10-16, membership-class): a synced group's label IDs with their registration chains and servers (notes/sync.md, Label discovery).
- `/group` (struct): `items: set<tid>`, `subgroups: set<tid>` (transitively included)
- `/groups` (set<tid>, synthetic, guaranteed): locally known groups containing this thing, directly or indirectly

Core-schema growth has one consequence worth knowing (review 2026-10-16): a node that cannot type a membership-class value (an unknown role case, say) treats it as not yet received and parks what depends on it until upgraded; nothing is lost, authorization is merely late (notes/versioning.md, Parking rule).

## Things
Things are composed of aspects and hold nothing else.

### Tids
- 120-bit, derived by hashing the creation record. Text form: 20-char base64url, prefixed `osis://` when ambiguous or user-visible (`osis://zqf7FN-YvhtF_Dy-nqdi`). In Rust: wrapper around a private u128. Uniformly distributed, so hashing is free.
- Created only by the tid generator (takes the owner; nonce from system entropy) or by parsing. No collision checking.
- A tid in a value may not exist/be known locally and may lack the expected aspects.

### Self-certifying tids (decided 2026-09-29; record layout is proposal)
Binds a thing to its first owner so nobody can publish a competing creation (notes/permissions.md).
- tid = first 120 bits of BLAKE3(creation record). Record = (owner actor tid, 32-byte random nonce); for a key actor (node, recovery key, link key), which owns itself, (algorithm-tagged public signing key, nonce); its encryption key is signed data in `/keys`, not part of the record (notes/crypto.md). Trust chain thing -> owner actor -> ... -> node key, each step checked by hashing.
- The record is checked when the thing's data is received, never for a dangling reference. References stay bare tids. The nonce keeps a bare tid from revealing its owner and seeds the thing's dedup secret (Hashing, below).
- Storage: owner kept as an index into a local table of known actors.
- Margin: forging a second record for a given tid costs 2^120; for any one of N known tids 2^120/N (N = 2^30: 2^90 hashes, roughly $10^8-10^9 at Bitcoin-ASIC efficiency, far more on GPUs; 2026 figures, hardware gets about 10x cheaper per decade). Below Bitcoin addresses (160 bits), above retired Tor v2 names (80 bits). Adequate, not generous.
- Two valid records for one tid: a conflicting record from a peer is bad input; keep what we have, ignore the other, emit a diagnostic (notes/api.md). Never panic on anything a peer can cause: a crafted collision (2^60, about $10^4 on rented GPUs) can be replayed against every node; both records of such a pair are the attacker's own. Panic only if the local generator produces a tid the node already holds.
- Rejected: key inside the tid (256 bits); bare tid plus owner told by the source node (unverifiable); (owner, local id) pairs (about 240 bits displayed).

### Hashing
Content hashes (deltas, links, chunk dedup, undo) are keyed BLAKE3 over canonical bytes, keyed with the thing's dedup secret (KDF of the creation nonce). Every reader holds it, so readers hash identically and nobody else can confirm a guess. There is no thing hash and no state hash: sync reconciles encrypted blobs by ID (notes/sync.md), and parked data (notes/versioning.md) could not be hashed as values anyway. Blob IDs are unkeyed BLAKE3 of ciphertext.

### Groups
A group is a thing with `/group`; membership is defined by that thing's data. A thing may be in many groups, membership changes over time, groups may contain themselves or be cyclic. Groups are the sync unit (notes/sync.md) and an app tool. Group membership grants no rights: a group's label only receives blobs of things the group may read (notes/permissions.md). A thing in no labeled group never syncs; nothing is in a group by being owned (owner 2026-10-16, notes/sync.md). Blind nodes see a synced group as a flat opaque set; nesting is a local index, though a node holding labels of both a group and a subgroup sees one blob set inside the other (accepted overlap leak, notes/sync.md). Example: spreadsheet thing = group of two axis things, each a group of row/column things, each a group of cells (each cell in two groups).

## Storage
Multiple backends (in-memory, sqlite, ...). Storage API kept clean and simple; sync, conflict resolution and listeners live above it. Backends hold ciphertext only (notes/local-store.md).
