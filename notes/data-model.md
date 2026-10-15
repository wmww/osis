# Data model: types, aspects, things, groups, storage
> Summary: Type system, aspect map and flags, core aspects, schema files, self-certifying tids, hashing, groups, storage layering. Decided by owner unless marked proposal.

## Types
- `string` (UTF-8), `blob` (bytes), `bool`, `int` (i64), `float` (f64), `tid`
- `enum<(N, V?)...>`: 0+ cases, each with an integer ID (on the wire) and optional payload type. An unknown case fails the typed read.
- `struct<(N, T)...>`: named fields with small integer IDs that go on the wire instead of names. All fields required at write time; open at read time (unknown IDs preserved and ignored), optional reader-side default (notes/versioning.md).
- `list<T>`: ordered
- `map<K, V>`, `set<T>`: any type as key/value/member; deterministically ordered when serialized

### Named types
Types can be named and referenced (allows recursion and sub-types with their own meaning); may take type parameters. Standard ones:
- `markdown` (string): markdown text, not assumed valid
- `option<T>` (enum): some(T) | none
- `any`: enum with a case per type

## Values
- Arbitrarily nested but never recursive. Alternatives: tids of things with the same aspect, or a map whose values reference other keys.
- Serialization is CBOR (notes/serialization.md).
- Large values: maps with millions of keys and single multi-GB blobs must work and sync efficiently. Mechanism (links, content-defined chunking) in notes/serialization.md.

## Aspects
An aspect has a key (AK) and a value. AK human-readable form: slash-prefixed, slash-separated, e.g. `/somenamespace/name`. AKs are strings on the wire and the stable identity of an aspect; the wire type never changes, only grows (notes/versioning.md).

### Aspect map
Maps AKs to value types; built from loaded schemas. Flags per aspect:
- `ro`: read-only (common for synthetic)
- `synthetic`: generated on the fly from other data
- `guaranteed`: exists on all things
- `indexed`: text-indexed for search
- Retention class (notes/crdt-sync.md): `preserve` keeps edit history until explicitly purged; `purge` drops superseded content immediately everywhere, at the cost of a snapshot upload and a blind-node retire per edit (use only where that is worth it); neither means `undefined`, nodes drop superseded content by local policy. Overridable per commit.
- `expires: duration` (2026-10-15): default expiry for writes to this AK, measured from the write; every node, blind ones included, drops the content at that time (notes/ephemeral.md). Overridable per commit.

Schemas also declare **signal kinds**: typed like an AK, but a signal is never stored and never an aspect (notes/ephemeral.md).

### Schema files
`*.osis` files define types and aspects for a use case/app, plus doc comments describing invariants. Loadable at runtime or at compile time via `load_schema!()`. Rust-like DSL, hand-written parser. Grammar sketch in notes/serialization.md. A file holds only the current wire schema (plus reserved IDs, `succeeds` links and a revision number); the loader checks it is an additive superset of the last published version (notes/versioning.md).

### Core aspects (always in the aspect map)
- `/tid` (tid, synthetic, guaranteed)
- `/aspects` (set<string>, synthetic, guaranteed): AKs present on this thing
- `/created` (struct, ro, guaranteed; shape proposal): the creation record the tid hashes (owner actor tid, nonce; below)
- `/members` (map<tid, role>; proposal): membership edges on this thing (notes/permissions.md)
- `/secrets`, `/handover` (proposal): an actor's role secrets wrapped to its members; hand-over records (notes/permissions.md)
- `/node` (struct): a sync node. Fields (2026-10-15, notes/ephemeral.md): software revision, schema revisions and forms it reads, last sync time; written at a low rate.
- `/group` (struct): `items: set<tid>`, `subgroups: set<tid>` (transitively included)
- `/groups` (set<tid>, synthetic, guaranteed): locally known groups containing this thing, directly or indirectly

## Things
Things are composed of aspects and hold nothing else.

### Tids
- 120-bit, derived by hashing the creation record. Text form: 20-char base64url, prefixed `osis://` when ambiguous or user-visible (`osis://zqf7FN-YvhtF_Dy-nqdi`). In Rust: wrapper around a private u128. Uniformly distributed, so hashing is free.
- Created only by the tid generator (takes the owner; nonce from system entropy) or by parsing. No collision checking.
- A tid in a value may not exist/be known locally and may lack the expected aspects.

### Self-certifying tids (decided 2026-09-29; record layout is proposal)
Binds a thing to its first owner so nobody can publish a competing creation (notes/permissions.md).
- tid = first 120 bits of BLAKE3(creation record). Record = (owner actor tid, random nonce of 128+ bits); for a key actor (node, recovery key), which owns itself, (public signing key, nonce). Trust chain thing -> owner actor -> ... -> node key, each step checked by hashing.
- The record is checked when the thing's data is received, never for a dangling reference. References stay bare tids. The nonce keeps a bare tid from revealing its owner and seeds the thing's dedup secret (Hashing, below).
- Storage: owner kept as an index into a local table of known actors.
- Margin: forging a second record for a given tid costs 2^120; for any one of N known tids 2^120/N (N = 2^30: 2^90 hashes, roughly $10^8-10^9 at Bitcoin-ASIC efficiency, far more on GPUs; 2026 figures, hardware gets about 10x cheaper per decade). Below Bitcoin addresses (160 bits), above retired Tor v2 names (80 bits). Adequate, not generous.
- Two valid records for one tid: a conflicting record from a peer is bad input; keep what we have, ignore the other, emit a diagnostic (notes/api.md). Never panic on anything a peer can cause: a crafted collision (2^60, about $10^4 on rented GPUs) can be replayed against every node; both records of such a pair are the attacker's own. Panic only if the local generator produces a tid the node already holds.
- Rejected: key inside the tid (256 bits); bare tid plus owner told by the source node (unverifiable); (owner, local id) pairs (about 240 bits displayed).

### Hashing
Content hashes (deltas, links, chunk dedup, undo) are keyed BLAKE3 over canonical bytes, keyed with the thing's dedup secret (KDF of the creation nonce). Every reader holds it, so readers hash identically and nobody else can confirm a guess. There is no thing hash and no state hash: sync reconciles encrypted blobs by ID (notes/sync.md), and parked data (notes/versioning.md) could not be hashed as values anyway. Blob IDs are unkeyed BLAKE3 of ciphertext.

### Groups
A group is a thing with `/group`; membership is defined by that thing's data. A thing may be in many groups, membership changes over time, groups may contain themselves or be cyclic. Groups are the sync unit (notes/sync.md) and an app tool. Group membership grants no rights: a group's label only receives blobs of things the group may read (notes/permissions.md). Blind nodes see a synced group as a flat opaque set; nesting is a local index. Example: spreadsheet thing = group of two axis things, each a group of row/column things, each a group of cells (each cell in two groups).

## Storage
Multiple backends (in-memory, sqlite, ...). Storage API kept clean and simple; sync, conflict resolution and listeners live above it. Backends hold ciphertext only (notes/local-store.md).
