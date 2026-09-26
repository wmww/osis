# Data model: types, aspects, things, groups, storage
> Summary: Type system, aspect map/flags/core aspects, schema files, tids, hashing, groups and storage layering; decided by owner, formerly spec/data.md.

## Types
- `string` (UTF-8), `blob` (bytes), `bool`, `int` (i64), `float` (f64), `tid`
- `enum<(N, V?)...>`: 0+ cases, each named, optional payload type
- `struct<(N, T)...>`: named fields, all required
- `list<T>`: ordered
- `map<K, V>`, `set<T>`: any type as key/value/member; deterministically ordered when serialized

### Named types
Types can be named and referenced (allows recursion and sub-types with their own meaning); may take type parameters. Standard ones:
- `markdown` (string): markdown text, not assumed valid
- `option<T>` (enum): some(T) | none
- `any`: enum with a case per type

## Values
- Arbitrarily nested but never recursive. Alternatives: tids of things with the same aspect, or a map whose values reference other keys.
- Serialization is CBOR (profile in notes/serialization.md).
- Large values: within reason, values are not assumed small or organized any particular way. Maps with millions of keys and single multi-GB blobs must work, and sync must stay efficient. Mechanism (links/chunking) is proposed in notes/serialization.md, not decided.

## Aspects
An aspect has a key (AK) and a value. AK human-readable form: slash-prefixed, slash-separated, e.g. `/somenamespace/name`. AK versioning: open (candidate: schema-as-data pinned by hash, see notes/serialization.md).

### Aspect map
Maps AKs to value types; built from loaded schemas. Flags per aspect:
- `ro`: read-only (common for synthetic)
- `synthetic`: generated on the fly from other data
- `guaranteed`: exists on all things
- `indexed`: text-indexed for search
- `history`: retain edit history

### Schema files
`*.osis` files define types and aspects for a use case/app, plus comments describing invariants. Loadable at runtime or at compile time via `load_schema!()`. Rust-like DSL, hand-written parser, no third-party parser library. Grammar sketch in notes/serialization.md.

### Core aspects (always in the aspect map)
- `/tid` (tid, synthetic, guaranteed): the thing's tid
- `/aspects` (set<string>, synthetic, guaranteed): AKs present on this thing
- `/node` (struct, currently empty): a sync node/device
- `/group` (struct): `items: set<tid>`, `subgroups: set<tid>` (transitively included)
- `/groups` (set<tid>, synthetic, guaranteed): groups containing this thing, directly or indirectly

## Things
Things are composed of aspects and hold nothing else.

### Tids
- Random 120-bit. Text form: 20-char base64url, prefixed `osis://` when ambiguous or user-visible (`osis://zqf7FN-YvhtF_Dy-nqdi`). In Rust: wrapper around a private u128. Uniformly distributed, so hashing is essentially free.
- Created only by a tid generator (seeded from system entropy, enough state to never repeat) or by parsing. No collision checking.
- A tid in a value may not exist/be known locally and may lack the expected aspects.

### Hashing
A thing has one canonical hash at a point in time: all values hash deterministically and all aspects must be known. Synthetic aspects excluded. Hashes refer to values and build Merkle trees, as in git. Caveat from CRDT work: sync trees likely need to hash CRDT *states*, keeping value hashes for links/dedup (notes/crdt-sync.md).

### Groups
A group is a thing with `/group`; membership is defined by that thing's data. A thing may be in many groups, membership changes over time, groups may contain themselves or be cyclic. Used for sync and app purposes. Example: spreadsheet thing = group of two axis things, each a group of row/column things, each a group of cells (each cell in two groups).

## Storage
Multiple backends (in-memory, sqlite, ...). Storage API kept clean and simple; sync, conflict resolution and listeners live above it.
