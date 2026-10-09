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
- 120-bit, derived by hashing a creation record (below). Text form: 20-char base64url, prefixed `osis://` when ambiguous or user-visible (`osis://zqf7FN-YvhtF_Dy-nqdi`). In Rust: wrapper around a private u128. Uniformly distributed, so hashing is essentially free.
- Created only by a tid generator (takes the owner; nonce from system entropy) or by parsing. No collision checking.
- A tid in a value may not exist/be known locally and may lack the expected aspects.

### Self-certifying tids (decided by owner 2026-09-29; record layout is proposal)
Binds a thing to its first owner so nobody can publish a competing creation (notes/permissions.md).
- tid = first 120 bits of BLAKE3(creation record). Record = (first owner actor tid, random nonce of 128+ bits), for actors too; for a key actor (node, recovery key), which owns itself, (public signing key, nonce). Trust chain thing -> owner actor -> ... -> node key, each step checked by hashing.
- Unchanged: size, text form, uniform distribution, offline generation without anyone's permission, no collision checking. Changed: the generator needs the owner; "random" becomes "hash of a record containing randomness".
- Record stored once per thing (core aspect), about 16 bytes beyond the owner, which is stored anyway. References in values stay a bare tid; the record is checked when the thing's data is received, never for a dangling reference. The nonce keeps a bare tid from revealing its owner.
- Storage: owner kept as an index into a local table of known actors; things of the node's own actor are the common case (owner's idea).
- Margin: forging a second record for one given tid costs 2^120; for any one of N known tids 2^120/N. Below Bitcoin addresses (160 bits), above Tor v2 onion names (80 bits, retired as too weak). Adequate, not generous.
- Cost estimate (2026, rough): 2^90 hashes is about $10^8-10^9 at Bitcoin-ASIC efficiency (network does ~2^94/year for ~$16B; no such ASIC exists for BLAKE3), $10^12-10^13 on GPUs. That is for N = 2^30 known tids and wins a random one of them; a chosen tid is 2^30 times more. Hardware gets roughly 10x cheaper per decade.
- Two valid records for one tid (decided by owner): a conflicting record from a peer is bad input; the node keeps what it has, ignores the other and emits a diagnostic (notes/api.md). Never panic on anything a peer can cause: a crafted collision (2^60) costs on the order of $10^4 on rented GPUs and one pair can be replayed against every node. Both records of a crafted pair are the attacker's own. Panic is only for the local generator producing a tid the node already holds.
- Rejected: key inside the tid (a public key is 256 bits); bare tid + key told by the source node (unverifiable, two nodes can learn different owners); (owner, local id) pairs as identity (binding by construction but about 240 bits, 40 chars displayed).

### Hashing
A thing has one canonical hash at a point in time: all values hash deterministically and all aspects must be known. Synthetic aspects excluded. Hashes refer to values and are used for links, dedup and undo. Sync does not hash values or states; it reconciles encrypted blobs by ID (notes/sync.md).

### Groups
A group is a thing with `/group`; membership is defined by that thing's data. A thing may be in many groups, membership changes over time, groups may contain themselves or be cyclic. Used for sync (the sync unit, notes/sync.md) and app purposes. Blind nodes see a synced group as a flat opaque set; nesting is a local index. Example: spreadsheet thing = group of two axis things, each a group of row/column things, each a group of cells (each cell in two groups).

## Storage
Multiple backends (in-memory, sqlite, ...). Storage API kept clean and simple; sync, conflict resolution and listeners live above it.
