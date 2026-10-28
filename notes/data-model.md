# Data model and serialization: rationale
> Summary: Why spec/data-model.md looks the way it does (tids, CBOR profile, large values, AK namespaces, groups), the schema DSL as implemented in osis-schema, storage layering, rejected options. Mostly owner decisions; shapes of `any` and the core aspects' types are proposals.

## Tids
- Self-certifying tids bind a thing to its first owner so nobody can publish a competing creation. The nonce keeps a bare tid from revealing its owner and seeds the dedup secret. References stay bare tids; the record is checked only when the thing's data arrives.
- Created only by the tid generator (takes the owner; nonce from system entropy) or by parsing. No collision checking. In Rust: a wrapper around a private u128. Uniformly distributed, so hashing a tid is free.
- Margin: a second record for a given tid costs 2^120; for any of N known tids 2^120/N (N = 2^30: 2^90 hashes, roughly $10^8–10^9 at Bitcoin-ASIC efficiency in 2026, far more on GPUs). Below Bitcoin addresses (160 bits), above retired Tor v2 names (80 bits). Adequate, not generous.
- A crafted collision pair (2^60, about $10^4 on rented GPUs) can be replayed against every node, hence "keep what we have, diagnostic, never panic"; both records of such a pair are the attacker's own. Panic only if the local generator produces a tid the node already holds.
- Storage: owner kept as an index into a local table of known actors.
- Rejected: key inside the tid (256 bits); bare tid plus owner told by the source node (unverifiable); (owner, local id) pairs (about 240 bits displayed).

## Values and CBOR
- CBOR: IETF standard, deterministic profile exists, tags cover osis types, diagnostic notation lets generic tools print any value. DAG-CBOR only allows string map keys. dCBOR's numeric reduction encodes 1.0 as 1, erasing the int/float distinction. Floats are always 8 bytes so a float's bytes are its bit pattern (owner confirmed the float rule).
- Names never go on the wire (owner): a value without its schema prints with numbered keys.
- New types are tags, because a major-type-level construct would need a format version bump.
- Strict decoding means bytes are hashed and stored as received, never re-encoded; important for multi-GB blobs.
- No serde on the wire: generic serde CBOR backends do not sort keys, enforce shortest heads or 8-byte floats, or reject non-canonical input, and serde's data model has no sets, tags or tids. Own encoder/decoder for `Value` (a few hundred lines). A serde layer converting app types to and from `Value` is an optional convenience.
- Cycles are not allowed; alternatives: tids of things with the same aspect, or a map whose values reference other keys.
- `any` is the raw value: struct and `map<int, T>` share an encoding, merge state tells them apart anyway, and a struct held in an `any` slot reading back as a map is the only loss. Its merge encoding follows the value's kind (spec/crdt.md §3.1), so a map in an `any` position merges per key and a string merges as a register; different kinds over time meet as slots. Rejected: an enum with one case per kind (eleven case IDs and a tag per node for a distinction that only matters for values held atomically).
- Set elements and map keys are atomic: choose `map<K, struct>` over `set<struct>` when parts of an element should be editable.

## Large values
- Two mechanisms, one chunker: large composites page their merge state (spec/crdt.md §8); large atomic values chunk into link trees (spec/data-model.md §6).
- Random chunk keys are required by the no-fingerprint rule (a content-derived key makes a retained blob ID a fingerprint), so equality of large values is by keyed content hash (spec/requirements.md, Data model). Dedup is by reuse from the current tree (notes/local-store.md).
- Whole-value access is always allowed, streaming also; whether the API exposes links or a separate abstraction is an implementation question.
- Implementation (osis-label `chunks`, `tree`): the writer knows the declared length up front, so inline vs link is decided before any byte (no buffering above the threshold). Equality by content hash lives in `osis_base::Value` itself, so every crdt and schema comparison (set read and ops, map keys, register diff) follows without special cases.
- Reuse checks: an old chunk is reused only if held, intact (blob ID, decryption, equal plaintext) and kept by the re-encryption rule; a node only if its blob is kept and its children are exactly the old node's (otherwise a fresh node over the reused children). Missing old blobs (lazily fetched) are simply written afresh: reuse is an optimization, a fresh encryption is always valid. Reused blobs are not in the delta's chunk list (it lists blobs the delta introduces). Pages are never reused.
- Tree nodes carry a plaintext length per link (spec/wire.md §6), so any reader seeks in O(depth) fetches with no local index (`TreeReader::seek`, the root node kept across seeks; a seek inside the chunk held moves without fetching). The alternative, a local rebuildable length index, left the first seek on a tree never read locally O(offset). Lengths sit inside the encrypted, Padmé-padded node, so a blind server learns nothing new (chunk blob sizes already bound chunk lengths). The node hash covers them (FC-4): a content hash pins every length, so equality by content hash, reuse and edit matching never meet a liar tree posing as an honest one; a reader still checks every length on its path (a writer can publish a liar tree under its own hash), never sizing a buffer from one, and parse rejects a level-k length above `512^(k-1) · CHUNK_MAX`.
- Reuse also serves list `edit`: an item the list lends (by content hash: the links at the edit's window when the read matches base there, else any it holds) keeps its link; `base` items become hash-only links so they match the list's read (notes/node.md Large values).
- Node (osis-node `engine/large.rs`, `engine/blobs.rs`; osis `large.rs`): the write path chunks large registers, blobs, strings, set elements and map keys; pages are fetched before their commit applies; the API offers `stream`, `len`, `set_stream`. A `set` over a large value reuses the current tree's chunks, so an edit writes and uploads O(change) (notes/node.md, Large values).

## Wire choices (spec/wire.md)
- Tags 1616-1619 sit in the IANA registry's unassigned 1401-18299 block (checked against the registry); every tag >= 256 costs a 3-byte head, so no cheaper choice existed in the allowed range. Registering them is optional.
- Core schema ID is 16 zero bytes: well known, and no randomly minted ID collides with it.
- The creation record is a struct value so `/created` stores exactly the hashed bytes. Link and recovery keys derive their nonce from the seed, so the link or card alone names the key actor's tid.
- Tree-node content hashes cover their children's hashes, not the bytes below: an edit rehashes one path (O(change)), while covered-bytes hashing rehashes up to the whole value per level. The root stays a function of the value's bytes, so equality by content holds. Nodes close on a content-hash byte (prolly-tree style) so an insert does not shift every later node.
- `MAX_BLOB / CHUNK_THRESHOLD = 64`: 128 KiB keeps ordinary documents inline; 8 MiB blobs fit one protocol message and browser memory.
- Value depth 64, any object 512: bounds decoder recursion; deeper app values are refused at write.

## AK namespaces
No registry exists, so namespace collisions between schemas are detected (schema ID in headers), never prevented; until detected their writes merge like concurrent writes (spec/requirements.md, Versioning). Pick namespaces unlikely to collide (app or org name).

## Groups
Example: spreadsheet thing = group of two axis things, each a group of row/column things, each a group of cells (each cell in two groups). Nothing is in a group by being owned (owner): apps place things explicitly (spec/requirements.md, Offline and network).

## Schema DSL (`*.osis` files; implemented in osis-schema)
Rust-like syntax, hand-written recursive-descent parser (no parser libraries, owner decision); grammar in `core/schema/src/parse.rs`. Two passes: the first collects items, the second types field defaults against the then-known types. `///` docs attach to the next item (type, field, case, aspect, signal), `//!` to the schema, and are kept in the schema value. Errors carry file, line, column; validation errors point at the item. No `load_schema!()` proc macro (compile time; codegen covers it).
```
//! Notes app schema.
schema 0x7f3a9c21e0d84b6a9b1c5e2d4f607a83;   // 16 bytes, random, minted once
revision 4;                                   // bumped on every publish

type priority = enum { 0 low, 1 medium, 2 high, 3 custom(int), reserved (4, 5) };
type task = struct {
    1 title: string,
    4 priority: option<priority>,            // option defaults to none
    7 status: option<status> succeeds 2,     // succeeds N or (N, M)
    8 weight: float = 1.0,                   // constant default
    reserved 5,
};
type tagged<T> = struct { 0 label: string, 1 value: T };

aspect /note/body: markdown [indexed];
aspect /note/last_opened: timestamp [expires: 30d];
aspect /note/pinned: map<tid, tagged<int>> [by: writer, keep_at_most: 0s];
aspect /note/title2: string succeeds /note/title;
signal /note/typing: struct { 0 who: tid, 1 at: timestamp };
```
- Aspect attributes: flags `ro`, `synthetic`, `guaranteed`, `indexed`; `by: nobody|admin|author|writer` (default `author`); `keep_at_least:`/`keep_at_most:` a duration (relative, after replaced) and/or `abs <wall ms>`; `expires: <duration>`. Durations `250ms`, `10s`, `5m`, `12h`, `30d`. Trailing commas everywhere.
- Default literals: numbers, strings, `0x` bytes, `true`/`false`, case names with optional `(payload)`, `[..]` for lists and sets, `{k: v}` for maps and structs (fields by name or ID; omitted fields take their defaults). A tid default is its text form.
- Validation: names resolve with the right arity; IDs unique, never both declared and reserved; `succeeds` names an ID of the same struct/enum; wrappers (`counter`/`max`/`min` of int or float only, `text`, `markdown`) never inside set elements or map keys (also through named and parametric types); named types must reach a structure (`type a = a;` fails); defaults typed; core AKs (one segment) only in the core schema (ID 0); a relative `keep_at_most` needs `by: writer`.
- Schema value (spec/data-model.md §10): every field written, `none` included, docs included; the meta-schema is `core/schema/schemas/meta.osis` (local ID `ff..ff`, never written anywhere). Lock files hold the canonical bytes so the checker can compare; the codegen bin publishes them.
- `creation` is the one struct the type system cannot express (fields 0 and 1 exclusive): typed keys read `/created` through `CreationRecord` (`Codec::CHECKS_ITSELF`).

## Storage
Multiple backends (in-memory, sqlite, ...). Storage API kept simple; sync, conflict resolution and listeners live above it. Backends hold ciphertext only (notes/local-store.md).
