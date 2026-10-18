# Data model and serialization: rationale
> Summary: Why spec/data-model.md looks the way it does (tids, CBOR profile, large values, AK namespaces, groups), the schema DSL sketch (proposal), storage layering, rejected options. Mostly owner decisions; shapes of `any`, the core aspects' types and the DSL syntax are proposals.

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
- `any` exists because struct and `map<int, T>` share an encoding; merge state tells them apart anyway, so `any` matters only for values held atomically. Open alternative: `any` as the raw value with int-keyed maps reading as `map<int, any>` (no case table, a few bytes less per node; a struct held in an `any` slot reads back as a map).
- Set elements and map keys are atomic: choose `map<K, struct>` over `set<struct>` when parts of an element should be editable.

## Large values
- Two mechanisms, one chunker: large composites page their merge state (spec/crdt.md §8); large atomic values chunk into link trees (spec/data-model.md §6).
- Random chunk keys are required by the no-fingerprint rule (a content-derived key makes a retained blob ID a fingerprint), so equality of large values is by keyed content hash (tension 19). Dedup is by reuse from the current tree (notes/local-store.md).
- Whole-value access is always allowed, streaming also; whether the API exposes links or a separate abstraction is an implementation question.

## AK namespaces
No registry exists, so namespace collisions between schemas are detected (schema ID in headers), never prevented; until detected their writes merge like concurrent writes (tension 20). Pick namespaces unlikely to collide (app or org name).

## Groups
Example: spreadsheet thing = group of two axis things, each a group of row/column things, each a group of cells (each cell in two groups). Nothing is in a group by being owned (owner): apps place things explicitly (tension 16).

## Schema DSL (`*.osis` files; syntax proposal)
Rust-like syntax, hand-written recursive-descent parser (no parser libraries, owner decision). The same parser serves runtime loading and the `load_schema!()` proc macro. `///` doc comments attach to the next item and are kept in the parsed schema so generic tools and agents can read invariants. Errors carry file, line, column.
```
//! Notes app schema.
schema 0x7f3a9c21e0d84b6a9b1c5e2d4f607a83;   // random, minted once, never changes
revision 4;                                   // bumped on every publish

type priority = enum { 0 low, 1 medium, 2 high, 3 custom(int) };

type task = struct {
    1 title: string,
    2 done: bool,
    3 tags: set<string>,
    4 priority: option<priority>,     // option defaults to none
    6 due: option<timestamp>,
    7 status: option<status> succeeds 2,   // new form for `done`; f and g live in app code
    reserved 5,
};

/// Markdown; not guaranteed valid.
aspect /note/body: markdown [indexed, keep_at_least: forever];
aspect /note/title: string [indexed];
aspect /note/tasks: list<task>;
aspect /note/views: counter<int>;
aspect /note/last_opened: timestamp [expires: 30d];
```
- Items: `schema ID;`, `revision N;`, `type NAME<PARAMS?> = TYPE;`, `aspect /a/k: TYPE [flags];`, `signal` kinds (syntax TBD). Trailing commas allowed. `reserved` lists IDs never to be used again; `succeeds` names the old item(s) a new item replaces (sets on either side for splits and merges). A field default is `= value` after the type.
- Open details: notes/versioning.md.

## Storage
Multiple backends (in-memory, sqlite, ...). Storage API kept simple; sync, conflict resolution and listeners live above it. Backends hold ciphertext only (notes/local-store.md).
