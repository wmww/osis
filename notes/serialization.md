# Serialization: CBOR wire format and schema DSL
> Summary: Design details for the canonical CBOR encoding of values (tags, ordering, floats, links for large values) and the Rust-like schema DSL; decided: CBOR + Rust-like DSL; the rest is proposal.

## Wire format: osis CBOR profile
CBOR (RFC 8949) restricted to a strict subset. Rationale: IETF standard, deterministic-encoding profile exists, tags cover the types osis adds, diagnostic notation lets generic tools print any value without a schema. DAG-CBOR (IPLD) is the closest prior art but only allows string map keys, so we don't use it directly.

### Type mapping
| osis | CBOR |
|---|---|
| string | text string (major 3) |
| blob | byte string (major 2) |
| bool | simple 20/21 |
| int | major 0/1; decoder rejects values outside i64 |
| float | always 8-byte float (0xfb), never 16/32-bit |
| list | array (major 4) |
| map | map (major 5); any key type; keys sorted by their canonical encoded bytes (bytewise lexicographic, RFC 8949 4.2.1) |
| struct | map with int keys (field IDs from the schema), sorted like any map; unknown IDs preserved |
| set | tag 258 around an array sorted by canonical encoded bytes of elements |
| tid | tag TID around a 15-byte byte string |
| enum | tag ENUM around `[id]` (no payload) or `[id, payload]`; case ID from the schema |
| link | tag LINK around (keyed BLAKE3 hash of the canonical value, blob ID, 32-byte blob key) |

Tag numbers not yet chosen. Use the 3-byte range (256..65535) in an unassigned region, e.g. TID=4001, ENUM=4002, LINK=4003, and check the IANA CBOR tag registry before fixing them. 258 (set) is already registered for exactly this purpose.

Struct and `map<int, T>` share an encoding. Acceptable because `any` is an enum, so an untyped value is still explicitly tagged by its case. Reserve a STRUCT tag number in case generic tools later need the distinction. Names never go on the wire (decided 2026-10-14, notes/versioning.md): a value without its schema prints with numbered keys; the core does not distribute schemas (notes/versioning.md).

### Canonical rules
- RFC 8949 4.2.1 core deterministic requirements: shortest integer/length heads, no indefinite-length items, sorted map keys, no duplicate keys.
- Do NOT use the dCBOR profile: its numeric reduction encodes 1.0 as 1, which erases the int/float distinction.
- No CBOR `null`/`undefined`; absence is expressed by `option<T>`.
- Decoder is strict: any non-canonical input is an error. Consequence: bytes on the wire are the canonical bytes, so they are hashed and stored as received, never re-encoded. Important for multi-GB blobs.
- Floats: value identity is the IEEE bit pattern. NaN is normalized to a single canonical pattern (positive quiet NaN, zero payload) when a value is constructed; the decoder rejects any other NaN. -0.0 and 0.0 are distinct values. (Not confirmed by owner.)
- Hash of a value = BLAKE3 of its canonical bytes. Thing hash = hash over the canonical encoding of the map AK -> value hash, synthetic aspects excluded (details TBD with sync/CRDT work).

### Serde
Decision: serde is not used on the wire. Own the encoder/decoder for `Value` (a few hundred lines for this subset). Reasons: generic serde CBOR backends don't sort keys, don't enforce shortest heads or 8-byte floats, and can't reject non-canonical input; serde's data model has no sets, tags or tids. A serde `Serializer`/`Deserializer` that converts app types to/from `Value` is a separate, optional convenience layer.

### Large values (links)
The LINK tag is the proposed mechanism for large values (notes/data-model.md):
- A large blob is split with content-defined chunking (e.g. FastCDC) into a tree of chunks; interior nodes are lists of links.
- A large map/set becomes a prolly tree (Noms/Dolt style): deterministic boundaries from hashing keys, so equal contents give equal trees regardless of edit history.
- Every node is an ordinary canonical value with its own hash. Chunks and tree nodes travel as separate encrypted blobs, each under a random key carried in its parent link; an editor reuses unchanged chunks from the current tree by content hash (notes/local-store.md), so a large body is fetched and deduped piecewise. Content-defined chunking is decided (2026-10-11); boundaries and sizes (FastCDC parameters) are not.
- Threshold for when a value gets chunked is undecided. API direction (owner 2026-10-12): whole-value access always allowed, streaming/partial access also available; whether that exposes links or a separate abstraction is an implementation question (notes/api.md).

## Schema DSL (*.osis files)
Rust-like syntax, hand-written recursive-descent parser (no third-party parser libs, owner decision). Same parser serves runtime loading and the `load_schema!()` proc macro.

Sketch:
```
/// Notes app schema.
type priority = enum { low, medium, high, custom(int) };

type task = struct {
    1 title: string,
    2 done: bool,
    3 tags: set<string>,
    4 priority: option<priority>,   // option defaults to none
    6 due: option<timestamp>,       // added later; reserved 5;
};

/// Markdown; not guaranteed valid.
aspect /note/body: markdown [indexed];
aspect /note/title: string [indexed];
aspect /note/tasks: list<task>;
```
Grammar notes:
- Items: `type NAME<PARAMS?> = TYPE;` and `aspect /a/k: TYPE [flag, flag];`. Trailing commas allowed. Fields and cases carry explicit integer IDs (syntax above is a sketch); `reserved`, `succeeds` and `revision` items record evolution (notes/versioning.md, syntax open).
- Type expressions: builtin names, `list<T>`, `map<K, V>`, `set<T>`, `enum { case, case(T) }`, `struct { field: T }`, named type with optional `<args>`.
- Comments: `//` ignored; `///` doc comments attach to the following item/field/case and are retained in the parsed schema so generic tools and agents can read invariants.
- Errors should carry file/line/column.

### Schema as data
The parsed schema is itself an osis value (struct of named types and aspects, docs included) using the same CBOR encoding. Decided 2026-10-14: an AK's version is the hash of its type closure; the writer's schema hash and revision go in the commit header; the core does not distribute schemas (a maintainer may publish one as a thing). Details in notes/versioning.md.

## Status
Decided by owner (2026-09-22): CBOR wire format, Rust-like DSL, no serde on the wire. Decided 2026-10-14: integer field/case IDs on the wire, open structs, schema as synced data (notes/versioning.md). Proposal only: tag numbers, float rule, strict decoding, link/chunking scheme, DSL grammar details.
