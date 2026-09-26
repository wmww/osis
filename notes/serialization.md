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
| struct | map with text keys, sorted like any map |
| set | tag 258 around an array sorted by canonical encoded bytes of elements |
| tid | tag TID around a 15-byte byte string |
| enum | tag ENUM around `[name]` (no payload) or `[name, payload]` |
| link | tag LINK around a 32-byte byte string (BLAKE3 hash of a canonical value) |

Tag numbers not yet chosen. Use the 3-byte range (256..65535) in an unassigned region, e.g. TID=4001, ENUM=4002, LINK=4003, and check the IANA CBOR tag registry before fixing them. 258 (set) is already registered for exactly this purpose.

Struct and `map<string, T>` share an encoding. Acceptable because `any` is an enum, so an untyped value is still explicitly tagged by its case name. Reserve a STRUCT tag number in case generic tools later need the distinction.

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
- Every node is an ordinary canonical value with its own hash, so sync compares subtrees and a node can store/relay data it has no schema for.
- Threshold for when a value gets chunked, and whether links are visible to the API or hidden below it, still undecided.

## Schema DSL (*.osis files)
Rust-like syntax, hand-written recursive-descent parser (no third-party parser libs, owner decision). Same parser serves runtime loading and the `load_schema!()` proc macro.

Sketch:
```
/// Notes app schema.
type priority = enum { low, medium, high, custom(int) };

type task = struct {
    title: string,
    done: bool,
    tags: set<string>,
    priority: option<priority>,
};

/// Markdown; not guaranteed valid.
aspect /note/body: markdown [indexed];
aspect /note/title: string [indexed];
aspect /note/tasks: list<task>;
```
Grammar notes:
- Items: `type NAME<PARAMS?> = TYPE;` and `aspect /a/k: TYPE [flag, flag];`. Trailing commas allowed.
- Type expressions: builtin names, `list<T>`, `map<K, V>`, `set<T>`, `enum { case, case(T) }`, `struct { field: T }`, named type with optional `<args>`.
- Comments: `//` ignored; `///` doc comments attach to the following item/field/case and are retained in the parsed schema so generic tools and agents can read invariants.
- Errors should carry file/line/column.

### Schema as data
The parsed schema is itself an osis value (struct of named types and aspects, docs included) using the same CBOR encoding. So a schema has a hash, can be stored and synced as a thing, and an AK could pin a schema version by hash. Candidate answer for AK versioning; not decided.

## Status
Decided by owner (2026-09-22): CBOR wire format, Rust-like DSL, no serde on the wire. Proposal only: tag numbers, float rule, strict decoding, link/chunking scheme, DSL grammar details.
