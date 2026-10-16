# Serialization: CBOR wire format and schema DSL
> Summary: Canonical CBOR encoding of values (tags, ordering, floats, links for large atomic values) and the Rust-like schema DSL. Decided: CBOR, Rust-like DSL, no serde on the wire, integer item IDs, open structs, content-defined chunking. Float rule confirmed 2026-10-16. Proposal: tag numbers, chunking parameters, grammar details (encoding wrappers, `schema`/`revision`/`reserved`/`succeeds` syntax, review 2026-10-16).

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
| link | tag LINK around (keyed content hash of the whole canonical value, blob ID, suite byte plus 32-byte blob key); stands in for a large atomic value (below) |

Encoding wrappers (`counter<int>`, `text`, notes/data-model.md) change nothing here: the value on the wire is the inner type's; the merge encoding lives in the delta fragment (spec/crdt.md §3).

Tag numbers not yet chosen. Use the 3-byte range (256..65535) in an unassigned region, e.g. TID=4001, ENUM=4002, LINK=4003, and check the IANA CBOR tag registry before fixing them. 258 (set) is already registered for exactly this purpose.

Struct and `map<int, T>` share an encoding. Where the schema is known the type decides; merge state tells them apart anyway (fragment encodings 4 and 7); the one place a value is genuinely untyped on the wire, the `any` type, is an enum whose case names the kind (notes/data-model.md). Reserve a STRUCT tag number in case generic tools later need the distinction in plain values. Names never go on the wire (decided 2026-10-14): a value without its schema prints with numbered keys; the core does not distribute schemas (notes/versioning.md).

### Canonical rules
- RFC 8949 4.2.1 core deterministic requirements: shortest integer/length heads, no indefinite-length items, sorted map keys, no duplicate keys. One deliberate deviation, of the kind 4.2.2 allows a protocol to make: floats are always 8 bytes rather than the shortest form that preserves the value, so a float's bytes are its bit pattern.
- Do NOT use the dCBOR profile: its numeric reduction encodes 1.0 as 1, which erases the int/float distinction.
- No CBOR `null`/`undefined`, no simple values other than true/false; absence is expressed by `option<T>`.
- **Extension point**: a new osis type is a new tag. Unknown tags are not errors: the `Value` model keeps an unknown tag with its content as raw canonical bytes, so parked data round-trips (notes/versioning.md), merges as an opaque register value and fails only the typed read. Anything else outside this profile is non-canonical and rejected; adding a major-type-level construct would need a format version bump, which is why types are added as tags instead.
- Decoder is strict: any non-canonical input is an error. So bytes on the wire are the canonical bytes and are hashed and stored as received, never re-encoded. Important for multi-GB blobs.
- Floats: value identity is the IEEE bit pattern. NaN is normalized to a single canonical pattern (positive quiet NaN, zero payload) when a value is constructed; the decoder rejects any other NaN. -0.0 and 0.0 are distinct values. (Confirmed by owner 2026-10-16.) Where merge has to order or sum floats (`max`, `min`, `counter`) it uses IEEE totalOrder and dot-order summation (spec/crdt.md §5.2), so reads are bit-identical on every node.
- Content hashes are keyed BLAKE3 over canonical bytes (notes/data-model.md, Hashing).

### Serde
Not used on the wire. Own the encoder/decoder for `Value` (a few hundred lines for this subset): generic serde CBOR backends don't sort keys, don't enforce shortest heads or 8-byte floats, and can't reject non-canonical input; serde's data model has no sets, tags or tids. A serde `Serializer`/`Deserializer` converting app types to/from `Value` is a separate, optional convenience layer.

### Large values (links)
Two mechanisms, one chunker (review 2026-10-16 untangled them):
- **Large composites** (maps, sets, lists, text) are merge fragments; their state pages at content-defined boundaries over element records sorted by dot, so equal content gives equal pages (spec/crdt.md §8). Nothing at the value level.
- **Large atomic values** (a blob, a string in register encoding, a large set element or map key) are split with content-defined chunking (decided 2026-10-11; e.g. FastCDC, parameters shared with §8 once fixed) into a tree of chunks; interior nodes are lists of links; the value's place in the enclosing CBOR holds the root link. Chunking is mandatory above a size threshold and forbidden below it (a constant of format version 1, value open: a few hundred KB), so the shape is a function of the content.
- Every chunk and tree node is an ordinary canonical value with its own keyed content hash and travels as a separate encrypted blob under a random key carried in its parent link; an editor reuses unchanged chunks from the current tree by content hash (notes/local-store.md), so a large body is fetched and deduped piecewise. The commit header lists the chunk blobs a delta introduced, with a delete token hash each (notes/sync.md).
- Random chunk keys are required by the no-fingerprint rule (a key derived from content would make the retained blob ID a fingerprint of purged content), so two independent writes of one large value produce different link bytes. **Equality of a large value is its keyed content hash**, never its bytes; the diff, set dedup and map key lookup compare that (constraints tension 19).
- Maximum blob size is a constant of format version 1 (chunk and commit blobs alike), so a receiver never allocates on a peer's claim; value open (a few MB).
- Whole-value access is always allowed, streaming/partial access also available; whether that exposes links or a separate abstraction is an implementation question (notes/api.md).

## Schema DSL (*.osis files)
Rust-like syntax, hand-written recursive-descent parser (no third-party parser libs, owner decision). Same parser serves runtime loading and the `load_schema!()` proc macro.

Sketch (syntax proposal; IDs, defaults and the evolution items are the open details of notes/versioning.md):
```
//! Notes app schema.
schema 0x7f3a9c21e0d84b6a9b1c5e2d4f607a83;   // random, minted once, never changes
revision 4 (2026-10-16);                      // bumped on every publish

type priority = enum { 0 low, 1 medium, 2 high, 3 custom(int) };

type task = struct {
    1 title: string,
    2 done: bool,
    3 tags: set<string>,
    4 priority: option<priority>,     // option defaults to none
    6 due: option<timestamp>,         // added in revision 3
    7 status: option<status> succeeds 2,   // new form for `done`; f and g live in app code
    reserved 5,
};

/// Markdown; not guaranteed valid.
aspect /note/body: markdown [indexed, preserve];
aspect /note/title: string [indexed];
aspect /note/tasks: list<task>;
aspect /note/views: counter<int>;
aspect /note/last_opened: timestamp [expires: 30d];
```
Grammar notes:
- Items: `schema ID;`, `revision N (date);`, `type NAME<PARAMS?> = TYPE;` and `aspect /a/k: TYPE [flag, flag];`. Trailing commas allowed. Fields and cases carry explicit integer IDs; `reserved` lists IDs that may never be used again; `succeeds` names the old item(s) a new item replaces (a set on either side when forms span several items).
- Type expressions: builtin names, `list<T>`, `map<K, V>`, `set<T>`, encoding wrappers `counter<T>`, `max<T>`, `min<T>`, `text`, `enum { case, case(T) }`, `struct { field: T }`, named type with optional `<args>`. A field default is a constant: `= value` after the type (option fields default to `none` implicitly).
- Comments: `//` ignored; `///` doc comments attach to the following item/field/case and are retained in the parsed schema so generic tools and agents can read invariants.
- Errors carry file/line/column.

### Schema as data
The parsed schema is itself an osis value (struct of schema ID, revision, named types and aspects, docs included) using the same CBOR encoding. The writer's (schema ID, revision) goes in the commit header's schema table; the core does not distribute schemas, a maintainer may publish one as a thing (notes/versioning.md).
