# Versioning: schema evolution, mixed app versions, format changes
> Summary: Decided 2026-10-14 with owner. The wire only grows: compact field/case IDs, open structs, reader-side defaults, additive-only schema checked at compile time. App-level type changes are views (f/g in app code) over the old representation; a real break is a new ID/AK plus `retire` (terminal reset) of the old one. Below the schema: merge is schema-free, unknown data is parked never dropped, one format version with "write the oldest that fits". No majors, mirroring, lenses or migration VM in the core.

## Problem
Many apps and app versions share data like a file format; apps do not always upgrade schemas, users do not always upgrade apps, nodes with different versions must sync, and the CRDT/sync layer itself must be able to evolve (rarely). Comparable in difficulty to CRDTs and blind sync.

## Three layers of compatibility
1. **Store/relay/merge** (must be universal): merge encodings are self-describing and join needs no schema, so any node joins any aspect state. Blob reconciliation is content-agnostic. A node that cannot interpret something is a blind node for it.
2. **Typing** (per app version): whether an app's schema can type a value. Failures are ordinary errors.
3. **Semantics** (human): invariants in doc comments. Not checkable.

## Below the schema (hard constraints, in notes/constraints.md)
- **Parking rule**: a node never discards, rejects or panics on data it cannot interpret (unknown merge encoding, format version, field ID, AK). It stores, relays, and re-examines after upgrade. "Not understood" is treated exactly like "not yet received": the node lags on that aspect, its own writes are ordinary concurrent writes, convergence covers the rest. Compaction never retires bodies it could not join; parked blobs accept blob-level snapshots/retires from newer nodes like a blind node does.
- **Compatibility surface** = blob contents only: commit header, delta encodings, chunk format, value CBOR. Local store layout, indexes, reconciliation protocol and API change freely (local state is rebuildable from blobs/snapshots).
- **One format version** on that surface. Readers accept every version up to their own forever. Writers emit the oldest version that can express the delta, so one upgraded node never strands a group unless it uses a new feature, and then only on that aspect.
- **Merge-encoding lattice**: the core defines an embedding for every upgrade edge (LWW register write = reset + insert-all in text CRDT; LWW int write = reset + increment in counter; ...). Join of mixed encodings converts the poorer side, so an aspect's stored encoding is the max seen. The schema's encoding is a minimum chosen by the first writer; downgrades are no-ops; value-level writes (structural diff) from an old app produce good deltas once the aspect is upgraded. Two encodings with no embedding: later write wins as a reset (lossy for concurrent edits, never broken).
- Crypto/key changes: per-label epochs; old nodes are blind for a new epoch until upgraded (notes/sync.md, not designed).

## Wire representation
- Struct field names and enum case names never go on the wire. Each has a small integer ID, explicit in the schema, never reused. Struct = CBOR map with int keys; enum = tag around `[id]` or `[id, payload]` (notes/serialization.md). Names live in the schema and app code, so a rename never touches data. Per-field overhead was otherwise a third or more of a field's register (timestamp + dot).
- AKs stay strings in the commit header (10-20 bytes against ~200 bytes commit overhead); a schema-relative index would make deltas unjoinable until the schema arrives.
- **Open structs**: writes are validated against the writer's schema (all its fields required at write time); stored state may carry field IDs no schema knows. Readers ignore unknown IDs. An app's structural-diff writes only touch fields its schema knows, so a diff never deletes what it cannot see.
- **Reader-side defaults**: a field may declare a default (`option<T>` defaults to none). Missing field + default = default on read, never materialized. A field without default cannot be added later and cannot stop being written (see retire).
- Unknown enum case, field type mismatch, missing required field: typed read of the aspect fails with an error carrying the path; the untyped `Value` API always works; path-based typed reads let an app skip one bad element in a large collection. No pre-declared fallback case, no `Unknown` variant (owner 2026-10-14: apps cannot do anything useful with a case they do not know; failures are the norm in osis).

## Schema identity and checking
- A schema file is the current wire schema only: types, aspects, IDs, docs, `reserved` IDs, `retired` items, `supersedes` links. No version history in the file.
- Identity of an AK's version = BLAKE3 of its type closure (referenced named types, flags, docs). Identical definitions in two apps are the same version by construction; no registry, no numbers.
- Compile-time checker (in `load_schema!()` and the runtime loader) compares against the last published hash and refuses anything that is not an additive superset: ID reuse, removed field without retire, default added to a formerly required field (strands old readers) unless explicitly marked, type change of an existing ID, encoding change not on an upgrade edge. Namespace collisions (two unrelated lineages with one AK name) are detected at read time, treated as untyped plus a diagnostic.
- Commit headers carry the writer's schema hash (encrypted, cheap). Lets a node keep per group the oldest schema version that has written recently, for adaptive compatibility (below) and diagnostics.
- **Schemas travel with data**: the parsed schema is an osis value; the first node to write with schema S into group G also writes S there as a thing (`/schema` aspect, deduplicated by hash). So a node that has a thing nearly always has its schema: numbered keys print with names, generic tools and agents read docs for unknown aspects, old nodes can tell the user which newer schema wrote what they cannot type. The DSL file is the authoring format; the value is the runtime form.

## Three kinds of change (owner's taxonomy)
1. **Additive**: new field with default, new case, new aspect, encoding upgrade. New IDs, nothing else. Free.
2. **App type change, representation additive + view**: the app's Rust type for the new version is a conversion over the wire type, f on read and g on write, in app code (codegen or hand-written; never in the schema, no VM). Old apps keep working on current data. g gets the current wire value as input (e.g. to preserve a units choice). Where the old representation cannot hold the new data, add a field with a new ID and declare `supersedes`; codegen then reads the new field unless the old one disagrees with g(new) (an old app wrote it since), in which case f(old) wins. Deterministic function of state, no timestamps, converges. Prefer extension over redundancy. Cost per edit is O(edit): conversion is per element on read, path ops on write.
3. **Breaking**: new ID or new AK, f for legacy data, no g; the old item is **retired**. Retire = terminal reset (reset with infinite timestamp): join drops every element under that ID past or future, from any writer, including the old node's own later writes once it has the marker. New apps write f(old) to the new representation and retire the old in the same commit, lazily on first touch or eagerly as a backfill over a group (O(group), explicit; deterministic f so concurrent backfills converge). Old apps then see the ordinary missing-aspect / missing-field error on migrated things and their concurrent edits to the old item lose regardless of timestamp. Nothing lingers: no ignored fields, no stale copies. Remains: one marker per thing per retired ID (a few bytes; cannot be compacted without making join depend on state outside the aspect), old values in historical bodies until normal compaction/purge, the reserved ID in the schema. Irreversible by construction (the ID itself is dead; undo cannot reinsert under it). Should look dangerous in the DSL.

2 decays into 3 by adding one `retired` line and deleting g. An aspect's wire type never changes (struct to float is not additive), so a change of the aspect's type is a new AK; `/name@2` is an allowed naming convention recorded with `supersedes`, with no core meaning.

Example (owner 2026-10-14): v1 `/measurement: struct { units: enum, value: float }`; v2 wants a float in meters. Stage 2: no wire change at all, the view converts on read and writes back (choose units: keep existing or always meters). Stage 3: add `/measurement@2: float`, retire `/measurement`, convert on touch or backfill; old apps see the aspect as absent.

What a break costs: that aspect, through old app versions, stops being usable. The old node still stores, relays and merges the new commits, every other aspect and every other app on that device keep working, and an upgrade needs no refetch. Nothing can do better: old code cannot know what new data means.

## "Everyone has upgraded" needs no global agreement
Retiring is an app-side decision about which old versions it still serves, baked into a release; the core needs no epoch and peers need not agree. A wiped device blocks nothing; a new device with old software hits errors on new things and should say "update required" (the error plus the schema thing in the group carry enough). Optional, opt-in per field: adaptive compatibility, where codegen keeps writing old fields in a group while any writer there used a schema needing them within a window (from header schema hashes) and stops otherwise, lazily backfilling if an old writer reappears. Default is simpler: a retained field is written until retired.

## Rejected (2026-10-14 discussion, keep for the record)
- Breaking change = always a new AK with dual writes: no lineage visible, ping-pong risk, forks by accident.
- Majors on the wire with core-managed bidirectional mirroring (f/g over aspect sets, derived-commit flag, deterministic derived IDs): duplicates every aspect under migration, O(aspect) per edit for whole-value f, needs caches, and a missing g made old nodes systematically overwrite newer edits. A path-level variant kept duplication small but needed a path language in the core and still could not express the interesting conversions.
- Declarative lens language (Cambria-style) in the schema, or any code/VM in the schema format.
- Pre-declared enum fallback case / generated `Unknown` variant.
- AK as index into the writer's schema; hashed AK names (no gain at typical lengths).

## Open details
- DSL syntax for IDs (explicit `1 title: string` style, with a tool that assigns next IDs), defaults, `reserved`, `retired`, `supersedes`.
- Where the "last published hash" lives for the checker (a line in the schema file, or a lock file).
- g's codegen contract (receives current wire value).
- Version-skew simulation as a standard test category: nodes on mixed schema versions and format versions, properties: wire convergence and stable per-reader projections.

## Prior art
Protobuf (IDs, reserved numbers, additive discipline), Avro (reader/writer schema resolution, defaults), Cambria (Ink & Switch; lenses over ops, rejected here), SQLite's file-format promise (read everything older forever).
