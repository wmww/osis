# Aspect/schema versioning and compatibility
> Summary: How AKs and schemas evolve: versioning, compat between app versions, changing an aspect's type or merge encoding (breaking). Candidate: schema as data pinned by hash. Undecided.
> Tags: data-model, serialization, crdt

Context: notes/data-model.md (aspect map, schema files), notes/serialization.md (schema as data), notes/crdt-sync.md (merge per type).

Questions:
- Identity of an aspect over time: is an AK versioned by name (`/note/body/v2`), by a schema hash pinned to the AK, or by compatible evolution rules?
- Which changes are compatible: adding an enum case, adding an optional struct field, widening a type? All struct fields are currently required, which makes most additions breaking.
- Merge encoding is chosen by the schema and enforced at write time; changing it (LWW string to text CRDT, add-wins to remove-wins) is breaking. How does a type change migrate existing state and old commits?
- Multiple apps and app versions share data like a file format. A node with an older schema must still sync, store and relay values it cannot type-check. Decide what it may do with them (store opaque, show in generic tools, refuse writes).
- Schema as data: parsed schema is an osis value with a hash and could be a synced thing. Does an AK pin a schema version by hash, and how do generic tools and agents discover schemas for unknown AKs?
- Doc comments carrying invariants are retained in the parsed schema; versioning should keep them attached.
