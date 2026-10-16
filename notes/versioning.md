# Versioning: schema evolution, mixed app versions, format changes
> Summary: Decided 2026-10-14 with owner. The core does five things: int IDs never reused, open structs with reader defaults, an additive checker against a lock file, the writer's schema revision in commit headers, and the parking rule plus encoding lattice below the schema. Everything else is a codegen convention over ordinary writes: a transition (old form, new form, read conversion f, write conversion g, `succeeds` link), a timestamp tie-break between forms, and a per-write policy for which form to write (oldest that fits unless the group has moved on). Blessed paths exist for cross-thing restructuring (model the new structure as a case, convert on edit), whole redesigns (import as ordinary writes, then drop f) and enums (cases never removed; a new case is a transition when old readers matter).

## Problem
Many apps and app versions share data like a file format. Apps do not always upgrade schemas, users do not always upgrade apps, nodes on different versions must sync, and the sync layer itself must evolve (rarely). Schema maintainers will make arbitrarily large breaking changes; the design must give every such change a path that is no harder than the cursed alternative.

## Terminology
- **Format version**: one integer on the blob surface (commit header, delta encodings, chunk format, value CBOR).
- **Schema revision**: integer plus publish date, bumped on every published change of a schema file.
- **Type hash**: BLAKE3 of an AK's type closure (named types, IDs, encodings; not docs or local flags). Identity of what a writer meant by the AK. Never called a version.
- App versions do not exist for the core.
- **Item**: anything with an ID in a schema: struct field, enum case, aspect.
- **Form**: the set of items that currently holds one piece of information.
- **Transition**: an old form, a new form, a read conversion f (old to new) and a write conversion g (new to old, may be exact, approximate or impossible). Declared by a `succeeds` link from the new items to the old; conversions live in app code.

## Three layers of compatibility
1. **Store, relay, merge** (universal): merge encodings are self-describing and join needs no schema, so any node joins any aspect state. Blob reconciliation is content-agnostic.
2. **Typing** (per app): whether an app's schema can type a value. Failures are ordinary errors.
3. **Semantics** (human): invariants in doc comments. Not checkable.

## What the core does
1. **Parking rule** (hard, notes/constraints.md): a node never discards, rejects or panics on data it cannot interpret (unknown format version, merge encoding, field ID, AK). It stores, relays, joins what it can and re-examines after upgrade. Not understood is treated like not yet received. Compaction never retires bodies the node could not join; parked blobs accept blob-level snapshots and retires from newer nodes like a blind node does.
2. **One format version** on the blob surface. Readers accept every older version forever. Writers emit the oldest version that can express the delta, so one upgraded node strands nobody unless it uses a new feature, and then only on that aspect. Header format is versioned separately from delta encodings (each delta names its encoding), so a node with an unknown encoding still reads the header and knows what it lags on. Local store layout, indexes, reconciliation protocol and API change freely.
3. **Merge-encoding lattice**: the core defines an embedding for every upgrade edge (LWW register write = reset + insert-all in text CRDT; LWW int = reset + increment in counter; ...). Join converts the poorer side, so an aspect's stored encoding is the max seen; the schema's encoding is a minimum. Two encodings with no embedding: later write wins as a reset. While a text aspect is in transition every save from an old LWW app wipes concurrent text edits; inherent, old code has no CRDT.
4. **Wire representation**: names never go on the wire. Each item has a small integer ID, explicit in the schema, never reused (struct = CBOR map with int keys, enum = tag around `[id]` or `[id, payload]`, notes/serialization.md). AKs stay strings in the header. **Open structs**: writes are validated against the writer's schema (all its fields required at write time); stored state may carry IDs no schema knows; readers ignore them; structural-diff writes touch only fields the writer knows; explicit replace resets the whole aspect. **Reader-side defaults**: a field may declare a default (`option<T>` defaults to none); missing field plus default reads as the default, never materialized. A field without default cannot be added later. Unknown enum case, type mismatch or missing required field fail the typed read with the path; the untyped `Value` API always works; path-based typed reads let an app skip one bad element of a collection. No `Unknown` variant.
5. **Schema identity and checker**. Each AK belongs to exactly one schema with one source of truth; only it extends the AK's type closure or allocates IDs under it. Another party needing more data adds aspects under its own schema. A schema file holds the current wire schema only (types, aspects, IDs, docs, `reserved` IDs, `succeeds` links, revision). The compile-time checker (in `load_schema!()` and the runtime loader) compares against a lock file holding the last published snapshot and refuses anything not an additive superset: ID reuse, removed item whose ID is not reserved, default added to a formerly required field unless marked, type change of an existing ID, encoding change off an upgrade edge, revision not bumped. Commit headers carry the writer's type hash and revision (encrypted). A revision above mine in my own schema's lineage is the "update required" signal. Per group, the node keeps the revisions seen in recent headers (input to the write policy). Namespace collisions and foreign schemas writing an AK are detected at read time as untyped plus a diagnostic. The parsed schema is an osis value; a maintainer may publish it as a thing; the core does not distribute schemas.

Crypto changes ride on algorithm enums (keys, signatures, sealed boxes), a suite byte in wraps and links, and a suite id per secret epoch; old nodes park what they cannot open until upgraded (notes/crypto.md, 2026-10-16).

## Transitions (codegen convention, not core)
The core never interprets a transition; merge is schema-free, so a maintainer who ignores the convention still converges, and the convention can change without touching stored data.

- **Additive change** (new field with default, new aspect, encoding upgrade): new IDs, nothing else, no transition.
- **Type change with the same representation**: f and g over the existing wire type, no schema change. Example: `/measurement: struct { units, value }` read as a float in meters, g chooses units on write.
- **Representation change**: when the old form cannot hold every new value, add items with new IDs and declare that the new form `succeeds` the old. Both forms stay in the schema and both stay writable. Forms are sets: one new set succeeds one old set, which covers splits and merges (full name into first and last, or the reverse).
- **Tie-break**: codegen reads the new form unless the old form carries a newer timestamp (an old app or a compatibility write wrote since), then f(old). Timestamp of a form = max over its leaf registers and resets. Ties (same commit) prefer new. A deterministic function of state, so it converges; timestamps are the system's one conflict rule already, so no round-trip law on f and g.
- **Removing an item** from the schema (dropping f) reserves its ID; data under it is parked, old apps still read and write it, nothing in the data changes. Only do this after an import (below).
- An aspect's wire type never changes; a change of type is a new AK. `/name@2` is a naming convention with no core meaning.
- Cost per edit is O(edit): conversion is per element on read, path ops on write.

## Which form is written: runtime policy per write
An app update must never by itself change what is stored; installing a revision with a transition only adds the ability to read and write the new form. For each write into a form with a transition, codegen chooses:
- **old only**, g(new): the default when g is exact, or when the app declares its approximation acceptable (float unit conversions). Old apps stay fully functional. The schema-level twin of "writers emit the oldest format version that fits".
- **new only**: when g is impossible for this value (the only case an app update can force, and only for values that use the new capability) or when policy says the group has moved on. Optionally reset the old form in the same commit so old apps see absence instead of a stale value; app's choice.
- **new plus lossy old**: when g has a useful approximation and old readers still matter.

Policy inputs, all local: whether g is exact; schema revisions seen in this group's headers within a window (move on once every recent writer is at or above the revision that introduced the transition); age of that revision; an explicit per-group or per-app compatibility setting. Headers show writers only, so a read-only old app is invisible to the header heuristic; the node capability aspect (revisions and forms each node reads, notes/ephemeral.md) makes it visible, paired with an age cutoff for dead nodes. The explicit setting overrides both. Thresholds are app or user policy; the core provides the per-group revision log and the write paths. Nothing needs global agreement: two nodes deciding differently produce a mix of forms that the tie-break reads correctly. A thing shared later into a group with old writers goes back to old-only on its next write there if g is exact.

What the new form costs where it is used: old apps see stale or missing data on that item, and their later edit to the old form wins through f at the granularity of the converted value, overwriting the new app's intervening edits. Every other aspect and app keeps working; an upgrade needs no refetch and no migration; every form stays readable and writable. Old code cannot know what new data means, so nothing can do better.

## Blessed paths for hard changes
Where maintainers would otherwise do something inconsistent.
- **Restructuring across things** (inline tasks become task things, cells become things): f cannot mint tids on read, and only members of the owner actor can create things the owner owns. Keep the information on the same thing and model the new structure as a case, e.g. a task gains `ref: option<tid>`; an element with a ref is a pointer and its inline fields are a stale copy that wins only by timestamp. Convert an element when a user edits or shares it, never in bulk. Bulk minting is only possible on owner nodes and duplicates under concurrency.
- **Whole redesign**: an import is fine: read every old form through f and write the new forms as ordinary writes, when policy says the group has moved on. Converges like any write (same deterministic value from any node). Drop f only after that; dropping f first is the "update made my data vanish" failure. The core has no migration concept; this is app code.
- **Enums**: a case can never be removed, since the value has no other case to fall back to; keep it and document it dead. A new case is a value g cannot express, so where old readers matter it goes into a succeeding item instead of the existing enum; old apps then see old cases perfectly and the new ones as stale or absent, instead of failing the typed read of every collection containing one. Where no old reader matters, add the case in place.
- **Semantic reuse** (same ID, new meaning, e.g. feet become meters): the one cursed path cheaper than the blessed one, uncatchable by the checker, same hole as protobuf. New ID, always.
- **A new required field**: not possible in place. Give it a default, or make a succeeding struct.

## Worked example
v1 notes app: `/note/tasks: list<task>`, `task { 1 title: string, 2 done: bool }`. v2 wants a status enum and shareable tasks.
- Status: add `3 status: option<status>` (default none). v2 reads status and falls back to done; g sets done from status, exact for todo and done, impossible for blocked. Blocked tasks are the only ones old apps see wrong.
- Tasks as things: add `4 ref: option<tid>`. Converted per task when a v2 user shares it. Old apps keep editing the inline copy, which wins when its timestamp is newer.
- Later v2 drops `done` from its view: reserve ID 2, old apps still write it, v2 ignores it.

## Rejected, keep from re-proposing
- Terminal reset / retire marker in the lattice (irreversible, per-thing markers forever, backfill or half-migrated groups; honoring old apps' later writes through f is better).
- Any conversion code or lens language in the schema format, or core-managed mirroring between forms (duplicates every aspect under migration, needs a path language in the core).
- Pre-declared enum fallback case or generated `Unknown` variant (apps cannot do anything useful with a case they do not know).
- Schema written into every group it is used in (needs an owner per writer and a membership write per group; two concurrent first writers mint two things).
- `succeeds` resolved by comparing old with g(new): needs g∘f exact, which float conversions break.
- Schema-relative AK indexes or hashed AK names (deltas unjoinable until the schema arrives; no gain at typical lengths).

## Open details
- DSL syntax for IDs (`1 title: string` style with a tool that assigns next IDs), defaults, `reserved`, `succeeds`, `revision` (number plus publish date).
- Codegen contract: g returns exact / approximate / impossible and receives the current wire value; the app's "approximation acceptable" declaration; the policy hook and default thresholds; the optional reset-old-on-new-only write; where the per-group revision log lives in the local store.
- Lock file format.
- Version-skew simulation as a standard test category: nodes on mixed schema revisions and format versions; properties: wire convergence and stable per-reader projections.

## Prior art
Protobuf (IDs, reserved numbers, additive discipline, one owner per message), Avro (reader/writer schema resolution, defaults), Cambria (Ink & Switch; lenses over ops, rejected here), SQLite's file-format promise (read everything older forever).
