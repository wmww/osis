# Versioning: conventions and rationale
> Summary: The problem, why the core rules of spec/versioning.md suffice, and the codegen conventions above them (decided with owner): transitions with read/write conversions and `succeeds` links, the timestamp tie-break between forms, the per-write policy for which form to write, blessed paths for hard changes, a worked example, rejected options, what osis-schema implements and what is open.

Pre-release (CLAUDE.md, spec/overview.md): none of this constrains today's formats; they change in place with no readers for earlier builds' data.

## Problem
Many apps and app versions share data like a file format. Apps do not always upgrade schemas, users do not always upgrade apps, nodes on different versions must sync, and the sync layer itself must evolve (rarely). Schema maintainers will make arbitrarily large breaking changes; every such change needs a path no harder than the cursed alternative.

Three layers of compatibility: store/relay/merge (universal: merge is schema-free), typing (per app, ordinary errors), semantics (doc comments, uncheckable). App versions do not exist for the core.

## Core vs convention
The core does five things (spec/versioning.md): IDs never reused, open structs with reader defaults, an additive checker, the writer's (schema ID, revision) in headers, and the parking rule plus encoding lattice. Everything below is a codegen convention over ordinary writes: the core never interprets it, merge converges whatever maintainers do, and the convention can change without touching stored data.
- Writers emitting the oldest format version that fits means one upgraded node strands nobody unless it uses a new feature, and then only on that aspect.
- The header's (schema ID, revision) answers the one question it must: "my schema's future revision" vs "a foreign schema on my AK". A per-delta type hash (32 bytes per delta) cannot tell those apart.
- Defaults are never materialized and immutable: changing one would read old data differently per revision; materializing them would make a default-valued field distinguishable from an unwritten one.
- Without the schema-aware diff an old app's save of a `set<struct>` would remove every element a newer app had extended and add a stripped copy, and a list with one unreadable element would be rewritten around it.

## Terminology
- **Item**: anything with an ID in a schema (field, case, aspect). **Form**: the set of items holding one piece of information.
- **Transition**: old form, new form, read conversion f (old to new), write conversion g (new to old: exact, approximate or impossible), declared by `succeeds` from the new items to the old. Conversions live in app code.

## Transitions
- **Additive change** (new field with default, new aspect, encoding upgrade): new IDs, no transition.
- **Type change with the same representation**: f and g over the existing wire type, no schema change (e.g. `struct { units, value }` read as a float in meters).
- **Representation change**: add items with new IDs; the new form `succeeds` the old. Both forms stay writable. Forms are sets, covering splits and merges.
- **Tie-break**: read the new form unless the old carries a newer timestamp (an old app wrote since), then f(old). Timestamp of a form = greatest commit `ts` over its leaf registers and resets; equal `ts` prefers new. Deterministic, so it converges, with no round-trip law on f and g. A new form equal to its default has no timestamp and reads as "use the old form": give defaults no other meaning.
- **Removing an item** (dropping f) reserves its ID; data under it is parked, old apps still use it. New records then lack the item, so do this only after an import, when old readers no longer matter.
- A change of type is a new AK; `/name@2` is only a naming convention.
- Cost per edit is O(edit): conversion is per element on read, path ops on write.

## Which form is written
An app update must never by itself change what is stored. Per write into a form with a transition, codegen chooses:
- **old only**, g(new): the default when g is exact or its approximation is declared acceptable. Old apps stay fully functional.
- **new only**: when g is impossible for this value, or policy says the group has moved on. Optionally reset the old form in the same commit.
- **new plus lossy old**: when g approximates usefully and old readers still matter.
Policy inputs, all local: whether g is exact; (schema ID, revision) pairs in this group's recent headers (move on once every recent writer is at or above the transition's revision); the revision's age; `/node.schemas` (makes read-only old apps visible; pair with an age cutoff for dead nodes, notes/ephemeral.md); an explicit per-group or per-app setting, which overrides. Two nodes deciding differently produce a mix the tie-break reads correctly. A thing shared later into a group with old writers goes back to old-only if g is exact.

Cost where the new form is used: old apps see stale or missing data on that item, and their later edit wins through f at the granularity of the converted value. Nothing can do better: old code cannot know what new data means.

## Blessed paths for hard changes
- **Restructuring across things** (inline tasks become task things): f cannot mint tids on read, and only owner-actor members can create the owner's things. Model the new structure as a case (a task gains `ref: option<tid>`; with a ref its inline fields are a stale copy that wins only by timestamp). Convert an element when a user edits or shares it, never in bulk.
- **Whole redesign**: an import (read old forms through f, write new forms) once policy says the group moved on; drop f only after that, or data "vanishes" on update.
- **Enums**: cases are never removed; document dead ones. A new case is a value g cannot express, so where old readers matter it goes into a succeeding item; otherwise add it in place.
- **Semantic reuse** (same ID, new meaning): the one cursed path cheaper than the blessed one and uncatchable by the checker. New ID, always.
- **A new required field**: give it a default, or make a succeeding struct.
- **Set elements and map keys** are atomic: an old app cannot edit new fields of one. Model editable records as `map<K, struct>` or `list<struct>`.

## Worked example
v1 notes app: `/note/tasks: list<task>`, `task { 1 title: string, 2 done: bool }`. v2 wants a status enum and shareable tasks.
- Status: add `3 status: option<status>`. v2 reads status, falls back to done; g sets done from status, exact for todo and done, impossible for blocked. Blocked tasks are the only ones old apps see wrong.
- Tasks as things: add `4 ref: option<tid>`, converted per task when shared. Old apps edit the inline copy, which wins when newer.
- Later v2 drops `done`: reserve ID 2; v1 fails to type tasks created after that, so only once v1 readers no longer matter.

## Version numbers on the wire
Format version 1 is the header's first field; the blob prefix has its own framing version byte so a blind node can tell a framing it cannot parse (it then keeps the blob without expiry or commitments); the node-to-node protocol negotiates its version in Hello, independent of both. Links, cards and bundles carry a format number of their own.

## Rejected
- Terminal reset / retire marker in the lattice (irreversible, per-thing markers forever, half-migrated groups).
- Conversion code or a lens language in the schema format; core-managed mirroring between forms (duplicates aspects, needs a path language in the core). Cambria-style lenses over ops.
- Pre-declared enum fallback case or generated `Unknown` variant (apps cannot do anything useful with an unknown case).
- Schema written into every group it is used in (needs an owner per writer; concurrent first writers mint two things).
- `succeeds` resolved by comparing old with g(new): needs g∘f exact, which float conversions break.
- Schema-relative AK indexes or hashed AK names (deltas unjoinable until the schema arrives).
- Per-delta type hash in the header (above).

## Implemented (osis-schema) vs open
- Implemented: DSL syntax (notes/data-model.md); the additive checker, one named `Rule` per spec/versioning.md §4 item, types compared structurally after expanding named types (renames are free, recursion coinductive); a `DefaultAdded` passes only for locations the caller lists (the "explicitly marked" escape; the schema value has no marker bit). Lock file `<file>.osis.lock`: header, BLAKE3 of the canonical form, canonical bytes in hex (`provisional`). "Publishing" = `osis-schema-gen --publish`, which refuses a revision that breaks the rules. Transition helpers (tie-break, write policy) are not built: no code reads `succeeds` yet; the links are data in the schema value.
- Open: whether a build whose file differs from its lock may write (proposal: writes untyped); the per-group revision log and the read API returning the greatest commit `ts` under a path (node/api); the optional reset-old-on-new-only write; version-skew simulation (sim).

## Prior art
Protobuf (IDs, reserved numbers, additive discipline, unknown-field preservation), Avro (reader/writer schema resolution, defaults), Cambria (Ink & Switch), SQLite's file-format promise.
