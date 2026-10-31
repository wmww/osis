# No way to find a schema by ID: foreign data reads as numbered fields
> Summary: the purpose is many apps, generic tools and agents sharing data "like a file format", and every delta names its (schema ID, revision), but the core distributes no schemas (owner decision) and the spec names no convention for where a schema with a given ID can be found. A generic tool or agent meeting an unknown schema ID sees a map with integer keys and nothing to resolve it with, which defeats the stated purpose for anyone but the app that minted the schema.
> Tags: schema, api, spec

Observed: spec/data-model.md §10 defines the schema value and says "The core never distributes schemas"; `/node.schemas` lists IDs and revisions a node has, not the schemas; spec/versioning.md §3 detects collisions by ID. File formats solve this with magic numbers plus a registry or embedded descriptors.

## Recommended fix (owner decision: it touches "the core distributes no schemas")
A convention over ordinary data, with one core aspect and no core mechanism:
1. Core aspect `/schema: blob` (the canonical bytes of a `schema` value, spec/data-model.md §10; a few KB), retention `author`, no bounds. A thing carrying it is a **schema thing**; `/name` may carry the schema's name.
2. **Rule for writers:** a node that writes under schema S into a group whose labels hold no schema thing for S (found by the group's `/schema` things: `schema.id` equals S) places one it owns into the group in the same or the next commit, with its newest revision. Readers of the label then hold every schema used under it; a generic tool reads any thing it can decrypt. Two writers placing concurrently give two equal things (dedup by content, harmless). An app that updates its schema re-places; the newest revision wins for typed reads of older data (additive rules make older data readable by it).
3. `/node.schemas` stays as is (what a node has), and the first-party schemas ship with the core as today.
Cost: a few KB per (schema, group) once, bounded by the schemas in use. This keeps the owner's decision that the core distributes nothing (the writer's app places data) while giving the file-format property the purpose section asks for. The `osis` crate should do step 2 in `commit()` for typed writes, so apps cannot forget it.


Round 13 (aspect key format decided, issues/aspect-key-format.md): no schema ID or revision travels on the wire any more; an app AK starts with a tid its maker owns, which may carry a note linking the schema's repository. A generic tool resolves an unknown app key through that tid by convention; first-party keys live in the osis repo. What is left here: the convention for that note (aspect, contents), done with the key-format sweep.
