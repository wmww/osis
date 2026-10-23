# Aspect key format: decide the grammar before stabilization
> Summary: AKs are slash-separated strings whose first segment is a namespace (spec/data-model.md §2); the owner wants a parsable string with a fixed grammar that carries, positionally and with reserved characters, the namespace, the name, a major version (a standard, so a node knows one aspect is a breaking-change successor of another without the schema), and an admin-only marker, with codegen the only writer of the string and app code seeing generated constants. Exact spelling (separators, reserved characters, whether slashes stay), the successor rule, and the refactor are a pre-stability owner discussion; incremental changes until then are fine.
> Tags: data-model, schema, api, owner-call

Decided so far (owner, Oct 2026):
- The key stays a string on the wire (readable in diagnostics, no struct encoding rules); its structure is a grammar over the string, equivalent to a struct for every purpose that matters.
- Markers are positional with reserved characters, never substrings ("admin" appearing anywhere must not mean anything).
- Major version in the key is a standard, not a codegen convention: same namespace and name with a higher major = successor form (spec/versioning.md §4: a type change is a new AK); a node may use the relation without the schema (diagnostics, grouping; no conversion implied).
- Admin-only aspects: a marker in the key, judged by the validity path like membership-class aspects (notes/permissions.md); no schema dependence, no wire bytes.
- Schema source stays out of the key (it is the schema ID in the header's schema table: 128 random bits, spec/data-model.md §10).
- A namespace registry (a file in this repo claimed by PR) is cheap and optional; none exists yet (notes/data-model.md AK namespaces).

Open for the discussion: separators (slashes may change), the reserved characters for version and admin markers, whether the core schema's single-segment keys keep their form, how generated constants and the DSL spell the markers, and the migration of existing keys (pre-release: a regeneration of vectors and schemas).
