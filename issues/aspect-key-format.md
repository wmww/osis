# Aspect key format: decide the grammar before stabilization
> Summary: AKs are slash-separated strings whose first segment is a namespace (spec/data-model.md §2); the owner wants a parsable string with a fixed grammar that carries, positionally and with reserved characters, the namespace, the name, a major version (a standard, so a node knows one aspect is a breaking-change successor of another without the schema), and an admin-only marker, with codegen the only writer of the string and app code seeing generated constants. Exact spelling (separators, reserved characters, whether slashes stay), the successor rule, and the refactor are a pre-stability owner discussion; incremental changes until then are fine.
> Tags: data-model, schema, api

Decided so far (owner, Oct 2026):
- The key stays a string on the wire (readable in diagnostics, no struct encoding rules); its structure is a grammar over the string, equivalent to a struct for every purpose that matters.
- Markers are positional with reserved characters, never substrings ("admin" appearing anywhere must not mean anything).
- Major version in the key is a standard, not a codegen convention: same namespace and name with a higher major = successor form (spec/versioning.md §4: a type change is a new AK); a node may use the relation without the schema (diagnostics, grouping; no conversion implied).
- Admin-only aspects: a marker in the key, judged by the validity path like membership-class aspects (notes/permissions.md); no schema dependence, no wire bytes.
- Schema source stays out of the key (it is the schema ID in the header's schema table: 128 random bits, spec/data-model.md §10).
- A namespace registry (a file in this repo claimed by PR) is cheap and optional; none exists yet (notes/data-model.md AK namespaces).

Open for the discussion: separators (slashes may change), the reserved characters for version and admin markers, whether the core schema's single-segment keys keep their form, how generated constants and the DSL spell the markers, and the migration of existing keys (pre-release: a regeneration of vectors and schemas).


## Decided (owner, round 13 decision session)
- **No machine mapping from AK to schema.** No schema ID or revision on the wire: the header's schema table and per-aspect schema index go. Schemas keep a version for people and tools, not attached to aspects. Disambiguation by convention only: first-party keys live in the osis repo; app keys start with a tid the app's maker owns (maybe a note on it linking the repo; nobody has to sync it).
- **An AK is a multi-segment path plus an aspect version**; no separate namespace, name, schema ID or schema version. A breaking change is a new aspect version; additive evolution within a version needs no marker (open structs, unknown cases read as absent).
- **Spelling**:
  - segments separated by `:`, the version after `.`, always written (`.0` included): `name.0`, `foo:bar.5`;
  - name segments: lowercase ASCII letters, digits, `_`, not starting with a digit (expandable later);
  - a tid-based AK starts with `:` then the 20-character tid segment: `:q3X9LmT0aB7cD2eF4gH:foo.1`;
  - markers after the version, in fixed order: `^` admin-only, then at most one lifetime: `~` ephemeral or `*` signal (`foo:bar.0^~`). One spelling per key.
- **Presence is not in the AK**: it becomes ephemeral plus expiry, refreshed by the author while present; possibly a write-level expiry kind "when the author is no longer connected" (owner: could be cool, maybe too complex). Evaluate in issues/eph-unify.md; signal stays a marker unless that evaluation shows it belongs on the write.
- Core keys drop the leading slash (`name.0`, `keys.0`); `members` becomes `roles` with issues/rename-roles-members.md.

Implementation: a format change everywhere AKs appear (spec, wire, DSL, codegen, schemas, vectors, tests, notes). Do it in the same sweep as issues/rename-roles-members.md and issues/one-node-kind.md (one churn), with a remnant-hunting review (owner completeness standard).
