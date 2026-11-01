# Aspect key format: decide the grammar before stabilization
> Summary: The AK grammar (spec/data-model.md §2): `:`-separated name segments, optional leading tid segment, `.N` aspect version, markers `^` admin-only and `~`/`*` lifetime; no schema ID on the wire. Built in sweep steps 5-7 (issues/one-node-kind.md): grammar and spelling, no schema mapping, markers carrying meaning (lifetime decides storage class; `^` needs admin). Nothing left but the optional namespace registry.
> Tags: data-model, schema, api

Decided so far (owner, Oct 2026):
- The key stays a string on the wire (readable in diagnostics, no struct encoding rules); its structure is a grammar over the string, equivalent to a struct for every purpose that matters.
- Markers are positional with reserved characters, never substrings ("admin" appearing anywhere must not mean anything).
- Major version in the key is a standard, not a codegen convention: same namespace and name with a higher major = successor form (spec/versioning.md §4: a type change is a new AK); a node may use the relation without the schema (diagnostics, grouping; no conversion implied).
- Admin-only aspects: a marker in the key, judged by the validity path like role-class aspects (spec/permissions.md §5.2); no schema dependence, no wire bytes.
- Schema source stays out of the key (superseded below: no schema ID at all).
- A namespace registry (a file in this repo claimed by PR) is cheap and optional; none exists yet (notes/data-model.md AK namespaces).

Open for the discussion: separators (slashes may change), the reserved characters for version and admin markers, whether the core schema's single-segment keys keep their form, how generated constants and the DSL spell the markers, and the migration of existing keys (pre-release: a regeneration of vectors and schemas).


## Decided (owner, round 13 decision session)
- **No machine mapping from AK to schema.** No schema ID or revision on the wire: the header's schema table and per-aspect schema index go. Schemas keep a version for people and tools, not attached to aspects. Disambiguation by convention only: first-party keys live in the osis repo; app keys start with a tid the app's maker owns (maybe a note on it linking the repo; nobody has to sync it).
- **An AK is a multi-segment path plus an aspect version**; no separate namespace, name, schema ID or schema version. A breaking change is a new aspect version; additive evolution within a version needs no marker (open structs, unknown cases read as absent).
- **Spelling**:
  - segments separated by `:`, the version after `.`, always written (`.0` included): `name.0`, `foo:bar.5`;
  - name segments: lowercase ASCII letters, digits, `_`, not starting with a digit (expandable later);
  - a tid-based AK starts with `:` then the 20-character tid segment: `:q3X9LmT0aB7cD2eF4gHJ:foo.1`;
  - markers after the version, in fixed order: `^` admin-only, then at most one lifetime: `~` ephemeral or `*` signal (`foo:bar.0^~`). One spelling per key.
- **Presence is not in the AK**: it becomes ephemeral plus expiry, refreshed by the author while present; possibly a write-level expiry kind "when the author is no longer connected" (owner: could be cool, maybe too complex). Done (presence-expiry, notes/ephemeral.md Values that live while their author is there: the write-level kind not built). Signal stays a marker unless that evaluation shows it belongs on the write.
- Core keys drop the leading slash (`name.0`, `keys.0`); `members` becomes `roles` with issues/rename-roles-members.md.

Dependent: issues/eph-unify.md (Left item 0) needs the lifetime marker so a receiver judges a part's storage class from the key alone.

Implementation: a format change everywhere AKs appear (spec, wire, DSL, codegen, schemas, vectors, tests, notes). Do it in the same sweep as issues/rename-roles-members.md and issues/one-node-kind.md (one churn), with a remnant-hunting review (owner completeness standard).

Sweep plan (steps, order, remnant hunts): issues/one-node-kind.md, Sweep plan.

Built (sweep step 5): the grammar (`osis_base::Ak`), the new spelling everywhere, `roles.0`; markers only parse and must match the schema's lifetime flags; untyped test keys carry them by convention. Built (step 6): no schema ID or revision on the wire; the engine keeps one local schema per app AK. Built (step 7): markers carry meaning: `~`/`*` are the lifetime of every key (the `ephemeral`/`signal` schema flags are gone) and decide storage class at every node from the key alone; `^` needs admin, judged by validity (spec/permissions.md §5.2).
