# Schema crate: types, DSL, checker, typed views, core schema, codegen
> Summary: Implement `osis-schema`: the type system of spec/data-model.md §3, the `*.osis` DSL (hand-written parser), schema identity and the additive evolution checker (spec/versioning.md), typed reads with path errors and reader defaults, the `View` for the diff, encoding selection per type, retention and expiry defaults per aspect, the core schema with the exact core-aspect types, and a code generator for app types.
> Tags: data-model, versioning, tests

Crate: `osis-schema`. Depends on: osis-core, osis-crdt (the `View` trait and encoding IDs). Unblocks: commit (retention defaults, schema table), node-core (typed writes), api, apps.
Spec: spec/data-model.md §2–§5, §9–§10; spec/versioning.md (all); spec/crdt.md §3.1, §9; spec/commits.md §5–§6 (retention, expiry fields). Notes: notes/data-model.md (DSL sketch), notes/versioning.md (transitions, `succeeds`, policy; which parts are codegen conventions). Spec trumps this plan.

## Deliverables
- Type model: scalars, enum/struct with explicit IDs and defaults, list/map/set, encoding wrappers (counter/max/min/text), named parametric and recursive types, standard named types (`option`, `markdown`, `timestamp`, `duration`, `any`); mapping type → merge encoding (spec/crdt.md §3.1; `any` takes the value kind's encoding); the rule that wrappers are not allowed as set elements or map keys.
- DSL parser (`schema`, `revision`, `type`, `aspect` with flags and retention/expiry defaults, `signal`, `reserved`, `succeeds`, doc comments, trailing commas; file/line/column errors). Recursive descent, no parser libraries.
- Schema as an osis value (canonical form per plans/protocol-spec.md item 5; provisional until then) with `SchemaId` and revision; a lock file (`<name>.osis.lock`: the last published revision's canonical value hash) and the **additive checker** between a file and its lock: every rule of spec/versioning.md §4 as a named check with a test that violates it.
- Typed views: `typed_read(value, type) -> Result<Typed, PathError>` per path, reader defaults, open structs (unknown IDs ignored), unknown enum case / type mismatch / missing required field errors with the path; untyped access always works.
- `View` implementation for the structural diff: projects reads onto the writer's schema, reports opaque elements, declared defaults.
- Write validation: every declared field required at write time; wrappers enforce no-wrapper-in-atomic positions; `CHUNK_THRESHOLD` classification of large atomic values (which positions must be links; plans/large-values.md does the chunking).
- Core schema: the core aspects of spec/data-model.md §9 with the exact composite types plans/protocol-spec.md item 6 fixes (`/created`, `/members`, `/keys`, `/secrets`, `/tenures`, `/label`, `/moved`, `/was`, `/node`, `/reach`, `/seen`, `/group`), the membership-class set, synthetic/guaranteed flags, the core schema ID, fixed retention for membership-class aspects; Rust structs with to/from `Value` for every core aspect (hand-written here; the other crates use them).
- `AspectKey` trait (type, AK, schema ID and revision, codec, retention and expiry defaults; notes/api.md Keys), `Aspect<T>` and `Signal<T>` constants, `Ak` as the untyped key with `T = Value`, `Path`/`Step` and the `p!` macro, field and case constants; re-exported by `osis`.
- Codegen: a library + `osis-schema-gen` bin that emits, from a `.osis` file, Rust types with `From`/`TryFrom<Value>`, one `Aspect<T>`/`Signal<T>` constant per declared aspect and signal kind, field/case constants for paths (typed path builders optional), usable from `build.rs`; the `list<struct>` warning (notes/api.md). A proc macro is optional and only if cheap (compile time); otherwise skip and note it.
- Transition conventions of notes/versioning.md (`succeeds`, tie-break by form timestamp, write-form policy) as codegen conventions: implement the data (links) and the tie-break read helper; the policy hook is a function pointer with the default rule; keep it small.

## Steps
- [x] Type model, encoding mapping, DSL parser with error tests, example schemas (notes app from notes/data-model.md; the core schema file).
- [x] Schema value form, lock file, additive checker (each §4 rule tested both ways).
- [ ] Typed reads, defaults, View, write validation; property: `typed_read(encode(typed)) == typed`.
- [ ] Core schema types and Rust structs; vectors for their canonical encodings once protocol-spec fixes them.
- [ ] Codegen bin + a generated example compiled in tests (build.rs in examples later).

## Tests
Parser fuzz target (test-infra); checker rules; typed-read errors carry paths; open-struct preservation through a write (unknown field survives `set_field`); version-skew unit tests (old schema reads data written by a newer revision; new reads old).

## Done when
The core schema and an app schema parse, check and generate; node-core consumes retention defaults and typed writes from here; notes/data-model.md and notes/versioning.md updated with what is implemented vs convention. Delete this plan.

## Progress
