# App-facing crates cleanup left over
> Summary: Simplifications of osis, osis-schema and osis-cli not done in the app-simplify pass: engine types and test hooks on the app API, an ambiguous `Ak` method pair, four hand-written `Type` traversals, small API warts.
> Tags: osis, schema, cli

No failing test; behaviour-preserving unless noted.

- **Engine on the app surface**: `osis` re-exports `osis_node::{Cause, Diagnostic, DiagnosticKind}` and (hidden) `osis_node` itself; hidden hooks `Osis::engine`, `sync_engine`, `take_actions`, `feed(SyncEvent)`, `waiting`, `Runtime::Manual`/`ManualNet` exist for the CLI's `inspect`, the sim and tests. A feature gate is ruled out (notes/build.md Feature unification); an `osis::testing` module or an extension trait would at least keep them off `Osis`'s own docs.
- **`Ak` is both `AspectKey` and `SignalKey`**: `ak.decode(..)` / `ak.encode(..)` are ambiguous wherever both traits are imported (`use osis::*`); call sites write `AspectKey::decode(&ak, ..)`.
- **`Type` traversals**: `Type::subst`, codegen `params_in` and `recursive_types::refs`, schema `named_refs` each walk children by hand; a `Type::children()` iterator would fold three of them.
- **Small API warts**: `Osis::servers()` returns `Result` but cannot fail; `osis_schema::read_path` is used only by its own tests; generated id modules carry `use super::*` only for the `use osis::schema as osis_schema` alias (a `$crate` macro would drop it).
