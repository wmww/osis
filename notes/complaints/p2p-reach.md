# p2p-reach
- The brief's scratch dir did not exist; a background run redirecting into it failed at once (exit 1, no output). Briefs could say "create it first".
- `osis-schema` generated code is regenerated with `OSIS_REGEN_VECTORS=1` (named for vectors, not codegen); found only by reading tests/it/codegen.rs.
- Rebase conflicts in generated files (`core/schema/tests/gen/core.rs`, `core/test/vectors/schema/core.vec`) whenever two branches touch core.osis: take main's and regenerate (`OSIS_REGEN_VECTORS=1` codegen test, `gen-vectors`).
