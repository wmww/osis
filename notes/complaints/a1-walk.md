# Complaints: a1-walk
> Summary: Footguns met building osis-perm's walk along stated paths (A1 step 3a).

- The workspace denies `clippy::indexing_slicing` in library code; a walk over interned tables written with `v[i]` everywhere had to be reworked at the end (a `Tab` whose out-of-range read gives a nil value). Read the lint list (Cargo.toml `[workspace.lints.clippy]`) before writing index-heavy library code.
- `osis_base::testenv` env var names must be listed in core/base/testenv-known.txt: reuse `OSIS_PERM_SEED` (through `common::seeded`) rather than inventing a variable for a new property.
- Mutation probes as source edits from a committed state (a script writing the file and restoring it from its own copy) worked well and kept the library free of test switches; they need the crate's default tests under a minute to be cheap.
