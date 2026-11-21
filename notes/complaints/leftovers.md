# leftovers
- Folding `osis_schema::Retention` reached engine tests (9 files under core/engine/tests/it, plus src unit tests) although the brief put engine tests off-limits: the schema type is used there directly; the edits are mechanical one-line swaps.
- `cli set` takes its flags only before the positionals (`[PATH] VALUE` is trailing): `set T AK V --retention writer` reads the flag as a value.
