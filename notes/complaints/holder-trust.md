# holder-trust
> Summary: Workflow notes from the holder-trust design branch.

- schema/core.osis is compiled (osis-schema statics, osis build.rs) and pinned by an aspect count in core/schema/tests/it/parse.rs: a spec-only schema change still needs a crate test edit and a build.
- TLC compares strings with integers as an error: model sentinels (no head, a fork step) as integers.
- `Engine::commit` skips `mark_acted` (only `Engine::write` marks and keeps), so a test "accepting" with `commit` silently accepts nothing; and a listing of a thing already listed changes no group, so an accept there needs `Engine::accept_invite`.
- An index derived from D's state needs D known: `Tx::derive` sees nothing before the account is set (a pairing applies D's commits first), so the record is observed again at load, reload and `paired`; `check_index` caught the missing load path.
