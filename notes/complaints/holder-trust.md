# holder-trust
> Summary: Workflow notes from the holder-trust design branch.

- schema/core.osis is compiled (osis-schema statics, osis build.rs) and pinned by an aspect count in core/schema/tests/it/parse.rs: a spec-only schema change still needs a crate test edit and a build.
- TLC compares strings with integers as an error: model sentinels (no head, a fork step) as integers.
