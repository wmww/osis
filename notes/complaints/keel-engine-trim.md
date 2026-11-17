# keel-engine-trim
- `git checkout <file>` to undo a trial edit also threw away earlier uncommitted edits in the same files (mod.rs files hold both). Commit a wip before any trial that may be reverted.
- Editing sources while a background `cargo test` compiles mixes states: the run reported failures from half-applied moves. Don't edit the crate under test until the run ends.
- `tools/deprecated_probe.py` writes nothing if its output directory is missing (the shell redirect fails first); mkdir the scratch dir before the background run.
- policy's code-ref check reads comments as code: a stale name in a code comment hides the same stale name in notes, so fixing comments surfaces note violations.
- Moving src tests to tests/it is cheap only for files on the public surface; most engine src tests reach `pub(crate)` internals (rotation's white-box helpers, `#[cfg(test)]` Core fields such as `lie_facts`, `whole_apply`, `piece_fault`), so the second engine compile stays.
